"""Local footprint drift monitor, upstream schema checker, and system doctor."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .formats import (
    FormatError,
    dump_json,
    extract_key_paths,
    parse_by_format,
    parse_json,
)
from .paths import RuntimeContext, atomic_write_text, file_mode, sha256_bytes, sha256_file
from .policy import detect_grok_state


MONITORED_BINARIES = (
    "agy",
    "claude",
    "codex",
    "gemini",
    "copilot",
    "gh",
    "kimi",
    "grok",
    "opencode",
    "cline",
    "goose",
    "aider",
    "bwrap",
)

AUTH_SKIP_NAMES = frozenset(
    {
        "antigravity-oauth-token",
        "oauth_creds.json",
        "google_accounts.json",
        ".credentials.json",
        "auth.json",
        "mcp_credentials.json",
        "hosts.yml",
        "secrets.yaml",
        "providers.json",
        "history.jsonl",
    }
)

AUTH_SKIP_DIRS = frozenset({"credentials", "keyrings", "ccd-session-secrets"})

HARNESS_ROOTS = (
    ".gemini",
    ".claude",
    ".codex",
    ".copilot",
    ".kimi-code",
    ".grok",
    ".config/opencode",
    ".config/devin",
    ".config/goose",
    ".cursor",
    ".cline",
)

HARNESS_SINGLETON_FILES = (
    ".claude.json",
    ".aider.conf.yml",
)

MEMORY_DIR_MARKERS = frozenset(
    {
        "memories",
        "memories_v2",
        "memories_extensions",
        "annotations",
        "implicit",
        "memory-bank",
        "memory",
    }
)

TRACKED_CONFIG_NAMES = {
    "settings.json": "json",
    "config.json": "json",
    "mcp_config.json": "json",
    "mcp-config.json": "json",
    "mcp.json": "json",
    "cli-config.json": "json",
    "cline_mcp_settings.json": "json",
    "user-settings.json": "json",
    "workspace-trust.json": "json",
    "opencode.jsonc": "jsonc",
    "opencode.json": "jsonc",
    "config.toml": "toml",
    "failsafe.config.toml": "toml",
    "managed_config.toml": "toml",
    "requirements.toml": "toml",
    "config.yaml": "yaml",
    ".claude.json": "json",
    ".aider.conf.yml": "yaml",
}


def _find_binary(name: str, home_dir: Path) -> Path | None:
    found = shutil.which(name)
    if found:
        return Path(found)
    local_bin = home_dir / ".local" / "bin" / name
    if local_bin.is_file() and os.access(local_bin, os.X_OK):
        return local_bin
    return None


def _collect_binaries(home_dir: Path, fast: bool = False) -> dict[str, dict[str, Any]]:
    bins: dict[str, dict[str, Any]] = {}
    for name in MONITORED_BINARIES:
        exe = _find_binary(name, home_dir)
        if not exe:
            continue
        entry: dict[str, Any] = {"path": str(exe)}
        try:
            real = exe.resolve()
            if real.is_file():
                entry["sha256"] = sha256_file(real)
        except OSError:
            pass
        if not fast:
            try:
                proc = subprocess.run(
                    [str(exe), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=1.5,
                    check=False,
                )
                ver = (proc.stdout or proc.stderr or "").strip().splitlines()
                if ver:
                    entry["version"] = ver[0][:120]
            except (OSError, subprocess.TimeoutExpired):
                pass
        bins[name] = entry
    return bins


def _collect_antigravity_builtin(home_dir: Path) -> dict[str, str]:
    base = home_dir / ".gemini" / "antigravity-cli"
    out: dict[str, str] = {}
    for rel in ("builtin/.checksum", "builtin/.manifest", "cache/CHANGELOG.md"):
        p = base / rel
        if p.is_file() and not p.is_symlink():
            try:
                out[rel] = sha256_file(p)
            except OSError:
                pass
    return out


def _collect_configs_and_memory(
    home_dir: Path,
    deployed_ro_paths: set[str],
) -> dict[str, Any]:
    key_shapes: dict[str, list[str]] = {}
    memory_paths: list[str] = []
    migration_markers: list[str] = []
    perm_regressions: list[dict[str, str]] = []
    file_metadata: dict[str, dict[str, Any]] = {}

    def scan_file(p: Path) -> None:
        rel = str(p.relative_to(home_dir))
        if p.name in AUTH_SKIP_NAMES:
            return
        try:
            st = os.lstat(p)
        except OSError:
            return
        if stat.S_ISLNK(st.st_mode):
            return
        mode = stat.S_IMODE(st.st_mode)
        abs_str = str(p.resolve()) if p.exists() else str(p)
        # Allow intentional 0444/0400 read-only deployed declarative targets & plugin-bundle files.
        is_ro_target = any(
            abs_str == rp or str(p) == rp or abs_str.startswith(rp.rstrip("/") + "/") or str(p).startswith(rp.rstrip("/") + "/")
            for rp in deployed_ro_paths
        )
        if not is_ro_target and (mode & 0o077) != 0 and p.name in TRACKED_CONFIG_NAMES:
            perm_regressions.append({"path": rel, "mode": f"{mode:04o}"})

        if p.name.upper() == "MEMORY.MD" or p.name in ("auto-memory.json",):
            memory_paths.append(rel)

        if p.name in (".migrated",) or p.name.endswith(".bad"):
            migration_markers.append(rel)

        fmt = TRACKED_CONFIG_NAMES.get(p.name)
        if fmt and stat.S_ISREG(st.st_mode):
            file_metadata[rel] = {"mode": f"{mode:04o}", "size": st.st_size}
            if st.st_size == 0:
                key_shapes[rel] = []
                return
            try:
                text = p.read_text(encoding="utf-8")
                parsed = parse_by_format(text, fmt)
                key_shapes[rel] = extract_key_paths(parsed)
                file_metadata[rel]["sha256"] = sha256_bytes(text.encode("utf-8"))
            except (FormatError, UnicodeDecodeError, OSError):
                key_shapes[rel] = ["<PARSE_ERROR>"]

    for root_rel in HARNESS_ROOTS:
        root_dir = home_dir / root_rel
        if not root_dir.exists() or root_dir.is_symlink():
            continue
        try:
            rmode = file_mode(root_dir)
            if (rmode & 0o077) != 0:
                perm_regressions.append({"path": root_rel, "mode": f"{rmode:04o}"})
        except OSError:
            pass
        for cur, dirs, files in os.walk(root_dir, followlinks=False):
            cur_p = Path(cur)
            dirs[:] = sorted(d for d in dirs if d not in AUTH_SKIP_DIRS and d not in (".git", "node_modules"))
            for d in list(dirs):
                dp = cur_p / d
                if dp.is_symlink():
                    continue
                if d in MEMORY_DIR_MARKERS:
                    memory_paths.append(str(dp.relative_to(home_dir)))
            for fname in sorted(files):
                fp = cur_p / fname
                scan_file(fp)

    for single_rel in HARNESS_SINGLETON_FILES:
        sp = home_dir / single_rel
        if sp.is_file() and not sp.is_symlink():
            scan_file(sp)

    return {
        "key_shapes": key_shapes,
        "memory_paths": sorted(set(memory_paths)),
        "migration_markers": sorted(set(migration_markers)),
        "perm_regressions": perm_regressions,
        "file_metadata": file_metadata,
    }


def _load_deployed_ro_paths(ctx: RuntimeContext) -> set[str]:
    manifest_path = ctx.state_dir / "deployed-manifest.json"
    if not manifest_path.exists():
        return set()
    try:
        doc = parse_json(manifest_path.read_text(encoding="utf-8"))
    except (FormatError, OSError):
        return set()
    out: set[str] = set()
    for item in doc.get("targets", {}).values():
        if isinstance(item, dict) and item.get("strategy") in ("ro", "plugin-bundle"):
            if item.get("path"):
                out.add(str(item["path"]))
    return out


def collect_footprint(ctx: RuntimeContext, fast: bool = False) -> dict[str, Any]:
    """Collect current local host footprint without reading any Tier-B secret contents."""
    ro_paths = _load_deployed_ro_paths(ctx)
    scanned = _collect_configs_and_memory(ctx.home_dir, ro_paths)
    return {
        "schema_version": "1.0",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "home_dir": str(ctx.home_dir),
        "binaries": _collect_binaries(ctx.home_dir, fast=fast),
        "antigravity_builtin": _collect_antigravity_builtin(ctx.home_dir),
        "grok_state": detect_grok_state(ctx.home_dir),
        **scanned,
    }


def watch_updates(
    ctx: RuntimeContext,
    update_baseline: bool = False,
    fast: bool = False,
) -> dict[str, Any]:
    """Compare current host footprint against saved baseline and flag drift."""
    baseline_path = ctx.state_dir / "host-footprint.json"
    current = collect_footprint(ctx, fast=fast)

    if update_baseline:
        atomic_write_text(baseline_path, dump_json(current), mode=0o600, boundary_root=ctx.state_dir)
        return {
            "ok": True,
            "baseline_updated": True,
            "baseline_path": str(baseline_path),
            "events": [],
        }

    events: list[dict[str, Any]] = []
    grok_state = current.get("grok_state", {})
    if grok_state.get("exists") and grok_state.get("ambiguous") and ctx.grok_flavor is None:
        events.append(
            {
                "type": "GROK_COLLISION",
                "severity": "error",
                "path": "~/.grok",
                "detail": "Ambiguous ~/.grok/ directory (xAI Grok Build vs @vibe-kit/grok-cli); pass --grok-flavor xai|vibekit",
            }
        )

    if not baseline_path.exists():
        blocking = [e for e in events if e["severity"] == "error"]
        return {
            "ok": len(blocking) == 0,
            "baseline_exists": False,
            "baseline_path": str(baseline_path),
            "events": events,
        }

    baseline = parse_json(baseline_path.read_text(encoding="utf-8"))

    # Binary changes
    old_bins = baseline.get("binaries", {})
    new_bins = current.get("binaries", {})
    for bname, binfo in new_bins.items():
        if bname not in old_bins or old_bins[bname].get("sha256") != binfo.get("sha256"):
            events.append(
                {
                    "type": "BINARY_CHANGED",
                    "severity": "info",
                    "path": binfo.get("path", bname),
                    "detail": f"{bname} binary digest or presence changed",
                }
            )

    # Builtin changes
    if baseline.get("antigravity_builtin") != current.get("antigravity_builtin"):
        events.append(
            {
                "type": "BUILTIN_CHANGED",
                "severity": "info",
                "path": "~/.gemini/antigravity-cli/builtin",
                "detail": "Antigravity builtin manifest/checksum changed",
            }
        )

    # Key-shape diffs (NEW_KEY / DROPPED_KEY)
    old_shapes = baseline.get("key_shapes", {})
    new_shapes = current.get("key_shapes", {})
    for cfg_rel, new_keys in new_shapes.items():
        if cfg_rel not in old_shapes:
            continue
        old_set = set(old_shapes[cfg_rel])
        new_set = set(new_keys)
        added = sorted(new_set - old_set)
        dropped = sorted(old_set - new_set)
        if added:
            events.append(
                {
                    "type": "NEW_KEY",
                    "severity": "error",
                    "path": cfg_rel,
                    "keys": added,
                    "detail": f"New config keys in {cfg_rel}: {', '.join(added[:10])}",
                }
            )
        if dropped:
            events.append(
                {
                    "type": "DROPPED_KEY",
                    "severity": "error",
                    "path": cfg_rel,
                    "keys": dropped,
                    "detail": f"Dropped config keys in {cfg_rel}: {', '.join(dropped[:10])}",
                }
            )

    # New memory paths
    old_mem = set(baseline.get("memory_paths", []))
    new_mem = set(current.get("memory_paths", []))
    for mp in sorted(new_mem - old_mem):
        events.append(
            {
                "type": "NEW_MEMORY_PATH",
                "severity": "error",
                "path": mp,
                "detail": f"New agent memory directory detected: {mp}",
            }
        )

    # New migration markers
    old_mig = set(baseline.get("migration_markers", []))
    new_mig = set(current.get("migration_markers", []))
    for mm in sorted(new_mig - old_mig):
        events.append(
            {
                "type": "MIGRATION_MARKER",
                "severity": "warning",
                "path": mm,
                "detail": f"New harness migration/backup marker: {mm}",
            }
        )

    # Permission regressions
    for reg in current.get("perm_regressions", []):
        events.append(
            {
                "type": "PERMISSION_REGRESSION",
                "severity": "warning",
                "path": reg["path"],
                "detail": f"Permissive mode {reg['mode']} on {reg['path']}",
            }
        )

    blocking = [e for e in events if e["severity"] == "error"]
    return {
        "ok": len(blocking) == 0,
        "baseline_exists": True,
        "baseline_path": str(baseline_path),
        "events": events,
    }


def upstream_check(
    ctx: RuntimeContext,
    fetch: bool = False,
    update_baseline: bool = False,
) -> dict[str, Any]:
    """Check policy/upstream-sources.json against pinned snapshots (and optionally live URLs)."""
    src_path = ctx.repo_root / "policy" / "upstream-sources.json"
    if not src_path.exists():
        return {"ok": False, "error": "Missing policy/upstream-sources.json", "results": []}

    doc = parse_json(src_path.read_text(encoding="utf-8"))
    sources = doc.get("sources", {}) if isinstance(doc, dict) else {}
    results: list[dict[str, Any]] = []
    ok = True
    updated = False

    for src_id, info in sorted(sources.items()):
        if not isinstance(info, dict):
            continue
        snap_raw = info.get("snapshot_file")
        snap_rel = str(snap_raw) if snap_raw else ""
        expected_sha = str(info.get("sha256") or "")
        url = str(info.get("url") or "")
        entry_res: dict[str, Any] = {"id": src_id, "harness": info.get("harness", ""), "status": "ok"}

        snap_path = (ctx.repo_root / snap_rel).resolve() if snap_rel else None
        if snap_path and not snap_path.is_relative_to(ctx.repo_root):
            entry_res["status"] = "invalid_path"
            ok = False
            results.append(entry_res)
            continue

        if not fetch:
            if not snap_rel:
                entry_res["status"] = "url_only_pinned"
            elif not snap_path or not snap_path.exists():
                entry_res["status"] = "missing_snapshot"
                ok = False
            else:
                actual = sha256_file(snap_path)
                if expected_sha and actual != expected_sha:
                    entry_res["status"] = "snapshot_hash_mismatch"
                    entry_res["actual_sha256"] = actual
                    entry_res["expected_sha256"] = expected_sha
                    ok = False
            results.append(entry_res)
            continue

        if not url.startswith("https://"):
            entry_res["status"] = "rejected_non_https"
            ok = False
            results.append(entry_res)
            continue

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "agentconfig-upstream-check/0.1"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read(10 * 1024 * 1024)
            live_sha = sha256_bytes(data)
            if update_baseline:
                if snap_path:
                    atomic_write_text(
                        snap_path,
                        data.decode("utf-8"),
                        mode=0o644,
                        boundary_root=ctx.repo_root,
                    )
                info["sha256"] = live_sha
                updated = True
                entry_res["status"] = "updated"
                entry_res["sha256"] = live_sha
            elif expected_sha and live_sha != expected_sha:
                entry_res["status"] = "DRIFT"
                entry_res["expected_sha256"] = expected_sha
                entry_res["live_sha256"] = live_sha
                ok = False
            else:
                entry_res["sha256"] = live_sha
        except (urllib.error.URLError, TimeoutError, UnicodeDecodeError, OSError) as exc:
            # Fail closed on fetch failure without modifying baseline.
            entry_res["status"] = "fetch_error"
            entry_res["detail"] = str(exc)
            ok = False
        results.append(entry_res)

    if updated:
        atomic_write_text(src_path, dump_json(doc), mode=0o644, boundary_root=ctx.repo_root)

    return {"ok": ok, "results": results}


def _check_gi_secret() -> bool:
    try:
        import gi  # type: ignore

        gi.require_version("Secret", "1")
        from gi.repository import Secret  # type: ignore

        return Secret is not None
    except Exception:
        return False


def doctor(ctx: RuntimeContext) -> dict[str, Any]:
    """Run local environment, tooling, permission, and integrity diagnostics."""
    from .deployer import verify_deployed

    checks: list[dict[str, Any]] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append({"check": name, "status": status, "detail": detail})

    for tool, required in (
        ("git", True),
        ("flock", True),
        ("bwrap", False),
        ("agy", False),
        ("age", False),
        ("sops", False),
        ("gitleaks", False),
        ("secret-tool", False),
    ):
        path = _find_binary(tool, ctx.home_dir)
        if path:
            add(f"tool:{tool}", "ok", str(path))
        else:
            add(f"tool:{tool}", "error" if required else "warn", "not found")

    add("keyring:gi.Secret", "ok" if _check_gi_secret() else "warn", "GNOME Secret GIR binding")

    cur_umask = os.umask(0o077)
    os.umask(cur_umask)
    add("process_umask", "ok" if cur_umask == 0o077 else "warn", f"{cur_umask:04o}")

    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    add("env:XDG_RUNTIME_DIR", "ok" if xdg else "warn", xdg or "unset in current shell")

    local_tmp = ctx.home_dir / ".local" / "tmp"
    if local_tmp.exists():
        m = file_mode(local_tmp)
        add("dir:~/.local/tmp", "ok" if (m & 0o077) == 0 else "error", f"mode {m:04o}")
    else:
        add("dir:~/.local/tmp", "warn", "missing")

    for sub in (".gemini", ".gemini/antigravity-cli", ".gemini/config", ".cache/antigravity"):
        p = ctx.home_dir / sub
        if p.exists() and not p.is_symlink():
            m = file_mode(p)
            add(f"dir:~/{sub}", "ok" if (m & 0o077) == 0 else "warn", f"mode {m:04o}")

    verify_res = verify_deployed(ctx)
    if verify_res.get("has_manifest"):
        add("deployed_manifest", "ok" if verify_res["ok"] else "error", f"{len(verify_res.get('issues', []))} issues")
    else:
        add("deployed_manifest", "info", "no deployed-manifest.json yet")

    watch_res = watch_updates(ctx, update_baseline=False, fast=True)
    add("watch_updates", "ok" if watch_res["ok"] else "error", f"{len(watch_res.get('events', []))} events")

    ok = all(c["status"] != "error" for c in checks)
    return {"ok": ok, "checks": checks}
