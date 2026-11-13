"""Atomic deployment, diffing, integrity verification, and snapshot rollback."""

from __future__ import annotations

import contextlib
import difflib
import fcntl
import os
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .formats import (
    FormatError,
    apply_managed_patch,
    dump_by_format,
    dump_json,
    extract_managed_subtree,
    get_dotted,
    parse_by_format,
    parse_json,
)
from .paths import (
    RuntimeContext,
    SafetyError,
    atomic_write_bytes,
    atomic_write_text,
    ensure_safe_dir,
    expand_target_path,
    file_mode,
    safe_target,
    sha256_bytes,
    sha256_file,
)
from .policy import detect_grok_state, validate_repo
from .render import RenderedTarget, load_targets_manifest, normalize_harness, render_target


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-%f")


@contextlib.contextmanager
def acquire_lock(ctx: RuntimeContext) -> Iterator[Path]:
    """Acquire exclusive flock on runtime_dir/agentcfg.lock."""
    ensure_safe_dir(ctx.runtime_dir, mode=0o700)
    lock_path = ctx.runtime_dir / "agentcfg.lock"
    safe_target(lock_path, boundary_root=ctx.runtime_dir)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(f"Another agentcfg process holds lock {lock_path}") from exc
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode("ascii"))
        yield lock_path
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def verify_git_head(ctx: RuntimeContext) -> tuple[bool, str]:
    """Verify signed git HEAD when commit.gpgsign is enabled or require_signed=True."""
    git_dir = ctx.repo_root / ".git"
    if not git_dir.exists():
        if ctx.require_signed:
            return False, "Missing .git repository for required commit signature check"
        return True, "no .git directory (skipped)"

    has_head = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=ctx.repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if has_head.returncode != 0:
        if ctx.require_signed:
            return False, "Repository has no commits to verify"
        return True, "no commits yet"

    gpgsign = subprocess.run(
        ["git", "config", "--bool", "--get", "commit.gpgsign"],
        cwd=ctx.repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    should_verify = ctx.require_signed or gpgsign.stdout.strip() == "true"
    if not should_verify:
        return True, "commit signing not enabled"

    sig_state_res = subprocess.run(
        ["git", "show", "-s", "--format=%G?", "HEAD"],
        cwd=ctx.repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    sig_state = sig_state_res.stdout.strip()
    if sig_state == "N" and not ctx.require_signed:
        return True, "HEAD unsigned (optional)"

    allowed_file = subprocess.run(
        ["git", "config", "--get", "gpg.ssh.allowedSignersFile"],
        cwd=ctx.repo_root,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if allowed_file and not Path(allowed_file).expanduser().exists() and not ctx.require_signed:
        return True, "allowedSignersFile missing on test host"

    res = subprocess.run(
        ["git", "verify-commit", "HEAD"],
        cwd=ctx.repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        detail = (res.stderr or res.stdout or f"git verify-commit HEAD failed (status={sig_state or 'unknown'})").strip()
        return False, detail
    return True, "HEAD signature verified"


def _git_head_sha(repo_root: Path) -> str:
    if not (repo_root / ".git").exists():
        return "untracked"
    res = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    return res.stdout.strip() if res.returncode == 0 else "unborn"


def _target_boundary(target: dict[str, Any], ctx: RuntimeContext) -> Path:
    if target.get("scope") == "project":
        if ctx.project_dir is None:
            raise ValueError("Project target requires --project <dir>")
        return ctx.project_dir
    return ctx.home_dir


def _resolve_target_path(target: dict[str, Any], ctx: RuntimeContext) -> Path:
    return expand_target_path(
        str(target["path"]),
        home_dir=ctx.home_dir,
        project_dir=ctx.project_dir,
    )


def _read_manifest_grok_flavor(ctx: RuntimeContext) -> str | None:
    mp = ctx.state_dir / "deployed-manifest.json"
    if not mp.exists():
        return None
    try:
        doc = parse_json(mp.read_text(encoding="utf-8"))
        val = doc.get("grok_flavor")
        return str(val) if val in ("xai", "vibekit") else None
    except (FormatError, OSError):
        return None


def _resolve_grok_flavor(targets: list[dict[str, Any]], ctx: RuntimeContext) -> str | None:
    grok_targets = [
        t for t in targets
        if t.get("enabled", True) and normalize_harness(str(t.get("harness", ""))) == "grok"
    ]
    if not grok_targets:
        return ctx.grok_flavor
    if ctx.grok_flavor is not None:
        return ctx.grok_flavor

    grok_state = detect_grok_state(ctx.home_dir)
    if grok_state["has_xai"] and grok_state["has_vibekit"]:
        raise RuntimeError(
            "GROK_FLAVOR_AMBIGUOUS: ~/.grok/ contains both xAI and Vibekit markers; specify --grok-flavor xai|vibekit"
        )
    if grok_state["exists"] and grok_state["ambiguous"]:
        saved = _read_manifest_grok_flavor(ctx)
        if saved is not None:
            return saved
        raise RuntimeError(
            "GROK_FLAVOR_AMBIGUOUS: ~/.grok/ collision risk detected; specify --grok-flavor xai|vibekit"
        )
    if grok_state["has_xai"] and not grok_state["has_vibekit"]:
        return "xai"
    if grok_state["has_vibekit"] and not grok_state["has_xai"]:
        return "vibekit"
    saved = _read_manifest_grok_flavor(ctx)
    if saved is not None:
        return saved
    flavors_in_catalog = {t.get("grok_flavor") for t in grok_targets if t.get("grok_flavor")}
    if len(flavors_in_catalog) > 1:
        raise RuntimeError(
            "GROK_FLAVOR_AMBIGUOUS: multiple Grok flavors configured; specify --grok-flavor xai|vibekit"
        )
    return next(iter(flavors_in_catalog), None)


def _filter_active_targets(
    targets: list[dict[str, Any]],
    ctx: RuntimeContext,
    only_target_paths: set[str] | None = None,
) -> list[dict[str, Any]]:
    active_list: list[dict[str, Any]] = []
    eff_flavor = _resolve_grok_flavor(targets, ctx)

    for t in targets:
        if not t.get("enabled", True):
            continue
        scope = t.get("scope", "global")
        if scope == "project" and ctx.project_dir is None:
            continue
        if normalize_harness(str(t.get("harness", ""))) == "grok":
            t_flavor = t.get("grok_flavor")
            if eff_flavor is not None and t_flavor is not None and t_flavor != eff_flavor:
                continue
        if only_target_paths is not None:
            tp = os.path.abspath(_resolve_target_path(t, ctx))
            if tp not in only_target_paths and not any(q.startswith(tp + "/") for q in only_target_paths):
                continue
        active_list.append(t)
    return active_list


def _wire_git_info_exclude(project_dir: Path, rel_path: str) -> None:
    """Append generated .agents/ exclusions to .git/info/exclude (never .gitignore)."""
    git_entry = project_dir / ".git"
    if not git_entry.exists():
        return
    if git_entry.is_file():
        # Handle git worktrees/submodules where .git points to gitdir.
        txt = git_entry.read_text(encoding="utf-8", errors="ignore").strip()
        if txt.startswith("gitdir:"):
            raw_gd = txt.split(":", 1)[1].strip()
            git_dir = Path(raw_gd) if Path(raw_gd).is_absolute() else (project_dir / raw_gd)
        else:
            return
    else:
        git_dir = git_entry

    info_dir = git_dir / "info"
    exclude_file = info_dir / "exclude"
    safe_target(exclude_file, boundary_root=git_dir)
    ensure_safe_dir(info_dir, mode=0o755, boundary_root=git_dir)

    top_dir = Path(rel_path).parts[0] if Path(rel_path).parts else rel_path
    pattern = f"{top_dir}/" if top_dir.startswith(".agents") else rel_path

    existing_lines: list[str] = []
    if exclude_file.exists():
        existing_lines = exclude_file.read_text(encoding="utf-8").splitlines()
    if pattern in existing_lines:
        return

    new_lines = existing_lines + [pattern]
    atomic_write_text(exclude_file, "\n".join(new_lines) + "\n", mode=0o644, boundary_root=git_dir)


def create_snapshot(
    ctx: RuntimeContext,
    targets: list[dict[str, Any]],
    label: str = "apply",
) -> Path:
    """Snapshot live managed targets, deployed-manifest.json, and memory files."""
    snap_dir = ctx.state_dir / "snapshots" / f"{_utc_stamp()}-{label}"
    ensure_safe_dir(snap_dir, mode=0o700, boundary_root=ctx.state_dir)

    records: list[dict[str, Any]] = []
    for t in targets:
        dest = _resolve_target_path(t, ctx)
        tid = str(t["id"])
        rec: dict[str, Any] = {
            "id": tid,
            "path": str(dest),
            "existed": os.path.lexists(dest),
            "is_dir": False,
            "files": [],
        }
        if os.path.lexists(dest) and not os.path.islink(dest):
            st = os.lstat(dest)
            if stat.S_ISDIR(st.st_mode):
                rec["is_dir"] = True
                rec["dir_mode"] = f"{stat.S_IMODE(st.st_mode):04o}"
                for p in sorted(dest.rglob("*")):
                    if p.is_file() and not p.is_symlink():
                        rel = p.relative_to(dest).as_posix()
                        snap_file = snap_dir / "targets" / tid / rel
                        data = p.read_bytes()
                        atomic_write_bytes(snap_file, data, mode=0o600, boundary_root=snap_dir)
                        rec["files"].append(
                            {
                                "rel": rel,
                                "snap_rel": str(snap_file.relative_to(snap_dir)),
                                "mode": f"{file_mode(p):04o}",
                                "sha256": sha256_bytes(data),
                            }
                        )
            elif stat.S_ISREG(st.st_mode):
                snap_file = snap_dir / "targets" / tid / dest.name
                data = dest.read_bytes()
                atomic_write_bytes(snap_file, data, mode=0o600, boundary_root=snap_dir)
                rec["mode"] = f"{stat.S_IMODE(st.st_mode):04o}"
                rec["snap_rel"] = str(snap_file.relative_to(snap_dir))
                rec["sha256"] = sha256_bytes(data)
        records.append(rec)

    manifest_file = ctx.state_dir / "deployed-manifest.json"
    had_manifest = manifest_file.exists()
    if had_manifest:
        atomic_write_bytes(
            snap_dir / "deployed-manifest.json",
            manifest_file.read_bytes(),
            mode=0o600,
            boundary_root=snap_dir,
        )

    # Snapshot key local memory files if present.
    for rel_pat in (
        ".gemini/GEMINI.md",
        ".claude/projects/*/memory/*.md",
        ".codex/memories/**/*.md",
        ".codex/memories_v2/**/*.md",
        ".config/goose/memory/**/*",
    ):
        for mp in sorted(ctx.home_dir.glob(rel_pat)):
            if mp.is_file() and not mp.is_symlink():
                rel = mp.relative_to(ctx.home_dir)
                atomic_write_bytes(
                    snap_dir / "memory" / rel,
                    mp.read_bytes(),
                    mode=0o600,
                    boundary_root=snap_dir,
                )

    meta = {
        "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "label": label,
        "home_dir": str(ctx.home_dir),
        "had_deployed_manifest": had_manifest,
        "targets": records,
    }
    atomic_write_text(snap_dir / "snapshot.json", dump_json(meta), mode=0o600, boundary_root=snap_dir)
    return snap_dir


def _deploy_single_target(
    target: dict[str, Any],
    rendered: RenderedTarget,
    ctx: RuntimeContext,
) -> dict[str, Any]:
    dest = _resolve_target_path(target, ctx)
    boundary = _target_boundary(target, ctx)
    mode = rendered.mode

    if rendered.files is not None:
        # Directory / plugin-bundle deployment.
        safe_target(dest, boundary_root=boundary, allow_dir_target=True)
        dir_mode = int(str(target.get("dir_mode", "0700")), 8)
        ensure_safe_dir(dest, mode=dir_mode, boundary_root=boundary)

        # Clean stale files not in rendered bundle.
        expected_rels = set(rendered.files.keys())
        for existing in sorted(dest.rglob("*"), reverse=True):
            if existing.is_symlink():
                raise SafetyError(f"Symlink found inside bundle directory: {existing}")
            rel = existing.relative_to(dest).as_posix()
            if existing.is_file() and rel not in expected_rels:
                existing.unlink()
            elif existing.is_dir() and not any(existing.iterdir()):
                existing.rmdir()

        file_hashes: dict[str, str] = {}
        for rel, data in sorted(rendered.files.items()):
            fdest = dest / rel
            atomic_write_bytes(fdest, data, mode=mode, boundary_root=boundary)
            file_hashes[rel] = sha256_bytes(data)

        return {
            "id": rendered.target_id,
            "harness": rendered.harness,
            "path": str(dest),
            "scope": target.get("scope", "global"),
            "strategy": rendered.strategy,
            "format": "dir",
            "mode": f"{mode:04o}",
            "files": file_hashes,
        }

    if rendered.strategy == "patch-managed-keys":
        safe_target(dest, boundary_root=boundary, allow_dir_target=False)
        existing_obj: dict[str, Any] = {}
        if os.path.lexists(dest):
            raw_txt = dest.read_text(encoding="utf-8")
            if raw_txt.strip():
                parsed = parse_by_format(raw_txt, rendered.format)
                if not isinstance(parsed, dict):
                    raise FormatError(f"Expected mapping in patched target {dest}")
                existing_obj = parsed
        desired_obj = rendered.patch_data or {}
        managed_keys = list(rendered.managed_keys or [])
        removed_keys = list(rendered.removed_keys or [])
        patched_obj = apply_managed_patch(existing_obj, desired_obj, managed_keys, removed_keys)
        new_bytes = dump_by_format(patched_obj, rendered.format).encode("utf-8")
        atomic_write_bytes(dest, new_bytes, mode=mode, boundary_root=boundary)

        subtree = extract_managed_subtree(patched_obj, managed_keys)
        subtree_sha = sha256_bytes(dump_json(subtree, sort_keys=True).encode("utf-8"))
        return {
            "id": rendered.target_id,
            "harness": rendered.harness,
            "path": str(dest),
            "scope": target.get("scope", "global"),
            "strategy": "patch-managed-keys",
            "format": rendered.format,
            "mode": f"{mode:04o}",
            "managed_keys": managed_keys,
            "removed_keys": removed_keys,
            "subtree_sha256": subtree_sha,
            "sha256": sha256_bytes(new_bytes),
        }

    # Declarative ro target.
    data = rendered.content or b""
    atomic_write_bytes(dest, data, mode=mode, boundary_root=boundary)
    return {
        "id": rendered.target_id,
        "harness": rendered.harness,
        "path": str(dest),
        "scope": target.get("scope", "global"),
        "strategy": rendered.strategy,
        "format": rendered.format,
        "mode": f"{mode:04o}",
        "sha256": sha256_bytes(data),
    }


def apply_targets(
    ctx: RuntimeContext,
    safe: bool = True,
    approve_drift: bool = False,
    failsafe: bool = False,
    only_target_paths: set[str] | None = None,
    run_pre_cleanse: bool = True,
) -> dict[str, Any]:
    """Safely validate, snapshot, render, deploy, exclude, and verify targets."""
    from .cleanse import run_cleanse
    from .monitor import watch_updates

    with acquire_lock(ctx):
        sig_ok, sig_msg = verify_git_head(ctx)
        if not sig_ok:
            raise RuntimeError(f"Git HEAD signature verification failed: {sig_msg}")

        all_targets = load_targets_manifest(ctx.repo_root)
        active_targets = _filter_active_targets(all_targets, ctx, only_target_paths=only_target_paths)

        if not approve_drift:
            drift = watch_updates(ctx, update_baseline=False, fast=True)
            if not drift["ok"]:
                reasons = "; ".join(e.get("detail", e.get("type", "drift")) for e in drift.get("events", []) if e.get("severity") == "error")
                raise RuntimeError(f"watch-updates drift gate blocked apply: {reasons}")

        eff_flavor = _resolve_grok_flavor(all_targets, ctx)
        val_report = validate_repo(
            ctx,
            staged=False,
            run_agy=False,
            check_grok_home=(ctx.grok_flavor is None and eff_flavor is None),
        )
        if not val_report.ok:
            errs = "; ".join(f"{e.path}: {e.message}" for e in val_report.errors[:5])
            raise RuntimeError(f"Validation failed before apply: {errs}")

        cleanse_summary: dict[str, Any] | None = None
        if run_pre_cleanse:
            cleanse_summary = run_cleanse(
                ctx,
                scope="config",
                dry_run=not safe,
                auto_quarantine=safe,
                restore_targets=False,
            )

        snap_dir = create_snapshot(ctx, active_targets, label="failsafe" if failsafe else "apply")

        manifest_path = ctx.state_dir / "deployed-manifest.json"
        deployed_map: dict[str, Any] = {}
        if only_target_paths is not None and manifest_path.exists():
            try:
                old_manifest = parse_json(manifest_path.read_text(encoding="utf-8"))
                deployed_map = dict(old_manifest.get("targets") or {})
            except (FormatError, OSError):
                deployed_map = {}

        applied_ids: list[str] = []
        try:
            for t in active_targets:
                rendered = render_target(t, ctx, failsafe=failsafe)
                rec = _deploy_single_target(t, rendered, ctx)
                deployed_map[rendered.target_id] = rec
                applied_ids.append(rendered.target_id)
                if rendered.repo_exclude and ctx.project_dir is not None:
                    _wire_git_info_exclude(ctx.project_dir, str(t["path"]))

            manifest_obj = {
                "schema_version": "1.0",
                "deployed_at": datetime.now(timezone.utc).isoformat(),
                "git_head": _git_head_sha(ctx.repo_root),
                "failsafe": failsafe,
                "grok_flavor": _resolve_grok_flavor(all_targets, ctx),
                "home_dir": str(ctx.home_dir),
                "targets": deployed_map,
            }
            atomic_write_text(
                manifest_path,
                dump_json(manifest_obj),
                mode=0o600,
                boundary_root=ctx.state_dir,
            )

            v_res = verify_deployed(ctx, only_ids=set(applied_ids) if only_target_paths else None)
            if not v_res["ok"]:
                raise RuntimeError(f"Post-apply verification failed: {v_res['issues']}")
        except Exception:
            # Automatic panic-safe rollback from snapshot.
            restore_snapshot(ctx, snapshot_id=snap_dir.name, take_pre_snapshot=False)
            raise

        return {
            "ok": True,
            "applied_ids": applied_ids,
            "snapshot_id": snap_dir.name,
            "manifest_path": str(manifest_path),
            "git_sig": sig_msg,
            "cleanse": cleanse_summary,
        }


def verify_deployed(ctx: RuntimeContext, only_ids: set[str] | None = None) -> dict[str, Any]:
    """Verify SHA-256 hashes (full or managed subtree) and POSIX permissions against deployed-manifest.json."""
    manifest_path = ctx.state_dir / "deployed-manifest.json"
    if not manifest_path.exists():
        return {"ok": False, "has_manifest": False, "issues": ["deployed-manifest.json missing"]}

    doc = parse_json(manifest_path.read_text(encoding="utf-8"))
    targets = doc.get("targets", {})
    issues: list[dict[str, str]] = []
    checked = 0

    for tid, rec in sorted(targets.items()):
        if only_ids is not None and tid not in only_ids:
            continue
        if not isinstance(rec, dict):
            continue
        checked += 1
        dest = Path(rec["path"])
        strategy = rec.get("strategy", "ro")
        expected_mode = int(str(rec.get("mode", "0444")), 8)

        if not os.path.lexists(dest):
            issues.append({"id": tid, "path": str(dest), "issue": "missing target"})
            continue
        if os.path.islink(dest):
            issues.append({"id": tid, "path": str(dest), "issue": "target replaced by symlink"})
            continue

        if strategy == "plugin-bundle" or rec.get("format") == "dir":
            if not dest.is_dir():
                issues.append({"id": tid, "path": str(dest), "issue": "expected directory"})
                continue
            expected_files: dict[str, str] = rec.get("files", {})
            actual_files: dict[str, Path] = {}
            for p in sorted(dest.rglob("*")):
                if os.path.islink(p):
                    issues.append({"id": tid, "path": str(p), "issue": "symlink inside bundle dir"})
                    continue
                if p.is_file():
                    actual_files[p.relative_to(dest).as_posix()] = p
            if set(actual_files.keys()) != set(expected_files.keys()):
                issues.append(
                    {
                        "id": tid,
                        "path": str(dest),
                        "issue": f"bundle file mismatch: expected {sorted(expected_files)}, got {sorted(actual_files)}",
                    }
                )
                continue
            for rel, fp in actual_files.items():
                actual_mode = file_mode(fp)
                if actual_mode != expected_mode:
                    issues.append({"id": tid, "path": str(fp), "issue": f"mode {actual_mode:04o} != {expected_mode:04o}"})
                actual_sha = sha256_file(fp)
                if actual_sha != expected_files[rel]:
                    issues.append({"id": tid, "path": str(fp), "issue": "sha256 drift"})
            continue

        actual_mode = file_mode(dest)
        if actual_mode != expected_mode:
            issues.append(
                {
                    "id": tid,
                    "path": str(dest),
                    "issue": f"mode {actual_mode:04o} != {expected_mode:04o}",
                }
            )

        if strategy == "patch-managed-keys":
            fmt = str(rec.get("format", "json"))
            managed_keys = list(rec.get("managed_keys") or [])
            removed_keys = list(rec.get("removed_keys") or [])
            try:
                parsed = parse_by_format(dest.read_text(encoding="utf-8"), fmt)
            except (FormatError, UnicodeDecodeError, OSError) as exc:
                issues.append({"id": tid, "path": str(dest), "issue": f"parse error: {exc}"})
                continue
            if not isinstance(parsed, dict):
                issues.append({"id": tid, "path": str(dest), "issue": "root is not a mapping"})
                continue
            sentinel = object()
            for rkey in removed_keys:
                if get_dotted(parsed, rkey, sentinel) is not sentinel:
                    issues.append({"id": tid, "path": str(dest), "issue": f"deprecated key {rkey!r} present"})
            subtree = extract_managed_subtree(parsed, managed_keys)
            actual_sub_sha = sha256_bytes(dump_json(subtree, sort_keys=True).encode("utf-8"))
            if actual_sub_sha != rec.get("subtree_sha256"):
                issues.append({"id": tid, "path": str(dest), "issue": "managed subtree sha256 drift"})
        else:
            actual_sha = sha256_file(dest)
            if actual_sha != rec.get("sha256"):
                issues.append({"id": tid, "path": str(dest), "issue": "sha256 drift"})

    return {
        "ok": len(issues) == 0,
        "has_manifest": True,
        "checked": checked,
        "issues": issues,
    }


def diff_targets(ctx: RuntimeContext, failsafe: bool = False) -> dict[str, Any]:
    """Render targets in memory and return unified diffs against live paths."""
    all_targets = load_targets_manifest(ctx.repo_root)
    active = _filter_active_targets(all_targets, ctx)
    diffs: list[dict[str, Any]] = []

    for t in active:
        rendered = render_target(t, ctx, failsafe=failsafe)
        dest = _resolve_target_path(t, ctx)

        if rendered.files is not None:
            for rel, new_bytes in sorted(rendered.files.items()):
                fdest = dest / rel
                old_txt = fdest.read_text(encoding="utf-8", errors="replace") if fdest.is_file() else ""
                new_txt = new_bytes.decode("utf-8", errors="replace")
                if old_txt != new_txt:
                    udiff = "".join(
                        difflib.unified_diff(
                            old_txt.splitlines(keepends=True),
                            new_txt.splitlines(keepends=True),
                            fromfile=f"live:{fdest}",
                            tofile=f"rendered:{rendered.target_id}/{rel}",
                        )
                    )
                    diffs.append({"id": rendered.target_id, "path": str(fdest), "changed": True, "diff": udiff})
            continue

        old_txt = dest.read_text(encoding="utf-8", errors="replace") if dest.is_file() else ""
        if rendered.strategy == "patch-managed-keys":
            existing_obj: dict[str, Any] = {}
            if old_txt.strip():
                try:
                    parsed = parse_by_format(old_txt, rendered.format)
                    if isinstance(parsed, dict):
                        existing_obj = parsed
                except FormatError:
                    existing_obj = {}
            patched = apply_managed_patch(
                existing_obj,
                rendered.patch_data or {},
                list(rendered.managed_keys or []),
                list(rendered.removed_keys or []),
            )
            new_txt = dump_by_format(patched, rendered.format)
        else:
            new_txt = (rendered.content or b"").decode("utf-8", errors="replace")

        changed = old_txt != new_txt
        udiff = ""
        if changed:
            udiff = "".join(
                difflib.unified_diff(
                    old_txt.splitlines(keepends=True),
                    new_txt.splitlines(keepends=True),
                    fromfile=f"live:{dest}",
                    tofile=f"rendered:{rendered.target_id}",
                )
            )
        diffs.append({"id": rendered.target_id, "path": str(dest), "changed": changed, "diff": udiff})

    return {
        "ok": True,
        "has_changes": any(d["changed"] for d in diffs),
        "changed_count": sum(1 for d in diffs if d["changed"]),
        "diffs": diffs,
    }


def restore_snapshot(
    ctx: RuntimeContext,
    snapshot_id: str | None = None,
    take_pre_snapshot: bool = True,
) -> dict[str, Any]:
    """Restore live targets from a named or latest snapshot."""
    snaps_root = ctx.state_dir / "snapshots"
    if not snaps_root.exists():
        raise RuntimeError(f"No snapshots directory found at {snaps_root}")

    if snapshot_id:
        snap_dir = snaps_root / snapshot_id
    else:
        candidates = sorted(d for d in snaps_root.iterdir() if d.is_dir() and (d / "snapshot.json").exists())
        if not candidates:
            raise RuntimeError(f"No snapshots found under {snaps_root}")
        snap_dir = candidates[-1]

    meta_file = snap_dir / "snapshot.json"
    if not meta_file.exists():
        raise RuntimeError(f"Snapshot metadata missing: {meta_file}")
    meta = parse_json(meta_file.read_text(encoding="utf-8"))

    if take_pre_snapshot:
        all_targets = load_targets_manifest(ctx.repo_root)
        active = [t for t in all_targets if t.get("enabled", True) and (t.get("scope", "global") != "project" or ctx.project_dir is not None)]
        create_snapshot(ctx, active, label="pre-restore")

    restored: list[str] = []
    removed: list[str] = []
    for rec in meta.get("targets", []):
        dest = Path(rec["path"])
        boundary = ctx.project_dir if (ctx.project_dir and dest.is_relative_to(ctx.project_dir)) else ctx.home_dir
        if not rec.get("existed"):
            if os.path.lexists(dest) and not os.path.islink(dest):
                if dest.is_dir():
                    shutil.rmtree(dest)
                else:
                    dest.unlink()
                removed.append(str(dest))
            continue

        if rec.get("is_dir"):
            dir_mode = int(str(rec.get("dir_mode", "0700")), 8)
            ensure_safe_dir(dest, mode=dir_mode, boundary_root=boundary)
            snap_rels = {f["rel"] for f in rec.get("files", [])}
            for p in sorted(dest.rglob("*"), reverse=True):
                if p.is_file() and p.relative_to(dest).as_posix() not in snap_rels:
                    p.unlink()
            for f in rec.get("files", []):
                fdest = dest / f["rel"]
                data = (snap_dir / f["snap_rel"]).read_bytes()
                atomic_write_bytes(fdest, data, mode=int(str(f["mode"]), 8), boundary_root=boundary)
            restored.append(str(dest))
        else:
            data = (snap_dir / rec["snap_rel"]).read_bytes()
            atomic_write_bytes(dest, data, mode=int(str(rec["mode"]), 8), boundary_root=boundary)
            restored.append(str(dest))

    manifest_dest = ctx.state_dir / "deployed-manifest.json"
    snap_manifest = snap_dir / "deployed-manifest.json"
    if meta.get("had_deployed_manifest") and snap_manifest.exists():
        atomic_write_bytes(manifest_dest, snap_manifest.read_bytes(), mode=0o600, boundary_root=ctx.state_dir)
    elif not meta.get("had_deployed_manifest") and manifest_dest.exists():
        manifest_dest.unlink()

    return {
        "ok": True,
        "snapshot_id": snap_dir.name,
        "restored": restored,
        "removed": removed,
    }
