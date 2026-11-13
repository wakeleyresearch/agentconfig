"""Scoped quarantine & repair engine with hard auth-preservation invariant."""

from __future__ import annotations

import errno
import fcntl
import os
import re
import shutil
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .formats import FormatError, dump_json, parse_by_format, parse_json
from .paths import (
    RuntimeContext,
    atomic_write_bytes,
    atomic_write_text,
    ensure_safe_dir,
    file_mode,
    sha256_bytes,
    sha256_file,
)
from .policy import (
    check_codex_config,
    check_hooks_config,
    check_mcp_config_object,
    load_security_policy,
    scan_invisible_unicode,
    scan_secrets,
)


PROTECTED_AUTH_REL_PATHS = (
    ".gemini/antigravity-cli/antigravity-oauth-token",
    ".gemini/oauth_creds.json",
    ".gemini/google_accounts.json",
    ".config/gh/hosts.yml",
    ".claude/.credentials.json",
    ".codex/auth.json",
    ".kimi-code/credentials",
    ".grok/auth.json",
    ".grok/mcp_credentials.json",
    ".local/share/opencode/auth.json",
    ".local/share/keyrings",
    ".config/Claude-3p/ccd-session-secrets",
    ".config/Claude-3p/plugin-mcp-auth",
)

PROTECTED_AUTH_BASENAMES = frozenset(
    {
        "antigravity-oauth-token",
        "oauth_creds.json",
        "google_accounts.json",
        ".credentials.json",
        "hosts.yml",
        "mcp_credentials.json",
    }
)

MEMORY_POISON_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"(?:curl|wget|nc|ncat)\s+[^\n]*(?:https?://|\|)", re.IGNORECASE),
    re.compile(r"(?:\.ssh/id_|antigravity-oauth-token|hosts\.yml|\.credentials\.json|auth\.json)", re.IGNORECASE),
    re.compile(r"/dev/tcp/", re.IGNORECASE),
    re.compile(r"exfiltrat", re.IGNORECASE),
]

CONFIG_SCAN_ROOTS = (
    ".gemini/config",
    ".gemini/antigravity-cli",
    ".gemini",
    ".claude",
    ".codex",
    ".copilot",
    ".kimi-code",
    ".grok",
    ".config/opencode",
    ".local/share/opencode",
    ".config/devin",
    ".config/goose",
    ".cursor",
    ".cline",
    ".kilocode",
    ".config/kilocode",
    ".continue",
    ".factory",
    ".droid",
    ".config/droid",
    ".litert-lm",
    ".config/litert-lm",
    ".ollama",
    ".config/ollama",
)

HARNESS_CONFIG_ROOTS: dict[str, tuple[str, ...]] = {
    "antigravity": (".gemini/config", ".gemini/antigravity-cli", ".agents"),
    "gemini-cli": (".gemini",),
    "claude-code": (".claude", ".claude.json"),
    "codex": (".codex",),
    "opencode": (".config/opencode", ".local/share/opencode"),
    "kilo": (".kilocode", ".config/kilocode"),
    "cline": (".cline",),
    "goose": (".config/goose",),
    "aider": (".aider.conf.yml", ".aider"),
    "continue": (".continue",),
    "cursor": (".cursor",),
    "copilot-cli": (".copilot", ".config/Code/User/mcp.json", ".config/github-copilot"),
    "droid": (".factory", ".droid", ".config/droid"),
    "litert-lm": (".litert-lm", ".config/litert-lm"),
    "ollama": (".ollama", ".config/ollama"),
    "kimi-code": (".kimi-code",),
    "grok": (".grok",),
    "devin": (".config/devin",),
}

HARNESS_RUNTIME_ROOTS: dict[str, tuple[str, ...]] = {
    "antigravity": (".gemini/antigravity-cli", ".gemini/config", ".cache/antigravity"),
    "gemini-cli": (".gemini",),
    "claude-code": (".claude",),
    "codex": (".codex",),
    "opencode": (".config/opencode", ".local/share/opencode", ".cache/opencode"),
    "kilo": (".kilocode", ".config/kilocode"),
    "cline": (".cline",),
    "goose": (".config/goose", ".local/share/goose"),
    "aider": (".aider",),
    "continue": (".continue",),
    "cursor": (".cursor",),
    "copilot-cli": (".copilot", ".config/github-copilot"),
    "droid": (".factory", ".droid", ".config/droid"),
    "litert-lm": (".litert-lm", ".cache/litert-lm"),
    "ollama": (".ollama",),
    "kimi-code": (".kimi-code",),
    "grok": (".grok",),
    "devin": (".config/devin",),
}

HARNESS_MEMORY_ROOTS: dict[str, tuple[str, ...]] = {
    "antigravity": (".gemini/antigravity-cli/annotations", ".gemini/antigravity-cli/implicit"),
    "gemini-cli": (".gemini/GEMINI.md", ".gemini/memories"),
    "claude-code": (".claude/projects", ".claude/memory"),
    "codex": (".codex/memories", ".codex/memories_v2"),
    "opencode": (".config/opencode/memory", ".local/share/opencode/memory"),
    "kilo": (".kilocode/memory", ".kilocode/memory-bank"),
    "cline": (".cline/memory-bank", ".cline/memory"),
    "goose": (".config/goose/memory",),
    "aider": (".aider/memory",),
    "continue": (".continue/memory",),
    "cursor": (".cursor/memory",),
    "copilot-cli": (".copilot/memory",),
    "droid": (".factory/memory", ".droid/memory"),
    "litert-lm": (".litert-lm",),
    "ollama": (".ollama",),
    "kimi-code": (".kimi-code/memory",),
    "grok": (".grok/memory",),
    "devin": (".config/devin/memory",),
}

_CLEANSE_HARNESS_ALIASES: dict[str, str] = {
    "agy": "antigravity",
    "gemini": "gemini-cli",
    "claude": "claude-code",
    "copilot": "copilot-cli",
    "vscode": "copilot-cli",
    "vscode-copilot": "copilot-cli",
    "jetbrains": "copilot-cli",
    "jetbrains-copilot": "copilot-cli",
    "kimi": "kimi-code",
    "kilocode": "kilo",
    "factory": "droid",
    "xai-grok": "grok",
    "grok-build": "grok",
    "grok-vibekit": "grok",
}


def resolve_cleanse_harnesses(
    harnesses: set[str] | list[str] | tuple[str, ...] | None,
) -> set[str] | None:
    """Normalize optional harness names to HARNESS_*_ROOTS keys."""
    if not harnesses:
        return None
    resolved: set[str] = set()
    for raw in harnesses:
        for part in str(raw).split(","):
            h = part.strip().lower()
            if not h:
                continue
            if h == "all":
                return None
            mapped = _CLEANSE_HARNESS_ALIASES.get(h, h)
            if mapped not in HARNESS_CONFIG_ROOTS:
                raise ValueError(
                    f"Unknown cleanse harness {raw!r}; choose from {sorted(HARNESS_CONFIG_ROOTS)}"
                )
            resolved.add(mapped)
    return resolved or None

CONFIG_EXT_TO_FMT = {
    ".json": "json",
    ".jsonc": "jsonc",
    ".toml": "toml",
    ".yaml": "yaml",
    ".yml": "yaml",
}

SENSITIVE_CONFIG_NAMES = frozenset(
    {
        "settings.json",
        "config.json",
        "mcp_config.json",
        "mcp-config.json",
        "mcp.json",
        "cli-config.json",
        "cline_mcp_settings.json",
        "user-settings.json",
        "opencode.jsonc",
        "config.toml",
        "failsafe.config.toml",
        "config.yaml",
        ".claude.json",
        ".aider.conf.yml",
    }
)

CLOUD_MEMORY_REMINDERS = [
    "Cloud memory note: disabling local capture does NOT delete server-side facts.",
    "  - GitHub Copilot Memory: purge at github.com -> Profile/Repo -> Copilot -> Memory",
    "  - ChatGPT Memory: purge at Settings -> Personalization -> Memory",
    "  - Claude.ai Memory: purge at Settings -> Capabilities -> Memory",
]


def is_auth_path(
    path: Path,
    home_dir: Path,
    policy: dict[str, Any] | None = None,
) -> bool:
    """Return True if path is a protected Tier-B auth/credential file or inside a protected auth dir."""
    abs_p = Path(os.path.abspath(path))
    abs_home = Path(os.path.abspath(home_dir))

    if path.name in PROTECTED_AUTH_BASENAMES:
        return True

    protected_rels = list(PROTECTED_AUTH_REL_PATHS)
    if policy:
        for raw in policy.get("auth_preservation_paths", []):
            if isinstance(raw, str) and raw.startswith("~/"):
                protected_rels.append(raw[2:])

    for rel in protected_rels:
        prot = Path(os.path.abspath(abs_home / rel))
        if abs_p == prot:
            return True
        try:
            abs_p.relative_to(prot)
            return True
        except ValueError:
            pass
    return False


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _open_fd_targets_map() -> dict[tuple[int, int], int]:
    """Map (st_dev, st_ino) -> pid for all readable /proc/<pid>/fd/* descriptors."""
    targets: dict[tuple[int, int], int] = {}
    proc_root = Path("/proc")
    if not proc_root.exists():
        return targets
    for pid_dir in proc_root.iterdir():
        if not pid_dir.name.isdigit():
            continue
        pid = int(pid_dir.name)
        fd_dir = pid_dir / "fd"
        try:
            for fd_link in fd_dir.iterdir():
                try:
                    st = os.stat(fd_link)
                    targets[(st.st_dev, st.st_ino)] = pid
                except OSError:
                    continue
        except OSError:
            continue
    return targets


def is_lock_live(lock_path: Path, open_fds: dict[tuple[int, int], int] | None = None) -> tuple[bool, str]:
    """Check flock, /proc/<pid>/fd, and PID contents before touching a lock file."""
    try:
        st = os.lstat(lock_path)
    except OSError:
        return False, "missing"

    if stat.S_ISLNK(st.st_mode):
        # Chromium/Electron SingletonLock encodes <hostname>-<pid>.
        try:
            target = os.readlink(lock_path)
            if "-" in target:
                maybe_pid = target.rsplit("-", 1)[-1]
                if maybe_pid.isdigit() and Path(f"/proc/{maybe_pid}").exists():
                    return True, f"live SingletonLock pid {maybe_pid}"
        except OSError:
            pass
        return False, "stale symlink lock"

    if not stat.S_ISREG(st.st_mode):
        return False, "non-regular lock"

    # 1. Try non-blocking flock(LOCK_EX | LOCK_NB) without truncating or modifying.
    fd = None
    try:
        fd = os.open(lock_path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        except BlockingIOError:
            return True, "active flock"
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                return True, "active flock"
    except OSError:
        pass
    finally:
        if fd is not None:
            os.close(fd)

    # 2. Check /proc/<pid>/fd open descriptors matching (st_dev, st_ino).
    fd_map = open_fds if open_fds is not None else _open_fd_targets_map()
    key = (st.st_dev, st.st_ino)
    if key in fd_map:
        return True, f"held open by pid {fd_map[key]}"

    # 3. Check PID text or JSON inside lockfile.
    try:
        raw = lock_path.read_text(encoding="utf-8", errors="ignore").strip()
        if raw:
            pid_val: int | None = None
            if raw.isdigit():
                pid_val = int(raw)
            elif raw.startswith("{"):
                obj = parse_json(raw)
                if isinstance(obj, dict) and isinstance(obj.get("pid"), int):
                    pid_val = obj["pid"]
            if pid_val is not None and pid_val > 0 and Path(f"/proc/{pid_val}").exists():
                return True, f"live pid {pid_val} in lockfile"
    except (OSError, FormatError):
        pass

    return False, "stale lock (no active flock or live pid)"


def check_sqlite_readonly(db_path: Path) -> tuple[bool, str]:
    """Run read-only PRAGMA quick_check on SQLite database."""
    if not db_path.is_file() or db_path.is_symlink():
        return True, "skip non-regular"
    if db_path.stat().st_size == 0:
        return False, "0-byte corrupt sqlite file"

    uri = f"file:{db_path.as_posix()}?mode=ro"
    conn = None
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=0.5)
        rows = conn.execute("PRAGMA quick_check;").fetchall()
        if rows == [("ok",)]:
            return True, "ok"
        return False, f"PRAGMA quick_check failed: {rows}"
    except sqlite3.DatabaseError as exc:
        # Retry immutable=1 read-only in case WAL directory is unsearchable/corrupt.
        if conn is not None:
            conn.close()
            conn = None
        try:
            imm_uri = f"file:{db_path.as_posix()}?mode=ro&immutable=1"
            conn = sqlite3.connect(imm_uri, uri=True, timeout=0.5)
            rows = conn.execute("PRAGMA quick_check;").fetchall()
            if rows == [("ok",)]:
                return True, "ok (immutable check)"
            return False, f"PRAGMA quick_check failed: {rows}"
        except sqlite3.DatabaseError as exc2:
            return False, f"SQLite read-only check error: {exc2 or exc}"
    finally:
        if conn is not None:
            conn.close()


class QuarantineSession:
    """Tracks and executes safe, non-executable quarantine moves."""

    def __init__(
        self,
        ctx: RuntimeContext,
        scope: str,
        policy: dict[str, Any],
        dry_run: bool = False,
        include_auth: bool = False,
        confirm_wipe_auth: bool = False,
    ) -> None:
        self.ctx = ctx
        self.scope = scope
        self.policy = policy
        self.dry_run = dry_run
        self.allow_auth_wipe = bool(include_auth and confirm_wipe_auth)
        self.timestamp = _utc_stamp()
        self.quarantine_dir = ctx.state_dir / "quarantine" / self.timestamp
        self.entries: list[dict[str, Any]] = []
        self.preserved: list[dict[str, str]] = []
        self.quarantined_paths: list[Path] = []
        self.warnings: list[str] = []

    def _dest_for(self, src: Path) -> Path:
        abs_src = Path(os.path.abspath(src))
        abs_home = Path(os.path.abspath(self.ctx.home_dir))
        try:
            rel = abs_src.relative_to(abs_home)
            return self.quarantine_dir / "home" / rel
        except ValueError:
            return self.quarantine_dir / "external" / abs_src.relative_to(abs_src.anchor)

    def quarantine_file(self, src: Path, item_scope: str, reason: str) -> bool:
        """Quarantine src unless protected by auth-preservation invariant."""
        if is_auth_path(src, self.ctx.home_dir, self.policy) and not self.allow_auth_wipe:
            self.preserved.append({"path": str(src), "reason": "auth-preservation invariant"})
            return False

        if not os.path.lexists(src):
            return False

        st = os.lstat(src)
        orig_mode = stat.S_IMODE(st.st_mode)
        is_symlink = stat.S_ISLNK(st.st_mode)
        digest = ""
        if not is_symlink and stat.S_ISREG(st.st_mode):
            try:
                digest = sha256_file(src)
            except OSError:
                digest = ""

        # Strip all execute/group/other bits (preserve at most 0600, or 0400 if owner write was off).
        new_mode = orig_mode & 0o600
        if new_mode == 0:
            new_mode = 0o400
        dest = self._dest_for(src)

        entry = {
            "original_path": str(src),
            "quarantine_path": str(dest),
            "sha256": digest,
            "orig_mode": f"{orig_mode:04o}",
            "new_mode": f"{new_mode:04o}",
            "scope": item_scope,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "was_symlink": is_symlink,
        }
        self.entries.append(entry)
        self.quarantined_paths.append(src)

        if self.dry_run:
            return True

        ensure_safe_dir(self.quarantine_dir, mode=0o700, boundary_root=self.ctx.state_dir)
        ensure_safe_dir(dest.parent, mode=0o700, boundary_root=self.ctx.state_dir)

        if is_symlink:
            link_target = os.readlink(src)
            atomic_write_text(
                Path(str(dest) + ".symlink.txt"),
                f"broken_symlink -> {link_target}\n",
                mode=0o400,
                boundary_root=self.quarantine_dir,
            )
            os.unlink(src)
        else:
            shutil.move(str(src), str(dest))
            os.chmod(dest, new_mode)
        return True

    def quarantine_snippet(
        self,
        src: Path,
        snippet_name: str,
        payload: bytes,
        item_scope: str,
        reason: str,
    ) -> None:
        """Store an excised poisoned snippet inside quarantine without removing the whole file."""
        dest = self._dest_for(src).with_name(snippet_name)
        entry = {
            "original_path": str(src),
            "quarantine_path": str(dest),
            "sha256": sha256_bytes(payload),
            "orig_mode": f"{file_mode(src):04o}" if src.exists() else "0600",
            "new_mode": "0400",
            "scope": item_scope,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "partial_excision": True,
        }
        self.entries.append(entry)
        if not self.dry_run:
            ensure_safe_dir(self.quarantine_dir, mode=0o700, boundary_root=self.ctx.state_dir)
            atomic_write_bytes(dest, payload, mode=0o400, boundary_root=self.quarantine_dir)

    def finalize(self) -> Path | None:
        """Write quarantine-manifest.json if any quarantine actions occurred."""
        if self.dry_run or not self.entries:
            return None
        ensure_safe_dir(self.quarantine_dir, mode=0o700, boundary_root=self.ctx.state_dir)
        manifest_path = self.quarantine_dir / "quarantine-manifest.json"
        combined_entries = list(self.entries)
        if manifest_path.exists():
            try:
                prev_doc = parse_json(manifest_path.read_text(encoding="utf-8"))
                if isinstance(prev_doc, dict) and isinstance(prev_doc.get("entries"), list):
                    combined_entries = list(prev_doc["entries"]) + combined_entries
            except (FormatError, OSError):
                pass
        manifest = {
            "schema_version": "1.0",
            "scope": self.scope,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "entries": combined_entries,
        }
        atomic_write_text(
            manifest_path,
            dump_json(manifest),
            mode=0o600,
            boundary_root=self.quarantine_dir,
        )
        return manifest_path


def _load_deployed_ro_set(ctx: RuntimeContext) -> set[str]:
    mp = ctx.state_dir / "deployed-manifest.json"
    if not mp.exists():
        return set()
    try:
        doc = parse_json(mp.read_text(encoding="utf-8"))
        out: set[str] = set()
        for t in doc.get("targets", {}).values():
            if isinstance(t, dict) and t.get("strategy") in ("ro", "plugin-bundle") and t.get("path"):
                out.add(str(t["path"]))
        return out
    except (FormatError, OSError):
        return set()


def _infer_harness(p: Path) -> str:
    s = str(p).lower()
    for h in (
        "antigravity",
        "litert-lm",
        "ollama",
        "gemini",
        "claude",
        "codex",
        "copilot",
        "kimi",
        "grok",
        "opencode",
        "kilo",
        "cursor",
        "devin",
        "cline",
        "goose",
        "aider",
        "continue",
        "droid",
        "factory",
    ):
        if h in s:
            return "droid" if h == "factory" else h
    return "generic"


def _is_modelfile(p: Path) -> bool:
    name_low = p.name.lower()
    return name_low == "modelfile" or name_low.startswith("modelfile.") or name_low.endswith(".modelfile")


def _check_symlink_escape_or_broken(
    p: Path,
    home_real: Path,
    session: QuarantineSession,
    item_scope: str,
    is_dir_hint: bool = False,
) -> bool:
    """Return True if path is a symlink; quarantine broken symlinks or symlinks escaping HOME."""
    if not (os.path.lexists(p) and p.is_symlink()):
        return False
    if not p.exists():
        reason = "broken symlink directory" if is_dir_hint else "broken symlink"
        session.quarantine_file(p, item_scope, reason)
        return True
    try:
        resolved = p.resolve()
        if not resolved.is_relative_to(home_real):
            session.quarantine_file(p, item_scope, f"symlink escape outside HOME -> {resolved}")
    except OSError:
        session.quarantine_file(p, item_scope, "unresolvable symlink")
    return True


def _config_roots_for_harnesses(harnesses: set[str] | None) -> tuple[list[str], list[str]]:
    if harnesses is None:
        return list(CONFIG_SCAN_ROOTS), [".claude.json", ".aider.conf.yml"]
    dir_roots: list[str] = []
    single_files: list[str] = []
    for h in sorted(harnesses):
        for rel in HARNESS_CONFIG_ROOTS.get(h, ()):
            if rel in (".claude.json", ".aider.conf.yml") or rel.endswith((".json", ".jsonc", ".toml", ".yaml", ".yml")):
                if rel not in single_files:
                    single_files.append(rel)
            else:
                if rel not in dir_roots:
                    dir_roots.append(rel)
    return dir_roots, single_files


def _runtime_roots_for_harnesses(harnesses: set[str] | None) -> list[str]:
    if harnesses is None:
        roots = list(CONFIG_SCAN_ROOTS)
        if ".cache/antigravity" not in roots:
            roots.append(".cache/antigravity")
        return roots
    roots = []
    for h in sorted(harnesses):
        for rel in HARNESS_RUNTIME_ROOTS.get(h, ()):
            if rel not in roots:
                roots.append(rel)
    return roots


def _cleanse_config(
    ctx: RuntimeContext,
    session: QuarantineSession,
    policy: dict[str, Any],
    harnesses: set[str] | None = None,
) -> None:
    ro_paths = _load_deployed_ro_set(ctx)
    home_real = ctx.home_dir.resolve()
    dir_roots, single_files = _config_roots_for_harnesses(harnesses)
    skip_agy_in_gemini = harnesses is not None and "gemini-cli" in harnesses and "antigravity" not in harnesses

    candidates: list[Path] = []
    for rel_root in dir_roots:
        root = ctx.home_dir / rel_root
        if os.path.lexists(root) and root.is_symlink() and not root.exists():
            session.quarantine_file(root, "config", "broken symlink directory")
            continue
        if not root.exists() or root.is_symlink():
            continue
        if root.is_file():
            candidates.append(root)
            continue
        for cur, dirs, files in os.walk(root, followlinks=False):
            cur_p = Path(cur)
            excluded = {".git", "node_modules", "conversations", "brain", "cache", "log", "logs", "crashes", "sessions", "worktrees"}
            if skip_agy_in_gemini and cur_p == (ctx.home_dir / ".gemini"):
                excluded.update({"antigravity-cli", "config"})
            dirs[:] = sorted(d for d in dirs if d not in excluded)
            for d in list(dirs):
                dp = cur_p / d
                if _check_symlink_escape_or_broken(dp, home_real, session, "config", is_dir_hint=True):
                    dirs.remove(d)
            for fn in sorted(files):
                candidates.append(cur_p / fn)

    for single in single_files:
        sp = ctx.home_dir / single
        if os.path.lexists(sp):
            candidates.append(sp)

    seen: set[Path] = set()
    for p in candidates:
        if p in seen:
            continue
        seen.add(p)
        if is_auth_path(p, ctx.home_dir, policy):
            session.preserved.append({"path": str(p), "reason": "auth-preservation invariant"})
            continue
        if os.path.lexists(p) and p.is_symlink():
            if not p.exists():
                session.quarantine_file(p, "config", "broken symlink")
            elif p.suffix.lower() not in (".md", ".mdc"):
                _check_symlink_escape_or_broken(p, home_real, session, "config")
            continue
        if not p.is_file():
            continue

        if p.suffix.lower() in (".pkl", ".pickle"):
            session.quarantine_file(p, "config", "unverified pickle file")
            continue

        st = os.lstat(p)
        mode = stat.S_IMODE(st.st_mode)
        abs_p = str(p)
        res_p = str(p.resolve())
        is_ro_target = any(
            abs_p == rp or res_p == rp or abs_p.startswith(rp.rstrip("/") + "/") or res_p.startswith(rp.rstrip("/") + "/")
            for rp in ro_paths
        )
        if not is_ro_target:
            if (mode & 0o002) != 0:
                session.quarantine_file(p, "config", f"world-writable unsafe mode {mode:04o}")
                continue

        if _is_modelfile(p):
            if not is_ro_target and (mode & 0o022) != 0:
                session.warnings.append(f"{p}: permissive mode {mode:04o} -> 0600")
                if not session.dry_run:
                    os.chmod(p, 0o600)
            try:
                mf_text = p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                session.quarantine_file(p, "config", "invalid UTF-8 in Modelfile")
                continue
            if scan_invisible_unicode(mf_text, str(p), policy):
                session.quarantine_file(p, "config", "invisible Unicode injection in Modelfile")
                continue
            mf_poison = _line_is_poisoned(mf_text, policy)
            if mf_poison:
                session.quarantine_file(p, "config", f"poisoned Modelfile SYSTEM directive ({mf_poison})")
                continue
            mf_secrets = [f for f in scan_secrets(mf_text, str(p), policy) if f.severity == "error"]
            if mf_secrets:
                session.quarantine_file(p, "config", f"secret in Modelfile: {mf_secrets[0].code}")
            continue

        fmt = CONFIG_EXT_TO_FMT.get(p.suffix.lower())
        if not fmt:
            continue

        if not is_ro_target:
            if (mode & 0o022) != 0 or (p.name in SENSITIVE_CONFIG_NAMES and (mode & 0o077) != 0):
                session.warnings.append(f"{p}: permissive mode {mode:04o} -> 0600")
                if not session.dry_run:
                    os.chmod(p, 0o600)

        if st.st_size == 0:
            continue

        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            session.quarantine_file(p, "config", "invalid UTF-8 in config file")
            continue

        if scan_invisible_unicode(text, str(p), policy):
            session.quarantine_file(p, "config", "invisible Unicode injection in config")
            continue

        try:
            parsed = parse_by_format(text, fmt)
        except FormatError as exc:
            session.quarantine_file(p, "config", f"syntax error: {exc}")
            continue

        harness = _infer_harness(p)
        findings = []
        if isinstance(parsed, dict):
            if harness == "codex" and p.suffix.lower() == ".toml":
                findings.extend(check_codex_config(parsed, policy, str(p)))
            else:
                findings.extend(check_mcp_config_object(parsed, harness, policy, str(p)))
            if "hook" in p.name.lower() or "hooks" in parsed or "notify" in parsed:
                findings.extend(check_hooks_config(parsed, policy, str(p)))
                hook_blob = dump_json({"hooks": parsed.get("hooks"), "notify": parsed.get("notify")})
                hook_poison = _line_is_poisoned(hook_blob, policy)
                if hook_poison:
                    session.quarantine_file(p, "config", f"rogue hook directive ({hook_poison})")
                    continue
        findings.extend(scan_secrets(text, str(p), policy))
        errs = [f for f in findings if f.severity == "error"]
        if errs:
            session.quarantine_file(p, "config", f"policy violation: {errs[0].code} ({errs[0].message})")


def _cleanse_runtime(
    ctx: RuntimeContext,
    session: QuarantineSession,
    policy: dict[str, Any],
    harnesses: set[str] | None = None,
) -> None:
    open_fds = _open_fd_targets_map()
    home_real = ctx.home_dir.resolve()
    sqlite_targets: list[Path] = []
    wal_shm_files: list[Path] = []
    skip_agy_in_gemini = harnesses is not None and "gemini-cli" in harnesses and "antigravity" not in harnesses

    search_roots = [ctx.home_dir / r for r in _runtime_roots_for_harnesses(harnesses)]

    seen_files: set[Path] = set()
    for root in search_roots:
        if not root.exists() or root.is_symlink():
            continue
        for cur, dirs, files in os.walk(root, followlinks=False):
            cur_p = Path(cur)
            excluded = {".git", "node_modules"}
            if skip_agy_in_gemini and cur_p == (ctx.home_dir / ".gemini"):
                excluded.update({"antigravity-cli", "config"})
            dirs[:] = sorted(d for d in dirs if d not in excluded)
            for d in list(dirs):
                dp = cur_p / d
                if _check_symlink_escape_or_broken(dp, home_real, session, "runtime", is_dir_hint=True):
                    dirs.remove(d)
            for fn in sorted(files):
                fp = cur_p / fn
                if fp in seen_files:
                    continue
                seen_files.add(fp)
                if is_auth_path(fp, ctx.home_dir, policy):
                    continue

                if fn.endswith(".lock") or fn == "SingletonLock":
                    live, why = is_lock_live(fp, open_fds=open_fds)
                    if live:
                        session.preserved.append({"path": str(fp), "reason": why})
                    else:
                        session.quarantine_file(fp, "runtime", why)
                    continue

                if _check_symlink_escape_or_broken(fp, home_real, session, "runtime"):
                    continue

                if fn.endswith((".pkl", ".pickle")):
                    session.quarantine_file(fp, "runtime", "unverified pickle file")
                    continue

                try:
                    st_mode = stat.S_IMODE(os.lstat(fp).st_mode)
                    if (st_mode & 0o002) != 0:
                        session.quarantine_file(fp, "runtime", f"world-writable runtime file/blob {st_mode:04o}")
                        continue
                except OSError:
                    continue

                if fn.endswith(".tmp") and not fn.startswith(".agentcfg."):
                    session.quarantine_file(fp, "runtime", "orphaned .tmp artifact")
                    continue

                if "staging" in fp.parts and fp.is_file():
                    session.quarantine_file(fp, "runtime", "stale staging cache file")
                    continue

                if fn.endswith((".db", ".sqlite")):
                    sqlite_targets.append(fp)
                elif fn.endswith(("-wal", "-shm")):
                    wal_shm_files.append(fp)

    # Check OPENCODE_DB if configured inside home_dir and opencode is in scope.
    if harnesses is None or "opencode" in harnesses:
        opencode_db = os.environ.get("OPENCODE_DB")
        if opencode_db and opencode_db != ":memory:":
            odb = Path(opencode_db)
            if odb.exists() and odb not in seen_files:
                sqlite_targets.append(odb)

    corrupt_dbs: set[Path] = set()
    for db in sqlite_targets:
        try:
            st = os.lstat(db)
            if (st.st_dev, st.st_ino) in open_fds:
                session.preserved.append({"path": str(db), "reason": f"SQLite DB open by pid {open_fds[(st.st_dev, st.st_ino)]}"})
                continue
        except OSError:
            continue

        healthy, detail = check_sqlite_readonly(db)
        if not healthy:
            corrupt_dbs.add(db)
            session.quarantine_file(db, "runtime", detail)
            for sfx in ("-wal", "-shm"):
                companion = Path(str(db) + sfx)
                if os.path.lexists(companion):
                    session.quarantine_file(companion, "runtime", f"WAL/SHM companion of corrupt {db.name}")

    # Quarantine orphaned -wal/-shm whose parent DB does not exist.
    for wfile in wal_shm_files:
        base_str = str(wfile)[:-4]
        base_db = Path(base_str)
        if base_db in corrupt_dbs:
            continue
        if not os.path.lexists(base_db):
            session.quarantine_file(wfile, "runtime", "orphaned WAL/SHM without base SQLite DB")


def _snapshot_memory_files(
    ctx: RuntimeContext,
    files: list[Path],
) -> Path | None:
    if not files:
        return None
    snap_dir = ctx.state_dir / "memory-snapshots" / _utc_stamp()
    ensure_safe_dir(snap_dir, mode=0o700, boundary_root=ctx.state_dir)
    abs_home = Path(os.path.abspath(ctx.home_dir))
    manifest_entries: list[dict[str, str]] = []
    for f in files:
        if not f.is_file() or f.is_symlink():
            continue
        try:
            rel = Path(os.path.abspath(f)).relative_to(abs_home)
        except ValueError:
            rel = Path(f.name)
        dest = snap_dir / rel
        data = f.read_bytes()
        atomic_write_bytes(dest, data, mode=0o600, boundary_root=snap_dir)
        manifest_entries.append({"path": str(f), "snapshot": str(dest), "sha256": sha256_bytes(data)})
    atomic_write_text(
        snap_dir / "manifest.json",
        dump_json({"created_at": datetime.now(timezone.utc).isoformat(), "files": manifest_entries}),
        mode=0o600,
        boundary_root=snap_dir,
    )
    return snap_dir


def _latest_memory_snapshot_sizes(ctx: RuntimeContext) -> dict[str, int]:
    base = ctx.state_dir / "memory-snapshots"
    if not base.exists():
        return {}
    snaps = sorted(d for d in base.iterdir() if d.is_dir())
    if not snaps:
        return {}
    latest = snaps[-1]
    sizes: dict[str, int] = {}
    for p in latest.rglob("*"):
        if p.is_file() and p.name != "manifest.json":
            sizes[str(p.relative_to(latest))] = p.stat().st_size
    return sizes


def _line_is_poisoned(line: str, policy: dict[str, Any]) -> str | None:
    if scan_invisible_unicode(line, "<memory>", policy):
        return "invisible Unicode character"
    for pat in MEMORY_POISON_PATTERNS:
        if pat.search(line):
            return f"poison directive matching {pat.pattern!r}"
    return None


_HARNESS_MEMORY_GLOBS: dict[str, tuple[str, ...]] = {
    "antigravity": (
        ".gemini/antigravity-cli/annotations/*.pbtxt",
        ".gemini/antigravity-cli/implicit/*.pb",
    ),
    "gemini-cli": (
        ".gemini/memories/**/*.md",
    ),
    "claude-code": (
        ".claude/projects/*/memory/*.md",
        ".claude/memory/**/*.md",
    ),
    "codex": (
        ".codex/memories/**/*.md",
        ".codex/memories_v2/**/*.md",
        ".codex/memories/extensions/skysight/**/*",
    ),
    "opencode": (
        ".config/opencode/memory/**/*",
        ".local/share/opencode/memory/**/*",
    ),
    "kilo": (
        ".kilocode/memory/**/*",
        ".kilocode/memory-bank/**/*",
    ),
    "cline": (
        ".cline/memory-bank/*.md",
        ".cline/memory/**/*.md",
    ),
    "goose": (
        ".config/goose/memory/**/*",
    ),
    "aider": (
        ".aider/memory/**/*",
    ),
    "continue": (
        ".continue/memory/**/*",
    ),
    "cursor": (
        ".cursor/memory/**/*",
    ),
    "copilot-cli": (
        ".copilot/memory/**/*",
    ),
    "droid": (
        ".factory/memory/**/*",
        ".droid/memory/**/*",
    ),
    "litert-lm": (
        ".litert-lm/**/Modelfile*",
        ".litert-lm/**/*.modelfile",
    ),
    "ollama": (
        ".ollama/**/Modelfile*",
        ".ollama/**/*.modelfile",
    ),
    "kimi-code": (
        ".kimi-code/memory/**/*",
    ),
    "grok": (
        ".grok/memory/**/*",
    ),
    "devin": (
        ".config/devin/memory/**/*",
    ),
}


def _cleanse_memory(
    ctx: RuntimeContext,
    session: QuarantineSession,
    policy: dict[str, Any],
    native_wipe: bool = False,
    harnesses: set[str] | None = None,
) -> None:
    memory_files: list[Path] = []
    gemini_md = ctx.home_dir / ".gemini" / "GEMINI.md"
    if (harnesses is None or "gemini-cli" in harnesses) and gemini_md.is_file() and not gemini_md.is_symlink():
        memory_files.append(gemini_md)

    active_harnesses = sorted(HARNESS_MEMORY_ROOTS.keys()) if harnesses is None else sorted(harnesses)
    for h in active_harnesses:
        for pat in _HARNESS_MEMORY_GLOBS.get(h, ()):
            for p in sorted(ctx.home_dir.glob(pat)):
                if p.is_file() and not p.is_symlink() and not is_auth_path(p, ctx.home_dir, policy):
                    memory_files.append(p)

    # Deduplicate while preserving order.
    deduped: list[Path] = []
    seen: set[Path] = set()
    for f in memory_files:
        if f not in seen and f.exists():
            seen.add(f)
            deduped.append(f)

    prev_sizes = _latest_memory_snapshot_sizes(ctx)
    if not session.dry_run and deduped:
        _snapshot_memory_files(ctx, deduped)

    for f in deduped:
        try:
            raw = f.read_bytes()
        except OSError:
            continue

        # Check anomalous growth vs previous baseline (>3x and >16 KB).
        try:
            rel_key = str(Path(os.path.abspath(f)).relative_to(Path(os.path.abspath(ctx.home_dir))))
            prev_sz = prev_sizes.get(rel_key)
            if prev_sz is not None and prev_sz > 0 and len(raw) > max(16384, prev_sz * 3):
                session.warnings.append(f"Anomalous memory size spike on {rel_key}: {prev_sz} -> {len(raw)} bytes")
        except ValueError:
            pass

        if f.suffix == ".pb":
            # Binary proto implicit memory: flag only if corrupted/poisoned or explicitly anomalous.
            continue

        text = raw.decode("utf-8", errors="replace")

        if f == gemini_md:
            # Selectively quarantine poisoned lines (especially under ## Gemini Added Memories).
            lines = text.splitlines(keepends=True)
            clean_lines: list[str] = []
            poisoned_lines: list[str] = []
            reasons: list[str] = []
            for ln in lines:
                why = _line_is_poisoned(ln, policy)
                if why:
                    poisoned_lines.append(ln)
                    reasons.append(why)
                else:
                    clean_lines.append(ln)
            if poisoned_lines:
                excised = "".join(poisoned_lines).encode("utf-8")
                session.quarantine_snippet(
                    f,
                    "GEMINI.md.poisoned-entries.md",
                    excised,
                    "memory",
                    f"poisoned GEMINI.md memory entries ({reasons[0]})",
                )
                if not session.dry_run:
                    atomic_write_text(f, "".join(clean_lines), mode=0o600, boundary_root=ctx.home_dir)
            continue

        # Whole-file check for dedicated auto-memory files and Modelfiles.
        poison_reason = _line_is_poisoned(text, policy)
        if poison_reason:
            label = "poisoned Modelfile SYSTEM directive" if _is_modelfile(f) else "poisoned memory file"
            session.quarantine_file(f, "memory", f"{label} ({poison_reason})")

    if native_wipe and not session.dry_run:
        import subprocess

        wipe_cmds: list[tuple[str, list[str]]] = [
            ("codex", ["codex", "debug", "clear-memories"]),
            ("grok", ["grok", "memory", "clear", "--all"]),
        ]
        for h_name, cmd_argv in wipe_cmds:
            if harnesses is not None and h_name not in harnesses:
                continue
            exe = shutil.which(cmd_argv[0])
            if exe:
                subprocess.run([exe, *cmd_argv[1:]], check=False, capture_output=True, text=True)

    session.warnings.extend(CLOUD_MEMORY_REMINDERS)


def run_cleanse(
    ctx: RuntimeContext,
    scope: str = "all",
    apply: bool = False,
    harnesses: set[str] | list[str] | tuple[str, ...] | None = None,
    dry_run: bool | None = None,
    auto_quarantine: bool = True,
    include_auth: bool = False,
    confirm_wipe_auth: bool = False,
    restore_targets: bool = True,
    native_wipe: bool = False,
) -> dict[str, Any]:
    """Run cleanse across config, memory, runtime, or all scopes (optionally scoped to harnesses)."""
    valid_scopes = {"config", "memory", "runtime", "all"}
    if scope not in valid_scopes:
        raise ValueError(f"Unsupported cleanse scope {scope!r}; choose from {sorted(valid_scopes)}")

    if include_auth and not confirm_wipe_auth:
        raise ValueError("--include-auth requires explicit --confirm-wipe-auth")

    norm_harnesses = resolve_cleanse_harnesses(harnesses)
    policy = load_security_policy(ctx.repo_root)
    if dry_run is not None:
        effective_dry = bool(dry_run) or not auto_quarantine
    else:
        effective_dry = not bool(apply)

    session = QuarantineSession(
        ctx=ctx,
        scope=scope,
        policy=policy,
        dry_run=effective_dry,
        include_auth=include_auth,
        confirm_wipe_auth=confirm_wipe_auth,
    )

    if scope in ("config", "all"):
        _cleanse_config(ctx, session, policy, harnesses=norm_harnesses)
    if scope in ("runtime", "all"):
        _cleanse_runtime(ctx, session, policy, harnesses=norm_harnesses)
    if scope in ("memory", "all"):
        _cleanse_memory(ctx, session, policy, native_wipe=native_wipe, harnesses=norm_harnesses)

    manifest_path = session.finalize()

    # Re-render quarantined config targets cleanly from SoT if requested and matched in targets.json.
    restored_ids: list[str] = []
    if not effective_dry and restore_targets and scope in ("config", "all") and session.quarantined_paths:
        from .deployer import apply_targets
        from .paths import expand_target_path
        from .render import load_targets_manifest

        quar_set = {os.path.abspath(p) for p in session.quarantined_paths}
        has_matching_target = False
        try:
            for t in load_targets_manifest(ctx.repo_root):
                if not t.get("enabled", True):
                    continue
                if t.get("scope", "global") == "project" and ctx.project_dir is None:
                    continue
                tp = os.path.abspath(
                    expand_target_path(str(t["path"]), home_dir=ctx.home_dir, project_dir=ctx.project_dir)
                )
                if tp in quar_set or any(q.startswith(tp + "/") for q in quar_set):
                    has_matching_target = True
                    break
        except Exception:
            has_matching_target = False

        if has_matching_target:
            try:
                res = apply_targets(
                    ctx,
                    safe=False,
                    approve_drift=True,
                    only_target_paths=quar_set,
                    run_pre_cleanse=False,
                )
                restored_ids = list(res.get("applied_ids", []))
            except Exception as exc:
                session.warnings.append(f"Skipped automatic target re-render: {exc}")

    return {
        "ok": True,
        "scope": scope,
        "applied": not effective_dry,
        "dry_run": effective_dry,
        "harnesses": sorted(norm_harnesses) if norm_harnesses else None,
        "quarantine_manifest": str(manifest_path) if manifest_path else None,
        "quarantined": session.entries,
        "preserved_auth_or_live": session.preserved,
        "restored_targets": restored_ids,
        "warnings": session.warnings,
    }
