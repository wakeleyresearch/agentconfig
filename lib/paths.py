"""Path resolution, lstat() symlink safety checks, and atomic file operations."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


class SafetyError(RuntimeError):
    """Raised when path safety (lstat symlink check or boundary check) fails."""


@dataclass(frozen=True)
class RuntimeContext:
    """Resolved execution roots for a single agentcfg invocation."""

    repo_root: Path
    home_dir: Path
    state_dir: Path
    runtime_dir: Path
    project_dir: Path | None = None
    grok_flavor: str | None = None
    require_signed: bool = False

    @classmethod
    def from_args(
        cls,
        repo: str | Path | None = None,
        home: str | Path | None = None,
        state_dir: str | Path | None = None,
        project: str | Path | None = None,
        grok_flavor: str | None = None,
        require_signed: bool = False,
    ) -> RuntimeContext:
        default_repo = Path(__file__).resolve().parent.parent
        repo_raw = repo or os.environ.get("AGENTCFG_REPO") or default_repo
        repo_root = Path(repo_raw).expanduser().resolve()

        real_home = Path.home().resolve()
        home_raw = home or os.environ.get("AGENTCFG_HOME")
        home_dir = Path(home_raw).expanduser().resolve() if home_raw else real_home

        state_raw = state_dir or os.environ.get("AGENTCFG_STATE_DIR")
        if state_raw:
            resolved_state = Path(state_raw).expanduser().resolve()
        else:
            resolved_state = (home_dir / ".local" / "state" / "agentcfg").resolve()

        # Isolate runtime locks inside state_dir when tests override home or state_dir.
        if state_raw or home_dir != real_home:
            runtime_dir = resolved_state / "runtime"
        else:
            xdg = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
            candidate = Path(xdg) / "agent-runtime"
            runtime_dir = candidate if Path(xdg).exists() else (resolved_state / "runtime")

        project_dir = Path(project).expanduser().resolve() if project else None
        flavor = grok_flavor or os.environ.get("AGENTCFG_GROK_FLAVOR") or None
        if flavor is not None:
            flavor = flavor.strip().lower()
            if flavor not in ("xai", "vibekit"):
                raise ValueError(f"Unsupported grok flavor {flavor!r}; expected 'xai' or 'vibekit'")

        return cls(
            repo_root=repo_root,
            home_dir=home_dir,
            state_dir=resolved_state,
            runtime_dir=runtime_dir,
            project_dir=project_dir,
            grok_flavor=flavor,
            require_signed=require_signed,
        )


def expand_target_path(
    raw_path: str,
    home_dir: Path,
    project_dir: Path | None = None,
) -> Path:
    """Expand a target path template against home_dir or project_dir."""
    if raw_path == "~":
        return home_dir
    if raw_path.startswith("~/"):
        return home_dir / raw_path[2:]
    p = Path(raw_path)
    if p.is_absolute():
        return p
    if project_dir is None:
        raise ValueError(f"Relative project target path {raw_path!r} requires project_dir")
    return project_dir / p


def _check_not_symlink(path: Path) -> os.stat_result | None:
    if not os.path.lexists(path):
        return None
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise SafetyError(f"Symlink component rejected by lstat(): {path}")
    return st


def safe_target(
    target_path: Path,
    boundary_root: Path | None = None,
    allow_dir_target: bool = False,
) -> None:
    """Verify every component via lstat() to prevent symlink traversal escapes."""
    if ".." in target_path.parts:
        raise SafetyError(f"Parent traversal ('..') rejected in target path: {target_path}")

    abs_target = Path(os.path.abspath(target_path))

    if boundary_root is not None:
        abs_root = Path(os.path.abspath(boundary_root))
        try:
            rel = abs_target.relative_to(abs_root)
        except ValueError as exc:
            raise SafetyError(
                f"Target {abs_target} escapes boundary root {abs_root}"
            ) from exc

        _check_not_symlink(abs_root)
        cur = abs_root
        parts = rel.parts
        for idx, part in enumerate(parts):
            cur = cur / part
            st = _check_not_symlink(cur)
            if st is None:
                continue
            is_last = idx == len(parts) - 1
            if not is_last:
                if not stat.S_ISDIR(st.st_mode):
                    raise SafetyError(f"Non-directory parent component: {cur}")
            else:
                if stat.S_ISFIFO(st.st_mode) or stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode) or stat.S_ISSOCK(st.st_mode):
                    raise SafetyError(f"Special file rejected at target: {cur}")
                if not allow_dir_target and stat.S_ISDIR(st.st_mode):
                    raise SafetyError(f"Expected file but found directory at target: {cur}")

        # Verify resolved deepest existing ancestor remains inside resolved boundary_root
        # whenever target sits strictly below boundary_root.
        if abs_root.exists() and abs_target != abs_root:
            root_real = abs_root.resolve()
            probe = abs_target.parent
            while not probe.exists() and probe != abs_root and probe != probe.parent:
                probe = probe.parent
            if probe.exists():
                probe_real = probe.resolve()
                if not probe_real.is_relative_to(root_real):
                    raise SafetyError(
                        f"Resolved parent {probe_real} escapes boundary {root_real}"
                    )
        return

    # Without explicit boundary_root, inspect every path component from filesystem root.
    cur = Path(abs_target.anchor)
    parts = abs_target.parts[1:]
    for idx, part in enumerate(parts):
        cur = cur / part
        st = _check_not_symlink(cur)
        if st is None:
            continue
        is_last = idx == len(parts) - 1
        if not is_last and not stat.S_ISDIR(st.st_mode):
            raise SafetyError(f"Non-directory parent component: {cur}")
        if is_last and (
            stat.S_ISFIFO(st.st_mode)
            or stat.S_ISCHR(st.st_mode)
            or stat.S_ISBLK(st.st_mode)
            or stat.S_ISSOCK(st.st_mode)
        ):
            raise SafetyError(f"Special file rejected at target: {cur}")


def ensure_safe_dir(
    directory: Path,
    mode: int = 0o700,
    boundary_root: Path | None = None,
) -> None:
    """Safely create directory hierarchy with explicit permissions (no symlink hops)."""
    safe_target(directory, boundary_root=boundary_root, allow_dir_target=True)
    abs_dir = Path(os.path.abspath(directory))
    if boundary_root is not None:
        abs_root = Path(os.path.abspath(boundary_root))
        if not abs_root.exists():
            os.makedirs(abs_root, mode=0o700, exist_ok=True)
            os.chmod(abs_root, 0o700)
        cur = abs_root
        parts = abs_dir.relative_to(abs_root).parts
    else:
        cur = Path(abs_dir.anchor)
        parts = abs_dir.parts[1:]

    for part in parts:
        cur = cur / part
        if not os.path.lexists(cur):
            os.mkdir(cur, mode)
            os.chmod(cur, mode)
        else:
            st = os.lstat(cur)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise SafetyError(f"Unsafe directory component {cur}")


def fsync_dir(directory: Path) -> None:
    """Flush directory entries to disk."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(directory, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(
    target: Path,
    data: bytes,
    mode: int,
    boundary_root: Path | None = None,
) -> None:
    """Atomically write bytes via same-FS NamedTemporaryFile + fsync + fchmod + os.replace."""
    safe_target(target, boundary_root=boundary_root, allow_dir_target=False)
    ensure_safe_dir(target.parent, mode=0o700, boundary_root=boundary_root)

    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=target.parent,
            prefix=".agentcfg.",
            suffix=".tmp",
            delete=False,
        ) as tf:
            tmp_path = tf.name
            tf.write(data)
            tf.flush()
            os.fsync(tf.fileno())
            os.fchmod(tf.fileno(), mode)
        os.replace(tmp_path, target)
        tmp_path = None
        fsync_dir(target.parent)
    finally:
        if tmp_path is not None and os.path.lexists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def atomic_write_text(
    target: Path,
    text: str,
    mode: int,
    boundary_root: Path | None = None,
) -> None:
    """UTF-8 atomic text wrapper around atomic_write_bytes."""
    atomic_write_bytes(target, text.encode("utf-8"), mode=mode, boundary_root=boundary_root)


def sha256_bytes(data: bytes) -> str:
    """Return lowercase hex SHA-256 of bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Stream-hash file contents without loading large binaries into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def file_mode(path: Path) -> int:
    """Return 0o7777 permission bits from lstat."""
    return stat.S_IMODE(os.lstat(path).st_mode)
