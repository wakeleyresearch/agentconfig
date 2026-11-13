"""Shared isolated test helpers for the agentconfig unittest suite."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping


REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTCFG_BIN = REPO_ROOT / "bin" / "agentcfg"
AGENTCFG_BACKUP_BIN = REPO_ROOT / "bin" / "agentcfg-backup"
AGENT_ENV_RUN_BIN = REPO_ROOT / "wrappers" / "agent-env-run"
MCP_SECRET_EXEC_BIN = REPO_ROOT / "wrappers" / "mcp-secret-exec"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def build_isolated_env(
    home: Path,
    state_dir: Path,
    extra_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return an isolated environment dictionary that never reads live ~/ dotfiles."""
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["AGENTCFG_HOME"] = str(home)
    env["AGENTCFG_STATE_DIR"] = str(state_dir)
    # Keep XDG runtime isolated inside state_dir so tests never write /run/user/<uid>.
    xdg_runtime = state_dir / "xdg-runtime"
    xdg_runtime.mkdir(parents=True, exist_ok=True)
    os.chmod(xdg_runtime, 0o700)
    env["XDG_RUNTIME_DIR"] = str(xdg_runtime)
    env.pop("AGENTCFG_REPO", None)
    env.pop("AGENTCFG_PROJECT", None)
    env.pop("AGENTCFG_GROK_FLAVOR", None)
    if extra_env:
        env.update(extra_env)
    return env


def run_agentcfg(
    *args: str,
    home: Path,
    state_dir: Path,
    repo: Path | None = None,
    project: Path | None = None,
    extra_env: Mapping[str, str] | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Execute bin/agentcfg against isolated temp directories."""
    cmd = [sys.executable, str(AGENTCFG_BIN), *args]
    if repo is not None:
        cmd.extend(["--repo", str(repo)])
    cmd.extend(["--home", str(home), "--state-dir", str(state_dir)])
    if project is not None:
        cmd.extend(["--project", str(project)])

    env = build_isolated_env(home, state_dir, extra_env=extra_env)
    return subprocess.run(
        cmd,
        cwd=repo or REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=check,
    )


def copy_repo_fixture(dst: Path) -> Path:
    """Copy declarative repo directories into a writable temporary directory."""
    for rel in ("policy", "canonical", "targets", "wrappers", "bin", "lib"):
        src = REPO_ROOT / rel
        if src.exists():
            shutil.copytree(src, dst / rel, symlinks=False)
    for rel_file in (".gitignore",):
        src_f = REPO_ROOT / rel_file
        if src_f.exists():
            shutil.copy2(src_f, dst / rel_file)
    secrets_dir = dst / "secrets"
    secrets_dir.mkdir(exist_ok=True)
    sops_yaml = REPO_ROOT / "secrets" / ".sops.yaml"
    if sops_yaml.exists():
        shutil.copy2(sops_yaml, secrets_dir / ".sops.yaml")
    return dst


def init_git_repo(path: Path, initial_commit: bool = True) -> Path:
    """Create an isolated temporary git repository for project/staged tests."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "AgentConfig Test"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@agentconfig.local"], cwd=path, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=path, check=True)
    subprocess.run(["git", "config", "tag.gpgsign", "false"], cwd=path, check=True)
    if initial_commit:
        readme = path / "README.md"
        if not readme.exists():
            readme.write_text("# Temp Repo\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=path, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=path, check=True)
    return path


def synth_secret(prefix: str, tail: str) -> str:
    """Construct synthetic secret tokens via concatenation so gitleaks stays clean."""
    return "".join([prefix, tail])


class IsolatedEnvMixin:
    """Mixin providing temporary home, state_dir, and repo copy cleaned up automatically."""

    def setUp(self) -> None:
        super().setUp()  # type: ignore[misc]
        self._tmp = tempfile.TemporaryDirectory(prefix="agentcfg-test-")
        self.tmp_path = Path(self._tmp.name)
        self.home_dir = self.tmp_path / "home"
        self.state_dir = self.tmp_path / "state"
        self.home_dir.mkdir(mode=0o700)
        self.state_dir.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self._tmp.cleanup()
        super().tearDown()  # type: ignore[misc]
