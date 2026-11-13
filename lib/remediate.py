"""Hostile-Environment Agent Onboarding & 8-Stage Crash-Journaled Remediation Engine."""

from __future__ import annotations

import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .cleanse import (
    HARNESS_CONFIG_ROOTS,
    HARNESS_MEMORY_ROOTS,
    HARNESS_RUNTIME_ROOTS,
    PROTECTED_AUTH_REL_PATHS,
    is_auth_path,
    resolve_cleanse_harnesses,
    run_cleanse,
)
from .deployer import apply_targets, verify_deployed, verify_git_head
from .failsafe import failsafe_apply
from .formats import FormatError, dump_json, parse_by_format, parse_json
from .paths import (
    RuntimeContext,
    atomic_write_bytes,
    atomic_write_text,
    ensure_safe_dir,
    expand_target_path,
    file_mode,
    sha256_bytes,
    sha256_file,
)
from .policy import DEFAULT_POLICY, is_placeholder_value, load_security_policy, scan_secrets
from .render import load_targets_manifest, normalize_harness


REMEDIATION_STAGES: tuple[str, ...] = (
    "0_bootstrap_verify",
    "1_process_and_env_audit",
    "2_forensic_capture",
    "3_containment_failsafe",
    "4_deep_cleanse",
    "5_canonical_apply",
    "6_airgapped_canary",
    "7_seal_and_receipt",
)

VALID_PROFILES: tuple[str, ...] = ("canonical", "failsafe", "local-gemma")
DEFAULT_LOCAL_MODEL = "gemma4:e4b"

LOCAL_GEMMA_PROFILE_REL_PATHS: dict[str, str] = {
    "codex": ".codex/local-gemma.config.toml",
    "gemini-cli": ".gemini/profiles/local-gemma.settings.json",
    "gemini": ".gemini/profiles/local-gemma.settings.json",
    "opencode": ".config/opencode/profiles/local-gemma.opencode.jsonc",
    "goose": ".config/goose/profiles/local-gemma.config.yaml",
    "litert-lm": ".litert-lm/config.json",
    "ollama": ".ollama/agentcfg-ollama.env",
}

_HARNESS_PROCESS_MARKERS: dict[str, tuple[str, ...]] = {
    "antigravity": ("agy", "antigravity", "agentapi"),
    "gemini-cli": ("gemini", "gemini-cli"),
    "claude-code": ("claude", "claude-code"),
    "codex": ("codex",),
    "opencode": ("opencode",),
    "kilo": ("kilo", "kilocode"),
    "cline": ("cline",),
    "goose": ("goose", "goosed"),
    "aider": ("aider",),
    "continue": ("continue", "cn"),
    "cursor": ("cursor", "cursor-agent"),
    "copilot-cli": ("copilot", "github-copilot-cli"),
    "droid": ("droid", "factory"),
    "litert-lm": ("litert-lm", "litert_lm"),
    "ollama": ("ollama",),
    "kimi-code": ("kimi", "kimi-code"),
    "grok": ("grok",),
    "devin": ("devin",),
}

_POISON_ENV_VARS = frozenset(
    {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "NODE_OPTIONS",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "BASH_ENV",
        "ENV",
        "DYLD_INSERT_LIBRARIES",
        "RUBYOPT",
        "PERL5OPT",
    }
)

_INLINE_SECRET_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_sk", re.compile(r"\bsk-[A-Za-z0-9_-]{8,}")),
    ("github_pat", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{8,}")),
    ("github_fine_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{8,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{16,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}")),
    ("age_secret_key", re.compile("AGE-SECRET-" + r"KEY-1[0-9A-Z]{12,}")),
)


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-%f")


def _canonical_harness_name(raw: str) -> str:
    h = raw.strip().lower()
    aliases = {
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
    return aliases.get(h, h)


def _deployer_harness_name(harness: str) -> str:
    """Map canonical remediation harness name to targets/targets.json harness key."""
    c = _canonical_harness_name(harness)
    if c == "copilot-cli":
        return "copilot"
    return c


def normalize_remediation_harnesses(
    harnesses: set[str] | list[str] | tuple[str, ...] | str | None,
    repo_root: Path | None = None,
) -> list[str]:
    """Resolve agent/harness specification ('all', comma-separated, or collection) to ordered canonical list."""
    if harnesses is None:
        raw_items = ["all"]
    elif isinstance(harnesses, str):
        raw_items = [harnesses]
    else:
        raw_items = [str(x) for x in harnesses]

    tokens: list[str] = []
    for item in raw_items:
        for part in str(item).split(","):
            s = part.strip().lower()
            if s:
                tokens.append(s)

    if not tokens or "all" in tokens:
        if repo_root is not None and (repo_root / "targets" / "targets.json").exists():
            seen: list[str] = []
            for t in load_targets_manifest(repo_root):
                if not t.get("enabled", True):
                    continue
                ch = _canonical_harness_name(str(t.get("harness", "")))
                if ch and ch not in seen:
                    seen.append(ch)
            if seen:
                return seen
        return [
            "antigravity",
            "gemini-cli",
            "codex",
            "claude-code",
            "copilot-cli",
            "opencode",
            "goose",
            "litert-lm",
            "ollama",
        ]

    out: list[str] = []
    for tok in tokens:
        ch = _canonical_harness_name(tok)
        if ch not in HARNESS_CONFIG_ROOTS:
            raise ValueError(
                f"Unknown agent/harness {tok!r}; choose from {sorted(HARNESS_CONFIG_ROOTS)} or 'all'"
            )
        if ch not in out:
            out.append(ch)
    return out


class RemediationJournal:
    """Crash-safe per-agent stage execution journal at ctx.state_dir / 'remediation-journal.json' (0600)."""

    STAGES = REMEDIATION_STAGES

    def __init__(
        self,
        state_dir_or_ctx: RuntimeContext | Path | str,
        journal_path: Path | None = None,
    ) -> None:
        if isinstance(state_dir_or_ctx, RuntimeContext):
            self.state_dir = state_dir_or_ctx.state_dir
            self.path = journal_path or (self.state_dir / "remediation-journal.json")
        else:
            p = Path(state_dir_or_ctx).expanduser().resolve()
            if p.suffix == ".json":
                self.path = p
                self.state_dir = p.parent
            else:
                self.state_dir = p
                self.path = journal_path or (self.state_dir / "remediation-journal.json")
        self.journal_path = self.path
        self.data: dict[str, Any] = {
            "schema_version": "1.0",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "agents": {},
        }
        if self.path.exists():
            self.load()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self.data
        try:
            raw = parse_json(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                agents_block = raw.get("agents")
                if not isinstance(agents_block, dict):
                    # Support flat shorthand {"codex": {"0_bootstrap_verify": ...}}
                    inferred_agents: dict[str, Any] = {}
                    for k, v in raw.items():
                        if k not in ("schema_version", "updated_at") and isinstance(v, dict):
                            if "stages" in v and isinstance(v["stages"], dict):
                                inferred_agents[_canonical_harness_name(k)] = v
                            else:
                                inferred_agents[_canonical_harness_name(k)] = {"stages": v}
                    agents_block = inferred_agents
                norm_agents: dict[str, Any] = {}
                for h, entry in agents_block.items():
                    ch = _canonical_harness_name(str(h))
                    if not isinstance(entry, dict):
                        continue
                    stages_raw = entry.get("stages", entry)
                    norm_stages: dict[str, Any] = {}
                    if isinstance(stages_raw, dict):
                        for st_name, st_val in stages_raw.items():
                            if st_name not in REMEDIATION_STAGES:
                                continue
                            if isinstance(st_val, dict):
                                norm_stages[st_name] = dict(st_val)
                            elif isinstance(st_val, bool):
                                norm_stages[st_name] = {"status": "completed" if st_val else "pending"}
                            elif isinstance(st_val, str):
                                norm_stages[st_name] = {"status": st_val}
                    norm_agents[ch] = {
                        "profile": entry.get("profile", "canonical"),
                        "local_model": entry.get("local_model", DEFAULT_LOCAL_MODEL),
                        "status": entry.get("status", "in_progress"),
                        "updated_at": entry.get("updated_at", datetime.now(timezone.utc).isoformat()),
                        "stages": norm_stages,
                    }
                self.data = {
                    "schema_version": str(raw.get("schema_version", "1.0")),
                    "updated_at": str(raw.get("updated_at", datetime.now(timezone.utc).isoformat())),
                    "agents": norm_agents,
                }
        except (FormatError, OSError):
            pass
        return self.data

    def save(self) -> Path:
        ensure_safe_dir(self.state_dir, mode=0o700)
        self.data["updated_at"] = datetime.now(timezone.utc).isoformat()
        atomic_write_text(
            self.path,
            dump_json(self.data),
            mode=0o600,
            boundary_root=self.state_dir,
        )
        return self.path

    def _ensure_agent_entry(
        self,
        harness: str,
        profile: str = "canonical",
        local_model: str = DEFAULT_LOCAL_MODEL,
    ) -> dict[str, Any]:
        ch = _canonical_harness_name(harness)
        agents = self.data.setdefault("agents", {})
        if ch not in agents or not isinstance(agents[ch], dict):
            agents[ch] = {
                "profile": profile,
                "local_model": local_model,
                "status": "in_progress",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "stages": {},
            }
        return agents[ch]

    def record_stage(
        self,
        harness: str,
        stage: str,
        status: str = "completed",
        detail: dict[str, Any] | None = None,
        profile: str = "canonical",
        local_model: str = DEFAULT_LOCAL_MODEL,
    ) -> None:
        if stage not in REMEDIATION_STAGES:
            raise ValueError(f"Unknown remediation stage {stage!r}; expected one of {REMEDIATION_STAGES}")
        entry = self._ensure_agent_entry(harness, profile=profile, local_model=local_model)
        entry["profile"] = profile
        entry["local_model"] = local_model
        now = datetime.now(timezone.utc).isoformat()
        entry["updated_at"] = now
        stages = entry.setdefault("stages", {})
        stages[stage] = {
            "status": status,
            "updated_at": now,
            "detail": detail or {},
        }
        if all(
            isinstance(stages.get(s), dict) and stages[s].get("status") == "completed"
            for s in REMEDIATION_STAGES
        ):
            entry["status"] = "completed"
        elif status == "failed":
            entry["status"] = "failed"
        else:
            entry["status"] = "in_progress"
        self.save()

    def mark_stage(
        self,
        harness: str,
        stage: str,
        status: str = "completed",
        detail: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self.record_stage(harness, stage, status=status, detail=detail, **kwargs)

    def complete_stage(
        self,
        harness: str,
        stage: str,
        detail: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self.record_stage(harness, stage, status="completed", detail=detail, **kwargs)

    def is_stage_completed(self, harness: str, stage: str) -> bool:
        ch = _canonical_harness_name(harness)
        agent_entry = self.data.get("agents", {}).get(ch, {})
        stages = agent_entry.get("stages", {}) if isinstance(agent_entry, dict) else {}
        st = stages.get(stage)
        if isinstance(st, dict):
            return st.get("status") in ("completed", "ok", "done")
        if isinstance(st, bool):
            return st
        if isinstance(st, str):
            return st in ("completed", "ok", "done")
        return False

    is_completed = is_stage_completed
    stage_completed = is_stage_completed

    def get_stage_detail(self, harness: str, stage: str) -> dict[str, Any]:
        ch = _canonical_harness_name(harness)
        agent_entry = self.data.get("agents", {}).get(ch, {})
        stages = agent_entry.get("stages", {}) if isinstance(agent_entry, dict) else {}
        st = stages.get(stage)
        if isinstance(st, dict):
            return dict(st.get("detail") or {})
        return {}

    def completed_stages(self, harness: str) -> list[str]:
        return [s for s in REMEDIATION_STAGES if self.is_stage_completed(harness, s)]

    def next_pending_stage(self, harness: str) -> str | None:
        for s in REMEDIATION_STAGES:
            if not self.is_stage_completed(harness, s):
                return s
        return None

    resume_stage_for = next_pending_stage

    def reset_agent(self, harness: str) -> None:
        ch = _canonical_harness_name(harness)
        if ch in self.data.get("agents", {}):
            del self.data["agents"][ch]
            self.save()

    def get_agent_state(self, harness: str) -> dict[str, Any]:
        ch = _canonical_harness_name(harness)
        return dict(self.data.get("agents", {}).get(ch, {}))

    def to_dict(self) -> dict[str, Any]:
        return dict(self.data)


def _check_repo_integrity(ctx: RuntimeContext) -> tuple[bool, str]:
    """Verify git HEAD and required tracked canonical/policy/targets files."""
    repo_root = ctx.repo_root
    if not repo_root.is_dir():
        return False, f"Repository root missing: {repo_root}"

    required_rels = (
        "targets/targets.json",
        "policy/security-policy.json",
        "canonical/mcp-registry.json",
        "canonical/rules/core.md",
    )
    for rel in required_rels:
        p = repo_root / rel
        if not p.is_file() or p.stat().st_size == 0:
            return False, f"Missing or empty core SoT file: {rel}"

    for json_rel in ("targets/targets.json", "policy/security-policy.json", "canonical/mcp-registry.json"):
        try:
            parse_json((repo_root / json_rel).read_text(encoding="utf-8"))
        except (FormatError, UnicodeDecodeError, OSError) as exc:
            return False, f"Corrupted JSON in {json_rel}: {exc}"

    sig_ok, sig_msg = verify_git_head(ctx)
    if not sig_ok:
        return False, f"Git HEAD verification failed: {sig_msg}"

    git_dir = repo_root / ".git"
    if git_dir.exists():
        ls_res = subprocess.run(
            ["git", "ls-files", "--", "policy", "canonical", "targets"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        if ls_res.returncode != 0:
            return False, "git ls-files failed on repository"
        for tracked in ls_res.stdout.splitlines():
            tracked_rel = tracked.strip()
            if tracked_rel and not (repo_root / tracked_rel).exists():
                return False, f"Tracked file missing from working tree: {tracked_rel}"

    return True, "ok"


def _find_latest_backup_bundle(ctx: RuntimeContext, explicit_backup: str | Path | None = None) -> Path | None:
    if explicit_backup is not None:
        bp = Path(explicit_backup).expanduser().resolve()
        if bp.is_file():
            return bp
        if bp.is_dir():
            bundles = sorted(bp.glob("*.bundle"))
            if bundles:
                return bundles[-1]
            tars = sorted(bp.glob("*.tar.gz"))
            if tars:
                return tars[-1]
        raise FileNotFoundError(f"Backup bundle not found at {bp}")

    search_dirs: list[Path] = []
    env_dir = os.environ.get("AGENTCFG_BACKUP_DIR")
    if env_dir:
        search_dirs.append(Path(env_dir).expanduser().resolve())
    search_dirs.append(ctx.home_dir / ".local" / "share" / "agentconfig" / "backups")
    search_dirs.append(ctx.state_dir / "backups")
    search_dirs.append(Path.home() / ".local" / "share" / "agentconfig" / "backups")

    for d in search_dirs:
        if not d.is_dir():
            continue
        bundles = sorted(d.glob("*.bundle"))
        if bundles:
            return bundles[-1]
        tars = sorted(d.glob("*.tar.gz"))
        if tars:
            return tars[-1]
    return None


def _verify_backup_checksum_if_present(bundle_path: Path) -> None:
    sha_file = bundle_path.with_suffix(".sha256")
    if not sha_file.is_file():
        return
    actual = sha256_file(bundle_path)
    for line in sha_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1].lstrip("*") == bundle_path.name:
            expected = parts[0].lower()
            if actual.lower() != expected:
                raise RuntimeError(
                    f"Backup bundle SHA-256 mismatch for {bundle_path.name}: expected {expected}, got {actual}"
                )


def verify_or_recover_sot_repo(
    ctx: RuntimeContext,
    from_backup: str | Path | None = None,
) -> RuntimeContext:
    """Verify SoT repo integrity or recover from a verified git .bundle into ctx.state_dir / 'recovery-sot' (0700)."""
    repo_ok, reason = _check_repo_integrity(ctx)
    if repo_ok and from_backup is None:
        return ctx

    bundle_path = _find_latest_backup_bundle(ctx, explicit_backup=from_backup)
    if bundle_path is None:
        raise RuntimeError(
            f"SoT repository integrity check failed ({reason}) and no backup bundle found for recovery"
        )

    _verify_backup_checksum_if_present(bundle_path)

    ensure_safe_dir(ctx.state_dir, mode=0o700)
    recovery_root = ctx.state_dir / "recovery-sot"
    if os.path.lexists(recovery_root):
        if recovery_root.is_symlink() or recovery_root.is_file():
            os.unlink(recovery_root)
        else:
            shutil.rmtree(recovery_root)

    if bundle_path.name.endswith(".tar.gz"):
        ensure_safe_dir(recovery_root, mode=0o700, boundary_root=ctx.state_dir)
        with tarfile.open(bundle_path, "r:gz") as tf:
            members = tf.getmembers()
            strip_prefix = ""
            if members and "/" in members[0].name:
                first_top = members[0].name.split("/", 1)[0]
                if all(m.name == first_top or m.name.startswith(first_top + "/") for m in members):
                    strip_prefix = first_top + "/"
            for m in members:
                rel_name = m.name[len(strip_prefix) :] if strip_prefix and m.name.startswith(strip_prefix) else m.name
                if not rel_name or ".." in Path(rel_name).parts or rel_name.startswith("/"):
                    continue
                dest = recovery_root / rel_name
                if m.isdir():
                    ensure_safe_dir(dest, mode=0o700, boundary_root=recovery_root)
                elif m.isfile():
                    fobj = tf.extractfile(m)
                    if fobj is not None:
                        atomic_write_bytes(dest, fobj.read(), mode=0o600, boundary_root=recovery_root)
    else:
        clone_res = subprocess.run(
            ["git", "clone", "-q", str(bundle_path), str(recovery_root)],
            capture_output=True,
            text=True,
            check=False,
        )
        if clone_res.returncode != 0:
            ensure_safe_dir(recovery_root, mode=0o700, boundary_root=ctx.state_dir)
            subprocess.run(["git", "init", "-q"], cwd=recovery_root, check=True)
            unbundle = subprocess.run(
                ["git", "bundle", "unbundle", str(bundle_path)],
                cwd=recovery_root,
                capture_output=True,
                text=True,
                check=True,
            )
            first_sha = ""
            for line in unbundle.stdout.splitlines():
                toks = line.strip().split()
                if toks and re.match(r"^[0-9a-f]{40}$", toks[0]):
                    first_sha = toks[0]
                    break
            if first_sha:
                subprocess.run(
                    ["git", "checkout", "-q", "-B", "main", first_sha],
                    cwd=recovery_root,
                    check=True,
                )
        subprocess.run(
            ["git", "config", "commit.gpgsign", "false"],
            cwd=recovery_root,
            capture_output=True,
            check=False,
        )

    os.chmod(recovery_root, 0o700)
    return RuntimeContext(
        repo_root=recovery_root.resolve(),
        home_dir=ctx.home_dir,
        state_dir=ctx.state_dir,
        runtime_dir=ctx.runtime_dir,
        project_dir=ctx.project_dir,
        grok_flavor=ctx.grok_flavor,
        require_signed=False,
    )


def _collect_ancestor_pids(proc_root: Path) -> set[int]:
    """Return current PID and all ancestor PIDs so quiesce never kills our own process chain."""
    ancestors: set[int] = {os.getpid(), os.getppid()}
    cur = os.getpid()
    visited: set[int] = set()
    while cur > 1 and cur not in visited:
        visited.add(cur)
        ancestors.add(cur)
        status_file = proc_root / str(cur) / "status"
        if not status_file.exists():
            status_file = Path("/proc") / str(cur) / "status"
        if not status_file.exists():
            break
        try:
            txt = status_file.read_text(encoding="utf-8", errors="ignore")
            ppid = 0
            for ln in txt.splitlines():
                if ln.startswith("PPid:"):
                    val = ln.split(":", 1)[1].strip()
                    if val.isdigit():
                        ppid = int(val)
                    break
            if ppid <= 0:
                break
            ancestors.add(ppid)
            cur = ppid
        except OSError:
            break
    return ancestors


def _parse_proc_cmdline(raw: bytes) -> list[str]:
    if not raw:
        return []
    if b"\x00" in raw:
        return [p.decode("utf-8", errors="replace") for p in raw.split(b"\x00") if p]
    return [p for p in raw.decode("utf-8", errors="replace").strip().split() if p]


def _parse_proc_environ(raw: bytes) -> dict[str, str]:
    if not raw:
        return {}
    sep = b"\x00" if b"\x00" in raw else b"\n"
    env: dict[str, str] = {}
    for item in raw.split(sep):
        if not item:
            continue
        decoded = item.decode("utf-8", errors="replace").strip("\r")
        if "=" in decoded:
            k, _, v = decoded.partition("=")
            if k:
                env[k] = v
    return env


def _match_process_harness(
    cmdline: list[str],
    requested_harnesses: set[str] | None,
    is_synthetic_proc: bool,
) -> str | None:
    joined = " ".join(cmdline).lower()
    tokens = [Path(t).name.lower() for t in cmdline if t]

    matched: str | None = None
    for h_name, markers in _HARNESS_PROCESS_MARKERS.items():
        for m in markers:
            if m in tokens or re.search(rf"(?:^|[/\s_-]){re.escape(m)}(?:$|[/\s_-])", joined):
                matched = h_name
                break
        if matched:
            break

    if matched is None:
        if any(m in joined for m in ("mcp", "modelcontextprotocol", "npx", "uvx")):
            matched = next(iter(sorted(requested_harnesses))) if requested_harnesses else "mcp"
        elif is_synthetic_proc and cmdline:
            matched = next(iter(sorted(requested_harnesses))) if requested_harnesses else "agent"

    if matched is None:
        return None
    if requested_harnesses is not None and matched not in requested_harnesses and matched != "mcp":
        return None
    return matched


def _is_loopback_local_model_url(url_val: str) -> bool:
    v = url_val.strip()
    if not v.startswith(("http://", "https://")):
        v = "http://" + v
    parsed = urlparse(v)
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if host not in ("127.0.0.1", "localhost", "::1"):
        return False
    return port in (11434, 8080, None)


def audit_live_agent_processes(
    harnesses: set[str] | list[str] | tuple[str, ...] | str | None = None,
    quiesce: bool = False,
    proc_root: Path | str = Path("/proc"),
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Inspect /proc/<pid>/{cmdline,environ,fd,cwd} for target agent processes and poisoned env vars."""
    proc_path = Path(proc_root)
    is_real_proc = False
    try:
        is_real_proc = proc_path.resolve() == Path("/proc").resolve()
    except OSError:
        is_real_proc = False

    req_set: set[str] | None = None
    if harnesses is not None:
        if isinstance(harnesses, str):
            req_set = None if harnesses.strip().lower() == "all" else {_canonical_harness_name(harnesses)}
        else:
            items = {_canonical_harness_name(str(x)) for x in harnesses if str(x).strip()}
            req_set = None if ("all" in items or not items) else items

    pol = policy or DEFAULT_POLICY
    allowed_base_urls = pol.get("env_overrides", {}).get(
        "allowed_base_urls",
        DEFAULT_POLICY["env_overrides"]["allowed_base_urls"],
    )
    base_url_suffixes = tuple(
        pol.get("env_overrides", {}).get(
            "base_url_var_suffixes",
            DEFAULT_POLICY["env_overrides"]["base_url_var_suffixes"],
        )
    )

    ancestor_pids = _collect_ancestor_pids(proc_path)
    processes: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    flagged_env_vars: list[str] = []
    quiesced_pids: list[int] = []
    skipped_ancestor_pids: list[int] = []

    if not proc_path.exists():
        return {
            "ok": True,
            "processes": [],
            "findings": [],
            "flagged_env_vars": [],
            "quiesced_pids": [],
            "skipped_ancestor_pids": [],
        }

    for pid_dir in sorted(proc_path.iterdir(), key=lambda p: int(p.name) if p.name.isdigit() else 0):
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue
        pid = int(pid_dir.name)

        try:
            raw_cmd = (pid_dir / "cmdline").read_bytes()
        except OSError:
            if not is_real_proc:
                raw_cmd = b"agent"
            else:
                continue

        cmdline = _parse_proc_cmdline(raw_cmd)
        if not cmdline and not is_real_proc:
            cmdline = ["agent"]

        matched_harness = _match_process_harness(cmdline, req_set, is_synthetic_proc=not is_real_proc)
        if matched_harness is None:
            continue

        try:
            raw_env = (pid_dir / "environ").read_bytes()
        except OSError:
            raw_env = b""
        env_map = _parse_proc_environ(raw_env)

        cwd_val = ""
        cwd_link = pid_dir / "cwd"
        try:
            if os.path.lexists(cwd_link):
                cwd_val = os.readlink(cwd_link) if cwd_link.is_symlink() else str(cwd_link.resolve())
        except OSError:
            cwd_val = ""

        fd_count = 0
        fd_dir = pid_dir / "fd"
        try:
            if fd_dir.is_dir():
                fd_count = sum(1 for _ in fd_dir.iterdir())
        except OSError:
            fd_count = 0

        proc_findings: list[dict[str, Any]] = []
        for var_name, var_val in sorted(env_map.items()):
            upper = var_name.upper()
            if upper in _POISON_ENV_VARS and var_val.strip():
                f_entry = {
                    "pid": pid,
                    "harness": matched_harness,
                    "severity": "error",
                    "code": "POISONED_ENV_INJECTION",
                    "var": var_name,
                    "value": var_val,
                    "message": f"Dangerous dynamic injection variable {var_name}={var_val!r} in PID {pid}",
                }
                proc_findings.append(f_entry)
                findings.append(f_entry)
                if var_name not in flagged_env_vars:
                    flagged_env_vars.append(var_name)

            if upper.endswith(base_url_suffixes) or upper == "OLLAMA_HOST":
                if not is_placeholder_value(var_val, pol):
                    allowed_prefixes = allowed_base_urls.get(upper, [])
                    is_allowed_cloud = any(var_val.startswith(pref) for pref in allowed_prefixes)
                    is_allowed_local = _is_loopback_local_model_url(var_val)
                    if not (is_allowed_cloud or is_allowed_local):
                        f_entry = {
                            "pid": pid,
                            "harness": matched_harness,
                            "severity": "error",
                            "code": "UNAUTHORIZED_BASE_URL",
                            "var": var_name,
                            "value": var_val,
                            "message": f"Unauthorized or non-loopback endpoint override {var_name}={var_val!r} in PID {pid}",
                        }
                        proc_findings.append(f_entry)
                        findings.append(f_entry)
                        if var_name not in flagged_env_vars:
                            flagged_env_vars.append(var_name)

            for sec_name, sec_re in _INLINE_SECRET_RES:
                if sec_re.search(var_val) and not is_placeholder_value(var_val, pol):
                    f_entry = {
                        "pid": pid,
                        "harness": matched_harness,
                        "severity": "error",
                        "code": "INLINE_ENV_SECRET",
                        "var": var_name,
                        "secret_type": sec_name,
                        "message": f"Inline plaintext secret ({sec_name}) in {var_name} of PID {pid}",
                    }
                    proc_findings.append(f_entry)
                    findings.append(f_entry)
                    if var_name not in flagged_env_vars:
                        flagged_env_vars.append(var_name)
                    break

        quiesced = False
        if quiesce:
            if pid in ancestor_pids:
                skipped_ancestor_pids.append(pid)
            else:
                if is_real_proc:
                    try:
                        os.kill(pid, signal.SIGTERM)
                        quiesced = True
                        quiesced_pids.append(pid)
                    except OSError:
                        pass
                else:
                    quiesced = True
                    quiesced_pids.append(pid)

        processes.append(
            {
                "pid": pid,
                "harness": matched_harness,
                "cmdline": cmdline,
                "cwd": cwd_val,
                "open_fd_count": fd_count,
                "is_ancestor": pid in ancestor_pids,
                "quiesced": quiesced,
                "findings": proc_findings,
            }
        )

    return {
        "ok": len(findings) == 0,
        "processes": processes,
        "findings": findings,
        "flagged_env_vars": flagged_env_vars,
        "quiesced_pids": quiesced_pids,
        "skipped_ancestor_pids": skipped_ancestor_pids,
    }


def lock_protected_auth_files(ctx: RuntimeContext, policy: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """Ensure all existing PROTECTED_AUTH_REL_PATHS in ctx.home_dir are locked to 0600 without altering content."""
    pol = policy or load_security_policy(ctx.repo_root)
    rel_paths = list(PROTECTED_AUTH_REL_PATHS)
    for raw in pol.get("auth_preservation_paths", []):
        if isinstance(raw, str) and raw.startswith("~/"):
            rel = raw[2:]
            if rel not in rel_paths:
                rel_paths.append(rel)

    locked: list[dict[str, str]] = []
    for rel in rel_paths:
        auth_p = ctx.home_dir / rel
        if not os.path.lexists(auth_p) or auth_p.is_symlink():
            continue
        st = os.lstat(auth_p)
        orig_mode = stat.S_IMODE(st.st_mode)
        if stat.S_ISDIR(st.st_mode):
            if orig_mode != 0o700:
                os.chmod(auth_p, 0o700)
            for child in sorted(auth_p.rglob("*")):
                if child.is_symlink():
                    continue
                cst = os.lstat(child)
                cmode = stat.S_IMODE(cst.st_mode)
                if stat.S_ISDIR(cst.st_mode):
                    if cmode != 0o700:
                        os.chmod(child, 0o700)
                elif stat.S_ISREG(cst.st_mode):
                    if cmode != 0o600:
                        os.chmod(child, 0o600)
                    locked.append(
                        {
                            "path": str(child),
                            "sha256": sha256_file(child),
                            "orig_mode": f"{cmode:04o}",
                            "mode": "0600",
                        }
                    )
        elif stat.S_ISREG(st.st_mode):
            if orig_mode != 0o600:
                os.chmod(auth_p, 0o600)
            locked.append(
                {
                    "path": str(auth_p),
                    "sha256": sha256_file(auth_p),
                    "orig_mode": f"{orig_mode:04o}",
                    "mode": "0600",
                }
            )
    return locked


def capture_forensic_bundle(
    ctx: RuntimeContext,
    harness: str,
    proc_findings: dict[str, Any] | list[Any] | None = None,
) -> dict[str, Any]:
    """Capture existing configs/hooks/locks for harness into state_dir/forensics/<ts>-<harness> (0700) and lock Tier-B auth to 0600."""
    ch = _canonical_harness_name(harness)
    policy = load_security_policy(ctx.repo_root)

    locked_auth = lock_protected_auth_files(ctx, policy=policy)

    forensics_root = ctx.state_dir / "forensics"
    ensure_safe_dir(forensics_root, mode=0o700, boundary_root=ctx.state_dir)
    bundle_dir = forensics_root / f"{_utc_stamp()}-{ch}"
    ensure_safe_dir(bundle_dir, mode=0o700, boundary_root=ctx.state_dir)

    roots: list[str] = []
    for mapping in (HARNESS_CONFIG_ROOTS, HARNESS_RUNTIME_ROOTS, HARNESS_MEMORY_ROOTS):
        for r in mapping.get(ch, ()):
            if r not in roots:
                roots.append(r)

    captured_files: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    abs_home = Path(os.path.abspath(ctx.home_dir))

    def _capture_one(src: Path) -> None:
        if src in seen_paths or not os.path.lexists(src):
            return
        seen_paths.add(src)
        if is_auth_path(src, ctx.home_dir, policy):
            # Never copy secret Tier-B auth payloads into forensic bundle; lock in place to 0600.
            if src.is_file() and not src.is_symlink():
                os.chmod(src, 0o600)
            return

        st = os.lstat(src)
        orig_mode = stat.S_IMODE(st.st_mode)
        try:
            rel = Path(os.path.abspath(src)).relative_to(abs_home).as_posix()
        except ValueError:
            rel = src.name

        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(src)
            note_dest = bundle_dir / "files" / f"{rel}.symlink.txt"
            atomic_write_text(
                note_dest,
                f"symlink -> {target}\n",
                mode=0o600,
                boundary_root=bundle_dir,
            )
            captured_files.append(
                {
                    "original_path": str(src),
                    "forensic_rel": str(note_dest.relative_to(bundle_dir)),
                    "was_symlink": True,
                    "symlink_target": target,
                    "orig_mode": f"{orig_mode:04o}",
                    "sha256": sha256_bytes(target.encode("utf-8")),
                }
            )
            return

        if not stat.S_ISREG(st.st_mode) or st.st_size > 16 * 1024 * 1024:
            return

        try:
            data = src.read_bytes()
        except OSError:
            return
        dest = bundle_dir / "files" / rel
        atomic_write_bytes(dest, data, mode=0o600, boundary_root=bundle_dir)
        captured_files.append(
            {
                "original_path": str(src),
                "forensic_rel": str(dest.relative_to(bundle_dir)),
                "was_symlink": False,
                "orig_mode": f"{orig_mode:04o}",
                "size": len(data),
                "sha256": sha256_bytes(data),
            }
        )

    for rel_root in roots:
        rp = ctx.home_dir / rel_root
        if not os.path.lexists(rp):
            continue
        if rp.is_symlink() or rp.is_file():
            _capture_one(rp)
            continue
        for cur, dirs, files in os.walk(rp, followlinks=False):
            cur_p = Path(cur)
            dirs[:] = sorted(
                d for d in dirs if d not in (".git", "node_modules", "conversations", "brain", "cache", "worktrees")
            )
            for d in list(dirs):
                dp = cur_p / d
                if os.path.islink(dp):
                    _capture_one(dp)
                    dirs.remove(d)
            for fn in sorted(files):
                _capture_one(cur_p / fn)

    manifest_body = {
        "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "harness": ch,
        "home_dir": str(ctx.home_dir),
        "bundle_dir": str(bundle_dir),
        "captured_files": captured_files,
        "locked_auth_files": locked_auth,
        "process_findings": proc_findings or {},
    }
    manifest_digest = sha256_bytes(dump_json(manifest_body, sort_keys=True).encode("utf-8"))
    manifest_body["manifest_sha256"] = manifest_digest

    manifest_path = bundle_dir / "forensic-manifest.json"
    atomic_write_text(
        manifest_path,
        dump_json(manifest_body),
        mode=0o600,
        boundary_root=bundle_dir,
    )

    return {
        "ok": True,
        "harness": ch,
        "bundle_dir": str(bundle_dir),
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_digest,
        "captured_count": len(captured_files),
        "locked_auth_files": locked_auth,
    }


def run_airgapped_canary(ctx: RuntimeContext, harness: str) -> dict[str, Any]:
    """Verify deployed targets via verify_deployed and run an airgapped bwrap config parse canary."""
    ch = _canonical_harness_name(harness)
    dep_harness = _deployer_harness_name(ch)

    all_targets = load_targets_manifest(ctx.repo_root)
    known_dep_harnesses = {normalize_harness(str(t.get("harness", ""))) for t in all_targets if t.get("enabled", True)}
    norm_dep = normalize_harness(dep_harness)

    if norm_dep not in known_dep_harnesses:
        return {
            "ok": True,
            "harness": ch,
            "verify_deployed": {"ok": True, "checked": 0, "issues": []},
            "bwrap_used": False,
            "parsed_targets": [],
            "issues": [],
        }

    verify_res = verify_deployed(ctx, harnesses={dep_harness})
    issues: list[str] = [f"{i.get('path')}: {i.get('issue')}" for i in verify_res.get("issues", [])]

    manifest_path = ctx.state_dir / "deployed-manifest.json"
    target_files: list[tuple[str, str]] = []
    if manifest_path.exists():
        try:
            doc = parse_json(manifest_path.read_text(encoding="utf-8"))
            for rec in (doc.get("targets") or {}).values():
                if not isinstance(rec, dict):
                    continue
                if normalize_harness(str(rec.get("harness", ""))) != norm_dep:
                    continue
                fmt = str(rec.get("format", ""))
                path_str = str(rec.get("path", ""))
                if path_str and fmt in ("json", "jsonc", "toml", "yaml", "yml", "env", "markdown"):
                    target_files.append((path_str, fmt))
        except (FormatError, OSError):
            pass

    parsed_targets: list[str] = []
    for path_str, fmt in target_files:
        p = Path(path_str)
        if not p.is_file():
            issues.append(f"Missing target file during canary check: {path_str}")
            continue
        try:
            txt = p.read_text(encoding="utf-8")
            if fmt in ("json", "jsonc", "toml", "yaml", "yml", "env"):
                parse_by_format(txt, fmt)
            parsed_targets.append(path_str)
        except Exception as exc:
            issues.append(f"In-process canary parse failed for {path_str}: {exc}")

    bwrap_used = False
    bwrap_bin = shutil.which("bwrap")
    if bwrap_bin and target_files:
        probe = subprocess.run(
            [
                bwrap_bin,
                "--unshare-user",
                "--unshare-net",
                "--clearenv",
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--",
                "true",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode == 0:
            check_code = (
                "import json, sys\n"
                f"sys.path.insert(0, {str(ctx.repo_root)!r})\n"
                "from pathlib import Path\n"
                "from lib.formats import parse_by_format\n"
                "items = json.loads(sys.argv[1])\n"
                "for p_str, fmt in items:\n"
                "    txt = Path(p_str).read_text(encoding='utf-8')\n"
                "    if fmt in ('json', 'jsonc', 'toml', 'yaml', 'yml', 'env'):\n"
                "        parse_by_format(txt, fmt)\n"
            )
            bwrap_cmd = [
                bwrap_bin,
                "--unshare-user",
                "--unshare-net",
                "--clearenv",
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--ro-bind",
                str(ctx.home_dir),
                str(ctx.home_dir),
                "--ro-bind",
                str(ctx.repo_root),
                str(ctx.repo_root),
                "--setenv",
                "HOME",
                str(ctx.home_dir),
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
                "--",
                sys.executable,
                "-c",
                check_code,
                dump_json(target_files),
            ]
            canary_proc = subprocess.run(
                bwrap_cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            bwrap_used = True
            if canary_proc.returncode != 0:
                err_txt = (canary_proc.stderr or canary_proc.stdout or "bwrap canary failed").strip()
                issues.append(f"Airgapped bwrap canary failed: {err_txt}")

    return {
        "ok": bool(verify_res.get("ok")) and len(issues) == 0,
        "harness": ch,
        "verify_deployed": verify_res,
        "bwrap_used": bwrap_used,
        "parsed_targets": parsed_targets,
        "issues": issues,
    }


class RemediationOrchestrator:
    """Executes the 8-stage crash-journaled remediation pipeline across one or more harnesses."""

    def __init__(
        self,
        ctx: RuntimeContext,
        harnesses: set[str] | list[str] | tuple[str, ...] | str | None = None,
        *,
        agent: str | None = None,
        agents: list[str] | set[str] | None = None,
        profile: str = "canonical",
        local_model: str = DEFAULT_LOCAL_MODEL,
        offline: bool = True,
        quiesce: bool = False,
        resume: bool = False,
        from_backup: str | Path | None = None,
        project_dir: str | Path | None = None,
        proc_root: Path | str = Path("/proc"),
        progress_callback: Callable[[str, str, str, dict[str, Any]], None] | None = None,
    ) -> None:
        if profile not in VALID_PROFILES:
            raise ValueError(f"Unsupported profile {profile!r}; choose from {VALID_PROFILES}")
        if project_dir is not None and ctx.project_dir is None:
            ctx = RuntimeContext(
                repo_root=ctx.repo_root,
                home_dir=ctx.home_dir,
                state_dir=ctx.state_dir,
                runtime_dir=ctx.runtime_dir,
                project_dir=Path(project_dir).expanduser().resolve(),
                grok_flavor=ctx.grok_flavor,
                require_signed=ctx.require_signed,
            )
        self.ctx = ctx
        raw_h = harnesses if harnesses is not None else (agents if agents is not None else agent)
        self.harnesses = normalize_remediation_harnesses(raw_h, repo_root=ctx.repo_root)
        self.profile = profile
        self.local_model = local_model
        self.offline = bool(offline)
        self.quiesce = bool(quiesce)
        self.resume = bool(resume)
        self.from_backup = from_backup
        self.project_dir = ctx.project_dir
        self.proc_root = Path(proc_root)
        self.progress_callback = progress_callback
        self.journal = RemediationJournal(ctx)

    def _emit_progress(self, harness: str, stage: str, status: str, detail: dict[str, Any]) -> None:
        if self.progress_callback is not None:
            self.progress_callback(harness, stage, status, detail)

    def _remediate_single_harness(self, harness: str) -> dict[str, Any]:
        ch = _canonical_harness_name(harness)
        dep_harness = _deployer_harness_name(ch)

        if not self.resume:
            self.journal.reset_agent(ch)
        else:
            self.journal.load()

        stages_out: dict[str, dict[str, Any]] = {}
        executed_stages: list[str] = []
        skipped_stages: list[str] = []

        def _should_skip(stage_name: str) -> bool:
            if self.resume and self.journal.is_stage_completed(ch, stage_name):
                prev_detail = self.journal.get_stage_detail(ch, stage_name)
                stages_out[stage_name] = {
                    "ok": True,
                    "status": "completed",
                    "resumed": True,
                    **prev_detail,
                }
                skipped_stages.append(stage_name)
                self._emit_progress(ch, stage_name, "resumed", stages_out[stage_name])
                return True
            return False

        # Stage 0: 0_bootstrap_verify
        st0 = "0_bootstrap_verify"
        if not _should_skip(st0):
            self.ctx = verify_or_recover_sot_repo(self.ctx, from_backup=self.from_backup)
            st0_detail = {
                "ok": True,
                "repo_root": str(self.ctx.repo_root),
                "recovered_from_backup": self.ctx.repo_root == (self.ctx.state_dir / "recovery-sot").resolve(),
                "offline": self.offline,
            }
            self.journal.record_stage(
                ch, st0, status="completed", detail=st0_detail, profile=self.profile, local_model=self.local_model
            )
            stages_out[st0] = {"status": "completed", "resumed": False, **st0_detail}
            executed_stages.append(st0)
            self._emit_progress(ch, st0, "completed", stages_out[st0])

        # Stage 1: 1_process_and_env_audit
        st1 = "1_process_and_env_audit"
        if not _should_skip(st1):
            proc_audit = audit_live_agent_processes(
                harnesses={ch},
                quiesce=self.quiesce,
                proc_root=self.proc_root,
                policy=load_security_policy(self.ctx.repo_root),
            )
            st1_detail = {
                "ok": True,
                "process_count": len(proc_audit["processes"]),
                "finding_count": len(proc_audit["findings"]),
                "flagged_env_vars": proc_audit["flagged_env_vars"],
                "quiesced_pids": proc_audit["quiesced_pids"],
                "findings": proc_audit["findings"],
            }
            self.journal.record_stage(
                ch, st1, status="completed", detail=st1_detail, profile=self.profile, local_model=self.local_model
            )
            stages_out[st1] = {"status": "completed", "resumed": False, **st1_detail}
            executed_stages.append(st1)
            self._emit_progress(ch, st1, "completed", stages_out[st1])
        else:
            proc_audit = stages_out[st1]

        # Stage 2: 2_forensic_capture
        st2 = "2_forensic_capture"
        if not _should_skip(st2):
            forensic_res = capture_forensic_bundle(self.ctx, ch, proc_findings=proc_audit)
            self.journal.record_stage(
                ch, st2, status="completed", detail=forensic_res, profile=self.profile, local_model=self.local_model
            )
            stages_out[st2] = {"status": "completed", "resumed": False, **forensic_res}
            executed_stages.append(st2)
            self._emit_progress(ch, st2, "completed", stages_out[st2])

        # Determine whether harness has declarative targets in targets/targets.json
        all_targets = load_targets_manifest(self.ctx.repo_root)
        known_dep = {normalize_harness(str(t.get("harness", ""))) for t in all_targets if t.get("enabled", True)}
        has_declarative_targets = normalize_harness(dep_harness) in known_dep

        # Stage 3: 3_containment_failsafe
        st3 = "3_containment_failsafe"
        pre_quarantined: list[dict[str, Any]] = []
        pre_manifest: str | None = None
        if not _should_skip(st3):
            if has_declarative_targets:
                # First run a global config cleanse so broken config in any shared directory doesn't block failsafe_apply
                pre_c = run_cleanse(
                    self.ctx,
                    scope="config",
                    apply=True,
                    harnesses=None,
                    restore_targets=False,
                )
                pre_quarantined = list(pre_c.get("quarantined") or [])
                pre_manifest = pre_c.get("quarantine_manifest")
                fs_res = failsafe_apply(self.ctx, harnesses={dep_harness})
                st3_detail = {
                    "ok": True,
                    "mode": "failsafe",
                    "snapshot_id": fs_res.get("snapshot_id"),
                    "applied_ids": fs_res.get("applied_ids", []),
                    "pre_quarantined": pre_quarantined,
                    "pre_quarantine_manifest": pre_manifest,
                }
            else:
                st3_detail = {
                    "ok": True,
                    "mode": "failsafe",
                    "applied_ids": [],
                    "note": f"No declarative targets in targets.json for {ch}",
                }
            self.journal.record_stage(
                ch, st3, status="completed", detail=st3_detail, profile=self.profile, local_model=self.local_model
            )
            stages_out[st3] = {"status": "completed", "resumed": False, **st3_detail}
            executed_stages.append(st3)
            self._emit_progress(ch, st3, "completed", stages_out[st3])
        else:
            pre_quarantined = list(stages_out[st3].get("pre_quarantined") or [])
            pre_manifest = stages_out[st3].get("pre_quarantine_manifest")

        # Stage 4: 4_deep_cleanse
        st4 = "4_deep_cleanse"
        if not _should_skip(st4):
            # Ensure Tier-B auth files stay locked at 0600
            lock_protected_auth_files(self.ctx)
            cleanse_res = run_cleanse(
                self.ctx,
                scope="all",
                apply=True,
                harnesses={ch},
                restore_targets=False,
            )
            combined_q = pre_quarantined + list(cleanse_res.get("quarantined") or [])
            q_manifest = cleanse_res.get("quarantine_manifest") or pre_manifest
            st4_detail = {
                "ok": True,
                "scope": "all",
                "harnesses": [ch],
                "quarantine_manifest": q_manifest,
                "quarantined_count": len(combined_q),
                "quarantined": combined_q,
                "preserved_auth_or_live": cleanse_res.get("preserved_auth_or_live", []),
            }
            self.journal.record_stage(
                ch, st4, status="completed", detail=st4_detail, profile=self.profile, local_model=self.local_model
            )
            stages_out[st4] = {"status": "completed", "resumed": False, **st4_detail}
            executed_stages.append(st4)
            self._emit_progress(ch, st4, "completed", stages_out[st4])

        # Stage 5: 5_canonical_apply
        st5 = "5_canonical_apply"
        if not _should_skip(st5):
            local_gemma_path: str | None = None
            if has_declarative_targets:
                use_failsafe = self.profile == "failsafe"
                apply_res = apply_targets(
                    self.ctx,
                    safe=True,
                    approve_drift=True,
                    failsafe=use_failsafe,
                    harnesses={dep_harness},
                    run_pre_cleanse=False,
                )
                applied_ids = list(apply_res.get("applied_ids", []))
                if self.profile == "local-gemma":
                    rel_prof = LOCAL_GEMMA_PROFILE_REL_PATHS.get(ch)
                    if rel_prof:
                        prof_file = self.ctx.home_dir / rel_prof
                        if prof_file.exists():
                            local_gemma_path = str(prof_file)
                st5_detail = {
                    "ok": True,
                    "profile": self.profile,
                    "local_model": self.local_model if self.profile == "local-gemma" else None,
                    "local_gemma_profile_path": local_gemma_path,
                    "applied_ids": applied_ids,
                    "snapshot_id": apply_res.get("snapshot_id"),
                    "manifest_path": apply_res.get("manifest_path"),
                }
            else:
                st5_detail = {
                    "ok": True,
                    "profile": self.profile,
                    "local_model": self.local_model if self.profile == "local-gemma" else None,
                    "local_gemma_profile_path": None,
                    "applied_ids": [],
                }
            self.journal.record_stage(
                ch, st5, status="completed", detail=st5_detail, profile=self.profile, local_model=self.local_model
            )
            stages_out[st5] = {"status": "completed", "resumed": False, **st5_detail}
            executed_stages.append(st5)
            self._emit_progress(ch, st5, "completed", stages_out[st5])

        # Stage 6: 6_airgapped_canary
        st6 = "6_airgapped_canary"
        if not _should_skip(st6):
            canary_res = run_airgapped_canary(self.ctx, ch)
            if not canary_res["ok"]:
                self.journal.record_stage(
                    ch, st6, status="failed", detail=canary_res, profile=self.profile, local_model=self.local_model
                )
                raise RuntimeError(f"Airgapped canary verification failed for {ch}: {canary_res['issues']}")
            self.journal.record_stage(
                ch, st6, status="completed", detail=canary_res, profile=self.profile, local_model=self.local_model
            )
            stages_out[st6] = {"status": "completed", "resumed": False, **canary_res}
            executed_stages.append(st6)
            self._emit_progress(ch, st6, "completed", stages_out[st6])

        # Stage 7: 7_seal_and_receipt
        st7 = "7_seal_and_receipt"
        receipts_dir = self.ctx.state_dir / "receipts"
        ensure_safe_dir(receipts_dir, mode=0o700, boundary_root=self.ctx.state_dir)
        receipt_path = receipts_dir / f"{_utc_stamp()}-{ch}.json"

        locked_auth_final = lock_protected_auth_files(self.ctx)
        receipt_payload: dict[str, Any] = {
            "schema_version": "1.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "ok": True,
            "harness": ch,
            "agent": ch,
            "profile": self.profile,
            "local_model": self.local_model if self.profile == "local-gemma" else None,
            "local_gemma_profile_path": stages_out[st5].get("local_gemma_profile_path"),
            "offline": self.offline,
            "resumed": self.resume,
            "repo_root": str(self.ctx.repo_root),
            "home_dir": str(self.ctx.home_dir),
            "state_dir": str(self.ctx.state_dir),
            "forensic_bundle": stages_out[st2].get("bundle_dir"),
            "forensic_manifest": stages_out[st2].get("manifest_path"),
            "quarantine_manifest": stages_out[st4].get("quarantine_manifest"),
            "quarantined_count": stages_out[st4].get("quarantined_count", 0),
            "locked_auth_files": locked_auth_final,
            "executed_stages": executed_stages + [st7],
            "skipped_stages": skipped_stages,
            "stages": {
                **stages_out,
                st7: {
                    "ok": True,
                    "status": "completed",
                    "resumed": False,
                    "receipt_path": str(receipt_path),
                },
            },
        }
        receipt_sha = sha256_bytes(dump_json(receipt_payload, sort_keys=True).encode("utf-8"))
        receipt_payload["receipt_sha256"] = receipt_sha
        receipt_payload["stages"][st7]["receipt_sha256"] = receipt_sha

        atomic_write_text(
            receipt_path,
            dump_json(receipt_payload),
            mode=0o600,
            boundary_root=self.ctx.state_dir,
        )

        st7_detail = {
            "ok": True,
            "receipt_path": str(receipt_path),
            "receipt_sha256": receipt_sha,
        }
        self.journal.record_stage(
            ch, st7, status="completed", detail=st7_detail, profile=self.profile, local_model=self.local_model
        )
        stages_out[st7] = {"status": "completed", "resumed": False, **st7_detail}
        executed_stages.append(st7)
        self._emit_progress(ch, st7, "completed", stages_out[st7])

        return {
            "ok": True,
            "harness": ch,
            "agent": ch,
            "profile": self.profile,
            "local_model": self.local_model if self.profile == "local-gemma" else None,
            "local_gemma_profile_path": stages_out[st5].get("local_gemma_profile_path"),
            "forensic_bundle": stages_out[st2].get("bundle_dir"),
            "forensic_manifest": stages_out[st2].get("manifest_path"),
            "quarantine_manifest": stages_out[st4].get("quarantine_manifest"),
            "quarantined": stages_out[st4].get("quarantined", []),
            "locked_auth_files": locked_auth_final,
            "receipt_path": str(receipt_path),
            "receipt_sha256": receipt_sha,
            "receipt": receipt_payload,
            "executed_stages": executed_stages,
            "skipped_stages": skipped_stages,
            "resumed_stages": skipped_stages,
            "stages": stages_out,
        }

    def remediate_agent(self, harness: str) -> dict[str, Any]:
        return self._remediate_single_harness(harness)

    remediate_harness = remediate_agent

    def run(
        self,
        harnesses: set[str] | list[str] | tuple[str, ...] | str | None = None,
        *,
        agent: str | None = None,
        agents: list[str] | set[str] | None = None,
        profile: str | None = None,
        local_model: str | None = None,
        offline: bool | None = None,
        quiesce: bool | None = None,
        resume: bool | None = None,
        from_backup: str | Path | None = None,
        project_dir: str | Path | None = None,
    ) -> dict[str, Any]:
        if profile is not None:
            if profile not in VALID_PROFILES:
                raise ValueError(f"Unsupported profile {profile!r}; choose from {VALID_PROFILES}")
            self.profile = profile
        if local_model is not None:
            self.local_model = local_model
        if offline is not None:
            self.offline = bool(offline)
        if quiesce is not None:
            self.quiesce = bool(quiesce)
        if resume is not None:
            self.resume = bool(resume)
        if from_backup is not None:
            self.from_backup = from_backup
        if project_dir is not None:
            self.project_dir = Path(project_dir).expanduser().resolve()
            self.ctx = RuntimeContext(
                repo_root=self.ctx.repo_root,
                home_dir=self.ctx.home_dir,
                state_dir=self.ctx.state_dir,
                runtime_dir=self.ctx.runtime_dir,
                project_dir=self.project_dir,
                grok_flavor=self.ctx.grok_flavor,
                require_signed=self.ctx.require_signed,
            )

        raw_h = harnesses if harnesses is not None else (agents if agents is not None else agent)
        if raw_h is not None:
            self.harnesses = normalize_remediation_harnesses(raw_h, repo_root=self.ctx.repo_root)

        per_agent: dict[str, dict[str, Any]] = {}
        receipt_paths: list[str] = []
        receipts: list[dict[str, Any]] = []

        for h in self.harnesses:
            res = self._remediate_single_harness(h)
            per_agent[h] = res
            if res.get("receipt_path"):
                receipt_paths.append(str(res["receipt_path"]))
            if isinstance(res.get("receipt"), dict):
                receipts.append(res["receipt"])

        first = per_agent[self.harnesses[0]] if len(self.harnesses) == 1 else {}
        return {
            "ok": all(r.get("ok", False) for r in per_agent.values()),
            "harnesses": list(self.harnesses),
            "agents": list(self.harnesses),
            "profile": self.profile,
            "local_model": self.local_model if self.profile == "local-gemma" else None,
            "offline": self.offline,
            "resumed": self.resume,
            "journal_path": str(self.journal.path),
            "receipt_paths": receipt_paths,
            "receipts": receipts,
            "results": per_agent,
            # Convenience top-level fields when a single harness is remediated:
            "harness": first.get("harness", self.harnesses[0] if self.harnesses else None),
            "agent": first.get("agent", self.harnesses[0] if self.harnesses else None),
            "stages": first.get("stages", {}),
            "executed_stages": first.get("executed_stages", []),
            "skipped_stages": first.get("skipped_stages", []),
            "resumed_stages": first.get("resumed_stages", []),
            "forensic_bundle": first.get("forensic_bundle"),
            "forensic_manifest": first.get("forensic_manifest"),
            "quarantine_manifest": first.get("quarantine_manifest"),
            "quarantined": first.get("quarantined", []),
            "locked_auth_files": first.get("locked_auth_files", []),
            "local_gemma_profile_path": first.get("local_gemma_profile_path"),
            "receipt_path": first.get("receipt_path", receipt_paths[0] if receipt_paths else None),
            "receipt_sha256": first.get("receipt_sha256"),
            "receipt": first.get("receipt"),
        }


def get_remediation_status(ctx: RuntimeContext) -> dict[str, Any]:
    """Return current remediation journal, recent receipts, forensic bundles, and live process audit."""
    journal = RemediationJournal(ctx)
    receipts_dir = ctx.state_dir / "receipts"
    recent_receipts: list[str] = []
    if receipts_dir.is_dir():
        recent_receipts = [str(p) for p in sorted(receipts_dir.glob("*.json"))[-10:]]

    forensics_dir = ctx.state_dir / "forensics"
    recent_forensics: list[str] = []
    if forensics_dir.is_dir():
        recent_forensics = [str(p) for p in sorted(forensics_dir.iterdir()) if p.is_dir()][-10:]

    proc_audit = audit_live_agent_processes(harnesses=None, quiesce=False)
    return {
        "ok": True,
        "journal_path": str(journal.path),
        "journal_exists": journal.path.exists(),
        "journal": journal.to_dict(),
        "recent_receipts": recent_receipts,
        "recent_forensics": recent_forensics,
        "live_process_audit": proc_audit,
    }


def run_remediation(
    ctx: RuntimeContext,
    harnesses: set[str] | list[str] | tuple[str, ...] | str | None = None,
    *,
    profile: str = "canonical",
    local_model: str = DEFAULT_LOCAL_MODEL,
    offline: bool = True,
    quiesce: bool = False,
    resume: bool = False,
    from_backup: str | Path | None = None,
    project_dir: str | Path | None = None,
    progress_callback: Callable[[str, str, str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Convenience entrypoint wrapping RemediationOrchestrator."""
    orch = RemediationOrchestrator(
        ctx,
        harnesses=harnesses,
        profile=profile,
        local_model=local_model,
        offline=offline,
        quiesce=quiesce,
        resume=resume,
        from_backup=from_backup,
        project_dir=project_dir,
        progress_callback=progress_callback,
    )
    return orch.run()
