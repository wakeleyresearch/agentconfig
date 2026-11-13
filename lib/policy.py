"""Policy enforcement, secret scanning, Unicode checks, and repository validation."""

from __future__ import annotations

import math
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .formats import (
    FormatError,
    parse_by_format,
    parse_json,
    parse_toml,
    parse_yaml_frontmatter,
    parse_yaml_subset,
)
from .paths import RuntimeContext, atomic_write_bytes


DEFAULT_POLICY: dict[str, Any] = {
    "schema_version": "1.0",
    "rules_budgets": {
        "antigravity_max_bytes": 24000,
        "antigravity_default_rules_tokens": 20000,
        "kimi_warn_bytes": 32768,
        "codex_skill_warn_bytes": 8192,
        "failsafe_max_bytes": 2048,
    },
    "hooks": {
        "max_timeout_seconds": 10,
    },
    "mcp": {
        "banned_commands": ["uvx"],
        "banned_command_patterns": [
            r"(?:^|\s)npx\s+(?:-y|--yes)(?:\s|$)",
            r"(?:^|\s)uvx(?:\s|$)",
            r"@latest(?:\b|$|\s|\"|')",
            r"\b(?:curl|wget)\b[^|]*\|\s*(?:sh|bash|zsh)\b",
        ],
        "banned_url_schemes": ["http://"],
        "allow_http_localhost": False,
        "sse_disallowed_harnesses": ["antigravity", "goose"],
        "banned_literal_credential_keys": [
            "token",
            "api_key",
            "apikey",
            "secret",
            "password",
            "passwd",
            "authorization",
            "x-api-key",
            "bearer_token",
            "client_secret",
            "access_token",
            "refresh_token",
            "private_key",
        ],
        "banned_header_names": [
            "authorization",
            "x-api-key",
            "proxy-authorization",
        ],
        "disallow_url_userinfo": True,
    },
    "env_overrides": {
        "base_url_var_suffixes": ["_BASE_URL", "_API_BASE", "_API_URL"],
        "allowed_base_urls": {
            "ANTHROPIC_BASE_URL": ["https://api.anthropic.com"],
            "OPENAI_BASE_URL": ["https://api.openai.com"],
            "GEMINI_API_BASE_URL": ["https://generativelanguage.googleapis.com"],
            "KIMI_BASE_URL": ["https://api.moonshot.cn", "https://api.moonshot.ai"],
            "XAI_BASE_URL": ["https://api.x.ai"],
        },
    },
    "local_model_loopback": {
        "enabled": True,
        "allowed_providers": ["ollama", "litert-lm", "gemma"],
        "allowed_hosts": ["127.0.0.1", "localhost"],
        "allowed_ports": [11434, 8080],
        "allowed_origins": [
            "http://127.0.0.1:11434",
            "http://localhost:11434",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
        ],
        "banned_hosts": ["0.0.0.0", "::", "*"],
    },
    "unicode": {
        "ban_invisible_ranges": [
            ["0x200B", "0x200F"],
            ["0x202A", "0x202E"],
            ["0x2060", "0x206F"],
            ["0xFEFF", "0xFEFF"],
            ["0xE0000", "0xE007F"],
        ],
    },
    "codex": {
        "banned_top_level_keys": ["profile", "profiles"],
        "banned_approval_policies": ["untrusted"],
    },
    "secrets": {
        "regex_patterns": [
            {"name": "openai_sk", "pattern": r"\bsk-(?:proj-|svcacct-|ant-api\d*-)?[A-Za-z0-9_-]{20,}\b"},
            {"name": "github_pat", "pattern": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"},
            {"name": "github_fine_pat", "pattern": r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"},
            {"name": "google_api_key", "pattern": r"\bAIza[0-9A-Za-z_-]{35}\b"},
            {"name": "aws_access_key", "pattern": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"},
            {"name": "age_secret_key", "pattern": "AGE-SECRET-" + r"KEY-1[0-9A-Z]{20,}"},
            {"name": "pem_private_key", "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE " + r"KEY-----"},
            {"name": "bearer_literal", "pattern": r"(?i)Bearer\s+(?!\$\{?[A-Z0-9_]+\}?)[A-Za-z0-9._\-+/=]{16,}"},
        ],
        "entropy_threshold": 4.2,
        "entropy_min_length": 20,
        "placeholder_allowlist_patterns": [
            r"^\$\{[A-Za-z0-9_:-]+\}$",
            r"^\$env:[A-Za-z0-9_]+$",
            r"^\{env:[A-Za-z0-9_]+\}$",
            r"^\$\{input:[A-Za-z0-9_-]+\}$",
        ],
    },
    "auth_preservation_paths": [
        "~/.gemini/antigravity-cli/antigravity-oauth-token",
        "~/.gemini/oauth_creds.json",
        "~/.gemini/google_accounts.json",
        "~/.config/gh/hosts.yml",
        "~/.claude/.credentials.json",
        "~/.codex/auth.json",
        "~/.kimi-code/credentials",
        "~/.grok/auth.json",
        "~/.grok/mcp_credentials.json",
        "~/.local/share/keyrings",
    ],
}

SAFE_CREDENTIAL_REF_KEYS = frozenset(
    {
        "secret_ref",
        "secret_refs",
        "bearertokenenvvar",
        "bearer_token_env_var",
        "env_var",
        "token_env_var",
        "api_key_env",
    }
)

_HEX_RE = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{32,128}$")
_SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_AT_IMPORT_RE = re.compile(r"(?:^|\s)@(?:[./~]|https?://|\[[^\]]+\]\([^)]+\))", re.MULTILINE)
_SHELL_EXFIL_RE = re.compile(
    r"(?:curl\s+[^|\n]*\|\s*(?:sh|bash|zsh)|wget\s+[^|\n]*\|\s*(?:sh|bash|zsh)|base64\s+-d\s*\|)",
    re.IGNORECASE,
)


@dataclass
class Finding:
    """Single validation, policy, or audit finding."""

    severity: str  # "error" | "warning"
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


@dataclass
class ValidationReport:
    """Aggregated findings across validation targets."""

    findings: list[Finding] = field(default_factory=list)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "warning"]

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0

    def add(self, severity: str, code: str, path: str, message: str) -> None:
        self.findings.append(Finding(severity=severity, code=code, path=path, message=message))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k] = _deep_merge(merged[k], v)
        else:
            merged[k] = v
    return merged


def load_security_policy(repo_root: Path) -> dict[str, Any]:
    """Load policy/security-policy.json merged atop defaults."""
    policy_path = repo_root / "policy" / "security-policy.json"
    if not policy_path.exists():
        return dict(DEFAULT_POLICY)
    raw = parse_json(policy_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise FormatError("policy/security-policy.json root must be a JSON object")
    return _deep_merge(DEFAULT_POLICY, raw)


def load_manifests_lock(repo_root: Path) -> dict[str, Any]:
    """Load policy/manifests.lock.json."""
    lock_path = repo_root / "policy" / "manifests.lock.json"
    if not lock_path.exists():
        return {"schema_version": "1.0", "servers": {}}
    raw = parse_json(lock_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise FormatError("policy/manifests.lock.json root must be a JSON object")
    return raw


def _parse_codepoint(raw: str | int) -> int:
    if isinstance(raw, int):
        return raw
    return int(str(raw), 16) if str(raw).lower().startswith("0x") else int(str(raw))


def scan_invisible_unicode(text: str, path: str, policy: dict[str, Any] | None = None) -> list[Finding]:
    """Detect hidden Unicode bidi/zero-width/tag/BOM characters."""
    pol = policy or DEFAULT_POLICY
    raw_ranges = pol.get("unicode", {}).get("ban_invisible_ranges", DEFAULT_POLICY["unicode"]["ban_invisible_ranges"])
    ranges = [(_parse_codepoint(lo), _parse_codepoint(hi)) for lo, hi in raw_ranges]
    findings: list[Finding] = []
    seen_codes: set[int] = set()
    for idx, ch in enumerate(text):
        cp = ord(ch)
        for lo, hi in ranges:
            if lo <= cp <= hi:
                if cp not in seen_codes:
                    seen_codes.add(cp)
                    findings.append(
                        Finding(
                            severity="error",
                            code="INVISIBLE_UNICODE",
                            path=path,
                            message=f"Forbidden invisible/control Unicode U+{cp:04X} at offset {idx}",
                        )
                    )
                break
    return findings


def shannon_entropy(token: str) -> float:
    """Compute Shannon entropy (bits per character)."""
    if not token:
        return 0.0
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_placeholder_value(val: str, policy: dict[str, Any] | None = None) -> bool:
    """Return True if string is a safe variable placeholder rather than a literal secret."""
    s = val.strip()
    if not s:
        return True
    pol = policy or DEFAULT_POLICY
    patterns = pol.get("secrets", {}).get(
        "placeholder_allowlist_patterns",
        DEFAULT_POLICY["secrets"]["placeholder_allowlist_patterns"],
    )
    return any(re.match(pat, s) for pat in patterns)


def _is_non_secret_token(tok: str) -> bool:
    if _HEX_RE.match(tok):
        return True
    if tok.startswith(("https://", "http://", "/", "~/", "./", "../", "agentconfig/")):
        return True
    if "/" in tok and tok.count("/") >= 2 and "=" not in tok:
        return True
    if "age1" in tok and tok.startswith("age1"):
        # age1... is an age PUBLIC recipient key, never a secret key.
        return True
    if tok.startswith(("ssh-ed25519", "AAAA")):
        return True
    # Pure ASCII-letter CamelCase schema identifiers (no digits/punctuation) are not secrets.
    if tok.isalpha():
        return True
    return False


def scan_secrets(
    text: str,
    path: str = "",
    policy: dict[str, Any] | None = None,
) -> list[Finding]:
    """Scan text using regex patterns plus Shannon entropy fallback."""
    pol = policy or DEFAULT_POLICY
    sec_cfg = pol.get("secrets", DEFAULT_POLICY["secrets"])
    findings: list[Finding] = []
    seen_keys: set[tuple[str, str]] = set()

    for entry in sec_cfg.get("regex_patterns", []):
        name = entry.get("name", "secret_regex")
        pat = entry.get("pattern", "")
        if not pat:
            continue
        for match in re.finditer(pat, text):
            snippet = match.group(0)
            if is_placeholder_value(snippet, pol):
                continue
            key = (name, snippet[:12])
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(
                    Finding(
                        severity="error",
                        code="SECRET_DETECTED",
                        path=path,
                        message=f"Matched secret pattern '{name}'",
                    )
                )

    threshold = float(sec_cfg.get("entropy_threshold", 4.2))
    min_len = int(sec_cfg.get("entropy_min_length", 20))
    for line in text.splitlines():
        lower = line.lower()
        if any(marker in lower for marker in ("sha256", "checksum", "digest", "integrity", "tools_list_sha256", "package_sha256")):
            continue
        for raw_tok in re.findall(r"[A-Za-z0-9_+/=-]{20,}", line):
            tok = raw_tok.strip("'\"")
            if len(tok) < min_len:
                continue
            if is_placeholder_value(tok, pol) or _is_non_secret_token(tok):
                continue
            if shannon_entropy(tok) >= threshold:
                key = ("high_entropy", tok[:8])
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(
                        Finding(
                            severity="error",
                            code="HIGH_ENTROPY_SECRET",
                            path=path,
                            message=f"High-entropy token detected (len={len(tok)}, H>={threshold:.1f})",
                        )
                    )
    return findings


def run_gitleaks_staged(repo_root: Path) -> list[Finding]:
    """Run gitleaks protect --staged if installed; returns findings on match."""
    exe = shutil.which("gitleaks")
    if not exe:
        return []
    proc = subprocess.run(
        [exe, "protect", "--staged", "--no-banner", "--redact"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return []
    msg = (proc.stderr or proc.stdout or "gitleaks detected staged secrets").strip().splitlines()[0]
    return [Finding(severity="error", code="GITLEAKS_STAGED", path="<staged>", message=msg)]


def check_local_model_endpoint(
    url_val: str,
    provider: str = "ollama",
    policy: dict[str, Any] | None = None,
    location: str = "",
    allow_portless_origin: bool = False,
) -> list[Finding]:
    """Validate a local-model loopback URL or host:port against local_model_loopback policy."""
    findings: list[Finding] = []
    pol = policy or DEFAULT_POLICY
    lm_cfg = pol.get("local_model_loopback", DEFAULT_POLICY["local_model_loopback"])
    if not lm_cfg.get("enabled", True):
        findings.append(
            Finding(
                severity="error",
                code="LOCAL_MODEL_LOOPBACK_DISABLED",
                path=location,
                message=f"Local model loopback policy disabled for {url_val!r}",
            )
        )
        return findings

    allowed_providers = {str(p).strip().lower() for p in lm_cfg.get("allowed_providers", ["ollama", "litert-lm", "gemma"])}
    allowed_providers.add("litert")
    allowed_hosts = {str(h).strip().lower() for h in lm_cfg.get("allowed_hosts", ["127.0.0.1", "localhost"])}
    allowed_ports = {int(p) for p in lm_cfg.get("allowed_ports", [11434, 8080])}
    banned_hosts = {str(b).strip().lower() for b in lm_cfg.get("banned_hosts", ["0.0.0.0", "::", "*"])}

    norm_provider = provider.strip().lower()
    if norm_provider not in allowed_providers:
        findings.append(
            Finding(
                severity="error",
                code="UNAUTHORIZED_LOCAL_MODEL_PROVIDER",
                path=location,
                message=f"Local HTTP loopback is not allowed for provider {provider!r}: {url_val!r}",
            )
        )
        return findings

    raw = url_val.strip()
    if not raw:
        findings.append(
            Finding(
                severity="error",
                code="EMPTY_LOCAL_MODEL_URL",
                path=location,
                message="Empty local model endpoint URL",
            )
        )
        return findings

    if "://" in raw:
        parsed = urlparse(raw)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()
        try:
            port = parsed.port
        except ValueError:
            findings.append(
                Finding(
                    severity="error",
                    code="INVALID_LOCAL_MODEL_URL",
                    path=location,
                    message=f"Invalid port in local model URL: {url_val!r}",
                )
            )
            return findings
        if scheme not in ("http", "https"):
            findings.append(
                Finding(
                    severity="error",
                    code="INVALID_LOCAL_MODEL_SCHEME",
                    path=location,
                    message=f"Unsupported scheme {scheme!r} for local model URL: {url_val!r}",
                )
            )
            return findings
        if parsed.username or parsed.password:
            findings.append(
                Finding(
                    severity="error",
                    code="URL_USERINFO_CREDENTIAL",
                    path=location,
                    message=f"Credentials in local model URL userinfo are forbidden: {url_val!r}",
                )
            )
    else:
        # Handle bare host or host:port (e.g. OLLAMA_HOST=127.0.0.1:11434)
        host_part, sep, port_part = raw.rpartition(":")
        if sep and port_part.isdigit():
            host = host_part.strip("[]").lower()
            port = int(port_part)
        else:
            host = raw.strip("[]").lower()
            port = None

    if host in banned_hosts or raw.lower().startswith(("http://0.0.0.0", "https://0.0.0.0", "0.0.0.0")):
        findings.append(
            Finding(
                severity="error",
                code="INSECURE_LOCAL_MODEL_BIND",
                path=location,
                message=f"Wildcard bind {raw!r} is forbidden for local model provider {provider!r}",
            )
        )
        return findings

    if host not in allowed_hosts:
        findings.append(
            Finding(
                severity="error",
                code="UNAUTHORIZED_LOCAL_MODEL_URL",
                path=location,
                message=f"Non-loopback host {host!r} is forbidden for local model provider {provider!r}: {url_val!r}",
            )
        )
        return findings

    if port is None:
        if not allow_portless_origin:
            findings.append(
                Finding(
                    severity="error",
                    code="UNAUTHORIZED_LOCAL_MODEL_PORT",
                    path=location,
                    message=f"Explicit loopback port ({sorted(allowed_ports)}) required for local model URL: {url_val!r}",
                )
            )
    elif port not in allowed_ports:
        findings.append(
            Finding(
                severity="error",
                code="UNAUTHORIZED_LOCAL_MODEL_PORT",
                path=location,
                message=f"Port {port} not in allowed local model ports {sorted(allowed_ports)}: {url_val!r}",
            )
        )

    return findings


validate_local_model_url = check_local_model_endpoint


def is_allowed_local_model_url(
    url_val: str,
    provider: str = "ollama",
    policy: dict[str, Any] | None = None,
) -> bool:
    """Return True iff url_val is an allowed loopback endpoint for provider."""
    return len(check_local_model_endpoint(url_val, provider=provider, policy=policy)) == 0


def check_local_model_config(
    data: dict[str, Any],
    harness: str = "",
    policy: dict[str, Any] | None = None,
    location: str = "",
) -> list[Finding]:
    """Validate local-model provider configurations across Codex, OpenCode, Gemini CLI, Goose, LiteRT-LM, and Ollama."""
    findings: list[Finding] = []
    pol = policy or DEFAULT_POLICY
    norm_h = _normalize_harness(harness) if harness else ""

    # 1. Codex [model_providers.<name>]
    model_providers = data.get("model_providers")
    if isinstance(model_providers, dict):
        for prov_name, prov_cfg in model_providers.items():
            if not isinstance(prov_cfg, dict):
                continue
            burl = prov_cfg.get("base_url") or prov_cfg.get("url")
            if isinstance(burl, str) and burl.strip():
                findings.extend(
                    check_local_model_endpoint(
                        burl.strip(),
                        provider=str(prov_name),
                        policy=pol,
                        location=f"{location}#model_providers.{prov_name}",
                    )
                )

    # 2. OpenCode V2 provider.<name>
    oc_providers = data.get("provider")
    if isinstance(oc_providers, dict):
        for prov_name, prov_cfg in oc_providers.items():
            if not isinstance(prov_cfg, dict):
                continue
            urls_to_check: list[str] = []
            for k in ("base_url", "baseURL", "url"):
                if isinstance(prov_cfg.get(k), str) and prov_cfg[k].strip():
                    urls_to_check.append(prov_cfg[k].strip())
            opts = prov_cfg.get("options")
            if isinstance(opts, dict):
                for k in ("baseURL", "base_url", "url"):
                    if isinstance(opts.get(k), str) and opts[k].strip():
                        urls_to_check.append(opts[k].strip())
            for u in urls_to_check:
                findings.extend(
                    check_local_model_endpoint(
                        u,
                        provider=str(prov_name),
                        policy=pol,
                        location=f"{location}#provider.{prov_name}",
                    )
                )

    # 3. Gemini CLI experimental.gemma
    exp = data.get("experimental")
    if isinstance(exp, dict) and isinstance(exp.get("gemma"), dict):
        gemma_cfg = exp["gemma"]
        runtime = str(gemma_cfg.get("runtime") or "litert-lm")
        for k in ("endpoint", "base_url", "url"):
            if isinstance(gemma_cfg.get(k), str) and gemma_cfg[k].strip():
                findings.extend(
                    check_local_model_endpoint(
                        gemma_cfg[k].strip(),
                        provider=runtime,
                        policy=pol,
                        location=f"{location}#experimental.gemma.{k}",
                    )
                )

    # 4. LiteRT-LM config (either top-level or inside base_settings)
    litert_blocks: list[dict[str, Any]] = []
    if norm_h == "litert-lm":
        if isinstance(data.get("base_settings"), dict):
            litert_blocks.append(data["base_settings"])
        else:
            litert_blocks.append(data)
    for lb in litert_blocks:
        if lb.get("telemetry") is True:
            findings.append(
                Finding(
                    severity="error",
                    code="LITERT_TELEMETRY_ENABLED",
                    path=location,
                    message="LiteRT-LM telemetry=true is forbidden",
                )
            )
        if lb.get("allow_remote") is True:
            findings.append(
                Finding(
                    severity="error",
                    code="LITERT_REMOTE_ENABLED",
                    path=location,
                    message="LiteRT-LM allow_remote=true is forbidden",
                )
            )
        if "host" in lb:
            h_val = str(lb["host"]).strip()
            p_val = lb.get("port", 8080)
            synth = h_val if "://" in h_val else f"http://{h_val}:{p_val}"
            findings.extend(
                check_local_model_endpoint(
                    synth,
                    provider="litert-lm",
                    policy=pol,
                    location=f"{location}#host",
                )
            )
        for k in ("endpoint", "base_url", "url"):
            if isinstance(lb.get(k), str) and lb[k].strip():
                findings.extend(
                    check_local_model_endpoint(
                        lb[k].strip(),
                        provider="litert-lm",
                        policy=pol,
                        location=f"{location}#{k}",
                    )
                )

    # 5. Ollama / Goose env settings (either top-level or inside base_settings)
    ollama_blocks: list[dict[str, Any]] = [data]
    if isinstance(data.get("base_settings"), dict):
        ollama_blocks.append(data["base_settings"])
    for ob in ollama_blocks:
        if "OLLAMA_HOST" in ob and ob["OLLAMA_HOST"] is not None:
            findings.extend(
                check_local_model_endpoint(
                    str(ob["OLLAMA_HOST"]).strip(),
                    provider="ollama",
                    policy=pol,
                    location=f"{location}#OLLAMA_HOST",
                )
            )
        if "OLLAMA_ORIGINS" in ob and ob["OLLAMA_ORIGINS"] is not None:
            for orig in str(ob["OLLAMA_ORIGINS"]).split(","):
                orig_s = orig.strip()
                if not orig_s:
                    continue
                findings.extend(
                    check_local_model_endpoint(
                        orig_s,
                        provider="ollama",
                        policy=pol,
                        location=f"{location}#OLLAMA_ORIGINS",
                        allow_portless_origin=True,
                    )
                )

    # 6. Top-level base_url / endpoint / url when harness is ollama / litert-lm / gemma
    if norm_h in ("ollama", "litert-lm", "gemma"):
        for k in ("base_url", "baseURL", "endpoint", "url"):
            if isinstance(data.get(k), str) and data[k].strip():
                findings.extend(
                    check_local_model_endpoint(
                        data[k].strip(),
                        provider=norm_h,
                        policy=pol,
                        location=f"{location}#{k}",
                    )
                )

    return findings


def _check_base_url_env(
    env_map: dict[str, Any],
    location: str,
    policy: dict[str, Any],
) -> list[Finding]:
    findings: list[Finding] = []
    env_cfg = policy.get("env_overrides", {})
    suffixes = tuple(env_cfg.get("base_url_var_suffixes", ["_BASE_URL", "_API_BASE", "_API_URL"]))
    allowed = env_cfg.get("allowed_base_urls", {})

    for var_name, raw_val in env_map.items():
        if not isinstance(var_name, str):
            continue
        upper = var_name.upper()
        val = str(raw_val) if raw_val is not None else ""
        if is_placeholder_value(val, policy):
            continue
        if upper == "OLLAMA_HOST":
            findings.extend(check_local_model_endpoint(val, provider="ollama", policy=policy, location=f"{location}:{var_name}"))
        elif upper == "OLLAMA_ORIGINS":
            for orig in val.split(","):
                if orig.strip():
                    findings.extend(
                        check_local_model_endpoint(
                            orig.strip(),
                            provider="ollama",
                            policy=policy,
                            location=f"{location}:{var_name}",
                            allow_portless_origin=True,
                        )
                    )
        elif upper.startswith(("OLLAMA_", "LITERT_LM_", "LITERT_", "GEMMA_")) and upper.endswith(suffixes):
            prov = "ollama" if upper.startswith("OLLAMA_") else ("gemma" if upper.startswith("GEMMA_") else "litert-lm")
            findings.extend(check_local_model_endpoint(val, provider=prov, policy=policy, location=f"{location}:{var_name}"))
        elif upper.endswith(suffixes):
            allowed_prefixes = allowed.get(upper, [])
            if not allowed_prefixes or not any(val.startswith(prefix) for prefix in allowed_prefixes):
                findings.append(
                    Finding(
                        severity="error",
                        code="UNAUTHORIZED_BASE_URL",
                        path=location,
                        message=f"Unauthorized base URL override {var_name}={val!r}",
                    )
                )
        for sec in scan_secrets(val, path=f"{location}:{var_name}", policy=policy):
            findings.append(sec)
    return findings


def _check_url(
    url_val: str,
    harness: str,
    location: str,
    policy: dict[str, Any],
    explicit_transport: str = "",
) -> list[Finding]:
    findings: list[Finding] = []
    mcp_cfg = policy.get("mcp", {})
    allow_localhost = bool(mcp_cfg.get("allow_http_localhost", False))
    sse_disallowed = {h.lower() for h in mcp_cfg.get("sse_disallowed_harnesses", ["antigravity", "goose"])}

    parsed = urlparse(url_val)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    norm_harness = _normalize_harness(harness)

    if norm_harness in ("ollama", "litert-lm", "gemma"):
        lm_findings = check_local_model_endpoint(url_val, provider=norm_harness, policy=policy, location=location)
        findings.extend(lm_findings)
    elif scheme == "http":
        if not (allow_localhost and host in ("localhost", "127.0.0.1", "::1")):
            findings.append(
                Finding(
                    severity="error",
                    code="INSECURE_HTTP_MCP",
                    path=location,
                    message=f"Plain http:// remote MCP URL forbidden: {url_val!r}",
                )
            )
    if mcp_cfg.get("disallow_url_userinfo", True) and (parsed.username or parsed.password):
        findings.append(
            Finding(
                severity="error",
                code="URL_USERINFO_CREDENTIAL",
                path=location,
                message=f"Credentials in URL userinfo are forbidden: {url_val!r}",
            )
        )

    is_sse = (
        explicit_transport.lower() == "sse"
        or parsed.path.lower().endswith("/sse")
        or "/sse/" in parsed.path.lower()
    )
    if is_sse and norm_harness in sse_disallowed:
        findings.append(
            Finding(
                severity="error",
                code="UNSUPPORTED_SSE_TRANSPORT",
                path=location,
                message=f"Legacy /sse MCP transport is forbidden for harness '{norm_harness}': {url_val!r}",
            )
        )
    return findings


def _normalize_harness(harness: str) -> str:
    h = harness.strip().lower()
    aliases = {
        "gemini-cli": "gemini",
        "claude-code": "claude",
        "kimi-code": "kimi",
        "xai-grok": "grok",
        "grok-build": "grok",
        "litert": "litert-lm",
        "litert-lm": "litert-lm",
        "ollama": "ollama",
    }
    return aliases.get(h, h)


def check_mcp_server_entry(
    name: str,
    entry: dict[str, Any],
    harness: str,
    policy: dict[str, Any],
    location: str = "",
) -> list[Finding]:
    """Validate a single MCP server configuration block."""
    findings: list[Finding] = []
    loc = f"{location}#mcp:{name}" if location else f"mcp:{name}"
    mcp_cfg = policy.get("mcp", {})
    banned_cmds = {c.lower() for c in mcp_cfg.get("banned_commands", ["uvx"])}
    banned_patterns = [re.compile(p, re.IGNORECASE) for p in mcp_cfg.get("banned_command_patterns", [])]
    banned_keys = {k.lower() for k in mcp_cfg.get("banned_literal_credential_keys", [])}
    banned_headers = {k.lower() for k in mcp_cfg.get("banned_header_names", [])}

    # Normalize command + args (handles str, list[str], Goose cmd+args).
    cmd_val = entry.get("command") or entry.get("cmd")
    args_val = entry.get("args", [])
    tokens: list[str] = []
    if isinstance(cmd_val, list):
        tokens.extend(str(x) for x in cmd_val)
    elif isinstance(cmd_val, str) and cmd_val.strip():
        tokens.extend(cmd_val.split())
    if isinstance(args_val, list):
        tokens.extend(str(x) for x in args_val)
    elif isinstance(args_val, str) and args_val.strip():
        tokens.extend(args_val.split())

    if tokens:
        cmd_base = Path(tokens[0]).name.lower()
        if cmd_base in banned_cmds:
            findings.append(
                Finding(
                    severity="error",
                    code="BANNED_MCP_COMMAND",
                    path=loc,
                    message=f"Banned unpinned MCP command '{cmd_base}'",
                )
            )
        joined = " ".join(tokens)
        for pat in banned_patterns:
            if pat.search(joined):
                findings.append(
                    Finding(
                        severity="error",
                        code="BANNED_MCP_PATTERN",
                        path=loc,
                        message=f"Banned MCP invocation matching {pat.pattern!r}: {joined!r}",
                    )
                )
        for i, tok in enumerate(tokens):
            if tok in ("-H", "--header") and i + 1 < len(tokens):
                hdr_arg = tokens[i + 1]
                if not is_placeholder_value(hdr_arg, policy):
                    findings.append(
                        Finding(
                            severity="error",
                            code="LITERAL_HEADER_ARG",
                            path=loc,
                            message=f"Literal CLI header argument forbidden: {tok} ...",
                        )
                    )

    transport = str(entry.get("type") or entry.get("transport") or "")
    for url_key in ("url", "httpUrl", "serverUrl", "uri"):
        raw_url = entry.get(url_key)
        if isinstance(raw_url, str) and raw_url.strip():
            findings.extend(_check_url(raw_url.strip(), harness, loc, policy, explicit_transport=transport))

    if transport.lower() == "sse" and _normalize_harness(harness) in {
        h.lower() for h in mcp_cfg.get("sse_disallowed_harnesses", ["antigravity", "goose"])
    }:
        findings.append(
            Finding(
                severity="error",
                code="UNSUPPORTED_SSE_TRANSPORT",
                path=loc,
                message=f"SSE transport forbidden for harness '{harness}'",
            )
        )

    # Check literal credential keys anywhere in the entry dict.
    for key, val in entry.items():
        lk = str(key).lower()
        if lk in SAFE_CREDENTIAL_REF_KEYS:
            continue
        if lk in banned_keys and isinstance(val, str) and val.strip() and not is_placeholder_value(val, policy):
            findings.append(
                Finding(
                    severity="error",
                    code="LITERAL_CREDENTIAL_KEY",
                    path=loc,
                    message=f"Literal credential key '{key}' is forbidden in declarative MCP config",
                )
            )

    for hdr_key in ("headers", "http_headers"):
        hdrs = entry.get(hdr_key)
        if isinstance(hdrs, dict):
            for hname, hval in hdrs.items():
                if not isinstance(hval, str):
                    continue
                if str(hname).lower() in banned_headers and not is_placeholder_value(hval, policy):
                    findings.append(
                        Finding(
                            severity="error",
                            code="LITERAL_CREDENTIAL_HEADER",
                            path=loc,
                            message=f"Literal auth header '{hname}' forbidden (use secret_ref / mcp-secret-exec)",
                        )
                    )

    for env_key in ("env", "envs", "environment"):
        env_map = entry.get(env_key)
        if isinstance(env_map, dict):
            findings.extend(_check_base_url_env(env_map, loc, policy))

    return findings


def check_mcp_config_object(
    data: dict[str, Any],
    harness: str,
    policy: dict[str, Any],
    location: str = "",
) -> list[Finding]:
    """Check all 5 MCP schema roots and top-level security settings in a parsed config."""
    findings: list[Finding] = []
    if data.get("enableAllProjectMcpServers") is True:
        findings.append(
            Finding(
                severity="error",
                code="AUTO_TRUST_PROJECT_MCP",
                path=location,
                message="enableAllProjectMcpServers=true is forbidden (CVE-2025-59536 / CVE-2026-21852)",
            )
        )

    if isinstance(data.get("env"), dict):
        findings.extend(_check_base_url_env(data["env"], location, policy))

    candidates: list[dict[str, Any]] = []
    for root_key in ("mcpServers", "servers", "mcp_servers", "extensions"):
        block = data.get(root_key)
        if isinstance(block, dict):
            candidates.append(block)
    mcp_block = data.get("mcp")
    if isinstance(mcp_block, dict):
        if isinstance(mcp_block.get("servers"), dict):
            candidates.append(mcp_block["servers"])
        else:
            # Handle OpenCode direct mcp.<server> or registry root "servers"
            pass
    if harness == "registry" and isinstance(data.get("servers"), dict):
        # Registry format already collected via "servers" above.
        pass

    for block in candidates:
        for srv_name, srv_cfg in block.items():
            if isinstance(srv_cfg, dict):
                findings.extend(check_mcp_server_entry(str(srv_name), srv_cfg, harness, policy, location))
    findings.extend(check_local_model_config(data, harness, policy, location))
    return findings


def check_codex_config(data: dict[str, Any], policy: dict[str, Any], location: str = "") -> list[Finding]:
    """Enforce Codex CLI v0.134.0+ / v0.149.0+ compatibility and MCP checks."""
    findings: list[Finding] = []
    codex_cfg = policy.get("codex", DEFAULT_POLICY["codex"])
    for key in codex_cfg.get("banned_top_level_keys", ["profile", "profiles"]):
        if key in data:
            findings.append(
                Finding(
                    severity="error",
                    code="CODEX_DEPRECATED_PROFILES",
                    path=location,
                    message=f"Deprecated Codex key '{key}' (removed in Codex v0.134.0+) is forbidden",
                )
            )
    ap = data.get("approval_policy")
    banned_ap = {str(x).lower() for x in codex_cfg.get("banned_approval_policies", ["untrusted"])}
    lm_providers = {
        str(p).lower()
        for p in policy.get("local_model_loopback", DEFAULT_POLICY["local_model_loopback"]).get(
            "allowed_providers", ["ollama", "litert-lm", "gemma"]
        )
    }
    is_local_model_profile = (
        "local-gemma" in location.lower()
        or (
            str(data.get("model_provider") or "").strip().lower() in lm_providers
            and "profile" not in data
            and "profiles" not in data
        )
    )
    if isinstance(ap, str) and ap.lower() in banned_ap and not is_local_model_profile:
        findings.append(
            Finding(
                severity="error",
                code="CODEX_RETIRED_APPROVAL_POLICY",
                path=location,
                message=f"Retired Codex approval_policy={ap!r} (crashes v0.149.0+); use 'on-request'",
            )
        )
    # Check Codex *_base_url keys against allowed base URLs.
    base_url_env: dict[str, Any] = {}
    if isinstance(data.get("openai_base_url"), str):
        base_url_env["OPENAI_BASE_URL"] = data["openai_base_url"]
    if base_url_env:
        findings.extend(_check_base_url_env(base_url_env, location, policy))
    findings.extend(check_mcp_config_object(data, "codex", policy, location))
    return findings


def check_hooks_config(data: Any, policy: dict[str, Any], location: str = "") -> list[Finding]:
    """Validate hook timeouts and commands."""
    findings: list[Finding] = []
    max_sec = float(policy.get("hooks", {}).get("max_timeout_seconds", 10))
    banned_patterns = [re.compile(p, re.IGNORECASE) for p in policy.get("mcp", {}).get("banned_command_patterns", [])]

    def walk_hook(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk_hook(item)
        elif isinstance(node, dict):
            if "timeout" in node and isinstance(node["timeout"], (int, float)):
                # Heuristic: values >= 1000 are often ms (Copilot/Cline), values <= 600 are seconds.
                val = float(node["timeout"])
                secs = val / 1000.0 if val >= 1000 else val
                if secs > max_sec:
                    findings.append(
                        Finding(
                            severity="error",
                            code="HOOK_TIMEOUT_EXCEEDED",
                            path=location,
                            message=f"Hook timeout {node['timeout']} exceeds max {max_sec}s",
                        )
                    )
            if "timeoutMs" in node and isinstance(node["timeoutMs"], (int, float)):
                if float(node["timeoutMs"]) / 1000.0 > max_sec:
                    findings.append(
                        Finding(
                            severity="error",
                            code="HOOK_TIMEOUT_EXCEEDED",
                            path=location,
                            message=f"Hook timeoutMs {node['timeoutMs']} exceeds max {max_sec}s",
                        )
                    )
            cmd = node.get("command")
            if isinstance(cmd, str):
                for pat in banned_patterns:
                    if pat.search(cmd):
                        findings.append(
                            Finding(
                                severity="error",
                                code="BANNED_HOOK_COMMAND",
                                path=location,
                                message=f"Hook command matches banned pattern {pat.pattern!r}",
                            )
                        )
            for v in node.values():
                if isinstance(v, (dict, list)):
                    walk_hook(v)

    walk_hook(data)
    return findings


def estimate_tokens(text: str) -> int:
    """Conservative token count approximation without external tokenizers."""
    return max(len(text.split()), (len(text.encode("utf-8")) + 3) // 4)


def check_rule_text(
    text: str,
    path: str,
    policy: dict[str, Any],
    is_failsafe: bool = False,
    check_antigravity: bool = True,
    check_kimi: bool = True,
) -> list[Finding]:
    """Validate rule file budgets, invisible Unicode, secrets, and failsafe invariants."""
    findings: list[Finding] = []
    findings.extend(scan_invisible_unicode(text, path, policy))
    findings.extend(scan_secrets(text, path, policy))

    if _SHELL_EXFIL_RE.search(text):
        findings.append(
            Finding(
                severity="error",
                code="SHELL_PIPE_EXFIL_RISK",
                path=path,
                message="Unsafe curl/wget pipe or base64 decode execution pattern in rule/skill",
            )
        )

    byte_len = len(text.encode("utf-8"))
    budgets = policy.get("rules_budgets", DEFAULT_POLICY["rules_budgets"])
    if check_antigravity:
        max_bytes = int(budgets.get("antigravity_max_bytes", 24000))
        if byte_len > max_bytes:
            findings.append(
                Finding(
                    severity="error",
                    code="ANTIGRAVITY_RULE_BYTE_CAP",
                    path=path,
                    message=f"Rule size {byte_len} B exceeds Antigravity {max_bytes} B hard cap",
                )
            )
    if check_kimi:
        kimi_warn = int(budgets.get("kimi_warn_bytes", 32768))
        if byte_len > kimi_warn:
            findings.append(
                Finding(
                    severity="warning",
                    code="KIMI_AGENTS_MD_WARN",
                    path=path,
                    message=f"Rule size {byte_len} B exceeds Kimi {kimi_warn} B recommended limit",
                )
            )
    if is_failsafe:
        fs_max = int(budgets.get("failsafe_max_bytes", 2048))
        if byte_len > fs_max:
            findings.append(
                Finding(
                    severity="error",
                    code="FAILSAFE_RULE_TOO_LARGE",
                    path=path,
                    message=f"Failsafe rule size {byte_len} B exceeds {fs_max} B cap",
                )
            )
        if _AT_IMPORT_RE.search(text):
            findings.append(
                Finding(
                    severity="error",
                    code="FAILSAFE_AT_IMPORT",
                    path=path,
                    message="Failsafe rules must not contain @ file/remote imports",
                )
            )
    return findings


def check_skill_markdown(text: str, skill_dir_name: str, path: str, policy: dict[str, Any]) -> list[Finding]:
    """Validate SKILL.md against agentskills.io and security policies."""
    findings: list[Finding] = []
    findings.extend(scan_invisible_unicode(text, path, policy))
    findings.extend(scan_secrets(text, path, policy))
    if _SHELL_EXFIL_RE.search(text):
        findings.append(
            Finding(
                severity="error",
                code="UNSAFE_SKILL_PAYLOAD",
                path=path,
                message="Skill contains unsafe pipe-to-shell or base64 execution pattern",
            )
        )
    try:
        fm, _ = parse_yaml_frontmatter(text)
    except FormatError as exc:
        findings.append(Finding(severity="error", code="INVALID_YAML_FRONTMATTER", path=path, message=str(exc)))
        return findings

    if not fm:
        findings.append(
            Finding(
                severity="error",
                code="MISSING_SKILL_FRONTMATTER",
                path=path,
                message="SKILL.md requires YAML frontmatter with name and description",
            )
        )
        return findings

    name = fm.get("name")
    desc = fm.get("description")
    if not isinstance(name, str) or not _SKILL_NAME_RE.match(name) or len(name) > 64:
        findings.append(
            Finding(
                severity="error",
                code="INVALID_SKILL_NAME",
                path=path,
                message=f"Skill name {name!r} must match ^[a-z0-9-]+$ (1-64 chars)",
            )
        )
    elif name != skill_dir_name:
        findings.append(
            Finding(
                severity="error",
                code="SKILL_NAME_DIR_MISMATCH",
                path=path,
                message=f"Skill name {name!r} must match parent directory {skill_dir_name!r}",
            )
        )

    if not isinstance(desc, str) or not (1 <= len(desc.strip()) <= 1024):
        findings.append(
            Finding(
                severity="error",
                code="INVALID_SKILL_DESCRIPTION",
                path=path,
                message="Skill description must be a non-empty string (<= 1024 chars)",
            )
        )

    codex_warn = int(policy.get("rules_budgets", {}).get("codex_skill_warn_bytes", 8192))
    byte_len = len(text.encode("utf-8"))
    if byte_len > codex_warn:
        findings.append(
            Finding(
                severity="warning",
                code="CODEX_SKILL_SIZE_WARN",
                path=path,
                message=f"Skill size {byte_len} B exceeds Codex {codex_warn} B split threshold",
            )
        )
    return findings


def detect_grok_state(home_dir: Path) -> dict[str, bool]:
    """Inspect ~/.grok/ for xAI Grok Build vs @vibe-kit/grok-cli collision markers."""
    grok_dir = home_dir / ".grok"
    if not grok_dir.exists():
        return {"exists": False, "has_xai": False, "has_vibekit": False, "ambiguous": False}
    xai_markers = ("config.toml", "managed_config.toml", "requirements.toml", "trusted_folders.toml", "sandbox.toml")
    vibekit_markers = ("user-settings.json", "workspace-trust.json")
    has_xai = any((grok_dir / m).exists() for m in xai_markers)
    has_vibekit = any((grok_dir / m).exists() for m in vibekit_markers)
    return {
        "exists": True,
        "has_xai": has_xai,
        "has_vibekit": has_vibekit,
        "ambiguous": (has_xai and has_vibekit) or (not has_xai and not has_vibekit),
    }


def _infer_harness_from_path(rel_path: str) -> str:
    lower = rel_path.lower()
    for candidate in (
        "antigravity",
        "litert-lm",
        "litert",
        "ollama",
        "gemini",
        "codex",
        "claude",
        "copilot",
        "kimi",
        "grok",
        "opencode",
        "cursor",
        "devin",
        "cline",
        "goose",
        "aider",
    ):
        if candidate in lower:
            return "litert-lm" if candidate == "litert" else candidate
    if "mcp-registry" in lower:
        return "registry"
    return "generic"


def validate_content_file(
    rel_path: str,
    text: str,
    policy: dict[str, Any],
    report: ValidationReport,
) -> None:
    """Validate a single repository file by path and format."""
    norm_rel = rel_path.replace("\\", "/")
    report.findings.extend(scan_invisible_unicode(text, rel_path, policy))
    is_upstream_schema = norm_rel.startswith("policy/upstream-schemas/")
    is_policy_def = norm_rel in ("policy/security-policy.json", ".githooks/pre-commit")

    if is_upstream_schema or is_policy_def:
        # Policy definitions and upstream schema snapshots only need syntax, Unicode, and regex secret checks.
        if not is_policy_def:
            for f in scan_secrets(text, rel_path, policy):
                if f.code == "SECRET_DETECTED":
                    report.findings.append(f)
        suffix = Path(rel_path).suffix.lower()
        if suffix in (".json", ".jsonc"):
            try:
                parse_by_format(text, "jsonc" if suffix == ".jsonc" else "json")
            except FormatError as exc:
                report.add("error", "INVALID_JSON", rel_path, str(exc))
        return

    report.findings.extend(scan_secrets(text, rel_path, policy))

    lower = rel_path.lower()
    suffix = Path(rel_path).suffix.lower()
    harness = _infer_harness_from_path(rel_path)

    if suffix in (".json", ".jsonc"):
        fmt = "jsonc" if (suffix == ".jsonc" or "opencode" in lower or "plugin.json" in lower) else "json"
        try:
            data = parse_by_format(text, fmt)
        except FormatError as exc:
            report.add("error", "INVALID_JSON", rel_path, str(exc))
            return
        if isinstance(data, dict):
            eff_harness = str(data.get("harness") or harness)
            if "hook" in lower:
                report.findings.extend(check_hooks_config(data, policy, rel_path))
            report.findings.extend(check_mcp_config_object(data, eff_harness, policy, rel_path))
        return

    if suffix == ".toml":
        try:
            data = parse_toml(text)
        except FormatError as exc:
            report.add("error", "INVALID_TOML", rel_path, str(exc))
            return
        if harness == "codex":
            report.findings.extend(check_codex_config(data, policy, rel_path))
        else:
            report.findings.extend(check_mcp_config_object(data, harness, policy, rel_path))
        return

    if suffix in (".yaml", ".yml"):
        try:
            data = parse_yaml_subset(text)
        except FormatError as exc:
            report.add("error", "INVALID_YAML", rel_path, str(exc))
            return
        if isinstance(data, dict):
            eff_harness = "goose" if "extensions" in data and harness == "generic" else harness
            report.findings.extend(check_mcp_config_object(data, eff_harness, policy, rel_path))
        return

    if suffix == ".env":
        try:
            data = parse_by_format(text, "env")
        except FormatError as exc:
            report.add("error", "INVALID_ENV", rel_path, str(exc))
            return
        if isinstance(data, dict):
            report.findings.extend(_check_base_url_env(data, rel_path, policy))
            report.findings.extend(check_local_model_config(data, harness, policy, rel_path))
        return

    if suffix in (".md", ".mdc"):
        is_failsafe = "profiles/failsafe" in lower
        if Path(rel_path).name == "SKILL.md":
            skill_dir = Path(rel_path).parent.name
            report.findings.extend(check_skill_markdown(text, skill_dir, rel_path, policy))
        elif "rules/" in lower or is_failsafe:
            report.findings.extend(check_rule_text(text, rel_path, policy, is_failsafe=is_failsafe))
        else:
            try:
                parse_yaml_frontmatter(text)
            except FormatError as exc:
                report.add("error", "INVALID_MARKDOWN_FRONTMATTER", rel_path, str(exc))
        return


def _validate_agy_plugin_bundle(ctx: RuntimeContext, report: ValidationReport) -> None:
    """Stage rendered Antigravity plugin bundle in a private temp dir and run agy plugin validate --strict."""
    agy_bin = shutil.which("agy")
    if not agy_bin:
        return
    targets_path = ctx.repo_root / "targets" / "targets.json"
    if not targets_path.exists():
        return
    try:
        targets_doc = parse_json(targets_path.read_text(encoding="utf-8"))
    except FormatError:
        return
    targets = targets_doc.get("targets", []) if isinstance(targets_doc, dict) else []
    has_plugin = any(t.get("strategy") == "plugin-bundle" and t.get("enabled", True) for t in targets)
    if not has_plugin:
        return

    # Lazy import avoids circular dependency with render.py.
    from .render import render_antigravity_plugin_bundle_files

    files = render_antigravity_plugin_bundle_files(ctx.repo_root)
    with tempfile.TemporaryDirectory(prefix="agentcfg-agy-") as td:
        os.chmod(td, 0o700)
        bundle_root = Path(td) / "agentconfig-core"
        for rel, content in files.items():
            dest = bundle_root / rel
            atomic_write_bytes(dest, content, 0o444, boundary_root=Path(td))
        proc = subprocess.run(
            [agy_bin, "plugin", "validate", str(bundle_root), "--strict", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            detail = (proc.stdout or proc.stderr or "agy plugin validate --strict failed").strip()
            report.add("error", "AGY_PLUGIN_VALIDATE_FAILED", "antigravity-plugin-bundle", detail)


def validate_repo(
    ctx: RuntimeContext,
    staged: bool = False,
    run_agy: bool = True,
    check_grok_home: bool = True,
) -> ValidationReport:
    """Run full repository or staged git blob validation."""
    report = ValidationReport()
    repo_root = ctx.repo_root

    try:
        policy = load_security_policy(repo_root)
    except FormatError as exc:
        report.add("error", "INVALID_SECURITY_POLICY", "policy/security-policy.json", str(exc))
        return report

    if staged:
        proc = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            report.add("error", "GIT_STAGED_FAILED", "<git>", proc.stderr.strip() or "git diff --cached failed")
            return report
        staged_files = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        declarative_prefixes = ("canonical/", "targets/", "policy/")
        declarative_names = {".mcp.json", "mcp_config.json", "mcp-config.json", "mcp.json", "cline_mcp_settings.json"}
        for rel in staged_files:
            norm_rel = rel.replace("\\", "/")
            if ".dec." in rel or rel.endswith((".key", ".pem")) or rel.startswith(".age/"):
                report.add("error", "FORBIDDEN_SECRET_FILE", rel, "Plaintext secret artifact staged for commit")
                continue
            blob = subprocess.run(
                ["git", "show", f":{rel}"],
                cwd=repo_root,
                capture_output=True,
                check=False,
            )
            if blob.returncode != 0:
                continue
            try:
                text = blob.stdout.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if norm_rel.startswith("secrets/"):
                if norm_rel not in ("secrets/.sops.yaml", "secrets/README.md"):
                    if not (".enc." in Path(norm_rel).name.lower() and "ENC[AES256_GCM," in text):
                        report.add("error", "UNENCRYPTED_SECRET_FILE", rel, "Files under secrets/ must be SOPS-encrypted (*.enc.*)")
                report.findings.extend(scan_invisible_unicode(text, rel, policy))
                for f in scan_secrets(text, rel, policy):
                    if f.code == "SECRET_DETECTED" and "ENC[AES256_GCM," not in text:
                        report.findings.append(f)
                continue
            if norm_rel.startswith(declarative_prefixes) or Path(norm_rel).name in declarative_names:
                validate_content_file(rel, text, policy, report)
            else:
                report.findings.extend(scan_invisible_unicode(text, rel, policy))
                if not norm_rel.startswith(("tests/", "docs/", "lib/policy.py", ".githooks/")) and norm_rel != "README.md":
                    for f in scan_secrets(text, rel, policy):
                        if f.code == "SECRET_DETECTED":
                            report.findings.append(f)
        report.findings.extend(run_gitleaks_staged(repo_root))
        return report

    # Full working-tree validation across policy/, canonical/, targets/, secrets/.
    for check_dir in ("policy", "canonical", "targets", "secrets"):
        base = repo_root / check_dir
        if not base.exists():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            rel = str(p.relative_to(repo_root))
            if ".dec." in rel or p.suffix in (".key", ".pem"):
                report.add("error", "FORBIDDEN_SECRET_FILE", rel, "Plaintext secret artifact found in repository")
                continue
            if p.name == "secrets.enc.yaml":
                # Encrypted SOPS files contain ciphertext and sops metadata only.
                try:
                    parse_yaml_subset(p.read_text(encoding="utf-8"))
                except (FormatError, UnicodeDecodeError) as exc:
                    report.add("error", "INVALID_ENC_YAML", rel, str(exc))
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            validate_content_file(rel, text, policy, report)

    # Aggregate Antigravity token budget across canonical/rules/*.md.
    rules_dir = repo_root / "canonical" / "rules"
    if rules_dir.exists():
        total_tokens = 0
        for rule_file in sorted(rules_dir.glob("*.md")):
            text = rule_file.read_text(encoding="utf-8")
            total_tokens += estimate_tokens(text)
        budget = int(policy.get("rules_budgets", {}).get("antigravity_default_rules_tokens", 20000))
        if total_tokens > budget:
            report.add(
                "error",
                "ANTIGRAVITY_RULES_TOKEN_BUDGET",
                "canonical/rules",
                f"Aggregate rules ~{total_tokens} tokens exceed Antigravity defaultRulesBudget ({budget})",
            )

    # Cross-check enabled mcp-registry entries against manifests.lock.json.
    reg_path = repo_root / "canonical" / "mcp-registry.json"
    if reg_path.exists():
        try:
            reg = parse_json(reg_path.read_text(encoding="utf-8"))
            lock = load_manifests_lock(repo_root)
            locked_servers = lock.get("servers", {}) if isinstance(lock, dict) else {}
            servers = reg.get("servers", {}) if isinstance(reg, dict) else {}
            for srv_name, srv_cfg in servers.items():
                if not isinstance(srv_cfg, dict):
                    continue
                if srv_cfg.get("enabled", False) and srv_cfg.get("transport") == "stdio":
                    if srv_name not in locked_servers:
                        report.add(
                            "error",
                            "UNPINNED_MCP_SERVER",
                            "canonical/mcp-registry.json",
                            f"Enabled stdio MCP server '{srv_name}' missing from policy/manifests.lock.json",
                        )
        except FormatError:
            pass

    # Validate targets/targets.json structure.
    targets_path = repo_root / "targets" / "targets.json"
    grok_targets_enabled = False
    if targets_path.exists():
        try:
            tdoc = parse_json(targets_path.read_text(encoding="utf-8"))
            seen_ids: set[str] = set()
            valid_strategies = {"ro", "replace-owned", "patch-managed-keys", "plugin-bundle"}
            for t in tdoc.get("targets", []):
                tid = t.get("id", "")
                if not tid or tid in seen_ids:
                    report.add("error", "INVALID_TARGET_ID", "targets/targets.json", f"Duplicate or empty target id {tid!r}")
                seen_ids.add(tid)
                strat = t.get("strategy")
                if strat not in valid_strategies:
                    report.add("error", "INVALID_TARGET_STRATEGY", "targets/targets.json", f"Target {tid!r} invalid strategy {strat!r}")
                if _normalize_harness(str(t.get("harness", ""))) == "grok" and t.get("enabled", True):
                    grok_targets_enabled = True
        except FormatError:
            pass

    if check_grok_home and grok_targets_enabled:
        grok_state = detect_grok_state(ctx.home_dir)
        if grok_state["exists"] and grok_state["ambiguous"] and ctx.grok_flavor is None:
            report.add(
                "error",
                "GROK_FLAVOR_AMBIGUOUS",
                str(ctx.home_dir / ".grok"),
                "~/.grok/ exists and may collide between xAI Grok Build and @vibe-kit/grok-cli; pass --grok-flavor xai|vibekit",
            )

    if run_agy:
        _validate_agy_plugin_bundle(ctx, report)

    return report
