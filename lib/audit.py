"""Pre-trust read-only repository auditor for cloned/unfamiliar codebases."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

from .formats import FormatError, parse_by_format
from .policy import (
    DEFAULT_POLICY,
    check_codex_config,
    check_hooks_config,
    check_mcp_config_object,
    load_security_policy,
    scan_invisible_unicode,
    scan_secrets,
)


RISKY_REL_PATHS = {
    ".mcp.json": ("high", "Project MCP server manifest"),
    ".vscode/mcp.json": ("high", "VS Code workspace MCP manifest"),
    ".claude/settings.json": ("medium", "Project Claude Code settings"),
    ".claude/settings.local.json": ("high", "Local Claude Code settings"),
    ".gemini/settings.json": ("medium", "Project Gemini CLI settings"),
    ".antigravity/settings.json": ("medium", "Project Antigravity settings"),
    ".codex/config.toml": ("medium", "Project Codex config"),
    ".codex/hooks.json": ("high", "Project Codex executable hooks"),
    ".grok/config.toml": ("medium", "Project Grok Build config"),
    ".grok/settings.json": ("medium", "Project @vibe-kit/grok-cli config"),
    ".agents/hooks.json": ("high", "Project Antigravity/agent executable hooks"),
    ".agents/skills.json": ("medium", "Project Antigravity skills manifest (check inherits)"),
    ".agents/plugins.json": ("medium", "Project Antigravity plugins manifest (check inherits)"),
    ".cursor/mcp.json": ("high", "Project Cursor MCP manifest"),
    ".cursor/hooks.json": ("high", "Project Cursor executable hooks"),
    ".devin/hooks.v1.json": ("high", "Project Devin executable hooks"),
}

RISKY_PREFIXES = (
    ".claude/hooks/",
    ".claude/plugins/",
    ".codex/rules/",
    ".grok/hooks/",
    ".cline/hooks/",
    ".github/hooks/",
)

EXT_FORMATS = {
    ".json": "json",
    ".jsonc": "jsonc",
    ".toml": "toml",
    ".yaml": "yaml",
    ".yml": "yaml",
}

EXTERNAL_AT_IMPORT_RE = re.compile(r"(?:^|\s)@(?:/|~/|\.\./|https?://)", re.MULTILINE)
EXFIL_URL_RE = re.compile(r"\b(?:curl|wget|nc|ncat)\s+[^\n]*\|\s*(?:sh|bash|zsh)", re.IGNORECASE)
BASE_URL_TEXT_RE = re.compile(r"\b[A-Z0-9_]*(?:BASE_URL|API_BASE|API_URL)\b")


def _infer_repo_harness(rel: str) -> str:
    lower = rel.lower()
    for key in ("antigravity", "gemini", "claude", "codex", "copilot", "vscode", "kimi", "grok", "opencode", "cursor", "devin", "cline", "goose"):
        if key in lower:
            return key
    return "generic"


def audit_repo(
    repo_path: Path,
    policy_repo_root: Path | None = None,
) -> dict[str, Any]:
    """Perform a read-only pre-trust security audit on repo_path."""
    target_root = Path(repo_path).expanduser().resolve()
    if not target_root.is_dir():
        raise FileNotFoundError(f"Audit path is not a directory: {target_root}")

    policy = load_security_policy(policy_repo_root) if policy_repo_root else DEFAULT_POLICY
    findings: list[dict[str, str]] = []

    def add(severity: str, code: str, rel: str, detail: str) -> None:
        findings.append(
            {
                "severity": severity,
                "code": code,
                "path": rel,
                "message": detail,
            }
        )

    for cur, dirs, files in os.walk(target_root, followlinks=False):
        cur_p = Path(cur)
        # Skip .git object storage and heavy dependency caches.
        dirs[:] = sorted(d for d in dirs if d not in (".git", "node_modules", ".venv", "__pycache__"))

        for d in list(dirs):
            dp = cur_p / d
            if os.path.islink(dp):
                rel = dp.relative_to(target_root).as_posix()
                try:
                    resolved = dp.resolve()
                    if not resolved.is_relative_to(target_root):
                        add("high", "SYMLINK_ESCAPE", rel, f"Directory symlink escapes repo root -> {resolved}")
                except OSError:
                    add("medium", "BROKEN_SYMLINK", rel, "Broken directory symlink")

        for fn in sorted(files):
            fp = cur_p / fn
            rel = fp.relative_to(target_root).as_posix()

            st = os.lstat(fp)
            if stat.S_ISLNK(st.st_mode):
                try:
                    resolved = fp.resolve()
                    if not resolved.is_relative_to(target_root):
                        add("high", "SYMLINK_ESCAPE", rel, f"File symlink escapes repo root -> {resolved}")
                except OSError:
                    add("medium", "BROKEN_SYMLINK", rel, "Broken file symlink")
                continue

            if not stat.S_ISREG(st.st_mode):
                continue

            if rel in RISKY_REL_PATHS:
                sev, desc = RISKY_REL_PATHS[rel]
                add(sev, "UNTRUSTED_REPO_CONFIG", rel, desc)

            if any(rel.startswith(pref) for pref in RISKY_PREFIXES):
                add("high", "UNTRUSTED_HOOK_OR_PLUGIN", rel, "Project hook/plugin/rule execution surface")

            if fn == "register.js" and fp.parent.name == "hooks":
                add("high", "UNSANDBOXED_MOD", rel, "Claude Code hooks/register.js runs unsandboxed in-process")

            is_agent_surface = (
                rel in RISKY_REL_PATHS
                or any(rel.startswith(pref) for pref in RISKY_PREFIXES)
                or rel.startswith((".agents/", ".claude/", ".codex/", ".gemini/", ".grok/", ".cursor/", ".devin/", ".cline/", ".vscode/"))
                or fn in ("AGENTS.md", "AGENTS.override.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", "SKILL.md", ".aider.conf.yml")
            )
            if not is_agent_surface:
                continue

            if st.st_size > 2 * 1024 * 1024:
                continue

            try:
                text = fp.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            for f in scan_invisible_unicode(text, rel, policy):
                add("high", f.code, rel, f.message)

            for f in scan_secrets(text, rel, policy):
                add("high", f.code, rel, f.message)

            if EXFIL_URL_RE.search(text):
                add("high", "SHELL_PIPE_EXEC", rel, "Pipe-to-shell curl/wget execution pattern")

            if fn.endswith((".md", ".mdc")):
                if EXTERNAL_AT_IMPORT_RE.search(text):
                    add("medium", "EXTERNAL_AT_IMPORT", rel, "External @path or @url import directive in instruction file")

            if BASE_URL_TEXT_RE.search(text):
                # Structured check handles exact allowlist; flag raw occurrences in non-policy markdown/hooks too.
                if fp.suffix.lower() not in EXT_FORMATS:
                    add("medium", "BASE_URL_REFERENCE", rel, "Mentions *_BASE_URL override")

            fmt = EXT_FORMATS.get(fp.suffix.lower())
            if fmt:
                try:
                    parsed = parse_by_format(text, fmt)
                except FormatError as exc:
                    add("medium", "MALFORMED_CONFIG", rel, str(exc))
                    continue
                if isinstance(parsed, dict):
                    harness = _infer_repo_harness(rel)
                    if harness == "codex" and fp.suffix.lower() == ".toml":
                        for f in check_codex_config(parsed, policy, rel):
                            add("high", f.code, rel, f.message)
                    else:
                        for f in check_mcp_config_object(parsed, harness, policy, rel):
                            add("high", f.code, rel, f.message)
                    if "hook" in rel.lower():
                        for f in check_hooks_config(parsed, policy, rel):
                            add("high", f.code, rel, f.message)
                    if "inherits" in parsed:
                        add("medium", "CONFIG_INHERITS", rel, "Manifest uses 'inherits' reference (verify provenance)")

    high_count = sum(1 for item in findings if item["severity"] == "high")
    med_count = sum(1 for item in findings if item["severity"] == "medium")
    return {
        "ok": high_count == 0,
        "repo": str(target_root),
        "high_count": high_count,
        "medium_count": med_count,
        "findings": findings,
    }
