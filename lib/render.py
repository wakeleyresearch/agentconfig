"""Deterministic cross-harness rendering for rules, skills, hooks, settings, and MCP."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .formats import (
    FormatError,
    dump_json,
    dump_toml,
    dump_yaml,
    parse_by_format,
    parse_json,
    parse_jsonc,
    parse_toml,
    parse_yaml_frontmatter,
)
from .paths import RuntimeContext


_HARNESS_ALIASES: dict[str, str] = {
    "agy": "antigravity",
    "gemini-cli": "gemini",
    "claude-code": "claude",
    "kimi-code": "kimi",
    "xai-grok": "grok",
    "grok-build": "grok",
    "grok-vibekit": "grok",
    "vscode": "copilot",
    "vscode-copilot": "copilot",
    "jetbrains": "copilot",
    "jetbrains-copilot": "copilot",
}

_HARNESS_SPEC_FILE: dict[str, str] = {
    "antigravity": "antigravity.json",
    "gemini": "gemini-cli.json",
    "gemini-cli": "gemini-cli.json",
    "codex": "codex.json",
    "claude": "claude-code.json",
    "claude-code": "claude-code.json",
    "copilot": "copilot.json",
    "vscode": "copilot.json",
    "jetbrains": "copilot.json",
    "kimi": "kimi-code.json",
    "kimi-code": "kimi-code.json",
    "grok": "grok.json",
    "opencode": "opencode.json",
    "cursor": "cursor.json",
    "devin": "devin.json",
    "cline": "cline.json",
    "goose": "goose.json",
    "aider": "aider.json",
}


@dataclass
class RenderedTarget:
    """Rendered output for a single target entry in targets/targets.json."""

    target_id: str
    harness: str
    strategy: str
    format: str
    mode: int
    content: bytes | None = None
    patch_data: dict[str, Any] | None = None
    files: dict[str, bytes] | None = None  # relative path -> bytes for directory/bundle targets
    managed_keys: list[str] | None = None
    removed_keys: list[str] | None = None
    repo_exclude: bool = False


def normalize_harness(harness: str) -> str:
    """Normalize harness aliases to canonical adapter keys."""
    h = harness.strip().lower()
    return _HARNESS_ALIASES.get(h, h)


def load_targets_manifest(repo_root: Path) -> list[dict[str, Any]]:
    """Load targets/targets.json list."""
    p = repo_root / "targets" / "targets.json"
    if not p.exists():
        return []
    raw = parse_json(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("targets"), list):
        raise FormatError("targets/targets.json must contain a 'targets' list")
    return raw["targets"]


def load_mcp_registry(repo_root: Path) -> dict[str, Any]:
    """Load canonical/mcp-registry.json."""
    p = repo_root / "canonical" / "mcp-registry.json"
    if not p.exists():
        return {"schema_version": "1.0", "servers": {}}
    raw = parse_json(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise FormatError("canonical/mcp-registry.json root must be a JSON object")
    return raw


def load_harness_spec(repo_root: Path, harness: str) -> dict[str, Any]:
    """Load canonical/harnesses/<spec>.json if present."""
    fname = _HARNESS_SPEC_FILE.get(harness.lower(), f"{harness.lower()}.json")
    p = repo_root / "canonical" / "harnesses" / fname
    if not p.exists():
        return {}
    raw = parse_json(p.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def _wrap_stdio_command(
    srv: dict[str, Any],
    repo_root: Path,
) -> tuple[str, list[str]]:
    cmd = str(srv.get("command", ""))
    args = [str(a) for a in srv.get("args", [])]
    secret_refs = srv.get("secret_refs") or []
    wrap = bool(srv.get("wrap_with_secret_exec", False) or secret_refs)
    if not wrap or not cmd:
        return cmd, args

    wrapper = str((repo_root / "wrappers" / "mcp-secret-exec").resolve())
    w_args: list[str] = []
    for ref in secret_refs:
        if isinstance(ref, dict) and ref.get("env_var") and ref.get("secret_ref"):
            w_args.extend(["--secret-ref", f"{ref['env_var']}={ref['secret_ref']}"])
    if srv.get("unshare_net"):
        w_args.append("--unshare-net")
    w_args.append("--")
    w_args.append(cmd)
    w_args.extend(args)
    return wrapper, w_args


def _server_matches_harness(srv: dict[str, Any], harness: str) -> bool:
    targets = srv.get("targets")
    if not targets:
        return True
    raw_h = harness.strip().lower()
    norm_h = normalize_harness(harness)
    normalized_targets = {str(t).strip().lower() for t in targets} | {
        normalize_harness(str(t)) for t in targets
    }
    return raw_h in normalized_targets or norm_h in normalized_targets


def _render_single_mcp_entry(
    srv_cfg: dict[str, Any],
    harness: str,
    repo_root: Path,
) -> dict[str, Any] | None:
    """Translate one canonical MCP server entry into the target harness schema."""
    raw_h = harness.strip().lower()
    norm_h = normalize_harness(harness)
    transport = str(srv_cfg.get("transport", "stdio")).lower()

    if transport == "stdio":
        cmd, args = _wrap_stdio_command(srv_cfg, repo_root)
        env = dict(srv_cfg.get("env") or {})
        cwd = srv_cfg.get("cwd")

        if norm_h == "opencode":
            entry: dict[str, Any] = {
                "type": "local",
                "command": [cmd, *args],
            }
            if env:
                entry["environment"] = env
            return entry

        if norm_h == "goose":
            entry = {
                "enabled": True,
                "type": "stdio",
                "cmd": cmd,
                "args": args,
            }
            if env:
                entry["envs"] = env
            if srv_cfg.get("timeout_ms"):
                entry["timeout"] = max(1, int(srv_cfg["timeout_ms"]) // 1000)
            return entry

        entry = {"command": cmd, "args": args}
        if raw_h in ("claude", "claude-code", "vscode", "vscode-copilot", "jetbrains", "jetbrains-copilot"):
            entry["type"] = "stdio"
        elif raw_h == "copilot":
            entry["type"] = "local"
            entry["tools"] = list(srv_cfg.get("enabled_tools") or ["*"])
        if env:
            entry["env"] = env
        if cwd and raw_h in ("antigravity", "gemini", "gemini-cli", "kimi", "kimi-code"):
            entry["cwd"] = cwd
        return entry

    # Remote Streamable HTTP transport.
    url = str(srv_cfg.get("url", ""))
    if not url:
        return None
    headers = dict(srv_cfg.get("headers") or {})
    bearer_var = srv_cfg.get("bearer_token_env_var")

    if raw_h in ("gemini", "gemini-cli"):
        entry = {"httpUrl": url}
        if headers:
            entry["headers"] = headers
        if srv_cfg.get("timeout_ms"):
            entry["timeout"] = int(srv_cfg["timeout_ms"])
        if srv_cfg.get("enabled_tools"):
            entry["includeTools"] = list(srv_cfg["enabled_tools"])
        if srv_cfg.get("disabled_tools"):
            entry["excludeTools"] = list(srv_cfg["disabled_tools"])
        return entry

    if raw_h in ("claude", "claude-code", "vscode", "vscode-copilot", "jetbrains", "jetbrains-copilot"):
        entry = {"type": "http", "url": url}
        if headers:
            entry["headers"] = headers
        return entry

    if raw_h == "copilot":
        entry = {
            "type": "http",
            "url": url,
            "tools": list(srv_cfg.get("enabled_tools") or ["*"]),
        }
        if headers:
            entry["headers"] = headers
        return entry

    if norm_h == "opencode":
        entry = {"type": "remote", "url": url}
        if headers:
            entry["headers"] = headers
        return entry

    if norm_h == "goose":
        entry = {
            "enabled": True,
            "type": "streamable_http",
            "uri": url,
        }
        if headers:
            entry["headers"] = headers
        if srv_cfg.get("timeout_ms"):
            entry["timeout"] = max(1, int(srv_cfg["timeout_ms"]) // 1000)
        return entry

    if norm_h in ("codex", "grok"):
        entry = {"url": url}
        if bearer_var:
            entry["bearer_token_env_var"] = bearer_var
        if headers:
            entry["http_headers"] = headers
        return entry

    if norm_h == "kimi":
        entry = {"url": url}
        if bearer_var:
            entry["bearerTokenEnvVar"] = bearer_var
        if headers:
            entry["headers"] = headers
        if srv_cfg.get("timeout_ms"):
            entry["startupTimeoutMs"] = int(srv_cfg["timeout_ms"])
        if srv_cfg.get("tool_timeout_ms"):
            entry["toolTimeoutMs"] = int(srv_cfg["tool_timeout_ms"])
        if srv_cfg.get("enabled_tools"):
            entry["enabledTools"] = list(srv_cfg["enabled_tools"])
        if srv_cfg.get("disabled_tools"):
            entry["disabledTools"] = list(srv_cfg["disabled_tools"])
        return entry

    if norm_h == "cline":
        entry = {"type": "streamableHttp", "url": url}
        if headers:
            entry["headers"] = headers
        return entry

    if norm_h == "devin":
        entry = {"transport": "http", "url": url}
        if headers:
            entry["headers"] = headers
        return entry

    # Antigravity, Cursor, and generic mcpServers.
    entry = {"url": url}
    if headers:
        entry["headers"] = headers
    return entry


def render_mcp_for_harness(
    registry: dict[str, Any],
    harness: str,
    repo_root: Path,
    include_disabled: bool = False,
) -> dict[str, Any]:
    """Render canonical/mcp-registry.json into the target harness's native MCP schema."""
    raw_h = harness.strip().lower()
    norm_h = normalize_harness(harness)
    if norm_h == "aider":
        return {}

    rendered_servers: dict[str, Any] = {}
    servers = registry.get("servers", {}) if isinstance(registry, dict) else {}
    for srv_name in sorted(servers.keys()):
        srv_cfg = servers[srv_name]
        if not isinstance(srv_cfg, dict):
            continue
        if not include_disabled and not srv_cfg.get("enabled", False):
            continue
        if not _server_matches_harness(srv_cfg, harness):
            continue
        translated = _render_single_mcp_entry(srv_cfg, harness, repo_root)
        if translated is not None:
            rendered_servers[srv_name] = translated

    if raw_h in ("vscode", "vscode-copilot", "jetbrains", "jetbrains-copilot"):
        return {"servers": rendered_servers, "inputs": []}
    if raw_h == "grok-vibekit":
        return {"mcpServers": rendered_servers}
    if norm_h == "opencode":
        return {"mcp": {"servers": rendered_servers}}
    if norm_h in ("codex", "grok"):
        return {"mcp_servers": rendered_servers}
    if norm_h == "goose":
        return {"extensions": rendered_servers}
    return {"mcpServers": rendered_servers}


def render_rules_markdown(repo_root: Path, failsafe: bool = False) -> str:
    """Concatenate canonical rules (or failsafe minimal rule) deterministically."""
    if failsafe:
        fs_rule = repo_root / "canonical" / "profiles" / "failsafe" / "rules.md"
        if fs_rule.exists():
            return fs_rule.read_text(encoding="utf-8")
        return "# Failsafe Mode\n\nOperate in read-only plan mode without external MCP tools.\n"

    rules_dir = repo_root / "canonical" / "rules"
    if not rules_dir.exists():
        return ""
    parts: list[str] = []
    for p in sorted(rules_dir.glob("*.md")):
        txt = p.read_text(encoding="utf-8").strip()
        if txt:
            parts.append(txt)
    return ("\n\n".join(parts) + "\n") if parts else ""


def _ensure_antigravity_rule_frontmatter(text: str) -> str:
    fm, body = parse_yaml_frontmatter(text)
    if fm is None:
        return "---\ntrigger: always_on\n---\n\n" + text.lstrip("\n")
    if "trigger" in fm:
        return text
    fm_copy = dict(fm)
    fm_copy["trigger"] = "always_on"
    return "---\n" + dump_yaml(fm_copy).rstrip("\n") + "\n---\n" + body.lstrip("\n")


def _adapt_hooks_for_antigravity(hooks_doc: dict[str, Any]) -> dict[str, Any]:
    """Convert Claude-style {"hooks": {...}} into Antigravity named top-level hooks."""
    def adapt_entries(entries: Any) -> Any:
        if not isinstance(entries, list):
            return entries
        out_list = []
        for item in entries:
            if not isinstance(item, dict):
                out_list.append(item)
                continue
            item_copy = copy.deepcopy(item)
            if item_copy.get("matcher") == "Bash":
                item_copy["matcher"] = "run_command"
            out_list.append(item_copy)
        return out_list

    if "hooks" in hooks_doc and isinstance(hooks_doc["hooks"], dict):
        inner = {ev: adapt_entries(val) for ev, val in hooks_doc["hooks"].items()}
        return {"agentconfig-guard": inner}
    return {
        name: (
            {ev: adapt_entries(val) for ev, val in block.items()}
            if isinstance(block, dict)
            else block
        )
        for name, block in hooks_doc.items()
    }


def render_antigravity_plugin_bundle_files(repo_root: Path, failsafe: bool = False) -> dict[str, bytes]:
    """Build deterministic file map for ~/.gemini/config/plugins/agentconfig-core/."""
    files: dict[str, bytes] = {}
    plugin_meta = {
        "name": "agentconfig-core",
        "version": "0.1.0",
        "description": "agentconfig canonical security baseline plugin",
    }
    files["plugin.json"] = dump_json(plugin_meta).encode("utf-8")

    if failsafe:
        files["hooks.json"] = dump_json({}).encode("utf-8")
        files["mcp_config.json"] = dump_json({"mcpServers": {}}).encode("utf-8")
        fs_rule = render_rules_markdown(repo_root, failsafe=True)
        files["rules/core.md"] = _ensure_antigravity_rule_frontmatter(fs_rule).encode("utf-8")
        return files

    # MCP config
    reg = load_mcp_registry(repo_root)
    mcp_doc = render_mcp_for_harness(reg, "antigravity", repo_root, include_disabled=False)
    files["mcp_config.json"] = dump_json(mcp_doc).encode("utf-8")

    # Hooks at plugin root
    merged_hooks: dict[str, Any] = {}
    hooks_dir = repo_root / "canonical" / "hooks"
    if hooks_dir.exists():
        for hp in sorted(hooks_dir.glob("*.json")):
            raw = parse_json(hp.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                merged_hooks.update(_adapt_hooks_for_antigravity(raw))
    files["hooks.json"] = dump_json(merged_hooks).encode("utf-8")

    # Rules
    rules_dir = repo_root / "canonical" / "rules"
    if rules_dir.exists():
        for rp in sorted(rules_dir.glob("*.md")):
            adapted = _ensure_antigravity_rule_frontmatter(rp.read_text(encoding="utf-8"))
            files[f"rules/{rp.name}"] = adapted.encode("utf-8")

    # Skills
    skills_dir = repo_root / "canonical" / "skills"
    if skills_dir.exists():
        for sp in sorted(skills_dir.rglob("*")):
            if sp.is_file():
                rel = sp.relative_to(skills_dir)
                files[f"skills/{rel.as_posix()}"] = sp.read_bytes()

    return files


def _render_skills_dir_files(repo_root: Path, failsafe: bool = False) -> dict[str, bytes]:
    if failsafe:
        return {}
    skills_dir = repo_root / "canonical" / "skills"
    if not skills_dir.exists():
        return {}
    return {
        sp.relative_to(skills_dir).as_posix(): sp.read_bytes()
        for sp in sorted(skills_dir.rglob("*"))
        if sp.is_file()
    }


def _load_failsafe_source(repo_root: Path, failsafe_source: str, fmt: str) -> tuple[bytes, Any]:
    p = repo_root / failsafe_source
    raw_bytes = p.read_bytes()
    if fmt in ("json", "jsonc", "toml", "yaml", "yml"):
        parsed = parse_by_format(raw_bytes.decode("utf-8"), fmt)
        return raw_bytes, parsed
    return raw_bytes, None


def render_target(
    target: dict[str, Any],
    ctx: RuntimeContext,
    failsafe: bool = False,
) -> RenderedTarget:
    """Deterministically render a single target entry from targets/targets.json."""
    repo_root = ctx.repo_root
    tid = str(target["id"])
    harness = str(target.get("harness", "generic"))
    strategy = str(target.get("strategy", "ro"))
    fmt = str(target.get("format", "json"))
    mode = int(str(target.get("mode", "0444")), 8)
    renderer = str(target.get("renderer", ""))
    managed_keys = list(target.get("managed_keys") or [])
    removed_keys = list(target.get("removed_keys") or [])
    repo_exclude = bool(target.get("repo_exclude", False))

    if renderer == "plugin_bundle" or strategy == "plugin-bundle":
        bundle_files = render_antigravity_plugin_bundle_files(repo_root, failsafe=failsafe)
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy="plugin-bundle",
            format="dir",
            mode=mode,
            files=bundle_files,
            repo_exclude=repo_exclude,
        )

    if renderer == "skills_dir":
        skill_files = _render_skills_dir_files(repo_root, failsafe=failsafe)
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy="ro",
            format="dir",
            mode=mode,
            files=skill_files,
            repo_exclude=repo_exclude,
        )

    if failsafe and target.get("failsafe_source"):
        raw_bytes, parsed = _load_failsafe_source(repo_root, str(target["failsafe_source"]), fmt)
        if strategy == "patch-managed-keys":
            fs_keys = list(target.get("failsafe_managed_keys") or managed_keys)
            if not fs_keys and isinstance(parsed, dict):
                fs_keys = list(parsed.keys())
            return RenderedTarget(
                target_id=tid,
                harness=harness,
                strategy=strategy,
                format=fmt,
                mode=mode,
                patch_data=parsed if isinstance(parsed, dict) else {},
                managed_keys=fs_keys,
                removed_keys=removed_keys,
                repo_exclude=repo_exclude,
            )
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy=strategy,
            format=fmt,
            mode=mode,
            content=raw_bytes,
            repo_exclude=repo_exclude,
        )

    if renderer == "rules_markdown":
        text = render_rules_markdown(repo_root, failsafe=failsafe)
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy=strategy,
            format="markdown",
            mode=mode,
            content=text.encode("utf-8"),
            repo_exclude=repo_exclude,
        )

    reg = load_mcp_registry(repo_root)
    spec = load_harness_spec(repo_root, harness)

    if renderer == "mcp_config":
        mcp_harness = str(target.get("variant") or harness)
        if failsafe:
            empty_reg = {"schema_version": "1.0", "servers": {}}
            mcp_doc = render_mcp_for_harness(empty_reg, mcp_harness, repo_root)
        else:
            mcp_doc = render_mcp_for_harness(reg, mcp_harness, repo_root)
        text = dump_json(mcp_doc) if fmt in ("json", "jsonc") else dump_toml(mcp_doc)
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy=strategy,
            format=fmt,
            mode=mode,
            content=text.encode("utf-8"),
            patch_data=mcp_doc if strategy == "patch-managed-keys" else None,
            managed_keys=managed_keys,
            removed_keys=removed_keys,
            repo_exclude=repo_exclude,
        )

    if renderer == "antigravity_settings":
        patch_obj = copy.deepcopy(spec.get("base_settings") or {})
        if isinstance(target.get("patch_values"), dict):
            patch_obj.update(target["patch_values"])
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy=strategy,
            format=fmt,
            mode=mode,
            content=dump_json(patch_obj).encode("utf-8"),
            patch_data=patch_obj,
            managed_keys=managed_keys,
            removed_keys=removed_keys,
            repo_exclude=repo_exclude,
        )

    if renderer == "claude_json":
        mcp_doc = render_mcp_for_harness(
            {"servers": {}} if failsafe else reg,
            "claude",
            repo_root,
        )
        patch_obj = copy.deepcopy(spec.get("claude_json_defaults") or {})
        patch_obj.update(mcp_doc)
        eff_keys = managed_keys or list(patch_obj.keys())
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy=strategy,
            format="json",
            mode=mode,
            content=dump_json(patch_obj).encode("utf-8"),
            patch_data=patch_obj,
            managed_keys=eff_keys,
            removed_keys=removed_keys,
            repo_exclude=repo_exclude,
        )

    if renderer == "harness_settings":
        settings_obj = copy.deepcopy(spec.get("base_settings") or {})
        norm_h = normalize_harness(harness)
        if norm_h in ("gemini", "opencode", "goose", "grok"):
            mcp_h = "grok-vibekit" if (norm_h == "grok" and target.get("grok_flavor") == "vibekit") else harness
            mcp_doc = render_mcp_for_harness(
                {"servers": {}} if failsafe else reg,
                mcp_h,
                repo_root,
            )
            for k, v in mcp_doc.items():
                settings_obj[k] = v
        if fmt == "yaml":
            serialized = dump_yaml(settings_obj)
        elif fmt == "toml":
            serialized = dump_toml(settings_obj)
        else:
            serialized = dump_json(settings_obj)
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy=strategy,
            format=fmt,
            mode=mode,
            content=serialized.encode("utf-8"),
            patch_data=settings_obj if strategy == "patch-managed-keys" else None,
            managed_keys=managed_keys or list(settings_obj.keys()),
            removed_keys=removed_keys or list(spec.get("removed_keys") or []),
            repo_exclude=repo_exclude,
        )

    if renderer == "codex_config":
        cfg_obj = copy.deepcopy(spec.get("base_settings") or {})
        mcp_doc = render_mcp_for_harness({"servers": {}} if failsafe else reg, "codex", repo_root)
        cfg_obj.update(mcp_doc)
        serialized = dump_toml(cfg_obj)
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy=strategy,
            format="toml",
            mode=mode,
            content=serialized.encode("utf-8"),
            patch_data=cfg_obj if strategy == "patch-managed-keys" else None,
            managed_keys=managed_keys or list(cfg_obj.keys()),
            removed_keys=removed_keys or ["profile", "profiles"],
            repo_exclude=repo_exclude,
        )

    if renderer == "codex_failsafe":
        fs_path = repo_root / "canonical" / "profiles" / "failsafe" / "codex" / "failsafe.config.toml"
        if fs_path.exists():
            content = fs_path.read_bytes()
        else:
            fallback = {
                "approval_policy": "on-request",
                "sandbox_mode": "read-only",
                "features": {"memories": False},
                "memories": {"disable_on_external_context": True},
                "mcp_servers": {},
            }
            content = dump_toml(fallback).encode("utf-8")
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy=strategy,
            format="toml",
            mode=mode,
            content=content,
            repo_exclude=repo_exclude,
        )

    if renderer == "gemini_policy":
        fs_pol = repo_root / "canonical" / "profiles" / "failsafe" / "gemini" / "policies" / "failsafe.toml"
        if fs_pol.exists():
            content = fs_pol.read_bytes()
        else:
            pol_doc = {
                "rule": [
                    {
                        "toolName": "save_memory",
                        "decision": "deny",
                        "priority": 100,
                    }
                ]
            }
            content = dump_toml(pol_doc).encode("utf-8")
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy=strategy,
            format="toml",
            mode=mode,
            content=content,
            repo_exclude=repo_exclude,
        )

    if renderer == "aider_conf":
        conf_obj = copy.deepcopy(spec.get("base_settings") or {"read": ["AGENTS.md"], "check-update": False})
        if failsafe:
            conf_obj = {
                "check-update": False,
                "restore-chat-history": False,
            }
        return RenderedTarget(
            target_id=tid,
            harness=harness,
            strategy=strategy,
            format="yaml",
            mode=mode,
            content=dump_yaml(conf_obj).encode("utf-8"),
            repo_exclude=repo_exclude,
        )

    raise ValueError(f"Unknown target renderer {renderer!r} for target {tid!r}")
