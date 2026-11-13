#!/usr/bin/env python3
"""Antigravity dynamic workflow for hostile-environment agent onboarding & remediation.

Executes a 3-phase orchestrated remediation pipeline via `run_workflow`:
  - Phase 1 (`parallel_triage`): Fans out `research` agents in parallel across target
    harnesses to inspect `/proc` anomalies, config/SQLite/lock corruption, and
    workspace supply-chain risks without modifying live evidence.
  - Phase 2 (`staged_remediation`): Runs `bin/agentcfg-remediate --non-interactive --json`
    sequentially via `pipeline` across each target agent (with `--profile` and
    `--local-model` from `args`).
  - Phase 3 (`independent_verification`): Runs an independent verification agent to
    inspect generated Remediation Receipts, execute `bin/agentcfg --json verify`,
    confirm Tier-B auth preservation, and verify zero secret leaks.
"""

from __future__ import annotations

import json
import shlex

try:
    from antigravity_workflow import agent, args, call_tool, log, parallel, phase, pipeline
except ImportError:
    # When executed directly by the Antigravity `run_workflow` runtime,
    # primitives (`agent`, `parallel`, `pipeline`, `phase`, `call_tool`, `args`, `log`)
    # are pre-injected into the module globals.
    pass


DEFAULT_AGENTS = ["codex", "claude-code", "gemini-cli", "opencode"]

TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "agent": {"type": "string"},
        "proc_anomalies": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Live /proc/<pid> environment, LD_PRELOAD, or *_BASE_URL anomalies.",
        },
        "config_corruption": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Corrupted JSON/TOML/YAML configs, broken SQLite DBs, stale locks, or poisoned memory.",
        },
        "workspace_risks": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Untrusted repo hooks, floating npx/uvx MCPs, symlink traps, or world-writable files.",
        },
        "recommended_profile": {
            "type": "string",
            "enum": ["canonical", "failsafe", "local-gemma"],
        },
        "summary": {"type": "string"},
    },
    "required": [
        "agent",
        "proc_anomalies",
        "config_corruption",
        "workspace_risks",
        "recommended_profile",
        "summary",
    ],
}

CHECK_SCHEMA = {
    "type": "object",
    "properties": {
        "verified": {"type": "boolean"},
        "agents_verified": {"type": "array", "items": {"type": "string"}},
        "receipt_paths": {"type": "array", "items": {"type": "string"}},
        "agentcfg_verify_ok": {"type": "boolean"},
        "auth_preserved": {"type": "boolean"},
        "zero_secret_leaks": {"type": "boolean"},
        "summary": {"type": "string"},
    },
    "required": [
        "verified",
        "agents_verified",
        "receipt_paths",
        "agentcfg_verify_ok",
        "auth_preserved",
        "zero_secret_leaks",
        "summary",
    ],
}


workflow_args = args if isinstance(globals().get("args"), dict) else {}
target_agents = list(workflow_args.get("agents") or DEFAULT_AGENTS)
profile = str(workflow_args.get("profile") or "local-gemma")
local_model = str(workflow_args.get("local_model") or "gemma4:e4b")
offline = bool(workflow_args.get("offline", True))
quiesce = bool(workflow_args.get("quiesce", False))
resume = bool(workflow_args.get("resume", False))
from_backup = workflow_args.get("from_backup")
project_dir = workflow_args.get("project_dir")


# ---------------------------------------------------------------------------
# Phase 1: Parallel Triage across target agents
# ---------------------------------------------------------------------------
phase("parallel_triage")
log(
    f"Starting parallel_triage across {len(target_agents)} agent(s): "
    f"{', '.join(target_agents)} (profile={profile}, local_model={local_model})"
)


def _build_triage_agent(target: str):
    project_clause = (
        f"Also run `python3 bin/agentcfg --json audit-repo {shlex.quote(str(project_dir))}` "
        f"to check workspace risks in {project_dir}."
        if project_dir
        else "Also check the current workspace with `python3 bin/agentcfg --json audit-repo .`."
    )
    prompt = (
        f"Triage target agent `{target}` in read-only mode before remediation.\n"
        f"1. Inspect `/proc` for running `{target}` or child MCP processes with poisoned environment "
        f"variables (`LD_PRELOAD`, `NODE_OPTIONS`, `PYTHONSTARTUP`, non-loopback `*_BASE_URL`, or inline secrets).\n"
        f"2. Run `python3 bin/agentcfg --json cleanse --harness {shlex.quote(target)} --scope all --dry-run` "
        f"to detect corrupted JSON/TOML/YAML configs, broken SQLite databases (`PRAGMA quick_check`), "
        f"dead-PID lock files, symlink escapes, permissive file modes (`0666`/`0777`), or poisoned memory.\n"
        f"3. {project_clause}\n"
        f"4. Do NOT modify or delete any files and NEVER print plaintext credentials.\n"
        f"Return your structured triage findings for `{target}`."
    )
    return agent(
        prompt=prompt,
        schema=TRIAGE_SCHEMA,
        role=f"Triage {target}",
        type_name="research",
        workspace="inherit",
    )


triage_reports = await parallel(target_agents, _build_triage_agent)
for report in triage_reports:
    log(
        f"[triage:{report.get('agent')}] proc={len(report.get('proc_anomalies', []))} "
        f"corrupt={len(report.get('config_corruption', []))} "
        f"risks={len(report.get('workspace_risks', []))} -> {report.get('summary')}"
    )


# ---------------------------------------------------------------------------
# Phase 2: Staged Remediation via bin/agentcfg-remediate
# ---------------------------------------------------------------------------
phase("staged_remediation")
log(f"Running staged_remediation for {', '.join(target_agents)} with profile={profile}")


def _build_remediate_cmd(target: str) -> str:
    cmd_parts = [
        "python3",
        "bin/agentcfg-remediate",
        "--agent",
        target,
        "--profile",
        profile,
        "--local-model",
        local_model,
        "--non-interactive",
        "--json",
    ]
    if offline:
        cmd_parts.append("--offline")
    if quiesce:
        cmd_parts.append("--quiesce")
    if resume:
        cmd_parts.append("--resume")
    if from_backup:
        cmd_parts.extend(["--from-backup", str(from_backup)])
    if project_dir:
        cmd_parts.extend(["--project", str(project_dir)])
    return " ".join(shlex.quote(part) for part in cmd_parts)


async def _remediate_single_agent(target: str) -> dict:
    cmd = _build_remediate_cmd(target)
    log(f"[remediate:{target}] Executing: {cmd}")
    raw_output = await call_tool(
        "run_command",
        CommandLine=cmd,
        WaitMsBeforeAsync=10000,
        toolSummary=f"Remediate {target}",
    )
    parsed: dict = {"agent": target, "command": cmd, "raw_output": raw_output}
    for line in reversed((raw_output or "").splitlines()):
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                parsed = json.loads(stripped)
                break
            except Exception:
                pass
    if "raw_output" in parsed:
        try:
            start = raw_output.find("{")
            end = raw_output.rfind("}")
            if start != -1 and end != -1 and end > start:
                parsed = json.loads(raw_output[start : end + 1])
        except Exception:
            pass
    log(f"[remediate:{target}] Completed: ok={parsed.get('ok', False)}")
    return parsed


remediation_results = await pipeline(target_agents, _remediate_single_agent)


# ---------------------------------------------------------------------------
# Phase 3: Independent Verification
# ---------------------------------------------------------------------------
phase("independent_verification")
log("Running independent_verification across Remediation Receipts and live targets")

verify_cmd = "python3 bin/agentcfg --json verify"
verify_raw = await call_tool(
    "run_command",
    CommandLine=verify_cmd,
    WaitMsBeforeAsync=10000,
    toolSummary="Verify deployed agentcfg targets",
)

verifier_prompt = (
    f"Independently verify the completed remediation run for target agents {target_agents}.\n"
    f"1. Inspect the remediation outputs:\n{json.dumps(remediation_results, indent=2)}\n"
    f"2. Inspect the `python3 bin/agentcfg --json verify` output:\n{verify_raw}\n"
    f"3. Check the latest tamper-evident Remediation Receipts in `~/.local/state/agentcfg/receipts/` "
    f"and confirm all 8 stages (`0_bootstrap_verify` through `7_seal_and_receipt`) succeeded.\n"
    f"4. Run `python3 bin/agentcfg --json validate` and `gitleaks detect --source . --no-banner --redact` "
    f"to confirm zero policy errors and zero plaintext secret leaks.\n"
    f"5. Confirm Tier-B authentication files remain preserved at `0600`."
)

verification_report = await agent(
    prompt=verifier_prompt,
    schema=CHECK_SCHEMA,
    role="Independent Remediation Verifier",
    type_name="self",
    workspace="inherit",
)

log(
    f"[verification] verified={verification_report.get('verified')} "
    f"verify_ok={verification_report.get('agentcfg_verify_ok')} "
    f"auth_preserved={verification_report.get('auth_preserved')} "
    f"zero_secret_leaks={verification_report.get('zero_secret_leaks')}"
)

final_output = {
    "ok": bool(verification_report.get("verified")),
    "agents": target_agents,
    "profile": profile,
    "local_model": local_model,
    "triage_reports": triage_reports,
    "remediation_results": remediation_results,
    "verification": verification_report,
}
print(json.dumps(final_output, indent=2))
