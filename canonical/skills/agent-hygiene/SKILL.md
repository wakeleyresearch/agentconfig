---
name: agent-hygiene
description: >-
  Audit unfamiliar repositories, validate canonical agent configurations, and
  recover safely from corrupted state or poisoned memory using agentcfg. Use when
  opening an unreviewed workspace, inspecting MCP/hook/rule safety, or running
  clean-room diagnostics.
---

# Agent Hygiene & Safe Operations

Use this skill when vetting an unfamiliar workspace, checking configuration
integrity, or recovering from broken runtime state.

## Pre-Trust Repository Audit

Before trusting or executing tools inside an unfamiliar repository:

1. Run `agentcfg audit-repo <path>` to inspect for workspace MCP configs,
   lifecycle hooks, custom environment overrides, and invisible Unicode
   directives.
2. Inspect any reported configuration files read-only before accepting folder
   trust prompts.
3. For risky or untrusted codebases, launch sessions inside `agent-env-run
   --untrusted` or `agent-env-run --failsafe` so host credentials remain
   isolated.

## Configuration & Secret Verification

1. Run `agentcfg validate` before staging or applying configuration changes.
2. Verify live targets match the signed repository baseline via `agentcfg diff`
   and `agentcfg verify`.
3. Never embed literal tokens or static authorization headers in configuration
   files; bind credentials out-of-band via `secret_ref` and `mcp-secret-exec`.

## Safe Cleanse & Recovery

1. Preview state diagnostics with `agentcfg cleanse --scope runtime --dry-run`
   or `agentcfg cleanse --scope config --dry-run` before quarantining corrupted
   files.
2. Confirm native authentication files remain untouched; never pass destructive
   auth flags unless explicitly requested by the user.
3. Use `agentcfg failsafe --apply` (and `--restore` afterward) or ephemeral
   `agent-env-run --failsafe <harness>` for zero-trust triage.
