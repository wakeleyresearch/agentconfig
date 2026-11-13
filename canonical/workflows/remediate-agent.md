---
name: remediate-agent
description: Step-by-step containment, forensic snapshot, harness-scoped cleanse, offline bundle recovery, and local Gemma 4 fallback workflow for hostile or degraded environments.
---

# `/remediate-agent` — Hostile-Environment Agent Onboarding & Remediation Workflow

Use this canonical workflow when onboarding a new coding agent harness or recovering an existing harness under simultaneous **malware indicators**, **corrupted configuration / SQLite / lock state**, and **degraded or offline network connectivity**.

---

## Quick Invocation

### 1. Standalone CLI / Interactive TUI (`bin/agentcfg-remediate`)

```bash
# Non-interactive single-agent remediation with offline local Gemma 4 fallback
python3 bin/agentcfg-remediate \
  --agent codex \
  --profile local-gemma \
  --local-model gemma4:e4b \
  --offline \
  --non-interactive \
  --json

# Interactive ANSI TUI wizard (auto-detects agent health and prompts for profile)
python3 bin/agentcfg-remediate --interactive

# Resume an interrupted remediation from the crash-safe journal
python3 bin/agentcfg-remediate --agent codex --resume --non-interactive --json
```

### 2. Integrated `agentcfg` Subcommands

```bash
# Onboard or remediate one or more harnesses via bin/agentcfg
python3 bin/agentcfg remediate --harness codex --profile local-gemma --local-model gemma4:e4b --offline
python3 bin/agentcfg onboard --harness gemini-cli --profile local-gemma --local-model gemma-4-E4B-it --offline
```

### 3. Dynamic Multi-Agent Orchestration (`run_workflow`)

Run [`workflows/remediate_agent_workflow.py`](../../workflows/remediate_agent_workflow.py) via the Antigravity `run_workflow` tool to execute **Phase 1 (`parallel_triage`)**, **Phase 2 (`staged_remediation`)**, and **Phase 3 (`independent_verification`)** across multiple target harnesses.

---

## Step-by-Step Remediation Procedure (Stages 0–7)

### Step 0: Offline Bundle Verification & Bootstrap (`0_bootstrap_verify`)

Before trusting the local repository working tree, verify Git HEAD integrity and tracked canonical files:

1. Check `git rev-parse --verify HEAD` and `python3 bin/agentcfg validate --skip-agy`.
2. If the repository is corrupted or unreachable and an offline backup bundle exists under `~/.local/share/agentconfig/backups/` (or is supplied via `--from-backup <bundle>`), extract the verified `.bundle` into an isolated `0700` staging directory (`~/.local/state/agentcfg/recovery-sot/`) and run all subsequent stages from that clean Source-of-Truth root.

```bash
# Recover directly from a verified offline git bundle
python3 bin/agentcfg-remediate \
  --agent claude-code \
  --from-backup ~/.local/share/agentconfig/backups/agentconfig-latest.bundle \
  --profile failsafe \
  --offline \
  --non-interactive
```

### Step 1: Live Process & Environment Audit (`1_process_and_env_audit`)

Inspect `/proc/<pid>/{cmdline,environ,fd,cwd}` for running instances of the target harness and child MCP servers:

1. Detect dangerous dynamic linker or runtime injection variables (`LD_PRELOAD`, `NODE_OPTIONS`, `PYTHONSTARTUP`).
2. Flag unauthorized non-loopback base URL overrides (`OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `GEMINI_API_BASE_URL`) or leaked inline credentials in process environments.
3. When `--quiesce` is enabled, send `SIGTERM` only to target agent processes that are **not** in the current operator process ancestor chain.

### Step 2: Forensic Evidence Capture & Tier-B Auth Lock (`2_forensic_capture`)

Preserve pre-remediation evidence before mutating any file on disk:

1. Copy existing target configs, hooks, and lockfiles into `~/.local/state/agentcfg/forensics/<UTC-ts>-<harness>/` (`0700`) with a SHA-256 `forensic-manifest.json` (`0600`).
2. Enforce the **Hard Auth-Preservation Invariant**: tighten existing Tier-B authentication files (`~/.codex/auth.json`, `~/.claude/.credentials.json`, `~/.gemini/oauth_creds.json`, `~/.gemini/antigravity-cli/antigravity-oauth-token`, `~/.config/gh/hosts.yml`, `~/.kimi-code/credentials/`, `~/.grok/auth.json`) to `0600` inside `0700` parent directories without ever deleting or overwriting them.

### Step 3: Zero-Trust Containment (`3_containment_failsafe`)

Immediately drop the target harness into a zero-trust containment state (`canonical/profiles/failsafe/`):

- Disables all external/remote MCP servers, lifecycle hooks, unsandboxed mods, and auto-memory capture.
- Enforces read-only sandboxing and explicit human approval policies (`approval_policy = "on-request"`, `sandbox_mode = "read-only"`).

```bash
# Manual containment switch if triaging interactively
python3 bin/agentcfg failsafe --apply --harness codex
```

### Step 4: Harness-Scoped Deep Cleanse (`4_deep_cleanse`)

Quarantine corrupted configs, broken runtime SQLite databases, stale locks, and poisoned memory for the target harness only:

```bash
# Dry-run inspection scoped to a single harness
python3 bin/agentcfg cleanse --harness codex --scope all --dry-run

# Execute harness-scoped quarantine across config, runtime, and memory
python3 bin/agentcfg cleanse --harness codex --scope all --auto-quarantine
```

- **Config scope**: Quarantines truncated JSON/TOML/YAML, symlink escapes outside `$HOME`, world-writable files (`0666`/`0777`), undeclared hooks, and unverified `.pkl` files into `~/.local/state/agentcfg/quarantine/<UTC-ts>/` (`0700`).
- **Runtime scope**: Checks lockfile PID liveness before removing dead locks and runs read-only SQLite `PRAGMA quick_check` before quarantining corrupted `.sqlite`/`.db` state files (`state_5.sqlite`, `conversation_summaries.db`, `session-store.db`, `sessions.db`).
- **Memory scope**: Scans `MEMORY.md`, `GEMINI.md`, and local `~/.ollama/Modelfile` `SYSTEM` directives for prompt-injection/exfiltration patterns and invisible Unicode (`U+200B..U+200F`, `U+202A..U+202E`, `U+FEFF`, `U+E0000..U+E007F`).

### Step 5: Canonical or Local-Gemma Profile Deployment (`5_canonical_apply`)

Atomically render and deploy the selected profile (`canonical`, `failsafe`, or `local-gemma`) with `lstat()` parent verification, same-filesystem staging, `os.fsync`, and strict file modes (`0400`/`0444`/`0600`):

- **`--profile local-gemma` (Offline / Bad-Network Fallback)**:
  - **Google LiteRT-LM (`~/.litert-lm/config.json`)**: Binds strictly to `127.0.0.1:8080` (`telemetry: false`, `max_context_tokens: 32768`) with primary model `gemma-4-E4B-it`, tool router `functiongemma-270m-it`, and safety gate `shieldgemma-2-4b-it`.
  - **Ollama Loopback (`~/.ollama/agentcfg-ollama.env`)**: Binds `OLLAMA_HOST=127.0.0.1:11434` (`OLLAMA_NOHISTORY=1`, `OLLAMA_CONTEXT_LENGTH=32768`) serving `gemma4:e2b`, `gemma4:e4b`, `gemma4:26b` (MoE), `gemma4:31b`, `functiongemma:270m`, and `shieldgemma2:4b`.
  - **Per-Harness Loopback Profiles**: Renders `~/.codex/local-gemma.config.toml` (`http://127.0.0.1:11434/v1/`), `~/.config/opencode/profiles/local-gemma.opencode.jsonc`, `~/.gemini/profiles/local-gemma.settings.json` (`http://127.0.0.1:8080`), and `~/.config/goose/profiles/local-gemma.config.yaml`.

### Step 6: Airgapped Canary Verification (`6_airgapped_canary`)

Verify deployed target checksums and permissions via `verify_deployed` and execute an airgapped `bwrap --unshare-net --clearenv` canary check parsing the rendered JSON/TOML/YAML configuration files with zero network access.

### Step 7: Tamper-Evident Receipt & Seal (`7_seal_and_receipt`)

Write a signed/hashed JSON Remediation Receipt to `~/.local/state/agentcfg/receipts/<UTC-ts>-<harness>.json` (`0600`) recording:

- Completed stage timestamps and journal state (`~/.local/state/agentcfg/remediation-journal.json`).
- Forensic bundle path and SHA-256 manifest digest.
- Quarantine directory path and count of quarantined items.
- Deployed target SHA-256 digests, active profile (`canonical`, `failsafe`, or `local-gemma`), and local model selection (`gemma4:e4b`).
- Overall receipt SHA-256 integrity seal.
