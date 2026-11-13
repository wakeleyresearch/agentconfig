# Hostile-Environment Agent Onboarding, Remediation & Google Local Models Runbook

> **Document Status**: Operator Architecture & Runbook (`wakeleyresearch/agentconfig`, Phase 5) — Implemented across [`lib/remediate.py`](../lib/remediate.py), [`lib/cleanse.py`](../lib/cleanse.py), [`bin/agentcfg-remediate`](../bin/agentcfg-remediate), [`bin/agentcfg`](../bin/agentcfg), [`canonical/harnesses/{litert-lm,ollama}.json`](../canonical/harnesses/), [`canonical/profiles/local-gemma/`](../canonical/profiles/local-gemma/), [`canonical/workflows/remediate-agent.md`](../canonical/workflows/remediate-agent.md), and [`workflows/remediate_agent_workflow.py`](../workflows/remediate_agent_workflow.py).

---

## Table of Contents

1. [Triple-Failure Threat Model (Malware + Corruption + Bad Network)](#1-triple-failure-threat-model-malware--corruption--bad-network)
2. [8-Stage Crash-Journaled Remediation Pipeline (`Stage 0` – `Stage 7`)](#2-8-stage-crash-journaled-remediation-pipeline-stage-0--stage-7)
3. [CLI & Interactive TUI Reference](#3-cli--interactive-tui-reference)
4. [Google Local Models Integration (2025–2026 Ecosystem)](#4-google-local-models-integration-20252026-ecosystem)
5. [Antigravity Dynamic Remediation Workflow (`run_workflow`)](#5-antigravity-dynamic-remediation-workflow-run_workflow)
6. [Incident Response & Operator Playbooks](#6-incident-response--operator-playbooks)

---

## 1. Triple-Failure Threat Model (Malware + Corruption + Bad Network)

Traditional configuration managers assume a benign workstation with intact configuration files, healthy SQLite state, and reliable internet connectivity. In real-world incident response and field operations, operators frequently face **three simultaneous failure modes** when onboarding or recovering an AI coding agent:

```text
+-----------------------------------------------------------------------------------+
|                    HOSTILE / DEGRADED WORKSTATION ENVIRONMENT                     |
+---------------------------+---------------------------+---------------------------+
|     1. ACTIVE MALWARE     |   2. STATE CORRUPTION     |  3. BAD / OFFLINE NETWORK |
|                           |                           |                           |
| - Rogue PreToolUse hooks  | - Truncated JSON/TOML     | - Airgapped / captive     |
| - Floating npx/uvx MCPs   |   from SIGKILL / OOM      |   portal / DNS hijack     |
| - /proc env poisoning     | - Corrupt SQLite DBs      | - Unreachable cloud APIs  |
|   (LD_PRELOAD, *_BASE_URL)|   (state_5, summaries.db) |   (OpenAI/Anthropic/Google|
| - Symlink traps -> /etc   | - Dead-PID lockfiles      |   endpoints timeout)      |
| - World-writable 0777     | - Stranded -wal/-shm      | - Corrupted or missing    |
| - Poisoned MEMORY.md &    |   journals                |   working tree without    |
|   Ollama Modelfile SYSTEM | - Permissive 0644 auth    |   upstream Git access     |
+---------------------------+---------------------------+---------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|               bin/agentcfg-remediate (8-Stage Crash-Safe Pipeline)                |
|                                                                                   |
|  Stage 0: Bootstrap & Offline Bundle Recovery  -->  ~/.local/state/agentcfg/      |
|  Stage 1: Live /proc & Env Audit (--quiesce)        recovery-sot/ (0700)          |
|  Stage 2: Forensic Snapshot & 0600 Auth Lock   -->  forensics/<ts>-<agent>/       |
|  Stage 3: Zero-Trust Failsafe Containment                                         |
|  Stage 4: Harness-Scoped Deep Cleanse          -->  quarantine/<ts>/ (0700)       |
|  Stage 5: Canonical / Local-Gemma Apply        -->  127.0.0.1:8080 / :11434       |
|  Stage 6: Airgapped bwrap Canary Verification                                     |
|  Stage 7: Tamper-Evident SHA-256 Receipt       -->  receipts/<ts>-<agent>.json    |
+-----------------------------------------------------------------------------------+
```

### 1.1 Failure Class A: Active Malware & Persistence Vectors

| Vector | Surface | Detection & Remediation Control |
| :--- | :--- | :--- |
| **Live Process Injection** | `/proc/<pid>/environ` (`LD_PRELOAD`, `NODE_OPTIONS`, `PYTHONSTARTUP`), unauthorized `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` / `GEMINI_API_BASE_URL` overrides, inline `sk-*` / `ghp_*` tokens in child MCP processes. | `audit_live_agent_processes()` inspects `/proc/<pid>/{cmdline,environ,fd,cwd}` before touching disk; optional `--quiesce` sends `SIGTERM` to non-ancestor target processes. |
| **Rogue Hooks & Floating MCPs** | `.agents/hooks.json`, `~/.codex/config.toml`, `~/.claude.json`, `.mcp.json` launching unpinned package runners or shell reverse pipes. | Stage 2 captures forensic copies (`0700`); Stage 3 applies zero-trust failsafe; Stage 4 quarantines undeclared hooks/MCPs; Stage 5 renders locked SoT targets. |
| **Symlink Escapes & Permissive Modes** | Symlinks inside `~/.codex/`, `~/.claude/`, `~/.gemini/`, `~/.ollama/` pointing outside `$HOME` (e.g. `/etc/passwd`) or `0666`/`0777` files/blobs. | `lstat()` parent traversal guards (`safe_target`) + `run_cleanse` symlink containment checks + automatic quarantine of out-of-tree symlinks and world-writable files. |
| **Persistent Memory & Modelfile Poisoning** | Prompt-injection directives (`ignore previous instructions`, `curl ...`, invisible Unicode `U+200B..U+200F`, `U+202A..U+202E`, `U+FEFF`, `U+E0000..U+E007F`) in `~/.codex/memories/MEMORY.md`, `~/.claude/projects/*/memory/*.md`, `~/.gemini/GEMINI.md`, or local `~/.ollama/Modelfile` `SYSTEM` prompts and unverified `.pkl` weights. | `run_cleanse(..., scope="all", harnesses={...})` scans memory files and local model manifests for `MEMORY_POISON_PATTERNS`, invisible Unicode, and pickle payloads, quarantining tainted files with `chmod 0400`. |

### 1.2 Failure Class B: Corrupted Configuration, SQLite & Runtime Locks

1. **Truncated JSON / JSONC / TOML / YAML Configs**: Power loss, `SIGKILL`, or OOM kills during agent self-updates leave half-written `~/.gemini/settings.json`, `~/.codex/config.toml`, `~/.config/opencode/opencode.jsonc`, or `~/.litert-lm/config.json`.
2. **Corrupted SQLite Databases & Stranded WAL/SHM Journals**: Unclean shutdowns corrupt `~/.codex/state_5.sqlite`, `logs_2.sqlite`, `memories_1.sqlite`, `memories_v2_1.sqlite`, `~/.gemini/antigravity-cli/conversation_summaries.db`, `~/.copilot/session-store.db`, or `~/.local/share/goose/sessions/sessions.db`. `run_cleanse` runs read-only `PRAGMA quick_check` via Python's stdlib `sqlite3` and quarantines damaged DBs alongside orphaned `-wal`/`-shm` journals.
3. **Dead-PID Lockfiles**: Stale `session.lock`, `updater/update.lock`, `presence/*.lock`, `updates/install.lock`, or `SingletonLock` files block agent startup. `run_cleanse` verifies PID liveness via `/proc/<pid>` before quarantining dead lockfiles.
4. **Tier-B Credential Preservation**: Throughout every stage, native OAuth and session credential files (`~/.codex/auth.json`, `~/.claude/.credentials.json`, `~/.gemini/oauth_creds.json`, `~/.gemini/antigravity-cli/antigravity-oauth-token`, `~/.config/gh/hosts.yml`, `~/.kimi-code/credentials/`, `~/.grok/auth.json`) are **never** deleted or overwritten; if found with permissive modes (`0644`), Stage 2 tightens them in place to `0600`.

### 1.3 Failure Class C: Degraded, Hostile, or Offline Network

1. **Unreachable Cloud Endpoints**: When cloud APIs (`api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`) are unreachable or untrusted (captive portal, MITM proxy, airgapped lab), agents fail closed or hang on startup.
2. **Corrupted Local Git Working Tree**: If `/home/omniboot/agentconfig` itself has a damaged working tree and cannot `git fetch` from GitHub, Stage 0 (`verify_or_recover_sot_repo`) automatically recovers from a verified offline Git bundle (`~/.local/share/agentconfig/backups/*.bundle` created by `bin/agentcfg-backup` or passed via `--from-backup`) into `~/.local/state/agentcfg/recovery-sot/` (`0700`).
3. **Loopback-Only Local Model Fallback (`--profile local-gemma`)**: Switches supported harnesses to strictly loopback-bound (`127.0.0.1:8080` LiteRT-LM or `127.0.0.1:11434` Ollama) **Google Gemma 4**, **FunctionGemma**, and **ShieldGemma 2** inference with zero outbound network dependency.

---

## 2. 8-Stage Crash-Journaled Remediation Pipeline (`Stage 0` – `Stage 7`)

`RemediationOrchestrator` in [`lib/remediate.py`](../lib/remediate.py) executes an 8-stage state machine for each target harness. Every transition is atomically journaled to `~/.local/state/agentcfg/remediation-journal.json` (`0600`) so an interrupted run can be resumed at the exact uncompleted stage via `--resume`.

| Stage ID | Stage Name | Key Operations & Invariants | Artifacts Produced |
| :--- | :--- | :--- | :--- |
| **`0_bootstrap_verify`** | **Bootstrap & Offline Bundle Recovery** | Verifies Git HEAD and tracked canonical files (`verify_or_recover_sot_repo`). If corrupted or `--from-backup <bundle>` is specified, clones the verified `.bundle` into `~/.local/state/agentcfg/recovery-sot/` (`0700`). | `remediation-journal.json` (`0600`), optional `recovery-sot/` (`0700`) |
| **`1_process_and_env_audit`** | **Live `/proc` & Environment Audit** | Scans `/proc/<pid>/{cmdline,environ,fd,cwd}` (`audit_live_agent_processes`) for target agent processes, `LD_PRELOAD` / `NODE_OPTIONS` / `PYTHONSTARTUP`, non-loopback `*_BASE_URL`, and inline secrets. Optional `--quiesce` sends `SIGTERM` to non-ancestor target processes. | Process audit findings recorded in journal & receipt |
| **`2_forensic_capture`** | **Forensic Snapshot & Tier-B Auth Lock** | Copies existing target configs, hooks, and lockfiles into `forensics/<UTC-ts>-<harness>/` (`0700`) with SHA-256 `forensic-manifest.json` (`0600`). Tightens any existing `PROTECTED_AUTH_REL_PATHS` in `$HOME` to `0600` without modifying their contents. | `~/.local/state/agentcfg/forensics/<UTC-ts>-<harness>/forensic-manifest.json` (`0600`) |
| **`3_containment_failsafe`** | **Zero-Trust Failsafe Containment** | Atomically deploys the harness's zero-trust `failsafe` profile (`failsafe_apply(ctx, harnesses={harness})`), immediately disabling external MCPs, hooks, unsandboxed mods, and auto-memory. | Pre-failsafe snapshot under `snapshots/` |
| **`4_deep_cleanse`** | **Harness-Scoped Deep Cleanse** | Runs `run_cleanse(ctx, scope="all", apply=True, harnesses={harness})` to quarantine invalid configs, broken symlinks, `0666`/`0777` files, dead-PID locks, corrupt SQLite DBs (`PRAGMA quick_check`), and poisoned memory/`Modelfile` files into `quarantine/<UTC-ts>/` (`0700`). | `~/.local/state/agentcfg/quarantine/<UTC-ts>/quarantine-manifest.json` (`0600`) |
| **`5_canonical_apply`** | **Canonical or Local-Gemma Apply** | Deploys the requested `--profile` (`canonical`, `failsafe`, or `local-gemma`) via `apply_targets(ctx, harnesses={harness})` with `lstat()` parent checks, same-dir temp staging, `os.fsync`, and `0400`/`0444`/`0600` modes. Records `local-gemma` profile paths and `--local-model`. | Rendered live configs + updated `deployed-manifest.json` (`0600`) |
| **`6_airgapped_canary`** | **Airgapped Canary Verification** | Validates live SHA-256 digests and file permissions via `verify_deployed(ctx, harnesses={harness})` and, when `bwrap` is installed, runs an isolated `bwrap --unshare-net --clearenv --ro-bind / /` syntax/parse canary check. | Canary verification status (`verify_ok`, `bwrap_canary_ok`) |
| **`7_seal_and_receipt`** | **Tamper-Evident Receipt & Seal** | Writes a comprehensive JSON receipt to `~/.local/state/agentcfg/receipts/<UTC-ts>-<harness>.json` (`0600`) sealed with an overall `receipt_sha256` digest and marks the journal completed. | `~/.local/state/agentcfg/receipts/<UTC-ts>-<harness>.json` (`0600`) |

---

## 3. CLI & Interactive TUI Reference

### 3.1 Standalone `bin/agentcfg-remediate`

```text
bin/agentcfg-remediate [--agent <name|all>] [--profile {canonical,failsafe,local-gemma}] \
  [--local-model <model>] [--offline] [--from-backup <bundle>] [--quiesce] \
  [--resume] [--project <dir>] [--repo <dir>] [--home <dir>] [--state-dir <dir>] \
  [--interactive | --non-interactive] [--json] [--status]
```

#### Common Invocation Patterns

```bash
# 1. Interactive ANSI TUI Wizard (auto-launches when stdin is a TTY)
bin/agentcfg-remediate --interactive

# 2. Non-interactive JSON remediation of Codex with local Gemma 4 E4B over loopback
bin/agentcfg-remediate \
  --agent codex \
  --profile local-gemma \
  --local-model gemma4:e4b \
  --offline \
  --non-interactive \
  --json

# 3. Remediate all harnesses into strict zero-trust failsafe mode, quiescing rogue processes
bin/agentcfg-remediate \
  --agent all \
  --profile failsafe \
  --quiesce \
  --offline \
  --non-interactive

# 4. Recover from an offline git bundle when the local repo is damaged
bin/agentcfg-remediate \
  --agent claude-code \
  --from-backup ~/.local/share/agentconfig/backups/agentconfig-latest.bundle \
  --profile canonical \
  --non-interactive

# 5. Inspect journal status or resume an interrupted run
bin/agentcfg-remediate --status --json
bin/agentcfg-remediate --agent codex --resume --non-interactive --json
```

### 3.2 `bin/agentcfg` Subcommands (`remediate`, `onboard`, `cleanse --harness`)

```bash
# Harness-scoped cleanse (inspect or quarantine ONLY the specified harness roots)
python3 bin/agentcfg cleanse --harness codex --harness ollama --scope all --dry-run
python3 bin/agentcfg cleanse -H codex -H litert-lm --scope all --auto-quarantine

# Remediate an existing harness through Stages 0-7
python3 bin/agentcfg remediate --harness codex --profile local-gemma --local-model gemma4:e4b --offline

# Onboard a fresh or untrusted harness with full forensic & canary verification
python3 bin/agentcfg onboard --harness opencode --profile local-gemma --local-model gemma4:26b --offline
```

---

## 4. Google Local Models Integration (2025–2026 Ecosystem)

To ensure resilient operation during cloud outages, bad networks, or airgapped incident response, `agentconfig` integrates Google's 2025–2026 local model family and local inference runtimes as first-class managed harnesses (`litert-lm` and `ollama`) and per-agent `--profile local-gemma` profiles.

### 4.1 Supported Google Local Model Catalog

| Model Family | Canonical Identifiers (Ollama / LiteRT-LM) | Architecture & Parameters | Primary Role in `agentconfig` |Recommended Hardware Tier |
| :--- | :--- | :--- | :--- | :--- |
| **Gemma 4 Effective 2B** | `gemma4:e2b` / `gemma-4-E2B-it` | Effective 2B (MatFormer sub-network, Apache 2.0, multimodal text/image/audio) | Ultra-low-latency CPU/edge fallback & airgapped canary triage | `>= 4 GiB` RAM (CPU / iGPU) |
| **Gemma 4 Effective 4B** | `gemma4:e4b` / `gemma-4-E4B-it` | Effective 4B (MatFormer, 128K context window; pinned at `32,768` locally) | **Default `--local-model`** for `--profile local-gemma` across Codex, Gemini CLI, OpenCode V2, and Goose | `>= 8 GiB` RAM / VRAM |
| **Gemma 4 26B MoE** | `gemma4:26b` / `gemma-4-26B-A4B-it` | 26B total / **~3.8B active** Mixture-of-Experts (`A4B`), 256K native context | High-speed multi-file coding & reasoning at 4B active inference cost | `>= 16–24 GiB` unified RAM / VRAM |
| **Gemma 4 31B Dense** | `gemma4:31b` / `gemma-4-31B-it` | 31B dense transformer, 256K native context, native system/thinking/tool tokens | Deep architectural synthesis & complex refactoring on workstation GPUs | `>= 24–32 GiB` VRAM / unified RAM |
| **Gemma 3 & Gemma 3n** | `gemma3:4b`, `gemma3:12b`, `gemma3:27b`, `gemma3n:e2b`, `gemma3n:e4b` | 1B–27B dense + Gemma 3n MatFormer mobile/laptop variants | Backward-compatible local coding & lightweight offline assistance | `4–24 GiB` RAM / VRAM |
| **FunctionGemma 270M** | `functiongemma:270m` / `functiongemma-270m-it` | 270M specialized deterministic function-calling & MCP tool-routing model | Fast local tool-call formatting and deterministic JSON schema routing alongside Gemma 4 | `< 1 GiB` RAM (runs alongside primary model) |
| **ShieldGemma 2 4B** | `shieldgemma2:4b` / `shieldgemma-2-4b-it` | 4B input/output safety & policy classifier (text + image) | Pre-execution prompt-injection & tool-output safety gate on loopback | `~3–4 GiB` RAM |

### 4.2 Hardened Local Runtimes (`litert-lm` & `ollama`)

Both local runtimes are managed in [`targets/targets.json`](../targets/targets.json) and enforced by [`policy/security-policy.json`](../policy/security-policy.json):

1. **Google LiteRT-LM (`canonical/harnesses/litert-lm.json` -> `~/.litert-lm/config.json`, `0600`)**:
   - Binds strictly to loopback (`"host": "127.0.0.1"`, `"port": 8080`, `"allow_remote": false`, `"telemetry": false`).
   - Configures `"default_model": "gemma-4-E4B-it"`, `"tool_router_model": "functiongemma-270m-it"`, `"safety_classifier_model": "shieldgemma-2-4b-it"`, and `"max_context_tokens": 32768`.
   - Powers **Gemini CLI native local routing** (`gemini gemma` / `experimental.gemma` in `~/.gemini/profiles/local-gemma.settings.json`).

2. **Ollama Hardened Loopback (`canonical/harnesses/ollama.json` -> `~/.ollama/agentcfg-ollama.env`, `0600`)**:
   - Enforces `OLLAMA_HOST=127.0.0.1:11434` (preventing `0.0.0.0:11434` LAN exposure), `OLLAMA_NOHISTORY=1`, `OLLAMA_ORIGINS=http://127.0.0.1,http://localhost`, and `OLLAMA_CONTEXT_LENGTH=32768` (preventing Ollama's default 2K–4K context truncation from breaking large agent system prompts and tool schemas).
   - `lib/cleanse.py` scans `~/.ollama/` and `~/.litert-lm/` for world-writable model blobs (`0666`/`0777`), symlink escapes, unverified `.pkl` files, and poisoned `Modelfile` `SYSTEM` prompts.

### 4.3 Per-Harness `local-gemma` Loopback Profiles

When `--profile local-gemma` is selected, `agentcfg` deploys standalone loopback configurations that pass `policy/security-policy.json`'s `local_model_loopback` allowlist (`http://127.0.0.1:11434` and `http://127.0.0.1:8080`, while still blocking `http://0.0.0.0*` and all remote `http://` endpoints):

| Harness | Deployed `local-gemma` Target Path | Loopback Endpoint & Configuration | How to Launch in Offline Local-Gemma Mode |
| :--- | :--- | :--- | :--- |
| **OpenAI Codex CLI** | `~/.codex/local-gemma.config.toml` (`0600`) | `model = "gemma4:e4b"`, `model_provider = "ollama"`, `approval_policy = "on-request"`, `sandbox_mode = "read-only"`, `[model_providers.ollama]` `base_url = "http://127.0.0.1:11434/v1/"`, `wire_api = "responses"` | `codex --profile local-gemma` (or `codex --oss -m gemma4:e4b`) |
| **Google Gemini CLI** | `~/.gemini/profiles/local-gemma.settings.json` (`0600`) | `experimental.gemma` enabled against LiteRT-LM `http://127.0.0.1:8080` (`gemma-4-E4B-it` + `functiongemma-270m-it` + `shieldgemma-2-4b-it`), `mcpServers: {}` | `gemini gemma` or `GEMINI_CLI_HOME=... gemini --approval-mode plan --sandbox` |
| **OpenCode V2** | `~/.config/opencode/profiles/local-gemma.opencode.jsonc` (`0600`) | `provider.ollama` at `http://127.0.0.1:11434/v1` with `gemma4:e4b` and `gemma4:26b` (`num_ctx: 32768`), `permissions.external_directory: "ask"` | `OPENCODE_CONFIG=~/.config/opencode/profiles/local-gemma.opencode.jsonc opencode --standalone` |
| **Goose** | `~/.config/goose/profiles/local-gemma.config.yaml` (`0600`) | `GOOSE_PROVIDER: "ollama"`, `GOOSE_MODEL: "gemma4:e4b"`, `OLLAMA_HOST: "127.0.0.1:11434"`, `extensions: {}` | ` goose run --no-session` (with `local-gemma.config.yaml`) |
| **Aider** | `~/.aider.conf.yml` (`0444`) | Compatible with `model: ollama_chat/gemma4:e4b` via `OLLAMA_API_BASE=http://127.0.0.1:11434` (`--no-check-update --no-restore-chat-history`) | `OLLAMA_API_BASE=http://127.0.0.1:11434 aider --model ollama_chat/gemma4:e4b --no-check-update` |

---

## 5. Antigravity Dynamic Remediation Workflow (`run_workflow`)

[`workflows/remediate_agent_workflow.py`](../workflows/remediate_agent_workflow.py) and [`workflows/workflow.json`](../workflows/workflow.json) provide a 3-phase dynamic workflow for Antigravity (`agy`):

1. **Phase 1 (`parallel_triage`)**: Uses `parallel(target_agents, ...)` to fan out read-only `research` agents across `args.get("agents", ["codex", "claude-code", "gemini-cli", "opencode"])`. Each agent inspects `/proc` anomalies, runs `agentcfg cleanse --harness <agent> --scope all --dry-run`, and audits workspace risks (`agentcfg audit-repo`).
2. **Phase 2 (`staged_remediation`)**: Uses `pipeline(target_agents, ...)` and `call_tool("run_command", ...)` to execute `python3 bin/agentcfg-remediate --agent <target> --profile <profile> --local-model <model> --non-interactive --json` sequentially without lock contention.
3. **Phase 3 (`independent_verification`)**: Spawns an independent verification agent to inspect the generated Remediation Receipts under `~/.local/state/agentcfg/receipts/`, run `python3 bin/agentcfg --json verify` and `python3 bin/agentcfg --json validate`, confirm Tier-B auth preservation (`0600`), and verify zero secret leaks.

---

## 6. Incident Response & Operator Playbooks

### Playbook 1: Compromised Workspace + Corrupt Codex State + Offline Network

```bash
# Step 1: Audit the suspect repository read-only
python3 bin/agentcfg audit-repo --strict /path/to/suspect-repo

# Step 2: Run full 8-stage remediation for Codex, quiescing live processes and switching to local Gemma 4
python3 bin/agentcfg-remediate \
  --agent codex \
  --profile local-gemma \
  --local-model gemma4:e4b \
  --quiesce \
  --offline \
  --non-interactive \
  --json

# Step 3: Verify deployed targets and inspect the tamper-evident receipt
python3 bin/agentcfg verify --harness codex
ls -la ~/.local/state/agentcfg/receipts/
```

### Playbook 2: Auditing & Cleansing Local Model Runtimes (`ollama` & `litert-lm`)

```bash
# Dry-run scan of ~/.ollama and ~/.litert-lm for poisoned Modelfiles, .pkl files, or 0666 blobs
python3 bin/agentcfg cleanse --harness ollama --harness litert-lm --scope all --dry-run

# Quarantine detected threats and re-render hardened loopback configs (127.0.0.1:11434 & 127.0.0.1:8080)
python3 bin/agentcfg-remediate --agent ollama --profile local-gemma --offline --non-interactive
python3 bin/agentcfg-remediate --agent litert-lm --profile local-gemma --offline --non-interactive
```
