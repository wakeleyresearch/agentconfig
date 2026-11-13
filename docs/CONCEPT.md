# `agentconfig` Architecture & Threat-Model Concept Paper

> **Document Status**: Draft Concept & Verified Architecture Specification (`wakeleyresearch/agentconfig`, branch `main`).  
> **Scope**: Defines the empirical host baseline, three-tier Source-of-Truth (SoT) model, per-harness configuration/memory/`/tmp/` specifications, supply-chain and pre-trust RCE defenses, `agentcfg cleanse` quarantine workflow, built-in `failsafe` profile mechanics, atomic deployment protocol, and local/upstream update-monitoring design.  
> **Research Provenance**: Synthesized from verified local host audits and official documentation research (`#7`, `#8`, `#15`, `#16`). Sections awaiting final per-harness schema reports from `@openai-anthropic` and `@emerging-harnesses` are explicitly marked as **Pending Deep Verification** while preserving cross-referenced facts already verified in the security architecture.

---

## Table of Contents

1. [Empirical Host & Local Environment Baseline](#1-empirical-host--local-environment-baseline)
2. [Three-Tier Source-of-Truth Architecture](#2-three-tier-source-of-truth-architecture)
3. [Target Models, Harnesses & Open Standards Specification](#3-target-models-harnesses--open-standards-specification)
4. [`/tmp/` & Agent Memory Surfaces and Hardening](#4-tmp--agent-memory-surfaces-and-hardening)
5. [Supply-Chain, Pre-Trust RCE & Network Resilience Threat Model](#5-supply-chain-pre-trust-rce--network-resilience-threat-model)
6. [`agentcfg cleanse` & Quarantine Workflow](#6-agentcfg-cleanse--quarantine-workflow)
7. [Built-in `failsafe` Profile Mechanics](#7-built-in-failsafe-profile-mechanics)
8. [Atomic Deployment, Integrity Verification & Cryptographic Provenance](#8-atomic-deployment-integrity-verification--cryptographic-provenance)
9. [Update-Change, Config-Migration & Schema-Evolution Monitoring](#9-update-change-config-migration--schema-evolution-monitoring)
10. [Open Design Decisions & Next Steps](#10-open-design-decisions--next-steps)

---

## 1. Empirical Host & Local Environment Baseline

The architecture targets multi-harness Linux workstations anchored to the observed baseline on `/home/omniboot` (**Ubuntu 24.04.5 LTS x86_64**, `uid=1000(omniboot)`, **`umask 0002`**, `1.9 GiB` RAM, `1.0 GiB` swap):

| Dimension | Observed Host State | Security / Operational Implication |
| :--- | :--- | :--- |
| **Root & Temp Filesystems** | `/tmp` (`1777 root:root`) and `/var/tmp` (`1777 root:root`) sit directly on `/` (`/dev/sda1`, `ext4`, `38G` total, `30G` avail, mounted `defaults`). | No `nosuid`, `nodev`, `noexec`, or size quota on `/tmp` or `/var/tmp`; runaway agent temp files threaten root disk exhaustion. |
| **Shared Memory & Runtime Dir** | `/dev/shm` (`1777 root:root`) is `tmpfs` (`958M`, `rw,nosuid,nodev,inode64` — **missing `noexec`**); `/run/user/1000` (`0700`) is `tmpfs` (`196092k` ≈ `191 MiB`, `rw,nosuid,nodev`). | Pointing `$TMPDIR` blindly at `/run/user/1000` causes `ENOSPC` on AppImages and package unpacks; `/dev/shm` allows execution. |
| **Session Environment Gaps** | `XDG_RUNTIME_DIR`, `TMPDIR`, `TEMP`, and `TMP` are **unset** in non-login subshells; `xrdp`/`dbus-launch` sets `DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/dbus-*` with `srwxrwxrwx` sockets. | Agent subshells and background runners fall back to world-writable `/tmp` unless wrapped explicitly. |
| **Kernel & `tmpfiles` State** | `fs.protected_symlinks=1`, `fs.protected_hardlinks=1`, `fs.protected_regular=2`, `fs.protected_fifos=1`. `/usr/lib/tmpfiles.d/tmp.conf` cleans `/tmp` at `30d`, while `/var/tmp` cleanup is commented out (`#q /var/tmp 1777 root root 30d`). `loginctl` `Linger=yes`; user `systemd-tmpfiles-setup.service` & `systemd-tmpfiles-clean.timer` exist (`disabled`, preset `enabled`). | Kernel `fs.protected_*` prevents *cross-UID* symlink/regular attacks in `1777` dirs, **not same-UID** compromises; `/var/tmp` retains leftovers indefinitely. |
| **Installed Local Harness** | `agy` CLI `1.5.8` (`/home/omniboot/.local/bin/agy`) + `/home/omniboot/.gemini/` + `~/.cache/antigravity/`. Neither `~/.codex`, `~/.claude`, `~/.copilot`, `~/.kimi`, `~/.grok`, `~/.cursor`, `~/.config/opencode`, nor upstream `~/.gemini/settings.json` / `~/.gemini/GEMINI.md` exist yet. | Clean opportunity to establish hardened permissions and canonical SoT before deploying additional harnesses. |
| **Permissive Permission Drift** | `umask 0002` caused `~/.gemini/` (`0755`), `antigravity-cli/` (`0755`), `config/` (`0755`), `~/.cache/antigravity/staging/` (`0775`), `conversation_summaries.db*` (`0644`), `log/cli-*.log` (`0644`), `crashes/*.log` (`0644`), `annotations/*.pbtxt` (`0644`), `implicit/*.pb` (`0644`), `brain/<uuid>/` (`0755`), `config/mcp_config.json` (`0644`) to be world-readable. Only `antigravity-oauth-token`, `antigravity-cli/settings.json`, `conversations/*.db*`, `history.jsonl`, `jetski_state.pbtxt`, `jetbox_summaries_proto.pb`, `updater/*`, and `config/config.json` were `0600`. | Local processes/accounts can read conversation summaries, logs, annotations, and MCP configurations unless explicitly hardened to `0700`/`0600` and launched under `umask 0077`. |
| **Available vs Missing Tooling** | **Installed**: `git 2.43.0`, `python3 3.12.3` (`tomllib`, `json`, `hashlib`, `fcntl`, `sqlite3` stdlib), `jq 1.7`, `gpg 2.4.4`, `ssh-keygen`, `bwrap 0.9.0`, `systemd 255`, `sha256sum 9.4`, `flock 2.39.3`, `gnome-keyring-daemon`. **Missing**: `sops`, `age`, `gitleaks`, `trufflehog`, `secret-tool` (`libsecret-tools`), `yq`, `node`/`npm`/`npx`, `uv`/`uvx`, `~/.ssh`. | Core `bin/agentcfg` must run on pure Python 3.12 stdlib with built-in regex/entropy secret fallbacks, treating external tools as progressively enhanced gates. |

---

## 2. Three-Tier Source-of-Truth Architecture

`agentconfig` enforces strict separation between declarative configuration, secrets, and mutable runtime state:

### 2.1 Tier Definitions

1. **Tier A — Canonical Declarative Source-of-Truth (Git-tracked in `/home/omniboot/agentconfig`)**
   - Contains canonical rules (`canonical/rules/`), reviewed skills (`canonical/skills/`), reviewed hooks (`canonical/hooks/`), the canonical MCP registry (`canonical/mcp-registry.json` referencing `secret_ref` IDs—never raw tokens), per-harness deterministic render specs (`canonical/harnesses/`), failsafe profiles (`canonical/profiles/failsafe/`), security policies & lockfiles (`policy/`), target mapping (`targets/targets.json`), environment/secret wrappers (`wrappers/`), and the sync engine (`bin/agentcfg`).
   - Every commit and release tag is signed via SSH (`git config gpg.format ssh`) and gated by `.githooks/pre-commit`.

2. **Tier B — Secrets & Authentication (NEVER committed in plaintext)**
   - **Runtime API tokens & MCP secrets**: Stored in `gnome-keyring` (`secret-tool`) and optionally backed up via `sops` + `age` in `secrets/secrets.enc.yaml` (encrypted to public `age` recipients defined in `secrets/.sops.yaml`, with private `age` key optionally stored in the keyring via `SOPS_AGE_KEY_CMD="secret-tool lookup application sops type age-key"`).
   - **Native OAuth / session auth files**: Remain out-of-band outside Git SoT with `0600` permissions inside `0700` parent directories (`~/.gemini/antigravity-cli/antigravity-oauth-token`, `~/.gemini/{oauth_creds.json,google_accounts.json}`, `~/.config/gh/hosts.yml`, `~/.claude/.credentials.json`, `~/.codex/auth.json`).
   - **Zero-leak runtime injection**: Stdio MCP servers and CLI runners never inherit ambient host secrets; `wrappers/mcp-secret-exec` clears the environment (`env -i`) and injects only the scoped credential variables required for that specific server.

3. **Tier C — Mutable Runtime State & `/tmp/` (Excluded from Git & SoT)**
   - SQLite conversation/summary DBs (`-wal`, `-shm`), transcripts, crash dumps, lockfiles, staging caches, updater state, and interactive app state files (`~/.gemini/config/{config.json,projects/,.migrated}`, `~/.gemini/trustedFolders.json`, `~/.copilot/config.json`, etc.).
   - Volatile temp files live exclusively inside private `0700` per-user directories (`$XDG_RUNTIME_DIR/agent-runtime` and `~/.local/tmp/`).

### 2.2 Deployment Strategies for Mixed Config Files

Harnesses do not always separate declarative config from runtime state cleanly:
- **`ro` (Declarative Target, `0400`/`0444`)**: For purely declarative target files (e.g., rules, prompts, standalone MCP configs). Deployed read-only and verified by whole-file SHA-256.
- **`plugin-bundle` (Antigravity Optimization)**: Deploys `agentconfig`'s shared rules, skills, hooks, and MCP config as a dedicated managed plugin at `~/.gemini/config/plugins/agentconfig-core/`, keeping Antigravity's mutable `~/.gemini/config/config.json` (`plugins.<dir>.enabled`, permission grants) isolated from SoT rewrites.
- **`patch-managed-keys` (`0600`)**: For mixed declarative+runtime files (`~/.claude.json`, `~/.gemini/antigravity-cli/settings.json`), `agentcfg` updates only declared managed JSON subtrees while leaving runtime caches, trust records, and timestamps intact, verifying the managed subtree hash rather than whole-file equality.

---

## 3. Target Models, Harnesses & Open Standards Specification

### 3.1 Google Antigravity (`agy` CLI 1.5.8, Antigravity 2.0 App, IDE, Python SDK) *(Verified)*

- **Surfaces & Paths**:
  - **Shared global customization root**: `~/.gemini/config/` (`config.json` atomic app state never meant for hand-editing, `mcp_config.json`, `.migrated`, `projects/`, `plugins/`, `skills/`, `agents/`, `rules/`, `sidecars/`, `skills.json`, `plugins.json`, `hooks.json`).
  - **CLI (`agy`)**: `~/.gemini/antigravity-cli/` (`settings.json`, `antigravity-oauth-token`, `builtin/{.manifest,.checksum,plugins/,skills/}`, `conversations/<uuid>.db*`, `conversation_summaries.db*`, `brain/<uuid>/`, `cache/`, `crashes/`, `annotations/*.pbtxt`, `implicit/*.pb`, `log/cli-*.log`, `presence/*.lock`, `updater/{update.lock,update_status.json}`, `history.jsonl`, `jetbox_summaries_proto.pb`, `jetski_state.pbtxt`). Wrapper `/home/omniboot/.gemini/antigravity-cli/bin/agentapi` delegates to `/home/omniboot/.local/bin/agy agentapi`.
  - **Antigravity 2.0 Desktop (Electron)**: `~/.gemini/antigravity/` (`sidecar_data/<sidecar_id>/`) + `~/.config/Antigravity/`.
  - **Antigravity IDE**: `~/.gemini/antigravity-ide/` + `~/.config/Antigravity/`. Manual `.tar.gz` unpacks require root-owned SUID `4755` `chrome-sandbox`; community AppImages mount at `/tmp/.mount_*`.
  - **Python SDK (`google-antigravity`)**: Bundles compiled agent runtime binary (`Agent`, `LocalAgentConfig`, `CapabilitiesConfig`; read-only by default).
  - **Project discovery**: `.agents/` (plus `.agent/`, `_agents/`, `_agent/`) walking CWD up to repo root (`.git`), `.antigravity/settings.json`, `GEMINI.md`, `AGENTS.md`.
- **Customization Precedence**:
  `(1) Workspace Project (CWD -> repo root) > (2) Workspace Declared (skills.json/plugins.json) > (3) Global Discovery (~/.gemini/config/) > (4) Built-in (.manifest) > (5) Global Declared`.
  Settings precedence: CLI flags (`--mode`, `--sandbox`, `--settings`) > Project (`.antigravity/settings.json` / UI overrides) > Global (`~/.gemini/antigravity-cli/settings.json` / `~/.gemini/config/config.json`).
  `skills.json` / `plugins.json` support `inherits` (`path`, `include_only`, `exclude`) and `entries` (1 level deep).
- **Rules, Memory & Limits**:
  - `GEMINI.md` / `AGENTS.md` (always on for dir + subdirs) and `.agents/rules/*.md` (`always_on`, `glob` comma-separated on abs paths, `model_decision`, `manual`). Supports deduplicated `@[label](path)` includes.
  - **Hard Limits**: **`24,000` bytes per rule file** (after include expansion) and **`20,000` tokens aggregate `defaultRulesBudget`** across always-on/global rules (built-ins exempt; overflow demoted to path pointers).
  - **Cross-session memory**: `/learn` edits rule files; `<conversation_summaries>` injects the last ~20 sessions on turn 1 from `conversation_summaries.db*` and `jetbox_summaries_proto.pb`, alongside `implicit/*.pb` and `annotations/*.pbtxt`.
- **Skills, Agents, Plugins, Sidecars, MCP & Hooks**:
  - **Skills**: `skills/<name>/SKILL.md` (YAML `name` matching dir + `description`; progressive disclosure).
  - **Subagents**: `agents/<name>.md` (`subagent: true`, `mainAgent: false`, `tools: [...]`; omitted defaults to small read-only set).
  - **Workflows deprecated**: Legacy `.agents/workflows/*.md` and `workflows.json` migrate via `/migrate-workflows` to `skills/<name>/SKILL.md` (`.md.bak`).
  - **Plugins**: `plugins/<dir>/plugin.json` (JSONC; unknown keys and duplicate `name` values are **silently dropped**). Enable state is keyed by **directory name `<dir>`** in `config.json` `plugins.<dir>.enabled` (overrides `plugin.json` `disabled`).
  - **Sidecars**: `sidecars/<id>/sidecar.json` (snake_case JSON; `command`/`args`/`env` or `"builtin": "schedule"` with `CRON_TZ=<IANA> <cron>`, `restart_policy`, `ui_config.views`, `agent_permissions`). Data stored in `~/.gemini/antigravity/sidecar_data/<id>/`.
  - **MCP (`mcp_config.json`)**: Top-level `"mcpServers"`. Stdio (`command`, `args`, `env`, `cwd`) and Streamable HTTP (`url` / legacy `serverUrl`, `headers`). **No legacy HTTP+SSE (`/sse`) support** (official docs suggest `npx -y mcp-remote`, which `agentconfig` policy forbids in unpinned form). Plugin `mcp_config.json` does **not** expand OS env vars—`${X}` resolves only declared `variables` (and plugins declaring `variables` start disabled).
  - **Hooks (`hooks.json`)**: `.agents/hooks.json` or `<plugin_dir>/hooks.json` (native plugins must place at root). Supports `SessionStart`, `PreToolUse`, `PostToolUse`, `PreInvocation`, `PostInvocation`, `Stop`. Only `type: "command"` (`sh -c`, synchronous, default 30s timeout, camelCase stdin/stdout payloads).
- **Permissions & Sandbox**: `action(target)` rules evaluated **`Deny > Ask > Allow`**. Linux namespace terminal sandbox blocks `~/.ssh`/`.env` and unapproved network while auto-permitting `/tmp` and `$TMPDIR`.
- **Update Behavior & Failsafe**:
  - `1.x -> 2.0` IDE migration; `1.5.7` changed default Agent Mode to `Auto` (`"agentMode": ""` restores Default) and `toolPermission: "strict"` overrides `auto`/`accept-edits`; `1.5.6` fixed `/permissions` clearing the migration marker; `1.5.8` fixed UTF-8 BOM files being silently dropped, added auto-quarantine of corrupted queued message files, and enforced atomic plugin install rollback rejecting out-of-plugin symlinks, FIFOs, and device files.
  - Failsafe mechanisms: `agy --settings <inline-json|path>`, `--mode plan --sandbox`, `--disable-slash-commands`, `ANTIGRAVITY_APP_DATA_DIR=<clean_dir>`, `agy acp --app-data-dir ... --gemini-dir ... --include-default-customizations=false`, `agy plugin validate --strict`.

### 3.2 Google Gemini CLI (`@google/gemini-cli` / `gemini`) *(Verified)*

- **Paths & Env Overrides**:
  - **System defaults (lowest)**: `/etc/gemini-cli/system-defaults.json` (`GEMINI_CLI_SYSTEM_DEFAULTS_PATH`).
  - **User global (`~/.gemini/`, root override: `GEMINI_CLI_HOME`)**: `settings.json`, `GEMINI.md`, `trustedFolders.json` (`GEMINI_CLI_TRUSTED_FOLDERS_PATH`), `commands/**/*.toml`, `skills/<name>/SKILL.md` (+ `~/.agents/skills/`), `agents/*.md`, `extensions/<name>/gemini-extension.json`, `policies/*.toml`, `sandbox.Dockerfile`.
  - **Project**: `.gemini/{settings.json,commands/**/*.toml,skills/,agents/*.md,policies/*.toml,sandbox.Dockerfile}`, `.agents/skills/`, `GEMINI.md`.
  - **System overrides (highest file)**: `/etc/gemini-cli/settings.json` (`GEMINI_CLI_SYSTEM_SETTINGS_PATH`), `/etc/gemini-cli/policies/*.toml`.
  - **Secrets**: `oauth_creds.json`, `google_accounts.json`, `.env` (`GEMINI_API_KEY`, `GOOGLE_API_KEY`), OS keychain for extension settings marked `"sensitive": true`.
  - **Runtime / tmp**: `~/.gemini/tmp/<project_hash>/{chats/session-*.json,logs.json,shell_history,checkpoints/}`, `~/.gemini/tmp/bin/`, `~/.gemini/history/<project_hash>/` (shadow git for `/restore`), `~/.gemini/{projects.json,installation_id,state.json}`.
- **Schema, Precedence & Context**:
  - Precedence: Hardcoded defaults < `system-defaults.json` < `~/.gemini/settings.json` < `.gemini/settings.json` < `/etc/gemini-cli/settings.json` < env/`.env` < CLI flags. Supports `$VAR`, `${VAR}`, `${VAR:-DEFAULT}` interpolation; scalars overwrite while `includeDirectories` and `mcpServers` merge.
  - `GEMINI.md` loads hierarchically (`~/.gemini/GEMINI.md` -> ancestors/workspace/subdirs, configurable via `context.fileName`), expanding `@./file.md` imports inline; `save_memory` appends under `## Gemini Added Memories` in `~/.gemini/GEMINI.md`.
- **MCP, Commands, Hooks, Policy Engine & Sandbox**:
  - `mcpServers` in `settings.json`: Stdio (`command`, `args`, `env`, `cwd`), Streamable HTTP (`httpUrl`), SSE (`url`), plus `headers`, `oauth: {enabled}`, `trust`, `timeout`, `includeTools`, `excludeTools`.
  - Hooks in `settings.json` (`SessionStart`..`PreCompress`): exit `0` parses JSON (`allow|deny|block|ask`), exit `2` = hard block via `stderr`.
  - Policy Engine `.toml` `[[rule]]`: Default < Extension < Workspace < User (`~/.gemini/policies/`) < Admin (`/etc/gemini-cli/policies/`).
  - Sandbox: `GEMINI_SANDBOX=docker|podman` (`ghcr.io/google/gemini-cli`) or macOS Seatbelt.
- **Update Behavior & Failsafe**:
  - `packages/cli/src/config/settings.ts` auto-migrates v1 flat keys to v2 nested blocks (`general.*`, `ui.*`, `model.*`, `security.*`) and validates against `schemas/settings.schema.json`. Extension manifests use `"migratedTo"`.
  - Folder Trust (`trustedFolders.json`) blocks workspace `.gemini/settings.json`, `.env`, and `.toml` commands in untrusted dirs.
  - Failsafe flags: `GEMINI_CLI_HOME=<clean_dir>`, `--approval-mode plan --sandbox`, `--allowed-mcp-server-names`, `--extensions`/`-e`. Experimental background memory extraction (`experimental.autoMemory`, writing `.patch` candidates into `.inbox/` for `/memory inbox`) is disabled via `"experimental": {"autoMemory": false}`; because there is **no built-in toggle to disable `save_memory` out-of-the-box**, `agentconfig` also enforces a Policy Engine rule (`toolName = "save_memory"`, `decision = "deny"`) in failsafe mode.

### 3.3 GitHub Copilot (CLI, Desktop App `github/app`, VS Code, JetBrains, Coding Agent) *(Verified)*

- **Copilot CLI (`@github/copilot` / `copilot`, replacing deprecated `gh copilot`)**:
  - Global root `~/.copilot/` (`COPILOT_HOME`): `settings.json` (superseded `config.json`, which still stores `trustedFolders`), `mcp-config.json`, `lsp-config.json`, `providers.json` (BYOK), `copilot-instructions.md`, `skills/`, `agents/`, `installed-plugins/`.
  - Auth env precedence: `COPILOT_GITHUB_TOKEN` > `GH_TOKEN` > `GITHUB_TOKEN`; `COPILOT_ALLOW_ALL` implies folder trust.
  - Project files: `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md` (`applyTo` glob, `excludeAgent`: `"code-review"`|`cloud-agent`), `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.github/agents/*.{agent.md,md}`, `.github/skills/`, `.agents/skills/`, `.github/hooks/*.json` (`{"version": 1, "hooks": {...}}`, `preToolUse` outputs `permissionDecision`), `.mcp.json`.
  - Runtime: `~/.copilot/{session-state/<id>/{events.jsonl,workspace.yaml},session-store.db,command-history-state/,logs/}` and containerized `/tmp/` staging.
- **GitHub Copilot Desktop App (`github/app`)**:
  - Shares `~/.copilot/` (`COPILOT_HOME`) + XDG `~/.config/`; repo config `.github/github-app.yml` (migrated from `.github/copilot-desktop.yml`). Linux `.AppImage` mounts `/tmp/.mount_*` (may require `--appimage-extract-and-run` on Ubuntu 24.04 userns) and can leak `LD_LIBRARY_PATH` into child `git` processes.
- **VS Code Copilot & JetBrains**:
  - VS Code: `~/.config/Code/User/{settings.json,mcp.json,prompts/*.prompt.md,globalStorage/github.copilot-chat/,workspaceStorage/<hash>/state.vscdb}`. Project `.vscode/mcp.json` uses **`"servers"` + `"inputs"`** (`${input:id}`), unlike `.mcp.json` (`"mcpServers"`). Legacy `.chatmode.md` migrates to `.agent.md`; legacy Local harness scheduled for removal **Feb 2027**.
  - JetBrains: `~/.config/github-copilot/intellij/{mcp.json,global-copilot-instructions.md}` (`"servers"` schema) + IDE `options/github-copilot.xml`.
  - GitHub Coding Agent (cloud): `.github/workflows/copilot-setup-steps.yml`; MCP servers and firewall allowlists come strictly from GitHub repo/org/enterprise UI settings (never workspace MCP files).
- **Copilot Memory, Updates & Failsafe**:
  - **Copilot Memory** is a server-side GitHub store: repo facts store **code citations** verified Just-In-Time (JIT) against current code and **auto-expire after 28 days** unless reinforced.
  - **Update quirks**: Cached prerelease `copilot` binaries can re-exec *before* parsing `settings.json`—making `COPILOT_AUTO_UPDATE=false` (`COP_AUTO_UPDATE=false`) or `--no-auto-update` essential. External `mcp-config.json` Zod parsers drop unsupported properties like `"disabled": true` (use `disabledMcpServers` or `--disable-mcp-server`).
  - **Failsafe & Memory Reset**: `COPILOT_HOME=<clean_dir>`, `--disable-builtin-mcps`, `--disable-mcp-server`, `--no-custom-instructions`, `/memory off` (VS Code `chat.copilot.memory.enabled: false`). **Important**: Disabling Copilot Memory stops capture/use only—existing stored facts require explicit **server-side purge** via GitHub.com profile/repo settings.

### 3.4 OpenAI (Codex CLI, Codex App, ChatGPT) *(Pending Deep Verification)*

> **Pending `@openai-anthropic`**: Full per-surface paths, TOML/JSON schema details, and ChatGPT desktop/connector behaviors will be merged upon verification of `@openai-anthropic`'s report. Below are the facts **already verified** in `#7` and `#15`:

- **Codex CLI (`codex`)**:
  - **Config root & overrides**: `~/.codex/` (`CODEX_HOME`), declarative `config.toml`, project `.codex/config.toml` and `AGENTS.md`.
  - **Auth (Tier B)**: `~/.codex/auth.json` (`0600`, never committed).
  - **Runtime & `/tmp/` (Tier C)**: `$CODEX_HOME/{sessions/,log/,sqlite/,history.jsonl}` and SQLite state DBs (`state_*.sqlite`, `logs_*.sqlite`). Linux `bwrap` (`workspace-write`) mounts `/tmp` and `$TMPDIR` as writable roots by default unless `exclude_slash_tmp` is configured; daemon sockets live in temp dirs (`/tmp/usertmp/<user>/codex-daemon-*` or `$TMPDIR`), and `SIGKILL`/OOM can strand synthetic `.git`/`.codex` mount targets.
  - **Memory & Failsafe**: Memory stores at `$CODEX_HOME/memories/` and `$CODEX_HOME/memories_v2/` (`MEMORY.md`, `memory_summary.md`, raw logs). Failsafe invocation: `--ask-for-approval untrusted --sandbox read-only` (or `--profile failsafe`), `[features] memories = false`, `[memories] generate_memories = false, use_memories = false`, empty `[mcp_servers]`.
  - **Upstream schema watch target**: `https://developers.openai.com/codex/config-schema.json` + `openai/codex` releases.
- **Codex App & ChatGPT**: *Full paths, connector/MCP schemas, custom instructions, projects, and memory export/wipe mechanics pending `@openai-anthropic` report.*

### 3.5 Anthropic (Claude Code CLI/IDE, Claude Desktop) *(Pending Deep Verification)*

> **Pending `@openai-anthropic`**: Complete Claude Code IDE, Claude Desktop, plugin/subagent/command, and precedence matrices will be merged upon verification of `@openai-anthropic`'s report. Below are the facts **already verified** in `#7` and `#15`:

- **Claude Code (`claude`)**:
  - **Config root & overrides**: `~/.claude/` (`CLAUDE_CONFIG_DIR`), mixed state/config `~/.claude.json` (managed via `patch-managed-keys` strategy), `settings.json`, `CLAUDE.md`, project `.mcp.json` and `.claude/settings.json`.
  - **Auth (Tier B)**: `~/.claude/.credentials.json` (`0600`, never committed).
  - **Runtime & `/tmp/` (Tier C)**: `~/.claude/{projects/,todos/,debug/,session-env/,history.jsonl}`. Creates session scratchpads under `/tmp/claude-<uid>/...` (respects `CLAUDE_CODE_TMPDIR` and `TMPDIR`). Built-in Bash sandbox overrides `$TMPDIR` to an isolated per-user sandbox path while unsandboxed commands inherit host `$TMPDIR`.
  - **Known Pre-Trust CVEs**: **CVE-2025-59536** (pre-trust repo hook/MCP RCE) and **CVE-2026-21852** (pre-trust `ANTHROPIC_BASE_URL` API-key exfiltration). Global `enableAllProjectMcpServers: true` must remain forbidden.
  - **Memory & Failsafe**: Auto-memory stored in `~/.claude/projects/*/memory/MEMORY.md` and topic `.md` files. Failsafe boot: `--bare` (sets `CLAUDE_CODE_SIMPLE=1`, skipping hooks, skills, plugins, MCP, auto-memory, and project `CLAUDE.md`) + `--strict-mcp-config --mcp-config /dev/null` + `--permission-mode plan` + `--setting-sources user`, plus `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` / `"autoMemoryEnabled": false`.
  - **Upstream schema watch target**: `https://json.schemastore.org/claude-code-settings.json` + Anthropic release notes.
- **Claude Desktop**: *Exact Linux/desktop config paths, MCP configuration, and runtime layout pending `@openai-anthropic` report.*

### 3.6 Emerging Harnesses & Cross-Agent Open Standards *(Pending Deep Verification)*

> **Pending `@emerging-harnesses`**: Exact per-tool paths, formats, and compatibility matrices for **Moonshot Kimi** (`Kimi Code CLI`, `~/.kimi`, `KIMI_CODE_HOME`), **xAI Grok** (Grok CLI / harnesses), **OpenCode** (`~/.config/opencode`), **Cursor** (`~/.cursor`), **Windsurf** (`~/.codeium/windsurf`), **Cline / Roo Code**, **Goose** (`~/.config/goose`), and **Aider** (`~/.aider.conf.yml`) will be merged upon verification of `@emerging-harnesses`'s report.

**Cross-Agent Open Standards Already Verified Across Target Harnesses (`#8`)**:
- **`AGENTS.md`**: Recognized across Antigravity, Gemini CLI (via `context.fileName`), GitHub Copilot (CLI & VS Code), and OpenAI Codex—serving as a prime canonical shared project instruction surface.
- **Agent Skills Open Standard (`SKILL.md`)**: Shared directory layout `.agents/skills/<name>/SKILL.md` (project) and `~/.agents/skills/<name>/SKILL.md` (user global) with YAML frontmatter (`name`, `description`) and progressive disclosure (`scripts/`, `examples/`, `resources/`, `references/`), honored by Antigravity, Gemini CLI, and GitHub Copilot.
- **MCP JSON Fragmentation (Requires Per-Harness Renderers)**: While stdio (`command`/`args`/`env`) and Streamable HTTP concepts align conceptually, schemas diverge across clients—`"mcpServers"` (Antigravity, Gemini CLI, Copilot CLI, `.mcp.json`) vs `"servers"` + `"inputs"` (VS Code `.vscode/mcp.json`, JetBrains `mcp.json`), and `url` vs `httpUrl` vs legacy `/sse` deprecation—requiring `bin/agentcfg` to render per-harness outputs from a single canonical `canonical/mcp-registry.json`.

---

## 4. `/tmp/` & Agent Memory Surfaces and Hardening

### 4.1 Why Default `/tmp` Fails Security and Stability

1. **Same-UID races in `1777` directories**: Kernel `fs.protected_symlinks=1` and `fs.protected_regular=2` block *cross-UID* attacks in `/tmp` and `/var/tmp`, **not** same-UID compromises (e.g., a rogue MCP server, malicious `postinstall`, or injected tool running as UID 1000 racing predictable paths such as `/tmp/lsrpc.sh` or `0775` subdirs).
2. **World-readable leaks via `umask 0002`**: Without explicit `0600`/`0700` creation, logs, crash dumps, conversation summaries, bash outputs, and MCP payloads are world-readable (`0644`/`0755`).
3. **Retention & Disk Exhaustion vs `ENOSPC` Trap**: `/tmp` shares `/` (`38G` ext4) with 30-day cleanup while `/var/tmp` never cleans up by default (`#q` commented out). Meanwhile, pointing `$TMPDIR` to `/run/user/1000` (`191 MiB`) triggers `ENOSPC` on AppImages (`/tmp/.mount_*`), Electron staging, or large repo unpacks.
4. **Cross-harness `/tmp/` clutter**: Antigravity `lsrpc.sh` & Chromium singletons (`/tmp/.org.chromium.Chromium.*`), Claude `/tmp/claude-<uid>/` & sandbox `$TMPDIR` mismatches, Codex `codex-daemon-*` sockets & stranded `bwrap` `.git`/`.codex` mount targets, `npx`/`uvx`/`mcp-remote` caches, and `xrdp` `/tmp/dbus-*` (`srwxrwxrwx`) sockets.

### 4.2 Two-Tier Private `0700` Temp Layout & Host Hardening

`wrappers/agent-env-run` enforces a two-tier `0700` temp architecture plus strict `umask 0077`:

```bash
umask 0077
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
install -d -m 0700 "$XDG_RUNTIME_DIR/agent-runtime" "$HOME/.local/tmp" "$HOME/.local/tmp/claude"
export TMPDIR="$HOME/.local/tmp"
export TEMP="$HOME/.local/tmp"
export TMP="$HOME/.local/tmp"
export CLAUDE_CODE_TMPDIR="$HOME/.local/tmp/claude"
```

- **Tier 1 (`$XDG_RUNTIME_DIR/agent-runtime`, `0700`, `tmpfs`)**: Holds small volatile locks (`agentcfg.lock`), IPC sockets, and PID files (auto-cleared on logout, bounded at `191 MiB`).
- **Tier 2 (`~/.local/tmp` & `~/.local/tmp/claude`, `0700`, ext4)**: Holds large scratchpads, AppImage unpacks, `bwrap` mounts, and Claude/Codex tool temp files. Wrapper scripts allocate isolated per-session subdirectories via `mktemp -d -p "$TMPDIR" "agent.XXXXXX"` with an `EXIT` cleanup trap.
- **Automatic age-out (`~/.config/user-tmpfiles.d/agent-tmp.conf`)**:
  ```text
  d %h/.local/tmp 0700 - - 3d
  d %h/.local/tmp/claude 0700 - - 2d
  e %h/.gemini/antigravity-cli/log - - - 14d
  e %h/.cache/antigravity/staging - - - 3d
  ```
  Enabled once via `XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user enable --now systemd-tmpfiles-setup.service systemd-tmpfiles-clean.timer`.
- **Existing local directory tightening & optional root mounts**: Tighten existing `~/.gemini/`, `~/.gemini/antigravity-cli/`, `~/.gemini/config/`, `~/.cache/antigravity/`, and `~/.cache/antigravity/staging/` to `0700`, and existing DBs/logs/configs to `0600`. Optional admin mount hardening adds `nosuid,nodev,noexec` to `/dev/shm` and `/var/tmp` (and `/tmp` once all wrappers set `$TMPDIR=$HOME/.local/tmp`), and shortens `/etc/tmpfiles.d/tmp.conf` retention (`3d` `/tmp`, `7d` `/var/tmp`).

### 4.3 Agent Memory Poisoning & Corruption Hardening

Agent memory transforms transient prompt injections or disk crashes into **cross-session persistent compromise**:
- **Local rule/memory append poisoning**: Gemini CLI `save_memory` appends directly to `~/.gemini/GEMINI.md` (`## Gemini Added Memories`); Antigravity `/learn` appends to `GEMINI.md`/`AGENTS.md`/`.agents/rules/*.md` (and prior to `1.5.8`, exceeding `24,000` bytes silently truncated rule tails); Claude Code writes `~/.claude/projects/*/memory/*.md`; Codex writes `$CODEX_HOME/{memories,memories_v2}/`.
- **Binary / SQLite memory corruption**: Unclean `SIGKILL`/OOM leaves Antigravity `conversation_summaries.db*`, `implicit/*.pb`, `annotations/*.pbtxt`, `jetbox_summaries_proto.pb`, Codex `$CODEX_HOME` SQLite DBs (`state_*.sqlite`, `logs_*.sqlite`, `memories_*.sqlite`), or Copilot `session-store.db` with broken WAL/SHM journals.
- **Cloud / Server-side memory**: GitHub Copilot Memory stores repo facts (28-day TTL, JIT code-citation verified) and user preferences server-side—where disabling local capture via `/memory off` or `chat.copilot.memory.enabled: false` does **not** purge existing server-side entries.
- **Hardening controls**: `agentcfg` maintains pre-change memory snapshots (`~/.local/state/agentcfg/memory-snapshots/`, `0700`/`0600`), scans all local memory stores for hidden Unicode, exfiltration directives (`curl`, `wget`, `.ssh`, `antigravity-oauth-token`, `hosts.yml`), and anomalous size spikes, supports selective line/file quarantine, and disables auto-memory in `failsafe` mode.

---

## 5. Supply-Chain, Pre-Trust RCE & Network Resilience Threat Model

### 5.1 Threat & Control Matrix

| Threat Vector | Mechanism & Precedents | `agentconfig` Control |
| :--- | :--- | :--- |
| **Untrusted Repo Configs (Pre-Trust RCE & Exfil)** | Cloned repos embed `.mcp.json`, `.vscode/mcp.json`, `.claude/settings.json`, `.gemini/settings.json`, `.codex/config.toml`, `.agents/hooks.json` (`sh -c`), `.agents/{skills,plugins}.json` (`inherits`), or `*_BASE_URL` overrides (**CVE-2025-59536**, **CVE-2026-21852**). | 1. Keep Workspace Trust ON (`security.folderTrust.enabled: true`, VS Code `security.workspace.trust.enabled: true`, `chat.mcp.autostart` off for untrusted, never global `enableAllProjectMcpServers: true`).<br>2. Run `agentcfg audit-repo <path>` before opening unfamiliar repos.<br>3. Sandbox untrusted repos inside `bwrap` (`0.9.0`) with an isolated `$HOME` excluding `~/.ssh`, `~/.config/gh`, `antigravity-oauth-token`, and keyring access. |
| **Unpinned `npx -y` / `uvx` & MCP Rug Pulls** | Floating package refs auto-pull mutable upstream code (`-y` skips confirmation); updated servers swap tool schemas/descriptions (**tool poisoning**) or spoof tools (**tool shadowing**). | 1. Policy ban on floating `npx -y` / `uvx` in `mcp-registry.json`.<br>2. Pre-install into locked per-server prefixes (`~/.local/share/agentconfig/mcp-venvs/<srv>/` via `npm ci --ignore-scripts` / `uv.lock --frozen`) or `image@sha256:...`.<br>3. Pin `tools/list` SHA-256 in `policy/manifests.lock.json`.<br>4. Wrap local-only stdio servers with `bwrap --unshare-net` and `env -i`. |
| **Malicious Skills & Plugins** | Community `SKILL.md` / `AGENTS.md` / `plugins/*` conceal indirect prompt injections, invisible Unicode (`U+200B..U+200F`, `U+202A..U+202E`, Tags `U+E0000..U+E007F`), or hidden `hooks.json` / `scripts/*.sh` (*ToxicSkills*). | Vendor external skills/plugins only at pinned Git SHAs after diff inspection; `agentcfg validate` strips/fails on invisible Unicode, unexpected `hooks.json`/`scripts/`, base64 payloads, and outbound `curl`/`wget`/`nc`; run `agy plugin validate --strict`. |
| **Plaintext Credential Theft** | Inline tokens in `mcp_config.json`, `.mcp.json`, `~/.claude.json`, `~/.codex/config.toml`, or `.env`, amplified by `umask 0002` `0644` files and child processes inheriting full `env`. | Zero plaintext secrets in Git or rendered configs; retrieve via `gnome-keyring` (`secret-tool`) or `sops+age`; launch stdio servers through `wrappers/mcp-secret-exec` using `env -i` whitelist (never passing `SOPS_AGE_KEY` or unrelated tokens). |
| **Network Corruption & Updater Failures** | Truncated `curl \| sh` / `npx` downloads, stale `updater/update.lock`, partial `~/.cache/antigravity/staging/`, mismatched `builtin/.checksum`, hung remote MCP / 30s synchronous hooks. | Ban `curl \| sh`; stage in `0700`, verify SHA-256/sig, parse-validate, atomic `os.replace`; hardlink/snapshot `~/.local/bin/agy` pre-update; disable unattended auto-updates (`DISABLE_AUTOUPDATER=1` for Claude Code, `COPILOT_AUTO_UPDATE=false` for Copilot CLI, `general.enableAutoUpdate: false` for Gemini CLI, `"update.mode": "none"` for Antigravity IDE); explicit hook `timeout` (`<=10s`) + `timeout -k 5s`; `--offline` profile disabling remote MCPs. |

---

## 6. `agentcfg cleanse` & Quarantine Workflow

`agentcfg cleanse` repairs corrupted configurations, dead runtime artifacts, and poisoned memory **without destroying evidence or wiping valid credentials**.

### 6.1 Scopes & Auth-Preservation Invariant

- **Scopes (`--scope config|memory|runtime|all`, default `config`)**:
  - **`config`**: Detects invalid JSON/TOML/YAML frontmatter, schema errors, undeclared MCP servers or `.agents/hooks.json`, policy violations (unpinned `npx -y`/`uvx`, unauthorized `*_BASE_URL`), broken symlinks, and unsafe permissions (`0777`, `0644`/`0755` on sensitive targets). Moves offending files to quarantine and atomically renders clean SoT.
  - **`runtime`**: Detects orphaned `.tmp` / `<path>.<uuid>.tmp` files, stale locks (`updater/update.lock`, `presence/*.lock`, Electron `SingletonLock`, `agentcfg.lock`), corrupt SQLite DBs / orphaned `-wal`/`-shm` (`conversations/*.db`, `conversation_summaries.db`, Codex `$CODEX_HOME` SQLite DBs such as `state_*.sqlite`, `logs_*.sqlite`, `memories_*.sqlite`, Copilot `session-store.db`), and stale staging caches. **Safety gates**: Always performs liveness checks (`flock -n` + `fuser` / `/proc/<pid>`) before touching any `.lock`, and checks SQLite files read-only via `PRAGMA quick_check` (supporting non-destructive dump/recover before re-initializing).
  - **`memory`**: Captures a full pre-cleanse snapshot (`0600`), scans local memory stores (`~/.gemini/GEMINI.md` `## Gemini Added Memories`, `~/.claude/projects/*/memory/*.md`, `$CODEX_HOME/{memories,memories_v2}/`, Antigravity `annotations/*.pbtxt` / `implicit/*.pb` / `conversation_summaries.db*` / `jetbox_summaries_proto.pb` / `history.jsonl`) for hidden Unicode, injection/exfiltration directives, or anomalous diff against `memory-snapshots/`, selectively quarantines tainted lines/files, and warns the user when cloud memory (Copilot / ChatGPT) requires a web UI purge (note: Copilot Memory is server-side; `copilot-memories.jsonl` is only the JSONL input format for `copilot memories import`).
- **Hard Auth-Preservation Invariant**: `antigravity-oauth-token`, `~/.config/gh/hosts.yml`, `~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, and `~/.local/share/keyrings/` are **never** quarantined or deleted—even under `--scope all`—unless `--include-auth --confirm-wipe-auth` is passed interactively.
- **Quarantine Mechanics**: Files move into `~/.local/state/agentcfg/quarantine/<UTC-ts>/` (`0700`), preserving relative paths, stripping execute bits (`chmod 0400`/`0600`), and recording `quarantine-manifest.json` (`original_path`, `sha256`, `orig_mode`, `scope`, `reason`, `timestamp`).

### 6.2 Safe Applicator Execution Sequence (`agentcfg apply --safe`)

1. Acquire exclusive `flock` on `${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/agentcfg.lock`.
2. Run `agentcfg watch-updates --check` (abort automatic overwrites on unexpected binary/schema drift).
3. Run `agentcfg validate` + secret scan (`gitleaks` + Python regex/entropy fallback).
4. Run `agentcfg cleanse --dry-run` (or `--auto-quarantine` on confirmed syntax/lock/permission corruption).
5. Snapshot current managed targets and memory (`~/.local/state/agentcfg/snapshots/<UTC-ts>/`) -> atomically render/patch targets (`0400`/`0444`/`0600`).
6. Update `deployed-manifest.json` (`0600`) and verify with `agentcfg verify` (non-zero exit on any hash or mode mismatch).

---

## 7. Built-in `failsafe` Profile Mechanics

`canonical/profiles/failsafe/` combined with `agentcfg failsafe` and `wrappers/agent-env-run --failsafe` guarantees every harness can boot into a **zero-trust safe state**:
- **Baseline Invariants**: Zero external/remote MCP servers, hooks and third-party plugins disabled, strict ask/read-only permissions, auto-memory disabled/bypassed, verified minimal rules (`<=2 KB`, no `@` includes), `umask 0077`, `env -i` whitelist, and clean isolated `$TMPDIR` (`~/.local/tmp/failsafe.<pid>`, `0700`).

### 7.1 Per-Harness Failsafe Controls

| Harness | Failsafe Flags, Settings & Memory Bypass |
| :--- | :--- |
| **Claude Code** | `--bare` (sets `CLAUDE_CODE_SIMPLE=1`, skips hooks, skills, plugins, MCP, auto-memory, and project `CLAUDE.md`) + `--strict-mcp-config --mcp-config /dev/null` + `--permission-mode plan` + `--setting-sources user`; `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` and `"autoMemoryEnabled": false`. |
| **Codex CLI** | `--ask-for-approval untrusted --sandbox read-only` (or `--profile failsafe`); failsafe `config.toml` sets `approval_policy = "on-request"`, `sandbox_mode = "read-only"`, `[features] memories = false`, `[memories] generate_memories = false, use_memories = false`, empty `[mcp_servers]`. |
| **Gemini CLI** | Failsafe `settings.json`: `security.folderTrust.enabled: true`, `general.defaultApprovalMode: "plan"`, `experimental.autoMemory: false`, empty `mcpServers: {}`; launch with `--approval-mode plan --sandbox`; Policy Engine `.toml` rule denying `save_memory`; clean `~/.gemini/GEMINI.md` without `## Gemini Added Memories`. |
| **Antigravity (`agy`)** | Launch with `--mode plan --sandbox --disable-slash-commands --settings <failsafe-settings.json>` (`toolPermission: "request-review"`, `agentMode: "plan"`) or isolated `ANTIGRAVITY_APP_DATA_DIR=<clean_dir>` / `agy acp --include-default-customizations=false`; disable third-party plugins in `config.json`, empty `mcp_config.json`, omit `hooks.json`. |
| **Copilot (CLI / VS Code)** | Copilot CLI: `COPILOT_HOME=<clean_dir>`, `--disable-builtin-mcps --no-custom-instructions --no-auto-update`, `/memory off` (and omit `--enable-memory` in `-p`). VS Code: `chat.copilot.memory.enabled: false`, `chat.mcp.autostart: "never"`, `chat.useAgentsMdFile: false`, `chat.useClaudeMdFile: false`, Restricted Mode / Workspace Trust enforced. *(Purge existing cloud memories via GitHub UI if compromised.)* |

### 7.2 Dual Operating Modes

1. **Ephemeral Non-Destructive Boot (`agent-env-run --failsafe <harness>`)**: Spins up an isolated `0700` runtime root (`HOME` / `XDG_CONFIG_HOME` / `CODEX_HOME` / `CLAUDE_CONFIG_DIR` / `GEMINI_CLI_HOME` / `COPILOT_HOME` / `ANTIGRAVITY_APP_DATA_DIR`) for incident triage and forensics without touching or destroying live corrupted evidence.
2. **Persistent Safe-Mode Switch (`agentcfg failsafe --apply` / `--restore`)**: Snapshots live configs and memory into `~/.local/state/agentcfg/snapshots/<UTC-ts>/`, atomically swaps deployed targets to `canonical/profiles/failsafe/`, and cleanly restores after remediation.

---

## 8. Atomic Deployment, Integrity Verification & Cryptographic Provenance

- **Crash-safe atomic replacement**:
  1. Stage rendered bytes using `tempfile.NamedTemporaryFile(dir=target.parent, prefix=".agentcfg.", suffix=".tmp", delete=False)` **on the same filesystem as the target** (preventing `EXDEV` and `/tmp` symlink races).
  2. Call `flush()` + `os.fsync(fd)`.
  3. Set strict permissions via `os.fchmod(fd, mode)` (`0400`/`0444` declarative, `0600` patched, `0500`/`0700` wrappers).
  4. Replace atomically via `os.replace(tmp, target)`—which succeeds even when overwriting `0444` files inside a user-writable directory, eliminating `chmod +w` race windows and `chattr +i` auto-updater breakage.
  5. `os.fsync` the parent directory file descriptor.
- **Integrity manifest & recovery (`verify` / `diff` / `restore`)**:
  - `~/.local/state/agentcfg/deployed-manifest.json` (`0600`) tracks target paths, SHA-256 hashes (full file or managed JSON subtree), file modes, `git rev-parse HEAD`, strategy, and timestamp.
  - `agentcfg verify` exits non-zero on any drift or mode regression; `agentcfg diff` renders into memory/`0700` staging and displays unified diffs; `agentcfg restore` snapshots current state first and atomically restores the last verified commit/manifest.
- **Signed Git provenance & offline immutable backups**:
  - Repository-local/user SSH signing (`git 2.43.0` + `ssh-keygen -t ed25519`): `gpg.format ssh`, `commit.gpgsign true`, `tag.gpgsign true`; `agentcfg apply` verifies `git verify-commit HEAD` before deploying.
  - Offline recovery bundles combine `git bundle create ... --all`, deterministic `git archive ... | gzip -n`, `sha256sum`, and optional `age -R` encryption.

---

## 9. Update-Change, Config-Migration & Schema-Evolution Monitoring

### 9.1 Local Footprint & Schema Monitor (`agentcfg watch-updates` / `agentcfg doctor`)

Maintains `~/.local/state/agentcfg/host-footprint.json` (`0600`), triggered both as a pre-flight gate inside `agentcfg apply --safe` and on a periodic `systemd --user` timer (`agentcfg-watch.timer`):
1. **Binary & Bundle Fingerprints**: Tracks versions and SHA-256 digests of `agy`, `claude`, `codex`, `gemini`, `copilot`, `gh`, plus `~/.gemini/antigravity-cli/builtin/{.checksum,.manifest}` and `cache/CHANGELOG.md`.
2. **Metadata-Only Directory & Permission Watch**: Scans path names, permissions, byte sizes, and SHA-256 of non-secret config files across `~/.gemini/`, `~/.claude/`, `~/.codex/`, and `~/.copilot/` (**explicitly excluding secret/auth files**). Flags new `.migrated` markers, unexpected memory directories (`memories_v2/`, `annotations/`, `implicit/`, `projects/*/memory/`), and `umask` permission regressions (`0644`/`0755`).
3. **JSON/TOML Key-Shape Diffing**: Computes sorted key-path trees of managed configs (`settings.json`, `config.json`, `mcp_config.json`, `config.toml`), halting unattended `apply` on `NEW_KEY`, `DROPPED_KEY`, or `NEW_MEMORY_PATH` until reviewed.

### 9.2 Upstream Schema & Release Monitor (`wakeleyresearch/agentconfig`)

Scheduled GitHub Actions workflow (`.github/workflows/upstream-schema-watch.yml`, minimal `contents: read`, `issues: write`) plus local `agentcfg upstream-check` diffs `policy/upstream-sources.json` targets against pinned snapshots in `policy/upstream-schemas/`:
- **Claude Code**: `https://json.schemastore.org/claude-code-settings.json` + Anthropic release notes.
- **Gemini CLI**: `https://raw.githubusercontent.com/google-gemini/gemini-cli/main/schemas/settings.schema.json` + `google-gemini/gemini-cli` releases.
- **Antigravity (`agy`)**: `https://antigravity.google/docs` changelog/CLI reference + local `agy changelog` / `builtin/.manifest` diff.
- **OpenAI Codex**: `https://developers.openai.com/codex/config-schema.json` + `openai/codex` releases.
- **GitHub Copilot & Emerging Harnesses**: Release notes and schema/path deprecation trackers across Copilot CLI/VS Code, Kimi, Grok, OpenCode, Goose, Cursor, Windsurf, Cline, Roo Code, and Aider.

Schema property additions, removals, deprecations, and memory-location shifts open a labeled GitHub Issue / draft PR for review before updating `canonical/harnesses/` render templates.

---

## 10. Open Design Decisions & Next Steps

Before implementing Phase 1–4 code in `wakeleyresearch/agentconfig`, the following design choices should be confirmed:
1. **Primary Tier-B secret backend**: Use `gnome-keyring` (`secret-tool`) as primary live lookup with `sops`+`age` (`secrets/secrets.enc.yaml`) for encrypted Git portability, or rely solely on `gnome-keyring` plus offline recovery exports?
2. **Canonical rules format**: Author shared rules in `canonical/rules/` using plain `AGENTS.md`-compatible Markdown (maximum portability, zero frontmatter) or Markdown with lightweight metadata headers stripped/translated per harness (Antigravity `always_on`/`glob`, Copilot `applyTo`)?
3. **`bwrap` sandboxing policy for untrusted repos**: Require `agent-env-run --isolated` (`bwrap` with synthetic `$HOME`) by default when opening repositories outside `~/src` or `trustedWorkspaces`, or invoke manually via `agentcfg audit-repo`?
4. **Update monitor cadence & auto-cleanse policy**: Keep `agentcfg apply --safe` strictly fail-closed when `watch-updates` detects schema drift or `cleanse` detects poisoned memory (requiring explicit `--approve-drift` / `--quarantine`), rather than auto-mutating live configs?
5. **Remaining harness matrix completion**: Merge `@openai-anthropic` and `@emerging-harnesses` verified reports into Sections [3.4](#34-openai-codex-cli-codex-app-chatgpt-pending-deep-verification), [3.5](#35-anthropic-claude-code-cliide-claude-desktop-pending-deep-verification), and [3.6](#36-emerging-harnesses--cross-agent-open-standards-pending-deep-verification) prior to Phase 3 renderer implementation.
