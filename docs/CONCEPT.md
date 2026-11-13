# `agentconfig` Architecture & Threat-Model Concept Paper

> **Document Status**: Draft Concept & Verified Cross-Harness Specification (`wakeleyresearch/agentconfig`, branch `main`).  
> **Scope**: Defines the empirical host baseline, three-tier Source-of-Truth (SoT) model, verified per-harness configuration/memory/`/tmp/` specifications across all target models and harnesses, supply-chain and pre-trust RCE defenses, `agentcfg cleanse` quarantine workflow, built-in `failsafe` profile mechanics, atomic deployment protocol, local/upstream update-monitoring design, and GitHub ecosystem benchmark (`#7`, `#8`, `#15`, `#16`, `#24`, `#25`, `#26`, `#27`).

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
10. [GitHub Ecosystem Reference & Empirical Anti-Patterns](#10-github-ecosystem-reference--empirical-anti-patterns)
11. [Open Design Decisions & Next Steps](#11-open-design-decisions--next-steps)

---

## 1. Empirical Host & Local Environment Baseline

The architecture targets multi-harness Linux workstations anchored to the observed baseline on `/home/omniboot` (**Ubuntu 24.04.5 LTS x86_64**, `uid=1000(omniboot)`, **`umask 0002`**, `1.9 GiB` RAM, `1.0 GiB` swap):

| Dimension | Observed Host State | Security / Operational Implication |
| :--- | :--- | :--- |
| **Root & Temp Filesystems** | `/tmp` (`1777 root:root`) and `/var/tmp` (`1777 root:root`) sit directly on `/` (`/dev/sda1`, `ext4`, `38G` total, `30G` avail, mounted `defaults`). | No `nosuid`, `nodev`, `noexec`, or size quota on `/tmp` or `/var/tmp`; runaway agent temp files threaten root disk exhaustion. |
| **Shared Memory & Runtime Dir** | `/dev/shm` (`1777 root:root`) is `tmpfs` (`958M`, `rw,nosuid,nodev,inode64` — **missing `noexec`**); `/run/user/1000` (`0700`) is `tmpfs` (`196092k` ≈ `191 MiB`, `rw,nosuid,nodev`). | Pointing `$TMPDIR` blindly at `/run/user/1000` causes `ENOSPC` on AppImages and package unpacks; `/dev/shm` allows execution. |
| **Session Environment Gaps** | `XDG_RUNTIME_DIR`, `TMPDIR`, `TEMP`, and `TMP` are **unset** in non-login subshells; `xrdp`/`dbus-launch` sets `DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/dbus-*` with `srwxrwxrwx` sockets. | Agent subshells and background runners fall back to world-writable `/tmp` unless wrapped explicitly. |
| **Kernel & `tmpfiles` State** | `fs.protected_symlinks=1`, `fs.protected_hardlinks=1`, `fs.protected_regular=2`, `fs.protected_fifos=1`. `/usr/lib/tmpfiles.d/tmp.conf` cleans `/tmp` at `30d`, while `/var/tmp` cleanup is commented out (`#q /var/tmp 1777 root root 30d`). `loginctl` `Linger=yes`; user `systemd-tmpfiles-setup.service` & `systemd-tmpfiles-clean.timer` exist (`disabled`, preset `enabled`). | Kernel `fs.protected_*` prevents *cross-UID* symlink/regular attacks in `1777` dirs, **not same-UID** compromises; `/var/tmp` retains leftovers indefinitely. |
| **Installed Local Harness** | `agy` CLI `1.5.8` (`/home/omniboot/.local/bin/agy`) + `/home/omniboot/.gemini/` + `~/.cache/antigravity/`. Neither `~/.codex`, `~/.claude`, `~/.copilot`, `~/.kimi`, `~/.kimi-code`, `~/.grok`, `~/.cursor`, `~/.config/opencode`, `~/.agents`, nor upstream `~/.gemini/settings.json` / `~/.gemini/GEMINI.md` exist yet. | Clean opportunity to establish hardened permissions and canonical SoT before deploying additional harnesses. |
| **Permissive Permission Drift** | `umask 0002` caused `~/.gemini/` (`0755`), `antigravity-cli/` (`0755`), `config/` (`0755`), `~/.cache/antigravity/staging/` (`0775`), `conversation_summaries.db*` (`0644`), `log/cli-*.log` (`0644`), `crashes/*.log` (`0644`), `annotations/*.pbtxt` (`0644`), `implicit/*.pb` (`0644`), `brain/<uuid>/` (`0755`), `config/mcp_config.json` (`0644`) to be world-readable. Only `antigravity-oauth-token`, `antigravity-cli/settings.json`, `conversations/*.db*`, `history.jsonl`, `jetski_state.pbtxt`, `jetbox_summaries_proto.pb`, `updater/*`, and `config/config.json` were `0600`. | Local processes/accounts can read conversation summaries, logs, annotations, and MCP configurations unless explicitly hardened to `0700`/`0600` and launched under `umask 0077`. |
| **Available vs Missing Tooling** | **Installed**: `git 2.43.0`, `python3 3.12.3` (`tomllib`, `json`, `hashlib`, `fcntl`, `sqlite3` stdlib), `jq 1.7`, `gpg 2.4.4`, `ssh-keygen`, `bwrap 0.9.0`, `systemd 255`, `sha256sum 9.4`, `flock 2.39.3`, `gnome-keyring-daemon`, `gh`. **Missing**: `sops` (requires binary/Go install; not in Ubuntu apt), `age`, `gitleaks`, `trufflehog`, `secret-tool` (`libsecret-tools`), `yq`, `node`/`npm`/`npx`, `uv`/`uvx`, `~/.ssh`. | Core `bin/agentcfg` must run on pure Python 3.12 stdlib with built-in regex/entropy secret fallbacks, treating external tools as progressively enhanced gates. |

---

## 2. Three-Tier Source-of-Truth Architecture

`agentconfig` enforces strict separation between declarative configuration, secrets, and mutable runtime state:

### 2.1 Tier Definitions

1. **Tier A — Canonical Declarative Source-of-Truth (Git-tracked in `/home/omniboot/agentconfig`)**
   - Contains canonical rules (`canonical/rules/`), reviewed skills (`canonical/skills/`), reviewed hooks (`canonical/hooks/`), the canonical MCP registry (`canonical/mcp-registry.json` referencing `secret_ref` IDs—never raw tokens), per-harness deterministic render specs (`canonical/harnesses/`), failsafe profiles (`canonical/profiles/failsafe/`), security policies & lockfiles (`policy/`), target mapping (`targets/targets.json`), environment/secret wrappers (`wrappers/`), and the sync engine (`bin/agentcfg`).
   - Every commit and release tag is signed via SSH (`git config gpg.format ssh`) and gated by `.githooks/pre-commit`.

2. **Tier B — Secrets & Authentication (NEVER committed in plaintext)**
   - **Runtime API tokens & MCP secrets**: Stored in `gnome-keyring` (`secret-tool`) and optionally backed up via `sops` + `age` in `secrets/secrets.enc.yaml` (encrypted to public `age` recipients defined in `secrets/.sops.yaml`, with private `age` key optionally stored in the keyring via `SOPS_AGE_KEY_CMD="secret-tool lookup application sops type age-key"`).
   - **Native OAuth / session auth files**: Remain out-of-band outside Git SoT with `0600` permissions inside `0700` parent directories (`~/.gemini/antigravity-cli/antigravity-oauth-token`, `~/.gemini/{oauth_creds.json,google_accounts.json}`, `~/.config/gh/hosts.yml`, `~/.claude/.credentials.json`, `$CODEX_HOME/auth.json`, `~/.kimi-code/credentials/`, `~/.grok/{auth.json,mcp_credentials.json}`).
   - **Zero-leak runtime injection**: Stdio MCP servers and CLI runners never inherit ambient host secrets; `wrappers/mcp-secret-exec` clears the environment (`env -i`) and injects only the scoped credential variables required for that specific server.

3. **Tier C — Mutable Runtime State & `/tmp/` (Excluded from Git & SoT)**
   - SQLite conversation/summary/state DBs (`-wal`, `-shm`), transcripts, crash dumps, lockfiles, staging caches, updater state, and interactive app state files (`~/.gemini/config/{config.json,projects/,.migrated}`, `~/.gemini/trustedFolders.json`, `~/.copilot/config.json`, etc.).
   - Volatile temp files live exclusively inside private `0700` per-user directories (`$XDG_RUNTIME_DIR/agent-runtime` and `~/.local/tmp/`).

### 2.2 Rendering & Deployment Strategies

Cross-harness symlink collisions (`ELOOP` / duplicate skill loading between `~/.agents/skills/` and `<agent>/skills/`), Antigravity `1.5.8` rejecting out-of-plugin symlinks, Antigravity 2.0 skipping `.gitignore`-listed `.agents/` directories, and container/`bwrap`/AppImage mount boundaries make deterministic **rendering** superior to naive symlink farms:
- **`ro` (Declarative Target, `0400`/`0444`)**: For purely declarative target files (rules, prompts, standalone MCP configs). Deployed read-only, validated for parent-dir `lstat()` safety (`safe_target`), and verified by whole-file SHA-256. Generated repo-local `.agents/` outputs are hidden via `.git/info/exclude` rather than `.gitignore` so Antigravity 2.0 loads them without dirtying `git status`.
- **`plugin-bundle` (Antigravity Optimization)**: Deploys `agentconfig`'s shared rules, skills, hooks, and MCP config as a dedicated managed plugin at `~/.gemini/config/plugins/agentconfig-core/`, keeping Antigravity's mutable `~/.gemini/config/config.json` (`plugins.<dir>.enabled`, permission grants) isolated from SoT rewrites.
- **`patch-managed-keys` (`0600`)**: For mixed declarative+runtime files (`~/.claude.json`, `~/.gemini/antigravity-cli/settings.json`), `agentcfg` applies an explicit allowlist of managed leaf keys (stripping known retired keys while preserving runtime caches, trust records, and timestamps) and verifies the managed subtree hash rather than whole-file equality.

---

## 3. Target Models, Harnesses & Open Standards Specification

### 3.1 Google Antigravity (`agy` CLI 1.5.8, Antigravity 2.0 App, IDE, Python SDK) *(Verified)*

- **Surfaces & Paths**:
  - **Shared global customization root**: `~/.gemini/config/` (`config.json` atomic app state never meant for hand-editing, `mcp_config.json`, `.migrated`, `projects/`, `plugins/`, `skills/`, `agents/`, `rules/`, `sidecars/`, `skills.json`, `plugins.json`, `hooks.json`).
  - **CLI (`agy`)**: `~/.gemini/antigravity-cli/` (`settings.json` [`0600`], `antigravity-oauth-token` [`0600`], `builtin/{.manifest,.checksum,plugins/,skills/}`, `conversations/<uuid>.db*`, `conversation_summaries.db*`, `brain/<uuid>/`, `cache/`, `crashes/`, `annotations/*.pbtxt`, `implicit/*.pb`, `log/cli-*.log`, `presence/*.lock`, `updater/{update.lock,update_status.json}`, `history.jsonl`, `jetbox_summaries_proto.pb`, `jetski_state.pbtxt`). Wrapper `/home/omniboot/.gemini/antigravity-cli/bin/agentapi` delegates to `/home/omniboot/.local/bin/agy agentapi`.
  - **Antigravity 2.0 Desktop (Electron)**: `~/.gemini/antigravity/` (`sidecar_data/<sidecar_id>/`) + `~/.config/Antigravity/`.
  - **Antigravity IDE**: `~/.gemini/antigravity-ide/` + `~/.config/Antigravity/`. Manual `.tar.gz` unpacks require root-owned SUID `4755` `chrome-sandbox`; community AppImages mount at `/tmp/.mount_*`.
  - **Python SDK (`google-antigravity`)**: Bundles compiled agent runtime binary (`Agent`, `LocalAgentConfig`, `CapabilitiesConfig`; read-only by default).
  - **Project discovery**: `.agents/` (plus `.agent/`, `_agents/`, `_agent/`) walking CWD up to repo root (`.git`), `.antigravity/settings.json`, `GEMINI.md`, `AGENTS.md`. **Gotcha (`#26`, `#27`)**: Antigravity 2.0 refuses to load `.agents/{rules,workflows,skills}` if listed in `.gitignore` (even when `Agent Gitignore Access` is enabled)—generated workspace files must use `.git/info/exclude`.
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
  - **Failsafe & Memory Reset**: `COPILOT_HOME=<clean_dir>`, `--disable-builtin-mcps`, `--disable-mcp-server`, `--no-custom-instructions`, `/memory off` (VS Code `chat.copilot.memory.enabled: false`). **Important**: Disabling Copilot Memory stops capture/use only—existing stored facts require explicit **server-side purge** via GitHub.com profile/repo settings (`copilot-memories.jsonl` is only the JSONL input format passed to `copilot memories import`, not a persistent local memory store).

### 3.4 OpenAI Ecosystem (Codex CLI/App/IDE & ChatGPT Desktop/Web) *(Verified)*

#### 3.4.1 Codex CLI, App Server, IDE Extension & Desktop App
- **Roots, Env Overrides & 7-Layer Precedence**:
  - `CODEX_HOME` (default `~/.codex`; must exist on disk if explicitly set); `CODEX_SQLITE_HOME` (default `$CODEX_HOME`, overridden by `sqlite_home` in `config.toml` / `requirements.toml`).
  - `config.toml` precedence (highest -> lowest): `(1)` CLI `-c`/`--config` (dotted keys) > `(2)` Project `.codex/config.toml` ordered root (`[".git"]`) to CWD (**trusted projects only**) > `(3)` Standalone named profile `$CODEX_HOME/<name>.config.toml` selected via `--profile <name>` (top-level keys; `[profiles.<name>]` and top-level `profile =` were dropped in `v0.134.0+`) > `(4)` User `$CODEX_HOME/config.toml` > `(5)` Cloud-managed `config.toml` defaults > `(6)` System `/etc/codex/config.toml` > `(7)` Built-in defaults.
  - **Blocked project keys**: Untrusted projects skip all repo `.codex/` layers (`config.toml`, `hooks.json`, `.rules`). Even in trusted projects, Codex ignores and warns on 10 host/auth/telemetry keys in `.codex/config.toml`: `openai_base_url`, `chatgpt_base_url`, `apps_mcp_product_sku`, `model_provider`, `model_providers`, `notify`, `profile`, `profiles`, `experimental_realtime_ws_base_url`, `otel`.
  - **Managed `requirements.toml` precedence**: `(1)` macOS MDM (`com.openai.codex:requirements_toml_base64`) > `(2)` Legacy `managed_config.toml` (`/etc/codex/managed_config.toml` Unix, `~/.codex/managed_config.toml` Win) > `(3)` Agent Security cloud bundle > `(4)` System `/etc/codex/requirements.toml` (`%ProgramData%\OpenAI\Codex\requirements.toml`).
  - **Desktop App paths**: macOS `~/Library/Logs/com.openai.codex/YYYY/MM/DD`, Sparkle cache, `~/Library/Application Support/{ChatGPT,com.openai.chat}`; Windows `%LOCALAPPDATA%\Codex\Logs\`, MSIX ChatGPT Desktop; Linux preview `.deb`/`.rpm`/Arch (`chatgpt` binary; XWayland default, `--ozone-platform=wayland`).
- **Instructions & Local 2-Phase Memory Pipeline**:
  - `AGENTS.override.md` / `AGENTS.md` (`/etc/codex/` + `$CODEX_HOME/` -> repo root to CWD; `project_doc_fallback_filenames`, `project_doc_max_bytes`).
  - **Async local memory (`[features].memories`, default off in CLI)**: Phase 1 extracts per-thread `raw_memory`/`rollout_summary`/`rollout_slug` into `memories_1.sqlite` / `memories_v2_1.sqlite` (with secret redaction); Phase 2 acquires global lock + git baseline (`~/.codex/memories/.git`), writes `raw_memories.md` / `rollout_summaries/*.md` / `phase2_workspace_diff.md`, spawns an isolated **no-network / no-collab** consolidation subagent producing `MEMORY.md`, `memory_summary.md`, and `skills/`, then resets the git baseline. Controlled via `memories.version` and `dual_write` across `$CODEX_HOME/{memories,memories_v2}/`; `/memories` toggles per-session use.
  - **Computer History (`skysight`)**: `$CODEX_HOME/memories/extensions/skysight/` (+ `memories_extensions/`) stores unencrypted local Markdown + 48h App Group event stream—accompanied by an official warning regarding prompt-injection risk from observed apps/websites.
- **Skills, Plugins, MCP, Hooks, Rules, Subagents & Sandbox**:
  - **Skills**: `SKILL.md` (`name`, `description`) + optional `agents/openai.yaml` (`policy`, `dependencies`) across `$CWD/.agents/skills`..`$REPO_ROOT/.agents/skills`, `$HOME/.agents/skills`, `/etc/codex/skills`, plugin `skills/`, and consolidated memory `skills/` (**follows symlinked skill folders**).
  - **Plugins**: Portable `plugin.json` (`extensions.com.openai`) with `.codex-plugin/plugin.json` fallback, `.mcp.json`, `.app.json`, `hooks/hooks.json`; marketplaces in `.agents/plugins/marketplace.json` / `.claude-plugin/marketplace.json`, cached under `$CODEX_HOME/plugins/cache/`. (**Unsupported in IDE extension.**)
  - **MCP (`[mcp_servers.<name>]` in `config.toml` / plugin `.mcp.json`)**: `stdio` (`command`, `args`) and HTTP (`url`, `bearer_token_env_var`, `http_headers`, OAuth + CIMD via `codex mcp login`).
  - **Hooks**: `~/.codex/hooks.json`, `<repo>/.codex/hooks.json` (trusted only), inline `[hooks]` in `config.toml`/`requirements.toml`, plugin `hooks/hooks.json` (`async: true` supported; exit `2` or `decision: "block"` blocks). **Critical caveat**: `PreToolUse` timeout, crash, or malformed output can **fail open** and allow tool execution (`[features].hooks = false` in `requirements.toml` locks off).
  - **Execution Rules & Subagents**: Starlark `rules/*.rules` (`prefix_rule`, `forbidden > prompt > allow`, `codex execpolicy check`); subagents in `~/.codex/agents/*.toml` & `.codex/agents/*.toml` (`developer_instructions`).
  - **Sandbox & Network Proxy**: `sandbox_mode`: `read-only` | `workspace-write` | `danger-full-access`; `approval_policy`: `on-request` | `never` | `{ granular = { ... } }` (**`untrusted` retired in `v0.149.0+`**, crashes on startup); `shell_environment_policy.ignore_default_excludes` defaults to **`true`**; `[network_proxy]` (`allow_local_binding = false` default); Linux `bwrap` + `seccomp` + `PR_SET_NO_NEW_PRIVS` + `/run/WSL` socket masking + `codex_uds`.
- **SQLite, Runtime, `/tmp/` & Secrets**:
  - SQLite DBs under `CODEX_SQLITE_HOME` (WAL default; `DELETE` on NFS): `state_5.sqlite`, `logs_2.sqlite`, `goals_1.sqlite`, `memories_1.sqlite`, `memories_v2_1.sqlite`, `queue_1.sqlite` (all `RecoveryMode::BackupAndRebuild` via `PRAGMA quick_check`), plus `thread_history_1.sqlite` (`RecoveryMode::Unavailable`).
  - Mutable `$CODEX_HOME`: `version.json`, `history.jsonl`, `sessions/` (`rollout-*.jsonl`), `archived_sessions/`, `log/`, `shell_snapshots/` (**3-day auto-prune**), `packages/standalone/`, `worktrees/`, `memories/`, `memories_v2/`, `memories_extensions/`, `plugins/cache/`.
  - `/tmp/` & Secrets: Large hook outputs -> `<temp_dir>/hook_outputs/<session_id>/<uuid>.txt`; `codex migrate-nfs-db` staging uses `.codex-nfs-migration.lock`. `$CODEX_HOME/auth.json` is **plaintext by default** when `cli_auth_credentials_store = "file"`.
- **Failsafes, Updates & Memory Purge**:
  - Failsafe: `codex --sandbox read-only --ask-for-approval on-request`, standalone `$CODEX_HOME/failsafe.config.toml` via `--profile failsafe`, `CODEX_HOME=$(mktemp -d) CODEX_SQLITE_HOME=<same>`, `--strict-config`, `--no-daemon`, `codex doctor`, `codex migrate-rollouts`, `codex migrate-nfs-db`.
  - Updates: `[features].in_app_updates = false` honored in **`requirements.toml` only**; `key_aliases.rs` normalizes renamed keys (`memories.no_memories_if_mcp_or_web_search` -> `memories.disable_on_external_context`, `agents.max_threads` -> `agents.max_concurrent_threads_per_session`); `[experimental_network]` -> `[network_proxy]` (`0.166.0`).
  - Memory wipe & bypass: `memories.disable_on_external_context = true` excludes MCP/web-search threads; **`codex debug clear-memories`** empties `$CODEX_HOME/{memories,memories_v2,memories_extensions}` contents while preserving dirs (refuses symlinked roots).

#### 3.4.2 ChatGPT Web, Consumer Memory, Projects, Developer Mode MCP & Dots
- Strictly cloud-isolated (does not read/write `~/.codex/memories/`). Custom Instructions (1,500 chars Free / 5,000 Plus+); Consumer Memory (`Reference saved memories`, `Reference chat history`, Project-only isolation, Temporary Chat; **deleting a chat does NOT delete saved memories**, and `Export data` omits the dynamic summary layer); **Dots** keep separate persistent notes; Developer Mode MCP (`Settings > Advanced > Developer Mode`) connects remote HTTPS `/mcp` via OAuth 2.1 + DCR, `No Auth`, or `Mixed`.

### 3.5 Anthropic Ecosystem (Claude Code CLI/IDE & Claude Desktop) *(Verified)*

#### 3.5.1 Claude Code (CLI, VS Code, JetBrains & Desktop Code Tab)
- **Roots, Env Overrides & 5-Tier Precedence**:
  - `CLAUDE_CONFIG_DIR` (default `~/.claude`; `~/.claude.json` stays in `$HOME`), `CLAUDE_CODE_PROJECT_DIR_NAME` (`v2.1.234+`), `CLAUDE_CODE_TMPDIR` (Claude appends `/claude-<uid>/` on Unix).
  - Precedence (highest -> lowest): `(1)` Managed (Server / MDM / `/etc/claude-code/managed-settings.json` + alphabetical `managed-settings.d/*.json`) > `(2)` CLI flags (`--settings`) > `(3)` `.claude/settings.local.json` > `(4)` `.claude/settings.json` (trust-gated) > `(5)` `~/.claude/settings.json`. Scalars take highest tier; arrays merge except `availableModels` and `modelPicker` (`v2.1.242+`).
- **Memory Hierarchy (`CLAUDE.md`, Rules, Auto-Memory & Subagent Memory)**:
  - `CLAUDE.md` load order: Managed (`/etc/claude-code/CLAUDE.md`) -> User (`~/.claude/CLAUDE.md`) -> Project (`./CLAUDE.md`, `./.claude/CLAUDE.md`, or `./AGENTS.md` via `cc-plugin-agents-md@builtin`) + `./CLAUDE.local.md`. `@path/to/import` external imports prompt for trust once per project; target `<200` lines/file (`claudeMdExcludes`).
  - `.claude/rules/*.md` (YAML `paths:` globs; symlinks outside root trigger trust dialog).
  - **Auto-memory**: `~/.claude/projects/<encoded-project>/memory/MEMORY.md` + topic `.md` (first **200 lines or 25 KB** loaded every session; `/memory` inspects/toggles; `autoMemoryEnabled: false` or `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`). Subagents support `memory: user|project|local`.
- **Skills, Subagents, Hooks, Plugins & Mods**:
  - **Skills & Commands**: `Enterprise > Personal (~/.claude/skills/) > Project (.claude/skills/) > --add-dir > Bundled > Plugin (/plugin:skill) > claude.ai synced`; `.claude/commands/*.md` merged into skills.
  - **Subagents**: `--agents` > `.claude/agents/*.md` > `~/.claude/agents/*.md` > Plugin `agents/*.md` (no `hooks` allowed on plugin subagents).
  - **Hooks**: **33 events** (`command`, `http`, `mcp`, `prompt`, `agent`; exit `2` hard block; `allowManagedHooksOnly`, `disableAllHooks`).
  - **Plugins & Mods**: Plugins use `.claude-plugin/{plugin,marketplace}.json`; state in `~/.claude/plugins/{installed_plugins.json,known_marketplaces.json}`. **Mods (`hooks/register.js`)** are JS modules executed **inside the Claude Code process with full user permissions (NOT OS-sandboxed)**—without managed settings / `managed-mcp.json` / Team-Enterprise auth, a mod's `tool.check` **can approve calls blocked by user `deny` or `ask` rules** (`allowManagedModsOnly`, `allowModsToOverrideDenyRules` in managed orgs).
- **MCP, Permissions & OS Sandbox**:
  - MCP: `~/.claude.json` (`user` + per-project `local`, `hasTrustDialogAccepted`), `.mcp.json` (`project` shared; `${VAR}`/`${VAR:-default}`; **missing `type` with `url` errors as stdio**; `headersHelper` trust-gated), `managed-mcp.json` + `allowedMcpServers`/`deniedMcpServers`.
  - Permissions (`deny -> ask -> allow`): `default` (`Manual`), `acceptEdits`, `plan`, `auto`, `dontAsk`, `bypassPermissions` (`disableBypassPermissionsMode: "disable"`).
  - OS Sandbox: Linux `bwrap` + `socat` + `@anthropic-ai/sandbox-runtime` (AppArmor profile needed on restricted Ubuntu 24.04 userns hosts); `sandbox.{filesystem,credentials,network}`. **`/tmp/` gotcha**: Built-in `Read`/`Edit`/`Write` ignore `filesystem.denyRead`/`allowWrite`, and **sandboxed commands inherit host `$TMPDIR`** (not `CLAUDE_CODE_TMPDIR/claude-<uid>/`).
- **Runtime, Secrets, Failsafes & Updates**:
  - Mixed `~/.claude.json` (up to 5 backups in `~/.claude/backups/.claude.json.corrupted.<ts>`), `.trash` caps (~1,024), `~/.claude/.credentials.json` (secrets, never Git).
  - **Failsafes**: **`claude --safe-mode`** (`CLAUDE_CODE_SAFE_MODE=1`, **primary built-in failsafe** disabling all user/project `CLAUDE.md`, skills, plugins, hooks, custom commands/agents, MCPs, auto-memory, and installed mods while retaining auth, model, permissions, and managed policy/built-in mods), **`claude --restricted`** (`CLAUDE_CODE_RESTRICTED=1`, evaluation isolation), **`claude --bare`** (`CLAUDE_CODE_SIMPLE=1`, minimal scripted mode skipping auto-discovery), `--strict-mcp-config`, `--setting-sources`, `--no-session-persistence`, `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1`, `claude doctor`/`/doctor`/`/skill-doctor`, `claude purge` (local transcript/history/`~/.claude.json` entry wipe).
  - Updates: `DISABLE_AUTOUPDATER=1` (keeps `claude update`), `DISABLE_UPDATES=1`; `-p` refuses to wipe corrupt `~/.claude.json`; old plugin caches marked `.orphaned_at` and deleted after 14 days.

#### 3.5.2 Claude Desktop (1P vs 3P `Claude-3p/`, Cowork, `.mcpb`) & `claude.ai`
- **1P Paths**: `~/.config/Claude/claude_desktop_config.json` (Linux; macOS `~/Library/Application Support/Claude/`, Win `%APPDATA%\Claude\`); `.mcpb` desktop extension bundles store credentials in OS keychain.
- **3P Enterprise (`Claude-3p/`) & Security Hazards**: Linux `~/.config/Claude-3p/` + shared `~/.claude/` & `~/.claude.json`. Runtime files include `local-agent-mode-sessions/` (unencrypted full-text `audit.jsonl` + `.audit-key` HMAC), `ccd-session-secrets/` (`0700`), and `plugin-mcp-auth/.credentials.json` (**plaintext on Linux/Windows**). Cowork VM limits network egress unless "All domains" (note doc discrepancy around `requireCoworkFullVmSandbox`); retention policies preserve Projects/Memory. **Beta `skillScanningEnabled` hazard**: rewrites user/uploaded text skills **in place with NO backup**. Consumer `claude.ai` keeps Account Memory, Project memory, and Ghost Incognito chats cloud-side.

### 3.6 Emerging Harnesses & Cross-Agent Open Standards *(Verified)*

1. **Moonshot Kimi (`MoonshotAI/kimi-code` & archived `kimi-cli`)**:
   - Legacy Python `kimi-cli` used `~/.kimi/`; active Node.js `kimi-code` uses `$KIMI_CODE_HOME` (`~/.kimi-code/`), while `~/.agents/{skills,agents,AGENTS.md}` always resolve via `$HOME`.
   - Global `config.toml`, `tui.toml`, `SYSTEM.md`, `AGENTS.md`, `mcp.json`, `credentials/*.json` (`0600`); project `.kimi-code/{local.toml,mcp.json,AGENTS.md,skills/,agents/}` (no project `config.toml`/hooks). **Env gotcha**: shell `KIMI_API_KEY` is ignored unless mapped via `[providers.<name>].api_key_env`. `AGENTS.md` warns above `32 KiB`; `--skills-dir` **replaces** auto-discovered skill dirs; native updates stage adjacent to the binary (`.staging/kimi-*`).
   - Failsafe/Memory: `kimi doctor [config|tui]`, `CONFIG_PERSIST_BLOCKED` prevents overwriting corrupt `config.toml`, `kimi migrate` imports `~/.kimi/` non-destructively, `KIMI_DISABLE_CRON=1`, session-only `contextMemory` + `wire.jsonl`.
2. **xAI Grok (Grok Build vs Remote MCP API vs `@vibe-kit/grok-cli`)**:
   - **Grok Build (Official Rust CLI)**: `$GROK_HOME` (`~/.grok/`): `config.toml`, `managed_config.toml`, `requirements.toml` (5-layer precedence topped by `/etc/grok/requirements.toml`), `sandbox.toml` (`bwrap`), `trusted_folders.toml`, `auth.json`, `mcp_credentials.json`, `hooks/*.json` (`command`/`http`, 5s timeout, exit `2` blocks). Project `.grok/config.toml` loads only `[mcp_servers]`, `[plugins]`, `[permission]`; auto-scans `~/.claude.json`, `.cursor/mcp.json`, `.mcp.json` unless disabled (`GROK_{CURSOR,CLAUDE}_*=0`). Remote xAI API (`api.x.ai/v1/responses`) uses `type: "mcp"`.
   - Failsafe/Memory: `grok inspect [--json]`, `grok mcp doctor`, `grok plugin validate`, `--no-memory`, `--no-plan`, `GROK_DISABLE_AUTOUPDATER=1`; Memory is **off by default** (`GROK_MEMORY=0`) and wiped via **`grok memory clear [--workspace|--global|--all]`**.
   - **Critical Path Collision**: Unofficial `@vibe-kit/grok-cli` (`superagent-ai/grok-cli`) stores `user-settings.json` / `.grok/settings.json` in the exact same `~/.grok/` and `.grok/` paths (`agentcfg` must detect/separate via `--grok-flavor xai|vibekit`).
3. **OpenCode V2 (`anomalyco/opencode`)**:
   - Strict XDG (`$OPENCODE_CONFIG_DIR` > `~/.config/opencode/`, `~/.local/share/opencode/`, `~/.cache/opencode/`, `~/.local/state/opencode/`, `/tmp/opencode`), `OPENCODE_DB`, `OPENCODE_TEST_HOME`, `opencode debug paths`. **`AGENTS.md` ONLY** (ignores `CLAUDE.md`); `mcp.servers` (`local`/`remote`); `{env:VAR}` expands unset vars to `""`; Plugins V2 (`@opencode/plugin`) break V1; `--standalone`. **V2 security regression**: `external_directory` defaults to **`allow`** (was `ask` in V1).
4. **Cursor IDE & CLI**:
   - `~/.cursor/{cli-config.json,mcp.json,hooks.json,rules/,skills/,worktrees/}`, `.cursor/rules/*.mdc` (plain `.md` ignored), `${CURSOR_PLUGIN_ROOT}` required in `mcp.json` (`${PLUGIN_ROOT}` fails), `hooks.json` (`failClosed`, `loop_limit: 5`, injects `CI=1`). `cli-config.json` backs up corrupt JSON as `.bad`. **Memories removed in Cursor 2.1** (export legacy memories to `.mdc`; prune `state.vscdb` via **GC Agent KV Blobs**).
5. **Windsurf -> Devin Desktop & Devin CLI (`docs.devin.ai`)**:
   - Windsurf IDE rebrands to **Devin Desktop** (June 2, 2026); `~/.config/devin/{config.json,mcp_config.json,AGENTS.md,skills/}`, `.devin/{rules/,skills/,hooks.v1.json}`. `v3000.3` auto-migrated `mcp_config.json`. **Quirks**: standalone CLI honors `.gitignore` **only** (ignores `.devinignore`/`.windsurfignore`); `read_config_from` ignores `CODEX_HOME`; `--sandbox` requires `bwrap` + `socat`; failsafes `--config`, `/rm-session`, `auto_update: false`.
6. **Cline (`cline/cline`) & Roo Code (`RooCodeInc/Roo-Code` — SUNSET May 15, 2026)**:
   - **Cline**: `~/.cline/` (`CLINE_DIR`) + `~/.cline/data/` (`CLINE_DATA_DIR`), `cline_mcp_settings.json` (`type: "streamableHttp"`), `AgentPlugin` worker threads (CLI/SDK/Kanban only), `cline doctor [fix|log]`, `memory-bank/*.md`. **`.clineignore` is deprecating** (non-security) in favor of `PreToolUse` hooks.
   - **Roo Code**: **All Roo Code products shut down May 15, 2026** (migrate to Cline). `McpHub.ts` throws on `url` without explicit `type: "streamable-http"|"sse"`; experimental `.roo/tools/*.{ts,js}` are auto-approved and copy `.env*`; Settings Export writes **plaintext API keys**.
7. **Goose (`aaif-goose/goose`) & Aider (`Aider-AI/aider`)**:
   - **Goose**: XDG (`~/.config/goose/`, `~/.local/share/goose/sessions/sessions.db`, `~/.local/state/goose/`) redirected uniformly by **`GOOSE_PATH_ROOT`**. `CONTEXT_FILE_NAMES` (`["AGENTS.md", ".goosehints"]`); `streamable_http` (no SSE); Open Plugins + `hooks/hooks.json`; `goose run --no-session`, `goose update --reconfigure`; Memory extension stores `~/.config/goose/memory/` & `.goose/memory/`.
   - **Aider**: `.aider.conf.yml` (Home -> Git Root -> CWD), **no `AGENTS.md` autoload / no MCP / no skills / no hooks** (requires `read: [AGENTS.md]`), `.aider.{chat,input}.history` auto-gitignored; `--no-check-update`, `--no-restore-chat-history`.
8. **Cross-Agent Open Standards & Rendering Compatibility**:
   - **`AGENTS.md`**: Supported natively across Antigravity, Gemini CLI (via `context.fileName`), Copilot, Codex, Kimi, Grok Build, OpenCode V2, Cursor, Devin/Windsurf, Cline, Roo (setting-gated), and Goose; Aider requires explicit `read: ["AGENTS.md"]`.
   - **Agent Skills (`agentskills.io`)**: `SKILL.md` (`name` 1–64 `[a-z0-9-]`, `description` 1–1024) in `~/.agents/skills/` and `.agents/skills/` works across Antigravity, Gemini CLI, Copilot, Codex, Kimi, OpenCode V2, Cursor, Devin, Cline, Roo, and Goose (Grok requires `.grok/skills/` locally).
   - **Agent Plugins (`agent-plugins.org` v1.0.0)**: Shared `plugin.json` + `skills/` + `mcp.json` + hooks convention across Antigravity, VS Code, Copilot, Cursor, Codex/ChatGPT, Goose, etc.
   - **MCP Divergence (Rendering Required)**: Clients split across 5 root keys (`mcpServers`, `servers`, `mcp.servers`, `mcp_servers`, `extensions`), divergent transport enums (`streamableHttp`, `streamable-http`, `streamable_http`, `http`, `remote`, omitted), and incompatible env expansion (`${VAR}`, `${env:VAR}`, `{env:VAR}`, `bearerTokenEnvVar`, or Antigravity plugin `variables`), forcing `bin/agentcfg` to render per-harness targets from `canonical/mcp-registry.json`.

---

## 4. `/tmp/` & Agent Memory Surfaces and Hardening

### 4.1 Why Default `/tmp` Fails Security and Stability

1. **Same-UID races in `1777` directories**: Kernel `fs.protected_symlinks=1` and `fs.protected_regular=2` block *cross-UID* attacks in `/tmp` and `/var/tmp`, **not** same-UID compromises (e.g., a rogue MCP server, malicious `postinstall`, or injected tool running as UID 1000 racing predictable paths such as `/tmp/lsrpc.sh` or `0775` subdirs).
2. **World-readable leaks via `umask 0002`**: Without explicit `0600`/`0700` creation, logs, crash dumps, conversation summaries, bash outputs, and MCP payloads are world-readable (`0644`/`0755`).
3. **Retention & Disk Exhaustion vs `ENOSPC` Trap**: `/tmp` shares `/` (`38G` ext4) with 30-day cleanup while `/var/tmp` never cleans up by default (`#q` commented out). Meanwhile, pointing `$TMPDIR` to `/run/user/1000` (`191 MiB`) triggers `ENOSPC` on AppImages (`/tmp/.mount_*`), Electron staging, or large repo unpacks.
4. **Cross-harness `/tmp/` clutter**: Antigravity `lsrpc.sh` & Chromium singletons (`/tmp/.org.chromium.Chromium.*`), Claude `$CLAUDE_CODE_TMPDIR/claude-<uid>/` vs sandbox host `$TMPDIR` mismatch, Codex `hook_outputs/<session>/` & `codex_uds` sockets & stranded `bwrap` `.git`/`.codex` mount targets, OpenCode `/tmp/opencode`, Aider `tempfile.mkdtemp()`, `npx`/`uvx`/`mcp-remote` caches, and `xrdp` `/tmp/dbus-*` (`srwxrwxrwx`) sockets.

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
- **Local rule/memory append poisoning**: Gemini CLI `save_memory` appends directly to `~/.gemini/GEMINI.md` (`## Gemini Added Memories`); Antigravity `/learn` appends to `GEMINI.md`/`AGENTS.md`/`.agents/rules/*.md`; Claude Code writes `~/.claude/projects/*/memory/*.md`; Codex writes `$CODEX_HOME/{memories,memories_v2}/` plus unencrypted `skysight` Computer History logs; Goose writes `~/.config/goose/memory/` and `.goose/memory/`.
- **Binary / SQLite memory corruption**: Unclean `SIGKILL`/OOM leaves Antigravity `conversation_summaries.db*`, `implicit/*.pb`, `annotations/*.pbtxt`, `jetbox_summaries_proto.pb`, Codex `$CODEX_HOME` SQLite DBs (`state_5.sqlite`, `logs_2.sqlite`, `goals_1.sqlite`, `memories_1.sqlite`, `memories_v2_1.sqlite`, `queue_1.sqlite`, `thread_history_1.sqlite`), Copilot `session-store.db`, OpenCode `OPENCODE_DB`, or Goose `sessions.db` with broken WAL/SHM journals.
- **Cloud / Server-side memory**: GitHub Copilot Memory (28-day TTL, JIT citation verified), ChatGPT Memory, and Claude.ai Memory persist server-side—disabling local capture stops future writes but does **not** delete stored cloud facts. Meanwhile, Claude Desktop's beta `skillScanningEnabled` rewrites local text skills in place without backups.
- **Hardening controls**: `agentcfg` maintains pre-change memory snapshots (`~/.local/state/agentcfg/memory-snapshots/`, `0700`/`0600`), scans local memory stores for hidden Unicode, exfiltration directives (`curl`, `wget`, `.ssh`, `antigravity-oauth-token`, `hosts.yml`), and anomalous size spikes, supports selective line/file quarantine + native wipes (`codex debug clear-memories`, `claude purge`, `grok memory clear --all`), and disables auto-memory in `failsafe` mode.

---

## 5. Supply-Chain, Pre-Trust RCE & Network Resilience Threat Model

### 5.1 Threat & Control Matrix

| Threat Vector | Mechanism & Precedents | `agentconfig` Control |
| :--- | :--- | :--- |
| **Untrusted Repo Configs (Pre-Trust RCE & Exfil)** | Cloned repos embed `.mcp.json`, `.vscode/mcp.json`, `.claude/settings.json`, `.gemini/settings.json`, `.codex/config.toml`, `.grok/hooks/*.json`, `.roo/tools/*.{ts,js}`, `.agents/hooks.json` (`sh -c`), `.agents/{skills,plugins}.json` (`inherits`), or `*_BASE_URL` overrides (**CVE-2025-59536**, **CVE-2026-21852**). | 1. Keep Workspace Trust ON (`security.folderTrust.enabled: true`, VS Code `security.workspace.trust.enabled: true`, `chat.mcp.autostart` off for untrusted, never global `enableAllProjectMcpServers: true`).<br>2. Run `agentcfg audit-repo <path>` before opening unfamiliar repos.<br>3. Sandbox untrusted repos inside `bwrap` (`0.9.0`) with an isolated `$HOME` excluding `~/.ssh`, `~/.config/gh`, `antigravity-oauth-token`, and keyring access. |
| **Unpinned `npx -y` / `uvx`, Typosquatting & Rug Pulls** | Floating refs auto-pull mutable upstream code (`uvx --with-requirements` ignores hashes; npm `mcp-server-git`/`mcp-server-sqlite` differ from official PyPI servers); updated servers swap tool schemas/descriptions (**tool poisoning**) or spoof tools (**tool shadowing**). | 1. Policy ban on floating `npx -y` / `@latest` / `uvx` in `mcp-registry.json`.<br>2. Pre-install into locked per-server prefixes (`~/.local/share/agentconfig/mcp-venvs/<srv>/` via `uv pip install --require-hashes` / `npm ci --ignore-scripts` with `min-release-age=7`) or `image@sha256:...`.<br>3. Pin `tools/list` SHA-256 in `policy/manifests.lock.json`.<br>4. Wrap local-only stdio servers with `bwrap --unshare-net` and `env -i`. |
| **Unsandboxed Mods, Fail-Open Hooks & Poisoned Skills** | Claude Code Mods (`hooks/register.js`) run unsandboxed and can override user `deny`/`ask` rules without managed policy; Codex `PreToolUse` hooks fail open on timeout/crash; community `SKILL.md` / `AGENTS.md` conceal invisible Unicode (`U+200B..U+200F`, `U+202A..U+202E`, Tags `U+E0000..U+E007F`). | Vendor external skills/plugins only at pinned Git SHAs after diff inspection; ban unauthorized Mods and monitor `allowManagedModsOnly`; enforce explicit hook `timeout` (`<=10s`) + `timeout -k 5s`; `agentcfg validate` strips/fails on invisible Unicode, unexpected `hooks.json`/`scripts/`, base64 payloads, and outbound `curl`/`wget`/`nc`; run `agy plugin validate --strict`. |
| **Plaintext Credential Theft** | Inline tokens in `mcp_config.json`, `.mcp.json`, `~/.claude.json`, `$CODEX_HOME/auth.json` (`file` store), Desktop `plugin-mcp-auth/.credentials.json` (Win/Linux), `audit.jsonl`, or Roo Settings Export, amplified by `umask 0002` `0644` files and full parent `env` inheritance. | Zero plaintext secrets in Git or rendered configs; ban literal credential keys/headers/URL userinfo (`fleet_mcp.py` pattern); retrieve via `gnome-keyring` (`secret-tool`) or `sops+age`; launch stdio servers through `wrappers/mcp-secret-exec` using `env -i` whitelist (never passing `SOPS_AGE_KEY` or unrelated tokens). |
| **Network Corruption & Updater Failures** | Truncated `curl \| sh` / `npx` downloads, stale `updater/update.lock` / `install.lock`, partial `~/.cache/antigravity/staging/`, mismatched `builtin/.checksum`, hung remote MCP / 30s synchronous hooks. | Ban `curl \| sh`; stage in `0700`, verify SHA-256/sig, parse-validate, atomic `os.replace`; hardlink/snapshot `~/.local/bin/agy` pre-update; disable unattended auto-updates (`DISABLE_AUTOUPDATER=1` for Claude Code, `COPILOT_AUTO_UPDATE=false` for Copilot CLI, `general.enableAutoUpdate: false` for Gemini CLI, `"update.mode": "none"` for Antigravity IDE, `GROK_DISABLE_AUTOUPDATER=1`, `"update": "disable"` OpenCode); `--offline` profile disabling remote MCPs. |

---

## 6. `agentcfg cleanse` & Quarantine Workflow

`agentcfg cleanse` repairs corrupted configurations, dead runtime artifacts, and poisoned memory **without destroying evidence or wiping valid credentials**.

### 6.1 Scopes & Auth-Preservation Invariant

- **Scopes (`--scope config|memory|runtime|all`, default `config`)**:
  - **`config`**: Detects invalid JSON/TOML/YAML frontmatter, schema errors, undeclared MCP servers or `.agents/hooks.json`, policy violations (unpinned `npx -y`/`uvx`, unauthorized `*_BASE_URL`, literal secret keys), broken symlinks, and unsafe permissions (`0777`, `0644`/`0755` on sensitive targets). Moves offending files to quarantine and atomically renders clean SoT.
  - **`runtime`**: Detects orphaned `.tmp` / `<path>.<uuid>.tmp` files, stale locks (`updater/update.lock`, `presence/*.lock`, `updates/install.lock`, Electron `SingletonLock`, `agentcfg.lock`), corrupt SQLite DBs / orphaned `-wal`/`-shm` (`conversations/*.db`, `conversation_summaries.db`, Codex `state_5.sqlite` / `logs_2.sqlite` / `goals_1.sqlite` / `memories_1.sqlite` / `memories_v2_1.sqlite` / `queue_1.sqlite` / `thread_history_1.sqlite`, Copilot `session-store.db`, OpenCode `OPENCODE_DB`, Goose `sessions.db`), and stale staging caches. **Safety gates**: Always performs liveness checks (`flock -n` + `fuser` / `/proc/<pid>`) before touching any `.lock`, and checks SQLite files read-only via `PRAGMA quick_check` (mirroring Codex's `BackupAndRebuild` pattern before re-initializing).
  - **`memory`**: Captures a full pre-cleanse snapshot (`0600`), scans local memory stores (`~/.gemini/GEMINI.md` `## Gemini Added Memories`, `~/.claude/projects/*/memory/*.md`, `$CODEX_HOME/{memories,memories_v2}/` & `skysight/`, Goose `~/.config/goose/memory/` & `.goose/memory/`, Antigravity `annotations/*.pbtxt` / `implicit/*.pb` / `conversation_summaries.db*` / `jetbox_summaries_proto.pb` / `history.jsonl`) for hidden Unicode, injection/exfiltration directives, or anomalous diff against `memory-snapshots/`, selectively quarantines tainted lines/files, integrates native reset commands (`codex debug clear-memories`, `claude purge`, `grok memory clear --all`), and warns the user when cloud memory (Copilot / ChatGPT / Claude.ai) requires a web UI purge (note: Copilot Memory is server-side; `copilot-memories.jsonl` is only the JSONL input format for `copilot memories import`).
- **Hard Auth-Preservation Invariant**: `antigravity-oauth-token`, `~/.config/gh/hosts.yml`, `~/.claude/.credentials.json`, `$CODEX_HOME/auth.json`, `~/.gemini/oauth_creds.json`, `~/.kimi-code/credentials/`, `~/.grok/{auth.json,mcp_credentials.json}`, and `~/.local/share/keyrings/` are **never** quarantined or deleted—even under `--scope all`—unless `--include-auth --confirm-wipe-auth` is passed interactively.
- **Quarantine Mechanics**: Files move into `~/.local/state/agentcfg/quarantine/<UTC-ts>/` (`0700`), preserving relative paths, stripping execute bits (`chmod 0400`/`0600`), and recording `quarantine-manifest.json` (`original_path`, `sha256`, `orig_mode`, `scope`, `reason`, `timestamp`).

### 6.2 Safe Applicator Execution Sequence (`agentcfg apply --safe`)

1. Acquire exclusive `flock` on `${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/agentcfg.lock`.
2. Run `agentcfg watch-updates --check` (abort automatic overwrites on unexpected binary/schema drift or `~/.grok/` `vibe-kit` ambiguity).
3. Run `agentcfg validate` + secret scan (`gitleaks` + Python regex/entropy fallback).
4. Run `agentcfg cleanse --dry-run` (or `--auto-quarantine` on confirmed syntax/lock/permission corruption).
5. Snapshot current managed targets and memory (`~/.local/state/agentcfg/snapshots/<UTC-ts>/`), verify parent paths via `lstat()`, and atomically render/patch targets (`0400`/`0444`/`0600`), writing repo `.agents/` exclusions to `.git/info/exclude`.
6. Update `deployed-manifest.json` (`0600`) and verify with `agentcfg verify` (non-zero exit on any hash or mode mismatch).

---

## 7. Built-in `failsafe` Profile Mechanics

`canonical/profiles/failsafe/` combined with `agentcfg failsafe` and `wrappers/agent-env-run --failsafe` guarantees every harness can boot into a **zero-trust safe state**:
- **Baseline Invariants**: Zero external/remote MCP servers, hooks, unsandboxed mods, and third-party plugins disabled, strict ask/read-only permissions, auto-memory disabled/bypassed, verified minimal rules (`<=2 KB`, no `@` includes), `umask 0077`, `env -i` whitelist, and clean isolated `$TMPDIR` (`~/.local/tmp/failsafe.<pid>`, `0700`).

### 7.1 Per-Harness Failsafe Controls

| Harness | Failsafe Flags, Settings & Memory Bypass |
| :--- | :--- |
| **Claude Code** | **Primary built-in failsafe**: **`claude --safe-mode`** (`CLAUDE_CODE_SAFE_MODE=1`, disables all user/project `CLAUDE.md`, skills, plugins, hooks, custom commands/agents, output styles, workflows, LSPs, MCPs, auto-memory, and installed mods while retaining auth, model, permissions, and managed policy). For stricter isolation: **`claude --restricted`** (`CLAUDE_CODE_RESTRICTED=1`, loads managed + `--settings` only, restricts tools to `--tools` & CWD) or **`claude --bare`** (`CLAUDE_CODE_SIMPLE=1`) + `--strict-mcp-config --mcp-config /dev/null` + `--permission-mode plan` + `--setting-sources user`; set `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` / `"autoMemoryEnabled": false`. |
| **Codex CLI** | **`codex --ask-for-approval on-request --sandbox read-only`** (`untrusted` was retired in `v0.149.0+` and crashes on startup) + standalone **`$CODEX_HOME/failsafe.config.toml`** invoked via `--profile failsafe` (top-level keys only; `[profiles.*]` and `profile =` were removed in `v0.134.0+`) + `--strict-config --no-daemon`. Failsafe `failsafe.config.toml` sets `approval_policy = "on-request"`, `sandbox_mode = "read-only"`, `[features].memories = false`, `memories.disable_on_external_context = true`, empty `[mcp_servers]`. Ephemeral isolation: `CODEX_HOME=$(mktemp -d) CODEX_SQLITE_HOME=<same>`. |
| **Gemini CLI** | Failsafe `settings.json`: `security.folderTrust.enabled: true`, `general.defaultApprovalMode: "plan"`, `experimental.autoMemory: false`, empty `mcpServers: {}`; launch with `GEMINI_CLI_HOME=<clean_dir>` or `--approval-mode plan --sandbox`; Policy Engine `.toml` rule denying `save_memory`; clean `~/.gemini/GEMINI.md` without `## Gemini Added Memories`. |
| **Antigravity (`agy`)** | Launch with `--mode plan --sandbox --disable-slash-commands --settings <failsafe-settings.json>` (`toolPermission: "request-review"`, `agentMode: "plan"`) or isolated `ANTIGRAVITY_APP_DATA_DIR=<clean_dir>` / `agy acp --include-default-customizations=false`; disable third-party plugins in `config.json`, empty `mcp_config.json`, omit `hooks.json`. |
| **Copilot (CLI / VS Code)** | Copilot CLI: `COPILOT_HOME=<clean_dir>`, `--disable-builtin-mcps --no-custom-instructions --no-auto-update` (`COPILOT_AUTO_UPDATE=false`), `/memory off` (and omit `--enable-memory` in `-p`). VS Code: `chat.copilot.memory.enabled: false`, `chat.mcp.autostart: "never"`, `chat.useAgentsMdFile: false`, `chat.useClaudeMdFile: false`, Restricted Mode / Workspace Trust enforced. *(Purge existing cloud memories via GitHub UI if compromised.)* |
| **Kimi / Grok / Cross-Model** | **Kimi**: `kimi doctor`, `--skills-dir <empty>`, `KIMI_DISABLE_CRON=1`, `KIMI_CODE_WATCH=false`. **Grok Build**: `grok inspect`, `grok mcp doctor`, `--no-memory --no-plan --no-subagents`, `GROK_{CURSOR,CLAUDE}_*=0`, `GROK_DISABLE_AUTOUPDATER=1`. **OpenCode V2**: `--standalone`, `OPENCODE_DB=:memory:`, `OPENCODE_DISABLE_PROJECT_CONFIG=1`. **Cursor**: `CURSOR_CONFIG_DIR=<clean>`, `--sandbox`. **Devin CLI**: `--config <clean>`, `--sandbox`. **Cline**: `cline doctor`, `--auto-approve false`, `--config <clean>`. **Goose**: `GOOSE_PATH_ROOT=<clean>`, `goose run --no-session`. **Aider**: `--config <clean>`, `--no-check-update --no-restore-chat-history`. |

### 7.2 Dual Operating Modes

1. **Ephemeral Non-Destructive Boot (`agent-env-run --failsafe <harness>`)**: Spins up an isolated `0700` runtime root (`HOME` / `XDG_CONFIG_HOME` / `CODEX_HOME` / `CLAUDE_CONFIG_DIR` / `GEMINI_CLI_HOME` / `COPILOT_HOME` / `ANTIGRAVITY_APP_DATA_DIR` / `KIMI_CODE_HOME` / `GROK_HOME` / `OPENCODE_TEST_HOME` / `GOOSE_PATH_ROOT`) for incident triage and forensics without touching or destroying live corrupted evidence.
2. **Persistent Safe-Mode Switch (`agentcfg failsafe --apply` / `--restore`)**: Snapshots live configs and memory into `~/.local/state/agentcfg/snapshots/<UTC-ts>/`, atomically swaps deployed targets to `canonical/profiles/failsafe/`, and cleanly restores after remediation.

---

## 8. Atomic Deployment, Integrity Verification & Cryptographic Provenance

- **Crash-safe atomic replacement**:
  1. Verify every parent path component via `lstat()` (`safe_target` pattern) to prevent symlink traversal escapes.
  2. Stage rendered bytes using `tempfile.NamedTemporaryFile(dir=target.parent, prefix=".agentcfg.", suffix=".tmp", delete=False)` **on the same filesystem as the target** (preventing `EXDEV` and `/tmp` symlink races).
  3. Call `flush()` + `os.fsync(fd)`.
  4. Set strict permissions via `os.fchmod(fd, mode)` (`0400`/`0444` declarative, `0600` patched, `0500`/`0700` wrappers).
  5. Replace atomically via `os.replace(tmp, target)`—which succeeds even when overwriting `0444` files inside a user-writable directory, eliminating `chmod +w` race windows and `chattr +i` auto-updater breakage.
  6. `os.fsync` the parent directory file descriptor.
  7. When writing repo-local `.agents/` outputs, append exclusions to `.git/info/exclude` rather than `.gitignore` (preserving Antigravity 2.0 visibility).
- **Integrity manifest & recovery (`verify` / `diff` / `restore`)**:
  - `~/.local/state/agentcfg/deployed-manifest.json` (`0600`) tracks target paths, SHA-256 hashes (full file or managed JSON/TOML subtree), file modes, `git rev-parse HEAD`, strategy, and timestamp.
  - `agentcfg verify` exits non-zero on any drift or mode regression; `agentcfg diff` renders into memory/`0700` staging and displays unified diffs; `agentcfg restore` snapshots current state first and atomically restores the last verified commit/manifest.
- **Signed Git provenance & offline immutable backups**:
  - Repository-local/user SSH signing (`git 2.43.0` + `ssh-keygen -t ed25519`): `gpg.format ssh`, `commit.gpgsign true`, `tag.gpgsign true`; `agentcfg apply` verifies `git verify-commit HEAD` before deploying.
  - Offline recovery bundles combine `git bundle create ... --all`, deterministic `git archive ... | gzip -n`, `sha256sum`, and optional `age -R` encryption.

---

## 9. Update-Change, Config-Migration & Schema-Evolution Monitoring

### 9.1 Local Footprint & Schema Monitor (`agentcfg watch-updates` / `agentcfg doctor`)

Maintains `~/.local/state/agentcfg/host-footprint.json` (`0600`), triggered both as a pre-flight gate inside `agentcfg apply --safe` and on a periodic `systemd --user` timer (`agentcfg-watch.timer`):
1. **Binary & Bundle Fingerprints**: Tracks versions and SHA-256 digests of `agy`, `claude`, `codex`, `gemini`, `copilot`, `gh`, `kimi`, `grok`, `opencode`, `cline`, `goose`, plus `~/.gemini/antigravity-cli/builtin/{.checksum,.manifest}` and `cache/CHANGELOG.md`.
2. **Metadata-Only Directory & Permission Watch**: Scans path names, permissions, byte sizes, and SHA-256 of non-secret config files across `~/.gemini/`, `~/.claude/`, `~/.codex/`, `~/.copilot/`, `~/.kimi-code/`, `~/.grok/`, `~/.config/{opencode,devin,goose}/`, `~/.cursor/`, and `~/.cline/` (**explicitly excluding secret/auth files**). Flags new `.migrated` markers, `~/.grok/` `xai` vs `@vibe-kit/grok-cli` collisions, unexpected memory directories (`memories_v2/`, `annotations/`, `implicit/`, `projects/*/memory/`, `memory/`), and `umask` permission regressions (`0644`/`0755`).
3. **JSON/TOML/YAML Key-Shape Diffing**: Computes sorted key-path trees of managed configs (`settings.json`, `config.json`, `mcp_config.json`, `config.toml`, `config.yaml`), halting unattended `apply` on `NEW_KEY`, `DROPPED_KEY`, or `NEW_MEMORY_PATH` until reviewed.

### 9.2 Upstream Schema & Release Monitor (`wakeleyresearch/agentconfig`)

Scheduled GitHub Actions workflow (`.github/workflows/upstream-schema-watch.yml`, minimal `contents: read`, `issues: write`, `persist-credentials: false`, SHA-pinned actions) plus local `agentcfg upstream-check` diffs `policy/upstream-sources.json` targets against pinned snapshots in `policy/upstream-schemas/` (adopting `agent-sh/agnix`'s fail-closed fetch guard, randomized `GITHUB_OUTPUT` delimiters, and single deduplicated drift issue, plus `farion1231/cc-switch`'s `schema-version.yml` SQLite DB migration sentinel):
- **Claude Code**: `https://json.schemastore.org/claude-code-settings.json` + `code.claude.com` changelog/release notes.
- **Gemini CLI**: `https://raw.githubusercontent.com/google-gemini/gemini-cli/main/schemas/settings.schema.json` + `google-gemini/gemini-cli` releases.
- **Antigravity (`agy`)**: `https://antigravity.google/docs` changelog/CLI reference + local `agy changelog` / `builtin/.manifest` diff.
- **OpenAI Codex**: `https://developers.openai.com/codex/config-schema.json` + `openai/codex` releases (`state_5`/`memories_v2` DB schema & key aliases).
- **GitHub Copilot, Open Standards & Emerging Harnesses**: `github/copilot-cli`, VS Code Copilot, `agentskills.io`, `modelcontextprotocol.io`, `MoonshotAI/kimi-code`, xAI Grok, `anomalyco/opencode`, Cursor, Devin, Cline, Goose, and Aider release notes and schema diffs.

---

## 10. GitHub Ecosystem Reference & Empirical Anti-Patterns

Verification against live open-source tooling and public GitHub code search (`#26`, `#27`) surfaced transferable architecture patterns and concrete anti-patterns to block by design:

### 10.1 High-Signal Ecosystem Patterns

| Category | Reference Repositories | Concrete Pattern Incorporated |
| :--- | :--- | :--- |
| **Canonical Rendering & Lockfiles** | [`intellectronica/ruler`](https://github.com/intellectronica/ruler), [`dyoshikawa/rulesync`](https://github.com/dyoshikawa/rulesync), [`getsentry/dotagents`](https://github.com/getsentry/dotagents), [`vercel-labs/skills`](https://github.com/vercel-labs/skills), [`wshobson/agents`](https://github.com/wshobson/agents) | Normalize divergent MCP root keys (`mcp`, `mcpServers`, `servers`, `mcp_servers`, `context_servers`); pin lockfiles by SHA-256/commit (`agents.lock`, `skills-lock.json` v2); split >8 KB skills where constrained; check symlink containment (`packages/dotagents/src/symlinks/manager.ts`); use `.git/info/exclude` for generated `.agents/` files so Antigravity 2.0 still loads them. |
| **Pure-Python SoT & Safe Patching** | [`Bil0000/agents-fleet`](https://github.com/Bil0000/agents-fleet), [`farion1231/cc-switch`](https://github.com/farion1231/cc-switch), [`shunk031/dotfiles`](https://github.com/shunk031/dotfiles) | Pure Python stdlib SoT; strict allowlist key patching (`lib/fleet_apply.py`, `home/dot_claude/modify_settings.json`) + `lstat()` parent checks; literal credential/header banning (`lib/fleet_mcp.py`); panic-safe rollback (`src-tauri/src/sync_utils.rs`); Antigravity config handling (`src-tauri/src/agy_config.rs`). |
| **Supply-Chain & Secret Hardening** | [`sebastienrousseau/dotfiles`](https://github.com/sebastienrousseau/dotfiles), [`trailofbits/claude-code-config`](https://github.com/trailofbits/claude-code-config), [`affaan-m/ECC`](https://github.com/affaan-m/ECC), [`andersonjoseph/jailed-agents`](https://github.com/andersonjoseph/jailed-agents) | Pre-build per-server MCP venvs (`uv pip install --require-hashes`, `npm ci --ignore-scripts`); `min-release-age=7` (`home/dot_npmrc`); `.sops.yaml`+`age` & `.gitleaks.toml`; explicit `Read(~/.ssh/**)`/`~/.config/gh/**` denies and `enableAllProjectMcpServers: false`; `bwrap` jails; SHA-pinned CI actions with `persist-credentials: false`. |
| **Schema Sentinels & Security Scanners** | [`agent-sh/agnix`](https://github.com/agent-sh/agnix), [`github/awesome-copilot`](https://github.com/github/awesome-copilot), [`Pantheon-Security/medusa`](https://github.com/Pantheon-Security/medusa), [`snyk/agent-scan`](https://github.com/snyk/agent-scan), [`cisco-ai-defense/skill-scanner`](https://github.com/cisco-ai-defense/skill-scanner), [`Dicklesworthstone/destructive_command_guard`](https://github.com/Dicklesworthstone/destructive_command_guard) | Automated schema/spec drift monitoring (`.github/workflows/spec-drift.yml`, `.github/workflows/schema-version.yml`), PR risk scanning (`pr-risk-scan.mjs`), pre-clone `.claude/` scanning, `history.jsonl` leak detection, and AST/YARA skill scanning. |

### 10.2 Verified Public-Repo Anti-Patterns Avoided

1. **Unpinned `npx -y` & copy-paste secret placeholders**: **15,584** public `.mcp.json` and **2,148** `mcp_config.json` files rely on floating `npx -y`, and popular templates embed `"YOUR_*_KEY_HERE"` placeholders directly in JSON (`agentconfig` enforces pre-built locked installs + `mcp-secret-exec`).
2. **Global project-MCP auto-trust**: **2,672** public `settings.json` files set `enableAllProjectMcpServers: true`, bypassing trust prompts and exposing **CVE-2025-59536** / **CVE-2026-21852** (`agentconfig` enforces `false`).
3. **Leaked auth & history files in dotfiles**: Public code search exposes **423** `auth.json` (`OPENAI_API_KEY`), **123** `oauth_creds.json` (`refresh_token`), **85** `.credentials.json` (`claudeAiOauth`), **5** `antigravity-oauth-token`, and **128** `.claude/history.jsonl` files (`agentconfig` enforces Tier-B/C exclusion + pre-commit/pre-apply secret gates).
4. **Silent typos, symlink traps & registry confusion**: Unvalidated parsers silently drop typos (`target` vs `targets`) or uppercase skill names; naive symlinks trigger `ELOOP` or fail Antigravity `1.5.8` plugin checks; `uvx --with-requirements` skips hash checks; and npm `mcp-server-git`/`mcp-server-sqlite` differ from official PyPI packages.

---

## 11. Open Design Decisions & Next Steps

Before implementing Phase 1–4 code in `wakeleyresearch/agentconfig`, confirm these five planning decisions:
1. **Primary Tier-B secret injection backend**: Use `age`/`sops` + kernel keyring / `gnome-keyring` (`secret-tool`), `systemd-creds`, or an external password CLI (`pass` / `op`) for `wrappers/mcp-secret-exec`? *(Note: `gpg` and `gnome-keyring-daemon` are preinstalled; `age` and `libsecret-tools` are in Ubuntu `apt`, while `sops` requires binary/Go installation.)*
2. **Pre-built MCP runtime policy strictness**: Enforce locked per-server build dirs (`uv pip install --require-hashes`, `npm ci --ignore-scripts`, `min-release-age=7`) for every STDIO MCP from day one, or allow an explicit break-glass local override?
3. **Canonical rules/skills metadata & Antigravity `.git/info/exclude` wiring**: Standardize `canonical/rules/` & `canonical/skills/` on `AGENTS.md` + `SKILL.md` + lightweight YAML/JSON sidecars (`ruler`/`rulesync` style) with automatic `.git/info/exclude` wiring for generated project `.agents/` directories?
4. **Default `bwrap` sandbox strictness**: Enforce `bwrap` (`0.9.0` installed) with private `$TMPDIR` + sanitized `/dev/shm` + `env -i` on all untrusted-repo and `failsafe` runs by default, or make `bwrap` opt-in for STDIO MCPs first?
5. **Fail-closed drift & collision gate**: Should `agentcfg apply` refuse targets whenever `watch-updates` detects schema drift or `~/.grok/` `vibe-kit` vs Grok Build path ambiguity (requiring explicit `--approve-drift` / `--grok-flavor xai|vibekit`)?
