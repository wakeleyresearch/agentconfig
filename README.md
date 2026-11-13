# agentconfig

> **Status: Implemented (Phases 1–4 Complete)** — The `agentconfig` Source-of-Truth engine ([`bin/agentcfg`](bin/agentcfg) + [`lib/`](lib/)), security policies ([`policy/`](policy/)), canonical catalogs and failsafe profiles ([`canonical/`](canonical/)), target definitions ([`targets/targets.json`](targets/targets.json)), environment and secret wrappers ([`wrappers/`](wrappers/)), host `systemd` watch timer ([`systemd/`](systemd/)), offline backup helper ([`bin/agentcfg-backup`](bin/agentcfg-backup)), and unit test suite ([`tests/`](tests/)) are implemented in this repository alongside the architecture specification in [`docs/CONCEPT.md`](docs/CONCEPT.md).

`agentconfig` is a security-hardened, Git-backed **Source-of-Truth (SoT)** architecture and CLI toolkit for managing AI coding agent configurations, rules, skills, MCP servers, hooks, `/tmp/` sandboxing, agent memory hygiene, and update-drift controls across heterogeneous CLI, IDE, and desktop harnesses.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Three-Tier Source-of-Truth Architecture](#three-tier-source-of-truth-architecture)
3. [Supported Agents & Harnesses Matrix](#supported-agents--harnesses-matrix)
4. [Core Subsystems](#core-subsystems)
5. [CLI & Wrapper Quickstart](#cli--wrapper-quickstart)
6. [GitHub Ecosystem Reference & Empirical Anti-Patterns](#github-ecosystem-reference--empirical-anti-patterns)
7. [Repository Layout](#repository-layout)
8. [Implementation Status & Roadmap](#implementation-status--roadmap)
9. [Further Reading](#further-reading)

---

## Problem Statement

Modern AI coding agents scatter instructions, MCP tool registries, hooks, permissions, caches, SQLite state, and persistent memory across dotfiles (`~/.gemini/`, `~/.claude/`, `~/.codex/`, `~/.copilot/`, `~/.kimi-code/`, `~/.grok/`, `~/.config/`), workspace folders (`.agents/`, `.github/`, `.vscode/`, `.mcp.json`), and shared `/tmp/`. On a multi-harness workstation (reference host: Ubuntu 24.04.5 LTS x86_64 with `umask 0002`), four systemic failure classes occur:

1. **Network Corruption & Crash Mid-Write**
   - Unverified remote installers (`curl | sh`), interrupted package downloads, or broken `npx`/`uvx` caches leave truncated tools and configs on disk.
   - Auto-updaters fail mid-flight (stale `updater/update.lock`, partial `~/.cache/antigravity/staging/`, mismatched `builtin/.checksum`), while `SIGKILL`/OOM events truncate JSON/TOML settings, strand `bwrap` synthetic mount targets, or leave corrupted SQLite WAL/SHM journals (`state_5.sqlite`, `conversation_summaries.db`, `session-store.db`).
   - Unresponsive remote HTTP MCP servers or synchronous hooks (for example, Antigravity `hooks.json` defaults to 30-second synchronous blocking, whereas Codex `PreToolUse` timeouts/crashes can fail open) stall or subvert sessions while ad-hoc UI edits silently drift from Git.

2. **Malware, Pre-Trust RCE & Supply-Chain Risks**
   - **Untrusted repository configs**: Cloned repos can embed `.mcp.json`, `.vscode/mcp.json`, `.claude/settings.json`, `.gemini/settings.json`, `.codex/config.toml`, `.grok/hooks/*.json`, `.agents/hooks.json`, or `*_BASE_URL` overrides—creating pre-trust remote code execution and API-key exfiltration vectors (e.g., Claude Code pre-trust hook/MCP RCE **CVE-2025-59536** and pre-trust `ANTHROPIC_BASE_URL` key theft **CVE-2026-21852**).
   - **Unsandboxed extension hooks & mods**: Claude Code Mods (`hooks/register.js`) execute inside the host process without an OS sandbox and—unless gated by managed policy—can override user `deny`/`ask` rules.
   - **Floating `npx -y` / `uvx` "rug pulls", typosquatting & tool poisoning**: Unpinned invocations pull mutable upstream versions without confirmation (`uvx --with-requirements` does not enforce hashes; npm `mcp-server-git`/`mcp-server-sqlite` are third-party/placeholder packages compared to official PyPI servers); malicious servers swap tool descriptions (**tool poisoning**) or spoof tools (**tool shadowing**).
   - **Poisoned skills & plugins**: Community `SKILL.md` files, `AGENTS.md` instructions, or plugin bundles hide invisible Unicode directives (`U+200B..U+200F`, `U+202A..U+202E`, Tags `U+E0000..U+E007F`) or malicious `hooks.json` / `scripts/*.sh` payloads.
   - **Plaintext credential exposure**: Under permissive `umask 0002`, config files and runtime logs/DBs default to world-readable `0644`/`0755`, exposing inline tokens, unencrypted logs (Claude Desktop `audit.jsonl`, `plugin-mcp-auth/.credentials.json` on Linux/Windows, Codex `$CODEX_HOME/auth.json` when `file`-backed), or leaking parent environment secrets into child stdio processes.

3. **`/tmp/` Exposure & Agent Memory Poisoning**
   - **Shared `1777` `/tmp/` and `/var/tmp/`**: Linux `fs.protected_symlinks=1` and `fs.protected_regular=2` block *cross-UID* attacks, not *same-UID* races from a compromised tool, MCP server, or `postinstall` script. Combined with `umask 0002`, temp scratchpads, bash captures, and logs leak locally; crashed runs linger up to 30 days in `/tmp` (and indefinitely in `/var/tmp` where cleanup is commented out by default). Conversely, blindly redirecting `$TMPDIR` to `/run/user/$UID` (`191 MiB` `tmpfs` on the reference host) triggers instant `ENOSPC` on AppImages and package unpacks.
   - **Persistent memory poisoning & data hazards**: Prompt injections or malformed entries written into long-lived memory stores—such as `~/.gemini/GEMINI.md` (`## Gemini Added Memories`), Antigravity `conversation_summaries.db*` / `implicit/*.pb` / `annotations/*.pbtxt`, Claude Code `~/.claude/projects/*/memory/MEMORY.md`, Codex `$CODEX_HOME/{memories,memories_v2}/` & unencrypted `skysight` Computer History logs, Goose `~/.config/goose/memory/`, or server-side Copilot/ChatGPT/Claude.ai Memory—persist across sessions. Meanwhile, Claude Desktop's beta `skillScanningEnabled` rewrites user text skills in place with zero backup.

4. **Schema Drift, Path Collisions & Breaking Changes on Updates**
   - Harnesses break or silently alter semantics across releases:
     - **Codex CLI**: `v0.134.0+` dropped `[profiles.*]` / `profile =` (profiles moved to standalone `$CODEX_HOME/<name>.config.toml`); `v0.149.0+` retired `approval_policy = "untrusted"` (crashes on startup).
     - **Antigravity (`agy`)**: `1.5.7` changed default Agent Mode to `Auto`, `1.5.8` fixed UTF-8 BOM config dropping, `1.x -> 2.0` migrated IDE paths, `plugin.json` silently drops unknown keys and rejects out-of-plugin symlinks, and Antigravity 2.0 skips repo `.agents/` files listed in `.gitignore` (requiring `.git/info/exclude`).
     - **Copilot & VS Code**: Copilot CLI superseded `config.json` user settings with `settings.json`, drops unsupported external `mcp-config.json` keys (e.g. `"disabled": true`), and prerelease binaries can re-exec *before* parsing `settings.json`; VS Code deprecated `.chatmode.md` -> `.agent.md` and scheduled legacy Local harness removal for February 2027.
     - **Emerging harnesses**: OpenCode V2 changed `external_directory` default from `ask` to `allow` and breaks V1 plugins; Cursor 2.1 removed automated Memories; Devin CLI v3000.3 split `mcp_config.json` out of `config.json`; xAI Grok Build collides on `~/.grok/` / `.grok/` with unofficial `@vibe-kit/grok-cli`.

---

## Three-Tier Source-of-Truth Architecture

`agentconfig` eliminates config drift, accidental secret commits, and runtime contamination by enforcing a strict three-tier boundary:

```text
+-------------------------------------------------------------------------+
| Tier A: Canonical Declarative Source-of-Truth (Git-tracked, SSH-signed) |
|   canonical/{rules,skills,hooks,mcp-registry.json,harnesses,profiles}   |
|   policy/{security-policy.json,manifests.lock.json,upstream-*.json}     |
|   targets/targets.json   wrappers/   bin/agentcfg                       |
+------------------------------------+------------------------------------+
                                     |
          validate + secret-scan + lock-check + atomic render (flock)
                                     |
                                     v
+-------------------------------------------------------------------------+
| Tier B: Secrets & Auth (NEVER committed in plaintext)                   |
|   - OS Keyring (gnome-keyring / secret-tool)                            |
|   - Optional SOPS + age encrypted store (secrets/secrets.enc.yaml)      |
|   - Native OAuth files kept out-of-band at 0600 in 0700 dirs            |
|   - Injected at runtime via env -i whitelist (wrappers/mcp-secret-exec) |
+------------------------------------+------------------------------------+
                                     |
+-------------------------------------------------------------------------+
| Tier C: Mutable Runtime State & /tmp/ (Excluded from Git & SoT)         |
|   - Session SQLite DBs (-wal/-shm), transcripts, logs, crashes, locks   |
|   - App state markers (config.json, trustedFolders.json, .migrated)     |
|   - Two-tier private 0700 temp dirs:                                    |
|       1. $XDG_RUNTIME_DIR/agent-runtime (small volatile IPC/locks)      |
|       2. ~/.local/tmp & ~/.local/tmp/claude (large scratch/AppImages)   |
+-------------------------------------------------------------------------+
```

- **Rendering over naive symlinks**: Cross-harness symlink collisions (`ELOOP` / duplicate loading between `~/.agents/skills` and `<agent>/skills`), Antigravity `1.5.8` rejecting out-of-plugin symlinks, Antigravity 2.0 skipping `.gitignore`-listed `.agents/` dirs, and `bwrap`/AppImage mount boundaries make deterministic per-harness rendering (`ro` + `.git/info/exclude` for generated project dirs) far safer than naive symlinks.
- **Optimization for mixed files**: Harnesses that mix declarative rules/MCPs with mutable runtime state use either **`plugin-bundle`** isolation (e.g., rendering shared Antigravity rules, skills, hooks, and MCP into `~/.gemini/config/plugins/agentconfig-core/`, leaving `~/.gemini/config/config.json` untouched) or **`patch-managed-keys`** with strict key allowlists and `lstat()` parent checks (e.g., `~/.claude.json`, `~/.gemini/antigravity-cli/settings.json`).

---

## Supported Agents & Harnesses Matrix

All target model families, harnesses, and cross-agent open standards are verified (`#7`, `#8`, `#15`, `#16`, `#24`, `#25`, `#26`, `#27`):

| Harness / Model Family | Global Config Root | Key Declarative Files | Secrets / Auth (Never Git) | Memory & `/tmp/` Surfaces | Built-in Failsafe / Clean-Boot Hooks |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Antigravity** (`agy` 1.5.8, App 2.0, IDE, Python SDK) | `~/.gemini/config/` & `~/.gemini/antigravity-cli/` (`~/.gemini/antigravity/`, `~/.gemini/antigravity-ide/`) | `config/{mcp_config.json,skills/,agents/,rules/,plugins/,sidecars/,skills.json,plugins.json,hooks.json}`, `antigravity-cli/settings.json`, repo `.agents/` (exclude via `.git/info/exclude`) | `antigravity-oauth-token` (`0600`), `ANTIGRAVITY_CSRF_TOKEN` | `GEMINI.md`/`AGENTS.md` (`/learn`, 24 KB/file, 20k token budget), `conversation_summaries.db*`, `jetbox_summaries_proto.pb`, `implicit/*.pb`, `annotations/*.pbtxt`; `/tmp/lsrpc.sh`, `/tmp/.mount_*`, Chromium singletons | `--settings`, `--mode plan --sandbox`, `--disable-slash-commands`, `ANTIGRAVITY_APP_DATA_DIR`, `agy acp --include-default-customizations=false`, `agy plugin validate --strict` |
| **Google Gemini CLI** (`@google/gemini-cli`) | `~/.gemini/` (`GEMINI_CLI_HOME`), `/etc/gemini-cli/` | `settings.json`, `GEMINI.md`, `commands/**/*.toml`, `skills/`, `agents/*.md`, `extensions/*/gemini-extension.json`, `policies/*.toml`, `sandbox.Dockerfile` | `oauth_creds.json`, `google_accounts.json`, `.env`, OS keychain (`sensitive: true`) | Hierarchical `GEMINI.md` + `save_memory` (`## Gemini Added Memories`) + `experimental.autoMemory` `.inbox/*.patch`; `~/.gemini/tmp/<hash>/`, `~/.gemini/history/<hash>/` (shadow git) | `GEMINI_CLI_HOME`, `--approval-mode plan --sandbox`, `--allowed-mcp-server-names`, `trustedFolders.json`, `experimental.autoMemory: false` + Policy Engine deny `save_memory`, `/restore` |
| **GitHub Copilot** (CLI, `github/app` Desktop, VS Code, JetBrains, Coding Agent) | `~/.copilot/` (`COPILOT_HOME`), `~/.config/Code/User/`, `~/.config/github-copilot/intellij/` | `~/.copilot/{settings.json,mcp-config.json,lsp-config.json,providers.json,copilot-instructions.md,skills/,agents/}`, `.vscode/mcp.json` (`servers`), `.github/{copilot-instructions.md,instructions/,agents/*.agent.md,prompts/,hooks/*.json,github-app.yml}` | `~/.config/gh/hosts.yml`, `COPILOT_GITHUB_TOKEN` / `GH_TOKEN`, BYOK keys in `providers.json`, inline `Authorization` headers | Server-side **Copilot Memory** (code citations + JIT check + 28d TTL), `session-state/`, `session-store.db`; `/tmp/.mount_*`, `/tmp/vscode-*.sock`, containerized `/tmp/` `events.jsonl` | `COPILOT_HOME`, `--disable-builtin-mcps`, `--disable-mcp-server`, `--no-custom-instructions`, `COPILOT_AUTO_UPDATE=false`, `/memory off`, VS Code `chat.copilot.memory.enabled: false` + GitHub UI purge |
| **Anthropic Claude** (Claude Code CLI/IDE, Claude Desktop 1P/3P, Cowork) | `~/.claude/` (`CLAUDE_CONFIG_DIR`), `~/.claude.json`, `/etc/claude-code/`, `~/.config/Claude{,-3p}/` | `settings.json`, `managed-settings.json`, `CLAUDE.md`, `.claude/{rules/*.md,skills/,agents/,settings.json}`, `.mcp.json`, `claude_desktop_config.json`, `.claude-plugin/` | `~/.claude/.credentials.json`, OS keychain, Desktop `ccd-session-secrets/`, `plugin-mcp-auth/.credentials.json` (plaintext Win/Linux) | `~/.claude/projects/*/memory/MEMORY.md`, subagent `memory:`, Desktop `spaces/<id>/memory/` & `audit.jsonl`; `$CLAUDE_CODE_TMPDIR/claude-<uid>/`, sandbox inherits host `$TMPDIR` | **`claude --safe-mode`** (`CLAUDE_CODE_SAFE_MODE=1`), `claude --restricted`, `claude --bare` (`CLAUDE_CODE_SIMPLE=1`), `--strict-mcp-config`, `--setting-sources`, `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`, `claude doctor`, `claude purge` |
| **OpenAI** (Codex CLI/App/IDE, ChatGPT Desktop/Web) | `~/.codex/` (`CODEX_HOME`, `CODEX_SQLITE_HOME`), `/etc/codex/` | `config.toml`, `<name>.config.toml` (`--profile <name>`; `[profiles.*]` dropped `v0.134.0+`), `requirements.toml`, `AGENTS.md`/`AGENTS.override.md`, `hooks.json`, `rules/*.rules`, `agents/*.toml` | `$CODEX_HOME/auth.json` (plaintext if `file`), MCP OAuth tokens, `$CODEX_HOME/memories/extensions/skysight/` unencrypted logs | `$CODEX_HOME/{memories,memories_v2}/` (`MEMORY.md`, `memory_summary.md`), SQLite (`state_5`, `logs_2`, `goals_1`, `memories_1`, `memories_v2_1`, `queue_1`, `thread_history_1`); `hook_outputs/`, `bwrap` `/tmp`; ChatGPT cloud memory | **`codex --ask-for-approval on-request --sandbox read-only`** (`untrusted` retired `v0.149.0+`), standalone `$CODEX_HOME/failsafe.config.toml` via `--profile failsafe`, `CODEX_HOME=$(mktemp -d)`, `--strict-config`, `--no-daemon`, `[features].memories = false`, `codex debug clear-memories`, `codex doctor` |
| **Moonshot Kimi** (`kimi-code`) | `~/.kimi-code/` (`KIMI_CODE_HOME`), `~/.agents/` (via `$HOME`) | `config.toml`, `tui.toml`, `SYSTEM.md`, `AGENTS.md`, `mcp.json`, `skills/`, `agents/`, project `.kimi-code/{local.toml,mcp.json,AGENTS.md,skills/}` | `credentials/*.json`, `credentials/mcp/*.json` (`0600`), `api_key_env` mapping | Session `contextMemory` + `wire.jsonl` + `AGENTS.md`/`SYSTEM.md`; adjacent binary `.staging/` updates & `updates/install.lock` | `kimi doctor [config\|tui]`, `--skills-dir`, `--agent-file`, `KIMI_DISABLE_CRON=1`, `KIMI_CODE_WATCH=false`, `CONFIG_PERSIST_BLOCKED`, `/reload` |
| **xAI Grok** (Grok Build vs `@vibe-kit/grok-cli`) | `$GROK_HOME` (`~/.grok/` — collides w/ `@vibe-kit/grok-cli`!), `/etc/grok/` | `config.toml`, `managed_config.toml`, `requirements.toml`, `sandbox.toml`, `trusted_folders.toml`, `hooks/*.json`, `skills/`, `AGENTS.md` | `auth.json`, `mcp_credentials.json` | Opt-in memory (`GROK_MEMORY=0` default, `--experimental-memory`), `sessions/`, `bwrap` (`sandbox.toml`) | `grok inspect`, `grok mcp doctor`, `grok plugin validate`, `--no-memory`, `--no-plan`, `GROK_{CURSOR,CLAUDE}_*=0`, `GROK_DISABLE_AUTOUPDATER=1`, `grok memory clear --all` |
| **Cross-Model & IDE Harnesses** (OpenCode V2, Cursor, Devin, Cline, Goose, Aider) | XDG (`~/.config/opencode/`, `~/.config/devin/`, `~/.config/goose/`), `~/.cursor/`, `~/.cline/`, `~/.aider.conf.yml` | `AGENTS.md` (all except Aider natively), `~/.agents/skills/*/SKILL.md`, `agent-plugins.org` `plugin.json`; per-harness `opencode.jsonc`, `.cursor/rules/*.mdc`, `mcp_config.json`, `cline_mcp_settings.json`, `config.yaml`, `.aider.conf.yml` | Goose `secrets.yaml`, Cline `providers.json`, inline headers | OpenCode SQLite (`OPENCODE_DB`), Cursor Memories **removed in 2.1**, Cline `memory-bank/*.md`, Goose `~/.config/goose/memory/`, Aider `.aider.{chat,input}.history`; `/tmp/opencode` | OpenCode `--standalone` / `OPENCODE_DB=:memory:`, Cursor `CURSOR_CONFIG_DIR` / `--sandbox`, Devin `--config` / `/rm-session`, Cline `cline doctor [fix\|log]`, Goose `goose run --no-session` / `GOOSE_PATH_ROOT`, Aider `--no-check-update` / `--no-restore-chat-history` |

---

## Core Subsystems

### 1. `agentcfg` Safe Applicator & Integrity Engine
A Python 3.12 stdlib engine (`bin/agentcfg` + `lib/*.py`, zero PyPI/third-party Python dependencies, with optional host GIR `gi.repository.Secret` fallback alongside `secret-tool`/`sops`) enforcing deterministic, verified deployments:
- **Pre-commit & pre-apply validation (`agentcfg validate`)**: Parses JSON (`json`), TOML (`tomllib`), and YAML frontmatter; enforces Antigravity's `24,000`-byte rule cap, Kimi's `32 KiB` `AGENTS.md` warning threshold, and `agy plugin validate --strict`; enforces `policy/security-policy.json` (bans floating `npx -y`/`uvx`/`@latest`, plain `http://` remote MCPs, legacy `/sse` in Antigravity/Goose, unauthorized `*_BASE_URL` overrides, literal credential keys/headers, and invisible Unicode).
- **Pre-built locked MCP runtimes**: Enforces locked per-server install prefixes (`~/.local/share/agentconfig/mcp-venvs/<srv>/` via `uv pip install --require-hashes` / `npm ci --ignore-scripts` with `min-release-age=7`) or digest-pinned OCI images (`image@sha256:...`), plus `tools/list` SHA-256 pinning in `policy/manifests.lock.json`.
- **Secret scanning**: Runs `gitleaks` plus a built-in regex (`sk-`, `ghp_`, `AIza`, `AKIA`, `AGE-SECRET-KEY-`, PEM headers, `Bearer `) and Shannon entropy fallback so scanning never silently degrades.
- **Atomic deployment (`agentcfg apply --safe`)**:
  1. Acquires an exclusive `flock` on `${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/agentcfg.lock`.
  2. Checks `agentcfg watch-updates --check` (halting on unexpected binary/schema drift or `~/.grok/` `vibe-kit` vs Grok Build path ambiguity).
  3. Runs validation, secret scanning, and `cleanse --dry-run`.
  4. Snapshots existing targets and memory, validates parent directory safety via `lstat()`, and stages each rendered output via `tempfile.NamedTemporaryFile` **in the target's parent directory** (same filesystem—eliminating `EXDEV` and `/tmp` races), followed by `flush()`, `os.fsync(fd)`, `os.fchmod(fd, mode)` (`0400`/`0444` for declarative targets, `0600` for patched configs, `0500`/`0700` for wrappers), atomic `os.replace`, and parent directory `fsync`.
  5. Writes generated project `.agents/` paths into `.git/info/exclude` (never `.gitignore`, ensuring Antigravity 2.0 loads them without dirtying `git status`).
- **Manifest, diff, audit & provenance**:
  - `agentcfg verify` & `agentcfg diff`: Validates live SHA-256 checksums and file permissions against `~/.local/state/agentcfg/deployed-manifest.json`.
  - `agentcfg audit-repo <path>`: Scans untrusted repositories before opening for `.mcp.json`, `.vscode/mcp.json`, `.claude/`, `.codex/`, `.grok/`, `.agents/{hooks,plugins,skills}.json`, and `*_BASE_URL` overrides.
  - **Signed Git provenance & offline backup**: SSH-signed Git commits/tags (`gpg.format ssh`) plus reproducible offline `git bundle` + `tar.gz` + `sha256sum` (+ optional `age` encryption).

### 2. `agentcfg cleanse` & Quarantine
Remediates corrupted state into a timestamped, non-executable `0700` quarantine directory (`~/.local/state/agentcfg/quarantine/<UTC-ts>/`) with `chmod 0400`/`0600` and a `quarantine-manifest.json` audit log before restoring clean SoT files:
- **Explicit Scopes (`--scope config|memory|runtime|all`, default `config`)**:
  - `config`: Invalid JSON/TOML/YAML, schema violations, undeclared MCP servers or `.agents/hooks.json`, banned unpinned `npx -y`/`uvx`, broken symlinks, and unsafe permissions (`0777`, world-readable `0644`/`0755` on sensitive files).
  - `runtime`: Orphaned `.tmp` files, stale locks (checked for liveness via `flock -n` / `fuser` / `/proc/<pid>` first), corrupt SQLite DBs or stranded WAL/SHM files (checked read-only via Python `sqlite3` `PRAGMA quick_check`, matching Codex's `BackupAndRebuild` pattern across `state_5.sqlite`, `logs_2.sqlite`, `conversation_summaries.db`, `session-store.db`, `sessions.db`), and stale staging caches.
  - `memory`: Poisoned or malformed local memory entries across `~/.gemini/GEMINI.md`, Claude `~/.claude/projects/*/memory/`, Codex `$CODEX_HOME/{memories,memories_v2}/` (`memories_1.sqlite`, `memories_v2_1.sqlite`, `MEMORY.md`) & `skysight` logs, Goose `~/.config/goose/memory/`, and Antigravity `annotations/`/`implicit/`/`conversation_summaries.db*`. Integrates native reset primitives (`codex debug clear-memories`, `claude purge`, `grok memory clear --all`) and reminds users to purge server-side memory (Copilot / ChatGPT / Claude.ai) via web UI.
- **Hard Auth-Preservation Invariant**: Credential and OAuth files (`antigravity-oauth-token`, `~/.config/gh/hosts.yml`, `~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, `~/.kimi-code/credentials/`, `~/.grok/auth.json`, `~/.local/share/keyrings/`) are **never** quarantined or wiped—even under `--scope all`—unless `--include-auth --confirm-wipe-auth` is explicitly passed interactively.

### 3. Built-in `failsafe` Mode
`canonical/profiles/failsafe/` + `agentcfg failsafe` + `wrappers/agent-env-run --failsafe` provide a minimal zero-trust recovery baseline per harness:
- **Zero external/remote MCP servers**, **hooks, unsandboxed mods & third-party plugins disabled**, **strict ask/read-only permissions**, **auto-memory disabled/bypassed**, **minimal verified rules (`<=2 KB`, no `@` file includes)**, and an **isolated `0700` `$TMPDIR` with `umask 0077` and `env -i`**.
- **Verified per-harness failsafe primitives**:
  - **Claude Code**: **`claude --safe-mode`** (`CLAUDE_CODE_SAFE_MODE=1`, primary built-in failsafe disabling all user/project customizations, mods, MCPs, and auto-memory while keeping auth/model/managed policy), plus `claude --restricted` (`CLAUDE_CODE_RESTRICTED=1`), `claude --bare` (`CLAUDE_CODE_SIMPLE=1`), `--strict-mcp-config --mcp-config /dev/null`, and `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`.
  - **Codex CLI**: **`codex --ask-for-approval on-request --sandbox read-only`** (`untrusted` retired in `v0.149.0+`, crashes on startup) + standalone **`$CODEX_HOME/failsafe.config.toml`** invoked via `--profile failsafe` (with top-level keys, since `[profiles.*]` was dropped in `v0.134.0+`), `--strict-config`, `--no-daemon`, `[features].memories = false`, `memories.disable_on_external_context = true`, or isolated `CODEX_HOME=$(mktemp -d) CODEX_SQLITE_HOME=<same>`.
  - **Gemini CLI / Antigravity / Copilot / Emerging**: `GEMINI_CLI_HOME` + `--approval-mode plan --sandbox` + Policy Engine deny `save_memory`; `agy --mode plan --sandbox --disable-slash-commands --settings` / `ANTIGRAVITY_APP_DATA_DIR`; Copilot `COPILOT_HOME` + `--disable-builtin-mcps --no-custom-instructions --no-auto-update` + `/memory off` + `chat.copilot.memory.enabled: false`; Kimi `kimi doctor` + `KIMI_DISABLE_CRON=1`; Grok `--no-memory --no-plan` + `GROK_{CURSOR,CLAUDE}_*=0`; OpenCode `--standalone` + `OPENCODE_DB=:memory:`; Cline `cline doctor`; Goose `goose run --no-session`.
- **Two operating modes**:
  1. **Ephemeral Non-Destructive Boot (`agent-env-run --failsafe <harness>`)**: Boots the harness inside an isolated `0700` runtime root for incident triage without overwriting live evidence.
  2. **Persistent Safe-Mode Switch (`agentcfg failsafe --apply` / `--restore`)**: Snapshots live configs and memory, atomically swaps deployed targets to the failsafe profile, and restores cleanly post-remediation.

### 4. `/tmp/` & Agent Memory Hardening
- **Two-tier private `0700` temp architecture**:
  - **Tier 1 (Small volatile IPC, sockets & locks)**: `$XDG_RUNTIME_DIR/agent-runtime` (`/run/user/$UID/agent-runtime`, `0700`, `tmpfs`, auto-cleared on logout, bounded at `191 MiB` on reference host).
  - **Tier 2 (Large scratch, AppImage unpacks & tool sandboxes)**: `~/.local/tmp` (`0700`, ext4) and `~/.local/tmp/claude` (`0700`), exported with `umask 0077`, `TMPDIR`/`TEMP`/`TMP`, and `CLAUDE_CODE_TMPDIR`, plus `systemd-tmpfiles --user` age-out rules (`~/.config/user-tmpfiles.d/agent-tmp.conf`) and per-session `mktemp -d` exit traps.
- **Host & existing directory tightening**: Fixes permissive `0755`/`0644` directories/DBs/logs in `~/.gemini/` and `~/.cache/antigravity/` to `0700`/`0600`; recommends `nosuid,nodev,noexec` on `/dev/shm` and `/var/tmp` (and `/tmp` once wrappers direct `$TMPDIR` to `~/.local/tmp`).
- **Memory hygiene**: Scans memory stores for invisible Unicode, exfiltration directives (`curl`, `wget`, `.ssh`, token paths), and anomalous growth; captures pre-cleanse memory snapshots (`0600`); selectively excises poisoned sections; and enforces opt-out flags against cloud/local memory capture.

### 5. Local & Upstream Update-Change Monitor
- **Local monitor (`agentcfg watch-updates` / `agentcfg doctor` / `systemd --user` timer)**: Maintains `~/.local/state/agentcfg/host-footprint.json` (`0600`) tracking binary versions & SHA-256 hashes (`agy`, `claude`, `codex`, `gemini`, `copilot`, `gh`, `kimi`, `grok`, `opencode`, `cline`, `goose`), Antigravity `builtin/{.checksum,.manifest}`, metadata-only config/permission/directory state (skipping secrets), and sorted JSON/TOML key-shape diffs. Halts unattended `agentcfg apply` on `NEW_KEY`, `DROPPED_KEY`, or `NEW_MEMORY_PATH`.
- **Upstream monitor (`.github/workflows/upstream-schema-watch.yml` + `agentcfg upstream-check`)**: Periodically checks pinned official JSON schemas and release feeds (`policy/upstream-sources.json`) against local snapshots (`policy/upstream-schemas/`), following fail-closed baseline-diffing patterns (`agent-sh/agnix` `spec-drift.yml`) and opening a deduplicated labeled GitHub Issue/draft PR on breaking deltas before renderers are updated.

---

## CLI & Wrapper Quickstart

All `agentcfg` commands accept optional global overrides before the subcommand:

```text
python3 bin/agentcfg [--repo REPO] [--home HOME] [--state-dir STATE_DIR] \
  [--project PROJECT] [--grok-flavor {xai,vibekit}] [--require-signed] [--json] <subcommand>
```

### Core `agentcfg` Commands

```bash
# 1. Inspect host tooling, permissions, systemd timers, and manifest state
python3 bin/agentcfg doctor

# 2. Validate policy rules, schemas, byte budgets, and secret scans
python3 bin/agentcfg validate [--staged] [--skip-agy] [--no-check-grok]

# 3. Preview unified diffs against live targets (or against canonical failsafe baseline)
python3 bin/agentcfg diff [--failsafe]

# 4. Atomically render and deploy targets (optionally quarantine corrupt state first)
python3 bin/agentcfg apply [--safe] [--approve-drift]

# 5. Verify live targets against ~/.local/state/agentcfg/deployed-manifest.json
python3 bin/agentcfg verify

# 6. Restore targets from a recorded snapshot under state_dir/snapshots/
python3 bin/agentcfg restore [--snapshot SNAPSHOT]

# 7. Quarantine corrupt configs, stale runtime locks/DBs/tmps, or poisoned memory
python3 bin/agentcfg cleanse [--scope {config,memory,runtime,all}] [--dry-run] \
  [--auto-quarantine] [--include-auth] [--confirm-wipe-auth] \
  [--no-restore-targets] [--native-wipe]

# 8. Switch live targets to/from failsafe or launch an isolated ephemeral failsafe session
python3 bin/agentcfg failsafe (--apply | --restore | --exec EXEC_HARNESS) [harness_args...]

# 9. Pre-trust read-only audit of an unfamiliar repository before opening an agent
python3 bin/agentcfg audit-repo [--strict] <path>

# 10. Local binary, config key-shape, and memory drift baseline checks
python3 bin/agentcfg watch-updates [--check] [--update-baseline] [--fast]

# 11. Compare pinned upstream schema snapshots (or fetch live HTTPS specs with --fetch)
python3 bin/agentcfg upstream-check [--fetch] [--update-baseline]
```

### Runtime Wrappers, Offline Backup & Tests

```bash
# Run any harness with umask 0077, two-tier 0700 $TMPDIR / $XDG_RUNTIME_DIR,
# optional failsafe env, or bwrap sandboxing for untrusted repos:
wrappers/agent-env-run [--home <dir>] [--repo <dir>] [--failsafe] \
  [--untrusted] [--require-bwrap] [--rw-cwd] -- <command> [args...]

# Inject only allowlisted secrets from gnome-keyring / sops+age under env -i:
wrappers/mcp-secret-exec [--secret-ref ENV_VAR=REF]... [--unshare-net] \
  [--require-bwrap] [--repo <dir>] -- <cmd> [args...]

# Create reproducible offline git bundle + deterministic tar.gz + SHA-256 (+ optional age encryption):
bin/agentcfg-backup [--repo <dir>] [--out-dir <dir>] [--age-recipient <age1...>]

# Run the unit & integration test suite:
python3 -m unittest discover -s tests -v
```

---

## GitHub Ecosystem Reference & Empirical Anti-Patterns

Ecosystem research (`#26`, verified in `#27`) benchmarked major open-source config managers, security baselines, and empirical failure modes across public GitHub repositories:

### Reference Implementations & Transferable Patterns

| Repository | Pattern / Capability Adopted by `agentconfig` |
| :--- | :--- |
| [`intellectronica/ruler`](https://github.com/intellectronica/ruler) | Canonical `.ruler/AGENTS.md` + `ruler.toml` normalizing 5 divergent MCP root keys (`mcp`, `mcpServers`, `servers`, `mcp_servers`, `context_servers`) across 25+ agents. |
| [`dyoshikawa/rulesync`](https://github.com/dyoshikawa/rulesync) | Multi-target generation (`doctor --strict`, `generate --check`), `.secretlintrc.json` + Trivy gating, and `.git/info/exclude` wiring so Antigravity 2.0 loads repo `.agents/` files without `.gitignore` rejection. |
| [`getsentry/dotagents`](https://github.com/getsentry/dotagents) & [`vercel-labs/skills`](https://github.com/vercel-labs/skills) | SHA-256 / commit-pinned lockfiles (`agents.lock`, `skills-lock.json` v2) and `lstat`/`realpath` symlink containment guards (`packages/dotagents/src/symlinks/manager.ts`). |
| [`farion1231/cc-switch`](https://github.com/farion1231/cc-switch) | Multi-harness support (`src-tauri/src/agy_config.rs`), panic-safe rollback (`src-tauri/src/sync_utils.rs`), and `.github/workflows/schema-version.yml` DB migration guard. |
| [`Bil0000/agents-fleet`](https://github.com/Bil0000/agents-fleet) | Pure Python stdlib SoT using key-allowlist patching (`lib/fleet_apply.py`), `lstat()` parent traversal checks, literal credential key/header banning (`lib/fleet_mcp.py`), and `systemd-creds`/Keychain injection. |
| [`agent-sh/agnix`](https://github.com/agent-sh/agnix) | 760-rule spec linter and `.github/workflows/spec-drift.yml` sentinel hashing upstream docs/schemas with fail-closed fetch guards and deduplicated drift issues. |
| [`wshobson/agents`](https://github.com/wshobson/agents) & [`affaan-m/ECC`](https://github.com/affaan-m/ECC) | Per-harness adapters (splitting >8 KB Codex skills), strict CI validation (`make validate STRICT=1`), pinned action SHAs, `persist-credentials: false`, and `npm ci --ignore-scripts`. |
| [`trailofbits/claude-code-config`](https://github.com/trailofbits/claude-code-config), [`shunk031/dotfiles`](https://github.com/shunk031/dotfiles) & [`sebastienrousseau/dotfiles`](https://github.com/sebastienrousseau/dotfiles) | Explicit `Read(~/.ssh/**)`/`~/.config/gh/**` denies, `enableAllProjectMcpServers: false`, chezmoi `home/dot_claude/modify_settings.json` patching, `min-release-age=7` (`home/dot_npmrc`), `.sops.yaml`+`age`, `.gitleaks.toml`, and pre-built locked MCP venvs (`MCP_POLICY.md`). |
| [`github/awesome-copilot`](https://github.com/github/awesome-copilot), [`andersonjoseph/jailed-agents`](https://github.com/andersonjoseph/jailed-agents) & Scanners | PR risk scanning (`pr-risk-scan.mjs`), `bwrap` zero-trust sandboxes, and pre-clone/skill vetting ([`Pantheon-Security/medusa`](https://github.com/Pantheon-Security/medusa), [`snyk/agent-scan`](https://github.com/snyk/agent-scan), [`cisco-ai-defense/skill-scanner`](https://github.com/cisco-ai-defense/skill-scanner), [`Dicklesworthstone/destructive_command_guard`](https://github.com/Dicklesworthstone/destructive_command_guard)). |

### Verified Public-Repo Anti-Patterns Avoided

- **Unpinned `npx -y` & copy-paste credential placeholders**: Verified **15,584** public `.mcp.json` and **2,148** `mcp_config.json` files use floating `npx -y` (`agentconfig` bans `npx -y`/`@latest`/`uvx` and injects tokens only via `mcp-secret-exec`).
- **Global project-MCP auto-trust**: **2,672** public `settings.json` files set `enableAllProjectMcpServers: true`, bypassing trust dialogs and exposing **CVE-2025-59536** / **CVE-2026-21852** (`agentconfig` enforces `false`).
- **Committed OAuth tokens & session histories**: Public GitHub search exposes **423** `auth.json` (`OPENAI_API_KEY`), **123** `oauth_creds.json` (`refresh_token`), **85** `.credentials.json` (`claudeAiOauth`), **5** `antigravity-oauth-token`, and **128** `.claude/history.jsonl` files (`agentconfig` enforces Tier-B exclusion + pre-commit/pre-apply secret gates).
- **Silent schema drops & path/registry traps**: Non-strict parsers silently drop misspelled keys (`target` vs `targets`) or uppercase skill names; naive symlinks trigger `ELOOP` or fail Antigravity `1.5.8` out-of-plugin checks; npm `mcp-server-git`/`mcp-server-sqlite` differ from official PyPI packages; and `~/.grok/` collides between xAI Grok Build and `@vibe-kit/grok-cli`.

---

## Repository Layout

```text
/home/omniboot/agentconfig/
├── README.md                                  # Project overview, CLI quickstart & roadmap (this file)
├── docs/
│   └── CONCEPT.md                             # Full architecture, per-harness spec & threat model
├── .gitignore                                 # Blocks *.dec.*, .age/, dist/, *.tmp, state/, backups/
├── .githooks/
│   └── pre-commit                             # Tracked secret, syntax, & policy gate
├── .github/
│   └── workflows/
│       └── upstream-schema-watch.yml          # Scheduled upstream schema & release diff monitor
├── bin/
│   ├── agentcfg                               # Python 3.12 CLI entrypoint (11 subcommands)
│   └── agentcfg-backup                        # Offline git bundle + tar.gz + sha256sum (+ age) helper
├── lib/                                       # Pure Python 3.12 stdlib engine (zero PyPI deps; optional GIR Secret)
│   ├── __init__.py
│   ├── audit.py                               # Untrusted repo scanner (audit-repo)
│   ├── cleanse.py                             # Config/memory/runtime quarantine & auth-preservation
│   ├── deployer.py                            # Atomic staging, flock, snapshots, manifest, verify/restore
│   ├── failsafe.py                            # Persistent failsafe swap & ephemeral session launcher
│   ├── formats.py                             # JSON/JSONC/TOML/YAML parsers & key-allowlist patchers
│   ├── monitor.py                             # Local footprint watch-updates & upstream-check
│   ├── paths.py                               # Repo/home/state path resolution & Grok flavor checks
│   ├── policy.py                              # Policy enforcement, budgets, invisible Unicode & secret fallback
│   └── render.py                              # Canonical -> per-harness target renderers
├── wrappers/
│   ├── agent-env-run                          # umask 0077, private 0700 $TMPDIR/$XDG_RUNTIME_DIR, --failsafe, bwrap
│   └── mcp-secret-exec                        # secret-tool / gi.Secret / sops+age -> env -i <VAR>=... <cmd>
├── systemd/
│   ├── agentcfg-watch.service                 # User oneshot service for agentcfg watch-updates --check
│   └── agentcfg-watch.timer                   # Periodic user systemd timer
├── policy/
│   ├── security-policy.json                   # Banned patterns (npx -y, http:// MCP), size caps, allowed *_BASE_URLs
│   ├── manifests.lock.json                    # Pinned MCP versions, package integrity hashes, tools/list SHA-256
│   ├── upstream-sources.json                  # Pinned upstream JSON schema & release-note URLs
│   └── upstream-schemas/                      # Pinned reference snapshots (agentskills, claude-code, codex, gemini-cli, opencode)
├── canonical/
│   ├── rules/
│   │   └── core.md                            # Shared canonical baseline rules
│   ├── skills/
│   │   └── agent-hygiene/
│   │       └── SKILL.md                       # Shared hygiene & pre-trust review skill
│   ├── hooks/
│   │   └── hooks.json                         # Canonical reviewed hook definitions
│   ├── mcp-registry.json                      # Canonical MCP catalog (uses secret_ref IDs, ZERO secrets)
│   ├── harnesses/                             # 13 per-harness specs (aider, antigravity, claude-code, cline, codex,
│   │                                          #   copilot, cursor, devin, gemini-cli, goose, grok, kimi-code, opencode)
│   └── profiles/
│       └── failsafe/                          # Minimal zero-trust failsafe baseline (rules.md + all 13 harnesses)
├── targets/
│   └── targets.json                           # Target paths, modes (0400/0444/0600), strategies (ro|patch-managed-keys|plugin-bundle)
├── secrets/
│   ├── .sops.yaml                             # age public-key recipients & encryption rules
│   └── README.md                              # Secret provisioning guide (secrets.enc.yaml optional locally)
└── tests/                                     # Isolated tempdir unittest suite (helpers.py + 5 test modules)
    ├── __init__.py
    ├── helpers.py
    ├── test_validate.py
    ├── test_rendering_and_schemas.py
    ├── test_deploy_apply_verify_restore.py
    ├── test_cleanse.py
    └── test_watch_audit_wrappers.py
```

---

## Implementation Status & Roadmap

- [x] **Phase 0 — Research & Architecture Concept (`main` docs)**:
  - Host baseline audit (`/home/omniboot`, `/tmp/`, `~/.gemini/`, `~/.cache/antigravity/`).
  - Verified deep-dive specs across all target models and harnesses: Google Antigravity (`agy` 1.5.8, App 2.0, IDE, SDK), Google Gemini CLI, GitHub Copilot (CLI, `github/app`, VS Code, JetBrains, Coding Agent), OpenAI (Codex CLI/App/IDE, ChatGPT Desktop/Web), Anthropic (Claude Code CLI/IDE, Claude Desktop 1P/3P, Cowork), Moonshot Kimi (`kimi-code`), xAI Grok (Grok Build & `@vibe-kit/grok-cli` collision), and cross-model harnesses (OpenCode V2, Cursor, Devin, Cline, Goose, Aider), plus open standards (`AGENTS.md`, `SKILL.md`, `agent-plugins.org`).
  - GitHub ecosystem benchmark & empirical anti-pattern audit (`#26`, `#27`).
  - Threat model, `/tmp/` & memory hardening design, `cleanse`, `failsafe`, and update-monitoring architecture ([`docs/CONCEPT.md`](docs/CONCEPT.md)).
- [x] **Phase 1 — Host Hardening & Repo Guardrails**:
  - Host tooling provisioned (`age` `v1.3.2`, `sops` `3.13.3`, `gitleaks` `8.30.1` in `~/.local/bin/`, GIR `gi.repository.Secret` available), SSH Git commit/tag signing + `.githooks/pre-commit` configured, `~/.gemini/` & `~/.cache/antigravity/` tightened to `0700`/`0600`, and `~/.local/tmp{,/claude}` (`0700`) + `~/.config/user-tmpfiles.d/agent-tmp.conf` active under `systemd-tmpfiles`.
- [x] **Phase 2 — Core `agentcfg` Engine, `cleanse` & `failsafe`**:
  - Implemented Python 3.12 stdlib `bin/agentcfg` + `lib/*.py` (`validate`, `diff`, `apply --safe`, `verify`, `restore`, `cleanse`, `failsafe`, `audit-repo`, `doctor`), `wrappers/{agent-env-run,mcp-secret-exec}`, and isolated `tests/` suite.
- [x] **Phase 3 — Canonical Catalog & Per-Harness Renderers**:
  - Populated `policy/`, `canonical/` (shared rules, `SKILL.md`, hooks, MCP registry, 13 harness definitions, and `canonical/profiles/failsafe/`), `targets/targets.json`, and deterministic renderers with `.git/info/exclude` wiring for repo `.agents/` targets.
- [x] **Phase 4 — Update Monitors & Offline Recovery**:
  - Implemented `agentcfg watch-updates`, `agentcfg upstream-check`, `systemd/agentcfg-watch.{service,timer}` (seeded `host-footprint.json` baseline and active user timer), `.github/workflows/upstream-schema-watch.yml`, and reproducible offline `bin/agentcfg-backup`.

---

## Further Reading

- [`docs/CONCEPT.md`](docs/CONCEPT.md) — Complete threat model, per-harness configuration/memory/`/tmp/` specifications, `cleanse`/`failsafe` state machines, GitHub ecosystem benchmark, atomic deployment protocol, and ratified implementation architecture.
