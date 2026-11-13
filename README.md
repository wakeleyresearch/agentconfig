# agentconfig

> **Status: Architecture & Concept Draft** — `README.md` and [`docs/CONCEPT.md`](docs/CONCEPT.md) specify the threat model, verified harness research, and planned Source-of-Truth architecture. The runtime engine (`bin/agentcfg`), canonical catalogs (`canonical/`), policies (`policy/`), and environment wrappers (`wrappers/`) are planned implementation targets and do not yet exist in this repository.

`agentconfig` is a security-hardened, Git-backed **Source-of-Truth (SoT)** architecture for managing AI coding agent configurations, rules, skills, MCP servers, hooks, `/tmp/` sandboxing, agent memory hygiene, and update-drift controls across heterogeneous CLI, IDE, and desktop harnesses.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Three-Tier Source-of-Truth Architecture](#three-tier-source-of-truth-architecture)
3. [Supported Agents & Harnesses Matrix](#supported-agents--harnesses-matrix)
4. [Core Subsystems](#core-subsystems)
5. [Planned Repository Layout](#planned-repository-layout)
6. [Draft Status & Roadmap](#draft-status--roadmap)
7. [Further Reading](#further-reading)

---

## Problem Statement

Modern AI coding agents scatter instructions, MCP tool registries, hooks, permissions, caches, SQLite state, and persistent memory across dotfiles (`~/.gemini/`, `~/.claude/`, `~/.codex/`, `~/.copilot/`, `~/.config/`), workspace folders (`.agents/`, `.github/`, `.vscode/`, `.mcp.json`), and shared `/tmp/`. On a multi-harness workstation (reference host: Ubuntu 24.04.5 LTS x86_64 with `umask 0002`), four systemic failure classes occur:

1. **Network Corruption & Crash Mid-Write**
   - Unverified remote installers (`curl | sh`), interrupted package downloads, or broken `npx`/`uvx` caches leave truncated tools and configs on disk.
   - Auto-updaters fail mid-flight (stale `updater/update.lock`, partial `~/.cache/antigravity/staging/`, mismatched `builtin/.checksum`), while `SIGKILL`/OOM events truncate JSON/TOML settings, strand `bwrap` synthetic mount targets, or leave corrupted SQLite WAL/SHM journals.
   - Unresponsive remote HTTP MCP servers or synchronous hooks (for example, Antigravity `hooks.json` defaults to 30-second synchronous blocking) stall sessions, while ad-hoc UI edits silently drift from Git.

2. **Malware, Pre-Trust RCE & Supply-Chain Risks**
   - **Untrusted repository configs**: Cloned repos can embed `.mcp.json`, `.vscode/mcp.json`, `.claude/settings.json`, `.gemini/settings.json`, `.codex/config.toml`, `.agents/hooks.json`, or `*_BASE_URL` overrides—creating pre-trust remote code execution and API-key exfiltration vectors (e.g., Claude Code pre-trust hook/MCP RCE **CVE-2025-59536** and pre-trust `ANTHROPIC_BASE_URL` key theft **CVE-2026-21852**).
   - **Floating `npx -y` / `uvx` "rug pulls" & MCP tool poisoning**: Unpinned package invocations pull mutable upstream versions without confirmation; malicious or compromised servers can swap tool descriptions (**tool poisoning**) or spoof trusted tools (**tool shadowing**).
   - **Poisoned skills & plugins**: Community `SKILL.md` files, `AGENTS.md` instructions, or plugin bundles can hide invisible Unicode directives (`U+200B..U+200F`, `U+202A..U+202E`, Tags `U+E0000..U+E007F`) or malicious `hooks.json` / `scripts/*.sh` payloads.
   - **Plaintext credential exposure**: Under permissive `umask 0002`, config files and runtime logs/DBs default to world-readable `0644`/`0755`, exposing inline tokens or leaking parent environment secrets into child stdio processes.

3. **`/tmp/` Exposure & Agent Memory Poisoning**
   - **Shared `1777` `/tmp/` and `/var/tmp/`**: Linux `fs.protected_symlinks=1` and `fs.protected_regular=2` block *cross-UID* attacks, not *same-UID* races from a compromised tool, MCP server, or `postinstall` script. Combined with `umask 0002`, temp scratchpads, bash captures, and logs leak locally; crashed runs linger up to 30 days in `/tmp` (and indefinitely in `/var/tmp` where cleanup is commented out by default). Conversely, blindly redirecting `$TMPDIR` to `/run/user/$UID` (`191 MiB` `tmpfs` on the reference host) triggers instant `ENOSPC` on AppImages and package unpacks.
   - **Persistent memory poisoning & corruption**: Prompt injections or malformed entries written into long-lived memory stores—such as `~/.gemini/GEMINI.md` (`## Gemini Added Memories`), Antigravity `conversation_summaries.db*` / `implicit/*.pb` / `annotations/*.pbtxt`, Claude Code auto-memory, Codex `memories` / `memories_v2`, or server-side Copilot Memory—persist across sessions and silently alter future agent behavior.

4. **Schema Drift & Breaking Changes on Agent Updates**
   - Harnesses silently migrate or drop configuration semantics across updates: Antigravity (`agy`) changed default agent mode to `Auto` in `1.5.7`, fixed UTF-8 BOM config ignoring in `1.5.8`, migrated IDE configs in `1.x -> 2.0`, and silently discards unknown `plugin.json` keys or legacy HTTP+SSE `/sse` MCP endpoints.
   - Gemini CLI auto-migrates v1 flat keys to v2 nested schemas; Copilot CLI superseded `config.json` user settings with `settings.json`, drops unsupported external `mcp-config.json` keys (e.g. `"disabled": true`), and can re-exec cached prerelease binaries *before* reading `settings.json`; VS Code deprecated `.chatmode.md` in favor of `.agent.md` and scheduled legacy Local harness removal for February 2027.

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

- **Optimization for mixed files**: Harnesses that mix declarative rules/MCPs with mutable runtime state use either **`plugin-bundle`** isolation (e.g., rendering shared Antigravity rules, skills, hooks, and MCP into a dedicated managed plugin `~/.gemini/config/plugins/agentconfig-core/`, leaving mutable `~/.gemini/config/config.json` untouched) or **`patch-managed-keys`** (e.g., `~/.claude.json`, `~/.gemini/antigravity-cli/settings.json`) so runtime trust/cache keys are preserved.

---

## Supported Agents & Harnesses Matrix

> **Research Coverage Note**: Entries marked **Verified** are backed by completed swarm research (`#7`, `#8`, `#15`, `#16`). Entries marked **Pending Deep Verification** include cross-references verified in the security architecture (`#7`, `#15`) while awaiting final per-harness schema reports from `openai-anthropic` and `emerging-harnesses`.

| Harness / Model Family | Status | Global Config Root | Key Declarative Files | Secrets / Auth (Never Git) | Memory & `/tmp/` Surfaces | Built-in Failsafe / Clean-Boot Hooks |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Antigravity** (`agy` 1.5.8, App 2.0, IDE, Python SDK) | **Verified** | `~/.gemini/config/` & `~/.gemini/antigravity-cli/` (`~/.gemini/antigravity/` App, `~/.gemini/antigravity-ide/` IDE) | `config/{mcp_config.json,skills/,agents/,rules/,plugins/,sidecars/,skills.json,plugins.json,hooks.json}`, `antigravity-cli/settings.json`, repo `.agents/` | `antigravity-oauth-token` (`0600`), `ANTIGRAVITY_CSRF_TOKEN` | `GEMINI.md`/`AGENTS.md` (`/learn`, 24 KB/file, 20k token budget), `conversation_summaries.db*`, `jetbox_summaries_proto.pb`, `implicit/*.pb`, `annotations/*.pbtxt`; `/tmp/lsrpc.sh`, `/tmp/.mount_*`, Chromium singletons | `--settings`, `--mode plan --sandbox`, `--disable-slash-commands`, `ANTIGRAVITY_APP_DATA_DIR`, `agy acp --include-default-customizations=false`, `agy plugin validate --strict` |
| **Google Gemini CLI** (`@google/gemini-cli`) | **Verified** | `~/.gemini/` (`GEMINI_CLI_HOME`), `/etc/gemini-cli/` | `settings.json`, `GEMINI.md`, `commands/**/*.toml`, `skills/`, `agents/*.md`, `extensions/*/gemini-extension.json`, `policies/*.toml`, `sandbox.Dockerfile` | `oauth_creds.json`, `google_accounts.json`, `.env`, OS keychain (`sensitive: true`) | Hierarchical `GEMINI.md` + `save_memory` (`## Gemini Added Memories`); `~/.gemini/tmp/<hash>/`, `~/.gemini/history/<hash>/` (shadow git) | `GEMINI_CLI_HOME`, `--approval-mode plan --sandbox`, `--allowed-mcp-server-names`, `trustedFolders.json`, Policy Engine deny `save_memory`, `/restore` |
| **GitHub Copilot** (CLI, `github/app` Desktop, VS Code, JetBrains, Coding Agent) | **Verified** | `~/.copilot/` (`COPILOT_HOME`), `~/.config/Code/User/`, `~/.config/github-copilot/intellij/` | `~/.copilot/{settings.json,mcp-config.json,lsp-config.json,providers.json,copilot-instructions.md,skills/,agents/}`, `.vscode/mcp.json` (`servers`), `.github/{copilot-instructions.md,instructions/,agents/*.agent.md,prompts/,hooks/*.json,github-app.yml}` | `~/.config/gh/hosts.yml`, `COPILOT_GITHUB_TOKEN` / `GH_TOKEN`, BYOK keys in `providers.json`, inline `Authorization` headers | Server-side **Copilot Memory** (code citations + JIT check + 28d TTL), `session-state/`, `session-store.db`; `/tmp/.mount_*`, `/tmp/vscode-*.sock`, containerized `/tmp/` `events.jsonl` | `COPILOT_HOME`, `--disable-builtin-mcps`, `--disable-mcp-server`, `--no-custom-instructions`, `COPILOT_AUTO_UPDATE=false`, `/memory off`, VS Code `chat.copilot.memory.enabled: false` + GitHub UI purge |
| **Anthropic Claude** (Claude Code CLI/IDE, Claude Desktop) | **Pending Deep Verification** *(cross-refs verified in `#7`, `#15`)* | `~/.claude/` (`CLAUDE_CONFIG_DIR`), `~/.claude.json` | `settings.json`, `CLAUDE.md`, `.mcp.json`, `.claude/{settings.json,skills/}` *(full matrix pending `@openai-anthropic`)* | `~/.claude/.credentials.json`, API keys / `ANTHROPIC_BASE_URL` guards | `~/.claude/projects/*/memory/MEMORY.md` & topic `.md`; `/tmp/claude-<uid>/` (`CLAUDE_CODE_TMPDIR`), bash sandbox `$TMPDIR` override | `--bare` (`CLAUDE_CODE_SIMPLE=1`), `--strict-mcp-config --mcp-config /dev/null`, `--permission-mode plan`, `--setting-sources user`, `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` |
| **OpenAI** (Codex CLI, Codex App, ChatGPT) | **Pending Deep Verification** *(cross-refs verified in `#7`, `#15`)* | `~/.codex/` (`CODEX_HOME`) | `config.toml`, `AGENTS.md`, `.codex/config.toml` *(full matrix pending `@openai-anthropic`)* | `~/.codex/auth.json` *(ChatGPT cloud auth pending)* | `$CODEX_HOME/{memories/,memories_v2/}` (`MEMORY.md`, `memory_summary.md`), `$CODEX_HOME/` SQLite DBs (`sqlite/`, `state_*.sqlite`); `bwrap` `/tmp` & `$TMPDIR` (`exclude_slash_tmp`), `codex-daemon-*` | `--ask-for-approval untrusted --sandbox read-only`, `--profile failsafe`, `[features] memories = false`, `[memories] generate_memories = false, use_memories = false` |
| **Emerging & Cross-Agent Harnesses** (Kimi, Grok, OpenCode, Cursor, Windsurf, Cline, Roo Code, Goose, Aider) | **Pending Deep Verification** *(open standards verified in `#8`)* | Per-harness XDG / `~/.<tool>/` *(matrix pending `@emerging-harnesses`)* | Open standards verified across major clients: `AGENTS.md`, `.agents/skills/<name>/SKILL.md` (`~/.agents/skills/`), MCP JSON registries (`mcpServers` vs `servers`) | OAuth files, keyring entries, API env vars *(full matrix pending)* | Local transcripts, rule/memory stores, `/tmp/` staging *(full matrix pending)* | Per-harness clean-env flags & read-only/offline overrides *(full matrix pending)* |

---

## Core Subsystems

### 1. `agentcfg` Safe Applicator & Integrity Engine
A planned Python 3.12 stdlib engine (`bin/agentcfg`, zero mandatory external Python dependencies) enforcing deterministic, verified deployments:
- **Pre-commit & pre-apply validation (`agentcfg validate`)**: Parses JSON (`json`), TOML (`tomllib`), and YAML frontmatter; enforces Antigravity's `24,000`-byte rule cap and `agy plugin validate --strict`; enforces `policy/security-policy.json` (bans floating `npx -y`/`uvx`, plain `http://` remote MCPs, legacy `/sse` in Antigravity, unauthorized `*_BASE_URL` overrides, and invisible Unicode).
- **Secret scanning**: Runs `gitleaks` plus a built-in regex (`sk-`, `ghp_`, `AIza`, `AKIA`, `AGE-SECRET-KEY-`, PEM headers, `Bearer `) and Shannon entropy fallback so scanning never silently degrades.
- **Atomic deployment (`agentcfg apply --safe`)**:
  1. Acquires an exclusive `flock` on `${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/agentcfg.lock`.
  2. Checks `agentcfg watch-updates --check` to halt unattended overwrites if a harness binary or schema drifted unexpectedly.
  3. Runs validation, secret scanning, and `cleanse --dry-run`.
  4. Snapshots existing targets and memory, then stages each rendered output via `tempfile.NamedTemporaryFile` **in the target's parent directory** (same filesystem—eliminating `EXDEV` and `/tmp` races), followed by `flush()`, `os.fsync(fd)`, `os.fchmod(fd, mode)` (`0400`/`0444` for declarative targets, `0600` for patched configs, `0500`/`0700` for wrappers), atomic `os.replace`, and parent directory `fsync`.
- **Manifest, diff, audit & provenance**:
  - `agentcfg verify` & `agentcfg diff`: Validates live SHA-256 checksums and file permissions against `~/.local/state/agentcfg/deployed-manifest.json`.
  - `agentcfg audit-repo <path>`: Scans untrusted repositories before opening for `.mcp.json`, `.vscode/mcp.json`, `.claude/`, `.agents/{hooks,plugins,skills}.json`, and `*_BASE_URL` overrides.
  - **Signed Git provenance & offline backup**: SSH-signed Git commits/tags (`gpg.format ssh`) plus reproducible offline `git bundle` + `tar.gz` + `sha256sum` (+ optional `age` encryption).

### 2. `agentcfg cleanse` & Quarantine
Remediates corrupted state into a timestamped, non-executable `0700` quarantine directory (`~/.local/state/agentcfg/quarantine/<UTC-ts>/`) with `chmod 0400`/`0600` and a `quarantine-manifest.json` audit log before restoring clean SoT files:
- **Explicit Scopes (`--scope config|memory|runtime|all`, default `config`)**:
  - `config`: Invalid JSON/TOML/YAML, schema violations, undeclared MCP servers or `.agents/hooks.json`, banned unpinned `npx -y`/`uvx`, broken symlinks, and unsafe permissions (`0777`, world-readable `0644`/`0755` on sensitive files).
  - `runtime`: Orphaned `.tmp` files, stale locks (checked for liveness via `flock -n` / `fuser` / `/proc/<pid>` first), corrupt SQLite DBs or stranded WAL/SHM files (checked read-only via Python `sqlite3` `PRAGMA quick_check`), and stale staging caches.
  - `memory`: Poisoned or malformed local memory entries across `GEMINI.md`, Claude `MEMORY.md`, Codex `memories/`, and Antigravity `annotations/`/`implicit/`/`conversation_summaries.db*`.
- **Hard Auth-Preservation Invariant**: Credential and OAuth files (`antigravity-oauth-token`, `~/.config/gh/hosts.yml`, `~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, `~/.local/share/keyrings/`) are **never** quarantined or wiped—even under `--scope all`—unless `--include-auth --confirm-wipe-auth` is explicitly passed interactively.

### 3. Built-in `failsafe` Mode
`canonical/profiles/failsafe/` + `agentcfg failsafe` + `wrappers/agent-env-run --failsafe` provide a minimal zero-trust recovery baseline per harness:
- **Zero external/remote MCP servers**, **hooks & third-party plugins disabled**, **strict ask/read-only permissions**, **auto-memory disabled/bypassed**, **minimal verified rules (`<=2 KB`, no `@` file includes)**, and an **isolated `0700` `$TMPDIR` with `umask 0077` and `env -i`**.
- **Two operating modes**:
  1. **Ephemeral Non-Destructive Boot (`agent-env-run --failsafe <harness>`)**: Boots the harness inside an isolated `0700` runtime root (`HOME`/`XDG_CONFIG_HOME`/`CODEX_HOME`/`CLAUDE_CONFIG_DIR` or `--settings`) for incident triage without overwriting live evidence.
  2. **Persistent Safe-Mode Switch (`agentcfg failsafe --apply` / `--restore`)**: Snapshots live configs and memory, atomically swaps deployed targets to the failsafe profile, and restores cleanly post-remediation.

### 4. `/tmp/` & Agent Memory Hardening
- **Two-tier private `0700` temp architecture**:
  - **Tier 1 (Small volatile IPC, sockets & locks)**: `$XDG_RUNTIME_DIR/agent-runtime` (`/run/user/$UID/agent-runtime`, `0700`, `tmpfs`, auto-cleared on logout, bounded at `191 MiB` on reference host).
  - **Tier 2 (Large scratch, AppImage unpacks & tool sandboxes)**: `~/.local/tmp` (`0700`, ext4) and `~/.local/tmp/claude` (`0700`), exported with `umask 0077`, `TMPDIR`/`TEMP`/`TMP`, and `CLAUDE_CODE_TMPDIR`, plus `systemd-tmpfiles --user` age-out rules (`~/.config/user-tmpfiles.d/agent-tmp.conf`) and per-session `mktemp -d` exit traps.
- **Host & existing directory tightening**: Fixes permissive `0755`/`0644` directories/DBs/logs in `~/.gemini/` and `~/.cache/antigravity/` to `0700`/`0600`; recommends `nosuid,nodev,noexec` on `/dev/shm` and `/var/tmp` (and `/tmp` once wrappers direct `$TMPDIR` to `~/.local/tmp`).
- **Memory hygiene**: Scans memory stores for invisible Unicode, exfiltration directives (`curl`, `wget`, `.ssh`, token paths), and anomalous growth; captures pre-cleanse memory snapshots (`0600`); selectively excises poisoned sections; and provides per-harness instructions to purge cloud stores (e.g., GitHub Copilot Memory web UI) that CLI flags alone cannot delete.

### 5. Local & Upstream Update-Change Monitor
- **Local monitor (`agentcfg watch-updates` / `agentcfg doctor` / `systemd --user` timer)**: Maintains `~/.local/state/agentcfg/host-footprint.json` (`0600`) tracking binary versions & SHA-256 hashes (`agy`, `claude`, `codex`, `gemini`, `copilot`, `gh`), Antigravity `builtin/{.checksum,.manifest}`, metadata-only config/permission/directory state (skipping secrets), and sorted JSON/TOML key-shape diffs. Halts unattended `agentcfg apply` on `NEW_KEY`, `DROPPED_KEY`, or `NEW_MEMORY_PATH`.
- **Upstream monitor (`.github/workflows/upstream-schema-watch.yml` + `agentcfg upstream-check`)**: Periodically checks pinned official JSON schemas and release feeds (`policy/upstream-sources.json`) against local snapshots (`policy/upstream-schemas/`), opening a labeled GitHub Issue/draft PR on breaking schema deltas before renderers are updated.

---

## Planned Repository Layout

```text
/home/omniboot/agentconfig/
├── README.md                              # Project overview & roadmap (this file)
├── docs/
│   └── CONCEPT.md                         # Full architecture, per-harness spec & threat model
├── .gitignore                             # Blocks *.dec.*, .age/, dist/, *.tmp, state/, backups/
├── .githooks/
│   └── pre-commit                         # Tracked secret, syntax, & policy gate
├── .github/
│   └── workflows/
│       └── upstream-schema-watch.yml      # Scheduled upstream schema & release diff monitor
├── policy/
│   ├── security-policy.json               # Banned patterns (npx -y, http:// MCP), size caps, allowed *_BASE_URLs
│   ├── manifests.lock.json                # Pinned MCP versions, package integrity hashes, tools/list SHA-256
│   ├── upstream-sources.json              # Pinned upstream JSON schema & release-note URLs
│   └── upstream-schemas/                  # Pinned reference schema snapshots for diffing
├── canonical/
│   ├── rules/                             # Shared Markdown rules (<=24,000 B check; aggregate token budget guard)
│   ├── skills/                            # Reviewed <skill>/SKILL.md + reviewed scripts/
│   ├── hooks/                             # Reviewed hooks.json fragments + scripts (<=10s timeout)
│   ├── mcp-registry.json                  # Canonical MCP catalog (uses secret_ref IDs, ZERO secrets)
│   ├── harnesses/                         # Per-harness deterministic render templates
│   └── profiles/
│       └── failsafe/                      # Built-in zero-trust minimal baseline per harness
├── secrets/
│   ├── .sops.yaml                         # age public-key recipients & encryption rules
│   └── secrets.enc.yaml                   # Optional SOPS+age encrypted secrets (NEVER plaintext)
├── targets/
│   └── targets.json                       # Target path, mode (0400/0444/0600), strategy (ro|patch-managed-keys|plugin-bundle)
├── wrappers/
│   ├── agent-env-run                      # Sets umask 0077, private $TMPDIR, $XDG_RUNTIME_DIR, --failsafe, optional bwrap
│   └── mcp-secret-exec                    # Fetches scoped secret via secret-tool/sops -> exec env -i <VAR>=... <cmd>
└── bin/
    └── agentcfg                           # Python 3.12 stdlib CLI: validate, diff, apply, verify, cleanse, failsafe, restore, audit-repo, watch-updates, upstream-check, doctor
```

---

## Draft Status & Roadmap

- [x] **Phase 0 — Research & Architecture Concept (`main` docs)**:
  - Host baseline audit (`/home/omniboot`, `/tmp/`, `~/.gemini/`, `~/.cache/antigravity/`).
  - Verified deep-dive specs for Google Antigravity (`agy` 1.5.8, App 2.0, IDE, SDK), Google Gemini CLI, and GitHub Copilot (CLI, `github/app`, VS Code, JetBrains, Coding Agent).
  - Threat model, `/tmp/` & memory hardening design, `cleanse`, `failsafe`, and update-monitoring architecture ([`docs/CONCEPT.md`](docs/CONCEPT.md)).
  - *(In progress)* Finalizing verified specs for OpenAI (Codex/ChatGPT), Anthropic (Claude Code/Desktop), and emerging/cross-agent harnesses (Kimi, Grok, OpenCode, Cursor, Windsurf, Cline, Roo Code, Goose, Aider).
- [ ] **Phase 1 — Host Hardening & Repo Guardrails**:
  - Install host dependencies (`libsecret-tools`, `age`, `gitleaks`, pinned `sops`), enable SSH Git commit/tag signing, configure `.githooks/pre-commit`, tighten `~/.gemini/` & `~/.cache/antigravity/` to `0700`/`0600`, and deploy `~/.config/user-tmpfiles.d/agent-tmp.conf`.
- [ ] **Phase 2 — Core `agentcfg` Engine, `cleanse` & `failsafe`**:
  - Implement Python 3.12 `bin/agentcfg` (`validate`, `diff`, `apply --safe`, `verify`, `restore`, `cleanse`, `failsafe`, `audit-repo`) and `wrappers/{agent-env-run,mcp-secret-exec}`.
- [ ] **Phase 3 — Canonical Catalog & Per-Harness Renderers**:
  - Populate `canonical/`, `targets/targets.json`, `policy/manifests.lock.json`, and deterministic renderers (starting with Antigravity `agentconfig-core` plugin bundle, Gemini CLI, and Copilot).
- [ ] **Phase 4 — Update Monitors & Offline Recovery**:
  - Implement `agentcfg watch-updates`, `systemd --user` timer, `.github/workflows/upstream-schema-watch.yml`, and reproducible offline `git bundle` + `age` backup scripts.

---

## Further Reading

- [`docs/CONCEPT.md`](docs/CONCEPT.md) — Complete threat model, per-harness configuration/memory/`/tmp/` specifications, `cleanse`/`failsafe` state machines, atomic deployment protocol, and open design decisions.
