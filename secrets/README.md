# Tier-B Secrets (`secrets/`)

`agentconfig` enforces strict separation between declarative configuration (Tier A) and secrets/credentials (Tier B):

1. **Runtime secrets**: Stored primarily in the user OS keyring (`gnome-keyring` via `gi.repository.Secret` or `secret-tool`) and injected per-process via `wrappers/mcp-secret-exec` under `env -i`.
2. **Encrypted portable backup**: Optionally stored in SOPS + `age` encrypted files (`secrets/secrets.enc.yaml`), encrypted against the public `age` recipient in [`secrets/.sops.yaml`](file:///home/omniboot/agentconfig/secrets/.sops.yaml).
3. **Private key location**:
   - Local `age` private key lives strictly outside this repository at `~/.config/sops/age/keys.txt` (`0600`) or in the OS keyring.
   - NEVER place `keys.txt`, `*.dec.*`, `.env`, `antigravity-oauth-token`, `auth.json`, `.credentials.json`, `oauth_creds.json`, `hosts.yml`, or any plaintext secret inside `/home/omniboot/agentconfig`.
4. **Usage**:
   ```bash
   # Encrypt / edit encrypted bundle from repo root (requires age key in ~/.config/sops/age/keys.txt)
   sops --config secrets/.sops.yaml secrets/secrets.enc.yaml

   # Decrypt to stdout only (never write plaintext *.dec.* into the working tree)
   sops -d secrets/secrets.enc.yaml
   ```
