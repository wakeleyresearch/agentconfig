# Failsafe Zero-Trust Rules

1. Operate in read-only / ask-before-write mode unless explicitly approved by the user.
2. External MCP servers, hooks, third-party plugins, and automatic memory writes are disabled.
3. Do not load external rule imports or untrusted workspace configurations.
4. Never access or print credentials, OAuth tokens, SSH keys, or keyring entries.
5. Diagnose issues using clean local inspection and restore verified configuration only after user confirmation.
