"""Tests for agentcfg validate policy, schema, budget, secret, Unicode, and Grok checks."""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

from lib.policy import (
    ValidationReport,
    check_codex_config,
    check_hooks_config,
    check_mcp_config_object,
    check_rule_text,
    load_security_policy,
    validate_content_file,
)
from tests.helpers import IsolatedEnvMixin, REPO_ROOT, copy_repo_fixture, init_git_repo, run_agentcfg, synth_secret


class ValidatePolicyTests(IsolatedEnvMixin, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.policy = load_security_policy(REPO_ROOT)

    def test_live_repo_validate_passes(self) -> None:
        proc = run_agentcfg("validate", "--json", home=self.home_dir, state_dir=self.state_dir)
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"], msg=data)
        self.assertEqual(data["error_count"], 0, msg=data)
        self.assertEqual(data["warning_count"], 0, msg=data)

    def test_rejects_banned_mcp_runners_and_latest_tags(self) -> None:
        bad_cases = [
            ("npx_dash_y", {"command": "npx", "args": ["-y", "mcp-server-git@1.0.0"]}, "BANNED_MCP_PATTERN"),
            ("npx_double_yes", {"command": "npx --yes mcp-server-git@1.0.0"}, "BANNED_MCP_PATTERN"),
            ("uvx_cmd", {"command": "uvx", "args": ["mcp-server-git"]}, "BANNED_MCP_COMMAND"),
            ("latest_tag", {"command": "npm", "args": ["exec", "foo-mcp@latest"]}, "BANNED_MCP_PATTERN"),
        ]
        for name, srv, expected_code in bad_cases:
            with self.subTest(name=name):
                findings = check_mcp_config_object(
                    {"mcpServers": {name: srv}},
                    harness="claude-code",
                    policy=self.policy,
                    location="canonical/mcp.json",
                )
                codes = {f.code for f in findings}
                self.assertIn(expected_code, codes, msg=findings)

        # Verify CLI validate also fails when injected into a repo copy.
        repo = copy_repo_fixture(self.tmp_path / "repo-bad-mcp")
        reg_path = repo / "canonical" / "mcp-registry.json"
        reg = json.loads(reg_path.read_text(encoding="utf-8"))
        reg["servers"]["bad-npx"] = {
            "enabled": False,
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@example/mcp@1.0.0"],
            "targets": ["claude-code"],
        }
        reg_path.write_text(json.dumps(reg, indent=2), encoding="utf-8")
        proc = run_agentcfg("validate", "--skip-agy", "--json", home=self.home_dir, state_dir=self.state_dir, repo=repo)
        self.assertEqual(proc.returncode, 1)
        data = json.loads(proc.stdout)
        self.assertFalse(data["ok"])
        self.assertIn("BANNED_MCP_PATTERN", {f["code"] for f in data["findings"]})

    def test_rejects_http_remote_mcp_and_url_userinfo(self) -> None:
        for url_val in ("http://mcp.example.com/mcp", "http://localhost:8080/mcp"):
            findings = check_mcp_config_object(
                {"mcpServers": {"insecure": {"url": url_val}}},
                harness="claude-code",
                policy=self.policy,
                location="test.json",
            )
            self.assertIn("INSECURE_HTTP_MCP", {f.code for f in findings}, msg=url_val)

        userinfo_findings = check_mcp_config_object(
            {"mcpServers": {"creds": {"url": "https://user:secretpass@mcp.example.com/mcp"}}},
            harness="claude-code",
            policy=self.policy,
            location="test.json",
        )
        self.assertIn("URL_USERINFO_CREDENTIAL", {f.code for f in userinfo_findings})

    def test_rejects_sse_in_antigravity_and_goose_only(self) -> None:
        for disallowed in ("antigravity", "goose"):
            with self.subTest(harness=disallowed):
                f_url = check_mcp_config_object(
                    {"mcpServers": {"s1": {"url": "https://mcp.example.com/sse"}}},
                    harness=disallowed,
                    policy=self.policy,
                    location=f"{disallowed}.json",
                )
                self.assertIn("UNSUPPORTED_SSE_TRANSPORT", {f.code for f in f_url})

                f_type = check_mcp_config_object(
                    {"extensions": {"s2": {"type": "sse", "uri": "https://mcp.example.com/events"}}},
                    harness=disallowed,
                    policy=self.policy,
                    location=f"{disallowed}.yaml",
                )
                self.assertIn("UNSUPPORTED_SSE_TRANSPORT", {f.code for f in f_type})

        # Allowed harnesses should not trigger UNSUPPORTED_SSE_TRANSPORT on HTTPS /sse.
        f_allowed = check_mcp_config_object(
            {"mcpServers": {"s3": {"type": "sse", "url": "https://mcp.example.com/sse"}}},
            harness="claude-code",
            policy=self.policy,
            location="claude.json",
        )
        self.assertNotIn("UNSUPPORTED_SSE_TRANSPORT", {f.code for f in f_allowed})

    def test_rejects_literal_secret_keys_tokens_and_bearer_headers_but_allows_placeholders(self) -> None:
        fake_gh = synth_secret("ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6")
        fake_sk = synth_secret("sk-proj-", "AbCdEfGhIjKlMnOpQrStUvWxYz123456")
        fake_bearer = synth_secret("Bearer ", "AbCdEfGhIjKlMnOpQrStUvWx123456")

        cases = [
            (
                "literal_api_key",
                {"mcpServers": {"s": {"command": "/opt/mcp/bin/srv", "api_key": "plain-literal-secret"}}},
                "LITERAL_CREDENTIAL_KEY",
            ),
            (
                "literal_bearer_header",
                {"mcpServers": {"s": {"url": "https://mcp.example.com/mcp", "headers": {"Authorization": fake_bearer}}}},
                "LITERAL_CREDENTIAL_HEADER",
            ),
            (
                "literal_x_api_key_header",
                {"mcpServers": {"s": {"url": "https://mcp.example.com/mcp", "http_headers": {"x-api-key": "my-literal-key"}}}},
                "LITERAL_CREDENTIAL_HEADER",
            ),
            (
                "cli_header_arg",
                {"mcpServers": {"s": {"command": "/opt/mcp/bin/srv", "args": ["-H", "Authorization: secret"]}}},
                "LITERAL_HEADER_ARG",
            ),
        ]
        for label, payload, expected in cases:
            with self.subTest(label=label):
                findings = check_mcp_config_object(payload, harness="claude-code", policy=self.policy, location="mcp.json")
                self.assertIn(expected, {f.code for f in findings}, msg=findings)

        # Regex secret scanning via validate_content_file.
        for label, token in [("github_pat", fake_gh), ("openai_sk", fake_sk), ("bearer", fake_bearer)]:
            with self.subTest(secret=label):
                rep = ValidationReport()
                validate_content_file(
                    "canonical/rules/bad.md",
                    f"# Rule\nDo not use {token} here.\n",
                    self.policy,
                    rep,
                )
                self.assertFalse(rep.ok)
                self.assertIn("SECRET_DETECTED", {f.code for f in rep.findings})

        # Symbolic placeholders must be accepted cleanly.
        rep_ok = ValidationReport()
        validate_content_file(
            "canonical/mcp-sample.json",
            json.dumps(
                {
                    "mcpServers": {
                        "safe": {
                            "url": "https://mcp.example.com/mcp",
                            "headers": {"Authorization": "${MCP_AUTH_HEADER}"},
                            "env": {"API_TOKEN": "${env:MCP_API_TOKEN}"},
                        }
                    }
                }
            ),
            self.policy,
            rep_ok,
        )
        self.assertTrue(rep_ok.ok, msg=rep_ok.to_dict())

    def test_rejects_invisible_unicode(self) -> None:
        for cp_name, ch in [
            ("zwsp", "\u200b"),
            ("rlo", "\u202e"),
            ("word_joiner", "\u2060"),
            ("bom", "\ufeff"),
            ("tag_char", "\U000e0001"),
        ]:
            with self.subTest(cp=cp_name):
                rep = ValidationReport()
                validate_content_file(
                    "canonical/rules/u.md",
                    f"# Clean Header\nPayload{ch}here\n",
                    self.policy,
                    rep,
                )
                self.assertFalse(rep.ok)
                self.assertIn("INVISIBLE_UNICODE", {f.code for f in rep.findings})

    def test_enforces_antigravity_24000_byte_cap_and_token_budget_and_failsafe_limits(self) -> None:
        exactly_24000 = "a" * 24000
        f_ok = check_rule_text(exactly_24000, "canonical/rules/ok.md", self.policy, check_kimi=False)
        self.assertEqual([f for f in f_ok if f.code == "ANTIGRAVITY_RULE_BYTE_CAP"], [])

        over_24000 = "a" * 24001
        f_over = check_rule_text(over_24000, "canonical/rules/too-big.md", self.policy, check_kimi=False)
        self.assertIn("ANTIGRAVITY_RULE_BYTE_CAP", {f.code for f in f_over})

        over_kimi = "a" * 32769
        f_kimi = check_rule_text(over_kimi, "canonical/rules/kimi.md", self.policy, check_antigravity=False)
        self.assertIn("KIMI_AGENTS_MD_WARN", {f.code for f in f_kimi})

        # Failsafe rule cap (<= 2048 B) and no @ imports.
        f_fs_big = check_rule_text("x" * 2049, "canonical/profiles/failsafe/rules.md", self.policy, is_failsafe=True)
        self.assertIn("FAILSAFE_RULE_TOO_LARGE", {f.code for f in f_fs_big})
        f_fs_at = check_rule_text("# Failsafe\n@./extra.md\n", "canonical/profiles/failsafe/rules.md", self.policy, is_failsafe=True)
        self.assertIn("FAILSAFE_AT_IMPORT", {f.code for f in f_fs_at})

        # Hook timeout > 10s fails.
        f_hook = check_hooks_config(
            {"g": {"PreToolUse": [{"matcher": "run_command", "hooks": [{"type": "command", "command": "true", "timeout": 15}]}]}},
            self.policy,
            "canonical/hooks/hooks.json",
        )
        self.assertIn("HOOK_TIMEOUT_EXCEEDED", {f.code for f in f_hook})

        # Aggregate defaultRulesBudget (>20,000 tokens across canonical/rules/*.md) fails CLI validate.
        repo = copy_repo_fixture(self.tmp_path / "repo-token-budget")
        # 4 files each <= 24,000 B (e.g. 23,000 B each = 92,000 B ~> 23,000 tokens > 20,000)
        for idx in range(4):
            (repo / "canonical" / "rules" / f"extra-{idx}.md").write_text(("word " * 4500) + "\n", encoding="utf-8")
        proc = run_agentcfg("validate", "--skip-agy", "--json", home=self.home_dir, state_dir=self.state_dir, repo=repo)
        self.assertEqual(proc.returncode, 1)
        data = json.loads(proc.stdout)
        self.assertIn("ANTIGRAVITY_RULES_TOKEN_BUDGET", {f["code"] for f in data["findings"]})

    def test_rejects_codex_deprecated_profiles_and_untrusted_approval_policy(self) -> None:
        bad_toml = 'profile = "legacy"\napproval_policy = "untrusted"\n\n[profiles.legacy]\nsandbox_mode = "read-only"\n'
        rep = ValidationReport()
        validate_content_file("canonical/harnesses/codex-test.toml", bad_toml, self.policy, rep)
        codes = {f.code for f in rep.findings}
        self.assertIn("CODEX_DEPRECATED_PROFILES", codes)
        self.assertIn("CODEX_RETIRED_APPROVAL_POLICY", codes)

        direct = check_codex_config(
            {"profiles": {"legacy": {}}, "approval_policy": "untrusted"},
            self.policy,
            "codex/config.toml",
        )
        self.assertEqual({f.code for f in direct}, {"CODEX_DEPRECATED_PROFILES", "CODEX_RETIRED_APPROVAL_POLICY"})

    def test_rejects_grok_home_ambiguity_without_grok_flavor(self) -> None:
        grok_dir = self.home_dir / ".grok"
        grok_dir.mkdir(mode=0o700)
        # Collision: both xAI and @vibe-kit/grok-cli marker files present.
        (grok_dir / "config.toml").write_text('approval_policy = "on-request"\n', encoding="utf-8")
        (grok_dir / "user-settings.json").write_text("{}\n", encoding="utf-8")

        proc_fail = run_agentcfg("validate", "--skip-agy", "--json", home=self.home_dir, state_dir=self.state_dir)
        self.assertEqual(proc_fail.returncode, 1)
        data_fail = json.loads(proc_fail.stdout)
        self.assertIn("GROK_FLAVOR_AMBIGUOUS", {f["code"] for f in data_fail["findings"]})

        for flavor in ("xai", "vibekit"):
            proc_ok = run_agentcfg(
                "validate",
                "--skip-agy",
                "--grok-flavor",
                flavor,
                "--json",
                home=self.home_dir,
                state_dir=self.state_dir,
            )
            self.assertEqual(proc_ok.returncode, 0, msg=proc_ok.stdout + proc_ok.stderr)

        # Also check empty/unknown ~/.grok/ directory without marker files.
        (grok_dir / "config.toml").unlink()
        (grok_dir / "user-settings.json").unlink()
        (grok_dir / "unknown.txt").write_text("ambiguous\n", encoding="utf-8")
        proc_unknown = run_agentcfg("validate", "--skip-agy", "--json", home=self.home_dir, state_dir=self.state_dir)
        self.assertEqual(proc_unknown.returncode, 1)
        self.assertIn("GROK_FLAVOR_AMBIGUOUS", {f["code"] for f in json.loads(proc_unknown.stdout)["findings"]})

    def test_rejects_unauthorized_base_url_and_unpinned_enabled_mcp(self) -> None:
        findings = check_mcp_config_object(
            {
                "mcpServers": {
                    "s": {
                        "command": "/opt/mcp/bin/srv",
                        "env": {"OPENAI_BASE_URL": "https://attacker.example/v1"},
                    }
                }
            },
            harness="claude-code",
            policy=self.policy,
            location="mcp.json",
        )
        self.assertIn("UNAUTHORIZED_BASE_URL", {f.code for f in findings})

        repo = copy_repo_fixture(self.tmp_path / "repo-unpinned")
        reg_path = repo / "canonical" / "mcp-registry.json"
        reg = json.loads(reg_path.read_text(encoding="utf-8"))
        reg["servers"]["unlisted-srv"] = {
            "enabled": True,
            "transport": "stdio",
            "command": "/opt/mcp/bin/unlisted",
            "args": [],
            "targets": ["codex"],
        }
        reg_path.write_text(json.dumps(reg, indent=2), encoding="utf-8")
        proc = run_agentcfg("validate", "--skip-agy", "--json", home=self.home_dir, state_dir=self.state_dir, repo=repo)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("UNPINNED_MCP_SERVER", {f["code"] for f in json.loads(proc.stdout)["findings"]})

    def test_validate_staged_in_temp_git_repo(self) -> None:
        repo = init_git_repo(copy_repo_fixture(self.tmp_path / "staged-repo"))

        # Stage a clean rule change -> passes validate --staged.
        clean_rule = repo / "canonical" / "rules" / "extra.md"
        clean_rule.write_text("# Extra Safe Rule\n\nFollow least privilege.\n", encoding="utf-8")
        subprocess.run(["git", "add", "canonical/rules/extra.md"], cwd=repo, check=True)
        proc_ok = run_agentcfg("validate", "--staged", "--json", home=self.home_dir, state_dir=self.state_dir, repo=repo)
        self.assertEqual(proc_ok.returncode, 0, msg=proc_ok.stdout + proc_ok.stderr)

        # Stage an invisible Unicode rule -> fails validate --staged.
        clean_rule.write_text("# Bad Rule\nHidden\u200bchar\n", encoding="utf-8")
        subprocess.run(["git", "add", "canonical/rules/extra.md"], cwd=repo, check=True)
        proc_bad = run_agentcfg("validate", "--staged", "--json", home=self.home_dir, state_dir=self.state_dir, repo=repo)
        self.assertEqual(proc_bad.returncode, 1)
        self.assertIn("INVISIBLE_UNICODE", {f["code"] for f in json.loads(proc_bad.stdout)["findings"]})

        # Stage forbidden .key filename -> fails validate --staged.
        subprocess.run(["git", "reset", "-q", "HEAD", "--", "canonical/rules/extra.md"], cwd=repo, check=True)
        clean_rule.unlink()
        bad_key = repo / "secrets" / "test.key"
        bad_key.write_text("dummy\n", encoding="utf-8")
        subprocess.run(["git", "add", "-f", "secrets/test.key"], cwd=repo, check=True)
        proc_key = run_agentcfg("validate", "--staged", "--json", home=self.home_dir, state_dir=self.state_dir, repo=repo)
        self.assertEqual(proc_key.returncode, 1)
        self.assertIn("FORBIDDEN_SECRET_FILE", {f["code"] for f in json.loads(proc_key.stdout)["findings"]})


if __name__ == "__main__":
    unittest.main()
