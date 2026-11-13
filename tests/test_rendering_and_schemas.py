"""Tests for canonical rendering across all 5 MCP schemas, failsafe profiles, and agy plugin validation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tomllib
import unittest
from pathlib import Path

from lib.formats import (
    dump_json,
    dump_toml,
    dump_yaml,
    parse_by_format,
    parse_jsonc,
    parse_yaml_frontmatter,
    parse_yaml_subset,
)
from lib.paths import RuntimeContext
from lib.render import (
    load_mcp_registry,
    load_targets_manifest,
    render_antigravity_plugin_bundle_files,
    render_mcp_for_harness,
    render_target,
)
from tests.helpers import IsolatedEnvMixin, REPO_ROOT, run_agentcfg


EXPECTED_HARNESSES = {
    "antigravity",
    "gemini-cli",
    "codex",
    "claude-code",
    "copilot",
    "kimi-code",
    "grok",
    "opencode",
    "cursor",
    "devin",
    "cline",
    "goose",
    "aider",
}


class RenderingAndSchemaTests(IsolatedEnvMixin, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.ctx = RuntimeContext.from_args(
            repo=REPO_ROOT,
            home=self.home_dir,
            state_dir=self.state_dir,
            project=self.tmp_path / "proj",
        )

    def test_renders_all_five_mcp_root_schemas_from_canonical_registry(self) -> None:
        reg = load_mcp_registry(REPO_ROOT)

        # 1. mcpServers (Antigravity, Claude, Gemini, Copilot CLI, Kimi, Cursor, Devin, Cline, Grok-Vibekit)
        for h in ("antigravity", "claude-code", "gemini-cli", "copilot", "kimi-code", "cursor", "devin", "cline", "grok-vibekit"):
            doc = render_mcp_for_harness(reg, h, REPO_ROOT, include_disabled=True)
            self.assertIn("mcpServers", doc, msg=f"missing mcpServers for {h}")
            parsed = json.loads(dump_json(doc))
            self.assertEqual(parsed, doc)

        # Verify specific HTTP transport dialects.
        gem_doc = render_mcp_for_harness(reg, "gemini-cli", REPO_ROOT, include_disabled=True)
        self.assertEqual(gem_doc["mcpServers"]["github-remote"]["httpUrl"], "https://api.githubcopilot.com/mcp/")
        cline_doc = render_mcp_for_harness(reg, "cline", REPO_ROOT, include_disabled=True)
        self.assertEqual(cline_doc["mcpServers"]["github-remote"]["type"], "streamableHttp")
        devin_doc = render_mcp_for_harness(reg, "devin", REPO_ROOT, include_disabled=True)
        self.assertEqual(devin_doc["mcpServers"]["github-remote"]["transport"], "http")
        kimi_doc = render_mcp_for_harness(reg, "kimi-code", REPO_ROOT, include_disabled=True)
        self.assertEqual(kimi_doc["mcpServers"]["github-remote"]["bearerTokenEnvVar"], "GITHUB_MCP_TOKEN")

        # 2. servers + inputs (VS Code & JetBrains Copilot)
        for h in ("vscode-copilot", "jetbrains-copilot"):
            vdoc = render_mcp_for_harness(reg, h, REPO_ROOT, include_disabled=True)
            self.assertIn("servers", vdoc)
            self.assertIn("inputs", vdoc)
            self.assertIn("git-ro", vdoc["servers"])
            self.assertEqual(vdoc["servers"]["github-remote"]["type"], "http")

        # 3. mcp.servers (OpenCode V2 JSONC)
        oc_doc = render_mcp_for_harness(reg, "opencode", REPO_ROOT, include_disabled=True)
        self.assertIn("mcp", oc_doc)
        self.assertIn("servers", oc_doc["mcp"])
        self.assertEqual(oc_doc["mcp"]["servers"]["git-ro"]["type"], "local")
        self.assertIsInstance(oc_doc["mcp"]["servers"]["git-ro"]["command"], list)
        self.assertEqual(oc_doc["mcp"]["servers"]["github-remote"]["type"], "remote")
        oc_roundtrip = parse_jsonc(dump_json(oc_doc))
        self.assertEqual(oc_roundtrip, oc_doc)

        # 4. [mcp_servers.*] TOML (Codex, xAI Grok)
        for h in ("codex", "grok"):
            tdoc = render_mcp_for_harness(reg, h, REPO_ROOT, include_disabled=True)
            self.assertIn("mcp_servers", tdoc)
            toml_text = dump_toml(tdoc)
            self.assertIn("[mcp_servers.", toml_text)
            parsed_toml = tomllib.loads(toml_text)
            self.assertEqual(parsed_toml["mcp_servers"]["github-remote"]["bearer_token_env_var"], "GITHUB_MCP_TOKEN")

        # 5. extensions YAML (Goose)
        gdoc = render_mcp_for_harness(reg, "goose", REPO_ROOT, include_disabled=True)
        self.assertIn("extensions", gdoc)
        self.assertEqual(gdoc["extensions"]["git-ro"]["type"], "stdio")
        self.assertEqual(gdoc["extensions"]["github-remote"]["type"], "streamable_http")
        self.assertEqual(gdoc["extensions"]["github-remote"]["uri"], "https://api.githubcopilot.com/mcp/")
        yaml_text = dump_yaml(gdoc)
        parsed_yaml = parse_yaml_subset(yaml_text)
        self.assertEqual(parsed_yaml, gdoc)

        # Aider has no native MCP support.
        self.assertEqual(render_mcp_for_harness(reg, "aider", REPO_ROOT, include_disabled=True), {})

    def test_mcp_secret_exec_wrapping_for_stdio_secret_refs(self) -> None:
        reg = {
            "schema_version": "1.0",
            "servers": {
                "wrapped-srv": {
                    "enabled": True,
                    "transport": "stdio",
                    "command": "/opt/mcp/bin/srv",
                    "args": ["--readonly"],
                    "secret_refs": [{"env_var": "SRV_TOKEN", "secret_ref": "agentconfig/srv_token"}],
                    "wrap_with_secret_exec": True,
                    "unshare_net": True,
                    "targets": ["claude-code", "codex", "opencode", "goose"],
                }
            },
        }
        claude_doc = render_mcp_for_harness(reg, "claude-code", REPO_ROOT)
        entry = claude_doc["mcpServers"]["wrapped-srv"]
        self.assertTrue(entry["command"].endswith("wrappers/mcp-secret-exec"))
        self.assertIn("--secret-ref", entry["args"])
        self.assertIn("SRV_TOKEN=agentconfig/srv_token", entry["args"])
        self.assertIn("--unshare-net", entry["args"])
        self.assertIn("/opt/mcp/bin/srv", entry["args"])

        # Disabled servers omitted unless include_disabled=True.
        reg["servers"]["wrapped-srv"]["enabled"] = False
        self.assertEqual(render_mcp_for_harness(reg, "claude-code", REPO_ROOT)["mcpServers"], {})

    def test_all_13_harness_specs_and_all_targets_render_cleanly(self) -> None:
        harnesses_dir = REPO_ROOT / "canonical" / "harnesses"
        found = {p.stem for p in harnesses_dir.glob("*.json")}
        self.assertEqual(found, EXPECTED_HARNESSES)

        targets = load_targets_manifest(REPO_ROOT)
        self.assertGreaterEqual(len(targets), 20)
        for t in targets:
            with self.subTest(target=t["id"]):
                rt = render_target(t, self.ctx, failsafe=False)
                if rt.files is not None:
                    self.assertGreater(len(rt.files), 0)
                elif rt.patch_data is not None:
                    self.assertIsInstance(rt.patch_data, dict)
                else:
                    self.assertIsNotNone(rt.content)

                # Also verify failsafe render succeeds for every target.
                rt_fs = render_target(t, self.ctx, failsafe=True)
                self.assertEqual(rt_fs.target_id, t["id"])

    def test_all_failsafe_profiles_parse_and_satisfy_zero_trust_invariants(self) -> None:
        fs_root = REPO_ROOT / "canonical" / "profiles" / "failsafe"
        files = sorted(p for p in fs_root.rglob("*") if p.is_file())
        self.assertGreaterEqual(len(files), 18)

        fmt_map = {
            ".json": "json",
            ".jsonc": "jsonc",
            ".toml": "toml",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".md": "markdown",
        }
        for fp in files:
            with self.subTest(file=str(fp.relative_to(fs_root))):
                fmt = fmt_map[fp.suffix.lower()]
                parsed = parse_by_format(fp.read_text(encoding="utf-8"), fmt)
                self.assertIsInstance(parsed, dict)

        # Codex failsafe: top-level keys only, no [profiles.*], no approval_policy="untrusted".
        codex_fs = tomllib.loads((fs_root / "codex" / "failsafe.config.toml").read_text(encoding="utf-8"))
        self.assertEqual(codex_fs["approval_policy"], "on-request")
        self.assertEqual(codex_fs["sandbox_mode"], "read-only")
        self.assertNotIn("profile", codex_fs)
        self.assertNotIn("profiles", codex_fs)
        self.assertFalse(codex_fs["features"]["memories"])
        self.assertEqual(codex_fs["mcp_servers"], {})

        # Claude failsafe.
        claude_fs = json.loads((fs_root / "claude" / "settings.json").read_text(encoding="utf-8"))
        self.assertFalse(claude_fs["autoMemoryEnabled"])
        self.assertFalse(claude_fs["enableAllProjectMcpServers"])
        self.assertTrue(claude_fs["disableAllHooks"])
        self.assertEqual(claude_fs["permissions"]["defaultMode"], "plan")

        # Gemini failsafe settings + save_memory deny policy.
        gemini_fs = json.loads((fs_root / "gemini" / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(gemini_fs["general"]["defaultApprovalMode"], "plan")
        self.assertFalse(gemini_fs["experimental"]["autoMemory"])
        self.assertEqual(gemini_fs["mcpServers"], {})

        gemini_pol = tomllib.loads((fs_root / "gemini" / "policies" / "failsafe.toml").read_text(encoding="utf-8"))
        self.assertTrue(any(r.get("toolName") == "save_memory" and r.get("decision") == "deny" for r in gemini_pol["rule"]))

        # Antigravity failsafe.
        agy_fs = json.loads((fs_root / "antigravity" / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(agy_fs["agentMode"], "plan")
        self.assertEqual(agy_fs["toolPermission"], "request-review")
        agy_mcp = json.loads((fs_root / "antigravity" / "mcp_config.json").read_text(encoding="utf-8"))
        self.assertEqual(agy_mcp["mcpServers"], {})

        # Failsafe rules.md budget & no @ imports.
        fs_rules = (fs_root / "rules.md").read_text(encoding="utf-8")
        self.assertLessEqual(len(fs_rules.encode("utf-8")), 2048)
        self.assertNotIn("@", fs_rules)

    def test_antigravity_plugin_bundle_passes_agy_plugin_validate_strict(self) -> None:
        files = render_antigravity_plugin_bundle_files(REPO_ROOT, failsafe=False)
        self.assertIn("plugin.json", files)
        self.assertIn("hooks.json", files)
        self.assertIn("mcp_config.json", files)
        self.assertIn("rules/core.md", files)
        self.assertIn("skills/agent-hygiene/SKILL.md", files)

        # Verify rules frontmatter trigger: always_on and run_command hook matcher adaptation.
        fm, _ = parse_yaml_frontmatter(files["rules/core.md"].decode("utf-8"))
        self.assertIsNotNone(fm)
        self.assertEqual(fm["trigger"], "always_on")  # type: ignore[index]
        hooks_obj = json.loads(files["hooks.json"].decode("utf-8"))
        self.assertNotIn("hooks", hooks_obj)

        bundle_dir = self.tmp_path / "agentconfig-core"
        for rel, data in files.items():
            dest = bundle_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

        agy_bin = shutil.which("agy") or str(Path.home() / ".local" / "bin" / "agy")
        if Path(agy_bin).is_file():
            env = os.environ.copy()
            env["HOME"] = str(self.home_dir)
            proc = subprocess.run(
                [agy_bin, "plugin", "validate", str(bundle_dir), "--strict", "--json"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report.get("errors", 0), 0, msg=report)
            self.assertEqual(report.get("warnings", 0), 0, msg=report)

    def test_upstream_check_offline_snapshots_pass(self) -> None:
        proc = run_agentcfg("upstream-check", "--json", home=self.home_dir, state_dir=self.state_dir)
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"], msg=data)
        self.assertGreaterEqual(len(data["results"]), 10)


if __name__ == "__main__":
    unittest.main()
