"""Tests for atomic apply, diff, verify, restore, permissions, lstat symlink safety, and .git/info/exclude."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import time
import tomllib
import unittest
from pathlib import Path

from lib.paths import SafetyError, atomic_write_bytes, file_mode, safe_target
from tests.helpers import IsolatedEnvMixin, copy_repo_fixture, init_git_repo, run_agentcfg


class DeployApplyVerifyRestoreTests(IsolatedEnvMixin, unittest.TestCase):
    def _seed_existing_configs(self) -> None:
        # Claude Code ~/.claude/settings.json with unrelated user key and allow rule.
        claude_dir = self.home_dir / ".claude"
        claude_dir.mkdir(mode=0o700, exist_ok=True)
        (claude_dir / "settings.json").write_text(
            json.dumps(
                {
                    "customUserTheme": "solarized",
                    "permissions": {
                        "allow": ["Read(./**)"],
                        "deny": ["Read(~/.old/**)"],
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        os.chmod(claude_dir / "settings.json", 0o600)

        # ~/.claude.json with unrelated runtime state.
        (self.home_dir / ".claude.json").write_text(
            json.dumps({"numStartups": 42, "projects": {"/tmp/demo": {"hasTrustDialogAccepted": True}}}, indent=2),
            encoding="utf-8",
        )
        os.chmod(self.home_dir / ".claude.json", 0o600)

        # Codex ~/.codex/config.toml with unrelated key + stale managed key.
        codex_dir = self.home_dir / ".codex"
        codex_dir.mkdir(mode=0o700, exist_ok=True)
        (codex_dir / "config.toml").write_text(
            'model = "gpt-5"\n'
            'approval_policy = "never"\n',
            encoding="utf-8",
        )
        os.chmod(codex_dir / "config.toml", 0o600)

        # Antigravity CLI ~/.gemini/antigravity-cli/settings.json with active user preferences.
        agy_dir = self.home_dir / ".gemini" / "antigravity-cli"
        agy_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        (agy_dir / "settings.json").write_text(
            json.dumps({"agentMode": "auto", "toolPermission": "default", "model": "gemini-pro"}, indent=2),
            encoding="utf-8",
        )
        os.chmod(agy_dir / "settings.json", 0o600)

    def test_apply_permissions_patching_git_exclude_diff_verify_restore(self) -> None:
        self._seed_existing_configs()
        proj = init_git_repo(self.tmp_path / "demo-project")

        # 1. Atomic apply across global + project targets.
        proc = run_agentcfg(
            "apply",
            "--safe",
            "--json",
            home=self.home_dir,
            state_dir=self.state_dir,
            project=proj,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        res = json.loads(proc.stdout)
        self.assertTrue(res["ok"], msg=res)
        self.assertIn("project-agents-rule", res["applied_ids"])
        self.assertIn("project-agents-skills", res["applied_ids"])

        # 2. Verify deployed-manifest.json and target POSIX permissions.
        manifest_path = self.state_dir / "deployed-manifest.json"
        self.assertTrue(manifest_path.is_file())
        self.assertEqual(file_mode(manifest_path), 0o600)

        self.assertEqual(file_mode(self.home_dir / ".codex" / "AGENTS.md"), 0o444)
        self.assertEqual(file_mode(self.home_dir / ".claude" / "CLAUDE.md"), 0o444)
        self.assertEqual(file_mode(self.home_dir / ".claude" / "settings.json"), 0o600)
        self.assertEqual(file_mode(self.home_dir / ".codex" / "config.toml"), 0o600)
        self.assertEqual(file_mode(self.home_dir / ".gemini" / "config" / "plugins" / "agentconfig-core"), 0o700)
        self.assertEqual(
            file_mode(self.home_dir / ".gemini" / "config" / "plugins" / "agentconfig-core" / "plugin.json"),
            0o444,
        )

        # Verify atomic_write_bytes supports strict 0400 declarative targets as well.
        strict_file = self.tmp_path / "strict-0400.json"
        atomic_write_bytes(strict_file, b'{"ok":true}\n', mode=0o400, boundary_root=self.tmp_path)
        self.assertEqual(file_mode(strict_file), 0o400)

        # 3. Verify patch-managed-keys preserved unrelated keys & removed deprecated keys.
        claude_cfg = json.loads((self.home_dir / ".claude" / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(claude_cfg["customUserTheme"], "solarized")
        self.assertEqual(claude_cfg["permissions"]["allow"], ["Read(./**)"])
        self.assertFalse(claude_cfg["enableAllProjectMcpServers"])
        self.assertFalse(claude_cfg["autoMemoryEnabled"])

        claude_user = json.loads((self.home_dir / ".claude.json").read_text(encoding="utf-8"))
        self.assertEqual(claude_user["numStartups"], 42)
        self.assertIn("/tmp/demo", claude_user["projects"])

        codex_cfg = tomllib.loads((self.home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
        self.assertEqual(codex_cfg["model"], "gpt-5")
        self.assertNotIn("profile", codex_cfg)
        self.assertNotIn("profiles", codex_cfg)
        self.assertEqual(codex_cfg["approval_policy"], "on-request")
        self.assertEqual(codex_cfg["sandbox_mode"], "read-only")

        agy_cfg = json.loads((self.home_dir / ".gemini" / "antigravity-cli" / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(agy_cfg["agentMode"], "auto")
        self.assertEqual(agy_cfg["model"], "gemini-pro")

        # 4. Verify project .agents/ deployed and wired via .git/info/exclude (not .gitignore).
        self.assertTrue((proj / ".agents" / "rules" / "core.md").is_file())
        self.assertTrue((proj / ".agents" / "skills" / "agent-hygiene" / "SKILL.md").is_file())
        exclude_lines = (proj / ".git" / "info" / "exclude").read_text(encoding="utf-8").splitlines()
        self.assertIn(".agents/", exclude_lines)
        self.assertFalse((proj / ".gitignore").exists())
        git_status = subprocess.run(["git", "status", "--porcelain"], cwd=proj, capture_output=True, text=True, check=True)
        self.assertEqual(git_status.stdout.strip(), "")

        # 5. diff reports no changes and verify passes.
        diff_clean = run_agentcfg("diff", "--json", home=self.home_dir, state_dir=self.state_dir, project=proj)
        self.assertEqual(diff_clean.returncode, 0, msg=diff_clean.stderr)
        self.assertFalse(json.loads(diff_clean.stdout)["has_changes"])

        verify_ok = run_agentcfg("verify", "--json", home=self.home_dir, state_dir=self.state_dir, project=proj)
        self.assertEqual(verify_ok.returncode, 0, msg=verify_ok.stdout)
        self.assertTrue(json.loads(verify_ok.stdout)["ok"])

        # Changing an unmanaged key in patch-managed-keys keeps verify passing.
        claude_cfg["unmanagedNote"] = "still-valid"
        (self.home_dir / ".claude" / "settings.json").write_text(json.dumps(claude_cfg, indent=2), encoding="utf-8")
        verify_unmanaged = run_agentcfg("verify", "--json", home=self.home_dir, state_dir=self.state_dir, project=proj)
        self.assertEqual(verify_unmanaged.returncode, 0, msg=verify_unmanaged.stdout)

        # 6. Drift on ro target & managed subtree triggers diff + verify failure, and restore fixes both.
        codex_rules = self.home_dir / ".codex" / "AGENTS.md"
        orig_rules = codex_rules.read_bytes()
        os.chmod(codex_rules, 0o600)
        codex_rules.write_text("# Drifted Rule\n", encoding="utf-8")
        os.chmod(codex_rules, 0o444)

        claude_cfg["enableAllProjectMcpServers"] = True
        (self.home_dir / ".claude" / "settings.json").write_text(json.dumps(claude_cfg, indent=2), encoding="utf-8")
        os.chmod(self.home_dir / ".claude" / "settings.json", 0o644)

        diff_drift = run_agentcfg("diff", "--json", home=self.home_dir, state_dir=self.state_dir, project=proj)
        self.assertTrue(json.loads(diff_drift.stdout)["has_changes"])

        verify_fail = run_agentcfg("verify", "--json", home=self.home_dir, state_dir=self.state_dir, project=proj)
        self.assertEqual(verify_fail.returncode, 1)
        vdata = json.loads(verify_fail.stdout)
        self.assertFalse(vdata["ok"])
        issue_texts = [i["issue"] for i in vdata["issues"]]
        self.assertIn("sha256 drift", issue_texts)
        self.assertIn("managed subtree sha256 drift", issue_texts)
        self.assertIn("mode 0644 != 0600", issue_texts)

        # Re-apply a second snapshot? No: restore latest snapshot (which holds pre-apply state? Wait!).
        # Note: apply created snapshot of pre-apply state! So let's verify restoring a post-apply snapshot
        # via failsafe --apply -> failsafe --restore AND via direct apply snapshot rollback.
        # First restore restores pre-apply state:
        restore_pre = run_agentcfg("restore", "--json", home=self.home_dir, state_dir=self.state_dir, project=proj)
        self.assertEqual(restore_pre.returncode, 0, msg=restore_pre.stdout + restore_pre.stderr)
        # Re-apply cleanly, take failsafe snapshot, drift, and restore!
        reapply = run_agentcfg(
            "apply",
            "--safe",
            "--approve-drift",
            "--grok-flavor",
            "xai",
            "--json",
            home=self.home_dir,
            state_dir=self.state_dir,
            project=proj,
        )
        self.assertEqual(reapply.returncode, 0, msg=reapply.stdout + reapply.stderr)
        fs_apply = run_agentcfg("failsafe", "--apply", "--json", home=self.home_dir, state_dir=self.state_dir, project=proj)
        self.assertEqual(fs_apply.returncode, 0, msg=fs_apply.stdout + fs_apply.stderr)
        fs_snap_id = json.loads(fs_apply.stdout)["snapshot_id"]

        # Confirm failsafe switched Antigravity settings & Claude settings to plan/safe-mode.
        agy_fs = json.loads((self.home_dir / ".gemini" / "antigravity-cli" / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(agy_fs["agentMode"], "plan")
        self.assertEqual(agy_fs["toolPermission"], "request-review")

        # Restore from failsafe snapshot and confirm original rendered state + verify OK.
        fs_rest = run_agentcfg("failsafe", "--restore", "--json", home=self.home_dir, state_dir=self.state_dir, project=proj)
        self.assertEqual(fs_rest.returncode, 0, msg=fs_rest.stdout + fs_rest.stderr)
        self.assertEqual(codex_rules.read_bytes(), orig_rules)
        self.assertEqual(file_mode(codex_rules), 0o444)
        agy_restored = json.loads((self.home_dir / ".gemini" / "antigravity-cli" / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(agy_restored["agentMode"], "auto")

        verify_restored = run_agentcfg("verify", "--json", home=self.home_dir, state_dir=self.state_dir, project=proj)
        self.assertEqual(verify_restored.returncode, 0, msg=verify_restored.stdout)

        # Also verify explicit --snapshot restore works after drifting.
        os.chmod(codex_rules, 0o600)
        codex_rules.write_text("# Tampered\n", encoding="utf-8")
        explicit_rest = run_agentcfg(
            "restore",
            "--snapshot",
            fs_snap_id,
            "--json",
            home=self.home_dir,
            state_dir=self.state_dir,
            project=proj,
        )
        self.assertEqual(explicit_rest.returncode, 0, msg=explicit_rest.stdout + explicit_rest.stderr)
        self.assertEqual(codex_rules.read_bytes(), orig_rules)
        self.assertEqual(run_agentcfg("verify", "--json", home=self.home_dir, state_dir=self.state_dir, project=proj).returncode, 0)

    def test_lstat_symlink_traversal_rejection(self) -> None:
        outside = self.tmp_path / "outside"
        outside.mkdir(mode=0o700)
        canary = outside / "AGENTS.md"
        canary.write_text("DO_NOT_OVERWRITE\n", encoding="utf-8")

        # Direct safe_target unit checks.
        with self.assertRaises(SafetyError):
            safe_target(self.home_dir / ".." / "escape.txt", boundary_root=self.home_dir)

        link_parent = self.home_dir / ".codex"
        os.symlink(outside, link_parent)
        with self.assertRaises(SafetyError):
            safe_target(link_parent / "AGENTS.md", boundary_root=self.home_dir)

        # Full CLI apply must reject symlinked ~/.codex and leave outside canary intact.
        proc = run_agentcfg("apply", "--safe", "--json", home=self.home_dir, state_dir=self.state_dir)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Symlink", proc.stdout + proc.stderr)
        self.assertEqual(canary.read_text(encoding="utf-8"), "DO_NOT_OVERWRITE\n")

        # Also test symlinked leaf target file inside real directory.
        link_parent.unlink()
        link_parent.mkdir(mode=0o700)
        os.symlink(canary, link_parent / "AGENTS.md")
        proc_leaf = run_agentcfg("apply", "--safe", "--json", home=self.home_dir, state_dir=self.state_dir)
        self.assertNotEqual(proc_leaf.returncode, 0)
        self.assertEqual(canary.read_text(encoding="utf-8"), "DO_NOT_OVERWRITE\n")

    def test_apply_flock_contention_and_require_signed(self) -> None:
        # Hold exclusive flock on state_dir/runtime/agentcfg.lock in a child process.
        rt_dir = self.state_dir / "runtime"
        rt_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        lock_file = rt_dir / "agentcfg.lock"
        holder_code = (
            "import fcntl, os, sys, time\n"
            "fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "print('LOCKED', flush=True)\n"
            "time.sleep(30)\n"
        )
        holder = subprocess.Popen(
            ["python3", "-c", holder_code, str(lock_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert holder.stdout is not None
            line = holder.stdout.readline().strip()
            self.assertEqual(line, "LOCKED")
            proc = run_agentcfg("apply", "--json", home=self.home_dir, state_dir=self.state_dir)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("lock", (proc.stdout + proc.stderr).lower())
        finally:
            holder.terminate()
            holder.wait(timeout=5)
            if holder.stdout:
                holder.stdout.close()
            if holder.stderr:
                holder.stderr.close()

        # --require-signed rejects unsigned temp git repo, accepts SSH-signed temp git repo.
        repo = init_git_repo(copy_repo_fixture(self.tmp_path / "signed-repo"))
        unsigned_proc = run_agentcfg(
            "apply",
            "--require-signed",
            "--json",
            home=self.home_dir,
            state_dir=self.state_dir,
            repo=repo,
        )
        self.assertNotEqual(unsigned_proc.returncode, 0)

        # Sign commit with ephemeral ssh key inside tmp_path (never touching ~/.ssh).
        key_path = self.tmp_path / "test_signing_key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)],
            check=True,
        )
        allowed = self.tmp_path / "allowed_signers"
        pub = Path(str(key_path) + ".pub").read_text(encoding="utf-8").strip()
        allowed.write_text(f"test@agentconfig.local {pub}\n", encoding="utf-8")
        subprocess.run(["git", "config", "gpg.format", "ssh"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.signingkey", str(key_path)], cwd=repo, check=True)
        subprocess.run(["git", "config", "gpg.ssh.allowedSignersFile", str(allowed)], cwd=repo, check=True)
        subprocess.run(["git", "config", "commit.gpgsign", "true"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "--allow-empty", "-S", "-q", "-m", "signed"], cwd=repo, check=True)

        signed_proc = run_agentcfg(
            "apply",
            "--require-signed",
            "--json",
            home=self.home_dir,
            state_dir=self.state_dir,
            repo=repo,
        )
        self.assertEqual(signed_proc.returncode, 0, msg=signed_proc.stdout + signed_proc.stderr)
        self.assertEqual(json.loads(signed_proc.stdout)["git_sig"], "HEAD signature verified")

    def test_patch_managed_keys_strips_deprecated_keys_while_preserving_unrelated(self) -> None:
        codex_dir = self.home_dir / ".codex"
        codex_dir.mkdir(mode=0o700, exist_ok=True)
        (codex_dir / "config.toml").write_text(
            'model = "gpt-5"\n'
            'profile = "legacy"\n\n'
            '[profiles.legacy]\n'
            'sandbox_mode = "read-only"\n',
            encoding="utf-8",
        )
        os.chmod(codex_dir / "config.toml", 0o600)

        proc = run_agentcfg("apply", "--json", home=self.home_dir, state_dir=self.state_dir)
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        codex_cfg = tomllib.loads((codex_dir / "config.toml").read_text(encoding="utf-8"))
        self.assertEqual(codex_cfg["model"], "gpt-5")
        self.assertNotIn("profile", codex_cfg)
        self.assertNotIn("profiles", codex_cfg)
        self.assertEqual(codex_cfg["approval_policy"], "on-request")
        self.assertEqual(run_agentcfg("verify", "--json", home=self.home_dir, state_dir=self.state_dir).returncode, 0)


if __name__ == "__main__":
    unittest.main()
