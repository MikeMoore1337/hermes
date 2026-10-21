"""H15 Codex integration and isolated project workspace installation (source-only)."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CODEX = (ROOT / 'deploy/h15/codex-hermes-mcp.ps1').read_text(encoding='utf-8-sig')
WORK = (ROOT / 'deploy/h15/windows-project-workspaces.ps1').read_text(encoding='utf-8-sig')


class CodexBrcMcpTests(unittest.TestCase):
    def test_exact_public_oauth_mcp_and_official_cli(self):
        self.assertIn('https://mcp.mikemoore.top/mcp', CODEX)
        self.assertIn('mcp add $ServerName --url $ServerUrl', CODEX)
        self.assertIn('mcp login $ServerName', CODEX)

    def test_preserve_global_config(self):
        self.assertIn('config.toml', CODEX)
        self.assertIn('Copy-Item -LiteralPath $ConfigPath -Destination $backup', CODEX)
        self.assertIn('CONFIG_BACKUP_HASH_MISMATCH', CODEX)
        self.assertIn('ALREADY_PRESENT_NO_CHANGE', CODEX)
        self.assertNotIn('Remove-Item -LiteralPath $ConfigPath', CODEX)
        self.assertIn('CODEX_HOME_LINK', CODEX)
        self.assertIn('CODEX_CONFIG_NOT_REGULAR', CODEX)
        self.assertIn('EXISTING_HERMES_URL_MISMATCH', CODEX)
        self.assertIn('Assert-HermesEndpoint', CODEX)

    def test_explicit_oauth_user_action(self):
        self.assertIn("'Login' {", CODEX)
        self.assertIn('OAUTH=REQUIRES_INTERACTIVE_LOGIN', CODEX)
        self.assertNotIn('OPENAI_API_KEY', CODEX)


class WindowsWorkspaceTests(unittest.TestCase):
    def test_mount_only_previously_approved_workspace(self):
        self.assertIn("Join-Path $HOME 'Hermes-H15-Test'", WORK)
        self.assertIn("Join-Path $MountHostRoot 'projects'", WORK)
        self.assertIn('BRC_CONTAINER_PROJECTS=/workspace/projects', WORK)
        self.assertIn('UNTRUSTED_DIRECTORY_OR_REPARSE_POINT', WORK)
        self.assertNotIn('docker.exe run', WORK)

    def test_allowlist_explicit_public_repositories(self):
        for name in ('hermes', 'your-fitness-coach', 'second-brain', 'ai-development-toolkit'):
            self.assertIn("'" + name + "'", WORK)
        self.assertIn('https://github.com/MikeMoore1337/', WORK)
        self.assertIn('EXISTING_REPOSITORY_ORIGIN_MISMATCH', WORK)
        self.assertIn('EXISTING_REPOSITORY_BRANCH_MISMATCH', WORK)

    def test_no_destructive_repo_operations(self):
        self.assertIn('ALREADY_PRESENT_NO_OVERWRITE', WORK)
        self.assertIn('DESTINATION_CREATED_CONCURRENTLY', WORK)
        self.assertIn('PUBLIC_CLONE_FAILED', WORK)
        self.assertIn("'--depth','1'", WORK)
        self.assertNotIn('reset --hard', WORK)
        self.assertNotIn('Remove-Item -Recurse', WORK)

    def test_second_brain_private_vault_excluded(self):
        self.assertIn('private Second Brain vault', WORK)
        self.assertIn('not syncs of uncommitted local changes', WORK)


if __name__ == '__main__':
    unittest.main()
