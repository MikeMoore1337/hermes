"""Native Windows owner-specified path approval gates (#454/#455)."""
import unittest

from control_center.native_windows_policy import (
    READ_ROOTS, APPROVAL_ACTIONS, READ_ACTIONS,
    classify_native_request, has_native_windows_access,
)


class NativeWindowsPolicyTests(unittest.TestCase):
    def test_four_exact_owner_approved_roots_read_policy_not_runtime(self):
        self.assertEqual(len(READ_ROOTS), 4)
        for project, root in READ_ROOTS.items():
            with self.subTest(project=project):
                for operation in READ_ACTIONS:
                    value = classify_native_request(root, operation)
                    self.assertEqual(value.project, project)
                    self.assertEqual(value.status, "read_policy_approved")
                    self.assertFalse(value.transport_ready)
                child = classify_native_request(root + r"\src\app.py", "read")
                self.assertEqual(child.status, "read_policy_approved")
                self.assertEqual(child.project, project)
        self.assertFalse(has_native_windows_access())

    def test_every_write_or_execution_requires_separate_explicit_approval(self):
        for project, root in READ_ROOTS.items():
            for operation in APPROVAL_ACTIONS:
                with self.subTest(project=project, operation=operation):
                    result = classify_native_request(root + r"\README.md", operation)
                    self.assertEqual(result.status, "owner_approval_required")
                    self.assertFalse(result.transport_ready)
                    self.assertIn("describe_exact_change", result.reason)

    def test_scoped_path_boundary_denies_siblings_parents_and_drives(self):
        blocked = [
            "D:\\", "C:\\", r"D:\Pet-projects",
            r"D:\Pet-projects\second-brain-workspace",
            r"D:\Pet-projects\second-brain-workspace\vault",
            r"D:\Pet-projects\hermes-tmp\file.txt",
            r"D:\Pet-projects\your-fitness-coach2",
            r"D:\Pet-projects\AI-development-toolkit-backup",
            r"D:\Users\Mike\.ssh\id_ed25519",
            r"C:\Windows\System32\drivers\etc\hosts",
        ]
        for path in blocked:
            with self.subTest(path=path):
                self.assertEqual(classify_native_request(path, "read").status, "denied")

    def test_unsafe_windows_paths_fail_closed(self):
        invalid = [
            "", None, ".", r"..\x", r"D:Pet-projects\hermes",
            "D:/Pet-projects/hermes",
            r"\\server\share\repo",
            r"\\?\D:\Pet-projects\hermes",
            "D:\\Pet-projects\\hermes\\..\\private",
            "D:\\Pet-projects\\hermes\\.\\README.md",
            "D:\\Pet-projects\\hermes\\a\\\\b",
            "D:\\Pet-projects\\hermes\\file.txt:stream",
            "D:\\Pet-projects\\hermes\\file. ",
            "D:\\Pet-projects\\hermes\\file\x00.txt",
            "D:\\Pet-projects\\hermes\\CON",
            "D:\\Pet-projects\\hermes\\file\n.txt",
            "D:\\Pet-projects\\hermes\\" + "a" * 1100,
        ]
        for path in invalid:
            with self.subTest(path=path):
                self.assertEqual(classify_native_request(path, "read").status, "denied")

    def test_private_vault_and_secret_paths_excluded_even_inside_root(self):
        root = READ_ROOTS["second-brain"]
        for suffix in (
            r"\vault\private.md", r"\.vault\secrets.md",
            r"\.ssh\id_rsa", r"\secrets\password.txt",
            r"\config\.env", r"\config\.env.prod",
            r"\config\private.key", r"\archive\backup.kdbx",
        ):
            with self.subTest(path=suffix):
                for operation in ("read", "write", "execute"):
                    decision = classify_native_request(root + suffix, operation)
                    self.assertEqual(decision.status, "denied")
                    self.assertEqual(decision.reason, "private_path_excluded")

    def test_casefold_only_and_unknown_operations(self):
        root = READ_ROOTS["hermes"].upper()
        self.assertEqual(classify_native_request(root, "read").status,
                         "read_policy_approved")
        self.assertEqual(classify_native_request(root, "execute").status,
                         "owner_approval_required")
        for operation in ("git", "run", "shell", "read_and_write", "", None):
            with self.subTest(operation=operation):
                self.assertEqual(classify_native_request(root, operation).status,
                                 "denied")

    def test_input_cannot_self_approve_actions(self):
        root = READ_ROOTS["hermes"]
        with self.assertRaises(TypeError):
            classify_native_request(root, "write", approved=True)
        self.assertEqual(classify_native_request(root, "write").status,
                         "owner_approval_required")


if __name__ == "__main__":
    unittest.main()
