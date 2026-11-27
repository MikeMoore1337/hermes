import os
import struct
import unittest
import ctypes
from pathlib import Path
import tempfile
import time

from device_fabric.windows_appcontainer_terminal import TerminalDenied
from device_fabric.windows_personal_psec_terminal import SyntheticPsecTerminal, build_spec


class PsecSpecificationTests(unittest.TestCase):
    def test_unicode_path_is_encoded_in_version_one_writable_policy(self):
        root = "D:\\projects\\Тест"
        data = build_spec(root)
        table, tag = struct.unpack_from("<I4s", data)
        self.assertEqual(tag, b"PSEC")
        self.assertEqual(struct.unpack_from("<HH", data, table + 4), (1, 0))
        pointer = table + 8
        vector = pointer + struct.unpack_from("<I", data, pointer)[0]
        self.assertEqual(struct.unpack_from("<I", data, vector)[0], 1)
        string_pointer = vector + 4
        string = string_pointer + struct.unpack_from("<I", data, string_pointer)[0]
        length = struct.unpack_from("<I", data, string)[0]
        self.assertEqual(data[string + 4:string + 4 + length].decode("utf-8"), root)

    def test_invalid_paths_are_rejected_before_launch(self):
        for root in ("D:\\", r"D:relative", r"\\server\share", r"D:\safe\..\elsewhere",
                     r"D:\safe\file:stream", r"D:\safe\*.py", "D:\\bad\ud800"):
            with self.subTest(root=root), self.assertRaises(TerminalDenied):
                build_spec(root)

    def test_project_state_and_readonly_runtime_are_separate_policy_roots(self):
        root, state, runtime = r"D:\fixture\project", r"D:\fixture\state", r"D:\fixture\runtime"
        data = build_spec(root, writable=(state,), readonly=(runtime,))
        table = struct.unpack_from("<I", data)[0]
        def vector(field):
            pointer = table + field
            offset = pointer + struct.unpack_from("<I", data, pointer)[0]
            count = struct.unpack_from("<I", data, offset)[0]
            values = []
            for index in range(count):
                slot = offset + 4 + index * 4
                pos = slot + struct.unpack_from("<I", data, slot)[0]
                length = struct.unpack_from("<I", data, pos)[0]
                values.append(data[pos + 4:pos + 4 + length].decode("utf-8"))
            return values
        self.assertEqual(vector(8), [root, state])
        self.assertEqual(vector(12), [runtime])
        for kw in ({"readonly": (root,)}, {"readonly": (root + r"\child",)},
                   {"writable": (r"D:\fixture",)}, {"writable": (state,), "readonly": (state,)}):
            with self.subTest(kw=kw), self.assertRaises(TerminalDenied):
                build_spec(root, **kw)

    def test_denied_child_is_encoded_and_other_paths_are_rejected(self):
        root = r'D:\fixture\project'
        data = build_spec(root, denied=(root + r'\.artifacts',))
        table = struct.unpack_from('<I', data)[0]
        pointer = table + 16
        vector = pointer + struct.unpack_from('<I', data, pointer)[0]
        self.assertEqual(struct.unpack_from('<I', data, vector)[0], 1)
        slot = vector + 4
        string = slot + struct.unpack_from('<I', data, slot)[0]
        length = struct.unpack_from('<I', data, string)[0]
        self.assertEqual(data[string + 4:string + 4 + length].decode(), root + r'\.artifacts')
        for value in (root, r'D:\another\child', root + r'\..\other', root + r'\bad*'):
            with self.subTest(value=value), self.assertRaises(TerminalDenied):
                build_spec(root, denied=(value,))

    if os.name == "nt":
        def test_native_denied_child_is_not_readable_in_a_writable_root(self):
            try:
                model = ctypes.WinDLL('processmodel', use_last_error=True, winmode=0x800)
                query = model.QueryProcessSecurityEnvironmentSupport
                query.argtypes = [ctypes.POINTER(ctypes.c_ulong)]
                query.restype = ctypes.c_long
                flags = ctypes.c_ulong()
                if query(ctypes.byref(flags)) != 0 or not flags.value & 1:
                    self.skipTest('PSEC deny paths unavailable')
            except (OSError, AttributeError):
                self.skipTest('PSEC deny paths unavailable')
            with tempfile.TemporaryDirectory(prefix='h454-psec-synthetic-') as directory:
                root = Path(directory) / 'project'
                denied = root / '.artifacts'
                denied.mkdir(parents=True)
                secret = denied / 'fixture.txt'
                secret.write_text('fixture', encoding='ascii')
                result = root / 'ok.txt'
                command = f'type "{secret}" >nul 2>&1 && exit /b 9 || (echo ok>"{result}")'
                terminal = SyntheticPsecTerminal(str(root), command=command, denied=(str(denied),))
                try:
                    deadline = time.monotonic() + 15
                    while terminal.poll() is None and time.monotonic() < deadline:
                        terminal.read()
                        time.sleep(0.02)
                    self.assertEqual(terminal.poll(), 0)
                    self.assertTrue(result.is_file())
                    self.assertEqual(secret.read_text(), 'fixture')
                finally:
                    terminal.close()

        def test_native_deny_remains_effective_for_a_missing_child(self):
            try:
                model = ctypes.WinDLL('processmodel', use_last_error=True, winmode=0x800)
                query = model.QueryProcessSecurityEnvironmentSupport
                query.argtypes = [ctypes.POINTER(ctypes.c_ulong)]
                query.restype = ctypes.c_long
                flags = ctypes.c_ulong()
                if query(ctypes.byref(flags)) != 0 or not flags.value & 1:
                    self.skipTest('PSEC deny paths unavailable')
            except (OSError, AttributeError):
                self.skipTest('PSEC deny paths unavailable')
            with tempfile.TemporaryDirectory(prefix='h454-psec-synthetic-') as directory:
                root = Path(directory) / 'project'
                root.mkdir()
                denied = root / '.artifacts'
                result = root / 'ok.txt'
                command = f'mkdir "{denied}" >nul 2>&1 && exit /b 9 || (echo ok>"{result}")'
                terminal = SyntheticPsecTerminal(str(root), command=command, denied=(str(denied),))
                try:
                    deadline = time.monotonic() + 15
                    while terminal.poll() is None and time.monotonic() < deadline:
                        terminal.read()
                        time.sleep(0.02)
                    self.assertEqual(terminal.poll(), 0)
                    self.assertTrue(result.is_file())
                    self.assertFalse(denied.exists())
                finally:
                    terminal.close()

        def test_original_project_cannot_be_used_as_a_synthetic_fixture(self):
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            with self.assertRaises(TerminalDenied):
                SyntheticPsecTerminal(root, command="exit /b 0")


if __name__ == "__main__":
    unittest.main()
