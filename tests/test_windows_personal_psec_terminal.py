import os
import struct
import unittest

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

    if os.name == "nt":
        def test_original_project_cannot_be_used_as_a_synthetic_fixture(self):
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            with self.assertRaises(TerminalDenied):
                SyntheticPsecTerminal(root, command="exit /b 0")


if __name__ == "__main__":
    unittest.main()
