import struct
import unittest
import os

from device_fabric.windows_personal_bfs_process import BfsProcess, BfsProcessDenied, build_spec


def read_string(data, pointer):
    offset = pointer + struct.unpack_from("<I", data, pointer)[0]
    length = struct.unpack_from("<I", data, offset)[0]
    return data[offset + 4:offset + 4 + length].decode("utf-8")


class BfsSpecificationTests(unittest.TestCase):
    def test_one_project_and_unicode_project_keep_their_paths(self):
        paths = [r"D:\projects\one", "D:\\projects\\Тест"]
        data = build_spec(paths)
        root, identifier = struct.unpack_from("<I4s", data, 0)
        self.assertEqual(identifier, b"SBOX")
        self.assertEqual(read_string(data, root + 4), "0.1.0")
        self.assertEqual(data[root + 8], 1)
        pointer = root + 12
        vector = pointer + struct.unpack_from("<I", data, pointer)[0]
        self.assertEqual(struct.unpack_from("<I", data, vector)[0], 2)
        self.assertEqual([read_string(data, vector + 4 + 4 * i) for i in range(2)], paths)

    def test_rejects_relative_root_duplicate_and_device_paths(self):
        for paths in ([], ["D:\\"], [r"D:relative"], [r"\\server\share"],
                      [r"D:\safe\..\outside"], [r"D:\safe", r"d:\SAFE"],
                      [r"D:\safe\file:stream"], [r"D:\safe\*.py"], ["D:\\bad\ud800"], [r"D:\x"] * 9):
            with self.subTest(paths=paths), self.assertRaises(BfsProcessDenied):
                build_spec(paths)

    @unittest.skipUnless(os.name == "nt", "Windows path semantics required")
    def test_original_project_is_not_a_synthetic_fixture(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with self.assertRaises(BfsProcessDenied):
            BfsProcess([root], root, "exit /b 0")


if __name__ == "__main__":
    unittest.main()
