"""Native search continuations keep bounded work and exact, stable results."""
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from device_fabric.native_list_pages import page
from device_fabric.native_search_pages import SearchPageDenied, parse_search_cursor, search_page


class MemoryTree:
    def __init__(self, separator='/'):
        self.separator = separator
        self.directories = {'': []}
        self.files = {}

    def file(self, path, data=b''):
        directory, _, name = path.rpartition(self.separator)
        self.directories[directory].append({'name': name, 'kind': 'file'})
        self.files[path] = data

    def directory(self, path):
        parent, _, name = path.rpartition(self.separator)
        self.directories[parent].append({'name': name, 'kind': 'directory'})
        self.directories[path] = []

    def list(self, path, cursor):
        entries = sorted(self.directories[path], key=lambda e: (e['name'].casefold(), e['name']))
        selected, next_cursor = page(entries, 'hermes', path, cursor)
        return {'entries': selected, 'next_cursor': next_cursor}

    def stat(self, path):
        return {'size_bytes': len(self.files[path])}

    def read(self, path):
        data = self.files[path]
        return {'data': base64.b64encode(data).decode('ascii'), 'size_bytes': len(data),
                'sha256': hashlib.sha256(data).hexdigest()}

    def search(self, query, cursor='', mode='names', root=''):
        return search_page(project='hermes', query=query, mode=mode, relative_root=root,
            cursor=cursor, separator=self.separator, list_dir=self.list,
            stat_file=self.stat, read_file=self.read)


class SearchPagesTests(unittest.TestCase):
    def test_invalid_and_oversized_cursors_are_rejected(self):
        for cursor in (None, 'bad!', 'YWJj', 'x' * 2049):
            with self.subTest(cursor=cursor), self.assertRaises(SearchPageDenied):
                parse_search_cursor(cursor)

    def collect(self, tree, query, mode='names'):
        cursor = ''
        found = []
        pages = 0
        while True:
            result = tree.search(query, cursor, mode)
            self.assertLessEqual(result['entries_scanned'], 512)
            self.assertLessEqual(result['bytes_scanned'], 2 * 1024 * 1024)
            self.assertLessEqual(len(result['matches']), 64)
            self.assertEqual(result['truncated'], bool(result['next_cursor']))
            self.assertFalse(result['incomplete'])
            found.extend(result['matches'])
            pages += 1
            self.assertLess(pages, 100)
            cursor = result['next_cursor']
            if not cursor:
                return found, pages

    def test_more_than_512_files_and_64_matches_across_process_independent_cursors(self):
        for sep in ('/', '\\'):
            with self.subTest(separator=sep):
                tree = MemoryTree(sep)
                for i in range(900):
                    tree.file(f'match-{i:04}.py')
                matches, pages = self.collect(tree, 'match')
                self.assertGreater(pages, 8)
                self.assertEqual(len(matches), 900)
                self.assertEqual(len({row['path'] for row in matches}), 900)

    def test_search_advances_over_empty_result_pages(self):
        tree = MemoryTree()
        for index in range(900):
            tree.file(f'a-{index:04}.py')
        tree.file('z-needle.py')
        matches, pages = self.collect(tree, 'needle')
        self.assertGreater(pages, 1)
        self.assertEqual(matches, [{'path': 'z-needle.py', 'kind': 'file'}])

    def test_nested_directories_and_partial_matching_file_are_resumed(self):
        for sep in ('/', '\\'):
            tree = MemoryTree(sep)
            tree.directory('src')
            tree.file('src' + sep + 'safe.py', b'\n'.join([b'needle'] * 150))
            matches, pages = self.collect(tree, 'needle', mode='content')
            self.assertGreaterEqual(pages, 3)
            self.assertEqual([row['line'] for row in matches], list(range(1, 151)))

    def test_sixty_nested_directories_fit_in_progress_cursor(self):
        tree = MemoryTree()
        current = ''
        for _ in range(60):
            current = current + '/a' if current else 'a'
            tree.directory(current)
        tree.file(current + '/needle.py')
        matches, _ = self.collect(tree, 'needle')
        self.assertEqual(matches, [{'path': current + '/needle.py', 'kind': 'file'}])

    def test_siblings_remain_reachable_across_nested_pages(self):
        tree = MemoryTree()
        tree.directory('a')
        tree.directory('b')
        tree.file('a/needle.py')
        tree.file('b/needle.py')
        tree.file('needle-root.py')
        matches, _ = self.collect(tree, 'needle')
        self.assertEqual({row['path'] for row in matches},
                         {'a/needle.py', 'b/needle.py', 'needle-root.py'})

    def test_changed_directory_query_and_partial_file_fail_closed(self):
        tree = MemoryTree()
        tree.file('safe.py', b'\n'.join([b'needle'] * 150))
        first = tree.search('needle', mode='content')
        cursor = first['next_cursor']
        with self.assertRaises(SearchPageDenied):
            tree.search('different', cursor, mode='content')
        tree.files['safe.py'] = b'changed'
        with self.assertRaises(SearchPageDenied):
            tree.search('needle', cursor, mode='content')
        tree.files['safe.py'] = b'\n'.join([b'needle'] * 150)
        tree.file('added.py')
        with self.assertRaises(SearchPageDenied):
            tree.search('needle', cursor, mode='content')

    def test_oversize_file_is_reported_incomplete_without_hiding_other_matches(self):
        tree = MemoryTree()
        tree.file('large.py', b'x' * (256 * 1024 + 1))
        tree.file('safe.py', b'needle')
        result = tree.search('needle', mode='content')
        self.assertEqual(result['matches'], [{'path':'safe.py', 'line':1}])
        self.assertTrue(result['incomplete'])
        self.assertFalse(result['next_cursor'])

    def test_content_byte_budget_continues_without_skipping_files(self):
        tree = MemoryTree()
        for index in range(3):
            tree.file(f'item-{index}.py', b'x' * (256 * 1024 - 8) + b'needle')
        matches, pages = self.collect(tree, 'needle', mode='content')
        self.assertGreaterEqual(pages, 2)
        self.assertEqual([row['path'] for row in matches], [f'item-{i}.py' for i in range(3)])


@unittest.skipUnless(sys.platform == 'linux', 'Linux handles required')
class RealLinuxSearchPagesTests(unittest.TestCase):
    def test_real_content_search_resumes_inside_one_file(self):
        from device_fabric.linux_native_files import LinuxNativeFiles
        from device_fabric.linux_native_search import LinuxNativeSearch
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'many.py').write_bytes(b'needle\n' * 150)
            with LinuxNativeFiles(root=root, project='hermes') as files:
                cursor = ''
                lines = []
                for _ in range(10):
                    result = LinuxNativeSearch(files).search('needle', mode='content',
                                                            relative_root='', cursor=cursor)
                    lines.extend(row['line'] for row in result['matches'])
                    cursor = result['next_cursor']
                    if not cursor:
                        break
                self.assertEqual(cursor, '')
                self.assertEqual(lines, list(range(1, 151)))

    def test_real_linux_search_resumes_beyond_512(self):
        from device_fabric.linux_native_files import LinuxNativeFiles
        from device_fabric.linux_native_read_dispatch import LinuxOriginalReadDispatcher
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index in range(1200):
                (root / f'needle-{index:04}.py').write_bytes(b'')
            with LinuxNativeFiles(root=root, project='hermes') as files:
                dispatcher = LinuxOriginalReadDispatcher(device_id='h454-linux-read-ci',
                    local_roots={'hermes': files}, is_device_revoked=lambda: False)
                cursor = ''
                seen = set()
                for index in range(30):
                    if index == 17:
                        dispatcher = LinuxOriginalReadDispatcher(device_id='h454-linux-read-ci',
                            local_roots={'hermes': files}, is_device_revoked=lambda: False)
                    if index == 4:
                        code = ('import json,sys; from pathlib import Path; '
                            'from device_fabric.linux_native_files import LinuxNativeFiles; '
                            'from device_fabric.linux_native_search import LinuxNativeSearch; '
                            'f=LinuxNativeFiles(root=Path(sys.argv[1]),project="hermes"); '
                            'print(json.dumps(LinuxNativeSearch(f).search("needle",mode="names",'
                            'relative_root="",cursor=sys.argv[2]))); f.close()')
                        result = json.loads(subprocess.run([sys.executable, '-B', '-c', code, str(root), cursor],
                                            capture_output=True, text=True, check=True).stdout)
                    else:
                        frame = json.dumps({'type': 'call', 'id': f'page-{index}', 'tool': 'native_file_search',
                            'args': {'project': 'hermes', 'query': 'needle', 'mode': 'names',
                                     'relative_root': '', 'cursor': cursor}}).encode()
                        result = dispatcher.call(frame)['result']
                    seen.update(row['path'] for row in result['matches'])
                    cursor = result['next_cursor']
                    if not cursor:
                        break
                self.assertEqual(cursor, '')
                self.assertEqual(len(seen), 1200)
if __name__ == '__main__':
    unittest.main()
