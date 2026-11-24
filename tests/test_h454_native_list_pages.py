"""Bounded pagination, mutation denial, and the read-only wire contracts."""
import json
from pathlib import Path
import platform
import sys
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.native_list_pages import NativePageDenied, page, parse_cursor, validate_next
from device_fabric.linux_native_read_dispatch import LIST, NativeLinuxReadDenied, parse_call
from scripts import h15_native_windows_mcp_stdio as windows
from scripts import h15_native_windows_outbound as outbound


def entries(count):
    return [{'name': f'file-{i:03}.py', 'kind': 'file'} for i in range(count)]


class NativePageContracts(unittest.TestCase):
    def test_three_pages_cover_every_authorized_entry_once(self):
        original = entries(173)
        cursor = ''
        result = []
        for expected in (64, 64, 45):
            batch, following = page(original, 'hermes', 'src', cursor)
            validate_next(cursor, following, batch, bool(following))
            self.assertEqual(len(batch), expected)
            result.extend(batch)
            cursor = following
        self.assertEqual(cursor, '')
        self.assertEqual(result, original)

    def test_mutation_other_directory_and_invalid_cursors_are_denied(self):
        original = entries(70)
        _, cursor = page(original, 'hermes', 'src', '')
        for values, project, relative in ((entries(71), 'hermes', 'src'),
                                           (original, 'other', 'src'),
                                           (original, 'hermes', 'different')):
            with self.subTest(project=project, relative=relative), self.assertRaises(NativePageDenied):
                page(values, project, relative, cursor)
        for bad in ('1:' + 'a'*64, '256:' + 'a'*64, '64:' + 'G'*64, '64:' + 'a'*65, '64', None):
            with self.subTest(cursor=bad), self.assertRaises(NativePageDenied):
                parse_cursor(bad)
        with self.assertRaises(NativePageDenied):
            page(entries(257), 'hermes', '', '')

    def test_false_or_malformed_next_page_is_rejected(self):
        for nxt, batch, truncated in (('64:'+'a'*64, entries(1), True),
                                      ('64:'+'a'*64, entries(64), False),
                                      ('128:'+'a'*64, entries(64), True),
                                      ('', entries(64), True)):
            with self.subTest(next=nxt, count=len(batch)), self.assertRaises(NativePageDenied):
                validate_next('', nxt, batch, truncated)
        with self.assertRaises(NativePageDenied):
            validate_next('64:'+'a'*64, '128:'+'b'*64, entries(64), True)

    def test_linux_wire_accepts_only_optional_valid_cursor_on_list(self):
        def request(tool, args):
            return json.dumps({'type': 'call', 'id': 'a', 'tool': tool, 'args': args}).encode()
        base = {'project': 'hermes', 'relative': ''}
        self.assertEqual(parse_call(request(LIST, {**base, 'cursor': ''}))[2]['cursor'], '')
        for tool, args in ((LIST, {**base, 'cursor': 'bad'}),
                           ('native_file_stat', {**base, 'cursor': ''}),
                           (LIST, {**base, 'cursor': None})):
            with self.subTest(tool=tool), self.assertRaises(NativeLinuxReadDenied):
                parse_call(request(tool, args))

    def test_windows_stdio_validates_and_passes_cursor_without_widening_path(self):
        session = windows.McpSession()
        session.handle({'jsonrpc':'2.0','id':1,'method':'initialize','params':{
            'protocolVersion':windows.PROTOCOL,'capabilities':{},'clientInfo':{}}})
        args = {'project':'hermes','relative':'','cursor':''}
        request = lambda a: {'jsonrpc':'2.0','id':2,'method':'tools/call',
                             'params':{'name':'native_file_list','arguments':a}}
        output = {'status':'ok','project':'hermes','relative':'','action':'list',
                  'kind':'directory','entries':entries(64),'truncated':True,
                  'next_cursor':'64:'+'a'*64}
        with patch.object(windows.native, 'handle_native_list', return_value=output) as read:
            response = session.handle(request(args))
            self.assertFalse(response['result']['isError'])
            read.assert_called_once_with('hermes', '', cursor='')
            self.assertTrue(session.handle(request({**args,'cursor':'bad'}))['result']['isError'])
            self.assertTrue(session.handle(request({**args,'relative':'..'}))['result']['isError'])
        self.assertIsNone(outbound.safe_call(session, {'type':'call','id':'bad',
            'tool':'native_file_list','args':{**args,'cursor':'bad'}}, set()))


@unittest.skipUnless(sys.platform == 'linux' and platform.machine().lower() in ('x86_64','aarch64'),
                     'real Linux openat2 fixture')
class NativeLinuxPageContracts(unittest.TestCase):
    def test_real_handles_page_and_reject_mutated_directory(self):
        from device_fabric.linux_native_files import LinuxNativeFiles, NativeLinuxDenied
        from device_fabric.linux_native_read_dispatch import LinuxOriginalReadDispatcher
        with tempfile.TemporaryDirectory(prefix='h454-page-fixture-') as temp:
            root = Path(temp)
            for i in range(130):
                (root/f'file-{i:03}.py').write_text('safe')
            (root/'.env').write_text('never returned')
            with LinuxNativeFiles(root=root, project='hermes') as files:
                dispatcher = LinuxOriginalReadDispatcher(device_id='h454-linux-read-ci',
                    local_roots={'hermes': files}, is_device_revoked=lambda: False)
                def call(identifier, cursor):
                    raw = json.dumps({'type':'call','id':identifier,'tool':LIST,
                        'args':{'project':'hermes','relative':'','cursor':cursor}}).encode()
                    return dispatcher.call(raw)['result']
                first = call('one', '')
                second = call('two', first['next_cursor'])
                third = call('three', second['next_cursor'])
                self.assertEqual([len(x['entries']) for x in (first,second,third)], [64,64,2])
                self.assertEqual(third['next_cursor'], '')
                self.assertNotIn('.env', repr((first,second,third)))
                (root/'new.py').write_text('safe')
                with self.assertRaises(NativeLinuxDenied):
                    files.list_directory(cursor=first['next_cursor'])
                with self.assertRaises(NativeLinuxReadDenied):
                    call('four', first['next_cursor'])


if __name__ == '__main__':
    unittest.main()
