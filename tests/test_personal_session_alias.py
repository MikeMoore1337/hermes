"""The standard termination name must never escape tracked sessions."""
import unittest

from device_fabric.personal_session_alias import advertised_tools, dispatch


class SessionAliasTests(unittest.TestCase):
    def test_alias_keeps_pid_schema_and_forwards_only_to_tracked_session_handler(self):
        original = [{'name': 'force_terminate', 'inputSchema': {'type': 'object', 'required': ['pid']}}]
        tools = advertised_tools(original)
        self.assertEqual(tools[-1]['name'], 'kill_process')
        self.assertEqual(tools[-1]['inputSchema'], original[0]['inputSchema'])
        calls = []
        def forward(name, args):
            calls.append((name, args))
            return {'content': []}
        self.assertEqual(dispatch('kill_process', {'pid': 123}, forward), {'content': []})
        self.assertEqual(calls, [('force_terminate', {'pid': 123})])
        for args in ({}, {'pid': True}, {'pid': 0}, {'pid': 123, 'extra': 1}, {'pid': '123'}):
            with self.subTest(args=args):
                self.assertTrue(dispatch('kill_process', args, forward)['isError'])
        self.assertEqual(len(calls), 1)

    def test_missing_or_duplicate_underlying_handler_is_denied(self):
        for tools in ([], [{'name': 'force_terminate'}, {'name': 'force_terminate'}],
                      [{'name': 'force_terminate'}, {'name': 'kill_process'}]):
            with self.subTest(tools=tools), self.assertRaises(ValueError):
                advertised_tools(tools)


if __name__ == '__main__':
    unittest.main()
