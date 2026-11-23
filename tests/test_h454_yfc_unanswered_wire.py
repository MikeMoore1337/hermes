"""A relay-accepted path can be silently discarded by the pinned reader."""
import unittest

from device_fabric.linux_native_outbound import _rpc_payload


class YfcUnansweredWireTests(unittest.TestCase):
    def test_non_normalized_path_is_discarded_before_the_call_budget(self):
        frame = {
            'type': 'call', 'id': 'synthetic-call-1', 'tool': 'native_file_read',
            'args': {'project': 'hermes', 'relative': 'a\u0301.md'},
            'client': {'name': 'synthetic-client'}, 'timeoutMs': 8000,
        }
        self.assertIsNone(_rpc_payload(frame))


if __name__ == '__main__':
    unittest.main()
