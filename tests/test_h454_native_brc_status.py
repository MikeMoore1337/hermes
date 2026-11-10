"""H454 native BRC authoritative owner-bearer status contracts."""
import json
import unittest
from unittest.mock import Mock, patch
from device_fabric import native_brc_status as status

TOKEN="brc_dev_"+"k"*64
ID="h454-win-native-"+"a"*32


def packet(device_id=ID):
    return json.dumps({
        "schema":status.SCHEMA,"device_id":device_id,
        "active":True,"owner_bound":True,
    },separators=(",",":")).encode("ascii")


class NativeStatusContracts(unittest.TestCase):
    def test_exact_current_owner_bound_response_and_bearer(self):
        self.assertTrue(status.parse_status(packet(),target="windows",device_id=ID))
        for x in (
            {"active":False}, {"active":1}, {"owner_bound":False},
            {"schema":"other"}, {"device_id":"h454-win-01335a1f6e6705b4"},
            {"admin":True},
        ):
            import copy
            p=json.loads(packet())
            p.update(x)
            raw=json.dumps(p,separators=(",",":")).encode()
            with self.subTest(x=x), self.assertRaises(status.StatusDenied):
                status.parse_status(raw,target="windows",device_id=ID)

    def test_malformed_noncanonical_and_forged_status_denied(self):
        for raw in (
            b"",b"{}",b"[]",b"\xff",packet()+b"\n",
            packet().replace(b'"active":',b'"active":false,"active":',1),
            packet().replace(b'"owner_bound":',b'"owner_bound":NaN,"owner_bound":',1),
            b"x"*(status.MAX_RESPONSE+1),
        ):
            with self.subTest(length=len(raw)),self.assertRaises(status.StatusDenied):
                status.parse_status(raw,target="windows",device_id=ID)

    def test_authorized_https_and_private_ssh_tunnel_only(self):
        class FakeResponse:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):return None
            def read(self,_max):return packet()

        class FakeOpener:
            def __init__(self):self.requests=[]
            def open(self,req,timeout=None):
                self.requests.append((req,timeout))
                return FakeResponse()
        opening=FakeOpener()
        with patch.object(status,"build_opener",return_value=opening):
            provider=status.status_provider(
                target="windows",device_id=ID,bearer=TOKEN,
                base_url=status.PUBLIC)
            self.assertTrue(provider())
        req=opening.requests[0][0]
        self.assertEqual(req.full_url,status.PUBLIC+status.PATH)
        self.assertEqual(req.get_header("Authorization"),"Bearer "+TOKEN)
        self.assertEqual(req.get_method(),"GET")
        self.assertEqual(opening.requests[0][1],8.0)

        for bad in (
            "http://hermes.mikemoore.top", "https://evil.example",
            "http://localhost:38183", "http://127.0.0.2:38183",
            "http://127.0.0.1:8080", "https://hermes.mikemoore.top.evil/ws",
        ):
            with self.subTest(url=bad), self.assertRaises(status.StatusDenied):
                status.status_provider(target="windows",device_id=ID,
                    bearer=TOKEN,base_url=bad)

    def test_revoke_and_private_tunnel_fail_closed(self):
        opener=Mock()
        with patch.object(status,"build_opener",return_value=opener):
            require_private=Mock(return_value=False)
            provider=status.status_provider(
                target="windows",device_id=ID,bearer=TOKEN,
                base_url=status.PRIVATE,
                private_tunnel_verified=require_private)
            self.assertFalse(provider())
            opener.open.assert_not_called()
        for failure in (OSError("sensitive token"),TimeoutError,ValueError):
            opener=Mock()
            opener.open.side_effect=failure
            with patch.object(status,"build_opener",return_value=opener):
                revoked=status.revoked_provider(
                    target="windows",device_id=ID,bearer=TOKEN,
                    base_url=status.PUBLIC)
                self.assertTrue(revoked())
        self.assertNotIn(TOKEN,repr(provider))

    def test_unknown_identity_fails_before_any_network(self):
        with patch.object(status,"build_opener",
                          side_effect=AssertionError("network not allowed")):
            with self.assertRaises(status.StatusDenied):
                status.status_provider(target="windows",
                    device_id="h454-win-01335a1f6e6705b4",bearer=TOKEN,
                    base_url=status.PUBLIC)


if __name__=="__main__":
    unittest.main()
