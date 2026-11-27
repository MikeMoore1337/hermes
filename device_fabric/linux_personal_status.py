"""Check a personal Linux device's current grant over the existing pinned TLS."""
from __future__ import annotations

import http.client
import json
import re
import ssl

from device_fabric import native_private_tls as private
from device_fabric.native_brc_enrollment import TOKEN, _unique

SCHEMA = 'h454-native-device-status-v1'
IDENTITIES = {
    'hermes-vps': re.compile(r'h454-linux-personal-hermes-[a-f0-9]{32}\Z'),
    'yfc-vps': re.compile(r'h454-linux-personal-yfc-[a-f0-9]{32}\Z'),
}


def bearer_state(config: private.PrivateRelay, *, target: str, device_id: str,
                 bearer: str, timeout: float = 8.0) -> bool | None:
    """True is an active owner-bound bearer; None denotes a transient outage."""
    if (type(config) is not private.PrivateRelay or target not in IDENTITIES or
            target != config.target or type(device_id) is not str or
            IDENTITIES[target].fullmatch(device_id) is None or type(bearer) is not str or
            TOKEN.fullmatch(bearer) is None or type(timeout) not in (int, float) or
            not 1 <= timeout <= 12):
        return False
    try:
        with private._connection(config, timeout) as secure:
            secure.settimeout(timeout)
            secure.sendall(('GET /device/native-status HTTP/1.1\r\n'
                f'Host: {private.HOST}:{private.PORT}\r\n'
                f'Authorization: Bearer {bearer}\r\n'
                'Accept: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n').encode('ascii'))
            response = http.client.HTTPResponse(secure)
            response.begin()
            if 500 <= response.status <= 599:
                return None
            if response.status != 200 or response.getheader('Content-Type') != 'application/json':
                return False
            length = response.getheader('Content-Length')
            if length is not None and not 0 < int(length) <= 512:
                return False
            raw = response.read(513)
            if not 0 < len(raw) <= 512:
                return False
        obj = json.loads(raw.decode('ascii'), object_pairs_hook=_unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        return (type(obj) is dict and set(obj) == {'schema', 'device_id', 'active', 'owner_bound'}
                and obj['schema'] == SCHEMA and obj['device_id'] == device_id
                and obj['active'] is True and obj['owner_bound'] is True
                and json.dumps(obj, separators=(',', ':')).encode('ascii') == raw)
    except ssl.SSLError:
        return False
    except (OSError, TimeoutError, http.client.RemoteDisconnected):
        return None
    except Exception:
        return False
