"""Private-TLS status for the separately paired personal Windows bearer."""
from __future__ import annotations

import http.client
import json
import ssl

from device_fabric import native_private_tls as private
from device_fabric.native_brc_enrollment import TOKEN, _unique
from device_fabric.windows_personal_commander_enrollment import DEVICE

SCHEMA = "h454-native-device-status-v1"


def bearer_state(config: private.PrivateRelay, *, device_id: str, bearer: str,
                 timeout: float = 8.0) -> bool | None:
    """True only for the current owner-bound grant; None is a temporary outage."""
    if (type(config) is not private.PrivateRelay or config.target != "windows"
        or config.relay_ipv4 != private.WINDOWS_LOOPBACK
        or type(device_id) is not str or DEVICE.fullmatch(device_id) is None
        or type(bearer) is not str or TOKEN.fullmatch(bearer) is None
        or type(timeout) not in (int, float) or not 1 <= timeout <= 12):
        return False
    try:
        with private._connection(config, timeout) as secure:
            secure.settimeout(timeout)
            headers = ("GET /device/native-status HTTP/1.1\r\n"
                f"Host: {private.HOST}:{private.PORT}\r\n"
                f"Authorization: Bearer {bearer}\r\n"
                "Accept: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").encode("ascii")
            secure.sendall(headers)
            response = http.client.HTTPResponse(secure)
            response.begin()
            if 500 <= response.status <= 599:
                return None
            if response.status != 200 or response.getheader("Content-Type") != "application/json":
                return False
            size = response.getheader("Content-Length")
            if size is not None and not 0 < int(size) <= 512:
                return False
            raw = response.read(513)
            if not 0 < len(raw) <= 512:
                return False
        data = json.loads(raw.decode("ascii"), object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        return (type(data) is dict and set(data) == {"schema", "device_id", "active", "owner_bound"}
                and data["schema"] == SCHEMA and data["device_id"] == device_id
                and data["active"] is True and data["owner_bound"] is True
                and json.dumps(data, separators=(",", ":")).encode("ascii") == raw)
    except ssl.SSLError:
        return False
    except (OSError, TimeoutError, http.client.RemoteDisconnected):
        return None
    except Exception:
        return False
