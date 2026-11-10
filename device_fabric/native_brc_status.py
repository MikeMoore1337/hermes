"""H454: current owner-bound native bearer revocation check via EXISTING BRC.

Requires an exact trusted relay HTTP(S) identity and current bearer. The
relay independently checks the actual SQLite token hash, admin owner,
platform/name/new native ID and paused flag on every check. No local
boolean can grant status without authenticated relay response.
"""
from __future__ import annotations

import json
import re
import ssl
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, HTTPSHandler, ProxyHandler, HTTPRedirectHandler, build_opener

from device_fabric.native_brc_enrollment import IDENTITY, TOKEN, _unique

SCHEMA = "h454-native-device-status-v1"
PATH = "/device/native-status"
PUBLIC = "https://hermes.mikemoore.top"
PRIVATE = "http://127.0.0.1:38183"
MAX_RESPONSE = 512


class StatusDenied(ValueError):
    """Never expose a bearer, HTTP path, host, or upstream provider error."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_status(raw: bytes, *, target: str, device_id: str) -> bool:
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_RESPONSE
            or target not in IDENTITY
            or type(device_id) is not str
            or IDENTITY[target].fullmatch(device_id) is None):
            raise StatusDenied("native_brc_status_denied")
        obj = json.loads(
            raw.decode("ascii"),object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if (type(obj) is not dict
            or set(obj) != {"schema","device_id","active","owner_bound"}
            or obj["schema"] != SCHEMA
            or obj["device_id"] != device_id
            or obj["active"] is not True
            or obj["owner_bound"] is not True
            or json.dumps(obj,separators=(",",":")).encode("ascii") != raw):
            raise StatusDenied("native_brc_status_denied")
        return True
    except Exception:
        raise StatusDenied("native_brc_status_denied") from None


def status_provider(
    *, target: str, device_id: str, bearer: str,
    base_url: str,
    private_tunnel_verified: Callable[[], bool] | None = None,
    timeout_seconds: float = 8.0,
) -> Callable[[], bool]:
    """Return an ACTIVE status provider; false means revoked or unavailable.

    A temporary current-user bearer cannot authorize itself. Only a
    validated TLS or independently verified owner SSH tunnel plus a
    current server database record can return ACTIVE.
    """
    if (target not in IDENTITY or type(device_id) is not str
        or IDENTITY[target].fullmatch(device_id) is None
        or type(bearer) is not str or TOKEN.fullmatch(bearer) is None
        or type(base_url) is not str or base_url not in (PUBLIC, PRIVATE)
        or type(timeout_seconds) not in (int, float)
        or not 1 <= timeout_seconds <= 12
        or (base_url == PRIVATE and not callable(private_tunnel_verified))):
        raise StatusDenied("native_brc_status_denied")
    opener = build_opener(
        ProxyHandler({}), _NoRedirect(),
        HTTPSHandler(context=ssl.create_default_context()),
    )

    def active() -> bool:
        try:
            if base_url == PRIVATE and private_tunnel_verified() is not True:
                return False
            req = Request(
                base_url + PATH, method="GET",
                headers={
                    "Authorization":"Bearer " + bearer,
                    "Accept":"application/json",
                    "Cache-Control":"no-store",
                })
            with opener.open(req, timeout=timeout_seconds) as response:
                if response.status != 200:
                    return False
                return parse_status(
                    response.read(MAX_RESPONSE + 1),
                    target=target,device_id=device_id,
                )
        except Exception:
            return False
    return active


def revoked_provider(**kwargs) -> Callable[[], bool]:
    """Safest callback for LinuxOriginalReadDispatcher / Win32 run_once."""
    active = status_provider(**kwargs)
    return lambda: active() is not True
