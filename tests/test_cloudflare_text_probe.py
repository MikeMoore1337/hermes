"""No-network credential hygiene and no paid fallback tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from scripts.cloudflare_text_probe import ProbeError, one_request, read_env


TOKEN = "synthetic" + "x" * 30
ENDPOINT = "https://api.cloudflare.com/client/v4/accounts/" + "0" * 32 + "/ai/v1"


class _Response:
    def __init__(self, payload: dict) -> None:
        self.status = 200
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit: int) -> bytes:
        assert limit <= 32768
        return self.payload


class CloudflareProbeTests(unittest.TestCase):
    def test_safe_single_request_no_fallback(self) -> None:
        client = MagicMock()
        client.open.return_value = _Response({
            "choices": [{"message": {"content": "OK"}}],
            "usage": {"prompt_tokens": 17, "completion_tokens": 30, "total_tokens": 47},
        })
        result = one_request(TOKEN, ENDPOINT, opener=client)
        self.assertEqual(result["result"], "ok")
        self.assertEqual(client.open.call_count, 1)
        request = client.open.call_args.args[0]
        self.assertEqual(request.full_url, ENDPOINT + "/chat/completions")
        payload = json.loads(request.data)
        self.assertEqual(payload["model"], "@cf/openai/gpt-oss-20b")
        self.assertEqual(payload["max_tokens"], 160)
        self.assertNotIn(TOKEN, str(result))

    def test_no_unapproved_endpoint(self) -> None:
        for base in ("http://api.cloudflare.com", "https://evil.com",
                     ENDPOINT + "?redirect=https://evil.com", ENDPOINT.replace("/ai/v1", "/ai/run")):
            with self.subTest(base=base), self.assertRaises(ProbeError):
                one_request(TOKEN, base)

    def test_private_env_mode_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / ".env"
            p.write_text(f"CLOUDFLARE_WORKERS_AI_API_TOKEN={TOKEN}\nCLOUDFLARE_WORKERS_AI_BASE_URL={ENDPOINT}\n")
            p.chmod(0o644)
            with self.assertRaises(ProbeError):
                read_env(p)
            p.chmod(0o600)
            self.assertEqual(read_env(p), (TOKEN, ENDPOINT))

    def test_no_unknown_env_key_or_duplicate_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / ".env"
            p.write_text(f"CLOUDFLARE_WORKERS_AI_API_TOKEN={TOKEN}\nCLOUDFLARE_WORKERS_AI_BASE_URL={ENDPOINT}\nOPENAI_API_KEY=x\n")
            p.chmod(0o600)
            with self.assertRaises(ProbeError):
                read_env(p)

    def test_empty_response_fails_closed(self) -> None:
        client = MagicMock()
        client.open.return_value = _Response({"choices": [{"message": {"content": None}}]})
        self.assertNotEqual(one_request(TOKEN, ENDPOINT, opener=client)["result"], "ok")


if __name__ == "__main__":
    unittest.main()
