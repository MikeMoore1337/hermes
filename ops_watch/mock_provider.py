"""Local OpenAI-compatible provider for the bounded Hermes experiment only."""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .incident_advisor import mock_result, prepare_context


def _reply(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, object]) -> None:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _stream_reply(handler: BaseHTTPRequestHandler, content: str) -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.send_header("Connection", "close")
    handler.end_headers()
    chunks = (
        {"role": "assistant"},
        {"content": content},
        {},
    )
    for index, delta in enumerate(chunks):
        choice: dict[str, object] = {"index": 0, "delta": delta}
        if index == len(chunks) - 1:
            choice["finish_reason"] = "stop"
        payload = {
            "id": "ops-incident-mock-stream",
            "object": "chat.completion.chunk",
            "choices": [choice],
        }
        handler.wfile.write(
            ("data: " + json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n\n").encode(
                "utf-8"
            )
        )
        handler.wfile.flush()
    handler.wfile.write(b"data: [DONE]\n\n")
    handler.wfile.flush()


class _Handler(BaseHTTPRequestHandler):
    server: "_Server"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        if self.path.rstrip("/") not in {"/models", "/v1/models"}:
            _reply(self, 404, {"error": {"type": "not_found"}})
            return
        _reply(
            self,
            200,
            {
                "object": "list",
                "data": [{"id": "ops-incident-mock-v1", "object": "model"}],
            },
        )

    def do_POST(self) -> None:
        if not self.path.rstrip("/").endswith("/chat/completions"):
            _reply(self, 404, {"error": {"type": "not_found"}})
            return
        self.server.request_count += 1
        self.server.count_file.write_text(str(self.server.request_count), encoding="ascii")
        if self.server.request_count > 1:
            _reply(self, 429, {"error": {"type": "retry_denied"}})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 32_768:
                raise ValueError
            payload = json.loads(self.rfile.read(length))
            messages = payload.get("messages")
            if not isinstance(messages, list) or payload.get("tools"):
                raise ValueError
            user_message = messages[-1].get("content") if messages else None
            if not isinstance(user_message, str):
                raise ValueError
            start = user_message.index("BEGIN_EVENT_CONTEXT") + len("BEGIN_EVENT_CONTEXT")
            end = user_message.index("END_EVENT_CONTEXT", start)
            context = json.loads(user_message[start:end].strip())
            context = prepare_context(context["incident"] | {"schema": "hermes-ops-incident-v1"})
            result = mock_result(context)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            _reply(self, 400, {"error": {"type": "invalid_bounded_request"}})
            return
        content = json.dumps(result, ensure_ascii=False, sort_keys=True)
        if payload.get("stream") is True:
            _stream_reply(self, content)
        else:
            _reply(
                self,
                200,
                {
                    "id": "ops-incident-mock-response",
                    "object": "chat.completion",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": content},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                },
            )


class _Server(ThreadingHTTPServer):
    request_count: int

    def __init__(self, address: tuple[str, int], count_file: Path):
        super().__init__(address, _Handler)
        self.request_count = 0
        self.count_file = count_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--count-file", type=Path, required=True)
    args = parser.parse_args()
    server = _Server(("127.0.0.1", args.port), args.count_file)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
