#!/usr/bin/env python3
"""OpenAI-compatible radiance stub for fast integration tests.

No third-party dependencies: the test image installs nothing beyond Python.
Implements /health, /v1/models, /v1/chat/completions (SSE and non-streaming,
including a tool call) and /v1/completions. It also echoes the principal the
gateway injected as X-Mock-Principal so tests can prove header injection.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = os.environ.get("MOCK_MODEL", "qwen3.8-27b")
DELAY_MS = int(os.environ.get("MOCK_DELAY_MS", "0"))
MAX_BODY = 32 * 1024 * 1024


def _now() -> int:
    return int(time.time())


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("mock: %s\n" % (fmt % args))

    # ---- helpers ---------------------------------------------------------
    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response_only(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        principal = self.headers.get("X-Radiance-Principal")
        if principal:
            self.send_header("X-Mock-Principal", principal)
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)
        self.wfile.flush()

    def _chunk(self, data: bytes) -> None:
        self.wfile.write(f"{len(data):X}\r\n".encode("ascii") + data + b"\r\n")
        self.wfile.flush()

    def _start_sse(self) -> None:
        self.send_response_only(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        principal = self.headers.get("X-Radiance-Principal")
        if principal:
            self.send_header("X-Mock-Principal", principal)
        self.end_headers()
        self.close_connection = True

    def _sse(self, payload: object) -> None:
        if DELAY_MS:
            time.sleep(DELAY_MS / 1000)
        self._chunk(b"data: " + json.dumps(payload).encode("utf-8") + b"\n\n")

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": {"message": "bad Content-Length"}})
            return None
        if length > MAX_BODY:
            self._json(413, {"error": {"message": "too large"}})
            return None
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": {"message": "invalid JSON"}})
            return None

    @staticmethod
    def _last_user(body: dict) -> str:
        for message in reversed(body.get("messages", [])):
            if message.get("role") == "user":
                content = message.get("content", "")
                return content if isinstance(content, str) else json.dumps(content)
        return ""

    @staticmethod
    def _wants_tool(body: dict) -> bool:
        if not body.get("tools"):
            return False
        messages = body.get("messages", [])
        if messages and messages[-1].get("role") == "tool":
            return False
        text = MockHandler._last_user(body).lower()
        return "readme" in text or "use the read tool" in text or "tool" in text

    # ---- routes ----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"status": "ok", "model": MODEL})
            return
        if self.path.rstrip("/") == "/v1/models":
            self._json(
                200,
                {
                    "object": "list",
                    "data": [
                        {
                            "id": MODEL,
                            "object": "model",
                            "created": _now(),
                            "owned_by": "radiance",
                        }
                    ],
                },
            )
            return
        self._json(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        body = self._read_json()
        if body is None:
            return
        if path == "/v1/chat/completions":
            self._chat(body)
        elif path == "/v1/completions":
            self._completion(body)
        else:
            self._json(404, {"error": {"message": "not found"}})

    def _chat(self, body: dict) -> None:
        stream = bool(body.get("stream"))
        tool = self._wants_tool(body)
        completion_id = f"chatcmpl-mock-{_now()}"
        usage = {
            "prompt_tokens": 17,
            "completion_tokens": 9,
            "total_tokens": 26,
        }
        if not stream:
            message: dict[str, object] = {"role": "assistant", "content": "mock reply"}
            finish = "stop"
            if tool:
                message = {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_mock_1",
                            "type": "function",
                            "function": {
                                "name": "read",
                                "arguments": '{"path":"README.md"}',
                            },
                        }
                    ],
                }
                finish = "tool_calls"
            self._json(
                200,
                {
                    "id": completion_id,
                    "object": "chat.completion",
                    "created": _now(),
                    "model": MODEL,
                    "choices": [
                        {"index": 0, "message": message, "finish_reason": finish}
                    ],
                    "usage": usage,
                },
            )
            return

        self._start_sse()

        def event(delta: dict, finish: object = None) -> None:
            self._sse(
                {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": _now(),
                    "model": MODEL,
                    "choices": [
                        {"index": 0, "delta": delta, "finish_reason": finish}
                    ],
                }
            )

        event({"role": "assistant"})
        if tool:
            event(
                {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call_mock_1",
                            "type": "function",
                            "function": {
                                "name": "read",
                                "arguments": '{"path":"README.md"}',
                            },
                        }
                    ]
                }
            )
            event({}, "tool_calls")
            self._sse(
                {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": _now(),
                    "model": MODEL,
                    "choices": [],
                    "usage": usage,
                }
            )
            self._chunk(b"data: [DONE]\n\n")
            self._chunk(b"")
            return
        for word in ("mock ", "streamed ", "reply"):
            event({"content": word})
        event({}, "stop")
        self._sse(
            {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": _now(),
                "model": MODEL,
                "choices": [],
                "usage": usage,
            }
        )
        self._chunk(b"data: [DONE]\n\n")
        self._chunk(b"")

    def _completion(self, body: dict) -> None:
        text = "mock completion"
        if body.get("stream"):
            self._start_sse()
            self._sse(
                {
                    "id": "cmpl-mock",
                    "object": "text_completion",
                    "created": _now(),
                    "model": MODEL,
                    "choices": [
                        {"index": 0, "text": text, "finish_reason": "stop"}
                    ],
                }
            )
            self._chunk(b"data: [DONE]\n\n")
            self._chunk(b"")
            return
        self._json(
            200,
            {
                "id": "cmpl-mock",
                "object": "text_completion",
                "created": _now(),
                "model": MODEL,
                "choices": [{"index": 0, "text": text, "finish_reason": "stop"}],
                "usage": {
                    "prompt_tokens": 4,
                    "completion_tokens": 2,
                    "total_tokens": 6,
                },
            },
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1:8000")
    args = parser.parse_args(argv)
    host, port = args.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), MockHandler)
    server.daemon_threads = True
    sys.stderr.write(f"mock: listening on {args.listen}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
