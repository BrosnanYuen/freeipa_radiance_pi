from __future__ import annotations

import base64
import http.client
import json
import logging
import os
import ssl
import stat
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from radiance_krb import kerberos
from radiance_krb import shim

SSE_EVENTS = (b"data: one\n\n", b"data: two\n\n", b"data: [DONE]\n\n")


def make_cert(tmp_path: Path) -> tuple[Path, Path]:
    key = tmp_path / "server.key"
    cert = tmp_path / "server.crt"
    proc = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"openssl unavailable: {proc.stderr}")
    return key, cert


class UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _chunk(self, data: bytes) -> None:
        self.wfile.write(f"{len(data):X}\r\n".encode() + data + b"\r\n")
        self.wfile.flush()

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def _record(self) -> None:
        self.server.calls.append(  # type: ignore[attr-defined]
            (self.command, self.path, self.headers.get("Authorization"))
        )

    def do_GET(self) -> None:  # noqa: N802
        self._record()
        if self.path.split("?")[0] == "/v1/models":
            self._json(
                200,
                {"object": "list", "data": [{"id": "mock", "object": "model"}]},
            )
            return
        self._json(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:  # noqa: N802
        self._record()
        calls = self.server.calls  # type: ignore[attr-defined]
        if self.server.fail_first and len(calls) == 1:  # type: ignore[attr-defined]
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Negotiate")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        if self.path.split("?")[0] != "/v1/chat/completions":
            self._json(404, {"error": {"message": "not found"}})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        for event in SSE_EVENTS:
            self._chunk(event)
            time.sleep(0.01)
        self._chunk(b"")


class FakeProvider:
    def __init__(self, tokens: list[bytes], calls: list[bytes] | None = None):
        self._tokens = list(tokens)
        self.calls = calls if calls is not None else []

    def token(self) -> bytes:
        self.calls.append(b"called")
        if not self._tokens:
            return b"default-token"
        if len(self._tokens) == 1:
            return self._tokens[0]
        return self._tokens.pop(0)


def start_stack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    provider_factory=None,
    fail_first: bool = False,
):
    key, cert = make_cert(tmp_path)
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    upstream.calls = []  # type: ignore[attr-defined]
    upstream.fail_first = fail_first  # type: ignore[attr-defined]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    upstream.socket = context.wrap_socket(upstream.socket, server_side=True)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()

    token_file = tmp_path / "agent" / "shim-token"
    ccache = tmp_path / "cc"
    ccache.write_bytes(b"ccache")
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{ccache}")
    config = shim.ShimConfig(
        listen_host="127.0.0.1",
        listen_port=0,
        edge_url=f"https://127.0.0.1:{upstream.server_address[1]}",
        service="HTTP/localhost",
        ca_file=cert,
        token_file=token_file,
    )
    provider_calls: list[bytes] = []
    if provider_factory is None:
        tokens = [b"first-token", b"second-token", b"third-token"]
        provider_factory = lambda service: FakeProvider(tokens, provider_calls)
    shim_server = shim.create_server(config, provider_factory=provider_factory)
    shim_thread = threading.Thread(target=shim_server.serve_forever, daemon=True)
    shim_thread.start()
    stack = {
        "config": config,
        "upstream": upstream,
        "shim": shim_server,
        "shim_port": shim_server.server_address[1],
        "token_file": token_file,
        "token": shim.read_token(token_file),
        "provider_calls": provider_calls,
    }

    def cleanup() -> None:
        shim_server.shutdown()
        shim_server.server_close()
        upstream.shutdown()
        upstream.server_close()

    return stack, cleanup


@pytest.fixture
def stack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    stack, cleanup = start_stack(tmp_path, monkeypatch)
    yield stack
    cleanup()


def request(stack, method, path, token=None, body=None, headers=None):
    connection = http.client.HTTPConnection(
        "127.0.0.1", stack["shim_port"], timeout=10
    )
    hdrs = dict(headers or {})
    if token is not None:
        hdrs["Authorization"] = f"Bearer {token}"
    payload = json.dumps(body).encode() if body is not None else None
    if payload is not None:
        hdrs["Content-Type"] = "application/json"
    connection.request(method, path, body=payload, headers=hdrs)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response, data


def test_ensure_token_file_0600_and_stable(tmp_path: Path) -> None:
    token_file = tmp_path / "agent" / "shim-token"
    token = shim.ensure_token_file(token_file)
    assert token
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    assert shim.ensure_token_file(token_file) == token
    token_file.write_text("custom\n")
    assert shim.ensure_token_file(token_file) == "custom"
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600


def test_healthz_reports_readiness(stack) -> None:
    response, data = request(stack, "GET", "/healthz")
    assert response.status == 200
    payload = json.loads(data)
    assert payload["status"] == "ok"
    assert payload["token"] is True
    assert payload["ca"] is True
    assert payload["ready"] is True


def test_missing_bearer_is_401(stack) -> None:
    response, data = request(stack, "GET", "/v1/models")
    assert response.status == 401
    assert response.getheader("WWW-Authenticate")
    assert b"error" in data


def test_wrong_bearer_is_401(stack) -> None:
    response, _ = request(stack, "GET", "/v1/models", token="wrong")
    assert response.status == 401


def test_valid_request_is_proxied_with_negotiate(stack) -> None:
    response, data = request(
        stack, "GET", "/v1/models", token=stack["token"]
    )
    assert response.status == 200
    assert json.loads(data)["data"][0]["id"] == "mock"
    auth = stack["upstream"].calls[0][2]
    assert auth.startswith("Negotiate ")


def test_token_file_is_reread_per_request(stack) -> None:
    old = stack["token"]
    stack["token_file"].write_text("rotated-token\n")
    assert request(stack, "GET", "/v1/models", token=old)[0].status == 401
    assert request(stack, "GET", "/v1/models", token="rotated-token")[0].status == 200


def test_retry_once_with_fresh_token(stack) -> None:
    stack["upstream"].fail_first = True
    response, data = request(
        stack, "POST", "/v1/chat/completions",
        token=stack["token"], body={"messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status == 200
    assert len(stack["upstream"].calls) == 2
    assert len(stack["provider_calls"]) == 2
    assert b"data: one" in data


def test_streaming_is_chunked_and_incremental(stack) -> None:
    connection = http.client.HTTPConnection(
        "127.0.0.1", stack["shim_port"], timeout=10
    )
    connection.request(
        "POST",
        "/v1/chat/completions",
        body=json.dumps(
            {"stream": True, "messages": [{"role": "user", "content": "hi"}]}
        ),
        headers={
            "Authorization": f"Bearer {stack['token']}",
            "Content-Type": "application/json",
        },
    )
    response = connection.getresponse()
    assert response.status == 200
    assert response.getheader("Transfer-Encoding") == "chunked"
    started = time.monotonic()
    first = response.readline()
    assert time.monotonic() - started < 2
    assert first.startswith(b"data: one")
    rest = first + response.read()
    assert b"data: two" in rest
    assert b"[DONE]" in rest
    connection.close()


def test_kerberos_error_becomes_actionable_401(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Provider:
        def token(self):
            raise kerberos.CredentialsExpired("expired; run `pi-krb login`")

    stack, cleanup = start_stack(
        tmp_path, monkeypatch, provider_factory=lambda service: Provider()
    )
    try:
        response, data = request(
            stack, "GET", "/v1/models", token=stack["token"]
        )
    finally:
        cleanup()
    assert response.status == 401
    assert b"pi-krb login" in data


def test_denied_path_is_404(stack) -> None:
    response, _ = request(stack, "GET", "/dashboard", token=stack["token"])
    assert response.status == 404
    response, _ = request(stack, "GET", "/v1/load_lora_adapter", token=stack["token"])
    assert response.status == 404


def test_no_token_in_logs(stack, caplog) -> None:
    caplog.set_level(logging.INFO)
    bare = stack["token"]
    request(stack, "GET", "/v1/models", token=bare)
    for record in caplog.records:
        assert bare not in record.getMessage()


def test_config_rejects_plaintext_edge(tmp_path: Path) -> None:
    with pytest.raises(shim.ShimConfigError):
        shim.ShimConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            edge_url="http://example.test:8443",
            service="HTTP/example.test",
            ca_file=tmp_path / "ca",
            token_file=tmp_path / "token",
        )
