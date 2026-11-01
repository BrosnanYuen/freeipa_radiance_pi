#!/usr/bin/env python3
"""SPNEGO credential agent for the Pi harness.

Pi speaks OpenAI Chat Completions with a bearer token; the edge speaks
Kerberos. This process sits between them:

    Pi --(HTTP + bearer)--> shim --(TLS 1.3 + Negotiate)--> edge

Design points:
  * The ccache is mounted only here (and in pi-login), never in pi-client.
  * The shim token is created 0600 if absent and re-read on every request.
  * One fresh GSSAPI context per request; a 401 triggers exactly one retry
    with a new authenticator.
  * Streaming responses are re-chunked without buffering.
  * Tokens, Authorization headers, prompts and responses are never logged.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import http.client
import json
import logging
import os
import secrets
import ssl
import sys
import time
from dataclasses import dataclass
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Mapping, Sequence
from urllib.parse import urlsplit

from . import kerberos

LOG = logging.getLogger("radiance-shim")

ALLOWED_PATHS = frozenset(
    {"/v1/models", "/v1/chat/completions", "/v1/completions"}
)
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}


class ShimConfigError(ValueError):
    """Invalid configuration; the process must not start."""


@dataclass(frozen=True)
class ShimConfig:
    listen_host: str
    listen_port: int
    edge_url: str
    service: str
    ca_file: Path
    token_file: Path
    max_body: int = 16 * 1024 * 1024
    timeout: float = 3600.0

    def __post_init__(self) -> None:
        parsed = urlsplit(self.edge_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ShimConfigError("--edge must be an https:// URL with a host")
        if not 0 <= self.listen_port <= 65535:
            raise ShimConfigError("invalid listen port")

    @property
    def edge(self) -> str:
        return self.edge_url.rstrip("/")


def read_token(token_file: Path) -> str | None:
    try:
        value = token_file.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def ensure_token_file(token_file: Path) -> str:
    """Create the shim token 0600 if absent; never rotate an existing one."""
    token_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = read_token(token_file)
    except Exception:  # pragma: no cover - read_token handles OSError
        existing = None
    if existing:
        os.chmod(token_file, 0o600)
        return existing
    generated = secrets.token_urlsafe(32)
    try:
        fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process won the race; use its token.
        existing = read_token(token_file)
        if not existing:
            raise ShimConfigError(f"token file {token_file} exists but is empty")
        return existing
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(generated + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(token_file, 0o600)
    return generated


def _bearer_matches(expected: str, header: str | None) -> bool:
    if not header or not header.lower().startswith("bearer "):
        return False
    provided = header[len("bearer ") :].strip()
    return bool(provided) and hmac.compare_digest(provided, expected)


class ShimHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    config: ShimConfig
    provider_factory: Callable[[str], kerberos.TokenProvider]

    def __init__(
        self,
        *args: object,
        config: ShimConfig,
        provider_factory: Callable[[str], kerberos.TokenProvider],
        **kwargs: object,
    ) -> None:
        self.config = config
        self.provider_factory = provider_factory
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    # ---- logging ---------------------------------------------------------
    def log_message(self, fmt: str, *args: object) -> None:
        # Request line only; BaseHTTPRequestHandler never logs headers.
        LOG.info("%s - %s", self.address_string(), fmt % args)

    # ---- responses -------------------------------------------------------
    def _send_json(
        self,
        status: int,
        payload: Mapping[str, object],
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response_only(status)
        self.send_header("Date", self.date_time_string())
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)
        self.wfile.flush()

    def _error(self, status: int, message: str, code: str) -> None:
        headers = {}
        if status == 401:
            headers["WWW-Authenticate"] = 'Bearer realm="radiance-shim"'
        self._send_json(
            status,
            {"error": {"type": code, "message": message}},
            headers,
        )

    # ---- health ----------------------------------------------------------
    def _health(self) -> None:
        ca_ok = self.config.ca_file.is_file()
        token_ok = read_token(self.config.token_file) is not None
        try:
            import gssapi  # noqa: F401

            gssapi_ok = True
        except Exception:
            gssapi_ok = False
        ready = kerberos.ccache_available()
        self._send_json(
            200,
            {
                "status": "ok",
                "ready": ready,
                "ccache": ready,
                "token": token_ok,
                "ca": ca_ok,
                "gssapi": gssapi_ok,
            },
        )

    # ---- request handling ------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def _handle(self, method: str) -> None:
        path = urlsplit(self.path).path
        if path == "/healthz":
            if method != "GET":
                self._error(405, "method not allowed", "method")
                return
            self._health()
            return

        if path not in ALLOWED_PATHS:
            self._error(404, "not found", "not_found")
            return
        if method not in ("GET", "POST"):
            self._error(405, "method not allowed", "method")
            return

        expected = read_token(self.config.token_file)
        if expected is None:
            self._error(503, "shim token file is missing", "token_missing")
            return
        if not _bearer_matches(expected, self.headers.get("Authorization")):
            self._error(401, "invalid or missing shim bearer token", "unauthorized")
            return

        body = self._read_body()
        if body is None:
            return

        started = time.monotonic()
        for attempt in range(2):
            try:
                provider = self.provider_factory(self.config.service)
                token = provider.token()
            except kerberos.KerberosError as exc:
                self._error(401, str(exc), "kerberos_credentials")
                return
            except Exception:
                LOG.exception("unexpected credential error")
                self._error(502, "credential acquisition failed", "kerberos")
                return
            try:
                conn, response = self._upstream(method, body, token)
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                LOG.warning("upstream request failed: %s", exc)
                self._error(502, "edge request failed", "upstream")
                return
            if response.status == 401 and attempt == 0:
                try:
                    response.read()
                finally:
                    conn.close()
                LOG.info("edge returned 401; retrying once with a fresh token")
                continue
            self._relay(conn, response, method, started)
            return

    def _read_body(self) -> bytes | None:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            self._error(411, "chunked request bodies are not supported", "length")
            return None
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return b""
        try:
            length = int(raw_length)
        except ValueError:
            self._error(400, "invalid Content-Length", "length")
            return None
        if length < 0 or length > self.config.max_body:
            self._error(413, "request body too large", "too_large")
            return None
        return self.rfile.read(length) if length else b""

    def _upstream(
        self, method: str, body: bytes, token: bytes
    ) -> tuple[http.client.HTTPSConnection, http.client.HTTPResponse]:
        parsed = urlsplit(self.config.edge)
        context = ssl.create_default_context(cafile=str(self.config.ca_file))
        conn = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            context=context,
            timeout=self.config.timeout,
        )
        headers = {
            "Host": parsed.netloc,
            "Authorization": "Negotiate "
            + base64.b64encode(token).decode("ascii"),
            "Accept": self.headers.get("Accept", "application/json"),
            "User-Agent": "radiance-krb-shim/0.1",
        }
        content_type = self.headers.get("Content-Type")
        if content_type:
            headers["Content-Type"] = content_type
        accept_encoding = self.headers.get("Accept-Encoding")
        if accept_encoding:
            headers["Accept-Encoding"] = accept_encoding
        conn.request(method, self.path, body=body if body else None, headers=headers)
        return conn, conn.getresponse()

    def _relay(
        self,
        conn: http.client.HTTPSConnection,
        response: http.client.HTTPResponse,
        method: str,
        started: float,
    ) -> None:
        status = response.status
        try:
            self.send_response_only(status)
            self.send_header("Date", self.date_time_string())
            for key, value in response.getheaders():
                lowered = key.lower()
                if lowered in _HOP_BY_HOP or lowered in ("server", "date"):
                    continue
                self.send_header(key, value)

            no_body = status in (204, 304) or method == "HEAD"
            if no_body:
                self.send_header("Content-Length", "0")
            else:
                self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

            if not no_body:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(
                        f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n"
                    )
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            LOG.info(
                "%s %s -> %d in %.0f ms",
                method,
                urlsplit(self.path).path,
                status,
                (time.monotonic() - started) * 1000,
            )
        except (BrokenPipeError, ConnectionResetError):
            LOG.info("client disconnected mid-response")
        finally:
            try:
                conn.close()
            except Exception:
                pass


def parse_listen(value: str) -> tuple[str, int]:
    try:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    except (ValueError, AttributeError) as exc:
        raise ShimConfigError(f"invalid --listen {value!r}; use HOST:PORT") from exc


def create_server(
    config: ShimConfig,
    provider_factory: Callable[[str], kerberos.TokenProvider] | None = None,
) -> ThreadingHTTPServer:
    if not config.ca_file.is_file():
        raise ShimConfigError(f"CA file not found: {config.ca_file}")
    ensure_token_file(config.token_file)
    factory = provider_factory or (
        lambda service: kerberos.TokenProvider(service)
    )
    handler = partial(
        ShimHandler, config=config, provider_factory=factory
    )
    server = ThreadingHTTPServer((config.listen_host, config.listen_port), handler)
    server.daemon_threads = True
    return server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="0.0.0.0:8088")
    parser.add_argument(
        "--edge", default="https://radiance.ipa.test:8443"
    )
    parser.add_argument(
        "--service", default="HTTP/radiance.ipa.test"
    )
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--log-level", default="INFO")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )
    try:
        host, port = parse_listen(args.listen)
        config = ShimConfig(
            listen_host=host,
            listen_port=port,
            edge_url=args.edge,
            service=args.service,
            ca_file=args.ca,
            token_file=args.token_file,
        )
        server = create_server(config)
    except ShimConfigError as exc:
        print(f"radiance-krb-shim: {exc}", file=sys.stderr)
        return 2
    LOG.info("listening on %s:%d; edge %s", host, port, config.edge)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
