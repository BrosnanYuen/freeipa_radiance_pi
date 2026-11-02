#!/usr/bin/env python3
"""radiance-gateway: Kerberos-authenticated reverse proxy for radiance.

The gateway is deliberately a separate process from the engine:

    Pi -> radiance-shim --TLS 1.3 + Negotiate--> radiance-gateway --key--> radiance

It terminates TLS, accepts one SPNEGO token per request with the FreeIPA keytab,
checks the authenticated principal against an LDAPS group, then forwards only
the three model routes to the engine over loopback.  The engine stays unmodified
and keeps its private bearer key.

This module has no third-party imports at module load time.  ``gssapi`` and
``ldap`` are imported when the gateway starts, so the pure helpers (header
parser, allowlist, filter escaping) can be unit-tested on a host without the
Kerberos packages.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import http.client
import json
import logging
import os
import re
import socket
import ssl
import stat
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("radiance-gateway")

ALLOWED_PATHS = frozenset({"/v1/models", "/v1/chat/completions", "/v1/completions"})
ALLOWED_METHODS = frozenset({"GET", "POST"})
MAX_BODY = 16 * 1024 * 1024
MAX_TOKEN = 64 * 1024
MAX_HEADERS = 50
HSTS = "max-age=63072000; includeSubDomains"
HOP_BY_HOP = frozenset(
    {
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
        "server",
        "date",
    }
)
_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._/@=-]{1,1024}$")


class GatewayError(Exception):
    """A refusal with an HTTP status and an OpenAI error type."""

    def __init__(self, status: int, kind: str, message: str):
        super().__init__(message)
        self.status = status
        self.kind = kind
        self.message = message


class ConfigError(ValueError):
    """Invalid configuration; the process must not start."""


# ------------------------------------------------------------------ pure helpers


def b64decode_token(text: str) -> bytes:
    """Strict standard base64, with padding, and a size bound."""
    if not text or len(text) % 4:
        raise GatewayError(401, "authentication_error", "invalid Negotiate token")
    if any(c.isspace() for c in text):
        raise GatewayError(401, "authentication_error", "invalid Negotiate token")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise GatewayError(401, "authentication_error", "invalid Negotiate token") from exc
    if not raw or len(raw) > MAX_TOKEN:
        raise GatewayError(401, "authentication_error", "invalid Negotiate token")
    return raw


def parse_authorization(value: Optional[str]) -> tuple[str, Optional[bytes]]:
    """Return (state, token), where state is 'absent', 'empty', 'token' or 'bad'.

    Only one spelling is accepted for a token: standard base64 with padding and
    no embedded whitespace.  That removes the parser ambiguity an attacker
    could exploit between this proxy and the engine.
    """
    if value is None or not value.strip():
        return "absent", None
    parts = value.strip().split()
    if not parts or parts[0].lower() != "negotiate":
        return "bad", None
    if len(parts) == 1:
        return "empty", None
    if len(parts) != 2:
        return "bad", None
    try:
        return "token", b64decode_token(parts[1])
    except GatewayError:
        return "bad", None


def allowed(path: str, method: str) -> bool:
    return method in ALLOWED_METHODS and urllib.parse.urlsplit(path).path in ALLOWED_PATHS


def escape_filter(value: str) -> str:
    """RFC 4515 escape for an LDAP assertion value."""
    out = []
    for ch in value:
        if ch == "\x00":
            out.append("\\00")
        elif ch == "(":
            out.append("\\28")
        elif ch == ")":
            out.append("\\29")
        elif ch == "*":
            out.append("\\2a")
        elif ch == "\\":
            out.append("\\5c")
        else:
            out.append(ch)
    return "".join(out)


def sanitize_principal(principal: str) -> str:
    """A principal is header/log text before it is an identity."""
    if not _PRINCIPAL_RE.match(principal):
        raise GatewayError(401, "authentication_error", "the authenticated principal is invalid")
    return principal


def error_object(kind: str, message: str) -> bytes:
    return json.dumps(
        {"error": {"message": message, "type": kind, "param": None, "code": None}},
        separators=(",", ":"),
    ).encode("utf-8")


def audit(**fields: object) -> None:
    """One JSON line per authenticated/refused request; never a token or body."""
    fields.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    sys.stdout.write(json.dumps(fields, separators=(",", ":")) + "\n")
    sys.stdout.flush()


# ------------------------------------------------------------------ configuration


def _check_private(path: Path, label: str, allow_root: bool = True) -> None:
    try:
        st = path.lstat()
    except OSError as exc:
        raise ConfigError(f"{label} {path} is not readable: {exc.strerror}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"{label} {path} must be a regular file, not a symlink")
    if st.st_size <= 0:
        raise ConfigError(f"{label} {path} is empty")
    if st.st_mode & 0o077:
        raise ConfigError(f"{label} {path} is mode {stat.S_IMODE(st.st_mode):04o}; use 0400/0600")
    me = os.geteuid()
    if me != 0 and st.st_uid not in (me, 0):
        raise ConfigError(f"{label} {path} is not owned by this user or root")
    if not allow_root and st.st_uid == 0 and me != 0:
        raise ConfigError(f"{label} {path} is root-owned and not readable by this user")


def _read_secret(path: Path, label: str) -> str:
    _check_private(path, label)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"{label} {path} cannot be read: {exc.strerror}") from exc
    value = text.strip()
    if not value:
        raise ConfigError(f"{label} {path} is empty")
    return value


@dataclass(frozen=True)
class GatewayConfig:
    listen: str
    port: int
    cert: Path
    key: Path
    keytab: Path
    service: str
    upstream_host: str
    upstream_port: int
    api_key_file: Path
    ldap_uri: str = ""
    ldap_base: str = ""
    ldap_bind_dn: str = ""
    ldap_bind_password_file: Optional[Path] = None
    ldap_ca_file: Optional[Path] = None
    ldap_group: str = ""
    ldap_cache_ttl: float = 60.0
    health_port: int = 8081
    max_body: int = MAX_BODY
    read_timeout: float = 10.0
    upstream_timeout: float = 3600.0
    max_connections: int = 128

    def validate(self) -> None:
        if not 0 <= self.port <= 65535 or not 0 <= self.health_port <= 65535:
            raise ConfigError("invalid port")
        if not self.service or "@" not in self.service:
            raise ConfigError("--service must name HTTP@host or HTTP/host@REALM")
        if self.service != self.service.strip() or any(ord(c) < 0x20 for c in self.service):
            raise ConfigError("--service contains a control character")
        _check_private(self.keytab, "keytab")
        _check_private(self.key, "TLS private key")
        for p, label in ((self.cert, "TLS certificate"),):
            if not p.is_file() or p.stat().st_size <= 0:
                raise ConfigError(f"{label} {p} is missing")
        _read_secret(self.api_key_file, "radiance API key")
        if self.max_body <= 0:
            raise ConfigError("--max-body must be positive")
        if self.ldap_cache_ttl < 0:
            raise ConfigError("--ldap-cache-ttl must not be negative")
        if self.ldap_group:
            if not self.ldap_uri.startswith("ldaps://"):
                raise ConfigError("--ldap-uri must be ldaps://")
            for label, value in (
                ("--ldap-base", self.ldap_base),
                ("--ldap-bind-dn", self.ldap_bind_dn),
                ("--ldap-group", self.ldap_group),
            ):
                if not value:
                    raise ConfigError(f"{label} is required with --ldap-group")
            if self.ldap_bind_password_file is None or self.ldap_ca_file is None:
                raise ConfigError("LDAP bind password and CA files are required")
            _check_private(self.ldap_bind_password_file, "LDAP bind password")
            if not self.ldap_ca_file.is_file() or self.ldap_ca_file.stat().st_size <= 0:
                raise ConfigError(f"LDAP CA file {self.ldap_ca_file} is missing")
        elif any(
            (
                self.ldap_uri,
                self.ldap_base,
                self.ldap_bind_dn,
                self.ldap_bind_password_file,
                self.ldap_ca_file,
            )
        ):
            raise ConfigError("LDAP options require --ldap-group")


# ------------------------------------------------------------------ Kerberos


class KerberosAuth:
    """One acceptor credential, one GSSAPI context per request."""

    def __init__(self, cfg: GatewayConfig):
        import gssapi  # imported only when serving

        self._gss = gssapi
        self._lock = threading.Lock()
        # MIT reads the keytab from KRB5_KTNAME.  The path is not a secret; the
        # keytab bytes never enter argv and are 0400.
        os.environ["KRB5_KTNAME"] = f"FILE:{cfg.keytab}"
        cache = Path(os.environ.get("KRB5RCACHEDIR", "/tmp/radiance-gateway"))
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(cache, 0o700)
        os.environ["KRB5RCACHEDIR"] = str(cache)
        name = gssapi.Name(cfg.service, gssapi.NameType.hostbased_service)
        try:
            self._creds = gssapi.Credentials(usage="accept", name=name)
        except Exception as exc:  # noqa: BLE001 - startup must fail closed
            raise ConfigError(f"cannot acquire the GSSAPI acceptor credential: {exc}") from exc

    def authenticate(self, value: Optional[str]) -> str:
        gssapi = self._gss
        parsed = parse_authorization(value)
        state, raw_token = parsed
        if state in ("absent", "empty"):
            raise GatewayError(401, "authentication_error", "Kerberos authentication required")
        if state == "bad" or raw_token is None:
            raise GatewayError(401, "authentication_error", "invalid Negotiate token")
        try:
            with self._lock:
                ctx = gssapi.SecurityContext(creds=self._creds, usage="accept")
                out = ctx.step(raw_token)
                complete = ctx.complete
                principal = str(ctx.initiator_name) if complete and ctx.initiator_name else ""
        except Exception as exc:  # noqa: BLE001 - any GSS failure is a refusal
            LOG.info("gssapi rejected a token: %s", type(exc).__name__)
            raise GatewayError(401, "authentication_error", "invalid Kerberos credential") from exc
        if not complete:
            raise GatewayError(401, "authentication_error", "incomplete Kerberos exchange")
        if not principal:
            raise GatewayError(401, "authentication_error", "GSSAPI returned no principal")
        # Some clients append the final token; Kerberos completes in one round.
        del out
        return sanitize_principal(principal)


# ------------------------------------------------------------------ LDAP


class LdapAuthorizer:
    """Cached LDAPS uid -> group check.  Fail closed on backend errors."""

    def __init__(self, cfg: GatewayConfig):
        import ldap

        self._ldap = ldap
        self.cfg = cfg
        self._lock = threading.Lock()
        self._conn = None
        self._cache: dict[str, tuple[float, bool]] = {}
        self._password = _read_secret(cfg.ldap_bind_password_file, "LDAP bind password")
        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, str(cfg.ldap_ca_file))
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

    def _connect(self):
        ldap = self._ldap
        if self._conn is None:
            conn = ldap.initialize(self.cfg.ldap_uri)
            conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
            self._conn = conn
        try:
            self._conn.simple_bind_s(self.cfg.ldap_bind_dn, self._password)
        except Exception:
            try:
                self._conn.unbind_s()
            except Exception:
                pass
            self._conn = None
            raise
        return self._conn

    def allow(self, principal: str) -> bool:
        local = principal.split("@", 1)[0]
        if "/" in local:
            local = local.split("/", 1)[0]
        if not local or any(ord(c) < 0x20 for c in local):
            return False
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(principal)
            if cached and cached[0] > now:
                return cached[1]
            try:
                ok = self._allow_locked(local)
            except Exception as exc:  # noqa: BLE001 - fail closed, but say why in the log
                LOG.error("LDAP authorization failed: %s", type(exc).__name__)
                self._conn = None
                raise GatewayError(503, "service_unavailable", "authentication is temporarily unavailable") from exc
            self._cache[principal] = (now + self.cfg.ldap_cache_ttl, ok)
            return ok

    def _allow_locked(self, local: str) -> bool:
        ldap = self._ldap
        conn = self._connect()
        base = self.cfg.ldap_base
        user_filter = f"(&(objectClass=posixAccount)(uid={escape_filter(local)}))"
        users = conn.search_s(base, ldap.SCOPE_SUBTREE, user_filter, ["dn"])
        users = [u for u in users if u[0]]
        if not users:
            return False
        user_dn = users[0][0]
        group_filter = f"(member={escape_filter(user_dn)})"
        groups = conn.search_s(self.cfg.ldap_group, ldap.SCOPE_BASE, group_filter, [])
        return bool(groups)


# ------------------------------------------------------------------ HTTP proxy


class Gateway:
    def __init__(self, cfg: GatewayConfig):
        self.cfg = cfg
        self.auth = KerberosAuth(cfg)
        self.ldap = LdapAuthorizer(cfg) if cfg.ldap_group else None
        self.api_key = _read_secret(cfg.api_key_file, "radiance API key")

    def principal(self, value: Optional[str]) -> str:
        principal = self.auth.authenticate(value)
        if self.ldap is not None and not self.ldap.allow(principal):
            raise GatewayError(403, "permission_error", "the authenticated principal is not authorized for this service")
        return principal

    def upstream(self, method: str, path: str, body: bytes, principal: str):
        conn = http.client.HTTPConnection(
            self.cfg.upstream_host, self.cfg.upstream_port, timeout=self.cfg.upstream_timeout
        )
        headers = {
            "Host": f"{self.cfg.upstream_host}:{self.cfg.upstream_port}",
            "Authorization": "Bearer " + self.api_key,
            "X-Radiance-Principal": principal,
            "Content-Type": "application/json",
            "Accept": "*/*",
        }
        try:
            conn.request(method, path, body if method == "POST" else None, headers)
            resp = conn.getresponse()
            return resp.status, resp.getheaders(), resp
        except Exception:
            conn.close()
            raise


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = ""
    sys_version = ""

    # The engine gateway object is attached to the server.
    @property
    def gateway(self) -> Gateway:
        return self.server.gateway  # type: ignore[attr-defined]

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.gateway.cfg.read_timeout)

    def log_message(self, fmt: str, *args: object) -> None:
        # Access logging is the JSON audit line, not BaseHTTPRequestHandler's.
        return

    def send_response(self, code: int, message: Optional[str] = None) -> None:
        # No Server banner.  Date is required by HTTP/1.1.
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _common_headers(self) -> None:
        self.send_header("Strict-Transport-Security", HSTS)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _json(self, status: int, kind: str, message: str, extra: Optional[dict[str, str]] = None) -> None:
        body = error_object(kind, message)
        self.send_response(status)
        self._common_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def _headers_ok(self) -> bool:
        if len(self.headers) > MAX_HEADERS:
            self._json(400, "invalid_request_error", "too many headers")
            return False
        for name in ("host", "authorization", "origin", "x-api-key", "content-length"):
            if len(self.headers.get_all(name) or []) > 1:
                self._json(400, "invalid_request_error", f"the {name} header was sent twice")
                return False
        te = (self.headers.get("Transfer-Encoding") or "").strip().lower()
        if te and te != "identity":
            self._json(411, "invalid_request_error", "transfer-coded request bodies are not accepted")
            return False
        return True

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            raise GatewayError(411, "invalid_request_error", "chunked request bodies are not accepted")
        raw = self.headers.get("Content-Length")
        if raw is None:
            if self.command == "POST":
                raise GatewayError(411, "invalid_request_error", "Content-Length is required")
            return b""
        try:
            length = int(raw)
        except ValueError as exc:
            raise GatewayError(400, "invalid_request_error", "invalid Content-Length") from exc
        if length < 0:
            raise GatewayError(400, "invalid_request_error", "invalid Content-Length")
        if length > self.gateway.cfg.max_body:
            raise GatewayError(413, "invalid_request_error", "request body is too large")
        body = self.rfile.read(length)
        if len(body) != length:
            raise GatewayError(400, "invalid_request_error", "request body ended early")
        return body

    def _proxy(self) -> None:
        started = time.monotonic()
        principal = ""
        status = 500
        size = 0
        try:
            if not self._headers_ok():
                status = 400
                return
            if not allowed(self.path, self.command):
                raise GatewayError(403, "permission_error", "this path is not available")
            principal = self.gateway.principal(self.headers.get("Authorization"))
            body = self._read_body()
            upstream_status, headers, resp = self.gateway.upstream(
                self.command, self.path, body, principal
            )
            status = upstream_status
            content_type = next((v for k, v in headers if k.lower() == "content-type"), "application/json")
            cache_control = next((v for k, v in headers if k.lower() == "cache-control"), "")
            chunked = content_type.startswith("text/event-stream")
            if chunked:
                self.send_response(status)
                self._common_headers()
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", cache_control or "no-cache")
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                while True:
                    data = resp.read1(8192) if hasattr(resp, "read1") else resp.read(8192)
                    if not data:
                        break
                    size += len(data)
                    self.wfile.write(f"{len(data):X}\r\n".encode("ascii") + data + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            else:
                payload = resp.read()
                size = len(payload)
                self.send_response(status)
                self._common_headers()
                self.send_header("Content-Type", content_type)
                if cache_control:
                    self.send_header("Cache-Control", cache_control)
                self.send_header("Content-Length", str(size))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
                self.wfile.flush()
                self.close_connection = True
            resp.close()
        except GatewayError as exc:
            status = exc.status
            extra = {}
            if exc.status == 401:
                extra["WWW-Authenticate"] = "Negotiate"
            self._json(exc.status, exc.kind, exc.message, extra)
        except (BrokenPipeError, ConnectionResetError):
            status = 499
        except Exception as exc:  # noqa: BLE001 - a proxy fault is a 502/500, never a traceback to the client
            LOG.error("gateway fault: %s: %s", type(exc).__name__, exc)
            status = 502 if principal else 500
            try:
                self._json(status, "api_error", "the gateway could not reach radiance")
            except Exception:
                pass
        finally:
            try:
                self.connection.cipher()
                tls_version = self.connection.version()
                cipher = self.connection.cipher()[0] if self.connection.cipher() else ""
            except Exception:
                tls_version, cipher = "", ""
            audit(
                principal=principal,
                peer=self.client_address[0],
                method=self.command,
                path=urllib.parse.urlsplit(self.path).path,
                status=status,
                bytes=size,
                dur_us=int((time.monotonic() - started) * 1_000_000),
                tls=tls_version,
                cipher=cipher,
            )

    def do_GET(self) -> None:  # noqa: N802
        self._proxy()

    def do_HEAD(self) -> None:  # noqa: N802
        self._json(405, "invalid_request_error", "method not allowed")

    def do_POST(self) -> None:  # noqa: N802
        self._proxy()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._json(401, "authentication_error", "Kerberos authentication required", {"WWW-Authenticate": "Negotiate"})


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 256

    def __init__(self, addr: tuple[str, int], gateway: Gateway):
        self.gateway = gateway
        self.slots = threading.BoundedSemaphore(gateway.cfg.max_connections)
        super().__init__(addr, Handler)

    def process_request(self, request, client_address):
        # Bound live connections before a thread is created. A connection over
        # the bound is closed; it does not queue behind a leaking worker.
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class HealthHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/healthz":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def _health_server(port: int) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), HealthHandler)
    srv.daemon_threads = True
    return srv


def _tls_context(cfg: GatewayConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= ssl.OP_NO_TICKET
    ctx.load_cert_chain(str(cfg.cert), str(cfg.key))
    # TLS 1.3 suites are not selected by set_ciphers() (that API is pre-1.3);
    # OpenSSL's TLS 1.3 defaults are the three AEAD suites the edge allowed.
    return ctx


def parse_args(argv: list[str]) -> GatewayConfig:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--listen", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--cert", type=Path, required=True)
    p.add_argument("--key", type=Path, required=True)
    p.add_argument("--keytab", type=Path, required=True)
    p.add_argument("--service", required=True)
    p.add_argument("--upstream-host", default="127.0.0.1")
    p.add_argument("--upstream-port", type=int, default=8000)
    p.add_argument("--api-key-file", type=Path, required=True)
    p.add_argument("--ldap-uri", default="")
    p.add_argument("--ldap-base", default="")
    p.add_argument("--ldap-bind-dn", default="")
    p.add_argument("--ldap-bind-password-file", type=Path)
    p.add_argument("--ldap-ca-file", type=Path)
    p.add_argument("--ldap-group", default="")
    p.add_argument("--ldap-cache-ttl", type=float, default=60.0)
    p.add_argument("--health-port", type=int, default=8081)
    p.add_argument("--max-body", type=int, default=MAX_BODY)
    p.add_argument("--read-timeout", type=float, default=10.0)
    p.add_argument("--upstream-timeout", type=float, default=3600.0)
    p.add_argument("--max-connections", type=int, default=128)
    a = p.parse_args(argv)
    cfg = GatewayConfig(
        listen=a.listen,
        port=a.port,
        cert=a.cert,
        key=a.key,
        keytab=a.keytab,
        service=a.service,
        upstream_host=a.upstream_host,
        upstream_port=a.upstream_port,
        api_key_file=a.api_key_file,
        ldap_uri=a.ldap_uri,
        ldap_base=a.ldap_base,
        ldap_bind_dn=a.ldap_bind_dn,
        ldap_bind_password_file=a.ldap_bind_password_file,
        ldap_ca_file=a.ldap_ca_file,
        ldap_group=a.ldap_group,
        ldap_cache_ttl=a.ldap_cache_ttl,
        health_port=a.health_port,
        max_body=a.max_body,
        read_timeout=a.read_timeout,
        upstream_timeout=a.upstream_timeout,
        max_connections=a.max_connections,
    )
    cfg.validate()
    return cfg


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        cfg = parse_args(argv)
        gateway = Gateway(cfg)
    except (ConfigError, OSError) as exc:
        LOG.error("%s", exc)
        return 2
    health = _health_server(cfg.health_port)
    threading.Thread(target=health.serve_forever, name="health", daemon=True).start()
    httpd = GatewayServer((cfg.listen, cfg.port), gateway)
    httpd.socket = _tls_context(cfg).wrap_socket(httpd.socket, server_side=True)
    LOG.info("listening on https://%s:%d (upstream %s:%d)", cfg.listen, cfg.port, cfg.upstream_host, cfg.upstream_port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        health.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
