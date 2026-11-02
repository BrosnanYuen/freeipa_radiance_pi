"""Clock-skew and denial-of-service robustness checks (T13, T17)."""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import pytest

pytestmark = pytest.mark.integration


def _curl_code(env: dict[str, str], url: str, ca: str, prefix: list[str] | None = None) -> tuple[int, str]:
    argv = [*(prefix or []), "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
            "--negotiate", "-u", ":", "--cacert", ca, url + "/v1/models"]
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)
    try:
        return int(proc.stdout.strip()), proc.stderr
    except ValueError:
        return -1, proc.stderr


def test_t13_client_clock_skew_is_rejected(
    pi_env, edge_ready, ca_bundle
) -> None:
    faketime = shutil.which("faketime")
    if not faketime:
        pytest.skip("faketime is not installed")

    normal, error = _curl_code(pi_env, edge_ready, ca_bundle)
    assert normal == 200, error

    skewed, error = _curl_code(
        pi_env, edge_ready, ca_bundle, prefix=[faketime, "+10 minutes"]
    )
    assert skewed == 401, (
        f"a +10 minute clock skew was not rejected (HTTP {skewed}); edge stderr: {error}"
    )


def test_t17_slow_header_is_closed(edge_ready, ca_bundle) -> None:
    parsed = urlparse(edge_ready)
    host = parsed.hostname or "radiance.ipa.test"
    port = parsed.port or 8443
    context = ssl.create_default_context(cafile=ca_bundle)

    started = time.monotonic()
    data = b""
    with socket.create_connection((host, port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(b"GET /v1/models HTTP/1.1\r\nHost: " + host.encode() + b"\r\n")
            tls.settimeout(30)
            try:
                while True:
                    chunk = tls.recv(1024)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, ssl.SSLError, ConnectionResetError):
                pass
    elapsed = time.monotonic() - started

    assert elapsed < 30, f"slow header was not bounded: {elapsed:.1f}s"
    assert b"408" in data or data == b"", data[:200]


def test_t17_one_hundred_concurrent_authenticated_requests(
    pi_env, spnego_factory, edge_ready, ca_bundle, http
) -> None:
    import os

    if os.environ.get("RADIANCE_GPU") == "1":
        pytest.skip("mock-profile capacity check; the real engine runs max-num-seqs 1")

    def one(index: int) -> int:
        response = http.post(
            edge_ready + "/v1/chat/completions",
            json={
                "model": "qwen3.8-27b",
                "messages": [{"role": "user", "content": f"concurrent {index}"}],
            },
            auth=spnego_factory(),
            verify=ca_bundle,
            timeout=120,
        )
        return response.status_code

    with ThreadPoolExecutor(max_workers=100) as pool:
        statuses = list(pool.map(one, range(100)))
    assert statuses == [200] * 100, statuses
