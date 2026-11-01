from __future__ import annotations

import socket
import ssl
from urllib.parse import urlsplit

import pytest

pytestmark = pytest.mark.security


def _connect(context: ssl.SSLContext, host: str, port: int = 8443):
    with socket.create_connection((host, port), timeout=10) as raw:
        return context.wrap_socket(raw, server_hostname=host)


def test_t6_tls13_handshake(edge_ready, ca_bundle) -> None:
    host = urlsplit(edge_ready).hostname
    context = ssl.create_default_context(cafile=ca_bundle)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    with _connect(context, host) as tls:
        assert tls.version() == "TLSv1.3"
        cipher = tls.cipher()
        assert cipher, "no cipher negotiated"
        assert cipher[0].startswith(("TLS_AES_", "TLS_CHACHA20_")), cipher


def test_t6_tls12_is_rejected(edge_ready, ca_bundle) -> None:
    host = urlsplit(edge_ready).hostname
    context = ssl.create_default_context(cafile=ca_bundle)
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises((ssl.SSLError, OSError)):
        _connect(context, host)


def test_t6_untrusted_ca_is_rejected(edge_ready) -> None:
    host = urlsplit(edge_ready).hostname
    # Do NOT use create_default_context(): it honours SSL_CERT_FILE, which this
    # test-runner sets to the IPA CA. A client context with no CAs loaded must
    # reject the edge chain.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    with pytest.raises((ssl.SSLError, ssl.SSLCertVerificationError, OSError)):
        _connect(context, host)


def test_t18_hsts_and_no_banner(
    pi_env, spnego_auth, edge_ready, ca_bundle, http
) -> None:
    response = http.get(
        edge_ready + "/v1/models",
        auth=spnego_auth,
        verify=ca_bundle,
        timeout=30,
    )
    assert response.status_code == 200
    hsts = response.headers.get("Strict-Transport-Security", "")
    assert "max-age=" in hsts
    server = response.headers.get("Server", "")
    assert "Apache/" not in server
    assert "2.4" not in server
    assert "X-Powered-By" not in response.headers
