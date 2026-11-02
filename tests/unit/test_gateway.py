"""Unit contract for the radiance-gateway proxy (no KDC or LDAP needed)."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("radiance_gateway", ROOT / "deploy/gateway/gateway.py")
gateway = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = gateway
SPEC.loader.exec_module(gateway)


def test_negotiate_parser_has_one_spelling() -> None:
    token = base64.b64encode(b"\x01\x02\x03\x04").decode()
    assert gateway.parse_authorization(None)[0] == "absent"
    assert gateway.parse_authorization("")[0] == "absent"
    assert gateway.parse_authorization("Negotiate")[0] == "empty"
    assert gateway.parse_authorization("Negotiate  ")[0] == "empty"
    state, parsed = gateway.parse_authorization("  negotiate  " + token + " ")
    assert state == "token" and parsed == b"\x01\x02\x03\x04"
    for bad in (
        "Bearer " + token,
        "Negotiate " + token + " extra",
        "Negotiate !!!!",
        "Negotiate " + token + "=",
        "Negotiate " + "A" * 100_000,
        "Basic x",
    ):
        assert gateway.parse_authorization(bad)[0] in ("bad", "empty"), bad


def test_base64_rejects_padding_and_whitespace_ambiguity() -> None:
    for bad in ("", "A", "AAA", "AAAA=", "====", "AA=A", "AA==AA==", "AA==\n"):
        with pytest.raises(gateway.GatewayError):
            gateway.b64decode_token(bad)
    assert gateway.b64decode_token("TWFu") == b"Man"


def test_allowlist_is_exact_and_excludes_admin_paths() -> None:
    assert gateway.allowed("/v1/models", "GET")
    assert gateway.allowed("/v1/chat/completions?x=1", "POST")
    assert gateway.allowed("/v1/completions", "POST")
    for path, method in (
        ("/v1/load_lora_adapter", "POST"),
        ("/dashboard", "GET"),
        ("/v1/audio", "POST"),
        ("/v1/models/", "GET"),
        ("//v1/models", "GET"),
        ("/v1/models", "DELETE"),
        ("/health", "GET"),
    ):
        assert not gateway.allowed(path, method), (path, method)


def test_ldap_filter_escaping_covers_metacharacters() -> None:
    assert gateway.escape_filter("alice") == "alice"
    assert gateway.escape_filter("a*b(c)d\\e") == "a\\2ab\\28c\\29d\\5ce"
    assert gateway.escape_filter("a\x00b") == "a\\00b"


def test_principal_is_validated_before_use_as_a_header_or_log_value() -> None:
    assert gateway.sanitize_principal("pi@IPA.TEST") == "pi@IPA.TEST"
    for bad in ("pi@IPA.TEST\r\nX: y", "", "x" * 2000, "pi\n@IPA.TEST"):
        with pytest.raises(gateway.GatewayError):
            gateway.sanitize_principal(bad)


def test_error_object_is_openai_shaped() -> None:
    payload = json.loads(gateway.error_object("authentication_error", "no"))
    assert payload["error"]["type"] == "authentication_error"
    assert payload["error"]["message"] == "no"


def test_config_refuses_unsafe_files_and_incomplete_ldap(tmp_path: Path) -> None:
    def make(name: str, mode: int, data: str = "x") -> Path:
        p = tmp_path / name
        p.write_text(data)
        p.chmod(mode)
        return p

    cert = make("cert.pem", 0o644)
    key = make("key.pem", 0o600)
    keytab = make("radiance.keytab", 0o400)
    api = make("api", 0o400, "k" * 32)
    cfg = gateway.GatewayConfig(
        listen="127.0.0.1",
        port=8443,
        cert=cert,
        key=key,
        keytab=keytab,
        service="HTTP@radiance.ipa.test",
        upstream_host="127.0.0.1",
        upstream_port=8000,
        api_key_file=api,
    )
    cfg.validate()
    keytab.chmod(0o644)
    with pytest.raises(gateway.ConfigError):
        cfg.validate()
    keytab.chmod(0o400)
    with pytest.raises(gateway.ConfigError):
        gateway.GatewayConfig(
            listen="127.0.0.1", port=8443, cert=cert, key=key, keytab=keytab,
            service="HTTP@radiance.ipa.test", upstream_host="127.0.0.1",
            upstream_port=8000, api_key_file=api, ldap_group="cn=ai-users,dc=x",
        ).validate()
