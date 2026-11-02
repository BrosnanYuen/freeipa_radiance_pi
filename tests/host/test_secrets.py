from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from helpers import ROOT, inspect, stack_logs

pytestmark = pytest.mark.host

SECRET_NAMES = (
    "ipa_admin_password",
    "ipa_dm_password",
    "pi_password",
    "mallory_password",
    "ldap_bind_password",
    "radiance_api_key",
)


def test_host_secret_modes(compose) -> None:
    for name in SECRET_NAMES:
        path = ROOT / "secrets" / name
        if not path.is_file():
            pytest.skip(f"{path} does not exist")
        mode = stat.S_IMODE(path.stat().st_mode)
        expected = 0o400 if name == "radiance_api_key" else 0o600
        assert mode == expected, (name, oct(mode))
    keytab = ROOT / "run/ipa-data/keytabs/radiance.keytab"
    assert stat.S_IMODE(keytab.stat().st_mode) == 0o600
    tls_key = ROOT / "run/ipa-data/certs/radiance.key"
    assert stat.S_IMODE(tls_key.stat().st_mode) == 0o600


def test_container_argv_and_env_carry_no_secrets(compose) -> None:
    secrets = []
    for name in SECRET_NAMES:
        path = ROOT / "secrets" / name
        if path.is_file():
            secrets.append(path.read_text().strip())
    assert secrets
    for service in (
        "ipa",
        "radiance-gateway",
        "radiance-shim",
        "pi-login",
        "pi-client",
        "radiance",
        "mock-radiance",
    ):
        data = inspect(compose, service)
        fields = " ".join(
            [
                *(data["Config"].get("Env") or []),
                *(data["Config"].get("Cmd") or []),
                *(data["Config"].get("Entrypoint") or []),
            ]
        )
        for secret in secrets:
            assert secret not in fields, f"{service} exposes a secret in argv/env"


def test_logs_contain_no_secret_values(compose) -> None:
    logs = stack_logs(compose)
    assert logs
    for name in SECRET_NAMES:
        path = ROOT / "secrets" / name
        if path.is_file():
            assert path.read_text().strip() not in logs, name
    assert "Authorization: Negotiate " not in logs
    assert "Bearer " not in logs


def test_audit_log_format_after_request(compose) -> None:
    logs = stack_logs(compose)
    if '"principal"' not in logs:
        pytest.skip("no authenticated request has been logged yet")
    assert "%{" not in logs
    assert "GSS_NAME" not in logs
    assert "Authorization" not in logs
