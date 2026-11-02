"""Destructive rotation checks. Opt in with RUN_DESTRUCTIVE=1.

Each test runs the corresponding scripts/rotate-*.sh against the live stack and
verifies the new credential works while the old one does not. The tests leave
the realm on the rotated credentials, which is the intended end state.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from helpers import ROOT, run

pytestmark = [pytest.mark.host, pytest.mark.destructive, pytest.mark.slow]


def _require_opt_in() -> None:
    if os.environ.get("RUN_DESTRUCTIVE") != "1":
        pytest.skip("set RUN_DESTRUCTIVE=1 (rotates live realm credentials)")


def _secret(name: str) -> str:
    return (ROOT / "secrets" / name).read_text(encoding="utf-8").strip()


def _kinit_ok(compose: list[str], password: str, ccache: str = "/tmp/cc_rotation") -> bool:
    proc = run(
        [
            *compose,
            "exec",
            "-T",
            "ipa",
            "env",
            f"KRB5CCNAME={ccache}",
            "bash",
            "-c",
            'read -r pw; printf "%s" "$pw" | kinit -f admin >/dev/null 2>&1 '
            "&& echo KINIT_OK; kdestroy >/dev/null 2>&1 || true",
        ],
        input_text=password + "\n",
        check=False,
    )
    return "KINIT_OK" in proc.stdout


def _ldap_bind_ok(compose: list[str], dn: str, password: str) -> bool:
    proc = run(
        [
            *compose,
            "exec",
            "-T",
            "-e",
            "LDAPTLS_CACERT=/etc/ipa/ca.crt",
            "ipa",
            "ldapwhoami",
            "-x",
            "-H",
            "ldaps://ipa.ipa.test:636",
            "-D",
            dn,
            "-y",
            "/dev/stdin",
        ],
        # ldapwhoami -y does not strip a newline; send the value bare.
        input_text=password,
        check=False,
    )
    return proc.returncode == 0 and dn.lower() in proc.stdout.lower()


def _serial(compose: list[str]) -> str:
    proc = run(
        [
            *compose,
            "exec",
            "-T",
            "radiance-gateway",
            "openssl",
            "x509",
            "-in",
            "/certs/radiance.crt",
            "-noout",
            "-serial",
        ]
    )
    return proc.stdout.strip()


def test_admin_password_rotation(compose: list[str]) -> None:
    _require_opt_in()
    old = _secret("ipa_admin_password")
    run(["bash", "scripts/rotate-admin-password.sh", "--force"])
    new = _secret("ipa_admin_password")
    assert new != old
    assert _kinit_ok(compose, new, "/tmp/cc_admin_new")
    assert not _kinit_ok(compose, old, "/tmp/cc_admin_old")


def test_directory_manager_password_rotation(compose: list[str]) -> None:
    _require_opt_in()
    old = _secret("ipa_dm_password")
    run(["bash", "scripts/rotate-dm-password.sh"])
    new = _secret("ipa_dm_password")
    assert new != old
    dn = "cn=Directory Manager"
    assert _ldap_bind_ok(compose, dn, new)
    assert not _ldap_bind_ok(compose, dn, old)


def test_ldap_bind_password_rotation(compose: list[str]) -> None:
    _require_opt_in()
    old = _secret("ldap_bind_password")
    run(["bash", "scripts/rotate-ldap-bind-password.sh"])
    new = _secret("ldap_bind_password")
    assert new != old
    dn = "uid=svc-radiance,cn=sysaccounts,cn=etc,dc=ipa,dc=test"
    assert _ldap_bind_ok(compose, dn, new)
    assert not _ldap_bind_ok(compose, dn, old)


def test_api_key_rotation(compose: list[str]) -> None:
    _require_opt_in()
    old = _secret("radiance_api_key")
    run(["bash", "scripts/rotate-api-key.sh"])
    new = _secret("radiance_api_key")
    assert new != old
    assert len(new) == 64
    mode = (ROOT / "secrets/radiance_api_key").stat().st_mode & 0o777
    assert mode == 0o400, oct(mode)


def test_certificate_rotation(compose: list[str]) -> None:
    _require_opt_in()
    before = _serial(compose)
    run(["bash", "scripts/rotate-cert.sh"])
    after = _serial(compose)
    assert after != before
    proc = subprocess.run(
        [
            "openssl",
            "s_client",
            "-connect",
            "127.0.0.1:8443",
            "-servername",
            "radiance.ipa.test",
            "-verify_hostname",
            "radiance.ipa.test",
            "-CAfile",
            str(ROOT / "run/ipa-data/certs/ca.crt"),
            "-verify_return_error",
        ],
        input="",
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
