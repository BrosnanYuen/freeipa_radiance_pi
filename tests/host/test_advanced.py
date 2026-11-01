"""Slow host checks that mutate the live realm/session.

Opt in with RUN_SLOW=1. They use the host's kinit/curl against the published
KDC and edge ports, so they exercise the same path a host-mode user would.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from helpers import ROOT, run

pytestmark = [pytest.mark.host, pytest.mark.slow]

REALM = "IPA.TEST"
EDGE = "https://radiance.ipa.test:8443/v1/models"


def _require_slow() -> None:
    if os.environ.get("RUN_SLOW") != "1":
        pytest.skip("set RUN_SLOW=1 (these checks wait for cache/ticket expiry)")


def _local_krb5(tmp_path: Path) -> Path:
    source = (ROOT / "run/krb5.conf").read_text(encoding="utf-8")
    path = tmp_path / "krb5.conf"
    path.write_text(source.replace("ipa.ipa.test", "127.0.0.1"), encoding="utf-8")
    return path


def _secret(name: str) -> str:
    path = ROOT / "secrets" / name
    if not path.is_file():
        pytest.skip(f"{path} is missing")
    return path.read_text(encoding="utf-8").strip()


def _kinit(
    tmp_path: Path,
    principal: str,
    password: str,
    lifetime: str = "8h",
) -> tuple[Path, Path]:
    krb5 = _local_krb5(tmp_path)
    ccache = tmp_path / f"cc_{principal}"
    env = os.environ.copy()
    env["KRB5_CONFIG"] = str(krb5)
    env["KRB5CCNAME"] = f"FILE:{ccache}"
    proc = subprocess.run(
        ["kinit", "-F", "-l", lifetime, principal],
        input=password + "\n",
        text=True,
        capture_output=True,
        env=env,
        timeout=60,
    )
    if proc.returncode != 0:
        pytest.fail(f"kinit {principal}: {proc.stderr or proc.stdout}")
    os.chmod(ccache, 0o600)
    return krb5, ccache


def _curl(ca: Path, env: dict[str, str]) -> int:
    proc = subprocess.run(
        [
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--negotiate",
            "-u",
            ":",
            "--cacert",
            str(ca),
            "--resolve",
            "radiance.ipa.test:8443:127.0.0.1",
            EDGE,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    try:
        return int(proc.stdout.strip())
    except ValueError:
        return -1


def _with_ccache(krb5: Path, ccache: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["KRB5_CONFIG"] = str(krb5)
    env["KRB5CCNAME"] = f"FILE:{ccache}"
    return env


def _wait_for(expected: int, ca: Path, env: dict[str, str], timeout: int = 80) -> int:
    deadline = time.monotonic() + timeout
    code = _curl(ca, env)
    while code != expected and time.monotonic() < deadline:
        time.sleep(2)
        code = _curl(ca, env)
    return code


def _bootstrap(cmd: str) -> subprocess.CompletedProcess[str]:
    return run(
        [
            "docker",
            "compose",
            "--env-file",
            ".env",
            "--profile",
            "bootstrap",
            "run",
            "--rm",
            "-T",
            "--entrypoint",
            "/bin/bash",
            "bootstrap",
            "-lc",
            cmd,
        ],
        check=False,
    )


def test_t4b_group_revocation(compose, tmp_path: Path) -> None:
    _require_slow()
    ca = ROOT / "run/ipa-data/certs/ca.crt"
    krb5, ccache = _kinit(tmp_path, "pi", _secret("pi_password"))
    env = _with_ccache(krb5, ccache)

    def status() -> int:
        return _curl(ca, env)

    assert _wait_for(200, ca, env) == 200, "pi is not authorized at test start"
    remove = _bootstrap(
        "kinit -f admin < /run/secrets/ipa_admin_password && "
        "ipa group-remove-member ai-users --users=pi"
    )
    if remove.returncode != 0:
        pytest.skip(f"could not remove pi from ai-users: {remove.stderr}")
    try:
        time.sleep(66)  # LDAPCacheTTL is 60
        assert status() == 403, "revocation was not effective after the cache TTL"
    finally:
        _bootstrap(
            "kinit -f admin < /run/secrets/ipa_admin_password && "
            "ipa group-add-member ai-users --users=pi"
        )
    assert _wait_for(200, ca, env) == 200, "pi was not re-authorized after restore"


def test_t10_short_ticket_expiry_and_recovery(compose, tmp_path: Path) -> None:
    _require_slow()
    ca = ROOT / "run/ipa-data/certs/ca.crt"
    krb5, ccache = _kinit(tmp_path, "pi", _secret("pi_password"), lifetime="30s")
    env = _with_ccache(krb5, ccache)
    assert _wait_for(200, ca, env) == 200
    time.sleep(40)
    assert _curl(ca, env) == 401  # ccache is expired
    krb5, ccache = _kinit(tmp_path, "pi", _secret("pi_password"))
    assert _wait_for(200, ca, _with_ccache(krb5, ccache)) == 200
