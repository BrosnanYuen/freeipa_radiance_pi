"""Destructive edge checks. Opt in with RUN_DESTRUCTIVE=1.

They corrupt/rotate the live keytab but restore a working edge afterwards.
"""

from __future__ import annotations

import base64
import os
import subprocess
import time
from pathlib import Path

import pytest

from helpers import ROOT, run

pytestmark = [pytest.mark.host, pytest.mark.destructive]

EDGE = "https://radiance.ipa.test:8443/v1/models"
CA = ROOT / "run/ipa-data/certs/ca.crt"
KEYTAB_DIR = ROOT / "run/ipa-data/keytabs"


def _require_opt_in() -> None:
    if os.environ.get("RUN_DESTRUCTIVE") != "1":
        pytest.skip("set RUN_DESTRUCTIVE=1 (mutates the live keytab)")


def _secret(name: str) -> str:
    return (ROOT / "secrets" / name).read_text(encoding="utf-8").strip()


def _host_env(tmp_path: Path) -> tuple[dict[str, str], Path]:
    krb5 = tmp_path / "krb5.conf"
    krb5.write_text(
        (ROOT / "run/krb5.conf").read_text().replace("ipa.ipa.test", "127.0.0.1"),
        encoding="utf-8",
    )
    ccache = tmp_path / "cc"
    env = os.environ.copy()
    env["KRB5_CONFIG"] = str(krb5)
    env["KRB5CCNAME"] = f"FILE:{ccache}"
    proc = subprocess.run(
        ["kinit", "-F", "pi"],
        input=_secret("pi_password") + "\n",
        text=True,
        capture_output=True,
        env=env,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    os.chmod(ccache, 0o600)
    return env, ccache


def _status(env: dict[str, str], token: str | None = None) -> int:
    headers = ["-H", f"Authorization: Negotiate {token}"] if token else ["--negotiate", "-u", ":"]
    proc = subprocess.run(
        [
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            *headers,
            "--cacert",
            str(CA),
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


def _wait_status(env, expected: int, timeout: int = 90) -> int:
    deadline = time.monotonic() + timeout
    code = _status(env)
    while code != expected and time.monotonic() < deadline:
        time.sleep(2)
        code = _status(env)
    return code


def _restart_edge_mock() -> None:
    run(
        [
            "docker",
            "compose",
            "--env-file",
            ".env",
            "up",
            "-d",
            "--force-recreate",
            "radiance-edge",
            "mock-radiance",
        ],
        check=False,
    )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        proc = run(
            ["docker", "compose", "--env-file", ".env", "exec", "-T", "radiance-edge", "curl", "-fsS", "http://127.0.0.1:8081/healthz"],
            check=False,
        )
        if proc.returncode == 0:
            return
        time.sleep(2)
    pytest.fail("edge did not become healthy")


def _keytab_container(command: str) -> None:
    run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{KEYTAB_DIR}:/keytabs",
            "alpine:3.22",
            "sh",
            "-c",
            command,
        ]
    )


def test_t5_wrong_keytab_is_rejected(compose, tmp_path: Path) -> None:
    _require_opt_in()
    env, _ = _host_env(tmp_path)
    assert _wait_status(env, 200) == 200
    _keytab_container(
        "cp /keytabs/radiance.keytab /keytabs/radiance.keytab.good && "
        "printf 'not-a-keytab\\n' > /keytabs/radiance.keytab && "
        "chmod 600 /keytabs/radiance.keytab"
    )
    try:
        _restart_edge_mock()
        assert _wait_status(env, 401, timeout=30) == 401
    finally:
        _keytab_container(
            "cp /keytabs/radiance.keytab.good /keytabs/radiance.keytab && "
            "chmod 600 /keytabs/radiance.keytab && rm -f /keytabs/radiance.keytab.good"
        )
        _restart_edge_mock()
    assert _wait_status(env, 200) == 200


def _negotiate_token(ccache_dir: Path) -> str:
    proc = run(
        [
            "docker",
            "compose",
            "--env-file",
            ".env",
            "--profile",
            "test",
            "run",
            "--rm",
            "-T",
            "-v",
            f"{ccache_dir}:/hostcc:ro",
            "-e",
            "KRB5CCNAME=FILE:/hostcc/cc",
            "test-runner",
            "python",
            "-c",
            (
                "import base64, gssapi; "
                "n=gssapi.Name('HTTP@radiance.ipa.test', gssapi.NameType.hostbased_service); "
                "c=gssapi.SecurityContext(name=n, usage='initiate'); "
                "print(base64.b64encode(c.step(None)).decode())"
            ),
        ],
        check=True,
    )
    token = proc.stdout.strip().splitlines()[-1]
    assert token
    return token


def test_t16_keytab_rotation_invalidates_old_tickets(compose, tmp_path: Path) -> None:
    _require_opt_in()
    env, _ = _host_env(tmp_path)
    assert _wait_status(env, 200) == 200
    token = _negotiate_token(tmp_path)
    assert _status(env, token=token) == 200
    run(["bash", "scripts/rotate-keytab.sh"], check=True)
    # The edge restart recreated its netns; the mock must follow it.
    run(
        [
            "docker",
            "compose",
            "--env-file",
            ".env",
            "up",
            "-d",
            "--force-recreate",
            "mock-radiance",
        ],
        check=False,
    )
    time.sleep(5)
    assert _status(env, token=token) == 401, "old service ticket survived rotation"
    # The ccache still holds the service ticket obtained before rotation, so a
    # re-login is required to exercise the new keytab.
    subprocess.run(["kdestroy"], env=env, timeout=30)
    env, _ = _host_env(tmp_path)
    assert _wait_status(env, 200) == 200, "fresh ticket failed after rotation"
