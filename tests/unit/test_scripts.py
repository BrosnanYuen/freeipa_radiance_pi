from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

import render_install_options
import render_krb5_conf

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
TEMPLATE = ROOT / "deploy/ipa/install-options.tmpl"


def test_krb5_renderer_content_and_mode(tmp_path: Path) -> None:
    out = tmp_path / "krb5.conf"
    assert (
        render_krb5_conf.main(
            [
                "--realm",
                "IPA.TEST",
                "--kdc",
                "ipa.ipa.test",
                "--domain",
                "ipa.test",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    text = out.read_text()
    assert stat.S_IMODE(out.stat().st_mode) == 0o644
    for expected in (
        "default_realm = IPA.TEST",
        "kdc = ipa.ipa.test:88",
        "admin_server = ipa.ipa.test:749",
        "permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96",
        "forwardable = false",
        "proxiable = false",
        "dns_lookup_kdc = false",
        "auth_to_local = RULE:[1:$1]",
        "[domain_realm]",
    ):
        assert expected in text
    assert "rc4" not in text.lower()
    assert "des" not in text.lower()


def test_install_options_render(tmp_path: Path) -> None:
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    (secret_dir / "ipa_admin_password").write_text("adminpass123456\n")
    (secret_dir / "ipa_dm_password").write_text("dmpass123456\n")
    out = tmp_path / "options"
    assert (
        render_install_options.main(
            [
                "--template",
                str(TEMPLATE),
                "--out",
                str(out),
                "--secret-dir",
                str(secret_dir),
                "--realm",
                "IPA.TEST",
                "--domain",
                "ipa.test",
            ]
        )
        == 0
    )
    text = out.read_text()
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert "--realm=IPA.TEST" in text
    assert "--domain=ipa.test" in text
    assert "--admin-password=adminpass123456" in text
    assert "--ds-password=dmpass123456" in text
    assert "--no-ntp" in text
    assert "#" not in text


def test_install_options_refuses_equal_passwords() -> None:
    template = TEMPLATE.read_text()
    with pytest.raises(ValueError):
        render_install_options.render_options(template, "samepassword", "samepassword")


@pytest.mark.parametrize("bad", ["short", 'has"quote', "has\nnewline", "has space"])
def test_install_options_refuses_unsafe_passwords(bad: str) -> None:
    template = TEMPLATE.read_text()
    with pytest.raises(ValueError):
        render_install_options.render_options(template, bad, "dmpass123456")


def test_install_options_requires_placeholders() -> None:
    with pytest.raises(ValueError):
        render_install_options.render_options("no placeholders", "adminpass123456", "dmpass123456")


def test_gen_cert_script(tmp_path: Path) -> None:
    if not shutil.which("openssl"):
        pytest.skip("openssl is not installed")
    env = os.environ.copy()
    env["CERT_DIR"] = str(tmp_path / "certs")
    env["RADIANCE_HOSTNAME"] = "radiance.ipa.test"
    first = subprocess.run(
        ["bash", str(SCRIPTS / "gen-cert.sh")],
        capture_output=True,
        text=True,
        env=env,
    )
    assert first.returncode == 0, first.stderr
    key = tmp_path / "certs/radiance.key"
    csr = tmp_path / "certs/radiance.csr"
    assert key.is_file() and csr.is_file()
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(csr.stat().st_mode) == 0o644
    key_before = key.read_bytes()
    subject = subprocess.run(
        ["openssl", "req", "-in", str(csr), "-noout", "-subject"],
        capture_output=True,
        text=True,
    )
    assert "radiance.ipa.test" in subject.stdout
    second = subprocess.run(
        ["bash", str(SCRIPTS / "gen-cert.sh")],
        capture_output=True,
        text=True,
        env=env,
    )
    assert second.returncode == 0
    assert key.read_bytes() == key_before


def test_up_sh_invariants() -> None:
    up = (SCRIPTS / "up.sh").read_text()
    assert "--gpu" in up and "--mock" in up
    assert "chmod 400 secrets/radiance_api_key" in up
    assert "shred -u /data/ipa-server-install-options" in up
    assert "wait_healthy ipa 1800" in up
    assert "radiance-shim" in up
    assert "RADIANCE_SECCOMP" in up
    assert "realpath -m" in up
    assert "render_install_options.py" in up
    assert "check_model_licenses.py" in up
    assert "render_env.py" in up


def test_down_sh_profiles() -> None:
    down = (SCRIPTS / "down.sh").read_text()
    for profile in ("bootstrap", "client", "gpu", "test-fast", "test"):
        assert f"--profile {profile}" in down


def test_rotate_keytab_script() -> None:
    text = (SCRIPTS / "rotate-keytab.sh").read_text()
    assert "ipa-getkeytab" in text
    assert "-p HTTP/radiance.ipa.test" in text
    assert "recreate_gateway_stack" in text


def test_rotation_scripts_exist_and_avoid_argv_secrets() -> None:
    for name in (
        "rotate-admin-password.sh",
        "rotate-dm-password.sh",
        "rotate-ldap-bind-password.sh",
        "rotate-api-key.sh",
        "rotate-cert.sh",
    ):
        path = SCRIPTS / name
        assert path.is_file(), name
        assert path.stat().st_mode & 0o111, name
        text = path.read_text()
        assert ". \"$(dirname \"$0\")/lib.sh\"" in text, name
        # The password is deliberately passed on stdin, never as an argument.
        assert "--password-file" not in text


def test_makefile_targets() -> None:
    makefile = (ROOT / "Makefile").read_text()
    for target in (
        "unit",
        "config",
        "edge-check",
        "up",
        "up-gpu",
        "smoke",
        "test-fast",
        "test-host",
        "test-rotation",
        "license-check",
        "reset",
        "env",
        "host-pi",
        "backup-ipa",
    ):
        assert f"{target}:" in makefile
