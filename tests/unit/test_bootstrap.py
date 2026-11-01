from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import bootstrap
from bootstrap import (
    Bootstrap,
    BootstrapError,
    Completed,
    KEYTAB_ENCTYPES,
    SYSACCOUNT_DN,
    load_secrets,
)

PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBmockcertificate\n"
    "-----END CERTIFICATE-----\n"
)
SECRETS = {
    "ipa_admin_password": "adminpass123456",
    "pi_password": "pipass123456",
    "mallory_password": "mallorypass123456",
    "ldap_bind_password": "ldapbind123456",
}


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.users: set[str] = set()
        self.groups: set[str] = set()
        self.members: dict[str, set[str]] = {"ai-users": set()}
        self.sysaccounts: set[str] = set()
        self.hosts: set[str] = set()
        self.services: set[str] = set()
        self.failures: set[str] = set()
        self.fail_cert = False
        self.pem: str | None = PEM

    def run(self, argv, stdin=None, check=True):
        argv = list(argv)
        self.calls.append((argv, stdin))
        joined = " ".join(argv)
        if any(marker in joined for marker in self.failures):
            if check:
                raise BootstrapError(f"simulated failure: {joined}")
            return Completed(argv, 1, "", "simulated failure")
        command = argv[1] if len(argv) > 1 and argv[0] == "ipa" else argv[0]
        if argv[0] == "kinit":
            return Completed(argv, 0)
        if argv[0] == "kdestroy":
            return Completed(argv, 0)
        if argv[0] == "ipa-getkeytab":
            target = Path(argv[argv.index("-k") + 1])
            target.write_bytes(b"FAKEKEYTAB")
            return Completed(argv, 0)
        if argv[0] == "ipa":
            if command == "user-show":
                return Completed(argv, 0 if argv[2] in self.users else 1)
            if command == "user-add":
                self.users.add(argv[2])
                return Completed(argv, 0)
            if command == "passwd":
                return Completed(argv, 0)
            if command == "user-mod":
                return Completed(argv, 0)
            if command == "group-show":
                group = argv[2]
                if group not in self.groups:
                    return Completed(argv, 1)
                members = sorted(self.members.get(group, set()))
                return Completed(argv, 0, f"Member users: {', '.join(members)}\n")
            if command == "group-add":
                self.groups.add(argv[2])
                return Completed(argv, 0)
            if command == "group-add-member":
                group = argv[2].split("=", 1)[-1] if argv[2] else ""
                user = argv[3].split("=", 1)[-1]
                self.members.setdefault(group, set()).add(user)
                return Completed(argv, 0)
            if command == "sysaccount-show":
                return Completed(argv, 0 if argv[2] in self.sysaccounts else 1)
            if command == "sysaccount-add":
                self.sysaccounts.add(argv[2])
                return Completed(argv, 0)
            if command == "host-show":
                return Completed(argv, 0 if argv[2] in self.hosts else 1)
            if command == "host-add":
                self.hosts.add(argv[2])
                return Completed(argv, 0)
            if command == "service-show":
                return Completed(argv, 0 if argv[2] in self.services else 1)
            if command == "service-add":
                self.services.add(argv[-1])
                return Completed(argv, 0)
            if command == "cert-request":
                if self.fail_cert:
                    return Completed(argv, 1, "", "certificate request failed")
                if self.pem:
                    return Completed(argv, 0, "Certificate:\n" + self.pem)
                return Completed(argv, 0, "Certificate:\nSerial number: 42\n")
            if command == "cert-show":
                out = next(arg for arg in argv if arg.startswith("--out="))
                Path(out.split("=", 1)[1]).write_text(PEM)
                return Completed(argv, 0)
            if command == "krbtpolicy-mod":
                return Completed(argv, 0)
            return Completed(argv, 0)
        return Completed(argv, 0)


def make_bootstrap(
    tmp_path: Path, runner: FakeRunner, *, force_keytab: bool = False
) -> Bootstrap:
    data = tmp_path / "data"
    certs = data / "certs"
    certs.mkdir(parents=True)
    (certs / "radiance.csr").write_text("-----BEGIN CERTIFICATE REQUEST-----\n")
    ca = tmp_path / "ca.crt"
    ca.write_text("CA CERT")
    return Bootstrap(
        runner=runner,
        secrets=SECRETS,
        data_dir=data,
        ca_source=ca,
        force_keytab=force_keytab,
    )


def test_happy_path(tmp_path: Path) -> None:
    runner = FakeRunner()
    job = make_bootstrap(tmp_path, runner)
    job.run()
    assert job.marker.is_file()
    assert job.marker.stat().st_mode & 0o777 == 0o600
    assert job.keytab.read_bytes() == b"FAKEKEYTAB"
    assert stat.S_IMODE(job.keytab.stat().st_mode) == 0o600
    assert "BEGIN CERTIFICATE" in job.cert.read_text()
    assert job.ca.read_text() == "CA CERT"
    assert "pi" in runner.members["ai-users"]
    assert "svc-radiance" in runner.sysaccounts
    assert "radiance.ipa.test" in runner.hosts
    assert "HTTP/radiance.ipa.test" in runner.services
    keytab_calls = [argv for argv, _ in runner.calls if argv[0] == "ipa-getkeytab"]
    assert keytab_calls and KEYTAB_ENCTYPES in keytab_calls[0]
    cert_calls = [argv for argv, _ in runner.calls if argv[1:2] == ["cert-request"]]
    assert "--profile=caIPAserviceCert" in cert_calls[0]
    policy = [argv for argv, _ in runner.calls if argv[1:2] == ["krbtpolicy-mod"]]
    assert "--maxlife=28800" in policy[0]
    assert "--maxrenew=604800" in policy[0]


def test_passwords_on_stdin_not_argv(tmp_path: Path) -> None:
    runner = FakeRunner()
    make_bootstrap(tmp_path, runner).run()
    for argv, stdin in runner.calls:
        for secret in SECRETS.values():
            assert secret not in " ".join(argv)
    kinit_calls = [(argv, stdin) for argv, stdin in runner.calls if argv[0] == "kinit"]
    assert kinit_calls[0][0] == ["kinit", "-f", "admin"]
    assert kinit_calls[0][1] == SECRETS["ipa_admin_password"] + "\n"
    passwd_calls = [(argv, stdin) for argv, stdin in runner.calls if argv[1:2] == ["passwd"]]
    assert passwd_calls
    assert passwd_calls[0][1] == (
        SECRETS["pi_password"] + "\n" + SECRETS["pi_password"] + "\n"
    )
    sysaccount = [argv for argv, _ in runner.calls if argv[1:2] == ["sysaccount-add"]]
    assert "--password" in sysaccount[0]
    assert SYSACCOUNT_DN.endswith("cn=sysaccounts,cn=etc,dc=ipa,dc=test")


def test_second_run_is_idempotent(tmp_path: Path) -> None:
    runner = FakeRunner()
    job = make_bootstrap(tmp_path, runner)
    job.run()
    runner.calls.clear()
    job.run()
    joined = [" ".join(argv) for argv, _ in runner.calls]
    for forbidden in ("user-add", "host-add", "service-add", "ipa-getkeytab", "cert-request", "passwd"):
        assert not any(forbidden in line for line in joined), forbidden
    assert job.marker.is_file()


def test_force_keytab_rotates(tmp_path: Path) -> None:
    runner = FakeRunner()
    job = make_bootstrap(tmp_path, runner, force_keytab=True)
    job.run()
    runner.calls.clear()
    job.run()
    assert any(argv[0] == "ipa-getkeytab" for argv, _ in runner.calls)


def test_missing_secret(tmp_path: Path) -> None:
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    (secret_dir / "ipa_admin_password").write_text("x")
    with pytest.raises(BootstrapError):
        load_secrets(secret_dir)


def test_failed_kinit_leaves_no_marker(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.failures.add("kinit -f admin")
    job = make_bootstrap(tmp_path, runner)
    with pytest.raises(BootstrapError):
        job.run()
    assert not job.marker.exists()


def test_missing_csr_leaves_no_marker(tmp_path: Path) -> None:
    runner = FakeRunner()
    job = make_bootstrap(tmp_path, runner)
    job.csr.unlink()
    with pytest.raises(BootstrapError):
        job.run()
    assert not job.marker.exists()


def test_cert_request_failure_leaves_no_marker(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.fail_cert = True
    job = make_bootstrap(tmp_path, runner)
    with pytest.raises(BootstrapError):
        job.run()
    assert not job.marker.exists()


def test_ticket_policy_already_set_is_not_a_failure(tmp_path: Path) -> None:
    runner = FakeRunner()
    job = make_bootstrap(tmp_path, runner)
    job.set_ticket_policy = lambda: None  # type: ignore[method-assign]
    # Exercise the real method with a no-op result instead.
    from bootstrap import BootstrapError, Completed

    class PolicyRunner(FakeRunner):
        def run(self, argv, stdin=None, check=True):
            if argv[1:2] == ["krbtpolicy-mod"]:
                return Completed(argv, 1, "", "no modifications to be performed")
            return super().run(argv, stdin=stdin, check=check)

    job2 = Bootstrap(
        runner=PolicyRunner(),
        secrets=SECRETS,
        data_dir=tmp_path / "data2",
        ca_source=job.ca_source,
    )
    (tmp_path / "data2/certs").mkdir(parents=True)
    (tmp_path / "data2/certs/radiance.csr").write_text("csr")
    job2.set_ticket_policy()


def test_cert_serial_fallback(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.pem = None
    job = make_bootstrap(tmp_path, runner)
    job.run()
    cert_show = [argv for argv, _ in runner.calls if argv[1:2] == ["cert-show"]]
    assert cert_show and cert_show[0][2] == "42"
    assert job.cert.is_file()


def test_secret_overrides() -> None:
    loaded = load_secrets(Path("/nonexistent"), overrides=SECRETS)
    assert loaded == SECRETS
