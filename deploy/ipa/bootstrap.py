#!/usr/bin/env python3
"""Idempotent FreeIPA bootstrap for the radiance stack.

Runs inside the one-off ``bootstrap`` service (which shares the IPA network
namespace). It creates users, groups, the service principal, the keytab and the
TLS certificate, and writes a completion marker the edge waits for.

The logic is deliberately importable and command-runner injectable so the unit
tests can exercise idempotency and failure paths without a real IPA server.

Security invariants:
  * passwords are never passed in argv (stdin only) and never logged;
  * failures leave no completion marker;
  * a pre-existing keytab is not rotated unless ``--force-keytab`` is given.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

LOG = logging.getLogger("ipa-bootstrap")

DEFAULT_DATA_DIR = Path("/data")
DEFAULT_SECRET_DIR = Path("/run/secrets")
MARKER_NAME = ".bootstrap-complete"
SYSACCOUNT_DN = "uid=svc-radiance,cn=sysaccounts,cn=etc,dc=ipa,dc=test"
KEYTAB_ENCTYPES = "aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96"
PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)
SERIAL_RE = re.compile(r"Serial number:\s*(\d+)")


class BootstrapError(RuntimeError):
    """A bootstrap step failed; the marker must not be written."""


@dataclass
class Completed:
    argv: Sequence[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner:
    """Thin subprocess wrapper; the unit tests replace this with a fake."""

    def __init__(self, timeout: int = 300) -> None:
        self.timeout = timeout

    def run(
        self,
        argv: Sequence[str],
        stdin: str | None = None,
        check: bool = True,
    ) -> Completed:
        LOG.info("+ %s", " ".join(shlex.quote(a) for a in argv))
        try:
            proc = subprocess.run(
                list(argv),
                input=stdin,
                text=True,
                capture_output=True,
                timeout=self.timeout,
                env=os.environ.copy(),
            )
        except FileNotFoundError as exc:
            raise BootstrapError(f"command not found: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise BootstrapError(f"command timed out: {argv[0]}") from exc
        result = Completed(argv, proc.returncode, proc.stdout, proc.stderr)
        if check and proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            tail = detail[-1] if detail else "no output"
            raise BootstrapError(
                f"{argv[0]} exited {proc.returncode}: {tail}"
            )
        return result


def _read_secret(secret_dir: Path, name: str, overrides: Mapping[str, str]) -> str:
    if name in overrides:
        value = overrides[name]
    else:
        path = secret_dir / name
        try:
            value = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise BootstrapError(f"missing secret {path}") from exc
    value = value.strip()
    if not value:
        raise BootstrapError(f"empty secret {name}")
    return value


@dataclass
class Bootstrap:
    runner: CommandRunner
    secrets: Mapping[str, str]
    data_dir: Path = DEFAULT_DATA_DIR
    realm: str = "IPA.TEST"
    domain: str = "ipa.test"
    kdc: str = "ipa.ipa.test"
    force_keytab: bool = False
    marker_name: str = MARKER_NAME
    extra_users: Sequence[str] = field(default_factory=list)
    ca_source: Path = Path("/etc/ipa/ca.crt")

    # ---- paths -----------------------------------------------------------
    @property
    def cert_dir(self) -> Path:
        return self.data_dir / "certs"

    @property
    def keytab_dir(self) -> Path:
        return self.data_dir / "keytabs"

    @property
    def keytab(self) -> Path:
        return self.keytab_dir / "radiance.keytab"

    @property
    def cert(self) -> Path:
        return self.cert_dir / "radiance.crt"

    @property
    def csr(self) -> Path:
        return self.cert_dir / "radiance.csr"

    @property
    def ca(self) -> Path:
        return self.cert_dir / "ca.crt"

    @property
    def marker(self) -> Path:
        return self.cert_dir / self.marker_name

    # ---- helpers ---------------------------------------------------------
    def _run(
        self, argv: Sequence[str], stdin: str | None = None, check: bool = True
    ) -> Completed:
        return self.runner.run(argv, stdin=stdin, check=check)

    def _ipa(
        self, argv: Sequence[str], stdin: str | None = None, check: bool = True
    ) -> Completed:
        return self._run(["ipa", *argv], stdin=stdin, check=check)

    def _exists(self, argv: Sequence[str]) -> bool:
        return self._run(argv, check=False).returncode == 0

    def _ensure_dir(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)

    # ---- individual steps -------------------------------------------------
    def kinit_admin(self) -> None:
        # The IPA JSON API delegates the admin TGT to the server to establish a
        # session, so this one-off bootstrap ticket must be forwardable. User
        # tickets for the edge are explicitly non-forwardable (-F) and never
        # leave the Pi host. kinit has no --password-file: stdin only.
        self._run(
            ["kinit", "-f", "admin"],
            stdin=self.secrets["ipa_admin_password"] + "\n",
        )

    def kdestroy(self) -> None:
        self._run(["kdestroy"], check=False)

    def ensure_group(self, name: str) -> None:
        if not self._exists(["ipa", "group-show", name]):
            self._ipa(["group-add", name])

    def ensure_user(self, uid: str, first: str, last: str) -> None:
        if self._exists(["ipa", "user-show", uid]):
            return
        self._ipa(
            [
                "user-add",
                uid,
                f"--first={first}",
                f"--last={last}",
                "--shell=/bin/bash",
            ]
        )
        self.set_password(uid, self.secrets[_secret_for_user(uid)])

    @staticmethod
    def _password_stdin(password: str) -> str:
        # ipa passwd prompts twice.
        return f"{password}\n{password}\n"

    def set_password(self, uid: str, password: str) -> None:
        self._ipa(["passwd", uid], stdin=self._password_stdin(password))
        # An admin reset can mark the password expired. Clear the expiry so the
        # test user can kinit non-interactively. Option verified in krbtpolicy
        # management and user plugin; fall back cleanly if unsupported.
        result = self._ipa(
            ["user-mod", uid, "--setattr=krbPasswordExpiration=20380101000000Z"],
            check=False,
        )
        if result.returncode != 0:
            LOG.warning(
                "could not clear password expiry for %s; kinit may prompt", uid
            )

    def ensure_group_member(self, group: str, uid: str) -> None:
        show = self._ipa(["group-show", group, "--all"], check=False)
        if show.returncode == 0 and re.search(
            rf"(?m)^\s*Member users:\s*.*\b{re.escape(uid)}\b", show.stdout
        ):
            return
        add = self._ipa(["group-add-member", group, f"--users={uid}"], check=False)
        if add.returncode != 0 and "already a member" not in (
            add.stderr + add.stdout
        ).lower():
            raise BootstrapError(
                f"could not add {uid} to {group}: {add.stderr.strip()}"
            )

    def ensure_sysaccount(self, uid: str = "svc-radiance") -> None:
        if self._exists(["ipa", "sysaccount-show", uid]):
            return
        password = self.secrets["ldap_bind_password"]
        self._ipa(["sysaccount-add", uid, "--password"], stdin=f"{password}\n{password}\n")

    def ensure_host(self, host: str = "radiance.ipa.test") -> None:
        if self._exists(["ipa", "host-show", host]):
            return
        self._ipa(["host-add", host, "--force", "--no-reverse"])

    def ensure_service(self, service: str = "HTTP/radiance.ipa.test") -> None:
        if self._exists(["ipa", "service-show", service]):
            return
        # No integrated DNS in this stack, so the host has no A/AAAA record to
        # validate. --force skips exactly that DNS check; --skip-host-check only
        # skips the host-object check.
        self._ipa(["service-add", "--force", service])

    def ensure_keytab(self) -> None:
        self._ensure_dir(self.keytab_dir)
        if self.keytab.exists() and not self.force_keytab:
            LOG.info("keytab exists; not rotating (use --force-keytab to rotate)")
            return
        tmp = self.keytab.with_suffix(".keytab.new")
        self._run(
            [
                "ipa-getkeytab",
                "-s",
                self.kdc,
                "-p",
                "HTTP/radiance.ipa.test",
                "-k",
                str(tmp),
                "-e",
                KEYTAB_ENCTYPES,
            ]
        )
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.keytab)

    def ensure_cert(self) -> None:
        self._ensure_dir(self.cert_dir)
        if self.cert.exists():
            LOG.info("TLS certificate exists; not reissuing")
            return
        if not self.csr.exists():
            raise BootstrapError(f"missing CSR {self.csr}")
        result = self._ipa(
            [
                "cert-request",
                "--principal=HTTP/radiance.ipa.test",
                "--profile=caIPAserviceCert",
                "--chain",
                str(self.csr),
            ],
            check=False,
        )
        if result.returncode != 0:
            raise BootstrapError(
                f"ipa cert-request failed: {result.stderr.strip() or result.stdout.strip()}"
            )
        blocks = PEM_RE.findall(result.stdout)
        if blocks:
            self.cert.write_text("\n".join(blocks) + "\n", encoding="utf-8")
        else:
            serial = SERIAL_RE.search(result.stdout)
            if not serial:
                raise BootstrapError(
                    "ipa cert-request produced neither a certificate nor a serial"
                )
            self._ipa(
                ["cert-show", serial.group(1), f"--out={self.cert}", "--chain"]
            )
        if not self.cert.exists():
            raise BootstrapError("certificate was not written")
        os.chmod(self.cert, 0o644)

    def copy_ca(self) -> None:
        self._ensure_dir(self.cert_dir)
        source = self.ca_source
        if not source.exists():
            raise BootstrapError(f"missing CA certificate {source}")
        self.ca.write_bytes(source.read_bytes())
        os.chmod(self.ca, 0o644)

    def set_ticket_policy(self) -> None:
        result = self._ipa(
            ["krbtpolicy-mod", "--maxlife=28800", "--maxrenew=604800"],
            check=False,
        )
        if result.returncode == 0:
            return
        output = (result.stdout + result.stderr).lower()
        if "no modifications" in output:
            LOG.info("ticket policy already set")
            return
        raise BootstrapError(
            f"ipa krbtpolicy-mod failed: {(result.stderr or result.stdout).strip()}"
        )

    def write_marker(self) -> None:
        self.marker.write_text("ok\n", encoding="utf-8")
        os.chmod(self.marker, 0o600)

    def clear_marker(self) -> None:
        try:
            self.marker.unlink()
        except FileNotFoundError:
            pass

    # ---- orchestration ----------------------------------------------------
    def run(self) -> None:
        self.clear_marker()
        try:
            self.kinit_admin()
            self.ensure_group("ai-users")
            self.ensure_group("ai-ops")
            self.ensure_user("pi", "Pi", "Harness")
            self.ensure_group_member("ai-users", "pi")
            self.ensure_user("mallory", "Mallory", "Tester")
            for uid in self.extra_users:
                self.ensure_user(uid, uid.capitalize(), "User")
            self.ensure_sysaccount()
            self.ensure_host()
            self.ensure_service()
            self.ensure_keytab()
            self.ensure_cert()
            self.copy_ca()
            self.set_ticket_policy()
            self.write_marker()
            LOG.info("bootstrap complete")
        finally:
            self.kdestroy()


def _secret_for_user(uid: str) -> str:
    return {"pi": "pi_password", "mallory": "mallory_password"}.get(
        uid, f"{uid}_password"
    )


def load_secrets(
    secret_dir: Path = DEFAULT_SECRET_DIR,
    overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    overrides = overrides or {}
    return {
        name: _read_secret(secret_dir, name, overrides)
        for name in (
            "ipa_admin_password",
            "pi_password",
            "mallory_password",
            "ldap_bind_password",
        )
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="FreeIPA bootstrap for radiance-krb")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--secret-dir", type=Path, default=DEFAULT_SECRET_DIR)
    parser.add_argument("--realm", default="IPA.TEST")
    parser.add_argument("--domain", default="ipa.test")
    parser.add_argument("--kdc", default="ipa.ipa.test")
    parser.add_argument("--force-keytab", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )
    try:
        secrets = load_secrets(args.secret_dir)
        job = Bootstrap(
            runner=CommandRunner(),
            secrets=secrets,
            data_dir=args.data_dir,
            realm=args.realm,
            domain=args.domain,
            kdc=args.kdc,
            force_keytab=args.force_keytab,
        )
        job.run()
    except BootstrapError as exc:
        LOG.error("bootstrap failed: %s", exc)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
