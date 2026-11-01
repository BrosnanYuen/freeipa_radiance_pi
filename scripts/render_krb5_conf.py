#!/usr/bin/env python3
"""Render the client krb5.conf used by every container (and host mode)."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

TEMPLATE = """\
[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false
    udp_preference_limit = 1
    forwardable = false
    proxiable = false
    ticket_lifetime = 8h
    renew_lifetime = 7d
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96

[realms]
    {realm} = {{
        kdc = {kdc}:88
        admin_server = {kdc}:749
        kpasswd_server = {kdc}:464
        auth_to_local = RULE:[1:$1]
        auth_to_local = DEFAULT
    }}

[domain_realm]
    .{domain} = {realm}
    {domain} = {realm}
"""


def render_krb5(realm: str, kdc: str, domain: str) -> str:
    if not realm or not kdc or not domain:
        raise ValueError("realm, kdc and domain are required")
    return TEMPLATE.format(realm=realm, kdc=kdc, domain=domain)


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".krb5-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o644)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--realm", default="IPA.TEST")
    parser.add_argument("--kdc", default="ipa.ipa.test")
    parser.add_argument("--domain", default="ipa.test")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        write_file(args.out, render_krb5(args.realm, args.kdc, args.domain))
    except ValueError as exc:
        print(f"render-krb5: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
