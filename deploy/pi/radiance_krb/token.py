#!/usr/bin/env python3
"""Print a fresh Negotiate token, or check that one can be acquired.

Exit codes are part of the contract:
  0 success
  2 no ccache
  3 expired credentials
  4 GSSAPI failure

Secrets never appear on stdout on failure, and no token is ever logged.
"""

from __future__ import annotations

import argparse
import base64
import sys
from typing import Sequence

from .kerberos import KerberosError, TokenProvider


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--service",
        default="HTTP/radiance.ipa.test",
        help="host-based service name (default: HTTP/radiance.ipa.test)",
    )
    parser.add_argument(
        "--format",
        choices=("header", "token"),
        default="header",
        help="Negotiate header (default) or bare base64 token",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="acquire a token to validate credentials, print nothing",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    provider = TokenProvider(args.service)
    try:
        token = provider.token()
    except KerberosError as exc:
        print(f"radiance-krb-token: {exc}", file=sys.stderr)
        return exc.exit_code
    if args.check:
        print("ok", file=sys.stderr)
        return 0
    encoded = base64.b64encode(token).decode("ascii")
    if args.format == "token":
        sys.stdout.write(encoded + "\n")
    else:
        sys.stdout.write("Negotiate " + encoded + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
