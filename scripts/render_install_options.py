#!/usr/bin/env python3
"""Render the FreeIPA install-options file without putting secrets in argv.

Reads ipa_admin_password and ipa_dm_password from a secret directory and writes
the options file 0600. The caller shreds it after the realm is installed.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

_SECRET_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{8,256}$")


def render_options(template: str, admin_password: str, dm_password: str) -> str:
    for label, value in (
        ("admin password", admin_password),
        ("Directory Manager password", dm_password),
    ):
        if not _SECRET_RE.match(value):
            raise ValueError(f"{label} is empty or contains unsafe characters")
    if admin_password == dm_password:
        raise ValueError("admin and Directory Manager passwords must differ")
    if "{{ADMIN_PASSWORD}}" not in template or "{{DM_PASSWORD}}" not in template:
        raise ValueError("template is missing a password placeholder")
    rendered = template.replace("{{ADMIN_PASSWORD}}", admin_password).replace(
        "{{DM_PASSWORD}}", dm_password
    )
    # The container concatenates this file with xargs: comments and blank lines
    # would become literal arguments to ipa-server-install.
    lines = [
        line
        for line in rendered.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--secret-dir", type=Path, default=Path("secrets"))
    parser.add_argument("--realm", default="IPA.TEST")
    parser.add_argument("--domain", default="ipa.test")
    args = parser.parse_args(argv)
    try:
        admin = (args.secret_dir / "ipa_admin_password").read_text().strip()
        dm = (args.secret_dir / "ipa_dm_password").read_text().strip()
        rendered = render_options(
            args.template.read_text(encoding="utf-8"), admin, dm
        ).replace("{{REALM}}", args.realm).replace("{{DOMAIN}}", args.domain)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".ipa-options-", dir=str(args.out.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, args.out)
            os.chmod(args.out, 0o600)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
    except (OSError, ValueError) as exc:
        print(f"render-install-options: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
