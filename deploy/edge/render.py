#!/usr/bin/env python3
"""Render the radiance edge virtual host from a template.

Secrets are read from files (never argv) and the rendered file is created with
mode 0600. The template is validated before Apache sees it: a secret containing
characters that could break out of an Apache quoted string is rejected rather
than escaped, because every secret in this stack is generated hex.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

_LDAP = "{{LDAP_BIND_PASSWORD}}"
_API = "{{RADIANCE_API_KEY}}"
_SECRET_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{8,256}$")


class RenderError(ValueError):
    """The template or a secret cannot be rendered safely."""


def _read_secret(path: Path, label: str) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RenderError(f"cannot read {label} from {path}: {exc.strerror}") from exc
    if not value:
        raise RenderError(f"{label} is empty")
    if not _SECRET_RE.match(value):
        raise RenderError(
            f"{label} contains characters that are unsafe in an Apache config"
        )
    return value


def render_vhost(template: str, ldap_password: str, api_key: str) -> str:
    """Replace the two secret placeholders and reject malformed input."""
    for label, value in (("LDAP bind password", ldap_password), ("radiance API key", api_key)):
        if not _SECRET_RE.match(value):
            raise RenderError(f"{label} contains unsafe characters")
    if _LDAP not in template or _API not in template:
        raise RenderError("template is missing a required secret placeholder")
    return template.replace(_LDAP, ldap_password).replace(_API, api_key)


def render_file(
    template_path: Path,
    out_path: Path,
    ldap_password_file: Path,
    api_key_file: Path,
) -> None:
    template = template_path.read_text(encoding="utf-8")
    rendered = render_vhost(
        template,
        _read_secret(ldap_password_file, "LDAP bind password"),
        _read_secret(api_key_file, "radiance API key"),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".radiance-", dir=str(out_path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, out_path)
        os.chmod(out_path, 0o600)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ldap-password-file", type=Path, required=True)
    parser.add_argument("--api-key-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        render_file(
            args.template, args.out, args.ldap_password_file, args.api_key_file
        )
    except RenderError as exc:
        print(f"render error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
