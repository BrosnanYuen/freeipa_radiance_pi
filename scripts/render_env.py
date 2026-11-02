#!/usr/bin/env python3
"""Render .env from .env.example with the current host's UID/GIDs.

The image pins and the model path stay as written; the four identity values and
the GPU device GIDs are filled from the invoking user and from ``getent`` (the
``grp`` module). Existing .env files are never overwritten unless --force is
given: they may contain deliberate host choices.
"""

from __future__ import annotations

import argparse
import grp
import os
import sys
from pathlib import Path
from typing import Mapping, Sequence

DETECTED_KEYS = ("PI_UID", "PI_GID", "RADIANCE_UID", "RADIANCE_GID", "RENDER_GID", "VIDEO_GID")


def _group_gid(name: str, fallback: int) -> int:
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return fallback


def render_env(
    text: str,
    *,
    uid: int,
    gid: int,
    render_gid: int,
    video_gid: int,
) -> str:
    values = {
        "PI_UID": str(uid),
        "PI_GID": str(gid),
        "RADIANCE_UID": str(uid),
        "RADIANCE_GID": str(gid),
        "RENDER_GID": str(render_gid),
        "VIDEO_GID": str(video_gid),
    }
    rendered: list[str] = []
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key = line.split("=", 1)[0].strip()
            if key in values:
                rendered.append(f"{key}={values[key]}")
                continue
        rendered.append(line)
    if text.endswith("\n"):
        rendered.append("")
    return "\n".join(rendered)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(".env.example"))
    parser.add_argument("--out", type=Path, default=Path(".env"))
    parser.add_argument("--force", action="store_true", help="overwrite an existing .env")
    parser.add_argument("--render-gid", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--video-gid", type=int, default=None, help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.out.exists() and not args.force:
        print(f"env: {args.out} already exists; left unchanged", file=sys.stderr)
        return 0
    try:
        source = args.source.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"env: cannot read {args.source}: {exc}", file=sys.stderr)
        return 2

    fallbacks = {"RENDER_GID": 989, "VIDEO_GID": 985}
    for line in source.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key.strip() in fallbacks and value.strip().isdigit():
                fallbacks[key.strip()] = int(value.strip())

    rendered = render_env(
        source,
        uid=os.getuid(),
        gid=os.getgid(),
        render_gid=args.render_gid
        if args.render_gid is not None
        else _group_gid("render", fallbacks["RENDER_GID"]),
        video_gid=args.video_gid
        if args.video_gid is not None
        else _group_gid("video", fallbacks["VIDEO_GID"]),
    )
    args.out.write_text(rendered, encoding="utf-8")
    os.chmod(args.out, 0o600)
    print(f"env: wrote {args.out} (UID/GIDs detected on this host)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
