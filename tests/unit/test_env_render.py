from __future__ import annotations

import os
import stat
from pathlib import Path

import render_env


def test_render_env_replaces_identity_values() -> None:
    source = (
        "# comment\n"
        "FREEIPA_IMAGE=quay.io/freeipa/freeipa-server:rocky-9\n"
        "PI_UID=1000\n"
        "PI_GID=1000\n"
        "RADIANCE_UID=1000\n"
        "RADIANCE_GID=1000\n"
        "RENDER_GID=989\n"
        "VIDEO_GID=985\n"
        "RADIANCE_MODELS=/srv/models/rad\n"
    )
    rendered = render_env.render_env(
        source, uid=1234, gid=2345, render_gid=111, video_gid=222
    )
    assert "PI_UID=1234" in rendered
    assert "PI_GID=2345" in rendered
    assert "RADIANCE_UID=1234" in rendered
    assert "RADIANCE_GID=2345" in rendered
    assert "RENDER_GID=111" in rendered
    assert "VIDEO_GID=222" in rendered
    assert "RADIANCE_MODELS=/srv/models/rad" in rendered
    assert rendered.startswith("# comment\n")
    assert rendered.endswith("\n")


def test_main_writes_private_env_and_refuses_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "example"
    source.write_text("PI_UID=1\nPI_GID=1\nRENDER_GID=1\nVIDEO_GID=1\n")
    out = tmp_path / ".env"
    assert (
        render_env.main(
            [
                "--source",
                str(source),
                "--out",
                str(out),
                "--render-gid",
                "7",
                "--video-gid",
                "8",
            ]
        )
        == 0
    )
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert f"RENDER_GID=7" in out.read_text()
    before = out.read_bytes()
    assert render_env.main(["--source", str(source), "--out", str(out)]) == 0
    assert out.read_bytes() == before


def test_main_force_overwrites(tmp_path: Path) -> None:
    source = tmp_path / "example"
    source.write_text("PI_UID=1\n")
    out = tmp_path / ".env"
    out.write_text("stale\n")
    assert (
        render_env.main(
            [
                "--source",
                str(source),
                "--out",
                str(out),
                "--force",
                "--render-gid",
                "1",
                "--video-gid",
                "2",
            ]
        )
        == 0
    )
    text = out.read_text()
    assert f"PI_UID={os.getuid()}" in text
