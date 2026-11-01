"""Host-side fixtures; these tests need Docker and a running stack."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from helpers import ROOT, run


@pytest.fixture(scope="session")
def compose_base() -> list[str]:
    if not Path("/var/run/docker.sock").exists() and os.environ.get("DOCKER_HOST") is None:
        pytest.skip("Docker is not available on this host")
    env_file = ".env" if (ROOT / ".env").is_file() else ".env.example"
    return ["docker", "compose", "--env-file", env_file]


@pytest.fixture(scope="session")
def compose(compose_base: list[str]) -> list[str]:
    proc = run([*compose_base, "ps", "--services", "--filter", "status=running"], check=False)
    if not proc.stdout.strip():
        pytest.skip("the stack is not running")
    return compose_base
