"""Host-side inspection helpers; these tests need Docker and a running stack."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def run(
    argv: list[str], *, input_text: str | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        argv,
        cwd=ROOT,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if check and proc.returncode != 0:
        raise AssertionError(
            f"command failed ({proc.returncode}): {' '.join(argv)}\n{proc.stderr}"
        )
    return proc


def container_id(compose_base: list[str], service: str) -> str:
    proc = run([*compose_base, "ps", "-q", service], check=False)
    containers = [line for line in proc.stdout.splitlines() if line.strip()]
    if not containers:
        pytest.skip(f"service {service} is not running")
    return containers[0]


def inspect(compose_base: list[str], service: str) -> dict:
    return json.loads(
        run(["docker", "inspect", container_id(compose_base, service)]).stdout
    )[0]


def exec_in(
    compose_base: list[str], service: str, command: list[str]
) -> subprocess.CompletedProcess[str]:
    return run([*compose_base, "exec", "-T", service, *command], check=False)


def stack_logs(compose_base: list[str]) -> str:
    return run(
        [*compose_base, "logs", "--no-color", "--tail=5000"], check=False
    ).stdout


def host_secret(name: str) -> str:
    path = ROOT / "secrets" / name
    if not path.is_file():
        pytest.skip(f"{path} does not exist")
    return path.read_text().strip()
