"""Pi end-to-end tests. Opt in with RUN_E2E=1 after ./scripts/up.sh."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from helpers import ROOT, host_secret, run

pytestmark = pytest.mark.host


@pytest.fixture(scope="module", autouse=True)
def require_opt_in():
    if os.environ.get("RUN_E2E") != "1":
        pytest.skip("set RUN_E2E=1 to run the Pi end-to-end tests")


@pytest.fixture(scope="module")
def compose(compose_base):
    proc = run([*compose_base, "ps", "--services", "--filter", "status=running"], check=False)
    if "radiance-shim" not in proc.stdout.split():
        pytest.skip("radiance-shim is not running; run ./scripts/up.sh")
    return compose_base


@pytest.fixture(scope="module")
def work_readme():
    path = ROOT / "work/README.md"
    created = not path.exists()
    if created:
        path.write_text(
            "# E2E workspace\n\nThis file exists so Pi's read tool has something to read.\n",
            encoding="utf-8",
        )
    yield path
    if created:
        path.unlink(missing_ok=True)


def _login(compose) -> None:
    proc = run(
        [
            *compose,
            "--profile",
            "client",
            "run",
            "--rm",
            "-T",
            "pi-login",
            "pi-krb",
            "login",
            "--password-stdin",
        ],
        input_text=host_secret("pi_password") + "\n",
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def _status(compose) -> str:
    proc = run(
        [*compose, "--profile", "client", "run", "--rm", "-T", "pi-login", "pi-krb", "status"],
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "aes256" in proc.stdout
    return proc.stdout


def _pi(compose, *args: str) -> subprocess.CompletedProcess[str]:
    return run(
        [
            *compose,
            "--profile",
            "client",
            "run",
            "--rm",
            "-T",
            "pi-client",
            "pi-krb",
            "run",
            *args,
        ],
        input_text="",
        check=False,
    )


def test_p1_login_status_and_models(compose, work_readme) -> None:
    _login(compose)
    _status(compose)
    proc = _pi(
        compose,
        "--print",
        "Read README.md and report the first line.",
        "--model",
        "radiance-krb/qwen3.8-27b",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip(), "Pi produced no output"
    models = ROOT / "run/pi-agent/models.json"
    assert models.is_file()
    payload = json.loads(models.read_text())
    provider = payload["providers"]["radiance-krb"]
    assert provider["apiKey"].startswith("!cat /agent/shim-token")
    assert provider["models"][0]["contextWindow"] > 0


def test_p2_json_mode(compose) -> None:
    proc = _pi(
        compose,
        "--mode",
        "json",
        "Say one short sentence.",
        "--model",
        "radiance-krb/qwen3.8-27b",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"type"' in proc.stdout
    assert "assistant" in proc.stdout


def test_p3_no_credential_prompt_after_login(compose) -> None:
    for turn in range(3):
        proc = _pi(
            compose,
            "--print",
            f"turn {turn}",
            "--model",
            "radiance-krb/qwen3.8-27b",
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "kinit" not in proc.stdout


def test_p4_engine_down_is_a_clean_error(compose) -> None:
    pytest.skip("covered by the shim 401 path; T10 host check is destructive")
