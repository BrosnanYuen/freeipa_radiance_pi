"""Host-mode Pi end-to-end smoke test. Opt in with RUN_E2E=1.

Pi runs on the host (the pinned npm release via npx), the shim is published on
127.0.0.1, and the shim alone holds the ccache. Three turns exercise the
non-container client path without touching the user's global Pi configuration.
"""

from __future__ import annotations

import os
import shutil

import pytest

from helpers import run

pytestmark = [pytest.mark.host, pytest.mark.slow]


def test_host_mode_pi_three_turns(compose) -> None:
    if os.environ.get("RUN_E2E") != "1":
        pytest.skip("set RUN_E2E=1 to run the host-mode Pi test")
    if shutil.which("npx") is None:
        pytest.skip("npx is not installed")
    proc = run(
        ["bash", "scripts/host-pi-smoke.sh", "--turns", "3"],
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "completed 3 turn(s)" in proc.stderr
