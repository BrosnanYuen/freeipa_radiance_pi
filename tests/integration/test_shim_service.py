from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def test_t20_shim_token_permissions(shim_token_path: Path) -> None:
    mode = stat.S_IMODE(shim_token_path.stat().st_mode)
    assert mode == 0o600, oct(mode)
    assert shim_token_path.read_text().strip()


def test_t20_shim_requires_the_token(
    shim_url, shim_token_path: Path, http
) -> None:
    missing = http.get(shim_url + "/v1/models", timeout=10)
    assert missing.status_code == 401

    wrong = http.get(
        shim_url + "/v1/models",
        headers={"Authorization": "Bearer wrong-token"},
        timeout=10,
    )
    assert wrong.status_code == 401

    ccache = Path(os.environ.get("KRB5CCNAME", "FILE:/creds/krb5cc").split(":", 1)[-1])
    if not ccache.is_file():
        pytest.skip("shim has no ccache yet; run pi-krb login")

    token = shim_token_path.read_text().strip()
    good = http.get(
        shim_url + "/v1/models",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    assert good.status_code == 200, good.text
    assert good.json()["data"]


def test_t20_health_does_not_require_auth(shim_url, http) -> None:
    response = http.get(shim_url + "/healthz", timeout=5)
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) >= {"status", "ready", "token", "ca", "gssapi"}
    assert json.dumps(payload)  # JSON-serializable
