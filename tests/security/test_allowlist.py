from __future__ import annotations

import pytest

pytestmark = pytest.mark.security

DENIED_PATHS = [
    "/dashboard",
    "/diagnostics",
    "/v1/load_lora_adapter",
    "/v1/unload_lora_adapter",
    "/v1/audio",
    "/v1/images/generations",
    "/v1/models/",
]


@pytest.mark.parametrize("path", DENIED_PATHS)
def test_t18b_denied_paths(
    pi_env, spnego_auth, edge_ready, ca_bundle, http, path: str
) -> None:
    response = http.get(
        edge_ready + path,
        auth=spnego_auth,
        verify=ca_bundle,
        timeout=20,
        allow_redirects=False,
    )
    assert response.status_code in (403, 404), (path, response.status_code)


def test_authenticated_post_to_denied_path(
    pi_env, spnego_auth, edge_ready, ca_bundle, http
) -> None:
    response = http.post(
        edge_ready + "/v1/load_lora_adapter",
        json={"lora_name": "x", "lora_path": "/tmp/x"},
        auth=spnego_auth,
        verify=ca_bundle,
        timeout=20,
    )
    assert response.status_code in (403, 404)
