from __future__ import annotations

import os

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.gpu]


def gpu_enabled() -> bool:
    return os.environ.get("RADIANCE_GPU") == "1"


@pytest.fixture(autouse=True)
def require_gpu():
    if not gpu_enabled():
        pytest.skip("set RADIANCE_GPU=1 to run GPU tests against the real model")


def test_t11_near_200k_prompt(
    pi_env, spnego_auth, edge_ready, ca_bundle, http
) -> None:
    if os.environ.get("RADIANCE_GPU_LONG") != "1":
        pytest.skip("set RADIANCE_GPU_LONG=1 for the 200k admission test")
    # Roughly 200k tokens of whitespace-delimited words.
    prompt = "token " * 200_000
    response = http.post(
        edge_ready + "/v1/chat/completions",
        json={
            "model": os.environ.get("RADIANCE_SERVED_NAME", "qwen3.8-27b"),
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 8,
        },
        auth=spnego_auth,
        verify=ca_bundle,
        timeout=1800,
    )
    assert response.status_code in (200, 400), response.text
    if response.status_code == 400:
        assert "context" in response.text.lower() or "length" in response.text.lower()


def test_t11b_quantisation_quality_is_manual() -> None:
    pytest.skip("requires a model-quality harness; see docs/CAPACITY.md")
