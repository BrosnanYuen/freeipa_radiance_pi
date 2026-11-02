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
    # 197,900 repetitions plus the chat template is 197,952 tokens (measured);
    # 200,000 repeats would exceed --max-model-len and is not a valid admission test.
    prompt = "token " * 197_900
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
    assert response.status_code == 200, response.text
    assert response.json()["usage"]["prompt_tokens"] > 190_000


def test_t11b_quantisation_quality(
    pi_env, spnego_auth, edge_ready, ca_bundle, http
) -> None:
    if os.environ.get("RADIANCE_GPU_V4") != "1":
        pytest.skip("start the engine with --kv-cache-dtype fp8_v4 and set RADIANCE_GPU_V4=1")
    # Retrieval at ~6.4k tokens: the access code sits at a different depth in
    # each prompt. Compared with fp8 in docs/measurements/T11b-2026-11-01.md.
    for code, position in (("ZX-9271", 0.1), ("QK-4418", 0.5), ("MV-3057", 0.9)):
        filler = "The archive contains routine maintenance notes. " * 900
        split = int(len(filler) * position)
        text = filler[:split] + f"Reference note: the access code is {code}. " + filler[split:]
        response = http.post(
            edge_ready + "/v1/chat/completions",
            json={
                "model": os.environ.get("RADIANCE_SERVED_NAME", "qwen3.8-27b"),
                "messages": [{
                    "role": "user",
                    "content": text + "\nQuestion: What is the access code? Answer with the code only.",
                }],
                "max_tokens": 16,
                "temperature": 0,
                "reasoning_effort": "none",
                "logprobs": True,
                "top_logprobs": 5,
            },
            auth=spnego_auth,
            verify=ca_bundle,
            timeout=180,
        )
        assert response.status_code == 200, response.text
        content = response.json()["choices"][0]["message"].get("content") or ""
        assert code in content, f"fp8_v4 lost {code}: {content!r}"
