from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

pytestmark = pytest.mark.integration

CHAT = {
    "model": "qwen3.8-27b",
    "messages": [{"role": "user", "content": "hello"}],
}


def test_t7_streaming_sse(pi_env, spnego_auth, edge_ready, ca_bundle, http) -> None:
    started = time.monotonic()
    with http.post(
        edge_ready + "/v1/chat/completions",
        json={**CHAT, "stream": True},
        auth=spnego_auth,
        verify=ca_bundle,
        stream=True,
        timeout=60,
    ) as response:
        assert response.status_code == 200, response.text
        lines = response.iter_lines(decode_unicode=True)
        first = next(line for line in lines if line)
        elapsed = time.monotonic() - started
        assert first.startswith("data:")
        assert elapsed < 5, f"first chunk took {elapsed:.1f}s"
        rest = "\n".join(lines)
    assert "mock" in first + rest
    if not os.environ.get("RADIANCE_GPU"):
        assert elapsed < 2, f"mock first chunk took {elapsed:.1f}s"


def test_t8_ten_turn_conversation(
    pi_env, spnego_factory, edge_ready, ca_bundle, http
) -> None:
    for turn in range(10):
        response = http.post(
            edge_ready + "/v1/chat/completions",
            json={
                **CHAT,
                "messages": [
                    {"role": "user", "content": f"turn {turn}"},
                ],
            },
            auth=spnego_factory(),
            verify=ca_bundle,
            timeout=60,
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["choices"][0]["message"]["content"]
        assert payload["usage"]["total_tokens"] > 0


def test_t17_oversized_body_is_rejected(
    pi_env, spnego_auth, edge_ready, ca_bundle, http
) -> None:
    payload = b'{"messages":[{"role":"user","content":"' + b"x" * (16 * 1024 * 1024 + 1) + b'"}]}'
    response = http.post(
        edge_ready + "/v1/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json"},
        auth=spnego_auth,
        verify=ca_bundle,
        timeout=60,
    )
    assert response.status_code == 413, response.status_code


def test_t17_parallel_requests(
    pi_env, spnego_factory, edge_ready, ca_bundle, http
) -> None:
    def one(index: int) -> int:
        response = http.post(
            edge_ready + "/v1/chat/completions",
            json={**CHAT, "messages": [{"role": "user", "content": f"p{index}"}]},
            auth=spnego_factory(),
            verify=ca_bundle,
            timeout=60,
        )
        return response.status_code

    with ThreadPoolExecutor(max_workers=10) as pool:
        statuses = list(pool.map(one, range(20)))
    assert statuses == [200] * 20
