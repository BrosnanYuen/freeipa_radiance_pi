from __future__ import annotations

import socket

import pytest

pytestmark = pytest.mark.integration

def test_t14_engine_has_no_network_route() -> None:
    for host, port in (
        ("radiance-gateway", 8000),
        ("radiance", 8000),
        ("mock-radiance", 8000),
        ("radiance-gateway", 8081),
    ):
        with pytest.raises(OSError):
            socket.create_connection((host, port), timeout=2).close()


def test_t14b_agent_network_isolation_is_host_checked() -> None:
    pytest.skip("needs docker exec into pi-client; covered by tests/host")


def test_t25_agent_never_talks_to_the_edge(shim_url) -> None:
    # pi-client is attached to shim-net only. This process (test-runner) can
    # reach both networks, so this asserts the shim surface itself rather than
    # the agent's routing; the latter is a host inspection (T23/T25).
    connection = socket.create_connection(
        (shim_url.split("//", 1)[1].split(":")[0], 8088), timeout=2
    )
    connection.close()
