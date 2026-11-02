from __future__ import annotations

import pytest

from helpers import exec_in, inspect

pytestmark = pytest.mark.host


def test_pi_client_mounts_and_networks(compose) -> None:
    data = inspect(compose, "pi-client")
    networks = set(data["NetworkSettings"]["Networks"])
    assert len(networks) == 1, networks
    assert "shim-net" in next(iter(networks))
    destinations = {mount["Destination"] for mount in data.get("Mounts", [])}
    assert {"/work", "/agent"} <= destinations
    for forbidden in ("/creds", "/certs", "/secrets", "/data", "/keytabs"):
        assert forbidden not in destinations, forbidden
    env = data["Config"].get("Env", [])
    joined = "\n".join(env)
    assert FILE_PREFIX not in joined  # no real ccache in the agent
    assert "RADIANCE_API_KEY" not in joined


FILE_PREFIX = "FILE:/creds"


def test_ipa_has_no_bootstrap_secrets(compose) -> None:
    data = inspect(compose, "ipa")
    destinations = {mount["Destination"] for mount in data.get("Mounts", [])}
    sources = {mount.get("Source", "") for mount in data.get("Mounts", [])}
    assert "/run/secrets" not in destinations
    assert not any("/secrets/" in source for source in sources)
    assert "/bootstrap" in destinations  # scripts, not credentials
    assert "/data" in destinations


def test_radiance_has_no_published_port(compose) -> None:
    data = inspect(compose, "radiance")
    assert not data["NetworkSettings"].get("Ports")
    assert data["HostConfig"]["NetworkMode"].startswith("container:")
    assert data["Config"]["User"] == "1000:1000" or ":" in data["Config"]["User"]


def test_edge_publishes_only_8443_on_loopback(compose) -> None:
    data = inspect(compose, "radiance-gateway")
    ports = data["NetworkSettings"].get("Ports") or {}
    published = {key for key, values in ports.items() if values}
    assert published == {"8443/tcp"}
    bindings = [binding for values in ports.values() if values for binding in values]
    for binding in bindings:
        assert binding["HostIp"] == "127.0.0.1"
        assert binding["HostPort"] == "8443"


def test_keytab_permissions(compose) -> None:
    proc = exec_in(
        compose,
        "radiance-gateway",
        ["stat", "-c", "%a %U:%G", "/run/gateway/radiance.keytab"],
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "400 gateway:gateway"


def test_pi_client_can_only_reach_the_shim(compose) -> None:
    allowed = exec_in(
        compose,
        "pi-client",
        ["curl", "-fsS", "--max-time", "3", "http://radiance-shim:8088/healthz"],
    )
    assert allowed.returncode == 0, allowed.stderr
    assert '"token":true' in allowed.stdout.replace(" ", "")

    for url in (
        "http://ipa.ipa.test:88",
        "https://radiance-gateway:8443/v1/models",
        "https://radiance.ipa.test:8443/v1/models",
    ):
        blocked = exec_in(
            compose,
            "pi-client",
            ["curl", "-skS", "--max-time", "3", "-o", "/dev/null", url],
        )
        assert blocked.returncode != 0, f"pi-client reached {url}"


def test_agent_has_no_kerberos_configuration(compose) -> None:
    data = inspect(compose, "pi-client")
    env = data["Config"].get("Env", [])
    assert not any(item.startswith("KRB5_CONFIG=") for item in env)
    proc = exec_in(
        compose,
        "pi-client",
        ["sh", "-c", "! test -e /creds && ! test -e /certs && ! test -e /secrets"],
    )
    assert proc.returncode == 0


def test_edge_capabilities(compose) -> None:
    data = inspect(compose, "radiance-gateway")
    caps = set(data["HostConfig"]["CapDrop"])
    assert "ALL" in caps
    assert data["HostConfig"]["ReadonlyRootfs"] is True
    assert "ALL" not in set(data["HostConfig"].get("CapAdd") or [])
