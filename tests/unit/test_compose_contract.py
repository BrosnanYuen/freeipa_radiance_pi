from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _service(compose: dict, name: str) -> dict:
    return compose["services"][name]


def _volumes(service: dict) -> list[str]:
    return [str(item) for item in service.get("volumes", [])]


def _ports(service: dict) -> list[str]:
    return [str(item) for item in service.get("ports", [])]


def test_compose_config_parses() -> None:
    if not shutil.which("docker"):
        pytest.skip("docker is not installed")
    proc = subprocess.run(
        ["docker", "compose", "--env-file", ".env.example", "config", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert proc.returncode == 0, proc.stderr


def test_expected_services(compose_config: dict) -> None:
    assert set(compose_config["services"]) == {
        "ipa",
        "bootstrap",
        "radiance-gateway",
        "radiance",
        "mock-radiance",
        "pi-login",
        "radiance-shim",
        "pi-client",
        "test-runner",
    }
    assert set(compose_config["networks"]) == {"krb-net", "shim-net"}
    assert compose_config["networks"]["shim-net"]["internal"] is True


def test_image_pins(compose_config: dict) -> None:
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    for name in (
        "FREEIPA_IMAGE",
        "RADIANCE_IMAGE",
        "GATEWAY_BASE_IMAGE",
        "PI_BASE_IMAGE",
        "TESTS_BASE_IMAGE",
    ):
        line = next(
            (item for item in env.splitlines() if item.startswith(name + "=")), None
        )
        assert line, name
        assert "@sha256:" in line, f"{name} must be digest-pinned"
    assert "PI_VERSION=" in env
    assert "PI_INTEGRITY=sha512-" in env


def test_edge_and_engine_topology(compose_config: dict) -> None:
    edge = _service(compose_config, "radiance-gateway")
    engine = _service(compose_config, "radiance")
    mock = _service(compose_config, "mock-radiance")
    assert _ports(edge) == ["${BIND_ADDR:-127.0.0.1}:8443:8443"]
    assert engine["network_mode"] == "service:radiance-gateway"
    assert mock["network_mode"] == "service:radiance-gateway"
    assert "ports" not in engine
    assert "ports" not in mock
    assert engine["profiles"] == ["gpu"]
    assert mock["profiles"] == ["test-fast"]
    assert engine["depends_on"]["radiance-gateway"]["condition"] == "service_healthy"
    assert engine["security_opt"] == [
        "no-new-privileges:true",
        "seccomp=${RADIANCE_SECCOMP:?set RADIANCE_SECCOMP in .env}",
    ]
    assert engine["cap_drop"] == ["ALL"]
    assert engine["read_only"] is True
    assert engine["ulimits"]["memlock"] == -1


def test_kdc_ports_are_loopback_by_default(compose_config: dict) -> None:
    ports = _ports(_service(compose_config, "ipa"))
    assert ports
    for entry in ports:
        assert entry.startswith("${BIND_ADDR:-127.0.0.1}:"), entry


def test_pi_client_is_isolated(compose_config: dict) -> None:
    client = _service(compose_config, "pi-client")
    assert list(client["networks"]) == ["shim-net"]
    volumes = _volumes(client)
    assert sorted(volumes) == ["./run/pi-agent:/agent", "./work:/work"]
    for forbidden in ("ccache", "secrets", "ipa-data", "certs", ".:/"):
        assert not any(forbidden in item for item in volumes), forbidden
    assert client["cap_drop"] == ["ALL"]
    assert client["security_opt"] == ["no-new-privileges:true"]
    assert client["read_only"] is True
    assert client["user"] == "${PI_UID:-1000}:${PI_GID:-1000}"
    assert "secrets" not in client
    # A decoy ccache path, never the real one.
    assert client["environment"]["KRB5CCNAME"] == "FILE:/tmp/does-not-exist"


def test_shim_and_login_are_the_only_ccache_holders(compose_config: dict) -> None:
    for name in ("pi-login", "radiance-shim"):
        service = _service(compose_config, name)
        assert any("run/ccache" in item for item in _volumes(service)), name
    assert any(
        "run/ccache" in item
        for item in _volumes(_service(compose_config, "radiance-shim"))
    )
    assert not any(
        "run/ccache" in item for item in _volumes(_service(compose_config, "pi-client"))
    )
    shim = _service(compose_config, "radiance-shim")
    assert set(shim["networks"]) == {"krb-net", "shim-net"}


def test_secret_scoping(compose_config: dict) -> None:
    ipa = _service(compose_config, "ipa")
    bootstrap = _service(compose_config, "bootstrap")
    assert "secrets" not in ipa, "the long-lived IPA service must not mount bootstrap secrets"
    assert set(bootstrap["secrets"]) == {
        "ipa_admin_password",
        "pi_password",
        "mallory_password",
        "ldap_bind_password",
    }
    assert "tmpfs" not in bootstrap or "/run" not in bootstrap.get("tmpfs", [])
    runner = _service(compose_config, "test-runner")
    sources = {
        item if isinstance(item, str) else item["source"]
        for item in runner["secrets"]
    }
    assert sources == {
        "pi_password",
        "mallory_password",
        "ipa_admin_password",
    }
    edge = _service(compose_config, "radiance-gateway")
    assert any("/secrets-src/ldap_bind_password" in v for v in _volumes(edge))
    assert any("/secrets-src/radiance_api_key" in v for v in _volumes(edge))


def test_no_docker_socket_or_privileged(compose_config: dict) -> None:
    for name, service in compose_config["services"].items():
        assert "docker.sock" not in json.dumps(service), name
        assert "privileged" not in service or service["privileged"] is not True, name
        assert "pid" not in service or service["pid"] != "host", name


def test_hardening(compose_config: dict) -> None:
    for name in (
        "bootstrap",
        "radiance-gateway",
        "radiance",
        "mock-radiance",
        "pi-login",
        "radiance-shim",
        "pi-client",
        "test-runner",
    ):
        service = _service(compose_config, name)
        assert service["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in service["security_opt"], name
    for name in ("radiance-gateway", "radiance", "mock-radiance", "pi-login", "radiance-shim", "pi-client"):
        assert _service(compose_config, name).get("read_only") is True, name


def test_engine_flags_single_source(compose_config: dict) -> None:
    engine = _service(compose_config, "radiance")
    command = [str(item) for item in engine["command"]]
    flags: dict[str, str | None] = {}
    index = 0
    while index < len(command):
        item = command[index]
        if item.startswith("--"):
            value = (
                command[index + 1]
                if index + 1 < len(command) and not command[index + 1].startswith("--")
                else None
            )
            flags[item] = value
            index += 2 if value is not None else 1
        else:
            index += 1
    assert flags["--host"] == "127.0.0.1"
    assert flags["--port"] == "8000"
    assert flags["--api-key-env"] == "RADIANCE_API_KEY"
    assert flags["--max-model-len"] == "${RADIANCE_CONTEXT_WINDOW:?set RADIANCE_CONTEXT_WINDOW (E0 measurement)}"
    assert flags["--mm-max-patches"] == "0"
    assert flags["--num-speculative-tokens"] == "0"
    assert flags["--kv-cache-dtype"] == "fp8"
    assert flags["--tp"] == "1"
    assert "--no-cors" in flags
    for dangerous in ("--debug-graph", "--profile-ops", "--live", "--api-key"):
        assert dangerous not in flags, dangerous
    assert "--model" in flags
    entrypoint = (ROOT / "deploy/radiance/entrypoint.sh").read_text(encoding="utf-8")
    assert "--model" not in entrypoint
    assert "--api-key-env" not in entrypoint


def test_seccomp_profile_is_present_and_pinned() -> None:
    profile = ROOT / "deploy/radiance/seccomp-radiance.json"
    assert profile.is_file()
    data = json.loads(profile.read_text())
    assert data["defaultAction"] == "SCMP_ACT_ERRNO"
    joined = json.dumps(data)
    for syscall in ("io_uring_setup", "io_uring_enter", "io_uring_register", "mbind", "set_mempolicy"):
        assert syscall in joined, syscall
    checksum = (ROOT / "deploy/radiance/SHA256SUMS").read_text().split()[0]
    assert len(checksum) == 64
    import hashlib

    assert hashlib.sha256(profile.read_bytes()).hexdigest() == checksum


def test_edge_healthcheck_is_independent_of_engine(compose_config: dict) -> None:
    edge = _service(compose_config, "radiance-gateway")
    command = " ".join(str(item) for item in edge["healthcheck"]["test"])
    assert "8081/healthz" in command
    assert "8000" not in command


def test_test_runner_mounts(compose_config: dict) -> None:
    volumes = _volumes(_service(compose_config, "test-runner"))
    assert any(item.startswith("./tests:") for item in volumes)
    assert any(item.startswith("./deploy:") for item in volumes)
    assert not any(item.startswith("./:/") for item in volumes)
    assert any("run/ipa-data/certs/ca.crt" in item for item in volumes)
    assert not any("keytabs" in item for item in volumes)
    assert not any("secrets/ldap_bind_password" in item for item in volumes)


def test_gitignore_covers_runtime_state(repo_root: Path) -> None:
    ignored = (repo_root / ".gitignore").read_text(encoding="utf-8").splitlines()
    for entry in ("/secrets/", "/run/", ".env"):
        assert entry in ignored, entry
    assert "/work/" in ignored or "/work/*" in ignored


def test_deploy_pi_verifies_npm_integrity() -> None:
    dockerfile = (ROOT / "deploy/pi/Dockerfile").read_text(encoding="utf-8")
    assert "PI_INTEGRITY" in dockerfile
    assert "integrity mismatch" in dockerfile
    assert "npm install -g --ignore-scripts" in dockerfile
    assert "python3-gssapi" in dockerfile
    assert "krb5-user" in dockerfile


def test_bootstrap_uses_no_run_tmpfs(compose_config: dict) -> None:
    # Compose secrets live under /run/secrets; a /run tmpfs would hide them.
    bootstrap = _service(compose_config, "bootstrap")
    assert "/run" not in bootstrap.get("tmpfs", [])


def test_capacity_gate_is_fail_closed(repo_root: Path) -> None:
    env = (repo_root / ".env.example").read_text(encoding="utf-8")
    assert "RADIANCE_CONTEXT_WINDOW=32768" in env
    assert "CAPACITY_MEASURED=0" in env
    up = (repo_root / "scripts/up.sh").read_text(encoding="utf-8")
    assert "CAPACITY_MEASURED" in up
    assert "E0 procedure" in up
    compose = (repo_root / "compose.yaml").read_text(encoding="utf-8")
    assert "${RADIANCE_CONTEXT_WINDOW:?" in compose
