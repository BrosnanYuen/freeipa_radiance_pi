"""Shared fixtures for unit, integration, security and host tests."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parents[1]))
for rel in ("deploy/pi", "deploy/gateway", "deploy/edge", "deploy/ipa", "scripts"):
    candidate = ROOT / rel
    if candidate.is_dir():
        sys.path.insert(0, str(candidate))


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def compose_config(repo_root: Path) -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load((repo_root / "compose.yaml").read_text(encoding="utf-8"))


def secret_file(name: str) -> Path:
    path = Path("/run/secrets") / name
    if not path.is_file():
        pytest.skip(f"Compose secret {name} is not mounted (run inside test-runner)")
    return path


@pytest.fixture(scope="session")
def pi_password() -> str:
    return secret_file("pi_password").read_text(encoding="utf-8").strip()


@pytest.fixture(scope="session")
def mallory_password() -> str:
    return secret_file("mallory_password").read_text(encoding="utf-8").strip()


@pytest.fixture(scope="session")
def admin_password() -> str:
    return secret_file("ipa_admin_password").read_text(encoding="utf-8").strip()


def kinit(principal: str, password: str, ccache: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["KRB5CCNAME"] = f"FILE:{ccache}"
    env.setdefault("KRB5_CONFIG", "/etc/krb5.conf")
    proc = subprocess.run(
        ["kinit", "-F", principal],
        input=password + "\n",
        text=True,
        capture_output=True,
        env=env,
        timeout=60,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"kinit {principal} failed: {(proc.stderr or proc.stdout).strip()}"
        )
    os.chmod(ccache, 0o600)
    return env


@pytest.fixture
def pi_ccache(tmp_path: Path, pi_password: str) -> Path:
    ccache = tmp_path / "krb5cc_pi"
    kinit("pi", pi_password, ccache)
    return ccache


@pytest.fixture
def mallory_ccache(tmp_path: Path, mallory_password: str) -> Path:
    ccache = tmp_path / "krb5cc_mallory"
    kinit("mallory", mallory_password, ccache)
    return ccache


@pytest.fixture
def pi_env(pi_ccache: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{pi_ccache}")
    monkeypatch.setenv("KRB5_CONFIG", "/etc/krb5.conf")
    return os.environ.copy()


@pytest.fixture
def mallory_env(
    mallory_ccache: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, str]:
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{mallory_ccache}")
    monkeypatch.setenv("KRB5_CONFIG", "/etc/krb5.conf")
    return os.environ.copy()


@pytest.fixture(scope="session")
def edge_url() -> str:
    url = os.environ.get("EDGE_URL", "")
    if not url:
        pytest.skip("EDGE_URL is not set")
    return url.rstrip("/")


@pytest.fixture(scope="session")
def ca_bundle() -> str:
    path = os.environ.get("REQUESTS_CA_BUNDLE", "/certs/ca.crt")
    if not Path(path).is_file():
        pytest.skip(f"CA bundle {path} is missing")
    return path


@pytest.fixture(scope="session")
def http():
    return pytest.importorskip("requests")


@pytest.fixture
def spnego_auth():
    module = pytest.importorskip("requests_gssapi")
    return module.HTTPSPNEGOAuth(opportunistic_auth=False)


@pytest.fixture
def spnego_factory():
    module = pytest.importorskip("requests_gssapi")

    def make():
        return module.HTTPSPNEGOAuth(opportunistic_auth=False)

    return make


@pytest.fixture(scope="session")
def edge_ready(edge_url: str, ca_bundle: str) -> str:
    requests = pytest.importorskip("requests")
    try:
        response = requests.get(
            edge_url + "/v1/models", verify=ca_bundle, timeout=5
        )
    except Exception as exc:  # noqa: BLE001 - any failure means "not ready"
        pytest.skip(f"edge is not reachable: {exc}")
    if response.status_code not in (200, 401, 403):
        pytest.skip(f"edge returned unexpected {response.status_code}")
    return edge_url


@pytest.fixture(scope="session")
def shim_url() -> str:
    url = os.environ.get("SHIM_URL", "http://radiance-shim:8088").rstrip("/")
    requests = pytest.importorskip("requests")
    try:
        response = requests.get(url + "/healthz", timeout=3)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"shim is not reachable: {exc}")
    if response.status_code != 200:
        pytest.skip(f"shim health returned {response.status_code}")
    return url


@pytest.fixture(scope="session")
def shim_token_path() -> Path:
    path = Path(os.environ.get("SHIM_TOKEN", "/agent/shim-token"))
    if not path.is_file():
        pytest.skip(f"shim token {path} is not mounted")
    return path
