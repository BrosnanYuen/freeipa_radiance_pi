from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

SKIP = {".git", "run", "secrets", "work", "__pycache__", ".pytest_cache"}
# In the test-runner the repository root is the container root, so never walk
# it wholesale: only these mounted paths are part of the project.
SCAN_PATHS = (
    "compose.yaml",
    ".env.example",
    "README.md",
    "PLAN.md",
    "RESEARCH.md",
    "deploy",
    "scripts",
    "tests",
    "docs",
)


def iter_text_files(root: Path):
    for entry in SCAN_PATHS:
        start = root / entry
        candidates = [start] if start.is_file() else (
            start.rglob("*") if start.is_dir() else []
        )
        for path in candidates:
            if not path.is_file() or any(part in SKIP for part in path.parts):
                continue
            try:
                yield path, path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue


def test_no_private_key_material(repo_root: Path) -> None:
    pattern = re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY")
    for path, text in iter_text_files(repo_root):
        assert not pattern.search(text), path


def test_compose_security_defaults(repo_root: Path) -> None:
    compose = (repo_root / "compose.yaml").read_text()
    assert "seccomp=${RADIANCE_SECCOMP:?set RADIANCE_SECCOMP in .env}" in compose
    assert "unconfined" not in compose
    assert "privileged: true" not in compose
    assert "docker.sock" not in compose
    assert "${BIND_ADDR:-127.0.0.1}" in compose
    assert "BIND_ADDR=0.0.0.0" not in (repo_root / ".env.example").read_text()


def test_agent_has_no_secret_mounts(repo_root: Path) -> None:
    yaml = pytest.importorskip("yaml")
    compose = yaml.safe_load((repo_root / "compose.yaml").read_text())
    client = compose["services"]["pi-client"]
    volumes = [str(item) for item in client.get("volumes", [])]
    for forbidden in ("ccache", "keytab", "ipa-data", "secrets", "certs"):
        assert not any(forbidden in volume for volume in volumes), forbidden
    assert client["environment"].get("KRB5CCNAME") != "FILE:/creds/krb5cc"


def test_test_runner_cannot_see_keytab_or_ipa_data() -> None:
    assert not Path("/keytabs").exists()
    assert not Path("/run/radiance").exists()
    assert not Path("/data").exists()


def test_env_example_has_no_secret_values(repo_root: Path) -> None:
    for line in (repo_root / ".env.example").read_text().splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        if re.search(r"(?i)(password|api[_-]?key|secret)", key):
            assert value.strip() == "", key


def test_rendered_edge_config_is_not_in_template(repo_root: Path) -> None:
    template = (repo_root / "deploy/edge/vhost.conf.tmpl").read_text()
    assert "AuthLDAPBindPassword \"{{LDAP_BIND_PASSWORD}}\"" in template
    assert "RequestHeader set Authorization \"Bearer {{RADIANCE_API_KEY}}\"" in template
    assert "0123456789abcdef" not in template
