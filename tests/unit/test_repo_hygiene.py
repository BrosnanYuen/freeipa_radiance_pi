from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCAN_DIRS = ("compose.yaml", ".env.example", "deploy", "scripts", "tests")
TEXT_SUFFIXES = {
    ".py",
    ".sh",
    ".yaml",
    ".yml",
    ".md",
    ".json",
    ".tmpl",
    ".example",
    ".ini",
    ".conf",
    ".txt",
    "",
}
SKIP_PARTS = {".git", "run", "secrets", "work", "__pycache__", ".pytest_cache"}


def iter_files():
    for entry in SCAN_DIRS:
        path = ROOT / entry
        if path.is_file():
            yield path
            continue
        if not path.is_dir():
            continue
        for candidate in path.rglob("*"):
            if not candidate.is_file():
                continue
            if any(part in SKIP_PARTS for part in candidate.parts):
                continue
            if candidate.suffix not in TEXT_SUFFIXES and candidate.name not in (
                ".env.example",
                ".gitignore",
            ):
                continue
            yield candidate


def test_no_private_keys_in_repo() -> None:
    pattern = re.compile(r"BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY")
    for path in iter_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        assert not pattern.search(text), f"private key material in {path}"


def test_no_literal_credentials_in_deploy_config() -> None:
    pattern = re.compile(
        r"(?i)(?:password|api[_-]?key|secret|token)\s*[:=]\s*[\"']?([A-Za-z0-9+/=_-]{16,})"
    )
    allowed_placeholders = {"0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"}
    for path in iter_files():
        if "tests/" in path.as_posix():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in pattern.finditer(text):
            value = match.group(1)
            if value.startswith(("/", "${", "{{")):
                continue
            assert value in allowed_placeholders, (
                f"possible literal credential in {path}: {match.group(0)!r}"
            )


def test_env_example_has_no_secret_values() -> None:
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        if re.search(r"(?i)(password|api[_-]?key|secret)", key):
            assert value.strip() == "", f"{key} must not carry a literal secret"


def test_from_lines_are_pinned_or_arg() -> None:
    for dockerfile in ROOT.rglob("Dockerfile"):
        if any(part in SKIP_PARTS for part in dockerfile.parts):
            continue
        for line in dockerfile.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.upper().startswith("FROM "):
                continue
            image = stripped.split(None, 1)[1].split()[0]
            assert image.startswith("${") or image == "scratch", (
                f"unpinned FROM in {dockerfile}: {line}"
            )
            assert ":latest" not in image


def test_no_latest_tags_in_env_or_compose() -> None:
    for name in (".env.example", "compose.yaml"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert ":latest" not in text, name


def test_shell_scripts_are_executable() -> None:
    for path in list((ROOT / "scripts").glob("*.sh")) + [
        ROOT / "deploy/gateway/entrypoint.sh",
        ROOT / "deploy/ipa/bootstrap.sh",
        ROOT / "deploy/radiance/entrypoint.sh",
    ]:
        assert path.stat().st_mode & 0o111, f"{path} is not executable"


def test_docs_exist() -> None:
    for name in ("README.md", "PLAN.md", "RESEARCH.md", "LICENSE"):
        assert (ROOT / name).is_file(), name
    for name in (
        "RUNBOOK.md",
        "THREAT-MODEL.md",
        "CAPACITY.md",
        "DEVIATIONS.md",
        "SECRETS.md",
        "MODEL-LICENSES.md",
    ):
        path = ROOT / "docs" / name
        assert path.is_file(), name
        assert path.stat().st_size > 500, name
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "PLAN.md" in readme
    assert "Quick start" in readme or "quick start" in readme


def test_ci_workflow_exists() -> None:
    path = ROOT / ".github/workflows/ci.yml"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "pytest" in text
    assert "docker compose" in text
    for scanner in ("gitleaks", "trivy", "yamllint", "hadolint", "syft"):
        assert scanner in text, scanner


def test_no_runtime_or_secret_paths_tracked() -> None:
    if not (ROOT / ".git").is_dir():
        pytest.skip("not a git checkout")
    try:
        proc = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git is unavailable")
    tracked = proc.stdout.splitlines()
    for forbidden in ("secrets/", "run/", "work/"):
        offenders = [
            item
            for item in tracked
            if item.startswith(forbidden) and item != "work/.gitkeep"
        ]
        assert offenders == [], offenders
    assert ".env" not in tracked


def test_license_is_gpl3() -> None:
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "GNU GENERAL PUBLIC LICENSE" in text
    assert "Version 3, 29 June 2007" in text


def test_plan_and_research_are_linked() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "[PLAN.md](PLAN.md)" in readme or "PLAN.md" in readme
    assert "RESEARCH.md" in readme
