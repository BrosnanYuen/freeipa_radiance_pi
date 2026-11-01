from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from radiance_krb import pi_krb


def test_models_config_shape() -> None:
    config = pi_krb.build_models_config(
        "http://radiance-shim:8088",
        "/agent/shim-token",
        "radiance-krb/qwen3.8-27b",
        200_000,
    )
    assert config["$schema"] == "https://pi.dev/schemas/models.schema.json"
    provider = config["providers"]["radiance-krb"]
    assert provider["baseUrl"] == "http://radiance-shim:8088/v1"
    assert provider["api"] == "openai-completions"
    assert provider["apiKey"] == "!cat /agent/shim-token"
    assert provider["authHeader"] is True
    model = provider["models"][0]
    assert model["id"] == "qwen3.8-27b"
    assert model["contextWindow"] == 200_000
    assert model["maxTokens"] <= 16_384
    assert model["input"] == ["text"]
    assert model["cost"] == {
        "input": 0,
        "output": 0,
        "cacheRead": 0,
        "cacheWrite": 0,
    }


def test_base_url_normalization() -> None:
    assert pi_krb.normalize_base_url("http://x:8088") == "http://x:8088/v1"
    assert pi_krb.normalize_base_url("http://x:8088/") == "http://x:8088/v1"
    assert pi_krb.normalize_base_url("http://x:8088/v1") == "http://x:8088/v1"
    assert pi_krb.normalize_base_url("http://x:8088/v1/") == "http://x:8088/v1"


def test_models_config_rejects_unsafe_paths_and_context() -> None:
    with pytest.raises(pi_krb.PiKrbError):
        pi_krb.build_models_config("http://x", "/agent/bad path", "p/m")
    with pytest.raises(pi_krb.PiKrbError):
        pi_krb.build_models_config("http://x", "/agent/token", "p/m", 10)


def test_write_models_config_mode_and_json(tmp_path: Path) -> None:
    agent = tmp_path / "agent"
    target = pi_krb.write_models_config(
        agent,
        pi_krb.build_models_config("http://x", "/agent/t", "radiance-krb/m", 4096),
    )
    assert target == agent / "models.json"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(agent.stat().st_mode) == 0o700
    payload = json.loads(target.read_text())
    assert payload["providers"]["radiance-krb"]["models"][0]["id"] == "m"


def test_model_without_provider_prefix() -> None:
    config = pi_krb.build_models_config(
        "http://x", "/agent/t", "qwen3.8-27b", 4096
    )
    assert "radiance-krb" in config["providers"]
    assert config["providers"]["radiance-krb"]["models"][0]["id"] == "qwen3.8-27b"


def test_enctype_parsing() -> None:
    output = """\
Valid starting     Expires            Service principal
11/01/26 04:00:00  11/01/26 12:00:00  krbtgt/IPA.TEST@IPA.TEST
    Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96
"""
    enctypes = pi_krb.parse_enctypes(output)
    assert "aes256-cts-hmac-sha1-96" in enctypes
    assert pi_krb.has_aes(enctypes)
    assert not pi_krb.has_aes({"rc4-hmac"})


def test_invalid_principal_is_refused_before_kinit(capsys) -> None:
    assert pi_krb.main(["login", "--principal=-rf"]) == 1
    assert "invalid principal" in capsys.readouterr().err
    assert pi_krb.main(["login", "--principal", "bad principal"]) == 1


def test_pi_flags_are_not_parsed_as_abbreviations() -> None:
    parser = pi_krb.build_parser()
    args, extra = parser.parse_known_args(
        [
            "run",
            "--mode",
            "json",
            "--print",
            "hi",
            "--model",
            "radiance-krb/m",
        ]
    )
    assert args.model == "radiance-krb/m"
    assert extra == ["--mode", "json", "--print", "hi"]


def test_health_url_strips_v1() -> None:
    assert pi_krb._health_url("http://x:8088") == "http://x:8088/healthz"
    assert pi_krb._health_url("http://x:8088/v1") == "http://x:8088/healthz"
    assert pi_krb._health_url("http://x:8088/v1/") == "http://x:8088/healthz"
