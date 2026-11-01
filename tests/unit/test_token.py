from __future__ import annotations

import base64
import os
import types
from pathlib import Path

import pytest

from radiance_krb import kerberos
from radiance_krb import token as token_cli


class FakeName:
    def __init__(self, value, name_type=None):
        self.value = value
        self.name_type = name_type


class FakeContext:
    instances: list["FakeContext"] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.token = b"\x01\x02TOKEN"
        FakeContext.instances.append(self)

    def step(self, value):
        return self.token


def fake_gssapi(context_cls=FakeContext):
    return types.SimpleNamespace(
        Name=FakeName,
        NameType=types.SimpleNamespace(hostbased_service="hostbased"),
        SecurityContext=context_cls,
    )


@pytest.fixture
def ccache(tmp_path: Path) -> Path:
    path = tmp_path / "cc"
    path.write_bytes(b"ccache")
    os.chmod(path, 0o600)
    return path


def env_for(ccache: Path) -> dict[str, str]:
    return {"KRB5CCNAME": f"FILE:{ccache}"}


def test_ccache_detection(tmp_path: Path) -> None:
    missing = {"KRB5CCNAME": f"FILE:{tmp_path/'missing'}"}
    assert kerberos.ccache_path(missing) == tmp_path / "missing"
    assert not kerberos.ccache_available(missing)
    with pytest.raises(kerberos.NoCCache):
        kerberos.TokenProvider(env=missing, gssapi_module=fake_gssapi()).token()


def test_provider_uses_hostbased_service(ccache: Path) -> None:
    FakeContext.instances.clear()
    provider = kerberos.TokenProvider(
        "HTTP/radiance.ipa.test", env=env_for(ccache), gssapi_module=fake_gssapi()
    )
    token = provider.token()
    assert token == b"\x01\x02TOKEN"
    assert provider.header() == "Negotiate " + base64.b64encode(token).decode()
    ctx = FakeContext.instances[-1]
    assert ctx.kwargs["usage"] == "initiate"
    assert ctx.kwargs["name"].value == "HTTP@radiance.ipa.test"
    assert ctx.kwargs["name"].name_type == "hostbased"
    assert "deleg" not in ctx.kwargs
    assert "mutual_authentication" not in ctx.kwargs


def test_hostbased_name_normalization() -> None:
    assert (
        kerberos.TokenProvider.hostbased_name("HTTP/radiance.ipa.test")
        == "HTTP@radiance.ipa.test"
    )
    assert (
        kerberos.TokenProvider.hostbased_name("HTTP@radiance.ipa.test")
        == "HTTP@radiance.ipa.test"
    )


def test_u2_cli_header_is_exact(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    class Provider:
        def __init__(self, service):
            assert service == "HTTP/radiance.ipa.test"

        def token(self):
            return b"\x01\x02"

    monkeypatch.setattr(token_cli, "TokenProvider", Provider)
    assert token_cli.main([]) == 0
    captured = capsys.readouterr()
    assert captured.out == "Negotiate AQI=\n"
    assert captured.err == ""


def test_u2_cli_token_format(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    class Provider:
        def __init__(self, service):
            pass

        def token(self):
            return b"\x01\x02"

    monkeypatch.setattr(token_cli, "TokenProvider", Provider)
    assert token_cli.main(["--format", "token"]) == 0
    assert capsys.readouterr().out == "AQI=\n"


def test_u3_no_ccache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{tmp_path/'nope'}")
    assert token_cli.main([]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "pi-krb login" in captured.err


@pytest.mark.parametrize(
    "error,code",
    [
        (kerberos.CredentialsExpired("expired"), 3),
        (kerberos.GSSFailure("boom"), 4),
        (kerberos.NoCCache("none"), 2),
    ],
)
def test_u4_u5_exit_codes(
    monkeypatch: pytest.MonkeyPatch, capsys, error: Exception, code: int
) -> None:
    class Provider:
        def __init__(self, service):
            pass

        def token(self):
            raise error

    monkeypatch.setattr(token_cli, "TokenProvider", Provider)
    assert token_cli.main([]) == code
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("radiance-krb-token:")


def test_u6_no_token_in_error_output(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    canary = "CANARY-SUPER-SECRET-TOKEN"

    class Provider:
        def __init__(self, service):
            pass

        def token(self):
            raise kerberos.GSSFailure(f"failed while handling {canary}")

    monkeypatch.setattr(token_cli, "TokenProvider", Provider)
    assert token_cli.main([]) == 4
    captured = capsys.readouterr()
    assert canary not in captured.out
    # The error text itself is allowed to name the failure, but a real token
    # must never be written. This provider has no token to leak.
    assert "Negotiate" not in captured.out


def test_expired_exception_mapping(ccache: Path) -> None:
    class ExpiredCredentialsError(Exception):
        pass

    class Context:
        def __init__(self, **kwargs):
            pass

        def step(self, value):
            raise ExpiredCredentialsError("credentials expired")

    with pytest.raises(kerberos.CredentialsExpired):
        kerberos.TokenProvider(
            env=env_for(ccache),
            gssapi_module=fake_gssapi(Context),
        ).token()


def test_missing_exception_mapping(ccache: Path) -> None:
    class MissingCredentialsError(Exception):
        pass

    class Context:
        def __init__(self, **kwargs):
            pass

        def step(self, value):
            raise MissingCredentialsError("no credentials")

    with pytest.raises(kerberos.NoCCache):
        kerberos.TokenProvider(
            env=env_for(ccache),
            gssapi_module=fake_gssapi(Context),
        ).token()


def test_generic_exception_mapping(ccache: Path) -> None:
    class Context:
        def __init__(self, **kwargs):
            pass

        def step(self, value):
            raise RuntimeError("boom")

    with pytest.raises(kerberos.GSSFailure):
        kerberos.TokenProvider(
            env=env_for(ccache),
            gssapi_module=fake_gssapi(Context),
        ).token()


def test_check_mode_prints_nothing_on_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    class Provider:
        def __init__(self, service):
            pass

        def token(self):
            return b"x"

    monkeypatch.setattr(token_cli, "TokenProvider", Provider)
    assert token_cli.main(["--check"]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ok" in captured.err
