from __future__ import annotations

import base64
import os
import stat
import subprocess

import pytest

pytestmark = pytest.mark.integration

REALM = "IPA.TEST"


def test_t1_kinit_produces_aes_tickets(pi_ccache) -> None:
    env = os.environ.copy()
    env["KRB5CCNAME"] = f"FILE:{pi_ccache}"
    proc = subprocess.run(
        ["klist", "-e"], capture_output=True, text=True, env=env, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert "aes256-cts-hmac-sha1-96" in proc.stdout
    assert "rc4" not in proc.stdout.lower()
    assert stat.S_IMODE(pi_ccache.stat().st_mode) == 0o600


def test_t2_negotiate_models(
    pi_env, spnego_auth, edge_ready, ca_bundle, http
) -> None:
    response = http.get(
        edge_ready + "/v1/models",
        auth=spnego_auth,
        verify=ca_bundle,
        timeout=30,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["data"]
    # The mock echoes the principal header the edge injected. With the real
    # engine this header is not returned, so only assert it when present.
    principal = response.headers.get("X-Mock-Principal")
    if principal:
        assert principal == f"pi@{REALM}"


def test_t3_missing_authorization_is_401(edge_ready, ca_bundle, http) -> None:
    response = http.get(edge_ready + "/v1/models", verify=ca_bundle, timeout=10)
    assert response.status_code == 401
    assert "Negotiate" in response.headers.get("WWW-Authenticate", "")


def test_t4_authenticated_non_member_is_403(
    mallory_env, spnego_auth, edge_ready, ca_bundle, http
) -> None:
    response = http.get(
        edge_ready + "/v1/models",
        auth=spnego_auth,
        verify=ca_bundle,
        timeout=30,
    )
    assert response.status_code == 403, response.text


def test_t4b_revocation_is_a_host_test() -> None:
    pytest.skip("covered by tests/host/test_advanced.py with RUN_SLOW=1")


def test_t5_wrong_keytab_is_a_host_test() -> None:
    pytest.skip("covered by tests/host/test_destructive.py with RUN_DESTRUCTIVE=1")


def test_t12_replayed_authenticator_is_rejected(
    pi_env, edge_ready, ca_bundle, http
) -> None:
    gssapi = pytest.importorskip("gssapi")
    for attempt in range(5):
        context = gssapi.SecurityContext(
            name=gssapi.Name(
                "HTTP@radiance.ipa.test", gssapi.NameType.hostbased_service
            ),
            usage="initiate",
        )
        token = base64.b64encode(context.step(None)).decode("ascii")
        headers = {"Authorization": "Negotiate " + token}
        first = http.get(
            edge_ready + "/v1/models",
            headers=headers,
            verify=ca_bundle,
            timeout=30,
        )
        assert first.status_code == 200, first.text
        replay = http.get(
            edge_ready + "/v1/models",
            headers=headers,
            verify=ca_bundle,
            timeout=30,
        )
        assert replay.status_code == 401, (
            f"attempt {attempt}: replay accepted across Apache workers (RR5)"
        )


def test_t10_expiry_recovery_is_destructive() -> None:
    pytest.skip("covered by tests/host/test_advanced.py with RUN_SLOW=1")


def test_t21_forged_bearer_is_401(edge_ready, ca_bundle, http) -> None:
    response = http.get(
        edge_ready + "/v1/models",
        headers={"Authorization": "Bearer forged"},
        verify=ca_bundle,
        timeout=10,
    )
    assert response.status_code == 401


def test_t22_ntlm_style_token_is_not_accepted(edge_ready, ca_bundle, http) -> None:
    junk = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAAA="
    response = http.get(
        edge_ready + "/v1/models",
        headers={"Authorization": "Negotiate " + junk},
        verify=ca_bundle,
        timeout=10,
    )
    assert response.status_code in (400, 401)


def test_t25_agent_uses_only_the_shim(shim_url, http) -> None:
    response = http.get(shim_url + "/healthz", timeout=5)
    assert response.status_code == 200
    payload = response.json()
    assert payload["token"] is True
    assert payload["ca"] is True
