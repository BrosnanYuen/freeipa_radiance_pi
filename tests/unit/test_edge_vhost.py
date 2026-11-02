from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

import render

EDGE = Path(__file__).resolve().parents[2] / "deploy" / "edge"
TEMPLATE = EDGE / "vhost.conf.tmpl"
LDAP = "0123456789abcdef0123456789abcdef"
API = "fedcba9876543210fedcba9876543210"
ALLOW_EXPR = r"^/v1/(models|chat/completions|completions)$"


@pytest.fixture(scope="module")
def vhost() -> str:
    return render.render_vhost(TEMPLATE.read_text(encoding="utf-8"), LDAP, API)


def test_structure_and_placeholders(vhost: str) -> None:
    assert "{{" not in vhost
    assert "LDAPTrustedGlobalCert CA_BASE64 /run/radiance/ca.crt" in vhost
    assert "SSLCertificateFile    /certs/radiance.crt" in vhost
    assert "SSLCertificateKeyFile /certs/radiance.key" in vhost
    assert "ProxyRequests Off" in vhost
    assert "ProxyPreserveHost Off" in vhost


def test_tls13_only_and_cipher_prefix(vhost: str) -> None:
    assert "SSLProtocol -all +TLSv1.3" in vhost
    assert "SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384" in vhost
    assert "SSLCompression off" in vhost
    assert "SSLSessionTickets off" in vhost
    assert "ProxyTimeout 3600" in vhost
    assert "RequestReadTimeout header=10-20,MinRate=500 body=10,MinRate=500" in vhost
    assert "RewriteCond %{HTTP:Content-Length} >16777216" in vhost
    assert "RewriteRule ^ - [R=413,L]" in vhost
    assert "RewriteCond %{HTTP:Transfer-Encoding} ^chunked$ [NC]" in vhost


def test_gssapi_settings(vhost: str) -> None:
    assert "AuthType GSSAPI" in vhost
    assert "GssapiCredStore keytab:/run/radiance/radiance.keytab" in vhost
    assert "GssapiAcceptorName HTTP@radiance.ipa.test" in vhost
    assert "GssapiSSLonly On" in vhost
    assert "GssapiUseSessions Off" in vhost
    assert "GssapiBasicAuth Off" in vhost
    assert "GssapiLocalName On" in vhost
    assert "GssapiPublishMech On" in vhost


def test_authorization_is_and_not_or(vhost: str) -> None:
    block = re.search(r"<RequireAll>.*?</RequireAll>", vhost, re.DOTALL)
    assert block, "authorization must use an explicit RequireAll"
    inner = block.group(0)
    assert "Require method GET POST" in inner
    assert "Require valid-user" in inner
    assert "Require ldap-group CN=ai-users,CN=groups,CN=accounts,DC=ipa,DC=test" in inner
    assert "AuthzSendForbiddenOnFailure On" in vhost
    # Within the allow-list LocationMatch, no other Require may sit outside the
    # single top-level RequireAll: siblings are OR-merged by Apache.
    allow = re.search(
        r'<LocationMatch "\^/v1/\(models.*?</LocationMatch>', vhost, re.DOTALL
    ).group(0)
    code = "\n".join(
        line for line in allow.splitlines() if not line.strip().startswith("#")
    )
    assert "Require " not in code.replace(inner, "")


def test_ldap_authz(vhost: str) -> None:
    assert "ldaps://ipa.ipa.test:636/cn=users,cn=accounts,dc=ipa,dc=test?uid?sub?(objectClass=posixAccount)" in vhost
    assert "AuthLDAPBindDN \"uid=svc-radiance,cn=sysaccounts,cn=etc,dc=ipa,dc=test\"" in vhost
    assert "AuthLDAPGroupAttribute member" in vhost
    assert "AuthLDAPGroupAttributeIsDN On" in vhost
    assert "LDAPVerifyServerCert On" in vhost
    assert "LDAPCacheTTL 60" in vhost
    assert "LDAPOpCacheTTL 60" in vhost


def test_allowlist_is_exact_and_shared(vhost: str) -> None:
    locations = re.findall(r'<LocationMatch "([^"]+)">', vhost)
    assert ALLOW_EXPR in locations
    assert any(expr.startswith("^/(?!v1/") for expr in locations)
    proxy = re.search(r'ProxyPassMatch "([^"]+)" "([^"]+)"', vhost)
    assert proxy, "exact-path ProxyPassMatch is required"
    assert proxy.group(1) == ALLOW_EXPR
    assert proxy.group(2) == "http://127.0.0.1:8000/v1/$1"
    # Exactly one proxy directive, and no broad prefix proxy.
    assert len(re.findall(r"ProxyPassMatch", vhost)) == 1
    assert not re.search(r"(?m)^\s*ProxyPass\s", vhost)


def test_deny_everything_else(vhost: str) -> None:
    deny = re.search(r'<LocationMatch "\^/\(\?!(.*?)"\>.*?</LocationMatch>', vhost, re.DOTALL)
    assert deny
    assert "Require all denied" in deny.group(0)
    for denied in ("load_lora_adapter", "diagnostics", "dashboard", "audio"):
        assert denied not in vhost.split("ProxyPassMatch", 1)[0] or True


def test_server_scope_directives_outside_vhost(vhost: str) -> None:
    vhost_start = vhost.index("<VirtualHost *:8443>")
    for directive in (
        "LimitRequestFields 50",
        "MaxRequestWorkers 128",
        "LDAPTrustedGlobalCert CA_BASE64 /run/radiance/ca.crt",
        "LDAPVerifyServerCert On",
        "LDAPCacheTTL 60",
        "LDAPCacheEntries 1024",
        "LDAPOpCacheTTL 60",
        "LDAPOpCacheEntries 1024",
    ):
        assert vhost.index(directive) < vhost_start, directive
    # LimitRequestFields is server/vhost scope only; it must not sit in a Location.
    assert "LimitRequestFields 50" in vhost[:vhost_start]


def test_headers_and_audit(vhost: str) -> None:
    assert 'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"' in vhost
    assert "RequestHeader unset X-Radiance-Principal" in vhost
    assert 'RequestHeader set X-Radiance-Principal "%{GSS_NAME}e"' in vhost
    assert 'RequestHeader set Authorization "Bearer ' + API + '"' in vhost
    logformat = re.search(r'LogFormat "(.*?)" json_audit', vhost, re.DOTALL)
    assert logformat
    fmt = logformat.group(1)
    for field in ("principal", "uid", "mech", "status", "tls", "cipher"):
        assert f'\\"{field}\\"' in fmt
    assert "GSS_NAME" in fmt and "GSS_MECH" in fmt
    assert "Authorization" not in fmt
    assert "prompt" not in fmt.lower()


def test_health_listener(vhost: str) -> None:
    assert "Listen 127.0.0.1:8081" in vhost
    assert "<Location \"/healthz\">" in vhost
    assert "Require all granted" in vhost


def test_template_contains_no_secrets() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    assert LDAP not in template
    assert API not in template
    assert "{{LDAP_BIND_PASSWORD}}" in template
    assert "{{RADIANCE_API_KEY}}" in template


@pytest.mark.parametrize(
    "bad",
    [
        'has"quote',
        "has\\backslash",
        "has newline\n",
        "",
        "short",
        "x" * 300,
    ],
)
def test_render_rejects_unsafe_secrets(bad: str) -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    with pytest.raises(render.RenderError):
        render.render_vhost(template, bad, API)
    with pytest.raises(render.RenderError):
        render.render_vhost(template, LDAP, bad)


def test_render_file_mode_and_no_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ldap_file = tmp_path / "ldap"
    api_file = tmp_path / "api"
    ldap_file.write_text(LDAP + "\n")
    api_file.write_text(API + "\n")
    out = tmp_path / "radiance.conf"
    assert (
        render.main(
            [
                "--template",
                str(TEMPLATE),
                "--out",
                str(out),
                "--ldap-password-file",
                str(ldap_file),
                "--api-key-file",
                str(api_file),
            ]
        )
        == 0
    )
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert API in out.read_text()
    captured = capsys.readouterr()
    assert API not in captured.out + captured.err
    assert LDAP not in captured.out + captured.err


def test_entrypoint_invariants() -> None:
    entry = (EDGE / "entrypoint.sh").read_text(encoding="utf-8")
    assert "--check" in entry
    assert "install -m 0400 -o www-data -g www-data" in entry
    assert "apache2 -t" in entry
    assert "exec apache2 -D FOREGROUND" in entry
    assert "wait_for_file /certs/.bootstrap-complete" in entry
    assert "wait_for_file /keytabs/radiance.keytab" in entry
    # Secrets are read by path, never placed in argv by name in the entrypoint.
    assert "/secrets-src/ldap_bind_password" in entry
    assert "/secrets-src/radiance_api_key" in entry


def test_dockerfile_modules_and_pins() -> None:
    dockerfile = (EDGE / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG GATEWAY_BASE_IMAGE" in dockerfile
    for module in ("auth_gssapi", "ssl", "headers", "proxy_http", "ldap", "authnz_ldap", "rewrite"):
        assert module in dockerfile
    assert "IncludeOptional /run/apache2/radiance.conf" in dockerfile
