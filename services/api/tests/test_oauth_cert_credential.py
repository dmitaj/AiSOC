"""Hosted OAuth: an Entra app certificate in place of a client secret.

Registration accepts either credential (certificate wins, Microsoft identity
platform only); the code exchange and the background refresh then send an
RS256 ``client_assertion`` the certificate's public key verifies, and no
``client_secret``. Secret behaviour is unchanged.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from app.api.v1.endpoints import oauth as ep
from app.models.oauth import OAuthAppCredential, OAuthState
from app.security.credential_vault import CredentialVault
from app.services import ms_client_assertion as mca
from app.workers import oauth_refresh as worker
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

MS_TOKEN = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MS_HINTS = {"token_url": MS_TOKEN, "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"}


def _key_and_cert() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aisoc-test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _key_pem(key: Any, password: bytes | None = None) -> str:
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc).decode()


KEY, CERT = _key_and_cert()
CERT_PEM = CERT.public_bytes(serialization.Encoding.PEM).decode()
FULL_PEM = _key_pem(KEY) + CERT_PEM
THUMB = CERT.fingerprint(hashes.SHA1()).hex().upper()


@pytest.fixture
def vault(monkeypatch: pytest.MonkeyPatch) -> CredentialVault:
    v = CredentialVault(Fernet.generate_key())
    monkeypatch.setattr(ep, "get_vault", lambda: v)
    monkeypatch.setattr(worker, "get_vault", lambda: v)
    return v


def _verify(assertion: str, client_id: str = "cid") -> dict[str, Any]:
    header = jwt.get_unverified_header(assertion)
    assert header["alg"] == "RS256" and header["typ"] == "JWT"
    assert header["x5t"] == mca._b64url(CERT.fingerprint(hashes.SHA1()))
    assert header["x5t#S256"] == mca._b64url(CERT.fingerprint(hashes.SHA256()))
    claims = jwt.decode(assertion, CERT.public_key(), algorithms=["RS256"], audience=MS_TOKEN)
    assert claims["iss"] == claims["sub"] == client_id
    assert claims["exp"] - claims["iat"] == 600 and claims["nbf"] == claims["iat"]
    uuid.UUID(claims["jti"])
    return claims


# --------------------------------------------------------------- registration


def _upsert_db() -> AsyncMock:
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=result)
    db.add = MagicMock()
    return db


async def _register(connector_type: str = "azure_entra", hints: dict | None = None, **body: Any) -> tuple[Any, AsyncMock]:
    db = _upsert_db()
    user = SimpleNamespace(tenant_id=uuid.uuid4())
    with patch.object(ep, "_fetch_catalog_entry", AsyncMock(return_value={"oauth": MS_HINTS if hints is None else hints})):
        view = await ep.upsert_oauth_app(connector_type, ep.OAuthAppRegistration(client_id="cid", **body), user, db)
    return view, db


@pytest.mark.asyncio
async def test_register_secret(vault: CredentialVault) -> None:
    view, db = await _register(client_secret="s3cret")
    row = db.add.call_args.args[0]
    assert vault.decrypt(row.client_secret_vault) == "s3cret"
    assert row.client_certificate_vault is None
    assert view.has_secret and not view.has_certificate


@pytest.mark.asyncio
async def test_register_certificate_wins_over_secret(vault: CredentialVault) -> None:
    view, db = await _register(client_secret="ignored", certificate_pem=FULL_PEM)
    row = db.add.call_args.args[0]
    assert row.client_secret_vault is None
    assert row.client_certificate_thumbprint == THUMB
    assert "PRIVATE KEY" in vault.decrypt(row.client_certificate_vault)
    assert view.has_certificate and not view.has_secret
    assert "PRIVATE KEY" not in view.model_dump_json()


@pytest.mark.asyncio
async def test_register_encrypted_key_with_thumbprint_only(vault: CredentialVault) -> None:
    pem = _key_pem(KEY, b"pw")
    view, db = await _register(certificate_pem=pem, certificate_thumbprint=THUMB.lower(), private_key_password="pw")
    stored = vault.decrypt(db.add.call_args.args[0].client_certificate_vault)
    assert "ENCRYPTED" not in stored  # re-serialised; the password is never stored
    assert view.certificate_thumbprint == THUMB


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {},
        {"client_secret": ""},
        {"certificate_pem": "not a pem"},
        {"certificate_pem": _key_pem(KEY)},  # no cert block, no thumbprint
        {"certificate_pem": _key_pem(KEY), "certificate_thumbprint": "zz"},
        {"certificate_pem": _key_pem(ec.generate_private_key(ec.SECP256R1())) + CERT_PEM},
        {"certificate_pem": _key_pem(KEY, b"pw") + CERT_PEM},  # encrypted, no password
    ],
)
async def test_register_rejects_bad_input(vault: CredentialVault, body: dict) -> None:
    with pytest.raises(HTTPException) as exc:
        await _register(**body)
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_register_certificate_refused_for_non_microsoft_provider(vault: CredentialVault) -> None:
    with pytest.raises(HTTPException) as exc:
        await _register("github", hints={"token_url": "https://github.com/login/oauth/access_token"}, certificate_pem=FULL_PEM)
    assert exc.value.status_code == 422
    assert "client secret only" in exc.value.detail
    # A token_url override is what decides, not the catalog.
    with pytest.raises(HTTPException):
        await _register(certificate_pem=FULL_PEM, token_url="https://github.com/login/oauth/access_token")


# --------------------------------------------------------------- code exchange


def _app_row(vault: CredentialVault, *, cert: bool) -> OAuthAppCredential:
    return OAuthAppCredential(
        tenant_id=uuid.uuid4(),
        connector_type="azure_entra",
        client_id="cid",
        client_secret_vault=None if cert else vault.encrypt("s3cret"),
        client_certificate_vault=vault.encrypt(FULL_PEM) if cert else None,
        client_certificate_thumbprint=THUMB if cert else None,
    )


async def _callback(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch, *, cert: bool) -> dict[str, str]:
    monkeypatch.setattr(ep.settings, "OAUTH_PUBLIC_BASE_URL", "https://api.example.com")
    state_row = OAuthState(
        state="st",
        tenant_id=uuid.uuid4(),
        connector_type="azure_entra",
        extras={},
        return_to="/onboarding",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    rows = iter([state_row, _app_row(vault, cert=cert)])

    def _result(*_a: Any, **_k: Any) -> MagicMock:
        r = MagicMock()
        r.scalar_one_or_none.return_value = next(rows, None)
        return r

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=_result)
    db.add = MagicMock()
    resp = MagicMock()
    resp.json.return_value = {"access_token": "at", "refresh_token": "rt", "expires_in": 3600}
    post = AsyncMock(return_value=resp)
    monkeypatch.setattr(ep, "_fetch_catalog_entry", AsyncMock(return_value={"oauth": MS_HINTS, "category": "identity"}))
    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.post = post
        out = await ep.oauth_callback(db, code="the-code", state="st")
    assert "oauth_success=1" in out.headers["location"]
    assert post.call_args.args[0] == MS_TOKEN
    return post.call_args.kwargs["data"]


@pytest.mark.asyncio
async def test_code_exchange_sends_client_assertion(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    body = await _callback(vault, monkeypatch, cert=True)
    assert "client_secret" not in body
    assert body["client_assertion_type"] == mca.ASSERTION_TYPE
    assert body["client_id"] == "cid" and body["code"] == "the-code"
    _verify(body["client_assertion"])


@pytest.mark.asyncio
async def test_code_exchange_secret_unchanged(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    body = await _callback(vault, monkeypatch, cert=False)
    assert body["client_secret"] == "s3cret"
    assert "client_assertion" not in body


# --------------------------------------------------------------- refresh


@pytest.mark.asyncio
async def test_refresh_sends_client_assertion(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    conn: Any = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        connector_type="azure_entra",
        auth_config=vault.encrypt_dict({"access_token": "old", "refresh_token": "rt"}),
        oauth_refresh_failures=0,
        health_status="active",
    )
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = _app_row(vault, cert=True)
    db.execute = AsyncMock(return_value=result)
    monkeypatch.setattr(worker._CatalogResolver, "hints_for", AsyncMock(return_value=MS_HINTS))
    resp = MagicMock()
    resp.json.return_value = {"access_token": "new", "expires_in": 3600}
    post = AsyncMock(return_value=resp)
    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.post = post
        assert await worker._refresh_one(db, connector=conn, timeout_s=5.0, alarm_threshold=3) is True
    body = post.call_args.kwargs["data"]
    assert body["grant_type"] == "refresh_token" and body["refresh_token"] == "rt"
    assert "client_secret" not in body
    _verify(body["client_assertion"])


def test_certificate_never_signed_for_non_microsoft_token_url(vault: CredentialVault) -> None:
    with pytest.raises(ValueError):
        mca.token_client_auth(vault, _app_row(vault, cert=True), "https://attacker.example/token")
