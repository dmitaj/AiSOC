"""AiSOC-generated Entra app certificates: generate, store, download, auto-rotate.

Rotation runs against a fake Entra (``httpx.MockTransport``) that only issues
a token for a client assertion signed by a certificate registered on the app,
and only accepts addKey/removeKey whose proof-of-possession verifies against a
registered certificate with the documented claims.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from app.api.v1.endpoints import connectors as conn_ep
from app.api.v1.endpoints import oauth as oauth_ep
from app.security.credential_vault import CredentialVault
from app.services import ms_cert_lifecycle as mcl
from app.workers import ms_cert_rotation as worker
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OBJECT_ID = "99999999-8888-7777-6666-555555555555"
OLD_KEY_ID = "0ld0ld00-0000-0000-0000-000000000000"
NEW_KEY_ID = "4e404e40-0000-0000-0000-000000000000"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
NOW = datetime.now(UTC)


@pytest.fixture
def vault(monkeypatch: pytest.MonkeyPatch) -> CredentialVault:
    v = CredentialVault(Fernet.generate_key())
    for mod in (conn_ep, oauth_ep, worker):
        monkeypatch.setattr(mod, "get_vault", lambda: v)
    monkeypatch.setattr(mcl, "validate_outbound_url", lambda url: url)  # no DNS in unit tests
    return v


@pytest.fixture
def pending(monkeypatch: pytest.MonkeyPatch) -> dict[str, dict]:
    """In-memory stand-in for the Redis pending store."""
    store: dict[str, dict] = {}

    async def _store(tenant_id: Any, payload: dict) -> str:
        pid = f"pid{len(store):05d}xyz"
        store[f"{tenant_id}:{pid}"] = json.loads(json.dumps(payload))
        return pid

    async def _load(tenant_id: Any, pid: str, *, consume: bool) -> dict:
        key = f"{tenant_id}:{pid}"
        if key not in store:
            raise mcl.PendingCertificateError("Generated certificate not found or expired")
        return store.pop(key) if consume else store[key]

    monkeypatch.setattr(mcl, "store_pending", _store)
    monkeypatch.setattr(mcl, "load_pending", _load)
    return store


def _user() -> SimpleNamespace:
    return SimpleNamespace(tenant_id=uuid.uuid4())


async def _generate(user: SimpleNamespace, **kw: Any) -> conn_ep.GeneratedCertificateResponse:
    body = {"connector_type": "azure_entra", "name": "Entra prod", "entra_directory_id": TENANT, **kw}
    return await conn_ep.generate_certificate(conn_ep.GenerateCertificateRequest(**body), user)


# --------------------------------------------------------------- generation


@pytest.mark.asyncio
async def test_generate_returns_public_half_only_and_parks_the_key(vault: CredentialVault, pending: dict) -> None:
    user = _user()
    resp = await _generate(user, application_object_id=OBJECT_ID)
    dumped = resp.model_dump_json()
    assert "PRIVATE KEY" not in dumped
    cert = x509.load_der_x509_certificate(base64.b64decode(resp.certificate_der_base64))
    assert x509.load_pem_x509_certificate(resp.certificate_pem.encode()) == cert
    assert resp.thumbprint == cert.fingerprint(hashes.SHA1()).hex().upper()  # noqa: S303
    assert cert.signature_hash_algorithm.name == "sha256"
    assert isinstance(cert.public_key(), rsa.RSAPublicKey) and cert.public_key().key_size == 2048
    life = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert timedelta(days=730) <= life <= timedelta(days=730, minutes=6)
    assert resp.not_after == cert.not_valid_after_utc
    cn = cert.subject.rfc4514_string()
    assert "AiSOC Entra prod 11111111" in cn and cert.issuer == cert.subject

    (stored,) = pending.values()
    assert "PRIVATE KEY" not in json.dumps(stored)  # vault ciphertext only, even in Redis
    pem = vault.decrypt(stored["pem_vault"])
    assert "PRIVATE KEY" in pem and mcl.certificate_of(pem) == cert
    assert stored["application_object_id"] == OBJECT_ID and stored["thumbprint"] == resp.thumbprint


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kw",
    [{"connector_type": "okta"}, {"application_object_id": "not-a-guid"}, {"entra_directory_id": "common"}, {"entra_directory_id": "a/b"}],
)
async def test_generate_rejects_bad_input(vault: CredentialVault, pending: dict, kw: dict) -> None:
    with pytest.raises(HTTPException) as exc:
        await _generate(_user(), **kw)
    assert exc.value.status_code == 422


def _create_db() -> AsyncMock:
    db = AsyncMock()
    db.add = MagicMock()
    return db


@pytest.mark.asyncio
async def test_create_consumes_pending_into_auth_config(vault: CredentialVault, pending: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    user = _user()
    gen = await _generate(user)
    monkeypatch.setattr(conn_ep, "refuse_if_over_limit", AsyncMock())
    monkeypatch.setattr(conn_ep, "_validate_connector_type", AsyncMock(return_value={"category": "iam"}))
    monkeypatch.setattr(conn_ep, "_build_connector_response", lambda c: c)
    db = _create_db()
    req = conn_ep.CreateConnectorRequest(
        name="Entra",
        connector_type="azure_entra",
        auth_config={"certificate_pending_id": gen.pending_certificate_id},
        # A client cannot claim a pasted certificate is AiSOC-managed.
        connector_config={"tenant_id": TENANT, "client_id": CLIENT_ID, "certificate_lifecycle": {"managed": True, "not_after": "x"}},
    )
    row = await conn_ep.create_connector(req, user, db)
    assert not pending  # consumed
    assert "certificate_pending_id" not in row.auth_config
    assert row.auth_config["certificate_pem"].startswith("vault:")
    assert mcl.thumbprint(mcl.certificate_of(vault.decrypt(row.auth_config["certificate_pem"]))) == gen.thumbprint
    life = row.connector_config["certificate_lifecycle"]
    assert life["managed"] is True and mcl.parse_ts(life["not_after"]) == gen.not_after

    # Reusing the id fails cleanly.
    with pytest.raises(HTTPException) as exc:
        await conn_ep.create_connector(req, user, _create_db())
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_pasted_pem_is_recorded_unmanaged_and_lifecycle_cannot_be_spoofed(
    vault: CredentialVault, pending: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    gen = mcl.generate_certificate("pasted")
    monkeypatch.setattr(conn_ep, "refuse_if_over_limit", AsyncMock())
    monkeypatch.setattr(conn_ep, "_validate_connector_type", AsyncMock(return_value={"category": "iam"}))
    monkeypatch.setattr(conn_ep, "_build_connector_response", lambda c: c)
    req = conn_ep.CreateConnectorRequest(
        name="Entra",
        connector_type="azure_entra",
        auth_config={"certificate_pem": gen.pem},
        connector_config={"certificate_lifecycle": {"managed": True}},
    )
    row = await conn_ep.create_connector(req, _user(), _create_db())
    life = row.connector_config["certificate_lifecycle"]
    assert life["managed"] is False and mcl.parse_ts(life["not_after"]) == gen.not_after


# --------------------------------------------------------------- download


def _row_db(row: Any) -> AsyncMock:
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    db.execute = AsyncMock(return_value=result)
    return db


@pytest.mark.asyncio
async def test_download_connector_cer(vault: CredentialVault) -> None:
    gen = mcl.generate_certificate("dl")
    conn = SimpleNamespace(connector_type="azure_entra", auth_config=vault.encrypt_dict({"certificate_pem": gen.pem}))
    resp = await conn_ep.download_connector_certificate(uuid.uuid4(), _user(), _row_db(conn))
    assert resp.media_type == "application/pkix-cert"
    assert x509.load_der_x509_certificate(resp.body) == gen.certificate
    assert b"PRIVATE" not in resp.body and ".cer" in resp.headers["content-disposition"]

    key_only = SimpleNamespace(
        connector_type="azure_entra", auth_config=vault.encrypt_dict({"certificate_pem": gen.pem.split("-----BEGIN CERTIFICATE")[0]})
    )
    with pytest.raises(HTTPException) as exc:
        await conn_ep.download_connector_certificate(uuid.uuid4(), _user(), _row_db(key_only))
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException):
        await conn_ep.download_connector_certificate(uuid.uuid4(), _user(), _row_db(None))


# --------------------------------------------------------------- OAuth app


@pytest.mark.asyncio
async def test_oauth_app_put_with_generated_certificate(vault: CredentialVault, pending: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    user = _user()
    gen = await _generate(user, application_object_id=OBJECT_ID)
    db = _row_db(None)
    db.add = MagicMock()
    hints = {"oauth": {"token_url": TOKEN_URL}}
    monkeypatch.setattr(oauth_ep, "_fetch_catalog_entry", AsyncMock(return_value=hints))
    payload = oauth_ep.OAuthAppRegistration(client_id=CLIENT_ID, certificate_pending_id=gen.pending_certificate_id)
    view = await oauth_ep.upsert_oauth_app("azure_entra", payload, user, db)
    row = db.add.call_args.args[0]
    assert row.client_certificate_managed is True and row.client_secret_vault is None
    assert row.client_certificate_thumbprint == gen.thumbprint == view.certificate_thumbprint
    assert row.client_certificate_not_after == gen.not_after == view.certificate_not_after
    assert row.client_certificate_rotation == {"entra_tenant_id": TENANT, "application_object_id": OBJECT_ID}
    assert view.certificate_managed and "PRIVATE KEY" not in view.model_dump_json()

    resp = await oauth_ep.download_oauth_app_certificate("azure_entra", user, _row_db(row))
    assert mcl.thumbprint(x509.load_der_x509_certificate(resp.body)) == gen.thumbprint


# --------------------------------------------------------------- fake Entra


class FakeEntra:
    """Registered certs, token issuance and addKey/removeKey PoP checks."""

    def __init__(self, registered: list[x509.Certificate], *, get_status: int = 200, add_status: int = 200, remove_status: int = 204):
        self.keys = {OLD_KEY_ID: registered[0]}
        self.get_status, self.add_status, self.remove_status = get_status, add_status, remove_status
        self.new_cert_works = True
        self.calls: list[str] = []
        self.added: list[dict] = []
        self.removed: list[dict] = []
        self.token_thumbs: list[str] = []

    def _by_x5t(self, x5t: str) -> x509.Certificate | None:
        for cert in self.keys.values():
            if mcl._b64url(cert.fingerprint(hashes.SHA1())) == x5t:  # noqa: S303
                return cert
        return None

    def _verify_pop(self, proof: str) -> x509.Certificate:
        cert = self._by_x5t(jwt.get_unverified_header(proof)["x5t"])
        assert cert is not None, "PoP signed by a key not registered on the app"
        claims = jwt.decode(proof, cert.public_key(), algorithms=["RS256"], audience="00000002-0000-0000-c000-000000000000")
        assert claims["iss"] == OBJECT_ID
        assert claims["exp"] - claims["nbf"] == 600
        return cert

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(f"{request.method} {request.url.path}")
        if url == TOKEN_URL:
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            assert form["scope"] == "https://graph.microsoft.com/.default" and form["grant_type"] == "client_credentials"
            assertion = form["client_assertion"]
            cert = self._by_x5t(jwt.get_unverified_header(assertion)["x5t"])
            if cert is None or (cert is not self.keys[OLD_KEY_ID] and not self.new_cert_works):
                return httpx.Response(401, json={"error": "invalid_client", "error_description": "AADSTS700027"})
            jwt.decode(assertion, cert.public_key(), algorithms=["RS256"], audience=TOKEN_URL)
            self.token_thumbs.append(mcl.thumbprint(cert))
            return httpx.Response(200, json={"access_token": f"tok-{mcl.thumbprint(cert)}"})
        assert request.url.host == "graph.microsoft.com"
        assert request.headers["authorization"].startswith("Bearer tok-")
        app_path = f"/v1.0/applications(appId='{CLIENT_ID}')"
        if request.method == "GET" and request.url.path == app_path:
            if self.get_status != 200:
                return httpx.Response(self.get_status, json={"error": {"message": "Insufficient privileges"}})
            kcs = [
                {"keyId": kid, "customKeyIdentifier": base64.b64encode(c.fingerprint(hashes.SHA1())).decode()}  # noqa: S303
                for kid, c in self.keys.items()
            ]
            return httpx.Response(200, json={"id": OBJECT_ID, "keyCredentials": kcs})
        body = json.loads(request.content)
        if request.url.path == f"{app_path}/addKey":
            signer = self._verify_pop(body["proof"])
            self.added.append({"body": body, "signer": signer})
            if self.add_status != 200:
                return httpx.Response(self.add_status, json={"error": {"message": "Proof of possession failed"}})
            assert body["passwordCredential"] is None
            self.keys[NEW_KEY_ID] = x509.load_der_x509_certificate(base64.b64decode(body["keyCredential"]["key"]))
            return httpx.Response(200, json={"keyId": NEW_KEY_ID, "type": "AsymmetricX509Cert", "usage": "Verify"})
        if request.url.path == f"{app_path}/removeKey":
            signer = self._verify_pop(body["proof"])
            self.removed.append({"keyId": body["keyId"], "signer": signer})
            if self.remove_status != 204:
                return httpx.Response(self.remove_status, json={"error": {"message": "boom"}})
            self.keys.pop(body["keyId"], None)
            return httpx.Response(204)
        return httpx.Response(404)


def _connector(vault: CredentialVault, *, not_after: datetime, managed: bool = True, life_extra: dict | None = None) -> Any:
    old = mcl.generate_certificate("AiSOC Entra 11111111")
    conn = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="Entra",
        connector_type="azure_entra",
        health_status="healthy",
        auth_config=vault.encrypt_dict({"certificate_pem": old.pem}),
        connector_config={
            "tenant_id": TENANT,
            "client_id": CLIENT_ID,
            "checkpoint": "c1",
            "certificate_lifecycle": {"managed": managed, "not_after": not_after.isoformat(), **(life_extra or {})},
        },
    )
    return conn, old


def _db_for(row: Any) -> AsyncMock:
    db = _row_db(row)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


async def _run(entra: FakeEntra, conn: Any, monkeypatch: pytest.MonkeyPatch) -> tuple[str, AsyncMock, AsyncMock]:
    audit = AsyncMock()
    monkeypatch.setattr(worker, "emit_audit", audit)
    sleep = AsyncMock()
    async with httpx.AsyncClient(transport=httpx.MockTransport(entra.handler)) as http:
        result = await worker.rotate_connector(_db_for(conn), conn, http=http, now=NOW, sleep=sleep)
    return result, audit, sleep


def _stored_pem(vault: CredentialVault, conn: Any) -> str:
    return vault.decrypt_dict(conn.auth_config)["certificate_pem"]


# --------------------------------------------------------------- rotation


@pytest.mark.asyncio
async def test_rotation_happy_path(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, old = _connector(vault, not_after=NOW + timedelta(days=10))
    entra = FakeEntra([old.certificate])
    result, audit, _ = await _run(entra, conn, monkeypatch)
    assert result == "rotated"

    # addKey: documented body, PoP signed by the CURRENT key (verified by FakeEntra).
    (add,) = entra.added
    assert add["signer"] == old.certificate
    kc = add["body"]["keyCredential"]
    assert kc["type"] == "AsymmetricX509Cert" and kc["usage"] == "Verify"
    new_cert = x509.load_der_x509_certificate(base64.b64decode(kc["key"]))

    # A token was obtained with the NEW cert before the swap.
    assert entra.token_thumbs == [mcl.thumbprint(old.certificate), mcl.thumbprint(new_cert)]

    # Swapped: stored PEM is the new key + cert; lifecycle updated; other config kept.
    pem = _stored_pem(vault, conn)
    assert mcl.certificate_of(pem) == new_cert and "PRIVATE KEY" in pem
    life = conn.connector_config["certificate_lifecycle"]
    assert life["managed"] and life["key_id"] == NEW_KEY_ID and life["application_object_id"] == OBJECT_ID
    assert mcl.parse_ts(life["not_after"]) == new_cert.not_valid_after_utc
    assert life["last_error"] is None and life.get("last_warning") is None
    assert conn.connector_config["checkpoint"] == "c1"

    # Old key removed with a PoP signed by the NEW key.
    assert entra.removed == [{"keyId": OLD_KEY_ID, "signer": new_cert}]
    assert set(entra.keys) == {NEW_KEY_ID}
    assert audit.await_args_list[-1].kwargs["action"] == "connectors:certificate_rotate"


@pytest.mark.asyncio
async def test_not_yet_due_is_skipped(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, old = _connector(vault, not_after=NOW + timedelta(days=31))
    entra = FakeEntra([old.certificate])
    result, audit, _ = await _run(entra, conn, monkeypatch)
    assert result == "skipped" and entra.calls == [] and audit.await_count == 0
    assert _stored_pem(vault, conn) == old.pem


@pytest.mark.asyncio
async def test_unmanaged_is_never_rotated(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, old = _connector(vault, not_after=NOW + timedelta(days=2), managed=False)
    entra = FakeEntra([old.certificate])
    result, _, _ = await _run(entra, conn, monkeypatch)
    assert result == "expiring_unmanaged" and entra.calls == []
    assert _stored_pem(vault, conn) == old.pem


@pytest.mark.asyncio
async def test_addkey_failure_keeps_old_cert_and_records(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, old = _connector(vault, not_after=NOW + timedelta(days=5))
    entra = FakeEntra([old.certificate], add_status=403)
    result, audit, _ = await _run(entra, conn, monkeypatch)
    assert result == "failed"
    assert _stored_pem(vault, conn) == old.pem
    life = conn.connector_config["certificate_lifecycle"]
    assert "addKey failed" in life["last_error"] and life["last_attempt_at"]
    assert conn.health_status == "unhealthy"  # < 7 days left: the alarm
    assert audit.await_args_list[-1].kwargs["action"] == "connectors:certificate_rotation_failed"
    assert entra.removed == []


@pytest.mark.asyncio
async def test_new_cert_never_authenticates_no_swap(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, old = _connector(vault, not_after=NOW + timedelta(days=20))
    entra = FakeEntra([old.certificate])
    entra.new_cert_works = False
    result, _, sleep = await _run(entra, conn, monkeypatch)
    assert result == "failed"
    assert _stored_pem(vault, conn) == old.pem
    assert "never authenticated" in conn.connector_config["certificate_lifecycle"]["last_error"]
    assert sleep.await_count == 5  # 6 bounded attempts
    assert conn.health_status == "healthy"  # 20 days left: recorded, not yet alarmed
    # The unusable key is removed again (PoP by the old key) so daily retries don't pile up keys.
    assert entra.removed == [{"keyId": NEW_KEY_ID, "signer": old.certificate}]


@pytest.mark.asyncio
async def test_removekey_failure_after_swap_keeps_swap(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, old = _connector(vault, not_after=NOW + timedelta(days=10))
    entra = FakeEntra([old.certificate], remove_status=500)
    result, _, _ = await _run(entra, conn, monkeypatch)
    assert result == "rotated"
    assert _stored_pem(vault, conn) != old.pem
    life = conn.connector_config["certificate_lifecycle"]
    assert "removing the previous certificate failed" in life["last_warning"] and life["last_error"] is None


@pytest.mark.asyncio
async def test_object_id_unresolvable_without_permission(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    conn, old = _connector(vault, not_after=NOW + timedelta(days=10))
    entra = FakeEntra([old.certificate], get_status=403)
    result, _, _ = await _run(entra, conn, monkeypatch)
    assert result == "failed" and "Application object ID" in conn.connector_config["certificate_lifecycle"]["last_error"]

    # With the object id supplied at generation, no directory read is needed;
    # the hand-uploaded first cert's keyId is unknown, so it is left for the operator.
    conn, old = _connector(vault, not_after=NOW + timedelta(days=10), life_extra={"application_object_id": OBJECT_ID})
    entra = FakeEntra([old.certificate], get_status=403)
    result, _, _ = await _run(entra, conn, monkeypatch)
    assert result == "rotated" and entra.removed == []
    assert "keyId is unknown" in conn.connector_config["certificate_lifecycle"]["last_warning"]


@pytest.mark.asyncio
async def test_oauth_app_rotation(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    old = mcl.generate_certificate("AiSOC azure_entra")
    app: Any = SimpleNamespace(
        tenant_id=uuid.uuid4(),
        connector_type="azure_entra",
        client_id=CLIENT_ID,
        token_url=None,
        client_certificate_vault=vault.encrypt(old.pem),
        client_certificate_thumbprint=old.thumbprint,
        client_certificate_not_after=NOW + timedelta(days=3),
        client_certificate_managed=True,
        client_certificate_rotation={"entra_tenant_id": TENANT, "application_object_id": OBJECT_ID, "key_id": OLD_KEY_ID},
    )
    entra = FakeEntra([old.certificate])
    monkeypatch.setattr(worker, "emit_audit", AsyncMock())
    async with httpx.AsyncClient(transport=httpx.MockTransport(entra.handler)) as http:
        assert await worker.rotate_app(_db_for(app), app, http=http, now=NOW, sleep=AsyncMock()) == "rotated"
    new_cert = mcl.certificate_of(vault.decrypt(app.client_certificate_vault))
    assert new_cert is not None
    assert app.client_certificate_thumbprint == mcl.thumbprint(new_cert) != old.thumbprint
    assert app.client_certificate_not_after == new_cert.not_valid_after_utc
    assert app.client_certificate_rotation["key_id"] == NEW_KEY_ID
    assert entra.removed == [{"keyId": OLD_KEY_ID, "signer": new_cert}]
    assert not any(c.startswith("GET") for c in entra.calls)  # object id + keyId known: no directory read


def test_outbound_hosts_are_pinned() -> None:
    with pytest.raises(mcl.RotationError):
        mcl._guard("https://evil.example/applications")


@pytest.mark.asyncio
async def test_pending_store_is_tenant_scoped_with_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    data: dict[str, tuple[str, int]] = {}
    fake = SimpleNamespace(
        set=AsyncMock(side_effect=lambda k, v, ex: data.__setitem__(k, (v, ex))),
        get=AsyncMock(side_effect=lambda k: data.get(k, (None,))[0]),
        delete=AsyncMock(side_effect=lambda k: data.pop(k, None)),
    )
    monkeypatch.setattr(mcl, "_redis", AsyncMock(return_value=fake))
    pid = await mcl.store_pending("t1", {"pem_vault": "vault:v1:x"})
    assert [ex for _, ex in data.values()] == [mcl.PENDING_TTL_SECONDS]
    with pytest.raises(mcl.PendingCertificateError):
        await mcl.load_pending("t2", pid, consume=True)  # another tenant
    assert (await mcl.load_pending("t1", pid, consume=False))["pem_vault"] == "vault:v1:x"
    await mcl.load_pending("t1", pid, consume=True)
    with pytest.raises(mcl.PendingCertificateError):
        await mcl.load_pending("t1", pid, consume=True)


@pytest.mark.asyncio
async def test_run_once_sweeps_tenant_by_tenant(vault: CredentialVault, monkeypatch: pytest.MonkeyPatch) -> None:
    not_due, _ = _connector(vault, not_after=NOW + timedelta(days=90))
    pasted, _ = _connector(vault, not_after=NOW + timedelta(days=3), managed=False)
    batches = iter([[uuid.uuid4()], [not_due, pasted], []])
    statements: list[str] = []

    async def _execute(stmt: Any) -> MagicMock:
        statements.append(str(stmt))
        result = MagicMock()
        result.scalars.return_value.all.return_value = next(batches)
        return result

    db = AsyncMock()
    db.execute = _execute
    session = MagicMock()
    session.return_value.__aenter__ = AsyncMock(return_value=db)
    session.return_value.__aexit__ = AsyncMock(return_value=None)
    monkeypatch.setattr(worker, "AsyncSessionLocal", session)
    stats = await worker.run_once()
    assert stats == {"skipped": 1, "expiring_unmanaged": 1, "rotated": 0, "failed": 0}
    assert all("tenant_id" in s for s in statements[1:])
