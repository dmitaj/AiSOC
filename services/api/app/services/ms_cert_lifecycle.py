"""Lifecycle of AiSOC-managed Entra app certificates: generate, park, rotate.

Generate
    :func:`generate_certificate` makes an RSA-2048 key and a self-signed,
    SHA-256, 730-day X.509 certificate. The stored form is the same PEM a
    pasted certificate becomes (unencrypted PKCS#8 key + CERTIFICATE block),
    so everything downstream (the connectors' ``CertificateCredential``, the
    OAuth ``client_assertion``) treats both alike. Only the public half ever
    leaves this service.

Park (pending credential)
    A certificate is generated *before* the operator has uploaded its .cer to
    Entra, and often before the connector / OAuth app row exists. Writing it
    straight into a saved connector would break a working one, so it is
    parked in Redis (vault ciphertext, tenant-scoped key, 24 h TTL) under a
    random id. The create / update / OAuth-app PUT call that carries
    ``certificate_pending_id`` consumes it; an abandoned one simply expires.

Rotate (Microsoft Graph ``addKey`` / ``removeKey``)
    Per https://learn.microsoft.com/graph/api/application-addkey and
    https://learn.microsoft.com/graph/application-rollkey-prooftoken :
    the call is authorised by an app-only Graph token from the *current*
    certificate (an application needs no permission to roll its own keys) and
    carries a proof-of-possession JWT signed by a current key, with
    ``aud=00000002-0000-0000-c000-000000000000``, ``iss`` = the application's
    **object id** (``id``, not ``appId``), ``nbf``/``exp`` 10 minutes apart.
    The URL may address the app by ``appId`` (``/applications(appId='…')``),
    so only ``iss`` needs the object id: it comes from the operator (portal
    Overview page) or from ``GET /applications(appId='…')?$select=id,
    keyCredentials``, which needs a directory read permission
    (Application.Read.All or Directory.Read.All) the app may not have.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app._vendor.ssrf_guard import SSRFError, validate_outbound_url
from app.services.ms_client_assertion import ASSERTION_TYPE, _cert, client_assertion

#: Connector types whose app-only auth accepts a certificate.
CERT_CONNECTOR_TYPES = frozenset(
    {"azure_entra", "m365_audit", "azure_defender", "azure_activity", "azure_event_hubs", "microsoft_sentinel", "microsoft_intune"}
)
#: ``connector_config`` key holding non-secret certificate metadata. One key so
#: the connectors service drops it from constructor kwargs with one entry.
LIFECYCLE_KEY = "certificate_lifecycle"
VALIDITY = timedelta(days=730)
ROTATE_WITHIN = timedelta(days=30)
PENDING_TTL_SECONDS = 24 * 3600

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
POP_AUDIENCE = "00000002-0000-0000-c000-000000000000"
_ALLOWED_HOSTS = frozenset({"graph.microsoft.com", "login.microsoftonline.com"})
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
_MULTI_TENANT_SEGMENTS = frozenset({"common", "organizations", "consumers"})


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def is_guid(value: str | None) -> bool:
    return bool(value and _GUID.match(value))


def valid_tenant(value: str | None) -> bool:
    return bool(value and _TENANT.match(value) and value.lower() not in _MULTI_TENANT_SEGMENTS)


def tenant_from_token_url(url: str | None) -> str | None:
    """The tenant segment of ``https://login.microsoftonline.com/<tenant>/…`` if it names one."""
    parts = urlparse(url or "")
    segment = parts.path.strip("/").split("/")[0] if parts.path else ""
    return segment if valid_tenant(segment) else None


# --------------------------------------------------------------- certificates


@dataclass(frozen=True)
class GeneratedCertificate:
    pem: str  # private key + certificate; vault-encrypt before storing
    thumbprint: str  # hex SHA-1, upper case (Entra's x5t / portal thumbprint)
    not_after: datetime
    certificate: x509.Certificate


def common_name(label: str | None, entra_tenant_id: str | None) -> str:
    short = (entra_tenant_id or "").split("-")[0].split(".")[0][:8]
    return " ".join(p for p in ("AiSOC", (label or "").strip()[:40], short) if p)


def generate_certificate(cn: str) -> GeneratedCertificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn[:64])])
    now = datetime.now(UTC).replace(microsecond=0)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + VALIDITY)
        .sign(key, hashes.SHA256())
    )
    pem = (
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        + cert.public_bytes(serialization.Encoding.PEM).decode()
    )
    return GeneratedCertificate(pem, thumbprint(cert), cert.not_valid_after_utc, cert)


def thumbprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA1()).hex().upper()  # noqa: S303 - Entra identifies certs by SHA-1 (x5t)


def certificate_of(pem: str | None) -> x509.Certificate | None:
    """The CERTIFICATE block of a stored PEM, or None (key-only PEM / unreadable)."""
    try:
        return _cert(pem or "")
    except ValueError:
        return None


def not_after_of(pem: str | None) -> datetime | None:
    cert = certificate_of(pem)
    return cert.not_valid_after_utc if cert else None


def public_view(cert: x509.Certificate) -> dict[str, Any]:
    """Everything about a certificate that may leave the server."""
    return {
        "thumbprint": thumbprint(cert),
        "not_after": cert.not_valid_after_utc,
        "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "certificate_der_base64": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(),
    }


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def parse_ts(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


# --------------------------------------------------------------- pending store


class PendingCertificateError(Exception):
    """The pending id is unknown, expired, or belongs to another tenant."""


def _pending_key(tenant_id: uuid.UUID | str, pending_id: str) -> str:
    return f"ms_cert_pending:{tenant_id}:{pending_id}"


async def _redis() -> Any:
    from app.core.scheduler_lock import _get_redis_client  # noqa: PLC0415 - the api's one shared client

    return await _get_redis_client()


async def store_pending(tenant_id: uuid.UUID | str, payload: dict[str, Any]) -> str:
    """Park ``payload`` (which holds only vault ciphertext) for 24 h; return its id."""
    pending_id = secrets.token_urlsafe(18)
    await (await _redis()).set(_pending_key(tenant_id, pending_id), json.dumps(payload), ex=PENDING_TTL_SECONDS)
    return pending_id


async def load_pending(tenant_id: uuid.UUID | str, pending_id: str, *, consume: bool) -> dict[str, Any]:
    if not isinstance(pending_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", pending_id):
        raise PendingCertificateError("certificate_pending_id is malformed")
    client = await _redis()
    key = _pending_key(tenant_id, pending_id)
    raw = await client.get(key)
    if raw is None:
        raise PendingCertificateError("Generated certificate not found or expired (24 h); generate a new one.")
    if consume:
        await client.delete(key)
    return json.loads(raw)


# --------------------------------------------------------------- Graph rotation


class RotationError(Exception):
    """Rotation stopped before the stored credential was swapped."""


@dataclass
class RotationInput:
    entra_tenant_id: str
    client_id: str
    pem: str  # current key + certificate
    label: str
    application_object_id: str | None = None
    key_id: str | None = None  # Entra keyId of the current certificate, when known


@dataclass
class RotationOutcome:
    new: GeneratedCertificate
    new_key_id: str | None
    application_object_id: str
    old_key_id: str | None
    new_token: str


def _guard(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        raise RotationError(f"refusing outbound call to {host!r}")
    try:
        validate_outbound_url(url)
    except SSRFError as exc:
        raise RotationError(f"egress guard refused {host}: {exc}") from exc
    return url


def _err(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        body = None
    body = body if isinstance(body, dict) else {}
    error = body.get("error")
    msg = error.get("message") if isinstance(error, dict) else body.get("error_description")
    return f"HTTP {resp.status_code}" + (f": {str(msg)[:200]}" if msg else "")


async def app_token(http: httpx.AsyncClient, tenant: str, client_id: str, pem: str) -> str:
    """Client-credentials Graph token signed with ``pem``'s key."""
    url = _guard(f"{LOGIN}/{tenant}/oauth2/v2.0/token")
    cert = certificate_of(pem)
    if cert is None:
        raise RotationError("stored PEM has no CERTIFICATE block")
    resp = await http.post(
        url,
        data={
            "client_id": client_id,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": client_assertion(pem, thumbprint(cert), client_id, url),
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
    )
    try:
        access = resp.json().get("access_token") if resp.status_code == 200 else None
    except ValueError:
        access = None
    if not access:
        raise RotationError(f"token request failed: {_err(resp)}")
    return str(access)


def proof_token(pem: str, application_object_id: str) -> str:
    """PoP JWT for addKey/removeKey, signed by ``pem``'s key with its cert's x5t."""
    cert = certificate_of(pem)
    if cert is None:
        raise RotationError("stored PEM has no CERTIFICATE block")
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    now = int(time.time())
    claims = {"aud": POP_AUDIENCE, "iss": application_object_id, "nbf": now, "exp": now + 600}
    return jwt.encode(claims, key, algorithm="RS256", headers={"x5t": _b64url(cert.fingerprint(hashes.SHA1()))})  # noqa: S303


def _app_url(client_id: str, action: str = "") -> str:
    return _guard(f"{GRAPH}/applications(appId='{client_id}')" + (f"/{action}" if action else ""))


def _match_key_id(key_credentials: list[dict[str, Any]], thumb: str) -> str | None:
    for kc in key_credentials or []:
        ident = kc.get("customKeyIdentifier") or ""
        try:
            raw = base64.b64decode(ident)
        except ValueError:
            raw = b""
        candidates = {raw.hex().upper(), raw.decode("ascii", "ignore").upper(), str(ident).upper()}
        if thumb in candidates:
            return kc.get("keyId")
    return None


async def remove_key(http: httpx.AsyncClient, token: str, client_id: str, key_id: str, proof: str) -> None:
    resp = await http.post(
        _app_url(client_id, "removeKey"),
        headers={"Authorization": f"Bearer {token}"},
        json={"keyId": key_id, "proof": proof},
    )
    if resp.status_code not in (200, 204):
        raise RotationError(f"removeKey failed: {_err(resp)}")


async def add_new_key(
    http: httpx.AsyncClient,
    inp: RotationInput,
    *,
    verify_attempts: int = 6,
    verify_delay_s: float = 30.0,
    sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
) -> RotationOutcome:
    """addKey a fresh certificate and prove it authenticates. Never touches stored state.

    Raises :class:`RotationError` on any failure; the caller keeps the old
    certificate. A key added but never usable is removed again (best effort)
    so a daily retry does not pile keys up on the app registration.
    """
    if not valid_tenant(inp.entra_tenant_id):
        raise RotationError("no tenant-specific Entra tenant id to request a token from")
    if not is_guid(inp.client_id):
        raise RotationError("client_id is not an application (client) id GUID")
    current = certificate_of(inp.pem)
    if current is None:
        raise RotationError("stored PEM has no CERTIFICATE block")
    try:
        token = await app_token(http, inp.entra_tenant_id, inp.client_id, inp.pem)
        object_id, old_key_id = inp.application_object_id, inp.key_id
        if not object_id or not old_key_id:
            resp = await http.get(
                _app_url(inp.client_id),
                params={"$select": "id,keyCredentials"},
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code == 200:
                body = resp.json()
                object_id = object_id or body.get("id")
                old_key_id = old_key_id or _match_key_id(body.get("keyCredentials") or [], thumbprint(current))
            elif not object_id:
                raise RotationError(
                    f"cannot resolve the application object id ({_err(resp)}); enter the Application object ID "
                    "from the app's Overview page when generating the certificate, or grant Application.Read.All"
                )
        if not is_guid(object_id):
            raise RotationError("application object id is not a GUID")

        new = generate_certificate(current.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
        resp = await http.post(
            _app_url(inp.client_id, "addKey"),
            headers={"Authorization": f"Bearer {token}"},
            json={
                "keyCredential": {"type": "AsymmetricX509Cert", "usage": "Verify", "key": base64.b64encode(der(new.certificate)).decode()},
                "passwordCredential": None,
                "proof": proof_token(inp.pem, object_id),
            },
        )
        if resp.status_code not in (200, 201):
            raise RotationError(f"addKey failed: {_err(resp)}")
        try:
            new_key_id = resp.json().get("keyId")
        except ValueError:
            new_key_id = None
    except httpx.HTTPError as exc:
        raise RotationError(f"Microsoft endpoint unreachable: {type(exc).__name__}") from exc

    # Entra replication can lag behind addKey; retry a bounded number of times.
    last = ""
    for attempt in range(verify_attempts):
        if attempt:
            await sleep(verify_delay_s)
        try:
            new_token = await app_token(http, inp.entra_tenant_id, inp.client_id, new.pem)
            return RotationOutcome(new, new_key_id, object_id, old_key_id, new_token)
        except (RotationError, httpx.HTTPError) as exc:
            last = str(exc) or type(exc).__name__
    if new_key_id:
        try:
            await remove_key(http, token, inp.client_id, new_key_id, proof_token(inp.pem, object_id))
        except (RotationError, httpx.HTTPError):
            pass
    raise RotationError(f"new certificate never authenticated after addKey ({last})")


async def remove_old_key(http: httpx.AsyncClient, client_id: str, outcome: RotationOutcome) -> str | None:
    """removeKey the replaced certificate with a PoP signed by the NEW key. Returns a warning or None."""
    if not outcome.old_key_id:
        return "previous certificate's keyId is unknown (uploaded by hand); delete it under Certificates & secrets"
    try:
        await remove_key(
            http, outcome.new_token, client_id, outcome.old_key_id, proof_token(outcome.new.pem, outcome.application_object_id)
        )
    except (RotationError, httpx.HTTPError) as exc:
        return f"rotated, but removing the previous certificate failed ({str(exc) or type(exc).__name__}); delete it in the portal"
    return None
