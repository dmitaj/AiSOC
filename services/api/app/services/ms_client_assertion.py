"""Entra app-certificate client authentication for the hosted OAuth flow.

Microsoft identity platform accepts an RS256 ``client_assertion`` (RFC 7523)
signed with the app certificate's private key in place of ``client_secret``.
The api service cannot import ``services/connectors`` (where the app-only
connectors do the same thing in ``ms_cert_auth.py``), so this is the api-side
twin, built on the already-installed PyJWT + ``cryptography``.
"""

from __future__ import annotations

import base64
import time
import uuid
from urllib.parse import urlparse

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.models.oauth import OAuthAppCredential
from app.security.credential_vault import CredentialVault

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
MICROSOFT_TOKEN_HOSTS = frozenset({"login.microsoftonline.com", "login.microsoft.com"})
_CERT_BEGIN = "-----BEGIN CERTIFICATE-----"


def is_microsoft_token_url(url: str | None) -> bool:
    return (urlparse(url or "").hostname or "").lower() in MICROSOFT_TOKEN_HOSTS


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _cert(pem: str) -> x509.Certificate | None:
    return x509.load_pem_x509_certificate(pem[pem.index(_CERT_BEGIN) :].encode()) if _CERT_BEGIN in pem else None


def normalize_certificate(pem: str, thumbprint: str = "", password: str = "") -> tuple[str, str]:
    """Validate an uploaded PEM; return ``(storable_pem, hex_sha1_thumbprint)``.

    The storable PEM is the RSA key re-serialised *unencrypted* (it is
    vault-encrypted at rest, so the password never needs storing) followed by
    the certificate block when one was supplied. Raises ``ValueError`` with an
    operator-facing message on any bad input.
    """
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=password.encode() if password else None)
    except Exception as exc:
        raise ValueError(
            f"certificate_pem must contain the app's PRIVATE KEY in PEM form (plus private_key_password if it is encrypted): {exc}"
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("certificate_pem private key must be RSA (Entra certificate credentials use RS256).")
    try:
        cert = _cert(pem)
    except Exception as exc:
        raise ValueError(f"certificate_pem contains an unreadable CERTIFICATE block: {exc}") from exc
    if cert is not None:
        thumb = cert.fingerprint(hashes.SHA1()).hex().upper()  # noqa: S303 - Entra identifies certs by SHA-1 (x5t)
    else:
        thumb = thumbprint.replace(":", "").replace(" ", "").strip().upper()
        if not thumb:
            raise ValueError(
                "certificate_thumbprint is required when certificate_pem has no CERTIFICATE block "
                "(copy it from Entra portal > App registrations > Certificates & secrets)."
            )
        if len(thumb) != 40 or any(c not in "0123456789ABCDEF" for c in thumb):
            raise ValueError("certificate_thumbprint must be a 40-character hex SHA-1 thumbprint.")
    stored = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    if cert is not None:
        stored += cert.public_bytes(serialization.Encoding.PEM).decode()
    return stored, thumb


def client_assertion(pem: str, thumbprint_hex: str, client_id: str, audience: str) -> str:
    """Sign the RS256 client assertion for ``audience`` (the token URL)."""
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    headers = {"x5t": _b64url(bytes.fromhex(thumbprint_hex))}
    cert = _cert(pem)
    if cert is not None:
        headers["x5t#S256"] = _b64url(cert.fingerprint(hashes.SHA256()))
    now = int(time.time())
    claims = {
        "aud": audience,
        "iss": client_id,
        "sub": client_id,
        "jti": str(uuid.uuid4()),
        "nbf": now,
        "iat": now,
        "exp": now + 600,
    }
    return jwt.encode(claims, key, algorithm="RS256", headers={"typ": "JWT", **headers})


def token_client_auth(vault: CredentialVault, app_credential: OAuthAppCredential, token_url: str) -> dict[str, str]:
    """Client-authentication part of a token-endpoint form for ``app_credential``.

    Decrypts whichever credential is stored; the certificate wins when both
    are. A certificate is refused for a non-Microsoft token host so a tampered
    ``token_url`` never receives an assertion meant for Entra. Raises
    :class:`CredentialVaultError` (decrypt) or ``ValueError`` (unusable row).
    """
    client_id = app_credential.client_id
    if app_credential.client_certificate_vault:
        if not is_microsoft_token_url(token_url):
            raise ValueError("certificate credentials are only supported for the Microsoft identity platform token endpoint")
        pem = vault.decrypt(app_credential.client_certificate_vault)
        return {
            "client_id": client_id,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": client_assertion(pem, app_credential.client_certificate_thumbprint or "", client_id, token_url),
        }
    if not app_credential.client_secret_vault:
        raise ValueError("OAuth app has neither a client secret nor a certificate")
    return {"client_id": client_id, "client_secret": vault.decrypt(app_credential.client_secret_vault)}
