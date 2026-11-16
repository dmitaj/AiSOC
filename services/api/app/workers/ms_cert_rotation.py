"""Daily rotation of AiSOC-generated Entra app certificates.

Covers both places a certificate lives: app-only Microsoft connector
instances (``CERT_CONNECTOR_TYPES``; ``auth_config.certificate_pem`` +
``connector_config.certificate_lifecycle``) and the hosted OAuth app
(``oauth_app_credentials.client_certificate_*``). Only rows marked managed —
the certificate was generated here — are rotated; a pasted certificate is
never touched beyond a log warning as it nears expiry (the UI shows its date).

A managed certificate within :data:`ROTATE_WITHIN` of expiry is rolled with
:func:`ms_cert_lifecycle.add_new_key` (addKey + proof the new key
authenticates), swapped into storage in one commit, then the old key is
removed with a PoP signed by the new key. Anything failing before the swap
keeps the old certificate, records ``last_error`` on the row (shown in the
UI), logs an ``ms_cert_rotation.alarm`` error, writes a failure audit entry,
and — like the OAuth refresh worker's alarm — flips a connector to
``unhealthy`` once less than :data:`ALARM_WITHIN` remains. The next daily
pass retries.

Started from ``app.main`` under the ``scheduler_lock`` lease (job
``ms_cert_rotation``) so one replica rotates at a time.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select

from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.models.connector import Connector
from app.models.oauth import OAuthAppCredential
from app.models.tenant import Tenant
from app.security.credential_vault import get_vault
from app.services.audit import emit_audit
from app.services.ms_cert_lifecycle import (
    CERT_CONNECTOR_TYPES,
    LIFECYCLE_KEY,
    ROTATE_WITHIN,
    RotationError,
    RotationInput,
    add_new_key,
    parse_ts,
    remove_old_key,
    tenant_from_token_url,
)

logger = logging.getLogger(__name__)

ALARM_WITHIN = timedelta(days=7)
Sleep = Callable[[float], Awaitable[Any]]


def _due(not_after: datetime | None, now: datetime) -> bool:
    return not_after is not None and not_after - now < ROTATE_WITHIN


async def _audit(db: Any, *, tenant_id: Any, action: str, resource: str, resource_id: str, changes: dict[str, Any]) -> None:
    await emit_audit(
        db=db,
        tenant_id=tenant_id,
        actor_email="system:ms_cert_rotation",
        action=action,
        resource=resource,
        resource_id=resource_id,
        changes=changes,
    )


def _alarm(kind: str, row_id: Any, reason: str) -> None:
    logger.error("ms_cert_rotation.alarm kind=%s id=%s reason=%s", kind, row_id, reason[:300].replace("\n", " "))


# --------------------------------------------------------------- connectors


async def _locked_connector(db: Any, conn: Connector) -> Connector | None:
    stmt = select(Connector).where(Connector.id == conn.id, Connector.tenant_id == conn.tenant_id).with_for_update()
    return (await db.execute(stmt)).scalar_one_or_none()


async def rotate_connector(db: Any, conn: Connector, *, http: httpx.AsyncClient, now: datetime, sleep: Sleep) -> str:
    """Returns one of ``skipped`` / ``expiring_unmanaged`` / ``rotated`` / ``failed``."""
    life = dict((conn.connector_config or {}).get(LIFECYCLE_KEY) or {})
    not_after = parse_ts(life.get("not_after"))
    if not _due(not_after, now):
        return "skipped"
    if not life.get("managed"):
        logger.warning("ms_cert_rotation.unmanaged_expiring connector_id=%s not_after=%s (rotate manually)", conn.id, not_after)
        return "expiring_unmanaged"

    vault = get_vault()
    auth = vault.decrypt_dict(conn.auth_config or {})
    merged = {**auth, **(conn.connector_config or {})}
    old_pem = str(auth.get("certificate_pem") or "")
    inp = RotationInput(
        entra_tenant_id=str(merged.get("tenant_id") or ""),
        client_id=str(merged.get("client_id") or ""),
        pem=old_pem,
        label=conn.name,
        application_object_id=life.get("application_object_id"),
        key_id=life.get("key_id"),
    )
    try:
        outcome = await add_new_key(http, inp, sleep=sleep)
    except Exception as exc:  # noqa: BLE001 - every failure is recorded the same way
        reason = str(exc) if isinstance(exc, RotationError) else f"unexpected {type(exc).__name__}"
        life.update(last_error=reason, last_attempt_at=now.isoformat())
        # Re-read under lock: the Graph calls took a while and the scheduler
        # may have advanced this row's checkpoint meanwhile.
        locked = await _locked_connector(db, conn) or conn
        locked.connector_config = {**(locked.connector_config or {}), LIFECYCLE_KEY: life}
        if not_after is not None and not_after - now < ALARM_WITHIN:
            locked.health_status = "unhealthy"
        await _audit(
            db,
            tenant_id=conn.tenant_id,
            action="connectors:certificate_rotation_failed",
            resource="connector",
            resource_id=str(conn.id),
            changes={"reason": reason},
        )
        await db.commit()
        _alarm("connector", conn.id, reason)
        return "failed"

    # Swap under a row lock, and only if nobody replaced the certificate while
    # Graph was being called.
    row = await _locked_connector(db, conn)
    current = vault.decrypt_dict(row.auth_config or {}) if row is not None else {}
    if row is None or current.get("certificate_pem") != old_pem:
        await db.rollback()
        logger.warning(
            "ms_cert_rotation.changed_underneath connector_id=%s; new Entra key %s left for the next pass", conn.id, outcome.new_key_id
        )
        return "skipped"
    current["certificate_pem"] = outcome.new.pem
    row.auth_config = vault.encrypt_dict(current)
    life.update(
        managed=True,
        not_after=outcome.new.not_after.isoformat(),
        thumbprint=outcome.new.thumbprint,
        key_id=outcome.new_key_id,
        application_object_id=outcome.application_object_id,
        rotated_at=now.isoformat(),
        last_attempt_at=now.isoformat(),
        last_error=None,
        last_warning=None,
    )
    row.connector_config = {**(row.connector_config or {}), LIFECYCLE_KEY: life}
    await _audit(
        db,
        tenant_id=row.tenant_id,
        action="connectors:certificate_rotate",
        resource="connector",
        resource_id=str(row.id),
        changes={
            "new_thumbprint": outcome.new.thumbprint,
            "not_after": outcome.new.not_after.isoformat(),
            "old_key_id": outcome.old_key_id,
        },
    )
    await db.commit()

    warning = await remove_old_key(http, inp.client_id, outcome)
    if warning:
        life["last_warning"] = warning
        row.connector_config = {**(row.connector_config or {}), LIFECYCLE_KEY: dict(life)}
        await db.commit()
        logger.warning("ms_cert_rotation.remove_old_key connector_id=%s %s", row.id, warning)
    logger.info("ms_cert_rotation.rotated connector_id=%s thumbprint=%s", row.id, outcome.new.thumbprint)
    return "rotated"


# --------------------------------------------------------------- OAuth apps


async def rotate_app(db: Any, app: OAuthAppCredential, *, http: httpx.AsyncClient, now: datetime, sleep: Sleep) -> str:
    not_after = parse_ts(app.client_certificate_not_after)
    if not app.client_certificate_vault or not _due(not_after, now):
        return "skipped"
    rid = f"{app.tenant_id}:{app.connector_type}"
    if not app.client_certificate_managed:
        logger.warning("ms_cert_rotation.unmanaged_expiring oauth_app=%s not_after=%s (rotate manually)", rid, not_after)
        return "expiring_unmanaged"

    vault = get_vault()
    old_vault = app.client_certificate_vault
    state = dict(app.client_certificate_rotation or {})
    inp = RotationInput(
        entra_tenant_id=tenant_from_token_url(app.token_url) or str(state.get("entra_tenant_id") or ""),
        client_id=app.client_id,
        pem=vault.decrypt(old_vault),
        label=app.connector_type,
        application_object_id=state.get("application_object_id"),
        key_id=state.get("key_id"),
    )
    try:
        outcome = await add_new_key(http, inp, sleep=sleep)
    except Exception as exc:  # noqa: BLE001
        reason = str(exc) if isinstance(exc, RotationError) else f"unexpected {type(exc).__name__}"
        state.update(last_error=reason, last_attempt_at=now.isoformat())
        app.client_certificate_rotation = state
        await _audit(
            db,
            tenant_id=app.tenant_id,
            action="connectors:certificate_rotation_failed",
            resource="oauth_app",
            resource_id=rid,
            changes={"reason": reason},
        )
        await db.commit()
        _alarm("oauth_app", rid, reason)
        return "failed"

    row = (
        await db.execute(
            select(OAuthAppCredential)
            .where(OAuthAppCredential.tenant_id == app.tenant_id, OAuthAppCredential.connector_type == app.connector_type)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None or row.client_certificate_vault != old_vault:
        await db.rollback()
        logger.warning("ms_cert_rotation.changed_underneath oauth_app=%s", rid)
        return "skipped"
    row.client_certificate_vault = vault.encrypt(outcome.new.pem)
    row.client_certificate_thumbprint = outcome.new.thumbprint
    row.client_certificate_not_after = outcome.new.not_after
    state.update(
        key_id=outcome.new_key_id,
        application_object_id=outcome.application_object_id,
        rotated_at=now.isoformat(),
        last_attempt_at=now.isoformat(),
        last_error=None,
        last_warning=None,
    )
    row.client_certificate_rotation = state
    await _audit(
        db,
        tenant_id=row.tenant_id,
        action="connectors:certificate_rotate",
        resource="oauth_app",
        resource_id=rid,
        changes={
            "new_thumbprint": outcome.new.thumbprint,
            "not_after": outcome.new.not_after.isoformat(),
            "old_key_id": outcome.old_key_id,
        },
    )
    await db.commit()

    warning = await remove_old_key(http, inp.client_id, outcome)
    if warning:
        row.client_certificate_rotation = {**state, "last_warning": warning}
        await db.commit()
        logger.warning("ms_cert_rotation.remove_old_key oauth_app=%s %s", rid, warning)
    return "rotated"


# --------------------------------------------------------------- loop


async def run_once(*, sleep: Sleep = asyncio.sleep) -> dict[str, int]:
    stats = {"skipped": 0, "expiring_unmanaged": 0, "rotated": 0, "failed": 0}
    now = datetime.now(UTC)
    async with AsyncSessionLocal() as db, httpx.AsyncClient(timeout=20.0) as http:
        # Tenant by tenant, so every read carries its tenant predicate.
        conns: list[Connector] = []
        apps: list[OAuthAppCredential] = []
        for tenant_id in (await db.execute(select(Tenant.id))).scalars().all():
            conns += (
                (
                    await db.execute(
                        select(Connector).where(Connector.tenant_id == tenant_id, Connector.connector_type.in_(CERT_CONNECTOR_TYPES))
                    )
                )
                .scalars()
                .all()
            )
            apps += (
                (
                    await db.execute(
                        select(OAuthAppCredential).where(
                            OAuthAppCredential.tenant_id == tenant_id, OAuthAppCredential.client_certificate_vault.is_not(None)
                        )
                    )
                )
                .scalars()
                .all()
            )
        for conn in conns:
            try:
                stats[await rotate_connector(db, conn, http=http, now=now, sleep=sleep)] += 1
            except Exception as exc:  # noqa: BLE001 - one bad row never stops the pass
                await db.rollback()
                logger.exception("ms_cert_rotation.row_failed connector_id=%s err=%s", conn.id, type(exc).__name__)
                stats["failed"] += 1
        for app in apps:
            try:
                stats[await rotate_app(db, app, http=http, now=now, sleep=sleep)] += 1
            except Exception as exc:  # noqa: BLE001
                await db.rollback()
                logger.exception("ms_cert_rotation.row_failed oauth_app=%s err=%s", app.connector_type, type(exc).__name__)
                stats["failed"] += 1
    return stats


async def run_forever() -> None:
    interval = max(60, settings.MS_CERT_ROTATION_INTERVAL_SECONDS)
    logger.info("ms_cert_rotation.started interval=%ds window=%sd", interval, ROTATE_WITHIN.days)
    while True:
        try:
            stats = await run_once()
            if stats["rotated"] or stats["failed"] or stats["expiring_unmanaged"]:
                logger.info("ms_cert_rotation.tick %s", stats)
        except Exception as exc:  # noqa: BLE001
            logger.exception("ms_cert_rotation.tick_failed err=%s", type(exc).__name__)
        await asyncio.sleep(interval)


__all__ = ["run_once", "run_forever", "rotate_connector", "rotate_app"]
