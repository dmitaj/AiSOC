"""An unavailable risk engine is not an empty queue, zero count, or absent host."""

import uuid

import httpx
import pytest
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import fusion
from fastapi import FastAPI

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000111")


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["queue", "stats", "host/WS-42"])
@pytest.mark.parametrize("mode", ["unconfigured", "timeout", "upstream_error"])
async def test_unavailable_is_503(monkeypatch, path, mode):
    app = FastAPI()
    app.include_router(fusion.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(uuid.uuid4(), TENANT, "analyst", "analyst@example.test")
    monkeypatch.setattr(fusion, "_FUSION_URL", "" if mode == "unconfigured" else "http://fusion.test")
    real = httpx.AsyncClient

    async def handler(req):
        if mode == "timeout":
            raise httpx.ReadTimeout("unavailable")
        return httpx.Response(503)

    class Client(real):
        def __init__(self, *a, **kw):
            kw.setdefault("transport", httpx.MockTransport(handler))
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    async with real(transport=httpx.ASGITransport(app), base_url="http://api.test") as client:
        result = await client.get("/api/v1/fusion/entity-risk/" + path)
    assert result.status_code == 503, result.text


@pytest.mark.asyncio
@pytest.mark.parametrize("status, body", [(200, {"entities": []}), (404, {"detail": "entity_not_found"})])
async def test_real_empty_and_real_absence_are_preserved(monkeypatch, status, body):
    monkeypatch.setattr(fusion, "_FUSION_URL", "http://fusion.test")
    real = httpx.AsyncClient

    async def handler(req):
        return httpx.Response(status, json=body)

    class Client(real):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    from fastapi import HTTPException

    if status == 404:
        with pytest.raises(HTTPException) as exc:
            await fusion._proxy_get("/entity-risk/host/WS-42")
        assert exc.value.status_code == 404
    else:
        assert await fusion._proxy_get("/entity-risk/queue") == body


# Shapes copied from a live fusion (EntityRiskRecord.to_dict / EntityRiskEngine.stats).
_FUSION_QUEUE = {
    "tenant_id": str(TENANT),
    "threshold": 80.0,
    "entities": [
        {
            "tenant_id": str(TENANT),
            "entity_type": "src_ip",
            "entity_value": "203.0.113.9",
            "score": 229.26,
            "alert_count": 14,
            "last_seen": "2026-11-15T20:25:14.488651Z",
            "contributing_alerts": ["a1"],
            "severities": {"high": 10, "medium": 4},
            "promoted_at": "2026-11-15T20:20:15.543868Z",
            "contributors": [
                {"alert_id": "a1", "severity": "high", "detection": "CrowdSec: x", "points": 20.0, "at": "2026-11-15T20:17:40+00:00Z"}
            ],
        }
    ],
}
_FUSION_STATS = {
    "tenant_id": str(TENANT),
    "tracked_entities": 5,
    "promoted_entities": 1,
    "score_bands": {"critical": 1, "high": 1, "medium": 3, "low": 0},
    "threshold": 80.0,
}


@pytest.mark.asyncio
async def test_fusion_payload_is_served_in_the_console_shape(monkeypatch):
    app = FastAPI()
    app.include_router(fusion.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(uuid.uuid4(), TENANT, "analyst", "analyst@example.test")
    monkeypatch.setattr(fusion, "_FUSION_URL", "http://fusion.test")
    real = httpx.AsyncClient

    async def handler(req):
        return httpx.Response(200, json=_FUSION_STATS if req.url.path.endswith("/stats") else _FUSION_QUEUE)

    class Client(real):
        def __init__(self, *a, **kw):
            kw.setdefault("transport", httpx.MockTransport(handler))
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    async with real(transport=httpx.ASGITransport(app), base_url="http://api.test") as client:
        queue = (await client.get("/api/v1/fusion/entity-risk/queue")).json()
        stats = (await client.get("/api/v1/fusion/entity-risk/stats")).json()

    [e] = queue["entities"]
    assert e["entity_type"] == "ip"
    assert e["severity_histogram"] == {"critical": 0, "high": 10, "medium": 4, "low": 0, "info": 0}
    assert (e["promoted"], e["display_score"], e["threshold"]) == (True, 229, 80.0)
    assert e["contributions"] == [
        {"alert_id": "a1", "severity": "high", "raw_points": 20.0, "observed_at": "2026-11-15T20:17:40+00:00", "title": "CrowdSec: x"}
    ]
    assert e["first_seen"] == "2026-11-15T20:17:40+00:00"
    assert (stats["total"], stats["promoted"], stats["bands"]) == (5, 1, _FUSION_STATS["score_bands"])
