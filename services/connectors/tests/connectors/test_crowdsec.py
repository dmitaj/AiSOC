"""CrowdSec LAPI alerts and decisions.

Paths, parameters and field names are the ones the LAPI OpenAPI spec lists.
The payloads are synthetic; addresses are RFC 5737 documentation ranges.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
from app.connectors import _CONNECTOR_CLASSES
from app.connectors.crowdsec import _LIMIT, _MIN_LOOKBACK_SECONDS, CrowdSecConnector, CrowdSecError

_ALERT: dict[str, Any] = {
    "id": 42,
    "machine_id": "aisoc",
    "created_at": "2026-11-15T10:00:00Z",
    "scenario": "crowdsecurity/http-bf-wordpress_bf",
    "message": "Ip 203.0.113.9 performed 'crowdsecurity/http-bf-wordpress_bf' (6 events over 4s)",
    "events_count": 6,
    "simulated": False,
    "source": {"scope": "Ip", "value": "203.0.113.9", "ip": "203.0.113.9", "cn": "NL", "as_number": "14061", "as_name": "DIGITALOCEAN-ASN"},
    "events": [
        {
            "timestamp": "2026-11-15T09:59:56Z",
            "meta": [{"key": "target_fqdn", "value": "app.example.com"}, {"key": "http_path", "value": "/wp-login.php"}],
        }
    ],
    "decisions": [{"id": 7, "type": "ban", "scope": "Ip", "value": "203.0.113.9", "duration": "3h59m", "origin": "crowdsec"}],
}


def _lapi(alerts: Callable[[httpx.Request], httpx.Response] | None = None, stream: Callable[[httpx.Request], httpx.Response] | None = None):
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if path == "/v1/watchers/login":
            ok = b'"pw"' in request.content
            return httpx.Response(200, json={"code": 200, "token": "jwt-1"}) if ok else httpx.Response(401, json={"message": "bad"})
        if path == "/v1/alerts":
            if request.headers.get("authorization") != "Bearer jwt-1":
                return httpx.Response(401, json={"message": "no token"})
            return (alerts or (lambda r: httpx.Response(200, json=[_ALERT])))(request)
        if path == "/v1/decisions/stream":
            return (stream or (lambda r: httpx.Response(200, json={"new": [], "deleted": []})))(request)
        return httpx.Response(404)

    return requests, httpx.MockTransport(handle)


def _machine(transport: httpx.MockTransport, password: str = "pw") -> CrowdSecConnector:
    return CrowdSecConnector("http://lapi:8080/", machine_id="aisoc", password=password, transport=transport)


def test_registered_with_one_secret_pair() -> None:
    assert "crowdsec" in {c.connector_id for c in _CONNECTOR_CLASSES}
    schema = CrowdSecConnector.schema().to_dict()
    assert schema["docs_url"] == "/docs/connectors/crowdsec"
    assert {f["name"] for f in schema["fields"] if f["type"] == "secret"} == {"password", "api_key"}


@pytest.mark.parametrize(
    "kwargs", [{"lapi_url": "lapi:8080", "api_key": "k"}, {"lapi_url": "http://lapi"}, {"lapi_url": "http://lapi", "machine_id": "m"}]
)
def test_bad_config_is_refused(kwargs: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        CrowdSecConnector(**kwargs)


@pytest.mark.asyncio
async def test_alert_is_normalized() -> None:
    requests, transport = _lapi()
    [event] = await _machine(transport).fetch_alerts(300)

    assert event["external_id"] == "42"
    assert event["title"] == "CrowdSec: crowdsecurity/http-bf-wordpress_bf"
    assert event["severity"] == "high"  # a ban decision
    assert event["src_ip"] == "203.0.113.9"
    assert (event["country"], event["asn"], event["as_name"]) == ("NL", "14061", "DIGITALOCEAN-ASN")
    assert (event["action"], event["duration"]) == ("ban", "3h59m")
    assert event["mitre_techniques"] == ["T1110"]
    assert (event["target_host"], event["http_path"]) == ("app.example.com", "/wp-login.php")
    assert event["raw_event"]["id"] == 42
    # `since` filters on start_at, so the request looks back at least an hour.
    assert requests[-1].url.params["since"] == f"{_MIN_LOOKBACK_SECONDS}s"
    assert requests[-1].url.params["limit"] == str(_LIMIT)


def test_severity_and_technique_without_a_ban() -> None:
    c = CrowdSecConnector("http://lapi", api_key="k")
    medium = c.normalize({**_ALERT, "decisions": [{"type": "captcha"}], "scenario": "crowdsecurity/http-crawl-non_statics"})
    assert (medium["severity"], medium["mitre_techniques"]) == ("medium", ["T1595"])
    assert c.normalize({**_ALERT, "simulated": True})["severity"] == "low"
    other = c.normalize({**_ALERT, "decisions": None, "scenario": "crowdsecurity/ssh-slow-bf"})
    assert "action" not in other
    assert "mitre_techniques" not in c.normalize({**_ALERT, "scenario": "crowdsecurity/CVE-2022-26134"})


@pytest.mark.asyncio
async def test_an_overlap_is_raised_once() -> None:
    _, transport = _lapi()
    c = _machine(transport)
    assert len(await c.fetch_alerts(300)) == 1
    c.set_checkpoint(c.get_checkpoint())
    assert await c.fetch_alerts(300) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("empty", [httpx.Response(404, json={"message": "nothing"}), httpx.Response(200, content=b"null")])
async def test_an_empty_window_is_not_an_error(empty: httpx.Response) -> None:
    _, transport = _lapi(alerts=lambda r: empty)
    assert await _machine(transport).fetch_alerts(300) == []


@pytest.mark.asyncio
async def test_a_refusal_raises_rather_than_reading_as_quiet() -> None:
    _, transport = _lapi(alerts=lambda r: httpx.Response(500, text="boom"))
    with pytest.raises(CrowdSecError, match="500"):
        await _machine(transport).fetch_alerts(300)


@pytest.mark.asyncio
async def test_connection_check_reports_bad_credentials() -> None:
    _, transport = _lapi()
    bad = await _machine(transport, password="wrong").test_connection()
    assert bad["success"] is False and "401" in bad["error"]
    assert (await _machine(transport).test_connection())["success"] is True


@pytest.mark.asyncio
async def test_bouncer_key_streams_decisions_then_only_the_delta() -> None:
    decision = {
        "id": 9,
        "type": "ban",
        "scope": "Ip",
        "value": "198.51.100.4",
        "duration": "4h",
        "origin": "crowdsec",
        "scenario": "crowdsecurity/http-probing",
    }
    seen: list[httpx.Request] = []

    def stream(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.headers["x-api-key"] == "k"
        return httpx.Response(200, json={"new": [decision], "deleted": None})

    _, transport = _lapi(stream=stream)
    c = CrowdSecConnector("http://lapi", api_key="k", transport=transport)
    [event] = await c.fetch_alerts(300)
    await c.fetch_alerts(300)

    assert [r.url.params["startup"] for r in seen] == ["true", "false"]
    assert (event["external_id"], event["src_ip"], event["severity"], event["mitre_techniques"]) == (
        "decision-9",
        "198.51.100.4",
        "high",
        ["T1595"],
    )
