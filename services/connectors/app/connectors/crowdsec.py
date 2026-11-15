"""CrowdSec alerts and decisions, read from a Local API (LAPI).

Vendor reference: the CrowdSec LAPI OpenAPI spec
(`https://crowdsecurity.github.io/api_doc/lapi/`).

Two credentials, one of which is enough:

* **Machine login (preferred).** `POST /v1/watchers/login` with a
  `machine_id` and `password` returns a JWT; `GET /v1/alerts?since=...` then
  returns alerts with their decisions, source (IP, AS, country), scenario and
  the events that triggered them. Create one with
  `cscli machines add aisoc --password '...'`.
* **Bouncer API key (decisions only).** `GET /v1/decisions/stream` with
  `X-Api-Key` returns active decisions and no scenario context. The first
  poll asks for `startup=true` (every active decision); later polls on the
  same connector instance get only what is new. Create one with
  `cscli bouncers add aisoc`.

The window
----------
LAPI's `since` filters on the alert's `start_at`, the moment its bucket
started filling, not the moment it overflowed and was recorded. A slow
brute force can therefore start before a window it was raised inside, so the
request always looks back at least `_MIN_LOOKBACK_SECONDS` and the rows the
overlap re-reads are dropped by identity (`id`).

`GET /v1/alerts` has `limit` but no continuation, so a poll returns at most
`_LIMIT` alerts; the cap binding is logged.

Read-only
---------
Nothing here adds or deletes a decision.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

#: Alerts one poll may return. LAPI's own default is 100.
_LIMIT = 500

#: Lower bound on the lookback, because `since` filters on `start_at`.
_MIN_LOOKBACK_SECONDS = 3600

#: (substring of the scenario name, MITRE ATT&CK technique), first match wins.
_TECHNIQUES = (
    ("brute", "T1110"),
    ("-bf", "T1110"),
    ("stuffing", "T1110"),
    ("scan", "T1595"),
    ("probing", "T1595"),
    ("crawl", "T1595"),
    ("enum", "T1595"),
    ("sensitive-files", "T1595"),
)


class CrowdSecError(RuntimeError):
    """The LAPI refused a request, with a message written for the operator."""


class CrowdSecConnector(BaseConnector):
    connector_id = "crowdsec"
    connector_name = "CrowdSec"
    connector_category = "network"

    #: Alert ids are unique per LAPI; see "The window" above for why not a watermark.
    dedup_identity_field = ("id",)

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "CrowdSec alerts and decisions from a Local API (LAPI): the scenario that fired, the source "
                "IP with its AS and country, and the ban or captcha decision taken. Machine login for full "
                "alerts, or a bouncer API key for decisions only. Read-only."
            ),
            docs_url="/docs/connectors/crowdsec",
            fields=[
                Field(
                    "lapi_url",
                    "string",
                    "LAPI URL",
                    placeholder="http://crowdsec.example.com:8080",
                    help_text="Base URL of the CrowdSec Local API (default port 8080).",
                ),
                Field("machine_id", "string", "Machine ID", required=False, help_text="From `cscli machines add`. Needed for alerts."),
                Field("password", "secret", "Machine password", required=False),
                Field(
                    "api_key",
                    "secret",
                    "Bouncer API key",
                    required=False,
                    help_text="From `cscli bouncers add`. Used for decisions only, and only when no machine is configured.",
                ),
                Field("verify_tls", "boolean", "Verify TLS Certificate", required=False, default=True),
            ],
            capabilities=cls.capabilities(),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        lapi_url: str,
        machine_id: str = "",
        password: str = "",
        api_key: str = "",
        verify_tls: bool = True,
        transport: Any | None = None,
    ) -> None:
        self._base_url = (lapi_url or "").strip().rstrip("/")
        if not self._base_url.startswith(("http://", "https://")):
            raise ValueError("lapi_url must start with http:// or https://")
        self._machine_id = (machine_id or "").strip()
        self._password = password or ""
        self._api_key = (api_key or "").strip()
        if not ((self._machine_id and self._password) or self._api_key):
            raise ValueError("configure a machine_id and password (alerts), or an api_key (decisions only)")
        self._verify_tls = bool(verify_tls)
        self._transport = transport
        self._streaming = False

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=30.0, verify=self._verify_tls, transport=self._transport)

    @property
    def _alerts_mode(self) -> bool:
        return bool(self._machine_id and self._password)

    async def _login(self, client: httpx.AsyncClient) -> dict[str, str]:
        try:
            response = await client.post(
                f"{self._base_url}/v1/watchers/login",
                json={"machine_id": self._machine_id, "password": self._password},
            )
        except httpx.HTTPError as exc:
            raise CrowdSecError(f"CrowdSec LAPI could not be reached at {self._base_url}: {exc}") from exc
        token = _object(_json(response)).get("token")
        if response.status_code != 200 or not isinstance(token, str):
            raise CrowdSecError(
                f"CrowdSec answered HTTP {response.status_code} to POST /v1/watchers/login: {response.text[:300]}"
                " Check the machine id and password, and that the machine was validated (`cscli machines validate`)."
            )
        return {"Authorization": f"Bearer {token}"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with self._client() as client:
                if self._alerts_mode:
                    headers = await self._login(client)
                    response = await client.get(f"{self._base_url}/v1/alerts", params={"limit": 1}, headers=headers)
                    path = "/v1/alerts"
                else:
                    response = await client.get(f"{self._base_url}/v1/decisions", headers={"X-Api-Key": self._api_key})
                    path = "/v1/decisions"
            if response.status_code not in (200, 404):  # 404 is LAPI's "nothing to list"
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"CrowdSec answered HTTP {response.status_code} to GET {path}: {response.text[:300]}",
                }
            return {"success": True, "connector": self.connector_id, "mode": "alerts" if self._alerts_mode else "decisions"}
        except (CrowdSecError, httpx.HTTPError) as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        async with self._client() as client:
            if not self._alerts_mode:
                return await self._fetch_decisions(client)
            headers = await self._login(client)
            lookback = max(int(since_seconds), _MIN_LOOKBACK_SECONDS)
            try:
                response = await client.get(
                    f"{self._base_url}/v1/alerts", params={"since": f"{lookback}s", "limit": _LIMIT}, headers=headers
                )
            except httpx.HTTPError as exc:
                raise CrowdSecError(f"CrowdSec LAPI could not be reached at {self._base_url}: {exc}") from exc
        # LAPI answers 404 or a JSON null for an empty result, depending on version.
        if response.status_code == 404:
            return []
        if response.status_code != 200:
            raise CrowdSecError(f"CrowdSec answered HTTP {response.status_code} to GET /v1/alerts: {response.text[:300]}")
        body = _json(response)
        alerts = [a for a in body if isinstance(a, dict)] if isinstance(body, list) else []
        if len(alerts) >= _LIMIT:
            logger.warning(
                "crowdsec.alerts_capped", limit=_LIMIT, detail="LAPI has no continuation; older alerts in the window are not read"
            )
        return [self.normalize(a) for a in self.apply_checkpoint(alerts)]

    async def _fetch_decisions(self, client: httpx.AsyncClient) -> list[dict[str, Any]]:
        try:
            response = await client.get(
                f"{self._base_url}/v1/decisions/stream",
                params={"startup": "false" if self._streaming else "true"},
                headers={"X-Api-Key": self._api_key},
            )
        except httpx.HTTPError as exc:
            raise CrowdSecError(f"CrowdSec LAPI could not be reached at {self._base_url}: {exc}") from exc
        if response.status_code != 200:
            raise CrowdSecError(f"CrowdSec answered HTTP {response.status_code} to GET /v1/decisions/stream: {response.text[:300]}")
        self._streaming = True
        new = _object(_json(response)).get("new")
        return [self.normalize_decision(d) for d in new if isinstance(d, dict)] if isinstance(new, list) else []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Canonical envelope for an alert, with the vendor record under `raw_event`."""
        source = _object(raw.get("source"))
        decisions = [d for d in raw.get("decisions") or [] if isinstance(d, dict)]
        scenario = _text(raw.get("scenario"))
        ban = any(_text(d.get("type")).lower() == "ban" for d in decisions)
        event: dict[str, Any] = {
            "source": self.connector_id,
            "external_id": _text(raw.get("id")) or _text(raw.get("uuid")),
            "title": f"CrowdSec: {scenario}" if scenario else "CrowdSec alert",
            "description": _text(raw.get("message")),
            "created_at": _text(raw.get("created_at")) or _text(raw.get("start_at")),
            "rule_name": scenario,
            "severity": "low" if raw.get("simulated") else ("high" if ban else "medium"),
            "src_ip": _text(source.get("ip")) or (_text(source.get("value")) if _text(source.get("scope")).lower() == "ip" else ""),
            "source_scope": _text(source.get("scope")),
            "source_value": _text(source.get("value")),
            "country": _text(source.get("cn")),
            "asn": _text(source.get("as_number")),
            "as_name": _text(source.get("as_name")),
            "latitude": source.get("latitude"),
            "longitude": source.get("longitude"),
            "machine_id": _text(raw.get("machine_id")),
            "events_count": raw.get("events_count"),
            "action": ",".join(dict.fromkeys(_text(d.get("type")) for d in decisions if _text(d.get("type")))),
            "duration": _text(decisions[0].get("duration")) if decisions else "",
            "mitre_techniques": _techniques(scenario),
            "raw_event": raw,
        }
        event.update(_first_event_meta(raw.get("events")))
        return {key: value for key, value in event.items() if value not in (None, "", [])}

    def normalize_decision(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Canonical envelope for a bouncer-stream decision (no alert context)."""
        scenario = _text(raw.get("scenario"))
        scope = _text(raw.get("scope"))
        value = _text(raw.get("value"))
        decision_type = _text(raw.get("type"))
        identity = _text(raw.get("id")) or f"{scope}:{value}:{decision_type}"
        event: dict[str, Any] = {
            "source": self.connector_id,
            "external_id": f"decision-{identity}",
            "title": f"CrowdSec {decision_type or 'decision'}: {value}" + (f" ({scenario})" if scenario else ""),
            "rule_name": scenario,
            "severity": "high" if decision_type.lower() == "ban" else "medium",
            "src_ip": value if scope.lower() == "ip" else "",
            "source_scope": scope,
            "source_value": value,
            "action": decision_type,
            "duration": _text(raw.get("duration")),
            "origin": _text(raw.get("origin")),
            "mitre_techniques": _techniques(scenario),
            "raw_event": raw,
        }
        return {key: val for key, val in event.items() if val not in (None, "", [])}


def _first_event_meta(events: Any) -> dict[str, Any]:
    """The reverse-proxy fields of the alert's first event (`target_fqdn`, `http_path`, ...), when present."""
    if not isinstance(events, list) or not events or not isinstance(events[0], dict):
        return {}
    meta = {m.get("key"): m.get("value") for m in events[0].get("meta") or [] if isinstance(m, dict)}
    out = {"target_host": meta.get("target_fqdn"), "http_path": meta.get("http_path"), "http_status": meta.get("http_status")}
    return {k: v for k, v in out.items() if v}


def _techniques(scenario: str) -> list[str]:
    name = scenario.lower()
    return [technique for needle, technique in _TECHNIQUES if needle in name][:1]


def _json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ("" if value is None else str(value))
