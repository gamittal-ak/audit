"""
Async Akamai API client.
All methods gate on a shared asyncio.Semaphore to avoid rate-limit errors.
"""
import asyncio
import logging
import math
import ssl
import socket
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

from app.services.edgegrid_auth import EdgeGridAuth

logger = logging.getLogger(__name__)

_PAPI_HEADERS = {
    "Content-type": "application/json",
    "PAPI-Use-Prefixes": "false",
}
_REPORT_HEADERS = {"Content-type": "application/json"}

_reporting_forbidden: set = set()


class AkamaiClient:
    def __init__(
        self,
        base_url: str,
        auth: EdgeGridAuth,
        sem: asyncio.Semaphore,
        timeout: float = 60.0,
    ):
        self.base_url = base_url
        self.auth = auth
        self.sem = sem
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            auth=self.auth,
            timeout=self.timeout,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    # ------------------------------------------------------------------ helpers

    def _url(self, path: str) -> str:
        return urljoin(self.base_url, path)

    async def _get(self, path: str, params: dict = None) -> dict:
        async with self.sem:
            resp = await self._client.get(
                self._url(path), params=params, headers=_PAPI_HEADERS
            )
            resp.raise_for_status()
            return resp.json()

    async def _post(self, path: str, params: dict = None, json_body: dict = None) -> httpx.Response:
        async with self.sem:
            return await self._client.post(
                self._url(path),
                params=params,
                json=json_body,
                headers=_REPORT_HEADERS,
                timeout=60.0,
            )

    # ------------------------------------------------------------------ PAPI

    async def get_groups(self, switch_key: str) -> dict:
        return await self._get("/papi/v1/groups", {"accountSwitchKey": switch_key})

    async def get_properties(
        self, switch_key: str, contract_id: str, group_id: str
    ) -> dict:
        return await self._get(
            "/papi/v1/properties",
            {
                "accountSwitchKey": switch_key,
                "contractId": contract_id,
                "groupId": group_id,
            },
        )

    async def get_hostnames(
        self,
        switch_key: str,
        contract_id: str,
        group_id: str,
        property_id: str,
        version: str,
    ) -> dict:
        return await self._get(
            f"/papi/v1/properties/{property_id}/versions/{version}/hostnames",
            {
                "accountSwitchKey": switch_key,
                "contractId": contract_id,
                "groupId": group_id,
                "validateHostnames": "true",
                "includeCertStatus": "true",
            },
        )

    async def get_rule_tree(
        self,
        switch_key: str,
        contract_id: str,
        group_id: str,
        property_id: str,
        version: str,
    ) -> dict:
        return await self._get(
            f"/papi/v1/properties/{property_id}/versions/{version}/rules",
            {
                "accountSwitchKey": switch_key,
                "contractId": contract_id,
                "groupId": group_id,
            },
        )

    # ------------------------------------------------------------------ Identity Management

    async def search_accounts(self, query: str) -> List[Dict[str, str]]:
        resp = await self._get(
            "/identity-management/v3/api-clients/self/account-switch-keys",
            {"search": query},
        )
        return resp if isinstance(resp, list) else []

    # ------------------------------------------------------------------ Reporting

    async def get_traffic(self, switch_key: str, cpcodes: List[str]) -> dict:
        if switch_key in _reporting_forbidden:
            return {"data": []}

        now = datetime.now(timezone.utc)
        end = _utc_midnight(now)
        start = _utc_midnight(now - timedelta(days=15))

        # Flatten / coerce cp codes to list of strings
        flat: List[str] = []
        for c in cpcodes:
            if isinstance(c, (list, tuple)):
                flat.extend(str(x).strip() for x in c if x is not None)
            elif c is not None:
                flat.append(str(c).strip())
        cpcodes = [c for c in flat if c]
        if not cpcodes:
            return {"data": []}

        body = {
            "dimensions": ["cpcode"],
            "metrics": [
                "offloadedBytesPercentage",
                "edgeBytesSum",
                "midgressBytesSum",
                "originBytesSum",
            ],
            "filters": [
                {
                    "dimensionName": "cpcode",
                    "operator": "IN_LIST",
                    "expressions": cpcodes,
                }
            ],
        }

        resp = await self._post(
            "/reporting-api/v2/reports/delivery/traffic/current/data",
            params={"accountSwitchKey": switch_key, "start": start, "end": end},
            json_body=body,
        )

        if resp.status_code == 403:
            _reporting_forbidden.add(switch_key)
            logger.warning(
                "Reporting API 403 for %s — traffic will be skipped for this account",
                switch_key,
            )
            return {"data": []}

        if resp.status_code != 200:
            logger.warning(
                "Reporting API returned %s for %s: %s",
                resp.status_code, switch_key, resp.text[:500],
            )

        resp.raise_for_status()
        data = resp.json()
        logger.info(
            "Reporting API returned %d rows for %d cpcodes (switch_key=%s)",
            len(data.get("data", [])), len(cpcodes), switch_key,
        )
        return data


# ------------------------------------------------------------------ utilities

def _utc_midnight(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.replace(hour=0, minute=0, second=0, microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def parse_traffic_metrics(traffic_data: dict) -> List[float]:
    """Extract [offload%, edgeGB, midgressGB, originGB] from a reporting API response."""
    if traffic_data and traffic_data.get("data"):
        row = traffic_data["data"][0]
        metrics = row.get("metrics", {})
        return [
            round(float(metrics.get("offloadedBytesPercentage", 0.0)), 2),
            round(float(metrics.get("edgeBytesSum", 0.0)) / math.pow(1000, 3), 2),
            round(float(metrics.get("midgressBytesSum", 0.0)) / math.pow(1000, 3), 2),
            round(float(metrics.get("originBytesSum", 0.0)) / math.pow(1000, 3), 2),
        ]
    return [0.0, 0.0, 0.0, 0.0]


def get_cert_details_sync(hostname: str, port: int = 443) -> Optional[dict]:
    """Synchronous TLS certificate inspection — run via asyncio.to_thread."""
    context = ssl.create_default_context()
    try:
        with context.wrap_socket(
            socket.socket(socket.AF_INET), server_hostname=hostname
        ) as s:
            s.connect((hostname, port))
            cert = s.getpeercert()

        subject = dict(x[0] for x in cert["subject"])
        issuer = dict(x[0] for x in cert["issuer"])
        return {
            "commonName": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", ""),
            "expiration": cert["notAfter"],
            "serialNumber": cert["serialNumber"],
            "version": cert["version"],
        }
    except Exception:
        return None
