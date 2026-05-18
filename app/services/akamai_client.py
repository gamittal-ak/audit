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

    async def get_activations(
        self,
        switch_key: str,
        contract_id: str,
        group_id: str,
        property_id: str,
    ) -> dict:
        return await self._get(
            f"/papi/v1/properties/{property_id}/activations",
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

    async def get_traffic(self, switch_key: str, cpcodes: List[str], days: int = 15, _max_retries: int = 5) -> dict:
        """Fetch traffic data for a list of cpcodes. Returns dict with 'data', 'status'."""
        if switch_key in _reporting_forbidden:
            return {"data": [], "status": "forbidden"}

        now = datetime.now(timezone.utc)
        end = _utc_midnight(now)
        start = _utc_midnight(now - timedelta(days=days))

        # Flatten / coerce cp codes to list of integers (API requires ints)
        flat: List[int] = []
        for c in cpcodes:
            if isinstance(c, (list, tuple)):
                for x in c:
                    if x is not None:
                        try:
                            flat.append(int(x))
                        except (ValueError, TypeError):
                            pass
            elif c is not None:
                try:
                    flat.append(int(c))
                except (ValueError, TypeError):
                    pass
        cpcodes = list(set(flat))
        if not cpcodes:
            return {"data": [], "status": "no_cpcodes"}

        body = {
            "dimensions": ["cpcode"],
            "metrics": [
                "offloadedBytesPercentage",
                "edgeBytesSum",
                "midgressBytesSum",
                "originBytesSum",
                "offloadedHitsPercentage",
            ],
            "filters": [
                {
                    "dimensionName": "cpcode",
                    "operator": "IN_LIST",
                    "expressions": cpcodes,
                }
            ],
        }

        import re as _re

        for attempt in range(1, _max_retries + 1):
            resp = await self._post(
                "/reporting-api/v2/reports/delivery/traffic/current/data",
                params={"accountSwitchKey": switch_key, "start": start, "end": end},
                json_body=body,
            )

            if resp.status_code == 403:
                # Check if specific cpcodes are unauthorized (not the whole account)
                resp_text = resp.text[:2000]
                if "unauthorized-objects" in resp_text or "unauthorized objects" in resp_text.lower():
                    # Extract unauthorized cpcode IDs from error detail
                    bad_ids: set = set()
                    for m in _re.findall(r'\b(\d{4,})\b', resp_text.split("unauthorized")[-1]):
                        try:
                            bad_ids.add(int(m))
                        except ValueError:
                            pass
                    if bad_ids:
                        remaining = [c for c in cpcodes if c not in bad_ids]
                        logger.warning(
                            "Reporting API 403: %d unauthorized cpcodes removed (%s) for switch_key=%s — retrying with %d remaining",
                            len(bad_ids), bad_ids, switch_key, len(remaining),
                        )
                        if remaining:
                            cpcodes = remaining
                            body["filters"][0]["expressions"] = cpcodes
                            continue  # retry without the bad cpcodes
                # Entire account is forbidden
                _reporting_forbidden.add(switch_key)
                logger.warning(
                    "Reporting API 403 for switch_key=%s — traffic will be skipped for this account. Response: %s",
                    switch_key,
                    resp_text,
                )
                return {"data": [], "status": "forbidden"}

            if resp.status_code == 429:
                if attempt < _max_retries:
                    wait = (2 ** attempt) + (attempt * 0.5)  # 2.5s, 4.5s, 8.5s, 16.5s
                    logger.warning(
                        "Reporting API 429 rate limit for switch_key=%s (attempt %d/%d) — retrying in %.1fs",
                        switch_key, attempt, _max_retries, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                logger.warning(
                    "Reporting API 429 rate limit for switch_key=%s — exhausted %d retries, skipping.",
                    switch_key, _max_retries,
                )
                return {"data": [], "status": "rate_limited"}

            if resp.status_code in (500, 502, 503, 504):
                if attempt < _max_retries:
                    wait = 2 ** attempt
                    logger.warning(
                        "Reporting API %s for switch_key=%s (attempt %d/%d) — retrying in %ds",
                        resp.status_code, switch_key, attempt, _max_retries, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                logger.warning(
                    "Reporting API %s for switch_key=%s — exhausted %d retries. Response: %s",
                    resp.status_code, switch_key, _max_retries, resp.text[:500],
                )
                return {"data": [], "status": "api_error"}

            if resp.status_code != 200:
                logger.warning(
                    "Reporting API returned %s for %s: %s",
                    resp.status_code, switch_key, resp.text[:500],
                )
                return {"data": [], "status": "api_error"}

            # Success
            data = resp.json()
            logger.info(
                "Reporting API returned %d rows for %d cpcodes (switch_key=%s)",
                len(data.get("data", [])), len(cpcodes), switch_key,
            )
            data["status"] = "ok"
            return data

        return {"data": [], "status": "api_error"}


# ------------------------------------------------------------------ utilities

def _utc_midnight(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.replace(hour=0, minute=0, second=0, microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )




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
