"""
Async Akamai API client.
All methods gate on a shared asyncio.Semaphore to avoid rate-limit errors.
"""
import asyncio
import logging
import math
import ssl
import re
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

    async def get_traffic(
        self,
        switch_key: str,
        cpcodes: List[str],
        days: int = 15,
        _max_retries: int = 5,
        chunk_size: int = 100,
        chunk_delay_seconds: float = 0.25,
    ) -> dict:
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
        cpcodes = sorted(set(flat))
        if not cpcodes:
            return {"data": [], "status": "no_cpcodes"}

        try:
            chunk_size = int(chunk_size)
        except (TypeError, ValueError):
            chunk_size = len(cpcodes)
        if chunk_size <= 0:
            chunk_size = len(cpcodes)

        chunks = [cpcodes[i:i + chunk_size] for i in range(0, len(cpcodes), chunk_size)]
        if len(chunks) > 1:
            logger.info(
                "Reporting API traffic fetch split into %d chunks (%d cpcodes, chunk_size=%d)",
                len(chunks), len(cpcodes), chunk_size,
            )

        data_rows: List[dict] = []
        cpcode_statuses: Dict[str, str] = {}
        failed_statuses: List[str] = []

        for idx, chunk in enumerate(chunks, start=1):
            if idx > 1 and chunk_delay_seconds > 0:
                await asyncio.sleep(chunk_delay_seconds)

            chunk_resp = await self._get_traffic_chunk(
                switch_key, chunk, start, end, _max_retries
            )
            status = chunk_resp.get("status", "api_error")
            rows = chunk_resp.get("data", [])
            data_rows.extend(rows)

            for cpc in chunk_resp.get("unauthorized_cpcodes", []):
                cpcode_statuses[str(cpc)] = "forbidden"

            if status not in ("ok", "no_cpcodes"):
                failed_statuses.append(status)
                for cpc in chunk_resp.get("failed_cpcodes", chunk):
                    cpcode_statuses.setdefault(str(cpc), status)

            if len(chunks) > 1:
                logger.info(
                    "Reporting API traffic chunk %d/%d: status=%s, %d rows for %d cpcodes",
                    idx, len(chunks), status, len(rows), len(chunk),
                )

        if failed_statuses:
            if data_rows or len(cpcode_statuses) < len(cpcodes):
                overall_status = "partial"
            elif all(s == failed_statuses[0] for s in failed_statuses):
                overall_status = failed_statuses[0]
            else:
                overall_status = "api_error"
        else:
            overall_status = "ok"

        logger.info(
            "Reporting API traffic complete: status=%s, %d rows for %d cpcodes (%d cpcodes marked)",
            overall_status, len(data_rows), len(cpcodes), len(cpcode_statuses),
        )
        result = {"data": data_rows, "status": overall_status}
        if cpcode_statuses:
            result["cpcode_statuses"] = cpcode_statuses
        return result

    async def _get_traffic_chunk(
        self,
        switch_key: str,
        cpcodes: List[int],
        start: str,
        end: str,
        max_retries: int,
    ) -> dict:
        pending = list(cpcodes)
        unauthorized: set = set()

        attempt = 1
        while attempt <= max_retries:
            resp = await self._post(
                "/reporting-api/v2/reports/delivery/traffic/current/data",
                params={"accountSwitchKey": switch_key, "start": start, "end": end},
                json_body=_traffic_body(pending),
            )

            if resp.status_code == 403:
                resp_text = resp.text[:2000]
                bad_ids = _extract_unauthorized_cpcodes(resp)
                if bad_ids is not None:
                    bad_ids = {c for c in bad_ids if c in pending}
                    if bad_ids:
                        unauthorized.update(bad_ids)
                        pending = [c for c in pending if c not in bad_ids]
                        logger.warning(
                            "Reporting API 403: %d unauthorized cpcodes removed (%s) for switch_key=%s — retrying with %d remaining",
                            len(bad_ids), sorted(bad_ids), switch_key, len(pending),
                        )
                        if not pending:
                            return {
                                "data": [],
                                "status": "ok",
                                "unauthorized_cpcodes": sorted(unauthorized),
                            }
                        continue

                    logger.warning(
                        "Reporting API 403 unauthorized-objects response for switch_key=%s, but no matching cpcodes could be extracted. Response: %s",
                        switch_key, resp_text,
                    )
                    return {
                        "data": [],
                        "status": "forbidden",
                        "failed_cpcodes": cpcodes,
                        "unauthorized_cpcodes": sorted(unauthorized),
                    }

                _reporting_forbidden.add(switch_key)
                logger.warning(
                    "Reporting API 403 for switch_key=%s — traffic will be skipped for this account. Response: %s",
                    switch_key,
                    resp_text,
                )
                return {
                    "data": [],
                    "status": "forbidden",
                    "failed_cpcodes": cpcodes,
                    "unauthorized_cpcodes": sorted(unauthorized),
                }

            if resp.status_code == 429:
                if attempt < max_retries:
                    wait = _retry_delay(resp, attempt)
                    logger.warning(
                        "Reporting API 429 rate limit for switch_key=%s (attempt %d/%d) — retrying in %.1fs",
                        switch_key, attempt, max_retries, wait,
                    )
                    await asyncio.sleep(wait)
                    attempt += 1
                    continue
                logger.warning(
                    "Reporting API 429 rate limit for switch_key=%s — exhausted %d retries, skipping.",
                    switch_key, max_retries,
                )
                return {"data": [], "status": "rate_limited", "failed_cpcodes": cpcodes}

            if resp.status_code in (500, 502, 503, 504):
                if attempt < max_retries:
                    wait = _retry_delay(resp, attempt)
                    logger.warning(
                        "Reporting API %s for switch_key=%s (attempt %d/%d) — retrying in %.1fs",
                        resp.status_code, switch_key, attempt, max_retries, wait,
                    )
                    await asyncio.sleep(wait)
                    attempt += 1
                    continue
                logger.warning(
                    "Reporting API %s for switch_key=%s — exhausted %d retries. Response: %s",
                    resp.status_code, switch_key, max_retries, resp.text[:500],
                )
                return {"data": [], "status": "api_error", "failed_cpcodes": cpcodes}

            if resp.status_code != 200:
                logger.warning(
                    "Reporting API returned %s for %s: %s",
                    resp.status_code, switch_key, resp.text[:500],
                )
                return {"data": [], "status": "api_error", "failed_cpcodes": cpcodes}

            data = resp.json()
            logger.info(
                "Reporting API returned %d rows for %d cpcodes (switch_key=%s)",
                len(data.get("data", [])), len(pending), switch_key,
            )
            return {
                "data": data.get("data", []),
                "status": "ok",
                "unauthorized_cpcodes": sorted(unauthorized),
            }

        return {"data": [], "status": "api_error", "failed_cpcodes": cpcodes}



# ------------------------------------------------------------------ utilities

def _traffic_body(cpcodes: List[int]) -> dict:
    return {
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


def _extract_unauthorized_cpcodes(resp: httpx.Response) -> Optional[set]:
    """Return unauthorized CPCode IDs, or None if this is not that 403 shape."""
    resp_text = resp.text[:4000]
    payload = {}
    try:
        payload = resp.json()
    except ValueError:
        pass

    title = str(payload.get("title", ""))
    problem_type = str(payload.get("type", ""))
    detail = str(payload.get("detail", ""))
    signal = f"{title} {problem_type} {detail} {resp_text}".lower()
    if "unauthorized" not in signal or "object" not in signal:
        return None

    source = detail or resp_text
    match = re.search(r"\[([^\]]+)\]", source)
    if match:
        source = match.group(1)
    elif ":" in source:
        source = source.split(":", 1)[1]

    ids = set()
    for token in re.findall(r"\b\d+\b", source):
        try:
            ids.add(int(token))
        except ValueError:
            pass
    return ids


def _retry_delay(resp: httpx.Response, attempt: int) -> float:
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            return max(float(retry_after), 0.0)
        except ValueError:
            try:
                from email.utils import parsedate_to_datetime
                retry_at = parsedate_to_datetime(retry_after)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=timezone.utc)
                return max((retry_at - datetime.now(timezone.utc)).total_seconds(), 0.0)
            except (TypeError, ValueError):
                pass
    return (2 ** attempt) + (attempt * 0.5)


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
