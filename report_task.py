"""
Celery task: run_report
Orchestrates the full async report pipeline inside asyncio.run().
"""
import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

from app.config import get_settings
from app.services.akamai_client import AkamaiClient, get_cert_details_sync, parse_traffic_metrics
from app.services.cache_service import get_or_fetch_rule_tree
from app.services.dns_service import get_network_details
from app.services.edgegrid_auth import auth_from_edgerc
from app.services.excel_service import generate_excel
from app.services.property_analysis import (
    has_adv_override,
    has_custom_override,
    count_custom_behaviors,
    origin_hostnames,
    has_sro,
    has_cw_qr,
    read_cpcode_list,
    rule_tree_complexity,
    extract_tls_settings,
)
from app.tasks.celery_app import celery_app


@celery_app.task(bind=True, name="tasks.run_report")
def run_report(self, switch_key: str, account_name: str, traffic_days: int = 15) -> dict:
    """Entry point called by FastAPI. Bridges sync Celery → async pipeline."""
    return asyncio.run(_async_run_report(self, switch_key, account_name, traffic_days))


# ------------------------------------------------------------------ async pipeline

async def _async_run_report(task, switch_key: str, account_name: str, traffic_days: int = 15) -> dict:
    settings = get_settings()

    base_url, auth = auth_from_edgerc(settings.edgerc_path, settings.edgerc_section)
    reporting_base_url, reporting_auth = auth_from_edgerc(
        settings.edgerc_path, settings.edgerc_reporting_section
    )
    sem = asyncio.Semaphore(settings.concurrency_limit)
    redis = await aioredis.from_url(settings.redis_url, decode_responses=True)

    # Prepare output folder
    safe_name = re.sub(r'[\\/:*?"<>|]', "_", account_name).strip()
    folder = Path(settings.reports_base_dir) / safe_name
    folder.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d%H%M%S")
    json_path = folder / f"report_{safe_name}_{timestamp}.json"
    xlsx_path = folder / f"report_{safe_name}_{timestamp}.xlsx"

    final_report: Dict[str, Any] = {"report": []}

    async with AkamaiClient(base_url, auth, sem) as client, \
               AkamaiClient(reporting_base_url, reporting_auth, sem) as reporting_client:

        # ---- Step 1: groups ------------------------------------------------
        _progress(task, "Fetching groups", 5)
        groups_data = await client.get_groups(switch_key)
        groups = groups_data.get("groups", {}).get("items", [])

        # ---- Step 2: properties for all groups in parallel -----------------
        _progress(task, f"Fetching properties for {len(groups)} groups", 15)
        prop_results = await asyncio.gather(
            *[
                client.get_properties(
                    switch_key, g["contractIds"][0], g["groupId"]
                )
                for g in groups
                if g.get("contractIds")
            ],
            return_exceptions=True,
        )

        # Build (group, properties) pairs
        group_prop_pairs = []
        for g, result in zip(
            [g for g in groups if g.get("contractIds")], prop_results
        ):
            if isinstance(result, Exception):
                logger.warning("get_properties failed for group %s (%s): %s", g["groupId"], g.get("groupName"), result)
                props = []
            else:
                props = result.get("properties", {}).get("items", [])
            group_prop_pairs.append((g, props))

        total_props = sum(len(p) for _, p in group_prop_pairs)

        # ---- Step 3: process every property in parallel (gated by semaphore)
        _progress(task, f"Analysing {total_props} properties", 20)
        prop_tasks = [
            _process_property(task, client, reporting_client, redis, switch_key, g, prop, settings, traffic_days)
            for g, props in group_prop_pairs
            for prop in props
        ]
        prop_outputs = await asyncio.gather(*prop_tasks, return_exceptions=True)

        # Reassemble into group → property tree
        idx = 0
        for g, props in group_prop_pairs:
            group_report = {
                "groupname": g["groupName"],
                "groupid": g["groupId"],
                "parentgroupid": g.get("parentGroupId"),
                "contractid": g["contractIds"][0],
                "properties": [],
            }
            for _ in props:
                out = prop_outputs[idx]
                idx += 1
                if not isinstance(out, Exception) and out:
                    group_report["properties"].append(out)
            final_report["report"].append(group_report)

        # ---- Step 4: write JSON --------------------------------------------
        _progress(task, "Writing JSON report", 90)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(final_report, f, indent=4)

        # ---- Step 5: generate Excel ----------------------------------------
        _progress(task, "Generating Excel", 95)
        generate_excel(str(json_path), str(xlsx_path))

    await redis.aclose()

    return {
        "account_name": account_name,
        "json_path": str(json_path),
        "xlsx_path": str(xlsx_path),
    }


# ------------------------------------------------------------------ property processing

async def _process_property(task, client, reporting_client, redis, switch_key, group, prop_details, settings, traffic_days=15):
    """Fetch and analyse a single property. Returns the property dict."""
    contract_id = group["contractIds"][0]
    group_id = group["groupId"]
    property_id = prop_details["propertyId"]
    version = str(prop_details.get("productionVersion") or prop_details.get("latestVersion") or 1)

    try:
        # Rule tree + hostnames + activations fetched concurrently
        rule_tree, hostnames_result, activations_result = await asyncio.gather(
            get_or_fetch_rule_tree(
                redis,
                client.get_rule_tree(switch_key, contract_id, group_id, property_id, version),
                switch_key,
                property_id,
                version,
                settings.rule_tree_cache_ttl,
            ),
            client.get_hostnames(switch_key, contract_id, group_id, property_id, version),
            client.get_activations(switch_key, contract_id, group_id, property_id),
            return_exceptions=True,
        )
        if isinstance(hostnames_result, Exception):
            logger.warning("get_hostnames failed for property %s (skipping hostnames): %s", property_id, hostnames_result)
            hostnames_data = {}
        else:
            hostnames_data = hostnames_result

        # Extract latest production activation
        last_activated = ""
        activated_by = ""
        if not isinstance(activations_result, Exception) and activations_result:
            activations = activations_result.get("activations", {}).get("items", [])
            for act in activations:
                if act.get("network") == "PRODUCTION" and act.get("status") == "ACTIVE":
                    last_activated = act.get("updateDate", act.get("submitDate", ""))
                    activated_by = act.get("activatedBy", act.get("createdBy", ""))
                    break

        # Analyse rule tree (pure functions — no I/O)
        cpcode_list, site_shield, custom_ss, client_chars, content_chars, origin_chars = \
            read_cpcode_list(rule_tree, switch_key)
        adv_override = has_adv_override(rule_tree)
        custom_override = has_custom_override(rule_tree)
        custom_behavior_count = count_custom_behaviors(rule_tree)
        origin_hosts = origin_hostnames(rule_tree)
        sro = has_sro(rule_tree)
        cw_qr = has_cw_qr(rule_tree)
        complexity = rule_tree_complexity(rule_tree)
        min_tls = extract_tls_settings(rule_tree)

        # Build CP code list with traffic
        cpcode_rows = cpcode_list  # list of (cpc, desc, prod) tuples
        all_cpcodes_flat = [c for cp, _, _ in cpcode_rows for c in cp if c]
        traffic_data = {}
        if all_cpcodes_flat:
            resp = await reporting_client.get_traffic(switch_key, all_cpcodes_flat, days=traffic_days)
            if resp.get("data"):
                for row in resp["data"]:
                    # Reporting API v2 returns flat rows: cpcode + metrics at top level
                    cpc = str(row.get("cpcode", ""))
                    if cpc:
                        traffic_data[cpc] = row

        cpcodes_out = []
        for cp_list, desc_list, prod_list in cpcode_rows:
            if not cp_list:
                continue
            traffic = {}
            cp_str = str(cp_list[0]) if cp_list else ""
            if cp_str in traffic_data:
                m = traffic_data[cp_str]
                import math as _math
                traffic = {
                    "bytesOffload": round(float(m.get("offloadedBytesPercentage", 0)), 2),
                    "edgeBytes": round(float(m.get("edgeBytesSum", 0)) / _math.pow(1000, 3), 2),
                    "midgressBytes": round(float(m.get("midgressBytesSum", 0)) / _math.pow(1000, 3), 2),
                    "originBytes": round(float(m.get("originBytesSum", 0)) / _math.pow(1000, 3), 2),
                    "cacheHitPct": round(float(m.get("hitsOffloadPercentage", 0)), 2),
                }
            cpcodes_out.append({
                "cpcode": cp_list,
                "description": desc_list,
                "product": prod_list,
                "traffic": traffic,
            })

        # Build hostname list with CNAME + cert details
        raw_hostnames = hostnames_data.get("hostnames", {}).get("items", [])
        cname_tasks = [
            get_network_details(h.get("cnameFrom", ""))
            for h in raw_hostnames
            if isinstance(h, dict)
        ]
        cname_results = await asyncio.gather(*cname_tasks, return_exceptions=True)

        cert_tasks = [
            asyncio.to_thread(get_cert_details_sync, h.get("cnameFrom", ""))
            for h in raw_hostnames
            if isinstance(h, dict) and h.get("cnameFrom")
        ]
        cert_results = await asyncio.gather(*cert_tasks, return_exceptions=True)

        hostnames_out = []
        cert_idx = 0
        for i, h in enumerate(raw_hostnames):
            if not isinstance(h, dict):
                continue
            net = cname_results[i] if not isinstance(cname_results[i], Exception) else ("", "", "")
            cert = cert_results[cert_idx] if cert_idx < len(cert_results) and not isinstance(cert_results[cert_idx], Exception) else None
            if h.get("cnameFrom"):
                cert_idx += 1
            hostnames_out.append({
                "name": h.get("cnameFrom", ""),
                "cnameFrom": h.get("cnameFrom", ""),
                "cnameTo": h.get("cnameTo", ""),
                "map": net[0],
                "type": net[1],
                "slot": net[2],
                "cert": cert,
            })

        # Aggregate cert info at property level (earliest expiry)
        earliest_expiry = ""
        cert_issuer = ""
        for h in hostnames_out:
            c = h.get("cert")
            if c:
                exp = c.get("expiration", "")
                if not earliest_expiry or (exp and exp < earliest_expiry):
                    earliest_expiry = exp
                    cert_issuer = c.get("issuer", "")

        return {
            "id": property_id,
            "name": prop_details.get("propertyName", ""),
            "origin": origin_hosts or None,
            "latestVersion": prop_details.get("latestVersion"),
            "stagingVersion": prop_details.get("stagingVersion"),
            "productionVersion": prop_details.get("productionVersion"),
            "cpcodes": cpcodes_out,
            "hostnames": hostnames_out,
            "adv_override_exists": adv_override,
            "custom_override_exists": custom_override,
            "count_custom_behavior": custom_behavior_count,
            "sro": sro if sro else False,
            "CW_QR": cw_qr,
            "site_shield": site_shield or custom_ss or None,
            "clientCharacteristics": client_chars or None,
            "contentCharacteristics": content_chars or None,
            "originCharacteristics": origin_chars or None,
            "total_rules": complexity["total_rules"],
            "max_depth": complexity["max_depth"],
            "behavior_count": complexity["behavior_count"],
            "cert_expiry": earliest_expiry,
            "cert_issuer": cert_issuer,
            "min_tls": min_tls,
            "last_activated": last_activated,
            "activated_by": activated_by,
        }

    except Exception:
        logger.exception("Error processing property %s", property_id)
        return None


# ------------------------------------------------------------------ helpers

def _progress(task, step: str, pct: int):
    task.update_state(state="PROGRESS", meta={"step": step, "pct": pct})
    print(f"[{pct}%] {step}")
