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
from app.services.akamai_client import AkamaiClient, get_cert_details_sync
from app.services.audit_log import audit_activity, event
from app.services.cache_service import get_or_fetch_rule_tree
from app.services.dns_service import get_network_details
from app.services.edgegrid_auth import auth_from_edgerc
from app.services.excel_service import generate_excel
from app.services.edge_security import collect_property_security
from app.services.edge_certificates import collect_certificate_inventory
from app.services.origin_findings import prepare_origin_report
from app.services.origin_cert_service import (
    extract_origins_from_rule_tree,
    probe_origin_certificate,
    assess_origin,
    generate_recommendations,
)
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
    """Entry point called by FastAPI. Bridges sync Celery -> async pipeline."""
    with audit_activity(self.request.id):
        event("Audit started. Collecting account configuration and traffic.")
        try:
            result = asyncio.run(_async_run_report(self, switch_key, account_name, traffic_days))
        except Exception:
            event("Audit failed. Check the error shown above for details.", "error")
            raise
        event("Audit complete. JSON and Excel reports are ready.", "success")
        return result


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

    final_report: Dict[str, Any] = {
        "schema_version": 3,
        "audit_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "report": [],
        "origin_inventory": [],
        "origin_certificates": [],
        "origin_actions": [],
        "origin_coverage": {},
    }

    probe_sem = asyncio.Semaphore(10)

    async with AkamaiClient(base_url, auth, sem) as client, \
               AkamaiClient(reporting_base_url, reporting_auth, sem) as reporting_client:

        # ---- Step 1: groups ------------------------------------------------
        _progress(task, "Fetching groups", 5)
        groups_data = await client.get_groups(switch_key)
        groups = groups_data.get("groups", {}).get("items", [])

        # ---- Step 2: properties for all group/contract combos --------------
        _progress(task, f"Fetching properties for {len(groups)} groups", 15)

        # Build all (group, contractId) pairs and deduplicate properties
        async def fetch_properties(group, contract_id):
            result = await client.get_properties(switch_key, contract_id, group["groupId"])
            count = len(result.get("properties", {}).get("items", []))
            event(f"Found {count} properties in group {group.get('groupName', group['groupId'])}.")
            return result

        fetch_tasks = []
        fetch_keys = []
        for g in groups:
            for cid in g.get("contractIds", []):
                fetch_tasks.append(
                    fetch_properties(g, cid)
                )
                fetch_keys.append((g, cid))

        prop_results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        # Deduplicate properties by propertyId, keeping group/contract context
        seen_prop_ids = set()
        group_prop_pairs = []
        group_map = {}

        for (g, cid), result in zip(fetch_keys, prop_results):
            if isinstance(result, Exception):
                event(f"Could not fetch properties for group {g['groupId']}; continuing with other groups.", "warning")
                logger.warning(
                    "get_properties failed for group %s contract %s: %s",
                    g["groupId"], cid, result,
                )
                continue
            props = result.get("properties", {}).get("items", [])
            deduped = []
            for p in props:
                pid = p["propertyId"]
                if pid not in seen_prop_ids:
                    seen_prop_ids.add(pid)
                    deduped.append(p)
            if deduped or not props:
                gkey = (g["groupId"], cid)
                if gkey not in group_map:
                    group_map[gkey] = (g, cid, [])
                group_map[gkey][2].extend(deduped)

        group_prop_pairs = [
            (g, cid, props) for g, cid, props in group_map.values()
        ]
        total_props = sum(len(props) for _, _, props in group_prop_pairs)

        certificate_inventory = await collect_certificate_inventory(
            client, switch_key, {cid for g in groups for cid in g.get("contractIds", [])}
        )
        final_report["edge_certificate_coverage"] = {
            k: certificate_inventory[k]
            for k in ("complete", "contracts", "enrollments", "errors", "inaccessible_contracts")
        }

        # ---- Step 3: analyse every property --------------------------------
        _progress(task, f"Analysing {total_props} properties", 20)
        completed_props = 0

        async def process_property(group, contract_id, prop):
            nonlocal completed_props
            result = await _process_property(task, client, redis, switch_key, group, contract_id, prop, settings, probe_sem, certificate_inventory)
            completed_props += 1
            step = f"Analysed {completed_props}/{total_props} properties"
            _progress(task, step, 20 + int(45 * completed_props / max(total_props, 1)), record=False)
            name = prop.get("propertyName") or prop["propertyId"]
            event(f"{step}: {name}" + ("" if result else " (could not collect this property)"), "info" if result else "warning")
            return result

        prop_tasks = []
        prop_meta = []
        for g, cid, props in group_prop_pairs:
            for prop in props:
                prop_tasks.append(
                    process_property(g, cid, prop)
                )
                prop_meta.append((g, cid, prop))

        prop_outputs = await asyncio.gather(*prop_tasks, return_exceptions=True)

        # ---- Step 4: fetch ALL traffic in ONE batched call ----------------
        _progress(task, "Fetching traffic data", 70)
        all_cpcodes: set = set()
        for out in prop_outputs:
            if not isinstance(out, Exception) and out:
                for cp_entry in out.get("cpcodes", []):
                    for c in cp_entry.get("cpcode", []):
                        if c:
                            try:
                                all_cpcodes.add(int(c))
                            except (ValueError, TypeError):
                                pass

        traffic_data: Dict[int, dict] = {}
        traffic_status_by_cpcode: Dict[int, str] = {}
        traffic_status = "no_cpcodes"
        if all_cpcodes:
            resp = await reporting_client.get_traffic(
                switch_key,
                list(all_cpcodes),
                days=traffic_days,
                _max_retries=settings.traffic_max_retries,
                chunk_size=settings.traffic_chunk_size,
                chunk_delay_seconds=settings.traffic_chunk_delay_seconds,
            )
            traffic_status = resp.get("status", "api_error")
            if resp.get("data"):
                for row in resp["data"]:
                    cpc_raw = row.get("cpcode")
                    if cpc_raw is not None:
                        try:
                            traffic_data[int(cpc_raw)] = row
                        except (ValueError, TypeError):
                            pass
            for cpc_raw, status in (resp.get("cpcode_statuses") or {}).items():
                try:
                    traffic_status_by_cpcode[int(cpc_raw)] = str(status)
                except (ValueError, TypeError):
                    pass
            logger.info(
                "Batched traffic fetch: status=%s, %d rows for %d cpcodes, %d cpcodes marked",
                traffic_status, len(traffic_data), len(all_cpcodes),
                len(traffic_status_by_cpcode),
            )

        # ---- Step 4.5: inject traffic into property outputs ---------------
        import math as _math
        for out in prop_outputs:
            if isinstance(out, Exception) or not out:
                continue
            for cp_entry in out.get("cpcodes", []):
                cp_list = cp_entry.get("cpcode", [])
                if not cp_list:
                    continue
                try:
                    cp_key = int(cp_list[0])
                except (ValueError, TypeError):
                    continue
                if cp_key in traffic_data:
                    row = traffic_data[cp_key]
                    m = row.get("metrics", row)
                    cp_entry["traffic"] = {
                        "bytesOffload": round(float(m.get("offloadedBytesPercentage", 0)), 2),
                        "edgeBytes": round(float(m.get("edgeBytesSum", 0)) / _math.pow(1000, 3), 2),
                        "midgressBytes": round(float(m.get("midgressBytesSum", 0)) / _math.pow(1000, 3), 2),
                        "originBytes": round(float(m.get("originBytesSum", 0)) / _math.pow(1000, 3), 2),
                        "cacheHitPct": round(float(m.get("offloadedHitsPercentage", 0)), 2),
                    }
                elif cp_key in traffic_status_by_cpcode:
                    cp_entry["traffic"] = {"_status": traffic_status_by_cpcode[cp_key]}
                elif traffic_status not in ("ok", "partial"):
                    cp_entry["traffic"] = {"_status": traffic_status}

        # ---- Step 5: collect origin inventory and certificates -------------
        _progress(task, "Collecting origin certificates", 80)
        all_origins = []
        for out in prop_outputs:
            if isinstance(out, Exception) or not out:
                continue
            all_origins.extend(out.get("_origin_inventory", []))

        # Deduplicate probe targets
        probe_targets = {}
        for origin in all_origins:
            if not origin.get("uses_https"):
                continue
            hostname = origin.get("resolved_hostname") or origin.get("origin_hostname", "")
            if not hostname or "{{" in hostname:
                continue
            port = origin.get("https_port", 443)
            sni = origin.get("effective_sni")
            if sni == "__request_hostname__":
                sni = None
            key = (hostname, port, sni or hostname)
            if key not in probe_targets:
                probe_targets[key] = {"hostname": hostname, "port": port, "sni": sni}

        # Probe all unique origin endpoints
        completed_probes = 0

        async def probe_target(target):
            nonlocal completed_probes
            try:
                result = await probe_origin_certificate(target["hostname"], target["port"], target["sni"], timeout=10.0, semaphore=probe_sem)
            except Exception:
                event(f"Origin certificate probe failed: {target['hostname']}:{target['port']}", "warning")
                raise
            finally:
                completed_probes += 1
            status = result.get("status", "unknown")
            event(f"Origin {completed_probes}/{len(probe_targets)}: {target['hostname']}:{target['port']} ({status})", "info" if status == "ok" else "warning")
            return result

        probe_tasks = []
        probe_keys = []
        for key, target in probe_targets.items():
            probe_tasks.append(
                probe_target(target)
            )
            probe_keys.append(key)

        if probe_tasks:
            _progress(
                task,
                f"Probing {len(probe_tasks)} origin endpoints",
                85,
            )
            probe_results = await asyncio.gather(
                *probe_tasks, return_exceptions=True
            )
        else:
            probe_results = []

        probe_map = {}
        for key, result in zip(probe_keys, probe_results):
            if isinstance(result, Exception):
                probe_map[key] = {
                    "status": "error",
                    "error": str(result),
                    "hostname": key[0],
                    "port": key[1],
                }
            else:
                probe_map[key] = result

        # Assess each origin
        for origin in all_origins:
            hostname = origin.get("resolved_hostname") or origin.get("origin_hostname", "")
            port = origin.get("https_port", 443)
            sni = origin.get("effective_sni")
            if sni == "__request_hostname__":
                sni = None
            key = (hostname, port, sni or hostname)
            live_probe = probe_map.get(key)
            assess_origin(origin, live_probe)

        # Generate recommendations
        origin_actions = generate_recommendations(all_origins)

        # Collect all certificates
        all_certs_list = []
        for origin in all_origins:
            for cert in origin.get("live_certificates", []):
                cert_record = dict(cert)
                cert_record["origin_hostname"] = (
                    origin.get("resolved_hostname") or origin["origin_hostname"]
                )
                cert_record["property_name"] = origin["property_name"]
                cert_record["property_id"] = origin["property_id"]
                cert_record["akamai_network"] = origin["akamai_network"]
                all_certs_list.append(cert_record)
            for cert in origin.get("configured_certificates", []):
                cert_record = dict(cert)
                cert_record["origin_hostname"] = (
                    origin.get("resolved_hostname") or origin["origin_hostname"]
                )
                cert_record["property_name"] = origin["property_name"]
                cert_record["property_id"] = origin["property_id"]
                cert_record["akamai_network"] = origin["akamai_network"]
                all_certs_list.append(cert_record)
            for cert in origin.get("configured_cas", []):
                cert_record = dict(cert)
                cert_record["origin_hostname"] = (
                    origin.get("resolved_hostname") or origin["origin_hostname"]
                )
                cert_record["property_name"] = origin["property_name"]
                cert_record["property_id"] = origin["property_id"]
                cert_record["akamai_network"] = origin["akamai_network"]
                all_certs_list.append(cert_record)

        # Coverage summary
        origin_coverage = {
            "total_origins": len(all_origins),
            "probed": sum(
                1 for o in all_origins
                if o.get("observation_status") == "observed"
            ),
            "http_only": sum(
                1 for o in all_origins
                if o.get("observation_status") == "http_only"
            ),
            "unreachable": sum(
                1 for o in all_origins
                if o.get("observation_status") in (
                    "dns_failure", "timeout", "tls_error",
                    "connection_refused", "connection_error",
                )
            ),
            "skipped": sum(
                1 for o in all_origins
                if o.get("observation_status") in ("skipped", "not_probed")
            ),
            "unresolved": sum(
                1 for o in all_origins
                if o.get("coverage_gaps")
            ),
            "total_certificates": len(all_certs_list),
            "expiring_30d": sum(
                1 for c in all_certs_list
                if c.get("days_remaining") is not None and 0 <= c["days_remaining"] <= 30
            ),
            "expired": sum(
                1 for c in all_certs_list
                if c.get("is_expired")
            ),
            "actions_critical": sum(
                1 for a in origin_actions if a["severity"] == "critical"
            ),
            "actions_warning": sum(
                1 for a in origin_actions if a["severity"] == "warning"
            ),
        }

        # Strip internal keys before serialization
        serializable_origins = []
        for o in all_origins:
            so = {k: v for k, v in o.items() if not k.startswith("_")}
            serializable_origins.append(so)

        final_report["origin_inventory"] = serializable_origins
        final_report["origin_certificates"] = all_certs_list
        final_report["origin_actions"] = origin_actions
        final_report["origin_coverage"] = origin_coverage

        # Reassemble into group -> property tree
        _progress(task, "Assembling report", 88)
        idx = 0
        for g, cid, props in group_prop_pairs:
            group_report = {
                "groupname": g["groupName"],
                "groupid": g["groupId"],
                "parentgroupid": g.get("parentGroupId"),
                "contractid": cid,
                "properties": [],
            }
            for _ in props:
                out = prop_outputs[idx]
                idx += 1
                if not isinstance(out, Exception) and out:
                    clean = {
                        k: v for k, v in out.items() if not k.startswith("_")
                    }
                    group_report["properties"].append(clean)
            final_report["report"].append(group_report)

        final_report = prepare_origin_report(final_report)

        # ---- Step 6: write JSON --------------------------------------------
        _progress(task, "Writing JSON report", 90)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(final_report, f, indent=4, default=str)

        # ---- Step 7: generate Excel ----------------------------------------
        _progress(task, "Generating Excel", 95)
        generate_excel(str(json_path), str(xlsx_path))

    # Persist file paths
    task_id = task.request.id
    if task_id:
        await redis.hset(f"task:{task_id}", mapping={
            "json_path": str(json_path),
            "xlsx_path": str(xlsx_path),
            "completed_at": time.strftime("%Y-%m-%d %H:%M UTC"),
        })
        await redis.expire(f"task:{task_id}", 30 * 86400)

    await redis.aclose()

    return {
        "account_name": account_name,
        "json_path": str(json_path),
        "xlsx_path": str(xlsx_path),
    }


# ------------------------------------------------------------------ property processing

async def _process_property(
    task, client, redis, switch_key, group, contract_id, prop_details,
    settings, probe_sem, certificate_inventory=None,
):
    """Fetch and analyse a single property. Returns the property dict."""
    group_id = group["groupId"]
    property_id = prop_details["propertyId"]

    try:
        # Determine versions to analyze
        prod_version = prop_details.get("productionVersion")
        staging_version = prop_details.get("stagingVersion")
        latest_version = prop_details.get("latestVersion") or 1

        # Primary version for existing analysis (backward compat)
        primary_version = str(prod_version or latest_version)

        # Fetch rule tree, hostnames, activations concurrently
        rule_tree, hostnames_result, activations_result = await asyncio.gather(
            get_or_fetch_rule_tree(
                redis,
                client.get_rule_tree(
                    switch_key, contract_id, group_id,
                    property_id, primary_version,
                ),
                switch_key,
                property_id,
                primary_version,
                settings.rule_tree_cache_ttl,
            ),
            client.get_hostnames(
                switch_key, contract_id, group_id,
                property_id, primary_version,
            ),
            client.get_activations(
                switch_key, contract_id, group_id, property_id,
            ),
            return_exceptions=True,
        )
        # Preserve the original API failure instead of passing it into rule analysis.
        if isinstance(rule_tree, Exception):
            raise rule_tree
        if not isinstance(rule_tree, dict):
            raise ValueError(f"Invalid rule tree for property {property_id}: expected an object")
        if isinstance(hostnames_result, Exception):
            event(f"Hostnames unavailable for property {property_id}; continuing with available data.", "warning")
            logger.warning(
                "get_hostnames failed for property %s: %s",
                property_id, hostnames_result,
            )
            hostnames_data = {}
        else:
            hostnames_data = hostnames_result

        edge_security = await collect_property_security(
            client, switch_key, contract_id, group_id, property_id, prop_details,
            primary_version, hostnames_result, certificate_inventory,
        )

        # Extract activation info
        last_activated = ""
        activated_by = ""
        if not isinstance(activations_result, Exception) and activations_result:
            activations = (
                activations_result.get("activations", {}).get("items", [])
            )
            for act in activations:
                if (
                    act.get("network") == "PRODUCTION"
                    and act.get("status") == "ACTIVE"
                ):
                    last_activated = act.get(
                        "updateDate", act.get("submitDate", "")
                    )
                    emails = act.get("notifyEmails", [])
                    activated_by = emails[0] if emails else ""
                    break

        # ---- Existing analysis (unchanged) ----
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

        # Build CP code list
        cpcodes_out = []
        for cp_list, desc_list, prod_list in cpcode_list:
            if not cp_list:
                continue
            cpcodes_out.append({
                "cpcode": cp_list,
                "description": desc_list,
                "product": prod_list,
                "traffic": {},
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
            net = (
                cname_results[i]
                if not isinstance(cname_results[i], Exception)
                else ("", "", "")
            )
            cert = (
                cert_results[cert_idx]
                if cert_idx < len(cert_results)
                and not isinstance(cert_results[cert_idx], Exception)
                else None
            )
            if h.get("cnameFrom"):
                cert_idx += 1
            hostnames_out.append({
                "edgeHostnameId": h.get("edgeHostnameId"),
                "certProvisioningType": h.get("certProvisioningType"),
                "certStatus": h.get("certStatus"),
                "name": h.get("cnameFrom", ""),
                "cnameFrom": h.get("cnameFrom", ""),
                "cnameTo": h.get("cnameTo", ""),
                "map": net[0],
                "type": net[1],
                "slot": net[2],
                "cert": cert,
            })

        # Aggregate cert info at property level
        earliest_expiry = ""
        cert_issuer = ""
        cert_expiry_days = None
        for h in hostnames_out:
            c = h.get("cert")
            if c:
                exp = c.get("expiration", "")
                if not earliest_expiry or (exp and exp < earliest_expiry):
                    earliest_expiry = exp
                    cert_issuer = c.get("issuer", "")

        certificate_types = sorted({t for n in edge_security.values()
                                    for t in n["certificate_types"] if t != "Unknown"})
        cert_type = ", ".join(certificate_types) or "Unknown"

        if earliest_expiry:
            try:
                from datetime import datetime as _dt
                for fmt in (
                    "%b %d %H:%M:%S %Y GMT",
                    "%b  %d %H:%M:%S %Y GMT",
                    "%Y-%m-%dT%H:%M:%SZ",
                ):
                    try:
                        exp_dt = _dt.strptime(earliest_expiry, fmt)
                        cert_expiry_days = (exp_dt - _dt.utcnow()).days
                        break
                    except ValueError:
                        continue
            except Exception:
                pass

        # ---- Origin inventory for all relevant versions ----
        origin_inventory = []
        versions_to_analyze = []

        if prod_version:
            versions_to_analyze.append(
                (prod_version, "PRODUCTION", rule_tree)
            )
        if staging_version and staging_version != prod_version:
            try:
                stg_tree = await get_or_fetch_rule_tree(
                    redis,
                    client.get_rule_tree(
                        switch_key, contract_id, group_id,
                        property_id, str(staging_version),
                    ),
                    switch_key,
                    property_id,
                    str(staging_version),
                    settings.rule_tree_cache_ttl,
                )
                versions_to_analyze.append(
                    (staging_version, "STAGING", stg_tree)
                )
            except Exception as e:
                event(f"Staging rules unavailable for property {property_id}.", "warning")
                logger.warning(
                    "Failed to fetch staging tree for %s v%s: %s",
                    property_id, staging_version, e,
                )
        elif staging_version and staging_version == prod_version:
            # Same version on both networks - tag production origins also as staging
            for o in origin_inventory:
                if o.get("akamai_network") == "PRODUCTION":
                    o["also_staging"] = True

        if (
            latest_version
            and latest_version != prod_version
            and latest_version != staging_version
        ):
            try:
                draft_tree = await get_or_fetch_rule_tree(
                    redis,
                    client.get_rule_tree(
                        switch_key, contract_id, group_id,
                        property_id, str(latest_version),
                    ),
                    switch_key,
                    property_id,
                    str(latest_version),
                    settings.rule_tree_cache_ttl,
                )
                versions_to_analyze.append(
                    (latest_version, "LATEST_DRAFT", draft_tree)
                )
            except Exception as e:
                event(f"Draft rules unavailable for property {property_id}.", "warning")
                logger.warning(
                    "Failed to fetch draft tree for %s v%s: %s",
                    property_id, latest_version, e,
                )

        if not versions_to_analyze:
            versions_to_analyze.append(
                (latest_version, "LATEST", rule_tree)
            )

        for ver, network, tree in versions_to_analyze:
            origins = extract_origins_from_rule_tree(
                tree,
                property_id=property_id,
                property_name=prop_details.get("propertyName", ""),
                property_version=ver,
                akamai_network=network,
                group_id=group_id,
                group_name=group["groupName"],
                contract_id=contract_id,
            )
            origin_inventory.extend(origins)

        return {
            "id": property_id,
            "name": prop_details.get("propertyName", ""),
            "origin": origin_hosts or None,
            "latestVersion": prop_details.get("latestVersion"),
            "stagingVersion": prop_details.get("stagingVersion"),
            "productionVersion": prop_details.get("productionVersion"),
            "cpcodes": cpcodes_out,
            "hostnames": hostnames_out,
            "edge_security": edge_security,
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
            "cert_type": cert_type,
            "cert_expiry_days": cert_expiry_days,
            "min_tls": min_tls,
            "last_activated": last_activated,
            "activated_by": activated_by,
            "_origin_inventory": origin_inventory,
        }

    except Exception:
        logger.exception("Error processing property %s", property_id)
        return None


# ------------------------------------------------------------------ helpers

def _progress(task, step: str, pct: int, record: bool = True):
    if record:
        event(step)
    task.update_state(state="PROGRESS", meta={"step": step, "pct": pct})
    print(f"[{pct}%] {step}")
