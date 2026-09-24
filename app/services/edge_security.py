"""Evidence-based edge network and certificate inventory.

HAPI securityType describes the delivery network, not whether a hostname has a
working certificate. PAPI secure=False is a legacy flag and does not prove
HTTP-only delivery. Neither suffixes nor failed TLS probes establish TLS mode.
"""
import copy
from collections import Counter
from app.services.edge_certificates import apply_certificate_evidence

MODES = {"STANDARD-TLS": "sTLS", "ENHANCED-TLS": "eTLS"}
CERTS = {"DEFAULT": "Default DV", "CPS_MANAGED": "CPS-managed"}
NETWORKS = ("PRODUCTION", "STAGING")


def hostname(value):
    return str(value or "").strip().rstrip(".").lower()


def edge_id(value):
    return str(value or "").removeprefix("ehn_")


def classify_hostname(item, edge, network):
    source = hostname(item.get("cnameFrom"))
    target = hostname(item.get("cnameTo"))
    mode = MODES.get(edge.get("securityType"), "Unknown")
    provisioning = item.get("certProvisioningType", "")
    cname_type = item.get("cnameType")
    # PAPI cnameType=SHARED_CERT is what Property Manager shows as "Shared". An
    # Akamai-owned *.akamaized.net name without it has no certificate attached, and
    # Property Manager shows "No certificate (HTTP Only)". The name alone decides neither.
    shared = cname_type == "SHARED_CERT"
    akamai_name = (source == target and source.endswith(".akamaized.net")
                   and len(source.split(".")) == 3)
    no_certificate = (akamai_name and not shared and cname_type
                      and provisioning == "CPS_MANAGED")
    unreported = akamai_name and not shared and not cname_type and provisioning != "DEFAULT"
    if shared:
        cert_type = "Akamai shared"
    elif no_certificate:
        cert_type = "No certificate"
    elif unreported:
        cert_type = "Unknown"
    else:
        cert_type = CERTS.get(provisioning, "Unknown")
    cert_status = item.get("certStatus")
    raw_statuses = cert_status.get(network.lower(), []) if isinstance(cert_status, dict) else []
    statuses = sorted({str(s["status"]) for s in (raw_statuses if isinstance(raw_statuses, list) else [])
                       if isinstance(s, dict) and s.get("status")})
    evidence = []
    if mode != "Unknown":
        evidence.append("HAPI securityType=" + edge["securityType"])
    else:
        evidence.append("Delivery network metadata unavailable; hostname suffix is not proof of TLS mode.")
    if shared:
        evidence.append("PAPI cnameType=SHARED_CERT (Akamai shared certificate; Property Manager shows 'Shared').")
    elif no_certificate:
        evidence.append(f"PAPI cnameType={cname_type}, certProvisioningType={provisioning} on an Akamai-owned "
                        "*.akamaized.net name with no shared certificate: Property Manager shows "
                        "'No certificate (HTTP Only)'. Clients that still connect over HTTPS receive "
                        "Akamai's *.akamaized.net wildcard certificate from the edge.")
    elif unreported:
        evidence.append("Akamai-owned *.akamaized.net name, but PAPI did not report cnameType, so shared "
                        "certificate use cannot be established.")
    elif provisioning:
        evidence.append("PAPI certProvisioningType=" + str(provisioning))
    protocol = "HTTPS certificate deployed" if "DEPLOYED" in statuses else "Unknown"
    if shared:
        protocol = "Shared HTTPS configured"
    elif no_certificate:
        protocol = "HTTP-only (Property Manager: no certificate)"
    elif provisioning == "DEFAULT" and protocol == "Unknown":
        protocol = "HTTPS provisioning " + (", ".join(statuses).lower() if statuses else "status unknown")
    if statuses:
        evidence.append(network.title() + " certificate status: " + ", ".join(statuses))
    if protocol == "Unknown":
        evidence.append("HTTPS availability and HTTP-only delivery are not established by the collected configuration.")
    row = dict(hostname=item.get("cnameFrom", ""), edge_hostname=item.get("cnameTo", ""),
                edge_hostname_id=item.get("edgeHostnameId", ""), tls_mode=mode,
                certificate_type=cert_type, provisioning_type=provisioning,
                certificate_status=", ".join(statuses) or "Not reported",
                protocol=protocol, evidence=" ".join(evidence),
                raw_hostname=copy.deepcopy(item), edge_metadata=copy.deepcopy(edge))
    if no_certificate:
        row["delivery_mode"] = "HTTP-only"
    return row


def summarize(rows, status="collected", reason=""):
    modes = sorted({r.get("delivery_mode", r["tls_mode"]) for r in rows})
    known = [m for m in modes if m != "Unknown"]
    label = "Mixed" if len(known) > 1 else known[0] if known else "Unknown"
    if known and "Unknown" in modes:
        label += " + Unknown"
    return dict(status=status, reason=reason, label=label, modes=modes or ["Unknown"],
                certificate_types=sorted({r["certificate_type"] for r in rows}) or ["Unknown"],
                hostname_count=len(rows), hostnames=rows)


async def collect_property_security(client, switch_key, contract_id, group_id,
                                    property_id, prop, primary_version, primary_result, certificate_inventory=None):
    """Collect each active network; reuse a shared version, support hostname buckets."""
    versions = {n: prop.get("productionVersion" if n == "PRODUCTION" else "stagingVersion") for n in NETWORKS}
    try:
        catalog = await client.get_edge_security_catalog(switch_key)
        items = catalog.get("edgeHostnames", [])
        if not isinstance(items, list):
            raise ValueError("Invalid HAPI hostname inventory")
        by_id = {edge_id(e.get("edgeHostnameId")): e for e in items if e.get("edgeHostnameId") is not None}
        by_name = {hostname(str(e.get("recordName", "")) + "." + str(e.get("dnsZone", ""))): e for e in items}
        catalog_reason = ""
    except Exception:
        by_id, by_name = {}, {}
        catalog_reason = "Edge Hostnames API unavailable or access not granted."
    cached = {str(primary_version): primary_result}
    bucket_result = None
    if prop.get("useHostnameBucket"):
        try:
            bucket_result = await client.get_active_hostnames(switch_key, contract_id, group_id, property_id)
        except Exception as exc:
            bucket_result = exc
    result = {}
    for network, version in versions.items():
        if not version:
            result[network] = dict(status="inactive", reason="No active version.", label="Not active",
                                   modes=[], certificate_types=[], hostname_count=0, hostnames=[])
            continue
        try:
            if prop.get("useHostnameBucket"):
                if isinstance(bucket_result, Exception):
                    raise bucket_result
                raw = []
                prefix = network.lower()
                for row in bucket_result:
                    if row.get(prefix + "CnameTo"):
                        raw.append({**row, "cnameTo": row[prefix + "CnameTo"],
                                    "edgeHostnameId": row.get(prefix + "EdgeHostnameId"),
                                    "certProvisioningType": row.get(prefix + "CertType"),
                                    "cnameType": row.get(prefix + "CnameType")})
            else:
                key = str(version)
                if key not in cached:
                    try:
                        cached[key] = await client.get_hostnames(switch_key, contract_id, group_id, property_id, key)
                    except Exception as exc:
                        cached[key] = exc
                payload = cached[key]
                if isinstance(payload, Exception):
                    raise payload
                raw = payload["hostnames"]["items"]
                if not isinstance(raw, list) or not all(isinstance(h, dict) for h in raw):
                    raise ValueError("Invalid hostname inventory")
            rows = []
            for h in raw:
                edge = by_id.get(edge_id(h.get("edgeHostnameId"))) or by_name.get(hostname(h.get("cnameTo")), {})
                row = classify_hostname(h, edge, network)
                rows.append(apply_certificate_evidence(row, edge, network, certificate_inventory))
            result[network] = summarize(rows, reason=catalog_reason or ("No hostnames returned." if not rows else ""))
        except Exception:
            result[network] = summarize([], "unavailable", "Hostnames could not be collected for this network.")
        result[network]["version"] = version
    return result


def _reclassify_legacy_shared(item, network):
    """Reports saved before cnameType was used labelled every matching *.akamaized.net
    name as shared. The saved raw PAPI/HAPI records hold the evidence to correct that."""
    rows = item.get("hostnames") or []
    stale = [r for r in rows if r.get("certificate_type") == "Akamai shared"
             and isinstance(r.get("raw_hostname"), dict)
             and r["raw_hostname"].get("cnameType") != "SHARED_CERT"]
    if not stale:
        return item
    fixed = [classify_hostname(r["raw_hostname"], r.get("edge_metadata") or {}, network) if r in stale else r
             for r in rows]
    extra = {k: v for k, v in item.items() if k not in ("status", "reason", "label", "modes",
             "certificate_types", "hostname_count", "hostnames")}
    return dict(**summarize(fixed, item.get("status", "collected"), item.get("reason", "")), **extra)


def prepare_edge_report(data):
    """Interpret snapshots without changing their saved evidence or legacy columns."""
    data = copy.deepcopy(data)
    counts = {n: Counter() for n in NETWORKS}
    for group in data.get("report", []):
        for prop in group.get("properties", []):
            security = prop.get("edge_security") or {}
            for network in NETWORKS:
                version = prop.get("productionVersion" if network == "PRODUCTION" else "stagingVersion")
                if network not in security:
                    security[network] = (dict(status="inactive", label="Not active", modes=[],
                        certificate_types=[], hostname_count=0, hostnames=[], reason="No active version.")
                        if not version else dict(**summarize([], "not_collected",
                        "TLS evidence was not collected in this report. Rerun the audit."), version=version))
                item = security[network]
                item = security[network] = _reclassify_legacy_shared(item, network)
                if item["status"] == "inactive":
                    counts[network]["inactive"] += 1
                    continue
                counts[network]["active"] += 1
                for mode in set(item["modes"]):
                    counts[network][mode] += 1
                if item["label"].startswith("Mixed"):
                    counts[network]["Mixed"] += 1
                if "Akamai shared" in item["certificate_types"]:
                    counts[network]["shared"] += 1
            prop["edge_security"] = security
            prop["edge_certificate_label"] = ", ".join(sorted({t for n in security.values()
                for t in n["certificate_types"] if t != "Unknown"})) or "Unknown"
    data["edge_security_summary"] = {n: dict(c) for n, c in counts.items()}
    return data
