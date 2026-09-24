"""
Converts a report JSON dict to an Excel .xlsx file.
Includes: Summary, All Data, Origins, Origin Certificates, Origin Actions sheets.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from app.services.origin_findings import prepare_origin_report
from app.services.edge_security import prepare_edge_report
from app.services.pivot_service import build_audit_pivots

from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
from openpyxl.worksheet.table import Table, TableStyleInfo

# ------------------------------------------------------------------ styles
_header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
_header_font = Font(color="FFFFFF", bold=True)
_alt_fill = PatternFill(start_color="E6F0F8", end_color="E6F0F8", fill_type="solid")
_group_fill = PatternFill(start_color="D9EAD3", end_color="D9EAD3", fill_type="solid")
_prop_fill = PatternFill(start_color="FFF2CC", end_color="FFF2CC", fill_type="solid")
_warn_fill = PatternFill(start_color="F4CCCC", end_color="F4CCCC", fill_type="solid")
_cert_warn_fill = PatternFill(start_color="FF8C00", end_color="FF8C00", fill_type="solid")
_cert_warn_font = Font(color="FFFFFF", bold=True)
_critical_fill = PatternFill(start_color="CC0000", end_color="CC0000", fill_type="solid")
_critical_font = Font(color="FFFFFF", bold=True)
_border = Border(
    left=Side(style="thin"),
    right=Side(style="thin"),
    top=Side(style="thin"),
    bottom=Side(style="thin"),
)

_HEADERS = [
    "Group Name", "Group ID", "Parent Group ID", "Contract ID",
    "Property ID", "Property Name", "Origin", "Client Characteristics",
    "Content Characteristics", "Origin Characteristics", "Latest Version",
    "Staging Version", "Production Version", "CP Code", "Description",
    "Product", "Offload %", "Edge GB", "Midgress GB", "Origin GB",
    "Cache Hit %", "CNAME From", "CNAME To", "Edge Map",
    "Network Type", "Slot", "Hostname Cert CN", "Hostname Cert Expiry",
    "Hostname Cert Issuer", "Hostname Cert Serial", "Hostname Cert Version",
    "Property Cert Expiry", "Property Cert Expiry Days", "Property Cert Type",
    "Property Cert Issuer", "Min TLS Version", "SRO", "Site Shield",
    "Advanced Override", "Custom Override", "Custom Behavior Count", "CW/QR",
    "Total Rules", "Max Depth", "Behavior Count", "Last Activated", "Activated By",
]

_ORIGIN_HEADERS = [
    "Property Name", "Property ID", "Version", "Akamai Network",
    "Group Name", "Contract ID", "Rule Path", "Conditions",
    "Origin Type", "Origin Hostname", "Resolved Hostname",
    "HTTP Port", "HTTPS Port", "Uses HTTPS",
    "Forward Host Header", "Custom FHH",
    "SNI Enabled", "Effective SNI",
    "Verification Mode", "Certs To Honor", "Trust Description",
    "CN Match Values", "Observation Status",
    "Configured Pins", "Configured CAs",
    "Coverage Gaps",
]

_CERT_HEADERS = [
    "Property Name", "Property ID", "Akamai Network",
    "Origin Hostname", "Source", "Collection Method",
    "Subject CN", "Subject", "SANs",
    "Issuer CN", "Issuer Org", "Issuer",
    "Serial Number", "SHA-256 Fingerprint",
    "Not Before", "Not After", "Days Remaining",
    "Expired", "Not Yet Valid",
    "Role", "Key Algorithm", "Key Size",
    "Signature Algorithm", "Self-Signed",
]

_ACTION_HEADERS = [
    "Severity", "Property Name", "Property ID", "Version",
    "Akamai Network", "Rule Path", "Origin Hostname",
    "Finding", "Evidence", "Days Remaining", "Recommendation",
]


def generate_excel(json_path: str, xlsx_path: str) -> str:
    with open(json_path, "r", encoding="utf-8") as f:
        data = prepare_edge_report(prepare_origin_report(json.load(f)))

    wb = Workbook()
    ws = wb.active
    ws.title = "All Data"
    ws.append(_HEADERS)

    for group in data.get("report", []):
        group_name = group.get("groupname", "")
        group_id = group.get("groupid", "")
        parent_group_id = group.get("parentgroupid", "")
        contract_id = group.get("contractid", "")
        properties = group.get("properties", [])

        if not properties:
            ws.append(
                [group_name, group_id, parent_group_id, contract_id]
                + [""] * (len(_HEADERS) - 4)
            )
            continue

        for prop in properties:
            base = _prop_base(
                group_name, group_id, parent_group_id, contract_id, prop
            )
            cpcodes = prop.get("cpcodes", [])
            hostnames = prop.get("hostnames", [])
            flags = _prop_flags(prop)
            cert_tls = _cert_tls_cols(prop)

            if not cpcodes and not hostnames:
                ws.append(base + [""] * 8 + [""] * 10 + cert_tls + flags)
                continue
            if not hostnames:
                for entry in _expand_cpcodes(cpcodes):
                    ws.append(base + entry + [""] * 10 + cert_tls + flags)
                continue
            if not cpcodes:
                for h in hostnames:
                    ws.append(
                        base + [""] * 8 + _hostname_cols(h) + cert_tls + flags
                    )
                continue
            for entry in _expand_cpcodes(cpcodes):
                for h in hostnames:
                    ws.append(
                        base + entry + _hostname_cols(h) + cert_tls + flags
                    )

    _format_worksheet(ws)

    # ---- Summary sheet ----
    _build_summary_sheet(wb, data)

    # ---- Origin sheets ----
    _build_origins_sheet(wb, data)
    _build_origin_certs_sheet(wb, data)
    _build_origin_actions_sheet(wb, data)

    _build_edge_sheets(wb, data)
    build_audit_pivots(wb, data)

    wb.save(xlsx_path)
    return xlsx_path


# ------------------------------------------------------------------ helpers

def _prop_base(group_name, group_id, parent_group_id, contract_id, prop):
    origin = prop.get("origin") or []
    if isinstance(origin, list):
        origin_str = ", ".join(str(x) for x in origin)
    else:
        origin_str = str(origin)
    return [
        group_name, group_id, parent_group_id, contract_id,
        prop.get("id", ""),
        prop.get("name", ""),
        origin_str,
        _cell_value(prop.get("clientCharacteristics")),
        _cell_value(prop.get("contentCharacteristics")),
        _cell_value(prop.get("originCharacteristics")),
        prop.get("latestVersion", ""),
        prop.get("stagingVersion", ""),
        prop.get("productionVersion", ""),
    ]


def _cell_value(value) -> str:
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _prop_flags(prop):
    cw_qr = prop.get("CW_QR") or []
    cw_qr_str = (
        ", ".join(str(x) for x in cw_qr)
        if isinstance(cw_qr, list) else str(cw_qr)
    )
    return [
        prop.get("sro", ""),
        prop.get("site_shield", ""),
        prop.get("adv_override_exists", ""),
        prop.get("custom_override_exists", ""),
        prop.get("count_custom_behavior", ""),
        cw_qr_str,
        prop.get("total_rules", ""),
        prop.get("max_depth", ""),
        prop.get("behavior_count", ""),
        prop.get("last_activated", ""),
        prop.get("activated_by", ""),
    ]


_STATUS_LABELS = {
    "rate_limited": "Rate Limited",
    "forbidden": "API Forbidden",
    "api_error": "API Error",
    "no_cpcodes": "",
}


def _expand_cpcodes(cpcodes: list) -> list:
    rows = []
    for entry in cpcodes:
        ids = entry.get("cpcode") or []
        descs = entry.get("description") or []
        prods = entry.get("product") or []
        if not ids:
            rows.append([""] * 8)
            continue
        traffic = entry.get("traffic") or {}
        status = traffic.get("_status")
        if status:
            label = _STATUS_LABELS.get(status, f"Error: {status}")
            count = max(len(ids), 1)
            for i in range(count):
                rows.append([
                    ids[i] if i < len(ids) else "",
                    descs[i] if i < len(descs) else "",
                    prods[i] if i < len(prods) else "",
                    label, label, label, label, label,
                ])
        else:
            count = max(len(ids), 1)
            for i in range(count):
                rows.append([
                    ids[i] if i < len(ids) else "",
                    descs[i] if i < len(descs) else "",
                    prods[i] if i < len(prods) else "",
                    traffic.get("bytesOffload", ""),
                    traffic.get("edgeBytes", ""),
                    traffic.get("midgressBytes", ""),
                    traffic.get("originBytes", ""),
                    traffic.get("cacheHitPct", ""),
                ])
    return rows or [[""] * 8]


def _hostname_cols(h):
    if isinstance(h, dict):
        cert = h.get("cert") or {}
        return [
            h.get("cnameFrom", ""),
            h.get("cnameTo", ""),
            h.get("map", ""),
            h.get("type", ""),
            h.get("slot", ""),
            cert.get("commonName", "") if isinstance(cert, dict) else "",
            cert.get("expiration", "") if isinstance(cert, dict) else "",
            cert.get("issuer", "") if isinstance(cert, dict) else "",
            cert.get("serialNumber", "") if isinstance(cert, dict) else "",
            cert.get("version", "") if isinstance(cert, dict) else "",
        ]
    return [str(h), "", "", "", "", "", "", "", "", ""]


def _cert_tls_cols(prop):
    return [
        prop.get("cert_expiry", ""),
        prop.get("cert_expiry_days", ""),
        prop.get("cert_type", ""),
        prop.get("cert_issuer", ""),
        prop.get("min_tls", ""),
    ]


def _format_worksheet(ws):
    for cell in ws[1]:
        cell.fill = _header_fill
        cell.font = _header_font
        cell.alignment = Alignment(
            horizontal="center", vertical="center", wrap_text=True
        )
        cell.border = _border
    ws.freeze_panes = "A2"
    for col in ws.columns:
        max_len = max(
            (len(str(c.value)) for c in col if c.value), default=0
        )
        ws.column_dimensions[col[0].column_letter].width = min(
            (max_len + 2) * 1.2, 40
        )

    edge_gb_idx = _HEADERS.index("Edge GB")
    cert_expiry_idx = _HEADERS.index("Property Cert Expiry")
    hostname_cert_expiry_idx = _HEADERS.index("Hostname Cert Expiry")

    for row_idx, row in enumerate(ws.iter_rows(min_row=2), 2):
        group_name = row[0].value
        property_id = row[4].value
        edge_val = row[edge_gb_idx].value
        is_zero_traffic = property_id and (
            edge_val is None or edge_val == "" or edge_val == 0
            or edge_val == 0.0
        )
        if is_zero_traffic:
            row_fill = _warn_fill
        else:
            row_fill = _group_fill if not property_id else _prop_fill
        for cell in row:
            cell.fill = row_fill
            cell.border = _border
            cell.alignment = Alignment(vertical="center")
        for idx in (cert_expiry_idx, hostname_cert_expiry_idx):
            cert_cell = row[idx]
            if cert_cell.value and _is_cert_expiring_soon(
                str(cert_cell.value), 30
            ):
                cert_cell.fill = _cert_warn_fill
                cert_cell.font = _cert_warn_font

    if ws.max_row > 1:
        tab = Table(displayName="ReportData", ref=ws.dimensions)
        tab.tableStyleInfo = TableStyleInfo(
            name="TableStyleMedium2",
            showFirstColumn=False,
            showLastColumn=False,
            showRowStripes=True,
            showColumnStripes=False,
        )
        ws.add_table(tab)


def _is_cert_expiring_soon(expiry_str: str, days: int = 30) -> bool:
    from datetime import datetime
    for fmt in (
        "%b %d %H:%M:%S %Y GMT",
        "%b  %d %H:%M:%S %Y GMT",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S+00:00",
    ):
        try:
            exp_dt = datetime.strptime(expiry_str, fmt)
            return 0 <= (exp_dt - datetime.utcnow()).days <= days
        except ValueError:
            continue
    return False


# ------------------------------------------------------------------ Summary

def _build_summary_sheet(wb, data):
    ws = wb.create_sheet("Summary", 0)
    ws.append(["Metric", "Value"])

    all_props = []
    total_groups = 0
    products = {}
    total_edge = 0.0
    total_origin = 0.0
    total_midgress = 0.0
    offload_sum = 0.0
    offload_count = 0
    cache_hit_sum = 0.0
    cache_hit_count = 0
    expiring_certs = []
    sro_count = 0
    adv_override_count = 0
    site_shield_count = 0

    for group in data.get("report", []):
        total_groups += 1
        for prop in group.get("properties", []):
            all_props.append(prop)
            if prop.get("sro"):
                sro_count += 1
            if prop.get("adv_override_exists"):
                adv_override_count += 1
            if prop.get("site_shield"):
                site_shield_count += 1
            for entry in prop.get("cpcodes", []):
                traffic = entry.get("traffic") or {}
                for p in (entry.get("product") or []):
                    if p:
                        products[p] = products.get(p, 0) + 1
                if traffic.get("edgeBytes"):
                    total_edge += float(traffic["edgeBytes"])
                if traffic.get("originBytes"):
                    total_origin += float(traffic["originBytes"])
                if traffic.get("midgressBytes"):
                    total_midgress += float(traffic["midgressBytes"])
                if traffic.get("bytesOffload"):
                    offload_sum += float(traffic["bytesOffload"])
                    offload_count += 1
                if traffic.get("cacheHitPct"):
                    cache_hit_sum += float(traffic["cacheHitPct"])
                    cache_hit_count += 1
            cert_exp = prop.get("cert_expiry", "")
            if cert_exp and _is_cert_expiring_soon(cert_exp, 30):
                expiring_certs.append(prop.get("name", "unknown"))

    avg_offload = (
        round(offload_sum / offload_count, 2) if offload_count else 0
    )
    avg_cache_hit = (
        round(cache_hit_sum / cache_hit_count, 2) if cache_hit_count else 0
    )

    # Origin coverage
    oc = data.get("origin_coverage", {})

    rows = [
        ("Total Groups", total_groups),
        ("Total Properties", len(all_props)),
        ("Total Edge GB", round(total_edge, 2)),
        ("Total Origin GB", round(total_origin, 2)),
        ("Total Midgress GB", round(total_midgress, 2)),
        ("Average Offload %", avg_offload),
        ("Average Cache Hit %", avg_cache_hit),
        ("Properties with SRO", sro_count),
        ("Properties with Adv Override", adv_override_count),
        ("Properties with Site Shield", site_shield_count),
        ("", ""),
        ("-- Origin Certificate Summary --", ""),
        ("Audit collection time (UTC)", data.get("audit_timestamp", "Unknown")),
        ("Interpretation", "Certificate findings are assessed at collection time."),
        ("Akamai Network", "Deployment network; does not identify customer QA/production environment."),
        ("Live certificate observation", "Presented certificate only; chain trust, hostname validation, Akamai delivery and renewal automation were not verified."),
        ("Short-lived leaf policy", "Lifetime <=31 days: renewal review above 10 days; warning at 8-10 days; critical at <=7 days. Pins and CA certificates are not downgraded."),
        ("Renewal reviews (rule references)", oc.get("renewal_reviews", 0)),
        ("Grouped origin findings", data.get("origin_findings_summary", {}).get("total", 0)),
        ("Total Origins Discovered", oc.get("total_origins", 0)),
        ("Origins Probed (TLS)", oc.get("probed", 0)),
        ("Origins HTTP-Only", oc.get("http_only", 0)),
        ("Origins Unreachable", oc.get("unreachable", 0)),
        ("Origins Skipped/Not Probed", oc.get("skipped", 0)),
        ("Origins with Unresolved Variables", oc.get("unresolved", 0)),
        ("Total Certificates Collected", oc.get("total_certificates", 0)),
        ("Certificates Expiring in 30 Days", oc.get("expiring_30d", 0)),
        ("Certificates Expired", oc.get("expired", 0)),
        ("Critical Actions", oc.get("actions_critical", 0)),
        ("Warning Actions", oc.get("actions_warning", 0)),
        ("", ""),
        ("-- Color Legend --", ""),
        ("Blue header", "Column headers"),
        ("Yellow row", "Standard property data row"),
        ("Red row", "Property row where Edge GB is blank or 0"),
        ("Green row", "Group row with no properties"),
        ("Orange cert cell", "Edge expiry within 30 days or origin warning; short-lived origin renewal reviews retain neutral formatting"),
        ("Dark red row", "Critical origin certificate action"),
        ("", ""),
        ("-- Products Breakdown --", ""),
    ]
    for prod_name, count in sorted(products.items(), key=lambda x: -x[1]):
        rows.append((f"  {prod_name}", count))

    if expiring_certs:
        rows.append(("", ""))
        rows.append(("-- Edge Certs Expiring Within 30 Days --", ""))
        for name in expiring_certs:
            rows.append((f"  {name}", ""))

    rows.extend([("", ""), ("-- Edge TLS Summary --", ""),
                 ("TLS interpretation", "Network and certificate provisioning are separate. A TLS network does not prove a deployed certificate. HTTP-only comes from Property Manager's 'No certificate (HTTP Only)' configuration (PAPI cnameType) or a complete accessible CPS inventory; it is not inferred from failed probes or legacy secure flags. Shared means PAPI cnameType SHARED_CERT."),
                 ("Legacy reports", "Unknown means evidence was unavailable or was not collected. Rerun to collect TLS metadata.")])
    for network, counts in data.get("edge_security_summary", {}).items():
        for mode in ("active", "sTLS", "eTLS", "HTTP-only", "Mixed", "shared", "Unknown", "inactive"):
            rows.append((network.title() + " properties: " + mode, counts.get(mode, 0)))
    rows.append(("Counting", "Each property is counted once per network and category. Mixed and shared counts may overlap TLS network counts."))

    for r in rows:
        ws.append(list(r))

    # Style
    for cell in ws[1]:
        cell.fill = _header_fill
        cell.font = _header_font
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = _border

    legend_fills = {
        "Blue header": (_header_fill, _header_font),
        "Yellow row": (_prop_fill, None),
        "Red row": (_warn_fill, None),
        "Green row": (_group_fill, None),
        "Orange cert cell": (_cert_warn_fill, _cert_warn_font),
        "Dark red row": (_critical_fill, _critical_font),
    }

    for row in ws.iter_rows(min_row=2):
        first_value = row[0].value
        fill_font = legend_fills.get(first_value)
        for cell in row:
            cell.border = _border
            cell.alignment = Alignment(vertical="center")
            if fill_font:
                cell.fill = fill_font[0]
                if fill_font[1]:
                    cell.font = fill_font[1]
            if (
                cell.value
                and isinstance(cell.value, str)
                and "Certs Expiring" in cell.value
            ):
                cell.fill = _cert_warn_fill
                cell.font = _cert_warn_font

    for row in ws.iter_rows(min_row=2):
        row[1].alignment = Alignment(vertical="top", wrap_text=True)
    ws.column_dimensions["A"].width = 40
    ws.column_dimensions["B"].width = 65


# ------------------------------------------------------------------ Origins sheet

def _build_origins_sheet(wb, data):
    ws = wb.create_sheet("Origins")
    ws.append(_ORIGIN_HEADERS)

    origins = data.get("origin_inventory", [])
    if not origins:
        ws.append(["Origin certificate details were not collected in this report."] + [""] * (len(_ORIGIN_HEADERS) - 1))
        _format_origin_sheet(ws, _ORIGIN_HEADERS, "OriginsTable")
        return

    for o in origins:
        cn_values = o.get("custom_cn_values", [])
        cn_str = ", ".join(cn_values) if cn_values else ""
        gaps = o.get("coverage_gaps", [])
        gaps_str = "; ".join(gaps) if gaps else ""
        ws.append([
            o.get("property_name", ""),
            o.get("property_id", ""),
            o.get("property_version", ""),
            o.get("akamai_network", ""),
            o.get("group_name", ""),
            o.get("contract_id", ""),
            o.get("rule_path", ""),
            o.get("conditions", ""),
            o.get("origin_type", ""),
            o.get("origin_hostname", ""),
            o.get("resolved_hostname", ""),
            o.get("http_port", ""),
            o.get("https_port", ""),
            o.get("uses_https", ""),
            o.get("forward_host_header", ""),
            o.get("custom_forward_host_header", ""),
            o.get("sni_enabled", ""),
            o.get("effective_sni", ""),
            o.get("verification_mode", ""),
            o.get("origin_certs_to_honor", ""),
            o.get("trust_description", ""),
            cn_str,
            o.get("observation_status", ""),
            len(o.get("configured_certificates", [])),
            len(o.get("configured_cas", [])),
            gaps_str,
        ])

    _format_origin_sheet(ws, _ORIGIN_HEADERS, "OriginsTable")


def _format_origin_sheet(ws, headers, table_name):
    for cell in ws[1]:
        cell.fill = _header_fill
        cell.font = _header_font
        cell.alignment = Alignment(
            horizontal="center", vertical="center", wrap_text=True
        )
        cell.border = _border
    ws.freeze_panes = "A2"
    for col in ws.columns:
        max_len = max(
            (len(str(c.value)) for c in col if c.value), default=0
        )
        ws.column_dimensions[col[0].column_letter].width = min(
            (max_len + 2) * 1.2, 50
        )
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.border = _border
            cell.alignment = Alignment(vertical="center")

    if ws.max_row > 1:
        tab = Table(displayName=table_name, ref=ws.dimensions)
        tab.tableStyleInfo = TableStyleInfo(
            name="TableStyleMedium2",
            showFirstColumn=False,
            showLastColumn=False,
            showRowStripes=True,
            showColumnStripes=False,
        )
        ws.add_table(tab)


# ------------------------------------------------------------------ Origin Certificates sheet

def _build_origin_certs_sheet(wb, data):
    ws = wb.create_sheet("Origin Certificates")
    ws.append(_CERT_HEADERS)

    certs = data.get("origin_certificates", [])
    if not certs:
        ws.append(["Origin certificate details were not collected in this report."] + [""] * (len(_CERT_HEADERS) - 1))
        _format_origin_sheet(ws, _CERT_HEADERS, "OriginCertsTable")
        return

    for c in certs:
        sans = c.get("san", [])
        sans_str = ", ".join(sans) if isinstance(sans, list) else str(sans)
        ws.append([
            c.get("property_name", ""),
            c.get("property_id", ""),
            c.get("akamai_network", ""),
            c.get("origin_hostname", ""),
            c.get("source", ""),
            c.get("collection_method", ""),
            c.get("subject_cn", ""),
            c.get("subject", ""),
            sans_str,
            c.get("issuer_cn", ""),
            c.get("issuer_org", ""),
            c.get("issuer", ""),
            c.get("serial_number", ""),
            c.get("sha256_fingerprint", ""),
            c.get("not_before", ""),
            c.get("not_after", ""),
            c.get("days_remaining", ""),
            c.get("is_expired", ""),
            c.get("is_not_yet_valid", ""),
            c.get("role", ""),
            c.get("key_algorithm", ""),
            c.get("key_size", ""),
            c.get("signature_algorithm", ""),
            c.get("is_self_signed", ""),
        ])

    _format_origin_sheet(ws, _CERT_HEADERS, "OriginCertsTable")

    # Match UI interpretation; a short-lived renewal review is not a warning.
    for row, cert in zip(ws.iter_rows(min_row=2), certs):
        severity = cert.get("assessment", {}).get("severity", "none")
        if severity in ("critical", "warning"):
            for cell in row:
                cell.fill = _critical_fill if severity == "critical" else _cert_warn_fill
                cell.font = _critical_font if severity == "critical" else _cert_warn_font


# ------------------------------------------------------------------ Origin Actions sheet

def _build_origin_actions_sheet(wb, data):
    ws = wb.create_sheet("Origin Actions")
    ws.append(_ACTION_HEADERS)

    actions = data.get("origin_actions", [])
    if not actions:
        ws.append(["No origin findings reported; check collection coverage."] + [""] * (len(_ACTION_HEADERS) - 1))
        _format_origin_sheet(ws, _ACTION_HEADERS, "OriginActionsTable")
        return

    for a in actions:
        ws.append([
            a.get("severity", ""),
            a.get("property_name", ""),
            a.get("property_id", ""),
            a.get("property_version", ""),
            a.get("akamai_network", ""),
            a.get("rule_path", ""),
            a.get("origin_hostname", ""),
            a.get("finding", ""),
            a.get("evidence", ""),
            a.get("days_remaining", ""),
            a.get("recommendation", ""),
        ])

    _format_origin_sheet(ws, _ACTION_HEADERS, "OriginActionsTable")

    # Color by severity
    sev_col = _ACTION_HEADERS.index("Severity")
    for row in ws.iter_rows(min_row=2):
        sev = str(row[sev_col].value).lower()
        if sev == "critical":
            for cell in row:
                cell.fill = _critical_fill
                cell.font = _critical_font
        elif sev == "warning":
            for cell in row:
                cell.fill = _cert_warn_fill
                cell.font = _cert_warn_font


def _build_edge_sheets(wb, data):
    props = wb.create_sheet("Edge TLS")
    props.append(["Group", "Contract ID", "Property", "Property ID", "Network",
                  "Version", "Delivery mode", "Certificate types", "Hostnames",
                  "Collection status", "Coverage note"])
    hosts = wb.create_sheet("Edge Hostnames")
    hosts.append(["Group", "Contract ID", "Property", "Property ID", "Network",
                  "Version", "Hostname", "Edge hostname", "Edge hostname ID",
                  "TLS network", "Certificate type", "Certificate provisioning",
                  "Certificate status", "HTTPS availability", "Evidence"])
    for group in data.get("report", []):
        for prop in group.get("properties", []):
            for network, item in prop["edge_security"].items():
                base = [group.get("groupname", ""), group.get("contractid", ""),
                        prop.get("name", ""), prop.get("id", ""), network, item.get("version", "")]
                props.append(base + [item["label"], ", ".join(item["certificate_types"]),
                                    item["hostname_count"], item["status"], item["reason"]])
                for h in item["hostnames"]:
                    hosts.append(base + [h["hostname"], h["edge_hostname"], h["edge_hostname_id"],
                                         h["tls_mode"], h["certificate_type"], h["provisioning_type"],
                                         h["certificate_status"], h["protocol"], h["evidence"]])
    for ws in (props, hosts):
        ws.freeze_panes = "G2"
        ws.auto_filter.ref = ws.dimensions
        for cell in ws[1]:
            cell.fill = _header_fill
            cell.font = _header_font
            cell.alignment = Alignment(wrap_text=True, vertical="top")
        for column in ws.columns:
            ws.column_dimensions[column[0].column_letter].width = min(55, max(16, len(str(column[0].value)) + 3))
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                # Evidence and hostnames are external text, never Excel formulas.
                if isinstance(cell.value, str):
                    cell.data_type = "s"
                cell.alignment = Alignment(wrap_text=True, vertical="top")
