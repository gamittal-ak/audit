"""
Converts a report JSON dict to an Excel .xlsx file.
Ported from json_to_excel.py — duplicate format_worksheet removed,
hostname handling fixed (uses dict .get() correctly).
"""
import json
from pathlib import Path

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
_cert_warn_fill = PatternFill(start_color="FF8C00", end_color="FF8C00", fill_type="solid")  # orange for cert expiry
_cert_warn_font = Font(color="FFFFFF", bold=True)
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


def generate_excel(json_path: str, xlsx_path: str) -> str:
    """
    Read the report JSON at json_path, produce an Excel workbook at xlsx_path.
    Returns xlsx_path.
    """
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

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
            ws.append([group_name, group_id, parent_group_id, contract_id] + [""] * (len(_HEADERS) - 4))
            continue

        for prop in properties:
            base = _prop_base(group_name, group_id, parent_group_id, contract_id, prop)
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
                    ws.append(base + [""] * 8 + _hostname_cols(h) + cert_tls + flags)
                continue

            for entry in _expand_cpcodes(cpcodes):
                for h in hostnames:
                    ws.append(base + entry + _hostname_cols(h) + cert_tls + flags)

    _format_worksheet(ws)

    # ---- Summary sheet ----
    _build_summary_sheet(wb, data)

    wb.save(xlsx_path)
    return xlsx_path


# ------------------------------------------------------------------ helpers

def _prop_base(group_name, group_id, parent_group_id, contract_id, prop) -> list:
    """Columns 1-10: group/property identity fields."""
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


def _prop_flags(prop) -> list:
    """Analysis flag fields, appended after cpcode/traffic/hostname/cert columns."""
    cw_qr = prop.get("CW_QR") or []
    cw_qr_str = ", ".join(str(x) for x in cw_qr) if isinstance(cw_qr, list) else str(cw_qr)
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
    """Expand each cpcode entry into a [cpcode, description, product, traffic...] row fragment."""
    rows = []
    for entry in cpcodes:
        ids = entry.get("cpcode") or []
        descs = entry.get("description") or []
        prods = entry.get("product") or []
        if not ids:
            rows.append([""] * 8)
            continue
        traffic = entry.get("traffic") or {}
        # Check if traffic pull failed (vs. legitimate zero / no data)
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


def _hostname_cols(h) -> list:
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


def _cert_tls_cols(prop) -> list:
    """Columns for Cert Expiry, Cert Type, Cert Issuer, Min TLS Version."""
    return [
        prop.get("cert_expiry", ""),
        prop.get("cert_expiry_days", ""),
        prop.get("cert_type", ""),
        prop.get("cert_issuer", ""),
        prop.get("min_tls", ""),
    ]


def _format_worksheet(ws):
    # Header row styling
    for cell in ws[1]:
        cell.fill = _header_fill
        cell.font = _header_font
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = _border

    ws.freeze_panes = "A2"

    # Auto-width (capped at 40)
    for col in ws.columns:
        max_len = max((len(str(c.value)) for c in col if c.value), default=0)
        ws.column_dimensions[col[0].column_letter].width = min((max_len + 2) * 1.2, 40)

    # Determine column indices dynamically
    edge_gb_idx = _HEADERS.index("Edge GB")
    cert_expiry_idx = _HEADERS.index("Property Cert Expiry")
    hostname_cert_expiry_idx = _HEADERS.index("Hostname Cert Expiry")

    # Row formatting
    for row_idx, row in enumerate(ws.iter_rows(min_row=2), 2):
        group_name = row[0].value
        property_id = row[4].value
        # Check for zero traffic — flag red if Edge GB is 0 or empty
        edge_val = row[edge_gb_idx].value
        is_zero_traffic = property_id and (edge_val is None or edge_val == "" or edge_val == 0 or edge_val == 0.0)
        if is_zero_traffic:
            row_fill = _warn_fill
        else:
            row_fill = _group_fill if not property_id else _prop_fill
        for cell in row:
            cell.fill = row_fill
            cell.border = _border
            cell.alignment = Alignment(vertical="center")

        # Cert expiry warning — orange highlight for certs expiring within 30 days
        for idx in (cert_expiry_idx, hostname_cert_expiry_idx):
            cert_cell = row[idx]
            if cert_cell.value and _is_cert_expiring_soon(str(cert_cell.value), 30):
                cert_cell.fill = _cert_warn_fill
                cert_cell.font = _cert_warn_font

    # Excel table
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
    """Check if a certificate expiry date string is within N days from now."""
    from datetime import datetime
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b  %d %H:%M:%S %Y GMT", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            exp_dt = datetime.strptime(expiry_str, fmt)
            return 0 <= (exp_dt - datetime.utcnow()).days <= days
        except ValueError:
            continue
    return False


def _build_summary_sheet(wb, data):
    """Add a 'Summary' sheet with account-level aggregates."""
    ws = wb.create_sheet("Summary", 0)  # Insert as first sheet

    summary_headers = [
        "Metric", "Value",
    ]
    ws.append(summary_headers)

    # Compute aggregates
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
                # Count products
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

            # Check cert expiry
            cert_exp = prop.get("cert_expiry", "")
            if cert_exp and _is_cert_expiring_soon(cert_exp, 30):
                expiring_certs.append(prop.get("name", "unknown"))

    avg_offload = round(offload_sum / offload_count, 2) if offload_count else 0
    avg_cache_hit = round(cache_hit_sum / cache_hit_count, 2) if cache_hit_count else 0

    # Write rows
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
        ("-- Color Legend --", ""),
        ("Blue header", "Column headers"),
        ("Yellow row", "Standard property data row"),
        ("Red row", "Property row where Edge GB is blank or 0"),
        ("Green row", "Group row with no properties"),
        ("Orange cert cell", "Certificate expires within 30 days"),
        ("", ""),
        ("-- Products Breakdown --", ""),
    ]
    for prod_name, count in sorted(products.items(), key=lambda x: -x[1]):
        rows.append((f"  {prod_name}", count))

    if expiring_certs:
        rows.append(("", ""))
        rows.append(("-- Certs Expiring Within 30 Days --", ""))
        for name in expiring_certs:
            rows.append((f"  {name}", ""))

    for r in rows:
        ws.append(list(r))

    # Style the summary sheet
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
            # Orange highlight for cert expiry section
            if cell.value and isinstance(cell.value, str) and "Certs Expiring" in cell.value:
                cell.fill = _cert_warn_fill
                cell.font = _cert_warn_font

    ws.column_dimensions["A"].width = 35
    ws.column_dimensions["B"].width = 20
