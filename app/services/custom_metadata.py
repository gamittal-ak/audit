"""Account-level custom behavior and custom override catalogs.

Two calls per account regardless of size: the catalogs are account-scoped
(every sampled entry returns sharingLevel ACCOUNT and the endpoints take
accountSwitchKey with no contract or group parameter), so there is no reason to
fan out per contract. Rule trees are already fetched for the primary version,
so joining usage costs no extra requests.

Deliberately not cached in Redis. It is two calls per audit, and an unkeyed
cache on shared workers could serve one account catalog into another account
report — the saving is not worth that failure mode.
"""
from typing import Optional

from app.services.audit_log import event

NOT_IN_CATALOG = "(not in account catalog)"


def _entry(row: dict, id_field: str) -> dict:
    """Normalise one catalog row. The raw xml is measured, never stored."""
    xml = row.get("xml")
    return {
        "id": str(row.get(id_field) or ""),
        "name": str(row.get("name") or ""),
        "description": str(row.get("description") or ""),
        "status": str(row.get("status") or ""),
        # Read rather than assumed: a future CONTRACT value must surface
        # instead of being silently mis-scoped as account-wide.
        "sharing_level": str(row.get("sharingLevel") or ""),
        "updated_by": str(row.get("updatedByUser") or ""),
        "updated_date": str(row.get("updatedDate") or ""),
        "approved_by": str(row.get("approvedByUser") or ""),
        "xml_chars": len(xml) if isinstance(xml, str) else 0,
        "use_count": 0,
        "property_count": 0,
        "properties": [],
    }


async def fetch_catalog(client, switch_key: str) -> dict:
    """Fetch both account catalogs.

    The two endpoints fail independently: a client denied custom-overrides but
    allowed custom-behaviors must still get the behavior catalog, so
    accessibility is tracked per catalog rather than once for the pair.
    """
    catalog = {
        "behaviors": {"accessible": True, "error": None},
        "overrides": {"accessible": True, "error": None},
        "custom_behaviors": [],
        "custom_overrides": [],
    }

    plan = (
        ("behaviors", "custom_behaviors", "get_custom_behaviors",
         "customBehaviors", "behaviorId"),
        ("overrides", "custom_overrides", "get_custom_overrides",
         "customOverrides", "overrideId"),
    )

    for slot, out_key, method, payload_key, id_field in plan:
        try:
            # Resolved inside the try: a client without the method degrades
            # this one catalog instead of failing the whole audit.
            payload = await getattr(client, method)(switch_key)
            rows = payload.get(payload_key)
            # PAPI wraps both catalogs in an {"items": [...]} envelope. Accept a
            # bare list too: an empty catalog is served either way, and treating
            # the envelope as unreadable marked every real account inaccessible.
            if isinstance(rows, dict):
                rows = rows.get("items")
            if not isinstance(rows, list):
                raise ValueError("Invalid catalog payload")
            catalog[out_key] = [_entry(r, id_field) for r in rows if isinstance(r, dict)]
        except Exception as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            catalog[slot]["accessible"] = False
            catalog[slot]["error"] = (
                f"HTTP {status}" if status else f"{type(exc).__name__}: {exc}"
            )
            # A denied catalog is not an empty catalog; per-property counts stay
            # accurate and the UI must say the difference.
            event(
                f"Account {slot} catalog is not visible to this API client "
                f"({catalog[slot]['error']}); behaviors will be shown by ID.",
                "warning",
            )

    catalog["accessible"] = (
        catalog["behaviors"]["accessible"] and catalog["overrides"]["accessible"]
    )
    catalog["error"] = catalog["behaviors"]["error"] or catalog["overrides"]["error"]
    return catalog


def _synthetic(identifier: str) -> dict:
    """A behavior referenced by a rule but absent from the account catalog.

    Worth surfacing rather than hiding: it means a rule points at metadata this
    account catalog does not describe.
    """
    return {
        "id": identifier, "name": NOT_IN_CATALOG, "description": "",
        "status": "", "sharing_level": "", "updated_by": "", "updated_date": "",
        "approved_by": "", "xml_chars": 0,
        "use_count": 0, "property_count": 0, "properties": [], "synthetic": True,
    }


def _bump(entry: dict, prop_id: str, prop_name: str, uses: int) -> None:
    entry["use_count"] += uses
    entry["property_count"] += 1
    entry["properties"].append({"id": prop_id, "name": prop_name, "uses": uses})


def build_catalog_usage(catalog: dict, report_groups: list) -> dict:
    """Join the account catalogs against every property advanced_metadata block."""
    behaviors_by_id = {e["id"]: e for e in catalog["custom_behaviors"]}
    overrides_by_id = {e["id"]: e for e in catalog["custom_overrides"]}
    advanced_groups: dict = {}
    properties_with = 0
    advanced_uses = 0
    match_uses = 0
    override_properties = 0

    for group in report_groups or []:
        for prop in group.get("properties") or []:
            metadata = prop.get("advanced_metadata")
            if not isinstance(metadata, dict) or not metadata.get("collected"):
                continue
            prop_id = str(prop.get("id") or "")
            prop_name = str(prop.get("name") or "")
            counts = metadata.get("counts") or {}
            if counts.get("total"):
                properties_with += 1

            uses_by_behavior: dict = {}
            for use in metadata.get("custom_behaviors") or []:
                behavior_id = use.get("behavior_id")
                if behavior_id:
                    uses_by_behavior[behavior_id] = uses_by_behavior.get(behavior_id, 0) + 1
            for behavior_id, uses in uses_by_behavior.items():
                entry = behaviors_by_id.get(behavior_id)
                if entry is None:
                    entry = _synthetic(behavior_id)
                    behaviors_by_id[behavior_id] = entry
                    catalog["custom_behaviors"].append(entry)
                _bump(entry, prop_id, prop_name, uses)

            custom_override = metadata.get("custom_override")
            if custom_override:
                override_id = custom_override.get("override_id") or ""
                entry = overrides_by_id.get(override_id)
                if entry is None:
                    entry = _synthetic(override_id)
                    entry["name"] = custom_override.get("name") or NOT_IN_CATALOG
                    overrides_by_id[override_id] = entry
                    catalog["custom_overrides"].append(entry)
                _bump(entry, prop_id, prop_name, 1)
                override_properties += 1

            # Advanced behaviors carry no Akamai identifier, so they are grouped
            # on the trimmed, case-folded description. Every surface must say so
            # -- this grouping is a convenience, not an authoritative identity.
            per_description: dict = {}
            for occurrence in metadata.get("advanced_behaviors") or []:
                description = str(occurrence.get("description") or "")
                key = description.strip().casefold()
                per_description.setdefault(key, [description, 0])
                per_description[key][1] += 1
                advanced_uses += 1
            for key, (description, uses) in per_description.items():
                entry = advanced_groups.get(key)
                if entry is None:
                    entry = {"description": description, "use_count": 0,
                             "property_count": 0, "properties": []}
                    advanced_groups[key] = entry
                _bump(entry, prop_id, prop_name, uses)

            match_uses += len(metadata.get("advanced_matches") or [])

    def order(entry: dict) -> tuple:
        # Most-used first; defined-but-unused entries sort last.
        return (-entry["use_count"], entry.get("name") or entry.get("description") or "")

    catalog["custom_behaviors"].sort(key=order)
    catalog["custom_overrides"].sort(key=order)
    catalog["advanced_behavior_groups"] = sorted(advanced_groups.values(), key=order)

    behaviors = catalog["custom_behaviors"]
    overrides = catalog["custom_overrides"]
    catalog["summary"] = {
        "catalog_size": len(behaviors),
        "in_use": sum(1 for e in behaviors if e["use_count"]),
        "unused": sum(1 for e in behaviors if not e["use_count"]),
        "override_catalog_size": len(overrides),
        "overrides_in_use": sum(1 for e in overrides if e["use_count"]),
        "overrides_unused": sum(1 for e in overrides if not e["use_count"]),
        "properties_with_custom_override": override_properties,
        "advanced_behavior_uses": advanced_uses,
        "advanced_behavior_distinct": len(advanced_groups),
        "advanced_match_uses": match_uses,
        "properties_with_advanced_metadata": properties_with,
    }
    # Half of all accounts land here. Every surface keys off this to collapse to
    # a one-line answer instead of rendering empty tables, sheets and pivots.
    catalog["summary"]["empty"] = not (
        behaviors or overrides or advanced_uses or match_uses or properties_with
    )
    return catalog


def prepare_metadata_report(data: dict) -> dict:
    """Display-time guard for reports saved before schema 4.

    Those audits never collected advanced metadata, so every surface must read
    as not-collected rather than as a measured zero.
    """
    try:
        version = int(data.get("schema_version") or 0)
    except (TypeError, ValueError):
        version = 0
    available = version >= 4 and isinstance(data.get("custom_metadata_catalog"), dict)
    data["advanced_metadata_available"] = available
    if not available:
        data["custom_metadata_catalog"] = {}
        for group in data.get("report") or []:
            for prop in group.get("properties") or []:
                prop.pop("advanced_metadata", None)
    return data
