"""
Pure functions for analyzing an Akamai property rule tree.
No I/O — all functions take a pre-fetched rule_tree dict.
"""
from typing import Any, Dict, List, Optional, Tuple

from nested_lookup import nested_lookup

# Accounts that require special Site Shield detection via advancedOverride XML
_SS_SPECIAL_ACCOUNTS = {"F-AC-1500804:1-2RBL"}
_SS_SEARCH_STRINGS = ["s607", "s198", "s479", "s42", "s697"]

_NO_DESCRIPTION = "(no description)"


def _has_key(d: dict, key: str) -> Any:
    """Recursively search nested dict for a key; returns the sub-dict or False."""
    return d if key in d else next(
        (_has_key(v, key) for v in d.values() if isinstance(v, dict)), False
    )


# --------------------------------------------------------- advanced metadata

def collect_advanced_metadata(rule_tree: dict) -> dict:
    """Walk the rule tree once and return the advanced_metadata block.

    Replaces has_adv_override / has_custom_override / count_custom_behaviors,
    which searched every name value in the tree by substring and looked for the
    override keys at every level. This walk is explicit and positional.

    Iterative by design. PAPI does not cap rule nesting and this runs against
    accounts we have never seen, so a recursion limit must not be able to fail
    an entire audit.

    Four private keys carry the exact values has_sro() used to search, so that
    function keeps byte-identical behaviour without re-walking the tree.
    """
    root = rule_tree.get("rules")
    if not isinstance(root, dict):
        root = {}

    advanced_behaviors: List[dict] = []
    advanced_matches: List[dict] = []
    custom_behaviors: List[dict] = []
    override_occurrences: List[dict] = []
    custom_override_occurrences: List[dict] = []
    override_xml_values: List[str] = []

    # (node, path tuple). Children are pushed reversed so popping yields
    # document order, which is the order the workbook and UI render in.
    stack: List[Tuple[dict, Tuple[str, ...]]] = [
        (root, (str(root.get("name") or "default"),))
    ]
    while stack:
        node, path = stack.pop()
        # Rule names are free text: they can be empty, duplicated between
        # siblings, or contain a slash. This is a human-readable locator only
        # and is never used as a key.
        rule_path = "/".join(path)

        # Collected at every rule, not just the default one. PAPI only allows
        # advancedOverride on the default rule, but the inventory has to be
        # complete: each occurrence is something that must be converted to a
        # custom behavior or custom override before Terraform can manage it.
        # Free here, since this walk already visits every node.
        node_override = node.get("advancedOverride")
        if isinstance(node_override, str) and node_override:
            override_occurrences.append({
                "rule_path": rule_path,
                "xml_chars": len(node_override),
                "position": "default" if len(path) == 1 else "nested",
            })
            override_xml_values.append(node_override)

        node_custom = node.get("customOverride")
        if isinstance(node_custom, dict) and node_custom.get("overrideId"):
            custom_override_occurrences.append({
                "rule_path": rule_path,
                "override_id": str(node_custom.get("overrideId")),
                "name": str(node_custom.get("name") or ""),
                "position": "nested",
            })

        behaviors = node.get("behaviors")
        if isinstance(behaviors, list):
            for behavior in behaviors:
                if not isinstance(behavior, dict):
                    continue
                name = behavior.get("name")
                options = behavior.get("options")
                if not isinstance(options, dict):
                    options = {}
                if name == "advanced":
                    xml = options.get("xml")
                    description = options.get("description")
                    description = str(description).strip() if description is not None else ""
                    advanced_behaviors.append({
                        "rule_path": rule_path,
                        "description": description or _NO_DESCRIPTION,
                        "xml_chars": len(xml) if isinstance(xml, str) else 0,
                    })
                elif name == "customBehavior":
                    behavior_id = options.get("behaviorId")
                    # An entry with no behaviorId is still a use; recording it
                    # as null surfaces it rather than silently dropping it.
                    custom_behaviors.append({
                        "rule_path": rule_path,
                        "behavior_id": str(behavior_id) if behavior_id else None,
                    })

        criteria = node.get("criteria")
        if isinstance(criteria, list):
            for criterion in criteria:
                if not isinstance(criterion, dict) or criterion.get("name") != "matchAdvanced":
                    continue
                options = criterion.get("options")
                if not isinstance(options, dict):
                    options = {}
                description = options.get("description")
                description = str(description).strip() if description is not None else ""
                xml = options.get("xml")
                advanced_matches.append({
                    "rule_path": rule_path,
                    "description": description or _NO_DESCRIPTION,
                    "xml_chars": len(xml) if isinstance(xml, str) else 0,
                })

        children = node.get("children")
        if isinstance(children, list):
            for child in reversed(children):
                if isinstance(child, dict):
                    stack.append((child, path + (str(child.get("name") or ""),)))

    # The legal position stays the headline number, so the existing
    # "Advanced Override" column keeps meaning what it always meant.
    # An empty string is absent, not present.
    override_xml = root.get("advancedOverride")
    override_xml = override_xml if isinstance(override_xml, str) else ""
    advanced_override = {"present": bool(override_xml), "xml_chars": len(override_xml)}
    nested_overrides = [o for o in override_occurrences if o["position"] == "nested"]

    # customOverride belongs at the response root; occurrences found on a rule
    # are kept too, for the same conversion-inventory reason.
    raw_custom_override = rule_tree.get("customOverride")
    custom_override: Optional[dict] = None
    if isinstance(raw_custom_override, dict) and raw_custom_override.get("overrideId"):
        custom_override = {
            "override_id": str(raw_custom_override.get("overrideId")),
            "name": str(raw_custom_override.get("name") or ""),
        }
        custom_override_occurrences.insert(0, {
            "rule_path": "", "override_id": custom_override["override_id"],
            "name": custom_override["name"], "position": "root",
        })
        override_xml_values.append(str(raw_custom_override))

    distinct = {b["behavior_id"] for b in custom_behaviors if b["behavior_id"]}
    counts = {
        "advanced_behaviors": len(advanced_behaviors),
        "advanced_matches": len(advanced_matches),
        "custom_behavior_uses": len(custom_behaviors),
        # Distinct counts identified behaviors only: a use carrying no
        # behaviorId has no identity to be distinct from.
        "custom_behaviors_distinct": len(distinct),
        "advanced_override": 1 if advanced_override["present"] else 0,
        "custom_override": 1 if custom_override else 0,
        # Occurrences off their legal position. Zero on every account sampled,
        # but counted rather than assumed, because a missed one is a property
        # that silently cannot be moved to Terraform.
        "advanced_override_nested": len(nested_overrides),
        "custom_override_nested": sum(
            1 for o in custom_override_occurrences if o["position"] == "nested"),
    }
    counts["advanced_override_total"] = len(override_occurrences)
    counts["custom_override_total"] = len(custom_override_occurrences)
    # Occurrences only. custom_behaviors_distinct is deliberately excluded: it
    # re-describes the same uses, so adding it would double-count them.
    counts["total"] = (
        counts["advanced_behaviors"]
        + counts["advanced_matches"]
        + counts["custom_behavior_uses"]
        + counts["advanced_override_total"]
        + counts["custom_override_total"]
    )

    return {
        "collected": True,
        "advanced_behaviors": advanced_behaviors,
        "advanced_matches": advanced_matches,
        "custom_behaviors": custom_behaviors,
        "advanced_override": advanced_override,
        "advanced_override_occurrences": override_occurrences,
        "custom_override": custom_override,
        "custom_override_occurrences": custom_override_occurrences,
        "counts": counts,
        # Every override payload in the tree, for has_sro(). Same coverage as
        # the old whole-tree nested_lookup, but gathered by the walk above, so
        # there is no second pass and no recursion limit to hit. Kept as a list
        # so no join separator can straddle two payloads and invent a match.
        "_override_payloads": override_xml_values,
    }


# Deprecated: superseded by collect_advanced_metadata(). Kept populated so
# nothing breaks mid-migration; remove once no caller reads them.
def has_adv_override(rule_tree: dict) -> bool:
    return nested_lookup("advancedOverride", rule_tree, with_keys=True).get("advancedOverride") is not None


def has_custom_override(rule_tree: dict) -> bool:
    return nested_lookup("customOverride", rule_tree, with_keys=True).get("customOverride") is not None


def count_custom_behaviors(rule_tree: dict) -> int:
    id_list = nested_lookup("name", rule_tree, with_keys=True)
    return sum("customBehavior" in v for values in id_list.values() for v in values)


def origin_hostnames(rule_tree: dict) -> List[str]:
    hosts: List[str] = []
    for origin in nested_lookup("hostname", rule_tree, with_keys=False):
        if "PMUSER" not in str(origin):
            hosts.append(origin)

    vars_map = nested_lookup("variables", rule_tree, with_keys=True)
    for items_list in vars_map.values():
        for items in items_list:
            for item in items:
                if "PMUSER_ORIGIN" in item.get("name", "") and item.get("value"):
                    hosts.append(item["value"])
    return hosts


def has_sro(rule_tree: dict, metadata: Optional[dict] = None) -> Any:
    """Returns the matching SRO search string or False.

    metadata is a collect_advanced_metadata() result. When supplied the tree is
    not re-walked: the walk already gathered every override payload, which is
    the same coverage the old whole-tree search had.
    """
    search_strings = [
        "<map>Cloud-Connect-a2466.akasrg.akamai.com</map>",
        "New-SRO-CW-Metadata-Feb 27, 2024",
    ]
    if metadata is not None:
        payloads = metadata.get("_override_payloads") or []
        for s in search_strings:
            if any(s in payload for payload in payloads):
                return s
        return False
    if has_adv_override(rule_tree):
        id_list = str(nested_lookup("advancedOverride", rule_tree, with_keys=True))
    elif has_custom_override(rule_tree):
        id_list = str(nested_lookup("customOverride", rule_tree, with_keys=True))
    else:
        return False

    for s in search_strings:
        if s in id_list:
            return s
    return False


def has_cw_qr(rule_tree: dict) -> List[str]:
    search_strings = ["dynamicThroughtputOptimization", "CloudWrapper-QuickRetry", "QuickRetry", "qr"]
    tree_str = str(rule_tree)
    result = ["False"]
    for s in search_strings:
        if s in tree_str:
            if result[0] == "False":
                result[0] = s
            else:
                result.append(s)
    return result


def rule_tree_complexity(rule_tree: dict) -> Dict[str, int]:
    """Count total rules (children nodes), max nesting depth, and total behaviors."""
    def _walk(node: dict, depth: int) -> Tuple[int, int, int]:
        children = node.get("children", [])
        behaviors = node.get("behaviors", [])
        total_rules = len(children)
        behavior_count = len(behaviors)
        max_depth = depth
        for child in children:
            cr, md, cb = _walk(child, depth + 1)
            total_rules += cr
            max_depth = max(max_depth, md)
            behavior_count += cb
        return total_rules, max_depth, behavior_count

    rules_node = rule_tree.get("rules", rule_tree)
    total, depth, behaviors = _walk(rules_node, 1)
    return {"total_rules": total, "max_depth": depth, "behavior_count": behaviors}


def extract_tls_settings(rule_tree: dict) -> str:
    """Find the minimum TLS version configured in the rule tree."""
    # Look for tls or related behavior options
    tree_str = str(rule_tree)
    for version in ["TLSv1.3", "TLSv1_3", "TLSv1.2", "TLSv1_2", "TLSv1.1", "TLSv1_1", "TLSv1", "TLSv1.0", "TLSv1_0"]:
        if version in tree_str:
            return version.replace("_", ".")
    return ""


def read_cpcode_list(rule_tree: dict, switch_key: str = "") -> Tuple:
    """
    Extract CP codes, site shield, and characteristics from the rule tree.
    Returns (cpcodeList, site_shield, custom_ss, client_chars, content_chars, origin_chars).
    """
    site_shield = ""
    custom_ss = ""
    client_characteristics = ""
    content_characteristics = ""
    origin_characteristics = ""
    cpcode_list = []

    # Special account: search advancedOverride XML for SS map names
    if switch_key in _SS_SPECIAL_ACCOUNTS:
        id_list = nested_lookup("advancedOverride", rule_tree, with_keys=True)
        for _id in id_list.values():
            for search_string in _SS_SEARCH_STRINGS:
                if search_string in str(_id[0]):
                    start = str(_id[0]).find(search_string)
                    custom_ss = str(_id[0])[start: start + len(search_string)]

    id_list = nested_lookup("behaviors", rule_tree, with_keys=True)
    for _id in id_list.values():
        for k in _id:
            if not isinstance(k, list):
                continue
            for v in k:
                if not isinstance(v, dict):
                    continue
                name = v.get("name", "")

                if name == "origin" and _has_key(v, "netStorage"):
                    cpc = nested_lookup("cpCode", v) or []
                    desc = nested_lookup("downloadDomainName", v) or []
                    prod = nested_lookup("originType", v) or []
                    cpcode_list.append((cpc, desc, prod))

                elif name == "cpCode" or _has_key(v, "cpCode"):
                    cpc = nested_lookup("id", v) or []
                    desc = nested_lookup("description", v) or []
                    prod_list = nested_lookup("products", v)
                    prod = prod_list[0] if prod_list else []
                    cpcode_list.append((cpc, desc, prod))

                elif name == "siteShield":
                    if nested_lookup("ssmap", v):
                        vals = nested_lookup("value", v)
                        if vals:
                            site_shield = vals[0]

                elif name == "contentCharacteristicsAMD":
                    content_characteristics = v.get("options", "")

                elif name == "clientCharacteristics":
                    client_characteristics = v.get("options", {}).get("country", "")

                elif name == "originCharacteristics":
                    origin_characteristics = v.get("options", "")

    return (
        cpcode_list,
        site_shield,
        custom_ss,
        client_characteristics,
        content_characteristics,
        origin_characteristics,
    )
