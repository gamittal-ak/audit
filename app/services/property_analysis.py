"""
Pure functions for analyzing an Akamai property rule tree.
No I/O — all functions take a pre-fetched rule_tree dict.
"""
from typing import Any, Dict, List, Tuple

from nested_lookup import nested_lookup

# Accounts that require special Site Shield detection via advancedOverride XML
_SS_SPECIAL_ACCOUNTS = {"F-AC-1500804:1-2RBL"}
_SS_SEARCH_STRINGS = ["s607", "s198", "s479", "s42", "s697"]


def _has_key(d: dict, key: str) -> Any:
    """Recursively search nested dict for a key; returns the sub-dict or False."""
    return d if key in d else next(
        (_has_key(v, key) for v in d.values() if isinstance(v, dict)), False
    )


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


def has_sro(rule_tree: dict) -> Any:
    """Returns the matching SRO search string or False."""
    search_strings = [
        "<map>Cloud-Connect-a2466.akasrg.akamai.com</map>",
        "New-SRO-CW-Metadata-Feb 27, 2024",
    ]
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
    # Look for 'tls' or related behavior options
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
