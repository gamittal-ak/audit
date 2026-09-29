"""Advanced and custom metadata: the walk, the catalog join, and the guards.

Rule-tree fixtures only; no network. Every count here was wrong or absent
before schema 4, so the assertions double as a record of what changed.
"""
import asyncio
from types import SimpleNamespace

import pytest

from app.services.custom_metadata import (
    NOT_IN_CATALOG,
    build_catalog_usage,
    fetch_catalog,
    prepare_metadata_report,
)
from app.services.property_analysis import (
    collect_advanced_metadata,
    count_custom_behaviors,
    has_adv_override,
    has_sro,
    read_cpcode_list,
)


def rule(name, behaviors=None, criteria=None, children=None, **extra):
    node = {"name": name, "behaviors": behaviors or [], "criteria": criteria or [],
            "children": children or []}
    node.update(extra)
    return node


def advanced(description, xml="<x/>"):
    return {"name": "advanced", "options": {"description": description, "xml": xml}}


def custom(behavior_id):
    return {"name": "customBehavior", "options": {"behaviorId": behavior_id}}


def tree(root, **extra):
    payload = {"rules": root}
    payload.update(extra)
    return payload


# ------------------------------------------------------------------ the walk

def test_advanced_behaviors_found_at_three_depths():
    root = rule("default", behaviors=[advanced("top level")], children=[
        rule("Key Files", children=[
            rule("First Request", children=[
                rule("ACL Check", behaviors=[advanced("Restrict tries to 1", "x" * 174)]),
            ]),
        ]),
        rule("Logging", behaviors=[advanced("Log Custom Details", "y" * 405)]),
    ])
    result = collect_advanced_metadata(tree(root))

    assert result["counts"]["advanced_behaviors"] == 3
    assert [b["rule_path"] for b in result["advanced_behaviors"]] == [
        "default",
        "default/Key Files/First Request/ACL Check",
        "default/Logging",
    ]
    assert [b["description"] for b in result["advanced_behaviors"]] == [
        "top level", "Restrict tries to 1", "Log Custom Details",
    ]
    assert [b["xml_chars"] for b in result["advanced_behaviors"]] == [4, 174, 405]


def test_uses_and_distinct_are_different_numbers():
    # Eight uses drawn from six distinct behaviors. One number alone misleads,
    # which is why the old single "Custom Behavior Count" column was replaced.
    root = rule("default", behaviors=[
        custom("cbe_1"), custom("cbe_1"), custom("cbe_1"),
        custom("cbe_2"), custom("cbe_3"),
    ], children=[
        rule("Deny by Location", behaviors=[custom("cbe_4"), custom("cbe_5")]),
        rule("Tagging", behaviors=[custom("cbe_6")]),
    ])
    counts = collect_advanced_metadata(tree(root))["counts"]

    assert counts["custom_behavior_uses"] == 8
    assert counts["custom_behaviors_distinct"] == 6


def test_rule_named_like_a_behavior_is_not_counted():
    # The substring bug: the old helper tested "customBehavior" against the
    # value of every name key in the tree, including rule names.
    root = rule("default", children=[rule("customBehavior cleanup")])
    payload = tree(root)

    assert count_custom_behaviors(payload) == 1          # the defect
    assert collect_advanced_metadata(payload)["counts"]["custom_behavior_uses"] == 0


def test_non_string_name_does_not_raise():
    root = rule("default", behaviors=[{"name": None, "options": {}}, custom("cbe_1")])
    payload = tree(root)

    with pytest.raises(TypeError):
        count_custom_behaviors(payload)                   # the defect
    assert collect_advanced_metadata(payload)["counts"]["custom_behavior_uses"] == 1


def test_empty_advanced_override_is_absent():
    result = collect_advanced_metadata(tree(rule("default", advancedOverride="")))

    assert result["advanced_override"] == {"present": False, "xml_chars": 0}
    assert result["counts"]["advanced_override"] == 0


def test_advanced_override_on_a_child_rule_is_recorded_not_dropped():
    # PAPI only allows advancedOverride on the default rule, so the headline
    # flag stays false -- but the occurrence is still inventoried. Each one has
    # to become a custom behavior or custom override before Terraform can
    # manage the property, so a missed one is a property that silently cannot
    # be converted.
    root = rule("default", children=[rule("Child", advancedOverride="<xml/>")])
    result = collect_advanced_metadata(tree(root))

    assert result["advanced_override"]["present"] is False
    assert result["counts"]["advanced_override"] == 0
    assert result["counts"]["advanced_override_nested"] == 1
    assert result["counts"]["advanced_override_total"] == 1
    assert result["advanced_override_occurrences"] == [
        {"rule_path": "default/Child", "xml_chars": 6, "position": "nested"},
    ]


def test_override_occurrences_record_both_positions():
    root = rule("default", advancedOverride="<top/>", children=[
        rule("Child", advancedOverride="<nested/>"),
    ])
    result = collect_advanced_metadata(tree(root))

    assert [o["position"] for o in result["advanced_override_occurrences"]] == [
        "default", "nested"]
    assert result["advanced_override"]["present"] is True
    assert result["counts"]["advanced_override_total"] == 2


def test_custom_override_is_read_from_the_response_root():
    payload = tree(rule("default"), customOverride={"overrideId": "cbo_9", "name": "Edge Override"})
    result = collect_advanced_metadata(payload)

    assert result["custom_override"] == {"override_id": "cbo_9", "name": "Edge Override"}
    assert result["counts"]["custom_override"] == 1


def test_custom_behavior_without_an_id_still_counts_as_a_use():
    root = rule("default", behaviors=[{"name": "customBehavior", "options": {}}])
    result = collect_advanced_metadata(tree(root))

    assert result["counts"]["custom_behavior_uses"] == 1
    assert result["counts"]["custom_behaviors_distinct"] == 0
    assert result["custom_behaviors"][0]["behavior_id"] is None


def test_advanced_matches_are_counted_on_the_criteria_side():
    root = rule("default", criteria=[
        {"name": "matchAdvanced", "options": {"description": "Edge case", "xml": "<m/>"}},
        {"name": "path", "options": {}},
    ])
    result = collect_advanced_metadata(tree(root))

    assert result["counts"]["advanced_matches"] == 1
    assert result["advanced_matches"][0]["description"] == "Edge case"


def test_total_counts_occurrences_without_double_counting_distinct():
    root = rule("default", behaviors=[advanced("a"), custom("cbe_1"), custom("cbe_1")],
                advancedOverride="<xml/>")
    counts = collect_advanced_metadata(tree(root))["counts"]

    # 1 advanced + 2 uses + 1 override. distinct (1) describes the same uses.
    assert counts["custom_behaviors_distinct"] == 1
    assert counts["total"] == 4


# --------------------------------------------------------------- robustness

def test_awkward_rule_names_still_produce_paths():
    # Rule names are free text: empty, duplicated between siblings, or
    # containing a slash. Paths are labels, never identity.
    root = rule("default", children=[
        rule("", behaviors=[advanced("blank name")]),
        rule("Dupe", behaviors=[advanced("first dupe")]),
        rule("Dupe", behaviors=[advanced("second dupe")]),
        rule("a/b", behaviors=[advanced("slash in name")]),
    ])
    result = collect_advanced_metadata(tree(root))

    assert [b["rule_path"] for b in result["advanced_behaviors"]] == [
        "default/", "default/Dupe", "default/Dupe", "default/a/b",
    ]
    assert result["counts"]["advanced_behaviors"] == 4


def test_deeply_nested_tree_does_not_hit_the_recursion_limit():
    # PAPI does not cap nesting. A recursive walk would fail the whole audit.
    depth = 2000
    node = rule("leaf", behaviors=[advanced("deepest")])
    for index in range(depth):
        node = rule(f"level-{index}", children=[node])
    root = rule("default", children=[node])

    result = collect_advanced_metadata(tree(root))

    assert result["counts"]["advanced_behaviors"] == 1
    assert result["advanced_behaviors"][0]["rule_path"].endswith("/leaf")
    # The walk must not reach for nested_lookup on the way out either.
    assert result["counts"]["total"] == 1


def test_missing_rules_key_is_handled():
    result = collect_advanced_metadata({})

    assert result["collected"] is True
    assert result["counts"]["total"] == 0


# ------------------------------------------------------- SRO regression guard

SRO_XML = "<map>Cloud-Connect-a2466.akasrg.akamai.com</map>"
DIRECTV = "F-AC-1500804:1-2RBL"


def test_has_sro_is_unchanged_when_handed_the_walk_result():
    # The one place this work could silently break something unrelated.
    for payload in (
        tree(rule("default", advancedOverride=SRO_XML + " s607 trailing")),
        tree(rule("default", children=[rule("Deep", children=[
            rule("Deeper", advancedOverride=SRO_XML)])])),
        tree(rule("default", advancedOverride="New-SRO-CW-Metadata-Feb 27, 2024")),
        tree(rule("default", advancedOverride="<xml>nothing special</xml>")),
        tree(rule("default")),
        tree(rule("default"), customOverride={"overrideId": "cbo_1", "name": SRO_XML}),
    ):
        metadata = collect_advanced_metadata(payload)
        assert has_sro(payload) == has_sro(payload, metadata)


def test_has_sro_still_finds_an_override_on_a_child_rule():
    # The walk collects overrides at every rule, so SRO detection keeps the
    # coverage the whole-tree nested_lookup had.
    payload = tree(rule("default", children=[rule("Child", advancedOverride=SRO_XML)]))
    metadata = collect_advanced_metadata(payload)

    assert has_sro(payload) == SRO_XML
    assert has_sro(payload, metadata) == SRO_XML
    assert has_adv_override(payload) is True


def test_site_shield_special_account_branch_still_matches():
    # DIRECTV is the only account that takes the _SS_SPECIAL_ACCOUNTS path.
    payload = tree(rule("default", advancedOverride="<edge>map s607 here</edge>"))

    _, _, custom_ss, _, _, _ = read_cpcode_list(payload, DIRECTV)
    assert custom_ss == "s607"

    # And the walk does not disturb it.
    collect_advanced_metadata(payload)
    _, _, again, _, _, _ = read_cpcode_list(payload, DIRECTV)
    assert again == "s607"


# ------------------------------------------------------------- catalog fetch

def catalog_row(identifier, id_field, name, **extra):
    row = {id_field: identifier, "name": name, "description": "desc",
           "status": "ACTIVE", "sharingLevel": "ACCOUNT", "xml": "<x/>",
           "updatedByUser": "someuser", "updatedDate": "2022-05-20T17:25:35Z",
           "approvedByUser": "approver"}
    row.update(extra)
    return row


class FakeClient:
    def __init__(self, behaviors=None, overrides=None,
                 behaviors_error=None, overrides_error=None):
        self._behaviors = behaviors or []
        self._overrides = overrides or []
        self._behaviors_error = behaviors_error
        self._overrides_error = overrides_error

    async def get_custom_behaviors(self, switch_key):
        if self._behaviors_error:
            raise self._behaviors_error
        return {"accountId": "act", "customBehaviors": self._behaviors}

    async def get_custom_overrides(self, switch_key):
        if self._overrides_error:
            raise self._overrides_error
        return {"accountId": "act", "customOverrides": self._overrides}


def forbidden():
    return SimpleNamespace(response=SimpleNamespace(status_code=403))


def http_error(status):
    error = RuntimeError("denied")
    error.response = SimpleNamespace(status_code=status)
    return error


def test_catalog_is_fetched_and_xml_is_measured_not_stored():
    client = FakeClient(behaviors=[catalog_row("cbe_1", "behaviorId", "Change Status",
                                               xml="z" * 412)])
    catalog = asyncio.run(fetch_catalog(client, "sk"))

    entry = catalog["custom_behaviors"][0]
    assert entry["id"] == "cbe_1"
    assert entry["name"] == "Change Status"
    assert entry["xml_chars"] == 412
    assert "xml" not in entry
    assert entry["updated_by"] == "someuser"
    assert catalog["accessible"] is True


def test_the_two_catalogs_fail_independently():
    client = FakeClient(behaviors=[catalog_row("cbe_1", "behaviorId", "Kept")],
                        overrides_error=http_error(403))
    catalog = asyncio.run(fetch_catalog(client, "sk"))

    assert catalog["behaviors"]["accessible"] is True
    assert len(catalog["custom_behaviors"]) == 1
    assert catalog["overrides"]["accessible"] is False
    assert catalog["overrides"]["error"] == "HTTP 403"
    assert catalog["accessible"] is False


def test_a_client_missing_the_endpoint_degrades_rather_than_raising():
    catalog = asyncio.run(fetch_catalog(SimpleNamespace(), "sk"))

    assert catalog["behaviors"]["accessible"] is False
    assert catalog["overrides"]["accessible"] is False
    assert catalog["custom_behaviors"] == []


def test_sharing_level_is_stored_verbatim():
    client = FakeClient(behaviors=[catalog_row("cbe_1", "behaviorId", "Shared",
                                               sharingLevel="CONTRACT")])
    catalog = asyncio.run(fetch_catalog(client, "sk"))

    # Read, not assumed: a CONTRACT value must surface, not be mis-scoped.
    assert catalog["custom_behaviors"][0]["sharing_level"] == "CONTRACT"


# -------------------------------------------------------------- catalog join

def report_with(*properties):
    return [{"groupname": "Example", "properties": list(properties)}]


def prop(identifier, name, **metadata):
    walked = collect_advanced_metadata(metadata.pop("payload"))
    return {"id": identifier, "name": name,
            "advanced_metadata": {k: v for k, v in walked.items()
                                  if not k.startswith("_")}}


def test_join_reports_uses_properties_and_unused_entries():
    client = FakeClient(behaviors=[
        catalog_row("cbe_used", "behaviorId", "Used behavior"),
        catalog_row("cbe_idle", "behaviorId", "Quick retry with ALT map"),
    ])
    catalog = asyncio.run(fetch_catalog(client, "sk"))
    groups = report_with(
        prop("1", "first", payload=tree(rule("default", behaviors=[
            custom("cbe_used"), custom("cbe_used")]))),
        prop("2", "second", payload=tree(rule("default", behaviors=[custom("cbe_used")]))),
    )

    catalog = build_catalog_usage(catalog, groups)
    used, idle = catalog["custom_behaviors"]

    assert used["id"] == "cbe_used"
    assert used["use_count"] == 3
    assert used["property_count"] == 2
    assert used["properties"] == [{"id": "1", "name": "first", "uses": 2},
                                  {"id": "2", "name": "second", "uses": 1}]
    assert idle["use_count"] == 0
    assert catalog["summary"]["in_use"] == 1
    assert catalog["summary"]["unused"] == 1
    assert catalog["summary"]["properties_with_advanced_metadata"] == 2


def test_behavior_used_but_absent_from_the_catalog_is_surfaced():
    catalog = asyncio.run(fetch_catalog(FakeClient(), "sk"))
    groups = report_with(prop("1", "first", payload=tree(
        rule("default", behaviors=[custom("cbe_ghost")]))))

    catalog = build_catalog_usage(catalog, groups)
    entry = next(e for e in catalog["custom_behaviors"] if e["id"] == "cbe_ghost")

    assert entry["name"] == NOT_IN_CATALOG
    assert entry["use_count"] == 1


def test_advanced_behaviors_group_by_description_across_properties():
    catalog = asyncio.run(fetch_catalog(FakeClient(), "sk"))
    groups = report_with(
        prop("1", "first", payload=tree(rule("default", behaviors=[
            advanced("Log Custom Details"), advanced("log custom details")]))),
        prop("2", "second", payload=tree(rule("default", behaviors=[
            advanced("  Log Custom Details  ")]))),
    )

    catalog = build_catalog_usage(catalog, groups)
    group = catalog["advanced_behavior_groups"][0]

    # Grouped on the trimmed, case-folded description; Akamai assigns no ID.
    assert group["use_count"] == 3
    assert group["property_count"] == 2
    assert catalog["summary"]["advanced_behavior_distinct"] == 1
    assert catalog["summary"]["advanced_behavior_uses"] == 3


def test_custom_overrides_resolve_to_names():
    client = FakeClient(overrides=[catalog_row("cbo_1", "overrideId", "Tubi Override")])
    catalog = asyncio.run(fetch_catalog(client, "sk"))
    groups = report_with(prop("1", "first", payload=tree(
        rule("default"), customOverride={"overrideId": "cbo_1", "name": "Tubi Override"})))

    catalog = build_catalog_usage(catalog, groups)

    assert catalog["custom_overrides"][0]["name"] == "Tubi Override"
    assert catalog["custom_overrides"][0]["use_count"] == 1
    assert catalog["summary"]["overrides_in_use"] == 1
    assert catalog["summary"]["overrides_unused"] == 0


# -------------------------------------------------- the empty account, and old reports

def test_empty_account_is_a_clean_result_not_a_broken_one():
    # Half of all sampled accounts have no advanced or custom metadata at all.
    catalog = asyncio.run(fetch_catalog(FakeClient(), "sk"))
    groups = report_with(prop("1", "plain", payload=tree(rule("default"))))

    catalog = build_catalog_usage(catalog, groups)
    summary = catalog["summary"]

    assert summary["empty"] is True
    assert summary["catalog_size"] == 0
    assert summary["override_catalog_size"] == 0
    assert summary["properties_with_advanced_metadata"] == 0
    assert catalog["advanced_behavior_groups"] == []


def test_an_account_with_only_a_catalog_is_not_empty():
    client = FakeClient(behaviors=[catalog_row("cbe_1", "behaviorId", "Defined but unused")])
    catalog = asyncio.run(fetch_catalog(client, "sk"))
    catalog = build_catalog_usage(catalog, report_with(
        prop("1", "plain", payload=tree(rule("default")))))

    assert catalog["summary"]["empty"] is False
    assert catalog["summary"]["unused"] == 1


def test_schema_three_reports_read_as_not_collected():
    data = prepare_metadata_report({
        "schema_version": 3,
        "report": [{"properties": [{"id": "1", "advanced_metadata": {"counts": {}}}]}],
    })

    assert data["advanced_metadata_available"] is False
    # Never show a zero we did not measure.
    assert "advanced_metadata" not in data["report"][0]["properties"][0]
    assert data["custom_metadata_catalog"] == {}


def test_schema_four_reports_are_available():
    data = prepare_metadata_report({
        "schema_version": 4,
        "custom_metadata_catalog": {"summary": {"empty": True}},
        "report": [],
    })

    assert data["advanced_metadata_available"] is True


def test_missing_schema_version_reads_as_not_collected():
    assert prepare_metadata_report({"report": []})["advanced_metadata_available"] is False
