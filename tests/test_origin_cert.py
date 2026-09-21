"""
Tests for origin certificate service.
Run inside Docker: docker exec akamai-audit-celery-worker-1 python -m pytest /app/tests/test_origin_cert.py -v
"""
import json
import asyncio
from datetime import datetime, timezone, timedelta
from app.services.origin_cert_service import (
    extract_origins_from_rule_tree,
    assess_origin,
    generate_recommendations,
    _is_safe_destination,
    _parse_configured_cert,
    _describe_trust,
    _days_remaining,
    probe_origin_certificate,
)


# ---- Rule tree fixtures ----

def _make_rule_tree(behaviors=None, children=None, variables=None):
    tree = {
        "rules": {
            "name": "default",
            "behaviors": behaviors or [],
            "children": children or [],
        }
    }
    if variables:
        tree["rules"]["variables"] = variables
    return tree


def _origin_behavior(hostname="origin.example.com", **overrides):
    opts = {
        "originType": "CUSTOMER",
        "hostname": hostname,
        "httpPort": 80,
        "httpsPort": 443,
        "forwardHostHeader": "REQUEST_HOST_HEADER",
        "originSni": False,
        "verificationMode": "PLATFORM_SETTINGS",
        "originCertsToHonor": "STANDARD_CERTIFICATE_AUTHORITIES",
    }
    opts.update(overrides)
    return {"name": "origin", "options": opts}


# ---- Tests ----

def test_basic_origin_extraction():
    tree = _make_rule_tree(behaviors=[_origin_behavior("origin.example.com")])
    origins = extract_origins_from_rule_tree(
        tree, property_id="prp_1", property_name="Test",
        property_version=1, akamai_network="PRODUCTION",
    )
    assert len(origins) == 1
    o = origins[0]
    assert o["origin_hostname"] == "origin.example.com"
    assert o["property_id"] == "prp_1"
    assert o["akamai_network"] == "PRODUCTION"
    assert o["uses_https"] is True


def test_conditional_origin_in_child_rule():
    child = {
        "name": "API Route",
        "criteria": [{"name": "path", "options": {"values": ["/api/*"], "matchOperator": "MATCHES_ONE_OF"}}],
        "behaviors": [_origin_behavior("api-origin.example.com")],
        "children": [],
    }
    tree = _make_rule_tree(
        behaviors=[_origin_behavior("default-origin.example.com")],
        children=[child],
    )
    origins = extract_origins_from_rule_tree(tree)
    assert len(origins) == 2
    hostnames = {o["origin_hostname"] for o in origins}
    assert "default-origin.example.com" in hostnames
    assert "api-origin.example.com" in hostnames
    api_origin = [o for o in origins if o["origin_hostname"] == "api-origin.example.com"][0]
    assert "API Route" in api_origin["rule_path"]
    assert "/api/*" in api_origin["conditions"]


def test_netstorage_origin():
    behavior = {
        "name": "origin",
        "options": {
            "originType": "NET_STORAGE",
            "netStorage": {"downloadDomainName": "ns.example.akamaihd.net"},
        },
    }
    tree = _make_rule_tree(behaviors=[behavior])
    origins = extract_origins_from_rule_tree(tree)
    assert len(origins) == 1
    assert origins[0]["origin_hostname"] == "ns.example.akamaihd.net"
    assert origins[0]["uses_https"] is False


def test_variable_resolution():
    tree = _make_rule_tree(
        behaviors=[_origin_behavior("{{user.PMUSER_ORIGIN_HOST}}")],
        variables=[{"name": "PMUSER_ORIGIN_HOST", "value": "resolved.example.com"}],
    )
    origins = extract_origins_from_rule_tree(tree)
    assert len(origins) == 1
    assert origins[0]["resolved_hostname"] == "resolved.example.com"
    assert not origins[0]["coverage_gaps"]


def test_unresolved_variable():
    tree = _make_rule_tree(
        behaviors=[_origin_behavior("{{user.PMUSER_DYNAMIC}}")],
    )
    origins = extract_origins_from_rule_tree(tree)
    assert len(origins) == 1
    assert origins[0]["resolved_hostname"] is None
    assert any("Unresolved" in g for g in origins[0]["coverage_gaps"])


def test_sni_from_origin_hostname():
    tree = _make_rule_tree(behaviors=[
        _origin_behavior(
            "origin.example.com",
            originSni=True,
            forwardHostHeader="ORIGIN_HOSTNAME",
        ),
    ])
    origins = extract_origins_from_rule_tree(tree)
    assert origins[0]["sni_enabled"] is True
    assert origins[0]["effective_sni"] == "origin.example.com"


def test_sni_from_request_hostname():
    tree = _make_rule_tree(behaviors=[
        _origin_behavior(
            "origin.example.com",
            originSni=True,
            forwardHostHeader="REQUEST_HOST_HEADER",
        ),
    ])
    origins = extract_origins_from_rule_tree(tree)
    assert origins[0]["effective_sni"] == "__request_hostname__"
    assert any("varies per public hostname" in g for g in origins[0]["coverage_gaps"])


def test_custom_port():
    tree = _make_rule_tree(behaviors=[
        _origin_behavior("origin.example.com", httpsPort=8443, httpPort=8080),
    ])
    origins = extract_origins_from_rule_tree(tree)
    assert origins[0]["https_port"] == 8443
    assert origins[0]["http_port"] == 8080


def test_specific_certificate_pinning():
    tree = _make_rule_tree(behaviors=[
        _origin_behavior(
            "origin.example.com",
            verificationMode="CUSTOM",
            originCertsToHonor="SPECIFIC_CERTIFICATES",
            customCertificates=[{
                "subjectCN": "origin.example.com",
                "sha256Fingerprint": "abc123def456",
                "notAfter": "2026-12-31",
            }],
        ),
    ])
    origins = extract_origins_from_rule_tree(tree)
    o = origins[0]
    assert o["verification_mode"] == "CUSTOM"
    assert o["origin_certs_to_honor"] == "SPECIFIC_CERTIFICATES"
    assert len(o["configured_certificates"]) == 1
    assert o["configured_certificates"][0]["subject_cn"] == "origin.example.com"
    assert "pinning" in o["trust_description"].lower()


def test_custom_ca():
    tree = _make_rule_tree(behaviors=[
        _origin_behavior(
            "origin.example.com",
            verificationMode="CUSTOM",
            originCertsToHonor="CUSTOM_CERTIFICATE_AUTHORITIES",
            customCertificateAuthorities=[{
                "subjectCN": "Internal CA",
                "sha256Fingerprint": "ca_fingerprint_123",
            }],
        ),
    ])
    origins = extract_origins_from_rule_tree(tree)
    o = origins[0]
    assert len(o["configured_cas"]) == 1
    assert o["configured_cas"][0]["source"] == "configured_ca"


def test_combined_trust():
    tree = _make_rule_tree(behaviors=[
        _origin_behavior(
            "origin.example.com",
            verificationMode="CUSTOM",
            originCertsToHonor="STANDARD_AND_CUSTOM_CERTS",
            customCertificates=[{"subjectCN": "pin1", "sha256Fingerprint": "fp1"}],
            customCertificateAuthorities=[{"subjectCN": "ca1", "sha256Fingerprint": "fp2"}],
        ),
    ])
    origins = extract_origins_from_rule_tree(tree)
    assert "Standard + Custom" in origins[0]["trust_description"]


# ---- Safety tests ----

def test_blocked_destinations():
    assert _is_safe_destination("127.0.0.1", 443) == (False, "Address 127.0.0.1 in blocked network 127.0.0.0/8")
    assert _is_safe_destination("169.254.169.254", 80) == (False, "Address 169.254.169.254 in blocked network 169.254.0.0/16")
    assert _is_safe_destination("10.0.0.1", 443) == (False, "Address 10.0.0.1 in blocked network 10.0.0.0/8")
    assert _is_safe_destination("localhost", 443) == (False, "Blocked hostname: localhost")
    assert _is_safe_destination("metadata.google.internal", 80) == (False, "Blocked hostname: metadata.google.internal")
    safe, _ = _is_safe_destination("origin.example.com", 443)
    assert safe is True


def test_port_validation():
    assert _is_safe_destination("origin.example.com", 0) == (False, "Port 0 out of range")
    assert _is_safe_destination("origin.example.com", 99999) == (False, "Port 99999 out of range")


# ---- Assessment tests ----

def test_assess_expired_cert():
    origin = {
        "property_id": "prp_1",
        "property_name": "Test",
        "property_version": 1,
        "akamai_network": "PRODUCTION",
        "rule_path": "default",
        "origin_hostname": "origin.example.com",
        "resolved_hostname": "origin.example.com",
        "uses_https": True,
        "origin_certs_to_honor": "STANDARD_CERTIFICATE_AUTHORITIES",
        "configured_certificates": [],
        "configured_cas": [],
        "coverage_gaps": [],
    }
    live_probe = {
        "status": "ok",
        "certificates": [{
            "source": "live_leaf",
            "subject_cn": "origin.example.com",
            "sha256_fingerprint": "abc123",
            "days_remaining": -5,
            "is_expired": True,
        }],
        "probes": [{"certificates": [{"sha256_fingerprint": "abc123"}]}],
    }
    result = assess_origin(origin, live_probe)
    assert result["observation_status"] == "observed"
    assert any("Expired" in f["finding"] for f in result["findings"])
    assert any(f["severity"] == "critical" for f in result["findings"])


def test_assess_expiring_cert():
    origin = {
        "property_id": "prp_1",
        "property_name": "Test",
        "property_version": 1,
        "akamai_network": "PRODUCTION",
        "rule_path": "default",
        "origin_hostname": "origin.example.com",
        "resolved_hostname": "origin.example.com",
        "uses_https": True,
        "origin_certs_to_honor": "STANDARD_CERTIFICATE_AUTHORITIES",
        "configured_certificates": [],
        "configured_cas": [],
        "coverage_gaps": [],
    }
    live_probe = {
        "status": "ok",
        "certificates": [{
            "source": "live_leaf",
            "subject_cn": "origin.example.com",
            "sha256_fingerprint": "abc123",
            "days_remaining": 15,
        }],
        "probes": [{"certificates": [{"sha256_fingerprint": "abc123"}]}],
    }
    result = assess_origin(origin, live_probe)
    assert any("30 days" in f["finding"] for f in result["findings"])


def test_assess_http_only():
    origin = {
        "property_id": "prp_1",
        "property_name": "Test",
        "property_version": 1,
        "akamai_network": "PRODUCTION",
        "rule_path": "default",
        "origin_hostname": "origin.example.com",
        "uses_https": False,
        "configured_certificates": [],
        "configured_cas": [],
        "coverage_gaps": [],
    }
    result = assess_origin(origin, None)
    assert result["observation_status"] == "http_only"


def test_assess_unreachable():
    origin = {
        "property_id": "prp_1",
        "property_name": "Test",
        "property_version": 1,
        "akamai_network": "PRODUCTION",
        "rule_path": "default",
        "origin_hostname": "origin.example.com",
        "resolved_hostname": "origin.example.com",
        "uses_https": True,
        "origin_certs_to_honor": "STANDARD_CERTIFICATE_AUTHORITIES",
        "configured_certificates": [],
        "configured_cas": [],
        "coverage_gaps": [],
    }
    live_probe = {"status": "timeout", "error": "Connection timed out"}
    result = assess_origin(origin, live_probe)
    assert result["observation_status"] == "timeout"


def test_assess_mixed_endpoints():
    origin = {
        "property_id": "prp_1",
        "property_name": "Test",
        "property_version": 1,
        "akamai_network": "PRODUCTION",
        "rule_path": "default",
        "origin_hostname": "origin.example.com",
        "resolved_hostname": "origin.example.com",
        "uses_https": True,
        "origin_certs_to_honor": "STANDARD_CERTIFICATE_AUTHORITIES",
        "configured_certificates": [],
        "configured_cas": [],
        "coverage_gaps": [],
    }
    live_probe = {
        "status": "ok",
        "certificates": [
            {"source": "live_leaf", "sha256_fingerprint": "aaa", "days_remaining": 100, "subject_cn": "a"},
            {"source": "live_leaf", "sha256_fingerprint": "bbb", "days_remaining": 100, "subject_cn": "b"},
        ],
        "probes": [
            {"certificates": [{"sha256_fingerprint": "aaa"}]},
            {"certificates": [{"sha256_fingerprint": "bbb"}]},
        ],
    }
    result = assess_origin(origin, live_probe)
    assert any("Different certificates" in f["finding"] for f in result["findings"])


# ---- Recommendation tests ----

def test_recommendations_pinned_cert():
    origin = {
        "property_id": "prp_1",
        "property_name": "Test",
        "property_version": 1,
        "akamai_network": "PRODUCTION",
        "rule_path": "default",
        "origin_hostname": "origin.example.com",
        "resolved_hostname": "origin.example.com",
        "origin_certs_to_honor": "SPECIFIC_CERTIFICATES",
        "observation_status": "observed",
        "findings": [{
            "severity": "critical",
            "finding": "Expired certificate (live_leaf)",
            "evidence": "CN=origin.example.com, expired 5 days ago",
            "days_remaining": -5,
        }],
    }
    actions = generate_recommendations([origin])
    assert len(actions) >= 1
    assert "pinning" in actions[0]["recommendation"].lower()


def test_recommendations_unreachable():
    origin = {
        "property_id": "prp_1",
        "property_name": "Test",
        "property_version": 1,
        "akamai_network": "PRODUCTION",
        "rule_path": "default",
        "origin_hostname": "origin.example.com",
        "resolved_hostname": "origin.example.com",
        "origin_certs_to_honor": "STANDARD_CERTIFICATE_AUTHORITIES",
        "observation_status": "dns_failure",
        "observation_error": "Name resolution failed",
        "findings": [],
    }
    actions = generate_recommendations([origin])
    assert len(actions) == 1
    assert "unreachable" in actions[0]["finding"].lower()
    assert "authorized network" in actions[0]["recommendation"].lower()


# ---- days_remaining tests ----

def test_days_remaining_iso():
    future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    d = _days_remaining(future)
    assert d is not None
    assert 29 <= d <= 30


def test_days_remaining_invalid():
    assert _days_remaining("not a date") is None
    assert _days_remaining("") is None


# ---- configured cert parsing ----

def test_parse_configured_cert_fingerprint():
    entry = {
        "subjectCN": "test.example.com",
        "sha256Fingerprint": "abcdef123456",
        "notAfter": "2027-01-01",
    }
    result = _parse_configured_cert(entry, "configured_pin")
    assert result is not None
    assert result["subject_cn"] == "test.example.com"
    assert result["sha256_fingerprint"] == "abcdef123456"
    assert result["source"] == "configured_pin"


def test_parse_configured_cert_empty():
    assert _parse_configured_cert({}, "configured_pin") is None
    assert _parse_configured_cert(None, "configured_pin") is None


# ---- Live probe test (against known public endpoint) ----

def test_probe_live_certificate():
    """Probe a known public HTTPS endpoint to verify the probe machinery works."""
    result = asyncio.get_event_loop().run_until_complete(
        probe_origin_certificate("www.akamai.com", 443, timeout=15.0)
    )
    assert result["status"] == "ok", f"Probe failed: {result}"
    assert len(result["certificates"]) >= 1
    cert = result["certificates"][0]
    assert cert["source"] == "live_leaf"
    assert cert["subject_cn"] or cert["san"]
    assert cert["sha256_fingerprint"]
    assert cert["not_after"]
    assert cert["key_algorithm"]


def test_probe_blocked_destination():
    result = asyncio.get_event_loop().run_until_complete(
        probe_origin_certificate("127.0.0.1", 443)
    )
    assert result["status"] == "skipped"
