"""Certificate lifecycle interpretation and grouped views of immutable audit evidence.

Policy: live leaf lifetimes <=31 days require renewal confirmation above 10 days.
At 8-10 days they warn; at <=7 days they remain critical. Pins and CA certificates
are never downgraded by this policy. Issuer/lifetime never proves auto-renewal.
"""
from copy import deepcopy
from datetime import datetime, timezone
import math

POLICY_VERSION = "origin-lifecycle-v1"
SHORT_LIFETIME_DAYS = 31
RENEWAL_WARNING_DAYS = 10
URGENT_DAYS = 7


def _date(value):
    if not value or not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except ValueError:
        return None


def certificate_assessment(cert, origin=None, at=None):
    origin = origin or {}
    start, end = _date(cert.get("not_before")), _date(cert.get("not_after"))
    observed = _date(cert.get("observation_time")) or _date(at)
    days = cert.get("days_remaining")
    if isinstance(days, bool) or not isinstance(days, (int, float)) or not math.isfinite(days):
        days = None
    if observed and end:
        days = math.floor((end - observed).total_seconds() / 86400)
    duration = (end - start).total_seconds() / 86400 if start and end and end > start else None
    source = cert.get("source", "unknown")
    trust = origin.get("origin_certs_to_honor", "")
    pinned = trust in ("SPECIFIC_CERTIFICATES", "CUSTOM_CERTIFICATES") or bool(origin.get("configured_certificates"))
    short = (
        source == "live_leaf" and cert.get("role") != "ca"
        and duration is not None and duration <= SHORT_LIFETIME_DAYS
        and not pinned
    )
    expired = (end <= observed) if end and observed else (cert.get("is_expired") is True or (days is not None and days < 0))
    not_yet = (start > observed) if start and observed else cert.get("is_not_yet_valid") is True
    code, severity, label = "valid", "none", "Outside expiry alert window"
    if expired:
        code, severity, label = "expired", "critical", "Expired certificate"
    elif not_yet:
        code, severity, label = "not_yet_valid", "critical", "Certificate not yet valid"
    elif days is None:
        code, severity, label = "unknown_validity", "info", "Certificate validity unavailable"
    elif days <= URGENT_DAYS:
        code, severity, label = "expiring_7d", "critical", "Certificate expiring within 7 days"
    elif short and days > RENEWAL_WARNING_DAYS:
        code, severity, label = "short_lived_review", "info", "Short-lived certificate — renewal status unverified"
    elif short:
        code, severity, label = "short_lived_warning", "warning", "Short-lived certificate — confirm renewal before expiry"
    elif days <= 30:
        code, severity, label = "expiring_30d", "warning", "Certificate expiring within 30 days"
    elif days <= 60:
        code, severity, label = "expiring_60d", "info", "Certificate expiring within 60 days"

    if code == "short_lived_review":
        recommendation = (
            "Confirm the origin owner and whether automated renewal is enabled and healthy. "
            "Check for renewal or domain-validation errors; recheck the presented certificate "
            "after the expected renewal. Short lifetime alone does not prove auto-renewal "
            "or require immediate manual replacement."
        )
    elif code == "short_lived_warning":
        recommendation = (
            "Confirm renewal status with the origin owner now and check for validation failures. "
            "Verify that a replacement is deployed before expiry; do not assume automated renewal will succeed."
        )
    elif code == "not_yet_valid":
        recommendation = "Verify certificate activation dates and clock accuracy with the origin owner; deploy a currently valid certificate if needed."
    elif code == "unknown_validity":
        recommendation = "Obtain the certificate validity dates from the origin owner; expiry could not be assessed."
    else:
        recommendation = (
            ("Verify replacement or renewal urgently with the origin owner. " if severity == "critical"
             else "Confirm the renewal plan with the origin owner. ")
            + "Ensure the replacement certificate and chain are deployed before expiry and match the required names."
        )
    # Retain trust-specific instructions even when expiry is urgent.
    if source == "configured_ca":
        recommendation += " Review the configured CA trust and any replacement CA before changing the origin chain."
    elif pinned:
        recommendation += (
            " This origin has specific certificate pinning: add the replacement pin alongside the existing certificate, "
            "activate overlapping trust, install and verify the replacement, then remove the old pin."
        )
    elif origin.get("configured_cas") or "CUSTOM" in trust or trust == "COMBO":
        recommendation += " Check that the replacement chain is accepted by the configured CA trust."

    note = (
        "Presented by the endpoint during the audit. Trust chain, hostname validation, "
        "Akamai delivery, and renewal automation were not verified."
        if source == "live_leaf" else
        "Read from origin configuration; this alone does not prove the certificate is currently presented."
    )
    evidence = f"CN={cert.get('subject_cn') or 'unknown'}"
    if start:
        evidence += f"; valid from {start.isoformat()}"
    if end:
        evidence += f"; expires {end.isoformat()}"
    if duration is not None:
        evidence += f"; lifetime {duration:.1f} days"
    if days is not None:
        evidence += f"; {days} days remaining at collection"
    if cert.get("sha256_fingerprint"):
        evidence += f"; SHA-256={cert['sha256_fingerprint']}"
    if source == "live_leaf":
        evidence += "; renewal status unverified"
    return {
        "code": code, "severity": severity, "finding": f"{label} ({source})",
        "label": label, "source": source, "days_remaining": days,
        "not_before": cert.get("not_before", ""), "not_after": cert.get("not_after", ""),
        "validity_days": round(duration, 2) if duration is not None else None,
        "is_short_lived": short, "is_expired": expired, "is_not_yet_valid": not_yet,
        "cert_fingerprint": cert.get("sha256_fingerprint", ""),
        "certificate_subject": cert.get("subject_cn", ""),
        "renewal_status": "unverified", "collection_note": note,
        "evidence": evidence, "recommendation": recommendation,
    }


def certificate_finding(cert, origin=None, at=None):
    assessment = certificate_assessment(cert, origin, at)
    return assessment if assessment["severity"] != "none" else None


def certificate_identity(cert, fallback):
    fingerprint = cert.get("sha256_fingerprint") or cert.get("cert_fingerprint")
    # Unknown identities must never collapse different certificates.
    return str(fingerprint).lower() if fingerprint else ("unknown", fallback)


def group_origin_actions(actions):
    groups = {}
    for index, action in enumerate(actions):
        identity = certificate_identity(action, index)
        if not action.get("cert_fingerprint") and action.get("finding", "").startswith("Origin unreachable ("):
            identity = ("unreachable", action.get("origin_hostname"), action.get("https_port"),
                        action.get("effective_sni"), action.get("evidence"))
        key = (
            identity, action.get("source", ""),
            action.get("code") or action.get("finding"), action.get("severity"),
            action.get("akamai_network"), action.get("recommendation"),
        )
        if key not in groups:
            groups[key] = dict(action, references=[], origin_hostnames=[], property_names=[], occurrence_count=0)
        grouped = groups[key]
        grouped["occurrence_count"] += 1
        ref = {field: action.get(field, "") for field in (
            "property_id", "property_name", "property_version", "akamai_network",
            "rule_path", "origin_hostname", "https_port", "effective_sni", "trust_description",
        )}
        if ref not in grouped["references"]:
            grouped["references"].append(ref)
        for field, value in (("origin_hostnames", action.get("origin_hostname", "")),
                             ("property_names", action.get("property_name", ""))):
            if value and value not in grouped[field]:
                grouped[field].append(value)
    order = {"critical": 0, "warning": 1, "info": 2}
    result = list(groups.values())
    for group in result:
        group["reference_count"] = len(group["references"])
    return sorted(result, key=lambda a: (order.get(a.get("severity"), 3),
                  a.get("days_remaining") if a.get("days_remaining") is not None else float("inf"),
                  a.get("certificate_subject", ""), a.get("origin_hostname", "")))


def findings_summary(groups, certificates):
    summary = {
        "critical": sum(a.get("severity") == "critical" for a in groups),
        "warning": sum(a.get("severity") == "warning" for a in groups),
        "renewal_review": sum(a.get("code") == "short_lived_review" for a in groups),
        "info": sum(a.get("severity") == "info" for a in groups),
        "total": len(groups),
        "references": sum(a.get("reference_count", 1) for a in groups),
    }
    unique = {}
    for index, cert in enumerate(certificates):
        key = certificate_identity(cert, index)
        unique.setdefault(key, cert)
    summary["unique_certificates"] = len(unique)
    summary["expired"] = sum(c.get("assessment", {}).get("is_expired", c.get("is_expired", False)) is True for c in unique.values())
    summary["due_30d"] = sum(
        isinstance(c.get("days_remaining"), (int, float)) and 0 <= c["days_remaining"] <= 30
        for c in unique.values()
    )
    return summary


def prepare_origin_report(report_data):
    """Reinterpret saved evidence at its original observation time, without I/O.

    Raw certificate and origin rows are retained. UI grouping is a separate view;
    Excel keeps one recommendation per rule reference.
    """
    from app.services.origin_cert_service import generate_recommendations
    data = dict(report_data)
    inventory = deepcopy(report_data.get("origin_inventory", []))
    at = report_data.get("audit_timestamp")
    reassessed = False
    unassessed_references = set()
    def reference_key(record):
        return (str(record.get("property_id", "")), record.get("property_version"),
                record.get("akamai_network"), record.get("rule_path"),
                record.get("resolved_hostname") or record.get("origin_hostname"))
    for origin in inventory:
        # Legacy origin inventories without certificate evidence retain their findings.
        cert_keys = ("live_certificates", "configured_certificates", "configured_cas")
        if not any(key in origin for key in cert_keys):
            unassessed_references.add(reference_key(origin))
            continue
        reassessed = True
        old = origin.get("findings", [])
        if not any(origin.get(key) for key in cert_keys):
            continue  # No certificate evidence: retain previously recorded findings.
        findings = [f for f in old if not f.get("cert_fingerprint") and not any(
            word in f.get("finding", "").lower() for word in ("expired certificate", "certificate expiring", "short-lived certificate", "certificate not yet valid")
        )]
        seen = set()
        for key in cert_keys:
            for index, cert in enumerate(origin.get(key, [])):
                finding = certificate_finding(cert, origin, at)
                if not finding:
                    continue
                identity = (certificate_identity(cert, (key, index)), finding["code"], cert.get("source"))
                if identity not in seen:
                    findings.append(finding)
                    seen.add(identity)
        origin["findings"] = findings
    if reassessed:
        actions = generate_recommendations(inventory)
        for action in report_data.get("origin_actions", []):
            if reference_key(action) in unassessed_references and action not in actions:
                actions.append(deepcopy(action))
    else:
        actions = deepcopy(report_data.get("origin_actions", []))

    # Match a flat certificate row to its rule contexts so configured pins are respected.
    contexts = {}
    for origin in inventory:
        key = (str(origin.get("property_id", "")), origin.get("akamai_network", ""),
               origin.get("resolved_hostname") or origin.get("origin_hostname", ""))
        contexts.setdefault(key, []).append(origin)
    certificates = deepcopy(report_data.get("origin_certificates", []))
    for cert in certificates:
        key = (str(cert.get("property_id", "")), cert.get("akamai_network", ""), cert.get("origin_hostname", ""))
        choices = contexts.get(key, [{}])
        assessments = [certificate_assessment(cert, origin, at) for origin in choices]
        severity_order = {"critical": 0, "warning": 1, "info": 2, "none": 3}
        assessment = min(assessments, key=lambda value: severity_order[value["severity"]])
        cert["assessment"] = assessment
        cert["days_remaining"] = assessment["days_remaining"]
        cert["is_expired"] = assessment["is_expired"]
        cert["is_not_yet_valid"] = assessment["is_not_yet_valid"]
    groups = group_origin_actions(actions)
    coverage = dict(report_data.get("origin_coverage", {}))
    if coverage or inventory:
        coverage["actions_critical"] = sum(a["severity"] == "critical" for a in actions)
        coverage["actions_warning"] = sum(a["severity"] == "warning" for a in actions)
        coverage["renewal_reviews"] = sum(a.get("code") == "short_lived_review" for a in actions)
    data.update(
        origin_inventory=inventory, origin_certificates=certificates, origin_actions=actions,
        origin_action_groups=groups, origin_findings_summary=findings_summary(groups, certificates),
        origin_coverage=coverage, origin_assessment_policy=POLICY_VERSION,
    )
    return data
