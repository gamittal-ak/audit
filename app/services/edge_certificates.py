"""CPS deployment evidence for edge HTTPS availability.

Negative evidence is scoped to a completely collected accessible account
inventory. It is never inferred from DNS suffixes or failed handshakes.
"""
import asyncio
from cryptography import x509
from cryptography.x509.oid import NameOID
from app.services.audit_log import event


def normal(value):
    name = str(value or "").strip().rstrip(".").lower()
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def covers(pattern, name):
    pattern, name = normal(pattern), normal(name)
    if pattern.startswith("*."):
        return name.count(".") == pattern.count(".") and name.endswith(pattern[1:])
    return name == pattern


def certificate_names(pem):
    cert = x509.load_pem_x509_certificate(pem.encode())
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    # Include legacy CN conservatively; this inventories configuration, not
    # browser trust or RFC hostname-validation success.
    names += [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return sorted({normal(n) for n in names if n})


async def collect_certificate_inventory(client, switch_key, contracts):
    contracts = sorted({str(c).removeprefix("ctr_") for c in contracts if c})
    result = {"complete": bool(contracts), "contracts": len(contracts), "enrollments": 0,
              "pending_names": [], "deployments": [], "errors": 0, "inaccessible_contracts": 0}
    enrollments = {}
    async def get_enrollments(contract):
        try:
            data = await client.get_cps_enrollments(switch_key, contract)
            rows = data["enrollments"]
            if not isinstance(rows, list):
                raise ValueError("Invalid enrollment list")
            for row in rows:
                if not isinstance(row, dict) or not str(row.get("id", "")).isdigit():
                    raise ValueError("Invalid enrollment ID")
                enrollments[str(row["id"])] = row
        except Exception as exc:
            result["complete"] = False
            result["errors"] += 1
            # CPS rejects contracts outside the API client's access control
            # group; certificates there stay unknown, so coverage is partial.
            if getattr(getattr(exc, "response", None), "status_code", None) in (400, 403):
                result["inaccessible_contracts"] += 1
    if contracts:
        event("Collecting CPS certificate deployments for edge TLS classification.")
    await asyncio.gather(*(get_enrollments(c) for c in contracts))
    result["enrollments"] = len(enrollments)
    completed = 0

    async def get_deployment(ident, enrollment):
        nonlocal completed
        try:
            csr = enrollment.get("csr") or {}
            if not isinstance(csr, dict) or not isinstance(csr.get("sans") or [], list):
                raise ValueError("Invalid enrollment identities")
            result["pending_names"].extend(normal(n) for n in [csr.get("cn")] + (csr.get("sans") or []) if n)
            data = await client.get_cps_deployments(switch_key, ident)
            for network in ("production", "staging"):
                if network not in data:
                    raise ValueError("Deployment network omitted")
                dep = data[network]
                if dep is None:
                    continue
                if not isinstance(dep, dict) or not all(k in dep for k in
                    ("primaryCertificate", "multiStackedCertificates", "networkConfiguration")):
                    raise ValueError("Invalid deployment")
                config = dep.get("networkConfiguration") or {}
                # dnsNames is null when a certificate has no SNI-only names.
                sni_names = config.get("dnsNames") or []
                if not isinstance(sni_names, list):
                    raise ValueError("Invalid SNI names")
                certificates = [dep.get("primaryCertificate")] + (dep.get("multiStackedCertificates") or [])
                for certificate in certificates:
                    if not certificate:
                        continue
                    pem = certificate.get("certificate")
                    if pem is None:
                        continue
                    names = certificate_names(pem)
                    secure_network = config.get("secureNetwork")
                    if secure_network not in ("standard-tls", "enhanced-tls") or not names:
                        raise ValueError("Deployment identity or network missing")
                    slots = enrollment.get("stagingSlots") if network == "staging" else enrollment.get("assignedSlots")
                    slots = slots or enrollment.get("slots") or []
                    result["deployments"].append({
                        "enrollment_id": ident, "network": network.upper(),
                        "tls_network": secure_network, "names": names,
                        "slots": [str(v) for v in slots],
                        "sni_names": [normal(v) for v in sni_names],
                        "expiry": certificate.get("expiry", ""),
                    })
        except Exception:
            result["complete"] = False
            result["errors"] += 1
        completed += 1
        if completed == len(enrollments) or completed % 20 == 0:
            event(f"Edge certificates: checked {completed}/{len(enrollments)} CPS enrollments.")
    await asyncio.gather(*(get_deployment(i, e) for i, e in enrollments.items()))
    result["pending_names"] = sorted(set(result["pending_names"]))
    event("Edge certificate inventory " + ("complete." if result["complete"] else "partially unavailable; HTTP-only classifications will remain unconfirmed."),
          "info" if result["complete"] else "warning")
    return result


def apply_certificate_evidence(row, edge, network, inventory):
    if not inventory or row["certificate_type"] == "Akamai shared":
        return row
    name = normal(row["hostname"])
    wanted = {"sTLS": "standard-tls", "eTLS": "enhanced-tls"}.get(row["tls_mode"])
    matches = []
    for cert in inventory["deployments"]:
        if cert["network"] != network or cert["tls_network"] != wanted:
            continue
        if wanted == "enhanced-tls" and (not edge.get("slotNumber") or str(edge["slotNumber"]) not in cert["slots"]):
            continue
        if any(covers(n, name) for n in cert["names"]):
            matches.append(cert)
    if matches:
        row["protocol"] = "CPS certificate deployed"
        row["certificate_status"] = "DEPLOYED (CPS)"
        row["cps_enrollment_ids"] = sorted({c["enrollment_id"] for c in matches})
        row["evidence"] += " Matching deployed CPS certificate: enrollment " + ", ".join(row["cps_enrollment_ids"]) + ". This is configuration evidence, not a live TLS validation."
    elif row["provisioning_type"] == "CPS_MANAGED" and row["protocol"] == "Unknown":
        planned = any(covers(n, name) for n in inventory["pending_names"])
        any_deployed = any(any(covers(n, name) for n in c["names"]) for c in inventory["deployments"])
        if planned or any_deployed:
            row["evidence"] += " A matching CPS enrollment or certificate exists, but deployment for this hostname/network was not established."
        elif (inventory["complete"] and wanted == "standard-tls" and name and "*" not in name
              and "." in name and not name.endswith((".akamaized.net", ".akamaihd.net",
                  ".akamai.net", ".edgesuite.net", ".edgekey.net"))):
            row["protocol"] = "HTTP-only (CPS inventory)"
            row["delivery_mode"] = "HTTP-only"
            row["evidence"] += (f" No matching certificate or enrollment found in the complete accessible CPS inventory "
                f"({inventory['contracts']} contracts, {inventory['enrollments']} enrollments). "
                "Classified HTTP-only within this inventory; certificates outside the API client's visibility are not ruled out.")
        else:
            reason = " CPS inventory is incomplete or the network cannot establish HTTP-only delivery."
            if inventory.get("inaccessible_contracts"):
                reason += (f" {inventory['inaccessible_contracts']} of {inventory['contracts']} contracts "
                           "are outside the API client's CPS access.")
            row["evidence"] += reason
    row["cps_coverage"] = "Complete accessible inventory" if inventory["complete"] else "Incomplete"
    return row
