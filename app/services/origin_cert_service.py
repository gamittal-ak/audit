"""
Origin certificate discovery, inspection, and assessment service.
Collects origin configurations from rule trees, probes live certificates,
parses configured certificates, and generates findings/recommendations.
"""
import asyncio
import hashlib
import ipaddress
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


# ------------------------------------------------------------------ origin extraction

def extract_origins_from_rule_tree(
    rule_tree: dict,
    property_id: str = "",
    property_name: str = "",
    property_version: int = 0,
    akamai_network: str = "",
    group_id: str = "",
    group_name: str = "",
    contract_id: str = "",
) -> List[Dict[str, Any]]:
    origins = []
    variables = _extract_variables(rule_tree)
    rules_node = rule_tree.get("rules", rule_tree)
    _walk_rules(
        rules_node, [], origins, variables,
        property_id, property_name, property_version,
        akamai_network, group_id, group_name, contract_id,
    )
    return origins


def _extract_variables(rule_tree: dict) -> Dict[str, str]:
    variables = {}
    for var in rule_tree.get("rules", {}).get("variables", []):
        name = var.get("name", "")
        value = var.get("value", "")
        if name:
            variables[name] = value
    return variables


def _resolve_variable(value: str, variables: Dict[str, str]) -> Tuple[str, bool]:
    if not value:
        return value, True
    result = value
    all_resolved = True
    for match in re.finditer(r'\{\{user\.(\w+)\}\}', value):
        var_name = match.group(1)
        if var_name in variables and variables[var_name]:
            result = result.replace(match.group(0), variables[var_name])
        else:
            all_resolved = False
    if "PMUSER_" in value:
        for var_name, var_value in variables.items():
            if var_name in value and var_value:
                result = result.replace("{{user." + var_name + "}}", var_value)
    if "{{" in result:
        all_resolved = False
    return result, all_resolved


def _walk_rules(
    node, path, origins, variables,
    property_id, property_name, property_version,
    akamai_network, group_id, group_name, contract_id,
):
    rule_name = node.get("name", "Unknown")
    current_path = path + [rule_name]
    criteria = node.get("criteria", [])
    conditions = _summarize_criteria(criteria)

    for behavior in node.get("behaviors", []):
        if behavior.get("name") == "origin":
            opts = behavior.get("options", {})
            origin = _parse_origin_behavior(
                opts, variables, current_path, conditions,
                property_id, property_name, property_version,
                akamai_network, group_id, group_name, contract_id,
            )
            if origin:
                origins.append(origin)

    for child in node.get("children", []):
        _walk_rules(
            child, current_path, origins, variables,
            property_id, property_name, property_version,
            akamai_network, group_id, group_name, contract_id,
        )


def _summarize_criteria(criteria: list) -> str:
    if not criteria:
        return ""
    parts = []
    for c in criteria:
        name = c.get("name", "")
        opts = c.get("options", {})
        if name == "path":
            values = opts.get("values", [])
            op = opts.get("matchOperator", "")
            parts.append("Path %s %s" % (op, ", ".join(str(v) for v in values)))
        elif name == "hostname":
            values = opts.get("values", [])
            parts.append("Hostname: %s" % ", ".join(str(v) for v in values))
        elif name == "requestHeader":
            hdr = opts.get("headerName", "")
            values = opts.get("values", [])
            parts.append("Header %s: %s" % (hdr, ", ".join(str(v) for v in values)))
        else:
            parts.append(name)
    return "; ".join(parts)


def _parse_origin_behavior(
    opts, variables, rule_path, conditions,
    property_id, property_name, property_version,
    akamai_network, group_id, group_name, contract_id,
):
    origin_type = opts.get("originType", "CUSTOMER")
    hostname = opts.get("hostname", "")
    if not hostname and origin_type == "NET_STORAGE":
        ns = opts.get("netStorage", {})
        hostname = ns.get("downloadDomainName", "")
    if not hostname:
        return None

    resolved_hostname, was_resolved = _resolve_variable(hostname, variables)
    coverage_gaps = []
    if not was_resolved:
        coverage_gaps.append("Unresolved variable in hostname: %s" % hostname)

    http_port = opts.get("httpPort", 80)
    https_port = opts.get("httpsPort", 443)
    uses_https = origin_type == "CUSTOMER"

    fhh = opts.get("forwardHostHeader", "REQUEST_HOST_HEADER")
    custom_fhh = opts.get("customForwardHostHeader", "")

    sni_enabled = opts.get("originSni", False)
    effective_sni = None
    if sni_enabled and uses_https:
        if fhh == "ORIGIN_HOSTNAME":
            effective_sni = resolved_hostname if was_resolved else hostname
        elif fhh == "CUSTOM" and custom_fhh:
            effective_sni = custom_fhh
        elif fhh == "REQUEST_HOST_HEADER":
            effective_sni = "__request_hostname__"
            coverage_gaps.append(
                "SNI derived from request hostname; varies per public hostname"
            )

    verification_mode = opts.get("verificationMode", "PLATFORM_SETTINGS")
    origin_certs = opts.get("originCertsToHonor", "STANDARD_CERTIFICATE_AUTHORITIES")
    custom_cn_values = opts.get("customValidCnValues", [])
    if isinstance(custom_cn_values, str):
        custom_cn_values = [custom_cn_values] if custom_cn_values else []

    configured_certs = []
    for entry in opts.get("customCertificates", []):
        parsed = _parse_configured_cert(entry, "configured_pin")
        if parsed:
            configured_certs.append(parsed)

    configured_cas = []
    for entry in opts.get("customCertificateAuthorities", []):
        parsed = _parse_configured_cert(entry, "configured_ca")
        if parsed:
            configured_cas.append(parsed)

    std_cas = opts.get("standardCertificateAuthorities", [])
    trust_description = _describe_trust(
        verification_mode, origin_certs, configured_certs,
        configured_cas, std_cas, custom_cn_values,
    )

    return {
        "property_id": property_id,
        "property_name": property_name,
        "property_version": property_version,
        "akamai_network": akamai_network,
        "group_id": group_id,
        "group_name": group_name,
        "contract_id": contract_id,
        "rule_path": " > ".join(rule_path),
        "conditions": conditions,
        "origin_type": origin_type,
        "origin_hostname": hostname,
        "resolved_hostname": resolved_hostname if was_resolved else None,
        "http_port": http_port,
        "https_port": https_port,
        "uses_https": uses_https,
        "forward_host_header": fhh,
        "custom_forward_host_header": custom_fhh or None,
        "sni_enabled": sni_enabled,
        "effective_sni": effective_sni,
        "verification_mode": verification_mode,
        "origin_certs_to_honor": origin_certs,
        "trust_description": trust_description,
        "custom_cn_values": custom_cn_values,
        "configured_certificates": configured_certs,
        "configured_cas": configured_cas,
        "standard_cas": std_cas,
        "coverage_gaps": coverage_gaps,
    }


def _parse_configured_cert(entry: dict, source: str) -> Optional[Dict[str, Any]]:
    if not entry:
        return None
    result = {
        "source": source,
        "collection_method": "config_fingerprint",
    }
    pem_data = entry.get("pemEncodedCert") or entry.get("pem")
    if pem_data and HAS_CRYPTOGRAPHY:
        try:
            parsed = _parse_pem_to_dict(pem_data)
            if parsed:
                parsed["source"] = source
                parsed["collection_method"] = "config_pem_parse"
                return parsed
        except Exception as e:
            result["parse_error"] = str(e)

    result["subject_cn"] = entry.get("subjectCN", entry.get("cn", ""))
    result["sha256_fingerprint"] = entry.get("sha256Fingerprint", "")
    if not result["sha256_fingerprint"]:
        for key in entry:
            if "fingerprint" in key.lower():
                result["sha256_fingerprint"] = "%s:%s" % (key, entry[key])
                break
    result["not_before"] = entry.get("notBefore", "")
    result["not_after"] = entry.get("notAfter", entry.get("expiresOn", ""))
    result["issuer"] = entry.get("issuerRDN", entry.get("issuer", ""))
    if result["not_after"]:
        result["days_remaining"] = _days_remaining(result["not_after"])
        result["is_expired"] = (
            result.get("days_remaining") is not None
            and result["days_remaining"] < 0
        )
    if not result["subject_cn"] and not result["sha256_fingerprint"]:
        return None
    return result


def _describe_trust(
    verification_mode, origin_certs, configured_certs,
    configured_cas, std_cas, custom_cn_values,
):
    parts = []
    if verification_mode == "PLATFORM_SETTINGS":
        parts.append("Platform-managed verification")
    elif verification_mode == "THIRD_PARTY":
        parts.append("Third-party CA verification")
    elif verification_mode == "CUSTOM":
        parts.append("Custom verification")
    else:
        parts.append("Verification: %s" % verification_mode)

    if origin_certs == "STANDARD_CERTIFICATE_AUTHORITIES":
        parts.append("Standard CAs")
    elif origin_certs == "CUSTOM_CERTIFICATE_AUTHORITIES":
        parts.append("Custom CAs (%d configured)" % len(configured_cas))
    elif origin_certs == "COMBO":
        parts.append("Standard + Custom CAs (%d custom)" % len(configured_cas))
    elif origin_certs in ("STANDARD_PLUS_CUSTOM", "STANDARD_AND_CUSTOM_CERTS"):
        parts.append(
            "Standard + Custom (%d pins, %d CAs)"
            % (len(configured_certs), len(configured_cas))
        )
    elif origin_certs in ("SPECIFIC_CERTIFICATES", "CUSTOM_CERTIFICATES"):
        parts.append(
            "Specific certificate pinning (%d pins)" % len(configured_certs)
        )

    if custom_cn_values:
        parts.append("CN match: %s" % ", ".join(custom_cn_values))
    return "; ".join(parts)


# ------------------------------------------------------------------ certificate probing

def _is_safe_destination(hostname: str, port: int) -> Tuple[bool, str]:
    if not (1 <= port <= 65535):
        return False, "Port %d out of range" % port
    try:
        addr = ipaddress.ip_address(hostname)
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                return False, "Address %s in blocked network %s" % (hostname, net)
        return True, ""
    except ValueError:
        pass
    lower = hostname.lower()
    if lower in ("localhost", "localhost.localdomain", "metadata.google.internal"):
        return False, "Blocked hostname: %s" % hostname
    if lower.endswith(".internal") or lower.endswith(".local"):
        return False, "Blocked hostname pattern: %s" % hostname
    return True, ""


async def probe_origin_certificate(
    hostname: str,
    port: int = 443,
    sni: str = None,
    timeout: float = 10.0,
    semaphore: asyncio.Semaphore = None,
) -> Dict[str, Any]:
    effective_sni = sni or hostname
    safe, reason = _is_safe_destination(hostname, port)
    if not safe:
        return {
            "status": "skipped",
            "reason": reason,
            "hostname": hostname,
            "port": port,
        }

    async def _do():
        return await asyncio.to_thread(
            _probe_sync, hostname, port, effective_sni, timeout
        )

    if semaphore:
        async with semaphore:
            return await _do()
    return await _do()


def _probe_sync(
    hostname: str, port: int, sni: str, timeout: float
) -> Dict[str, Any]:
    result = {
        "hostname": hostname,
        "port": port,
        "sni": sni,
        "observation_time": datetime.now(timezone.utc).isoformat(),
        "certificates": [],
        "status": "error",
    }
    try:
        addr_infos = socket.getaddrinfo(
            hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        result["status"] = "dns_failure"
        result["error"] = str(e)
        return result
    except socket.timeout:
        result["status"] = "dns_timeout"
        result["error"] = "DNS resolution timed out"
        return result

    if not addr_infos:
        result["status"] = "dns_failure"
        result["error"] = "No addresses resolved"
        return result

    safe_addrs = []
    for ai in addr_infos:
        addr = ai[4][0]
        try:
            ip = ipaddress.ip_address(addr)
            if not any(ip in net for net in _BLOCKED_NETWORKS):
                safe_addrs.append(ai)
        except ValueError:
            safe_addrs.append(ai)

    if not safe_addrs:
        result["status"] = "skipped"
        result["error"] = "All resolved addresses in blocked networks"
        return result

    seen_addrs = set()
    probes = []
    for ai in safe_addrs:
        family = ai[0]
        addr = ai[4][0]
        if addr in seen_addrs:
            continue
        seen_addrs.add(addr)
        p = _probe_single_address(addr, port, sni, timeout, family)
        p["resolved_address"] = addr
        probes.append(p)

    result["probes"] = probes
    all_certs = []
    any_success = False
    for p in probes:
        if p.get("certificates"):
            all_certs.extend(p["certificates"])
            any_success = True
    result["certificates"] = all_certs
    if any_success:
        result["status"] = "ok"
    elif probes:
        result["status"] = probes[0].get("status", "error")
        result["error"] = probes[0].get("error", "Unknown error")
    return result


def _probe_single_address(addr, port, sni, timeout, family):
    result = {"status": "error", "resolved_address": addr}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((addr, port))
        ssock = ctx.wrap_socket(sock, server_hostname=sni)
        der_cert = ssock.getpeercert(binary_form=True)
        if der_cert and HAS_CRYPTOGRAPHY:
            parsed = _parse_der_to_dict(der_cert, "live_leaf", 0)
            if parsed:
                parsed["probe_address"] = addr
                parsed["probe_port"] = port
                parsed["probe_sni"] = sni
                result["certificates"] = [parsed]
                result["status"] = "ok"
        elif der_cert:
            result["certificates"] = [{
                "source": "live_leaf",
                "collection_method": "tls_handshake_no_verify",
                "probe_address": addr,
                "sha256_fingerprint": hashlib.sha256(der_cert).hexdigest(),
            }]
            result["status"] = "ok"
        ssock.close()
    except ssl.SSLError as e:
        result["status"] = "tls_error"
        result["error"] = str(e)
    except socket.timeout:
        result["status"] = "timeout"
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["status"] = "connection_refused"
        result["error"] = "Connection refused"
    except OSError as e:
        result["status"] = "connection_error"
        result["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return result


# ------------------------------------------------------------------ X.509 parsing

def _parse_der_to_dict(der_data, source, depth):
    if not HAS_CRYPTOGRAPHY:
        return None
    try:
        cert = x509.load_der_x509_certificate(der_data)
    except Exception:
        return None
    return _x509_to_dict(cert, source, depth, "tls_handshake_no_verify")


def _parse_pem_to_dict(pem_data):
    if not HAS_CRYPTOGRAPHY:
        return None
    if isinstance(pem_data, str):
        pem_data = pem_data.encode()
    cert = x509.load_pem_x509_certificate(pem_data)
    return _x509_to_dict(cert, "configured", 0, "config_pem_parse")


def _x509_to_dict(cert, source, depth, method):
    now = datetime.now(timezone.utc)
    subject_cn = ""
    subject_parts = []
    try:
        for attr in cert.subject:
            subject_parts.append("%s=%s" % (attr.oid._name, attr.value))
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                subject_cn = attr.value
    except Exception:
        pass

    issuer_cn = ""
    issuer_org = ""
    issuer_parts = []
    try:
        for attr in cert.issuer:
            issuer_parts.append("%s=%s" % (attr.oid._name, attr.value))
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                issuer_cn = attr.value
            if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                issuer_org = attr.value
    except Exception:
        pass

    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        pass

    serial = format(cert.serial_number, "X")
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    if hasattr(cert, "not_valid_before_utc"):
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    else:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    days_remaining = (not_after - now).days

    key_algorithm = ""
    key_size = ""
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_algorithm = "RSA"
        key_size = str(pub_key.key_size)
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_algorithm = "ECDSA"
        key_size = pub_key.curve.name
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        key_algorithm = "Ed25519"
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        key_algorithm = "Ed448"
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_algorithm = "DSA"
        key_size = str(pub_key.key_size)

    sig_algo = ""
    try:
        sig_algo = cert.signature_algorithm_oid._name
    except Exception:
        pass

    is_self_signed = cert.issuer == cert.subject
    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bc.value.ca
    except Exception:
        pass

    return {
        "source": source,
        "collection_method": method,
        "subject_cn": subject_cn,
        "subject": ", ".join(subject_parts),
        "san": sans,
        "issuer": ", ".join(issuer_parts),
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
        "serial_number": serial,
        "sha256_fingerprint": fingerprint,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "is_expired": days_remaining < 0,
        "is_not_yet_valid": now < not_before,
        "role": "ca" if is_ca else "leaf",
        "key_algorithm": key_algorithm,
        "key_size": key_size,
        "signature_algorithm": sig_algo,
        "is_self_signed": is_self_signed,
        "chain_depth": depth,
        "observation_time": now.isoformat(),
    }


def _days_remaining(date_str):
    now = datetime.now(timezone.utc)
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d",
        "%b %d %H:%M:%S %Y GMT",
    ):
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (dt - now).days
        except ValueError:
            continue
    return None


# ------------------------------------------------------------------ assessment

def assess_origin(origin, live_probe):
    findings = []
    if not origin.get("uses_https"):
        origin["observation_status"] = "http_only"
    elif live_probe is None:
        origin["observation_status"] = "not_probed"
    elif live_probe.get("status") == "ok":
        origin["observation_status"] = "observed"
    else:
        origin["observation_status"] = live_probe.get("status", "error")
        origin["observation_error"] = live_probe.get("error", "")

    live_certs = []
    if live_probe and live_probe.get("certificates"):
        live_certs = live_probe["certificates"]

    all_certs = (
        live_certs
        + origin.get("configured_certificates", [])
        + origin.get("configured_cas", [])
    )

    for cert in all_certs:
        days = cert.get("days_remaining")
        if days is None:
            continue
        src = cert.get("source", "unknown")
        cn = cert.get("subject_cn", "unknown")
        fp = cert.get("sha256_fingerprint", "")[:16]
        if days < 0:
            findings.append({
                "severity": "critical",
                "finding": "Expired certificate (%s)" % src,
                "evidence": "CN=%s, expired %d days ago, fingerprint=%s..."
                % (cn, abs(days), fp),
                "days_remaining": days,
                "cert_fingerprint": cert.get("sha256_fingerprint", ""),
            })
        elif days <= 7:
            findings.append({
                "severity": "critical",
                "finding": "Certificate expiring within 7 days (%s)" % src,
                "evidence": "CN=%s, %d days remaining, fingerprint=%s..."
                % (cn, days, fp),
                "days_remaining": days,
                "cert_fingerprint": cert.get("sha256_fingerprint", ""),
            })
        elif days <= 30:
            findings.append({
                "severity": "warning",
                "finding": "Certificate expiring within 30 days (%s)" % src,
                "evidence": "CN=%s, %d days remaining, fingerprint=%s..."
                % (cn, days, fp),
                "days_remaining": days,
                "cert_fingerprint": cert.get("sha256_fingerprint", ""),
            })
        elif days <= 60:
            findings.append({
                "severity": "info",
                "finding": "Certificate expiring within 60 days (%s)" % src,
                "evidence": "CN=%s, %d days remaining, fingerprint=%s..."
                % (cn, days, fp),
                "days_remaining": days,
                "cert_fingerprint": cert.get("sha256_fingerprint", ""),
            })

    if live_probe and live_probe.get("probes"):
        fps = set()
        for p in live_probe["probes"]:
            for c in p.get("certificates", []):
                fp = c.get("sha256_fingerprint")
                if fp:
                    fps.add(fp)
        if len(fps) > 1:
            findings.append({
                "severity": "warning",
                "finding": "Different certificates observed across endpoints",
                "evidence": "%d distinct fingerprints across %d endpoints"
                % (len(fps), len(live_probe["probes"])),
            })

    for gap in origin.get("coverage_gaps", []):
        findings.append({
            "severity": "info",
            "finding": "Coverage limitation",
            "evidence": gap,
        })

    origin["findings"] = findings
    origin["live_certificates"] = live_certs
    return origin


def generate_recommendations(origins):
    actions = []
    for origin in origins:
        for finding in origin.get("findings", []):
            if finding["severity"] not in ("critical", "warning"):
                continue
            action = {
                "property_id": origin["property_id"],
                "property_name": origin["property_name"],
                "property_version": origin["property_version"],
                "akamai_network": origin["akamai_network"],
                "rule_path": origin["rule_path"],
                "origin_hostname": origin.get("resolved_hostname")
                or origin["origin_hostname"],
                "finding": finding["finding"],
                "severity": finding["severity"],
                "evidence": finding["evidence"],
                "days_remaining": finding.get("days_remaining"),
            }
            trust = origin.get("origin_certs_to_honor", "")
            if "Expired" in finding["finding"] or "expiring" in finding[
                "finding"
            ].lower():
                if trust in ("SPECIFIC_CERTIFICATES", "CUSTOM_CERTIFICATES"):
                    action["recommendation"] = (
                        "This origin uses specific certificate pinning. "
                        "Add the replacement certificate to customCertificates "
                        "alongside the existing certificate, activate overlapping "
                        "trust, install the new certificate on the origin, verify, "
                        "then remove the old pin."
                    )
                elif "CUSTOM" in trust:
                    action["recommendation"] = (
                        "This origin uses custom CA trust. "
                        "Verify the replacement certificate chains to the "
                        "configured CA. If the CA is also expiring, prepare "
                        "overlapping CA trust."
                    )
                else:
                    action["recommendation"] = (
                        "Renew/install the certificate and chain on the origin. "
                        "Confirm the replacement is issued by an accepted CA "
                        "and matches the required names."
                    )
            elif "Different certificates" in finding["finding"]:
                action["recommendation"] = (
                    "Multiple certificates observed across endpoints. "
                    "Investigate partial rollout or certificate selection "
                    "differences."
                )
            else:
                action["recommendation"] = finding["evidence"]
            actions.append(action)

        obs = origin.get("observation_status", "")
        if obs in (
            "dns_failure",
            "timeout",
            "tls_error",
            "connection_refused",
            "connection_error",
        ):
            actions.append({
                "property_id": origin["property_id"],
                "property_name": origin["property_name"],
                "property_version": origin["property_version"],
                "akamai_network": origin["akamai_network"],
                "rule_path": origin["rule_path"],
                "origin_hostname": origin.get("resolved_hostname")
                or origin["origin_hostname"],
                "finding": "Origin unreachable (%s)" % obs,
                "severity": "warning",
                "evidence": origin.get(
                    "observation_error",
                    "Could not connect from audit environment",
                ),
                "recommendation": (
                    "Verify certificate status from an authorized network "
                    "or with the origin owner. Configured certificates are "
                    "shown but live state could not be confirmed."
                ),
            })
    return actions
