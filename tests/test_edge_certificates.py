import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from app.services.edge_security import classify_hostname, summarize
from app.services.edge_certificates import collect_certificate_inventory, apply_certificate_evidence, covers


def pem():
    key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"www.example.com")])
    now=datetime.now(timezone.utc)
    return x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=30)).add_extension(x509.SubjectAlternativeName([x509.DNSName("*.example.com")]),critical=False).sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def inventory(complete=True):
    return {"complete":complete,"contracts":1,"enrollments":0,"pending_names":[],"deployments":[],"errors":0}


def hostname_row(mode="STANDARD-TLS", provision="CPS_MANAGED"):
    return classify_hostname({"cnameFrom":"www.example.com","cnameTo":"www.example.com.edgesuite.net",
                              "certProvisioningType":provision},{"securityType":mode},"PRODUCTION")


def test_complete_empty_inventory_classifies_http_only_with_scope():
    result=apply_certificate_evidence(hostname_row(),{},"PRODUCTION",inventory())
    assert result["delivery_mode"]=="HTTP-only"
    assert "API client's visibility" in result["evidence"]
    assert summarize([result])["label"]=="HTTP-only"


@pytest.mark.parametrize("complete,mode,provision",[(False,"STANDARD-TLS","CPS_MANAGED"),
    (True,"ENHANCED-TLS","CPS_MANAGED"),(True,"STANDARD-TLS","DEFAULT"),
    (True,"UNKNOWN","CPS_MANAGED")])
def test_ambiguous_cases_never_http_only(complete,mode,provision):
    result=apply_certificate_evidence(hostname_row(mode,provision),{},"PRODUCTION",inventory(complete))
    assert result.get("delivery_mode")!="HTTP-only"


def test_pending_and_other_network_matches_prevent_negative_classification():
    data=inventory();data["pending_names"]=["*.example.com"]
    assert apply_certificate_evidence(hostname_row(),{},"PRODUCTION",data).get("delivery_mode")!="HTTP-only"
    data=inventory();data["deployments"]=[dict(network="STAGING",tls_network="standard-tls",names=["*.example.com"],slots=[],enrollment_id="1")]
    assert apply_certificate_evidence(hostname_row(),{},"PRODUCTION",data).get("delivery_mode")!="HTTP-only"


def test_enhanced_tls_requires_matching_slot():
    data=inventory();data["deployments"]=[dict(network="PRODUCTION",tls_network="enhanced-tls",
        names=["*.example.com"],slots=["123"],enrollment_id="1")]
    row=hostname_row("ENHANCED-TLS")
    assert apply_certificate_evidence(deepcopy(row),{"slotNumber":456},"PRODUCTION",data)["protocol"]=="Unknown"
    assert apply_certificate_evidence(deepcopy(row),{"slotNumber":123},"PRODUCTION",data)["protocol"]=="CPS certificate deployed"


def test_wildcard_single_label_only():
    assert covers("*.example.com","WWW.Example.COM.")
    assert not covers("*.example.com","a.b.example.com")
    assert not covers("*.example.com","example.com")
    assert not covers("*.example.com","badexample.com")


def test_collect_parse_deduplicate_contract_and_enrollment():
    dep={"networkConfiguration":{"secureNetwork":"standard-tls"},
         "primaryCertificate":{"certificate":pem(),"expiry":"2026-10-24"},
         "multiStackedCertificates":[]}
    c=SimpleNamespace(get_cps_enrollments=AsyncMock(return_value={"enrollments":[
        {"id":"42","csr":{"cn":"www.example.com","sans":["*.example.com"]}}]}),
        get_cps_deployments=AsyncMock(return_value={"production":dep,"staging":None}))
    data=asyncio.run(collect_certificate_inventory(c,"a",["ctr_c","c","d"]))
    assert data["complete"] and data["contracts"]==2 and data["enrollments"]==1
    assert c.get_cps_deployments.await_count==1
    assert "*.example.com" in data["deployments"][0]["names"]
    assert apply_certificate_evidence(hostname_row(),{},"PRODUCTION",data)["protocol"]=="CPS certificate deployed"


@pytest.mark.parametrize("payload",[{},{"production":{},"staging":None},
    {"production":{"networkConfiguration":{},"primaryCertificate":{"certificate":"bad pem"},"multiStackedCertificates":[]},"staging":None}])
def test_malformed_deployment_blocks_negative_evidence(payload):
    c=SimpleNamespace(get_cps_enrollments=AsyncMock(return_value={"enrollments":[{"id":"1","csr":{}}]}),
                      get_cps_deployments=AsyncMock(return_value=payload))
    data=asyncio.run(collect_certificate_inventory(c,"a",["c"]))
    assert not data["complete"]
    assert apply_certificate_evidence(hostname_row(),{},"PRODUCTION",data).get("delivery_mode")!="HTTP-only"


def test_contract_failure_is_partial_inventory():
    c=SimpleNamespace(get_cps_enrollments=AsyncMock(side_effect=PermissionError()))
    data=asyncio.run(collect_certificate_inventory(c,"a",["c"]))
    assert not data["complete"] and data["errors"]==1


def test_null_sni_names_is_valid_deployment():
    dep={"networkConfiguration":{"secureNetwork":"enhanced-tls","dnsNames":None},
         "primaryCertificate":{"certificate":pem()},"multiStackedCertificates":[]}
    c=SimpleNamespace(get_cps_enrollments=AsyncMock(return_value={"enrollments":[{"id":"7","csr":{}}]}),
                      get_cps_deployments=AsyncMock(return_value={"production":dep,"staging":dep}))
    data=asyncio.run(collect_certificate_inventory(c,"a",["c"]))
    assert data["complete"] and data["errors"]==0 and data["deployments"][0]["sni_names"]==[]


def test_contract_outside_access_group_is_counted_and_explained():
    error=Exception("Invalid Contract");error.response=SimpleNamespace(status_code=400)
    c=SimpleNamespace(get_cps_enrollments=AsyncMock(side_effect=error))
    data=asyncio.run(collect_certificate_inventory(c,"a",["c","d"]))
    assert not data["complete"] and data["inaccessible_contracts"]==2
    row=apply_certificate_evidence(hostname_row(),{},"PRODUCTION",data)
    assert row.get("delivery_mode")!="HTTP-only" and "2 of 2 contracts" in row["evidence"]
