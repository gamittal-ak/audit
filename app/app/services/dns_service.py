"""
Async CNAME resolution wrapping the sync dnspython library.
"""
import asyncio
from typing import Tuple

import dns
from dns import resolver
from dns.exception import DNSException
from tldextract import tldextract

_NAMESERVERS = ["8.8.8.8", "8.8.4.4"]
_MAX_HOPS = 20


def _resolve_cname_sync(domain: str) -> list:
    my_resolver = resolver.Resolver(configure=False)
    my_resolver.nameservers = _NAMESERVERS
    answers = []
    for query_type in dns.rdatatype.RdataType:
        if query_type == dns.rdatatype.RdataType.CNAME:
            try:
                answers.append(my_resolver.resolve(domain, query_type))
            except DNSException:
                pass
    return answers


def _get_network_details_sync(cname_from: str, hops: int = 0) -> Tuple[str, str, str]:
    """
    Follow CNAME chain until an akamaiedge.net / akamai.net record is found.
    Returns (map_name, flow_type, slot) or ('', '', '') on failure.
    """
    if not cname_from or hops >= _MAX_HOPS:
        return ("", "", "")

    try:
        answers = _resolve_cname_sync(cname_from)
    except Exception:
        return ("", "", "")

    if not answers:
        return ("", "", "")

    ans = str(answers[0].rrset[0])[:-1]  # strip trailing dot

    if any(s in ans for s in ("akamaiedge.net", "akamaiedge-staging.net", "akamai.net")):
        ext = tldextract.extract(ans)
        subdomain = ext.subdomain
        if not subdomain:
            return ("", "", "")
        parts = subdomain.split(".")
        map_name = parts[1] if len(parts) > 1 else ""
        host_part = parts[0] if parts else ""
        flow_type = "ESSL" if host_part.startswith("e") else "FreeFlow"
        slot = host_part[1:] if host_part.startswith("e") else host_part
        return (map_name, flow_type, slot)

    return _get_network_details_sync(ans, hops + 1)


async def get_network_details(cname_from: str) -> Tuple[str, str, str]:
    """Async wrapper: runs CNAME resolution in a thread pool."""
    if not cname_from:
        return ("", "", "")
    return await asyncio.to_thread(_get_network_details_sync, cname_from)
