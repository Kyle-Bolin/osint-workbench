"""Which network (AS) announces an IP, via Team Cymru's IP-to-ASN service.

The internet's routers tell each other "send traffic for this prefix to me"
over BGP. Each network that does this has an Autonomous System number (ASN).
Team Cymru summarises the global BGP tables and publishes the result as DNS
TXT records, so this needs nothing beyond dnspython:

    4.3.2.1.origin.asn.cymru.com  TXT  "15169 | 1.2.3.0/24 | US | arin | 2023-12-28"
    AS15169.asn.cymru.com         TXT  "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"

Fields are ASN | prefix | country | registry | allocation date, and for the
second query ASN | country | registry | date | AS name.
Docs: https://www.team-cymru.com/ip-asn-mapping
"""
import ipaddress

import dns.resolver

from osint.claims import BASE_CONFIDENCE, Claim
from osint.modules.dns_lookup import NOT_FOUND


def origin_query(ip: str) -> str:
    """1.2.3.4 -> 4.3.2.1.origin.asn.cymru.com, reversed the same way as reverse DNS."""
    addr = ipaddress.ip_address(ip)
    reversed_ip = addr.reverse_pointer.rsplit(".", 2)[0]  # drop ".in-addr.arpa" / ".ip6.arpa"
    zone = "origin.asn.cymru.com" if addr.version == 4 else "origin6.asn.cymru.com"
    return f"{reversed_ip}.{zone}"


def _claim(subject: str, predicate: str, value: str, why: str) -> Claim:
    # BGP is what the routing system itself uses, so it gets the same base
    # score as DNS answers. Team Cymru is a summary of it, not the registry:
    # RDAP's network owner is the independent second opinion.
    return Claim(
        subject=subject, predicate=predicate, object=value, source="team-cymru",
        confidence=BASE_CONFIDENCE["authoritative"], rationale=why,
    )


def _fields(txt: str) -> list[str]:
    return [part.strip() for part in txt.split("|")]


def parse_origin(ip: str, txt: str) -> list[Claim]:
    asns, prefix = _fields(txt)[:2]
    claims = [_claim(ip, "bgp_prefix", prefix, "routed prefix seen in BGP (Team Cymru)")]
    for asn in asns.split():  # a prefix can be announced by more than one AS
        claims.append(_claim(ip, "announced_by", f"AS{asn}", "origin AS seen in BGP (Team Cymru)"))
    return claims


def parse_as_name(txt: str) -> list[Claim]:
    fields = _fields(txt)
    return [_claim(f"AS{fields[0]}", "as_name", fields[-1], "AS name (Team Cymru)")]


def _txt(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    try:
        answer = resolver.resolve(name, "TXT", lifetime=5)
    except NOT_FOUND:
        return []
    return [b"".join(rdata.strings).decode(errors="replace") for rdata in answer]


def lookup_asn(ip: str, resolver: dns.resolver.Resolver | None = None) -> list[Claim]:
    resolver = resolver or dns.resolver.Resolver()
    claims = []
    for txt in _txt(resolver, origin_query(ip)):
        claims.extend(parse_origin(ip, txt))
    # The same AS can come back once per covering prefix; keep one claim each.
    claims = list({(c.predicate, c.object): c for c in claims}.values())

    for asn in sorted({c.object for c in claims if c.predicate == "announced_by"}):
        for txt in _txt(resolver, f"{asn}.asn.cymru.com"):
            claims.extend(parse_as_name(txt))
    return claims
