"""DNS records for a domain, using dnspython."""
import dns.exception
import dns.resolver

from osint.claims import BASE_CONFIDENCE, Claim

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
PREDICATES = {
    "A": "has_ipv4",
    "AAAA": "has_ipv6",
    "MX": "mail_handled_by",
    "NS": "nameserver",
    "TXT": "txt_record",
    "CNAME": "alias_of",
}


def _format(rtype: str, rdata) -> str:
    if rtype == "MX":
        return str(rdata.exchange).rstrip(".")
    if rtype in ("NS", "CNAME"):
        return str(rdata.target).rstrip(".")
    if rtype == "TXT":
        return b"".join(rdata.strings).decode(errors="replace")
    return rdata.to_text()


def lookup_dns(domain: str, resolver: dns.resolver.Resolver | None = None) -> list[Claim]:
    resolver = resolver or dns.resolver.Resolver()
    claims = []
    for rtype in RECORD_TYPES:
        try:
            answer = resolver.resolve(domain, rtype, lifetime=5)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        for rdata in answer:
            claims.append(Claim(
                subject=domain,
                predicate=PREDICATES[rtype],
                object=_format(rtype, rdata),
                source="dns",
                confidence=BASE_CONFIDENCE["authoritative"],
                rationale=f"{rtype} record returned by DNS",
            ))
    return claims
