"""DNS records for a domain, and reverse DNS for an IP, using dnspython."""
import dns.exception
import dns.resolver
import dns.reversename

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
# Errors that mean "no record here", so the lookup moves on instead of failing.
NOT_FOUND = (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
             dns.resolver.NoNameservers, dns.exception.Timeout)


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
        except NOT_FOUND:
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


def lookup_reverse_dns(ip: str, resolver: dns.resolver.Resolver | None = None) -> list[Claim]:
    """The hostname an IP's PTR record gives.

    Reverse DNS lives in its own zone: 8.8.8.8 is looked up as
    8.8.8.8.in-addr.arpa (octets reversed), and IPv6 as reversed hex digits
    under ip6.arpa. Whoever runs the IP block sets the PTR record, and nothing
    checks that the name points back to the IP, so it's a hint about who runs
    the machine rather than proof.
    """
    resolver = resolver or dns.resolver.Resolver()
    try:
        answer = resolver.resolve(dns.reversename.from_address(ip), "PTR", lifetime=5)
    except NOT_FOUND:
        return []
    return [
        Claim(
            subject=ip, predicate="reverse_dns", object=str(rdata.target).rstrip("."),
            source="dns", confidence=BASE_CONFIDENCE["authoritative"],
            rationale="PTR record returned by DNS (set by the IP's owner)",
        )
        for rdata in answer
    ]
