"""Registration data via RDAP, the JSON successor to WHOIS.

RDAP covers IP addresses too: the regional internet registries (ARIN, RIPE,
APNIC, LACNIC, AFRINIC) record who each block of addresses was handed to.
rdap.org redirects every query to whichever registry holds the answer.
"""
import httpx

from osint.claims import BASE_CONFIDENCE, Claim

RDAP_URL = "https://rdap.org/domain/{domain}"
RDAP_IP_URL = "https://rdap.org/ip/{ip}"


def _claim(subject: str, predicate: str, value: str, why: str, url: str) -> Claim:
    return Claim(
        subject=subject, predicate=predicate, object=value, source="rdap",
        confidence=BASE_CONFIDENCE["authoritative"], rationale=why,
        evidence_url=url,
    )


def parse_rdap(domain: str, data: dict, url: str = "") -> list[Claim]:
    claims = []

    def add(predicate: str, value: str, why: str) -> None:
        claims.append(_claim(domain, predicate, value, why, url))

    for event in data.get("events", []):
        action, date = event.get("eventAction"), event.get("eventDate")
        if action in ("registration", "expiration", "last changed") and date:
            add(action.replace(" ", "_") + "_date", date, f"RDAP {action} event")

    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            name = _vcard_value(entity, "fn")
            if name:
                add("registrar", name, "RDAP registrar entity")

    for ns in data.get("nameservers", []):
        name = ns.get("ldhName")
        if name:
            add("nameserver", name.lower(), "RDAP nameserver list")

    for status in data.get("status", []):
        add("status", status, "RDAP domain status")
    return claims


def parse_ip_rdap(ip: str, data: dict, url: str = "") -> list[Claim]:
    """The registry record for the block of addresses an IP belongs to."""
    claims = []

    def add(predicate: str, value: str, why: str) -> None:
        claims.append(_claim(ip, predicate, value, why, url))

    if data.get("name"):
        add("network_name", data["name"], "RDAP network name")

    # Most registries list the block as CIDR prefixes; fall back to start/end.
    cidrs = [
        f"{c.get('v4prefix') or c.get('v6prefix')}/{c['length']}"
        for c in data.get("cidr0_cidrs", [])
    ]
    if not cidrs and data.get("startAddress") and data.get("endAddress"):
        cidrs = [f"{data['startAddress']} - {data['endAddress']}"]
    for cidr in cidrs:
        add("network_range", cidr, "RDAP network block")

    if data.get("country"):
        add("registered_country", data["country"], "RDAP network country")

    for entity in _all_entities(data.get("entities", [])):
        roles = entity.get("roles", [])
        name, email = _vcard_value(entity, "fn"), _vcard_value(entity, "email")
        if "registrant" in roles and name:
            add("network_owner", name, "RDAP registrant of the block")
        if "abuse" in roles and email:
            add("abuse_contact", email, "RDAP abuse contact")
    return claims


def _all_entities(entities: list[dict]):
    """Entities can nest: ARIN puts the abuse contact inside the registrant."""
    for entity in entities:
        yield entity
        yield from _all_entities(entity.get("entities", []))


def _vcard_value(entity: dict, field: str) -> str:
    vcard = entity.get("vcardArray", [None, []])[1]
    for item in vcard:
        if item and item[0] == field:
            return item[3]
    return ""


def lookup_rdap(domain: str, client: httpx.Client | None = None) -> list[Claim]:
    client = client or httpx.Client(timeout=10, follow_redirects=True)
    url = RDAP_URL.format(domain=domain)
    resp = client.get(url)
    resp.raise_for_status()
    return parse_rdap(domain, resp.json(), url=str(resp.url))


def lookup_ip_rdap(ip: str, client: httpx.Client | None = None) -> list[Claim]:
    client = client or httpx.Client(timeout=10, follow_redirects=True)
    resp = client.get(RDAP_IP_URL.format(ip=ip))
    resp.raise_for_status()
    return parse_ip_rdap(ip, resp.json(), url=str(resp.url))
