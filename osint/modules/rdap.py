"""Registration data via RDAP, the JSON successor to WHOIS."""
import httpx

from osint.claims import BASE_CONFIDENCE, Claim

RDAP_URL = "https://rdap.org/domain/{domain}"


def parse_rdap(domain: str, data: dict, url: str = "") -> list[Claim]:
    claims = []

    def add(predicate: str, value: str, why: str) -> None:
        claims.append(Claim(
            subject=domain, predicate=predicate, object=value, source="rdap",
            confidence=BASE_CONFIDENCE["authoritative"], rationale=why,
            evidence_url=url,
        ))

    for event in data.get("events", []):
        action, date = event.get("eventAction"), event.get("eventDate")
        if action in ("registration", "expiration", "last changed") and date:
            add(action.replace(" ", "_") + "_date", date, f"RDAP {action} event")

    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            name = _vcard_name(entity)
            if name:
                add("registrar", name, "RDAP registrar entity")

    for ns in data.get("nameservers", []):
        name = ns.get("ldhName")
        if name:
            add("nameserver", name.lower(), "RDAP nameserver list")

    for status in data.get("status", []):
        add("status", status, "RDAP domain status")
    return claims


def _vcard_name(entity: dict) -> str:
    vcard = entity.get("vcardArray", [None, []])[1]
    for item in vcard:
        if item and item[0] == "fn":
            return item[3]
    return ""


def lookup_rdap(domain: str, client: httpx.Client | None = None) -> list[Claim]:
    client = client or httpx.Client(timeout=10, follow_redirects=True)
    url = RDAP_URL.format(domain=domain)
    resp = client.get(url)
    resp.raise_for_status()
    return parse_rdap(domain, resp.json(), url=str(resp.url))
