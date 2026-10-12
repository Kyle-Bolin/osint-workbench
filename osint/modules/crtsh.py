"""Subdomains from certificate transparency logs (crt.sh)."""
import httpx

from osint.claims import BASE_CONFIDENCE, Claim

CRTSH_URL = "https://crt.sh/"


def parse_crtsh(domain: str, rows: list[dict]) -> list[Claim]:
    names = set()
    for row in rows:
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith("." + domain) and name != domain:
                names.add(name)
    return [
        Claim(
            subject=domain, predicate="has_subdomain", object=name,
            source="crt.sh", confidence=BASE_CONFIDENCE["log"],
            rationale="name appears on a logged TLS certificate",
            evidence_url=f"{CRTSH_URL}?q={name}",
        )
        for name in sorted(names)
    ]


def lookup_subdomains(domain: str, client: httpx.Client | None = None) -> list[Claim]:
    client = client or httpx.Client(timeout=30)
    resp = client.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"})
    resp.raise_for_status()
    return parse_crtsh(domain, resp.json())
