"""Rough location of an IP, from ipinfo.io.

IP geolocation is a company's best guess from its own database, not a fact:
the country is usually right, the city often isn't, and an anycast address
(8.8.8.8, Cloudflare's IPs) answers from many places at once. So these claims
start at the "weak" base score, well below DNS or registry data.

ipinfo works without an account at a low rate limit. For more, make a free
token at https://ipinfo.io/signup and set it before starting the app:

    export IPINFO_TOKEN=...        # Windows: set IPINFO_TOKEN=...

The token is read from the environment and sent in a request header, so it
never lands in the code, in git, or in an evidence URL shown on the page.
"""
import os

import httpx

from osint.claims import BASE_CONFIDENCE, Claim

IPINFO_URL = "https://ipinfo.io/{ip}/json"


def parse_ipinfo(ip: str, data: dict, url: str = "") -> list[Claim]:
    why = "ipinfo.io location estimate"
    if data.get("anycast"):
        why += "; anycast address, so it is served from many places"
    claims = []

    def add(predicate: str, value: str) -> None:
        claims.append(Claim(
            subject=ip, predicate=predicate, object=value, source="ipinfo",
            confidence=BASE_CONFIDENCE["weak"], rationale=why, evidence_url=url,
        ))

    if data.get("country"):
        add("geo_country", data["country"])
    city = ", ".join(part for part in (data.get("city"), data.get("region")) if part)
    if city:
        add("geo_city", city)
    if data.get("loc"):
        add("geo_coordinates", data["loc"])
    return claims


def lookup_geo(ip: str, client: httpx.Client | None = None, token: str | None = None) -> list[Claim]:
    token = token or os.environ.get("IPINFO_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    client = client or httpx.Client(timeout=10)
    url = IPINFO_URL.format(ip=ip)
    resp = client.get(url, headers=headers)
    resp.raise_for_status()
    return parse_ipinfo(ip, resp.json(), url=url)
