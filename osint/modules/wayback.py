"""Snapshot history from the Wayback Machine's CDX API.

The CDX API is the Wayback Machine's index: one row per capture, with when it
was taken and the URL as crawled. Asking it about a domain's homepage gives a
timeline: when the site first appeared, years it went dark, and a link to see
what it looked like each year.
"""
from datetime import datetime

import httpx

from osint.claims import BASE_CONFIDENCE, Claim

CDX_URL = "https://web.archive.org/cdx/search/cdx"
SNAPSHOT_URL = "https://web.archive.org/web/{timestamp}/{original}"


def parse_cdx(domain: str, rows: list[list[str]]) -> list[Claim]:
    """CDX JSON is a table: the first row holds the column names, the rest are captures."""
    if not rows:
        return []
    header, *captures = rows
    claims = []
    for values in captures:
        row = dict(zip(header, values))
        # 14-digit Wayback timestamps (YYYYMMDDhhmmss) are in UTC.
        taken = datetime.strptime(row["timestamp"], "%Y%m%d%H%M%S")
        claims.append(Claim(
            subject=domain, predicate="archived_at",
            object=taken.strftime("%Y-%m-%dT%H:%M:%SZ"),
            source="wayback", confidence=BASE_CONFIDENCE["log"],
            rationale=f"first Wayback Machine capture of {row['original']} in {taken.year}",
            evidence_url=SNAPSHOT_URL.format(timestamp=row["timestamp"], original=row["original"]),
        ))
    return claims


def lookup_wayback(domain: str, client: httpx.Client | None = None) -> list[Claim]:
    client = client or httpx.Client(timeout=30)
    resp = client.get(CDX_URL, params={
        "url": domain,               # the homepage; http/https and www. count as the same page
        "output": "json",
        "fl": "timestamp,original",  # only the columns we use
        "filter": "statuscode:200",  # captures where the site served a page, not a redirect or error
        "collapse": "timestamp:4",   # first capture of each year: a timeline, not 100,000 rows
    })
    resp.raise_for_status()
    # Treat an empty body like [] (no captures), so a never-archived domain isn't an error.
    return parse_cdx(domain, resp.json() if resp.text.strip() else [])
