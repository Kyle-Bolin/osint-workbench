"""Who a Mastodon account follows and who follows it, from its own server.

Mastodon has no central site: `kyle@infosec.exchange` lives on the
infosec.exchange server, and that server's public API answers for it with no
key (300 requests per 5 minutes per IP). An account can hide its follows and
followers in its settings; the lists then come back empty while the counts on
the profile stay visible.

Mastodon also checks profile links for you. If the linked page links back to
the profile with `rel="me"`, the server marks the field verified, so a
verified link counts as proof and an unverified one is just something typed in.
"""
import re

import httpx

from osint.accounts import follow_claims, linked_account_claims
from osint.claims import BASE_CONFIDENCE, Claim

MAX_ACCOUNTS = 200  # per list; profile claims carry the full counts
HREF_RE = re.compile(r'href="([^"]+)"')


def node(account: dict, home_server: str) -> str:
    """The API writes accounts on the same server as plain `user`, and
    accounts elsewhere as `user@server`. Nodes always carry the server."""
    acct = account["acct"].lower()
    return f"mastodon:{acct if '@' in acct else acct + '@' + home_server}"


def parse_account(account: dict, server: str) -> list[Claim]:
    subject, url = node(account, server), account.get("url", "")
    claims = []

    def add(predicate: str, value) -> None:
        claims.append(Claim(
            subject=subject, predicate=predicate, object=str(value), source="mastodon",
            confidence=BASE_CONFIDENCE["authoritative"], rationale=f"profile on {server}", evidence_url=url,
        ))

    for key, predicate in (("display_name", "display_name"), ("followers_count", "followers_count"),
                           ("following_count", "following_count"), ("created_at", "created_at")):
        if account.get(key) not in (None, ""):
            add(predicate, account[key])

    for field in account.get("fields", []):
        match = HREF_RE.search(field.get("value", ""))
        if not match:
            continue
        link = match.group(1)
        if field.get("verified_at"):
            claims.append(Claim(
                subject=subject, predicate="verified_link", object=link, source="mastodon",
                confidence=BASE_CONFIDENCE["authoritative"],
                rationale=f"{server} checked that {link} links back with rel=\"me\"", evidence_url=link,
            ))
        else:
            claims += linked_account_claims(subject, [link], "mastodon", f"profile field {field.get('name', '')!r}, not verified")
    return claims


def _list(client: httpx.Client, url: str, limit: int) -> list[dict]:
    """Page through a list (80 per page, the server maximum) via the Link header."""
    found, params = [], {"limit": 80}
    while url and len(found) < limit:
        resp = client.get(url, params=params)
        resp.raise_for_status()
        found += resp.json()
        url, params = resp.links.get("next", {}).get("url"), None
    return found[:limit]


def lookup_mastodon_network(
    address: str, client: httpx.Client | None = None, limit: int = MAX_ACCOUNTS,
) -> list[Claim]:
    """`address` is `user@server`. Profile, verified links, who it follows and
    who follows it (up to `limit` of each)."""
    user, server = address.split("@")
    client = client or httpx.Client(timeout=15, follow_redirects=True)
    api = f"https://{server}/api/v1/accounts"
    resp = client.get(f"{api}/lookup", params={"acct": user})
    resp.raise_for_status()
    account = resp.json()
    following = _list(client, f"{api}/{account['id']}/following", limit)
    followers = _list(client, f"{api}/{account['id']}/followers", limit)
    url = account.get("url", "")
    return parse_account(account, server) + follow_claims(
        node(account, server), [node(a, server) for a in following], [node(a, server) for a in followers],
        source="mastodon", following_url=f"{url}/following", followers_url=f"{url}/followers",
    )
