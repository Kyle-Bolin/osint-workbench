"""Who a Bluesky account follows and who follows it, from Bluesky's public API.

Bluesky is built on the AT Protocol, where follows are public records by
design, and Bluesky runs a public, keyless, cached API for reading them:
https://public.api.bsky.app. No account or key needed.

A Bluesky handle can be your own domain (`kyle.dev`). Bluesky only shows that
handle after a DNS TXT record at `_atproto.kyle.dev` (or a file on the site)
points back to the account, so a domain handle is proof that whoever controls
the domain controls the account. That's the bridge from the domain lookups to
the social graph.
"""
import httpx

from osint.accounts import follow_claims
from osint.claims import BASE_CONFIDENCE, Claim

API = "https://public.api.bsky.app/xrpc/"
PROFILE_URL = "https://bsky.app/profile/{handle}"
MAX_ACCOUNTS = 200  # per list; profile claims carry the full counts
# Handles under these domains belong to a hosting service, not the account owner.
HOSTED_SUFFIXES = (".bsky.social",)


def node(actor: dict) -> str:
    """Bluesky shows `handle.invalid` when a handle stops verifying; the DID
    (the account's permanent ID) still names the account."""
    handle = actor.get("handle", "")
    return f"bluesky:{actor['did'] if handle in ('', 'handle.invalid') else handle}"


def profile_url(actor: dict) -> str:
    return PROFILE_URL.format(handle=node(actor).removeprefix("bluesky:"))


def parse_profile(profile: dict) -> list[Claim]:
    account, handle, url = node(profile), profile.get("handle", ""), profile_url(profile)
    claims = []

    def add(predicate: str, value, why: str, score: str = "authoritative") -> None:
        claims.append(Claim(
            subject=account, predicate=predicate, object=str(value), source="bluesky",
            confidence=BASE_CONFIDENCE[score], rationale=why, evidence_url=url,
        ))

    add("has_did", profile["did"], "the account's permanent ID")
    if profile.get("displayName"):
        add("display_name", profile["displayName"], "Bluesky profile")
    for key, predicate in (("followersCount", "followers_count"), ("followsCount", "following_count")):
        if key in profile:
            add(predicate, profile[key], "Bluesky profile counter")
    if profile.get("createdAt"):
        add("created_at", profile["createdAt"], "Bluesky profile")
    if handle and handle != "handle.invalid" and not handle.endswith(HOSTED_SUFFIXES):
        add("verified_domain", handle, "Bluesky only shows a domain handle after the domain points back to the account")
    return claims


def _list(client: httpx.Client, method: str, key: str, actor: str, limit: int) -> list[dict]:
    """Page through getFollows/getFollowers (100 per page) until `limit`."""
    found, cursor = [], None
    while len(found) < limit:
        params = {"actor": actor, "limit": min(100, limit - len(found))}
        if cursor:
            params["cursor"] = cursor
        resp = client.get(API + method, params=params)
        resp.raise_for_status()
        data = resp.json()
        found += data.get(key, [])
        cursor = data.get("cursor")
        if not cursor or not data.get(key):
            break
    return found[:limit]


def lookup_bluesky_network(
    handle: str, client: httpx.Client | None = None, limit: int = MAX_ACCOUNTS,
) -> list[Claim]:
    """Profile, who it follows and who follows it (up to `limit` of each)."""
    client = client or httpx.Client(timeout=15)
    resp = client.get(API + "app.bsky.actor.getProfile", params={"actor": handle})
    resp.raise_for_status()
    profile = resp.json()
    following = _list(client, "app.bsky.graph.getFollows", "follows", profile["did"], limit)
    followers = _list(client, "app.bsky.graph.getFollowers", "followers", profile["did"], limit)
    url = profile_url(profile)
    return parse_profile(profile) + follow_claims(
        node(profile), [node(a) for a in following], [node(a) for a in followers], source="bluesky",
        following_url=f"{url}/follows", followers_url=f"{url}/followers",
    )
