"""Who an X account follows and who follows it, through X's paid API.

X has no free read access. Its API is pay-per-use: you buy credits in the
Developer Console (https://console.x.com) and each account read costs about
$0.01, or $0.001 for your own lists (X's "owned reads"). Reading the same
account again on the same UTC day isn't charged twice. Set a spending limit in
the console as well; this module also stops after `X_MAX_ACCOUNTS` accounts
per list (default 100), so one lookup of someone else's lists costs at most
about 100 + 100 + 1 profile = $2.01.

Make an app in the console, copy its Bearer Token, and set it before starting
the app. It stays in the environment and a request header, never in git:

    export X_BEARER_TOKEN=...      # Windows: set X_BEARER_TOKEN=...
    export X_MAX_ACCOUNTS=100      # optional

Why not scrape x.com instead? X's terms forbid crawling or scraping without
written consent and set damages for heavy use, so the paid API is the only
allowed way in.
"""
import logging
import os

import httpx

from osint.accounts import follow_claims, linked_account_claims
from osint.claims import BASE_CONFIDENCE, Claim

API = "https://api.x.com/2"
PROFILE_URL = "https://x.com/{username}"
DEFAULT_MAX_ACCOUNTS = 100
USER_FIELDS = "created_at,public_metrics,entities"

log = logging.getLogger(__name__)


class MissingAPIKey(RuntimeError):
    """Raised before any request is made, so a missing key never costs anything."""


def parse_user(user: dict) -> list[Claim]:
    account = f"x:{user['username'].lower()}"
    url = PROFILE_URL.format(username=user["username"])
    claims = []

    def add(predicate: str, value) -> None:
        claims.append(Claim(
            subject=account, predicate=predicate, object=str(value), source="x-api",
            confidence=BASE_CONFIDENCE["authoritative"], rationale="X profile", evidence_url=url,
        ))

    add("has_x_id", user["id"])
    if user.get("name"):
        add("display_name", user["name"])
    metrics = user.get("public_metrics", {})
    for key, predicate in (("followers_count", "followers_count"), ("following_count", "following_count")):
        if key in metrics:
            add(predicate, metrics[key])
    if user.get("created_at"):
        add("created_at", user["created_at"])
    # The profile's website, already expanded from X's t.co short link.
    links = [u["expanded_url"] for u in user.get("entities", {}).get("url", {}).get("urls", []) if u.get("expanded_url")]
    claims += linked_account_claims(account, links, "x-api", "website on their X profile")
    return claims


def _list(client: httpx.Client, url: str, headers: dict, limit: int) -> list[dict]:
    """Page through followers/following (up to 1,000 per page) until `limit`.
    X bills per account returned, so each page asks for no more than is left."""
    found, token = [], None
    while len(found) < limit:
        params = {"max_results": max(1, min(1000, limit - len(found)))}
        if token:
            params["pagination_token"] = token
        resp = client.get(url, params=params, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        found += data.get("data", [])
        token = data.get("meta", {}).get("next_token")
        if not token:
            break
    return found[:limit]


def _nodes(users: list[dict]) -> list[str]:
    return [f"x:{u['username'].lower()}" for u in users]


def lookup_x_network(
    username: str, client: httpx.Client | None = None, token: str | None = None, limit: int | None = None,
) -> list[Claim]:
    """Profile, who they follow and who follows them (up to `limit` of each). Costs money."""
    token = token or os.environ.get("X_BEARER_TOKEN")
    if not token:
        raise MissingAPIKey("X needs a paid API key: set X_BEARER_TOKEN (see osint/modules/x_api.py)")
    limit = limit if limit is not None else int(os.environ.get("X_MAX_ACCOUNTS", DEFAULT_MAX_ACCOUNTS))
    headers = {"Authorization": f"Bearer {token}"}
    client = client or httpx.Client(timeout=15)

    resp = client.get(f"{API}/users/by/username/{username}", params={"user.fields": USER_FIELDS}, headers=headers)
    resp.raise_for_status()
    body = resp.json()
    if "data" not in body:  # X answers 200 with an "errors" list for a missing or suspended user
        message = body.get("errors", [{}])[0].get("detail", "user not found")
        raise httpx.HTTPStatusError(message, request=resp.request, response=resp)
    user = body["data"]
    following = _list(client, f"{API}/users/{user['id']}/following", headers, limit)
    followers = _list(client, f"{API}/users/{user['id']}/followers", headers, limit)
    # Logged so the bill is never a surprise (stderr; the MCP server needs stdout clean).
    log.info("X API: read %d accounts for %s (about $%.2f at $0.01 each)",
             1 + len(following) + len(followers), username, 0.01 * (1 + len(following) + len(followers)))
    url = PROFILE_URL.format(username=user["username"])
    return parse_user(user) + follow_claims(
        f"x:{user['username'].lower()}", _nodes(following), _nodes(followers), source="x-api",
        following_url=f"{url}/following", followers_url=f"{url}/followers",
    )
