"""Who a GitHub user follows, who follows them, and the accounts they link to.

GitHub's REST API serves all of this publicly. Without a token it allows 60
requests an hour per IP, and one lookup here uses about six. For 5,000 an hour,
make a token with no scopes at https://github.com/settings/tokens and set it
before starting the app:

    export GITHUB_TOKEN=...        # Windows: set GITHUB_TOKEN=...

GitHub profiles are a good bridge between platforms: people list their
website, X account and other social accounts there. Those are typed in by the
user and nothing checks them, so they come back as "weak" claims.
"""
import os

import httpx

from osint.accounts import follow_claims, linked_account_claims
from osint.claims import BASE_CONFIDENCE, Claim

API = "https://api.github.com"
MAX_ACCOUNTS = 200  # per list; profile claims carry the full counts


def parse_user(user: dict, social_accounts: list[dict]) -> list[Claim]:
    account, url = f"github:{user['login'].lower()}", user["html_url"]
    claims = []

    def add(predicate: str, value) -> None:
        claims.append(Claim(
            subject=account, predicate=predicate, object=str(value), source="github",
            confidence=BASE_CONFIDENCE["authoritative"], rationale="GitHub profile", evidence_url=url,
        ))

    for key, predicate in (("name", "display_name"), ("company", "company"), ("location", "location"),
                           ("followers", "followers_count"), ("following", "following_count"),
                           ("created_at", "created_at")):
        if user.get(key) not in (None, ""):
            add(predicate, user[key])

    links = [a["url"] for a in social_accounts if a.get("url")]
    if user.get("blog"):
        links.append(user["blog"])
    if user.get("twitter_username"):
        links.append(f"https://x.com/{user['twitter_username']}")
    claims += linked_account_claims(account, list(dict.fromkeys(links)), "github", "listed on their GitHub profile")
    return claims


def _list(client: httpx.Client, url: str, headers: dict, limit: int) -> list[dict]:
    """Page through a list (100 per page), following the Link: rel="next" header."""
    found, params = [], {"per_page": 100}
    while url and len(found) < limit:
        resp = client.get(url, params=params, headers=headers)
        resp.raise_for_status()
        found += resp.json()
        url, params = resp.links.get("next", {}).get("url"), None  # the next URL carries its own query
    return found[:limit]


def _nodes(users: list[dict]) -> list[str]:
    return [f"github:{u['login'].lower()}" for u in users]


def lookup_github_network(
    username: str, client: httpx.Client | None = None, token: str | None = None, limit: int = MAX_ACCOUNTS,
) -> list[Claim]:
    """Profile, linked accounts, who they follow and who follows them (up to `limit` of each)."""
    token = token or os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    client = client or httpx.Client(timeout=15)

    resp = client.get(f"{API}/users/{username}", headers=headers)
    resp.raise_for_status()
    user = resp.json()
    social = _list(client, f"{API}/users/{username}/social_accounts", headers, 100)
    following = _list(client, f"{API}/users/{username}/following", headers, limit)
    followers = _list(client, f"{API}/users/{username}/followers", headers, limit)
    return parse_user(user, social) + follow_claims(
        f"github:{user['login'].lower()}", _nodes(following), _nodes(followers), source="github",
        following_url=f"{user['html_url']}?tab=following", followers_url=f"{user['html_url']}?tab=followers",
    )
