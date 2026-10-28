"""Social network lookups, tested offline with MockTransport.

The sample responses are trimmed to the fields the modules read, in the shape
each platform's API documents.
"""
import httpx
import pytest
from fastapi.testclient import TestClient

from osint import app as app_module
from osint.accounts import account_from_url, parse_account
from osint.claims import BASE_CONFIDENCE, Claim
from osint.modules.bluesky import lookup_bluesky_network, parse_profile
from osint.modules.github import lookup_github_network
from osint.modules.mastodon import lookup_mastodon_network, parse_account as parse_mastodon_account
from osint.modules.x_api import MissingAPIKey, lookup_x_network


def triples(claims: list[Claim]) -> set[tuple[str, str, str]]:
    return {(c.subject, c.predicate, c.object) for c in claims}


def mock_client(routes: dict, seen: list | None = None) -> httpx.Client:
    """Answer each request from `routes`, keyed by URL path (plus query, if that key exists)."""
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        path, query = request.url.path, request.url.query.decode()
        for key in (f"{path}?{query}", path):
            if key in routes:
                status, body, headers = routes[key] if isinstance(routes[key], tuple) else (200, routes[key], {})
                return httpx.Response(status, json=body, headers=headers)
        return httpx.Response(404, json={"error": f"no route for {path}?{query}"})
    return httpx.Client(transport=httpx.MockTransport(handler))


# --- account names ---

@pytest.mark.parametrize("raw,expected", [
    ("github:Octocat", ("github", "octocat")),
    ("bluesky:@Kyle.dev", ("bluesky", "kyle.dev")),
    ("mastodon:@kyle@infosec.exchange", ("mastodon", "kyle@infosec.exchange")),
    ("@kyle@Infosec.Exchange", ("mastodon", "kyle@infosec.exchange")),
    ("x:@Kyle_B", ("x", "kyle_b")),
])
def test_parse_account(raw, expected):
    assert parse_account(raw) == expected


@pytest.mark.parametrize("raw", ["github:-bad-", "x:way_too_long_for_x_names", "mastodon:kyle", "myspace:tom"])
def test_parse_account_rejects_bad_handles(raw):
    with pytest.raises(ValueError):
        parse_account(raw)


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/Octocat", "github:octocat"),
    ("https://twitter.com/kyle_b", "x:kyle_b"),
    ("https://x.com/kyle_b/", "x:kyle_b"),
    ("https://bsky.app/profile/kyle.dev", "bluesky:kyle.dev"),
    ("https://www.linkedin.com/in/Kyle-Bolin", "linkedin:kyle-bolin"),
    ("https://infosec.exchange/@kyle", "mastodon:kyle@infosec.exchange"),
    ("https://kyle.dev/about", None),
    ("https://github.com/octocat/hello-world", None),
])
def test_account_from_url(url, expected):
    assert account_from_url(url) == expected


# --- Bluesky ---

BSKY_PROFILE = {
    "did": "did:plc:abc123", "handle": "kyle.dev", "displayName": "Kyle",
    "followersCount": 2, "followsCount": 1, "createdAt": "2024-02-01T00:00:00.000Z",
}


def test_bluesky_domain_handle_is_a_verified_domain():
    claims = triples(parse_profile(BSKY_PROFILE))
    assert ("bluesky:kyle.dev", "verified_domain", "kyle.dev") in claims
    assert ("bluesky:kyle.dev", "has_did", "did:plc:abc123") in claims


def test_bluesky_hosted_handle_proves_no_domain():
    profile = {**BSKY_PROFILE, "handle": "kyle.bsky.social"}
    assert "verified_domain" not in {c.predicate for c in parse_profile(profile)}


def test_lookup_bluesky_network_pages_through_both_lists():
    seen = []
    client = mock_client({
        "/xrpc/app.bsky.actor.getProfile": BSKY_PROFILE,
        "/xrpc/app.bsky.graph.getFollows": {"follows": [{"did": "did:plc:b", "handle": "bob.bsky.social"}]},
        "/xrpc/app.bsky.graph.getFollowers?actor=did%3Aplc%3Aabc123&limit=100": {
            "followers": [{"did": "did:plc:a", "handle": "alice.bsky.social"}], "cursor": "page2",
        },
        "/xrpc/app.bsky.graph.getFollowers?actor=did%3Aplc%3Aabc123&limit=100&cursor=page2": {
            # A handle that stopped verifying: the DID still names the account.
            "followers": [{"did": "did:plc:c", "handle": "handle.invalid"}],
        },
    }, seen)
    claims = lookup_bluesky_network("kyle.dev", client=client)
    edges = {t for t in triples(claims) if t[1] == "follows"}
    assert edges == {
        ("bluesky:kyle.dev", "follows", "bluesky:bob.bsky.social"),
        ("bluesky:alice.bsky.social", "follows", "bluesky:kyle.dev"),
        ("bluesky:did:plc:c", "follows", "bluesky:kyle.dev"),
    }
    follows = [c for c in claims if c.predicate == "follows"]
    assert all(c.confidence == BASE_CONFIDENCE["authoritative"] for c in follows)
    assert follows[0].evidence_url == "https://bsky.app/profile/kyle.dev/follows"
    assert len(seen) == 4


def test_lookup_bluesky_network_stops_at_the_limit():
    many = {"follows": [{"did": f"did:plc:{i}", "handle": f"u{i}.bsky.social"} for i in range(5)], "cursor": "more"}
    client = mock_client({
        "/xrpc/app.bsky.actor.getProfile": BSKY_PROFILE,
        "/xrpc/app.bsky.graph.getFollows": many,
        "/xrpc/app.bsky.graph.getFollowers": {"followers": []},
    })
    claims = lookup_bluesky_network("kyle.dev", client=client, limit=3)
    assert sum(c.predicate == "follows" for c in claims) == 3


# --- GitHub ---

GITHUB_USER = {
    "login": "Kyle-Bolin", "name": "Kyle", "html_url": "https://github.com/Kyle-Bolin",
    "blog": "https://kyle.dev", "twitter_username": "kyle_b", "company": None,
    "followers": 1, "following": 2, "created_at": "2021-03-04T00:00:00Z",
}
GITHUB_ROUTES = {
    "/users/kyle-bolin": GITHUB_USER,
    "/users/kyle-bolin/social_accounts": [{"provider": "linkedin", "url": "https://www.linkedin.com/in/kyle-bolin"}],
    "/users/kyle-bolin/followers": [{"login": "Alice", "html_url": "https://github.com/Alice"}],
    "/users/kyle-bolin/following": (200, [{"login": "octocat", "html_url": "https://github.com/octocat"}],
                                    {"Link": '<https://api.github.com/users/kyle-bolin/following?per_page=100&page=2>; rel="next"'}),
    "/users/kyle-bolin/following?per_page=100&page=2": [{"login": "torvalds", "html_url": "https://github.com/torvalds"}],
}


def test_lookup_github_network_maps_follows_and_linked_accounts(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seen = []
    claims = lookup_github_network("kyle-bolin", client=mock_client(GITHUB_ROUTES, seen))
    found = triples(claims)
    assert ("github:kyle-bolin", "follows", "github:octocat") in found
    assert ("github:kyle-bolin", "follows", "github:torvalds") in found  # from page 2
    assert ("github:alice", "follows", "github:kyle-bolin") in found
    # Typed into the profile, so weak; profile URLs become account nodes.
    linked = {c.object: c.confidence for c in claims if c.predicate in ("claims_account", "links_to")}
    assert linked == {"linkedin:kyle-bolin": 0.4, "https://kyle.dev": 0.4, "x:kyle_b": 0.4}
    assert "Authorization" not in seen[0].headers


def test_lookup_github_network_sends_the_token_in_a_header():
    seen = []
    claims = lookup_github_network("kyle-bolin", client=mock_client(GITHUB_ROUTES, seen), token="ghp_secret")
    assert all(r.headers["Authorization"] == "Bearer ghp_secret" for r in seen)
    assert all("ghp_secret" not in str(r.url) for r in seen)
    assert all("ghp_secret" not in c.evidence_url for c in claims)


# --- Mastodon ---

MASTODON_ACCOUNT = {
    "id": "109", "acct": "kyle", "display_name": "Kyle", "url": "https://infosec.exchange/@kyle",
    "followers_count": 1, "following_count": 1, "created_at": "2022-11-01T00:00:00.000Z",
    "fields": [
        {"name": "Website", "value": '<a href="https://kyle.dev" rel="me nofollow noopener noreferrer" target="_blank">kyle.dev</a>',
         "verified_at": "2023-01-01T00:00:00.000+00:00"},
        {"name": "GitHub", "value": '<a href="https://github.com/Kyle-Bolin" rel="me">github.com/Kyle-Bolin</a>',
         "verified_at": None},
        {"name": "Pronouns", "value": "they/them", "verified_at": None},
    ],
}


def test_mastodon_verified_links_are_authoritative_and_others_weak():
    claims = parse_mastodon_account(MASTODON_ACCOUNT, "infosec.exchange")
    by_object = {c.object: (c.predicate, c.confidence) for c in claims if c.predicate in ("verified_link", "claims_account", "links_to")}
    assert by_object == {
        "https://kyle.dev": ("verified_link", BASE_CONFIDENCE["authoritative"]),
        "github:kyle-bolin": ("claims_account", BASE_CONFIDENCE["weak"]),
    }


def test_lookup_mastodon_network_adds_the_server_to_local_accounts():
    client = mock_client({
        "/api/v1/accounts/lookup": MASTODON_ACCOUNT,
        "/api/v1/accounts/109/following": [{"acct": "bob@mastodon.social", "url": "https://mastodon.social/@bob"}],
        "/api/v1/accounts/109/followers": [{"acct": "carol", "url": "https://infosec.exchange/@carol"}],
    })
    claims = lookup_mastodon_network("kyle@infosec.exchange", client=client)
    edges = {t for t in triples(claims) if t[1] == "follows"}
    assert edges == {
        ("mastodon:kyle@infosec.exchange", "follows", "mastodon:bob@mastodon.social"),
        ("mastodon:carol@infosec.exchange", "follows", "mastodon:kyle@infosec.exchange"),
    }


# --- X (paid) ---

X_USER = {"data": {
    "id": "42", "username": "Kyle_B", "name": "Kyle", "created_at": "2015-01-01T00:00:00.000Z",
    "public_metrics": {"followers_count": 5000, "following_count": 3},
    "entities": {"url": {"urls": [{"url": "https://t.co/x", "expanded_url": "https://kyle.dev"}]}},
}}


def test_x_without_a_key_fails_before_any_request(monkeypatch):
    monkeypatch.delenv("X_BEARER_TOKEN", raising=False)
    seen = []
    with pytest.raises(MissingAPIKey):
        lookup_x_network("kyle_b", client=mock_client({}, seen))
    assert seen == []


def test_x_asks_only_for_what_the_cap_allows(monkeypatch):
    monkeypatch.setenv("X_MAX_ACCOUNTS", "2")
    seen = []
    client = mock_client({
        "/2/users/by/username/kyle_b": X_USER,
        "/2/users/42/following": {"data": [{"id": "7", "username": "Bob"}], "meta": {"result_count": 1}},
        "/2/users/42/followers?max_results=2": {
            "data": [{"id": "8", "username": "alice"}], "meta": {"result_count": 1, "next_token": "t" * 16},
        },
        f"/2/users/42/followers?max_results=1&pagination_token={'t' * 16}": {
            "data": [{"id": "9", "username": "carol"}], "meta": {"result_count": 1, "next_token": "u" * 16},
        },
    }, seen)
    claims = lookup_x_network("kyle_b", client=client, token="secret")
    edges = {t for t in triples(claims) if t[1] == "follows"}
    assert edges == {
        ("x:kyle_b", "follows", "x:bob"),
        ("x:alice", "follows", "x:kyle_b"),
        ("x:carol", "follows", "x:kyle_b"),
    }
    # 5,000 followers, but the cap stopped it after 2: one profile + 3 list pages.
    assert len(seen) == 4
    assert all(int(r.url.params.get("max_results", 0)) <= 2 for r in seen)
    assert all(r.headers["Authorization"] == "Bearer secret" for r in seen)
    assert ("x:kyle_b", "links_to", "https://kyle.dev") in triples(claims)


def test_x_missing_user_is_an_http_error():
    client = mock_client({"/2/users/by/username/nobody": {"errors": [{"detail": "Could not find user"}]}})
    with pytest.raises(httpx.HTTPStatusError, match="Could not find user"):
        lookup_x_network("nobody", client=client, token="secret")


# --- the app ---

@pytest.mark.parametrize("raw,expected", [
    ("github:Octocat", ("github:octocat", "account")),
    ("@kyle@infosec.exchange", ("mastodon:kyle@infosec.exchange", "account")),
    ("bluesky:kyle.dev", ("bluesky:kyle.dev", "account")),
    ("kyle.dev", ("kyle.dev", "domain")),          # without a prefix it's a domain
    ("https://x.com/kyle", ("x.com", "domain")),   # a URL is still a domain
])
def test_clean_target_tells_accounts_from_domains(raw, expected):
    assert app_module.clean_target(raw) == expected


def test_api_runs_only_the_platforms_module_with_the_bare_handle(monkeypatch):
    calls = []

    def github(username):
        calls.append(username)
        return [Claim("github:" + username, "follows", "github:octocat", "github", 0.95),
                Claim("github:" + username, "claims_account", "linkedin:kyle", "github", 0.4),
                Claim("github:" + username, "claims_account", "x:kyle_b", "github", 0.4)]

    monkeypatch.setitem(app_module.ACCOUNT_MODULES, "github", github)
    client = TestClient(app_module.app)
    body = client.get("/api/lookup", params={"q": "github:Kyle-Bolin"}).json()
    assert calls == ["kyle-bolin"]
    assert body["kind"] == "account" and list(body["modules"]) == ["github"]
    assert client.get("/api/lookup", params={"q": "github:not valid"}).status_code == 400

    html = client.get("/", params={"q": "github:kyle-bolin"}).text
    assert 'href="/?q=x%3Akyle_b"' in html             # your own linked account: one click to look up
    assert 'href="/?q=linkedin%3Akyle"' not in html     # nothing can look up LinkedIn
    assert 'href="/?q=github%3Aoctocat"' not in html    # someone you follow: no lookup link, one hop only
