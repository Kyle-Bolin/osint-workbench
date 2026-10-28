"""Social media accounts as claim nodes, written `platform:handle`.

A domain or an IP names itself, but a handle doesn't: `kyle` on GitHub and
`kyle` on X can be different people. So every account claim uses
`platform:handle` (`github:octocat`, `bluesky:kyle.dev`,
`mastodon:kyle@infosec.exchange`, `x:kyle`) as its subject or object, and the
pivot graph gets one node per account.

The prefix is also how the app tells an account from a domain: a Bluesky
handle like `kyle.dev` *is* a domain name, so it can't be told apart any
other way.
"""
import re
from urllib.parse import urlparse

from osint.claims import BASE_CONFIDENCE, Claim

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
GITHUB_RE = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,38}$")
X_RE = re.compile(r"^[a-z0-9_]{1,15}$")
MASTODON_USER_RE = re.compile(r"^[a-z0-9_]{1,30}$")
BLUESKY_DID_RE = re.compile(r"^did:(plc|web):[a-z0-9._:%-]+$")


def clean_bluesky(raw: str) -> str:
    handle = raw.strip().lower().removeprefix("@")
    if not (DOMAIN_RE.match(handle) or BLUESKY_DID_RE.match(handle)):
        raise ValueError(f"Not a Bluesky handle: {raw!r} (expected something like kyle.bsky.social)")
    return handle


def clean_github(raw: str) -> str:
    login = raw.strip().lower().removeprefix("@")  # GitHub logins ignore case
    if not GITHUB_RE.match(login):
        raise ValueError(f"Not a GitHub username: {raw!r}")
    return login


def clean_mastodon(raw: str) -> str:
    """`@kyle@infosec.exchange` -> `kyle@infosec.exchange`. The server part is
    required: there is no central Mastodon, so a bare name means nothing."""
    address = raw.strip().lower().removeprefix("@")
    user, _, server = address.partition("@")
    if not (MASTODON_USER_RE.match(user) and DOMAIN_RE.match(server)):
        raise ValueError(f"Not a Mastodon address: {raw!r} (expected user@server, like kyle@infosec.exchange)")
    return address


def clean_x(raw: str) -> str:
    username = raw.strip().lower().removeprefix("@")
    if not X_RE.match(username):
        raise ValueError(f"Not an X username: {raw!r}")
    return username


CLEANERS = {"bluesky": clean_bluesky, "github": clean_github, "mastodon": clean_mastodon, "x": clean_x}


def parse_account(raw: str) -> tuple[str, str]:
    """`github:Octocat` -> ("github", "octocat"). `@user@server` alone is a
    Mastodon address. Raises ValueError for anything else."""
    text = raw.strip()
    if text.startswith("@") and text.count("@") == 2:
        return "mastodon", clean_mastodon(text)
    platform, sep, handle = text.partition(":")
    platform = platform.lower()
    if not sep or platform not in CLEANERS:
        raise ValueError(f"Not an account: {raw!r} (try {', '.join(p + ':name' for p in CLEANERS)})")
    return platform, CLEANERS[platform](handle)


def looks_like_account(raw: str) -> bool:
    """True for `platform:...` with a known platform, or `@user@server`."""
    text = raw.strip()
    return text.startswith("@") or text.partition(":")[0].lower() in CLEANERS


# Profile URLs people paste into their bios, mapped back to account nodes.
_PROFILE_URLS = [
    ("github", {"github.com", "www.github.com"}, re.compile(r"^/([^/]+)/?$")),
    ("x", {"x.com", "www.x.com", "twitter.com", "www.twitter.com"}, re.compile(r"^/([^/]+)/?$")),
    ("bluesky", {"bsky.app"}, re.compile(r"^/profile/([^/]+)/?$")),
]


def account_from_url(url: str) -> str | None:
    """`https://github.com/octocat` -> `github:octocat`; None if the URL isn't
    a profile page we recognise. LinkedIn profiles become `linkedin:<slug>`
    nodes even though nothing here can look them up: LinkedIn's API doesn't
    offer connections to individual developers."""
    parsed = urlparse(url if "://" in url else "https://" + url)
    host, path = parsed.netloc.lower(), parsed.path
    if host in {"linkedin.com", "www.linkedin.com"}:
        match = re.match(r"^/in/([^/]+)/?$", path)
        return f"linkedin:{match.group(1).lower()}" if match else None
    for platform, hosts, pattern in _PROFILE_URLS:
        match = pattern.match(path) if host in hosts else None
        if match:
            try:
                return f"{platform}:{CLEANERS[platform](match.group(1))}"
            except ValueError:
                return None
    # Mastodon servers have any domain, but profile paths look like /@user.
    match = re.match(r"^/@([a-z0-9_]{1,30})/?$", path, re.IGNORECASE)
    if match and DOMAIN_RE.match(host):
        return f"mastodon:{match.group(1).lower()}@{host}"
    return None


def follow_claims(
    account: str, following: list[str], followers: list[str], source: str,
    following_url: str = "", followers_url: str = "",
) -> list[Claim]:
    """Turn the two lists of account nodes into `follows` edges pointing the right way.

    The platform's own list is its record of who follows whom, so the edge is
    "authoritative": true at the moment it was read, though follows change.
    The evidence URL is the list page where you can see it yourself.
    """
    def edge(subject: str, obj: str, url: str, why: str) -> Claim:
        return Claim(
            subject=subject, predicate="follows", object=obj, source=source,
            confidence=BASE_CONFIDENCE["authoritative"], rationale=why, evidence_url=url,
        )

    claims = [edge(account, other, following_url, f"in {account}'s following list") for other in following]
    claims += [edge(other, account, followers_url, f"in {account}'s followers list") for other in followers]
    return claims


def linked_account_claims(account: str, urls: list[str], source: str, why: str) -> list[Claim]:
    """Links the account owner typed into their own profile. Anyone can type
    any URL there, so these start at "weak" until something verifies them."""
    claims = []
    for url in urls:
        other = account_from_url(url)
        claims.append(Claim(
            subject=account, predicate="claims_account" if other else "links_to",
            object=other or url, source=source, confidence=BASE_CONFIDENCE["weak"],
            rationale=why, evidence_url=url,
        ))
    return claims
