"""MCP server: lets Claude (Desktop or Code) run the lookup modules as tools.

MCP (Model Context Protocol) is how an AI client discovers and calls tools.
Claude starts this file as a subprocess and talks JSON-RPC over its
stdin/stdout, so nothing here may print to stdout: logs go to stderr.

Each tool is a thin wrapper around a `lookup_x` function. The function's type
hints become the tool's input schema, its docstring becomes the description
Claude reads to decide when to call it, and the `LookupResult` dataclass
becomes the output schema.

Run it: python -m osint.mcp_server   (see "Use it from Claude" in the README)
"""
import json
import logging
import re
from dataclasses import dataclass, replace
from typing import Callable

import dns.exception
import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from osint import accounts
from osint.claims import Claim
from osint.modules.bluesky import lookup_bluesky_network
from osint.modules.crtsh import lookup_subdomains
from osint.modules.dns_lookup import lookup_dns
from osint.modules.github import lookup_github_network
from osint.modules.mastodon import lookup_mastodon_network
from osint.modules.rdap import lookup_rdap
from osint.modules.x_api import MissingAPIKey, lookup_x_network

log = logging.getLogger(__name__)

# The client shows these to Claude when it connects: the house rules from CLAUDE.md.
INSTRUCTIONS = """\
Lookups from a personal OSINT workbench. Every tool returns claims
(subject -predicate-> object), each with a source, a rationale and a
confidence score set by the workbench's own rules. Explain a score if it
helps, but never invent or change one. Only investigate the owner's own
domains, CTF targets, and bug-bounty programs that allow recon.

The *_network tools map a social account's follows and followers. Only run
them on the owner's own accounts (or an organisation or CTF account), never
on accounts that turn up in a follow list: mapping stays one hop out.
x_network costs real money per account read, so only call it when the owner
asks for X specifically.
"""

server = MCPServer("osint-workbench", instructions=INSTRUCTIONS)

# Tells the client these tools only read public data, so they're safe to
# auto-approve, but they do reach out to the internet.
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=True)

# Same rules as clean_domain in osint/app.py. Kept here so the MCP server
# doesn't import the web app; the two can share one helper once the app
# routes by input type (IP lookups, usernames).
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")

# Failures we expect from upstream services (timeouts, HTTP errors, a garbled
# crt.sh response). Claude gets the message so it can retry or move on. Anything
# else is a bug: the SDK logs its traceback and Claude only sees "Error executing tool".
UPSTREAM_ERRORS = (httpx.HTTPError, dns.exception.DNSException, json.JSONDecodeError, MissingAPIKey)


@dataclass
class LookupResult:
    target: str          # the cleaned domain, IP or handle that was actually looked up
    claims: list[Claim]


def clean_domain(raw: str) -> str:
    domain = raw.strip().lower().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0].removeprefix("www.")
    if not DOMAIN_RE.match(domain):
        raise ToolError(f"Not a valid domain: {raw!r}")
    return domain


def handle_cleaner(clean: Callable[[str], str]) -> Callable[[str], str]:
    """The account cleaners in osint/accounts.py raise ValueError; Claude needs a ToolError."""
    def cleaned(raw: str) -> str:
        try:
            return clean(raw)
        except ValueError as exc:
            raise ToolError(str(exc)) from None
    return cleaned


def run_lookup(
    lookup: Callable[[str], list[Claim]], raw: str, clean: Callable[[str], str] = clean_domain,
) -> LookupResult:
    target = clean(raw)
    try:
        claims = lookup(target)
    except UPSTREAM_ERRORS as exc:
        raise ToolError(f"{type(exc).__name__}: {exc}") from exc
    # Provenance: the AI ran this lookup. The confidence is untouched, because
    # it comes from the module's source rules, not from who asked.
    claims = [replace(c, found_by="ai") for c in claims]
    # Logged to stderr so every AI tool call can be traced later.
    log.info("%s(%r) -> %d claims", lookup.__name__, target, len(claims))
    return LookupResult(target=target, claims=claims)


@server.tool(annotations=READ_ONLY)
def dns_records(domain: str) -> LookupResult:
    """Look up a domain's DNS records: A and AAAA (IP addresses), MX (mail
    servers), NS (nameservers), TXT (SPF, site verification) and CNAME (alias).
    Fast. A good first step for any domain."""
    return run_lookup(lookup_dns, domain)


@server.tool(annotations=READ_ONLY)
def rdap_registration(domain: str) -> LookupResult:
    """Look up a domain's registration data via RDAP (the modern WHOIS):
    registrar, registration/expiry/last-changed dates, nameservers and status
    flags. Only works on registered domains, not subdomains."""
    return run_lookup(lookup_rdap, domain)


@server.tool(annotations=READ_ONLY)
def ct_subdomains(domain: str) -> LookupResult:
    """Find a domain's subdomains from certificate transparency logs (crt.sh):
    every name that has appeared on a public TLS certificate. Can take up to
    30 seconds, and crt.sh is sometimes overloaded, so retry once on errors."""
    return run_lookup(lookup_subdomains, domain)


@server.tool(annotations=READ_ONLY)
def bluesky_network(handle: str) -> LookupResult:
    """Map a Bluesky account: profile, who it follows and who follows it (up
    to 200 of each), as `follows` claims between `bluesky:handle` nodes. A
    handle that is a domain (not *.bsky.social) comes back as a
    verified_domain claim, which links it to that domain's lookups. Free."""
    return run_lookup(lookup_bluesky_network, handle, handle_cleaner(accounts.clean_bluesky))


@server.tool(annotations=READ_ONLY)
def github_network(username: str) -> LookupResult:
    """Map a GitHub user: profile, the website and social accounts they list
    (weak claims, since nothing checks them), who they follow and who follows
    them (up to 200 of each). Free; GitHub allows about 10 of these an hour
    without a GITHUB_TOKEN."""
    return run_lookup(lookup_github_network, username, handle_cleaner(accounts.clean_github))


@server.tool(annotations=READ_ONLY)
def mastodon_network(address: str) -> LookupResult:
    """Map a Mastodon account, given as user@server (like kyle@infosec.exchange):
    profile, links (verified ones are checked by the server with rel="me"),
    who it follows and who follows it (up to 200 of each). Free. Lists are
    empty if the account hides them."""
    return run_lookup(lookup_mastodon_network, address, handle_cleaner(accounts.clean_mastodon))


@server.tool(annotations=READ_ONLY)
def x_network(username: str) -> LookupResult:
    """Map an X (Twitter) account: profile, who it follows and who follows it,
    capped at X_MAX_ACCOUNTS of each (default 100). Uses X's PAID API: about
    $0.01 per account read, so up to about $2 per call. Only use it when the
    owner asks for X. Fails without X_BEARER_TOKEN, before anything is charged."""
    return run_lookup(lookup_x_network, username, handle_cleaner(accounts.clean_x))


if __name__ == "__main__":
    server.run()  # stdio transport: the client starts us and owns stdin/stdout
