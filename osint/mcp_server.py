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

from osint.claims import Claim
from osint.modules.crtsh import lookup_subdomains
from osint.modules.dns_lookup import lookup_dns
from osint.modules.rdap import lookup_rdap
from osint.modules.wayback import lookup_wayback

log = logging.getLogger(__name__)

# The client shows these to Claude when it connects: the house rules from CLAUDE.md.
INSTRUCTIONS = """\
Lookups from a personal OSINT workbench. Every tool returns claims
(subject -predicate-> object), each with a source, a rationale and a
confidence score set by the workbench's own rules. Explain a score if it
helps, but never invent or change one. Only investigate the owner's own
domains, CTF targets, and bug-bounty programs that allow recon.
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
UPSTREAM_ERRORS = (httpx.HTTPError, dns.exception.DNSException, json.JSONDecodeError)


@dataclass
class LookupResult:
    domain: str          # the cleaned domain that was actually looked up
    claims: list[Claim]


def clean_domain(raw: str) -> str:
    domain = raw.strip().lower().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0].removeprefix("www.")
    if not DOMAIN_RE.match(domain):
        raise ToolError(f"Not a valid domain: {raw!r}")
    return domain


def run_lookup(lookup: Callable[[str], list[Claim]], raw_domain: str) -> LookupResult:
    domain = clean_domain(raw_domain)
    try:
        claims = lookup(domain)
    except UPSTREAM_ERRORS as exc:
        raise ToolError(f"{type(exc).__name__}: {exc}") from exc
    # Provenance: the AI ran this lookup. The confidence is untouched, because
    # it comes from the module's source rules, not from who asked.
    claims = [replace(c, found_by="ai") for c in claims]
    # Logged to stderr so every AI tool call can be traced later.
    log.info("%s(%r) -> %d claims", lookup.__name__, domain, len(claims))
    return LookupResult(domain=domain, claims=claims)


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
def wayback_history(domain: str) -> LookupResult:
    """Look up a domain's history in the Wayback Machine: the first archived
    capture of its homepage in each year, with a link to view that snapshot.
    Shows when a site first appeared, years it went dark, and how it changed.
    The archive can be slow or busy, so retry once on errors."""
    return run_lookup(lookup_wayback, domain)


if __name__ == "__main__":
    server.run()  # stdio transport: the client starts us and owns stdin/stdout
