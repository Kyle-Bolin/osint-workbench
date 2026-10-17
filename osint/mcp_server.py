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
import ipaddress
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
from osint.modules.asn import lookup_asn
from osint.modules.crtsh import lookup_subdomains
from osint.modules.dns_lookup import lookup_dns, lookup_reverse_dns
from osint.modules.geoip import lookup_geo
from osint.modules.rdap import lookup_ip_rdap, lookup_rdap

log = logging.getLogger(__name__)

# The client shows these to Claude when it connects: the house rules from CLAUDE.md.
INSTRUCTIONS = """\
Lookups from a personal OSINT workbench. Every tool returns claims
(subject -predicate-> object), each with a source, a rationale and a
confidence score set by the workbench's own rules. Explain a score if it
helps, but never invent or change one. Domain tools take a domain; IP tools
take a public IP, such as an address dns_records found. Only investigate the
owner's own domains, CTF targets, and bug-bounty programs that allow recon.
"""

server = MCPServer("osint-workbench", instructions=INSTRUCTIONS)

# Tells the client these tools only read public data, so they're safe to
# auto-approve, but they do reach out to the internet.
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=True)

# Same rules as clean_domain and clean_target in osint/app.py. Kept here so
# the MCP server doesn't import the web app; worth moving into one shared
# helper when usernames add a third kind of input.
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")

# Failures we expect from upstream services (timeouts, HTTP errors, a garbled
# crt.sh response). Claude gets the message so it can retry or move on. Anything
# else is a bug: the SDK logs its traceback and Claude only sees "Error executing tool".
UPSTREAM_ERRORS = (httpx.HTTPError, dns.exception.DNSException, json.JSONDecodeError)


@dataclass
class LookupResult:
    target: str          # the cleaned domain or IP that was actually looked up
    claims: list[Claim]


def clean_domain(raw: str) -> str:
    domain = raw.strip().lower().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0].removeprefix("www.")
    if not DOMAIN_RE.match(domain):
        raise ToolError(f"Not a valid domain: {raw!r}")
    return domain


def clean_ip(raw: str) -> str:
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        raise ToolError(f"Not a valid IP address: {raw!r}") from None
    if not ip.is_global:  # 192.168.x.x, 10.x.x.x, ::1 and friends
        raise ToolError(f"{ip} is a private or reserved address; public lookups can't see it")
    return str(ip)


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
def reverse_dns(ip: str) -> LookupResult:
    """Look up an IP address's reverse DNS (PTR record): the hostname the
    IP's owner gave it, which often names the hosting company or service.
    A hint, not proof, since nothing checks it. Fast."""
    return run_lookup(lookup_reverse_dns, ip, clean_ip)


@server.tool(annotations=READ_ONLY)
def ip_asn(ip: str) -> LookupResult:
    """Find which network announces an IP address: its origin AS number and
    name (like AS15169 GOOGLE) and the routed prefix, from BGP data via
    Team Cymru. Fast. Usually names the hosting provider or CDN."""
    return run_lookup(lookup_asn, ip, clean_ip)


@server.tool(annotations=READ_ONLY)
def ip_network(ip: str) -> LookupResult:
    """Look up who an IP address's block is registered to, via RDAP at the
    regional registry (ARIN, RIPE, ...): network name, owner, address range,
    country and abuse contact. An independent check on ip_asn."""
    return run_lookup(lookup_ip_rdap, ip, clean_ip)


@server.tool(annotations=READ_ONLY)
def ip_geolocation(ip: str) -> LookupResult:
    """Estimate where an IP address is (country, city, coordinates) from
    ipinfo.io. It's a commercial database's guess: the country is usually
    right, the city often isn't, and anycast IPs have no single location,
    so these claims start at a low confidence. Rate-limited without a token."""
    return run_lookup(lookup_geo, ip, clean_ip)


if __name__ == "__main__":
    server.run()  # stdio transport: the client starts us and owns stdin/stdout
