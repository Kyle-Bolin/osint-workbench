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
import sqlite3
from contextlib import closing
from dataclasses import dataclass, replace
from typing import Callable

import dns.exception
import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from osint import notebook
from osint.claims import Claim
from osint.modules.crtsh import lookup_subdomains
from osint.modules.dns_lookup import lookup_dns
from osint.modules.rdap import lookup_rdap

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


# --- Case notebook --------------------------------------------------------
# The same cases as the web app's Cases page (osint/notebook.py), so Claude
# and you work in one notebook. The tools that write to it aren't marked
# read-only, but they only ever add rows (nothing here edits or deletes),
# which is what destructive_hint=False tells the client.

NOTEBOOK_READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)
NOTEBOOK_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)
# save_lookup_to_case does both: a lookup on the internet, then a notebook write.
LOOKUP_AND_SAVE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True)

# Lookup tools whose results can be saved into a case: tool name -> (the
# module name the web app uses, so a case's lookup log reads the same either
# way, and the tool function). A new lookup tool gets a line here too.
CASE_LOOKUPS = {
    "dns_records": ("dns", dns_records),
    "rdap_registration": ("rdap", rdap_registration),
    "ct_subdomains": ("subdomains", ct_subdomains),
}


@dataclass
class CaseInfo:
    id: int
    name: str
    description: str
    created_at: str
    lookup_count: int = 0
    note_count: int = 0


def require_case(db: sqlite3.Connection, case_id: int) -> dict:
    case = notebook.get_case(db, case_id)
    if case is None:
        raise ToolError(f"No case with id {case_id}; list_cases shows the ones that exist")
    return case


@server.tool(annotations=NOTEBOOK_READ)
def list_cases() -> list[CaseInfo]:
    """List the investigations (cases) in the workbench's notebook, newest
    first, with how many lookups and notes each holds. Use it to find the
    case_id the other case tools need."""
    with closing(notebook.connect()) as db:
        return [CaseInfo(**case) for case in notebook.list_cases(db)]


@server.tool(annotations=NOTEBOOK_WRITE)
def create_case(name: str, description: str = "") -> CaseInfo:
    """Start a new case: a notebook for one investigation that keeps every
    saved lookup's claims (with when and by whom) and notes. The owner sees
    it on the web app's Cases page and can export it as Markdown."""
    if not name.strip():
        raise ToolError("A case needs a name")
    with closing(notebook.connect()) as db:
        case_id = notebook.create_case(db, name, description)
        return CaseInfo(**notebook.get_case(db, case_id))


@server.tool(annotations=NOTEBOOK_READ)
def read_case(case_id: int) -> str:
    """Read a whole case as Markdown: its notes, its claims grouped by
    subject (repeats folded together, with first and last seen), and the log
    of lookups run in it. Read it before adding to a case you didn't start."""
    with closing(notebook.connect()) as db:
        require_case(db, case_id)
        return notebook.export_markdown(db, case_id)


@server.tool(annotations=NOTEBOOK_WRITE)
def add_case_note(case_id: int, note: str) -> str:
    """Add a note to a case: what you noticed, what you concluded and why,
    or what to check next. Notes are marked as written by the AI. Put
    findings in claims (via save_lookup_to_case), not in notes; notes are
    for reasoning, and you never set a confidence score yourself."""
    if not note.strip():
        raise ToolError("The note is empty")
    with closing(notebook.connect()) as db:
        require_case(db, case_id)
        notebook.add_note(db, case_id, note, written_by="ai")
    return f"Note added to case {case_id}"


@server.tool(annotations=LOOKUP_AND_SAVE)
def save_lookup_to_case(case_id: int, lookup: str, target: str) -> LookupResult:
    """Run one lookup tool and save its claims into a case. When you're
    working a case, use this instead of calling the lookup tool directly, so
    the results stay with the investigation. `lookup` is the lookup tool's
    name (dns_records, rdap_registration or ct_subdomains) and `target` is
    what that tool takes. Returns the same claims the lookup tool would."""
    if lookup not in CASE_LOOKUPS:
        raise ToolError(f"Unknown lookup {lookup!r}; use one of: {', '.join(CASE_LOOKUPS)}")
    module, tool = CASE_LOOKUPS[lookup]
    with closing(notebook.connect()) as db:
        require_case(db, case_id)  # before the lookup, so a typo doesn't waste a slow call
        result = tool(target)  # a failed lookup raises ToolError and saves nothing
        notebook.record_lookup(db, case_id, module, result.domain, result.claims, run_by="ai")
    return result


if __name__ == "__main__":
    server.run()  # stdio transport: the client starts us and owns stdin/stdout
