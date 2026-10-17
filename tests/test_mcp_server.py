"""The MCP server, tested through a real MCP client.

`Client(server)` connects in-process, so these tests exercise the same
list-tools and call-tool messages Claude sends, without a subprocess or the
network. The lookups themselves are swapped for fakes.
"""
import asyncio
import sys
from pathlib import Path

import httpx
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from osint import mcp_server, notebook
from osint.claims import Claim

REPO_ROOT = Path(__file__).parent.parent
LOOKUP_TOOLS = {"dns_records", "rdap_registration", "ct_subdomains"}
CASE_TOOLS = {"list_cases", "create_case", "read_case", "add_case_note", "save_lookup_to_case"}


def call(tool: str, arguments: dict):
    async def go():
        async with Client(mcp_server.server) as client:
            return await client.call_tool(tool, arguments)
    return asyncio.run(go())


def list_tools(server_or_params):
    async def go():
        async with Client(server_or_params) as client:
            return (await client.list_tools()).tools
    return asyncio.run(go())


def test_one_read_only_tool_per_module():
    tools = {t.name: t for t in list_tools(mcp_server.server)}
    assert set(tools) == LOOKUP_TOOLS | CASE_TOOLS
    for name in LOOKUP_TOOLS:
        assert tools[name].annotations.read_only_hint
        assert "claims" in tools[name].output_schema["properties"]
    # Every lookup can also be saved into a case.
    assert set(mcp_server.CASE_LOOKUPS) == LOOKUP_TOOLS


def test_tool_returns_claims_found_by_ai_with_rule_based_confidence(monkeypatch):
    def fake_dns(domain):
        return [Claim(domain, "has_ipv4", "93.184.216.34", "dns", 0.95)]

    monkeypatch.setattr(mcp_server, "lookup_dns", fake_dns)
    result = call("dns_records", {"domain": "https://www.Example.com/path"})
    assert not result.is_error
    assert result.structured_content["domain"] == "example.com"
    claim = result.structured_content["claims"][0]
    assert claim["object"] == "93.184.216.34"
    assert claim["found_by"] == "ai"
    assert claim["confidence"] == 0.95


def test_bad_input_and_upstream_failures_come_back_as_readable_errors(monkeypatch):
    result = call("dns_records", {"domain": "not a domain"})
    assert result.is_error
    assert "Not a valid domain" in result.content[0].text

    def down(domain):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(mcp_server, "lookup_rdap", down)
    result = call("rdap_registration", {"domain": "example.com"})
    assert result.is_error
    assert "ConnectError: connection refused" in result.content[0].text


def test_server_starts_over_stdio():
    # How Claude launches it: a subprocess speaking MCP on stdin/stdout.
    # Listing tools makes no lookups, so this stays offline.
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "osint.mcp_server"], cwd=REPO_ROOT,
    )
    assert {t.name for t in list_tools(params)} == LOOKUP_TOOLS | CASE_TOOLS


def fake_dns(domain):
    return [Claim(domain, "has_ipv4", "93.184.216.34", "dns", 0.95)]


def test_case_tools_share_the_notebook_with_the_web_app(monkeypatch):
    tools = {t.name: t for t in list_tools(mcp_server.server)}
    for name in CASE_TOOLS - {"list_cases", "read_case"}:
        assert not tools[name].annotations.read_only_hint  # they write, so they must say so

    monkeypatch.setattr(mcp_server, "lookup_dns", fake_dns)
    case_id = call("create_case", {"name": "Claude's case"}).structured_content["id"]
    result = call("save_lookup_to_case", {"case_id": case_id, "lookup": "dns_records", "target": "Example.com"})
    assert not result.is_error
    assert result.structured_content["claims"][0]["found_by"] == "ai"
    assert not call("add_case_note", {"case_id": case_id, "note": "IANA's reserved example range"}).is_error

    # The same rows the web app's case page reads.
    db = notebook.connect()
    [lookup] = notebook.case_lookups(db, case_id)
    assert (lookup["module"], lookup["target"], lookup["run_by"], lookup["claim_count"]) == ("dns", "example.com", "ai", 1)
    assert notebook.case_notes(db, case_id)[0]["written_by"] == "ai"

    [listed] = call("list_cases", {}).structured_content["result"]
    assert (listed["name"], listed["lookup_count"], listed["note_count"]) == ("Claude's case", 1, 1)
    report = call("read_case", {"case_id": case_id}).content[0].text
    assert "93.184.216.34" in report and "(written by ai)" in report


def test_case_tools_refuse_bad_input_and_save_nothing_on_failure(monkeypatch):
    def down(domain):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(mcp_server, "lookup_rdap", down)
    case_id = call("create_case", {"name": "errors"}).structured_content["id"]

    for tool, arguments, message in [
        ("read_case", {"case_id": 99}, "No case with id 99"),
        ("create_case", {"name": "  "}, "needs a name"),
        ("add_case_note", {"case_id": case_id, "note": " "}, "empty"),
        ("save_lookup_to_case", {"case_id": case_id, "lookup": "whois", "target": "example.com"}, "Unknown lookup"),
        ("save_lookup_to_case", {"case_id": case_id, "lookup": "rdap_registration", "target": "example.com"},
         "ConnectError"),
    ]:
        result = call(tool, arguments)
        assert result.is_error, tool
        assert message in result.content[0].text
    assert notebook.case_lookups(notebook.connect(), case_id) == []
