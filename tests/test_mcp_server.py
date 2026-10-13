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

from osint import mcp_server
from osint.claims import Claim

REPO_ROOT = Path(__file__).parent.parent


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
    assert set(tools) == {"dns_records", "rdap_registration", "ct_subdomains"}
    for tool in tools.values():
        assert tool.annotations.read_only_hint
        assert "claims" in tool.output_schema["properties"]


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
    assert {t.name for t in list_tools(params)} == {"dns_records", "rdap_registration", "ct_subdomains"}
