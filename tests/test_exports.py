"""Reading your own LinkedIn and X data exports. No network: the samples are
made-up rows in the shape the real export files use."""
import asyncio
import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from mcp import Client

from osint import app as app_module
from osint import mcp_server
from osint.claims import Claim
from osint.modules import exports
from osint.modules.exports import linkedin_owner, parse_linkedin_connections, parse_x_archive, read_exports

# The real file opens with a note about missing emails before the header.
CONNECTIONS_CSV = '''﻿Notes:
"When exporting your connection data, you may notice that some of the email addresses are missing."

First Name,Last Name,URL,Email Address,Company,Position,Connected On
Ada,Lovelace,https://www.linkedin.com/in/ada-lovelace,ada@example.com,Analytical Engines,Programmer,12 Mar 2024
Grace,Hopper,https://www.linkedin.com/in/grace-hopper,,"Navy, US",Rear Admiral,01 Feb 2023
No,Url,,,Somewhere,Someone,01 Jan 2020
'''

X_ACCOUNT = '''window.YTD.account.part0 = [
  {"account": {"email": "kyle@example.com", "username": "Kyle_B", "accountId": "42", "accountDisplayName": "Kyle"}}
]'''
X_FOLLOWING = '''window.YTD.following.part0 = [
  {"following": {"accountId": "7", "userLink": "https://twitter.com/intent/user?user_id=7"}}
]'''
X_FOLLOWER = '''window.YTD.follower.part0 = [
  {"follower": {"accountId": "8", "userLink": "https://twitter.com/intent/user?user_id=8"}}
]'''
X_FOLLOWER_PART1 = '''window.YTD.follower.part1 = [
  {"follower": {"accountId": "9", "userLink": "https://twitter.com/intent/user?user_id=9"}}
]'''


def triples(claims: list[Claim]) -> set[tuple[str, str, str]]:
    return {(c.subject, c.predicate, c.object) for c in claims}


def zip_of(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return buffer.getvalue()


# --- LinkedIn ---

def test_linkedin_connections_become_edges_with_profile_details():
    claims = parse_linkedin_connections(CONNECTIONS_CSV.lstrip("﻿"), owner="linkedin:kyle-bolin")
    found = triples(claims)
    assert ("linkedin:kyle-bolin", "connected_to", "linkedin:ada-lovelace") in found
    assert ("linkedin:ada-lovelace", "display_name", "Ada Lovelace") in found
    assert ("linkedin:grace-hopper", "company", "Navy, US") in found  # a quoted comma stays in the value
    assert ("linkedin:grace-hopper", "position", "Rear Admiral") in found
    assert sum(c.predicate == "connected_to" for c in claims) == 2   # the row without a URL is skipped
    assert all("@" not in c.object for c in claims)                  # emails are left out on purpose
    edge = next(c for c in claims if c.object == "linkedin:ada-lovelace")
    assert "12 Mar 2024" in edge.rationale
    assert edge.evidence_url == "https://www.linkedin.com/in/ada-lovelace"


def test_linkedin_without_the_header_is_refused():
    with pytest.raises(ValueError, match="Connections.csv"):
        parse_linkedin_connections("name,url\nAda,x\n")


@pytest.mark.parametrize("raw,expected", [
    ("", "linkedin:me"),
    ("https://www.linkedin.com/in/Kyle-Bolin/", "linkedin:kyle-bolin"),
    ("kyle-bolin", "linkedin:kyle-bolin"),
])
def test_linkedin_owner(raw, expected):
    assert linkedin_owner(raw) == expected


@pytest.mark.parametrize("raw", ["https://github.com/kyle", "not a profile!"])
def test_linkedin_owner_rejects_other_things(raw):
    with pytest.raises(ValueError):
        linkedin_owner(raw)


# --- X archive ---

def test_x_archive_follows_point_the_right_way_and_skip_the_email():
    claims = parse_x_archive({
        "account.js": X_ACCOUNT, "following.js": X_FOLLOWING,
        "follower.js": X_FOLLOWER, "follower-part1.js": X_FOLLOWER_PART1,
    })
    assert triples(claims) == {
        ("x:kyle_b", "has_x_id", "42"),
        ("x:kyle_b", "follows", "x:id:7"),
        ("x:id:8", "follows", "x:kyle_b"),
        ("x:id:9", "follows", "x:kyle_b"),
    }
    assert all("example.com" not in c.object for c in claims)
    assert next(c for c in claims if c.object == "x:id:7").evidence_url.endswith("user_id=7")


def test_x_archive_without_account_js_uses_x_me():
    assert triples(parse_x_archive({"following.js": X_FOLLOWING})) == {("x:me", "follows", "x:id:7")}


# --- uploads and zips ---

def test_read_exports_finds_the_files_inside_a_zip():
    data = zip_of({
        "Connections.csv": CONNECTIONS_CSV,
        "data/account.js": X_ACCOUNT, "data/following.js": X_FOLLOWING,
        "data/tweets.js": "window.YTD.tweets.part0 = []",   # not needed, not read
    })
    claims = read_exports({"export.zip": data})
    assert {c.source for c in claims} == {"linkedin-export", "x-archive"}
    assert ("linkedin:me", "connected_to", "linkedin:ada-lovelace") in triples(claims)


def test_read_exports_refuses_a_member_that_unpacks_too_big(monkeypatch):
    monkeypatch.setattr(exports, "MAX_FILE_BYTES", 10)
    with pytest.raises(ValueError, match="refusing"):
        read_exports({"export.zip": zip_of({"data/follower.js": X_FOLLOWER})})


def test_read_exports_with_nothing_it_knows():
    with pytest.raises(ValueError, match="No Connections.csv"):
        read_exports({"notes.txt": b"hello"})


def test_import_page_shows_one_section_per_export():
    client = TestClient(app_module.app)
    response = client.post("/import", files=[
        ("files", ("Connections.csv", CONNECTIONS_CSV.encode(), "text/csv")),
        ("files", ("following.js", X_FOLLOWING.encode(), "text/javascript")),
    ], data={"linkedin_profile": "https://www.linkedin.com/in/kyle-bolin"})
    assert response.status_code == 200
    assert "linkedin-export" in response.text and "x-archive" in response.text
    assert "linkedin:kyle-bolin" in response.text

    broken = client.post("/import", files=[("files", ("export.zip", b"not a zip", "application/zip"))])
    assert broken.status_code == 200
    assert "Couldn&#39;t read that upload: BadZipFile" in broken.text


# --- MCP ---

def call(tool: str, arguments: dict):
    async def go():
        async with Client(mcp_server.server) as client:
            return await client.call_tool(tool, arguments)
    return asyncio.run(go())


def test_mcp_reads_an_export_from_disk(tmp_path):
    path = tmp_path / "Connections.csv"
    path.write_text(CONNECTIONS_CSV, encoding="utf-8")
    result = call("read_network_export", {"path": str(path), "linkedin_profile": "kyle-bolin"})
    assert not result.is_error
    claims = result.structured_content["claims"]
    assert {"subject": "linkedin:kyle-bolin", "object": "linkedin:ada-lovelace"}.items() <= claims[0].items()
    assert all(c["found_by"] == "ai" for c in claims)


def test_mcp_export_tool_only_opens_export_files(tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE KEY")
    result = call("read_network_export", {"path": str(secret)})
    assert result.is_error
    assert "PRIVATE KEY" not in result.content[0].text
