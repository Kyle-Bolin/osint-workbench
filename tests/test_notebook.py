from fastapi.testclient import TestClient

from osint import app as app_module
from osint import notebook
from osint.claims import Claim


def claim(obj, source="dns", subject="example.com", predicate="has_ipv4", **kw):
    return Claim(subject, predicate, obj, source, 0.95, rationale="A record returned by DNS", **kw)


def test_saves_lookups_claims_and_notes():
    db = notebook.connect(":memory:")
    case_id = notebook.create_case(db, "  Audit of example.com ", "practice run")
    notebook.record_lookup(db, case_id, "dns", "example.com", [claim("93.184.216.34")])
    notebook.record_lookup(db, case_id, "subdomains", "example.com", [], error="HTTPStatusError: 502")
    notebook.add_note(db, case_id, "MX looks like Google Workspace", written_by="ai")

    assert notebook.get_case(db, case_id)["name"] == "Audit of example.com"
    [listed] = notebook.list_cases(db)
    assert (listed["lookup_count"], listed["note_count"]) == (2, 1)
    lookups = notebook.case_lookups(db, case_id)
    assert [(l["module"], l["claim_count"], l["error"]) for l in lookups] == [
        ("dns", 1, None), ("subdomains", 0, "HTTPStatusError: 502"),
    ]
    assert notebook.case_notes(db, case_id)[0]["written_by"] == "ai"
    assert notebook.get_case(db, 999) is None


def test_case_claims_folds_repeats_but_keeps_sources_apart():
    db = notebook.connect(":memory:")
    case_id = notebook.create_case(db, "repeats")
    first = claim("93.184.216.34", timestamp="2026-10-01T10:00:00+00:00")
    again = claim("93.184.216.34", timestamp="2026-10-17T10:00:00+00:00", found_by="ai")
    ns_dns = claim("a.iana-servers.net", predicate="nameserver")
    ns_rdap = claim("a.iana-servers.net", predicate="nameserver", source="rdap")
    notebook.record_lookup(db, case_id, "dns", "example.com", [first, ns_dns])
    notebook.record_lookup(db, case_id, "dns", "example.com", [again])
    notebook.record_lookup(db, case_id, "rdap", "example.com", [ns_rdap])

    facts = notebook.case_claims(db, case_id)
    assert [(f["predicate"], f["source"]) for f in facts] == [
        ("has_ipv4", "dns"), ("nameserver", "dns"), ("nameserver", "rdap"),
    ]
    ip = facts[0]
    assert (ip["first_seen"], ip["last_seen"]) == (first.timestamp, again.timestamp)
    assert ip["found_by"] == "ai, me"


def test_deleting_a_case_takes_its_rows_with_it():
    # Checks that foreign keys are switched on: SQLite ignores ON DELETE CASCADE otherwise.
    db = notebook.connect(":memory:")
    case_id = notebook.create_case(db, "temp")
    notebook.record_lookup(db, case_id, "dns", "example.com", [claim("93.184.216.34")])
    with db:
        db.execute("DELETE FROM cases WHERE id = ?", (case_id,))
    assert db.execute("SELECT COUNT(*) FROM claims").fetchone()[0] == 0


def test_export_markdown():
    db = notebook.connect(":memory:")
    case_id = notebook.create_case(db, "Audit", "my own domain")
    notebook.add_note(db, case_id, "Check the SPF record next.")
    notebook.record_lookup(db, case_id, "dns", "example.com", [
        claim("v=spf1 a|mx -all", predicate="txt_record"),
        claim("www.example.com", source="crt.sh", predicate="has_subdomain",
              evidence_url="https://crt.sh/?q=www.example.com"),
    ])
    notebook.record_lookup(db, case_id, "rdap", "example.com", [], error="ConnectError: refused")

    md = notebook.export_markdown(db, case_id)
    assert md.startswith("# Audit\n")
    assert "my own domain" in md
    assert "Check the SPF record next." in md
    assert "### example.com" in md
    assert "v=spf1 a\\|mx -all" in md  # a | inside a value would split the table cell
    assert "[www.example.com](<https://crt.sh/?q=www.example.com>)" in md
    assert "| rdap | example.com | me | 0 | ConnectError: refused |" in md


def test_format_when():
    assert notebook.format_when("2026-10-17T18:04:05+00:00") == "2026-10-17 18:04 UTC"
    assert notebook.format_when("2026-10-17T20:04:05+02:00") == "2026-10-17 18:04 UTC"
    assert notebook.format_when("not a date") == "not a date"


def test_default_path_follows_env(notebook_in_tmp):
    assert notebook.default_path() == notebook_in_tmp


def fake_modules(monkeypatch):
    def dns(domain):
        return [claim("93.184.216.34", subject=domain)]

    def down(domain):
        raise RuntimeError("upstream down")

    monkeypatch.setattr(app_module, "MODULES", {"dns": dns, "rdap": down})


def test_lookups_are_saved_only_while_a_case_is_selected(monkeypatch):
    fake_modules(monkeypatch)
    client = TestClient(app_module.app)

    client.get("/", params={"q": "example.com"})  # no case yet: nothing saved
    page = client.post("/cases", data={"name": "Web audit", "description": "via the UI"})
    assert page.status_code == 200 and "Saving lookups to" in page.text  # redirected to /
    assert client.cookies.get("case") == "1"

    page = client.get("/", params={"q": "example.com"})
    assert "Saved 1 claim to" in page.text

    client.post("/cases/deselect")
    client.get("/", params={"q": "example.com"})

    db = notebook.connect()
    assert [l["error"] for l in notebook.case_lookups(db, 1)] == [None, "RuntimeError: upstream down"]
    assert len(notebook.case_claims(db, 1)) == 1


def test_case_page_notes_and_export(monkeypatch):
    fake_modules(monkeypatch)
    client = TestClient(app_module.app)
    client.post("/cases", data={"name": "Notes test"})
    client.get("/", params={"q": "example.com"})

    page = client.post("/cases/1/notes", data={"body": "<script>alert(1)</script>"})
    assert page.status_code == 200
    assert "&lt;script&gt;" in page.text  # notes are escaped, not run
    assert "93.184.216.34" in page.text

    export = client.get("/cases/1/export.md")
    assert export.headers["content-type"].startswith("text/markdown")
    assert 'filename="case-1-notes-test.md"' in export.headers["content-disposition"]
    assert "# Notes test" in export.text

    assert client.get("/cases").status_code == 200
    assert client.get("/cases/99").status_code == 404
    assert client.post("/cases/99/select").status_code == 404


def test_blank_case_names_and_notes_are_ignored():
    client = TestClient(app_module.app)
    client.post("/cases", data={"name": "   "})
    assert client.cookies.get("case") is None
    client.post("/cases", data={"name": "real"})
    client.post("/cases/1/notes", data={"body": "  \n "})

    db = notebook.connect()
    assert [c["name"] for c in notebook.list_cases(db)] == ["real"]
    assert notebook.case_notes(db, 1) == []
