import httpx
from fastapi.testclient import TestClient

from osint import app as app_module
from osint.modules.wayback import lookup_wayback, parse_cdx

# What the CDX API returns with output=json: a header row, then one row per capture.
CDX_SAMPLE = [
    ["timestamp", "original"],
    ["20020120142510", "http://example.com:80/"],
    ["20030202104805", "http://www.example.com/"],
    ["20240101000013", "https://example.com/"],
]


def test_parse_cdx_turns_captures_into_dated_claims():
    claims = parse_cdx("example.com", CDX_SAMPLE)
    assert [c.object for c in claims] == [
        "2002-01-20T14:25:10Z", "2003-02-02T10:48:05Z", "2024-01-01T00:00:13Z",
    ]
    first = claims[0]
    assert (first.subject, first.predicate, first.source) == ("example.com", "archived_at", "wayback")
    assert first.evidence_url == "https://web.archive.org/web/20020120142510/http://example.com:80/"


def test_parse_cdx_with_no_captures():
    assert parse_cdx("example.com", []) == []


def test_lookup_wayback_asks_for_one_capture_per_year():
    seen = {}

    def handler(request):
        seen.update(request.url.params)
        return httpx.Response(200, json=CDX_SAMPLE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    claims = lookup_wayback("example.com", client=client)
    assert len(claims) == 3
    assert seen["url"] == "example.com"
    assert seen["collapse"] == "timestamp:4"
    assert seen["filter"] == "statuscode:200"


def test_lookup_wayback_treats_empty_body_as_no_captures():
    transport = httpx.MockTransport(lambda req: httpx.Response(200, text=""))
    assert lookup_wayback("example.com", client=httpx.Client(transport=transport)) == []


def test_page_shows_timeline_with_gaps(monkeypatch):
    def fake_wayback(domain):
        return parse_cdx(domain, CDX_SAMPLE)

    monkeypatch.setattr(app_module, "MODULES", {"wayback": fake_wayback})
    html = TestClient(app_module.app).get("/", params={"q": "example.com"}).text
    assert 'href="https://web.archive.org/web/20030202104805/http://www.example.com/"' in html
    assert "20 yr gap" in html  # nothing archived from 2004 to 2023
