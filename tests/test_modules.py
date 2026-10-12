import httpx
import pytest
from fastapi.testclient import TestClient

from osint import app as app_module
from osint.claims import Claim, combine
from osint.modules.crtsh import parse_crtsh
from osint.modules.rdap import lookup_rdap, parse_rdap


def test_combine_raises_confidence_for_agreeing_sources():
    assert combine(0.5, 0.5) == 0.75
    assert combine(0.9) == 0.9


def test_parse_crtsh_dedupes_and_strips_wildcards():
    rows = [
        {"name_value": "www.example.com\n*.api.example.com"},
        {"name_value": "WWW.example.com"},
        {"name_value": "example.com"},
        {"name_value": "evil-example.com"},
    ]
    names = [c.object for c in parse_crtsh("example.com", rows)]
    assert names == ["api.example.com", "www.example.com"]


RDAP_SAMPLE = {
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
    ],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-IANA"]]]}],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
    "status": ["client delete prohibited"],
}


def test_parse_rdap():
    claims = {(c.predicate, c.object) for c in parse_rdap("example.com", RDAP_SAMPLE)}
    assert ("registration_date", "1995-08-14T04:00:00Z") in claims
    assert ("registrar", "RESERVED-IANA") in claims
    assert ("nameserver", "a.iana-servers.net") in claims


def test_lookup_rdap_uses_http_client():
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=RDAP_SAMPLE))
    claims = lookup_rdap("example.com", client=httpx.Client(transport=transport))
    assert any(c.predicate == "registrar" for c in claims)


@pytest.mark.parametrize("raw,expected", [
    ("Example.com", "example.com"),
    ("https://www.example.com/path", "example.com"),
])
def test_clean_domain(raw, expected):
    assert app_module.clean_domain(raw) == expected


def test_api_reports_module_errors_without_failing(monkeypatch):
    def boom(domain):
        raise RuntimeError("upstream down")

    def ok(domain):
        return [Claim(domain, "has_ipv4", "93.184.216.34", "dns", 0.95)]

    monkeypatch.setattr(app_module, "MODULES", {"dns": ok, "rdap": boom})
    client = TestClient(app_module.app)
    body = client.get("/api/lookup", params={"domain": "example.com"}).json()
    assert body["modules"]["dns"]["claims"][0]["object"] == "93.184.216.34"
    assert "upstream down" in body["modules"]["rdap"]["error"]
    assert client.get("/api/lookup", params={"domain": "not a domain"}).status_code == 400
    assert client.get("/", params={"domain": "example.com"}).status_code == 200
