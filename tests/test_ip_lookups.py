"""IP lookups, tested offline: a fake resolver for DNS, MockTransport for HTTP."""
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from osint import app as app_module
from osint.claims import BASE_CONFIDENCE, Claim
from osint.modules.asn import lookup_asn, origin_query, parse_origin
from osint.modules.dns_lookup import lookup_reverse_dns
from osint.modules.geoip import lookup_geo, parse_ipinfo
from osint.modules.rdap import lookup_ip_rdap, parse_ip_rdap


class FakeResolver:
    """Answers from a dict instead of the network: {(name, type): [record text, ...]}."""

    def __init__(self, records: dict):
        self.records = records
        self.asked = []

    def resolve(self, name, rtype, lifetime=None):
        name = str(name).rstrip(".")
        self.asked.append(name)
        if (name, rtype) not in self.records:
            raise dns.resolver.NXDOMAIN
        rdtype = dns.rdatatype.from_text(rtype)
        return [dns.rdata.from_text(dns.rdataclass.IN, rdtype, text) for text in self.records[(name, rtype)]]


def triples(claims: list[Claim]) -> set[tuple[str, str, str]]:
    return {(c.subject, c.predicate, c.object) for c in claims}


# --- reverse DNS ---

def test_reverse_dns_reads_the_ptr_record():
    resolver = FakeResolver({("8.8.8.8.in-addr.arpa", "PTR"): ["dns.google."]})
    claims = lookup_reverse_dns("8.8.8.8", resolver=resolver)
    assert triples(claims) == {("8.8.8.8", "reverse_dns", "dns.google")}


def test_reverse_dns_without_a_ptr_record_finds_nothing():
    assert lookup_reverse_dns("8.8.8.8", resolver=FakeResolver({})) == []


# --- ASN (Team Cymru) ---

def test_origin_query_reverses_the_address():
    assert origin_query("1.2.3.4") == "4.3.2.1.origin.asn.cymru.com"
    v6 = origin_query("2001:db8::1")
    assert v6.startswith("1.0.0.0.") and v6.endswith(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com")


def test_parse_origin_handles_a_prefix_with_two_origin_asns():
    claims = parse_origin("104.16.1.1", "13335 209242 | 104.16.0.0/13 | US | arin | 2014-03-28")
    assert triples(claims) == {
        ("104.16.1.1", "bgp_prefix", "104.16.0.0/13"),
        ("104.16.1.1", "announced_by", "AS13335"),
        ("104.16.1.1", "announced_by", "AS209242"),
    }


def test_lookup_asn_adds_the_as_name_once():
    resolver = FakeResolver({
        ("8.8.8.8.origin.asn.cymru.com", "TXT"): [
            '"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"',
            '"15169 | 8.8.0.0/16 | US | arin | 1992-12-01"',
        ],
        ("AS15169.asn.cymru.com", "TXT"): ['"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"'],
    })
    claims = lookup_asn("8.8.8.8", resolver=resolver)
    assert ("8.8.8.8", "announced_by", "AS15169") in triples(claims)
    assert ("AS15169", "as_name", "GOOGLE - Google LLC, US") in triples(claims)
    assert [c.predicate for c in claims].count("announced_by") == 1
    assert resolver.asked.count("AS15169.asn.cymru.com") == 1


# --- network owner (RDAP) ---

# Trimmed from the shape ARIN returns for 8.8.8.8.
IP_RDAP_SAMPLE = {
    "objectClassName": "ip network",
    "handle": "NET-8-8-8-0-2",
    "startAddress": "8.8.8.0",
    "endAddress": "8.8.8.255",
    "name": "GOGL",
    "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
    "entities": [{
        "roles": ["registrant"],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]]],
        "entities": [{
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "network-abuse@google.com"]]],
        }],
    }],
}


def test_parse_ip_rdap_finds_owner_range_and_nested_abuse_contact():
    claims = triples(parse_ip_rdap("8.8.8.8", IP_RDAP_SAMPLE))
    assert ("8.8.8.8", "network_name", "GOGL") in claims
    assert ("8.8.8.8", "network_range", "8.8.8.0/24") in claims
    assert ("8.8.8.8", "network_owner", "Google LLC") in claims
    assert ("8.8.8.8", "abuse_contact", "network-abuse@google.com") in claims


def test_parse_ip_rdap_without_cidrs_uses_start_and_end():
    sample = {"name": "EXAMPLE-NET", "startAddress": "193.0.0.0", "endAddress": "193.0.7.255", "country": "NL"}
    claims = triples(parse_ip_rdap("193.0.6.139", sample))
    assert ("193.0.6.139", "network_range", "193.0.0.0 - 193.0.7.255") in claims
    assert ("193.0.6.139", "registered_country", "NL") in claims


def test_lookup_ip_rdap_asks_rdap_org_for_the_ip():
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(200, json=IP_RDAP_SAMPLE)

    claims = lookup_ip_rdap("8.8.8.8", client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert seen == ["/ip/8.8.8.8"]
    assert any(c.predicate == "network_owner" for c in claims)


# --- geolocation (ipinfo) ---

IPINFO_SAMPLE = {
    "ip": "8.8.8.8", "hostname": "dns.google", "city": "Mountain View", "region": "California",
    "country": "US", "loc": "37.4056,-122.0775", "org": "AS15169 Google LLC", "anycast": True,
}


def test_parse_ipinfo_scores_location_as_weak():
    claims = parse_ipinfo("8.8.8.8", IPINFO_SAMPLE)
    assert ("8.8.8.8", "geo_city", "Mountain View, California") in triples(claims)
    assert all(c.confidence == BASE_CONFIDENCE["weak"] for c in claims)
    assert all("anycast" in c.rationale for c in claims)


def test_lookup_geo_sends_the_token_in_a_header_not_the_url():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=IPINFO_SAMPLE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    claims = lookup_geo("8.8.8.8", client=client, token="secret-token")
    assert requests[0].headers["Authorization"] == "Bearer secret-token"
    assert "secret-token" not in str(requests[0].url)
    assert all("secret-token" not in c.evidence_url for c in claims)


def test_lookup_geo_works_without_a_token(monkeypatch):
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=IPINFO_SAMPLE)

    lookup_geo("8.8.8.8", client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert "Authorization" not in requests[0].headers


# --- the app: IP input, and domain -> IP links ---

@pytest.mark.parametrize("raw,expected", [
    ("8.8.8.8", ("8.8.8.8", "ip")),
    (" 2001:4860:4860:0:0:0:0:8888 ", ("2001:4860:4860::8888", "ip")),
    ("Example.com", ("example.com", "domain")),
])
def test_clean_target_tells_ips_from_domains(raw, expected):
    assert app_module.clean_target(raw) == expected


@pytest.mark.parametrize("raw", ["192.168.1.1", "10.0.0.1", "127.0.0.1", "::1"])
def test_clean_target_rejects_private_addresses(raw):
    with pytest.raises(HTTPException) as exc:
        app_module.clean_target(raw)
    assert exc.value.status_code == 400


def test_api_runs_ip_modules_for_an_ip(monkeypatch):
    def geo(ip):
        return [Claim(ip, "geo_country", "US", "ipinfo", 0.4)]

    def domain_only(target):
        raise AssertionError("domain modules should not run for an IP")

    monkeypatch.setattr(app_module, "MODULES", {"dns": domain_only})
    monkeypatch.setattr(app_module, "IP_MODULES", {"geo": geo})
    body = TestClient(app_module.app).get("/api/lookup", params={"q": "8.8.8.8"}).json()
    assert body["kind"] == "ip"
    assert list(body["modules"]) == ["geo"]
    assert body["modules"]["geo"]["claims"][0]["object"] == "US"


def test_page_links_a_domains_ips_to_an_ip_lookup(monkeypatch):
    def dns(domain):
        return [
            Claim(domain, "has_ipv4", "93.184.216.34", "dns", 0.95),
            Claim(domain, "has_ipv6", "2606:2800:220:1::", "dns", 0.95),
        ]

    monkeypatch.setattr(app_module, "MODULES", {"dns": dns})
    html = TestClient(app_module.app).get("/", params={"q": "example.com"}).text
    assert 'href="/?q=93.184.216.34"' in html
    assert 'href="/?q=2606%3A2800%3A220%3A1%3A%3A"' in html
