# OSINT Workbench

A personal, learn-by-building OSINT tool. Type a domain and see its DNS records,
registration data (RDAP, the modern WHOIS), and subdomains from certificate
transparency logs, all on one page. Type an IP address, or click one in a
domain's DNS results, to see its reverse DNS, the network (AS) that announces it,
who the address block is registered to, and a rough location.

Every result is stored as a **claim**: `subject -predicate-> object` with a
source, a confidence score, and a short rationale. That shape is what the later
pieces (pivot graph, case notebook, AI investigator, broker-data module) build on.

## Run it

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn osint.app:app --reload
```

Open http://127.0.0.1:8000 and try `example.com` or `8.8.8.8`.
JSON API: `http://127.0.0.1:8000/api/lookup?q=example.com` (or `?q=8.8.8.8`)

Optional: IP geolocation uses ipinfo.io, which works without an account at a low
rate limit. For more, make a free token at https://ipinfo.io/signup and
`export IPINFO_TOKEN=...` before starting the app. Keep it out of git.

## Tests

```bash
pytest
```

## Layout

| Path | What it is |
|---|---|
| `osint/claims.py` | The `Claim` dataclass, base confidence rules, and `combine()` for corroboration |
| `osint/modules/dns_lookup.py` | A, AAAA, MX, NS, TXT, CNAME via dnspython; reverse DNS (PTR) for an IP |
| `osint/modules/rdap.py` | Registrar, dates, nameservers, status via rdap.org; network owner and range for an IP |
| `osint/modules/crtsh.py` | Subdomains from crt.sh |
| `osint/modules/asn.py` | Origin AS and routed prefix for an IP, via Team Cymru's DNS service |
| `osint/modules/geoip.py` | Rough IP location from ipinfo.io |
| `osint/app.py` | FastAPI app: runs modules in parallel, renders the page |

Each module is a plain function `lookup_x(domain or ip) -> list[Claim]` with no web
code in it, so it can later be exposed as an MCP tool for an AI agent unchanged.

## Roadmap

1. ~~Domain basics (DNS + RDAP)~~
2. ~~Certificate transparency subdomains~~
3. Image metadata (EXIF + map)
4. Username check across sites
5. Wayback Machine history
6. ~~IP / infrastructure lookups~~ (Shodan still to add)
7. Pivot graph
8. Case notebook (SQLite)
9. Broker-data self-lookup
10. MCP server so Claude can run the modules and add scored claims

## Use it responsibly

Point it at your own domains, CTF targets, and programs that allow recon. Keep
lookups about people pointed at yourself.
