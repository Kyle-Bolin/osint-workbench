# OSINT Workbench

A personal, learn-by-building OSINT tool. Type a domain and see its DNS records,
registration data (RDAP, the modern WHOIS), and subdomains from certificate
transparency logs, all on one page. Type an IP address, or click one in a
domain's DNS results, to see its reverse DNS, the network (AS) that announces it,
who the address block is registered to, and a rough location. Type a social
account (`github:octocat`, `bluesky:kyle.dev`, `@kyle@infosec.exchange`,
`x:kyle_b`) to map who it follows, who follows it, and the other accounts and
sites its profile links to. Or upload your own LinkedIn or X data export to map
your connections there.

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

### Social accounts

| Platform | Typed as | Cost | Key |
|---|---|---|---|
| Bluesky | `bluesky:handle` | Free | None |
| GitHub | `github:username` | Free | Optional `GITHUB_TOKEN` (no scopes) raises the limit from 60 to 5,000 requests an hour |
| Mastodon | `@user@server` or `mastodon:user@server` | Free | None |
| X | `x:username` | Paid: about $0.01 per account read | `X_BEARER_TOKEN` from https://console.x.com, after buying credits |

Each lookup reads up to 200 accounts per list (X: `X_MAX_ACCOUNTS`, default
100, so at most about $2 per lookup). Set a spending limit in the X console
too.

LinkedIn works differently: its API doesn't offer connections to individual
developers and its terms forbid scraping. So for LinkedIn, and for X without
paying, upload your own data export under "Map your own LinkedIn or X network"
on the page:

- **LinkedIn:** Settings > Data privacy > Get a copy of your data. Upload the
  zip or `Connections.csv` from it, plus your profile URL so the connections
  hang off your own node.
- **X:** Settings > Your account > Download an archive of your data. Upload the
  zip, or `data/follower.js`, `data/following.js` and `data/account.js`. The
  archive only has account IDs, so the accounts show up as `x:id:<number>`.

Emails in the exports are skipped, and nothing is saved yet (that waits for the
case notebook).

## Use it from Claude (MCP server)

`osint/mcp_server.py` exposes each lookup as an MCP tool, so Claude Code or
Claude Desktop can investigate a domain with this code. Claude starts the
server itself; you only register it once. Use full paths, because Claude may
launch it from another folder.

**Claude Code**, from the repo root with the venv set up:

```bash
claude mcp add osint-workbench -e PYTHONPATH="$PWD" -- "$PWD/.venv/bin/python" -m osint.mcp_server
```

**Claude Desktop**: add this to `claude_desktop_config.json` (Settings >
Developer > Edit Config) and restart the app:

```json
{
  "mcpServers": {
    "osint-workbench": {
      "command": "/full/path/to/osint-workbench/.venv/bin/python",
      "args": ["-m", "osint.mcp_server"],
      "env": {"PYTHONPATH": "/full/path/to/osint-workbench"}
    }
  }
}
```

On Windows the Python path is `.venv\Scripts\python.exe`. Then ask Claude
something like "investigate example.com with the osint-workbench tools".

| Tool | Module function |
|---|---|
| `dns_records` | `lookup_dns` |
| `rdap_registration` | `lookup_rdap` |
| `ct_subdomains` | `lookup_subdomains` |
| `bluesky_network` | `lookup_bluesky_network` |
| `github_network` | `lookup_github_network` |
| `mastodon_network` | `lookup_mastodon_network` |
| `x_network` | `lookup_x_network` (paid) |
| `read_network_export` | `read_exports` (a LinkedIn or X export file on your computer) |

Claims that come back through MCP have `found_by: "ai"`; their confidence is
still set by the module's rules. To poke at the tools without Claude, the MCP
Inspector works too: `npx @modelcontextprotocol/inspector .venv/bin/python -m osint.mcp_server`.

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
| `osint/accounts.py` | `platform:handle` account names, profile URL to account, and the shared `follows` claim builder |
| `osint/modules/bluesky.py` | Bluesky follows and followers, and a domain handle as a verified domain |
| `osint/modules/github.py` | GitHub follows and followers, and the accounts a profile links to |
| `osint/modules/mastodon.py` | Mastodon follows and followers, with `rel="me"` verified links |
| `osint/modules/x_api.py` | X follows and followers through the paid API, capped per lookup |
| `osint/modules/exports.py` | Your LinkedIn connections and X follows from your own data exports |
| `osint/app.py` | FastAPI app: runs modules in parallel, renders the page |
| `osint/mcp_server.py` | MCP server: the same modules as tools for Claude |

Each module is a plain function `lookup_x(domain) -> list[Claim]` with no web
code in it, so the web app and the MCP server both call it unchanged.

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
10. MCP server so Claude can ~~run the modules~~ and add scored claims (needs the case notebook)
11. ~~Social network mapping~~ (Bluesky, GitHub, Mastodon, X API, and LinkedIn / X data exports)

## Use it responsibly

Point it at your own domains, CTF targets, and programs that allow recon. Keep
lookups about people pointed at yourself. Network mapping goes one hop out from
your own accounts: the accounts in your follow lists show up, but the page
doesn't offer to look them up in turn.
