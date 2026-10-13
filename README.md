# OSINT Workbench

A personal, learn-by-building OSINT tool. Type a domain and see its DNS records,
registration data (RDAP, the modern WHOIS), and subdomains from certificate
transparency logs, all on one page.

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

Open http://127.0.0.1:8000 and try `example.com`.
JSON API: `http://127.0.0.1:8000/api/lookup?domain=example.com`

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
| `osint/modules/dns_lookup.py` | A, AAAA, MX, NS, TXT, CNAME via dnspython |
| `osint/modules/rdap.py` | Registrar, dates, nameservers, status via rdap.org |
| `osint/modules/crtsh.py` | Subdomains from crt.sh |
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
6. IP / infrastructure lookups
7. Pivot graph
8. Case notebook (SQLite)
9. Broker-data self-lookup
10. MCP server so Claude can ~~run the modules~~ and add scored claims (needs the case notebook)

## Use it responsibly

Point it at your own domains, CTF targets, and programs that allow recon. Keep
lookups about people pointed at yourself.
