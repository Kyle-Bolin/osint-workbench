# OSINT Workbench: notes for Claude

Personal learning project for Kyle (GitHub: Kyle-Bolin). It's just for them: no other users, no monetization.
The goal is to learn by building, so explain the why behind changes and keep code readable over clever.

- Stack: Python, FastAPI, Jinja2 templates, dnspython, httpx, pytest. SQLite when persistence arrives.
- Every module is a plain function `lookup_x(input) -> list[Claim]` with no web code in it (see `osint/claims.py`).
  Keep it that way: the MCP server / AI agent will call these functions directly.
- Every new lookup module or feature gets exposed in the MCP server (`osint/mcp_server.py`) in the same PR, so
  Claude can always do what the web app can. That means a thin `@server.tool` wrapper whose docstring tells Claude
  when to use it, a row in the README's MCP tool table, and the new name in the expected tool sets in
  `tests/test_mcp_server.py`. Read-only lookups keep `annotations=READ_ONLY`; tools that write data must not.
  If a feature has nothing Claude could call (pure UI), say so in the PR description instead.
- Confidence scores come from rules in `osint/claims.py` (base score by source type, `combine()` for
  independent corroboration). An AI may explain a score but never invents one.
- Tests must not hit the network: test parsers with sample data, and use `httpx.MockTransport` for clients.
- Practice targets: Kyle's own domains and accounts, CTFs, and programs that allow recon. Person lookups only on Kyle.
- Full idea brief, learning path and AI-layer design: `docs/brief.md`. Roadmap: README.
