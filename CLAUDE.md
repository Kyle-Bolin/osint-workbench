# OSINT Workbench: notes for Claude

Personal learning project for Kyle (GitHub: Kyle-Bolin). It's just for them: no other users, no monetization.
The goal is to learn by building, so explain the why behind changes and keep code readable over clever.

- Stack: Python, FastAPI, Jinja2 templates, dnspython, httpx, pytest. SQLite when persistence arrives.
- Every module is a plain function `lookup_x(input) -> list[Claim]` with no web code in it (see `osint/claims.py`).
  Keep it that way: the MCP server / AI agent will call these functions directly.
- Confidence scores come from rules in `osint/claims.py` (base score by source type, `combine()` for
  independent corroboration). An AI may explain a score but never invents one.
- Tests must not hit the network: test parsers with sample data, and use `httpx.MockTransport` for clients.
- Practice targets: Kyle's own domains and accounts, CTFs, and programs that allow recon. Person lookups only on Kyle.
- Full idea brief, learning path and AI-layer design: `docs/brief.md`. Roadmap: README.
