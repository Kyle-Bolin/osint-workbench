# Idea: OSINT Toolkit Website

*Status: direction set · 2026-10-12*

**Decided:** personal tool, built as a learning project. No other users, no monetization. Python backend confirmed. See "Revised direction" below; the market sections further down are kept for reference.


## Revised direction: a personal OSINT workbench you build to learn
Since it's just for you, the "don't run lookups yourself" caution mostly goes away, and the most educational shape is the **workbench**: you write each lookup yourself instead of linking to someone else's tool. Each module teaches a real concept, and the playbook and notebook ideas become the glue.

### Learning path (build in this order)
| # | Module | What it does | What you learn |
|---|---|---|---|
| 1 | Domain basics | WHOIS + DNS records (A, MX, TXT, NS) for a domain | How DNS works, RDAP vs WHOIS, calling public APIs |
| 2 | Cert transparency | Pull subdomains from crt.sh | CT logs, JSON APIs, dedup and parsing |
| 3 | Image metadata | Upload a photo, read EXIF (camera, timestamp, GPS) and plot it on a map | File formats, privacy leaks, maps (Leaflet) |
| 4 | Username check | Check if a username exists across ~20 sites | HTTP status codes, rate limiting, async requests (how Sherlock/Maigret work) |
| 5 | Web archive | Snapshot history from the Wayback Machine for a URL | Archive APIs, timelines |
| 6 | IP / infra | Geolocate an IP, ASN lookup, reverse DNS, optional Shodan with a free key | Networking basics, API keys and secrets handling |
| 7 | Pivot graph | Every result becomes a node; click to pivot (domain → IP → other domains) | Graph data models, visualization (Cytoscape.js or vis-network) |
| 8 | Case notebook | Save findings per case with timestamps and source URLs, export Markdown | Persistence (SQLite), evidence provenance |
| 9 | Broker-data self-lookup | Look yourself up via 2 or 3 people-data APIs; each result stored as a claim with source and confidence. Brokers that agree raise the score, conflicts get flagged | Commercial data APIs, entity matching, scoring under conflicting sources. See [data broker dossier](data-broker-dossier.md#pairing-with-the-osint-toolkit-idea) |

### Suggested stack
- **Backend:** Python + FastAPI (most OSINT libraries are Python: `dnspython`, `python-whois`, `exifread`, `httpx`). A backend is needed because browsers block most of these requests (CORS).
- **Frontend:** plain HTML + HTMX, or a small React/Svelte app if you also want to learn that.
- **Storage:** SQLite.
- **Run it locally** (or behind a password if you ever host it).

### MVP (first weekend)
Modules 1 and 2 behind a single search box: type a domain, see WHOIS, DNS records, and subdomains on one page. That's a working tool and touches backend, APIs, and parsing.

### Practice targets
Your own domains and accounts, deliberately public targets (e.g. `example.com`, bug-bounty programs that allow recon), and OSINT CTFs (Trace Labs, TryHackMe OSINT rooms, Sofia Santos's OSINT exercises). Keep personal-data lookups pointed at yourself; it's a good habit and the self-audit results are genuinely interesting.

### AI investigator layer (idea, 2026-10-12)
Goal: an AI agent can call the same modules you do, follow pivots on its own, and write what it finds into the case with a confidence score you can review.

**Good news:** if each module is a plain Python function that takes an input and returns structured JSON, the AI part is mostly extra layers on top. It doesn't need a rewrite. That's worth designing for from day one.

**Pieces and rough effort (hobby pace)**
| Piece | What it is | Effort |
|---|---|---|
| 1. Clean module functions | `lookup_dns(domain) -> dict` etc., no web code mixed in | Free if done from the start |
| 2. Findings model | Store every result as a *claim* (below), not raw output | A weekend |
| 3. MCP server | Wrap the modules with the Python MCP SDK (FastMCP) so Claude Desktop / Claude Code can call them directly. No agent loop to write yourself | An evening or two |
| 4. Confidence scoring | Rules that set and update scores (below) | A weekend, then ongoing tuning |
| 5. Built-in agent loop | "Investigate this domain" button in your own UI that runs Claude via the API with tool use, streaming its steps | One or two weekends |
| 6. Review UI | Accept / reject / edit AI claims; rejected ones teach you where scoring is off | A weekend |

Steps 1 to 4 already get you "AI uses the toolset and updates the investigation" by working through Claude Desktop. Step 5 is only needed if you want it inside your own site.

**Claim shape**
```
subject: "example.com"   predicate: "hosted_on"   object: "93.184.216.34"
source: "dns_lookup"     evidence_url / raw_ref   found_by: "ai" | "me"
confidence: 0.95         rationale: "authoritative A record"   timestamp
```
Everything (domains, IPs, usernames, people, photos) becomes nodes; claims are the edges. This is also what feeds the pivot graph.

**Confidence scoring (simple version that works)**
- **Base score by method:** authoritative data (DNS, certificate logs, WHOIS) about 0.9; weak correlation (same username on two sites, similar profile photo) about 0.3 to 0.5; AI inference with no direct source capped at 0.3.
- **Corroboration raises it:** combine independent sources with `1 - (1-a)(1-b)`. Two 0.5 sources give 0.75. Two results from the *same* upstream source don't count as independent.
- **Contradiction lowers it**, and the claim gets flagged for you to look at.
- **Age decays it** for things that change (DNS, hosting); not for historical facts (a 2019 archive snapshot).
- **Rule for the AI:** it can't push a claim above about 0.8 without two independent sources, and must write a rationale for each score. Scores come from your rules; the AI only explains them. Letting the model invent numbers makes them meaningless.

**Guardrails**
- A per-investigation budget (max tool calls and tokens) so a pivot chain can't run away.
- Every AI tool call is logged with its inputs and outputs, so any claim can be traced back.
- Only pivot from targets you started the case with (your own domains, CTF targets); no free-roaming into people's personal data.
- Polite rate limits per upstream site.

**Learning payoff:** this adds tool use, agent loops, MCP, and evidence/uncertainty modelling to the project. Those are probably the most in-demand skills on the list.

**Suggested order:** build modules 1 and 2 as clean functions, add the claim model, then the MCP server. At that point you can watch Claude investigate a domain using your own code, and decide whether the in-app agent is worth building.

### Still open
- Which module sounds most fun to start with?

---

## Original analysis (for reference)

## The one-liner
A website that helps people do open-source intelligence (OSINT) work: finding, verifying, and organizing publicly available information about a person, organization, domain, image, or event.

"OSINT toolkit website" can mean three very different products, so the first job is picking one:

1. **A curated directory** of tools and techniques (like OSINT Framework).
2. **A workbench** that actually runs lookups and stitches results together (like a lightweight Maltego / SpiderFoot in the browser).
3. **A guided method** that walks you through an investigation step by step (like a checklist or playbook engine).

## Who it's for
| Audience | What they need | Willingness to pay |
|---|---|---|
| Journalists and fact-checkers | Verify images, video, accounts, and claims fast | Low individually, newsrooms pay |
| Security teams (red team, threat intel, CTI) | Recon on domains, infra, leaked creds, exposed assets | High |
| Trust and safety / fraud analysts | Check if a profile, seller, or business is real | Medium to high |
| Students and CTF players | Learn methodology, practice on challenges | Low, but big funnel |
| Researchers and hobbyists (e.g. Trace Labs, geolocation fans) | Fun, community, puzzles | Low |
| Ordinary people | "Is this person/landlord/date/seller legit?", "what's out there about me?" | Medium, consumer scale |

## Existing alternatives and where they fall short
- **OSINT Framework (osintframework.com)**: the classic tree of links. Free and broad, but many links are dead or stale, there is no guidance on *which* tool to use or *how*, and it does nothing itself.
- **IntelTechniques (Michael Bazzell)**: well-respected tools and books. Search tools were pulled from public access years ago over abuse and legal concerns, and the good material sits behind books and paid training.
- **Bellingcat Online Investigation Toolkit**: high-quality, community-maintained, verification focused. Still a reference list; strongest for journalism, thinner for security use cases.
- **Start.me OSINT pages, awesome-osint on GitHub**: huge link dumps. Great for discovery, no curation of quality, no workflow.
- **Maltego, SpiderFoot, Recon-ng, theHarvester**: real tooling that runs lookups and builds graphs. Powerful but desktop or self-hosted, steep learning curve, and the good data sources need paid API keys.
- **Commercial people-search (Spokeo, Pipl, etc.)**: easy, but opaque sourcing, ethically murky, and often wrong.
- **OSINT Industries, Epieos, etc.**: email/phone to accounts lookup as a service. Narrow and paid, but shows there's demand for "type one thing, get results".

**Common gaps:** link rot, no "where do I start" guidance, no way to keep notes and evidence together, nothing that teaches method while you work, and a big divide between "list of links" and "expert desktop tool".

## Possible angles and differentiators
1. **Living, verified directory.** Every tool gets an automated health check (is it up, does it still work, free or paid, needs signup?) plus short "use it when..." notes. Fixes the link-rot problem that every directory has. Cheapest to build.
2. **Investigation playbooks.** Pick a starting point (username, email, domain, image, phone, location) and get an ordered, interactive checklist of what to try, with the right tools prefilled with your query. Teaches method while you work.
3. **Case notebook.** A place to log what you searched, where, when, and what you found, with screenshots and URLs archived (e.g. via the Wayback Machine). Produces a clean, timestamped report. Journalists and analysts care a lot about provenance.
4. **Pivot workbench.** Runs safe, low-risk lookups itself (WHOIS, DNS, certificate transparency, reverse image links, username availability, EXIF) and shows pivots as a simple graph. Highest value, highest cost and risk.
5. **Self-audit mode.** "What can people find about me?" for regular users, with removal guides. Clear ethical story and consumer appeal.
6. **Practice ground.** Built-in challenges with answers (geolocate this photo, find this fake company's owner). Community and funnel.

My lean: **2 + 3 (playbooks plus a notebook) on top of 1 (a healthy directory)**. That combination is genuinely missing, doesn't require running risky lookups yourself, and is a coherent web app rather than another link list.

## Smallest MVP worth building
A static-ish web app, no backend lookups:
- **Directory** of ~100 hand-picked tools, tagged by input type (username, email, domain, image, phone, location), cost, and signup requirement, with a nightly job that flags dead links.
- **5 playbooks** (username, email, domain, image, location). Enter a query, get a checklist where each step opens the right tool with the query filled in, and you tick off steps and jot findings.
- **Notebook saved in the browser** (localStorage or IndexedDB, no accounts), exportable to Markdown or PDF with timestamps and links.
- **No data leaves the user's browser** except the clicks out to third-party tools. That keeps hosting cheap and sidesteps most privacy and liability issues for v1.

Rough build: a weekend to a couple of weeks for one person (e.g. Next.js or Astro, a JSON/YAML tools file in a repo so the community can PR new tools, and a GitHub Action for link checks).

What success looks like: people bookmark it and come back, and someone outside your circle sends a PR adding a tool.

## Legal and ethical considerations
- **Dual use is the core issue.** The same toolkit helps journalists and stalkers. IntelTechniques pulled its public search tools for this reason. Decide early which features you won't build (e.g. no automated person dossiers, no address lookups, no aggregation of a private individual's data).
- **Running lookups server-side** makes you a data processor: GDPR/CCPA exposure, terms-of-service violations for scraping (LinkedIn, Meta, etc.), and in the US, possible FCRA issues if anything looks like a background check for employment, housing, or credit.
- **Breach data** (leaked passwords, combo lists) is legally and ethically radioactive. Link to Have I Been Pwned-style services rather than hosting anything.
- **Acceptable use policy and framing.** Clear statement of intended use, a "don't use this to harass people" stance, links to ethics guides (Bellingcat, Berkeley Protocol on Digital Open Source Investigations).
- **Client-side-only MVP** is the cleanest posture: you're a reference and note-taking tool, not a data broker.

## Open questions for you
1. Which product shape: directory, playbooks, or workbench?
2. Who's the first user: journalists, security folks, or regular people?
3. Is this a side project / portfolio piece, or something you'd want to monetize?
4. Do you have an OSINT background yourself, or is this partly about learning the field?
5. Open source (community-maintained tool list) or closed?
6. Any specific frustration that sparked the idea? That's usually the best wedge.
