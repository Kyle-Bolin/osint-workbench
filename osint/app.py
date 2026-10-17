import ipaddress
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from osint import notebook
from osint.claims import Claim
from osint.modules.asn import lookup_asn
from osint.modules.crtsh import lookup_subdomains
from osint.modules.dns_lookup import lookup_dns, lookup_reverse_dns
from osint.modules.geoip import lookup_geo
from osint.modules.rdap import lookup_ip_rdap, lookup_rdap

app = FastAPI(title="OSINT Workbench")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
templates.env.filters["when"] = notebook.format_when

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
# Modules that take a domain, and modules that take an IP address.
MODULES = {"dns": lookup_dns, "rdap": lookup_rdap, "subdomains": lookup_subdomains}
IP_MODULES = {"reverse_dns": lookup_reverse_dns, "asn": lookup_asn,
              "network": lookup_ip_rdap, "geo": lookup_geo}
# Claims whose value is an IP: the page links them to an IP lookup (domain -> IP).
IP_PREDICATES = {"has_ipv4", "has_ipv6"}


def clean_domain(raw: str) -> str:
    domain = raw.strip().lower().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0].removeprefix("www.")
    if not DOMAIN_RE.match(domain):
        raise HTTPException(400, f"Not a valid domain: {raw!r}")
    return domain


def clean_target(raw: str) -> tuple[str, str]:
    """Work out what was typed: (address, "ip") or (domain, "domain")."""
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return clean_domain(raw), "domain"
    if not ip.is_global:  # 192.168.x.x, 10.x.x.x, ::1 and friends
        raise HTTPException(400, f"{ip} is a private or reserved address; public lookups can't see it")
    return str(ip), "ip"


def investigate(target: str, kind: str = "domain") -> dict:
    """Run every module for this kind of target in parallel; one failing module doesn't sink the rest."""
    modules = IP_MODULES if kind == "ip" else MODULES
    results = {}
    with ThreadPoolExecutor() as pool:
        futures = {name: pool.submit(fn, target) for name, fn in modules.items()}
        for name, future in futures.items():
            try:
                results[name] = {"claims": [c.to_dict() for c in future.result()], "error": None}
            except Exception as exc:  # show the error next to the module
                results[name] = {"claims": [], "error": f"{type(exc).__name__}: {exc}"}
    return {"target": target, "kind": kind, "modules": results}


@app.get("/api/lookup")
def api_lookup(q: str) -> dict:
    target, kind = clean_target(q)
    return investigate(target, kind)


# The case notebook (osint/notebook.py). Pick a case and it becomes the
# "current case": every lookup you run from then on is saved into it, until
# you stop. The current case's id lives in a browser cookie, so it carries
# across pages, including the IP links you click to pivot from a domain.
CASE_COOKIE = "case"


def get_db():
    """FastAPI dependency: one SQLite connection per request, closed afterwards."""
    conn = notebook.connect()
    try:
        yield conn
    finally:
        conn.close()


def current_case(request: Request, db: sqlite3.Connection) -> dict | None:
    case_id = request.cookies.get(CASE_COOKIE, "")
    return notebook.get_case(db, int(case_id)) if case_id.isdigit() else None


def save_investigation(db: sqlite3.Connection, case_id: int, result: dict) -> int:
    """Record each module's run from investigate() in a case. Returns the number of claims saved."""
    saved = 0
    for module, outcome in result["modules"].items():
        claims = [Claim(**c) for c in outcome["claims"]]
        notebook.record_lookup(db, case_id, module, result["target"], claims, error=outcome["error"])
        saved += len(claims)
    return saved


@app.get("/", response_class=HTMLResponse)
def index(request: Request, q: str = "", db: sqlite3.Connection = Depends(get_db)):
    context = {"q": q, "result": None, "error": None, "ip_predicates": IP_PREDICATES}
    if q:
        try:
            target, kind = clean_target(q)
            context["result"] = investigate(target, kind)
        except HTTPException as exc:
            context["error"] = exc.detail
    # A plain GET that writes is usually a smell, but here the lookups above
    # really did run again, so saving them keeps the case's log honest.
    case = current_case(request, db)
    context["current_case"] = case
    if case and context["result"]:
        context["saved"] = save_investigation(db, case["id"], context["result"])
    return templates.TemplateResponse(request, "index.html", context)


def get_case_or_404(db: sqlite3.Connection, case_id: int) -> dict:
    case = notebook.get_case(db, case_id)
    if case is None:
        raise HTTPException(404, f"No case with id {case_id}")
    return case


@app.get("/cases", response_class=HTMLResponse)
def cases_page(request: Request, db: sqlite3.Connection = Depends(get_db)):
    context = {"cases": notebook.list_cases(db), "current_case": current_case(request, db)}
    return templates.TemplateResponse(request, "cases.html", context)


# Forms POST, then redirect to a page (303 See Other). Refreshing that page
# re-runs the GET, not the POST, so a refresh can't create a case twice.

@app.post("/cases")
def create_case(name: str = Form(""), description: str = Form(""),
                db: sqlite3.Connection = Depends(get_db)):
    if not name.strip():
        return RedirectResponse("/cases", status_code=303)
    case_id = notebook.create_case(db, name, description)
    # A new case becomes the current one, and you start on the lookup page.
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(CASE_COOKIE, str(case_id), httponly=True, samesite="lax")
    return response


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_page(request: Request, case_id: int, db: sqlite3.Connection = Depends(get_db)):
    context = {
        "case": get_case_or_404(db, case_id),
        "claims": notebook.case_claims(db, case_id),
        "notes": notebook.case_notes(db, case_id),
        "lookups": notebook.case_lookups(db, case_id),
        "current_case": current_case(request, db),
        "ip_predicates": IP_PREDICATES,
    }
    return templates.TemplateResponse(request, "case.html", context)


@app.post("/cases/{case_id}/notes")
def add_note(case_id: int, body: str = Form(""), db: sqlite3.Connection = Depends(get_db)):
    get_case_or_404(db, case_id)
    if body.strip():
        notebook.add_note(db, case_id, body)
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


@app.post("/cases/{case_id}/select")
def select_case(case_id: int, db: sqlite3.Connection = Depends(get_db)):
    get_case_or_404(db, case_id)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(CASE_COOKIE, str(case_id), httponly=True, samesite="lax")
    return response


@app.post("/cases/deselect")
def deselect_case():
    response = RedirectResponse("/cases", status_code=303)
    response.delete_cookie(CASE_COOKIE)
    return response


@app.get("/cases/{case_id}/export.md", response_class=PlainTextResponse)
def export_case(case_id: int, db: sqlite3.Connection = Depends(get_db)):
    case = get_case_or_404(db, case_id)
    slug = re.sub(r"[^a-z0-9]+", "-", case["name"].lower()).strip("-") or "case"
    return PlainTextResponse(
        notebook.export_markdown(db, case_id),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="case-{case_id}-{slug}.md"'},
    )
