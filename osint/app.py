import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from osint.modules.crtsh import lookup_subdomains
from osint.modules.dns_lookup import lookup_dns
from osint.modules.rdap import lookup_rdap

app = FastAPI(title="OSINT Workbench")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
MODULES = {"dns": lookup_dns, "rdap": lookup_rdap, "subdomains": lookup_subdomains}


def clean_domain(raw: str) -> str:
    domain = raw.strip().lower().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0].removeprefix("www.")
    if not DOMAIN_RE.match(domain):
        raise HTTPException(400, f"Not a valid domain: {raw!r}")
    return domain


def investigate(domain: str) -> dict:
    """Run every module in parallel; one failing module doesn't sink the rest."""
    results = {}
    with ThreadPoolExecutor() as pool:
        futures = {name: pool.submit(fn, domain) for name, fn in MODULES.items()}
        for name, future in futures.items():
            try:
                results[name] = {"claims": [c.to_dict() for c in future.result()], "error": None}
            except Exception as exc:  # show the error next to the module
                results[name] = {"claims": [], "error": f"{type(exc).__name__}: {exc}"}
    return {"domain": domain, "modules": results}


@app.get("/api/lookup")
def api_lookup(domain: str) -> dict:
    return investigate(clean_domain(domain))


@app.get("/", response_class=HTMLResponse)
def index(request: Request, domain: str = ""):
    context = {"domain": domain, "result": None, "error": None}
    if domain:
        try:
            context["result"] = investigate(clean_domain(domain))
        except HTTPException as exc:
            context["error"] = exc.detail
    return templates.TemplateResponse(request, "index.html", context)
