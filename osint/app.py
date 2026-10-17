import csv
import ipaddress
import json
import re
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from osint.accounts import looks_like_account, parse_account
from osint.modules.asn import lookup_asn
from osint.modules.bluesky import lookup_bluesky_network
from osint.modules.crtsh import lookup_subdomains
from osint.modules.dns_lookup import lookup_dns, lookup_reverse_dns
from osint.modules.exports import read_exports
from osint.modules.geoip import lookup_geo
from osint.modules.github import lookup_github_network
from osint.modules.mastodon import lookup_mastodon_network
from osint.modules.rdap import lookup_ip_rdap, lookup_rdap
from osint.modules.x_api import lookup_x_network

app = FastAPI(title="OSINT Workbench")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
# Modules that take a domain, modules that take an IP address, and one module
# per social platform, which takes that platform's handle.
MODULES = {"dns": lookup_dns, "rdap": lookup_rdap, "subdomains": lookup_subdomains}
IP_MODULES = {"reverse_dns": lookup_reverse_dns, "asn": lookup_asn,
              "network": lookup_ip_rdap, "geo": lookup_geo}
ACCOUNT_MODULES = {"bluesky": lookup_bluesky_network, "github": lookup_github_network,
                   "mastodon": lookup_mastodon_network, "x": lookup_x_network}
# Claims whose value the page links to a lookup of its own: domain -> IP, and
# from an account to the domain it's verified on or other accounts it lists as its own.
# Accounts in a follow list are deliberately not in here: mapping stays one hop from you.
PIVOT_PREDICATES = {"has_ipv4", "has_ipv6", "verified_domain", "claims_account"}


def clean_domain(raw: str) -> str:
    domain = raw.strip().lower().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0].removeprefix("www.")
    if not DOMAIN_RE.match(domain):
        raise HTTPException(400, f"Not a valid domain: {raw!r}")
    return domain


def clean_account(raw: str) -> str:
    try:
        platform, handle = parse_account(raw)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return f"{platform}:{handle}"


def clean_target(raw: str) -> tuple[str, str]:
    """Work out what was typed: (address, "ip"), (platform:handle, "account") or (domain, "domain")."""
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        if looks_like_account(raw):
            return clean_account(raw), "account"
        return clean_domain(raw), "domain"
    if not ip.is_global:  # 192.168.x.x, 10.x.x.x, ::1 and friends
        raise HTTPException(400, f"{ip} is a private or reserved address; public lookups can't see it")
    return str(ip), "ip"


def can_look_up(value: str) -> bool:
    try:
        clean_target(value)
    except HTTPException:
        return False
    return True


def investigate(target: str, kind: str = "domain") -> dict:
    """Run every module for this kind of target in parallel; one failing module doesn't sink the rest."""
    if kind == "account":  # one module, the platform's own, given the bare handle
        platform, arg = target.split(":", 1)
        modules = {platform: ACCOUNT_MODULES[platform]}
    else:
        modules, arg = (IP_MODULES if kind == "ip" else MODULES), target
    results = {}
    with ThreadPoolExecutor() as pool:
        futures = {name: pool.submit(fn, arg) for name, fn in modules.items()}
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


def page_context(q: str = "") -> dict:
    return {"q": q, "result": None, "error": None,
            "pivot_predicates": PIVOT_PREDICATES, "can_look_up": can_look_up}


@app.get("/", response_class=HTMLResponse)
def index(request: Request, q: str = ""):
    context = page_context(q)
    if q:
        try:
            target, kind = clean_target(q)
            context["result"] = investigate(target, kind)
        except HTTPException as exc:
            context["error"] = exc.detail
    return templates.TemplateResponse(request, "index.html", context)


# What a broken or wrong upload raises: shown on the page instead of a 500.
BAD_UPLOAD = (ValueError, KeyError, IndexError, csv.Error, json.JSONDecodeError, zipfile.BadZipFile)


@app.post("/import", response_class=HTMLResponse)
def import_exports(request: Request, files: list[UploadFile] = File(...), linkedin_profile: str = Form("")):
    """Your LinkedIn or X data export in, `connected_to` / `follows` claims out.
    Uploads are read in memory and not kept: saving waits for the case notebook."""
    context = page_context()
    try:
        # UploadFile.file is a temp file on disk for big uploads; read_exports reads it in place.
        claims = read_exports({f.filename or "": f.file for f in files}, linkedin_profile)
    except BAD_UPLOAD as exc:
        context["error"] = f"Couldn't read that upload: {type(exc).__name__}: {exc}"
        return templates.TemplateResponse(request, "index.html", context)
    modules = {}
    for claim in claims:  # one section per export, like one per module for a lookup
        modules.setdefault(claim.source, {"claims": [], "error": None})["claims"].append(claim.to_dict())
    context["result"] = {"target": None, "kind": "import", "modules": modules}
    return templates.TemplateResponse(request, "index.html", context)
