"""Your own network, from the data exports LinkedIn and X give you.

LinkedIn has no API for connections that an individual can use, and both
LinkedIn and X forbid scraping. But both let you download your own data:

- LinkedIn: Settings > Data privacy > Get a copy of your data. The zip holds
  `Connections.csv`: name, profile URL, company, position and date connected
  for each first-degree connection.
- X: Settings > Your account > Download an archive of your data. The zip
  holds `data/follower.js` and `data/following.js` (account IDs only, no
  usernames) and `data/account.js` (your own username and ID).

Upload the zip itself or just those files. Only the files named above are
read from a zip, and each is size-checked before it is unpacked (a "zip bomb"
can claim a few KB and expand to gigabytes).

Kept out on purpose: the email column in Connections.csv and the email in
account.js. Mapping a network needs who is connected to whom, not how to
contact them.
"""
import csv
import io
import json
import re
import zipfile
from pathlib import PurePosixPath
from typing import BinaryIO

from osint.accounts import account_from_url
from osint.claims import BASE_CONFIDENCE, Claim

LINKEDIN_FILE = "connections.csv"
# Big archives split a list across follower.js, follower-part1.js, ...
X_FILE_RE = re.compile(r"^(follower|following|account)(-part\d+)?\.js$")
MAX_FILE_BYTES = 50 * 1024 * 1024  # far more than any real follower list


def linkedin_owner(raw: str = "") -> str:
    """Your own node. Connections.csv doesn't say whose export it is, so it's
    `linkedin:me` unless you give your profile URL or its /in/ name."""
    raw = raw.strip()
    if not raw:
        return "linkedin:me"
    if "/" in raw:
        node = account_from_url(raw) or ""
    else:
        slug = raw.lower().removeprefix("linkedin:")
        node = f"linkedin:{slug}" if re.match(r"^[\w-]{3,100}$", slug) else ""
    if not node.startswith("linkedin:"):
        raise ValueError(f"Not a LinkedIn profile: {raw!r} (expected linkedin.com/in/your-name)")
    return node


def parse_linkedin_connections(text: str, owner: str = "linkedin:me") -> list[Claim]:
    """Connections.csv -> `connected_to` edges (LinkedIn connections go both
    ways), plus each connection's name, company and position at export time."""
    # The file starts with a few lines of notes before the real header.
    lines = text.lstrip("﻿").splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("First Name,")), None)
    if start is None:
        raise ValueError("No 'First Name,...' header: is this LinkedIn's Connections.csv?")
    claims = []
    for row in csv.DictReader(lines[start:]):
        url = (row.get("URL") or "").strip()
        other = account_from_url(url) if url else None
        if not other:
            continue  # no profile URL means nothing to name the node by
        connected = (row.get("Connected On") or "").strip()

        def add(subject: str, predicate: str, value: str, why: str) -> None:
            claims.append(Claim(
                subject=subject, predicate=predicate, object=value, source="linkedin-export",
                confidence=BASE_CONFIDENCE["authoritative"], rationale=why, evidence_url=url,
            ))

        add(owner, "connected_to", other, f"in your LinkedIn export, connected {connected or 'on an unknown date'}")
        name = " ".join(part for part in (row.get("First Name", "").strip(), row.get("Last Name", "").strip()) if part)
        for predicate, value in (("display_name", name), ("company", row.get("Company", "")),
                                 ("position", row.get("Position", ""))):
            if value.strip():
                add(other, predicate, value.strip(), "their LinkedIn profile at the time of your export")
    return claims


def _ytd_records(text: str) -> list[dict]:
    """X archive files are JavaScript: `window.YTD.follower.part0 = [...]`.
    Everything after the first `=` is JSON, so read it as data, never run it."""
    _, sep, body = text.partition("=")
    if not sep:
        raise ValueError("Not an X archive file (expected 'window.YTD... = [...]')")
    return json.loads(body)


def parse_x_archive(files: dict[str, str]) -> list[Claim]:
    """`files` maps follower.js / following.js / account.js (and any -partN
    files) to their text. Accounts in the lists are `x:id:<number>` nodes,
    because the archive only has IDs; the evidence URL opens each one on X."""
    owner, claims = "x:me", []
    if "account.js" in files:
        account = _ytd_records(files["account.js"])[0]["account"]
        owner = f"x:{account['username'].lower()}"
        claims.append(Claim(
            subject=owner, predicate="has_x_id", object=account["accountId"], source="x-archive",
            confidence=BASE_CONFIDENCE["authoritative"], rationale="account.js in your X archive",
        ))

    # Each record looks like {"following": {"accountId": "...", "userLink": "..."}}.
    # The evidence URL is userLink: with only an ID, opening it on X is the
    # quickest way to see who the account is.
    for filename, text in sorted(files.items()):
        key = X_FILE_RE.match(filename).group(1)
        if key == "account":
            continue
        for record in _ytd_records(text):
            other = f"x:id:{record[key]['accountId']}"
            subject, obj = (owner, other) if key == "following" else (other, owner)
            claims.append(Claim(
                subject=subject, predicate="follows", object=obj, source="x-archive",
                confidence=BASE_CONFIDENCE["authoritative"],
                rationale=f"{filename} in your X archive", evidence_url=record[key].get("userLink", ""),
            ))
    return claims


def _known(name: str) -> bool:
    return name == LINKEDIN_FILE or bool(X_FILE_RE.match(name))


def _read_zip(data: bytes | BinaryIO) -> dict[str, bytes]:
    """An X archive with media can be gigabytes, so a file object is read in
    place (zipfile seeks to the members it needs) rather than loaded whole."""
    found = {}
    with zipfile.ZipFile(io.BytesIO(data) if isinstance(data, bytes) else data) as archive:
        for info in archive.infolist():
            name = PurePosixPath(info.filename).name.lower()
            if not _known(name):
                continue
            if info.file_size > MAX_FILE_BYTES:
                raise ValueError(f"{info.filename} unpacks to {info.file_size:,} bytes; refusing to read it")
            found[name] = archive.read(info)
    return found


def read_exports(files: dict[str, bytes | BinaryIO], linkedin_profile: str = "") -> list[Claim]:
    """Read uploaded export files (or zips of them) by name. `files` maps each
    file name to its bytes or an open binary file. Claims from LinkedIn have
    source "linkedin-export" and from X "x-archive", so the page can show them apart."""
    named = {}
    for filename, data in files.items():
        name = PurePosixPath(filename.replace("\\", "/")).name.lower()
        if name.endswith(".zip"):
            named.update(_read_zip(data))
        elif _known(name):
            if not isinstance(data, bytes):
                data = data.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                raise ValueError(f"{filename} is over {MAX_FILE_BYTES:,} bytes; refusing to read it")
            named[name] = data
    if not named:
        raise ValueError("No Connections.csv, follower.js, following.js or account.js found")
    text = {name: data.decode("utf-8-sig") for name, data in named.items()}
    claims = []
    if LINKEDIN_FILE in text:
        claims += parse_linkedin_connections(text[LINKEDIN_FILE], linkedin_owner(linkedin_profile))
    x_files = {name: body for name, body in text.items() if X_FILE_RE.match(name)}
    if x_files:
        claims += parse_x_archive(x_files)
    return claims
