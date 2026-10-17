"""The case notebook: cases, saved claims and notes in SQLite.

A case is one investigation ("audit my own domain", "CTF challenge 3"). It keeps:

- lookups: every module run saved into the case (which module, on what
  target, when, run by whom, and the error if it failed);
- claims: exactly what each lookup returned, linked to that lookup;
- notes: free text, yours or the AI's.

Saving is append-only. Running the same lookup again adds new rows instead of
overwriting old ones, because "seen on Monday and again on Friday" is evidence
too. `case_claims()` folds the repeats together for display.

Like the lookup modules, this file has no web code in it: the web app and the
MCP server both call these functions directly. Python's built-in `sqlite3`
does the storage, so there is nothing extra to install, and the whole notebook
is one file (`osint.db` at the repo root, ignored by git).
"""
import os
import sqlite3
from datetime import datetime, timezone
from itertools import groupby
from pathlib import Path

from osint.claims import Claim

REPO_ROOT = Path(__file__).resolve().parent.parent

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lookups (
    id       INTEGER PRIMARY KEY,
    case_id  INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    module   TEXT NOT NULL,      -- "dns", "rdap", "subdomains", ...
    target   TEXT NOT NULL,      -- what was looked up
    run_by   TEXT NOT NULL,      -- "me" or "ai"
    ran_at   TEXT NOT NULL,
    error    TEXT                -- NULL when the module succeeded
);

CREATE TABLE IF NOT EXISTS claims (
    id           INTEGER PRIMARY KEY,
    case_id      INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    lookup_id    INTEGER REFERENCES lookups(id) ON DELETE CASCADE,
    subject      TEXT NOT NULL,
    predicate    TEXT NOT NULL,
    object       TEXT NOT NULL,
    source       TEXT NOT NULL,
    confidence   REAL NOT NULL,
    rationale    TEXT NOT NULL,
    evidence_url TEXT NOT NULL,
    found_by     TEXT NOT NULL,
    timestamp    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY,
    case_id    INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    written_by TEXT NOT NULL,    -- "me" or "ai"
    created_at TEXT NOT NULL
);
"""
# CREATE TABLE IF NOT EXISTS only creates missing tables; it never changes an
# existing one. If a column is added later, the simplest path for a personal
# tool is an ALTER TABLE step here, or deleting osint.db and starting fresh.


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_path() -> Path:
    """Where the notebook lives. Set OSINT_DB to use a different file.

    It's anchored to the repo rather than the current folder, so the web app
    and the MCP server (which Claude may start from anywhere) share one file.
    """
    return Path(os.environ.get("OSINT_DB", REPO_ROOT / "osint.db"))


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open the notebook, creating its tables on first use."""
    # FastAPI may open the connection in one worker thread and use it in
    # another. Each request still gets its own connection, so turning off
    # sqlite3's same-thread check is safe here.
    conn = sqlite3.connect(path or default_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row  # rows behave like dicts: row["name"]
    conn.execute("PRAGMA foreign_keys = ON")  # SQLite leaves these off by default
    conn.executescript(SCHEMA)
    return conn


# Writes. Each one runs inside `with conn:`, which commits when the block
# finishes and rolls back if it raises, so a half-saved lookup can't happen.

def create_case(conn: sqlite3.Connection, name: str, description: str = "") -> int:
    with conn:
        cur = conn.execute(
            "INSERT INTO cases (name, description, created_at) VALUES (?, ?, ?)",
            (name.strip(), description.strip(), _now()),
        )
    return cur.lastrowid


def record_lookup(conn: sqlite3.Connection, case_id: int, module: str, target: str,
                  claims: list[Claim], error: str | None = None, run_by: str = "me") -> int:
    """Save one module run and the claims it returned. Returns the lookup's id."""
    with conn:
        cur = conn.execute(
            "INSERT INTO lookups (case_id, module, target, run_by, ran_at, error)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, module, target, run_by, _now(), error),
        )
        lookup_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO claims (case_id, lookup_id, subject, predicate, object, source,"
            " confidence, rationale, evidence_url, found_by, timestamp)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(case_id, lookup_id, c.subject, c.predicate, c.object, c.source, c.confidence,
              c.rationale, c.evidence_url, c.found_by, c.timestamp) for c in claims],
        )
    return lookup_id


def add_note(conn: sqlite3.Connection, case_id: int, body: str, written_by: str = "me") -> int:
    with conn:
        cur = conn.execute(
            "INSERT INTO notes (case_id, body, written_by, created_at) VALUES (?, ?, ?, ?)",
            (case_id, body.strip(), written_by, _now()),
        )
    return cur.lastrowid


# Reads. They return plain dicts so callers (templates, MCP tools) don't need
# to know about sqlite3.Row.

def list_cases(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("""
        SELECT cases.*,
               (SELECT COUNT(*) FROM lookups WHERE lookups.case_id = cases.id) AS lookup_count,
               (SELECT COUNT(*) FROM notes WHERE notes.case_id = cases.id) AS note_count
        FROM cases ORDER BY id DESC
    """)
    return [dict(row) for row in rows]


def get_case(conn: sqlite3.Connection, case_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    return dict(row) if row else None


def case_notes(conn: sqlite3.Connection, case_id: int) -> list[dict]:
    rows = conn.execute("SELECT * FROM notes WHERE case_id = ? ORDER BY id", (case_id,))
    return [dict(row) for row in rows]


def case_lookups(conn: sqlite3.Connection, case_id: int) -> list[dict]:
    """The case's lookup log, oldest first, with how many claims each run returned."""
    rows = conn.execute("""
        SELECT lookups.*,
               (SELECT COUNT(*) FROM claims WHERE claims.lookup_id = lookups.id) AS claim_count
        FROM lookups WHERE case_id = ? ORDER BY id
    """, (case_id,))
    return [dict(row) for row in rows]


def case_claims(conn: sqlite3.Connection, case_id: int) -> list[dict]:
    """The case's claims with repeats folded together, sorted by subject.

    Each fact from each source appears once, with when it was first and last
    seen; the newest copy supplies the confidence, rationale and evidence. The
    same fact from two different sources stays as two rows: how much they
    corroborate each other is a scoring rule (`combine()` in claims.py), not a
    storage one.
    """
    facts: dict[tuple, dict] = {}
    for row in conn.execute("SELECT * FROM claims WHERE case_id = ? ORDER BY id", (case_id,)):
        key = (row["subject"], row["predicate"], row["object"], row["source"])
        fact = facts.setdefault(key, {"first_seen": row["timestamp"], "found_by": set()})
        fact["found_by"].add(row["found_by"])
        fact.update(
            subject=row["subject"], predicate=row["predicate"], object=row["object"],
            source=row["source"], confidence=row["confidence"], rationale=row["rationale"],
            evidence_url=row["evidence_url"], last_seen=row["timestamp"],
        )
    for fact in facts.values():
        fact["found_by"] = ", ".join(sorted(fact["found_by"]))
    return [facts[key] for key in sorted(facts)]


# Markdown export

def format_when(timestamp: str) -> str:
    """'2026-10-17T18:04:05+00:00' -> '2026-10-17 18:04 UTC'."""
    try:
        when = datetime.fromisoformat(timestamp)
    except ValueError:
        return timestamp
    return when.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _cell(value) -> str:
    """Make a value safe inside a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _row(*cells) -> str:
    return "| " + " | ".join(cells) + " |"


def export_markdown(conn: sqlite3.Connection, case_id: int) -> str:
    """The whole case as a Markdown report: notes, claims by subject, and the lookup log."""
    case = get_case(conn, case_id)
    if case is None:
        raise KeyError(f"No case with id {case_id}")

    lines = [
        f"# {case['name']}", "",
        f"Case {case['id']}, opened {format_when(case['created_at'])}. "
        f"Exported {format_when(_now())}.", "",
    ]
    if case["description"]:
        lines += [case["description"], ""]

    lines += ["## Notes", ""]
    notes = case_notes(conn, case_id)
    if not notes:
        lines += ["No notes yet.", ""]
    for note in notes:
        by_ai = " (written by ai)" if note["written_by"] == "ai" else ""
        lines += [f"### {format_when(note['created_at'])}{by_ai}", "", note["body"], ""]

    lines += ["## Claims", ""]
    claims = case_claims(conn, case_id)
    if not claims:
        lines += ["No claims saved yet.", ""]
    for subject, facts in groupby(claims, key=lambda fact: fact["subject"]):
        lines += [
            f"### {subject}", "",
            _row("Predicate", "Value", "Confidence", "Why", "Source", "Found by",
                 "First seen", "Last seen"),
            _row(*["---"] * 8),
        ]
        for fact in facts:
            value = _cell(fact["object"])
            if fact["evidence_url"]:
                value = f"[{value}](<{fact['evidence_url']}>)"
            lines.append(_row(
                _cell(fact["predicate"]), value, str(fact["confidence"]), _cell(fact["rationale"]),
                _cell(fact["source"]), fact["found_by"], format_when(fact["first_seen"]),
                format_when(fact["last_seen"]),
            ))
        lines.append("")

    lines += ["## Lookup log", ""]
    lookups = case_lookups(conn, case_id)
    if not lookups:
        lines += ["No lookups saved yet.", ""]
    else:
        lines += [_row("When", "Module", "Target", "Run by", "Claims", "Error"), _row(*["---"] * 6)]
        for lookup in lookups:
            lines.append(_row(
                format_when(lookup["ran_at"]), _cell(lookup["module"]), _cell(lookup["target"]),
                lookup["run_by"], str(lookup["claim_count"]), _cell(lookup["error"] or ""),
            ))
        lines.append("")
    return "\n".join(lines)
