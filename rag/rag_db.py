"""
Shared DB helpers for the aegis-rag vulnerability knowledge base.

This module is deployed to the KALI side (default DB path /opt/aegis-rag/ragl.sqlite).
The orchestrator never touches the DB directly -- it calls the `rag_search` MCP tool,
which WSL-execs rag_query.py, which uses this module.

Schema notes:
  * `vulns`      -- one row per CVE (plus LEGACY-* rows for the imported corpus).
                    Each ingestor writes ONLY its own columns via upsert_vuln(); it
                    never clobbers columns owned by another feed (NVD=title/desc/cvss,
                    KEV=kev, EPSS=epss, Exploit-DB=exploitdb_ids).
  * `vulns_fts`  -- FTS5 mirror of (cve_id,title,description) for ranked keyword search.
  * `RAGL`       -- back-compat VIEW (title, body) so the original RAGManager keeps working.
  * `ingest_state` -- per-source watermark for incremental refresh.
"""
import os
import re
import sqlite3
import datetime

DEFAULT_DB = os.environ.get("AEGIS_RAG_DB", "/opt/aegis-rag/ragl.sqlite")

# Matches CVE-YYYY-NNNN.. (4+ digits). Case-insensitive; callers upper() the result.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SCHEMA = """
CREATE TABLE IF NOT EXISTS vulns (
    cve_id        TEXT PRIMARY KEY,
    title         TEXT,
    description   TEXT,
    source        TEXT,          -- comma-joined provenance (nvd,kev,epss,exploitdb,legacy)
    url           TEXT,
    published     TEXT,
    modified      TEXT,
    cvss_v3       REAL,
    severity      TEXT,
    epss          REAL,          -- 0..1 probability of exploitation in next 30 days
    epss_pctl     REAL,          -- 0..1 percentile among all CVEs
    kev           INTEGER DEFAULT 0,   -- 1 = on CISA Known-Exploited list
    kev_due       TEXT,
    refs          TEXT,          -- newline-joined reference URLs
    exploitdb_ids TEXT,          -- comma-joined Exploit-DB ids
    updated_at    TEXT
);

CREATE VIRTUAL TABLE IF NOT EXISTS vulns_fts USING fts5(
    cve_id UNINDEXED,
    title,
    description,
    tokenize = 'porter unicode61'
);

CREATE VIEW IF NOT EXISTS RAGL (title, body) AS
    SELECT TRIM(COALESCE(cve_id,'') || ' ' || COALESCE(title,'')), COALESCE(description,'')
    FROM vulns;

CREATE TABLE IF NOT EXISTS ingest_state (
    source   TEXT PRIMARY KEY,
    last_run TEXT,
    cursor   TEXT,
    note     TEXT
);
"""


def now_iso() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path: str = None) -> sqlite3.Connection:
    path = path or DEFAULT_DB
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    conn = sqlite3.connect(path, timeout=120)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    return conn


# Columns an ingestor may set. `source` is merged specially (union), never replaced.
_UPSERT_COLS = (
    "title", "description", "url", "published", "modified",
    "cvss_v3", "severity", "epss", "epss_pctl", "kev", "kev_due",
    "refs", "exploitdb_ids",
)


def _merge_source(existing: str, new: str) -> str:
    parts = [p for p in (existing or "").split(",") if p]
    for p in (new or "").split(","):
        if p and p not in parts:
            parts.append(p)
    return ",".join(parts)


def upsert_vuln(conn: sqlite3.Connection, cve_id: str, source: str,
                fill_only=(), **fields) -> None:
    """
    Insert or update one vuln row, touching only the provided (non-None) fields.
    `source` is unioned into the existing provenance list. Keeps vulns_fts in sync.

    fill_only: field names that must only be written when the existing column is
    NULL/empty (used e.g. for KEV title/description so they never clobber richer
    NVD text, regardless of ingest order).
    """
    cve_id = cve_id.strip()
    if not cve_id:
        return
    fill_only = set(fill_only)
    cur = conn.execute(
        "SELECT source, title, description, cvss_v3, url, refs, exploitdb_ids, "
        "published, modified, severity, epss, epss_pctl, kev, kev_due "
        "FROM vulns WHERE cve_id=?", (cve_id,))
    row = cur.fetchone()
    provided = {k: v for k, v in fields.items() if k in _UPSERT_COLS and v is not None}

    if row is None:
        cols = ["cve_id", "source", "updated_at"] + list(provided.keys())
        vals = [cve_id, source or "", now_iso()] + list(provided.values())
        placeholders = ",".join("?" for _ in cols)
        conn.execute(
            f"INSERT INTO vulns ({','.join(cols)}) VALUES ({placeholders})", vals
        )
    else:
        existing = dict(zip(
            ("source", "title", "description", "cvss_v3", "url", "refs",
             "exploitdb_ids", "published", "modified", "severity",
             "epss", "epss_pctl", "kev", "kev_due"), row))
        merged_source = _merge_source(existing["source"], source)
        sets = ["source=?", "updated_at=?"]
        vals = [merged_source, now_iso()]
        for k, v in provided.items():
            if k in fill_only and (existing.get(k) not in (None, "")):
                continue  # keep the existing (richer) value
            sets.append(f"{k}=?")
            vals.append(v)
        vals.append(cve_id)
        conn.execute(f"UPDATE vulns SET {','.join(sets)} WHERE cve_id=?", vals)

    _sync_fts(conn, cve_id)


def _sync_fts(conn: sqlite3.Connection, cve_id: str) -> None:
    conn.execute("DELETE FROM vulns_fts WHERE cve_id=?", (cve_id,))
    conn.execute(
        "INSERT INTO vulns_fts (cve_id, title, description) "
        "SELECT cve_id, COALESCE(title,''), COALESCE(description,'') "
        "FROM vulns WHERE cve_id=?",
        (cve_id,),
    )


def set_state(conn: sqlite3.Connection, source: str, cursor: str = None, note: str = None) -> None:
    conn.execute(
        "INSERT INTO ingest_state (source,last_run,cursor,note) VALUES (?,?,?,?) "
        "ON CONFLICT(source) DO UPDATE SET last_run=excluded.last_run, "
        "cursor=COALESCE(excluded.cursor, ingest_state.cursor), "
        "note=COALESCE(excluded.note, ingest_state.note)",
        (source, now_iso(), cursor, note),
    )


def get_state(conn: sqlite3.Connection, source: str):
    cur = conn.execute("SELECT last_run,cursor,note FROM ingest_state WHERE source=?", (source,))
    return cur.fetchone()


def stats(conn: sqlite3.Connection) -> dict:
    q = conn.execute
    def _src(label):
        return q("SELECT COUNT(*) FROM vulns WHERE source LIKE ?", (f"%{label}%",)).fetchone()[0]
    return {
        "total": q("SELECT COUNT(*) FROM vulns").fetchone()[0],
        "cve": q("SELECT COUNT(*) FROM vulns WHERE cve_id LIKE 'CVE-%'").fetchone()[0],
        "legacy": _src("legacy"),
        "kev": q("SELECT COUNT(*) FROM vulns WHERE kev=1").fetchone()[0],
        "with_epss": q("SELECT COUNT(*) FROM vulns WHERE epss IS NOT NULL").fetchone()[0],
        "with_exploitdb": q("SELECT COUNT(*) FROM vulns WHERE exploitdb_ids IS NOT NULL").fetchone()[0],
        "certcc": _src("certcc"),
        "cisa_adv": _src("cisa-adv"),
        "fulldisclosure": _src("fulldisclosure"),
        "cvedetails": _src("cvedetails"),
        "poc_github": _src("poc-github"),
        "msf": _src("msf"),
        "nuclei": _src("nuclei"),
    }
