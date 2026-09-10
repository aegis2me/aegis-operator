#!/usr/bin/env python3
"""
Import the original Aegis RAGL corpus (the flat title/body SQLite, ~4.2k rows)
into the new store so nothing is lost. Rows that already carry a CVE id are keyed
by it; the rest become LEGACY-<n> entries with source='legacy'.

Usage: seed_legacy.py <legacy_RAGL.sqlite> [target_db]
"""
import sqlite3
import sys

import rag_db

CVE_RE = rag_db.CVE_RE


def run(legacy_path, db_path=None):
    conn = rag_db.connect(db_path)
    src = sqlite3.connect(legacy_path)
    rows = src.execute("SELECT title, body FROM RAGL").fetchall()
    print(f"[legacy] {len(rows)} rows in {legacy_path}")

    n = 0
    for i, (title, body) in enumerate(rows):
        title = title or ""
        body = body or ""
        m = CVE_RE.search(title) or CVE_RE.search(body)
        cve_id = m.group(0).upper() if m else f"LEGACY-{i:05d}"
        # For real-CVE matches, legacy text is fill-only so NVD stays authoritative.
        fill = ("title", "description") if cve_id.startswith("CVE-") else ()
        rag_db.upsert_vuln(
            conn, cve_id, source="legacy", fill_only=fill,
            title=title[:200] or None,
            description=body or None,
        )
        n += 1
        if n % 500 == 0:
            conn.commit()
    conn.commit()
    rag_db.set_state(conn, "legacy", note=f"{n} rows imported")
    print(f"[legacy] imported {n} rows; stats:", rag_db.stats(conn))
    conn.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: seed_legacy.py <legacy_RAGL.sqlite> [target_db]", file=sys.stderr)
        sys.exit(2)
    run(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
