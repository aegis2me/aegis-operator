#!/usr/bin/env python3
"""
Ingest EPSS (Exploit Prediction Scoring System) scores from FIRST.org.

Bulk daily CSV (gzipped): every scored CVE with epss (0..1 probability of
exploitation in the next 30 days) and percentile. ~250k rows, a few MB.

EPSS is UPDATE-ONLY: it never creates rows for CVEs we don't already track
(otherwise we'd pull the entire CVE universe with no title/description). Run it
AFTER nvd/kev so the interesting CVEs exist.

Source: https://www.first.org/epss/
Feed:   https://epss.cyentia.com/epss_scores-current.csv.gz
"""
import csv
import gzip
import io
import sys

import rag_db
from http_util import make_session, get

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def run(db_path=None):
    conn = rag_db.connect(db_path)
    sess = make_session()
    print(f"[epss] fetching {EPSS_URL}")
    raw = get(sess, EPSS_URL, timeout=180).content
    text = gzip.decompress(raw).decode("utf-8", errors="replace")

    # Build a set of CVEs we already track so we only update those (fast, bounded).
    known = {r[0] for r in conn.execute("SELECT cve_id FROM vulns WHERE cve_id LIKE 'CVE-%'")}
    print(f"[epss] {len(known)} tracked CVEs to enrich")

    reader = csv.reader(io.StringIO(text))
    updated = 0
    model = None
    for row in reader:
        if not row:
            continue
        if row[0].startswith("#"):
            model = ",".join(row)  # header comment carries model version/date
            continue
        if row[0] == "cve":
            continue  # column header
        cve = row[0].strip().upper()
        if cve not in known:
            continue
        try:
            epss = float(row[1])
            pctl = float(row[2])
        except (IndexError, ValueError):
            continue
        rag_db.upsert_vuln(conn, cve, source="epss", epss=epss, epss_pctl=pctl)
        updated += 1
        if updated % 500 == 0:
            conn.commit()
    conn.commit()
    rag_db.set_state(conn, "epss", cursor=(model or "")[:120], note=f"{updated} updated")
    print(f"[epss] updated {updated} CVEs ({model})")
    conn.close()


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else None)
