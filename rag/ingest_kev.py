#!/usr/bin/env python3
"""
Ingest the CISA Known Exploited Vulnerabilities (KEV) catalog.

One small JSON, refreshed daily by CISA. Sets kev=1 / kev_due on each listed CVE,
and fills a title/description for CVEs not already known from another feed so a
KEV-only entry is still searchable.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Feed:   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
import sys

import rag_db
from http_util import make_session, get

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def run(db_path=None):
    conn = rag_db.connect(db_path)
    sess = make_session()
    print(f"[kev] fetching {KEV_URL}")
    data = get(sess, KEV_URL, timeout=90).json()
    vulns = data.get("vulnerabilities", [])
    print(f"[kev] catalog version {data.get('catalogVersion')} :: {len(vulns)} entries")

    n = 0
    for v in vulns:
        cve = (v.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        name = v.get("vulnerabilityName") or ""
        desc = v.get("shortDescription") or ""
        rag_db.upsert_vuln(
            conn, cve, source="kev",
            kev=1,
            kev_due=v.get("dueDate"),
            # fill-only: never overwrite richer NVD title/description.
            fill_only=("title", "description"),
            title=name or None,
            description=desc or None,
        )
        n += 1
        if n % 200 == 0:
            conn.commit()
    conn.commit()
    rag_db.set_state(conn, "kev", cursor=str(data.get("catalogVersion")),
                     note=f"{n} entries")
    print(f"[kev] upserted {n} KEV entries")
    print("[kev] stats:", rag_db.stats(conn))
    conn.close()


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else None)
