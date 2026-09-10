#!/usr/bin/env python3
"""
Enrich existing CVE rows with CVE Details (cvedetails.com) metadata.

Honest scope: CVE Details is a THIRD-PARTY aggregator whose numbers are derived from
CVE/NVD/EPSS -- data this store already holds directly. Its genuine value is (a) a
convenient per-CVE browse URL and (b) their exploit-availability / extended-reference
metadata, which today lives behind an API key. So this ingestor is deliberately
ENRICHMENT-ONLY and does not scrape:
  * always: adds a deterministic cvedetails browse URL as a reference + 'cvedetails'
    provenance to the targeted CVE rows (no network needed for this part).
  * if CVEDETAILS_API_KEY is set: also calls the official API per CVE (rate-limited)
    to pull exploit-exists / extra references, appended to refs.

Targets (pick one; default = --top 300):
  * --cves CVE-...,CVE-...   explicit list
  * --top N                  the N most operationally relevant CVE rows already in the
                             store (KEV first, then high EPSS, then CVSS), newest-first
Non-fatal on any API error. Source: https://www.cvedetails.com
"""
import os
import sys
import time

import rag_db
from http_util import make_session, get

API_KEY = os.environ.get("CVEDETAILS_API_KEY", "").strip()
API_BASE = os.environ.get("CVEDETAILS_API", "https://www.cvedetails.com/api/v1")
RATE_SLEEP = float(os.environ.get("CVEDETAILS_SLEEP", "1.5"))


def _browse_url(cve: str) -> str:
    return f"https://www.cvedetails.com/cve/{cve}/"


def _select_top(conn, n):
    rows = conn.execute(
        "SELECT cve_id FROM vulns WHERE cve_id LIKE 'CVE-%' "
        "ORDER BY kev DESC, COALESCE(epss,0) DESC, COALESCE(cvss_v3,0) DESC, "
        "COALESCE(published,'') DESC LIMIT ?", (n,)
    ).fetchall()
    return [r[0] for r in rows]


def _api_enrich(sess, cve):
    """Best-effort official-API pull. Returns a short note string or None."""
    if not API_KEY:
        return None
    try:
        r = get(sess, f"{API_BASE}/vulnerability/info/{cve}",
                headers={"Authorization": f"Bearer {API_KEY}"}, timeout=40)
        j = r.json()
    except Exception as e:
        print(f"[cvedetails] api {cve} failed: {e}", file=sys.stderr)
        return None
    data = j.get("data", j) if isinstance(j, dict) else {}
    exploit = data.get("exploitExists") or data.get("exploit_exists")
    parts = []
    if exploit is not None:
        parts.append(f"cvedetails:exploitExists={bool(exploit)}")
    refs = data.get("references") or []
    if isinstance(refs, list) and refs:
        parts.append("refs:" + " ".join(str(x) for x in refs[:5]))
    return " ".join(parts) or None


def run(db_path=None, cves=None, top=0):
    conn = rag_db.connect(db_path)
    sess = make_session() if API_KEY else None

    if cves:
        targets = [c.strip().upper() for c in cves if c.strip()]
    else:
        targets = _select_top(conn, top or 300)
    print(f"[cvedetails] enriching {len(targets)} CVEs "
          f"(api_key={'yes' if API_KEY else 'no -> link-only'})")

    n = 0
    for cve in targets:
        # link-only enrichment always applies (no scraping)
        extra = _api_enrich(sess, cve) if API_KEY else None
        if API_KEY:
            time.sleep(RATE_SLEEP)
        rag_db.upsert_vuln(
            conn, cve, source="cvedetails",
            refs=_browse_url(cve),
            description=extra,  # only non-None when API returned something
        )
        n += 1
        if n % 200 == 0:
            conn.commit()
    conn.commit()
    rag_db.set_state(conn, "cvedetails",
                     note=f"{n} CVEs enriched ({'api' if API_KEY else 'link-only'})")
    print(f"[cvedetails] enriched {n} CVEs")
    print("[cvedetails] stats:", rag_db.stats(conn))
    conn.close()


if __name__ == "__main__":
    args = sys.argv[1:]
    cves = None
    top = 0
    if "--cves" in args:
        i = args.index("--cves")
        cves = args[i + 1].split(",") if i + 1 < len(args) else []
    if "--top" in args:
        i = args.index("--top")
        top = int(args[i + 1]) if i + 1 < len(args) else 300
    db = next((a for a in args if not a.startswith("--")
               and not a.isdigit() and not a.upper().startswith("CVE-")), None)
    run(db, cves=cves, top=top)
