#!/usr/bin/env python3
"""
Ingest enriched CVE records from the NVD 2.0 REST API.

Two modes:
  * backfill  (default): pull every CVE PUBLISHED from --from-year (default 2018)
               to now, walking <=120-day pubDate windows, paginated 2000/page.
  * --since-last : incremental -- pull everything MODIFIED since the last nvd run
               (uses lastMod window). This is what refresh.sh calls.

Rate limits (NVD): 5 requests / 30s without a key, 50 / 30s with one. Set
NVD_API_KEY in the environment to get the fast lane. Honors HTTP(S)_PROXY.

Source: https://nvd.nist.gov      API: https://services.nvd.nist.gov/rest/json/cves/2.0
"""
import datetime as dt
import os
import sys
import time

import rag_db
from http_util import make_session, get

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000
WINDOW_DAYS = 120
API_KEY = os.environ.get("NVD_API_KEY", "").strip()
SLEEP = 0.7 if API_KEY else 6.5   # stay under the published rate limit


def _headers():
    return {"apiKey": API_KEY} if API_KEY else {}


def _fmt(d: dt.datetime) -> str:
    # NVD wants ISO-8601 with milliseconds
    return d.strftime("%Y-%m-%dT%H:%M:%S.000")


def _extract(cve: dict) -> dict:
    cid = cve.get("id", "").upper()
    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"),
                descs[0]["value"] if descs else "")
    # title = first sentence-ish of the description (cap length)
    title = desc.split(". ")[0][:200] if desc else cid

    cvss = severity = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            cvss = data.get("baseScore")
            severity = data.get("baseSeverity") or arr[0].get("baseSeverity")
            break

    refs = "\n".join(r.get("url", "") for r in cve.get("references", []) if r.get("url"))
    return dict(
        cve_id=cid, title=title, description=desc,
        cvss_v3=cvss, severity=severity,
        published=cve.get("published"), modified=cve.get("lastModified"),
        url=f"https://nvd.nist.gov/vuln/detail/{cid}",
        refs=refs or None,
    )


def _pull_window(conn, sess, param_start, param_end, start, end):
    """Paginate one date window; param_* are the NVD param names to use."""
    idx, total, got = 0, None, 0
    while True:
        params = {
            param_start: _fmt(start), param_end: _fmt(end),
            "resultsPerPage": PAGE, "startIndex": idx,
        }
        r = get(sess, API, params=params, headers=_headers(), timeout=120, retries=5, backoff=SLEEP)
        j = r.json()
        total = j.get("totalResults", 0)
        vulns = j.get("vulnerabilities", [])
        for item in vulns:
            rec = _extract(item.get("cve", {}))
            if rec["cve_id"]:
                rag_db.upsert_vuln(conn, rec["cve_id"], source="nvd",
                                   **{k: v for k, v in rec.items() if k != "cve_id"})
                got += 1
        conn.commit()
        idx += PAGE
        time.sleep(SLEEP)
        if idx >= total or not vulns:
            break
    return got, total


def backfill(conn, sess, from_year):
    start = dt.datetime(from_year, 1, 1)
    now = dt.datetime.utcnow()
    grand = 0
    while start < now:
        end = min(start + dt.timedelta(days=WINDOW_DAYS), now)
        print(f"[nvd] window pub {start.date()} .. {end.date()}")
        got, total = _pull_window(conn, sess, "pubStartDate", "pubEndDate", start, end)
        grand += got
        print(f"[nvd]   +{got} (window total {total}); running {grand}")
        rag_db.set_state(conn, "nvd", cursor=end.isoformat(), note=f"backfill {grand}")
        start = end
    print(f"[nvd] backfill done: {grand} CVE records")


def since_last(conn, sess):
    st = rag_db.get_state(conn, "nvd")
    if st and st[0]:
        since = dt.datetime.strptime(st[0][:19], "%Y-%m-%dT%H:%M:%S")
    else:
        since = dt.datetime.utcnow() - dt.timedelta(days=8)
    now = dt.datetime.utcnow()
    grand = 0
    start = since
    while start < now:
        end = min(start + dt.timedelta(days=WINDOW_DAYS), now)
        print(f"[nvd] delta lastMod {start.date()} .. {end.date()}")
        got, total = _pull_window(conn, sess, "lastModStartDate", "lastModEndDate", start, end)
        grand += got
        start = end
    rag_db.set_state(conn, "nvd", cursor=now.isoformat(), note=f"delta {grand}")
    print(f"[nvd] incremental done: {grand} records touched")


def run():
    db_path = None
    from_year = 2018
    mode = "backfill"
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--since-last":
            mode = "since"
        elif a == "--from-year":
            from_year = int(args[i + 1]); i += 1
        elif a == "--db":
            db_path = args[i + 1]; i += 1
        elif not a.startswith("--"):
            db_path = a
        i += 1

    conn = rag_db.connect(db_path)
    sess = make_session()
    print(f"[nvd] mode={mode} api_key={'yes' if API_KEY else 'no'} sleep={SLEEP}s")
    if mode == "since":
        since_last(conn, sess)
    else:
        backfill(conn, sess, from_year)
    print("[nvd] stats:", rag_db.stats(conn))
    conn.close()


if __name__ == "__main__":
    run()
