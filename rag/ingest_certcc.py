#!/usr/bin/env python3
"""
Ingest CERT/CC Vulnerability Notes (kb.cert.org).

CERT/CC publishes deep technical writeups for complex / multi-vendor vulnerabilities
(VU#NNNNNN notes). They frequently predate or complement the NVD entry and often
carry vendor-coordination detail NVD lacks. Value-add to the store:
  * a note that references CVE(s) -> attach its title/overview/url as fill-only text
    and add 'certcc' provenance to those CVE rows (NVD stays authoritative).
  * a note with NO CVE (many VINCE notes) -> a searchable CERTCC-VU-<id> row.

Feeds (env-overridable, tried in order; all failures are NON-FATAL so refresh.sh
never wedges):
  * CERTCC_FEED  -- an Atom/RSS feed of recent notes
                    (default https://www.kb.cert.org/vuls/atomfeed/)
  * per-note JSON at https://www.kb.cert.org/vuls/api/<id>/ is used to enrich a note
    with its full overview + referenced CVEs when --enrich is set.
  * --backfill <N> pulls the newest N notes from the VINCE note API index
    (https://www.kb.cert.org/vuls/api/) instead of only the feed's recent window.

Source: https://www.kb.cert.org/vuls/
"""
import hashlib
import os
import re
import sys
import xml.etree.ElementTree as ET

import rag_db
from http_util import make_session, get

FEED_URL = os.environ.get("CERTCC_FEED", "https://www.kb.cert.org/vuls/atomfeed/")
API_ROOT = os.environ.get("CERTCC_API", "https://www.kb.cert.org/vuls/api/")
CVE_RE = rag_db.CVE_RE
VU_RE = re.compile(r"VU#?\s?(\d{4,7})")
TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(s: str) -> str:
    return TAG_RE.sub(" ", s or "").replace("&nbsp;", " ").strip()


def _key_for(vu_id: str, link: str, title: str) -> str:
    if vu_id:
        return f"CERTCC-VU-{vu_id}"
    h = hashlib.sha1((link or title or "").encode("utf-8", "replace")).hexdigest()[:12]
    return f"CERTCC-{h}"


def _iter_feed_entries(text: str):
    """Yield (title, link, summary) from an Atom or RSS document, tolerantly."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        print(f"[certcc] feed parse error: {e}", file=sys.stderr)
        return
    # Atom
    ns = {"a": "http://www.w3.org/2005/Atom"}
    entries = root.findall(".//a:entry", ns)
    if entries:
        for e in entries:
            title = (e.findtext("a:title", default="", namespaces=ns) or "").strip()
            link_el = e.find("a:link", ns)
            link = (link_el.get("href") if link_el is not None else "") or ""
            summ = (e.findtext("a:summary", default="", namespaces=ns)
                    or e.findtext("a:content", default="", namespaces=ns) or "")
            yield title, link, _strip_html(summ)
        return
    # RSS 2.0 fallback
    for it in root.findall(".//item"):
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        summ = _strip_html(it.findtext("description") or "")
        yield title, link, summ


def _enrich_note(sess, vu_id):
    """Return (overview, cve_list) from the per-note JSON API, best-effort."""
    if not vu_id:
        return None, []
    try:
        j = get(sess, f"{API_ROOT}{vu_id}/", timeout=45).json()
    except Exception as e:
        print(f"[certcc] enrich VU#{vu_id} failed: {e}", file=sys.stderr)
        return None, []
    note = j.get("note", j) if isinstance(j, dict) else {}
    overview = note.get("overview") or note.get("clean_desc") or ""
    cves = set()
    for key in ("cveids", "cve", "vuls"):
        val = note.get(key)
        if isinstance(val, list):
            for x in val:
                cves.update(m.upper() for m in CVE_RE.findall(str(x)))
        elif isinstance(val, str):
            cves.update(m.upper() for m in CVE_RE.findall(val))
    return _strip_html(overview) or None, sorted(cves)


def run(db_path=None, enrich=False, backfill=0):
    conn = rag_db.connect(db_path)
    sess = make_session()

    entries = []
    if backfill:
        print(f"[certcc] backfill: newest {backfill} notes via {API_ROOT}")
        try:
            idx = get(sess, API_ROOT, timeout=60).json()
            notes = idx if isinstance(idx, list) else idx.get("notes", idx.get("results", []))
            for n in notes[:backfill]:
                nid = str(n.get("vuid") or n.get("idnumber") or n.get("id") or "")
                nid = (VU_RE.search(nid).group(1) if VU_RE.search(nid) else re.sub(r"\D", "", nid))
                title = n.get("name") or n.get("title") or f"VU#{nid}"
                link = n.get("url") or f"https://www.kb.cert.org/vuls/id/{nid}"
                entries.append((title, link, _strip_html(n.get("overview") or "")))
        except Exception as e:
            print(f"[certcc] backfill index failed ({e}); falling back to feed", file=sys.stderr)

    if not entries:
        print(f"[certcc] fetching feed {FEED_URL}")
        try:
            entries = list(_iter_feed_entries(get(sess, FEED_URL, timeout=60).text))
        except Exception as e:
            print(f"[certcc] feed fetch failed ({e}); nothing ingested", file=sys.stderr)
            conn.close()
            return
    print(f"[certcc] {len(entries)} notes")

    n_cve = n_note = 0
    for title, link, summary in entries:
        vu_m = VU_RE.search(title) or VU_RE.search(link)
        vu_id = vu_m.group(1) if vu_m else ""
        cves = {m.upper() for m in CVE_RE.findall(f"{title} {summary}")}
        overview = summary
        if enrich and vu_id:
            ov, api_cves = _enrich_note(sess, vu_id)
            overview = ov or overview
            cves.update(api_cves)

        if cves:
            for cve in cves:
                rag_db.upsert_vuln(
                    conn, cve, source="certcc",
                    fill_only=("title", "description"),
                    title=title[:200] or None,
                    description=(overview or title) or None,
                    url=link or None,
                    refs=link or None,
                )
                n_cve += 1
        else:
            rag_db.upsert_vuln(
                conn, _key_for(vu_id, link, title), source="certcc",
                title=title[:200] or None,
                description=overview or title or None,
                url=link or None,
                refs=link or None,
            )
            n_note += 1
        if (n_cve + n_note) % 100 == 0:
            conn.commit()

    conn.commit()
    rag_db.set_state(conn, "certcc", note=f"{n_cve} cve-links, {n_note} standalone notes")
    print(f"[certcc] upserted {n_cve} CVE enrichments + {n_note} standalone notes")
    print("[certcc] stats:", rag_db.stats(conn))
    conn.close()


if __name__ == "__main__":
    args = sys.argv[1:]
    enrich = "--enrich" in args
    backfill = 0
    if "--backfill" in args:
        i = args.index("--backfill")
        backfill = int(args[i + 1]) if i + 1 < len(args) else 200
    db = next((a for a in args if not a.startswith("--") and not a.isdigit()), None)
    run(db, enrich=enrich, backfill=backfill)
