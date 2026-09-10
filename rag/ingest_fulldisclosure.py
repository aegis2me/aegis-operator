#!/usr/bin/env python3
"""
Ingest the Full Disclosure mailing list (early / raw vulnerability disclosure chatter,
often the FIRST public appearance of a PoC before any CVE is assigned).

Primary feed is the Seclists RSS mirror (recent window). --backfill <year> walks the
Seclists monthly archive index pages for a fuller pull. Non-official source, so entries
are stored as advisory rows:
  * post referencing CVE(s) -> add 'fulldisclosure' provenance + url ref (fill-only text)
    to those CVE rows.
  * post with no CVE -> a searchable FD-<hash> row (title + list url).

Feeds (env-overridable):
  * FD_FEED       -- default https://seclists.org/rss/fulldisclosure.rss
  * FD_ARCHIVE    -- default https://seclists.org/fulldisclosure/   (for --backfill)
Source: https://seclists.org/fulldisclosure/
"""
import calendar
import hashlib
import os
import re
import sys
import xml.etree.ElementTree as ET

import rag_db
from http_util import make_session, get

FEED_URL = os.environ.get("FD_FEED", "https://seclists.org/rss/fulldisclosure.rss")
ARCHIVE = os.environ.get("FD_ARCHIVE", "https://seclists.org/fulldisclosure/")
CVE_RE = rag_db.CVE_RE
TAG_RE = re.compile(r"<[^>]+>")
# Seclists post links look like /fulldisclosure/2026/Sep/12
POST_RE = re.compile(r'href="((?:/fulldisclosure/|https://seclists\.org/fulldisclosure/)\d{4}/[A-Za-z]{3}/\d+)"')
TITLE_RE = re.compile(r'href="[^"]*/fulldisclosure/\d{4}/[A-Za-z]{3}/\d+"[^>]*>(.*?)</a>', re.DOTALL)


def _strip_html(s: str) -> str:
    return TAG_RE.sub(" ", s or "").replace("&nbsp;", " ").strip()


def _key_for(link: str, title: str) -> str:
    h = hashlib.sha1((link or title or "").encode("utf-8", "replace")).hexdigest()[:12]
    return f"FD-{h}"


def _upsert(conn, title, link, desc, counters):
    cves = {m.upper() for m in CVE_RE.findall(f"{title} {desc}")}
    if cves:
        for cve in cves:
            rag_db.upsert_vuln(
                conn, cve, source="fulldisclosure",
                fill_only=("title", "description"),
                title=title[:200] or None,
                description=desc or title or None,
                url=link or None, refs=link or None,
            )
            counters[0] += 1
    else:
        rag_db.upsert_vuln(
            conn, _key_for(link, title), source="fulldisclosure",
            title=title[:200] or None,
            description=desc or title or None,
            url=link or None, refs=link or None,
        )
        counters[1] += 1


def _iter_rss(text: str):
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        print(f"[fd] rss parse error: {e}", file=sys.stderr)
        return
    for it in root.findall(".//item"):
        yield ((it.findtext("title") or "").strip(),
               (it.findtext("link") or "").strip(),
               _strip_html(it.findtext("description") or ""))


def _iter_archive(sess, year):
    """Walk the monthly index pages for a year, yielding (title, absolute_link)."""
    for mi in range(1, 13):
        mon = calendar.month_abbr[mi]  # 'Jan'..'Dec'
        url = f"{ARCHIVE.rstrip('/')}/{year}/{mon}/"
        try:
            html = get(sess, url, timeout=45).text
        except Exception as e:
            print(f"[fd]   {year}/{mon} skip ({e})", file=sys.stderr)
            continue
        links = POST_RE.findall(html)
        titles = TITLE_RE.findall(html)
        for i, link in enumerate(links):
            if link.startswith("/"):
                link = "https://seclists.org" + link
            title = _strip_html(titles[i]) if i < len(titles) else link
            yield title, link
        print(f"[fd]   {year}/{mon}: {len(links)} posts")


def run(db_path=None, backfill_year=0):
    conn = rag_db.connect(db_path)
    sess = make_session()
    counters = [0, 0]  # [cve-links, standalone]

    if backfill_year:
        print(f"[fd] backfill archive year {backfill_year} from {ARCHIVE}")
        for i, (title, link) in enumerate(_iter_archive(sess, backfill_year)):
            _upsert(conn, title, link, "", counters)
            if i % 100 == 0:
                conn.commit()
    else:
        print(f"[fd] fetching feed {FEED_URL}")
        try:
            items = list(_iter_rss(get(sess, FEED_URL, timeout=60).text))
        except Exception as e:
            print(f"[fd] feed fetch failed ({e}); nothing ingested", file=sys.stderr)
            conn.close()
            return
        print(f"[fd] {len(items)} posts")
        for title, link, desc in items:
            _upsert(conn, title, link, desc, counters)
        conn.commit()

    conn.commit()
    rag_db.set_state(conn, "fulldisclosure",
                     note=f"{counters[0]} cve-links, {counters[1]} standalone posts")
    print(f"[fd] upserted {counters[0]} CVE enrichments + {counters[1]} standalone posts")
    print("[fd] stats:", rag_db.stats(conn))
    conn.close()


if __name__ == "__main__":
    args = sys.argv[1:]
    year = 0
    if "--backfill" in args:
        i = args.index("--backfill")
        year = int(args[i + 1]) if i + 1 < len(args) else 0
    db = next((a for a in args if not a.startswith("--") and not a.isdigit()), None)
    run(db, backfill_year=year)
