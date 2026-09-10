#!/usr/bin/env python3
"""
Ingest CISA Alerts & Advisories -- the general cybersecurity advisories and the
ICS-CERT / ICS-medical advisories (distinct from the KEV catalog, which ingest_kev.py
already covers). These carry joint bulletins, ICS/OT product advisories, and mitigation
guidance, often referencing CVE(s).

Behaviour:
  * advisory that references CVE(s) -> add 'cisa-adv' provenance + fill-only title/desc
    + advisory url as a reference on those CVE rows.
  * advisory with no CVE -> a searchable CISA-<id> row (id = ICSA-.. / AA.. when present,
    else a hash of the link).

Feeds (env CISA_FEEDS, comma-separated; defaults below). Each fetch is NON-FATAL.
Source: https://www.cisa.gov/news-events/cybersecurity-advisories
"""
import hashlib
import os
import re
import sys
import xml.etree.ElementTree as ET

import rag_db
from http_util import make_session, get

DEFAULT_FEEDS = [
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
    "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml",
]
FEEDS = [u.strip() for u in os.environ.get("CISA_FEEDS", ",".join(DEFAULT_FEEDS)).split(",") if u.strip()]
CVE_RE = rag_db.CVE_RE
ADV_ID_RE = re.compile(r"\b((?:ICSA|ICSMA|AA|ICS-ALERT)-\d{2,4}-\d{2,4}(?:-\d+)?)\b", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(s: str) -> str:
    return TAG_RE.sub(" ", s or "").replace("&nbsp;", " ").strip()


def _iter_items(text: str):
    """Yield (title, link, description, pubdate) from an RSS/Atom document."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        print(f"[cisa] feed parse error: {e}", file=sys.stderr)
        return
    items = root.findall(".//item")
    if items:
        for it in items:
            yield ((it.findtext("title") or "").strip(),
                   (it.findtext("link") or "").strip(),
                   _strip_html(it.findtext("description") or ""),
                   (it.findtext("pubDate") or "").strip())
        return
    ns = {"a": "http://www.w3.org/2005/Atom"}
    for e in root.findall(".//a:entry", ns):
        link_el = e.find("a:link", ns)
        yield ((e.findtext("a:title", default="", namespaces=ns) or "").strip(),
               (link_el.get("href") if link_el is not None else "") or "",
               _strip_html(e.findtext("a:summary", default="", namespaces=ns)
                           or e.findtext("a:content", default="", namespaces=ns) or ""),
               (e.findtext("a:updated", default="", namespaces=ns) or "").strip())


def _key_for(adv_id: str, link: str, title: str) -> str:
    if adv_id:
        return f"CISA-{adv_id.upper()}"
    h = hashlib.sha1((link or title or "").encode("utf-8", "replace")).hexdigest()[:12]
    return f"CISA-{h}"


def run(db_path=None):
    conn = rag_db.connect(db_path)
    sess = make_session()
    total_cve = total_adv = 0

    for feed in FEEDS:
        print(f"[cisa] fetching {feed}")
        try:
            text = get(sess, feed, timeout=60).text
        except Exception as e:
            print(f"[cisa] fetch failed ({e}); skipping this feed", file=sys.stderr)
            continue
        items = list(_iter_items(text))
        print(f"[cisa]   {len(items)} advisories")
        for title, link, desc, pub in items:
            blob = f"{title} {desc}"
            cves = {m.upper() for m in CVE_RE.findall(blob)}
            adv_m = ADV_ID_RE.search(f"{title} {link}")
            adv_id = adv_m.group(1) if adv_m else ""
            if cves:
                for cve in cves:
                    rag_db.upsert_vuln(
                        conn, cve, source="cisa-adv",
                        fill_only=("title", "description"),
                        title=title[:200] or None,
                        description=desc or title or None,
                        url=link or None,
                        refs=link or None,
                        published=pub or None,
                    )
                    total_cve += 1
            else:
                rag_db.upsert_vuln(
                    conn, _key_for(adv_id, link, title), source="cisa-adv",
                    title=title[:200] or None,
                    description=desc or title or None,
                    url=link or None,
                    refs=link or None,
                    published=pub or None,
                )
                total_adv += 1
        conn.commit()

    rag_db.set_state(conn, "cisa-adv", note=f"{total_cve} cve-links, {total_adv} standalone advisories")
    print(f"[cisa] upserted {total_cve} CVE enrichments + {total_adv} standalone advisories")
    print("[cisa] stats:", rag_db.stats(conn))
    conn.close()


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else None)
