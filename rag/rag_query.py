#!/usr/bin/env python3
"""
Hybrid retrieval over the aegis-rag store. This is the single entry point both
operators call (Claude/aegis via the rag_search MCP tool, DeepSeek via
aegis_operator's rag_search tool).

Strategy:
  1. If the query contains CVE ids -> exact lookup of those rows (authoritative).
  2. Otherwise -> FTS5 keyword search ranked by bm25, then re-scored to surface
     actively-exploited (KEV), high-EPSS, high-CVSS results near the top.

Output: human table by default, or --json for tool consumption:
    {"query":..., "mode":"cve|search", "items":[{cve_id,title,severity,cvss,
     epss,epss_pctl,kev,kev_due,exploitdb_ids,url,source,snippet}]}
"""
import argparse
import json
import re
import sys

import rag_db

CVE_RE = rag_db.CVE_RE
FIELDS = ("cve_id", "title", "description", "source", "url", "published",
          "cvss_v3", "severity", "epss", "epss_pctl", "kev", "kev_due", "exploitdb_ids")


def _row_to_item(row, snippet_len=280):
    d = dict(zip(FIELDS, row))
    desc = d.pop("description", None) or ""
    d["snippet"] = (desc[:snippet_len] + "…") if len(desc) > snippet_len else desc
    d["kev"] = bool(d.get("kev"))
    return d


def _select(conn, where, params, limit):
    cols = ",".join(FIELDS)
    return conn.execute(
        f"SELECT {cols} FROM vulns WHERE {where} LIMIT ?", (*params, limit)
    ).fetchall()


def cve_lookup(conn, ids, k):
    ids = [i.upper() for i in ids]
    rows = _select(conn, f"cve_id IN ({','.join('?' for _ in ids)})", ids, max(k, len(ids)))
    # preserve query order
    order = {c: n for n, c in enumerate(ids)}
    rows.sort(key=lambda r: order.get(r[0], 999))
    return [_row_to_item(r) for r in rows]


_FTS_SAFE = re.compile(r"[^0-9a-zA-ZÀ-￿]+")


def _fts_query(q):
    # Build a safe FTS5 MATCH expression: OR the significant tokens, each as a prefix.
    toks = [t for t in _FTS_SAFE.split(q) if len(t) >= 2]
    if not toks:
        return None
    return " OR ".join(f'"{t}"*' for t in toks[:12])


def search(conn, q, k):
    match = _fts_query(q)
    if not match:
        return []
    cols = ",".join("v." + c for c in FIELDS)
    # bm25: lower is better. Boost KEV / EPSS / CVSS so exploited, likely-exploited,
    # and severe results rise. Final ORDER BY ascending on the composite score.
    sql = f"""
        SELECT {cols},
               bm25(vulns_fts) - 3.0*v.kev - 2.0*COALESCE(v.epss,0)
                                - 0.15*COALESCE(v.cvss_v3,0) AS score
        FROM vulns_fts
        JOIN vulns v ON v.cve_id = vulns_fts.cve_id
        WHERE vulns_fts MATCH ?
        ORDER BY score ASC
        LIMIT ?
    """
    try:
        rows = conn.execute(sql, (match, k)).fetchall()
    except Exception:
        # fall back to LIKE if the MATCH expression is rejected
        like = f"%{q.strip()}%"
        rows = _select(conn, "title LIKE ? OR description LIKE ?", (like, like), k)
        return [_row_to_item(r) for r in rows]
    return [_row_to_item(r[:-1]) for r in rows]


def main():
    ap = argparse.ArgumentParser(description="Query the aegis vulnerability RAG.")
    ap.add_argument("query", nargs="*")
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--db", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()
    q = " ".join(args.query).strip()

    conn = rag_db.connect(args.db)
    if args.stats:
        print(json.dumps(rag_db.stats(conn), indent=2))
        return
    if not q:
        ap.error("a query is required (or use --stats)")

    ids = list(dict.fromkeys(m.group(0) for m in CVE_RE.finditer(q)))
    if ids:
        items, mode = cve_lookup(conn, ids, args.k), "cve"
    else:
        items, mode = search(conn, q, args.k), "search"

    if args.json:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(json.dumps({"query": q, "mode": mode, "count": len(items),
                          "items": items}, ensure_ascii=False))
        return

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if not items:
        print(f"No results for: {q}")
        return
    for it in items:
        flags = []
        if it["kev"]:
            flags.append(f"KEV(due {it.get('kev_due') or '?'})")
        if it.get("epss") is not None:
            flags.append(f"EPSS {it['epss']:.3f}")
        if it.get("exploitdb_ids"):
            flags.append(f"EDB {it['exploitdb_ids']}")
        head = f"{it['cve_id']}  CVSS {it.get('cvss_v3') or '-'} {it.get('severity') or ''}"
        if flags:
            head += "  [" + " | ".join(flags) + "]"
        print(head)
        print(f"  {it.get('title') or ''}")
        if it.get("snippet"):
            print(f"  {it['snippet']}")
        print(f"  {it.get('url') or ''}   src={it.get('source')}")
        print()


if __name__ == "__main__":
    main()
