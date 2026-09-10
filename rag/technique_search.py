#!/usr/bin/env python3
"""
technique_search.py -- query the TECHNIQUES DATABASE (how-to-test + tool mapping), for the
operator/co-pilot (suggesting + checking) and the Kali driver stack. Complements the CVE RAG.

Reads techniques_db.json (curated) + learned_techniques.json (self-improved from verified findings,
if present) from this dir or $AEGIS_RAG (default /opt/aegis-rag). Import `search()` from the operator,
or use the CLI.

Usage:
    technique_search.py "sql injection"                 # keyword search
    technique_search.py "money bypass" --class BusinessLogic
    technique_search.py ssrf --tools                    # show tool mapping
    technique_search.py idor --json
"""
import os, sys, json, argparse, glob

HERE = os.path.dirname(os.path.abspath(__file__))
DIRS = [HERE, os.environ.get("AEGIS_RAG", "/opt/aegis-rag")]


def _load():
    techs = []
    for d in DIRS:
        for fn in ("techniques_db.json", "learned_techniques.json", "mitre_attack.json"):
            p = os.path.join(d, fn)
            if os.path.exists(p):
                try:
                    data = json.load(open(p, encoding="utf-8"))
                    for t in data.get("techniques", []):
                        t.setdefault("_source_file", fn)
                        techs.append(t)
                except Exception:
                    pass
    # de-dup by id (curated first wins unless learned is newer -- keep both notes via id suffix)
    seen = {}
    for t in techs:
        seen[t.get("id", id(t))] = t   # later (learned) overrides same id
    return list(seen.values())


def _load_cooccurrence():
    """Load the self-learned cross-class co-occurrence rules (from cooccurrence_from_findings.py)."""
    rules = []
    for d in DIRS:
        p = os.path.join(d, "learned_cooccurrence.json")
        if os.path.exists(p):
            try:
                rules += json.load(open(p, encoding="utf-8")).get("rules", [])
            except Exception:
                pass
    return rules


def _load_hitrates():
    """Load the self-learned per-class hit-rate/EV table (from hitrate_from_findings.py)."""
    for d in DIRS:
        p = os.path.join(d, "learned_hitrates.json")
        if os.path.exists(p):
            try:
                return json.load(open(p, encoding="utf-8")).get("classes", {})
            except Exception:
                pass
    return {}


def cooccurring(cls, min_conf=0.5):
    """Classes that co-occur with `cls` (as antecedent), best-confidence first -> the learned
    'if `cls` is present, also test these' guidance. Returns [{consequent,confidence,lift,...}]."""
    best = {}
    for r in _load_cooccurrence():
        if r.get("antecedent", "").lower() == (cls or "").lower() and r.get("confidence", 0) >= min_conf:
            b = r.get("consequent")
            if b and (b not in best or r["confidence"] > best[b]["confidence"]):
                best[b] = r
    return sorted(best.values(), key=lambda r: (-r["confidence"], -r.get("lift", 0)))


def related_techniques(cls, min_conf=0.5, limit=10):
    """Techniques for the classes that co-occur with `cls` -- populates 'test B next' suggestions
    from the SAME technique DB, tagged with the co-occurrence confidence that surfaced them."""
    techs = _load()
    out = []
    for r in cooccurring(cls, min_conf):
        for t in techs:
            if t.get("class", "").lower() == r["consequent"].lower():
                out.append({**t, "_cooccur_from": cls, "_confidence": r["confidence"], "_lift": r.get("lift")})
    return out[:limit]


def search(query, cls=None, limit=10):
    q = (query or "").lower().split()
    hitrates = _load_hitrates()   # learned per-class EV -> boost historically-productive classes first
    out = []
    for t in _load():
        if cls and t.get("class", "").lower() != cls.lower():
            continue
        hay = " ".join(str(t.get(k, "")) for k in
                       ("id", "class", "desc", "how_to_test", "oracle", "applies_to",
                        "kali_tools", "new_code", "real_world_basis")).lower()
        score = sum(hay.count(w) for w in q) if q else 1
        if score:
            ev = float((hitrates.get(t.get("class", ""), {}) or {}).get("ev", 0.0))
            out.append((score * (1.0 + ev), t))   # neutral (x1) when a class has no learned history
    out.sort(key=lambda x: -x[0])
    return [t for _, t in out[:limit]]


def _fmt(t, show_tools):
    lines = [f"[{t.get('class','?')}] {t.get('id','?')} — {t.get('desc','')}"]
    if show_tools:
        kt = ", ".join(t.get("kali_tools", []) or []) or "-"
        nc = ", ".join(t.get("new_code", []) or []) or "-"
        lines.append(f"    kali: {kt}")
        lines.append(f"    code: {nc}")
    lines.append(f"    test: {t.get('how_to_test','')}")
    lines.append(f"    oracle: {t.get('oracle','')}")
    if t.get("real_world_basis"):
        lines.append(f"    basis: {t['real_world_basis']}")
    if t.get("learned"):
        lines.append(f"    (LEARNED from a verified finding)")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="?", default="")
    ap.add_argument("--class", dest="cls", default=None)
    ap.add_argument("--tools", action="store_true", help="show Kali tool / code mapping")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--cooccur", metavar="CLASS", default=None,
                    help="show classes/techniques that co-occur with CLASS ('if A verified, also test B')")
    ap.add_argument("--hitrates", action="store_true",
                    help="show the learned per-class hit-rate / EV ranking (what has paid off)")
    a = ap.parse_args()
    if a.hitrates:
        hr = _load_hitrates()
        if a.json:
            print(json.dumps(hr, indent=2)); return
        if not hr:
            print("no learned hit-rates yet (run rag/hitrate_from_findings.py over the findings ledger)"); return
        print("learned per-class hit-rate (test highest-EV first):")
        for cls, r in hr.items():
            print(f"  {cls:16s} ev={r['ev']:<6} hitrate={r['hitrate']} "
                  f"(hits {r['hits']}/{r['attempts']}, sev {r['avg_severity']})")
        return
    if a.cooccur:
        co = cooccurring(a.cooccur)
        rel = related_techniques(a.cooccur, limit=a.limit)
        if a.json:
            print(json.dumps({"cooccurring": co, "related_techniques": rel}, indent=2)); return
        if not co:
            print(f"no learned co-occurrence for class {a.cooccur!r} "
                  f"(run rag/cooccurrence_from_findings.py over the findings ledger first)"); return
        print(f"if {a.cooccur} is present, also test (learned):")
        for r in co:
            print(f"  -> {r['consequent']}  (confidence {r['confidence']}, lift {r.get('lift')})")
        print()
        for t in rel:
            print(_fmt(t, a.tools)); print()
        return
    res = search(a.query, a.cls, a.limit)
    if a.json:
        print(json.dumps(res, indent=2)); return
    if not res:
        print("no matching techniques"); return
    print(f"{len(res)} technique(s):\n")
    for t in res:
        print(_fmt(t, a.tools)); print()


if __name__ == "__main__":
    main()
