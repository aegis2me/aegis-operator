#!/usr/bin/env python3
"""
cooccurrence_from_findings.py -- self-learning association-rule miner (board consensus #1).

Companion to techniques_from_findings.py in the SAME self-improving loop. Where that turns each
verified finding into a technique entry (learned_techniques.json), THIS mines CROSS-CLASS
CO-OCCURRENCE across the hash-chained VERIFIED-findings ledger(s): when one weakness CLASS is
present on a target/run, which OTHER classes tend to be present too. Emits rules "A -> B" with
support, confidence P(B|A), and lift into learned_cooccurrence.json -- read by technique_search.py
to surface "if A verified, also test B" guidance. This extends the within-class pattern-generalizer
(sibling sweep) to CROSS-class, and POPULATES the techniques DB with co-occurrence priors.

Contained + offline: reads the owner's own local ledgers, writes a local JSON. No egress.

Usage:
    python cooccurrence_from_findings.py <findings.jsonl> [more.jsonl ...] [--min-support 0.1 --min-conf 0.5]
"""
import os, sys, json, argparse, itertools
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    from techniques_from_findings import _CLASS   # reuse the SAME claim->class mapping
except Exception:
    _CLASS = {}


def classify(claim_type: str) -> str:
    pfx = (claim_type or "unknown").split(".")[0]
    return _CLASS.get(claim_type) or _CLASS.get(pfx) or (pfx.capitalize() or "Unknown")


def contexts_from_findings(findings) -> list:
    """Group VERIFIED findings into CONTEXTS (same target_id + run_id) -> the SET of distinct
    weakness classes seen together. Co-occurrence is learned across these context sets."""
    ctx = defaultdict(set)
    for f in findings:
        if f.get("status") and f["status"] != "verified":
            continue
        key = (f.get("target_id", "?"), f.get("run_id", "?"))
        ctx[key].add(classify(f.get("claim_type")))
    return [s for s in ctx.values() if s]


def mine(contexts, min_support=0.1, min_conf=0.5) -> list:
    """Association-rule mining over the class-sets. For each ordered pair (A,B):
      support(A->B) = contexts with both / all contexts
      confidence    = P(B|A) = contexts with both / contexts with A
      lift          = confidence / P(B)   (>1 = positively associated)
    Returns rules passing the thresholds, ranked by confidence then lift then count."""
    n = len(contexts)
    if n == 0:
        return []
    single, pair = defaultdict(int), defaultdict(int)
    for cs in contexts:
        for a in cs:
            single[a] += 1
        for a, b in itertools.permutations(sorted(cs), 2):
            pair[(a, b)] += 1
    rules = []
    for (a, b), c in pair.items():
        support = c / n
        confidence = c / single[a] if single[a] else 0.0
        lift = confidence / (single[b] / n) if single[b] else 0.0
        if support >= min_support and confidence >= min_conf:
            rules.append({"antecedent": a, "consequent": b, "support": round(support, 3),
                          "confidence": round(confidence, 3), "lift": round(lift, 3),
                          "count": c, "contexts": n})
    rules.sort(key=lambda r: (r["confidence"], r["lift"], r["count"]), reverse=True)
    return rules


def _load_findings(paths) -> list:
    """Read verified findings from event-sourced stores (FindingStore) or flat jsonl, fail-soft."""
    out = []
    for p in paths:
        got = []
        try:
            from verified_findings import FindingStore   # on path via techniques_from_findings
            got = FindingStore(p).verified()
        except Exception:
            got = []
        if not got:
            try:
                for line in open(p, encoding="utf-8"):
                    line = line.strip()
                    if not line:
                        continue
                    e = json.loads(line)
                    f = e.get("finding") if e.get("type") == "record" else e
                    if f and f.get("claim_type"):
                        out.append(f)
                continue
            except Exception:
                got = []
        out += got
    return out


def main():
    ap = argparse.ArgumentParser(description="Mine cross-class co-occurrence from verified findings.")
    ap.add_argument("stores", nargs="+", help="verified-findings jsonl store(s)")
    ap.add_argument("--min-support", type=float, default=0.1)
    ap.add_argument("--min-conf", type=float, default=0.5)
    ap.add_argument("--out", default=os.path.join(HERE, "learned_cooccurrence.json"))
    a = ap.parse_args()
    findings = _load_findings(a.stores)
    ctx = contexts_from_findings(findings)
    rules = mine(ctx, a.min_support, a.min_conf)
    json.dump({"rules": rules, "contexts": len(ctx), "min_support": a.min_support,
               "min_conf": a.min_conf}, open(a.out, "w", encoding="utf-8"), indent=2)
    print(f"[cooccurrence] {len(findings)} findings -> {len(ctx)} contexts -> {len(rules)} rules -> {a.out}")
    for r in rules[:10]:
        print(f"  {r['antecedent']} -> {r['consequent']}  conf={r['confidence']} lift={r['lift']} (n={r['count']})")


if __name__ == "__main__":
    main()
