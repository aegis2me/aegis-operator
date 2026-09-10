#!/usr/bin/env python3
"""
hitrate_from_findings.py -- self-learning HIT-RATE REWEIGHTING (board consensus #2).

Third miner in the same self-improving loop as techniques_from_findings.py (findings -> techniques)
and cooccurrence_from_findings.py (findings -> "if A also test B"). This one reads the VERIFIED and
REJECTED findings in the hash-chained ledger(s) and computes, per weakness CLASS, an empirical
success rate:

    hitrate = verified / (verified + rejected)          # how often testing this class pays off
    ev      = hitrate * avg_severity_of_hits            # expected value = pay-off x how bad it is

Emits learned_hitrates.json, which technique_search.py uses to try historically-productive classes
FIRST (a boost on the ranking), so effort concentrates where it has paid off -- without starving
untried cells (a class with no attempts keeps a neutral prior). Optional time-decay (half-life in
days) so stale results don't dominate as the target evolves.

Contained + offline: reads the owner's own local ledgers, writes a local JSON. No egress.

Usage:
    python hitrate_from_findings.py <findings.jsonl> [more.jsonl ...] [--half-life 30]
"""
import os, sys, json, argparse, datetime
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    from cooccurrence_from_findings import classify          # reuse the SAME claim->class mapping
except Exception:
    def classify(claim_type):
        return (claim_type or "unknown").split(".")[0].capitalize() or "Unknown"

_SEV = {"critical": 4.0, "high": 3.0, "medium": 2.0, "med": 2.0, "low": 1.0, "unknown": 1.0, "": 1.0}


def _finding_ts(f):
    """Best-effort timestamp for a finding (first evidence ts), for optional decay."""
    for e in (f.get("evidence") or []):
        if isinstance(e, dict) and e.get("timestamp"):
            return e["timestamp"]
    return f.get("ts") or ""


def _decay_weight(ts, now, half_life_days):
    if not half_life_days or not ts:
        return 1.0
    try:
        t = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        age_days = (now - t).total_seconds() / 86400.0
        return 0.5 ** (max(age_days, 0.0) / half_life_days)
    except Exception:
        return 1.0


def compute_hitrates(findings, half_life_days=None, now=None):
    """PURE core. findings: finding-state dicts with a `status` (verified|rejected). Returns
    {class: {attempts, hits, hitrate, avg_severity, ev}} sorted by EV descending."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    agg = defaultdict(lambda: {"attempts": 0.0, "hits": 0.0, "sevsum": 0.0})
    for f in findings:
        st = f.get("status")
        if st not in ("verified", "rejected"):
            continue
        cls = classify(f.get("claim_type"))
        w = _decay_weight(_finding_ts(f), now, half_life_days)
        a = agg[cls]
        a["attempts"] += w
        if st == "verified":
            a["hits"] += w
            a["sevsum"] += w * _SEV.get((f.get("severity") or "").lower(), 1.0)
    out = {}
    for cls, a in agg.items():
        hitrate = a["hits"] / a["attempts"] if a["attempts"] else 0.0
        avg_sev = a["sevsum"] / a["hits"] if a["hits"] else 1.0
        out[cls] = {"attempts": round(a["attempts"], 2), "hits": round(a["hits"], 2),
                    "hitrate": round(hitrate, 3), "avg_severity": round(avg_sev, 2),
                    "ev": round(hitrate * avg_sev, 3)}
    return dict(sorted(out.items(), key=lambda kv: -kv[1]["ev"]))


def _load_all_findings(paths):
    """Read ALL finding STATES (verified + rejected) from event-sourced stores or flat jsonl."""
    out = []
    for p in paths:
        got = []
        try:
            from verified_findings import FindingStore   # on path via cooccurrence/techniques_from_findings
            got = list(FindingStore(p).findings().values())
        except Exception:
            got = []
        if got:
            out += got
            continue
        try:
            for line in open(p, encoding="utf-8"):
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                f = e.get("finding") if e.get("type") == "record" else e
                if f and f.get("claim_type"):
                    out.append(f)
        except Exception:
            pass
    return out


def main():
    ap = argparse.ArgumentParser(description="Compute per-class hit-rate/EV from the findings ledger.")
    ap.add_argument("stores", nargs="+")
    ap.add_argument("--half-life", type=float, default=None, help="decay half-life in days (optional)")
    ap.add_argument("--out", default=os.path.join(HERE, "learned_hitrates.json"))
    a = ap.parse_args()
    findings = _load_all_findings(a.stores)
    rates = compute_hitrates(findings, a.half_life)
    json.dump({"classes": rates, "half_life_days": a.half_life}, open(a.out, "w", encoding="utf-8"), indent=2)
    print(f"[hitrate] {len(findings)} finding-states -> {len(rates)} classes -> {a.out}")
    for cls, r in list(rates.items())[:12]:
        print(f"  {cls:16s} ev={r['ev']:<6} hitrate={r['hitrate']} (hits {r['hits']}/{r['attempts']}, sev {r['avg_severity']})")


if __name__ == "__main__":
    main()
