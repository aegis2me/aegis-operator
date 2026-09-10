"""tier_report.py -- the 3-TIER (neutral) hunt report: fold one or more findings ledgers and group the
oracle-VERIFIED findings by TRUST TIER (who can reach them: anon < user < admin), so the human sees the
anon-vs-logged-user gap difference the doctrine requires ('crawl with all creds; verdict with none').

Reuses run_monitor._fold_ledger (record+transition folding + trust-tag extraction) so this never drifts
from the live view. Every finding carries reachable/intended/verdict + severity; the report separates:
  - by REACHABLE TIER: anon-reachable (no creds) vs user-reachable (creds needed) vs admin-only.
  - EXPLOITABLE (a tier below intended reaches it, or a confirmed non-authz gap) vs INTENDED (admin-doing-admin).
The anon block is exactly the attack surface of an UNAUTHENTICATED attacker; the delta to the user block is
the 'logged-in gains' surface. Advisory only -- reads ledgers, writes markdown, changes nothing.
"""
from __future__ import annotations
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from run_monitor import _fold_ledger

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_TIER_ORDER = {"anon": 0, "user": 1, "admin": 2, "": 3}


def _verified(findings):
    return [f for f in findings if f.get("status") == "verified"]


def _sev_tally(findings):
    t = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "medium")
        t[s if s in t else "medium"] += 1
    return t


# when the SAME finding appears in more than one pass, its trust verdict should be the STRONGEST/most-correct
# label seen -- a stale 'intended' from an earlier (pre-trust-fix) run must not shadow a later 'confirmed'/
# 'exploitable' for the identical gap. Lower rank = stronger/more-actionable.
_VERDICT_RANK = {"exploitable": 0, "confirmed": 1, "": 2, "unreachable": 3, "intended": 4}


def _dedup(findings):
    """Fold identical findings across passes by (surface, claim_type, severity, source) -- a scaffold CVE
    seen in both pass A and pass B is one gap, not two. Keep the earliest-created instance, note passes, and
    let the STRONGEST trust verdict win (so a stale 'intended' from a pre-fix run can't shadow 'confirmed')."""
    by = {}
    for f in findings:
        k = (f.get("surface", ""), f.get("claim_type", ""), f.get("severity", ""), f.get("source", ""),
             (f.get("summary", "") or "")[:60])
        if k not in by:
            by[k] = dict(f); by[k]["_passes"] = set()
        else:
            # keep the stronger verdict for the merged row
            cur = _VERDICT_RANK.get(by[k].get("trust_verdict", ""), 2)
            new = _VERDICT_RANK.get(f.get("trust_verdict", ""), 2)
            if new < cur:
                passes = by[k]["_passes"]; by[k] = dict(f); by[k]["_passes"] = passes
        # reachable tier of a merged finding = the LOWEST tier that confirmed it (the least-privileged
        # attacker who can reach it -- if both anon and user found it, it's anon-reachable = more severe).
        cur_t = _TIER_ORDER.get(by[k].get("reachable", "") or "", 3)
        new_t = _TIER_ORDER.get(f.get("reachable", "") or "", 3)
        if new_t < cur_t:
            by[k]["reachable"] = f.get("reachable", "")
        by[k]["_passes"].add(f.get("_pass", "?"))
    return list(by.values())


def _sev_line(t):
    return (f"critical {t['critical']} · high {t['high']} · medium {t['medium']} · "
            f"low {t['low']} · info {t['info']}")


def _row(f):
    sev = f.get("severity", "medium").upper()
    v = f.get("trust_verdict", "") or "-"
    ex = "EXPLOITABLE" if v == "exploitable" else ("confirmed" if v == "confirmed" else ("intended" if v == "intended" else v))
    passes = "+".join(sorted(p for p in f.get("_passes", []) if p != "?")) or "?"
    summ = (f.get("summary") or f.get("claim_type") or "").replace("\n", " ")[:90]
    surf = f.get("surface", "") or "-"
    src = f.get("source", "?")
    return f"| {sev} | {ex} | `{surf}` | {summ} | {src} | {passes} |"


def build(ledgers: dict, out_path: str, target="FixFlow mirror", notes=None) -> str:
    """ledgers = {pass_label: ledger_path}. Fold each, tag with its pass, group verified by reachable tier."""
    all_v = []
    per_pass = {}
    for label, path in ledgers.items():
        folded = _fold_ledger(path)
        ver = _verified(folded)
        for f in ver:
            f["_pass"] = label
        per_pass[label] = ver
        all_v.extend(ver)
    merged = _dedup(all_v)

    # bucket by reachable tier
    buckets = {"anon": [], "user": [], "admin": [], "": []}
    for f in merged:
        buckets.setdefault(f.get("reachable", "") or "", []).append(f)

    lines = []
    lines.append(f"# 3-Tier Neutral Hunt Report — {target}")
    lines.append("")
    lines.append("_Neutral run: the crawler mapped surface with all creds, but every verdict is rendered "
                 "at the LOWEST tier that reaches the finding. Owner/admin access was never used as a "
                 "testing path. Tiers: **anon** (no creds) < **user** (any logged-in role) < **admin**._")
    lines.append("")

    # headline severity by pass
    lines.append("## Severity summary (oracle-verified, deduplicated)")
    lines.append("")
    lines.append(f"- **All passes (merged):** {_sev_line(_sev_tally(merged))}  — {len(merged)} distinct findings")
    for label in ledgers:
        lines.append(f"- **Pass {label}:** {_sev_line(_sev_tally(per_pass.get(label, [])))}  "
                     f"— {len(per_pass.get(label, []))} findings")
    lines.append("")

    # the anon-vs-user delta (the doctrine point)
    anon_n = len(buckets["anon"]); user_n = len(buckets["user"]); admin_n = len(buckets["admin"])
    lines.append("## Trust-tier delta (anon vs logged-in vs admin)")
    lines.append("")
    lines.append(f"- **anon-reachable** (unauthenticated attacker surface): **{anon_n}**")
    lines.append(f"- **user-reachable** (any authenticated role — the 'logged-in gains'): **{user_n}**")
    lines.append(f"- **admin-only** (reachable only at admin tier): **{admin_n}**")
    if buckets[""]:
        lines.append(f"- _tier-untagged (legacy/older-format finding): {len(buckets[''])}_")
    lines.append("")
    lines.append("> The anon block is what an attacker with **no account** can reach; the step up to the "
                 "user block is the extra surface a login grants. These are genuinely different attack "
                 "surfaces — a gap present at anon tier is strictly more severe than the same gap gated behind a login.")
    lines.append("")

    hdr = "| Severity | Verdict | Surface | Finding | Oracle/Source | Pass |"
    sep = "|---|---|---|---|---|---|"
    for tier in ("anon", "user", "admin", ""):
        b = buckets[tier]
        if not b:
            continue
        title = {"anon": "Anon tier — reachable WITHOUT credentials",
                 "user": "User tier — reachable by any logged-in role",
                 "admin": "Admin tier — reachable only at admin",
                 "": "Tier-untagged (legacy findings)"}[tier]
        lines.append(f"## {title}  ({len(b)})")
        lines.append("")
        lines.append(hdr); lines.append(sep)
        for f in sorted(b, key=lambda x: (_SEV_ORDER.get(x.get("severity", "medium"), 2),
                                          x.get("surface", ""))):
            lines.append(_row(f))
        lines.append("")

    if notes:
        lines.append("## Run context & variance")
        lines.append("")
        for n in notes:
            lines.append(f"- {n}")
        lines.append("")

    lines.append("---")
    lines.append("_Only oracle-verified findings are listed. `EXPLOITABLE` = a tier below the intended one "
                 "reaches an access-control gap; `confirmed` = a verified non-authz gap (dep-CVE / rate / "
                 "secret / injection) exploitable at whatever tier can trigger it; `intended` = "
                 "admin-doing-admin, listed for completeness, not a finding._")
    md = "\n".join(lines) + "\n"
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(md)
    return md


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", action="append", default=[], metavar="LABEL=PATH",
                    help="pass label = ledger path (repeatable, e.g. A-technician=operator/ledger_archive/x.jsonl)")
    ap.add_argument("--out", default=os.path.join(HERE, "tier_report.md"))
    ap.add_argument("--target", default="FixFlow mirror")
    ap.add_argument("--note", action="append", default=[], help="run-context bullet (repeatable)")
    a = ap.parse_args()
    ledgers = {}
    for spec in a.ledger:
        if "=" in spec:
            lbl, p = spec.split("=", 1); ledgers[lbl] = p
    if not ledgers:
        ledgers = {"current": os.path.join(HERE, "hunt_findings.jsonl")}
    md = build(ledgers, a.out, target=a.target, notes=a.note)
    print(md)
    print(f"\n[written] {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
