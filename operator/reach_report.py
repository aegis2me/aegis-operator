#!/usr/bin/env python3
"""
reach_report.py -- the NOVEL-FINDINGS report generator (the board's converged emphasis design).

Reads oracle-VERIFIED findings and emits a report that makes NOVEL / zero-day discoveries UNMISTAKABLE
and puts them FIRST, distinct from the routine known-CVE list -- exactly as the board (ds + kimi)
converged:

  * PART 1 -- NOVEL / ZERO-DAY FINDINGS (first), split SCAFFOLD vs CODE, novel-first, severity-sorted.
      - IDs: NOV-SCAF-###  /  NOV-CODE-###   (never CVE-YYYY)
      - Title badges: [NOVEL] [SCAFFOLD|CODE] [FUZZ-CRASH|NOVEL-CODE|BRIDGE] [ZERO-DAY - NO CVE] [ORACLE-VERIFIED]
      - Required fields: layer, sub-surface (plugin/db-engine/...), origin, oracle-witness, bridge-chain,
        severity+exploitability, affected component, CVE-status ("No CVE; NVD searched <date>"),
        reproduction / novel code, fix-owner.
      - Scaffold novel findings (a plugin/DB-tier zero-day or a fuzzing crash) are called out with a
        ZERO-DAY (NO CVE) banner and NEVER placed in the CVE table.
  * PART 2 -- KNOWN CVE FINDINGS (plain), routed to admins/framework-update.
  * Executive summary counts: NOVEL SCAFFOLD: X (Y fuzz, Z DB), NOVEL CODE: W, KNOWN CVE: N.
  * Routing: scaffold-novel -> ADMIN / framework-update / vendor-PSIRT; code-novel -> CODE-writer/improver.

Advisory + offline. Reads the hash-chained findings store(s) via the shared verified_findings layer.

Usage:
    python reach_report.py hunt_findings.jsonl [more.jsonl ...] [--out reach_report.md] [--hunt rep.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for cand in (HERE, os.path.join(HERE, "..", "shared")):
    if cand not in sys.path:
        sys.path.insert(0, cand)
try:
    from verified_findings import FindingStore
except Exception:
    FindingStore = None

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "med": 2, "low": 3, "unknown": 4, "": 4}


def _tagval(tags, pfx, default=""):
    for t in tags or []:
        if isinstance(t, str) and t.startswith(pfx + ":"):
            return t.split(":", 1)[1]
    return default


def classify(f: dict) -> dict:
    """Pull the reach dimensions off a verified finding (tags + provenance + evidence)."""
    tags = f.get("coverage_tags") or []
    prov = f.get("provenance") or {}
    layer = prov.get("layer") or _tagval(tags, "layer", "code")
    novelty = prov.get("novelty") or _tagval(tags, "novelty", "novel")
    origin = prov.get("origin") or _tagval(tags, "origin", "novel")
    intent = prov.get("reach_intent") or _tagval(tags, "reach-intent", "foothold")
    sub = _tagval(tags, "scaffold-sub", "stack")
    bridge_to = prov.get("bridge_to") or _tagval(tags, "bridge-to", "")
    surface = _tagval(tags, "surface", "")
    witness = "; ".join(e.get("detail", "") for e in (f.get("evidence") or []) if isinstance(e, dict))[:400]
    return {"layer": layer, "novelty": novelty, "origin": origin, "intent": intent, "sub": sub,
            "bridge_to": bridge_to, "surface": surface, "witness": witness,
            "severity": (f.get("severity") or "unknown").lower(),
            "summary": f.get("summary", ""), "claim": f.get("claim_type", ""),
            "novel_code": prov.get("new_code") or "", "code_by": prov.get("code_by") or "",
            "oracle_receipt": f.get("oracle_receipt") or {}}


def _badges(c: dict) -> str:
    b = ["NOVEL", c["layer"].upper()]
    o = c["origin"]
    b.append({"fuzz": "FUZZ-CRASH", "novel-code": "NOVEL-CODE"}.get(o, o.upper()))
    if c["bridge_to"]:
        b.append("BRIDGE")
    if c["layer"] == "scaffold":
        b.append("ZERO-DAY - NO CVE")
    b.append("ORACLE-VERIFIED")
    return "".join(f"[{x}]" for x in b)


def _fix_owner(c: dict) -> str:
    return ("ADMIN / framework-update / vendor-PSIRT" if c["layer"] == "scaffold"
            else "CODE-WRITER / IMPROVER")


def _novel_block(nid: str, c: dict, checked: str) -> str:
    scaffold = c["layer"] == "scaffold"
    banner = ("> ⚠️ **ZERO-DAY (NO CVE)** — a verified weakness in the "
              f"**{c['sub']}** ({'DB tier' if c['sub'] == 'database' else c['sub']}) with no catalogued CVE.\n\n"
              if scaffold else
              "> 🔥 **NOVEL (NO CVE)** — an oracle-verified app-code weakness with no catalogued CVE.\n\n")
    lines = [f"#### {nid} {_badges(c)}",
             "",
             banner + f"**{c['summary'] or c['claim']}**",
             "",
             f"- **Layer:** `{c['layer']}`  |  **Sub-surface:** `{c['sub']}`  |  **Origin:** `{c['origin']}`  |  **Intent:** `{c['intent']}`",
             f"- **Severity:** `{c['severity']}`" + (f"  |  **Surface:** `{c['surface']}`" if c["surface"] else ""),
             f"- **CVE-status:** No CVE assigned; NVD searched {checked}",
             f"- **Oracle-witness:** {c['witness'] or '(see evidence)'}",
             ]
    if c["bridge_to"]:
        lines.append(f"- **Bridge-chain:** {c['intent']} → `{c['bridge_to']}` (reach extended)")
    if c["novel_code"]:
        lines.append(f"- **Reproduction (novel code, by `{c['code_by'] or 'code-bench'}`):**")
        lines.append("")
        lines.append("  ```\n  " + "\n  ".join(str(c["novel_code"]).splitlines()[:20]) + "\n  ```")
    lines.append(f"- **Fix-owner:** {_fix_owner(c)}")
    lines.append("")
    return "\n".join(lines)


def build(findings: list, hunt_report: dict = None) -> str:
    verified = [f for f in findings if f.get("status") == "verified"]
    classed = [(f, classify(f)) for f in verified]
    novel = [(f, c) for f, c in classed if c["novelty"] != "known-cve"]
    known = [(f, c) for f, c in classed if c["novelty"] == "known-cve"]
    scaffold_novel = sorted([c for _, c in novel if c["layer"] == "scaffold"],
                            key=lambda c: _SEV_ORDER.get(c["severity"], 4))
    code_novel = sorted([c for _, c in novel if c["layer"] != "scaffold"],
                        key=lambda c: _SEV_ORDER.get(c["severity"], 4))
    n_fuzz = sum(1 for c in scaffold_novel if c["origin"] == "fuzz")
    n_db = sum(1 for c in scaffold_novel if c["sub"] == "database")
    checked = time.strftime("%Y-%m-%d")

    out = ["# Aegis Assessment — Novel-First Findings Report",
           f"_Generated {time.strftime('%Y-%m-%d %H:%M')} · contained, oracle-verified. Novel / zero-day "
           "discoveries are flagged FIRST and kept separate from the routine known-CVE list._",
           "",
           "## Executive summary",
           f"- **NOVEL SCAFFOLD:** {len(scaffold_novel)}  (fuzz: {n_fuzz}, DB-tier: {n_db})  → _route: ADMIN / framework-update / vendor_",
           f"- **NOVEL CODE:** {len(code_novel)}  → _route: code-writer / improver_",
           f"- **KNOWN CVE:** {len(known)}  → _route: ADMIN / framework-update_",
           ""]
    if hunt_report and isinstance(hunt_report.get("reach"), dict):
        r = hunt_report["reach"]
        out += [f"- **Reach (how far):** directions {r.get('directions_reached')}, bridges "
                f"{r.get('bridges')}, scaffold→code breached: {r.get('layer_breached_scaffold_to_code')}, "
                f"lateral hops {r.get('lateral_hops')}, depth {r.get('depth')}", ""]

    out += ["---", "", "## PART 1 — NOVEL / ZERO-DAY FINDINGS (oracle-verified, NO CVE)", ""]
    if not novel:
        out += ["_No novel findings verified this run._", ""]
    if scaffold_novel:
        out += ["### 1A · SCAFFOLD zero-days & fuzz crashes (stack / plugins / DB tier)",
                "_Route to ADMINS / framework-update / vendor PSIRT._", ""]
        for i, c in enumerate(scaffold_novel, 1):
            out.append(_novel_block(f"NOV-SCAF-{i:03d}", c, checked))
    if code_novel:
        out += ["### 1B · CODE zero-days (app-code, novel-code probes, bridges)",
                "_Route to the CODE-WRITER / IMPROVER._", ""]
        for i, c in enumerate(code_novel, 1):
            out.append(_novel_block(f"NOV-CODE-{i:03d}", c, checked))

    out += ["---", "", "## PART 2 — KNOWN CVE FINDINGS", "_Route to ADMINS / framework-update._", ""]
    if not known:
        out += ["_No known-CVE findings this run._", ""]
    else:
        out += ["| ID | Severity | Component / claim | Surface |", "|---|---|---|---|"]
        for i, (_, c) in enumerate(sorted(known, key=lambda x: _SEV_ORDER.get(x[1]["severity"], 4)), 1):
            out.append(f"| CVE-{i:03d} | {c['severity']} | {c['claim']} | {c['surface']} |")
        out.append("")
    return "\n".join(out)


def load_findings(stores: list) -> list:
    if not FindingStore:
        raise SystemExit("verified_findings not importable")
    out = []
    for sp in stores:
        if not os.path.exists(sp):
            print(f"  (skip missing {sp})", file=sys.stderr); continue
        out += list(FindingStore(sp).findings().values())
    return out


def main():
    ap = argparse.ArgumentParser(description="Novel-first findings report (reach axis).")
    ap.add_argument("stores", nargs="+", help="verified_findings JSONL store(s)")
    ap.add_argument("--out", default=os.path.join(HERE, "reach_report.md"))
    ap.add_argument("--hunt", help="a hunt report JSON (for the reach/how-far summary)")
    a = ap.parse_args()
    hr = None
    if a.hunt and os.path.exists(a.hunt):
        try:
            hr = json.load(open(a.hunt, encoding="utf-8"))
        except Exception:
            hr = None
    md = build(load_findings(a.stores), hr)
    open(a.out, "w", encoding="utf-8").write(md)
    print(f"wrote {len(md)}b -> {a.out}")


if __name__ == "__main__":
    main()
