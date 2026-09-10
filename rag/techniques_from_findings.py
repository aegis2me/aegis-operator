#!/usr/bin/env python3
"""
techniques_from_findings.py -- the self-improving loop: turn VERIFIED findings into technique-DB
entries so the database grows from what actually worked on our own stack (highest-signal source).

Run it after a verify round / as the pipeline's loop step (decoupled from the shared verified_findings
layer on purpose, to avoid drift across its vendored copies). Upserts into learned_techniques.json,
which technique_search.py reads alongside the curated techniques_db.json.

Usage:
    python techniques_from_findings.py <findings.jsonl> [--out learned_techniques.json]
    # or scan several stores:
    python techniques_from_findings.py store1.jsonl store2.jsonl
"""
import os, sys, json, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
# find a verified_findings module (operator vendored copy or shared/)
for cand in (os.path.join(os.path.dirname(HERE), "operator"),
             os.path.join(os.path.dirname(HERE), "shared"),
             os.path.join(os.path.dirname(HERE), "exploitgym", "exploitgym")):
    if os.path.exists(os.path.join(cand, "verified_findings.py")):
        sys.path.insert(0, cand); break
try:
    from verified_findings import FindingStore
except Exception:
    FindingStore = None

_CLASS = {"money": "BusinessLogic", "logic": "BusinessLogic", "access": "AccessControl",
          "authz": "AccessControl", "authn": "Authn", "idor": "AccessControl", "traversal": "FileAccess",
          "file": "FileAccess", "ssrf": "SSRF", "ssti": "Injection", "inj": "Injection",
          "xss": "XSS", "deser": "Deserialization", "secrets": "Secrets", "exposure": "Secrets",
          "cred": "Secrets", "availability": "Availability", "audit": "Audit",
          "defense_in_depth": "Hardening", "privesc": "PrivEsc", "traversal.file_disclosure": "FileAccess"}


def learn_from_finding(f: dict) -> dict:
    """Map one VERIFIED finding-state dict to a technique-DB entry. Captures the REACH dimensions
    (layer/novelty/origin/intent/sub-surface/bridge) and, for a proven novel-code probe, the CODE that
    worked -- so a verified scaffold/code bridge or foothold becomes a REUSABLE learned technique the
    Planner can rank next time (the closed loop the owner asked for)."""
    claim = f.get("claim_type", "unknown")
    prefix = claim.split(".")[0]
    ev = f.get("evidence") or []
    how = "; ".join(e.get("detail", "") for e in ev if isinstance(e, dict))[:300] or \
          "; ".join(t for t in f.get("coverage_tags", []))
    prov = f.get("provenance") or {}
    tags = [t for t in (f.get("coverage_tags") or []) if isinstance(t, str)]

    def _tagval(pfx):
        for t in tags:
            if t.startswith(pfx + ":"):
                return t.split(":", 1)[1]
        return ""

    layer = prov.get("layer") or _tagval("layer")
    novelty = prov.get("novelty") or _tagval("novelty")
    origin = prov.get("origin") or _tagval("origin")
    intent = prov.get("reach_intent") or _tagval("reach-intent")
    sub = _tagval("scaffold-sub")
    bridge_to = prov.get("bridge_to") or _tagval("bridge-to")
    novel_code = prov.get("new_code") or ""
    entry = {
        "id": "learned." + claim,
        "class": _CLASS.get(prefix, prefix.capitalize() or "Learned"),
        "desc": (f.get("summary", "")[:220]),
        "kali_tools": [],
        "new_code": [prov.get("code_by") or prov.get("via") or prov.get("provider") or "operator"],
        "how_to_test": how,
        "oracle": f.get("oracle_id") or "verified against DB/HTTP ground truth",
        "applies_to": [t.split(":", 1)[1] for t in tags if t.startswith("surface:")] or ["this stack"],
        "severity_hint": f.get("severity", "unknown"),
        "learned": True,
        "source_run": f.get("run_id", ""),
        # --- REACH dimensions (how far / which direction) ---
        "reach": {"layer": layer, "novelty": novelty, "origin": origin, "intent": intent,
                  "sub_surface": sub, "bridge_to": bridge_to},
        "tags": [t for t in ("learned", novelty, origin, layer, ("bridge" if bridge_to else "")) if t],
    }
    if novel_code:                                   # the actual proven probe -> replayable technique
        entry["novel_code"] = novel_code
    return entry


def upsert(entries, out_path):
    existing = {}
    if os.path.exists(out_path):
        try:
            for t in json.load(open(out_path, encoding="utf-8")).get("techniques", []):
                existing[t["id"]] = t
        except Exception:
            pass
    added = 0
    for e in entries:
        if e["id"] not in existing:
            added += 1
        existing[e["id"]] = e  # newest wins
    json.dump({"_note": "LEARNED techniques auto-derived from VERIFIED findings (self-improving loop). "
               "Read by technique_search.py alongside techniques_db.json.",
               "techniques": list(existing.values())},
              open(out_path, "w", encoding="utf-8"), indent=2)
    return added, len(existing)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stores", nargs="+", help="verified_findings JSONL store(s)")
    ap.add_argument("--out", default=os.path.join(HERE, "learned_techniques.json"))
    a = ap.parse_args()
    if not FindingStore:
        sys.exit("verified_findings not importable")
    entries = []
    for sp in a.stores:
        if not os.path.exists(sp):
            print(f"  (skip missing {sp})"); continue
        fs = FindingStore(sp).findings()
        v = [f for f in fs.values() if f.get("status") == "verified"]
        print(f"  {sp}: {len(v)} verified / {len(fs)} findings")
        entries += [learn_from_finding(f) for f in v]
    added, total = upsert(entries, a.out)
    print(f"learned techniques: +{added} new, {total} total -> {a.out}")


if __name__ == "__main__":
    main()
