#!/usr/bin/env python3
"""
attack_coverage.py -- MITRE ATT&CK coverage reporting (the Caldera/Navigator-heatmap parity gap).

Two things:
  1. `capabilities()` -- the ATT&CK technique IDs Aegis's DISCOVERY vectors can exercise (parsed from the
     techniques DB `how_to_test` text + the discovery legs), i.e. the coverage we CLAIM.
  2. `navigator_layer(stores)` -- reads oracle-VERIFIED findings and emits a MITRE ATT&CK Navigator layer
     JSON: capability techniques scored 1 (available) and CONFIRMED techniques scored 2 (verified this run),
     so coverage + gaps render as a heatmap you can open at mitre-attack.github.io/attack-navigator.

Offline-safe; no network. Verified findings never self-report -- only what the oracle confirmed scores 2.

    python operator/attack_coverage.py hunt_findings.jsonl --out attack_layer.json
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
_TID = re.compile(r"T\d{4}(?:\.\d{3})?")


def _techniques_db():
    for p in (os.path.join(os.environ.get("AEGIS_RAG_HOME", "/opt/aegis-rag"), "techniques_db.json"),
              os.path.join(ROOT, "rag", "techniques_db.json")):
        try:
            return json.load(open(p, encoding="utf-8")).get("techniques", [])
        except Exception:
            continue
    return []


def capabilities() -> dict:
    """{technique_id: [source technique-db ids]} that Aegis discovery can exercise (claimed coverage)."""
    out: dict = {}
    for t in _techniques_db():
        blob = " ".join(str(t.get(k, "")) for k in ("how_to_test", "desc", "oracle"))
        for tid in _TID.findall(blob):
            out.setdefault(tid, []).append(t.get("id", "?"))
    return out


def _verified_ids(stores):
    """ATT&CK IDs that appear on oracle-VERIFIED findings (from coverage_tags / technique / receipt)."""
    ids = set()
    try:
        sys.path.insert(0, os.path.join(ROOT, "shared")); sys.path.insert(0, HERE)
        from verified_findings import FindingStore
    except Exception:
        FindingStore = None
    for sp in stores:
        if not os.path.exists(sp):
            continue
        if FindingStore:
            for f in FindingStore(sp).findings().values():
                if f.get("status") != "verified":
                    continue
                blob = json.dumps(f)
                ids.update(_TID.findall(blob))
        else:
            for line in open(sp, encoding="utf-8"):
                if '"verified"' in line:
                    ids.update(_TID.findall(line))
    return ids


def navigator_layer(stores, name="Aegis Discovery Coverage") -> dict:
    caps = capabilities()
    confirmed = _verified_ids(stores)
    techs = []
    for tid in sorted(set(caps) | confirmed):
        verified = tid in confirmed
        techs.append({"techniqueID": tid, "score": 2 if verified else 1,
                      "color": "#c62828" if verified else "#90caf9",
                      "comment": ("VERIFIED this run" if verified else "available")
                                 + ((" via " + ",".join(caps.get(tid, []))) if caps.get(tid) else ""),
                      "enabled": True})
    return {
        "name": name, "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack", "description": "Aegis discovery-vector ATT&CK coverage; "
        "score 1 = capability available, score 2 = oracle-verified this run.",
        "gradient": {"colors": ["#90caf9", "#c62828"], "minValue": 1, "maxValue": 2},
        "techniques": techs,
    }


def main():
    ap = argparse.ArgumentParser(description="ATT&CK Navigator coverage layer for Aegis discovery.")
    ap.add_argument("stores", nargs="*", help="verified_findings JSONL store(s); default: operator/hunt_findings.jsonl")
    ap.add_argument("--out", default=os.path.join(HERE, "attack_layer.json"))
    ap.add_argument("--name", default="Aegis Discovery Coverage")
    a = ap.parse_args()
    stores = a.stores or glob.glob(os.path.join(HERE, "hunt_findings.jsonl"))
    layer = navigator_layer(stores, a.name)
    json.dump(layer, open(a.out, "w", encoding="utf-8"), indent=2)
    verified = sum(1 for t in layer["techniques"] if t["score"] == 2)
    print(f"ATT&CK layer -> {a.out}: {len(layer['techniques'])} technique(s), {verified} verified this run")


if __name__ == "__main__":
    main()
