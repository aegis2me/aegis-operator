#!/usr/bin/env python3
"""
ingest_mitre.py -- populate the techniques DB from the MITRE ATT&CK framework (Enterprise), and keep it
LIVE-updated the same way the CVE feeds are (offline+online, staleness-gated, backup/rollback,
VPN-gated egress via HTTP(S)_PROXY). This is the Planner's ATT&CK knowledge source (see docs/PLANNER.md).

It fetches the ATT&CK Enterprise STIX bundle, maps each technique (attack-pattern) into the SAME schema
`technique_search.py` already reads -- {id, class, desc, applies_to, kali_tools, real_world_basis, ...}
plus ATT&CK fields (mitre_id, mitre_tactics, mitre_subtechnique, data_sources, url) -- and writes
`mitre_attack.json` ({"techniques":[...]}) next to techniques_db.json. ATT&CK software that "uses" a
technique is attached as a `kali_tools` hint. Deprecated/revoked techniques are skipped.

OFFLINE-SAFE + STALENESS-GATED: skips the network if the local file is newer than --max-age-days
(default 30; ATT&CK ships ~quarterly). On any fetch/parse error the existing file is left intact
(atomic write via a temp + os.replace, with a .bak backup). Reference data only -- never authorization
to touch anything off-scope.

Usage:
    python ingest_mitre.py                 # refresh if stale (>30d), else no-op
    python ingest_mitre.py --force         # always fetch
    python ingest_mitre.py --out /opt/aegis-rag/mitre_attack.json
"""
import argparse
import datetime
import json
import os
import shutil
import sys
import time

from http_util import make_session, get

# Maintained ATT&CK STIX 2.1 (Enterprise). Fallback to the legacy mirror if the first is unreachable.
SOURCES = [
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
]
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(os.environ.get("AEGIS_RAG_HOME", "/opt/aegis-rag"), "mitre_attack.json")


def _mitre_id(obj):
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"], ref.get("url", "")
    return None, ""


def _tactics(obj):
    return [p.get("phase_name") for p in (obj.get("kill_chain_phases") or [])
            if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")]


def parse_stix(bundle: dict) -> list:
    """STIX bundle -> list of technique entries in technique_search's schema."""
    objs = bundle.get("objects", []) or []
    # map ATT&CK 'tool' software (NOT 'malware') stix-id -> name; only actual tools are useful as a
    # tool-hint for the Planner (malware family names like QakBot aren't runnable tools).
    sw_name = {o["id"]: o.get("name") for o in objs if o.get("type") == "tool" and o.get("id")}
    uses = {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "uses":
            src, tgt = o.get("source_ref", ""), o.get("target_ref", "")
            if src in sw_name and tgt.startswith("attack-pattern--"):
                uses.setdefault(tgt, []).append(sw_name[src])

    techniques = []
    for o in objs:
        if o.get("type") != "attack-pattern":
            continue
        if o.get("x_mitre_deprecated") or o.get("revoked"):
            continue
        mid, url = _mitre_id(o)
        if not mid:
            continue
        tactics = _tactics(o)
        name = o.get("name", "")
        desc = (o.get("description", "") or "").replace("\n", " ").strip()
        tools = sorted(set(uses.get(o["id"], [])))[:12]
        techniques.append({
            "id": mid,                                          # e.g. T1059.001
            "class": (tactics[0].replace("-", "_") if tactics else "mitre"),  # primary tactic as class
            "desc": f"{name} — {desc[:300]}".strip(" —"),
            "applies_to": o.get("x_mitre_platforms", []) or [],
            "kali_tools": tools,                                # ATT&CK software hints (may need mapping)
            "new_code": [],
            "how_to_test": f"ATT&CK {mid} ({', '.join(tactics) or 'n/a'}) -- {name}",
            "oracle": "confirm the technique's observable (data source) fired; oracle per sub-task",
            "real_world_basis": f"MITRE ATT&CK {mid}" + (f" [{', '.join(tactics)}]" if tactics else ""),
            "mitre_id": mid,
            "mitre_tactics": tactics,
            "mitre_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
            "data_sources": o.get("x_mitre_data_sources", []) or [],
            "url": url,
            "source": "mitre",
        })
    return techniques


def _age_days(path):
    if not os.path.exists(path):
        return None
    return (time.time() - os.path.getmtime(path)) / 86400.0


def run(out_path=None, max_age_days=30.0, force=False, timeout=180) -> dict:
    out = out_path or DEFAULT_OUT
    age = _age_days(out)
    if not force and age is not None and age < max_age_days:
        return {"skipped": f"fresh ({age:.1f}d < {max_age_days}d)", "path": out}
    sess = make_session()
    bundle, src_used, err = None, None, None
    for url in SOURCES:
        try:
            print(f"[mitre] fetching {url}")
            bundle = get(sess, url, timeout=timeout).json()
            src_used = url
            break
        except Exception as e:
            err = str(e)[:160]
            print(f"[mitre] source failed: {err}", file=sys.stderr)
    if bundle is None:
        # OFFLINE-SAFE: leave the existing file untouched
        return {"error": f"all ATT&CK sources unreachable: {err}", "offline_fallback": True, "path": out}
    try:
        techs = parse_stix(bundle)
    except Exception as e:
        return {"error": f"parse failed (existing file kept): {e}", "path": out}
    if not techs:
        return {"error": "no techniques parsed (existing file kept)", "path": out}

    ver = ""
    for o in bundle.get("objects", []):
        if o.get("type") == "x-mitre-collection":
            ver = (o.get("x_mitre_version") or "")
            break
    doc = {"_note": "MITRE ATT&CK Enterprise techniques mapped into the aegis techniques DB "
                    "(populated + live-updated by ingest_mitre.py). Reference only; authorized/contained use.",
           "generated": datetime.datetime.now().isoformat(timespec="seconds"),
           "source": src_used, "attack_version": ver, "count": len(techs), "techniques": techs}

    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    if os.path.exists(out):
        try:
            shutil.copy(out, out + ".bak")
        except Exception:
            pass
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False)
    os.replace(tmp, out)                                        # atomic swap
    print(f"[mitre] wrote {len(techs)} techniques (ATT&CK v{ver or '?'}) -> {out}")
    return {"updated": True, "count": len(techs), "attack_version": ver, "path": out, "source": src_used}


def main():
    ap = argparse.ArgumentParser(description="Populate/refresh the techniques DB from MITRE ATT&CK.")
    ap.add_argument("--out", default=None)
    ap.add_argument("--max-age-days", type=float,
                    default=float(os.environ.get("AEGIS_MITRE_MAX_AGE_DAYS", "30")))
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--timeout", type=int, default=180)
    a = ap.parse_args()
    r = run(a.out, a.max_age_days, a.force, a.timeout)
    print(json.dumps(r, indent=2))
    # non-zero only on a hard error (so rag_update marks it failed but keeps the offline store)
    sys.exit(1 if r.get("error") else 0)


if __name__ == "__main__":
    main()
