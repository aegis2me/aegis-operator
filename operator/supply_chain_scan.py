"""
Supply-chain auto-run leg (contained, read-only).

Ties the pieces together: generate an SBOM of the twin (syft, via kali_driver's `security_scan`
kind="sbom"), then DIFF every component against the offline vuln RAG (OSV/NVD/KEV/EPSS on the Kali
box) and emit a ranked report of vulnerable third-party dependencies. No egress -- the RAG lookup
is fully local; the SBOM is read-only. This is the "known-CVE-in-dependency" half of the
supply-chain class (the novel/typosquat half is the ExploitGym scenario's job).

Design keeps the core PURE and testable: `scan_sbom(sbom_json, rag_query)` takes the CycloneDX JSON
and an injected `rag_query(query, k)` callable, so it unit-tests without Kali/syft/network. The CLI
wires `rag_query` to the Kali-resident rag_query.py (same store the operator's rag_search uses).

Usage:
    # 1) get an SBOM (operator tool: security_scan kind=sbom target=<image|dir>) -> save cyclonedx json
    # 2) python supply_chain_scan.py --sbom sbom.json            # diffs vs the offline RAG
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

WSL_DISTRO = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")


def _run_kali(cmd: str, distro: str = None, timeout: int = 120):
    """Run a shell command in the Kali toolset. On Windows -> via `wsl -d <distro>`; when ALREADY inside
    the Kali/WSL netns (sys.platform != win32) -> a plain local `bash -lc` (a nested `wsl` there fails with
    'No such file or directory: wsl' -- which is exactly what emptied the supply-chain scan when the leg
    ran in-Kali). Same platform shim as sandbox._kali."""
    argv = (["bash", "-lc", cmd] if sys.platform != "win32"
            else ["wsl", "-d", distro or WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd])
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def parse_cyclonedx(sbom_json: dict) -> list:
    """Return [{name, version, purl}] from a CycloneDX SBOM (syft -o cyclonedx-json)."""
    comps = []
    for c in (sbom_json.get("components") or []):
        name, ver = c.get("name"), c.get("version")
        if name:
            comps.append({"name": name, "version": ver or "", "purl": c.get("purl", "")})
    # de-dup on (name, version)
    seen, out = set(), []
    for c in comps:
        key = (c["name"], c["version"])
        if key not in seen:
            seen.add(key); out.append(c)
    return out


def _rank_key(hit: dict):
    """Rank vulnerable deps: KEV first, then EPSS, then CVSS (all descending)."""
    return (1 if hit.get("kev") else 0,
            float(hit.get("epss") or 0.0),
            float(hit.get("cvss_v3") or hit.get("cvss") or 0.0))


def scan_sbom(sbom_json: dict, rag_query, k: int = 3) -> dict:
    """PURE core: for each SBOM component, keyword-query the RAG for CVEs mentioning the component and
    collect CANDIDATE matches. IMPORTANT: `rag_query` is FTS keyword search -- it does NOT check whether
    the installed version is in the CVE's affected range, so a patched dependency can still match on the
    name alone. Results are therefore **candidates to confirm**, not confirmed-vulnerable; the
    ground-truth supply-chain oracle is `scan_image()` (grype, which does version-range matching). Each
    hit is flagged `candidate: True`. `rag_query(query:str, k:int) -> {items:[{cve_id,cvss_v3,epss,kev}]}`."""
    components = parse_cyclonedx(sbom_json)
    candidates = []
    for c in components:
        q = f"{c['name']} {c['version']}".strip()
        try:
            res = rag_query(q, k) or {}
        except Exception as e:
            res = {"error": str(e), "items": []}
        for it in (res.get("items") or []):
            candidates.append({"package": c["name"], "version": c["version"], "purl": c["purl"],
                               "cve": it.get("cve_id"), "cvss": it.get("cvss_v3") or it.get("cvss"),
                               "epss": it.get("epss"), "kev": bool(it.get("kev")),
                               "kev_due": it.get("kev_due"), "url": it.get("url"),
                               "candidate": True, "match": "name-keyword (version NOT range-checked)"})
    candidates.sort(key=_rank_key, reverse=True)
    return {"components_scanned": len(components),
            "note": "CANDIDATE keyword matches (version not range-checked) -- confirm with grype scan_image()",
            "candidate_count": len(candidates),
            "vulnerable_count": len(candidates),   # kept for back-compat; these are candidates, not confirmed
            "kev_count": sum(1 for v in candidates if v["kev"]),
            "vulnerable": candidates}


def scan_image(image: str, kali_distro: str = None, min_sev=("High", "Critical"), timeout: int = 600) -> dict:
    """SHARED supply-chain leg (used by all 3 modes): run grype on a container image inside Kali and
    return the HIGH/CRITICAL vulnerable dependencies. grype IS the ground-truth oracle here."""
    import shlex
    distro = kali_distro or WSL_DISTRO
    # --scope all-layers: the app's npm deps live in intermediate layers; the default 'squashed' scope
    # missed them (empty scan). GRYPE_DB_AUTO_UPDATE=false: use the CACHED vuln DB -- grype's on-scan DB
    # check hangs on the network here, which returned a FAST empty result (looked like "no vulns" but was
    # "DB not ready"). AEGIS_GRYPE_DB_UPDATE=1 re-enables the online refresh when you want a fresh DB.
    auto = "true" if os.environ.get("AEGIS_GRYPE_DB_UPDATE") == "1" else "false"
    cmd = f"GRYPE_DB_AUTO_UPDATE={auto} grype {shlex.quote(image)} -o json --scope all-layers 2>/dev/null"
    try:
        p = _run_kali(cmd, distro=distro, timeout=timeout)
        out = p.stdout or ""
        i = out.find("{")                                  # tolerate a leading progress/log line before the JSON
        data = json.loads(out[i:]) if i >= 0 else {}
    except Exception as e:
        return {"image": image, "error": str(e), "count": 0, "vulnerable": []}
    vulns, seen = [], set()
    for m in (data.get("matches") or []):
        art = m.get("artifact", {}) or {}
        v = m.get("vulnerability", {}) or {}
        sev = v.get("severity", "")
        if min_sev and sev not in min_sev:
            continue
        key = (art.get("name"), v.get("id"))
        if key in seen:
            continue
        seen.add(key)
        vulns.append({"package": art.get("name"), "version": art.get("version"), "type": art.get("type"),
                      "vuln": v.get("id"), "severity": sev,
                      "fixed": ",".join((v.get("fix", {}) or {}).get("versions", []) or [])})
    vulns.sort(key=lambda x: {"Critical": 0, "High": 1}.get(x["severity"], 2))
    return {"image": image, "total_matches": len(data.get("matches") or []), "count": len(vulns),
            "vulnerable": vulns}


def _kali_rag_query(query: str, k: int = 3) -> dict:
    """CLI wiring: run the Kali-resident rag_query.py (the same offline store as rag_search)."""
    import shlex
    cmd = f"python3 /opt/aegis-rag/rag_query.py --json --k {int(k)} {shlex.quote(query)}"
    try:
        p = _run_kali(cmd, timeout=120)
        # tolerate leading log lines: take the last line that parses as JSON
        for ln in reversed((p.stdout or "").splitlines()):
            ln = ln.strip()
            if ln.startswith("{"):
                return json.loads(ln)
    except Exception:
        pass
    return {"items": []}


# ---------- CVE CONFIRMATION (reduce false positives) ----------
# grype/cpe flag a CVE PRESENT by version range, but the vulnerable code path may be unreachable/unused
# -> false positive. This pass adds OFFLINE exploitability EVIDENCE (CISA KEV + EPSS + Exploit-DB/PoC)
# and a confidence CLASS, so the admin report can rank CONFIRMED-exploitable above merely-present and drop
# the noise. It NEVER auto-runs a destructive exploit (doctrine): a public PoC is referenced + a
# non-destructive confirm hint is emitted for the operator to run under the gate.
def _searchsploit(query, kali_distro=None):
    """Offline Exploit-DB lookup via searchsploit --json (--cve for a CVE id, else keyword). [] on error."""
    import re as _re, shlex as _shlex
    q = (query or "").strip()
    if not q:
        return []
    is_cve = bool(_re.match(r"(?i)CVE-\d{4}-\d+$", q))
    args = ["searchsploit", "--json"] + (["--cve", q] if is_cve else q.split()[:4])
    cmd = " ".join(_shlex.quote(a) for a in args) + " 2>/dev/null"
    try:
        p = _run_kali(cmd, distro=kali_distro, timeout=60)
        out = p.stdout or ""
        i = out.find("{")
        j = json.loads(out[i:]) if i >= 0 else {}
        return [{"edb": e.get("EDB-ID"), "title": e.get("Title"), "path": e.get("Path")}
                for e in (j.get("RESULTS_EXPLOIT") or [])[:5]]
    except Exception:
        return []


def confirm_cve(vuln, base=None, kali_distro=None):
    """Confirmation pass for one PRESENT CVE (a scan_image() item {package,version,vuln,severity,fixed}).
    Gathers OFFLINE evidence -- KEV / EPSS / Exploit-DB / searchsploit PoC -- and classifies confidence:
    exploited-in-wild (KEV) > poc-public > epss-high > version-present (possible FP). Returns a dict the
    report surfaces as a confidence tag. Non-destructive: references a PoC, never runs a destructive one."""
    cve = vuln.get("vuln") or vuln.get("cve") or ""
    pkg, ver = vuln.get("package", ""), vuln.get("version", "")
    try:
        items = (_kali_rag_query(cve or f"{pkg} {ver}", k=3) or {}).get("items") or []
        meta = next((it for it in items if (it.get("cve_id") or "").upper() == cve.upper()),
                    items[0] if items else {})
    except Exception:
        meta = {}
    kev = bool(meta.get("kev"))
    epss = meta.get("epss")
    edb_ids = meta.get("exploitdb_ids") or []
    poc = _searchsploit(cve or f"{pkg} {ver}", kali_distro)
    poc_public = bool(edb_ids or poc)
    try:
        epss_f = float(epss) if epss is not None else None
    except Exception:
        epss_f = None
    if kev:
        conf = "exploited-in-wild"          # CISA KEV: known exploited -> treat as real, top priority
    elif poc_public:
        conf = "poc-public"                 # public PoC / Exploit-DB entry -> likely exploitable
    elif epss_f is not None and epss_f >= 0.5:
        conf = "epss-high"                  # statistically likely exploited
    else:
        conf = "version-present"            # matched by VERSION only -> possible FP if path unreachable
    if poc_public:
        refs = [f"EDB-{p['edb']}" for p in poc if p.get("edb")] or [str(x) for x in edb_ids[:2]]
        hint = (f"public PoC available ({', '.join(refs[:3])}) -- adapt against the mirror under the gate "
                f"(non-destructive) to confirm the vulnerable path is REACHED before acting")
    else:
        hint = (f"no public PoC found -- confirm by exercising {pkg}'s vulnerable code path on the mirror; "
                f"if it is not reachable/used, DOWNGRADE this finding (likely false positive)")
    return {"cve": cve, "confidence": conf, "kev": kev, "epss": epss, "exploitdb_ids": edb_ids,
            "poc": poc[:3], "poc_public": poc_public, "reachable": "unknown", "how_to_confirm": hint}


def confirm_all(scan_result, base=None, kali_distro=None, limit=12):
    """Annotate a scan_image() result's `vulnerable` items with confirm_cve evidence (bounded to the top
    `limit` by severity; offline). Adds a `confidence_counts` summary so the report ranks confirmed above
    present. Fail-safe + opt-out (AEGIS_CVE_CONFIRM=0)."""
    if os.environ.get("AEGIS_CVE_CONFIRM", "1") == "0":
        return scan_result
    counts = {}
    for v in (scan_result.get("vulnerable") or [])[:limit]:
        try:
            c = confirm_cve(v, base=base, kali_distro=kali_distro)
        except Exception as e:
            c = {"confidence": "unconfirmed", "error": str(e)[:120]}
        v["confirm"] = c
        counts[c.get("confidence", "unconfirmed")] = counts.get(c.get("confidence", "unconfirmed"), 0) + 1
    scan_result["confidence_counts"] = counts
    scan_result["confirmed_note"] = ("CVE confirmation: KEV/PoC/EPSS evidence per item; prioritise "
                                     "exploited-in-wild > poc-public > epss-high > version-present "
                                     "(version-present = confirm reachability or treat as candidate).")
    return scan_result


def main():
    ap = argparse.ArgumentParser(description="Diff an SBOM against the offline vuln RAG (supply-chain leg).")
    ap.add_argument("--sbom", required=True, help="CycloneDX JSON SBOM (from security_scan kind=sbom)")
    ap.add_argument("--k", type=int, default=3, help="max RAG hits per component")
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    a = ap.parse_args()
    with open(a.sbom, encoding="utf-8") as f:
        sbom = json.load(f)
    report = scan_sbom(sbom, _kali_rag_query, k=a.k)
    if a.json:
        print(json.dumps(report, indent=2)); return
    print(f"[supply-chain] {report['components_scanned']} components, "
          f"{report.get('candidate_count', report['vulnerable_count'])} CANDIDATE CVE matches "
          f"({report['kev_count']} KEV) -- keyword-based, confirm with grype:")
    for v in report["vulnerable"]:
        flag = " [KEV]" if v["kev"] else ""
        print(f"  {v['package']}@{v['version']} -> {v['cve']} "
              f"(cvss={v['cvss']} epss={v['epss']}){flag}")


if __name__ == "__main__":
    main()
