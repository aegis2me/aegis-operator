#!/usr/bin/env python3
"""
NOTICE: Defensive research/benchmark/self-help on OWNED or EXPLICITLY-AUTHORIZED systems (and mirrors) ONLY.
Unauthorized/offensive use is prohibited and is the user's sole act. Use = acceptance of DISCLAIMER.md.

iterative_hunt_live.py -- wire IterativeHunt into the OPERATOR path.

execute -> runs a board-proposed move against the mirror behind the non-destructive guard
           (the test_suggestions doctrine: plant/write OK, NEVER erase/drop).
oracle  -> the deterministic verified_findings layer: records a candidate, runs the move's
           oracle(s), and (for HIGH/CRITICAL) requires >=2 INDEPENDENT oracle confirmations
           (verify_consensus). Only "verified" counts; over-claims are rejected.

The loop persists for a budget (~40), refines from each oracle delta, and escalates on a foothold
(see iterative_hunt.IterativeHunt). Contained + mirror-only.

Usage:
    python iterative_hunt_live.py --objective "reach as deep as you can" --role owner
"""
from __future__ import annotations

import os, re, sys, json
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "shared"))
from iterative_hunt import IterativeHunt, board_brainstorm, tiered_brainstorm
from verified_findings import FindingStore, Finding, Evidence, Verifier
try:
    import reach as _reach                            # reach-axis finding tags (layer/novelty/origin)
except Exception:
    _reach = None


def _reach_tags(move, result=None):
    return _reach.finding_tags(move, result) if _reach else []


def _reach_prov(move, result=None):
    return _reach.finding_provenance(move, result) if _reach else {}

BASE = os.environ.get("AEGIS_TARGET", "https://localhost:8443")
_DESTRUCTIVE = re.compile(r"\b(DELETE\s+FROM|DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE|rm\s+-rf)\b", re.I)


def guard(move: dict):
    """Non-destructive doctrine: block erase/drop/truncate and HTTP DELETE."""
    blob = " ".join(str(move.get(k, "")) for k in ("method", "code", "payload", "body"))
    if _DESTRUCTIVE.search(blob) or move.get("method", "").upper() == "DELETE":
        return False, "destructive (erase/drop/delete) -- blocked by non-destructive doctrine"
    return True, ""


def make_execute(base=BASE, session_for_role=None, requests_mod=None):
    """execute(move, phase) -> result. Runs the guarded HTTP move against the mirror as the move's
    role. `session_for_role(role)->session` supplies an authenticated session (default: a fresh one)."""
    req = requests_mod
    if req is None:
        import requests as req  # noqa
        req.packages.urllib3.disable_warnings()

    def _sess(role):
        if session_for_role:
            return session_for_role(role)
        return req.Session()

    import vectors
    ctx = {"base": base, "session_for_role": (session_for_role or _sess), "cve_confirm": True}

    def execute(move, phase):
        ok, why = guard(move)
        if not ok:
            return {"move": move, "blocked": why, "status": 0, "body": ""}
        # SHARED vectors: web / recon / supply_chain / static / fuzz / misconfig / rag -- same
        # fact-finding tools every mode has. Operator wraps them with the non-destructive guard only.
        return vectors.dispatch(move, phase, ctx)

    return execute


def _graded_score(signals: dict) -> dict:
    """Graded severity/confidence for a verified finding (PyRIT-pattern scorer). Complements the oracle's
    binary verdict; offline-safe -> {} if scoring is unavailable."""
    try:
        import scoring
        return scoring.score_finding(signals).as_dict()
    except Exception:
        return {}


def make_oracle(store: FindingStore, oracle_factory=None, session_for_role=None,
                authz_baseline_role=None, authz_intended_roles=None, base=BASE):
    """oracle(result) -> (verdict, receipt), via verified_findings. Records a candidate then verifies
    with the move's oracle(s); HIGH/CRITICAL require >=2 independent confirmations (consensus).
    `oracle_factory(move) -> [Oracle,...]` builds the ground-truth oracle(s) (default: HTTP/DB/authz).
    `session_for_role(role)->Session` (optional) enables the cross-role AuthzOracle so BROKEN-ACCESS /
    over-reach board hypotheses AUTO-CONFIRM (a non-privileged role reaching a surface a baseline role
    is denied). `authz_baseline_role` = a role that must be denied (default env AEGIS_AUTHZ_BASELINE or
    'technician'); `authz_intended_roles` = roles never flagged (business-intended privilege, default
    env AEGIS_AUTHZ_INTENDED)."""
    verifier = Verifier(store)
    _AUTHZ = ("authz", "idor", "bola", "over-read", "overread", "over-reach", "overreach",
              "broken-access", "broken_access", "access-control", "access_control", "privesc",
              "authorization", "segregation")

    def _default_factory(move):
        from verified_findings import HttpOracle, DbOracle
        # BROKEN-ACCESS / OVER-REACH auto-confirm: a plain status oracle can't express over-reach, so
        # for an authz-class move naming a ROLE we build the cross-role AuthzOracle (verified only when
        # the tested role gets 2xx AND a baseline role is denied on the same surface -- FP-resistant).
        cls = " ".join(str(move.get(k, "")) for k in ("vuln_class", "class", "technique", "why_novel")).lower()
        role = str(move.get("role") or move.get("trust") or "").lower().strip()
        base_role = (authz_baseline_role or os.environ.get("AEGIS_AUTHZ_BASELINE", "technician")).lower()
        intended = (authz_intended_roles if authz_intended_roles is not None
                    else [r.strip() for r in (os.environ.get("AEGIS_AUTHZ_INTENDED", "") or "").split(",") if r.strip()])
        if session_for_role and role and role != base_role and any(a in cls for a in _AUTHZ) \
                and not move.get("oracles") and not move.get("oracle"):
            from verified_findings import AuthzOracle
            surf = move.get("path") or move.get("surface") or "/"
            return [AuthzOracle(base, move.get("method", "GET"), surf if str(surf).startswith("/") else "/" + str(surf),
                                role, base_role, session_for_role, json_body=move.get("body"),
                                intended_roles=intended, oracle_id="hunt-authz@0")]
        specs = move.get("oracles") or ([move["oracle"]] if move.get("oracle") else [])
        if not specs:
            # NORMALIZE a board move's free-text hint into a machine oracle, so a GROUNDED board
            # hypothesis can actually be verified instead of logged rejected("no oracle"). Pull an
            # expected HTTP status from the move's `expected_oracle` prose plus any body_regex.
            import re as _re
            eo = str(move.get("expected_oracle") or "")
            mstat = _re.search(r"\b([1-5]\d\d)\b", eo)
            est = int(mstat.group(1)) if mstat else None
            if est is None:                              # relational / word forms (like check_oracle)
                lo = eo.lower()
                if _re.search(r"\b2xx\b|\bsuccess|granted|accessible|returns? (data|200|ok)|leak|disclos", lo):
                    est = 200
                elif _re.search(r"\b5xx\b|server error|\b500\b|crash|unhandled", lo):
                    est = 500
                elif _re.search(r"forbidden|denied|blocked|\b403\b", lo):
                    est = 403
            br = move.get("body_regex") or move.get("expected_body_regex") or None
            if est is not None or br:
                specs = [{"expected_status": est, "body_regex": br}]
        out = []
        for i, s in enumerate(specs):
            if isinstance(s, str):
                # a BARE oracle NAME (relational: idempotency/invariant/auth_state/resource_persistence/
                # differential) belongs to the stateful/differential legs, which carry their own ground
                # truth and are handled upstream in oracle(). Reaching the generic HTTP factory with one
                # means that leg errored or the move was misrouted -> skip it (no HTTP oracle) rather than
                # crash on s.get(). An empty oracle list -> a graceful "no oracle" rejection.
                continue
            if s.get("kind") == "db":
                out.append(DbOracle(s["container"], s.get("user", os.environ.get("AEGIS_DB_USER", "app")),
                                    s.get("db", os.environ.get("AEGIS_DB_NAME", "app")),
                                    s["sql"], s.get("expected_regex", ".+"),
                                    pgpassword=s.get("pgpassword", ""), oracle_id=f"hunt-db@{i}"))
            else:
                out.append(HttpOracle(base, move.get("method", "GET"), move.get("path", "/"),
                                      json_body=move.get("body"), expected_status=s.get("expected_status"),
                                      body_regex=s.get("body_regex"), oracle_id=f"hunt-http@{i}"))
        return out

    factory = oracle_factory or _default_factory
    _secrets_seen = set()

    def oracle(result):
        move = result["move"]
        # PASSIVE SECRETS: a high-confidence secret/PII leak in ANY response is a SIDE finding, recorded
        # independently of the move's own verdict (deduped by surface+kinds so we don't flood). Commercial
        # scanners flag this on all traffic; here it rides on every response the loop already produced.
        _ss = result.get("secrets_scan")
        if _ss:
            _sig = (str(_ss.get("surface")), ",".join(_ss.get("kinds") or []))
            if _sig not in _secrets_seen:
                _secrets_seen.add(_sig)
                try:
                    sf = Finding(claim_type="secrets.leak_in_response",
                                 summary=("Secrets/PII in response at " + str(_ss.get("surface")) + ": " +
                                          ", ".join(_ss.get("kinds") or []))[:200],
                                 severity="high", target_id="target-mirror",
                                 evidence=[asdict(Evidence(kind="note", detail=json.dumps(h)[:200]))
                                           for h in (_ss.get("hits") or [])[:6]],
                                 coverage_tags=[f"surface:{_ss.get('surface','')}", "technique:secrets-scan",
                                                "class:sensitive-data-exposure"] + _reach_tags(move, result),
                                 provenance={"provider": "secrets", **_reach_prov(move, result)})
                    _fid = store.record_candidate(sf)
                    store._transition(_fid, "verified", "secrets.leak_in_response",
                                      {"surface": _ss.get("surface"), "kinds": _ss.get("kinds"),
                                       "status": _ss.get("status")})
                except Exception:
                    pass
        if result.get("blocked"):
            return ("rejected", {"blocked": result["blocked"]})
        of = result.get("ossfuzz")
        if of is not None:
            # THE FUZZER's reproduce() IS the deterministic ground-truth oracle (like grype for supply
            # chain): a crash that REPRODUCES is verified; the board interpretation rides along as the
            # verdict. Findings that didn't reproduce are rejected. Each unique crash bucket is recorded.
            reproduced = [ff for ff in (result.get("findings") or []) if ff.get("reproduced")]
            if not reproduced:
                return ("rejected", {"detail": "fuzzing produced no reproduced crash", "ossfuzz": of.get("crash_count", 0)})
            buckets = []
            for ff in reproduced:
                interp = ff.get("interpretation") or {}
                vtext = (interp.get("verdict") or "").lower()
                sev = next((s for s in ("critical", "high", "med", "low") if s in vtext), None) \
                    or ("high" if ff.get("vuln_class") == "memory-safety" else "medium")
                sev = {"med": "medium"}.get(sev, sev)
                f = Finding(claim_type=f"ossfuzz.{ff.get('vuln_class', 'crash')}",
                            summary=(ff.get("mechanism") or "grey-box fuzzing crash")[:200],
                            severity=sev, target_id="target-mirror",
                            evidence=[asdict(Evidence(kind="note", detail=(ff.get("evidence") or "")[:400])),
                                      asdict(Evidence(kind="note", detail=f"testcase={ff.get('testcase')} "
                                             f"bucket={ff.get('bucket')} reproduced=True"))],
                            coverage_tags=[f"surface:{ff.get('surface', '')}", "technique:ossfuzz",
                                           f"bucket:{ff.get('bucket')}"],
                            provenance={"provider": "fuzzer", "engine": of.get("engine")})
                fid = store.record_candidate(f)
                store._transition(fid, "verified", "fuzzer.reproduce",
                                  {"testcase": ff.get("testcase"), "bucket": ff.get("bucket"),
                                   "verdict": (interp.get("verdict") or "")[:400]})
                buckets.append(ff.get("bucket"))
            rcpt = {"weakness": "ossfuzz.crash", "reproduced": len(reproduced),
                    "buckets": sorted(set(buckets))}
            rcpt["score"] = _graded_score({"reproduced": True,
                "controllable_write": any(ff.get("vuln_class") == "memory-safety" for ff in reproduced),
                "dos_only": all(ff.get("vuln_class") == "crash" for ff in reproduced)})
            return ("verified", rcpt)
        sc = result.get("supply_chain")
        if sc is not None:                                     # grype IS the ground-truth oracle
            vulns = sc.get("vulnerable", [])
            if vulns:
                f = Finding(claim_type="supply_chain.vulnerable_dependency",
                            summary=f"{len(vulns)} HIGH/CRITICAL vulnerable deps in {sc.get('image')}",
                            severity="high", target_id="target-mirror",
                            evidence=[asdict(Evidence(kind="note", detail=f"{v['package']} {v['version']} {v['vuln']} {v['severity']} fix={v['fixed']}")) for v in vulns[:10]],
                            coverage_tags=["technique:supply-chain-sca", f"surface:image:{sc.get('image')}"]
                                          + _reach_tags(move, result),
                            provenance={"provider": "grype", **_reach_prov(move, result)})
                fid = store.record_candidate(f)
                store._transition(fid, "verified", "grype", {"count": len(vulns), "top": vulns[:5]})
                return ("verified", {"weakness": "supply_chain.vulnerable_dependency", "count": len(vulns), "top": vulns[:5]})
            return ("rejected", {"detail": "no HIGH/CRITICAL deps"})
        pr = result.get("probe")
        # Only the probe leg (novel-code writer, action='probe'/'code') sets result['probe']; every other
        # leg leaves it unset. dispatch() attaches its normalized uniform view as result['probe_schema']
        # (NOT 'probe'), so this branch fires ONLY for a genuine code-writer probe and never shadows the
        # HTTP/DB/Authz oracles built below.
        if pr is not None:                                     # NOVEL-CODE probe: the leg's own oracle
            # A coder-written bridge/foothold probe carries its OWN ground truth (probe_verified), like
            # grype/ossfuzz. A proven probe is a VERIFIED (typically NOVEL, non-CVE) finding -- flagged
            # by the reach tags so the report can EMPHASIZE it (novel stack/scaffold or app zero-day).
            if not result.get("probe_verified"):
                return ("rejected", {"detail": "novel-code probe did not prove its oracle",
                                     "probe": {k: pr.get(k) for k in ("verdict", "notes")}})
            sev = (move.get("severity") or "high").lower()
            f = Finding(claim_type=move.get("technique") or f"novel-code.{_reach.intent_of(move) if _reach else 'foothold'}",
                        summary=(move.get("why_novel") or move.get("new_code") or "novel-code probe")[:200],
                        severity=sev, target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=f"probe {pr.get('verdict')} :: {pr.get('notes','')[:200]}")),
                                  asdict(Evidence(kind="note", detail=f"code_by={move.get('code_by')} code={str(pr.get('code',''))[:300]}"))],
                        coverage_tags=[f"surface:{move.get('surface', move.get('path',''))}",
                                       f"technique:{move.get('technique','novel-code')}"] + _reach_tags(move, result),
                        provenance={"provider": "novel_code", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", "probe.oracle",
                              {"verdict": pr.get("verdict"), "notes": pr.get("notes", "")[:300]})
            return ("verified", {"weakness": f.claim_type, "layer": (_reach.direction_of(move) if _reach else ""),
                                 "origin": (_reach.finding_origin(move, result) if _reach else "novel"),
                                 "probe": {k: pr.get(k) for k in ("verdict", "notes")}})
        sf = result.get("stateful")
        if sf is not None:                                    # STATEFUL leg: its relational oracle IS ground truth
            import json as _json
            if not result.get("stateful_verified"):
                return ("rejected", {"detail": "stateful invariant/idempotency held (no bug)",
                                     "stateful": {k: sf.get(k) for k in ("oracle", "before", "after", "bound", "repeats")}})
            sev = (move.get("severity") or "high").lower()
            f = Finding(claim_type=move.get("technique") or f"stateful.{sf.get('oracle')}",
                        summary=(move.get("why_novel") or
                                 f"{sf.get('oracle')} violation on {sf.get('surface')}: before={sf.get('before')} "
                                 f"after={sf.get('after')} bound={sf.get('bound')} repeats={sf.get('repeats')}")[:200],
                        severity=sev, target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=f"{sf.get('oracle')} :: {_json.dumps(sf.get('receipt'))[:300]}")),
                                  asdict(Evidence(kind="note", detail=f"trace={_json.dumps(sf.get('trace'))[:300]}"))],
                        coverage_tags=[f"surface:{sf.get('surface','')}", f"technique:{move.get('technique','stateful')}",
                                       f"class:{move.get('vuln_class','business-logic')}"] + _reach_tags(move, result),
                        provenance={"provider": "stateful", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", f"stateful.{sf.get('oracle')}", sf.get("receipt") or {})
            return ("verified", {"weakness": f.claim_type, "oracle": sf.get("oracle"),
                                 "before": sf.get("before"), "after": sf.get("after"), "bound": sf.get("bound"),
                                 "surface": sf.get("surface")})
        idr = result.get("idor")
        if idr is not None:                                   # IDOR / BOLA object-level authz sweep
            if idr.get("verdict") != "verified":
                return ("rejected", {"detail": idr.get("note") or "no object-level over-reach",
                                     "surface": idr.get("surface"), "ids_swept": idr.get("ids_swept")})
            leads = idr.get("leads") or []
            f = Finding(claim_type="idor.object_level_authz",
                        summary=("IDOR/BOLA on " + str(idr.get("surface")) + ": non-owner role(s) read the "
                                 "owner's objects -- " + ", ".join(f"{l.get('role')}#{str(l.get('id'))[:8]}"
                                 for l in leads[:4]))[:200],
                        severity="high", target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=json.dumps(l)[:200])) for l in leads[:6]],
                        coverage_tags=[f"surface:{idr.get('surface','')}", "technique:idor-sweep",
                                       "class:broken-object-level-authz"] + _reach_tags(move, result),
                        provenance={"provider": "idor", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", "idor.object_level_authz",
                              {"surface": idr.get("surface"), "leads": leads[:8], "checked": idr.get("checked")})
            return ("verified", {"weakness": f.claim_type, "surface": idr.get("surface"),
                                 "leads": leads[:6], "n_leads": idr.get("n_leads")})
        ma = result.get("massassign")
        if ma is not None:                                    # mass assignment / auto-binding
            if ma.get("verdict") != "verified":
                return ("rejected", {"detail": ma.get("note"), "surface": ma.get("surface")})
            f = Finding(claim_type="web.mass_assignment",
                        summary=("Mass assignment at " + str(ma.get("surface")) + ": privileged field(s) "
                                 + ", ".join(l.get("field") for l in (ma.get("leads") or [])) + " accepted")[:200],
                        severity="high", target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=json.dumps(l)[:200])) for l in (ma.get("leads") or [])[:6]],
                        coverage_tags=[f"surface:{ma.get('surface','')}", "technique:mass-assignment",
                                       "class:broken-object-property-level-authz"] + _reach_tags(move, result),
                        provenance={"provider": "mass_assign", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", "web.mass_assignment",
                              {"surface": ma.get("surface"), "leads": (ma.get("leads") or [])[:8]})
            return ("verified", {"weakness": f.claim_type, "surface": ma.get("surface"),
                                 "fields": [l.get("field") for l in (ma.get("leads") or [])]})
        orr = result.get("openredir")
        if orr is not None:                                   # open redirect
            if orr.get("verdict") != "verified":
                return ("rejected", {"detail": "no external redirect", "surface": orr.get("surface")})
            f = Finding(claim_type="web.open_redirect",
                        summary=("Open redirect at " + str(orr.get("surface")) + " via param '" +
                                 str(orr.get("param")) + "' -> external " + str(orr.get("canary")))[:200],
                        severity="medium", target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=json.dumps(orr)[:300]))],
                        coverage_tags=[f"surface:{orr.get('surface','')}", "technique:open-redirect",
                                       "class:unvalidated-redirect"] + _reach_tags(move, result),
                        provenance={"provider": "open_redirect", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", "web.open_redirect",
                              {"surface": orr.get("surface"), "param": orr.get("param"), "via": orr.get("via")})
            return ("verified", {"weakness": f.claim_type, "surface": orr.get("surface"), "param": orr.get("param")})
        sfx = result.get("sessfix")
        if sfx is not None:                                   # session fixation
            if sfx.get("verdict") != "verified":
                return ("rejected", {"detail": sfx.get("note"), "surface": sfx.get("surface")})
            f = Finding(claim_type="auth.session_fixation",
                        summary=("Session fixation: id not rotated on login and stays authenticated ("
                                 + str(sfx.get("cookie")) + ")")[:200],
                        severity="high", target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=json.dumps(sfx)[:300]))],
                        coverage_tags=[f"surface:{sfx.get('surface','')}", "technique:session-fixation",
                                       "class:broken-authentication"] + _reach_tags(move, result),
                        provenance={"provider": "session_fixation", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", "auth.session_fixation", {"cookie": sfx.get("cookie")})
            return ("verified", {"weakness": f.claim_type, "cookie": sfx.get("cookie")})
        up = result.get("upload")
        if up is not None:                                    # unrestricted / dangerous file upload
            if up.get("verdict") != "verified":
                return ("rejected", {"detail": up.get("note"), "surface": up.get("surface")})
            f = Finding(claim_type="web.unrestricted_upload",
                        summary=("Unrestricted upload at " + str(up.get("surface")) + ": " + str(up.get("note")))[:200],
                        severity=up.get("severity","high"), target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=json.dumps(up)[:300]))],
                        coverage_tags=[f"surface:{up.get('surface','')}", "technique:file-upload",
                                       "class:unrestricted-file-upload"] + _reach_tags(move, result),
                        provenance={"provider": "file_upload", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", "web.unrestricted_upload", {"surface": up.get("surface"), "filename": up.get("filename")})
            return ("verified", {"weakness": f.claim_type, "surface": up.get("surface")})
        xr = result.get("xss")
        if xr is not None:                                    # DOM/reflected XSS (executed in browser)
            if xr.get("verdict") != "verified":
                return ("rejected", {"detail": "no XSS execution", "surface": xr.get("surface")})
            f = Finding(claim_type="web.xss",
                        summary=("XSS (" + str(xr.get("context")) + ") at " + str(xr.get("surface")) + " via '"
                                 + str(xr.get("param")) + "' -- payload EXECUTED")[:200],
                        severity="high", target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=json.dumps(xr)[:300]))],
                        coverage_tags=[f"surface:{xr.get('surface','')}", "technique:xss-headless",
                                       "class:cross-site-scripting"] + _reach_tags(move, result),
                        provenance={"provider": "xss", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", "web.xss", {"surface": xr.get("surface"), "param": xr.get("param"), "context": xr.get("context")})
            return ("verified", {"weakness": f.claim_type, "surface": xr.get("surface"), "param": xr.get("param")})
        sr = result.get("ssrf")
        if sr is not None:                                    # SSRF (OOB canary callback)
            if sr.get("verdict") != "verified":
                return ("rejected", {"detail": "no OOB callback", "surface": sr.get("surface")})
            f = Finding(claim_type="web.ssrf",
                        summary=("SSRF at " + str(sr.get("surface")) + " via param '" + str(sr.get("param"))
                                 + "' -> canary called back")[:200],
                        severity="high", target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=json.dumps(h)[:200])) for h in (sr.get("hits") or [])[:4]],
                        coverage_tags=[f"surface:{sr.get('surface','')}", "technique:ssrf-canary",
                                       "class:server-side-request-forgery"] + _reach_tags(move, result),
                        provenance={"provider": "ssrf", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", "web.ssrf", {"surface": sr.get("surface"), "param": sr.get("param")})
            return ("verified", {"weakness": f.claim_type, "surface": sr.get("surface"), "param": sr.get("param")})
        cs = result.get("csrf")
        if cs is not None:                                    # CSRF posture
            if cs.get("verdict") != "verified":
                return ("rejected", {"detail": cs.get("note"), "surface": cs.get("surface")})
            f = Finding(claim_type="web.csrf_exposed",
                        summary=("CSRF exposure at " + str(cs.get("surface")) + ": " + str(cs.get("note")))[:200],
                        severity="medium", target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=json.dumps(cs)[:300]))],
                        coverage_tags=[f"surface:{cs.get('surface','')}", "technique:csrf-posture",
                                       "class:cross-site-request-forgery"] + _reach_tags(move, result),
                        provenance={"provider": "csrf", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", "web.csrf_exposed", {"surface": cs.get("surface")})
            return ("verified", {"weakness": f.claim_type, "surface": cs.get("surface")})
        sh = result.get("secheaders")
        if sh is not None:                                    # cookie flags + security headers
            if sh.get("verdict") != "verified":
                return ("rejected", {"detail": sh.get("note"), "surface": sh.get("surface"),
                                     "missing_headers": sh.get("missing_headers")})
            f = Finding(claim_type="config.security_headers",
                        summary=("Security misconfig at " + str(sh.get("surface")) + ": " + str(sh.get("note")))[:200],
                        severity=sh.get("severity", "low"), target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=json.dumps(i)[:200])) for i in (sh.get("issues") or [])[:8]],
                        coverage_tags=[f"surface:{sh.get('surface','')}", "technique:security-headers",
                                       "class:security-misconfiguration"] + _reach_tags(move, result),
                        provenance={"provider": "security_headers", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", "config.security_headers",
                              {"surface": sh.get("surface"), "issues": (sh.get("issues") or [])[:8]})
            return ("verified", {"weakness": f.claim_type, "surface": sh.get("surface"),
                                 "n_issues": sh.get("n_issues"), "severity": sh.get("severity")})
        rt = result.get("rate")
        if rt is not None:                                    # rate-limit / anti-automation weakness
            if rt.get("verdict") != "verified":
                return ("rejected", {"detail": rt.get("note"), "surface": rt.get("surface"),
                                     "throttle_seen": rt.get("throttle_seen")})
            f = Finding(claim_type="rate.no_rate_limit",
                        summary=("No rate-limit/anti-automation on " + str(rt.get("surface")) + ": " +
                                 str(rt.get("processed")) + " rapid requests, no throttle (brute-force feasible)")[:200],
                        severity="medium", target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=json.dumps(rt.get("status_histogram"))[:200]))],
                        coverage_tags=[f"surface:{rt.get('surface','')}", "technique:rate-limit-probe",
                                       "class:improper-anti-automation"] + _reach_tags(move, result),
                        provenance={"provider": "rate", **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", "rate.no_rate_limit",
                              {"surface": rt.get("surface"), "attempts": rt.get("attempts"),
                               "histogram": rt.get("status_histogram")})
            return ("verified", {"weakness": f.claim_type, "surface": rt.get("surface"),
                                 "attempts": rt.get("attempts")})
        dfr = result.get("differential")
        if dfr is not None:                                   # MECH 2: oracle-diversity LEADs (not verified)
            import json as _json2
            leads = dfr.get("leads") or []
            if not leads:
                return ("rejected", {"detail": "no differential delta above the noise floor",
                                     "surface": dfr.get("surface"), "noise": dfr.get("noise")})
            # A raw delta is a LEAD, not proof: record it as a CANDIDATE to chase; per board doctrine it
            # promotes to VERIFIED only when a SECOND oracle confirms it (not here).
            f = Finding(claim_type="differential.lead",
                        summary=("differential delta on " + str(dfr.get("surface")) + ": " +
                                 ", ".join(f"{l.get('metric')}[{l.get('a')}vs{l.get('b')}]" for l in leads[:4]))[:200],
                        severity="info", target_id="target-mirror",
                        evidence=[asdict(Evidence(kind="note", detail=_json2.dumps(l)[:200])) for l in leads[:6]],
                        coverage_tags=[f"surface:{dfr.get('surface','')}", "technique:differential",
                                       "status:lead"] + _reach_tags(move, result),
                        provenance={"provider": "differential", **_reach_prov(move, result)})
            store.record_candidate(f)     # stays CANDIDATE == a LEAD (never transitioned to verified here)
            return ("rejected", {"lead": True, "weakness": "differential.lead", "surface": dfr.get("surface"),
                                 "leads": leads[:6], "note": "lead recorded (candidate); promote on 2nd-oracle confirm"})
        dv = result.get("discovery")
        if dv is not None:                                    # DISCOVERY-PARITY leg -- carries its own ground truth
            if not result.get("discovery_verified"):
                return ("rejected", {"detail": dv.get("summary") or "discovery not confirmed",
                                     "needs": dv.get("needs"), "kind": dv.get("kind")})
            sev = (dv.get("severity") or "medium").lower()
            ev = [asdict(Evidence(kind="note", detail=str(e)[:300])) for e in (dv.get("evidence") or [])[:4]] \
                or [asdict(Evidence(kind="note", detail=(dv.get("summary") or "")[:300]))]
            f = Finding(claim_type=f"discovery.{dv.get('kind','?')}",
                        summary=(dv.get("summary") or "")[:200], severity=sev, target_id="target-mirror",
                        evidence=ev,
                        coverage_tags=[f"surface:{dv.get('surface','')}", f"technique:{dv.get('technique','')}",
                                       f"discovery:{dv.get('kind','')}"] + _reach_tags(move, result),
                        provenance={"provider": "discovery", "kind": dv.get("kind"), **_reach_prov(move, result)})
            fid = store.record_candidate(f)
            store._transition(fid, "verified", f"discovery.{dv.get('kind','')}",
                              {"summary": dv.get("summary", ""), "items": (dv.get("items") or [])[:10],
                               "technique": dv.get("technique")})
            return ("verified", {"weakness": f.claim_type, "kind": dv.get("kind"),
                                 "technique": dv.get("technique"), "items": (dv.get("items") or [])[:8],
                                 "next_moves": dv.get("next_moves") or []})   # -> discovery chaining
        sev = (move.get("severity") or "medium").lower()
        f = Finding(claim_type=move.get("technique", "novel"),
                    summary=(move.get("why_novel") or move.get("technique") or "")[:200],
                    severity=sev, target_id="target-mirror",
                    evidence=[asdict(Evidence(kind="http", detail=f"{result.get('status')} {str(result.get('body'))[:160]}"))],
                    coverage_tags=[f"surface:{move.get('surface', move.get('path', ''))}",
                                   f"technique:{move.get('technique', '')}"] + _reach_tags(move, result),
                    provenance={"provider": "iterative_hunt", **_reach_prov(move, result)})
        fid = store.record_candidate(f)
        oracles = factory(move)
        if not oracles:                                   # no independent oracle -> cannot verify
            verifier.store._transition(fid, "rejected", "no-oracle", {"why": "no ground-truth oracle"})
            return ("rejected", {"why": "no oracle"})
        if sev in ("high", "critical"):
            verifier.verify_consensus(fid, oracles, min_confirm=min(2, len(oracles)))
        else:
            verifier.verify(fid, oracles[0])
        st = store.findings()[fid]
        receipt = st.get("oracle_receipt") or {}
        if st["status"] == "verified":
            tags = " ".join(str(t) for t in (move.get("coverage_tags") or [])).lower()
            cls = (move.get("vuln_class") or move.get("technique") or "").lower()
            receipt = dict(receipt, score=_graded_score({
                "consensus": sev in ("high", "critical"),
                "cross_account": "idor" in cls or "idor" in tags or "cross" in tags,
                "auth_bypass": "auth" in cls, "rce": "rce" in cls or "rce" in tags,
                "controllable_write": "write" in cls or "injection" in cls}))
        return (st["status"], receipt)

    return oracle


def run_hunt(objective, role="owner", budget=40, store_path=None, base=BASE,
             session_for_role=None, authz_baseline_role=None, authz_intended_roles=None,
             extra_seeds=None, campaign=None, level="operator", max_tier=None):
    # UPDATE THE CVE DB BEFORE THE RUN -- offline-safe, opt-in (AEGIS_RAG_ONLINE=1); never blocks.
    try:
        from rag_refresh import ensure_fresh
        ensure_fresh()
    except Exception:
        pass
    store = FindingStore(store_path or os.path.join(HERE, "hunt_findings.jsonl"))
    # AUTH (was F1, never wired into the operator CLI path): if the caller didn't supply session_for_role,
    # build it from the env (AEGIS_ROLE_MAP + AEGIS_LOGIN_PIN) so seeds run AUTHENTICATED. Without this the
    # CLI ran every move UNAUTHENTICATED -> stateful setup (POST /api/invoices) 401 -> no plant -> before==
    # after -> every relational/authz finding falsely REJECTED. Offline-safe: no map -> None (unchanged).
    if session_for_role is None:
        try:
            import session_factory
            session_for_role = session_factory.from_env(base)
        except Exception:
            session_for_role = None
    # default the cross-role AuthzOracle baseline to the run role when the caller didn't set one, so the
    # authenticated session is actually used as the authz baseline.
    if authz_baseline_role is None and session_for_role is not None:
        authz_baseline_role = role
    # THE PLANNER (multi-scenario): plans[0] seeds the 40-attempt loop with prior-successful (DB/ATT&CK)
    # anchors + board-devised NOVEL approaches; the remaining candidate scenarios are the mid-run
    # RE-OPEN queue -- when the loop would otherwise stall out, it pulls the next scenario's still-new
    # moves. All offline-safe: no planner/board/DB -> seeds=[] + no re-open, loop uses its own brainstorm.
    try:
        from planner import plan_session
        sess = plan_session(objective, base, roles=[role], mode="operator", base=base)
    except Exception:
        sess = None
    seeds = sess.initial_seeds() if sess else []
    # SURFACE-AWARE anchors: caller-supplied seed moves against REAL enumerated routes go FIRST, so the
    # loop probes endpoints that actually exist (not board-guessed paths) before spending free budget.
    if extra_seeds:
        # Stamp the run ROLE onto caller seeds that omit it: the role-seeding wrapper below only touches
        # BOARD moves, so a seed without `role` would run as the default role AND skip the cross-role
        # AuthzOracle (which needs move['role']). Seeds that name their own role keep it.
        seeds = [dict(m, role=m.get("role", role)) for m in extra_seeds] + list(seeds)
    _exec = make_execute(base, session_for_role=session_for_role)
    # CAMPAIGN RELAY: resume prior CONFIRMED footholds as DEEPER, NON-LAZY escalation anchors + cross-mode
    # dedup, with STALE re-confirm (footholds die), a fail-closed TIER gate, and a >=20% breadth floor.
    _seen = set(); _attempted_new = 0
    if campaign:
        try:
            from campaign_ledger import relay_prepare, fingerprint as _fp, _TIER
            _mt = max_tier if max_tier is not None else _TIER.get(level, 1)
            # session_for_role gives relay_prepare a LIGHT liveness check (F2) + authenticates escalations
            # (F1); L1 Operator already runs with session_for_role in its execute ctx.
            _anchors, _seen, _notes = relay_prepare(campaign, level, _mt, budget,
                                                    session_for_role=session_for_role)
            if _anchors:
                seeds = [dict(m, role=m.get("role", role)) for m in _anchors] + list(seeds)
            if _seen:                                   # skip hypotheses already confirmed/refuted upstream
                seeds = [m for m in seeds if _fp(m) not in _seen]
            _attempted_new = len([m for m in seeds if m.get("seed") != "resume"])
            print(f"[relay] level={level} tier={_mt} resumed={_notes.get('resumed')} "
                  f"stale_refuted={_notes.get('stale_refuted')} dedup_skip={len(_seen)} "
                  f"breadth_new_seeds={_attempted_new}", flush=True)
        except Exception as _e:
            print(f"[relay] resume skipped: {_e}", flush=True)
    reopen = (lambda ctx, why: sess.reopen(ctx, why)) if sess else None
    intel = (sess.intel if sess else None)   # OBSERVATORY: planner informs the board; novelty stays the board's
    # NOVEL-CODE WRITER (board -> code bench -> contained probe -> proven/discarded). Offline-safe;
    # AEGIS_NOVEL_CODE=0 disables (moves then run as ordinary moves).
    code_writer = None
    if os.environ.get("AEGIS_NOVEL_CODE", "1") != "0":
        try:
            from novel_code import make_code_writer
            code_writer = make_code_writer()
        except Exception:
            code_writer = None
    # MECH 1: 'clean is a hypothesis' deterministic deepener (artifact-check / implication /
    # invariant-inversion) + MODE-2 structural mutate -- deterministic, non-destructive, offline-safe.
    _deepen = _mutate = None
    try:
        from hunt_strategies import deepen_on_clean as _doc, mutate as _mutate
        _deepen = lambda mv: _doc(mv)
    except Exception:
        _deepen = _mutate = None
    # ALL STAGES: deterministic-first tiered brainstorm (T0 bandit + T1 synth) with the board as
    # stall-breaker/cold-start explorer. Kill: AEGIS_TIERED_BRAINSTORM=0 -> pure board_brainstorm.
    hunt = IterativeHunt(tiered_brainstorm, _exec,
                         make_oracle(store, session_for_role=session_for_role,
                                     authz_baseline_role=authz_baseline_role,
                                     authz_intended_roles=authz_intended_roles, base=base),
                         budget=budget, seed_moves=seeds, reopen=reopen, intel=intel,
                         code_writer=code_writer, deepen=_deepen, mutate=_mutate)
    # seed the role onto every move the board proposes
    orig = hunt.brainstorm
    hunt.brainstorm = lambda ctx: [dict(m, role=m.get("role", role)) for m in (orig(ctx) or [])]
    res = hunt.run(base, objective)
    # RELAY handoff + ANTI-LAZINESS: append this level's CONFIRMED footholds for the next level and flag a
    # level that added NO new confirmed depth (dead-end / lazy).
    if campaign:
        try:
            from campaign_ledger import relay_finalize
            verdict = relay_finalize(campaign, level,
                                     [c.get("move") or {} for c in (res.get("confirmed") or [])],
                                     attempted_new=_attempted_new)
            res["relay"] = verdict
            print(f"[relay] level={level} finalize: new_confirmed_depth={verdict['new_confirmed_depth']} "
                  f"lazy={verdict['lazy']}", flush=True)
        except Exception as _e:
            print(f"[relay] finalize skipped: {_e}", flush=True)
    try:                                                  # RUN COSTS: attach the campaign's API-$ rollup
        import cost_meter
        res["api_cost"] = cost_meter.rollup()
    except Exception:
        pass
    return res


def main():
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("--objective", required=True)
    ap.add_argument("--role", default="owner")
    ap.add_argument("--budget", type=int, default=40)
    ap.add_argument("--campaign", default=os.environ.get("AEGIS_CAMPAIGN"),
                    help="campaign id -> join the CROSS-MODE RELAY (resume prior legs' confirmed footholds "
                         "+ write this leg's). Default: $AEGIS_CAMPAIGN. Omit for a standalone (no-relay) run.")
    ap.add_argument("--level", default="operator", choices=["operator", "exploitgym", "redteam"],
                    help="relay LEVEL/tier of this leg (operator=1, exploitgym=2, redteam=3).")
    ap.add_argument("--max-tier", type=int, default=None,
                    help="permission-tier ceiling for the relay resume (default: this level's tier).")
    ap.add_argument("--store", default=None, help="findings ledger path (default operator/hunt_findings.jsonl).")
    a = ap.parse_args()
    print(json.dumps(run_hunt(a.objective, a.role, a.budget, store_path=a.store,
                              campaign=a.campaign, level=a.level, max_tier=a.max_tier), indent=2, default=str))


if __name__ == "__main__":
    main()
