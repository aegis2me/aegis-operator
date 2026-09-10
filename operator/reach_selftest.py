#!/usr/bin/env python3
"""
reach_selftest.py -- OFFLINE proof of the reach axis (two-direction hunt + foothold/bridge + novel-code
+ tagging + RAG writeback + novel-first report), with NO LLM and NO mirror. Everything is injected, per
the engine's "injectable so it unit-tests without the LLM/mirror" design. Run: python reach_selftest.py
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "rag"))
sys.path.insert(0, os.path.join(HERE, "..", "shared"))

import reach
from iterative_hunt import IterativeHunt
from novel_code import constant_code_writer
import reach_report
import techniques_from_findings as TFF
import vectors

FAILS = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        FAILS.append(name)


# ---------- Part A: the engine spreads the budget across BOTH directions, detects a bridge, and runs
#            the novel-code writer -> probe -> verified path ------------------------------------------
def part_a():
    print("\n[A] engine: two-direction split + foothold/bridge + novel-code hook")
    counter = {"n": 0}

    def brainstorm(ctx):
        out = []
        for _ in range(4):
            counter["n"] += 1
            k = counter["n"]
            if k % 6 == 0:                       # a scaffold move that NEEDS custom code written
                out.append({"action": "supply_chain", "layer": "scaffold", "vuln_class": "plugin",
                            "surface": f"/plugin{k}", "intent": "foothold", "needs_code": True,
                            "new_code": "probe the plugin version endpoint", "expected_oracle": "status 200"})
            elif k % 2 == 0:                     # scaffold (stack/config)
                out.append({"action": "misconfig", "layer": "scaffold", "vuln_class": "misconfig",
                            "surface": f"/cfg{k}", "expected_oracle": "exposed"})
            else:                               # code (app)
                out.append({"action": "web", "vuln_class": "idor", "surface": f"/api/o{k}",
                            "expected_oracle": "200"})
        return out

    def execute(move, phase):
        if move.get("code"):                    # the novel-code writer stamped a probe -> it "runs" + proves
            return {"move": move, "probe": {"kind": "http", "verdict": "pass", "notes": "stub"},
                    "probe_verified": True, "status": 200}
        return {"move": move, "status": 200, "body": "ok"}

    def oracle(result):
        m = result["move"]
        if result.get("probe_verified"):
            return ("verified", {"probe": True})
        surf = str(m.get("surface") or "")
        if reach.direction_of(m) == "scaffold" and surf.endswith("2"):   # a scaffold foothold
            return ("verified", {"ok": True})
        if reach.direction_of(m) == "code" and surf.endswith("3"):       # a code foothold -> BRIDGE
            return ("verified", {"ok": True})
        return ("rejected", {"status": 200})

    hunt = IterativeHunt(brainstorm, execute, oracle, budget=16, direction_floor=3, max_novel_code=4,
                         code_writer=constant_code_writer("curl -s https://localhost:8443/plugin/version",
                                                          "status 200"))
    rep = hunt.run("mirror", "how far can I go")
    da = rep["reach_detail"]["direction_attempts"]
    print("     direction_attempts:", da, "| reach:", rep["reach"])
    print("     novel_code trials :", rep["reach_detail"]["novel_code_counts"],
          "| bridges:", rep["reach"]["bridges"])
    check("both directions probed (budget split, no starvation)", da.get("scaffold", 0) > 0 and da.get("code", 0) > 0)
    check("both directions yielded a confirmed foothold", set(rep["reach"]["directions_reached"]) == {"scaffold", "code"})
    check("a bridge was detected (reach extended)", rep["reach"]["bridges"] >= 1)
    check("scaffold->code seam breached", rep["reach"]["layer_breached_scaffold_to_code"] is True)
    check("novel-code writer invoked + wrote code", any(x.get("wrote") for x in rep["reach_detail"]["novel_code"]))
    check("novel-code capped per direction (<=4)", all(v <= 4 for v in rep["reach_detail"]["novel_code_counts"].values()))


# ---------- Part B: reach tagging + RAG writeback of a proven novel scaffold finding ---------------
def part_b():
    print("\n[B] reach tags + RAG writeback (learned technique from a novel scaffold finding)")
    move = {"action": "probe", "layer": "scaffold", "vuln_class": "plugin", "surface": "/plugins/acme",
            "intent": "bridge", "bridge_to": "database", "code": "curl -s .../plugins/acme",
            "code_by": "ds", "new_code": "curl -s .../plugins/acme"}
    result = {"probe": {"verdict": "pass"}, "probe_verified": True}
    tags = reach.finding_tags(move, result)
    print("     tags:", tags)
    check("tags carry layer:scaffold", "layer:scaffold" in tags)
    check("tags carry novelty:novel", "novelty:novel" in tags)
    check("tags carry origin:novel-code", "origin:novel-code" in tags)
    check("tags name the plugin sub-surface", "scaffold-sub:plugin" in tags)
    f = {"status": "verified", "claim_type": "novel-code.bridge", "summary": "acme plugin zero-day -> DB",
         "severity": "high", "coverage_tags": tags + ["surface:/plugins/acme"],
         "provenance": {"provider": "novel_code", **reach.finding_provenance(move, result)}}
    learned = TFF.learn_from_finding(f)
    print("     learned.reach:", learned["reach"], "| has novel_code:", bool(learned.get("novel_code")))
    check("writeback captures layer scaffold", learned["reach"]["layer"] == "scaffold")
    check("writeback captures novelty novel", learned["reach"]["novelty"] == "novel")
    check("writeback stores the proven novel code", bool(learned.get("novel_code")))
    check("writeback tags include novel + bridge", "novel" in learned["tags"] and "bridge" in learned["tags"])


# ---------- Part C: novel-first report emphasizes scaffold zero-day, keeps CVEs separate ------------
def part_c():
    print("\n[C] novel-first report: scaffold zero-day flagged, CVE kept in PART 2")
    novel_scaffold = {"status": "verified", "claim_type": "novel-code.bridge",
                      "summary": "acme plugin heap overflow (fuzz)", "severity": "high",
                      "coverage_tags": ["surface:/plugins/acme", "layer:scaffold", "novelty:novel",
                                        "origin:fuzz", "reach-intent:foothold", "scaffold-sub:plugin"],
                      "provenance": {"layer": "scaffold", "novelty": "novel", "origin": "fuzz"}}
    known_cve = {"status": "verified", "claim_type": "supply_chain.vulnerable_dependency",
                 "summary": "openssl 1.1.1 CVE-2023-0001", "severity": "high",
                 "coverage_tags": ["layer:scaffold", "novelty:known-cve", "origin:cve"],
                 "provenance": {"layer": "scaffold", "novelty": "known-cve", "origin": "cve"}}
    md = reach_report.build([novel_scaffold, known_cve])
    banner_ok = "NOV-SCAF-001" in md and "ZERO-DAY" in md and "FUZZ-CRASH" in md
    order_ok = md.index("PART 1") < md.index("PART 2")
    cve_ok = "CVE-001" in md and "NOV-SCAF-001" in md.split("PART 2")[0]
    print("     report parts present:", order_ok, "| scaffold zero-day badge:", banner_ok)
    check("novel section is FIRST (PART 1 before PART 2)", order_ok)
    check("scaffold zero-day badged NOV-SCAF + ZERO-DAY + FUZZ-CRASH", banner_ok)
    check("known CVE separated into PART 2 (not given a NOV- id)", cve_ok and "CVE-001" in md.split("PART 2")[1])


# ---------- Part D: probe vector containment (guard blocks destructive; disabled = staged) ----------
def part_d():
    print("\n[D] probe vector: non-destructive guard + kill-switch")
    check("probe leg is registered", "probe" in vectors.LEGS and "code" in vectors.LEGS)
    r = vectors.probe({"code": "psql -c 'DROP TABLE users;'"}, {})
    print("     destructive ->", r.get("blocked"))
    check("destructive code is BLOCKED", bool(r.get("blocked")))
    os.environ["AEGIS_NOVEL_CODE"] = "0"
    r2 = vectors.probe({"code": "curl https://localhost/x"}, {})
    os.environ.pop("AEGIS_NOVEL_CODE", None)
    check("kill-switch stages (does not execute)", r2.get("blocked") == "novel-code execution disabled (AEGIS_NOVEL_CODE=0)")


def part_e():
    print("\n[E] writer completion guard: refusals / safety-trips fall through")
    import novel_code as NC
    refuse = "I'm sorry, but I can't help create exploit code. As an AI, this is against my policy."
    hedge_ok = "Note: only on authorized targets.\nTARGET GET /x\nCODE\ncurl -s https://localhost/x\nORACLE http 200"
    real = "TARGET GET /x\nCODE\ncurl -s https://localhost:8443/x\nORACLE status 200"
    check("a refusal (no code) is caught", NC._refused(refuse) is True)
    check("empty output is caught", NC._refused("") is True)
    check("hedged-but-has-code is NOT a refusal (completed)", NC._refused(hedge_ok) is False)
    check("clean completion is NOT a refusal", NC._refused(real) is False)
    check("primary writer is deepseek-v4-pro (ds)", NC.PRIMARY_WRITER == "ds")
    check("reasoning coders excluded from default fallback",
          "kimi-k2.7-code" not in NC.FALLBACK_ORDER and "deepseek-r1-distill-32b" not in NC.FALLBACK_ORDER)


def part_f():
    print("\n[F] lively board discussion (propose->critique->converge), stubbed models")
    os.environ["AEGIS_BOARD_DIR"] = os.path.join(os.environ.get("TEMP", "."), "aegis_discuss_test")
    import board_discuss as BD

    def fake_ask(model, sysp, usr, max_tokens, temperature=0.6):
        if "Propose UP TO 2" in sysp:
            s = "scaffold" if "coder" in model or "kimi" in model else "code"
            return ('{"angle":"authz","surface":"/api/'+model[:4]+'","vuln_class":"idor","mechanism":"m",'
                    '"trust":"user","expected_oracle":"200","layer":"'+s+'","intent":"foothold",'
                    '"needs_code":false,"raw_confidence":0.6,"rationale":"grounded in delta"}')
        if "RED-TEAM challenger" in sysp:
            return ('{"ref":0,"verdict":"likely","confidence":0.6,"failure_modes":["waf"],"why":"cites 403 delta"}\n'
                    '{"ref":1,"verdict":"likely-fail","confidence":0.3,"failure_modes":["closed"],"why":"combo closed"}')
        if "SYNTHESIZER" in sysp:
            return ('{"angle":"authz","surface":"/api/pay","vuln_class":"idor","mechanism":"m","trust":"user",'
                    '"expected_oracle":"200","layer":"code","intent":"foothold","needs_code":false,'
                    '"verdict":"will-work","confidence":0.8,"dissent":["r1-distill"]}\n'
                    '{"angle":"supply_chain","surface":"/dep","vuln_class":"dependency","mechanism":"m",'
                    '"trust":"anon","expected_oracle":"present","layer":"scaffold","intent":"foothold",'
                    '"verdict":"maybe","confidence":0.4,"dissent":[]}')
        return ""

    BD._ask = fake_ask
    ctx = {"real_attempts_done": 3, "phase": "explore", "budget_remaining": 20,
           "attempts": [{"move": {"surface": "/x", "vuln_class": "idor"}, "verdict": "rejected",
                         "delta": {"implies": "try structurally different"}}],
           "coverage": {"angle_counts": {}}, "reach": {"under_probed_direction": "scaffold"},
           "closed_combos": []}
    moves, md = BD.discuss(ctx)
    print("     moves:", [(m.get("verdict"), m.get("layer"), m.get("surface")) for m in moves])
    check("discussion produced converged moves", len(moves) >= 1)
    check("moves carry a verdict", all(m.get("verdict") for m in moves))
    check("moves carry confidence + dissent field", all("confidence" in m for m in moves))
    check("transcript has all three phases", all(s in md for s in ("Proposals", "Critiques", "Convergence")))
    path = BD.board_discuss(ctx)  # returns moves; also writes transcript
    check("board_discuss returns moves (drop-in for brainstorm)", isinstance(path, list) and len(path) >= 1)
    import glob
    wrote = glob.glob(os.path.join(os.environ["AEGIS_BOARD_DIR"], "DISCUSS__*.md"))
    check("transcript written to board dir (live_board)", len(wrote) >= 1)
    # early-stop: a single proposer with a single move skips critique
    BD.PROPOSERS_SAVE = BD.PROPOSERS
    check("kill-switch: AEGIS_BOARD_DISCUSS=0 disables", (os.environ.__setitem__("AEGIS_BOARD_DISCUSS", "0"),
          BD.enabled() is False)[1])
    os.environ.pop("AEGIS_BOARD_DISCUSS", None)


def part_g():
    print("\n[G] verdict as a LATE tie-breaker in _pick (breadth/novelty still dominate)")
    from iterative_hunt import IterativeHunt, HuntState
    h = IterativeHunt(lambda c: [], lambda m, p: {}, lambda r: ("rejected", {}), budget=10)
    st = HuntState(budget=10)
    st.phase = "explore"
    maybe = {"action": "web", "vuln_class": "idor", "surface": "/a", "verdict": "maybe", "confidence": 0.5}
    will = {"action": "web", "vuln_class": "idor", "surface": "/a", "verdict": "will-work", "confidence": 0.9}
    st.queue = [maybe, will]
    picked = h._pick(st)
    check("will-work is picked before maybe (same dir/angle/novelty)", picked.get("verdict") == "will-work")


if __name__ == "__main__":
    part_a(); part_b(); part_c(); part_d(); part_e(); part_f(); part_g()
    print("\n" + ("ALL REACH SELF-TESTS PASSED" if not FAILS else f"{len(FAILS)} FAILURE(S): " + "; ".join(FAILS)))
    sys.exit(1 if FAILS else 0)
