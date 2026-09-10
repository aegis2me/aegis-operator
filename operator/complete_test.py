"""complete_test.py -- the AEGIS COMPLETE TEST: the default full assessment, all four stages across the
CROSS-MODE RELAY. This is what "run the complete test" means: not one leg, but the whole chain.

    L1 Operator   (tier 1, non-destructive)        -- discover + confirm footholds
      |  (campaign ledger: only ORACLE-CONFIRMED footholds hand off, deduped, tier-gated, re-confirmed)
    L2 ExploitGym (tier 2, + audit)                -- RESUME L1, go DEEPER (escalate), never re-walk
      |
    L3 Red-Team   (tier 3, + FAIL-CLOSED authorization/scope, deeper escalation budget)
      |
    L4 Remediation (board code-fixes, two audiences) -- fix every VERIFIED weakness

One engine, three modes, shared vectors (docs/ARCHITECTURE): each leg is the same iterative-hunt loop with a
different DOCTRINE WRAPPER and a higher permission tier, resuming the prior legs' confirmed footholds from the
shared campaign ledger (campaign_ledger.py) and spending its budget only on NEW depth. L3 is FAIL-CLOSED: the
target must be in the Rules-of-Engagement scope or the leg does not run.

All legs write to ONE findings ledger + heartbeat so the live monitor (run_monitor.py findings --follow) shows
findings landing across every leg. Offline-safe: a leg that errors is logged and the chain continues, so
remediation still runs over whatever was confirmed.

Usage:
    python operator/complete_test.py --role dispatcher --budget 50 --campaign complete-<id> \
        --auth redteam/authorization.local.json --report operator/complete_test_report.md
"""
from __future__ import annotations
import os, sys, json, time, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "shared"))
sys.path.insert(0, os.path.join(ROOT, "redteam"))

from iterative_hunt_live import run_hunt, BASE

_TIER = {"operator": 1, "exploitgym": 2, "redteam": 3}


def _log(msg):
    print(f"[complete-test] {msg}", flush=True)


def _scope_ok(auth_path, base):
    """FAIL-CLOSED authorization gate for the Red-Team leg: the target host must be in the RoE scope."""
    if not auth_path or not os.path.exists(auth_path):
        return False, f"no authorization file ({auth_path}) -- fail-closed, Red-Team leg skipped"
    try:
        from urllib.parse import urlparse
        host = urlparse(base).hostname or ""
        roe = json.load(open(auth_path, encoding="utf-8"))
        hosts = set((roe.get("scope") or {}).get("hosts") or [])
        if host in hosts:
            return True, f"host {host} in RoE scope ({sorted(hosts)})"
        return False, f"host {host} NOT in RoE scope {sorted(hosts)} -- fail-closed"
    except Exception as e:
        return False, f"authorization parse failed ({e}) -- fail-closed"


def _leg(level, *, objective, role, budget, campaign, store, base, extra_seeds=None, roe=None):
    """Run one relay leg via the shared engine at this level/tier, resuming prior confirmed footholds."""
    tier = _TIER[level]
    # Red-Team's deeper escalation budget from the RoE (escalate_frac / max_escalate_steps), env-passed.
    if level == "redteam" and roe:
        rules = roe.get("rules_of_engagement") or {}
        os.environ["AEGIS_ESCALATE_FRAC"] = str(rules.get("escalate_frac", 0.5))
        os.environ["AEGIS_MAX_ESCALATE_STEPS"] = str(rules.get("max_escalate_steps", 8))
    os.environ["AEGIS_AUDIT"] = "1" if level in ("exploitgym", "redteam") else "0"
    t0 = time.time()
    _log(f"=== LEG {tier} [{level}] start (budget={budget}, resume from prior confirmed footholds) ===")
    try:
        rep = run_hunt(objective, role, budget, store_path=store, base=base,
                       campaign=campaign, level=level, max_tier=tier, extra_seeds=extra_seeds)
    except Exception as e:
        _log(f"LEG {level} ERROR (chain continues): {e}")
        return {"level": level, "tier": tier, "error": str(e), "confirmed": []}
    conf = rep.get("confirmed") or []
    cov = rep.get("coverage", {})
    reach = rep.get("reach", {})
    _log(f"=== LEG {tier} [{level}] done in {time.time()-t0:.0f}s: confirmed={len(conf)} "
         f"coverage={cov.get('n_covered')}/{cov.get('n_total')} "
         f"both_dirs={reach.get('both_directions')} depth={reach.get('depth')} ===")
    return {"level": level, "tier": tier, "report": rep, "confirmed": conf}


def run_complete(*, role="dispatcher", budget=50, campaign=None, base=None,
                 auth_path=None, store=None, objective=None, report_path=None,
                 emit_fixes=True):
    base = base or os.environ.get("AEGIS_TARGET", BASE)
    campaign = campaign or f"complete-{int(time.time())}"
    store = store or os.path.join(HERE, "hunt_findings.jsonl")
    report_path = report_path or os.path.join(HERE, "complete_test_report.md")
    os.environ["AEGIS_CAMPAIGN"] = campaign
    os.environ["AEGIS_LEDGER"] = store            # so the live monitor follows THIS run's ledger
    objective = objective or ("COMPLETE cross-mode relay test: discover, confirm, then escalate deeper each "
                              "leg. Priorities: money-integrity (credit-note/deposit idempotency + invariant "
                              "+ TOCTOU), rebuilt authorization grid (second-route bypass, response leakage, "
                              "field over-read, settings cross-write, row scoping), supply-chain CVEs. "
                              "Non-destructive: plant, never delete.")
    _log(f"campaign={campaign}  target={base}  role={role}  budget/leg={budget}  ledger={store}")

    results = []
    # ---- L1 Operator ----
    results.append(_leg("operator", objective=objective, role=role, budget=budget,
                        campaign=campaign, store=store, base=base))
    # ---- L2 ExploitGym (resume L1) ----
    results.append(_leg("exploitgym", objective=objective, role=role, budget=budget,
                        campaign=campaign, store=store, base=base))
    # ---- L3 Red-Team (resume L1+L2), FAIL-CLOSED ----
    roe = None
    ok, why = _scope_ok(auth_path, base)
    _log(f"Red-Team authorization: {why}")
    if ok:
        try:
            roe = json.load(open(auth_path, encoding="utf-8"))
        except Exception:
            roe = None
        results.append(_leg("redteam", objective=objective, role=role, budget=budget,
                            campaign=campaign, store=store, base=base, roe=roe))
    else:
        results.append({"level": "redteam", "tier": 3, "skipped": why, "confirmed": []})

    # ---- L4 Remediation (board code-fixes over the campaign's confirmed findings) ----
    _log("=== STAGE 4 [remediation] board code-fixes over all verified findings ===")
    rem_report = os.path.join(HERE, "complete_test_remediation.md")
    rem_cmd = [sys.executable, os.path.join(HERE, "remediation_board.py"),
               "--findings", store, "--panel", "ds,cf,qwen", "--synthesize",
               "--report", rem_report, "--write-ledger"]
    if emit_fixes:
        rem_cmd.append("--emit-fixes")
    try:
        r = subprocess.run(rem_cmd, cwd=ROOT, capture_output=True, text=True, timeout=2400)
        _log(f"remediation exit={r.returncode}; report={rem_report}")
        rem_ok = (r.returncode == 0)
    except Exception as e:
        _log(f"remediation ERROR: {e}")
        rem_ok = False

    summary = _write_report(results, campaign, base, report_path, rem_report if rem_ok else None)
    _log(f"COMPLETE TEST done. report -> {report_path}")
    return summary


def _write_report(results, campaign, base, report_path, rem_report):
    lines = [f"# AEGIS Complete Test -- cross-mode relay", "",
             f"_Target **{base}** | campaign `{campaign}` | {time.strftime('%Y-%m-%d %H:%M')}_", "",
             "Four stages across the cross-mode relay: each leg RESUMES the prior legs' oracle-confirmed "
             "footholds from the shared campaign ledger and goes DEEPER. One engine, three modes, one campaign.", ""]
    lines.append("## Relay legs")
    lines.append("")
    lines.append("| Leg | Tier | Status | Confirmed (this leg) | Coverage | Both dirs | Depth |")
    lines.append("|---|---|---|---|---|---|---|")
    total_conf = 0
    for r in results:
        lvl = r["level"]; tier = r["tier"]
        if r.get("skipped"):
            lines.append(f"| {lvl} | {tier} | SKIPPED ({r['skipped'][:40]}) | 0 | - | - | - |")
            continue
        if r.get("error"):
            lines.append(f"| {lvl} | {tier} | ERROR ({r['error'][:40]}) | 0 | - | - | - |")
            continue
        rep = r.get("report", {}); cov = rep.get("coverage", {}); reach = rep.get("reach", {})
        n = len(r.get("confirmed", [])); total_conf += n
        lines.append(f"| {lvl} | {tier} | ok | {n} | {cov.get('n_covered')}/{cov.get('n_total')} "
                     f"| {reach.get('both_directions')} | {reach.get('depth')} |")
    lines.append("")
    lines.append(f"**Total confirmed footholds across the relay: {total_conf}** (deduped in the campaign ledger; "
                 "later legs escalate rather than re-find).")
    lines.append("")
    lines.append("See the tier-grouped findings in `tier_report.md` (run tier_report.py on this ledger) and the "
                 "code recommendations below.")
    lines.append("")
    if rem_report and os.path.exists(rem_report):
        lines.append("## Stage 4 -- Remediation & code recommendations")
        lines.append("")
        lines.append(f"Full two-audience remediation (admin updates + code-writer patches): `{os.path.basename(rem_report)}`")
        lines.append("")
        try:
            rem = open(rem_report, encoding="utf-8").read()
            head = rem[:4000]
            lines.append("<details><summary>remediation report (head)</summary>\n")
            lines.append(head)
            lines.append("\n</details>")
        except Exception:
            pass
    md = "\n".join(lines) + "\n"
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(md)
    return {"campaign": campaign, "legs": results, "report": report_path,
            "remediation": rem_report, "total_confirmed": total_conf}


def main():
    import argparse
    ap = argparse.ArgumentParser(description="AEGIS complete test -- 4-stage cross-mode relay")
    ap.add_argument("--role", default="dispatcher")
    ap.add_argument("--budget", type=int, default=50, help="budget PER LEG")
    ap.add_argument("--campaign", default=None)
    ap.add_argument("--target", default=None)
    ap.add_argument("--auth", default=os.path.join(ROOT, "redteam", "authorization.local.json"),
                    help="Red-Team Rules-of-Engagement (fail-closed; leg skipped if target not in scope)")
    ap.add_argument("--store", default=None)
    ap.add_argument("--report", default=None)
    ap.add_argument("--no-fixes", action="store_true", help="skip --emit-fixes in remediation")
    a = ap.parse_args()
    out = run_complete(role=a.role, budget=a.budget, campaign=a.campaign, base=a.target,
                       auth_path=a.auth, store=a.store, report_path=a.report, emit_fixes=not a.no_fixes)
    print(json.dumps({"campaign": out["campaign"], "total_confirmed": out["total_confirmed"],
                      "report": out["report"]}, indent=2, default=str))
    print("COMPLETE TEST EXIT: 0")


if __name__ == "__main__":
    main()
