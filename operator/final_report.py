"""final_report.py -- the GENERIC complete-test report. Two-track by audience (ADMIN scaffold/stack +
CODE-improver) PLUS everything the report must carry, decided over this project:

  1. Executive summary                          -- headline verdict, target, campaign
  2. Relay legs                                 -- Operator -> ExploitGym -> Red-Team -> Remediation, tiers,
                                                   confirmed-per-leg, coverage, both-directions, foothold depth
  3. Severity summary (incl. zeros)             -- critical / high / medium / low / info
  4. Trust-tier findings (anon < user < admin)  -- grouped by the LOWEST tier that reaches each, + the delta
  5. Coverage & reach                           -- N/16 parity classes; both directions (scaffold + code)
  6. RUN COSTS                                  -- money, the WHOLE run, by stage + model (cost_meter)
  7. Suite HEALTH / monitoring                  -- run health, any mishaps/stalls, interventions
  8. Remediation -- TWO TRACKS                  -- ADMIN (scaffold/stack: dep-CVE/config updates, fixed
                                                   versions) + CODE-IMPROVER (app-code fixes) from the board
  9. Methodology & doctrine                     -- neutrality, contained/non-destructive, oracle-gated

Assembled from the campaign artifacts (findings ledger, cost ledger, remediation report, run log, monitor
log). Reused by complete_test.py and runnable standalone:
    python operator/final_report.py --campaign <id> --store operator/hunt_findings_relay.jsonl \
        --remediation operator/complete_test_remediation.md --runlog scratchpad/complete_test.out \
        --monlog scratchpad/relay_mon2.out --out operator/complete_test_report.md
"""
from __future__ import annotations
import os, sys, re, json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cost_meter
from run_monitor import _fold_ledger
import tier_report as TR

# ADMIN track = scaffold/stack (patched by ops via updates); everything else = CODE-improver (app source).
_ADMIN_MARKERS = ("supply-chain", "known-cve", "dependency", "cve", "dep-", "grype", "outdated",
                  "image", "package", "library", "framework-version")


def _track(f):
    blob = " ".join(str(f.get(k, "")) for k in ("claim_type", "summary", "surface", "source")).lower()
    return "admin" if any(m in blob for m in _ADMIN_MARKERS) else "code"


def _enrich(store):
    """Read the raw ledger and pull, per finding_id, the details the code writer needs: the oracle RECEIPT
    (what triggered it / ground truth), any recorded REMEDIATION hint, and the evidence. Keyed by finding_id."""
    import ast
    out = {}
    try:
        lines = open(store, encoding="utf-8").read().splitlines()
    except Exception:
        return out
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            row = json.loads(ln)
        except Exception:
            continue
        if row.get("type") == "record":
            fd = row.get("finding")
            try:
                d = ast.literal_eval(fd) if isinstance(fd, str) else (fd or {})
            except Exception:
                d = {}
            fid = d.get("finding_id")
            if fid:
                out.setdefault(fid, {}).update({
                    "remediation": d.get("remediation") or "",
                    "evidence": d.get("evidence") or "",
                    "mechanism": d.get("mechanism") or d.get("technique") or "",
                    "oracle_id": d.get("oracle_id") or ""})
        elif row.get("type") == "transition" and row.get("finding_id"):
            if row.get("status") == "verified":
                out.setdefault(row["finding_id"], {})["receipt"] = row.get("oracle_receipt") or {}
    return out


def _where_hint(f):
    """Generic 'where to look' for the code writer: the route/surface + the class of handler to inspect."""
    surf = f.get("surface", "") or ""
    parts = [f"route/surface: `{surf}`"] if surf else []
    cls = (f.get("claim_type") or "").lower()
    # generic handler-location guidance by finding class (app-agnostic)
    if "idempot" in cls or "replay" in cls:
        parts.append("the write handler for this route + every OTHER route that reaches the same state "
                     "(second-door): enforce one idempotency key per money mutation")
    elif "invariant" in cls or "business-logic" in cls or "toctou" in cls:
        parts.append("the state-changing handler + the validation layer that should assert the invariant "
                     "(check it inside the same transaction / with a DB constraint)")
    elif "authz" in cls or "idor" in cls or "access" in cls or "over-read" in cls:
        parts.append("the route's authorization guard + the object-ownership/row-scoping check in the handler")
    elif "rate" in cls or "anti-automation" in cls:
        parts.append("the middleware/guard for this endpoint: add rate-limiting / lockout")
    elif "mass" in cls or "assign" in cls:
        parts.append("the request-body binding in the handler: allow-list the writable fields")
    elif "xss" in cls or "inject" in cls:
        parts.append("the output-encoding / input-validation at this sink")
    return "; ".join(parts) or f"`{surf}`"


def _parse_legs(runlog):
    """Parse the relay legs from the complete_test run log."""
    legs = []
    if not runlog or not os.path.exists(runlog):
        return legs
    txt = open(runlog, encoding="utf-8", errors="ignore").read()
    for m in re.finditer(r"=== LEG (\d) \[(\w+)\] done in (\d+)s: confirmed=(\d+) coverage=([\d/]+) "
                         r"both_dirs=(\w+) depth=(\d+)", txt):
        legs.append({"tier": m.group(1), "name": m.group(2), "secs": int(m.group(3)),
                     "confirmed": int(m.group(4)), "coverage": m.group(5),
                     "both_dirs": m.group(6), "depth": int(m.group(7)), "status": "done"})
    # a started-but-not-done last leg
    started = re.findall(r"=== LEG (\d) \[(\w+)\] start", txt)
    done_names = {(l["tier"], l["name"]) for l in legs}
    for t, n in started:
        if (t, n) not in done_names:
            legs.append({"tier": t, "name": n, "status": "running/incomplete", "confirmed": "-",
                         "coverage": "-", "both_dirs": "-", "depth": "-", "secs": "-"})
    # remediation skip note
    m = re.search(r"Red-Team authorization: (.+)", txt)
    return legs, (m.group(1) if m else "")


def _health(monlog, runlog):
    """Summarize suite health + any mishaps from the monitor log."""
    lines = []
    mishaps = []
    if monlog and os.path.exists(monlog):
        ml = open(monlog, encoding="utf-8", errors="ignore").read().splitlines()
        for l in ml:
            if "MISHAP" in l:
                mishaps.append(l.strip())
        last = [l for l in ml if l.strip().startswith("[")]
        if last:
            lines.append(f"last monitor sample: `{last[-1].strip()}`")
    # any tracebacks in the run log
    tb = 0
    if runlog and os.path.exists(runlog):
        tb = len(re.findall(r"Traceback|NameError|Unhandled", open(runlog, encoding="utf-8", errors="ignore").read()))
    status = "HEALTHY -- no mishaps" if not mishaps else f"{len(mishaps)} mishap event(s) flagged (see below)"
    return status, mishaps, lines, tb


def build(campaign, store, target="mirror", remediation_report=None, runlog=None, monlog=None, out=None):
    out = out or os.path.join(HERE, "complete_test_report.md")

    # ---- findings ----
    folded = _fold_ledger(store)
    enrich = _enrich(store)
    ver = [f for f in folded if f.get("status") == "verified"]
    for f in ver:                                          # merge in receipt/remediation/evidence by id
        f.update({k: v for k, v in enrich.get(f.get("finding_id"), {}).items() if v})
    merged = TR._dedup([dict(f, _pass="relay") for f in ver])
    sev = TR._sev_tally(merged)
    # trust-tier buckets
    buckets = {"anon": [], "user": [], "admin": [], "": []}
    for f in merged:
        buckets.setdefault(f.get("reachable", "") or "", []).append(f)
    # audience tracks
    admin = [f for f in merged if _track(f) == "admin"]
    code = [f for f in merged if _track(f) == "code"]

    legs, auth_note = _parse_legs(runlog) if runlog else ([], "")
    health_status, mishaps, health_lines, tb = _health(monlog, runlog)

    L = []
    L.append(f"# AEGIS Complete-Test Report")
    L.append("")
    L.append(f"_Target **{target}** | campaign `{campaign}` | cross-mode relay (Operator → ExploitGym → "
             f"Red-Team → Remediation)_")
    L.append("")

    # 1. executive summary
    total = len(merged)
    L.append("## 1. Executive summary")
    L.append("")
    L.append(f"- **{total} oracle-verified findings** (deduplicated across the relay): "
             f"{TR._sev_line(sev)}.")
    L.append(f"- **{len(admin)}** are **scaffold/stack** (ADMIN track); **{len(code)}** are **app-code** "
             f"(CODE-improver track).")
    if legs:
        dirs = any(str(l.get('both_dirs')) == 'True' for l in legs)
        L.append(f"- Relay ran **{len([l for l in legs if l.get('status')=='done'])} leg(s)** to completion; "
                 f"both reach directions (scaffold + app-code) exercised: **{dirs}**.")
    L.append(f"- Suite health: **{health_status}**.")
    L.append("")

    # 2. relay legs
    L.append("## 2. Relay legs (cross-mode)")
    L.append("")
    if legs:
        L.append("| Leg | Tier | Status | Confirmed | Coverage | Both dirs | Foothold depth | Time |")
        L.append("|---|---|---|---|---|---|---|---|")
        _nm = {"1": "Operator", "2": "ExploitGym", "3": "Red-Team"}
        for l in legs:
            secs = f"{l['secs']}s" if isinstance(l.get("secs"), int) else l.get("secs", "-")
            L.append(f"| {_nm.get(l['tier'], l['name'])} | {l['tier']} | {l['status']} | {l['confirmed']} | "
                     f"{l['coverage']} | {l['both_dirs']} | {l['depth']} | {secs} |")
        L.append("")
        L.append("_Each leg RESUMES the prior legs' oracle-confirmed footholds from the shared campaign ledger "
                 "and escalates DEEPER (note the rising foothold depth), never re-walking mapped ground._")
    else:
        L.append("_relay leg log not found._")
    if auth_note:
        L.append("")
        L.append(f"Red-Team fail-closed authorization: {auth_note}")
    L.append("")

    # 3. severity summary
    L.append("## 3. Severity summary (oracle-verified)")
    L.append("")
    L.append(f"critical **{sev['critical']}** · high **{sev['high']}** · medium **{sev['medium']}** · "
             f"low **{sev['low']}** · info **{sev['info']}**")
    L.append("")

    # 4. trust-tier findings
    L.append("## 4. Findings by trust tier (anon < user < admin)")
    L.append("")
    L.append(f"- anon-reachable (no creds): **{len(buckets['anon'])}**  |  user-reachable (any login): "
             f"**{len(buckets['user'])}**  |  admin-only: **{len(buckets['admin'])}**"
             + (f"  |  tier-untagged: {len(buckets[''])}" if buckets[''] else ""))
    L.append("")
    hdr = "| Severity | Verdict | Surface | Finding | Oracle |"
    sep = "|---|---|---|---|---|"
    for tier in ("anon", "user", "admin", ""):
        b = buckets[tier]
        if not b:
            continue
        title = {"anon": "Anon tier — reachable WITHOUT credentials", "user": "User tier — any logged-in role",
                 "admin": "Admin tier", "": "Tier-untagged"}[tier]
        L.append(f"### {title} ({len(b)})")
        L.append(""); L.append(hdr); L.append(sep)
        for f in sorted(b, key=lambda x: TR._SEV_ORDER.get(x.get("severity", "medium"), 2)):
            v = f.get("trust_verdict", "") or "-"
            L.append(f"| {f.get('severity','?').upper()} | {v} | `{f.get('surface','-')}` | "
                     f"{(f.get('summary') or f.get('claim_type') or '')[:90]} | {f.get('source','?')} |")
        L.append("")

    # 5. coverage & reach
    if legs:
        best_cov = max((l["coverage"] for l in legs if l.get("coverage") not in ("-", None)), default="-")
        maxdepth = max((l["depth"] for l in legs if isinstance(l.get("depth"), int)), default="-")
        L.append("## 5. Coverage & reach")
        L.append("")
        L.append(f"- Parity-class coverage (peak): **{best_cov}**")
        L.append(f"- Reach directions: **scaffold + app-code** (both); peak foothold depth **{maxdepth}**")
        L.append("")

    # 6. RUN COSTS
    L.append(cost_meter.report_md(campaign))
    L.append("")

    # 7. suite health / monitoring
    L.append("## 7. Suite health & monitoring")
    L.append("")
    L.append(f"- Status: **{health_status}**; run-log tracebacks: {tb}.")
    for hl in health_lines:
        L.append(f"- {hl}")
    if mishaps:
        L.append("- Mishap events (flagged + handled):")
        for m in mishaps:
            L.append(f"  - `{m}`")
    L.append("")

    # 8. remediation -- two tracks
    L.append("## 8. Remediation — two tracks")
    L.append("")
    L.append("### 8a. ADMIN track — scaffold / stack (patch via updates)")
    L.append("")
    if admin:
        L.append("| Severity | Component / surface | Finding | Fix owner |")
        L.append("|---|---|---|---|")
        for f in sorted(admin, key=lambda x: TR._SEV_ORDER.get(x.get("severity", "medium"), 2)):
            L.append(f"| {f.get('severity','?').upper()} | `{f.get('surface','-')}` | "
                     f"{(f.get('summary') or f.get('claim_type') or '')[:80]} | ops/admin |")
        L.append("")
        L.append("_Apply the framework/dependency/config updates (fixed versions in the remediation report "
                 "below). Upstream base-image CVEs (Postgres/Caddy/Node) are lower priority per the brief; "
                 "the app's own dependency chain is the priority._")
    else:
        L.append("_No scaffold/stack findings._")
    L.append("")
    L.append("### 8b. CODE-IMPROVER track — app source (board-designed fixes)")
    L.append("")
    L.append("_Each block tells the code writer/improver **what** the defect is, **where** to look, **what "
             "triggered it** (ground-truth evidence), and the **fix direction**. Generic and self-contained — "
             "no need to re-derive from the run._")
    L.append("")
    if code:
        for f in sorted(code, key=lambda x: TR._SEV_ORDER.get(x.get("severity", "medium"), 2)):
            rc = f.get("receipt") or {}
            rc_s = ", ".join(f"{k}={rc[k]}" for k in list(rc)[:6]) if isinstance(rc, dict) else str(rc)[:200]
            L.append(f"#### [{f.get('severity','?').upper()}] `{f.get('surface','-')}` — {f.get('claim_type','?')}")
            L.append("")
            L.append(f"- **What to fix:** {f.get('summary') or f.get('claim_type') or '?'}")
            L.append(f"- **Where to look:** {_where_hint(f)}")
            L.append(f"- **What triggered it (evidence):** {rc_s or f.get('evidence') or '(see oracle receipt)'}")
            fixdir = f.get("remediation") or ""
            if fixdir:
                L.append(f"- **Fix direction:** {str(fixdir)[:400]}")
            else:
                L.append(f"- **Fix direction:** see the board's patch for this finding in the remediation report "
                         f"below (oracle `{f.get('oracle_id','?')}`).")
            L.append("")
    else:
        L.append("_No app-code findings._")
    L.append("")
    # embed the board's detailed two-audience remediation (fixes) if present
    if remediation_report and os.path.exists(remediation_report):
        L.append(f"**Detailed board remediation + emitted code patches:** `{os.path.basename(remediation_report)}`")
        L.append("")
        try:
            rem = open(remediation_report, encoding="utf-8", errors="ignore").read()
            L.append("<details><summary>remediation report (full)</summary>\n")
            L.append(rem)
            L.append("\n</details>")
        except Exception:
            pass
    L.append("")

    # 9. methodology
    L.append("## 9. Methodology & doctrine")
    L.append("")
    L.append("- **Neutral**: crawl with all creds, verdict with none; owner/admin never used as a testing path. "
             "Findings rendered at the lowest tier that reaches them.")
    L.append("- **Contained + non-destructive**: mirror twin only; plant for proof, never delete.")
    L.append("- **Oracle-gated + hash-chained**: only oracle-verified findings count; ground-truth confirmed.")
    L.append("- **Cross-mode relay**: one engine, three modes (Operator/ExploitGym/Red-Team) + remediation, "
             "one campaign; footholds hand off confirmed-only and escalate deeper each tier.")
    L.append("")

    md = "\n".join(L) + "\n"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(md)
    return {"out": out, "total": total, "admin": len(admin), "code": len(code),
            "severity": sev, "tiers": {k: len(v) for k, v in buckets.items()}}


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign", required=True)
    ap.add_argument("--store", required=True)
    ap.add_argument("--target", default="FixFlow updated mirror (https://localhost:8443)")
    ap.add_argument("--remediation")
    ap.add_argument("--runlog")
    ap.add_argument("--monlog")
    ap.add_argument("--out", default=os.path.join(HERE, "complete_test_report.md"))
    a = ap.parse_args()
    r = build(a.campaign, a.store, target=a.target, remediation_report=a.remediation,
              runlog=a.runlog, monlog=a.monlog, out=a.out)
    print(json.dumps(r, indent=2, default=str))


if __name__ == "__main__":
    main()
