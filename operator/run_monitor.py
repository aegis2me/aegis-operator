"""run_monitor.py -- HANG detection + progress observability for a long (up to ~1.5h) hunt run.

The loop's adaptive stop (MECH5), max_no_progress, and the wall-clock budget are all checked BETWEEN
attempts -- so a SINGLE wedged probe (a timeout that never fires, a stuck subprocess, a future headless
browser) freezes the whole run and none of them fire. This is the board-converged minimum that removes the
"wait 1.5h on a dead run" risk (STALL is already handled by MECH5; this is purely HANG + observability):

  1. PER-ATTEMPT HARD TIMEOUT  -- the load-bearing fix. Each attempt runs under a deadline; a hung attempt
     is ABANDONED and the run continues (never frozen). Class-aware timeout (a grype/headless leg gets more).
  2. HEARTBEAT file            -- atomic JSON keyed on `last_event_at`, bumped on leg START and attempt
     complete, so a slow-but-alive leg is distinguishable from a hang and the run is observable/ tailable.
  3. IN-PROCESS WATCHDOG       -- if `last_event_at` goes stale beyond T_stale, sets a stop flag so the loop
     FINALIZES PARTIAL results (never loses confirmed findings). An external killer (optional) is the backstop
     for a watchdog that is itself wedged.

Kill-switch: AEGIS_MONITOR=0. Pure-stdlib, offline-safe: monitoring only observes/aborts, never touches the
target (non-destructive).
"""
from __future__ import annotations
import json, os, threading, time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FTimeout

# Per-leg (action) hard-timeout seconds: slow-but-legitimate legs get more headroom (board: ~2x p99).
_LEG_TIMEOUT = {
    "supply_chain": 600, "ossfuzz": 900, "fuzz": 900, "static": 300, "recon": 300,
    "stateful": 300, "resource_persistence": 300, "idor": 240, "differential": 180,
    "rate": 180, "session_fixation": 90, "open_redirect": 120, "mass_assign": 120,
    "security_headers": 60, "web": 60, "probe": 180, "misconfig": 180, "rag": 120,
}
_DEFAULT_TIMEOUT = 90
_HEADLESS_TIMEOUT = 1200          # future DOM/headless leg


def leg_timeout(move) -> float:
    a = str((move or {}).get("action", "web"))
    if (move or {}).get("headless") or a in ("dom", "xss_dom", "xss"):
        return _HEADLESS_TIMEOUT
    try:
        return float(os.environ.get("AEGIS_ATTEMPT_TIMEOUT", "")) or _LEG_TIMEOUT.get(a, _DEFAULT_TIMEOUT)
    except Exception:
        return _LEG_TIMEOUT.get(a, _DEFAULT_TIMEOUT)


def run_attempt(fn, timeout):
    """Run fn() under a hard deadline. Returns (result, hung: bool). A hung attempt is ABANDONED (the worker
    thread is not force-killed -- Python can't -- but the run continues; the leg's own per-op timeouts and,
    for subprocess/headless legs, process-level kills are the primary bound; this is the backstop that
    prevents a FREEZE). Never raises fn's exception as a freeze."""
    ex = ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(fn)
    try:
        return fut.result(timeout=timeout), False
    except _FTimeout:
        return None, True
    except Exception as e:
        return {"status": -1, "body": f"[attempt error] {e}"}, False
    finally:
        ex.shutdown(wait=False)        # abandon a hung worker rather than blocking on it


class RunMonitor:
    """Heartbeat + in-process watchdog. beat() on every leg start + attempt complete; should_stop() is
    checked by the loop to finalize partial results on staleness."""
    def __init__(self, run_id="", path=None, stale_after=None, wall_budget=None):
        here = os.path.dirname(os.path.abspath(__file__))
        self.path = path or os.environ.get("AEGIS_HEARTBEAT") or os.path.join(here, "run_heartbeat.json")
        self.run_id = run_id or ("run-" + str(int(time.time())))
        self.enabled = str(os.environ.get("AEGIS_MONITOR", "1")).lower() not in ("0", "false", "no", "off")
        self.start = time.time()
        self.last_event = self.start
        try:
            self.wall_budget = float(wall_budget or os.environ.get("AEGIS_WALLCLOCK_BUDGET", "3600"))
        except Exception:
            self.wall_budget = 3600.0
        # T_stale: max legit leg timeout + grace, unless overridden. The watchdog only trips on a genuine
        # no-progress freeze (last_event bumped at leg start, so a slow-but-alive leg won't trip it).
        try:
            self.stale_after = float(stale_after or os.environ.get("AEGIS_STALE_AFTER", "")) or (max(_LEG_TIMEOUT.values()) + 120)
        except Exception:
            self.stale_after = max(_LEG_TIMEOUT.values()) + 120
        self.state = {"run_id": self.run_id, "pid": os.getpid(), "state": "running", "stage": os.environ.get("AEGIS_STAGE", "operator"),
                      "attempt": 0, "attempts_hung": 0, "current_leg": None, "last_event": "start", "last_error": None}
        self._stop = threading.Event()
        self._stop_reason = None
        self._wd = None
        if self.enabled:
            self._write()
            self._wd = threading.Thread(target=self._watch, daemon=True)
            self._wd.start()

    def beat(self, event, **fields):
        if not self.enabled:
            return
        self.last_event = time.time()
        self.state.update(fields)
        self.state["last_event"] = event
        self._write()

    def _write(self):
        try:
            self.state["last_event_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.last_event))
            self.state["wall_clock_elapsed_s"] = round(time.time() - self.start, 1)
            self.state["wall_clock_budget_s"] = self.wall_budget
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.state, fh, indent=1, default=str)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def _watch(self):
        poll = min(5.0, max(0.5, self.stale_after / 3.0))     # fine enough to catch short thresholds
        while not self._stop.is_set():
            time.sleep(poll)
            now = time.time()
            if now - self.last_event > self.stale_after:
                self._stop_reason = "watchdog_stale"; self._stop.set()
                self.state["state"] = "stale"; self._write(); return
            if now - self.start > self.wall_budget:
                self._stop_reason = "wall_clock_budget"; self._stop.set()
                self.state["state"] = "wall_clock"; self._write(); return

    def should_stop(self):
        return self.enabled and self._stop.is_set()

    def stop_reason(self):
        return self._stop_reason

    def close(self, state="done"):
        self._stop.set()
        if self.enabled:
            self.state["state"] = state; self._write()


# ---------------- MID-RUN LIVE VIEW: suite HEALTH + FINDINGS table (read-only) ----------------
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _fold_ledger(path):
    """Read the findings ledger (hash-chained source of truth, cross-stage) read-only and fold record +
    transition lines by finding_id (last transition wins). Tolerates a partially-written last line."""
    import json as _j, ast, re as _re
    recs = {}
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except Exception:
        return []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            row = _j.loads(ln)
        except Exception:
            continue                                   # skip a partial/corrupt line
        t = row.get("type")
        if t == "record":
            f = row.get("finding")
            try:
                d = ast.literal_eval(f) if isinstance(f, str) else (f or {})
            except Exception:
                d = {}
            fid = d.get("finding_id") or row.get("finding_id")
            if not fid:
                continue
            surface = ""; reachable = ""; intended = ""; tverdict = ""
            for tag in (d.get("coverage_tags") or []):
                st = str(tag)
                if st.startswith("surface:"):
                    surface = st.split(":", 1)[1]
                elif st.startswith("trust-reachable:"):
                    reachable = st.split(":", 1)[1]
                elif st.startswith("trust-intended:"):
                    intended = st.split(":", 1)[1]
                elif st.startswith("trust-verdict:"):
                    tverdict = st.split(":", 1)[1]
            prov = d.get("provenance") or {}
            recs.setdefault(fid, {}).update({
                "finding_id": fid, "claim_type": d.get("claim_type", "?"),
                "severity": str(d.get("severity", "medium")).lower(), "summary": d.get("summary", ""),
                "source": prov.get("provider", "?"), "layer": prov.get("layer", ""), "surface": surface,
                "reachable": reachable, "intended": intended, "trust_verdict": tverdict,
                "created_at": row.get("ts", "")})
        elif t == "transition":
            fid = row.get("finding_id")
            if fid:
                recs.setdefault(fid, {}).update({"status": row.get("status"), "verified_at": row.get("ts", "")})
    return list(recs.values())


def _tally(findings):
    t = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "leads": 0}
    for f in findings:
        if f.get("status") == "verified":
            t[f.get("severity", "medium") if f.get("severity") in t else "medium"] += 1
        elif f.get("status") == "candidate" and "lead" in str(f.get("claim_type", "")):
            t["leads"] += 1
    return t


def _health(heartbeat_path):
    """Classify suite health from the heartbeat (read-only): RUNNING / STALE / STOPPED / DONE / ABORTED,
    with a staleness clock so the human can INTERVENE. Uses both the declared state and the file's freshness
    (a process that died mid-run stops updating the file, so mtime staleness => STOPPED)."""
    import json as _j
    try:
        hb = _j.load(open(heartbeat_path, encoding="utf-8"))
    except Exception:
        return {"status": "NO HEARTBEAT", "banner": "!! suite NOT RUNNING / not started (no heartbeat file)",
                "detail": {}}
    try:
        file_age = time.time() - os.path.getmtime(heartbeat_path)
    except Exception:
        file_age = 0
    state = str(hb.get("state", "?"))
    stale_after = 300
    if state == "done":
        status, banner = "DONE", "run complete"
    elif state in ("stale",):
        status, banner = "STALE", "!! WATCHDOG STALE -- a probe hung; run finalized partial. INTERVENE"
    elif state in ("wall_clock", "aborted"):
        status, banner = "ABORTED", f"run aborted ({state})"
    elif file_age > stale_after:
        status, banner = "STOPPED?", f"!! no heartbeat update for {int(file_age)}s -- process may have STOPPED. INTERVENE"
    else:
        status, banner = "RUNNING", f"running (last event {int(file_age)}s ago)"
    return {"status": status, "banner": banner, "detail": hb, "file_age": int(file_age)}


def render_view(ledger=None, heartbeat=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ledger = ledger or os.environ.get("AEGIS_LEDGER") or os.path.join(here, "hunt_findings.jsonl")
    heartbeat = heartbeat or os.environ.get("AEGIS_HEARTBEAT") or os.path.join(here, "run_heartbeat.json")
    h = _health(heartbeat); hb = h["detail"]
    findings = _fold_ledger(ledger)
    ver = [f for f in findings if f.get("status") == "verified"]
    ver.sort(key=lambda f: (_SEV_ORDER.get(f.get("severity"), 5), f.get("verified_at", "")), reverse=False)
    t = _tally(findings)
    L = []
    L.append("=" * 78)
    L.append(f" AEGIS RUN -- HEALTH: {h['status']:9}  |  {h['banner']}")
    if hb:
        L.append(f"   stage={hb.get('stage','?')} phase={hb.get('last_event','?')} attempt={hb.get('attempt','?')}"
                 f" leg={hb.get('current_leg','-')} surface={hb.get('current_surface','-')}")
        L.append(f"   wall={hb.get('wall_clock_elapsed_s','?')}s / {hb.get('wall_clock_budget_s','?')}s"
                 f"  hung={hb.get('attempts_hung',0)}  coverage={hb.get('coverage','?')} classes")
    L.append("-" * 78)
    L.append(f" FINDINGS (verified): critical {t['critical']} | high {t['high']} | medium {t['medium']}"
             f" | low {t['low']}   (+ leads {t['leads']}, info {t['info']})")
    # TRUST-TIER breakdown (assumed-access guard): show findings by the LOWEST tier that reaches them, and
    # flag EXPLOITABLE (reachable < intended) vs INTENDED (admin-doing-admin etc. -- not a real gap).
    expl = [f for f in ver if f.get("trust_verdict") == "exploitable"]
    by_tier = {"anon": 0, "user": 0, "admin": 0}
    for f in ver:
        r = f.get("reachable") or ""
        if r in by_tier:
            by_tier[r] += 1
    L.append(f" TRUST TIERS (reachable-by): anon {by_tier['anon']} | user {by_tier['user']} |"
             f" admin {by_tier['admin']}   ->  EXPLOITABLE (reachable<intended): {len(expl)}"
             f"  (admin-intended shown as context)")
    L.append("-" * 78)
    if ver:
        L.append(f" {'SEV':8} {'REACH':6} {'INT':6} {'EXPL':5} {'CLASS':24} SURFACE")
        for f in ver:
            ex = "YES" if f.get("trust_verdict") == "exploitable" else ("int" if f.get("trust_verdict") == "intended" else "-")
            L.append(f" {f.get('severity','?'):8} {str(f.get('reachable',''))[:6]:6} {str(f.get('intended',''))[:6]:6}"
                     f" {ex:5} {str(f.get('claim_type','?'))[:24]:24} {str(f.get('surface',''))[:26]}")
    else:
        L.append(" (no verified findings yet)")
    L.append("=" * 78)
    return "\n".join(L)


def findings_cli(follow=False, ledger=None, heartbeat=None, interval=None):
    if interval is None:
        try:
            interval = int(os.environ.get("AEGIS_VIEW_INTERVAL", "20"))   # default refresh 20s
        except Exception:
            interval = 20
    if not follow:
        print(render_view(ledger, heartbeat)); return
    try:
        while True:
            out = render_view(ledger, heartbeat)
            os.system("cls" if os.name == "nt" else "clear")
            print(out, flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    cmd = args[0] if args else "findings"
    follow = ("--follow" in args or "-f" in args)
    if cmd in ("findings", "view", "status"):
        findings_cli(follow=follow)
    else:
        print("usage: run_monitor.py findings [--follow]   # live suite HEALTH + FINDINGS table (read-only)")
