#!/usr/bin/env python3
"""
redteam.py -- the THIRD run option (beside Operator and ExploitGym), under the changed doctrine
(redteam/DOCTRINE.md): authorization-gated, owned live targets, RoE-bound. This is the first-class
pen-test path.

Every action passes `Authorization.guard(action, target, payload)` BEFORE it runs -- out-of-scope,
disallowed, expired, or destructive-without-RoE actions are blocked, audited, and never executed. It
reuses the persistent iterative-hunt loop (operator/iterative_hunt.py) with a SCOPE-ENFORCING
executor, plus a recon/ASM leg and a pluggable network-exploitation driver.

Fail-closed: no valid authorization ⇒ nothing runs.

Usage:
    python redteam/redteam.py --auth redteam/authorization.json --objective "..." --target <in-scope host>
"""
from __future__ import annotations

import argparse, json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "operator"))
sys.path.insert(0, os.path.join(HERE, "..", "shared"))
from authorization import Authorization, NotAuthorized
from iterative_hunt import IterativeHunt, board_brainstorm, tiered_brainstorm

KALI = ["wsl", "-d", os.environ.get("AEGIS_KALI_DISTRO", "kali-linux"), "-u", "root", "--", "bash", "-lc"]
KILL_FLAG = os.path.join(HERE, ".redteam_stop")


class RedTeamRun:
    def __init__(self, auth: Authorization, objective: str, budget: int = 40, audit_path: str = None,
                 exploit_driver=None, escalate_frac: float = None, max_escalate_steps: int = None):
        self.auth = auth
        self.objective = objective
        self.budget = budget
        self.audit_path = audit_path or os.path.join(HERE, "redteam_audit.jsonl")
        # network-exploitation driver is PLUGGABLE: wire your authorized Metasploit-RPC / tooling here.
        # Default is a dry stub that only records intent (never runs a live exploit on its own).
        self.exploit_driver = exploit_driver or self._dry_exploit
        # PER-MODE escalation depth. Operator/ExploitGym keep the loop's breadth-biased defaults
        # (0.15 / 3); RED-TEAM is a dedicated PIVOT engagement, so it defaults DEEPER -- and each
        # pivot hop is a NOVEL confirm on a NEW host, not convergence on one bug. RoE can override.
        roe = auth.roe if hasattr(auth, "roe") else {}
        self.escalate_frac = (escalate_frac if escalate_frac is not None
                              else roe.get("escalate_frac", 0.5))
        self.max_escalate_steps = (max_escalate_steps if max_escalate_steps is not None
                                   else roe.get("max_escalate_steps", 8))
        # lateral-movement / cross-host chaining (contained, scope-gated). RoE may carry an internal
        # topology (`pivot_map`) and a crown-jewel `goal` host (e.g. the domain controller).
        from lateral import PivotExpander
        self.expander = PivotExpander(auth, pivot_map=roe.get("pivot_map"), goal=roe.get("goal"))

    # ---- audit (append-only) ----
    def _audit(self, kind, detail):
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": kind, "detail": detail}
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

    def _killed(self):
        return os.path.exists(KILL_FLAG)

    # ---- legs (all scope-gated by the caller) ----
    def _recon(self, target):
        """Active recon on an in-scope target (nmap service scan). Read-only."""
        cmd = f"command -v nmap >/dev/null 2>&1 && nmap -sV -T4 --top-ports 100 {target} 2>/dev/null | head -60 || echo 'nmap not installed'"
        try:
            p = subprocess.run(KALI + [cmd], capture_output=True, text=True, timeout=300)
            return {"status": 200, "body": (p.stdout or "")[:4000]}
        except Exception as e:
            return {"status": -1, "body": str(e)}

    @staticmethod
    def _dry_exploit(target, module, options):
        """Default network-exploit driver: DRY. Records the intended module; does not fire a live
        exploit. Replace with an authorized Metasploit-RPC/tooling driver to make it live."""
        return {"status": 0, "body": f"[dry-run] would run module {module!r} against {target} opts={options} "
                                     f"(wire an authorized msfrpc driver to execute)"}

    def _web(self, move, target):
        import requests
        try:
            requests.packages.urllib3.disable_warnings()
        except Exception:
            pass
        method = (move.get("method") or "GET").upper()
        path = move.get("path") or "/"
        base = target if target.startswith("http") else "https://" + target
        try:
            r = requests.request(method, base + (path if path.startswith("/") else "/" + path),
                                 json=move.get("body"), verify=False, timeout=20)
            return {"status": r.status_code, "body": (r.text or "")[:4000]}
        except Exception as e:
            return {"status": -1, "body": str(e)}

    # ---- the scope-enforcing executor every move goes through ----
    def make_execute(self):
        def execute(move, phase):
            if self._killed():
                self._audit("kill_switch", "stop flag present -- halting")
                return {"move": move, "blocked": "kill-switch", "status": 0, "body": ""}
            # Default a plain move to the SHARED-VECTOR action name "web" (not the legacy "web_exploit"),
            # so it matches the shared vectors.dispatch vocabulary AND the RoE allowed_actions ("web").
            # A module-bearing move is a network_exploit; a recon-tagged one is recon. (A live smoke
            # showed every board web move defaulting to "web_exploit" and being blocked as not-allowed.)
            action = move.get("action") or ("recon" if move.get("technique", "").startswith("recon")
                                             else "network_exploit" if move.get("module")
                                             else "web")
            raw = move.get("target") or move.get("surface") or move.get("host") or ""
            # SCOPE is a HOST check, but web moves carry a PATH ("/api/invoices"), not a host. A path (or
            # empty) is resolved against the RUN's primary in-scope target; a move naming its OWN host (a
            # cross-host pivot) is scoped on that host. Without this, every in-scope web move false-blocks
            # as "out of scope" (its path isn't a host) -- surfaced by a live red-team sweep.
            run_target = getattr(self, "target", "") or ""
            is_path = (not raw) or str(raw).startswith("/")
            scope_target = run_target if is_path else raw
            payload = " ".join(str(move.get(k, "")) for k in ("payload", "body", "code", "module"))
            ok, why = self.auth.guard(action, scope_target, payload, test_id=move.get("test_id", ""))
            if not ok:
                self._audit("blocked", {"action": action, "target": scope_target, "path": raw, "why": why})
                return {"move": move, "blocked": why, "status": 0, "body": ""}
            self._audit("action", {"phase": phase, "action": action, "target": scope_target, "path": raw})
            if action == "network_exploit":
                return dict(self.exploit_driver(scope_target, move.get("module"), move.get("options", {})), move=move)
            # SHARED vectors (recon/web/supply_chain/static/fuzz/misconfig/rag): red-team has the SAME
            # fact-finding tools as the other modes -- wrapped by the authorization guard above. `base` is
            # the target ORIGIN (scheme://host:port); the web leg appends the move's own path.
            import vectors
            origin = scope_target if str(scope_target).startswith("http") else ("https://" + str(scope_target))
            ctx = {"base": origin}
            if getattr(self, "_sfr", None):          # F1: authenticate resumed stateful footholds (env AEGIS_ROLE_MAP)
                ctx["session_for_role"] = self._sfr
            return vectors.dispatch(move, phase, ctx)
        return execute

    def run(self, target, oracle):
        # UPDATE THE CVE DB BEFORE THE RUN -- offline-safe, opt-in (AEGIS_RAG_ONLINE=1); never blocks.
        try:
            from rag_refresh import ensure_fresh
            self._audit("rag.refresh", ensure_fresh())
        except Exception:
            pass
        self._audit("run.begin", {"engagement": self.auth.data.get("engagement"), "target": target,
                                  "objective": self.objective})
        if not self.auth.in_scope(target):
            self._audit("refused", {"target": target, "why": "primary target out of scope"})
            raise NotAuthorized(f"primary target {target!r} is out of scope -- refusing")

        # the run's PRIMARY in-scope target -- path-only moves are scoped + based on this (see make_execute).
        self.target = target
        # F1: generic env-configured session factory (AEGIS_ROLE_MAP) so resumed stateful footholds
        # authenticate; None if unconfigured (offline-safe, same as before).
        try:
            import session_factory as _sf
            self._sfr = _sf.from_env(target)
        except Exception:
            self._sfr = None
        # authorized INITIAL ACCESS to the primary target = the chain's entry foothold.
        self.expander.own(target)

        def tracking_oracle(result):
            """Wrap the caller's oracle: a CONFIRMED foothold OWNS that host in the attack graph, so
            the next escalation round can pivot from it (cross-host lateral movement)."""
            verdict, receipt = oracle(result)
            if verdict == "verified":
                mv = result.get("move", {}) or {}
                h = mv.get("host") or mv.get("target")
                if h:
                    self.expander.own(h, via=mv.get("pivot_from") or target, relation="pivot")
                    self._audit("owned", {"host": h, "via": mv.get("pivot_from") or target,
                                          "hop": mv.get("hop", 0)})
            return verdict, receipt

        def pivot_brainstorm(ctx):
            """On escalation, PREPEND scope-gated cross-host pivot moves from the most-recently owned
            host -- then the board's own ideas. A new host is a new surface, so the loop's depth gate
            treats a pivot as legitimate escalation, and the per-mode deeper escalation budget lets the
            chain run web -> internal -> crown-jewel."""
            base = board_brainstorm(ctx) or []
            if ctx.get("phase") == "escalate" and self.expander.owned_order:
                latest = self.expander.owned_order[-1]
                hop = len(self.expander.owned_order)
                return self.expander.pivot_moves(latest, hop) + base
            return base

        # THE PLANNER (multi-scenario): plans[0] seeds the loop; the rest are the mid-run RE-OPEN queue
        # (pulled when the loop would otherwise stall out). Offline-safe (None -> no seeds/re-open).
        # Every seeded/re-opened move still passes auth.guard() in make_execute(), so out-of-scope /
        # destructive planner ideas are blocked exactly as any other move.
        try:
            from planner import plan_session
            sess = plan_session(self.objective, target, mode="redteam", task_level="pentest", base=target)
        except Exception:
            sess = None
        seeds = sess.initial_seeds() if sess else []
        # CAMPAIGN RELAY (L3): resume L1+L2 CONFIRMED footholds as DEEPER (pivot) anchors + dedup -- continue
        # the chain, do not replay. Every resumed move still passes auth.guard() below. Env-gated.
        _camp = os.environ.get("AEGIS_CAMPAIGN"); _seen = set(); _attempted_new = 0
        if _camp:
            try:
                from campaign_ledger import relay_prepare, fingerprint as _fp
                _anchors, _seen, _notes = relay_prepare(_camp, "redteam", 3, self.budget, session_for_role=self._sfr)
                if _anchors: seeds = [dict(m) for m in _anchors] + list(seeds)
                if _seen: seeds = [m for m in seeds if _fp(m) not in _seen]
                _attempted_new = len([m for m in seeds if m.get("seed") != "resume"])
                self._audit("relay", {"level": "redteam", "tier": 3, **_notes, "dedup": len(_seen)})
            except Exception as _e:
                self._audit("relay.skip", {"err": str(_e)[:120]})
        reopen = (lambda ctx, why: sess.reopen(ctx, why)) if sess else None
        intel = (sess.intel if sess else None)   # OBSERVATORY planner: informs the board; novelty is the board's
        # NOVEL-CODE WRITER: on the reach axis the board proposes a foothold/bridge that needs code, the
        # code bench WRITES the contained probe, it is tried (every move still passes auth.guard in
        # make_execute) and proven/discarded. A cross-host pivot is itself a reach BRIDGE. Offline-safe;
        # AEGIS_NOVEL_CODE=0 disables. Deeper per-mode escalation budget already lets the chain run.
        code_writer = None
        if os.environ.get("AEGIS_NOVEL_CODE", "1") != "0":
            try:
                from novel_code import make_code_writer
                code_writer = make_code_writer()
            except Exception:
                code_writer = None
        _deepen = _mutate = None
        try:
            from hunt_strategies import deepen_on_clean as _doc, mutate as _mutate
            _deepen = lambda mv: _doc(mv)
        except Exception:
            _deepen = _mutate = None
        # tiered: deterministic-first; pivot_brainstorm (board + scope-gated lateral pivots) is the
        # stall/escalate-time board_fn, so RT's pivot chain still fires on escalate (not suppressed).
        _bs = (lambda ctx: tiered_brainstorm(ctx, board_fn=pivot_brainstorm))
        hunt = IterativeHunt(_bs, self.make_execute(), tracking_oracle,
                             budget=self.budget, escalate_frac=self.escalate_frac,
                             max_escalate_steps=self.max_escalate_steps, seed_moves=seeds,
                             reopen=reopen, intel=intel, code_writer=code_writer,
                             deepen=_deepen, mutate=_mutate)
        rep = hunt.run(target, self.objective)
        if _camp:
            try:
                from campaign_ledger import relay_finalize
                _v = relay_finalize(_camp, "redteam", [c.get("move") or {} for c in (rep.get("confirmed") or [])],
                                    attempted_new=_attempted_new)
                rep["relay"] = _v; self._audit("relay.finalize", _v)
            except Exception as _e:
                self._audit("relay.skip", {"err": str(_e)[:120]})
        rep["pivot_chain"] = self.expander.chain()
        self._audit("run.end", {"attempts": rep["attempts_used"], "confirmed": len(rep["confirmed"]),
                                "pivot_chain": rep["pivot_chain"]})
        return rep


def main():
    ap = argparse.ArgumentParser(description="Aegis RED-TEAM mode (authorization-gated live pen-test).")
    ap.add_argument("--auth", default=os.path.join(HERE, "authorization.json"))
    ap.add_argument("--objective", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--budget", type=int, default=40)
    a = ap.parse_args()
    try:
        auth = Authorization.load(a.auth)
    except NotAuthorized as e:
        print(f"[REFUSED] {e}"); sys.exit(2)
    print("[red-team] authorization:", json.dumps(auth.summary()))
    from verified_findings import FindingStore
    from iterative_hunt_live import make_oracle
    store = FindingStore(os.path.join(HERE, "redteam_findings.jsonl"))
    run = RedTeamRun(auth, a.objective, budget=a.budget)
    rep = run.run(a.target, make_oracle(store))
    print(json.dumps(rep, indent=2, default=str))


if __name__ == "__main__":
    main()
