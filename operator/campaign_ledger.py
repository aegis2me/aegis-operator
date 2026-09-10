"""Campaign relay ledger -- the CROSS-MODE handoff artifact. The three run modes stop being parallel
replay: L1 Operator (tier 1, non-destructive) -> L2 ExploitGym (tier 2) -> L3 Red-Team (tier 3), each
RESUMING the prior levels' CONFIRMED footholds and going DEEPER (escalate), never re-walking mapped
ground. Append-only JSONL + SHA-256 chain. See docs / stateful-probing-design memory.

Board-converged guardrails: only CONFIRMED footholds hand off; a later level RE-CONFIRMS cheaply before
trusting (footholds go stale); confirmed AND refuted fingerprints form a dedup cache so budget = NEW
depth only; permission_tier + scope_hash travel per entry (fail-closed); refutations propagate."""
import os, json, time, hashlib, threading

_PRIOR = {"operator": [], "exploitgym": ["operator"], "redteam": ["operator", "exploitgym"]}
_TIER = {"operator": 1, "exploitgym": 2, "redteam": 3}


def _atomic_rewrite(path, entries):
    """Rewrite the whole ledger ATOMICALLY (board review): the ledger is the hash-chained source of truth,
    so a crash/interrupt mid-rewrite must never leave it truncated or half-written. Write a sibling temp
    file, flush+fsync, then os.replace (atomic on the same filesystem). Caller holds the lock."""
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, default=str) + "\n")
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass                                      # fsync unsupported on some filesystems -- non-fatal
    os.replace(tmp, path)


def fingerprint(move):
    """Cross-mode hypothesis fingerprint: (surface, vuln_class, technique, oracle, action_intent). The
    action_intent axis means L2 WEAPONIZING a confirmed L1 vuln is NOT deduped against L1's PROBE, but an
    identical re-probe is."""
    parts = [str(move.get("surface") or move.get("path") or ""),
             str(move.get("vuln_class") or ""), str(move.get("technique") or ""),
             str(move.get("oracle") or ""), str(move.get("action_intent") or move.get("intent") or "confirm")]
    return "|".join(p.lower() for p in parts)


class CampaignLedger:
    def __init__(self, campaign_id, root=None):
        self.id = campaign_id
        d = root or os.environ.get("AEGIS_CAMPAIGN_DIR") \
            or os.path.join(os.path.dirname(os.path.abspath(__file__)), "campaigns")
        os.makedirs(d, exist_ok=True)
        self.path = os.path.join(d, f"{campaign_id}.jsonl")
        self._lock = threading.Lock()
        self.entries = self._load()

    def _load(self):
        out = []
        if os.path.exists(self.path):
            for ln in open(self.path, encoding="utf-8"):
                ln = ln.strip()
                if ln:
                    try: out.append(json.loads(ln))
                    except Exception: pass
        return out

    def _last_hash(self):
        return self.entries[-1]["event_hash"] if self.entries else ""

    def append(self, level, move, status, receipt, confidence=0.9, scope_hash=""):
        with self._lock:
            base = {"id": (move.get("finding_id")
                           or hashlib.sha256((fingerprint(move) + str(time.time())).encode()).hexdigest()[:16]),
                    "level": level, "tier": _TIER.get(level, 1), "fingerprint": fingerprint(move),
                    "status": status, "surface": move.get("surface") or move.get("path"),
                    "technique": move.get("technique"), "vuln_class": move.get("vuln_class"),
                    "oracle": move.get("oracle"), "layer": move.get("layer"),
                    "parent_id": move.get("parent_id"),
                    "artifact": {"move": {k: move.get(k) for k in
                                          ("action", "role", "surface", "technique", "vuln_class", "oracle",
                                           "setup", "measure", "bound", "action_step", "control_step",
                                           "probe_step", "logout_step", "repeat", "invariant", "layer",
                                           "container", "severity", "why_novel") if move.get(k) is not None},
                                 "receipt": receipt},
                    "confidence": confidence, "scope_hash": scope_hash, "consumed_by": [], "ts": time.time()}
            base["prev_hash"] = self._last_hash()
            base["event_hash"] = hashlib.sha256(
                (json.dumps({k: base[k] for k in base if k != "event_hash"}, sort_keys=True, default=str)
                 + base["prev_hash"]).encode()).hexdigest()
            self.entries.append(base)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(base, default=str) + "\n")
            return base["id"]

    def confirmed_footholds(self, level, min_confidence=0.7, max_age=None):
        prior = _PRIOR.get(level, []); now = time.time()
        return [e for e in self.entries
                if e.get("level") in prior and e.get("status") == "confirmed"
                and e.get("confidence", 1.0) >= min_confidence
                and (max_age is None or (now - e.get("ts", now)) <= max_age)
                and level not in (e.get("consumed_by") or [])]

    def seen_fingerprints(self):
        """Confirmed + refuted -> the positive/negative cache for cross-mode dedup."""
        return {e["fingerprint"] for e in self.entries if e.get("status") in ("confirmed", "refuted")}

    def mark_consumed(self, entry_id, level):
        changed = False
        for e in self.entries:
            if e.get("id") == entry_id and level not in (e.get("consumed_by") or []):
                e.setdefault("consumed_by", []).append(level); changed = True
        if changed:
            with self._lock:
                _atomic_rewrite(self.path, self.entries)


def resume_seeds(campaign_id, level, root=None, min_confidence=0.7, max_age=3600):
    """Turn prior levels' CONFIRMED footholds into ESCALATION anchor moves for `level` (deeper, NOT
    re-discovery). Each anchor: action_intent=escalate, parent_id, resumed_from, a DISTINCT fingerprint
    (so it isn't deduped against the L1 confirm), and -- for a stateful foothold -- a deeper replay.
    Returns (anchor_moves, seen_fingerprints) so the caller can skip already confirmed/refuted work."""
    led = CampaignLedger(campaign_id, root)
    seen = led.seen_fingerprints()
    anchors = []
    for e in led.confirmed_footholds(level, min_confidence, max_age):
        m = dict((e.get("artifact") or {}).get("move") or {})
        if not m:
            continue
        m["seed"] = "resume"; m["action_intent"] = "escalate"
        m["parent_id"] = e.get("id"); m["resumed_from"] = e.get("level")
        if m.get("oracle") in ("invariant", "idempotency"):
            m["repeat"] = max(int(m.get("repeat", 2)), 5)          # DEEPER: more replays -> larger impact
            m["technique"] = (m.get("technique") or "stateful") + ".escalate"
        m["why_novel"] = f"[resume from {e.get('level')}] escalate confirmed foothold {e.get('surface')} deeper."
        anchors.append(m)
        led.mark_consumed(e.get("id"), level)
    return anchors, seen


# ---- refutation propagation ----
def _rewrite(led):
    with led._lock:
        _atomic_rewrite(led.path, led.entries)


def _refute(led, entry_id, reason):
    for e in led.entries:
        if e.get("id") == entry_id and e.get("status") != "refuted":
            e["status"] = "refuted"; e["refute_reason"] = reason
    # prune dependents (children whose parent_id == entry_id)
    for e in led.entries:
        if e.get("parent_id") == entry_id and e.get("status") != "refuted":
            e["status"] = "refuted"; e["refute_reason"] = "parent refuted: " + reason
    _rewrite(led)


# per-resuming-level deepen INTENT + its minimum permission tier (fail-closed gate)
_LEVEL_INTENT = {"exploitgym": "weaponize", "redteam": "pivot"}
_INTENT_TIER = {"confirm": 1, "escalate": 2, "weaponize": 2, "chain": 2, "pivot": 3, "lateral": 3}


def _light_live(mv, session_for_role):
    """LIGHT liveness check for a foothold (F2: do NOT re-run the whole stateful probe -- that is expensive
    and MUTATES state). A single GET on the foothold surface as its role: live iff a real HTTP response
    comes back and the surface isn't gone (404) or 5xx-erroring. Assume-live when not cheaply checkable."""
    surface = (mv.get("surface") or (mv.get("action_step") or {}).get("path")
               or (mv.get("measure") or {}).get("path") or "/")
    if not str(surface).startswith("/"):
        return True
    try:
        import requests, os as _os
        base = _os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
        s = session_for_role(mv.get("role", "owner"))
        r = s.get(base.rstrip("/") + surface, timeout=15, verify=False)
        return r.status_code < 500 and r.status_code != 404
    except Exception:
        return False


def relay_prepare(campaign, level, max_tier, budget, session_for_role=None, root=None,
                  min_confidence=0.7, max_age=3600):
    """Resume prior CONFIRMED footholds as DEEPER escalation anchors for `level`, non-lazily:
      - deepen INTENT is level-specific (exploitgym->weaponize, redteam->pivot) with tier-scaled depth;
      - TIER gate: an anchor whose intent tier exceeds this level's max_tier is dropped (fail-closed);
      - STALE re-confirm: reconfirm(move)->bool; a dead foothold is REFUTED + dependents pruned, NOT escalated;
      - BREADTH floor: resume anchors capped at floor(0.8*budget) so >=20% budget stays for NEW work.
    Returns (anchors, seen_fingerprints, notes)."""
    led = CampaignLedger(campaign, root)
    seen = led.seen_fingerprints()
    intent = _LEVEL_INTENT.get(level, "escalate")
    tier = _TIER.get(level, 1)
    itier = _INTENT_TIER.get(intent, 1)
    anchors, stale = [], 0
    if itier <= max_tier:
        for e in led.confirmed_footholds(level, min_confidence, max_age):
            mv = dict((e.get("artifact") or {}).get("move") or {})
            if not mv:
                continue
            if session_for_role is not None:                # STALE liveness (light; F2) before trusting
                if not _light_live(mv, session_for_role):
                    _refute(led, e["id"], "stale: surface not live at " + level); stale += 1; continue
            mv["seed"] = "resume"; mv["action_intent"] = intent; mv["min_tier"] = itier
            mv["parent_id"] = e.get("id"); mv["resumed_from"] = e.get("level")
            if mv.get("oracle") in ("invariant", "idempotency"):
                mv["repeat"] = max(int(mv.get("repeat", 2)), 5 * tier)   # DEEPER per tier (bigger impact)
                mv["technique"] = (mv.get("technique") or "stateful") + "." + intent
            mv["why_novel"] = f"[relay {e.get('level')}->{level}] {intent} confirmed foothold " \
                              f"{e.get('surface')} deeper (tier {tier})."
            anchors.append(mv); led.mark_consumed(e.get("id"), level)
    # BOARD AUDIT (f) -- RING-FENCE fresh breadth from relayed depth: resumed anchors let the NEXT stage
    # spend its budget deepening KNOWN surfaces, crowding out new angles. Reserve a tunable fraction of the
    # budget that relayed anchors CANNOT consume (default 0.35, up from 0.2), and cap the ABSOLUTE anchor
    # count per stage -- so each stage always opens genuinely new ground alongside resumed depth.
    import os as _os
    try:
        reserved = float(_os.environ.get("AEGIS_RELAY_BREADTH_FRAC", "0.35"))
    except Exception:
        reserved = 0.35
    reserved = min(0.9, max(0.0, reserved))
    cap = max(1, int((1.0 - reserved) * budget))
    try:
        max_anchors = int(_os.environ.get("AEGIS_RELAY_MAX_ANCHORS", "0"))
    except Exception:
        max_anchors = 0
    if max_anchors > 0:
        cap = min(cap, max_anchors)
    dropped = max(0, len(anchors) - cap)
    anchors = anchors[:cap]
    return anchors, seen, {"resumed": len(anchors), "stale_refuted": stale,
                           "breadth_reserved_frac": round(reserved, 2), "dropped_for_breadth": dropped,
                           "anchor_cap": cap, "tier": tier}


def relay_finalize(campaign, level, confirmed_moves, attempted_new=0, breadth_floor=1, root=None):
    """Append this level's CONFIRMED footholds and compute ANTI-LAZINESS. A level is LAZY iff it added NO
    new confirmed DEPTH (an escalate/weaponize/pivot/chain confirm, or a fresh non-inherited confirm) AND
    attempted fewer than `breadth_floor` genuinely-new hypotheses. A lazy level is flagged in the ledger."""
    led = CampaignLedger(campaign, root)
    new_depth = 0
    for mv in (confirmed_moves or []):
        led.append(level, mv, "confirmed", {"why": (mv.get("why_novel") or "")[:200]})
        if mv.get("action_intent") in ("escalate", "weaponize", "chain", "pivot", "lateral") \
                or not mv.get("parent_id"):
            new_depth += 1
    lazy = (new_depth == 0) and (attempted_new < breadth_floor)
    if lazy:
        led.append(level, {"surface": "(campaign)", "technique": "relay.deadend", "action_intent": "note"},
                   "note", {"lazy": True, "detail": "level added no new confirmed depth and did no new work"})
    return {"level": level, "new_confirmed_depth": new_depth, "attempted_new": attempted_new, "lazy": lazy}
