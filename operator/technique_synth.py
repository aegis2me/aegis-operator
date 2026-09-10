"""technique_synth.py -- MECH 3: board-INTERNAL technique synthesis (self-expanding, deterministic).

The board today RANKS known techniques + writes novel code. This adds a T1 DETERMINISTIC generator that
INVENTS new techniques by composing TWO known primitive classes into one synthetic technique with a
RUNNABLE, non-destructive move shape -- so the technique DB grows techniques no human seeded, without an
LLM in the hot path and without an N*N combinatorial blow-up (the compositions are CURATED, and each is
fingerprinted + bounded by the loop's own novelty/info-gain budget).

On an oracle-VERIFIED win a synthetic technique is written back to learned_techniques.json as
board-INVENTED -- guarded by the poisoning gate the board converged on (>=k DISTINCT verified instances,
PARAMETERIZED not hardcoded, provenance + success/failure counters, treat the store as a CACHE WITH
EVICTION not a trusted source). See operator/board_deepening_proposal.md.
"""
from __future__ import annotations
import json, os, re, time


def _surface(anchor):
    s = (anchor or {}).get("surface") or (anchor or {}).get("path") or ""
    return s if isinstance(s, str) and s.startswith("/") else ""


def _replay_as_identity(anchor):
    """replay x cross-user (AccessControl) = REPLAY-AS-ANOTHER-IDENTITY: replay a state-changing action
    while authenticated as a DIFFERENT role than the one that owns the resource -- an idempotency/authz
    cross that neither class tests alone."""
    s = _surface(anchor)
    if not s:
        return None
    victim = anchor.get("role") or "owner"
    attacker = "technician" if victim != "technician" else "dispatcher"
    return {"action": "stateful", "oracle": "idempotency", "surface": s, "role": attacker,
            "technique": "synth.replay_x_crossuser", "vuln_class": "authz+idempotency", "severity": "high",
            "measure": {"method": "GET", "path": s, "reduce": "count"},
            "action_step": {"method": "POST", "path": s}, "repeat": 2, "unit": 1.0,
            "metric": "cross-identity-replay-count", "seed": "synth",
            "why_novel": f"REPLAY-AS-ANOTHER-IDENTITY: replay a change on {s} as {attacker} (not the owning "
                         f"{victim}) -- authz x idempotency, a cross neither class probes alone."}


def _toctou_on_invariant(anchor, tpl=None):
    """invariant (Business-Logic/Stateful) x timing = TOCTOU-ON-INVARIANT: drive a template's invariant
    probe under CONCURRENCY so a check-then-act window can breach a bound that holds sequentially."""
    if not tpl or tpl.get("oracle") != "invariant":
        return None
    m = dict(tpl)
    m["technique"] = "synth.invariant_x_timing"
    m["vuln_class"] = "business-logic+TOCTOU"
    m["seed"] = "synth"
    m["concurrency"] = int(m.get("concurrency", 4))
    m["repeat"] = max(2, m.get("repeat", 2))
    m["why_novel"] = ("TOCTOU-ON-INVARIANT: race the invariant "
                      f"({tpl.get('invariant', 'bound')}) with concurrent action_steps -- a check-then-act "
                      "window can breach a bound that holds under sequential replay.")
    return m


def _double_effect_race(anchor, tpl=None):
    """idempotency x concurrency = DOUBLE-EFFECT RACE: an idempotency template run with concurrent
    duplicate submissions -> a duplicate booking a single-shot replay would miss."""
    if not tpl or tpl.get("oracle") != "idempotency":
        return None
    m = dict(tpl)
    m["technique"] = "synth.idempotency_x_concurrency"
    m["vuln_class"] = "idempotency+race"
    m["seed"] = "synth"
    m["concurrency"] = int(m.get("concurrency", 5))
    m["repeat"] = max(2, m.get("repeat", 2))
    m["why_novel"] = ("DOUBLE-EFFECT RACE: submit the idempotency action_step CONCURRENTLY -- a duplicate "
                      "effect that a sequential replay (already tested) would not surface.")
    return m


def _privfield_backdoor(anchor):
    """mass-assignment (BusinessLogic) x second-route (AccessControl) = PRIVILEGE-FIELD VIA BACK DOOR:
    set a privileged field on a resource through a secondary write route that skips the primary route's
    field allow-list. Differential-observed (compare the resource across routes/roles)."""
    s = _surface(anchor)
    if not s:
        return None
    role = anchor.get("role") or "owner"
    return {"action": "differential", "surface": s, "role": role, "method": "GET",
            "variants": [role, "technician"], "noise_k": 5,
            "technique": "synth.massassign_x_secondroute", "vuln_class": "mass-assignment+authz",
            "seed": "synth",
            "why_novel": f"PRIVILEGE-FIELD VIA BACK DOOR: probe whether a secondary write route to {s} lets "
                         f"a privileged field through that the primary route's allow-list blocks."}


def _invalidation_race(anchor, tpl=None):
    """SCAFFOLD: auth_state x timing = SESSION-INVALIDATION RACE. Drive the auth_state template under
    CONCURRENCY so a token still honoured inside the revocation window is caught -- a scaffold TOCTOU a
    single sequential post-logout probe misses."""
    if not tpl or tpl.get("oracle") != "auth_state":
        return None
    m = dict(tpl)
    m["technique"] = "synth.authstate_x_timing"
    m["vuln_class"] = "broken-auth/session+TOCTOU"
    m["layer"] = "scaffold"
    m["seed"] = "synth"
    m["concurrency"] = int(m.get("concurrency", 6))
    m["why_novel"] = ("SESSION-INVALIDATION RACE: fire concurrent same-auth probes as logout runs -- a "
                      "revocation-window reuse the sequential auth_state probe cannot see.")
    return m


def _leak_under_load(anchor, tpl=None):
    """SCAFFOLD: resource_persistence x concurrency = LEAK-UNDER-LOAD. Drive the resource-persistence
    template's heavy request CONCURRENTLY so a leak the paced sequential run lets the GC keep up with
    surfaces under real load."""
    if not tpl or tpl.get("oracle") != "resource_persistence":
        return None
    m = dict(tpl)
    m["technique"] = "synth.resourcepersist_x_concurrency"
    m["vuln_class"] = "resource-exhaustion+concurrency"
    m["layer"] = "scaffold"
    m["seed"] = "synth"
    m["concurrency"] = int(m.get("concurrency", 8))
    m["why_novel"] = ("LEAK-UNDER-LOAD: fire the heavy request concurrently -- a memory leak a paced "
                      "sequential run hides (GC keeps up) shows up under real concurrent load.")
    return m


# Each rule: (id, needs_template_oracle, builder). needs_template_oracle picks which template to feed.
# CODE-direction rules (invariant/idempotency) + SCAFFOLD-direction rules (auth_state/resource_persistence)
# + surface-generic rules that fire on EITHER direction -> MECH3 synth is two-direction (code + scaffold).
_RULES = [
    ("replay_x_crossuser",           None,                   lambda a, t: _replay_as_identity(a)),
    ("invariant_x_timing",           "invariant",            lambda a, t: _toctou_on_invariant(a, t)),
    ("idempotency_x_concurrency",    "idempotency",          lambda a, t: _double_effect_race(a, t)),
    ("massassign_x_secondroute",     None,                   lambda a, t: _privfield_backdoor(a)),
    ("authstate_x_timing",           "auth_state",           lambda a, t: _invalidation_race(a, t)),
    ("resourcepersist_x_concurrency","resource_persistence", lambda a, t: _leak_under_load(a, t)),
]


def synthesize(confirmed=None, templates=None, fp=None, limit=8, seed=None) -> list:
    """Emit deterministic synthetic candidate moves. Anchors = CONFIRMED footholds (preferred) else the
    surfaces the fingerprint/templates suggest. Deduped by (surface, technique); bounded by `limit`.
    Emission ORDER is shuffled by a SEEDED RNG (board audit (e)) so the same cross-products are not always
    tried first across runs -- decorrelated from enumeration order, still reproducible via AEGIS_SEED."""
    import random as _r
    if seed is None:
        try:
            seed = int(os.environ.get("AEGIS_SEED")) if os.environ.get("AEGIS_SEED") else None
        except Exception:
            seed = None
    rng = _r.Random(seed) if seed is not None else _r.Random()
    try:
        if templates is None:
            import stateful_templates as _stt
            templates = _stt.templates()
    except Exception:
        templates = templates or []
    tpl_by_oracle = {}
    for t in (templates or []):
        tpl_by_oracle.setdefault(t.get("oracle"), t)
    anchors = list(confirmed or [])
    if not anchors:
        # no confirmed foothold yet -> anchor the anchor-free rules on the template surfaces
        anchors = [{"surface": t.get("surface"), "role": t.get("role")} for t in (templates or [])] or [{}]
    out, seen = [], set()
    rng.shuffle(anchors)
    for anchor in anchors:
        a = anchor.get("move") if isinstance(anchor, dict) and "move" in anchor else anchor
        rules = list(_RULES)
        rng.shuffle(rules)
        for rid, need, build in rules:
            tpl = tpl_by_oracle.get(need) if need else None
            if need and not tpl:
                continue
            try:
                m = build(a or {}, tpl)
            except Exception:
                m = None
            if not m:
                continue
            m.setdefault("path", m.get("surface"))
            sig = (m.get("surface"), m.get("technique"))
            if sig in seen:
                continue
            seen.add(sig)
            out.append(m)
            if len(out) >= limit:
                return out
    return out


# ---------------- poisoning-gated writeback (board consensus) ----------------
def _looks_parameterized(move) -> bool:
    """Reject a probe hardcoded to literal target values: a template is PARAMETERIZED when its bodies use
    {{var}} capture (or carry no literal ids). Hardcoded literal ids => brittle/overfit => don't learn it."""
    blob = json.dumps({k: move.get(k) for k in ("setup", "measure", "action_step", "bound") if k in move})
    if "{{" in blob:
        return True
    body = (move.get("action_step") or {}).get("body") or {}
    for v in (body.values() if isinstance(body, dict) else []):
        if isinstance(v, str) and re.search(r"[0-9a-f]{8}-|^\d{3,}$", v):
            return False
    return True


def record_invented(move, instances: list, path=None, k: int = 2) -> dict:
    """Write a VERIFIED synthetic technique back to learned_techniques.json as board-INVENTED, guarded:
      - >=k DISTINCT verified instances (instances = list of receipts/surfaces, not one-off);
      - PARAMETERIZED (no hardcoded literal target ids);
      - provenance + success/failure counters (cache-with-eviction, not a trusted store).
    Returns {written: bool, reason}. Never raises (offline-safe)."""
    distinct = {json.dumps(i, sort_keys=True) if not isinstance(i, str) else i for i in (instances or [])}
    if len(distinct) < k:
        return {"written": False, "reason": f"need >={k} distinct verified instances, got {len(distinct)}"}
    if not _looks_parameterized(move):
        return {"written": False, "reason": "probe not parameterized (hardcoded literal target) -- refused"}
    path = path or os.path.join(os.path.dirname(__file__), "..", "rag", "learned_techniques.json")
    try:
        db = json.load(open(path, encoding="utf-8"))
    except Exception:
        db = {"_note": "LEARNED techniques (self-improving loop).", "techniques": []}
    techs = db.setdefault("techniques", [])
    tid = "invented." + str(move.get("technique", "synth")).replace("synth.", "")
    entry = next((t for t in techs if t.get("id") == tid), None)
    if entry is None:
        entry = {"id": tid, "class": move.get("vuln_class", "synthetic"), "invented": True,
                 "desc": move.get("why_novel", ""), "oracle": move.get("oracle", "differential"),
                 "provenance": {"source": "technique_synth", "composed": move.get("technique"),
                                "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                 "success": 0, "failure": 0, "surfaces": []}
        techs.append(entry)
    entry["success"] = int(entry.get("success", 0)) + 1
    entry["surfaces"] = sorted(set(entry.get("surfaces", [])) | {i for i in distinct if isinstance(i, str)})
    entry["last_verified"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        tmp = path + ".tmp"
        json.dump(db, open(tmp, "w", encoding="utf-8"), indent=1)
        os.replace(tmp, path)
        return {"written": True, "id": tid, "reason": "invented technique recorded (parameterized, >=k instances)"}
    except Exception as e:
        return {"written": False, "reason": f"write failed: {e}"}


def demote_on_failure(tid, path=None) -> dict:
    """Cache-with-eviction: bump the failure counter; EVICT once failures exceed successes (a technique
    that stops working is removed, not silently trusted)."""
    path = path or os.path.join(os.path.dirname(__file__), "..", "rag", "learned_techniques.json")
    try:
        db = json.load(open(path, encoding="utf-8"))
    except Exception:
        return {"evicted": False, "reason": "no store"}
    techs = db.get("techniques", [])
    e = next((t for t in techs if t.get("id") == tid), None)
    if not e:
        return {"evicted": False, "reason": "not found"}
    e["failure"] = int(e.get("failure", 0)) + 1
    evicted = e["failure"] > int(e.get("success", 0))
    if evicted:
        db["techniques"] = [t for t in techs if t.get("id") != tid]
    try:
        tmp = path + ".tmp"
        json.dump(db, open(tmp, "w", encoding="utf-8"), indent=1)
        os.replace(tmp, path)
    except Exception as ex:
        return {"evicted": False, "reason": f"write failed: {ex}"}
    return {"evicted": evicted, "reason": "evicted (failures>successes)" if evicted else "failure recorded"}


def demote_on_lowyield(tid, min_trials: int = 4, min_rate: float = 0.34, path=None) -> dict:
    """Board audit (g): eviction on FAILURE alone lets a 'verified but practically useless' technique
    survive and bias future ranking (its n=0 -> tried-first priority). Evict a technique whose
    success/(success+failure) yield falls below `min_rate` once it has >=min_trials trials -- so the
    self-improving DB does not accumulate technically-valid-but-low-value entries."""
    path = path or os.path.join(os.path.dirname(__file__), "..", "rag", "learned_techniques.json")
    try:
        db = json.load(open(path, encoding="utf-8"))
    except Exception:
        return {"evicted": False, "reason": "no store"}
    techs = db.get("techniques", [])
    e = next((t for t in techs if t.get("id") == tid), None)
    if not e:
        return {"evicted": False, "reason": "not found"}
    trials = int(e.get("success", 0)) + int(e.get("failure", 0))
    if trials < min_trials:
        return {"evicted": False, "reason": f"only {trials} trials (<{min_trials}) -- kept"}
    rate = int(e.get("success", 0)) / max(1, trials)
    evicted = rate < min_rate
    if evicted:
        db["techniques"] = [t for t in techs if t.get("id") != tid]
        try:
            tmp = path + ".tmp"
            json.dump(db, open(tmp, "w", encoding="utf-8"), indent=1)
            os.replace(tmp, path)
        except Exception as ex:
            return {"evicted": False, "reason": f"write failed: {ex}"}
    return {"evicted": evicted, "reason": f"yield {rate:.2f} {'<' if evicted else '>='} {min_rate}"}
