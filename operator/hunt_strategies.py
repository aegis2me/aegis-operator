"""
hunt_strategies.py -- the two discovery modes (board consensus), as seeding/steering strategies for
IterativeHunt. No new engine: MODE 1 pre-seeds the loop with anchor-derived moves; MODE 2 supplies a
`mutate` hook + budget/deepening policy.

MODE 1 -- KNOWN-ANCHOR EXPANSION ("full picture"): from a verified finding/fact, complete the picture
around it -- full-method/auth completion checklist, sibling classes (pattern-generalizer), co-occurring
classes ("if A verified also test B"), role privilege fanout, and adjacent surfaces.

MODE 2 -- NOVEL DEEPENING: technique-mutation engine (swap transport/encoding/auth-placement/verb),
a read->write->execute->persist->lateral deepening ladder, and a round-budget allocator
(deepen / novel-same-surface / novel-surface).
"""
from __future__ import annotations

_METHODS = ["GET", "POST", "PUT", "PATCH"]
_AUTH_CTX = ["owner", "finance", "dispatcher", "technician", "warehouse"]
_LADDER = ["read", "write", "execute", "persist", "lateral"]   # deepening: what more can this give me


# ---------------- MODE 1: known-anchor expansion ----------------
def anchor_expansion(anchor: dict, cooccurring=None, roles=None, methods=None, adjacent=None) -> list:
    """Given a KNOWN anchor {surface, technique, class, role?}, emit the seed moves that complete the
    picture around it. `cooccurring(cls)->[{consequent,confidence}]` (from technique_search) and
    `adjacent` (list of neighbouring surfaces discovered from the anchor) are optional."""
    surface = anchor.get("surface") or anchor.get("path") or "/"
    technique = anchor.get("technique") or anchor.get("class") or "anchor"
    seeds, seen = [], set()

    def add(m):
        sig = (m["surface"], m.get("method", "GET"), m.get("role", ""), m.get("technique", ""))
        if sig not in seen:
            seen.add(sig); seeds.append(m)

    # 1. completion checklist: every method x auth-context on the anchor surface
    for meth in (methods or _METHODS):
        for role in (roles or _AUTH_CTX):
            add({"surface": surface, "path": surface, "method": meth, "role": role,
                 "technique": technique, "why_novel": f"completion: {meth} as {role}", "seed": "checklist"})
    # 2. sibling classes (pattern-generalizer intent) + 3. co-occurring classes ("if A also test B")
    cls = anchor.get("class") or technique
    for r in (cooccurring(cls) if cooccurring else []):
        add({"surface": surface, "path": surface, "method": "GET", "technique": r.get("consequent", ""),
             "why_novel": f"co-occurs with {cls} (conf {r.get('confidence')})", "seed": "cooccur",
             "severity": "high"})
    # 4. role privilege fanout: same technique across roles + a privilege-boundary variant
    for role in (roles or _AUTH_CTX):
        add({"surface": surface, "path": surface, "method": "POST", "role": role, "technique": technique,
             "why_novel": f"privilege fanout as {role}", "seed": "role-fanout"})
    # 5. adjacent-surface enumeration (links/ids/redirects extracted from the anchor)
    for s in (adjacent or []):
        add({"surface": s, "path": s, "method": "GET", "technique": technique,
             "why_novel": f"adjacent surface of {surface}", "seed": "adjacent"})
    return seeds


# ---------------- MODE 2: novel deepening ----------------
def mutate(move: dict) -> dict | None:
    """Technique-mutation engine: derive a STRUCTURALLY different variant of a failed move (so the
    novelty fingerprint differs) -- swap verb, then encoding, then auth placement, then transport.
    Returns None once the mutation ladder for this move is exhausted."""
    step = move.get("_mut_step", 0)
    m = dict(move)
    m.pop("_mut_step", None)
    if step == 0:   # swap verb
        order = ["GET", "POST", "PATCH", "PUT"]
        cur = (move.get("method") or "GET").upper()
        m["method"] = order[(order.index(cur) + 1) % len(order)] if cur in order else "POST"
    elif step == 1:  # swap body encoding
        m["encoding"] = {"json": "form", "form": "multipart", "multipart": "json"}.get(move.get("encoding", "json"), "json")
    elif step == 2:  # swap auth placement
        m["auth_in"] = {"header": "cookie", "cookie": "query", "query": "header"}.get(move.get("auth_in", "header"), "cookie")
    elif step == 3:  # swap transport
        m["transport"] = "ws" if str(move.get("transport", "http")).lower() == "http" else "http"
    else:
        return None
    m["_mut_step"] = step + 1
    m["why_novel"] = f"mutation#{step + 1} of {move.get('technique', '?')}"
    return m


def deepening_ladder(confirmed_move: dict) -> list:
    """For a confirmed finding, 'what more can this give me' -> read->write->execute->persist->lateral.
    Emits the next-rung probes so a low-severity foothold is pushed toward higher impact."""
    surface = confirmed_move.get("surface") or confirmed_move.get("path") or "/"
    at = confirmed_move.get("rung", "read")
    idx = _LADDER.index(at) if at in _LADDER else 0
    return [{"surface": surface, "path": surface, "technique": f"deepen:{rung}", "rung": rung,
             "why_novel": f"escalate {at}->{rung}", "severity": "high", "method": "POST"}
            for rung in _LADDER[idx + 1:]]


def allocate_budget(remaining: int, phase: str) -> dict:
    """Split the remaining round budget: escalate phase leans to depth; else balance deepen/novel."""
    if phase == "escalate":
        return {"deepen": int(0.6 * remaining), "novel_same": int(0.3 * remaining), "novel_surface": remaining - int(0.6 * remaining) - int(0.3 * remaining)}
    return {"deepen": int(0.5 * remaining), "novel_same": int(0.3 * remaining), "novel_surface": remaining - int(0.5 * remaining) - int(0.3 * remaining)}


# ---------------- MODE 1b (MECH 1): "clean is a HYPOTHESIS, not a stop" ----------------
# Keyword -> the SAFETY INVARIANT that must hold for that surface, and the mechanism a "secure here"
# result IMPLIES becomes the next target. Deterministic; drives invariant-inversion + implication moves.
_INVARIANTS = {
    "credit":  "sum(issued credit notes) <= invoice.total",
    "invoice": "sum(credits/adjustments) <= invoice.total",
    "refund":  "sum(refunds) <= amount captured",
    "deposit": "a deposit is booked at most once per intended payment (idempotent)",
    "payment": "a payment is applied at most once (idempotent)",
    "order":   "order state transitions are monotonic (a closed order cannot re-open)",
    "stock":   "stock/quantity never goes negative",
    "quantity":"stock/quantity never goes negative",
    "price":   "unit price cannot be set below cost by a non-owner",
    "role":    "a role grant cannot exceed the granter's own privilege",
    "logout":  "logout invalidates every live session token server-side",
    "session": "a revoked/expired session is rejected within the revocation window",
    "token":   "a revoked token is rejected within the revocation window",
}
# surfaces whose "secure" result IMPLIES a session/auth mechanism worth racing (implication attack).
_AUTH_HINTS = ("auth", "login", "logout", "session", "token", "account", "identity", "password", "pin")


def _kw_hits(text: str, keys) -> bool:
    t = (text or "").lower()
    return any(k in t for k in keys)


def deepen_on_clean(move: dict, *, templates=None, depth: int = 0, max_depth: int = 1) -> list:
    """MECH 1 -- a CLEAN/refuted leg is a hypothesis, not a halt. Given an info-gaining, non-noise move
    that came back CLEAN, emit the deterministic deeper-hypothesis families (each a RUNNABLE, non-
    destructive move on a REAL distinctness axis, so none collides with the parent as a lazy tweak):

      1. ARTIFACT CHECK    -- was 'clean' genuine or an oracle artifact? re-observe the SAME surface with
         the DIFFERENTIAL leg (cross-session/role + noise floor); a 'clean' that equals a nonexistent-
         path baseline, or that hides a cross-role delta, is a false negative the single status check missed.
      2. IMPLICATION ATTACK-- 'secure here' IMPLIES a mechanism; attack the MECHANISM, not the surface
         again. Auth/session surfaces -> race the invalidation (auth_state); others -> concurrency/order
         delta (differential, repeated) -- the double-effect / TOCTOU class.
      3. INVARIANT INVERSION-- the invariant that must hold for this surface to be safe; if a stateful
         TEMPLATE matches the surface keywords, emit it (an ungated path that violates the invariant via
         a second door -- exactly how the credit-note over-credit was found).

    Bounded by max_depth (default 1: one deepening generation per cleared surface -- the loop's own
    novelty/dedup guards stop re-expansion). `templates` = stateful_templates.templates() (optional;
    lazily loaded if omitted). Returns [] when nothing deterministic applies."""
    if depth >= max_depth:
        return []
    # DEEPEN GATE (board review): only deepen a STATE-CHANGING / AUTH-BOUNDARY / app-behaviour leg -- NOT
    # recon/scaffold noise (a fingerprint/SBOM/nmap delta passed the info-gain filter but deepening it is
    # wasted budget). Restrict to the app-code legs whose "clean" genuinely implies a deeper hypothesis.
    _APP_ACTIONS = {"web", "fact", "authz", "money", "stateful", "idor", "probe", "code", "differential"}
    if str(move.get("action", "web")) not in _APP_ACTIONS:
        return []
    surface = move.get("surface") or move.get("path") or move.get("target") or "/"
    if not isinstance(surface, str) or not surface.startswith("/"):
        return []                                   # only deepen HTTP surfaces deterministically
    role = move.get("role") or "owner"
    out, seen = [], set()

    def add(m):
        m.setdefault("path", m["surface"]); m["_deepen_depth"] = depth + 1
        sig = (m["surface"], m.get("action"), m.get("oracle") or m.get("mechanism") or m.get("technique"))
        if sig not in seen:
            seen.add(sig); out.append(m)

    # 1. ARTIFACT CHECK -- distinguishing re-observation via the differential leg.
    add({"action": "differential", "surface": surface, "role": role, "method": move.get("method", "GET"),
         "variants": [role, "anon", "technician"], "noise_k": 5,
         "vuln_class": "false-negative/oracle-artifact", "mechanism": "differential-reobserve",
         "technique": "deepen:artifact-check", "seed": "deepen",
         "why_novel": f"clean@{surface} may be an oracle artifact -- re-observe with a distinguishing "
                      f"(cross-session + noise-floor) oracle a single status check can't see."})

    # 2. IMPLICATION ATTACK -- attack the mechanism 'secure here' implies.
    if _kw_hits(surface, _AUTH_HINTS):
        add({"action": "stateful", "oracle": "auth_state", "surface": surface, "role": role,
             "logout_step": {"method": "POST", "path": "/api/auth/logout"},
             "vuln_class": "broken-auth/session", "mechanism": "invalidation-race",
             "technique": "deepen:implication-auth", "severity": "high", "seed": "deepen",
             "why_novel": f"secure@{surface} implies an invalidation mechanism -- race the logout / reuse "
                          f"the token across the revocation window."})
    else:
        add({"action": "differential", "surface": surface, "role": role, "method": "GET",
             "variants": [role, role, role], "noise_k": 6,
             "vuln_class": "concurrency/TOCTOU", "mechanism": "concurrency-order",
             "technique": "deepen:implication-concurrency", "seed": "deepen",
             "why_novel": f"secure@{surface} under a single sequential request implies nothing under "
                          f"concurrency -- look for a double-effect / order-dependent delta."})

    # 3. INVARIANT INVERSION -- if a stateful template asserts an invariant for this surface, try it.
    try:
        if templates is None:
            import stateful_templates as _stt
            templates = _stt.templates()
    except Exception:
        templates = templates or []
    inv = next((v for k, v in _INVARIANTS.items() if k in surface.lower()), None)
    for tpl in (templates or []):
        if _kw_hits(surface, tpl.get("applies") or []):
            m = dict(tpl); m["seed"] = "deepen"; m["role"] = tpl.get("role", role)
            m["technique"] = "deepen:invariant-inversion"
            m["why_novel"] = (f"invariant for {surface} ({inv or tpl.get('invariant') or 'safety bound'}) "
                              f"-- seek an UNGATED path that violates it (second-door).")
            add(m)
            break                                   # one invariant probe per cleared surface (bounded)
    return out
