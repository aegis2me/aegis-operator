#!/usr/bin/env python3
"""
reach.py -- the shared REACH AXIS: the "how far can I go here?" model that ALL THREE modes
(Operator, ExploitGym, Red-Team) reason along, alongside the existing angle/approach-family axis in
iterative_hunt.py. Pure, dependency-free, offline-safe -- it unit-tests without the LLM/mirror.

THE PARAMOUNT PRINCIPLE (owner's directive): find out HOW FAR you can go, non-destructively, without
damaging the system under inspection. The budget's ~40 attempts are split across TWO DIRECTIONS of
probing -- consistent with the mirror-build doctrine's "real code vs scaffold" fidelity split
(docs/ARCHITECTURE_DIAGRAM.md): the SAME stack can be a bare scaffold (no app code) or the stack WITH
the app code running on it, and each is a genuinely different attack surface:

  * SCAFFOLD  -- the STACK + INSTALLED MODULES only (framework, dependencies, runtime, server,
    container, OS, config), as if NO application code were present. "Is the platform itself a door?"
    Natural vectors: supply_chain (SBOM/deps), misconfig (exposed config/infra), recon (services/
    stack fingerprint), fuzz (stack fuzzer surface), rag (known-CVE in the stack), static-on-deps.
  * CODE      -- the stack TOGETHER WITH the actual application code running on it. "Is the app a
    door the platform isn't?" Natural vectors: web (HTTP app behaviour), ossfuzz (the app's OWN
    buildable source), probe (a coder-written custom probe), and the web vuln families
    (authz/injection/xss/ssrf/ssti/xxe/traversal/auth/...), static-on-app-source.

For BOTH directions the board asks the SAME "how far" questions (HOW_FAR_QUESTIONS below): is there
another option open -- a backdoor, a window, a side entrance? is this layer CLOSED at all? and, above
all, can I establish a FOOTHOLD or a BRIDGE (in the stack, or in the stack+code) to go DEEPER or
LATERALLY -- and if nothing existing opens the way, WHAT CODE could I write to bridge further?

Move intents (move["intent"]):
    map       -- reconnoitre the layer (does it even have a seam?)
    foothold  -- establish a confirmed primitive on a layer (the first way in)
    bridge    -- CROSS from one layer/host to a deeper or lateral one (scaffold->code, app->host,
                 host->host) -- this is what actually answers "how far": each bridge extends reach
    escalate  -- deepen an already-owned foothold on the SAME layer/host
"""
from __future__ import annotations

# --- the two directions of probing (the reach axis) -------------------------------------------------
LAYERS = ("scaffold", "code")

# action -> default direction. An explicit move["layer"]/move["direction"] always overrides this.
_SCAFFOLD_ACTIONS = {"supply_chain", "misconfig", "recon", "fuzz", "rag"}
_CODE_ACTIONS = {"web", "fact", "authz", "money", "ossfuzz", "probe", "code"}
# vuln-class keywords that mean "this is exercising the APP's own code" (the code layer) even when the
# action is generic. Stack/dependency-flavoured classes fall to scaffold.
_CODE_CLASS_HINTS = ("idor", "bola", "authz", "authorization", "privesc", "over-read", "sqli",
                     "injection", "rce", "xss", "ssrf", "ssti", "xxe", "traversal", "lfi", "rfi",
                     "auth-bypass", "mass-assign", "mass_assignment", "race", "toctou", "csrf",
                     "deserial", "business-logic", "logic", "workflow")
_SCAFFOLD_CLASS_HINTS = ("supply", "dependency", "sca", "cve", "misconfig", "exposure", "outdated",
                         "version", "default-cred", "infra", "container", "image", "config",
                         # the scaffold layer explicitly INCLUDES plugins/modules and the DB tier
                         # (engine/version/config/extension), not just the app framework:
                         "plugin", "module", "extension", "addon", "middleware", "db-engine",
                         "database-server", "dbms", "redis", "broker", "message-queue", "cache-server")

# scaffold sub-surfaces a probe/finding can name -- so a stack weakness is reported precisely.
SCAFFOLD_SUBSURFACES = ("framework", "dependency", "plugin", "module", "runtime", "container",
                        "server", "config", "database", "db-extension", "cache", "broker")

INTENTS = ("map", "foothold", "bridge", "escalate")

# how a verified finding is CLASSIFIED for the report's two tracks (PIPELINE stage 10):
NOVELTY = ("known-cve", "novel")


def _s(move, *keys) -> str:
    for k in keys:
        v = move.get(k) if isinstance(move, dict) else None
        if v:
            return str(v).lower().strip()
    return ""


def direction_of(move) -> str:
    """Which of the two directions a move probes: 'scaffold' (stack + installed modules only) or
    'code' (the stack WITH the app code). Explicit move['layer']/['direction'] wins; else inferred
    from the action, then the vuln-class hints. Defaults to 'code' (the app is the usual surface)."""
    if not isinstance(move, dict):
        return "code"
    explicit = _s(move, "layer", "direction")
    if explicit in LAYERS:
        return explicit
    if explicit in ("stack", "platform", "infra", "dependencies", "deps"):
        return "scaffold"
    if explicit in ("app", "application", "source"):
        return "code"
    action = _s(move, "action") or "web"
    if action in _SCAFFOLD_ACTIONS:
        return "scaffold"
    if action in _CODE_ACTIONS:
        return "code"
    blob = " ".join(_s(move, k) for k in ("vuln_class", "class", "technique", "mechanism", "why_novel"))
    if any(h in blob for h in _CODE_CLASS_HINTS):
        return "code"
    if any(h in blob for h in _SCAFFOLD_CLASS_HINTS):
        return "scaffold"
    # `static` and other ambiguous legs default to code (app source) unless flagged scaffold above.
    return "code"


def other_direction(direction: str) -> str:
    return "code" if direction == "scaffold" else "scaffold"


def intent_of(move) -> str:
    """The move's reach INTENT (map/foothold/bridge/escalate). Explicit move['intent'] wins; else
    inferred: a move that names a deeper/lateral target it bridges TO is a bridge, a recon/map leg is
    map, otherwise foothold (the default 'get a way in')."""
    if not isinstance(move, dict):
        return "foothold"
    it = _s(move, "intent")
    if it in INTENTS:
        return it
    if move.get("bridge_to") or move.get("pivot_from") or move.get("host"):
        return "bridge"
    if _s(move, "action") in ("recon", "rag") or _s(move, "vuln_class") in ("map", "recon"):
        return "map"
    return "foothold"


def is_bridge(move, foothold) -> bool:
    """A move is a BRIDGE relative to a confirmed foothold iff it EXTENDS REACH: it crosses to a
    different LAYER (scaffold<->code) or a different HOST than the foothold. That is the mechanical
    test for 'went further', distinct from escalating the same foothold in place."""
    if not isinstance(move, dict) or not isinstance(foothold, dict):
        return False
    if direction_of(move) != direction_of(foothold):
        return True
    mh = _s(move, "host", "target")
    fh = _s(foothold, "host", "target")
    # a path (starts with /) is not a host -- ignore it for the cross-host test
    mh = "" if mh.startswith("/") else mh
    fh = "" if fh.startswith("/") else fh
    return bool(mh and fh and mh != fh)


def finding_novelty(move, result=None) -> str:
    """Classify a VERIFIED finding for the report's two tracks: 'known-cve' when it matches a known CVE
    (a supply-chain/SCA hit, a RAG CVE lookup, or a move/evidence naming a CVE), else 'novel' -- a
    zero-day-style / new-code / fuzzing-discovered weakness that is NOT a catalogued CVE. Novel findings
    (including on the SCAFFOLD layer -- plugins, modules, the DB tier -- and fuzzing crashes) are the
    ones the report must EMPHASIZE, and they route to the code-writer track, not the admin/CVE track."""
    move = move if isinstance(move, dict) else {}
    result = result if isinstance(result, dict) else {}
    if result.get("supply_chain") is not None:
        return "known-cve"
    blob = " ".join(str(move.get(k, "")) for k in ("action", "vuln_class", "class", "technique",
                                                   "cve", "why_novel")) + " " + str(result.get("body", ""))
    if "cve-" in blob.lower() or move.get("cve") or _s(move, "action") == "rag":
        return "known-cve"
    return "novel"


def finding_origin(move, result=None) -> str:
    """Finer-grained ORIGIN of a finding (for the report detail): cve | fuzz | novel-code | novel.
    Distinguishes a fuzzing crash and a coder-written-probe win from a plain deterministic novel find."""
    move = move if isinstance(move, dict) else {}
    result = result if isinstance(result, dict) else {}
    if finding_novelty(move, result) == "known-cve":
        return "cve"
    if result.get("ossfuzz") is not None or _s(move, "action") in ("fuzz", "ossfuzz"):
        return "fuzz"
    if move.get("code") or move.get("new_code") or _s(move, "action") in ("probe", "code"):
        return "novel-code"
    return "novel"


def scaffold_subsurface(move) -> str:
    """Best-effort scaffold SUB-SURFACE a move touches (plugin / module / database / ...), so a novel
    stack finding is reported precisely ('novel finding in the DB tier' not just 'in the stack')."""
    blob = " ".join(_s(move, k) for k in ("surface", "path", "target", "vuln_class", "class",
                                          "technique", "mechanism", "why_novel", "bridge_to"))
    for sub in SCAFFOLD_SUBSURFACES:
        if sub.split("-")[0] in blob:
            return sub
    if any(k in blob for k in ("postgres", "mysql", "psql", "mongo", "sql", "redis")):
        return "database"
    if any(k in blob for k in ("plugin", "extension", "addon")):
        return "plugin"
    return "stack"


def finding_tags(move, result=None) -> list:
    """Uniform coverage_tags a VERIFIED finding carries so the report + RAG writeback can flag the
    reach dimensions consistently: layer, novelty, origin, reach-intent, and (for scaffold) the
    sub-surface. Both wrapper oracles and techniques_from_findings read these."""
    move = move if isinstance(move, dict) else {}
    layer = direction_of(move)
    tags = [f"layer:{layer}", f"novelty:{finding_novelty(move, result)}",
            f"origin:{finding_origin(move, result)}", f"reach-intent:{intent_of(move)}"]
    if layer == "scaffold":
        tags.append(f"scaffold-sub:{scaffold_subsurface(move)}")
    if move.get("bridge_to"):
        tags.append(f"bridge-to:{str(move.get('bridge_to'))[:40]}")
    if move.get("verdict"):                          # board-discussion verdict travels onto the finding
        tags.append(f"verdict:{str(move.get('verdict'))[:20]}")
    # TRUST TIER (assumed-access guard): tag reachable/intended/exploitable so the report groups by tier and
    # never mislabels admin-doing-admin as an exploit. Offline-safe.
    try:
        import trust
        tags += trust.tags(move, baseline_intended=move.get("intended_tier"))
    except Exception:
        pass
    return tags


def finding_provenance(move, result=None) -> dict:
    """Reach provenance fields for a finding (merged into Finding.provenance) -- carries the actual
    novel code that worked, so a proven novel-code bridge becomes a REUSABLE learned technique."""
    move = move if isinstance(move, dict) else {}
    prov = {"layer": direction_of(move), "novelty": finding_novelty(move, result),
            "origin": finding_origin(move, result), "reach_intent": intent_of(move)}
    if move.get("code") or move.get("new_code"):
        prov["new_code"] = str(move.get("code") or move.get("new_code"))[:800]
    if move.get("code_by"):
        prov["code_by"] = move.get("code_by")
    if move.get("bridge_to"):
        prov["bridge_to"] = move.get("bridge_to")
    # kimi's rule: the board discussion's verdict/confidence/DISSENT travel with the move and are never
    # deleted -- so a finding records what the board thought (and who disagreed) about it.
    for k in ("verdict", "confidence", "dissent"):
        if move.get(k) not in (None, "", []):
            prov[k] = move.get(k)
    try:
        import trust
        prov["trust"] = trust.finding_trust(move, baseline_intended=move.get("intended_tier"))
    except Exception:
        pass
    return prov


def reach_summary(directions_confirmed, bridges, layer_breached, lateral_hops=0) -> dict:
    """Score HOW FAR the run got: which directions yielded a confirmed foothold, how many bridges
    extended reach, whether the scaffold->code seam was actually crossed, and lateral hops. `depth`
    is a small integer any mode can compare run-to-run."""
    dirs = sorted(set(directions_confirmed or []))
    n_bridge = len(bridges or [])
    depth = len(dirs) + n_bridge + (1 if layer_breached else 0) + int(lateral_hops or 0)
    return {
        "directions_reached": dirs,
        "both_directions": set(LAYERS).issubset(dirs),
        "bridges": n_bridge,
        "layer_breached_scaffold_to_code": bool(layer_breached),
        "lateral_hops": int(lateral_hops or 0),
        "depth": depth,
    }


# --- the "how far can I go?" question set the board reasons through, for EACH direction --------------
HOW_FAR_QUESTIONS = (
    "Is there ANOTHER option open to me here -- a backdoor, a window, a side entrance, a forgotten "
    "endpoint, a debug/admin interface, a default credential, an exposed secret or config?",
    "Is this DOOR closed AT ALL -- how sealed is THIS layer (the bare stack/scaffold, vs the stack "
    "with the app code)? Where is the seam?",
    "Can I establish a FOOTHOLD or a BRIDGE -- in the stack, or in the stack+code -- to go DEEPER "
    "(scaffold -> code, app -> host) or LATERALLY (host -> host)?",
    "If NOTHING already open lets me through: WHAT CODE could I write -- a small, contained, "
    "non-destructive probe -- to BRIDGE further and answer how far this goes?",
)

# framing fragment injected into the board's system prompt so novelty is explicitly enriched with the
# two-direction / foothold-bridge / write-novel-code option.
BOARD_REACH_DOCTRINE = (
    "REACH DOCTRINE -- the paramount question is HOW FAR CAN I GO here, non-destructively, WITHOUT "
    "damaging the system under inspection. Split your ideas across TWO DIRECTIONS of probing and TAG "
    "each move with `layer`: (A) layer='scaffold' -- the STACK + INSTALLED MODULES only (framework, "
    "dependencies, runtime, server, container, OS, config) AS IF NO APP CODE WERE PRESENT; (B) "
    "layer='code' -- the stack TOGETHER WITH the app's ACTUAL code. For EACH direction ask: (1) is "
    "there another option open -- a backdoor, a window, a forgotten/debug/admin door, a default cred, "
    "an exposed secret/config? (2) is this layer closed AT ALL -- where is the seam? (3) can I "
    "establish a FOOTHOLD (a first confirmed primitive) or a BRIDGE (cross scaffold->code, app->host, "
    "or host->host) to go DEEPER or LATERALLY? Tag the move's `intent` as map|foothold|bridge|escalate "
    "and, for a bridge, name what it crosses TO in `bridge_to`. (4) WHEN NOTHING ALREADY OPEN LETS YOU "
    "THROUGH, propose NOVEL CODE: set `needs_code:true` and describe in `new_code` the small, "
    "contained, NON-DESTRUCTIVE probe to WRITE (a custom request/script that targets a gap in THIS "
    "stack or THIS app's behaviour) to establish the foothold/bridge -- the code bench will write it, "
    "it will be tried against the contained mirror, and proven or discarded by the oracle."
)


def annotate(move) -> dict:
    """Stamp a move with its resolved layer + intent (idempotent) so downstream reporting/writeback is
    uniform. Returns the same dict (mutated) for convenience."""
    if isinstance(move, dict):
        move.setdefault("layer", direction_of(move))
        move.setdefault("intent", intent_of(move))
    return move
