#!/usr/bin/env python3
"""
iterative_hunt.py -- budgeted, adaptive, MULTI-ATTEMPT discovery loop (board consensus).

Replaces one-shot "brainstorm -> try -> stop" with a persistent loop that spends its budget on
GENUINELY DIFFERENT attempts -- not 40 lazy variations of one idea, and not padding/gaming the count.
The board (discovery panel) advised the structure this implements:

  * HYPOTHESIS IDENTITY, not payload string. Every attempt is a falsifiable hypothesis fingerprinted
    by (angle, normalized-surface, vuln-class, mechanism, oracle-type) + the distinctness axes
    (trust-boundary, encoding, transport, method). The PAYLOAD VALUE is excluded from identity, so a
    value-only tweak COLLIDES with its parent (rejected as lazy) while a change on any real axis is a
    genuinely distinct hypothesis. This is the board's "multi-axis distinctness" rule made mechanical.
  * ANGLE DIVERSITY. Moves are grouped into approach-families (angles); breadth-first scheduling tries
    the least-used angle next, and a hard cap keeps any single angle <= max_angle_share of the budget.
  * INFORMATION-GAIN BUDGET. The budget counts REAL attempts only: an execution that yields no new
    information (a repeat response signature, an error/timeout, no oracle result) is NOISE -- it is
    bounded separately (max_noise) and does NOT advance the real-attempt budget. So "40" means 40 real
    attempts; a model cannot pad the count with noise.
  * LEGITIMATE DEPTH vs LAZY REPETITION. Escalation of an ORACLE-CONFIRMED foothold is exempt from the
    angle cap, but each escalation move must be genuine DEPTH -- it must change surface / vuln-class /
    mechanism / trust-boundary vs the foothold (read->write, user->admin, app->host, new sink). Merely
    re-probing the confirmed vuln with a new payload is rejected, not counted as escalation.
  * STALL -> PIVOT, not quit. A stall on one angle rotates to a different angle; the run ends only when
    the board can no longer propose novel moves (board_saturation), the noise ceiling is hit, the round
    cap is reached, or the real-attempt budget is spent.

Design is injectable so it unit-tests without the LLM/mirror:
    brainstorm(context) -> [move, ...]      # candidate next-move list (real: a board fan-out)
    execute(move, phase) -> result          # run it against the mirror (real: test_suggestions)
    oracle(result) -> (verdict, receipt)    # deterministic ground truth: "verified"/"rejected"

Contained: state-mutating attempts are snapshot-restored by the executor; the reward-hack monitor
should screen confirmed findings; nothing here is destructive.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field

# REACH AXIS (the "how far can I go?" two-direction model) is a co-located shared module. Guarded so a
# stripped-down import path can still load the engine (reach features then degrade, never crash).
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
try:
    import reach as _reach
except Exception:                                    # pragma: no cover - reach.py is normally co-located
    _reach = None


def direction_of(move) -> str:
    """The move's probing DIRECTION on the reach axis: 'scaffold' (stack + installed modules only) or
    'code' (the stack WITH the app code). Delegates to reach.py; degrades to 'code' if unavailable."""
    if _reach is not None:
        try:
            return _reach.direction_of(move)
        except Exception:
            pass
    return str((move or {}).get("layer") or (move or {}).get("direction") or "code").lower() \
        if isinstance(move, dict) else "code"


def intent_of(move) -> str:
    if _reach is not None:
        try:
            return _reach.intent_of(move)
        except Exception:
            pass
    return str((move or {}).get("intent") or "foothold").lower() if isinstance(move, dict) else "foothold"


def _is_reach_bridge(move, foothold) -> bool:
    if _reach is not None:
        try:
            return _reach.is_bridge(move, foothold)
        except Exception:
            pass
    return False


_LAYERS = getattr(_reach, "LAYERS", ("scaffold", "code"))


def _verdict_rank(move) -> int:
    """Board-discussion verdict -> priority rank (ds's 'verdict drives order'). Used ONLY as a LATE
    tie-breaker in _pick, so the loop's breadth/direction/novelty guarantees still dominate; a
    likely-fail is deprioritized but NOT dropped (kept for diversity / to avoid local optima)."""
    v = str((move or {}).get("verdict", "maybe")).lower() if isinstance(move, dict) else "maybe"
    return {"will-work": 0, "likely": 1, "maybe": 2, "likely-fail": 3}.get(v, 2)


def _confidence(move) -> float:
    try:
        return float((move or {}).get("confidence", 0.0))
    except (TypeError, ValueError):
        return 0.0


# --- hypothesis identity: the board's "dedup on the hypothesis, not the payload" rule ---------------
_ID_SEG = re.compile(r"/(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F][0-9a-fA-F-]{15,})(?=/|$)")


def _norm_surface(move: dict) -> str:
    """Normalize a target surface so /users/1 and /users/2 are the SAME target (a value tweak), while
    different endpoints or different PARAMETER NAMES (a different sink / data-flow path) stay distinct.
    Parameter VALUES are dropped; parameter NAMES are kept."""
    s = str(move.get("surface") or move.get("path") or move.get("target") or "").lower()
    s = s.split("?")[0].split("#")[0]
    s = _ID_SEG.sub("/#", s)
    params = move.get("param") or move.get("params")
    if isinstance(params, (list, tuple)):
        names = sorted(str(p).split("=")[0].strip() for p in params if str(p).strip())
    elif params:
        names = [str(params).split("=")[0].strip()]
    else:
        names = []
    return s + ("|p=" + ",".join(names) if names else "")


def _norm_tech(move: dict) -> str:
    t = re.sub(r"[^0-9a-z ]+", " ", str(move.get("technique", "") or "").lower())
    return " ".join(t.split()[:4])


def _oracle_type(move: dict) -> str:
    """The kind of ground-truth SIGNAL the attempt expects -- part of what makes two attempts distinct
    (a status check vs a timing side-channel vs a DB row-change are different experiments)."""
    ors = move.get("oracles") or ([move["oracle"]] if move.get("oracle") else [])
    kinds = sorted({str((o or {}).get("kind", "http")) for o in ors if isinstance(o, dict)})
    if kinds:
        return ",".join(kinds)
    eo = move.get("expected_oracle") or move.get("expected_signal") or ""
    return str(eo).lower().strip()[:32]


def _hypo_identity(move: dict) -> tuple:
    """The falsifiable-hypothesis fingerprint. Two moves are the SAME hypothesis iff every field
    matches; differing on ANY field is a genuinely distinct attempt. PAYLOAD VALUE is deliberately
    absent -- a value-only change collides here (lazy tweak) unless it also changes a real axis."""
    if not isinstance(move, dict):                 # defensive: a malformed (non-dict) move never crashes dedup
        move = {}
    return (
        angle_of(move),                                                   # approach-family
        _norm_surface(move),                                              # target surface + param names
        str(move.get("vuln_class") or move.get("class") or "").lower().strip() or _norm_tech(move),
        str(move.get("mechanism") or "").lower().strip(),                 # how the bug manifests
        _oracle_type(move),                                               # expected oracle signal
        str(move.get("trust") or move.get("role") or move.get("auth_in") or "").lower().strip(),  # trust boundary
        str(move.get("encoding") or "").lower().strip(),                  # protocol/encoding layer
        str(move.get("transport") or "").lower().strip(),
        str(move.get("method") or "").upper().strip(),
    )


def _sig(move: dict) -> str:
    """16-hex hypothesis signature (see _hypo_identity)."""
    return hashlib.sha256("|".join(_hypo_identity(move)).encode()).hexdigest()[:16]


def _combo(move: dict) -> tuple:
    """Coarse (angle, surface, vuln-class) key -- the unit a surface gets 'closed' on after repeated
    refutation, and the unit an information-gain signature is bucketed under."""
    return (angle_of(move), _norm_surface(move),
            str(move.get("vuln_class") or move.get("class") or "").lower().strip() or _norm_tech(move))


# --- angle (approach-family) classification: drives DIVERSITY across the budget ----------------------
# Two moves can be distinct hypotheses yet the SAME approach-family (e.g. IDOR on two endpoints). The
# angle is the coarse *approach* -- the budget is spread across angles so the 40 are genuinely varied.
_NON_WEB = ("supply_chain", "static", "fuzz", "misconfig", "recon", "rag")
_TECH_FAMILIES = (
    (("idor", "bola", "authz", "authorization", "privesc", "over-read", "overread", "access-control",
      "broken-access"), "authz"),
    (("sqli", "sql-injection", "nosql", "injection", "rce", "command-inj", "cmdi"), "injection"),
    (("xss", "cross-site-script", "html-inject"), "xss"),
    (("ssrf",), "ssrf"),
    (("ssti", "template"), "ssti"),
    (("xxe",), "xxe"),
    (("path-traversal", "lfi", "rfi", "traversal", "directory"), "traversal"),
    (("jwt", "session", "auth-bypass", "login", "credential", "oauth", "saml"), "auth"),
    (("mass-assign", "mass_assignment", "over-post", "parameter-pollution"), "mass_assignment"),
    (("race", "toctou", "concurren"), "race"),
    (("csrf",), "csrf"),
    (("deserial", "insecure-deser"), "deserialization"),
    (("rate", "brute", "enum"), "rate_enum"),
    (("business-logic", "workflow", "money", "price", "coupon", "refund"), "business_logic"),
    (("info-disclos", "verbose-error", "debug", "stacktrace", "leak"), "info_disclosure"),
)


def angle_of(move: dict) -> str:
    """Coarse approach-family for a move (the diversity unit)."""
    a = str(move.get("action", "") or "").lower()
    if a in _NON_WEB:
        return a
    blob = " ".join(str(move.get(k, "")) for k in
                    ("angle", "class", "vuln_class", "technique", "surface", "param", "why_novel")).lower()
    for keys, fam in _TECH_FAMILIES:
        if any(k in blob for k in keys):
            return fam
    for k in ("angle", "class", "vuln_class"):
        v = str(move.get(k, "") or "").lower().strip()
        if v:
            return "web:" + v.split()[0]
    tech = str(move.get("technique", "") or "").lower().strip()
    return ("web:" + tech.split()[0]) if tech else "web:other"


@dataclass
class HuntState:
    budget: int                            # REMAINING real (information-gaining) attempts
    noise_left: int = 0                    # remaining budget for non-gaining executions
    phase: str = "exploit"                 # exploit -> escalate -> pivot
    tried: set = field(default_factory=set)          # hypothesis signatures already attempted
    attempts: list = field(default_factory=list)     # every execution (real + noise)
    confirmed: list = field(default_factory=list)
    queue: list = field(default_factory=list)
    no_progress: int = 0
    board_rounds: int = 0
    board_rounds_total: int = 0                        # cumulative board rounds (NOT reset on re-open -- honest report)
    since_board: int = 0                               # real attempts since the last board round (interleave cadence)
    escalate_budget: int = 0
    stop_reason: str = ""
    angle_counts: dict = field(default_factory=dict)   # approach-family -> executions (drives spread)
    seen_signals: set = field(default_factory=set)     # (combo,status,body-bucket) -> repeat = noise
    combo_counts: dict = field(default_factory=dict)   # coarse combo -> executions (angle accounting)
    close_counts: dict = field(default_factory=dict)   # coarse combo -> UNPRODUCTIVE refutes (closing)
    dir_confirms: dict = field(default_factory=dict)   # reach direction -> CONFIRMED count (yield numerator)
    covered_classes: set = field(default_factory=set)  # parity classes probed this run (coverage gate)
    eps_used: int = 0                                   # cumulative epsilon-diversify picks this run
    eps_wave: int = -1                                  # current diversify wave index
    eps_wave_count: int = 0                             # epsilon picks in the current wave
    eps_rng: object = None                              # per-wave seeded RNG stream H(AEGIS_SEED, wave)
    eps_strata: set = field(default_factory=set)        # strata already drawn this wave (one draw/stratum)
    cost_spent: float = 0.0                             # MECH5: cumulative cost units spent (real attempts)
    dir_cost: dict = field(default_factory=dict)        # MECH5: cost units spent per reach direction
    dir_yhist: dict = field(default_factory=dict)       # MECH5: per-direction [(yield, was_confirm)] history
    dir_stopped: set = field(default_factory=set)       # MECH5: directions adaptively stopped (yield flat)
    floor_yields: list = field(default_factory=list)    # MECH5: per-try yields during the floor (for tau)
    combo_foothold: set = field(default_factory=set)   # combos that produced a confirmed foothold
    closed: set = field(default_factory=set)           # combos refuted enough to stop grinding
    seen_surfaces: set = field(default_factory=set)    # normalized surfaces ever attempted (novelty)
    seen_classes: set = field(default_factory=set)     # vuln-classes ever attempted (novelty)
    conf_surfaces: set = field(default_factory=set)    # surfaces/classes already CONFIRMED (dedup convergence)
    conf_classes: set = field(default_factory=set)
    escalate_steps: int = 0                            # consecutive deepening steps on current foothold
    escalate_rounds: int = 0                           # board reconvenes spent on the current escalation
    stash: list = field(default_factory=list)          # breadth moves preserved across a brief escalation
    since_fresh_angle: int = 0                         # real attempts since a never-tried angle (breadth floor)
    novelty_hist: list = field(default_factory=list)   # per-attempt novelty score (report)
    real_attempts: int = 0
    noise: int = 0
    reopens: int = 0                                   # mid-run Planner re-opens spent (bounded)
    reopen_log: list = field(default_factory=list)     # {why, injected, reopen} per re-open (report)
    # --- REACH AXIS: HOW FAR CAN I GO -- two directions of probing (scaffold vs stack+code) ---
    direction_counts: dict = field(default_factory=dict)   # 'scaffold'/'code' -> real attempts (spread)
    conf_directions: set = field(default_factory=set)      # directions that yielded a confirmed foothold
    bridges: list = field(default_factory=list)            # confirmed reach-extending crossings
    layer_breached: bool = False                           # scaffold seam actually crossed into code
    lateral_hops: int = 0                                  # confirmed cross-host bridges
    novel_code_counts: dict = field(default_factory=dict)  # direction -> novel-code trials spent (capped)
    novel_code_log: list = field(default_factory=list)     # {direction, wrote, verdict} per novel-code trial
    since_other_dir: int = 0                               # real attempts since the under-probed direction


class IterativeHunt:
    def __init__(self, brainstorm, execute, oracle, *, budget=40, max_board_rounds=15,
                 max_no_progress=3, escalate_frac=0.15, seed_moves=None, mutate=None, max_mutations=2, deepen=None, max_deepen=1,
                 max_angle_share=0.35, max_noise=None, close_after=3, max_escalate_steps=3,
                 breadth_floor=5, reopen=None, max_reopens=2, board_cadence=None, intel=None,
                 direction_floor=4, code_writer=None, max_novel_code=None):
        self.brainstorm, self.execute, self.oracle = brainstorm, execute, oracle
        try:
            budget = int(budget)
        except (TypeError, ValueError):
            budget = 40
        budget = max(0, budget)                    # never negative -> the run loop treats 0 as a clean no-op
        self.budget, self.max_board_rounds = budget, max_board_rounds
        # MECH5 -- ADAPTIVE COST-UNIT BUDGET GOVERNOR (board-converged). A flat try-count is cost-blind
        # now that the board is deterministic-first: the deterministic FLOOR reproduces the core findings,
        # heavy scaffold probes (grype/docker) cost far more than a cheap HTTP try, and extra tries no
        # longer pay a per-try board tax. So: keep `budget` as the cost FLOOR (always runs, exempt from the
        # adaptive stop), spend in COST UNITS up to a hard CEILING, and stop a direction early when its
        # marginal yield flattens. Kill-switch AEGIS_MECH5=0 -> exact legacy flat-budget behaviour.
        self.mech5 = str(os.environ.get("AEGIS_MECH5", "1")).lower() not in ("0", "false", "no", "off")
        self.cost_floor = budget                                             # deterministic core (~40)
        try:
            self.cost_ceiling = int(os.environ.get("AEGIS_COST_CEILING", str(3 * budget)))   # ~120
        except Exception:
            self.cost_ceiling = 3 * budget
        try:
            self.dir_cost_cap = int(os.environ.get("AEGIS_DIR_COST_CAP", str(2 * budget)))    # ~80/dir
        except Exception:
            self.dir_cost_cap = 2 * budget
        # HARD TRY CEILING: whatever the cost mix, a hot run may never exceed this many real (info-gaining)
        # tries -- the "equivalent of max ~50 runs total" cap. Default 1.25x the floor (40 -> 50). This
        # binds before the cost ceiling on cheap-try runs; the cost ceiling still guards heavy-try runs.
        try:
            self.max_tries = int(os.environ.get("AEGIS_MAX_TRIES", str(max(budget, round(1.25 * budget)))))
        except Exception:
            self.max_tries = max(budget, round(1.25 * budget))
        self.max_no_progress, self.escalate_frac = max_no_progress, escalate_frac
        # AWARD NOVELTY, NOT CONVERGENCE: escalation (deepening one confirmed foothold) is a CONVERGENT
        # move, so it gets only a SMALL slice of the budget (escalate_frac, default 15% vs the old 40%),
        # is entered ONLY for a NOVEL confirm (a surface/vuln-class not confirmed before), and is capped
        # at `max_escalate_steps` consecutive steps before the loop is forced back to breadth.
        self.max_escalate_steps = max_escalate_steps
        # BREADTH FLOOR: every `breadth_floor` real attempts, if a never-tried angle is still reachable,
        # force it -- so the loop cannot quietly collapse into depth on already-seen ground.
        self.breadth_floor = breadth_floor
        # DIVERSITY: no single approach-family may consume more than this share of the budget while
        # exploring/pivoting.
        self.max_angle_share = max_angle_share
        # INFORMATION-GAIN BUDGET: noise executions (no new info) are bounded separately and never
        # advance the real-attempt budget, so the count cannot be padded. Default: as many as the budget.
        self.max_noise = budget if max_noise is None else max_noise
        # a coarse (angle,surface,class) combo is CLOSED after this many refuted executions with no
        # foothold -- stop grinding a dead surface unless a move brings new_evidence.
        self.close_after = close_after
        # MODE 1 (known-anchor expansion): pre-seed the queue with anchor-derived moves.
        self.seed_moves = seed_moves or []
        # MODE 2 (novel deepening): on a failed move, mutate it one degree along a distinctness axis.
        self.mutate, self.max_mutations = mutate, max_mutations
        # MECH 1 (deepen-on-clean): a CLEAN, info-gaining leg is a HYPOTHESIS, not a stop.
        # `deepen(move)->[moves]` emits deeper falsifiable moves (artifact-check /
        # implication-attack / invariant-inversion); bounded by max_deepen per surface.
        self.deepen, self.max_deepen = deepen, max_deepen
        # MID-RUN RE-OPEN (the Planner's loop-back): when the loop would otherwise terminate, ask
        # `reopen(context, why) -> [moves]` for the NEXT candidate plan (a genuinely different
        # scenario) and inject its still-novel moves as fresh breadth. Bounded by max_reopens so
        # re-planning can never thrash the budget. None = no re-open (single-plan behaviour).
        self.reopen, self.max_reopens = reopen, max_reopens
        # BOARD INTERLEAVE: even when the Planner supplies seeds / re-open keeps the queue full, the
        # context-aware board (the novelty engine) must be consulted on a cadence -- otherwise
        # planner-novel seeds monopolise the budget and `brainstorm` never drives (observed:
        # board_rounds=0 with the Planner on, but grounded moves once it was disabled). Every
        # `board_cadence` REAL attempts we run a board round and inject its novel cands at the FRONT
        # of the queue, so a grounded board hypothesis is tried while still novel. Bounded overall by
        # max_board_rounds so the LLM-call cost stays capped. Default cadence ~= breadth_floor.
        self.board_cadence = max(2, int(board_cadence if board_cadence else breadth_floor))
        # OBSERVATORY PLANNER: `intel` (a dict or a callable()->dict, e.g. PlannerSession.intel) is
        # FACTUAL context (ranked technique classes) surfaced to the board each round -- NOT moves to
        # run. Novelty at this stage is the board's job; the Planner only informs + supplies its
        # deterministic anchors via seed_moves. None = no planner context (offline-safe).
        self.intel = intel
        # --- REACH AXIS knobs (the board's converged design) ---
        # DIRECTION FLOOR (no starvation): the ~40 attempts are spread across the TWO directions
        # (scaffold = stack+installed-modules, code = stack+app-code). `_pick` prefers the under-probed
        # direction; every `direction_floor` real attempts, if the under-probed direction has a queued
        # move, force it -- so neither door goes un-knocked (ds: floor>=10 total; kimi: ~35%). 0 disables.
        self.direction_floor = max(0, int(direction_floor or 0))
        # NOVEL-CODE WRITER: injectable code_writer(move, context) -> move. When the board proposes a
        # move that NEEDS custom code to establish a foothold/bridge (needs_code / an unwritten new_code
        # brief), the writer (code bench + analyst) WRITES the contained, non-destructive probe onto the
        # move (move['code'], action='probe') so it can be tried and proven/discarded by the oracle.
        # None = no writer (the move runs as-is). Injectable so the loop unit-tests without the LLM.
        self.code_writer = code_writer
        # per-DIRECTION cap on novel-code trials so generated code never dominates the budget (ds/kimi:
        # ~0.2 x budget, ~8 for 40). Only real information-gaining trials count against the budget as
        # usual; this caps how many of them may be code the board asked us to WRITE.
        self.max_novel_code = int(max_novel_code) if max_novel_code is not None else max(2, int(0.2 * budget))

    # ---- novelty / diversity helpers --------------------------------------------------------------
    def _novel(self, move, st: HuntState) -> bool:
        """A move is novel iff its HYPOTHESIS signature has not been attempted. Payload value is not
        part of the signature, so a value-only tweak of a prior attempt is NOT novel (lazy)."""
        return _sig(move) not in st.tried

    def _angle_cap(self) -> int:
        return max(2, int(round(self.max_angle_share * self.budget)))

    def _saturated(self, st: HuntState) -> set:
        cap = self._angle_cap()
        return {a for a, n in st.angle_counts.items() if n >= cap}

    def _is_depth(self, move, foothold) -> bool:
        """Legitimate escalation must CHANGE the hypothesis vs the confirmed foothold on surface,
        vuln-class, mechanism, or trust-boundary -- not merely re-probe it with a new payload/verb."""
        a, b = _hypo_identity(move), _hypo_identity(foothold)
        if any(a[i] != b[i] for i in (1, 2, 3, 5)):      # surface / vuln_class / mechanism / trust
            return True
        # a REACH BRIDGE (crossing scaffold<->code or app->host vs the foothold) is genuine depth: it
        # extends how far we got, even if the surface string looks similar.
        return _is_reach_bridge(move, foothold)

    def _novelty(self, move, st: HuntState) -> int:
        """NOVELTY score (0-3): how many of the hypothesis's coarse components -- angle, surface,
        vuln-class -- have NEVER been attempted before. Higher = more genuinely new ground. Measured
        pre-attempt so it can STEER selection toward novelty and away from convergence."""
        ang, surf, cls = _combo(move)
        return ((ang not in st.angle_counts) + (surf not in st.seen_surfaces)
                + (cls not in st.seen_classes))

    def _pick(self, st: HuntState):
        """A pending MODE-2 MUTATION is a bounded, immediate follow-up to a just-failed probe -- fire
        it PROMPTLY (before a queue reset loses it), any phase. In escalate: FIFO (deepen the foothold).
        In explore/pivot: reward NOVELTY -- prefer the least-tried angle, and among ties the move that
        opens the MOST new ground (novelty score). BREADTH FLOOR: if it has been `breadth_floor` real
        attempts since a never-tried angle and a fresh angle is queued, force that fresh angle."""
        if not st.queue:
            return None
        for i, m in enumerate(st.queue):
            if m.get("_mut_depth"):
                return st.queue.pop(i)
        if st.phase == "escalate":
            return st.queue.pop(0)
        if st.since_fresh_angle >= self.breadth_floor:
            fresh = [i for i, m in enumerate(st.queue) if angle_of(m) not in st.angle_counts]
            if fresh:
                return st.queue.pop(fresh[0])
        # DIRECTION FLOOR (no starvation): keep BOTH doors knocked. Every `direction_floor` real
        # attempts, if the under-probed direction (scaffold=stack+modules vs code=stack+app-code) is
        # actually behind AND has a queued move, force it -- so the budget splits across the two
        # directions instead of collapsing onto one (the board's converged floor rule).
        if self.direction_floor and st.since_other_dir >= self.direction_floor:
            under = self._under_probed_direction(st)
            other = "code" if under == "scaffold" else "scaffold"
            if st.direction_counts.get(under, 0) < st.direction_counts.get(other, 0):
                picks = [i for i, m in enumerate(st.queue) if direction_of(m) == under]
                if picks:
                    return st.queue.pop(picks[0])
        # COVERAGE-COMPLETENESS GATE (Phase A breadth, commercial-parity): before deepening, ensure EVERY
        # parity class gets >=1 probe. RESTRICT the candidate set to moves whose class is still UNCOVERED
        # (when any exist) -- the normal ranking below then chooses the BEST among them, so coverage breadth
        # is guaranteed WITHOUT overriding the novelty/verdict tie-break within the preferred set. Kill:
        # AEGIS_COVERAGE_GATE=0.
        cov_idx = None
        if str(os.environ.get("AEGIS_COVERAGE_GATE", "1")).lower() not in ("0", "false", "no", "off"):
            try:
                import coverage as _cov
                _unc = _cov.uncovered(st.covered_classes)
                if _unc:
                    ci = [i for i, m in enumerate(st.queue) if _cov.class_of(m) in _unc]
                    if ci:
                        cov_idx = set(ci)
            except Exception:
                cov_idx = None
        # WITHIN-RUN EXPLORATORY TAIL (board-converged): stratified EPSILON-DIVERSIFY-IN-WAVES. On an
        # epsilon fraction of EXPLORATORY picks, take a seeded-random move from a relevant-but-UNDER-
        # EXPLORED stratum (class x surface not yet tried this run) instead of the novelty-argmin -> one
        # run sweeps multiple seed-neighbourhoods (the variety that used to need multiple runs). Reached
        # only AFTER the breadth/direction floors above (floor-protected), only in explore/pivot (yields
        # to escalate/deepen), add-only (a queued, still-gated move), T0 stats untouched (flagged _eps).
        if cov_idx is None:                              # skip diversify while still covering (Phase A)
            ep = self._epsilon_pick(st)
            if ep is not None:
                return st.queue.pop(ep)
        # YIELD-WEIGHTED direction steering (board-converged): the floor above is the hard COVERAGE
        # guarantee; here we steer the EXPLORATORY remainder toward the higher-YIELD direction (UCB,
        # capped) so the budget digs where signal is -- without starving (the floor keeps both doors
        # knocked). Equal/early yields -> pref is None -> identical to the least-probed rule below.
        pref = self._dir_pref(st)

        def _dirkey(i):
            d = direction_of(st.queue[i])
            stopped = 1 if (self.mech5 and d in st.dir_stopped) else 0   # MECH5: stopped dir sorts LAST
            primary = (0 if d == pref else 1) if pref is not None else st.direction_counts.get(d, 0)
            return (stopped, primary,                                 # yield-preferred (or least-probed) dir
                    st.angle_counts.get(angle_of(st.queue[i]), 0),    # then least-tried angle
                    -self._novelty(st.queue[i], st),                  # then most-novel
                    _verdict_rank(st.queue[i]),                       # board verdict (late tie-break)
                    -_confidence(st.queue[i]),                        # higher confidence first
                    i)
        # COVERAGE gate restricts the candidate set to uncovered-class moves (when any); the ranking above
        # still picks the BEST among them, so breadth is guaranteed without overriding the tie-break.
        cand = sorted(cov_idx) if cov_idx else range(len(st.queue))
        idx = min(cand, key=_dirkey)
        return st.queue.pop(idx)

    def _epsilon_pick(self, st: HuntState):
        """Stratified epsilon-diversify-in-waves (board-converged). Returns a queue index to pick from a
        relevant-but-UNDER-EXPLORED stratum, or None to fall through to the normal novelty pick. Bounds:
        eps=AEGIS_EPS_FRAC (0.15, cumulative cap eps*budget; per-wave cap min(eps*budget, breadth_floor));
        wave = real_attempts // breadth_floor, RNG stream = H(AEGIS_SEED, wave); one draw per stratum per
        wave. Add-only (the returned move still passes the loop's novelty/dedup/angle gates) and marked
        `_eps` so the T0 bandit does NOT learn from it (keeps T0 stats identical to a non-epsilon run).
        Floor-protected: only reached after the breadth/direction floors; explore/pivot only (yields to
        escalate/deepen). Kill-switch: AEGIS_EPS_DIVERSIFY=0."""
        if str(os.environ.get("AEGIS_EPS_DIVERSIFY", "1")).lower() in ("0", "false", "no", "off"):
            return None
        if st.phase not in ("explore", "pivot") or not st.queue:
            return None
        try:
            frac = float(os.environ.get("AEGIS_EPS_FRAC", "0.15"))
        except Exception:
            frac = 0.15
        frac = min(0.20, max(0.0, frac))                 # board cap: never exceed 0.20
        E = max(1, self.budget)
        if st.eps_used >= int(frac * E):                 # cumulative cap -> stop epsilon for the run
            return None
        B = max(1, self.breadth_floor)
        wave = st.real_attempts // B
        if wave != st.eps_wave:                           # new wave -> re-seed a SEPARATE RNG stream
            import random as _r, hashlib as _h
            seed = str(os.environ.get("AEGIS_SEED", ""))
            hh = int(_h.sha256(f"{seed}|eps|{wave}".encode()).hexdigest()[:8], 16)
            st.eps_rng = _r.Random(hh); st.eps_wave = wave
            st.eps_wave_count = 0; st.eps_strata = set()
        per_wave_cap = max(1, min(int(frac * E), B))
        if st.eps_wave_count >= per_wave_cap:
            return None
        rng = st.eps_rng
        if rng.random() >= frac:                          # spread ~frac of exploratory picks as epsilon
            return None
        # relevant-but-under-explored strata among queued moves (class x surface not yet tried this run),
        # excluding strata already drawn this wave (one draw per stratum -> sweep, don't cluster).
        strata = {}
        for i, m in enumerate(st.queue):
            surf = str(m.get("surface") or m.get("path") or "")
            cls = str(m.get("vuln_class") or m.get("angle") or m.get("technique") or "")
            under = (surf and surf not in st.seen_surfaces) or (cls and cls not in st.seen_classes)
            if not under:
                continue
            key = (cls, surf)
            if key in st.eps_strata:
                continue
            strata.setdefault(key, []).append(i)
        if not strata:
            return None                                  # nothing under-explored -> forfeit to normal pick
        key = rng.choice(sorted(strata.keys()))
        idx = rng.choice(strata[key])
        st.queue[idx]["_eps"] = True                     # flag: T0 must not learn from an epsilon pick
        st.eps_used += 1; st.eps_wave_count += 1; st.eps_strata.add(key)
        return idx

    # ---- MECH5: cost-unit governor ----------------------------------------------------------------
    _COST = {"web": 1, "fact": 1, "authz": 1, "money": 1, "stateful": 1, "probe": 1, "code": 1, "rag": 1,
             "misconfig": 1, "differential": 2, "recon": 2, "static": 2, "fuzz": 3, "ossfuzz": 3,
             "supply_chain": 4}

    def _try_cost(self, move) -> float:
        """Estimated cost UNITS for a try (board's cost-asymmetry point): a cheap HTTP try = 1; a
        differential/recon = 2; a fuzz/ossfuzz = 3; a grype image scan / docker resource-persistence probe
        = 4; +1 for a concurrent (race) probe. Refined by the move's own action/oracle/concurrency."""
        base = self._COST.get(str(move.get("action", "web")), 1)
        if move.get("oracle") == "resource_persistence":
            base = max(base, 4)
        if int(move.get("concurrency", 1) or 1) > 1:
            base += 1
        return float(max(1, base))

    @staticmethod
    def _impact(move) -> float:
        """Expected-impact weight (yield numerator): severity x a money/auth/egress bonus."""
        w = {"critical": 2.0, "high": 1.6, "medium": 1.0, "low": 0.6, "info": 0.4}.get(
            str(move.get("severity", "medium")).lower(), 1.0)
        cls = str(move.get("vuln_class", "")).lower()
        if any(k in cls for k in ("money", "invariant", "idempotency", "authz", "auth", "ssrf", "exfil",
                                  "privesc", "business")):
            w *= 1.3
        return w

    def _maybe_stop_direction(self, st: HuntState, _dir: str):
        """MECH5 adaptive per-direction stop: once past the FLOOR and the direction's per-dir floor, stop it
        when marginal yield has flattened -- windowed mean < tau AND no new confirm in the window AND a
        non-positive slope (diminishing returns CONFIRMED, not just a cold streak) -- or when it hits its
        cost cap. The deterministic floor is exempt (never stopped below cost_floor)."""
        if not self.mech5 or _dir in st.dir_stopped:
            return
        if st.dir_cost.get(_dir, 0) >= self.dir_cost_cap:            # hard per-direction cost cap
            st.dir_stopped.add(_dir); return
        if st.cost_spent < self.cost_floor:                          # floor exempt -> never stop yet
            return
        per_dir_floor = max(10, int(0.3 * self.cost_floor))          # ~12 for a 40 floor
        if st.dir_cost.get(_dir, 0) < per_dir_floor:
            return
        hist = st.dir_yhist.get(_dir, [])
        W = 8
        if len(hist) < 2 * W:
            return
        ys = [y for y, _c in hist]
        last, prev = ys[-W:], ys[-2 * W:-W]
        mean_last = sum(last) / W
        recent_confirms = sum(c for _y, c in hist[-W:])
        tau = 0.12 * (self._median(st.floor_yields) if st.floor_yields else 0.5)
        slope_nonpos = (sum(last) / W) <= (sum(prev) / W)            # newer half <= older half
        if mean_last < tau and recent_confirms == 0 and slope_nonpos:
            st.dir_stopped.add(_dir)

    @staticmethod
    def _median(xs):
        s = sorted(xs)
        n = len(s)
        return 0.0 if n == 0 else (s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0)

    def _dir_pref(self, st: HuntState):
        """Yield-weighted UCB over the two reach directions (scaffold vs code), FLOOR-gated + CAPPED.
        Returns the direction to prefer for the exploratory remainder, or None to fall through to the
        default least-probed rule (early, floor-filling, equal-yield, or disabled). NON-inhibiting: the
        direction_floor in _pick still forces the under-probed direction for coverage; this only reorders
        preference among what's queued. Kill-switch: AEGIS_DIR_ADAPT=0 -> None (current behaviour)."""
        if str(os.environ.get("AEGIS_DIR_ADAPT", "1")).lower() in ("0", "false", "no", "off"):
            return None
        import math
        dirs = list(_LAYERS)
        counts = {d: st.direction_counts.get(d, 0) for d in dirs}
        tot = sum(counts.values())
        # still filling the per-direction floor -> defer to the floor / least-probed rule (coverage first)
        if tot < 2 * max(1, self.direction_floor):
            return None
        # CAP: if one direction already holds >= cap of the tries, prefer the OTHER (bounds runaway)
        cap = float(os.environ.get("AEGIS_DIR_CAP", "0.7"))
        for d in dirs:
            if tot > 0 and counts[d] / tot >= cap:
                return "code" if d == "scaffold" else "scaffold"
        # yield-weighted UCB: reward = confirmed findings per try in that direction
        def _score(d):
            n = counts[d]
            if n == 0:
                return float("inf")                       # try an unprobed direction first
            return st.dir_confirms.get(d, 0) / n + 0.5 * math.sqrt(math.log(max(1, tot)) / n)
        s = {d: _score(d) for d in dirs}
        # tie (equal score, e.g. both zero-yield) -> None so the least-probed rule keeps today's balance
        if abs(s[dirs[0]] - s[dirs[1]]) < 1e-9:
            return None
        return max(dirs, key=lambda d: s[d])

    def _under_probed_direction(self, st: HuntState) -> str:
        """The reach direction with fewer REAL attempts so far. Ties resolve to 'scaffold' so the
        platform door is always knocked, not only the app."""
        counts = {d: st.direction_counts.get(d, 0) for d in _LAYERS}
        return min(_LAYERS, key=lambda d: (counts[d], list(_LAYERS).index(d)))

    def _maybe_write_code(self, move, st: HuntState, direction: str, target, objective):
        """NOVEL-CODE PATH (board -> writer -> execute -> oracle -> RAG). When the board asked for a
        custom probe to be WRITTEN to open a foothold/bridge (move['needs_code'], or a move carrying a
        new_code BRIEF but no runnable code yet) AND a code_writer is wired, fan out to it: the writer
        (code bench + analyst) WRITES the contained, NON-DESTRUCTIVE probe onto the move (move['code'],
        typically action='probe'). Bounded per DIRECTION by max_novel_code so generated code can never
        dominate the budget. Offline-safe + injectable: no writer / any error -> move unchanged (it just
        runs as an ordinary move, judged by the oracle like any other)."""
        if not self.code_writer:
            return move
        wants = bool(move.get("needs_code")) or (bool(move.get("new_code")) and not move.get("code"))
        if not wants:
            return move
        if st.novel_code_counts.get(direction, 0) >= self.max_novel_code:
            return move                                  # per-direction novel-code cap reached
        st.novel_code_counts[direction] = st.novel_code_counts.get(direction, 0) + 1
        wrote = False
        try:
            out = self.code_writer(move, self._context(st, target, objective))
            if isinstance(out, dict):
                move = out
                wrote = bool(move.get("code"))
        except Exception:
            pass
        st.novel_code_log.append({"direction": direction, "wrote": wrote, "intent": intent_of(move),
                                  "brief": (str(move.get("new_code"))[:100] if move.get("new_code") else "")})
        return move

    # statuses that mean the app MEANINGFULLY HANDLED the request (so a refutation there taught us
    # something real). A bare 404 / connection error / timeout with no oracle evidence is padding.
    _INFORMATIVE_STATUS = {"200", "201", "202", "204", "206", "301", "302", "400", "401", "403",
                           "405", "406", "409", "413", "415", "422", "429", "500", "501", "502", "503"}

    def _info_gain(self, move, verdict, receipt, result, st: HuntState) -> int:
        """1 = real work (new information), 0 = noise -- the board's anti-padding rule. A confirmed
        foothold is always real. A REFUTATION counts as real only when it refuted WITH EVIDENCE: a
        not-seen-before response signature for this combo AND either an oracle receipt or a status that
        shows the app actually handled the request. Repeats, generic 404s, errors and timeouts are
        noise -- so a model cannot pad the 40 by poking nonexistent endpoints."""
        if verdict == "verified":
            return 1
        if (result or {}).get("blocked"):
            return 0                    # a guard-blocked move did no work -> noise, never a real attempt
        status = str((result or {}).get("status"))
        body = str((result or {}).get("body") or "")
        sig = (_combo(move), status, len(body) // 64)
        novel = sig not in st.seen_signals
        st.seen_signals.add(sig)
        if not novel:
            return 0
        # an unreachable/errored oracle receipt is NOT evidence -- treat it as noise so a dead target
        # (or a transport error) can never pad the real-attempt budget.
        has_evidence = bool(receipt) and not (isinstance(receipt, dict)
                                              and (receipt.get("error") or receipt.get("unreachable")))
        return 1 if (has_evidence or status in self._INFORMATIVE_STATUS) else 0

    # ---- board context ----------------------------------------------------------------------------
    def _context(self, st: HuntState, target, objective) -> dict:
        cap = self._angle_cap()
        over = sorted([a for a, n in st.angle_counts.items() if n >= cap])
        tried_angles = set(st.angle_counts)
        under = [a for a in (list(_NON_WEB) + [f for _, f in _TECH_FAMILIES]) if a not in tried_angles]
        try:
            pintel = (self.intel() if callable(self.intel) else self.intel) if self.intel else None
        except Exception:
            pintel = None
        # REACH AXIS state for the board: which of the two directions is under-probed, per-direction
        # confirmed footholds, bridges established, and how much novel-code budget remains per direction.
        under_dir = self._under_probed_direction(st)
        dir_counts = {d: st.direction_counts.get(d, 0) for d in _LAYERS}
        nc_left = {d: max(0, self.max_novel_code - st.novel_code_counts.get(d, 0)) for d in _LAYERS}
        how_far = list(getattr(_reach, "HOW_FAR_QUESTIONS", ()))
        return {"target": target, "objective": objective, "phase": st.phase,
                "planner_intel": pintel,      # OBSERVATORY: factual ranked techniques (not moves) -- novelty is yours
                "real_attempts_done": st.real_attempts, "real_attempts_target": self.budget,
                "budget_remaining": st.budget, "noise_so_far": st.noise, "confirmed": st.confirmed,
                "attempts": [{"move": a["move"], "verdict": a["verdict"], "gain": a["gain"],
                              "delta": a["delta"]} for a in st.attempts[-8:]],
                "avoid_signatures": list(st.tried),
                "closed_combos": ["/".join(map(str, c)) for c in sorted(st.closed)],
                "coverage": {"angle_counts": dict(st.angle_counts), "angle_cap": cap,
                             "over_explored": over, "under_explored": under},
                # REACH AXIS -- the paramount "how far can I go?" state, so the board splits its ideas
                # across the two directions and reasons about footholds/bridges/novel-code per direction.
                "reach": {"question": "HOW FAR CAN I GO here, non-destructively, without damaging the target?",
                          "directions": {"scaffold": "the STACK + INSTALLED MODULES only (framework, deps, "
                                         "runtime, container, config) as if NO app code were present",
                                         "code": "the stack TOGETHER WITH the app's ACTUAL code"},
                          "direction_attempts": dir_counts,
                          "under_probed_direction": under_dir,
                          "confirmed_directions": sorted(st.conf_directions),
                          "bridges_established": len(st.bridges),
                          "layer_breached_scaffold_to_code": st.layer_breached,
                          "lateral_hops": st.lateral_hops,
                          "novel_code_budget_left": nc_left,
                          "how_far_questions": how_far},
                "hypothesis_template": {"angle": "approach-family", "surface": "/api/..",
                                        "vuln_class": "e.g. sqli|idor|ssrf", "mechanism": "how it manifests",
                                        "precondition": "observable pre-state", "trust": "anon|user|admin|internal",
                                        "expected_oracle": "exact observable signal", "payload": "..",
                                        "layer": "scaffold|code", "intent": "map|foothold|bridge|escalate",
                                        "bridge_to": "what a bridge crosses TO (app_code|host|peer_host)",
                                        "needs_code": "true if a custom probe must be WRITTEN to open this",
                                        "new_code": "brief of the contained, non-destructive probe to write"},
                "instruction": (
                    "Propose up to 5 NOVEL next moves, each a FALSIFIABLE HYPOTHESIS in the "
                    "hypothesis_template shape. RULES: (1) each move must differ from EVERY prior "
                    "attempt on at least one of {surface, vuln_class, mechanism, trust, expected_oracle} "
                    "-- a payload-only tweak is NOT a new attempt; (2) each move in this batch must be a "
                    "DIFFERENT approach-family than the others; "
                    + (f"(3) do NOT propose these saturated angles: {over}; " if over else "")
                    + (f"prefer under-explored angles: {under[:8]}; " if under else "")
                    + (f"(4) do NOT re-open closed combos {['/'.join(map(str,c)) for c in sorted(st.closed)][:6]} "
                       "unless the move carries new_evidence=true; " if st.closed else "")
                    + "(5) every move MUST declare an expected_oracle (a concrete observable) -- moves "
                      "without one cannot be verified and are wasted. "
                    # --- REACH: the how-far framing, applied to BOTH directions ---
                    + f"(6) REACH: spend the next moves on the UNDER-PROBED direction '{under_dir}' so "
                      "BOTH doors get knocked -- tag every move with `layer` (scaffold|code). For EACH "
                      "direction ask: is there ANOTHER option open (backdoor/window/forgotten-or-debug "
                      "door/default-cred/exposed-secret)? is this layer CLOSED at all -- where's the "
                      "seam? can I establish a FOOTHOLD or a BRIDGE (scaffold->code, app->host, "
                      "host->host) to go DEEPER or LATERALLY? Tag `intent` (map|foothold|bridge|escalate) "
                      "and, for a bridge, name `bridge_to`. "
                    + ("(7) WHEN nothing already open lets you through, set needs_code:true and describe "
                       "in `new_code` the small, contained, NON-DESTRUCTIVE probe to WRITE (a custom "
                       "request/script targeting a gap in THIS stack or THIS app) to open the "
                       "foothold/bridge -- the code bench writes it, it is tried on the contained mirror, "
                       f"and proven/discarded by the oracle (novel-code budget left: {nc_left}). "
                       if any(nc_left.values()) else "")
                    + ("ESCALATE the confirmed foothold: change surface/vuln_class/mechanism/trust or "
                       "BRIDGE to a new layer/host (read->write, user->admin, scaffold->code, app->host) "
                       "-- not the same probe with a new payload."
                       if st.phase == "escalate" else
                       "PIVOT to a different approach-family / the under-probed direction." if st.phase == "pivot" else
                       "Explore high-EV / co-occurring classes across DISTINCT approach-families AND both "
                       "reach directions."))}

    @staticmethod
    def _delta(move, verdict, receipt) -> dict:
        return {"tested": {k: move.get(k) for k in ("surface", "technique", "param", "mechanism")},
                "outcome": verdict,
                "implies": ("primitive confirmed -> escalate (change surface/class/mechanism/trust)"
                            if verdict == "verified"
                            else "this hypothesis is refuted -> try a structurally different one"),
                "receipt": (receipt or {})}

    # ---- the loop ---------------------------------------------------------------------------------
    def _try_reopen(self, st: HuntState, target, objective, why: str) -> bool:
        """Ask the Planner for the NEXT candidate plan and inject its still-novel moves as fresh
        breadth, resetting the breadth allowance so the new scenario gets a fair run. Returns True if
        a re-open happened. Bounded by max_reopens; offline-safe (a reopen error = no re-open)."""
        if not self.reopen or st.reopens >= self.max_reopens:
            return False
        try:
            moves = self.reopen(self._context(st, target, objective), why) or []
        except Exception:
            moves = []
        fresh = [m for m in moves if self._novel(m, st)]
        if not fresh:
            return False
        st.reopens += 1
        st.queue = fresh
        st.stash = []
        st.phase = "pivot"
        st.no_progress = 0
        st.board_rounds = 0            # the new scenario gets its own breadth allowance (bounded overall by max_reopens)
        st.escalate_rounds = 0
        st.reopen_log.append({"why": why, "injected": len(fresh), "reopen": st.reopens})
        return True

    def run(self, target, objective) -> dict:
        # MECH5: the loop spends COST UNITS up to the CEILING (so the adaptive stop / ceiling govern
        # termination, not a flat try-count); legacy mode keeps the flat try budget.
        _init_budget = self.cost_ceiling if self.mech5 else self.budget
        _noise = max(self.max_noise, _init_budget) if self.mech5 else self.max_noise
        st = HuntState(budget=_init_budget, noise_left=_noise)
        st.queue = [m for m in self.seed_moves if self._novel(m, st)]     # MODE 1: anchor seeds first
        # RUN MONITOR: heartbeat + in-process watchdog for HANG detection (a wedged probe can't freeze the
        # run -- per-attempt hard timeout below) + wall-clock budget. Offline-safe; AEGIS_MONITOR=0 disables.
        try:
            from run_monitor import RunMonitor, run_attempt, leg_timeout
            _mon = RunMonitor(run_id=f"{target}")
        except Exception:
            _mon, run_attempt, leg_timeout = None, None, None
        while st.budget > 0 and st.noise_left > 0:
            # HANG / wall-clock: the watchdog set a stop flag (no heartbeat progress, or budget exceeded) ->
            # finalize partial results (confirmed findings are already recorded).
            if _mon is not None and _mon.should_stop():
                st.stop_reason = _mon.stop_reason() or "watchdog_stale"; break
            # MECH5: stop when BOTH directions have adaptively stopped (diminishing returns confirmed in
            # each) -- the deterministic floor already ran, so there is nothing productive left to spend on.
            if self.mech5 and len(st.dir_stopped) >= len(_LAYERS):
                st.stop_reason = "diminishing_returns_adaptive"; break
            # HARD TRY CEILING: never exceed ~max_tries real tries however cheap the cost mix (user cap).
            if self.mech5 and st.real_attempts >= self.max_tries:
                st.stop_reason = "try_ceiling"; break
            # BOARD INTERLEAVE: if the queue is being kept full by planner seeds / re-open, the
            # queue-empty brainstorm path below never fires -- so force a board round on a cadence and
            # put its novel cands FIRST, guaranteeing the context-aware novelty engine actually drives
            # (fixes: board_rounds=0 / unmoored planner-novel moves dominating under the Planner).
            if (self.brainstorm and st.phase != "escalate" and st.queue
                    and st.since_board >= self.board_cadence
                    and st.board_rounds_total < self.max_board_rounds):
                st.since_board = 0
                st.board_rounds += 1; st.board_rounds_total += 1
                bcands = [c for c in (self.brainstorm(self._context(st, target, objective)) or [])
                          if self._novel(c, st)]
                if bcands:
                    st.queue = bcands + [m for m in st.queue if self._novel(m, st)]   # board-first
            if not st.queue:                                              # need more moves
                # BOARD-ROUND ACCOUNTING: breadth reconvenes count against the breadth budget
                # (max_board_rounds). ESCALATION reconvenes are a SEPARATE, small allowance so a run
                # with many footholds cannot burn the breadth budget on deepening -- and when that
                # allowance is spent, escalation pivots back to breadth (restoring the stash) rather
                # than ending the whole run.
                if st.phase == "escalate":
                    st.escalate_rounds += 1
                    if st.escalate_rounds > self.max_escalate_steps:
                        st.phase = "pivot"; st.escalate_steps = 0
                        st.queue = [m for m in st.stash if self._novel(m, st)]; st.stash = []
                        continue
                else:
                    st.board_rounds += 1; st.board_rounds_total += 1; st.since_board = 0
                    if st.board_rounds > self.max_board_rounds:
                        if self._try_reopen(st, target, objective, "max_board_rounds"):
                            continue
                        st.stop_reason = "max_board_rounds"; break
                cands = [c for c in (self.brainstorm(self._context(st, target, objective)) or [])
                         if self._novel(c, st)]
                if not cands:
                    # board is out of ideas. If we were ESCALATING and preserved a breadth queue,
                    # resume that (award novelty) rather than ending the whole run on one thread.
                    if st.stash:
                        st.phase = "pivot"; st.escalate_steps = 0
                        st.queue = [m for m in st.stash if self._novel(m, st)]; st.stash = []
                        if st.queue:
                            continue
                    if self._try_reopen(st, target, objective, "board_saturation"):
                        continue
                    st.stop_reason = "board_saturation"; break
                st.queue = cands
            move = self._pick(st)
            if move is None:
                continue
            if not self._novel(move, st):
                continue
            ang = angle_of(move)
            combo = _combo(move)
            _dir = direction_of(move)                    # reach direction: scaffold | code
            if _reach is not None:
                try:
                    _reach.annotate(move)                # stamp layer+intent for oracle/report/writeback
                except Exception:
                    pass

            # GATE 1 -- escalation must be genuine DEPTH (not a lazy re-probe of the confirmed vuln).
            if st.phase == "escalate" and st.confirmed and not self._is_depth(move, st.confirmed[-1]["move"]):
                continue
            # GATE 2 -- angle cap (explore/pivot only): drop over-cap moves while a different angle is
            # still reachable, so the budget spreads instead of padding one approach.
            if st.phase != "escalate" and st.angle_counts.get(ang, 0) >= self._angle_cap():
                sat = self._saturated(st)
                if (any(angle_of(m) not in sat for m in st.queue)
                        or any(a not in st.angle_counts for a in (list(_NON_WEB) + [f for _, f in _TECH_FAMILIES]))
                        or st.board_rounds < self.max_board_rounds):
                    continue
            # GATE 3 -- no known-closed revisit: a combo refuted `close_after` times with no foothold is
            # closed; only a move bringing new_evidence may reopen it.
            if combo in st.closed and not move.get("new_evidence"):
                continue

            ang_novel = ang not in st.angle_counts                       # first touch of this angle?
            novelty = self._novelty(move, st)                            # 0-3, measured PRE-attempt
            # NOVEL-CODE PATH: if the board asked for a probe to be WRITTEN to open this foothold/bridge,
            # the code_writer writes it onto the move now (bounded per direction). Then dedup on the
            # FINAL move + execute (contained, non-destructive) + oracle proves/discards it.
            move = self._maybe_write_code(move, st, _dir, target, objective)
            st.tried.add(_sig(move))
            # PER-ATTEMPT HARD TIMEOUT + heartbeat (HANG fix): run the leg under a class-aware deadline so a
            # wedged probe is ABANDONED and the run continues instead of freezing. beat() at leg start so a
            # slow-but-alive leg (grype/headless) doesn't trip the watchdog.
            if _mon is not None:
                try:
                    import coverage as _cvm
                    _cv = f"{len(st.covered_classes & _cvm.PARITY_CLASSES)}/{len(_cvm.PARITY_CLASSES)}"
                except Exception:
                    _cv = "?"
                _mon.beat("leg_start", attempt=st.real_attempts, current_leg=str(move.get("action", "web")),
                          current_surface=str(move.get("surface") or move.get("path") or ""), coverage=_cv)
                result, _hung = run_attempt(lambda: self.execute(move, st.phase), leg_timeout(move))
                if _hung:
                    _mon.state["attempts_hung"] = _mon.state.get("attempts_hung", 0) + 1
                    result = {"status": -1, "body": "[hung -- per-attempt timeout; abandoned]", "move": move}
            else:
                result = self.execute(move, st.phase)
            verdict, receipt = self.oracle(result)
            try:                                          # COVERAGE: this parity class has now been probed
                import coverage as _cov
                if not (result or {}).get("blocked"):
                    st.covered_classes.add(_cov.class_of(move))
            except Exception:
                pass
            gain = self._info_gain(move, verdict, receipt, result, st)
            surf, cls = combo[1], combo[2]
            st.angle_counts[ang] = st.angle_counts.get(ang, 0) + 1
            st.seen_surfaces.add(surf); st.seen_classes.add(cls)
            st.combo_counts[combo] = st.combo_counts.get(combo, 0) + 1
            st.novelty_hist.append(novelty)
            st.attempts.append({"move": move, "verdict": verdict, "phase": st.phase, "angle": ang,
                                "gain": gain, "novelty": novelty, "delta": self._delta(move, verdict, receipt)})

            # INFORMATION-GAIN BUDGET: only real work advances the budget; noise is bounded separately.
            if gain > 0:
                st.real_attempts += 1
                # MECH5: spend COST UNITS (cost-asymmetry aware) instead of a flat 1; record per-try YIELD
                # = impact/cost (a confirm counts double) so a direction's marginal productivity is
                # measurable, then evaluate the adaptive per-direction stop. Legacy: flat 1.
                cost = self._try_cost(move) if self.mech5 else 1
                st.budget -= cost
                if self.mech5:
                    st.cost_spent += cost
                    st.dir_cost[_dir] = st.dir_cost.get(_dir, 0) + cost
                    _confirmed = (verdict == "verified")
                    yld = ((2.0 if _confirmed else 1.0) * self._impact(move)) / cost
                    st.dir_yhist.setdefault(_dir, []).append((yld, 1 if _confirmed else 0))
                    if st.cost_spent <= self.cost_floor:
                        st.floor_yields.append(yld)
                st.since_board += 1
                st.since_fresh_angle = 0 if ang_novel else st.since_fresh_angle + 1
                # REACH: count this real attempt toward its direction; if it advanced the direction that
                # WAS under-probed, reset the floor counter (both doors kept warm), else increment it.
                _under_before = self._under_probed_direction(st)
                st.direction_counts[_dir] = st.direction_counts.get(_dir, 0) + 1
                st.since_other_dir = 0 if _dir == _under_before else st.since_other_dir + 1
                self._maybe_stop_direction(st, _dir)     # MECH5: stop this direction if yield flattened
            else:
                st.noise += 1
                st.noise_left -= 1

            if verdict == "verified":
                st.confirmed.append({"move": move, "phase": st.phase})
                st.dir_confirms[_dir] = st.dir_confirms.get(_dir, 0) + 1   # yield-weighted direction split
                st.combo_foothold.add(combo)
                st.no_progress = 0
                # REACH: this direction now has a confirmed foothold. Detect a BRIDGE -- a confirm that
                # crossed to a NEW layer (scaffold->code) or a NEW host vs a PRIOR foothold: that is the
                # mechanical proof we "went further" (kimi/ds: a bridge needs an oracle-confirmed witness
                # AND a crossing; the oracle-verified verdict IS the witness). A bridge becomes a new
                # depth start below (novel_confirm -> escalate).
                st.conf_directions.add(_dir)
                _prior = [c["move"] for c in st.confirmed[:-1]]
                _bridged = next((fh for fh in reversed(_prior) if _is_reach_bridge(move, fh)), None)
                if _bridged is not None:
                    _from = direction_of(_bridged)
                    st.bridges.append({"from_layer": _from, "to_layer": _dir, "intent": intent_of(move),
                                       "surface": move.get("surface") or move.get("path") or move.get("target"),
                                       "bridge_to": move.get("bridge_to") or move.get("host"),
                                       "via_code": bool(move.get("code")), "phase": st.phase})
                    if _from == "scaffold" and _dir == "code":
                        st.layer_breached = True
                    _mh = str(move.get("host") or move.get("target") or "")
                    _fh = str(_bridged.get("host") or _bridged.get("target") or "")
                    if _mh and not _mh.startswith("/") and _fh and not _fh.startswith("/") and _mh != _fh:
                        st.lateral_hops += 1
                # AWARD NOVELTY, NOT CONVERGENCE: only ESCALATE (converge on this thread) when the
                # foothold opens NEW ground -- a surface or vuln-class not already confirmed. A repeat
                # confirm of an already-owned surface/class is logged but does NOT trigger convergence;
                # the budget stays on breadth.
                novel_confirm = (surf not in st.conf_surfaces) or (cls not in st.conf_classes)
                st.conf_surfaces.add(surf); st.conf_classes.add(cls)
                if st.phase != "escalate" and novel_confirm:
                    st.phase = "escalate"; st.escalate_steps = 0; st.escalate_rounds = 0
                    st.escalate_budget = max(1, int(self.escalate_frac * st.budget))
                    st.stash = st.queue                                   # PRESERVE breadth for later
                    st.queue = []                                         # reconvene for escalation moves
                # a repeat/known confirm (or one while already escalating) must NOT wipe the breadth
                # queue -- award novelty: keep exploring rather than converging on the win.
            else:
                st.no_progress += 1
                if st.phase == "escalate":
                    st.escalate_budget -= 1
                    st.escalate_steps += 1
                # MODE 2: mutate the failed move one degree along a distinctness axis and try it next.
                if self.mutate and move.get("_mut_depth", 0) < self.max_mutations:
                    m = self.mutate(move)
                    if m and _sig(m) not in st.tried:
                        st.queue.insert(0, dict(m, _mut_depth=move.get("_mut_depth", 0) + 1))
                # MECH 1: a CLEAN result that GAINED INFORMATION (not noise/404) is a hypothesis,
                # not a halt -- enqueue the deterministic deeper families (artifact-check /
                # implication / invariant-inversion) as fresh, novel breadth. Bounded: only from a
                # non-deepen (or shallow) parent, so deepening cannot recurse without limit.
                spawned_deepen = False
                if (self.deepen and gain > 0
                        and move.get("_deepen_depth", 0) < self.max_deepen):
                    try:
                        kids = self.deepen(move) or []
                    except Exception:
                        kids = []
                    for k in kids:
                        if _sig(k) not in st.tried and self._novel(k, st):
                            st.queue.append(k)          # breadth (FIFO): deepen without starving novelty
                            spawned_deepen = True
                # close a combo that has been refuted enough with no foothold. BOARD AUDIT (b):
                # CLEAN-LEG IMMUNITY -- an info-gaining clean leg that spawned deeper hypotheses is
                # evidence FOR the surface (more to try), not a dead-end, so it does NOT count toward
                # closing. Only UNPRODUCTIVE refutes (no new depth enqueued) push a combo closed; once
                # a combo's bounded deepen is exhausted, refutes count and it closes as before.
                if not spawned_deepen:
                    st.close_counts[combo] = st.close_counts.get(combo, 0) + 1
                if (combo not in st.combo_foothold
                        and st.close_counts.get(combo, 0) >= self.close_after):
                    st.closed.add(combo)

            # escalate exhausted / stalled / STEP-CAPPED -> pivot back to breadth (bound convergence),
            # RESTORING the preserved breadth queue so novel exploration resumes where it left off.
            # BOARD AUDIT (d) -- RING-FENCE the two-direction reach floor from escalation: escalate's FIFO
            # _pick bypasses direction_floor, so a long depth run can STARVE the under-probed direction.
            # Force an early exit back to breadth once the other direction has starved beyond a hard
            # multiple (2x) of direction_floor -- then the breadth-phase direction_floor can fire.
            _dir_starved = (self.direction_floor and st.since_other_dir >= 2 * self.direction_floor)
            if st.phase == "escalate" and (st.escalate_budget <= 0 or st.no_progress >= self.max_no_progress
                                           or st.escalate_steps >= self.max_escalate_steps or _dir_starved):
                st.phase = "pivot"; st.no_progress = 0; st.escalate_steps = 0
                st.queue = [m for m in st.stash if self._novel(m, st)]; st.stash = []
            # stalled while exploring: a stall on ONE angle is not a reason to quit -- pivot to a
            # DIFFERENT angle and keep spending the budget on genuinely different tries.
            elif st.phase != "escalate" and st.no_progress >= self.max_no_progress:
                fresh = any(a not in st.angle_counts
                            for a in (list(_NON_WEB) + [f for _, f in _TECH_FAMILIES]))
                if st.budget > 0 and (fresh or st.phase != "pivot"):
                    # rotate to PIVOT but KEEP the queue -- pending moves are still novel breadth to
                    # spend the budget on; only reconvene the board once the queue actually empties.
                    st.phase = "pivot"; st.no_progress = 0
                elif self._try_reopen(st, target, objective, "diminishing_returns"):
                    continue
                else:
                    st.stop_reason = "diminishing_returns"; break

        st.stop_reason = st.stop_reason or ("noise_ceiling" if st.noise_left <= 0
                                            else ("cost_ceiling" if self.mech5 else "budget_exhausted"))
        try:
            import coverage as _covmod
            _covsum = _covmod.summary(st.covered_classes)
        except Exception:
            _covsum = None
        if _mon is not None:
            try:
                _mon.beat("run_complete", attempt=st.real_attempts, confirmed=len(st.confirmed))
                _mon.close(state=("aborted" if st.stop_reason in ("watchdog_stale", "wall_clock_budget") else "done"))
            except Exception:
                pass
        return {"target": target, "objective": objective, "stop_reason": st.stop_reason,
                "attempts_used": len(st.attempts),          # total executions (real + noise)
                "real_attempts": st.real_attempts,          # information-gaining attempts
                # MECH5: cost-unit accounting -- what was actually SPENT vs the floor/ceiling, per direction,
                # and which directions were adaptively stopped on flattening yield.
                "cost": ({"spent": round(st.cost_spent, 1), "floor": self.cost_floor,
                          "ceiling": self.cost_ceiling, "per_direction": dict(st.dir_cost),
                          "stopped_directions": sorted(st.dir_stopped)} if self.mech5 else None),
                "coverage": _covsum,
                "noise_attempts": st.noise, "board_rounds": st.board_rounds,
                "board_rounds_total": st.board_rounds_total,
                "confirmed": st.confirmed, "attempt_log": st.attempts,
                "reopens": st.reopens, "reopen_log": st.reopen_log,
                "diversity": {"distinct_angles": len(st.angle_counts),
                              "angle_counts": dict(st.angle_counts),
                              "angle_cap": self._angle_cap(),
                              "distinct_hypotheses": len(st.tried),
                              "distinct_surfaces": len(st.seen_surfaces),
                              "closed_combos": len(st.closed)},
                # NOVELTY vs CONVERGENCE report: mean novelty of attempts + how many DISTINCT surfaces/
                # classes were confirmed (coverage) vs total confirms (a low ratio = over-convergence).
                "novelty": {"mean": round(sum(st.novelty_hist) / len(st.novelty_hist), 2) if st.novelty_hist else 0,
                            "hist": st.novelty_hist,
                            "confirmed_surfaces": len(st.conf_surfaces),
                            "confirmed_classes": len(st.conf_classes),
                            "total_confirms": len(st.confirmed)},
                # REACH -- HOW FAR the run got: which of the two directions (scaffold/code) yielded a
                # confirmed foothold, how many bridges extended reach, whether the scaffold->code seam
                # was crossed, and lateral hops. `depth` is a run-to-run comparable integer.
                "reach": (_reach.reach_summary(st.conf_directions, st.bridges, st.layer_breached,
                                               st.lateral_hops) if _reach else
                          {"directions_reached": sorted(st.conf_directions), "bridges": len(st.bridges),
                           "layer_breached_scaffold_to_code": st.layer_breached,
                           "lateral_hops": st.lateral_hops}),
                "reach_detail": {"direction_attempts": dict(st.direction_counts),
                                 "bridges": st.bridges, "novel_code": st.novel_code_log,
                                 "novel_code_counts": dict(st.novel_code_counts)}}


def board_brainstorm(context: dict) -> list:
    """Real wiring: a MULTI-ROUND board fan-out. Each call is one round -- the board sees the full
    history + deltas + coverage + closed combos in `context` and returns NOVEL hypothesis moves.
    Sanitize privileged context before the panel."""
    import os, sys
    HERE = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, HERE)
    # LIVELY BOARD: when enabled, run the bounded MULTI-MODEL DISCUSSION (propose -> critique -> converge)
    # instead of a single static pass. It returns the SAME hypothesis moves (now carrying verdict/
    # confidence/dissent) and writes a transcript for live_board.ps1. Offline-safe: [] falls through to
    # the single-pass below. Kill-switch AEGIS_BOARD_DISCUSS=0.
    try:
        import board_discuss as BD
        if BD.enabled():
            moves = BD.board_discuss(context)
            if moves:
                return moves
    except Exception:
        pass
    import remediation_board as RB
    reach_doctrine = getattr(_reach, "BOARD_REACH_DOCTRINE", "")
    sysp = ("You are the discovery board on an AUTHORIZED contained mirror. Given the attempt history, "
            "oracle deltas, `coverage`, `reach`, and `closed_combos`, output up to 5 NOVEL next moves as "
            "JSON lines in the `hypothesis_template` shape: "
            '{"angle":"..","surface":"/api/..","vuln_class":"..","mechanism":"..","precondition":"..",'
            '"trust":"anon|user|admin|internal","expected_oracle":"exact observable","payload":"..",'
            '"layer":"scaffold|code","intent":"map|foothold|bridge|escalate","bridge_to":"app_code|host|peer_host",'
            '"needs_code":false,"tool":"kali-tool-or-empty","new_code":"brief of the contained probe to WRITE '
            'if no tool fits","why_novel":".."}. '
            + (reach_doctrine + " " if reach_doctrine else "")
            + "RAW MATERIAL FOR NOVELTY -- use it, do not just label: (a) `planner_intel.attack_toolset` is "
            "MITRE ATT&CK / technique-DB entries (each with `tools`, `how_to_test`, `mitre_tactics`) already "
            "pulled from the RAG and ranked for THIS target -- COMBINE and CHAIN them (mix techniques, chain "
            "tactics, compose/adapt their tools) into novel approaches; (b) prefer tools in "
            "`planner_intel.kali_tools_present` (actually installed here) -- name the one you use in `tool`; "
            "(c) when no installed tool fits, WRITE a custom approach: a short Python probe / crafted request "
            "in `new_code` that targets a gap in THIS code's behaviour (a zero-day-style hypothesis). Keep "
            "EVERY move RELEVANT to `planner_intel.target_stack` (this app's actual code/stack) -- no "
            "off-stack techniques -- then go beyond the DB with genuinely new, UNTESTED ideas. Ground every "
            "move in the live oracle deltas + confirmed footholds; never run a DB entry verbatim. "
            "HARD RULES: (1) every move MUST differ from EVERY prior attempt on at least one of "
            "{surface, vuln_class, mechanism, trust, expected_oracle} -- a payload-only tweak is NOT a "
            "new attempt and will be rejected; (2) each move in the batch must be a DIFFERENT "
            "approach-family (angle); (3) never propose an over_explored or closed combo (unless you set "
            'new_evidence=true); (4) every move MUST carry a concrete expected_oracle or it is wasted. '
            "Angles include authz, injection, ssrf, ssti, xxe, traversal, auth, mass_assignment, race, "
            "csrf, deserialization, business_logic, info_disclosure and non-web vectors supply_chain, "
            "static, fuzz, misconfig, recon, rag.")
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
    txt = RB._post_openai_style(ep + "/chat/completions", os.environ.get("AEGIS_LLM_API_KEY", ""),
                               "deepseek-v4-pro", sysp, json.dumps(context)[:6000], 1600, think=False)
    moves = []
    for line in (txt or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):          # ignore non-object JSON (arrays/scalars) from the board
                    moves.append(obj)
            except Exception:
                pass
    return moves


# ---------------- T0/T1 TIERED BRAINSTORM (board = ranker / stall-breaker) ----------------
# The board-converged architecture: a UCB bandit (T0) learns which technique-CLASS pays off and ranks;
# DETERMINISTIC generators (T1: MECH3 synth anchored on CONFIRMED footholds) supply cheap runnable moves;
# the multi-model board (board_brainstorm) is called only as the STALL-BREAKER / cold-start explorer, not
# every round. Preserves the board entirely (it still runs) -- this only gates WHEN it is asked, so the
# COLD board functions (code_review/remediation/board_ask/...) are untouched. Kill: AEGIS_TIERED_BRAINSTORM=0.
_BANDIT = None


def _get_bandit():
    global _BANDIT
    if _BANDIT is None:
        try:
            import t0_bandit as _tb
            _BANDIT = _tb.Bandit(path=_tb.default_path())
        except Exception:
            _BANDIT = False                      # sentinel: bandit unavailable -> pure board behaviour
    return _BANDIT


def tiered_brainstorm(context: dict, board_fn=None) -> list:
    """Deterministic-first hypothesis generation with the board as stall-breaker. Returns hypothesis moves
    (same shape board_brainstorm returns), each tagged with `tier` + `arm` for the audit."""
    board_fn = board_fn or board_brainstorm
    if str(os.environ.get("AEGIS_TIERED_BRAINSTORM", "1")).lower() in ("0", "false", "no", "off"):
        return board_fn(context)
    bandit = _get_bandit()
    if not bandit:
        return board_fn(context)
    import os as _os
    try:
        import t0_bandit as _tb
        _tb.learn_from_context(bandit, context)          # T0: fold observed rewards in
    except Exception:
        pass
    confirmed = (context or {}).get("confirmed") or []
    closed = set()
    for c in (context or {}).get("closed_combos") or []:
        parts = str(c).split("/")
        if len(parts) >= 3:
            closed.add(parts[2].lower())                 # the class segment of an over-explored combo
    ranked_arms = bandit.select(k=4, exclude=closed)
    # T1: MECH3 synth composed on CONFIRMED footholds (the deterministic depth the planner can't pre-seed
    # because it runs before any confirm). Cold start (no confirms) -> T1 empty -> board explores.
    t1 = []
    if confirmed:
        try:
            import technique_synth as _ts
            t1 = _ts.synthesize(confirmed=confirmed, limit=int(_os.environ.get("AEGIS_SYNTH_MOVE_CAP", "4")))
        except Exception:
            t1 = []
        # prefer synth moves whose class the bandit currently favours (ranker role); stable, best-first
        def _prio(m):
            cls = str(m.get("vuln_class") or "").lower()
            hit = next((i for i, a in enumerate(ranked_arms) if a in cls or cls in a), len(ranked_arms))
            return hit
        t1.sort(key=_prio)
        for m in t1:
            m["tier"] = "T1-synth"; m["arm"] = m.get("vuln_class")
    # Call the board (stall-breaker / deep-seek / NOVELTY QUOTA). Board = the only MULTI-MODEL generative
    # novelty source; synth (T1) only recombines KNOWN classes, so gating the board purely on stall would
    # SUPPRESS true novelty once a foothold exists (board audit finding (c), unanimous). So also give the
    # board a periodic NOVELTY QUOTA: every K-th confirmed foothold, and whenever T1 yields < M distinct
    # deterministic moves. Cases: (1) STALL (pivot); (2) DEEP-SEEK (escalate -- RT pivots fire here); (3)
    # T1 thin (< M distinct); (4) QUOTA (K new confirms since the board last ran). Else skip the board.
    phase = (context or {}).get("phase")
    M = int(os.environ.get("AEGIS_BOARD_MIN_SYNTH", "2"))
    K = int(os.environ.get("AEGIS_BOARD_FOOTHOLD_QUOTA", "3"))
    n_conf = len(confirmed)
    last_served = getattr(bandit, "_board_served_at", -1)
    quota_due = n_conf > 0 and (n_conf - last_served) >= K
    thin = len({(m.get("surface"), m.get("technique")) for m in t1}) < M
    stall = phase in ("pivot", "escalate") or not t1 or thin or quota_due
    if stall:
        bandit._board_served_at = n_conf
    out = list(t1)
    if stall:
        try:
            bmoves = board_fn(context) or []
        except Exception:
            bmoves = []
        for m in bmoves:
            if isinstance(m, dict):
                m.setdefault("tier", "T3-board")
                m.setdefault("arm", m.get("vuln_class") or m.get("angle"))
                bandit.register(str(m.get("arm") or "").lower())
        # dedup: don't return a board move a synth move already covers (surface+class)
        seen = {(str(m.get("surface")), str(m.get("vuln_class") or "").lower()) for m in t1}
        out += [m for m in bmoves if isinstance(m, dict)
                and (str(m.get("surface")), str(m.get("vuln_class") or "").lower()) not in seen]
    try:
        bandit.save()
    except Exception:
        pass
    return out
