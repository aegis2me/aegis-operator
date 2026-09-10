# Board deepening — go further, find more, beyond the human eye, without destroying the system

Coordinator (Claude) board contribution. The full multi-model panel (`board_ask.py`) + the HuggingFace
Aug-2026 incident report couldn't be processed in the build session (Bash blocked; PDF needs poppler). This
is Claude's proposal to merge with the panel's takes and the report specifics in a fresh session.

Goal (user): improve the whole mechanism to dig DEEPER + FURTHER and find MORE — even where a human sees
nothing — with the board inventing novel ways and EXPANDING its own techniques internally, going beyond a
standard red team, all NON-DESTRUCTIVELY.

## Principle: "no more here" is a HYPOTHESIS, not a stop
Every clean/empty leg must spawn a deeper hypothesis tree, never a halt. Three generators the board runs on
a "clean" result:
1. **Artifact check** — is "clean" real or an oracle artifact? (the SPA-200 lesson: a 200 that equals a
   nonexistent-path baseline proved nothing). Distinguish before believing a negative.
2. **Implication attack** — what does "secure here" IMPLY that becomes the next target? "Logout invalidates
   the session" -> now attack the invalidation MECHANISM: race the logout, concurrent sessions, fixation,
   token reuse across the revocation window.
3. **Invariant inversion** — instead of "can I reach X", ask "what INVARIANT must hold for X to be safe, and
   is there a PATH that violates it that nobody gates?" (this is exactly what found the credit-note
   over-credit: sum(credits)<=invoice.total, violated via a second door). Every "safe" surface has an
   invariant; enumerate and try to break each by an ungated path.

## Mechanism 1 — DIFFERENTIAL / oracle-diversity discovery (see what a human can't)
A human checks one signal (status/body). The board runs MANY oracles on the SAME interaction and reads the
DELTAS a human never computes: response TIMING (side-channels/TOCTOU), size, error-message entropy, business
STATE-metric deltas (the stateful measure), cross-role / cross-session / cross-order response diffs,
header/field-order fingerprints. The DIFFERENCE between two responses that "look identical" to a human is
where novel bugs live. Add a `differential` oracle family: run N variants (role x time x order x
concurrency), flag any statistically-significant delta as a lead the loop must chase.

## Mechanism 2 — board-INTERNAL technique synthesis (self-expanding, not just DB ranking)
Today the board RANKS known techniques + writes novel-code. Add a technique-SYNTHESIS loop that INVENTS:
- **Cross-product of two known classes** -> a new one: replay x cross-user = replay-as-another-identity;
  invariant x timing = TOCTOU-on-invariant; mass-assignment x second-route = privilege-field via the back
  door; idempotency x concurrency = double-effect race.
- Fingerprint the synthetic technique, try it (novel-code probe, non-destructive), and on an oracle-VERIFIED
  win **write it back to learned_techniques.json as a technique the board INVENTED**. The MITRE + curated DB
  is the seed; the board's cross-products are the expansion. Over time the DB grows techniques no human
  seeded — "expanded internally in the board." Guard against combinatorial blow-up with the same
  distinctness-fingerprint + information-gain budget the loop already uses.

## Mechanism 3 — deeper-than-red-team via CHAIN + STATE, not destruction
Standard red team = foothold + escalate (often destructive). Go FURTHER without damage:
- The **campaign relay** (each leg deeper, no replay) — already built (2-tier proven; 3-tier wired).
- **Attack-graph reasoning over CONFIRMED edges** — the board reasons "confirmed foothold A + weakness B +
  violable invariant C => a chain to crown-jewel D" and PROVES the chain step-by-step, each step
  oracle-verified, none destructive (plant-for-proof, never erase). Depth = chain length + invariant-severity,
  MEASURED — not blast radius.
- **Reachability/impact proof without harm** — prove you COULD reach/alter X by planting an inert marker and
  showing the path, then snapshot-restore. The non-destructive doctrine is an ENABLER: because we never
  erase, the board can EXPLORE more aggressively (replay/chain/race under snapshot) than a human who fears
  breaking prod. Depth without damage.

## Mechanism 4 — LEARN-FROM-INCIDENTS pipeline (turn a real report into a discovery path)
A real-world incident report is a ground-truth attack narrative. Build an ingester: incident report ->
extract (a) attack PRIMITIVES used (each -> a new technique class), (b) DEFENDER BLIND SPOTS (each -> a new
oracle/leg), (c) ROOT-CAUSE class (each -> an invariant to check on our own targets) -> emit new
techniques_db entries + oracle hypotheses -> the board tries them on the mirror. THIS is how the HF Aug-2026
report feeds the discovery path (fold in once it's readable): map its kill-chain to our technique classes,
its missed-signals to our differential oracles, its root cause to an invariant family we assert everywhere.
(Reuse the RAG ingest pattern — like ingest_mitre.py — as `ingest_incident.py`.)

## Mechanism 5 — keep-digging budget = information-gain x expected-impact
The loop should spend MORE where board uncertainty is HIGH and impact is HIGH (money paths, auth, data
egress), and where a leg returned "clean" but the board's meta-reasoning says "clean here is surprising /
weakly tested." A scheduler weighting attempts by expected information gain x expected impact makes it dig
exactly where a human gives up but signal remains — instead of uniform breadth.

## Where to wire it (minimal-diff, reuses what exists)
- `operator/vectors.py`: a `differential` leg (N-variant runner + delta detector); the `stateful`/relational
  oracles already give the state-delta measure.
- `shared/verified_findings.py`: `DifferentialOracle` (significant delta across variants) + a `ChainOracle`
  (a sequence of oracle-verified edges reaching a goal state).
- `operator/board_discuss.py` / planner: the technique-SYNTHESIS wave (cross-product of ranked classes) +
  writeback of invented techniques to `learned_techniques.json`.
- `rag/ingest_incident.py`: incident report -> primitives/blind-spots/root-causes -> techniques_db + oracle
  seeds (mirror ingest_mitre.py).
- The loop's scheduler: add the info-gain x impact weighting; "clean" results enqueue the 3 deeper
  hypotheses above instead of closing the surface.

## Non-destructive invariant (non-negotiable, throughout)
Every mechanism above obeys the doctrine: plant/write/replay/chain FOR PROOF, snapshot-restore, NEVER
erase/delete, no off-box egress. Depth is measured by chain length + invariant severity + novelty, not by
damage. That is the whole point — see and do more than a standard red team WITHOUT destroying the system.

## Fresh-session follow-ups (Bash needed)
1. Install poppler (apt) -> read the HF Aug-2026 report -> run `board_ask.py` with this proposal as
   `--claude` so the FULL panel (ds/kimi/llamas/r1-distill/qwq) critiques + extends it.
2. Build `ingest_incident.py` on the report -> seed the new techniques/oracles -> try them on the mirror.
3. Prototype the `differential` leg + `DifferentialOracle` + the technique-synthesis wave; prove each on the
   mirror (a differential/timing lead, a board-invented technique that verifies).

## CODE-WRITER + SYNTHESIZER placement (board-validated 2026-09-10; unanimous)
The code-writer serves TWO jobs (keep them distinct):
- **FIND (novel-code for zero-day gaps)** -- discovery; wants DIVERGENCE -> this is the high-value/high-
  uncertainty lane that MAY escalate to the ensemble.
- **CONFIRM (probe-code to prove a suspected gap)** -- verification; wants a cheap CORRECT single writer ->
  retrieval-first + fast coder. This is the common case and must stay cheap.

SYNTHESIZER (MECH 3) = T1 DETERMINISTIC (grammar/e-graph cross-product over techniques_db) -- off the board;
board only ranks/invents on stall.

CODE-WRITER pipeline (gated execution-enabler, NOT consensus-per-write):
1. GATE behind the selector: write only for the bandit/deterministic-chosen candidate that passes an
   expected-gain threshold AND is a retrieval-miss AND is actually necessary (T0/T1 can't answer it). Board
   ranker may FORCE a write on selector stall.
2. RETRIEVAL FIRST from learned_techniques. Key = (target_id + target_version/schema_hash,
   surface_canonical_signature, technique_class, oracle_type, env/toolchain_hash). Reuse ONLY on exact key
   match + >=k verified runs + success-rate>=s + within TTL + a LIGHT oracle re-verify (no LLM). NEVER reuse
   across schema/toolchain drift (silent-wrong-answer). Re-write on drift/flakiness.
3. TIERED CODER: FAST coder (qwen2.5-coder / llama-4-scout) default for routine CONFIRM probes; deepseek-v4-pro
   for high-value; ensemble (DS+qwen) only for the FIND/high-uncertainty lane. Keep ordered fallback.
4. qwq = VERIFIER that RUNS the probe (not static "looks right"; not a per-write vote); budget-capped.
5. ENSEMBLE TRIGGER = OBSERVE uncertainty, don't predict it. Cheapest signal: first-attempt ORACLE SELF-TEST
   FAILURE -> escalate. Also: high-impact surface (money/auth/egress) + surface-novelty + historical low
   write-success on the class + parse/compile failure. (kimi's weighted signal formula.)
6. WRITEBACK poisoning gate (the #1 risk, both ds+kimi): write back ONLY if the probe passed its oracle on
   >=k DISTINCT inputs/instances (not one-off) + qwq-verified + PARAMETERIZED (reject hardcoded literal-target
   constants) + provenance + success/failure counters. Auto-DEMOTE/EVICT on first downstream failure (decaying
   reliability). Treat learned_techniques as a CACHE WITH EVICTION, not a trusted store.
7. NEGATIVE CACHE: remember FAILED probes so they aren't re-attempted every round.
8. COST BACKPRESSURE: hard budget cap + fail-fast timeout on the coder call so escalation-creep can't restore
   the cost. Feedback: actual info-gain + probe reliability -> the T0 BANDIT (classes that yield reusable
   verified probes get prioritized).

TOP 3 RISKS (converged): (1) writeback poisoning via brittle/overfit probes -> multi-instance oracle +
eviction; (2) staleness reuse across target drift -> schema/toolchain hash in the key + cheap re-verify;
(3) escalation creep (ensemble becomes default) -> hard budget cap + OBSERVED-failure trigger, not predicted.
Non-destructive throughout.

## MECHANISM INTERACTION AUDIT (board + Claude, 2026-09-10) -- do the mechanisms ALIGN?
User asked: do all built-in mechanisms ALIGN (novelty / randomness / deep-seeking / progressing further)
or does any one CANCEL / INHIBIT / BLOCK another -- across ALL THREE stages? Full panel (ds + coders) +
Claude. VERDICT: NO mechanism CANCELS another; the design is strictly LAYERED (generators PROPOSE -> bandit
RANKS -> the scheduler is the sole AUTHORITATIVE gate). Conflicts found were BUDGET/ORDERING only, all
fixable by reservation/ordering/quota. 5 INHIBIT pairs (now FIXED), 2 ALIGN. Holds for all 3 stages (one
shared loop; doctrine wrappers only ADD guards, never loosen the scheduler).

| Pair | Verdict | Fix (implemented) |
|---|---|---|
| (a) bandit exploit vs breadth floors | ALIGN | bandit stays ADVISORY; max_angle_share/breadth_floor/direction_floor gate after ranking |
| (b) deepen-on-clean vs close_after | INHIBIT->FIXED | clean-leg immunity: only UNPRODUCTIVE refutes (no deepen kids) count toward closing (close_counts) |
| (c) tiered gating the board | INHIBIT->FIXED | board NOVELTY QUOTA: also every K-th foothold / when T1 thin, not stall-only |
| (d) escalation vs two-direction reach | INHIBIT->FIXED | ring-fence: force exit from escalate to breadth once other direction starved > 2x direction_floor |
| (e) UCB+synth determinism | INHIBIT->FIXED | seeded stochastic tie-break (bandit) + seeded synth emission shuffle (AEGIS_SEED) |
| (f) relay depth vs fresh breadth | INHIBIT->FIXED | ring-fence fresh-breadth frac 0.35 (was 0.2) + absolute anchor cap per stage |
| (g) writeback low-yield poisoning | ALIGN(hole)->FIXED | evict on failure OR low-yield (yield<min_rate over >=min_trials), not failure-only |

Highest-impact fixes: (c) board suppression post-foothold, and (d) depth starving breadth. Both were
stage-invariant, worst in Red-Team (longest campaigns + 3-tier relay). Raw panel answers:
board/board_files/ANSWER__*__17890305*.md.
