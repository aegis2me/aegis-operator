# AEGIS full-mechanism review (board + Claude, 2026-09-10)

Panel: ds_direct + coders (kimi, r1-distill, llama-3.3) + Claude self-assessment. Strong consensus.
Constraint honored: recommendations stay non-destructive, contained, reasonable for security testing.

## Theme
The FINDING mechanisms (oracles / stateful / differential / synth / reach axis) are the value and are sound.
The META-SELECTION layer is where the over-engineering lives. CUT there; reinvest the budget in the missing
oracles below.

## (1) Workings — real flaws to fix
- **MECH2 self-confirmation:** a differential LEAD promoted by another differential delta is circular. The
  2nd confirmation (incl. the HIGH >=2 rule) MUST be an INDEPENDENT oracle CLASS (e.g. Invariant + AuthState),
  not a variant re-run.
- **Selection controllers can starve each other at 50 tries:** UCB bandit x yield-split x epsilon x cost all
  vote on the next try; at ~50 decisions the UCB has no statistical power (it's noise). One exploration channel.
- **CLEAN-LEG IMMUNITY + close_after = stall trap** on a genuinely clean surface (immune leg burns the
  ceiling). Cap immunity by info-gain DECAY, not just "clean".
- **MECH1 deepen fires on recon noise** that passed the info-gain filter. Gate deepen on a STATE-CHANGING or
  AUTH-BOUNDARY leg only.
- **Escalation shares the breadth budget** -> a late novel confirm can starve breadth_floor. Give escalation a
  small SEPARATE reserve.
- **Static cost weights vs yield-slope stop:** a cheap-but-dead angle outlives an expensive-but-productive one.
  Weight the stop by COST-PER-CONFIRM.
- **Applicability judged pre-mirror** -> false-negatives (a technique marked inapplicable never gets a probe).
  Make applicability PROVISIONAL until one mirror probe.
- **Grype lists CVEs without reachability:** add call-graph/reachability pruning so scaffold CVEs are ranked by
  whether the app actually reaches the vulnerable function.

## (2) Missing (concrete blind spots — priority)
The stack is money/logic-heavy and AUTHN-SHALLOW. Blind to:
1. **IDOR/BOLA enumeration breadth** (role x object-id x verb matrix) -- the #1 real-world API bug; UNANIMOUS.
2. **Authn/session depth:** JWT alg=none/kid confusion, reset-token reuse/entropy, session fixation, MFA bypass
   via response tampering, account enumeration (timing/status), cookie flags.
3. **SSRF/egress:** via an in-mirror CANARY listener (contained) -- currently unconfirmable, silently dropped.
4. **Mass-assignment / API schema depth:** OpenAPI/route-driven field-level (readOnly bypass, additionalProperties,
   nested/polymorphic) -- current mass-assign cross-products are too coarse.
5. **File-upload / path-traversal / zip-slip** -- absent (proof = plant a benign marker inside the sandbox).
6. **Rate-limit / lockout / brute-force** -- absent (proof = N+1, observe 429/lockout, stop).
7. **Multi-step business logic beyond money:** coupon stacking, referral self-credit, refund-after-ship,
   state-machine skips (order->shipped without payment). Invariant oracle generalizes but isn't instantiated.
8. **Secrets/PII in responses** (keys/tokens/other users' PII, stack traces) -- cheap, high-yield regex pass.
9. **Client-side/DOM** (if the mirror serves JS): DOM-XSS, postMessage, open-redirect.

## (3) Optimise for results -- top 3 (highest leverage)
1. **IDOR/BOLA enumeration engine as a first-class oracle** -- deterministic role x object x verb sweep from the
   mirror's own routes; confirm on cross-role 200-with-foreign-data. Cheap (HTTP=1), reads-only. Typically
   out-yields the entire money-logic suite in real apps.
2. **Canary SSRF + secrets-in-response oracle** -- one in-mirror listener + one regex pass over every response.
   Near-zero cost; converts two currently-unconfirmable classes into ORACLE-verified findings.
3. **Class-independent 2nd oracle, gate HIGH on it** -- fixes the MECH2 double-count; fewer false HIGHs -> budget
   stops chasing echoes -> frees budget for (1) and (2).
Runner-up: instantiate the Invariant oracle for non-money state machines (order/refund/coupon) -- near-free,
reuses existing machinery. + schema-driven API fuzzing turns MECH3 from guesser into coverage-guided finder.

## (4) Overboard -- cut/simplify (for a ~50-try contained run)
- **Selection stack: 4 mechanisms solving one problem** (where to spend the next try). CUT to DETERMINISTIC-FIRST
  + a single EPSILON-GREEDY over technique-classes. DELETE the T0 UCB bandit (no power at 50 tries) + the
  wave-stratifier. (Unanimous.)
- **Cost-predictor / replayable pricing / by-model-stage ledger** = enterprise telemetry for a 50-try run. CUT to
  a running unit counter + hard ceiling; keep the ledger ONLY for cross-campaign comparison.
- **MECH5 adaptive stop:** don't tune further; simplify to "stop after K consecutive no-confirm legs".
- **MECH3 cache-with-eviction:** premature -> in-memory, evict on failure.
- **Ensemble code-writer:** keep fast-coder only; wire the ensemble path only once it's seen to fire.
- **Sol:** booted (done).

## Suggested build order (if adopted)
A. Fix (1)-flaws that are cheap + high-value: class-independent 2nd oracle; deepen gate; immunity decay.
B. Add the missing oracles in yield order: IDOR/BOLA sweep -> secrets-in-response -> SSRF canary ->
   rate-limit/lockout -> file-upload marker -> non-money invariants -> schema-driven mass-assign.
C. SIMPLIFY the selection layer (deterministic-first + epsilon-greedy; retire bandit/wave-stratifier/cost-
   predictor to kill-switched dormancy rather than deletion, so nothing is lost).

---

# ADDENDUM — COMMERCIAL PARITY (5/5) under free-compute + 40-min wall-clock (board + Claude)

New constraints: match commercial suites (Burp Pro / Acunetix / Invicti / ZAP); local compute FREE; budget =
20-40 min wall-clock + REAL results (try-count is NOT the constraint). This PARTIALLY INVERTS the "cut the
selection stack" verdict (that was correct only at ~50 tries).

## Keep vs cut (revised)
- KEEP + re-arm: **UCB bandit** (now COVERAGE-AWARE: reward = new-class coverage + oracle-confirmed finding);
  **tiered** (tier by class-coverage DEFICIT, not prior yield); **epsilon** (lower to 0.05-0.1, anti-stagnation
  only -- UCB now handles exploration). At 200-500 tries these regain statistical power for BREADTH scheduling.
- CUT regardless of try-count: **cost-PREDICTOR** (free compute -> predicting cost to avoid a probe is anti-goal;
  keep a DURATION timer for scheduling, not a predictor); **yield-split** (a scarce-try budget heuristic; folds
  into the coverage-deficit scheduler which does it better).

## Budget model: wall-clock + HARD COVERAGE GATE
- Governor = WALL-CLOCK (default ~30 min, cap 40) + adaptive stop; retire the hard 50-try cap.
- **Coverage-completeness gate (hard barrier):** maintain a checklist of every OWASP Top 10 (2021) + API Top 10
  (2023) class; NO depth spend on any class until EVERY class has >=1 ORACLE-VERIFIED probe executed. This is
  what makes a "5/5 coverage" claim defensible.
- **Phase A breadth sweep** (~40%, ~16 min): one canonical probe per class, PARALLEL. **Phase B depth** (~60%,
  ~24 min): coverage-aware bandit spends remaining time on highest-yield leads; classes with 0 hits get a
  floor of mutated retries. **Reserve ~10%** of wall-clock to RE-RUN any class that errored/timed out.
- Adaptive stop only AFTER the coverage gate passes.

## Missing-oracle build order (parity-per-hour, highest first)
1. IDOR/BOLA authz-differential sweep (role x object x verb; stateful oracle already exists -- just wire).
2. SSRF via in-mirror CANARY / OOB sink (contained). 3. DOM/stored XSS via HEADLESS browser pool (the single
biggest "not Burp-grade" gap). 4. Authn depth (JWT alg=none/kid, session fixation, reset-token, MFA bypass,
account enumeration) -- reuses AuthState. 5. Schema-driven mass-assign/param fuzz (OpenAPI/GraphQL). 6.
Rate-limit/lockout + secrets/PII-in-response (trivial, do together). 7. File-upload/traversal/zip-slip (plant
a benign marker inside the sandbox). Plus passive: CSRF token-diff, open-redirect canary, XXE/deser parser,
security-headers/TLS/misconfig, SCA/CVE (have via grype), API-spec conformance.
OUR EDGE ON TOP OF PARITY (commercial suites are weak here): the stateful/relational + business-logic CHAIN
layer (invariant/idempotency/TOCTOU + a ChainOracle over confirmed edges).

## Fit in 40 min -> PARALLELISM REQUIRED (serial ~= 11-32 min for the heavy adds, does not fit safely)
Per-class workers (Phase A ~= max(class) not sum) + a HEADLESS BROWSER POOL (3-5 contexts; DOM is the long
pole) + concurrent probes within a class (5-10 in flight, RATE-CAPPED -- non-destructive correctness, avoid
accidental DoS). Heavy scaffold probes (grype/docker) run ONCE, not per-try.

## False-parity traps (must-avoid to credibly claim 5/5)
- Coverage != detection: only ORACLE-VERIFIED true-positives count; a class probed-but-unconfirmable reads as a
  miss. - DOM/stored XSS is non-optional. - authz differential (IDOR/BOLA) is non-optional for API-grade. -
  need an OOB/CANARY channel (SSRF/blind-XXE/blind-injection). - AUTHENTICATED scanning PER ROLE (not
  unauth-only). - an ACTIVE CRAWLER to discover the surface (seeding from routes alone misses undocumented
  endpoints). - FP discipline: every finding ships a reproducible oracle trace + confidence. - SCA/CVE + API-
  spec awareness present. - a timed-out class must be RE-RUN, never counted "clean" (the most common false 5/5).

## Net
Don't cut for cost (compute is free) -- cut only true ceremony (cost predictor + yield-split). KEEP the
re-armed selection stack for breadth scheduling. ADD the full missing-oracle set + an active crawler + a
coverage-completeness gate + a headless pool. Govern by a 40-min wall-clock, coverage-first-then-depth. That
turns "strong niche (money/logic)" into "commercial-parity + a stateful edge nobody else has."
