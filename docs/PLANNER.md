# The Planner — pre-execution planning stage

The **Planner** is the plan stage that runs **before** the three run modes (Operator, ExploitGym,
Red-Team) and their three task levels (fact-finding → envelope-pushing → pentest). It devises a
working execution plan — which techniques + tools to use, in what order — then keeps improving it,
feeding the shared 40-attempt iterative-hunt loop and re-opening the plan mid-run when a better one
emerges. Board-designed (ds/kimi/qwq/gpt-oss consensus).

## Role at a glance — what the Planner drives, and where it steps back
The Planner **drives the start** and **learns at the end**; at the discovery stage it is **observatory**.
Novelty at the discovery stage is the **live board's** job, not the Planner's.

| Stage | Planner's role | Who owns it |
|---|---|---|
| **Before the run** (fingerprint → rank → candidate plans) | **DRIVES.** Fingerprints, ranks prior-successful/ATT&CK `(technique,tool)` combos, builds + sequences the scenarios (fast-track/thorough/covert). | Planner |
| **Loop start** (seed the 40-attempt hunt) | **DRIVES.** Seeds the loop with the plan's **deterministic anchor moves** (`seed:"planner"` — replays of what verified before + ATT&CK anchors). This is the concrete "from the start" — the loop's first moves are the Planner's. | Planner |
| **Discovery loop** (novelty) | **OBSERVES.** Exposes its ranked-technique classes as *context* (`PlannerSession.intel()` → `planner_intel`) — knowledge, not moves. It does **not** generate/inject novelty here. | **Live board** |
| **Stall** (re-open) | **DRIVES the reset.** Injects the NEXT scenario's deterministic anchors (bounded by `max_reopens`); novelty from those is again the board's. | Planner (anchors) / board (novelty) |
| **After a verified win** | **LEARNS.** Writes `(technique+tool+scenario+fingerprint)` back to the learned DB so ranking improves next run. | Planner |

Without the Planner (`AEGIS_PLANNER=0`) the loop starts cold on the board brainstorm alone — no anchors,
no prior-success priming, no observatory context. So the Planner's value is the **warm start** (anchors +
ranking + scenario order) and the **learning**, not the mid-run creativity.

```
objective + target  ──►  PLANNER  ──►  ranked plan (seed_moves)  ──►  iterative-hunt 40-attempt loop
                            ▲                                                       │
                            └────────────── re-open (better plan / stall) ◄─────────┘
                            └────────────── write-back on VERIFIED success ─────────►  techniques DB
```

## It builds on what already exists (does NOT rebuild)
- **`operator/planner_core.py`** — the gated, bounded task-graph executor (decompose → execute → grade
  → retry/re-branch, behind the approval gate, with runaway guards). The Planner is its *strategy
  front-end*.
- **The prior-success DB (already built)** — `rag/techniques_db.json` (curated) + `learned_techniques.json`
  + `learned_cooccurrence.json` + `learned_hitrates.json`, queried via `rag/technique_search.py`. This is
  the "what worked before" store; the Planner reads it first and writes verified wins back to it.
- **`operator/tool_gap_resolver.py`** — board-advised tool acquire/adapt.
- **`rag/rag_update.py`** — the offline+online refresh pattern (opt-in, staleness-gated, backup/rollback,
  VPN-gated egress) reused for the MITRE ATT&CK feed.

## Components
1. **Prior-Success Ranker** — fingerprint the target (surface/stack/roles), query the techniques DB and
   rank `(technique, tool)` combos by `hit_rate·EV + co-occurrence + recency` (reuses `technique_search`).
2. **MITRE ATT&CK sync** (`rag/ingest_mitre.py`) — populates the techniques DB from `attack.mitre.org`
   (Enterprise STIX), mapping each `Txxxx` (tactic, technique, sub-technique, associated software,
   data-sources, platforms) into the techniques-DB schema (`mitre_attack.json`, loaded by
   `technique_search`). **Live-updated exactly like the CVE RAG** — a `mitre` feed in `rag_update.py`
   (opt-in `AEGIS_RAG_ONLINE`, staleness-gated `AEGIS_MITRE_MAX_AGE_DAYS`, backup/rollback, VPN-gated).
   ATT&CK **tactics become the plan backbone** (recon → access → escalation → lateral → objective).
3. **Tool Planner** — per task, choose Kali-resident vs external/other-distro tools; if missing, acquire
   or adapt via `tool_gap_resolver` (apt/pip/clone-pinned/docker/build, or a wrapper to adapt an
   existing tool). Records a tool inventory.
4. **Candidate Plan Generator + Scorer** — the board proposes 3–5 candidate plans (varying technique
   order, tool choice, surface priority, ATT&CK coverage — e.g. fast-track / covert / thorough);
   scored `Σ(success_prob·tool_reliability)·scenario_fit·novelty_bonus`; top plan selected, the rest
   kept in a priority queue.
5. **Inject → loop** — the chosen plan seeds the 40-attempt hunt as **MODE-1 anchor `seed_moves`**; the
   loop's diversity / novelty / information-gain rules still govern execution.
6. **Re-open (loop-back)** — mid-run, on a stall or an emergent surface/technique, the Planner re-scores
   the queue and injects a better plan, which flows into the 40 novel-approach retries. Bounded so
   re-planning can't thrash the budget (cap concurrent plans).
7. **Closed-Loop Learner** — on an **oracle-verified** success, write back `(technique + tool + scenario
   context + target fingerprint)` into `learned_techniques.json` via the existing
   `techniques_from_findings` / co-occurrence / hit-rate miners — so the Planner gets smarter each run.

## DB additions
- **ATT&CK fields** on technique entries: `id` = `Txxxx`, `mitre_id`, `mitre_tactics[]`, `mitre_subtechnique`,
  `applies_to[]` (platforms), `kali_tools[]` (associated software hints), `data_sources[]`, `url`,
  `real_world_basis` = "MITRE ATT&CK …". Written to `rag/mitre_attack.json`, loaded alongside the curated
  + learned DBs by `technique_search`.
- **Plans ledger** (later stage): `plans` (candidate plans, scores, status queued/active/superseded/
  completed) + `plan_steps` (technique, tool, order, attempt-budget, outcome) so re-opens + write-backs
  are auditable.

## Guardrails (unchanged)
`planner_core`'s hard bounds (node ceiling + wall-clock); the authorization / non-destructive doctrine;
MITRE egress **offline-safe + VPN-gated** (identical to the CVE refresh). ATT&CK data is *reference* —
it never grants authorization to touch anything off-scope.

## Build stages (all built)
1. **MITRE ingest + live-refresh** — `ingest_mitre.py` + a `mitre` feed in `rag_update.py`. ✅
2. **Prior-Success Ranker + Planner core** — `operator/planner.py` querying the DB (relevance-filtered
   by the board), emitting **deterministic anchor** `seed_moves` into the loop + **observatory
   `intel()`** (ranked-technique context) for the board, write-back on verified success
   (`record_success`). ✅ *(The board's plan-time `board_novel` suggestions inform scenario **scoring**
   only — they are no longer executed as loop moves; discovery-stage novelty is the live board's.)*
3. **Multi-scenario generation + mid-run re-open** — wired across all three modes. ✅

### Stage 3 — how it works
- **`Planner.candidate_plans(...)`** generates N scenarios (`_SCENARIOS`: **fast-track / thorough /
  covert**) that vary technique ORDER, novel-probe budget and surface priority. The DB rank + board
  relevance filter run ONCE (shared); each scenario re-orders that relevant set by its emphasis and
  draws its OWN fresh batch of board-novel approaches **to score/differentiate the scenarios**, so the
  plans are genuinely different. Scored `scenario_fit(task_level) + emphasis_coverage + novelty +
  breadth`, best-first. **Only the scenario's deterministic anchors are executed as loop `seed_moves`;
  its board-novel batch stays plan-time-only (scoring) — the live board generates novelty at run time.**
- **`plan_session(...)`** returns a **`PlannerSession`** holding that ordered queue (offline-safe → `None`
  on any failure). `plans[0].seed_moves` seed the run; the rest are the re-open queue.
- **`IterativeHunt(..., reopen=cb, max_reopens=2)`** — when the loop would otherwise terminate
  (`board_saturation` / `diminishing_returns` / `max_board_rounds`), `_try_reopen` calls `cb(context, why)`
  for the NEXT scenario's moves, injects the still-novel ones as fresh breadth, and resets the breadth
  allowance. **Bounded by `max_reopens`** so re-planning can never thrash the budget. The run report
  carries `reopens` + `reopen_log`.
- All three runners (`iterative_hunt_live.py`, `redteam/redteam.py`, `exploitgym/.../iterhunt.py`) build a
  session and pass `seed_moves=` + `reopen=`. Red-Team's re-opened moves still pass `auth.guard()`.
- **Kill-switch:** `AEGIS_PLANNER=0` disables the Planner entirely (no seeds, no re-open); the loop then
  runs on its own board brainstorm exactly as before. Preview scenarios: `planner.py "<obj>" --target <t>
  --scenarios 3`.
