# Aegis Operator — Architecture

## Processes

```
                       ┌─────────────────────────────────────────────┐
                       │  operator/aegis_operator.py  (the co-pilot)  │
                       │  LLM in the operator seat + approval gate +  │
                       │  planner_core + rag_search + findings ledger │
                       └───────────────┬─────────────────────────────┘
                                       │ tool calls (HTTP)
              ┌────────────────────────┼───────────────────────────┐
              ▼                        ▼                            ▼
   orchestrator/bridge_server  orchestrator/kali_driver   orchestrator/browser_use
   (8765) LangChain tool-loop   (8901) run shell in Kali    (8902) Playwright browser
                                       │
                                       ▼
                             Kali WSL  +  Docker target twin  +  /opt/aegis-rag
```

- **bridge (8765)** — the executor: an OpenAI-compatible tool-calling loop that turns a task into `kali_driver` / `browser_use` calls, with the data-boundary / anti-hallucination system prompt.
- **kali_driver (8901)** — one MCP tool, `run_command`, executing shell in the `kali-linux` WSL distro (where the target twin and the tools live).
- **browser_use (8902)** — Playwright browser automation as MCP tools.
- **operator** — can drive the bridge, or run its own direct tool-loop + `planner_core` for multi-step plans. Standalone: no external scheduler required.

## Run modes + the discovery engine

Three run modes share ONE budgeted discovery engine (`operator/iterative_hunt.py` — the ~40-attempt loop with diversity / novelty / information-gain accounting) over the shared attack-vector dispatch (`operator/vectors.py`: web / recon / supply_chain / static / fuzz / misconfig / rag):

- **Operator** — `operator/iterative_hunt_live.py` (the co-pilot's live hunt against the mirror).
- **ExploitGym** — `exploitgym/exploitgym/operators/iterhunt.py` (the contained benchmark operator).
- **Red-Team** — `redteam/redteam.py` (scope-enforcing, with cross-host pivot chaining via `redteam/lateral.py`). Probes are guarded on TWO axes by `redteam/authorization.py` (`classify_probe` → recon / active / destructive): safe read-only recon is allowed in-scope and on research hosts; anything destructive or out-of-scope is blocked — non-destructiveness alone is **not** authorization.

## The Planner (pre-execution plan stage)

Before any of the three modes run, **the Planner** (`operator/planner.py` — distinct from the bounded task-graph executor `planner_core.py`) devises the plan and feeds the loop (full design in `docs/PLANNER.md`):

```
objective+target ─▶ fingerprint ─▶ rank prior-successful (technique,tool) from the techniques DB
                                      ─▶ board keeps ONLY relevant + devises NOVEL approaches
                                      ─▶ candidate plans (fast-track/thorough/covert) ─▶ seed_moves ─┐
                                                                                                     ▼
                        techniques DB ◀── write-back verified wins ──  ~40-attempt iterative-hunt loop
                        (MITRE ATT&CK + learned)                                    │
                                      ▲───────────── mid-run RE-OPEN (next scenario) ┘
```

- **`Planner` / `plan_session` / `candidate_plans`** — ranks the techniques DB, has the board keep only techniques relevant to the environment and devise NOVEL approaches beyond the DB, and emits MODE-1 anchor `seed_moves`.
- **Multi-scenario + re-open** — several candidate plans (fast-track / thorough / covert) are scored; the top seeds the run and the rest form a queue. The loop (`iterative_hunt.py`, `reopen=` / `max_reopens=2`) pulls the next scenario mid-run when it would otherwise stall — bounded so re-planning can't thrash the budget.
- **Techniques DB** — `rag/techniques_db.json` + learned files + **MITRE ATT&CK** (`rag/ingest_mitre.py` → `rag/mitre_attack.json`, loaded by `rag/technique_search.py`), live-refreshed like the CVE feeds. Verified wins are written back (`record_success`) so the next plan ranks them higher (closed loop). Kill-switch: `AEGIS_PLANNER=0`.

## The verification spine (shared)

Every finding from the operator **and** from ExploitGym flows through `shared/verified_findings.py`:

```
candidate ──(oracle checks DB/HTTP ground truth)──▶ verified   ← only these count
          └─────────────────────────────────────▶ rejected   ← over-claims auto-dropped
```

- **Event-sourced + hash-chained**: append-only JSONL, `verify_chain()` detects tampering.
- **Oracles**: `HttpOracle`, `DbOracle`, `CallableOracle`; `run_marker()` scopes an oracle to one run.
- **Coverage** (`shared/coverage_matrix.py`): records tested `(surface, method, role, technique)` cells so gaps are visible — findings tell you what was *found*, coverage tells you what was *checked-and-clean*.

## The board (multi-model collaboration)

File-based blackboard: agents drop `*.md` posts (FINDING / HUNCH / ASK / ANSWER / STRATEGY / …) into a board directory; `board/board_view.py` + `live_board.ps1` render it live. Contributors:
- The operator's own model, plus **Cloudflare Workers AI** open models via `operator/cf_agent.py` (roster in `operator/board_roster.json`, slugs in `cf_models.json`).
- A content-policy **QA-reframe** shim lets gated models still contribute defensively-framed analysis.
Doctrine: many models *suggest*; one operator *executes and verifies*. Convergence across independently-trained models is the signal.

### The code bench + consultant

- **Six code writers** (`operator/code_suggester.py`, `CODE_SUGGESTERS`) emit runnable `TARGET/CODE/ORACLE` blocks: `qwen2.5-coder-32b`, `ds` (deepseek-v4-pro, direct), `kimi-k2.7-code`, `llama-3.3-70b`, `llama-4-scout`, `deepseek-r1-distill-32b` — via Cloudflare Workers AI (paid) or DeepSeek direct, each skipping gracefully if unavailable.
- **Consultant / analyst / verifier** — `qwq-32b` (`AEGIS_ANALYST_MODEL`) gives a reasoning second opinion after the coders propose (`review_suggestions`), and consolidates the code-review round.
- **Board code-review** (`operator/code_review.py`) — periodically the same coders review the Aegis **codebase itself**; `qwq-32b` consolidates a prioritized improvement plan. Secret-looking lines are redacted before any file reaches a model; advisory only (writes `code_review_report.md`, never auto-applies). This is the *board's* review — distinct from Claude Code's own `/code-review`.

## Data / trust boundaries

- Contained twin on an isolated network; non-destructive (plant/write for proof, never erase).
- Secrets only in gitignored `secret.env` / `set-env.local.ps1`.
- Findings scored from ground truth, never from a model's self-report.
