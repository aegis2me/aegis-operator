---
name: aegis
description: Operate the standalone Aegis security-research + AI-operator stack in THIS repo (operator co-pilot + ExploitGym benchmark + Red-Team mode + the Planner + oracle-verified findings + offline vuln RAG + multi-model board). Use whenever the user asks to run/test/report an authorized contained assessment, drive the co-pilot, run the ExploitGym benchmark or Red-Team mode, run the pre-execution Planner, fan out the 6-model code bench, run the board code-review of the repo, do credential-exposure recon or credential-replay escalation, snapshot/reset the mirror, run the stage-10 remediation round (whole-panel fixes for verified weaknesses, routed to admins/framework-updates + the code writer/improver), or follow the discovery pipeline. Everything here is for the owner's OWN, authorized, contained targets.
---

# The Aegis Operator Stack

A self-contained toolkit for authorized, contained security research + AI-operator benchmarking.
It is self-contained and standalone: no external task scheduler — the bridge + `planner_core`
are the whole engine. Test only the owner's own targets, against a MIRROR, non-destructively.

## Layout (run all three from this folder)
- `operator/` — the co-pilot: `aegis_operator.py` (LLM in the seat, approval gate, ledger/memory,
  tool-loop, `rag_search`, providers deepseek|openai|cloudflare), `planner.py` (the strategic PLANNER —
  the pre-execution plan stage), `planner_core.py` (the bounded task-graph EXECUTOR — distinct from the
  Planner), `code_review.py` (board code-review of this repo), `fuzzer.py` (THE FUZZER — grey-box
  OSS-Fuzz-tooling fuzzing of buildable mirror source), `config.py`.
- `orchestrator/` — `bridge_server.py` (8765, tool-calling loop) + `kali_driver_server.py` (8901,
  `run_command` in Kali WSL) + `browser_use_server.py` (8902, Playwright).
- `exploitgym/` — the contained autonomous-exploitation benchmark (`run|bench|suite|report`) +
  `methods/` (deterministic testers) + `race_money.py`.
- `shared/` — `verified_findings.py` (oracle-gated, hash-chained findings; only verified counts; carries a
  stage-10 `remediation` field + append-only `record_remediation` writeback) + `coverage_matrix.py` (gap
  grid). SINGLE SOURCE in shared/; the operator/ + exploitgym/ copies are logic-free re-export SHIMS
  that load the shared module (cached in sys.modules), so they can't drift.
- `rag/` — vuln store (`/opt/aegis-rag`: NVD/KEV/EPSS/Exploit-DB/MSF/PoC-GitHub/nuclei). OFFLINE by
  default; **online refresh is opt-in** (`rag_update.py` / `refresh.sh`, offline-safe): set
  `AEGIS_RAG_ONLINE=1` and every mode calls `operator/rag_refresh.ensure_fresh()` at run start to pull
  public-feed deltas (staleness-gated by `AEGIS_RAG_MAX_AGE_H`, backup+rollback, never blocks a run).
- `board/` — file-based multi-model blackboard (`live_board.ps1`, `board_view.py`).
- `redteam/` — the THIRD run mode: authorization-gated first-class pentest (`redteam.py`, fail-closed
  `authorization.py`, `attack_graph.py`, `crash_triage.py`, `lateral.py`, `DOCTRINE.md`). Owned INTERNAL
  MIRRORS only. **Cross-host LATERAL MOVEMENT** (`lateral.py`): on an oracle-confirmed foothold the host
  is OWNED in the attack graph and scope-gated PIVOT moves are proposed to in-scope reachable hosts (from
  a RoE `pivot_map` topology, else a flat model) -> chains web->internal->crown-jewel `goal`; the chain is
  reconstructed + scored. Red-Team uses a DEEPER per-mode escalation budget (`escalate_frac` 0.5 /
  `max_escalate_steps` 8, RoE-overridable) since each pivot hop is a NOVEL confirm on a new host; Operator/
  ExploitGym keep the breadth-biased loop defaults (0.15 / 3).

## Iterative hunt — one engine, three modes, shared vectors
Beyond the single-pass co-pilot there is a budgeted, adaptive **discovery loop** (`operator/iterative_hunt.py`)
driven by the board. It is shared unchanged by THREE modes that differ only in the doctrine wrapper each
puts around a move: **Operator** (`operator/iterative_hunt_live.py`, non-destructive guard), **ExploitGym**
(`exploitgym/.../operators/iterhunt.py`, + audit), **Red-Team** (`redteam/redteam.py`, + fail-closed
authorization/scope guard). All three dispatch through the SAME fact-finding **vectors** (`operator/vectors.py`):
`web · recon · supply_chain · static · fuzz · misconfig · rag` — so no mode is blind to a class the others see.
The loop spends its budget (~40) on **genuinely different** attempts, not 40 variations of one idea:
each attempt is a falsifiable **hypothesis** fingerprinted by `(angle, surface, vuln-class, mechanism,
oracle-signal)` + distinctness axes, EXCLUDING the payload value (a value-only tweak collides = rejected as
lazy); breadth-first scheduling + a hard per-angle cap spread the budget; **novelty is awarded over
convergence** (escalation of an oracle-confirmed foothold is a small, capped, novel-confirm-only slice, and
breadth is preserved across it); the budget counts only **information-gaining** attempts (generic 404s /
transport errors / repeats are noise, bounded separately, and cannot pad the count). Only oracle-verified
findings count. Run: `python operator/iterative_hunt_live.py --objective "..." --role owner --budget 40`.
- Docs: `README.md`, `INSTALL.md`, `docs/PIPELINE.md` (the canonical flow + honest status table),
  `docs/ARCHITECTURE_DIAGRAM.md`, `HELP.md` (human how-tos, e.g. porting fixes to the mirror; operator-searchable).

## The Planner — pre-execution PLAN stage (docs/PLANNER.md is authoritative)
Before the three run modes, **the Planner** (`operator/planner.py`) devises the plan that seeds the loop
(distinct from `planner_core.py`, the task-graph executor). It: **fingerprints** the target (surfaces /
stack / roles / task-level) → **ranks** prior-successful `(technique, tool)` combos from the techniques DB
→ the **board keeps ONLY environment-relevant** techniques (drops what doesn't apply here) **AND devises
NOVEL approaches** beyond the DB (a new technique, a mix of existing ones, or `new-code`) → emits these as
MODE-1 anchor **`seed_moves`** into the ~40-attempt iterative-hunt loop → builds **multi-scenario candidate
plans** (`fast-track` / `thorough` / `covert`) and, on a mid-run stall, performs a **bounded RE-OPEN**
(the loop pulls the next scenario instead of quitting; capped by `max_reopens`) → on an **oracle-verified**
win, **writes the technique+tool back** to `learned_techniques.json` (closed loop). The techniques DB is
populated from **MITRE ATT&CK** (`rag/ingest_mitre.py` → `mitre_attack.json`) and **live-refreshed like the
CVE feeds** (a `mitre` feed in `rag/rag_update.py`; opt-in `AEGIS_RAG_ONLINE`, staleness `AEGIS_MITRE_MAX_AGE_DAYS`).
Runs in all three modes (offline-safe: falls back to the board brainstorm if the DB/board is unreachable).
Kill-switch: `AEGIS_PLANNER=0`. Preview: `python operator/planner.py "<objective>" --target <t> --scenarios 3`.

## The discovery pipeline (docs/PIPELINE.md is authoritative)
0 scope/authorize → 1 survey+fingerprint(real) → 2 threat-model/rank → 3 credential-exposure
(optional, manual) → **4 BUILD THE MIRROR + VALIDATE FIDELITY** (real code+synthetic data preferred;
scaffold fallback; snapshot baseline) → 5 known-vuln pass (RAG) → 6 confirm via Kali → 7 novel
discovery (credentialed, per-role): (a) board hunches with the **6-model code bench** (qwen2.5-coder-32b,
DeepSeek-v4-pro, kimi-k2.7-code, llama-3.3-70b, llama-4-scout, deepseek-r1-distill-32b) emitting runnable
code — reviewed by the **qwq-32b** analyst/verifier, (b) deterministic methods → 8 run the suggested code (`test_suggestions.py`,
non-destructive guard) → 9 confirm — **the oracle decides** (≥2-confirmation consensus for HIGH) +
post-exploit chaining (`credential_replay`) → 10 coverage matrix + metrics → loop, or the **remediation round**
(`remediation_board.py`, END OF PIPELINE): each VERIFIED weakness → whole panel proposes the fix on the board,
attributed to source + consensus, split to **two audiences** — *known-cve* (RAG-filled fixed-version/KEV) →
framework/dependency **update for ADMINS**; *novel* → panel-designed **code fix for the CODE WRITER/IMPROVER**
(`--emit-fixes` → code-bench patch in the report, non-destructive) → durable two-track `remediation_report.md`
(+ `--write-ledger` chains it onto the findings ledger).
**Cross-cutting:** the board is consulted at DECISION POINTS (0,2,4,5,7,10), available everywhere;
**board data-hygiene** — sanitize privileged context (creds/secrets) before generalist models see it;
verification gate at 6/8/9 (deterministic oracle); mirror-not-prod; ground-truth scoring, never
self-report; attribute every finding to source.

## Key tools (operator/)
- **`aegis_operator.py --task "..."`** — the co-pilot. `--auto-approve` only in the sandbox;
  `--provider deepseek|openai|cloudflare`; `--target-mode mirror|split|live`; `--max-iter N`;
  `--remediate-on-finish` (stage-10 auto-run). **At startup it PRELOADS this skill into its system prompt**
  (same as Claude Code's `/aegis`; disable with `AEGIS_SKILL_PRELOAD=0`) and can re-query it (+ HELP.md /
  RESILIENCE.md) via the `search_docs` tool — so a DeepSeek-driven run starts with the full playbook in context.
- **`code_suggester.py all "<prompt>" --out-dir suggestions`** — fan out the **6-model CODE BENCH**:
  `qwen2.5-coder-32b`, `ds` (DeepSeek-v4-pro, direct), `kimi-k2.7-code`, `llama-3.3-70b`, `llama-4-scout`,
  `deepseek-r1-distill-32b` (CF Workers-AI paid or DeepSeek-direct; each skips gracefully if unavailable)
  emit runnable `TARGET/CODE/ORACLE` blocks (gpt-oss stay board contributors, not code writers). `--review`
  then has the **qwq-32b** analyst/verifier review + rank them. (Single model: `code_suggester.py ds|qwen "<prompt>" --out f.md`.)
- **`code_review.py [--paths ...] [--models ...]`** — the **board CODE-REVIEW** of THIS repo (periodic,
  from-time-to-time — not per run): the 6 coders review the Aegis source in bundles and emit structured
  suggestions; the **qwq-32b** consultant consolidates a ranked improvement plan (`code_review_report.md`).
  Secret-looking lines are REDACTED before any model sees a file; advisory only (writes a report, changes
  nothing). Distinct from Claude Code's own `/code-review`. E.g. `python operator/code_review.py --paths operator shared rag redteam exploitgym`.
- **`fuzzer.py check|scaffold|build|run|triage`** — **THE FUZZER**: grey-box, coverage-guided fuzzing of
  the mirror's OWN buildable source via self-hosted **OSS-Fuzz tooling** (libFuzzer/AFL++/Honggfuzz + build
  harness), contained in Kali/Docker. Distinct from the black-box `fuzz` vector; also a loop vector
  (`action: ossfuzz`, move carries `project`+`fuzzer`). Crashes are candidate findings, verified only when
  they REPRODUCE. Non-destructive; the one egress (pulling `gcr.io/oss-fuzz-base/*`) is gated by
  `AEGIS_OSSFUZZ_PULL=1` (off by default). Google's HOSTED OSS-Fuzz is NOT used (private targets).
  **Languages:** c++/c, python (Atheris), go/rust/jvm, and **js/ts via Jazzer.js** (`--language js` — native
  npm/node, no OSS-Fuzz image; proven on a real Node/JS parser (the mirror's own)).
- **`test_suggestions.py --file f.md --source <model> --execute --role <r>`** — the co-pilot RUNS each
  suggestion against the mirror behind a non-destructive guard, checks the oracle, records
  verified/rejected attributed to source. Dry-run by default.
- **`credential_exposure.py <owned-domain>`** (OPTIONAL, largely MANUAL -- reliable sources are paid) — asks the board for sources, then
  queries HIBP/Dehashed/LeakCheck/IntelX/GitHub/dorks/local-dump for leaked creds (each gated on its
  key). Owned-domain allowlist; secrets shown for the testing loop (`--redact` for reports).
- **`credential_replay.py --name/--pin | --user/--password --execute`** — authenticates a (leaked)
  cred, then runs the escalation battery (over-read / IDOR / self-privesc), oracle-checked,
  snapshot-restored. `--mode mirror` default.
- **`mirror_snapshot.py snapshot|restore|list [name]`** — DB-level snapshot/reset of the mirror.
- **`remediation_board.py [--synthesize] [--emit-fixes] [--write-ledger] [--eg-results DIR]`** (STAGE 10,
  END OF PIPELINE) — the remediation round: reads oracle-VERIFIED findings only (operator ledger + optional
  ExploitGym results), posts each confirmed weakness to the chat board (sanitized brief, no secrets), and the
  **whole panel** (ds/DeepSeek-v4-pro, sol, gpt-oss-120b/20b, qwen-coder, kimi, llama-4-scout, r1-distill)
  proposes the fix — each attributed to source, optional per-finding consensus. **Two paths / two audiences:** *known-cve* → RAG auto-fills
  fixed-version/KEV/advisory, routed to **ADMINS** (framework/dependency/config update); *novel* (no CVE) →
  panel-designed **code** fix, routed to the **CODE WRITER/IMPROVER**. `--emit-fixes` hands each finding to
  the **code bench** → a concrete patch (`operator/remediation_fixes/`, non-destructive, not auto-applied);
  `--write-ledger` chains the remediation onto the hash-chained findings ledger. Output: `remediation_report.md`
  split into the Admin + Code-writer tracks. `--claude-note "..."` adds the coordinator's take. Watch live:
  `board/live_board.ps1`. **MIRROR-side only** — fixes target the mirror twin (where findings were confirmed),
  for review + further testing there; proposed, never auto-applied, never run against the real target.
  **The operator can run it itself** (autonomous, no human in the loop): the co-pilot has a `remediation` tool
  and `aegis_operator.py --remediate-on-finish` (or `AEGIS_REMEDIATE_ON_FINISH=1`) auto-runs the round over the
  run's verified findings at the end — so a DeepSeek-driven run completes stage 10 on its own.
- **`remediation_port.py --transport wsl|docker|dir`** (operator tool `port_fix_to_mirror`) — deliver the code
  writer/improver's emitted patch (`operator/remediation_fixes/`) INTO the mirror to test the improved code. The
  mirror may run ANY distro (Ubuntu/openSUSE/Kali) or a Docker image: `wsl` (copy into the WSL mirror distro —
  `--distro`/`AEGIS_MIRROR_DISTRO`), `docker` (`docker cp` into a running mirror container, `--container`),
  `dir` (copy to a USB/staging dir for hand-carry, `--dest`). MIRROR-side only — STAGES the patch, never applies
  it, never touches the real target; prints the apply command. Human how-to for each transport: **`HELP.md`**.
- **`remediation_verify.py --transport wsl|docker|local`** (operator tool `verify_fix_on_mirror`) — the STAGE-10
  **CLOSED LOOP** (mirror-only): snapshot the mirror → APPLY the fix on it (code patch via `git apply` + the
  system/framework bump via the mirror OS's package manager) → RE-RUN each finding's exploit/oracle on the
  patched system → **CLOSED / STILL-OPEN / BROKE-AFTER-UPDATE** → restore the snapshot. `--allow-download` permits
  fetching the framework update onto the mirror (authorized mirror-side egress; off by default). `--health-cmd`
  checks the app still runs after the update; `--repair` runs a **board-driven fix** when the update breaks the
  code: the operator diagnoses → the panel suggests (differences) → the **primary code writers (DS, Qwen, Kimi,
  Llama-4-Scout, R1-distill)** each emit a patch and are **benchmarked** (applies/heals/size; DS↔Qwen convergence
  is the headline metric), the best kept — and a **post-update report** says what must be done to get things
  running. Real target is NEVER patched or re-tested.
- **Techniques DB** — `rag/techniques_db.json` (curated) + `learned_techniques.json` (self-improved) +
  `mitre_attack.json` (**MITRE ATT&CK**, ingested + live-refreshed by `rag/ingest_mitre.py` via the `mitre`
  feed in `rag_update.py`) + `rag/technique_search.py` (deployed to `/opt/aegis-rag`): the HOW-to-test +
  Kali-tool/new-code mapping per technique class (complements the CVE RAG). This is the DB **the Planner
  ranks and writes verified wins back to**. Query: `technique_search.py "<class/keyword>" --tools`.
  **Self-improving loop:** `rag/techniques_from_findings.py <findings.jsonl>` turns VERIFIED findings into
  `learned_techniques.json` (DB grows from what worked) — the stage-10 loop step. Runnable probes:
  `exploitgym/techniques/probe_techniques.py`.
- **Expanding the board** — add members via any of three routes (see HELP.md "Expanding the board"): a
  DIRECT provider API key (DeepSeek/OpenAI), CLOUDFLARE Workers AI (`@cf/...` slugs; Workers Paid unlocks
  KIMI etc.), or ANY OpenAI-compatible aggregator/local runtime (OpenRouter/Together/Groq/Ollama/vLLM).
  Add key→`secret.env`, model→`board_roster.json`(+`cf_models.json`/`ROLE_PROMPTS` for CF), then bake it off.
- **`cf_agent.py`** — Cloudflare Workers AI board agents; `board_roster.json` = constant contributors
  (claude, deepseek-direct, sol, gpt-oss-120b, gpt-oss-20b) + the 6 `code_suggesters` (qwen2.5-coder-32b,
  ds, kimi-k2.7-code, llama-3.3-70b, llama-4-scout, deepseek-r1-distill-32b) + the qwq-32b analyst/verifier
  consultant. Slugs in `cf_models.json`; baked code role in `cf_agent.ROLE_PROMPTS`.
- **Human channel (watch + ask):** `board/live_board.ps1` is your default live window onto the chat (~25s refresh, `AEGIS_BOARD_REFRESH` to tune; auto-opens with `start-all.ps1`). To talk to the panel, frame a question via the co-pilot: `operator/board_ask.py "<question>"` — it posts to the board and the panel answers there (board chat = `deepseek-v4-flash` for budget). Board data-hygiene: no secrets in the question.

## Running it
1. `copy secret.env.example secret.env` + `set-env.local.ps1.example set-env.local.ps1`; fill LLM key.
2. `./start-all.ps1` (kali_driver + browser_use + bridge). 3. drive via the tools above.
4. Watch the board: `board/live_board.ps1`.

## Doctrine (non-negotiable)
Contained mirror only; non-destructive (plant/write for proof, NEVER erase/delete); no off-box egress
(OSINT recon is the one authorized external exception, owned domains only, via Kali/VPN); no
external-agent recruitment / persistence / evasion; only oracle-verified findings count.

## Gotchas
- WSL path mangling: prefix host↔Kali commands with `MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`.
- WSL idle-shutdown: the distro (and the mirror's docker containers) shut down seconds after no attached
  session — which kills a live target mid-run. Hold it up with a backgrounded `wsl -d kali-linux -- sleep 3600`
  for the duration of a hunt/smoke, and re-`docker compose up -d` the mirror if it dropped.
- Shell loops don't survive host→WSL→bash: a `for x in … $x …` loop comes back with `$x` empty — enumerate
  explicitly instead of looping over a variable.
- Generic-target env (keep the repo generic — no client values in code): DB oracle defaults `AEGIS_DB_USER`
  / `AEGIS_DB_NAME` (default `app`); demo/test login PIN `AEGIS_TEST_PIN` (default `000000`); target base
  `AEGIS_TARGET`; Kali distro `AEGIS_KALI_DISTRO`. Point these at the mirror on the box, not in the code.
- Online CVE refresh (opt-in): `AEGIS_RAG_ONLINE=1` enables it; `AEGIS_RAG_MAX_AGE_H` (default 12) is the
  staleness window; `AEGIS_RAG_HOME` (default `/opt/aegis-rag`). Public vuln feeds only (authorized-OSINT
  lane), never target data; offline-safe (a feed/network failure leaves the local store intact).
- Python: set `AEGIS_PYTHON` to the full interpreter path (or use `python3`) if `python` isn't on PATH.
- Secrets only in gitignored `secret.env`/`set-env.local.ps1` — never paste keys in chat.
- Cloudflare Workers AI is on the **PAID plan** now: the CF coders (qwen2.5-coder, kimi-k2.7-code,
  llama-3.3-70b, llama-4-scout, deepseek-r1-distill-32b) and the qwq-32b consultant all work; DeepSeek is
  still reached DIRECT (api.deepseek.com). Any model unavailable/403 (e.g. plan/token missing) is skipped
  gracefully — it never crashes a run. On the free tier only qwen2.5-coder + gpt-oss are reachable.
- CF auto-parses a JSON reply, so a model's `message.content` can arrive as a dict/list, not a string —
  code paths that consume CF output must normalize it to text (see `code_review.py::_as_text`).
- Reasoning coders (kimi, r1-distill) and DeepSeek "think" by default: for answer-only paths disable it
  (DeepSeek `thinking:{type:disabled}`) or give a large token budget, else `content` comes back empty and
  raw `reasoning_content` leaks instead of the intended output.
- Sol (GPT-5.6) is content-gated — use the QA-reframe shim; DeepSeek harness under-emits — direct
  calls are reliable.
- Model config: co-pilot BRAIN (AEGIS_MODEL) + code path = `deepseek-v4-pro` (benchmarked); board chat may use `deepseek-v4-flash` for budget.
