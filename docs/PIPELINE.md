# Aegis Operator — Discovery Pipeline v3 (the canonical flow)

The end-to-end flow for assessing one target. **All aggressive testing runs against a MIRROR of the
real target — never production.** Building that mirror (stage 4) is the load-bearing stage. The
**verification gate** (the oracle layer) runs across stages 6/8/9, and the **coverage matrix + metrics**
(stage 10) decide whether to loop back to novel discovery or stop. Only oracle-verified findings count.

**v3 changes** (from the board review): sequential stage numbering; the board is consulted at *decision
points* (not blocking every step); **board data-hygiene** (privileged context is sanitized before it
reaches generalist models); **deterministic-oracle + multi-oracle consensus** for verification; explicit
**mirror-fidelity validation** before the known-vuln pass.

```
 0 SCOPE/AUTHORIZE ─▶ 1 SURVEY+FINGERPRINT(real) ─▶ 2 THREAT-MODEL/RANK ─▶ 3 CRED-EXPOSURE(opt,manual)
                                                                                   │
                                                                                   ▼
                    ╔══════════════════════════════════════════════════════════════════╗
                    ║ 4 BUILD THE MIRROR (copy of real target) + VALIDATE FIDELITY      ║
                    ║   real code+synthetic data (high) │ scaffold (low) · SNAPSHOT base ║
                    ╚══════════════════════════════════════════════════════════════════╝
                                                            │  (everything below hits the MIRROR)
                                                            ▼
        5 KNOWN-VULN PASS(CVE/RAG) ─▶ 6 CONFIRM known exploits via Kali ──┐ oracle
                                                            │(gaps/none)   │ gate
                                                            ▼              │
                    P PLAN — the PLANNER seeds the loop (see PLANNER.md)  │
                                                            ▼              │
                    7 NOVEL DISCOVERY — REACH: how far? 2 directions     │
                       scaffold (stack+modules) ⇄ code (stack+app)        │
                       ├ (a) LIVE BOARD DISCUSSION → moves+verdicts        │
                       │      propose→critique→converge (+transcript)      │
                       │      + novel-code writer builds foothold/bridge   │
                       └ (b) deterministic: pattern-gen / race / fuzz      │
                       ↺ Planner RE-OPENS a better scenario on a stall    │
                                                            ▼              │
                    8 RUN SUGGESTED CODE (guard + snapshot-restore) ───────┤
                                                            ▼              │
                    9 CONFIRM — oracle decides (consensus for HIGH) ◀───────┘
                       + POST-EXPLOIT / CHAIN (priv-esc, IDOR, multi-step)
                                                            │ record + attribute
                                                            ▼
                    10 COVERAGE MATRIX + METRICS ─ gaps? ─▶ reset snapshot, back to 7
                                                            │ else ▼  REPORT
```

## Stages

**0. Scope & authorize.** Contained mirror only; authorization artefact (owner, RoE, date, approver);
non-destructive doctrine (plant/write for proof, never erase); no off-box egress. *(board decision point)*

**1. Survey & fingerprint the REAL target.** Enumerate the surface — endpoints, roles, stack, versions —
via `kali_driver` (nmap/whatweb/httpx/dir-brute) and, in grey-box, source-read. Drives the mirror.

**2. Threat-model / asset-criticality ranking.** Rank the surface by impact (money, auth, PII,
integrations) so effort — and scan depth — targets the high-value surface first. *(board decision point)*

**3. Credential-exposure recon — OPTIONAL, largely MANUAL.** Check whether the owner's own domain has
leaked accounts (breaches/pastes/open web) — extra data that can open new paths. Automated
(`credential_exposure.py`) but the reliable sources are paid, so in practice a manual search side-input;
if the owner supplies a key/dump it queries automatically. **Any credential found feeds `credential_replay`**
(stage 9). Owned domains only; report for rotation. *(board suggests sources — sanitized, see hygiene)*

**Sources you can choose from** — each gated on its own env var; set only what you have and the tool
runs whatever is configured, reporting the rest as `NEEDS <KEY>`:

| Source | Env var(s) | Cost | What it does |
|---|---|---|---|
| **dorks** | — (keyless) | **free** | Generates Google / Pastebin / GitHub / Marginalia search-dork URLs for manual follow-up. |
| **web_search** | `BRAVE_API_KEY` — or `GOOGLE_CSE_KEY`+`GOOGLE_CSE_CX` — else keyless DuckDuckGo | **free tier / free** | Runs the search, fetches result pages, greps for creds. **Brave Search API (free tier) is the recommended reliable backend**; Google CSE is free to ~100/day then paid; keyless DDG works but is rate-limited. |
| **github** | `GITHUB_TOKEN` | **free** | GitHub code-search for the domain + "password" (GitHub disables unauthenticated code-search, so the free token is required). |
| **local_dump** | `AEGIS_BREACH_DUMP=/path/to/dump(s)` | **free** | Greps a local breach-compilation you already hold — you supply the data. |
| **hibp** | `HIBP_API_KEY` | **paid** | Have I Been Pwned — domain / account breach search. |
| **dehashed** | `DEHASHED_EMAIL`+`DEHASHED_KEY` | **paid** | Dehashed — breach-record search by domain. |
| **leakcheck** | `LEAKCHECK_KEY` | **paid** | LeakCheck — domain search. |
| **intelx** | `INTELX_KEY` | **paid** | Intelligence X — pastes / leaks / dark-web search. |

The **free / keyless path** (dorks + keyless web search + a local dump) is the manual-follow-up baseline;
the **breach databases — HIBP / Dehashed / LeakCheck / IntelX — are paid**, and they are what make this
reliable (hence "largely MANUAL" until a key is added). The cheapest way to make the *automated* path
useful without a paid breach subscription is a **Brave Search API key (free tier)** or a **GitHub token**.
Scope is enforced by the `AEGIS_OWNED_DOMAINS` allowlist — owned domains only.

**4. BUILD THE MIRROR + VALIDATE FIDELITY.** *(load-bearing)* Stand up a twin in Kali Docker on an
isolated network; test everything below against it, never prod:
- **Preferred — a REAL mirror:** actual application **code + config** with **synthetic data** (highest
  fidelity → findings are real). **Fallback — a scaffold reconstruction** from the fingerprint (behavioural,
  low fidelity, e.g. a legacy PHP app) — good for known-CVE/protocol, weak for code-logic.
- **Snapshot the baseline** (reset between episodes / after write-heavy tests).
- **Validate fidelity (v3):** run a fidelity test-set (known-good behaviours the real target exhibits) and
  **record measured divergence** — so stage 6 judges a non-firing CVE against real drift, not assumption.
- `--target-mode mirror|split|live`; build an isolated twin of your app (real code paths, synthetic data, no egress). *(board decision point: what to reproduce)*

**5. Known-vuln pass.** Fingerprint → known issues via `rag_search` (NVD/KEV/EPSS/Exploit-DB/MSF/PoC/nuclei)
+ live `exploit_search`. Candidate CVEs/exploits. *(board decision point: which CVEs are worth firing)*

**6. Confirm known exploits via Kali.** Fire each candidate against the mirror; **oracle-verify**. A CVE
that doesn't fire is refuted — *unless* the stage-4 fidelity record says the twin diverges on that path.

**P. Plan — the Planner (before the loop; see `docs/PLANNER.md`).** The Planner (`operator/planner.py`)
fingerprints the target, then queries the techniques DB (`rag/technique_search.py` over `techniques_db.json`
+ `learned_techniques.json` + `mitre_attack.json`) for the best PRIOR-SUCCESSFUL `(technique, tool)` combos.
The **board keeps only the environment-RELEVANT techniques**, which the Planner emits as MODE-1
**deterministic anchor** `seed_moves` (replays of what verified before + ATT&CK anchors) into the stage-7
~40-attempt loop, and builds several **candidate scenarios** (fast-track / thorough / covert); on a stall it
**RE-OPENS** with the next scenario (bounded, so re-planning can't thrash the budget). **At the discovery
stage the Planner is observatory:** it hands the loop its ranked-technique context (`intel()`), but the
**genuinely NOVEL approaches are devised by the LIVE board** during the loop — grounded in the run's oracle
deltas and confirmed footholds — not frozen by the Planner up front. (The board's plan-time novel suggestions
inform scenario scoring only.) Oracle-verified wins are **written back** to `learned_techniques.json`
(closed loop). The ATT&CK technique DB is populated by `rag/ingest_mitre.py` and **live-refreshed like the CVE
feeds** (a `mitre` feed in `rag/rag_update.py`; opt-in `AEGIS_RAG_ONLINE`, staleness `AEGIS_MITRE_MAX_AGE_DAYS`,
backup/rollback, VPN-gated egress). The Planner seeds all **three run modes** (Operator, ExploitGym, Red-Team);
disable it with `AEGIS_PLANNER=0`. *(board decision points: Planner relevance-filter + candidate-plan scoring; the LIVE board generates novelty during the loop)*

**7. Novel discovery (if gaps remain), credentialed and per-role.** Authenticated, every role, across the
surface. *(board decision point — hunches from ALL agents)*:

**REACH AXIS — the paramount question is HOW FAR CAN I GO here, non-destructively, without damaging the
target.** The ~40-attempt loop splits its budget across **two directions of probing** (a hard `direction_floor`
keeps neither starved): **`scaffold`** — the STACK + INSTALLED MODULES only (framework, dependencies,
**plugins/modules**, runtime, container, config, and the **DB tier/engine/extensions**) as if no app code were
present; and **`code`** — the stack TOGETHER WITH the app's actual code. For **both** directions the board asks:
is there another option open (backdoor / window / forgotten-or-debug door / default cred / exposed secret)? is
this layer closed at all — where's the seam? can I establish a **FOOTHOLD** or a **BRIDGE** (scaffold→code,
app→host, host→host) to go deeper or laterally? A bridge (an oracle-confirmed crossing to a new layer/host) is
what actually extends reach and is tracked as legitimate depth (`operator/reach.py`).

- **(a) Board hunches — a LIVE, INTERACTIVE board DISCUSSION** (`operator/board_discuss.py`), not a single
  ask→reply. Each round is a bounded multi-model deliberation: **PROPOSE** (proposers ds / qwen2.5-coder /
  kimi run in **parallel isolation** so ideas stay diverse; llama-4-scout joins as a wildcard when coverage is
  stale) → **CRITIQUE** (a rotating **red-team** attacks each proposal — *what will work, what would likely
  work, what might not, what would likely fail, and why* — citing an oracle-delta/coverage/reach fact) →
  **CONVERGE** (the scorer/synthesizer **`qwq-32b`** / gpt-oss-120b merges to ≤5 moves, stamps a **verdict**
  (`will-work | likely | maybe | likely-fail`) + confidence + **dissent**, and preserves ≥1 minority move). It
  emits the loop's normal hypothesis moves — now carrying verdict/confidence/dissent — **plus a readable
  TRANSCRIPT written to the board dir** (`board/board_files/DISCUSS__round-*.md`) for `board/live_board.ps1`.
  The **verdict is a *late* tie-breaker** in move selection, so the loop's breadth/direction/novelty guarantees
  still dominate; dissent travels onto the finding and is never deleted. Bounded (per-phase token caps, parallel
  waves, early-stop) and runs on the board cadence; offline-safe fallback to the single-pass `board_brainstorm`;
  kill-switch `AEGIS_BOARD_DISCUSS=0`. When the discussion decides a foothold/bridge **needs custom code**, the
  **novel-code writer** (`operator/novel_code.py`, primary `deepseek-v4-pro` + ordered fallback, with a
  refusal/completion guard so a model that trips a safety switch is skipped) has the **6-coder code bench**
  (`qwen2.5-coder-32b`, `ds`, `kimi-k2.7-code`, `llama-3.3-70b`, `llama-4-scout`, `deepseek-r1-distill-32b`)
  write a runnable, NON-DESTRUCTIVE `TARGET/CODE/ORACLE` probe (executed via the `probe` vector, proven/discarded
  by the oracle; `AEGIS_NOVEL_CODE=0` disables).
- **(b) Deterministic methods** — pattern-generalizer, concurrency/race, property/invariant fuzzer,
  taint/dataflow, model-based state-machine, and — when the mirror is buildable source — **THE FUZZER**
  (`operator/fuzzer.py`, grey-box coverage-guided fuzzing via self-hosted OSS-Fuzz tooling in Kali/Docker;
  crashes are candidate findings, verified only when they reproduce). Distinct from the black-box `fuzz` vector.

**8. Run suggested code.** The co-pilot executes each suggestion against the mirror via
`test_suggestions.py`, behind the **non-destructive guard**; restore the snapshot after write-heavy runs.

**9. Confirm — the oracle decides.** *(v3)* The **oracle is the deterministic authority** (HTTP status/body,
DB query, DOM/render for XSS, callback for SSRF, cross-account for IDOR, race-invariant). Claude *interprets
and records* but is **not the sole judge**. **HIGH-severity requires multi-oracle consensus — ≥2 independent
confirmations** before `verified`; over-claims auto-drop. Record to the hash-chained ledger + coverage
matrix, **attributed to source**. Then **post-exploitation / chaining** (priv-esc, IDOR, multi-step;
`credential_replay`) to measure real impact.

**10. Loop / remediation report.** Coverage matrix + metrics (exploit-success rate, time-to-exploit, FP
rate; gym also branch/mutation coverage) decide: gaps left → **reset the mirror snapshot** and back to stage
7; gaps closed → **the remediation round** (`remediation_board.py`) — the end of the pipeline. Every
oracle-VERIFIED weakness (found → worked → tested → confirmed) is posted to the chat board and the **whole
panel** proposes the fix, each suggestion **attributed to source** + an optional per-finding consensus. Two
paths, two audiences:
- **known-cve** — the fix is grounded in the offline vuln store (RAG auto-fills fixed-version / KEV due date
  / advisory). Routed to **ADMINS** as a framework/dependency/config **update**.
- **novel** — a weakness discovered here with no CVE; the panel *designs* the fix. Routed to the **CODE
  WRITER/IMPROVER** as a source change. `--emit-fixes` hands each finding to the **6-coder code bench**
  (deepseek-v4-pro, qwen2.5-coder-32b, kimi-k2.7-code, llama-3.3-70b, llama-4-scout, deepseek-r1-distill-32b)
  which emits a concrete **patch** (non-destructive — proposed, never auto-applied).

**Novel-first flagging (reach).** Findings are tagged `layer` (scaffold|code), `novelty` (known-cve|novel),
and `origin` (cve|fuzz|novel-code|novel). `operator/reach_report.py` renders a **NOVEL / ZERO-DAY section
FIRST**, separate from the routine CVE list: ids `NOV-SCAF-###` / `NOV-CODE-###`, badges + a ZERO-DAY (NO CVE)
banner + a CVE-status line, with the required fields (sub-surface — plugin/db-engine/… — origin, oracle-witness,
bridge-chain, exploitability, fix-owner). A **scaffold zero-day (a plugin/DB-tier weakness or a FUZZING crash)
is never listed in the CVE table** and routes to ADMINS/framework/PSIRT; a **code** novel finding routes to the
code-writer. Every oracle-verified reach win — including a proven **novel-code bridge/foothold** — is written
back to the learned techniques RAG (`rag/techniques_from_findings.py`, carrying its layer/intent/origin + the
code that worked) so the Planner ranks it next time (closed loop).

Output: a durable **remediation report** split into the Admin (framework updates) and Code-writer (code
changes) tracks; `--write-ledger` chains the chosen remediation onto the hash-chained findings ledger
(append-only, verified findings only). **MIRROR-side only** — fixes target the mirror twin (where the
findings were confirmed) for review + further testing there; proposed, never auto-applied, never run against
the real target. The co-pilot can run this itself for a **fully autonomous (no-human) run**: it has a
`remediation` tool, and `aegis_operator.py --remediate-on-finish` (env `AEGIS_REMEDIATE_ON_FINISH=1`)
deterministically runs the round over the run's verified findings at the end.

**The closed loop (mirror-only).** Deliver the code writer/improver's patch to the mirror
(`remediation_port.py` / `port_fix_to_mirror`: WSL/Docker/USB, any mirror OS), then
`remediation_verify.py` / `verify_fix_on_mirror`: snapshot → APPLY (code `git apply` + framework bump via the
mirror OS's package manager; `--allow-download` for the fetch) → RE-RUN each finding's exploit/oracle on the
patched system → **CLOSED / STILL-OPEN / BROKE-AFTER-UPDATE** → restore. If the update breaks the code
(`--health-cmd`), `--repair` runs a board round — operator diagnoses, panel suggests, the primary code writers
**DS / Qwen / Kimi / Scout / R1 are benchmarked** (applies/heals/size + convergence), best kept — with a **post-update report** on
what to do to get things running. Everything on the mirror twin; the real target is never patched or re-tested.
*(board decision point: next steps)*

## Track-specific refinements
- **Direct co-pilot test:** an explicit approval checkpoint past the guard (default dry-run) + `--max-iter`.
- **Autonomous ExploitGym:** per-episode snapshot reset, reward shaping (partial-exploit credit),
  curriculum (easy→hard), benchmark metrics.

## Cross-cutting invariants
- **Board = consulted at DECISION POINTS, available everywhere (v3).** The multi-model chat (Claude,
  DeepSeek, Sol, gpt-oss-120b/20b, qwen-coder) can be opened at any stage, but it is *actively consulted*
  at the marked decision points (0, 2, 4, 5, 7, 10) — it is **not a blocking gate on every micro-step**.
  Doctrine: many suggest, one operator executes and verifies.
- **Board data-hygiene (v3).** Privileged context is **sanitized before it reaches generalist board
  models**: real credentials/secrets, and sensitive real-target specifics, are **not** sent to the panel —
  the board gets the abstract decision (e.g. "an account is exposed; where to look next"), not the raw
  secret. Credential *values* stay operator-local (used only against the mirror). External members
  (DeepSeek/Sol/CF) see only sanitized prompts.
- **Verification = deterministic oracle (v3).** The oracle output decides verified/rejected; Claude never
  self-certifies a finding. HIGH-severity needs ≥2 independent oracle confirmations. Ground truth only,
  never a model's self-report.
- **Mirror, not prod.** Every aggressive action hits the stage-4 twin; recorded fidelity keeps results honest.
- **Containment + non-destructive** throughout; guard + snapshot-restore enforce it.
- **Attribution** — every verified finding records which model/method/CVE produced it.
- **Three run modes, one engine.** The same budgeted ~40-attempt discovery loop (`operator/iterative_hunt.py`)
  + shared vectors (`operator/vectors.py`) drives all three modes: **Operator** (`operator/iterative_hunt_live.py`),
  **ExploitGym** (`exploitgym/exploitgym/operators/iterhunt.py`), and **Red-Team** (`redteam/redteam.py`). Because
  the engine is shared, all three inherit the **reach axis** (two-direction scaffold⇄code probing + foothold/
  bridge + novel-code writer) and the **interactive board discussion** (via the shared `board_brainstorm`, which
  delegates to `board_discuss` when enabled). The Planner seeds and re-opens all three; Red-Team additionally
  gates every move through its authorization guard (safe read-only recon allowed in-scope + on research hosts;
  destructive / out-of-scope blocked), and a cross-host pivot is itself a reach bridge.
- **Board code-review (maintenance, from time to time).** Once the system has settled, the 6-coder bench reviews
  the Aegis code *itself* and the consultant **`qwq-32b`** consolidates a prioritized improvement plan
  (`operator/code_review.py` → `code_review_report.md`; secret-redacting hygiene; advisory — proposed, never
  auto-applied). This is the BOARD's self-review, distinct from Claude Code's own `/code-review` command.

## Running it
- Plan (the Planner): `python operator/planner.py "<objective>" --target <t> --stack ... --scenarios 3`
  to preview candidate plans; it runs automatically to seed the loop in each mode (disable `AEGIS_PLANNER=0`).
  Populate/refresh the ATT&CK DB with `python rag/ingest_mitre.py` (and the `mitre` feed in `rag_update.py`).
- Stage 1–3: operator recon + `rag_search`; rank by hand; credential-exposure is a manual side-input.
- Stage 4: build the twin (real code + synthetic data preferred); `--target-mode mirror`; `mirror_snapshot.py snapshot baseline`.
- Stage 5–6: operator (`rag_search` + `kali_driver`) + oracle.
- Stage 7a: the loop's per-round hunches come from the **interactive board discussion** automatically (shared
  `board_brainstorm` → `operator/board_discuss.py`; transcripts land in `board/board_files/DISCUSS__*.md`, watch
  with `board/live_board.ps1`); `AEGIS_BOARD_DISCUSS=0` reverts to the single pass, and roles/caps are tunable
  (`AEGIS_DISCUSS_PROPOSERS` / `_CHALLENGERS` / `_SYNTH` / `_TOK_*`). A standalone board round is still
  `code_suggester.py all` (`--review` adds qwq-32b); 7b: the deterministic testers. The reach loop itself:
  `python operator/iterative_hunt_live.py --objective "how far can I go" --role owner --budget 40`
  (novel-code writer on by default; `AEGIS_NOVEL_CODE=0` to disable, `AEGIS_NOVEL_CODE_ENSEMBLE=1` for the
  DS+Qwen convergence writer).
- Stage 10 (reach report): `python operator/reach_report.py <findings.jsonl> [--hunt <rep.json>]` renders the
  novel-first report (NOV-SCAF/NOV-CODE, CVEs kept separate). Offline self-test of the whole reach + discussion
  machinery (no LLM/mirror): `python operator/reach_selftest.py`.
- Stage 8–9: `python operator/test_suggestions.py --file <f> --source <model> --execute --role <r>`; then `credential_replay.py` for escalation.
- Stage 10: `coverage_matrix.report(...)`, reset snapshot, iterate; then the remediation round —
  `python operator/remediation_board.py --synthesize --emit-fixes --write-ledger` (add
  `--eg-results ../exploitgym/eg_results` to fold the gym's verified findings) → whole-panel fixes on the
  board, `operator/remediation_report.md` (Admin/framework + Code-writer tracks), code patches under
  `operator/remediation_fixes/`, and remediations chained onto the ledger.
- Maintenance (from time to time): `python operator/code_review.py` — the 6-coder bench reviews the Aegis code
  itself and qwq-32b consolidates a prioritized plan into `code_review_report.md` (advisory; secrets redacted).
