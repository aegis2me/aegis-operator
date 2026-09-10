# Aegis Operator

> ⚠️ **LEGAL NOTICE — READ [`DISCLAIMER.md`](DISCLAIMER.md) BEFORE USE.** This is a **defensive
> security-research, benchmark, and self-help tool for systems you OWN or are EXPLICITLY AUTHORIZED in
> writing to test** (and mirror copies of them) — **nothing else**. Any unauthorized, offensive, or
> unlawful use is strictly prohibited and is the sole, independent act of the user, not the Author.
> **By using this Software you accept the terms in `DISCLAIMER.md` in full.**

A self-contained toolkit for **authorized, contained security research and AI-operator benchmarking** against your *own* applications. It has **three run modes on one shared discovery engine**, backed by a multi-model board and an oracle-gated verification layer:

1. **Operator co-pilot** (`operator/`) — an LLM in the operator seat (DeepSeek / OpenAI-compatible), with an approval gate, an offline vuln-RAG, a planner, and a hash-chained findings ledger. Drives a Kali toolset via the orchestrator.
2. **ExploitGym** (`exploitgym/`) — a contained autonomous-exploitation benchmark: run one or more operators (Claude / DeepSeek / GPT / Cloudflare open models) against a disposable twin and score them from *ground truth*, never from the model's own transcript.
3. **Red-Team** (`redteam/`) — a **first-class, authorization-gated pen-test** mode: a fail-closed scope/RoE guard (owned targets only; safe-recon vs destructive classified separately), an attack graph, and **cross-host lateral movement** (foothold → internal service → crown-jewel), exercised against **internal mirrors**.

All three share:
- **A multi-model board** (`board/`, `operator/cf_agent.py`, `operator/code_suggester.py`) — a panel where **coders propose** runnable exploit code, an **analyst/verifier gives a second opinion**, and the coordinator decides; extensible via **direct provider API keys, Cloudflare Workers AI, or any OpenAI-compatible platform** (see HELP.md "Expanding the board").
- **A shared verification layer** (`shared/`, single source; components import it via logic-free shims) — an oracle-gated, event-sourced, hash-chained **findings store** (only oracle-verified counts; HIGH needs ≥2 confirmations) + a **coverage matrix** so untested surface stays visible.
- **One discovery engine** (`operator/iterative_hunt.py`) — a budgeted loop of *genuinely different* attempts (hypothesis-dedup, angle diversity, information-gain budget, novelty-over-convergence), shared by all three modes through the same fact-finding vectors (see below).
- **A pre-execution Planner** (`operator/planner.py`) — runs **before** any mode and **drives the start of the run**: it fingerprints the target, ranks prior-successful `(technique, tool)` combos from the techniques DB (curated + learned + **MITRE ATT&CK**), has the board keep only *environment-relevant* techniques, then builds **multi-scenario candidate plans** (fast-track / thorough / covert) and seeds the loop with each plan's **deterministic anchor moves** (start from what worked before + ATT&CK-informed), **re-opening** the next scenario mid-run on a stall; verified wins are written back so it gets smarter each run. **At the discovery stage the Planner is *observatory*** — it supplies its ranked-technique knowledge as context but **does not generate the novelty; the live board does** (it sees the deltas + footholds). Kill-switch `AEGIS_PLANNER=0`. See **docs/PLANNER.md**.

Supporting pieces: `orchestrator/` (the bridge + Kali/browser MCP tool servers) and `rag/` (the offline-**and-online** vuln knowledge store). A periodic **board code-review** (`operator/code_review.py`) turns the same panel on Aegis's *own* source — the coders review it and the consultant consolidates a prioritized improvement plan (advisory only).

> **Mirror / scaffold testing — never test production directly.** The core safety model: you **fingerprint** the real/production environment, then **build a local twin** and test *that*, never the live target. The twin is one of two forms, and the difference in coverage is the point:
> - **Real-code mirror** — the app's **actual code** + synthetic data. Because the real code is present, you can test **broadly**: the full discovery loop reaches **code- and business-logic flaws** (IDOR, broken access control, money-validation, mass-assignment, logic injection) *in addition to* the stack layer. Highest fidelity — findings are real.
> - **Behavioral scaffold** — when you **don't have the source**, the *stack* is reconstructed from the fingerprint alone (framework, versions, endpoints, headers, error shapes) and stood up locally with **no actual code present**. That's enough for **stack-/dependency-/config-level** tests (known-CVEs, misconfig, supply-chain, protocol) but **not** the app's own code-logic — you can't test logic that isn't there.
>
> Either way the aggression stays on the **local mirror/scaffold** (or a dedicated production-mirror you own), so real production is never touched. `--target-mode mirror` drives this; `docs/PIPELINE.md` stage 4 is the load-bearing "build the twin + validate fidelity" step.
>
> **Scope & ethics.** This is for testing systems you own or are explicitly authorized to test, in a contained environment. Everything here assumes a disposable twin on an isolated network. Non-destructive by doctrine: plant/write is allowed for proof; erase/delete is not. No external-agent recruitment, no off-box egress, no evasion/persistence.

> **Responsible use & dual-use.** AEGIS automates reconnaissance and *oracle-verified* weakness
> confirmation, so — like any offensive-security tooling — it is **dual-use**: the same capabilities that
> harden a system you own can harm systems you do not. **Only run it against assets you own or have
> explicit, written authorization to test.** AEGIS **cannot verify that authorization** — the scope
> allowlist, `--target-mode`, the non-destructive doctrine, and the "no persistence/evasion" stance are
> operator-enforced conventions a fork can change; they reduce blast radius, they do **not** confirm
> intent. So: **live-target mode is not the default (use `mirror`)**; keep runs attributable (record an
> operator id / run id); do not point the OSINT/VPN lane at third parties; and disclose any real findings
> only through authorized channels. Unauthorized scanning, access, or credential use is illegal and is
> **not** a supported use of this project. (Board-reviewed dual-use assessment; stronger technical
> safeguards — verifiable authorization e.g. a signed scope token / DNS-TXT proof, and append-only audit
> logging — are recommended hardening, not yet enforced.)

> **Prior art & positioning.** Each individual capability here has prior art (e.g. PentAGI/CAI for the operator, NYU CTF Bench for the benchmark, T3MP3ST for oracle-graded red-teaming, OSS-Fuzz-Gen/ClusterFuzzLite for the fuzzer, LiteLLM for model routing). What appears distinctive is the **integration** — the deterministic-oracle + hash-chained-evidence + one-shared-discovery-loop triad, plus the ATT&CK-ranked Planner with mid-run re-open, combined in a single stack. To be careful about the claim: **we found no publicly available GitHub project integrating this complete set of capabilities into a single shared architecture** — which is not a proof of research or patent novelty, only that no equivalent all-in-one repo was found.
>
> **Adopted (borrowed patterns, kept in-house, offline).** Rather than take on those tools as dependencies, we borrowed their best ideas: **PyRIT**'s graded scorer (`shared/scoring.py`, complements the oracle — never replaces it), **garak**'s uniform probe schema + taxonomy (`shared/probe_schema.py`), **OSS-Fuzz-Gen**'s structure-aware seed generation (`operator/seed_gen.py`), **NYU CTF/Cybench** task-metadata fields on the ExploitGym `Scenario`, and **cve-search**'s correct CPE version-range matching (`rag/cpe_match.py`). The grey-box fuzzer additionally runs **OSS-Fuzz/Jazzer.js** tooling self-hosted (incl. a native JS engine, proven on a real Node parser).

---

## What's where

```
aegis-operator/
├── operator/          the co-pilot harness (aegis_operator.py) + config, planner, board agents
├── exploitgym/        the autonomous-exploitation benchmark (runner, scenarios, operators)
├── redteam/           authorization-gated first-class pentest mode (RoE, scope guard, attack graph)
├── orchestrator/      bridge_server.py + kali_driver_server.py + browser_use_server.py
├── shared/            canonical verified_findings.py + coverage_matrix.py (operator/ + exploitgym/ import via shims)
├── rag/               offline vuln RAG store (ingest_*.py, rag_db.py, systemd units)
├── board/             live_board.ps1 + board_view.py (multi-model blackboard viewer)
├── docs/              architecture notes
├── start-all.ps1      launches the orchestrator (kali_driver + browser_use + bridge)
├── requirements.txt   merged Python deps
├── secret.env.example / set-env.local.ps1.example   copy + fill in your keys
└── INSTALL.md         full setup for a fresh machine
```

## Quick start (after INSTALL.md)

```powershell
# 1. secrets
copy set-env.local.ps1.example set-env.local.ps1   # then edit in your LLM key

# 2. bring up the tool servers + bridge
./start-all.ps1

# 3a. run the operator co-pilot on a task
cd operator
python aegis_operator.py --task "review the target app's invoice endpoints for money-validation gaps"
#   add --auto-approve only inside the contained sandbox

# 3b. or run an ExploitGym benchmark
cd ../exploitgym
python -m exploitgym.cli run <scenario-id>

# 3c. or run the authorization-gated RED-TEAM mode (owned/in-scope targets only)
cd ../redteam
python redteam.py --auth authorization.json --objective "..." --target <in-scope host>

# 3d. fan out the board's code bench + analyst/verifier pass on a task
cd ../operator
python code_suggester.py all "test /api/invoices for a money-validation gap" --review

# 3e. watch the multi-model board (optional)
cd ../board
./live_board.ps1

# 3f. preview the Planner's candidate plans for a target (optional; runs automatically before each mode)
cd ../operator
python planner.py "reach as deep as you can" --target https://localhost:8443 --scenarios 3

# 3g. periodic board code-review of Aegis's OWN source -> code_review_report.md
python code_review.py --paths operator shared rag redteam exploitgym
```

## How the modes + board fit together

- **Operator, ExploitGym, and Red-Team** all record findings through the **same** `verified_findings` layer, so a claim is only counted once an oracle confirms it against DB/HTTP ground truth — over-claims are auto-rejected — and they share the **coverage matrix** so every mode sees which `(surface, role, technique)` cells are still gaps.
- **The board drives discovery for all three:** coders propose runnable code → an **analyst/verifier** (`qwq-32b`) gives a second opinion (correctness, does the oracle really prove it, non-destructive?) and ranks → the coordinator decides → the oracle gates. Members are added cheaply via Cloudflare Workers AI (`operator/cf_agent.py`, roster in `board_roster.json`), direct provider keys, or any OpenAI-compatible platform.
- **Red-Team** differs only in its doctrine wrapper: a fail-closed authorization/scope guard on top of the same engine + vectors + board, so benchmark and co-pilot findings transfer straight into an RoE-bound engagement.

## Iterative hunt — three modes, one engine

Beyond the single-pass co-pilot, Aegis runs a **budgeted, adaptive discovery loop** (`operator/iterative_hunt.py`) driven by the board. One engine, three run modes that differ only in the doctrine wrapper each puts around a move:

- **Operator** (`operator/iterative_hunt_live.py`) — non-destructive guard; gap-finding on your mirror.
- **ExploitGym** (`exploitgym/.../operators/iterhunt.py`) — + audit trail; contained autonomous scoring.
- **Red-Team** (`redteam/redteam.py`) — + a **fail-closed authorization/scope guard**; RoE-bound pentest against internal mirrors. Includes **cross-host lateral movement** (`redteam/lateral.py`): a confirmed foothold OWNs its host in an attack graph and proposes scope-gated pivot moves to reachable in-scope hosts, chaining web → internal service → crown-jewel `goal` (e.g. domain controller); the chain is reconstructed and scored. Red-Team runs a **deeper per-mode escalation budget** (each pivot hop is a novel confirm on a new host) while Operator/ExploitGym stay breadth-biased.

All three dispatch through the **same fact-finding vectors** (`operator/vectors.py`): `web · recon · supply_chain · static · fuzz · misconfig · rag`, so no mode is blind to a class the others can see.

The loop spends its budget (~40) on **genuinely different** attempts, not 40 variations of one idea:

- Each attempt is a falsifiable **hypothesis**, fingerprinted by `(angle, surface, vuln-class, mechanism, oracle-signal)` plus the distinctness axes — **excluding the payload value**, so a value-only tweak collides and is rejected as lazy.
- **Breadth-first** scheduling and a hard per-angle cap spread the budget across distinct approaches.
- **Novelty is rewarded over convergence**: escalation of an oracle-confirmed foothold is bounded (small budget slice, capped steps) and gated to *novel* confirms; breadth exploration is preserved across a brief escalation.
- The budget counts only **information-gaining** attempts — generic 404s, transport errors and repeats are *noise* (bounded separately) and cannot pad the count.
- Only oracle-verified findings are recorded (HIGH/CRITICAL need ≥2 independent confirmations).

The CVE RAG is **offline by default and online on demand**: set `AEGIS_RAG_ONLINE=1` and each run first calls `ensure_fresh()`, which pulls public-feed deltas (CISA-KEV, EPSS, NVD lastMod-delta, …) to update the local store before hunting — staleness-gated, backed up with rollback, and **offline-safe** (a network/feed failure leaves the existing store intact and the run proceeds). These are public vulnerability feeds only, never anything about the target. That feed/OSINT egress can be routed through a **VPN egress gate** (opt-in, fail-closed — `AEGIS_VPN_REQUIRED=1`, optional `AEGIS_VPN_COUNTRY=<ISO>`, WireGuard `AEGIS_VPN_WG_CONF` preferred over OpenVPN `AEGIS_VPN_CONFIG`) so it never leaves via the box's own IP; if a required tunnel can't be established the refresh is skipped and the run stays offline. All VPN config files + values are gitignored (see INSTALL.md).

### Board members (and extending the roster)

`board_roster.json` defines the panel. The **constant contributors**, queried every round:

| Member | Model | Where | Role |
|---|---|---|---|
| **claude** | Anthropic | external (bills separately) | overseer / verifier — highest signal-per-byte |
| **deepseek-direct** | DeepSeek V4 (pro/flash) | external — `api.deepseek.com` | concise + broad; also a code-writer |
| **sol** | GPT-5.6 | external | deepest analyst (content-gated — QA-reframe shim) |
| **gpt-oss-120b** | `@cf/openai/gpt-oss-120b` | Cloudflare Workers AI | strategy / breadth (not a code-writer) |
| **gpt-oss-20b** | `@cf/openai/gpt-oss-20b` | Cloudflare Workers AI | input / strategy (not a code-writer) |

**Code bench** (emit runnable `TARGET/CODE/ORACLE` blocks) — **six coders**, each skipping gracefully if unavailable: **qwen2.5-coder-32b**, **deepseek-direct** (v4-pro), **kimi-k2.7-code**, **llama-3.3-70b**, **llama-4-scout**, **deepseek-r1-distill-32b** (all Cloudflare Workers AI paid, except DeepSeek which is reached direct). The **analyst/verifier consultant** is **qwq-32b** — a second opinion after the bench, before the oracle. This same bench powers the periodic **board code-review** (`operator/code_review.py`).

**Extending the roster via Cloudflare Workers AI (paid).** The free CF tier (~10k Neurons/day) covers the gpt-oss + qwen models; the **paid Workers AI plan** unlocks the stronger coders now wired into the bench — **kimi-k2.7-code**, **llama-4-scout** and **deepseek-r1-distill-32b** (the last two added after a code-review bake-off) — plus `kimi-k2.6`, `glm-5.3` and CF's own `deepseek-v4-pro`. To add another: put its `@cf/…` slug in `operator/cf_models.json`, list it in `board_roster.json` (`code_suggesters` / `always_include` / `active_cf_optional`), and — for a code-writer — give it the code role in `operator/cf_agent.py` (`ROLE_PROMPTS`); run `python operator/cf_agent.py list` with paid CF creds to confirm the slug. Beyond CF, any **direct provider API key** or **OpenAI-compatible aggregator** works the same way (see HELP.md "Expanding the board").

## Run modes (three options)

| Mode | Doctrine | Purpose |
|---|---|---|
| **Operator** (`operator/aegis_operator.py`) | contained mirror, non-destructive, no egress | LLM co-pilot assessment of a mirror twin |
| **ExploitGym** (`exploitgym/`) | contained disposable twin, per-episode reset | benchmark autonomous exploitation, scored from ground truth |
| **Red-Team** (`redteam/`) | **authorization-gated, RoE-bound, richer INTERNAL MIRROR environments** | first-class pen-test *depth* — network / cloud / AD / binary / post-exploitation — on owned, contained mirror twins |

**Red-Team** broadens *capability* (network-service exploitation, cloud/k8s/AD attack-graph analysis,
binary crash→exploit triage, post-exploitation & lateral movement) and runs against **richer,
multi-host internal mirror environments** — still owned and contained, **never production**. The
relaxation is capability + environment richness, not "go live". It is **fail-closed**: a valid
authorization artifact (owner, scope allowlist, expiry, Rules of Engagement) is mandatory, every
action passes an owned-scope + allowed-action + non-destructive gate (`redteam/authorization.py`),
and everything is audited with a kill-switch. See `redteam/DOCTRINE.md`. The heavy exploitation
driver is pluggable (wire an authorized Metasploit-RPC instance); the default is a dry stub that only
records intent.

## Standalone by design

There is no external task scheduler. The orchestrator (bridge + MCP servers) is the whole engine; the operator's own `planner_core` handles multi-step planning.

### The `AEGIS_SCHEDULER_URL` hook (optional, off by default)

`AEGIS_SCHEDULER_URL` is a dormant integration seam for an **external task-tree scheduler** — a separate HTTP service that would decompose an objective into a task tree, track task status, and re-dispatch subtasks across a shared `task_id`. **No such service ships here.**

- **How it runs by default: it doesn't.** The variable defaults to `http://127.0.0.1:37695`, where nothing listens. The operator's scheduler-facing tools (`t_spawn` → `POST /task`, task-status polls, `t_read_task_context`, `t_resume`, report finalization) probe it with a short-timeout reachability check (`GET /docs`); when nothing answers they report **"unavailable"** and the operator falls back to driving itself. Leaving the variable unset is the normal, intended state.
- **What runs multi-step work instead:** `operator/planner_core.py` turns an objective into a verified task graph in-process, and `orchestrator/bridge_server.py` (port 8765) executes the tool-calling loop with per-`task_id` checkpoints (`checkpoints/<task_id>.json`), pause (a `.pause` flag file), and resume (the same `task_id` picks the checkpoint back up). That is the whole engine.
- **To enable one anyway:** stand up your own service speaking that HTTP API (`/docs`, `/task`, `/get/task/status`, …) on some host/port, then set `AEGIS_SCHEDULER_URL=http://<host>:<port>` in `secret.env` / `set-env.local.ps1`. The operator's scheduler tools then go live and delegate task-tree management to it.

See **INSTALL.md** for prerequisites and a fresh-machine setup, and **docs/ARCHITECTURE.md** for how the pieces talk.
