# RESILIENCE — failure-handling, recovery & kill-switches

How Aegis stays up (or fails safe) when a piece is missing, slow, or wedged, and how to recover a run.
This is the runbook the operator consults via `search_docs` (see `operator/aegis_operator.py` `DOC_FILES`);
companion to **HELP.md** (human how-tos), **docs/PIPELINE.md** (the flow), and **.claude/skills/aegis/SKILL.md**
(the playbook). Everything here is a real, verifiable behavior of the code — not aspiration.

## Core principle: offline-safe, never block a run
Every optional stage degrades instead of failing the run:
- **Planner** (`operator/planner.py`) — on any error (Kali/DB/board unreachable) `plan_session()` returns
  `None`; the loop falls back to the board's own brainstorm with no seed anchors and no mid-run re-open.
  Kill-switch: `AEGIS_PLANNER=0`.
- **Board discussion** (`operator/board_discuss.py`) — `discuss()` returns `[]` on any failure, and the loop
  falls back to the single-pass `board_brainstorm`. Kill-switch: `AEGIS_BOARD_DISCUSS=0`. If it is slow, the
  bottleneck is usually the converge/synth model; tune the roster with `AEGIS_DISCUSS_SYNTH` /
  `AEGIS_DISCUSS_CHALLENGERS` / `AEGIS_DISCUSS_N_CHALLENGERS`, or disable it and rely on the anchors + brainstorm.
- **Novel-code writer** (`operator/novel_code.py`) — unavailable ⇒ moves that asked for a written probe just
  run as ordinary moves. Kill-switch: `AEGIS_NOVEL_CODE=0`.
- **CVE/technique RAG** — offline by default; each per-model / per-feed call skips gracefully.
- **Skill preload** — `AEGIS_SKILL_PRELOAD=0` if you don't want the SKILL baked into the operator prompt;
  `search_docs` still serves HELP.md / this file / the SKILL.

## Model-availability resilience
Any board member that is unavailable/403 (missing key, wrong plan, rate limit) is **skipped gracefully** —
it never crashes a run. On the Cloudflare free tier only `qwen2.5-coder` + `gpt-oss` are reachable; the paid
Workers-AI plan unlocks the stronger coders (kimi, llama-4-scout, r1-distill, qwq-32b). **DeepSeek is reached
direct** (`api.deepseek.com`) and is the reliable path; the co-pilot brain + code path use `deepseek-v4-pro`,
board chat may use `deepseek-v4-flash` for budget. Reasoning models (kimi, r1-distill, qwq, DeepSeek) "think"
by default — answer-only paths must disable thinking or give a large token budget, else `content` is empty.

## Resume, pause & checkpoints (`orchestrator/bridge_server.py`, port 8765)
A tool-calling run keys off `task_id`:
- Message history is saved to `checkpoints/<task_id>.json` each iteration.
- Dropping a `.pause` flag (`checkpoints/<task_id>.pause`) stops the loop cleanly at the next iteration
  boundary and **keeps** the checkpoint.
- A later request with the **same `task_id`** picks the checkpoint back up and continues the same
  conversation instead of starting over. On natural completion the checkpoint is deleted.

So a crashed/paused/interrupted run resumes by re-issuing the same `task_id`; a fresh `task_id` starts over.
`operator/planner_core.py` builds the multi-step task graph in-process — there is no external scheduler
(the `AEGIS_SCHEDULER_URL` seam is dormant and defaults to a port where nothing listens; see README).

## Online CVE refresh — opt-in, staleness-gated, rollback-safe
`AEGIS_RAG_ONLINE=1` makes each run first call `operator/rag_refresh.ensure_fresh()` to pull public-feed
deltas before hunting. It is bounded and fail-safe: staleness window `AEGIS_RAG_MAX_AGE_H` (default 12),
store at `AEGIS_RAG_HOME` (default `/opt/aegis-rag`), a backup is taken with rollback, and **a network/feed
failure leaves the existing store intact and the run proceeds offline**. Public vuln feeds only — never target
data. The egress can be forced through a **fail-closed VPN gate**: `AEGIS_VPN_REQUIRED=1` (optional
`AEGIS_VPN_COUNTRY`, WireGuard `AEGIS_VPN_WG_CONF` preferred over OpenVPN `AEGIS_VPN_CONFIG`); if a required
tunnel can't be established the refresh is skipped and the run stays offline.

## Verification & non-destructive safety (fail toward "not a finding")
- **Only oracle-verified findings count** (`shared/verified_findings.py`); HIGH/CRITICAL need ≥2 independent
  confirmations. An unverifiable claim is rejected, never recorded — over-claiming fails safe.
- **Non-destructive doctrine** — the guard blocks `DELETE FROM` / `DROP` / `TRUNCATE` / `rm -rf` / HTTP
  `DELETE`; plant/write for proof is allowed, erase/delete is not.
- **Snapshot/restore** the mirror around anything stateful: `operator/mirror_snapshot.py snapshot|restore`.

## Mirror / WSL resilience (the contained target)
- **WSL idle-shutdown** kills the distro (and the mirror's docker containers) seconds after the last attached
  session — which drops a live target mid-run. Hold it up with a backgrounded
  `wsl -d kali-linux -- sleep 3600` for the duration of a hunt, and re-`docker compose up -d` the mirror if it
  dropped (in the mirror dir, e.g. `/opt/fixflow-mirror`). Docker in Kali may need root: `wsl -d kali-linux -u root`.
- **WSL path mangling** — prefix host↔Kali commands with `MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`.
- **Shell loops don't survive host→WSL→bash** — a `for x in … $x …` loop (and `$(...)`/`$!` captures) can come
  back empty; enumerate explicitly or put the logic in a script file that bash reads locally.
- **Python not on PATH** — set `AEGIS_PYTHON` to the full interpreter path (honored by `start-all.ps1`,
  `board/live_board.ps1`, and `exploitgym`), or use `python3`.

## Kill-switches & env, at a glance
| Toggle | Effect |
|---|---|
| `AEGIS_PLANNER=0` | skip the Planner; loop uses its own brainstorm |
| `AEGIS_BOARD_DISCUSS=0` | skip the multi-round board; single-pass brainstorm (faster) |
| `AEGIS_NOVEL_CODE=0` | don't write custom probes; run moves as-is |
| `AEGIS_SKILL_PRELOAD=0` | don't bake the SKILL into the operator prompt |
| `AEGIS_KALI_AUTOSTART=0` | don't try to boot Kali (use when already inside it) |
| `AEGIS_RAG_ONLINE=1` | opt in to the online CVE refresh (else fully offline) |
| `AEGIS_VPN_REQUIRED=1` | fail-closed VPN gate for the feed/OSINT egress |
| `AEGIS_REMEDIATE_ON_FINISH=1` | auto-run the stage-10 remediation round at run end |

## Recovery quick-reference
| Symptom | Likely cause → fix |
|---|---|
| Target refuses connections mid-run | WSL/mirror idle-shutdown → keepalive `sleep`, re-`docker compose up -d` |
| Run "hung", no output | model call in flight (block-buffered stdout); check with `py-spy dump --pid <pid>` — calls are bounded by a per-call timeout |
| Board very slow before findings | converge/synth model latency → `AEGIS_BOARD_DISCUSS=0` or a lighter `AEGIS_DISCUSS_SYNTH` |
| Everything "rejected", zero findings | check the move actually reaches its oracle (concrete method/path; authz moves need the suspect `role`); confirm the target state by hand |
| A model 403s / is missing | expected — it's skipped; DeepSeek-direct is the reliable path |
| Interrupted / crashed run | re-issue the same `task_id` to resume from the checkpoint |
| Online refresh failed | non-fatal — the local store is intact and the run continues offline |

Secrets live only in gitignored `secret.env` / `set-env.local.ps1` — never in the repo or in chat.
