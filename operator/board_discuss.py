#!/usr/bin/env python3
"""
board_discuss.py -- the LIVELY, INTERACTIVE board discussion for each hunt-round (the board's converged
design: ds + gpt-oss-120b + kimi + llamas + r1-distill). Replaces the single static ask->reply
(board_brainstorm's one pass) with a BOUNDED multi-model DELIBERATION: models propose, then react to
each other -- what will work, what would LIKELY work, what MIGHT not, what would LIKELY FAIL and why --
then a scorer/synthesizer converges to the ranked next-moves the loop consumes.

PROTOCOL per round (waves; parallel where roles are independent):
  1. PROPOSE   -- proposers, PARALLEL + ISOLATED (each sees ONLY the live state, not peers -> genuine
     diversity, ds's anti-groupthink lever). Each emits <=2 grounded, falsifiable hypothesis moves.
  2. CRITIQUE  -- rotating RED-TEAM challengers, parallel: attack each proposal citing an oracle-delta/
     coverage/reach fact; MUST include a contrarian failure reason; assign a verdict + confidence.
  3. (REBUT    -- attacked proposers amend once; OFF by default for latency, AEGIS_DISCUSS_REBUT=1.)
  4. CONVERGE  -- the scorer/synthesizer (qwq-32b; fallback gpt-oss-120b, then ds) merges to <=5 moves,
     stamps verdict (will-work|likely|maybe|likely-fail) + confidence + dissent, PRESERVES >=1 minority
     move (confidence>=0.3) and injects an off-class adversarial move if all proposals converge.

HAND-OFF: returns the SAME hypothesis-shaped moves IterativeHunt consumes (angle/surface/vuln_class/
mechanism/trust/expected_oracle/layer/intent/needs_code) -- each now carrying verdict/confidence/dissent
-- AND writes a readable TRANSCRIPT to the board dir for live_board.ps1.

BOUNDED: per-phase token caps, parallel waves, early-stop when <=1 proposal. Runs only on the loop's
board cadence (not every attempt). OFFLINE-SAFE: any failure returns [] so board_brainstorm falls back
to its single-pass. Kill-switch AEGIS_BOARD_DISCUSS=0.
"""
from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

_DS_NAMES = {"ds", "deepseek", "deepseek-direct", "deepseek-v4-pro", "deepseek-v4-flash"}

# roles -> roster (env-overridable). NO direction split; rotation avoids staleness.
PROPOSERS = [m.strip() for m in (os.environ.get("AEGIS_DISCUSS_PROPOSERS")
             or "ds,qwen2.5-coder-32b,kimi-k2.7-code").split(",") if m.strip()]
PROPOSER_WILDCARD = os.environ.get("AEGIS_DISCUSS_WILDCARD", "llama-4-scout")
CHALLENGER_POOL = [m.strip() for m in (os.environ.get("AEGIS_DISCUSS_CHALLENGERS")
                   or "ds,qwen2.5-coder-32b,llama-3.3-70b,deepseek-r1-distill-32b").split(",") if m.strip()]
SYNTH_ORDER = [m.strip() for m in (os.environ.get("AEGIS_DISCUSS_SYNTH")
               or "qwq-32b,gpt-oss-120b,ds").split(",") if m.strip()]

# per-phase token caps (bounded cost). Converge is larger: it emits up to 5 full moves + verdicts.
TOK_PROPOSE = int(os.environ.get("AEGIS_DISCUSS_TOK_PROPOSE", "550"))
TOK_CRITIQUE = int(os.environ.get("AEGIS_DISCUSS_TOK_CRITIQUE", "500"))
TOK_CONVERGE = int(os.environ.get("AEGIS_DISCUSS_TOK_CONVERGE", "1400"))  # qwq is a reasoning model -> budget
N_CHALLENGERS = int(os.environ.get("AEGIS_DISCUSS_N_CHALLENGERS", "2"))
_VERDICTS = ("will-work", "likely", "maybe", "likely-fail")

# FAST-PATH latency controls (the board's own latency recommendation). DEFAULT = fast: a single fast,
# non-reasoning model proposes the next moves each round; the full 3-wave (propose+critique+converge, with
# the slow reasoning models) fires ONLY on a pivot or stall -- cutting a typical round from ~90-120s to
# ~25-35s while preserving depth where it matters. Env:
#   AEGIS_BOARD_FAST=0        -> always run the full 3-wave (previous behaviour)
#   AEGIS_BOARD_FAST_MODEL    -> the single hot-path model (default deepseek-v4-flash: fast, non-reasoning)
#   AEGIS_DISCUSS_TOK_FAST    -> hot-path token cap
#   AEGIS_BOARD_FULL_STALL    -> closed-combo count that forces the full board (stall signal)
#   AEGIS_BOARD_FULL_EVERY    -> also run the full board every Nth round (0 = only on pivot/stall)
FAST = str(os.environ.get("AEGIS_BOARD_FAST", "1")).lower() not in ("0", "false", "no", "off")
FAST_MODEL = os.environ.get("AEGIS_BOARD_FAST_MODEL", "deepseek-v4-flash")
TOK_FAST = int(os.environ.get("AEGIS_DISCUSS_TOK_FAST", "700"))


def enabled() -> bool:
    return str(os.environ.get("AEGIS_BOARD_DISCUSS", "1")).lower() not in ("0", "false", "no", "off")


def _as_text(x) -> str:
    """Normalize a model reply to text -- CF auto-parses JSON so content can arrive as a dict/list
    (see the cf gotcha). Mirrors code_review._as_text."""
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        for k in ("content", "text", "message", "answer"):
            if isinstance(x.get(k), str):
                return x[k]
        return json.dumps(x)
    if isinstance(x, list):
        return "\n".join(_as_text(i) for i in x)
    return str(x or "")


def _ask(model: str, sysp: str, usr: str, max_tokens: int, temperature: float = 0.6) -> str:
    """Ask ONE roster model. ds/deepseek -> DeepSeek direct (thinking off); everything else -> CF.
    Offline-safe: any failure -> ''."""
    m = (model or "").lower()
    try:
        if m in _DS_NAMES:
            import remediation_board as RB
            ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
            model_id = "deepseek-v4-pro" if m in ("ds", "deepseek", "deepseek-direct", "deepseek-v4-pro") \
                else "deepseek-v4-flash"
            return _as_text(RB._post_openai_style(ep + "/chat/completions",
                                                  os.environ.get("AEGIS_LLM_API_KEY", ""),
                                                  model_id, sysp, usr, max_tokens, think=False) or "")
        import cf_agent
        return _as_text(cf_agent.ask(model, sysp, usr, max_tokens=max_tokens, temperature=temperature))
    except Exception:
        return ""


def _parse_moves(text: str) -> list:
    """Parse JSON-line move objects (the format every phase is asked to emit); tolerate a JSON array."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip().rstrip(",")
        if line.startswith("{"):
            try:
                o = json.loads(line)
                if isinstance(o, dict):
                    out.append(o)
            except Exception:
                pass
    if not out:                                          # fallback: a single [...] array
        i, j = (text or "").find("["), (text or "").rfind("]")
        if 0 <= i < j:
            try:
                arr = json.loads(text[i:j + 1])
                out = [o for o in arr if isinstance(o, dict)]
            except Exception:
                out = []
    return out


def _state_block(context: dict) -> str:
    """The grounding STATE every model sees each turn -- oracle deltas + coverage + reach + closed
    combos + under-probed direction + on-stack intel. Trimmed to keep tokens bounded."""
    ctx = context or {}
    recent = []
    for a in (ctx.get("attempts") or [])[-6:]:
        mv = a.get("move", {}) or {}
        recent.append({"surface": mv.get("surface") or mv.get("path") or mv.get("target"),
                       "vuln_class": mv.get("vuln_class") or mv.get("class"),
                       "verdict": a.get("verdict"), "implies": (a.get("delta") or {}).get("implies")})
    pintel = ctx.get("planner_intel") or {}
    block = {
        "phase": ctx.get("phase"), "budget_remaining": ctx.get("budget_remaining"),
        "oracle_deltas": recent,
        "coverage": ctx.get("coverage"),
        "reach": ctx.get("reach"),
        "closed_combos": (ctx.get("closed_combos") or [])[:8],
        "confirmed": [ (c.get("move", {}) or {}).get("surface") for c in (ctx.get("confirmed") or [])[:6] ],
        "on_stack": (pintel.get("target_stack") if isinstance(pintel, dict) else None),
        "kali_tools_present": (pintel.get("kali_tools_present") if isinstance(pintel, dict) else None),
    }
    return json.dumps(block)[:2800]


_MOVE_SHAPE = ('{"angle":"..","surface":"/api/..","vuln_class":"..","mechanism":"how it manifests",'
               '"trust":"anon|user|admin|internal","expected_oracle":"exact observable","layer":"scaffold|code",'
               '"intent":"map|foothold|bridge|escalate","needs_code":false,"new_code":"brief if code must be written",'
               '"raw_confidence":0.0,"rationale":"<=20 words grounded in a delta/coverage/reach fact"}')


def _propose(model: str, state: str) -> list:
    sysp = (f"You are '{model}' on the discovery board (AUTHORIZED, contained mirror). Propose UP TO 2 "
            "DISTINCT, FALSIFIABLE next-move hypotheses grounded ONLY in the STATE (oracle deltas, "
            "coverage, reach). Reason about HOW FAR you can go non-destructively; split ideas across the "
            "TWO reach directions (layer='scaffold' = stack+installed-modules only; layer='code' = the "
            "app's actual code) -- prefer the under_probed_direction. NO payload-only tweaks; each move "
            "must differ from prior attempts on surface/vuln_class/mechanism/trust/expected_oracle. "
            "Output JSON LINES, one move per line, EXACTLY this shape: " + _MOVE_SHAPE)
    moves = _parse_moves(_ask(model, sysp, "STATE:\n" + state, TOK_PROPOSE))
    for mv in moves[:2]:
        mv["_by"] = model
    return moves[:2]


def _critique(model: str, state: str, proposals: list) -> list:
    brief = [{"i": i, "surface": p.get("surface"), "vuln_class": p.get("vuln_class"),
              "mechanism": p.get("mechanism"), "layer": p.get("layer"), "by": p.get("_by")}
             for i, p in enumerate(proposals)]
    sysp = (f"You are '{model}', a RED-TEAM challenger on the board. For EACH proposal, judge concretely: "
            "will it work? what would LIKELY work, what MIGHT not, what would LIKELY FAIL -- and WHY. You "
            "MUST cite a specific oracle-delta/coverage/reach fact and give at least one CONTRARIAN "
            "failure reason. Output JSON LINES, one per proposal: "
            '{"ref":<i>,"verdict":"will-work|likely|maybe|likely-fail","confidence":0.0,'
            '"failure_modes":[".."],"why":"contrarian reason citing evidence"}')
    crit = _parse_moves(_ask(model, sysp, "STATE:\n" + state + "\nPROPOSALS:\n" + json.dumps(brief), TOK_CRITIQUE))
    for c in crit:
        c["_by"] = model
    return crit


def _converge(state: str, proposals: list, critiques: list) -> list:
    for model in SYNTH_ORDER:
        sysp = (f"You are '{model}', the board's SYNTHESIZER + likelihood SCORER. Given the PROPOSALS and "
                "the RED-TEAM CRITIQUES, select UP TO 5 best next moves for the hunt. Merge duplicates. "
                "Assign each a verdict (will-work|likely|maybe|likely-fail), a confidence 0-1, and dissent "
                "(list the roles/models that disagreed). PRESERVE at least one MINORITY/dissenting move if "
                "its confidence >= 0.3 (avoid local optima); if ALL proposals share one surface/vuln_class, "
                "ADD one adversarial move from a DIFFERENT class. Output JSON LINES, one move per line, "
                "this shape plus verdict/confidence/dissent: " + _MOVE_SHAPE[:-1] +
                ',"verdict":"likely","confidence":0.0,"dissent":["role"]}')
        usr = "STATE:\n" + state + "\nPROPOSALS:\n" + json.dumps(proposals)[:3500] + \
              "\nCRITIQUES:\n" + json.dumps(critiques)[:3000]
        moves = _parse_moves(_ask(model, sysp, usr, TOK_CONVERGE))
        if moves:
            for mv in moves:
                mv.setdefault("verdict", "maybe")
                mv["_synth"] = model
            return moves[:5]
    return []


def _transcript(rnd, proposals, critiques, final) -> str:
    L = [f"## Board discussion — round @{rnd}  ({time.strftime('%Y-%m-%d %H:%M:%S')})", ""]
    L.append("### Proposals")
    for p in proposals:
        L.append(f"- **[{p.get('_by')}]** `{p.get('layer','?')}` {p.get('surface')} "
                 f"({p.get('vuln_class')}) — conf {p.get('raw_confidence')}: {p.get('rationale','')}")
    L.append("\n### Critiques (what will / likely / might-not / likely-fail)")
    for c in critiques:
        L.append(f"- **[{c.get('_by')}]** → proposal {c.get('ref')}: **{c.get('verdict')}** "
                 f"(conf {c.get('confidence')}) — {c.get('why','')}; fails: {c.get('failure_modes')}")
    L.append("\n### Convergence (final ranked moves)")
    for m in final:
        L.append(f"- **{m.get('verdict','?').upper()}** (conf {m.get('confidence')}) `{m.get('layer','?')}` "
                 f"{m.get('surface')} [{m.get('vuln_class')}/{m.get('intent','foothold')}]"
                 + (f" — dissent {m.get('dissent')}" if m.get('dissent') else ""))
    return "\n".join(L)


def _write_transcript(md: str, rnd) -> str:
    try:
        root = os.path.dirname(HERE)
        bdir = os.environ.get("AEGIS_BOARD_DIR", os.path.join(root, "board", "board_files"))
        os.makedirs(bdir, exist_ok=True)
        path = os.path.join(bdir, f"DISCUSS__round-{rnd}__{int(time.time()*1000)}.md")
        open(path, "w", encoding="utf-8").write(md)
        return path
    except Exception:
        return ""


def _needs_full(ctx: dict) -> bool:
    """The full 3-wave board fires only on a PIVOT, a STALL (many closed combos), or every Nth round if
    configured -- otherwise the fast single-pass runs. AEGIS_BOARD_FAST=0 forces the full board always."""
    if not FAST:
        return True
    ctx = ctx or {}
    if ctx.get("phase") == "pivot":
        return True
    if len(ctx.get("closed_combos") or []) >= int(os.environ.get("AEGIS_BOARD_FULL_STALL", "4")):
        return True
    every = int(os.environ.get("AEGIS_BOARD_FULL_EVERY", "0"))
    rnd = int(ctx.get("real_attempts_done", 0) or 0)
    return bool(every and rnd and rnd % every == 0)


def _fast_discuss(state: str, rnd) -> tuple:
    """HOT-PATH single pass: ONE fast, non-reasoning model proposes the next moves directly -- no separate
    critique/converge waves, no reasoning-model tail. Same move shape the loop consumes; the full board
    still runs on pivots/stalls. Offline-safe -> ([], '')."""
    sysp = (f"You are '{FAST_MODEL}', the FAST discovery board. From the STATE (oracle deltas, coverage, "
            "reach) propose UP TO 5 DISTINCT, FALSIFIABLE next-move hypotheses -- the best the current "
            "knowledge allows -- spread across the two reach directions, preferring the under-probed one. "
            "Each must differ on surface/vuln_class/mechanism/trust/expected_oracle (NO payload-only tweaks). "
            "Stay ON-TARGET/applicable to this environment. Output JSON LINES, one move per line, this shape "
            "plus verdict/confidence: " + _MOVE_SHAPE[:-1] + ',"verdict":"likely","confidence":0.0}')
    final = _parse_moves(_ask(FAST_MODEL, sysp, "STATE:\n" + state, TOK_FAST, temperature=0.5))
    for mv in final[:5]:
        mv.setdefault("verdict", "maybe")
        mv.setdefault("confidence", mv.get("raw_confidence", 0.5))
        mv["_synth"] = FAST_MODEL
        mv["_fast"] = True
    if not final:
        return [], ""
    return final[:5], _transcript(rnd, [], [], final[:5])


def discuss(context: dict) -> tuple:
    """Run one board discussion. FAST by default (single-pass); the full 3-wave (propose->critique->converge)
    fires only on pivots/stalls (see _needs_full). Returns (moves, transcript_md). moves carry verdict/
    confidence/dissent. Offline-safe: returns ([], '') if the board is unreachable / produces nothing."""
    ctx = context or {}
    rnd = ctx.get("real_attempts_done", 0)
    state = _state_block(ctx)

    # HOT PATH: single fast pass unless a pivot/stall demands the full deliberation. If the fast pass yields
    # nothing, fall through to the full board (robustness).
    if not _needs_full(ctx):
        fast, md = _fast_discuss(state, rnd)
        if fast:
            return fast, md

    # wildcard proposer when coverage is stale (many closed combos) or we are pivoting
    proposers = list(PROPOSERS)
    if PROPOSER_WILDCARD and (len(ctx.get("closed_combos") or []) >= 2 or ctx.get("phase") == "pivot") \
            and PROPOSER_WILDCARD not in proposers:
        proposers.append(PROPOSER_WILDCARD)

    # WAVE 1 -- propose (parallel + isolated)
    proposals = []
    with ThreadPoolExecutor(max_workers=max(1, len(proposers))) as ex:
        for res in ex.map(lambda mdl: _propose(mdl, state), proposers):
            proposals.extend(res or [])
    if not proposals:
        return [], ""
    # EARLY-STOP: only one idea on the table -> skip critique, converge trivially
    if len(proposals) <= 1:
        final = [dict(proposals[0], verdict=proposals[0].get("verdict", "maybe"),
                      confidence=proposals[0].get("raw_confidence", 0.5))]
        md = _transcript(rnd, proposals, [], final)
        return final, md

    # WAVE 2 -- critique (rotating red-team, parallel)
    seed = int(rnd)
    challengers, seen = [], set()
    for k in range(len(CHALLENGER_POOL)):
        c = CHALLENGER_POOL[(seed + k) % len(CHALLENGER_POOL)]
        if c not in seen:
            seen.add(c); challengers.append(c)
        if len(challengers) >= N_CHALLENGERS:
            break
    critiques = []
    with ThreadPoolExecutor(max_workers=max(1, len(challengers))) as ex:
        for res in ex.map(lambda mdl: _critique(mdl, state, proposals), challengers):
            critiques.extend(res or [])

    # WAVE 3 -- (rebut, optional/off) then WAVE 4 -- converge
    final = _converge(state, proposals, critiques)
    if not final:                                        # synth failed -> use proposals as maybe-moves
        final = [dict(p, verdict="maybe", confidence=p.get("raw_confidence", 0.4)) for p in proposals[:5]]
    md = _transcript(rnd, proposals, critiques, final)
    return final, md


def board_discuss(context: dict) -> list:
    """Drop-in for board_brainstorm: runs the interactive discussion, writes the transcript to the board
    dir (for live_board.ps1), and returns the ranked hypothesis moves. [] on any failure (caller falls
    back to the single-pass brainstorm)."""
    if not enabled():
        return []
    try:
        moves, md = discuss(context)
    except Exception:
        return []
    if md:
        _write_transcript(md, (context or {}).get("real_attempts_done", 0))
    return moves


# --- verdict -> priority rank, used by the loop as a LATE tie-breaker (breadth/novelty still dominate) -
def verdict_rank(move) -> int:
    v = str((move or {}).get("verdict", "maybe")).lower() if isinstance(move, dict) else "maybe"
    return {"will-work": 0, "likely": 1, "maybe": 2, "likely-fail": 3}.get(v, 2)
