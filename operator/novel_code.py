#!/usr/bin/env python3
"""
novel_code.py -- the NOVEL-CODE WRITER for the reach axis (the board's converged design):

    board proposes an APPROACH + DIRECTION  ->  the novel-code writer WRITES the probe (code bench)
    ->  it is TRIED against the contained mirror (vectors.probe)  ->  PROVEN or DISCARDED (oracle)
    ->  if proven, WRITTEN BACK to the learned techniques RAG (techniques_from_findings).

`make_code_writer()` returns a `code_writer(move, context) -> move` callable to hand IterativeHunt via
`code_writer=`. When the board asks for custom code to open a foothold/bridge (move['needs_code'] or a
new_code brief with no runnable code), the loop calls this: it takes the board's DIRECTION + APPROACH,
fans the brief out to the code bench (code_suggester -- qwen2.5-coder / DeepSeek / ...), has the
analyst rank them, parses the best runnable TARGET/CODE/ORACLE, guards it NON-DESTRUCTIVE, and stamps
`move['code']` + `move['oracle']` + action='probe' so vectors.probe can run + verify it.

The write is TIED TO THE TWO LEVELS: a 'scaffold' brief asks for a probe against the STACK + installed
modules only (framework/deps/runtime/container/config); a 'code' brief asks for a probe against the
app's ACTUAL code on that stack.

Offline-safe + injectable: any failure (no keys, bench unreachable, nothing parseable) returns the move
UNCHANGED, so it simply runs as an ordinary move and the oracle judges it. Tests can inject their own
writer (e.g. constant_code_writer) instead of calling the LLM bench.
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

try:
    import reach as _reach
except Exception:
    _reach = None


def _direction(move) -> str:
    if _reach is not None:
        try:
            return _reach.direction_of(move)
        except Exception:
            pass
    return str((move or {}).get("layer") or "code").lower()


# WHO WRITES THE PROBE (the board's converged decision, ds + kimi):
#   * PRIMARY = deepseek-v4-pro ("ds") -- the STRONGER, NON-reasoning coder (returns final code fast +
#     reliably in-loop; no reasoning_content burn), and the DS<->Qwen convergence anchor.
#   * FALLBACK ORDER (if the primary is unavailable): qwen2.5-coder-32b -> llama-4-scout -> llama-3.3-70b.
#     Reasoning coders (r1-distill, kimi) are DISQUALIFIED for in-loop use (the empty-output gotcha) --
#     reachable only via an explicit AEGIS_NOVEL_CODE_MODELS list (with thinking disabled / a big budget).
#   * NO direction/intent split -- one writer handles scaffold+code and foothold+bridge (unanimous).
#   * OPT-IN ENSEMBLE (AEGIS_NOVEL_CODE_ENSEMBLE=1): run DS + qwen in parallel and let the qwq-32b
#     analyst pick, preferring their agreement -- the repo's DS<->Qwen convergence-trust signal, for
#     high-value bridges where the extra round-trip is worth it.
PRIMARY_WRITER = "ds"
FALLBACK_ORDER = ["ds", "qwen2.5-coder-32b", "llama-4-scout", "llama-3.3-70b"]
ENSEMBLE_MODELS = ["ds", "qwen2.5-coder-32b"]


def _fallback_order():
    v = (os.environ.get("AEGIS_NOVEL_CODE_MODELS") or "").strip()
    if v.lower() == "all":
        try:
            import code_suggester as CS
            return list(CS.CODE_SUGGESTERS)
        except Exception:
            return list(FALLBACK_ORDER)
    if v:
        return [m.strip() for m in v.split(",") if m.strip()]
    return list(FALLBACK_ORDER)


def _ensemble_on():
    return str(os.environ.get("AEGIS_NOVEL_CODE_ENSEMBLE", "0")).lower() in ("1", "true", "yes", "on")


def _brief(move, context) -> str:
    """Build the code-bench prompt from the board's move -- tied to the DIRECTION (scaffold vs code)."""
    layer = _direction(move)
    intent = str(move.get("intent") or "foothold")
    goal = str(move.get("new_code") or move.get("why_novel") or move.get("technique") or "custom probe")
    surface = move.get("surface") or move.get("path") or move.get("target") or "/"
    pintel = (context or {}).get("planner_intel") or {}
    stack = pintel.get("target_stack") if isinstance(pintel, dict) else None
    layer_desc = ("the STACK + INSTALLED MODULES ONLY -- framework / dependencies / runtime / "
                  "container / server / config, AS IF NO APP CODE WERE PRESENT"
                  if layer == "scaffold" else
                  "the app's ACTUAL CODE running on the stack")
    parts = [
        "AUTHORIZED, CONTAINED mirror assessment. The discovery board proposes the approach below and "
        "asks you to WRITE the probe. The paramount question is HOW FAR CAN I GO here, "
        "non-destructively, WITHOUT damaging the system.",
        f"DIRECTION: '{layer}' -- {layer_desc}.",
        f"INTENT: establish a {intent}"
        + (f" and BRIDGE to {move['bridge_to']}" if move.get("bridge_to") else "") + ".",
        f"GOAL / APPROACH (from the board): {goal}.",
        f"TARGET SURFACE: {surface}.",
    ]
    if move.get("expected_oracle"):
        parts.append(f"EXPECTED OBSERVABLE: {move['expected_oracle']}.")
    if stack:
        parts.append("TARGET STACK: " + json.dumps(stack)[:400] + ".")
    parts.append(
        "Emit EXACTLY ONE runnable suggestion in TARGET / CODE / ORACLE form. CODE = a single curl "
        "command against the mirror base URL, OR a short self-contained python3 snippet. ORACLE = an "
        "INDEPENDENT observable that PROVES the foothold/bridge (an HTTP status/body assertion, or a "
        "SQL SELECT returning proof) -- NOT a self-printed 'SUCCESS'. STRICTLY NON-DESTRUCTIVE: "
        "plant/read for proof, NEVER erase/drop/delete/truncate.")
    return "\n".join(parts)


def _runnable(code: str) -> bool:
    c = (code or "").lower()
    return ("curl" in c or "http" in c or "import " in c or "print(" in c or "requests." in c)


_BOILERPLATE = re.compile(
    r"copy-?pasteable payload/snippet ready to run"
    r"|the exact check that proves success or failure"
    r"|precise surface:\s*http method"
    r"|a psql query, an http status/body assertion"
    r"|assume https?://\S+ with -k", re.I)


def _is_boilerplate(text: str) -> bool:
    """True if the 'code'/'oracle' is the ROLE-PROMPT TEMPLATE text echoed back by the model, not a
    real probe. Such moves MUST be discarded: the template's own example `curl ... /` otherwise replays
    against the SPA root and self-verifies on a bare 200 (observed FP: T1590/T1069 marked HIGH)."""
    return bool(_BOILERPLATE.search(text or ""))


# A writer must ACTUALLY COMPLETE the task. A model that trips a content-safety switch / refuses /
# hedges (and produces no runnable code) is a FAILED write -- the writer falls through to the next
# model. Content-gated models (Sol/GPT) and empty-output reasoning coders (kimi/r1-distill) are already
# kept out of the default path; this guard catches a refusal from any model so the loop still gets code.
_REFUSAL = re.compile(
    r"\b(i\s*(?:can'?t|cannot|can not|won'?t|am\s+unable|am\s+not\s+able)\s+(?:help|assist|provide|"
    r"create|write|generate|produce)|i'?m\s+sorry[, ]|as\s+an\s+ai\b|against\s+(?:my\s+)?(?:policy|"
    r"policies|guidelines)|violat\w*\s+(?:policy|guidelines)|cannot\s+comply|must\s+decline|"
    r"i\s+will\s+not|not\s+appropriate\b|ethic\w*\s+(?:concerns?|guidelines)|refuse\b)", re.I)


def _refused(text: str) -> bool:
    """True if the model refused / tripped a safety switch and did NOT complete the write (no runnable
    code). If it hedged but still emitted runnable code, that's a completed write -- not a refusal."""
    t = (text or "").strip()
    if not t or t.startswith("[error]") or t.startswith("[raw reasoning"):
        return True
    return bool(_REFUSAL.search(t[:800])) and not _runnable(t)


def _pick_best(outs: dict, analyst: bool):
    """Parse the bench outputs into TARGET/CODE/ORACLE; keep guard-passing, runnable ones; return the
    best. If the analyst is on, prefer the model it names first; else preference-order the coders."""
    try:
        import test_suggestions as TS
    except Exception:
        return None
    cands = []                                       # [(model, {target,code,oracle})]
    for model, text in (outs or {}).items():
        if _refused(text):                           # skip refusals / safety-trips / non-completions
            continue
        try:
            for sug in TS.parse(text):
                code = sug.get("code") or ""
                if not _runnable(code):
                    continue
                if _is_boilerplate(code) or _is_boilerplate(sug.get("oracle") or ""):
                    continue                          # role-prompt template echoed back -- not a real probe
                ok, _ = TS.guard(code)               # never carry destructive code forward
                if ok:
                    cands.append((model, sug))
        except Exception:
            continue
    if not cands:
        return None
    order = None
    if analyst:
        try:
            import code_suggester as CS
            review = CS.review_suggestions(outs) or ""
            # crude but effective: the first model name the analyst mentions is its top pick
            low = review.lower()
            order = sorted({m for m, _ in cands},
                           key=lambda m: (low.find(m.lower()) if low.find(m.lower()) >= 0 else 10 ** 6))
        except Exception:
            order = None
    if order:
        rank = {m: i for i, m in enumerate(order)}
        cands.sort(key=lambda mc: rank.get(mc[0], 10 ** 6))
    model, sug = cands[0]
    return {"model": model, "code": sug.get("code", ""), "oracle": sug.get("oracle", ""),
            "target": sug.get("target", ""), "n_candidates": len(cands)}


def _one(model, brief, max_tokens):
    """Ask ONE coder for a probe; parse the best runnable, guard-passing TARGET/CODE/ORACLE. Returns a
    best-dict or None."""
    try:
        import code_suggester as CS
        import test_suggestions as TS
    except Exception:
        return None
    try:
        text = CS.suggest(model, brief, max_tokens=max_tokens)
    except Exception:
        return None
    if _refused(text):                               # refused / tripped safety / no completion -> fall through
        return None
    try:
        for sug in TS.parse(text):
            code = sug.get("code") or ""
            if _is_boilerplate(code) or _is_boilerplate(sug.get("oracle") or ""):
                continue                              # role-prompt template echoed back -- not a real probe
            if _runnable(code) and TS.guard(code)[0]:
                return {"model": model, "code": code, "oracle": sug.get("oracle", ""),
                        "target": sug.get("target", "")}
    except Exception:
        return None
    return None


def _stamp(move, best, via, bench=None):
    out = dict(move)
    out["action"] = "probe"
    out["code"] = best["code"]
    out["oracle"] = best.get("oracle") or move.get("expected_oracle") or ""
    out["code_by"] = best.get("model")
    prov = {**(move.get("provenance") or {}), "code_by": best.get("model"), "via": via,
            "layer": _direction(move), "intent": move.get("intent") or "foothold"}
    if bench:
        prov["bench_models"] = list(bench)
    out["provenance"] = prov
    return out


def make_code_writer(models=None, analyst=None, max_tokens=1400):
    """Return a code_writer(move, context) -> move for IterativeHunt(code_writer=...). The board's
    converged design: a SINGLE primary writer (deepseek-v4-pro) with an ordered FALLBACK, or -- when
    AEGIS_NOVEL_CODE_ENSEMBLE=1 -- a DS+Qwen ensemble picked by the qwq-32b analyst (convergence-trust).
    Stamps the best runnable, NON-DESTRUCTIVE probe onto the move (action='probe'). Offline-safe: on any
    failure the move is returned unchanged (it runs as an ordinary move and the oracle judges it)."""
    ensemble = _ensemble_on()

    def code_writer(move, context=None):
        if not isinstance(move, dict):
            return move
        brief = _brief(move, context)
        if ensemble:                                  # DS+Qwen fan-out + analyst pick (opt-in)
            try:
                import code_suggester as CS
                outs = CS.suggest_all(brief, max_tokens=max_tokens, models=models or ENSEMBLE_MODELS)
                best = _pick_best(outs, True if analyst is None else analyst)
                if best and best.get("code"):
                    return _stamp(move, best, "novel_code:ensemble", bench=list(outs))
            except Exception:
                pass
            return move
        # single primary + ordered fallback: first coder to yield runnable guarded code wins
        for model in (models or _fallback_order()):
            best = _one(model, brief, max_tokens)
            if best and best.get("code"):
                return _stamp(move, best, "novel_code")
        return move
    return code_writer


def constant_code_writer(code: str, oracle: str = "", model: str = "stub"):
    """A deterministic writer (tests / offline demos): always stamps the given code/oracle onto a move
    that needs code. No LLM. Mirrors make_code_writer's output contract."""
    def code_writer(move, context=None):
        if not isinstance(move, dict):
            return move
        wants = bool(move.get("needs_code")) or (bool(move.get("new_code")) and not move.get("code"))
        if not wants:
            return move
        out = dict(move, action="probe", code=code,
                   oracle=oracle or move.get("expected_oracle") or "", code_by=model)
        out["provenance"] = {**(move.get("provenance") or {}), "code_by": model, "via": "novel_code:stub",
                             "layer": _direction(move), "intent": move.get("intent") or "foothold"}
        return out
    return code_writer
