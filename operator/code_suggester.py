#!/usr/bin/env python3
"""
code_suggester.py -- get code-flavoured, TESTABLE suggestions from a model.

BOTH qwen2.5-coder AND DeepSeek are first-class exploit-code suggesters here, using the SAME baked
role (cf_agent.CODE_FLAVOURED_ROLE) so each returns runnable TARGET/CODE/ORACLE blocks -- neither is
ignored. Output is designed to feed straight into test_suggestions.py (the co-pilot then runs each
suggestion against the target and confirms/refutes it).

Usage:
    python code_suggester.py qwen "test the invoice money endpoints for out-of-range values"
    python code_suggester.py ds   "..."            # DeepSeek, same code-flavoured role
    python code_suggester.py qwen "..." --out sugg_qwen.md
"""
import os, sys, json, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cf_agent
from cf_agent import CODE_FLAVOURED_ROLE   # the single source of the code-suggester role


def _load_secret_env():
    p = os.path.join(HERE, "secret.env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1); k = k.strip()
                if not os.environ.get(k):   # set if missing OR inherited-empty (setdefault kept "" )
                    os.environ[k] = v.strip().strip('"').strip("'")


def _deepseek(user: str, max_tokens: int, temperature: float) -> str:
    """DeepSeek (direct, OpenAI-compatible) with the SAME code-flavoured role qwen uses."""
    _load_secret_env()
    key = (os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
          )
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or os.environ.get("DEEPSEEK_ENDPOINT")
          or "https://api.deepseek.com").rstrip("/")
    # code suggestions use the STRONGER deepseek-v4-pro by default (AEGIS_CODE_MODEL overrides);
    # the board chat can stay on flash for budget -- this path is separate.
    model = (os.environ.get("AEGIS_CODE_MODEL") or "deepseek-v4-pro")
    if not key:
        return "[error] no DeepSeek key (set AEGIS_LLM_API_KEY in secret.env)"
    body = json.dumps({"model": model,
                       "messages": [{"role": "system", "content": CODE_FLAVOURED_ROLE},
                                    {"role": "user", "content": user}],
                       "max_tokens": max_tokens, "temperature": temperature}).encode()
    req = urllib.request.Request(ep + "/chat/completions", data=body, method="POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=180))
    m = (r.get("choices") or [{}])[0].get("message", {})
    _content = (m.get("content") or "").strip()
    if _content:
        return _content
    # No final answer (e.g. a thinking model ran out of budget mid-reasoning). Surface the
    # reasoning but LABEL it, so raw chain-of-thought is never mistaken for a clean answer.
    _reasoning = (m.get("reasoning_content") or "").strip()
    return ("[raw reasoning, no final content] " + _reasoning) if _reasoning else ""


_DS_NAMES = {"ds", "deepseek", "deepseek-direct", "deepseek-v4-pro", "deepseek-v4-flash"}
_QWEN_NAMES = {"qwen", "qwen-coder", "qwen2.5-coder", "qwen2.5-coder-32b"}

# The code-generation bench = the two models that actually write good testable code here:
# qwen2.5-coder-32b (CF coder) + DeepSeek (v4-pro). gpt-oss-120b/20b were dropped from CODE-WRITING
# (thin/noisy at code-writing in our comparison) but REMAIN board contributors (always_include) for input/strategy.
# The code bench: qwen2.5-coder + DeepSeek-v4-pro (direct) + KIMI-2.7-code + Llama-3.3-70b (all CF paid
# ones skip gracefully if the plan/token isn't set). NB reasoning coders (kimi) need a larger token
# budget or they spend it all on reasoning_content and return no final code -- see suggest_all default.
CODE_SUGGESTERS = ["qwen2.5-coder-32b", "ds", "kimi-k2.7-code", "llama-3.3-70b",
                   "llama-4-scout", "deepseek-r1-distill-32b"]  # +Llama-4-Scout & R1-distill (bake-off winners)


def suggest(model: str, user: str, max_tokens: int = 1600, temperature: float = 0.4) -> str:
    """Return code-flavoured TARGET/CODE/ORACLE suggestions from DeepSeek or any CF model.
    The code role is applied to EVERY model (qwen auto-injects it; the rest get it as the system),
    so any CF coder called directly also emits runnable code, not prose."""
    m = model.lower()
    if m in _DS_NAMES:
        return _deepseek(user, max_tokens, temperature)
    friendly = "qwen2.5-coder-32b" if m in _QWEN_NAMES else model
    # pass the code role as the system so gpt-oss etc. also produce TARGET/CODE/ORACLE
    return cf_agent.ask(friendly, CODE_FLAVOURED_ROLE, user,
                        max_tokens=max_tokens, temperature=temperature)


def suggest_all(user: str, max_tokens: int = 1600, models=None, max_workers: int = None) -> dict:
    """Fan out to the code bench IN PARALLEL (bounded thread pool). Returns {model: suggestions}. Each
    model's output feeds test_suggestions.py (--source <model>). Workers default to
    AEGIS_BENCH_WORKERS or 6 -- enough to overlap the slow calls without tripping the CF rate limit."""
    from concurrent.futures import ThreadPoolExecutor
    models = list(models or CODE_SUGGESTERS)
    workers = max_workers or int(os.environ.get("AEGIS_BENCH_WORKERS", "6"))

    def one(m):
        try:
            return m, suggest(m, user, max_tokens)
        except Exception as e:
            return m, f"[error] {type(e).__name__}: {e}"
    out = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(models)))) as ex:
        for m, r in ex.map(one, models):     # ex.map preserves order; collected in the main thread
            out[m] = r
    return out


# The board's ANALYST/VERIFIER model -- a second opinion AFTER the coders propose, BEFORE the oracle
# runs. Reasoning-heavy (qwq-32b); override with AEGIS_ANALYST_MODEL.
ANALYST_MODEL = os.environ.get("AEGIS_ANALYST_MODEL", "qwq-32b")


def review_suggestions(suggestions: dict, analyst: str = None, max_tokens: int = 2200) -> str:
    """Board function: after the code bench proposes suggestions, an ANALYST/VERIFIER reviews them as a
    second opinion -- is each CODE correct/likely to work? does the ORACLE actually PROVE the claim (no
    false positive)? is it NON-DESTRUCTIVE (plant/read only, never erase/drop)? -- flags the bad ones
    and RANKS the rest best-first for execution. This is advisory triage; the deterministic oracle in
    test_suggestions.py remains the actual gate. Returns the analyst's review text ('' if unavailable).
    """
    import cf_agent
    analyst = analyst or ANALYST_MODEL
    blob = "\n\n".join(f"### Suggestion from {m}:\n{(s or '').strip()}"
                       for m, s in suggestions.items() if s and s.strip() and not s.startswith("[error]"))
    if not blob.strip():
        return "(no suggestions to review)"
    sysp = ("You are the board's ANALYST/VERIFIER on an AUTHORIZED contained mirror. The code bench has "
            "proposed the exploit-code suggestions below. For EACH, judge concisely: (1) is the CODE "
            "correct and likely to actually work? (2) does its ORACLE truly PROVE the claim, or could it "
            "false-positive? (3) is it strictly NON-DESTRUCTIVE (plant/read for proof, never "
            "erase/drop/delete)? Flag any that are wrong, unsafe, or prove nothing. Then RANK the "
            "viable ones best-first for execution, with a one-line reason each. Be concrete and terse.")
    return cf_agent.ask(analyst, sysp, blob, max_tokens=max_tokens) or ""


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("model", help="ds | qwen | gpt-oss-120b | gpt-oss-20b | <cf name> | all")
    ap.add_argument("prompt")
    ap.add_argument("--max-tokens", type=int, default=1200)
    ap.add_argument("--out", help="write the suggestions to this file (single model)")
    ap.add_argument("--out-dir", help="with model=all: write one <model>.md per suggester here")
    ap.add_argument("--review", action="store_true",
                    help="with model=all: after the bench, have the ANALYST/VERIFIER review + rank the suggestions")
    a = ap.parse_args()
    if a.model.lower() == "all":
        outs = suggest_all(a.prompt, a.max_tokens)
        d = a.out_dir or os.path.join(HERE, "suggestions")
        os.makedirs(d, exist_ok=True)
        for m, txt in outs.items():
            fn = os.path.join(d, f"{m.replace('/', '_')}.md")
            open(fn, "w", encoding="utf-8").write(txt)
            print(f"  {m:20s} -> {len(txt):5d}b  {fn}")
        if a.review:
            print(f"\n=== ANALYST/VERIFIER review ({ANALYST_MODEL}) ===")
            rev = review_suggestions(outs)
            open(os.path.join(d, "_analyst_review.md"), "w", encoding="utf-8").write(rev)
            print(rev[:1200] + ("..." if len(rev) > 1200 else ""))
        print(f"\nnow test each:  for src in {' '.join(outs)}; do "
              f"python test_suggestions.py --file {d}/<src>.md --source $src --execute; done")
    else:
        out = suggest(a.model, a.prompt, a.max_tokens)
        if a.out:
            open(a.out, "w", encoding="utf-8").write(out); print(f"wrote {len(out)}b -> {a.out}")
        else:
            print(out)
