"""cost_meter.py -- RUN COSTS: estimate the USD cost of a full 4-stage run (Planner + Operator +
ExploitGym + Red-Team). Only LLM API calls cost money; deterministic tiers + Kali tools run on owned
compute (=$0). Board-converged design (see the board answer + operator/model_prices.json):

  capture EXACT usage per call (raw, provider-native units) -> append one JSONL line to a CAMPAIGN-scoped
  append-only ledger (aggregates across the 4 SEPARATE-process stages) -> PRICE as a separate REPLAYABLE
  pass (a price-table fix re-prices history without re-running) -> report total / by-model / by-stage as a
  RANGE (low/expected/high), with n_calls + tokens visible.

Design invariants: never price at write time; never drop a call (no-usage -> chars/4, flagged estimated);
reasoning_tokens fold into completion; retries logged per attempt; robust to CF returning tokens OR neurons.
Offline-safe: every function swallows its own errors -- cost accounting must NEVER break a run.
"""
from __future__ import annotations
import json, os, time, hashlib

_HERE = os.path.dirname(os.path.abspath(__file__))
_PRICES_CACHE = None


def _prices():
    global _PRICES_CACHE
    if _PRICES_CACHE is None:
        try:
            _PRICES_CACHE = json.load(open(os.path.join(_HERE, "model_prices.json"), encoding="utf-8")).get("prices", {})
        except Exception:
            _PRICES_CACHE = {"_default": {"in": 0.40, "out": 0.60}}
    return _PRICES_CACHE


def _rate(model: str) -> dict:
    """Longest-substring match of the model id against the price table; '_default' fallback."""
    p = _prices()
    m = str(model or "").lower()
    best, blen = p.get("_default", {"in": 0.40, "out": 0.60}), -1
    for k, v in p.items():
        if k == "_default":
            continue
        if k.lower() in m and len(k) > blen:
            best, blen = v, len(k)
    return best


def ledger_path(campaign_id: str = None) -> str:
    """Campaign-scoped ledger file. AEGIS_COST_LEDGER overrides; else ledger/<campaign>.jsonl; else a
    shared default. One file per campaign keeps growth bounded + makes the 4 stages append to one place."""
    env = os.environ.get("AEGIS_COST_LEDGER")
    if env:
        return env
    cid = campaign_id or os.environ.get("AEGIS_CAMPAIGN") or "adhoc"
    d = os.path.join(_HERE, "cost_ledger")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return os.path.join(d, f"{str(cid).replace('/', '_')}.jsonl")


def _norm_usage(usage: dict) -> dict:
    """Normalize a provider usage block to a common shape, folding reasoning tokens into completion
    (most providers bill them as output) and surfacing cache buckets + CF neurons when present."""
    u = usage or {}
    pt = int(u.get("prompt_tokens") or u.get("input_tokens") or 0)
    ct = int(u.get("completion_tokens") or u.get("output_tokens") or 0)
    rt = int(u.get("reasoning_tokens") or (u.get("completion_tokens_details") or {}).get("reasoning_tokens") or 0)
    ct += rt                                              # reasoning billed as completion -> don't under-count
    details = u.get("prompt_tokens_details") or {}
    cache_hit = int(u.get("prompt_cache_hit_tokens") or details.get("cached_tokens") or 0)
    neurons = u.get("neurons")
    return {"prompt_tokens": pt, "completion_tokens": ct, "reasoning_tokens": rt,
            "cache_hit_tokens": cache_hit, "neurons": neurons}


def record(model: str, usage: dict, *, caller: str = "", provider: str = "", stage: str = None,
           campaign_id: str = None, attempt: int = 1, status: str = "ok", raw_chars: int = 0):
    """Append ONE ledger line for a call. usage = the API response's `usage` block (or None). We store the
    RAW usage verbatim (re-priceable later); priced_usd is filled by the rollup, not here. Never raises."""
    if str(os.environ.get("AEGIS_COST_METER", "1")).lower() in ("0", "false", "no", "off"):
        return
    try:
        stage = stage or os.environ.get("AEGIS_STAGE") or "operator"
        nu = _norm_usage(usage)
        est = False
        if not usage and (nu["prompt_tokens"] + nu["completion_tokens"]) == 0 and raw_chars:
            # no usage returned (e.g. streamed) -> estimate from chars, FLAG it, never count as $0
            nu["completion_tokens"] = max(1, raw_chars // 4); est = True
            status = status if status != "ok" else "no_usage_estimated"
        line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "campaign_id": campaign_id or os.environ.get("AEGIS_CAMPAIGN") or "adhoc",
                "stage": stage, "caller": caller, "provider": provider or _provider_of(model),
                "model": model, "usage": nu, "usage_unit": ("neurons" if nu.get("neurons") else "tokens"),
                "attempt": attempt, "status": status, "estimated": est, "priced_usd": None}
        path = ledger_path(campaign_id)
        blob = json.dumps(line, ensure_ascii=False) + "\n"
        with open(path, "a", encoding="utf-8") as fh:     # append is atomic enough for one-line records
            fh.write(blob)
    except Exception:
        pass                                              # cost accounting must never break a run


def _provider_of(model: str) -> str:
    m = str(model or "").lower()
    if m.startswith("@cf/") or "workers" in m:
        return "cf"
    if "gpt" in m or "o1" in m or "o3" in m:
        return "openai"
    return "deepseek"


def price_line(line: dict) -> float:
    """Price one ledger line from the CURRENT table (replayable). USD."""
    u = line.get("usage") or {}
    r = _rate(line.get("model", ""))
    pt, ct = u.get("prompt_tokens", 0), u.get("completion_tokens", 0)
    cache_hit = u.get("cache_hit_tokens", 0) or 0
    # DeepSeek cache: hit tokens priced at a fraction if the table carries an `in_cache` rate
    cache_rate = r.get("in_cache", r["in"] * 0.1)
    miss = max(0, pt - cache_hit)
    return (miss * r["in"] + cache_hit * cache_rate + ct * r["out"]) / 1e6


def rollup(campaign_id: str = None, path: str = None) -> dict:
    """Read a campaign's ledger, PRICE every line from the current table, and summarize as a RANGE.
    Returns {expected_usd, low_usd, high_usd, by_model, by_stage, n_calls, tokens, estimated_calls, ...}."""
    path = path or ledger_path(campaign_id)
    out = {"expected_usd": 0.0, "low_usd": 0.0, "high_usd": 0.0, "by_model": {}, "by_stage": {},
           "n_calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "estimated_calls": 0,
           "price_table_hash": _price_hash(), "ledger": path}
    try:
        lines = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    except Exception:
        out["note"] = "no ledger yet"; return out
    for ln in lines:
        usd = price_line(ln)
        u = ln.get("usage") or {}
        out["expected_usd"] += usd
        out["n_calls"] += 1
        out["prompt_tokens"] += u.get("prompt_tokens", 0)
        out["completion_tokens"] += u.get("completion_tokens", 0)
        if ln.get("estimated"):
            out["estimated_calls"] += 1
        out["by_model"][ln.get("model", "?")] = round(out["by_model"].get(ln.get("model", "?"), 0) + usd, 6)
        out["by_stage"][ln.get("stage", "?")] = round(out["by_stage"].get(ln.get("stage", "?"), 0) + usd, 6)
    # RANGE (board §4): prices approximate + rounds uncertain -> low = exp*0.6, high = exp*1.8
    exp = out["expected_usd"]
    out["expected_usd"] = round(exp, 4)
    out["low_usd"] = round(exp * 0.6, 4)
    out["high_usd"] = round(exp * 1.8, 4)
    out["by_model"] = {k: round(v, 4) for k, v in sorted(out["by_model"].items(), key=lambda x: -x[1])}
    out["by_stage"] = {k: round(v, 4) for k, v in out["by_stage"].items()}
    return out


def _price_hash() -> str:
    try:
        return hashlib.sha256(json.dumps(_prices(), sort_keys=True).encode()).hexdigest()[:12]
    except Exception:
        return "?"


def report_md(campaign_id: str = None, path: str = None) -> str:
    """A markdown RUN COSTS block for the report."""
    r = rollup(campaign_id, path)
    if r.get("note"):
        return "## RUN COSTS\n\n_No LLM API calls recorded (deterministic-only run, or metering off)._\n"
    lines = ["## RUN COSTS",
             "",
             f"**Estimated ~${r['expected_usd']} USD**  (range ${r['low_usd']} – ${r['high_usd']}; "
             f"prices approximate — see `model_prices.json`).",
             "",
             f"- API calls: **{r['n_calls']}**   -   prompt tokens: {r['prompt_tokens']:,}   -   "
             f"completion tokens: {r['completion_tokens']:,}"
             + (f"  |  [!] {r['estimated_calls']} call(s) had no usage (token-estimated)" if r['estimated_calls'] else ""),
             "",
             "**By stage:** " + (", ".join(f"{k} ${v}" for k, v in r["by_stage"].items()) or "—"),
             "",
             "**By model:**",
             ""]
    if r["by_model"]:
        lines += ["| model | USD |", "|---|---|"]
        lines += [f"| {k} | ${v} |" for k, v in r["by_model"].items()]
    else:
        lines.append("—")
    lines += ["",
              "_Only LLM API calls are billed; deterministic tiers + Kali tools (grype/docker/nmap) run on "
              "owned compute ($0). Token counts are exact; unit prices are estimates — the raw usage is "
              f"logged (ledger `{os.path.basename(r['ledger'])}`, price-table `{r['price_table_hash']}`) so a "
              "price fix re-prices history without re-running._"]
    return "\n".join(lines)


# ---- self-calibrating a-priori PREDICTOR (EWMA over past ledgers) ---------------------------------
def predict(campaign_globs=None, alpha: float = 0.3) -> dict:
    """Estimate a run's cost BEFORE running, from historical ledgers: EWMA of per-(stage,model) $/campaign.
    Cold start (no history) -> flagged low confidence. Returns {expected_usd, low, high, confidence, basis}."""
    import glob
    d = os.path.join(_HERE, "cost_ledger")
    files = campaign_globs or sorted(glob.glob(os.path.join(d, "*.jsonl")))
    per_campaign = []
    for f in files:
        r = rollup(path=f)
        if r.get("n_calls"):
            per_campaign.append(r["expected_usd"])
    if not per_campaign:
        return {"expected_usd": None, "confidence": "low", "basis": "no history -- run once to calibrate"}
    ewma = per_campaign[0]
    for v in per_campaign[1:]:
        ewma = alpha * v + (1 - alpha) * ewma
    return {"expected_usd": round(ewma, 4), "low_usd": round(ewma * 0.6, 4), "high_usd": round(ewma * 1.8, 4),
            "confidence": "med" if len(per_campaign) >= 3 else "low",
            "basis": f"EWMA(alpha={alpha}) over {len(per_campaign)} past campaign ledgers"}


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"
    cid = sys.argv[2] if len(sys.argv) > 2 else None
    if cmd == "report":
        print(report_md(cid))
    elif cmd == "rollup":
        print(json.dumps(rollup(cid), indent=2))
    elif cmd == "predict":
        print(json.dumps(predict(), indent=2))
    else:
        print("usage: cost_meter.py [report|rollup|predict] [campaign_id]")
