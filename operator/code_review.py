#!/usr/bin/env python3
"""
code_review.py -- THE BOARD CODE-REVIEW round (periodic self-review of the Aegis codebase).

Once the system has SETTLED, the same multi-model board that hunts vulns is asked to review the stack's
OWN source and suggest improvements -- exactly like the stage-10 remediation round, but the subject is
our code, not the mirror's. The CODE members (qwen2.5-coder-32b, DeepSeek-v4-pro, kimi-k2.7-code,
llama-3.3-70b) each review the source and emit structured suggestions; the CONSULTANT/ANALYST (qwq-32b)
then consolidates them -- dedups, ranks by severity x consensus, and writes a prioritized improvement
plan. Attribution is preserved (who raised what). Run it from time to time, not every run.

Reuses the existing board plumbing (code_suggester + cf_agent). Board data-hygiene: secret-looking lines
are REDACTED before any file is shown to a model. Reviews our OWN repo only -- read-only, writes a report,
changes nothing.

Usage:
    python code_review.py                                  # review the core engine, all coders + consultant
    python code_review.py --paths operator shared rag redteam exploitgym
    python code_review.py --include .py .ps1 --md          # include PowerShell + markdown docs
    python code_review.py --models qwen2.5-coder-32b ds    # a subset of reviewers
    python code_review.py --max-bundles 4 --no-consultant --out review.md
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)                       # operator/ -> repo root
sys.path.insert(0, HERE)

import cf_agent
import code_suggester
from code_suggester import CODE_SUGGESTERS, ANALYST_MODEL, _load_secret_env

# ---- what to review ---------------------------------------------------------------------------------
DEFAULT_PATHS = ["operator", "shared", "rag", "redteam", "exploitgym", "orchestrator"]
EXCLUDE_DIRS = {".git", "__pycache__", "backups", "node_modules", ".venv", "venv", ".pytest_cache",
                ".idea", ".mypy_cache", "suggestions", "remediation_fixes", "hunt_findings", "dist"}
# never show these to a model (secrets / large generated data / binaries)
EXCLUDE_GLOBS = [
    r"secret\.env.*", r"set-env\.local.*", r".*\.ovpn$", r"wg.*\.conf$", r".*wireguard.*\.conf$",
    r"vpn-auth.*", r".*\.sqlite$", r".*\.db$", r"mitre_attack\.json$", r"learned_.*\.json$",
    r"ragl\.sqlite.*", r".*\.min\.js$", r".*\.lock$", r".*\.png$", r".*\.jpg$", r".*\.gif$",
    r".*\.pyc$", r".*\.bak(-.*)?$", r".*\.tmp$",
]
# lines that look like a secret get redacted before review (defence in depth vs. the .env excludes)
_SECRET_LINE = re.compile(
    r'(?i)(api[_-]?key|secret|token|password|passwd|bearer|authorization|cf_api_token|'
    r'deepseek_api_key|aegis_llm_api_key|private[_-]?key)\s*[:=]\s*.+')
_SECRET_BLOB = re.compile(r'(?i)(cfut_[a-z0-9]+|sk-[a-z0-9]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)')

REVIEW_ROLE = (
    "You are a SENIOR software reviewer on the Aegis board (Python-heavy security-research + AI-operator "
    "stack: an LLM operator co-pilot, an autonomous-exploitation benchmark, an oracle-verified findings "
    "ledger, an offline vuln RAG, and a multi-model board). You are reviewing the stack's OWN source for "
    "IMPROVEMENTS -- correctness bugs, security/robustness of the tool itself, error handling, resource "
    "leaks, concurrency/locking, API misuse, dead code, duplication, readability, and MISSING TEST "
    "COVERAGE. You are NOT writing exploits and NOT reviewing a target -- the subject is our own code. "
    "Be concrete and cite the file + a line/symbol. Do not invent files you were not shown.\n\n"
    "OUTPUT: one JSON object PER suggestion, one per line (JSONL), NOTHING else -- no prose, no fences. "
    "Schema: "
    '{"file":"<path as shown>","line":<int or 0>,"area":'
    '"correctness|security|robustness|performance|readability|duplication|design|test-coverage",'
    '"severity":"high|med|low","effort":"S|M|L","suggestion":"<what to change, one sentence>",'
    '"rationale":"<why it matters / failure mode>"}. '
    "Prefer a few HIGH-signal findings over many trivial ones. If a file is clean, emit nothing for it."
)

CONSULTANT_ROLE = (
    "You are the board's CONSULTANT/ANALYST (a reasoning model). The code bench has independently "
    "reviewed the Aegis codebase and produced the raw suggestions below (each tagged with the model that "
    "raised it). CONSOLIDATE them into an actionable improvement plan: (1) DEDUPLICATE near-identical "
    "findings, noting CONSENSUS (how many distinct models raised each); (2) RANK by severity x consensus x "
    "blast-radius; (3) drop anything speculative or that fights the project's doctrine (contained/mirror-"
    "only, non-destructive, offline-safe, generic-only public repo); (4) group into THEMES. "
    "Output MARKDOWN: a short '## Themes' overview, then '## Prioritized improvements' as a numbered list, "
    "each item: **[severity/effort] file -- change** (models: X, Y) followed by a one-line why. Be decisive "
    "and specific; this plan will be handed to the code writer/improver."
)


# ---- file collection + hygiene ----------------------------------------------------------------------
def _excluded(rel: str) -> bool:
    base = os.path.basename(rel)
    return any(re.fullmatch(g, base) for g in EXCLUDE_GLOBS)


def _scrub(text: str) -> str:
    """Redact secret-looking lines/blobs before any model sees the file (board data-hygiene)."""
    out = []
    for ln in text.splitlines():
        if _SECRET_LINE.match(ln.strip()):
            key = ln.split("=", 1)[0] if "=" in ln else ln.split(":", 1)[0]
            out.append(f"{key}= <redacted>")
        else:
            out.append(_SECRET_BLOB.sub("<redacted>", ln))
    return "\n".join(out)


def collect_files(paths, includes, root=REPO) -> list:
    """-> [(relpath, scrubbed_text, nlines)] for every included, non-excluded source file."""
    files = []
    for p in paths:
        ap = os.path.join(root, p)
        if os.path.isfile(ap):
            walk = [(os.path.dirname(ap), [], [os.path.basename(ap)])]
        else:
            walk = os.walk(ap)
        for dirpath, dirnames, filenames in walk:
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
            for fn in sorted(filenames):
                if not any(fn.endswith(ext) for ext in includes):
                    continue
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, root).replace("\\", "/")
                if _excluded(rel):
                    continue
                try:
                    txt = open(full, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                if not txt.strip():
                    continue
                files.append((rel, _scrub(txt), txt.count("\n") + 1))
    # de-dup by relpath (a path can be reached twice) and sort for stable bundling
    seen = {}
    for rel, txt, n in files:
        seen[rel] = (rel, txt, n)
    return sorted(seen.values(), key=lambda t: t[0])


def bundle_files(files, max_chars=16000) -> list:
    """Pack files into review bundles <= max_chars, each a concatenation with '### FILE:' headers. A
    single file larger than the budget is split into parts so nothing is silently dropped."""
    bundles, cur, cur_len = [], [], 0

    def flush():
        nonlocal cur, cur_len
        if cur:
            bundles.append("\n".join(cur)); cur, cur_len = [], 0

    for rel, txt, n in files:
        header = f"### FILE: {rel} ({n} lines)\n"
        block = header + txt + "\n"
        if len(block) <= max_chars:
            if cur_len + len(block) > max_chars:
                flush()
            cur.append(block); cur_len += len(block)
        else:                                      # oversize file -> split into parts
            flush()
            lines, part, plen, idx = txt.splitlines(keepends=True), [], 0, 1
            for ln in lines:
                if plen + len(ln) > max_chars - len(header) - 40 and part:
                    bundles.append(f"### FILE: {rel} (part {idx}, {n} lines total)\n" + "".join(part))
                    part, plen, idx = [], 0, idx + 1
                part.append(ln); plen += len(ln)
            if part:
                bundles.append(f"### FILE: {rel} (part {idx}, {n} lines total)\n" + "".join(part))
    flush()
    return bundles


# ---- model calls ------------------------------------------------------------------------------------
def _deepseek_review(system: str, user: str, max_tokens: int, temperature: float) -> str:
    """DeepSeek (direct, OpenAI-compatible) with the REVIEW system prompt (NOT the exploit-code role)."""
    import urllib.request
    _load_secret_env()
    key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        return "[error] no DeepSeek key (set AEGIS_LLM_API_KEY in secret.env)"
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or os.environ.get("DEEPSEEK_ENDPOINT")
          or "https://api.deepseek.com").rstrip("/")
    model = os.environ.get("AEGIS_CODE_MODEL") or "deepseek-v4-pro"
    # DeepSeek pro/flash are THINKING models by default; left on, the chain-of-thought outruns the
    # token budget and `content` comes back empty (raw reasoning instead of JSONL). Disable it for
    # this answer-only review path -- pro stays high-quality, just non-verbose (faster + cheaper).
    body = json.dumps({"model": model,
                       "messages": [{"role": "system", "content": system},
                                    {"role": "user", "content": user}],
                       "thinking": {"type": "disabled"},
                       "max_tokens": max_tokens, "temperature": temperature}).encode()
    req = urllib.request.Request(ep + "/chat/completions", data=body, method="POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        r = json.load(urllib.request.urlopen(req, timeout=180))
    except Exception as e:
        return f"[error] {type(e).__name__}: {str(e)[:140]}"
    m = (r.get("choices") or [{}])[0].get("message", {})
    return (m.get("content") or m.get("reasoning_content") or "").strip()


def _as_text(c) -> str:
    """Normalize a chat message's content to TEXT (CF auto-parses JSON replies into dict/list). Single
    source of truth lives in cf_agent._as_text; delegate so both stay in lockstep."""
    return cf_agent._as_text(c)


def _cf_review(model: str, system: str, user: str, max_tokens: int, temperature: float) -> str:
    """CF chat completion for a REVIEW (our system verbatim, no code-writer role), content normalized
    to text, 403/unavailable skipped gracefully. Kept local so the shared board path is untouched."""
    import urllib.request
    try:
        _, token = cf_agent._acct_token()
        body = json.dumps({"model": cf_agent.resolve(model),
                           "messages": [{"role": "system", "content": system},
                                        {"role": "user", "content": user}],
                           "max_tokens": max_tokens, "temperature": temperature}).encode()
        req = urllib.request.Request(cf_agent._base() + "/chat/completions", data=body, method="POST",
                                     headers={"Authorization": f"Bearer {token}",
                                              "Content-Type": "application/json"})
        r = json.load(urllib.request.urlopen(req, timeout=150))
    except Exception as e:
        return f"[error] {type(e).__name__}: {str(e)[:140]}"
    ch = (r.get("choices") or [{}])[0].get("message", {})
    txt = _as_text(ch.get("content"))
    if txt:
        return txt
    reasoning = _as_text(ch.get("reasoning_content"))
    return ("[raw reasoning, no final content] " + reasoning) if reasoning else ""


def _ask(model: str, system: str, user: str, max_tokens: int = 2400, temperature: float = 0.3) -> str:
    """Route a REVIEW call to the right backend WITHOUT the code-writer role: DeepSeek direct, else CF.
    Never raises -- returns a '[error] ...' string on failure so one bad model can't stop the round."""
    m = model.lower()
    if m in code_suggester._DS_NAMES:
        return _deepseek_review(system, user, max_tokens, temperature)
    friendly = "qwen2.5-coder-32b" if m in code_suggester._QWEN_NAMES else model
    return _cf_review(friendly, system, user, max_tokens, temperature)


def _parse_findings(text: str, model: str) -> list:
    """Liberal JSONL parse: pull one finding per '{...}' line; also accept a fenced JSON array."""
    if not text or text.startswith("[error]") or text.startswith("[raw reasoning"):
        return []
    found = []
    # try a fenced / bare JSON array first
    mobj = re.search(r"\[\s*\{.*\}\s*\]", text, re.S)
    if mobj:
        try:
            for f in json.loads(mobj.group(0)):
                if isinstance(f, dict):
                    found.append(f)
        except Exception:
            pass
    if not found:
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{") and line.endswith("}"):
                try:
                    found.append(json.loads(line))
                except Exception:
                    pass
    out = []
    for f in found:
        if not isinstance(f, dict) or not f.get("suggestion"):
            continue
        out.append({"file": str(f.get("file", "?"))[:120], "line": f.get("line", 0),
                    "area": str(f.get("area", "design"))[:20], "severity": str(f.get("severity", "low"))[:6],
                    "effort": str(f.get("effort", "M"))[:2], "suggestion": str(f.get("suggestion", ""))[:400],
                    "rationale": str(f.get("rationale", ""))[:400], "model": model})
    return out


# ---- the round --------------------------------------------------------------------------------------
_SEV_RANK = {"high": 0, "med": 1, "medium": 1, "low": 2}

# The final consolidation uses a NON-REASONING model by default (thinking disabled via _ask) so it emits
# the actual plan instead of raw chain-of-thought (qwq/r1 starved their token budget on reasoning).
CONSOLIDATOR = os.environ.get("AEGIS_CONSOLIDATOR", "ds")


def _strip_think(t: str) -> str:
    """Drop any <think>...</think> block or a leading '[raw reasoning...]' label a reasoning model leaks."""
    t = re.sub(r"<think>.*?</think>", "", t or "", flags=re.S | re.I)
    t = re.sub(r"^\s*\[raw reasoning[^\]]*\]\s*", "", t, flags=re.I)
    return t.strip()


def _dedup_findings(findings: list) -> list:
    """G-A/G-C: merge near-identical findings (same file+area+summary-gist) BEFORE consolidation, tracking
    CONSENSUS (how many distinct models raised it) and count -- so the consultant sees the whole picture
    compressed, not a 14k-char slice, and single-model self-rated 'high' is visible as low-consensus."""
    merged = {}
    for f in findings:
        gist = " ".join(re.findall(r"[a-z0-9]+", (f.get("summary") or f.get("suggestion") or "").lower())[:8])
        key = (f.get("file", "?"), f.get("area", "?"), gist)
        m = merged.get(key)
        if not m:
            merged[key] = {"file": f.get("file"), "area": f.get("area"),
                           "severity": (f.get("severity") or "low"), "suggestion": f.get("suggestion", ""),
                           "models": {f.get("model")}, "count": 1, "lines": {f.get("line")}}
        else:
            m["models"].add(f.get("model")); m["count"] += 1; m["lines"].add(f.get("line"))
            if _SEV_RANK.get((f.get("severity") or "low").lower(), 3) < _SEV_RANK.get(m["severity"].lower(), 3):
                m["severity"] = f.get("severity")
    out = []
    for m in merged.values():
        m["models"] = sorted(x for x in m["models"] if x)
        m["consensus"] = len(m["models"])
        m["lines"] = sorted(x for x in m["lines"] if x)[:5]
        out.append(m)
    out.sort(key=lambda m: (_SEV_RANK.get(m["severity"].lower(), 3), -m["consensus"], -m["count"]))
    return out


def _consolidate(uniq: list, consolidator: str = None, chunk_chars: int = 15000) -> str:
    """Map-reduce consolidation over the DEDUPED findings so every finding informs the plan (G-A). One
    pass if it fits; otherwise summarize per batch then reduce. Non-reasoning consolidator, think stripped."""
    consolidator = consolidator or CONSOLIDATOR
    lines = [f"[{u['severity']}/{u['area']}] {u['file']}:{','.join(map(str, u['lines'])) or '-'} "
             f"(x{u['count']}, {u['consensus']} model(s): {','.join(u['models'])}) {u['suggestion'][:200]}"
             for u in uniq]

    def _one(body, sysp=CONSULTANT_ROLE):
        return _strip_think(_ask(consolidator, sysp, body, max_tokens=3000, temperature=0.2))

    joined = "\n".join(lines)
    if len(joined) <= chunk_chars:
        return _one("Deduplicated board suggestions -- [sev/area] file:lines (xcount, models) suggestion:\n" + joined)
    chunks, cur, cl = [], [], 0
    for ln in lines:
        if cl + len(ln) > chunk_chars and cur:
            chunks.append("\n".join(cur)); cur, cl = [], 0
        cur.append(ln); cl += len(ln) + 1
    if cur:
        chunks.append("\n".join(cur))
    partials = []
    for i, ch in enumerate(chunks):
        p = _one(f"PARTIAL batch {i+1}/{len(chunks)} of deduplicated findings -- extract the themed, "
                 f"high-value items (keep file + severity + consensus):\n{ch}",
                 sysp="You are consolidating ONE batch of code-review findings into terse themed bullets "
                      "with file + severity + consensus. No preamble, no reasoning.")
        partials.append(f"### batch {i+1}\n{p}")
    return _one("Consolidate these per-batch summaries into ONE final prioritized plan:\n" + "\n\n".join(partials))


def run_review(paths=None, includes=(".py",), models=None, max_bundles=8, max_bundle_chars=16000,
               consultant=True, review_tokens=2400, max_workers=None) -> dict:
    from concurrent.futures import ThreadPoolExecutor
    paths = paths or DEFAULT_PATHS
    models = models or list(CODE_SUGGESTERS)
    files = collect_files(paths, list(includes))
    if not files:
        return {"error": "no source files matched", "paths": paths, "includes": list(includes)}
    bundles = bundle_files(files, max_bundle_chars)
    truncated = len(bundles) > max_bundles
    bundles = bundles[:max_bundles]

    # PARALLEL fan-out over every (model, bundle) task via a bounded pool -- the old nested loop ran all
    # models x bundles strictly sequentially (e.g. ~400 calls back-to-back). Workers default to
    # AEGIS_REVIEW_WORKERS or 6; results are collected in the MAIN thread (ex.map) so no shared-state race.
    workers = max_workers or int(os.environ.get("AEGIS_REVIEW_WORKERS", "6"))
    tasks = [(model, i, b) for model in models for i, b in enumerate(bundles)]

    def _do(task):
        model, i, b = task
        user = (f"Review this source (bundle {i+1}/{len(bundles)}). Emit JSONL suggestions per the "
                f"schema, citing the file paths shown.\n\n{b}")
        txt = _ask(model, REVIEW_ROLE, user, max_tokens=review_tokens)
        if txt.startswith("[error]") or txt.startswith("[raw reasoning") or not txt:
            return model, None, {"model": model, "bundle": i + 1, "why": (txt or "empty")[:120]}
        return model, _parse_findings(txt, model), None

    all_findings, per_model, errors = [], {m: 0 for m in models}, []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(tasks) or 1))) as ex:
        for model, fs, err in ex.map(_do, tasks):
            if err:
                errors.append(err)
            if fs:
                all_findings.extend(fs); per_model[model] += len(fs)

    # consolidation over DEDUPED findings (G-A: map-reduce, all findings inform the plan; G-B: a
    # non-reasoning consolidator so it emits the plan, not chain-of-thought; G-C: consensus-aware dedup).
    consolidated, unique = "", _dedup_findings(all_findings)
    if consultant and unique:
        consolidated = _consolidate(unique)
        if not consolidated or consolidated.startswith("[error]"):
            errors.append({"model": CONSOLIDATOR, "stage": "consolidate", "why": (consolidated or "empty")[:120]})
            consolidated = ""

    all_findings.sort(key=lambda f: (_SEV_RANK.get(f["severity"].lower(), 3), f["file"]))
    return {"files_reviewed": len(files), "bundles": len(bundles), "truncated": truncated,
            "models": models, "per_model": per_model, "findings": all_findings,
            "unique_findings": len(unique), "consolidated": consolidated,
            "consultant": CONSOLIDATOR if consultant else None,
            "errors": errors, "paths": paths, "includes": list(includes)}


def write_report(res: dict, out_path: str) -> str:
    now = datetime.datetime.now().isoformat(timespec="seconds")
    L = [f"# Aegis board code-review", "",
         f"_Generated {now} -- reviewers: {', '.join(res['models'])}"
         + (f"; consultant: {res['consultant']}" if res.get("consultant") else "") + "._", "",
         f"Reviewed **{res['files_reviewed']} files** in {res['bundles']} bundle(s) "
         f"({'TRUNCATED -- raise --max-bundles for full coverage' if res.get('truncated') else 'full pass'}); "
         f"paths: `{', '.join(res['paths'])}`. "
         f"{len(res.get('findings') or [])} raw suggestions -> {res.get('unique_findings', '?')} unique after dedup.", ""]
    if res.get("consolidated"):
        L += ["## Consultant's consolidated plan", "", res["consolidated"], "", "---", ""]
    # per-model tally
    L += ["## Suggestions by model", ""]
    for m, n in res["per_model"].items():
        L.append(f"- **{m}**: {n} suggestion(s)")
    L.append("")
    # full table, severity-first
    L += ["## All suggestions", "",
          "| sev | area | file | change | model |", "|---|---|---|---|---|"]
    for f in res["findings"]:
        loc = f["file"] + (f":{f['line']}" if f.get("line") else "")
        sug = f["suggestion"].replace("|", "\\|")
        L.append(f"| {f['severity']} | {f['area']} | `{loc}` | {sug} | {f['model']} |")
    L.append("")
    if res.get("errors"):
        L += ["## Reviewer skips / errors", ""]
        for e in res["errors"]:
            L.append(f"- {json.dumps(e, ensure_ascii=False)}")
        L.append("")
    L += ["> Board code-review is ADVISORY: suggestions are proposed, never auto-applied. Apply via the "
          "code writer/improver after human review. Doctrine unchanged (contained/mirror-only, "
          "non-destructive, generic-only public repo).", ""]
    text = "\n".join(L)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return out_path


def main():
    ap = argparse.ArgumentParser(description="Board code-review: coders review the Aegis source, the "
                                             "consultant consolidates a prioritized improvement plan.")
    ap.add_argument("--paths", nargs="*", default=None, help=f"dirs/files to review (default: {DEFAULT_PATHS})")
    ap.add_argument("--include", nargs="*", default=[".py"], help="file extensions to include (default .py)")
    ap.add_argument("--ps1", action="store_true", help="also include .ps1")
    ap.add_argument("--md", action="store_true", help="also include .md docs")
    ap.add_argument("--models", nargs="*", default=None, help=f"reviewers (default: {CODE_SUGGESTERS})")
    ap.add_argument("--max-bundles", type=int, default=8, help="cap review bundles per model (cost bound)")
    ap.add_argument("--max-bundle-chars", type=int, default=16000)
    ap.add_argument("--review-tokens", type=int, default=2400)
    ap.add_argument("--workers", type=int, default=None,
                    help="parallel model calls (default AEGIS_REVIEW_WORKERS or 6)")
    ap.add_argument("--no-consultant", action="store_true", help="skip the analyst consolidation step")
    ap.add_argument("--out", default=os.path.join(HERE, "code_review_report.md"))
    ap.add_argument("--json", action="store_true", help="also print the raw result JSON")
    a = ap.parse_args()

    includes = list(a.include)
    if a.ps1 and ".ps1" not in includes:
        includes.append(".ps1")
    if a.md and ".md" not in includes:
        includes.append(".md")

    res = run_review(a.paths, includes, a.models, a.max_bundles, a.max_bundle_chars,
                     consultant=not a.no_consultant, review_tokens=a.review_tokens, max_workers=a.workers)
    if res.get("error"):
        print(json.dumps(res, indent=2)); sys.exit(1)
    out = write_report(res, a.out)
    print(f"reviewed {res['files_reviewed']} files / {res['bundles']} bundle(s) with "
          f"{len(res['models'])} reviewer(s); {len(res['findings'])} suggestion(s) "
          f"-> {out}" + (f"  (+{res['consultant']} consolidation)" if res.get("consolidated") else ""))
    for m, n in res["per_model"].items():
        print(f"  {m}: {n}")
    if res.get("truncated"):
        print("  NOTE: coverage truncated -- raise --max-bundles for the whole codebase")
    if a.json:
        print(json.dumps(res, indent=2, default=str))


if __name__ == "__main__":
    main()
