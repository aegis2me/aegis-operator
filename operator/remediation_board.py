#!/usr/bin/env python3
"""
remediation_board.py -- stage-10 REMEDIATION round on the chat board.

After the operator + ExploitGym have run against the target, this takes every VERIFIED finding
(only verified counts -- same rule as reports/scores) and, per weakness, asks the WHOLE board for a
FIX: specifically what to update on the installed framework/component side (version bump, config
change, or code-level patch) -- not how to exploit it. Every suggestion lands on the shared board,
attributed to its source model, so the panel's takes sit side by side and can be compared/merged.

Doctrine / hygiene (PIPELINE v3): advisory only, no target actions. The panel sees a SANITIZED
weakness brief -- claim type, summary, severity, surface/technique tags, and (if attributed) the
CVE/RAG fix context -- never raw secrets or credentials from the evidence. Only VERIFIED findings
are sent. Every suggestion is attributed to its source (board doctrine: attribute every finding).

The panel (roster board_roster.json -> always_include + the coder):
    ds_direct    DeepSeek -- concrete fix (v4-pro for the code/version path by default)
    sol          GPT-5.6 (QA-reframe shim; content-gated)
    gpt-oss-120b @cf strategy/breadth
    gpt-oss-20b  @cf input/strategy
    qwen         qwen2.5-coder-32b -- concrete dependency/config patch
Claude is the coordinator running this; add its take with --claude-note, and --synthesize folds the
panel into one consensus remediation per finding (deepseek-v4-pro).

Usage:
    python remediation_board.py                                   # all verified findings, full panel
    python remediation_board.py --findings path/to/findings.jsonl
    python remediation_board.py --eg-results ../exploitgym/eg_results   # fold ExploitGym verified findings
    python remediation_board.py --panel ds,sol,qwen --synthesize
    python remediation_board.py --claude-note "Upgrade express 4.17->4.21; the fix is the qs bump."
    python remediation_board.py --dry-run                         # print the briefs; don't call the panel

Watch it land live: board/live_board.ps1
"""
import os, sys, json, time, glob, re, argparse, threading, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "shared"))
import cf_agent


def _load_secret_env():
    p = os.path.join(HERE, "secret.env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1); k = k.strip()
                if not os.environ.get(k):
                    os.environ[k] = v.strip().strip('"').strip("'")


_load_secret_env()
BOARD = os.environ.get("AEGIS_BOARD_DIR", os.path.join(ROOT, "board", "board_files"))
os.makedirs(BOARD, exist_ok=True)

REMEDIATION_SYS = (
    "You are a remediation engineer on a shared board for the owner's OWN authorized, contained test. "
    "You are given a VERIFIED weakness found on the app twin. Propose the FIX -- NOT how to exploit it. "
    "Split your answer into the two audiences that own the fix:\n"
    "  ADMIN (framework/dependency/config updates -- ops owns this): name the affected component/framework "
    "and installed vs fixed version; the exact dependency/framework version bump, patch install, or config/"
    "hardening change; KEV/advisory deadlines if any.\n"
    "  CODE (source-code improvements -- the code writer/improver owns this): the code-level change that "
    "fixes root cause (name the file/module; minimal diff/snippet).\n"
    "Fill only the audience(s) that apply -- a dependency CVE is usually ADMIN-only; a novel logic flaw is "
    "usually CODE-only. Prefer the smallest change that fixes root cause; cite references (CVE/advisory/docs). "
    "Terse, actionable. Output only your remediation under those two headings."
)

# secret-ish tokens we strip from the sanitized brief before the panel sees it
_SECRET_RX = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key|token|bearer|authorization|cookie|session|"
    r"pin|ssn|private[_-]?key)\s*[:=]\s*\S+")
_LONGHEX_RX = re.compile(r"\b[A-Fa-f0-9]{24,}\b")
_JWT_RX = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")


def _scrub(text: str) -> str:
    """Board data-hygiene: redact secret-looking material from a finding brief."""
    if not text:
        return text
    text = _SECRET_RX.sub(lambda m: m.group(0).split(m.group(1))[0] + m.group(1) + "=[REDACTED]", text)
    text = _JWT_RX.sub("[REDACTED-JWT]", text)
    text = _LONGHEX_RX.sub("[REDACTED]", text)
    return text


def board(tag, who, text):
    fn = os.path.join(BOARD, f"{tag}__{who}__{int(time.time() * 1e9)}.md")
    open(fn, "w", encoding="utf-8").write(f"# {tag} from {who}\n\n" + (text or "[empty]"))
    print(f"  [{who}] {tag} ({len(text or '')}b)")


# ---------------- RAG: deterministic CVE fix context (fail-soft, optional) ----------------
_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _cves_in(f):
    """CVEs attributed to a finding: provenance.cve first, then any in the summary/evidence."""
    out, seen = [], set()
    prov = f.get("provenance") or {}
    cand = [prov.get("cve"), prov.get("rag_ref")]
    cand.append(f.get("summary", ""))
    for e in (f.get("evidence") or []):
        cand.append(e.get("detail", "") if isinstance(e, dict) else str(e))
    for c in cand:
        for m in _CVE_RX.findall(str(c or "")):
            u = m.upper()
            if u not in seen:
                seen.add(u); out.append(u)
    return out


def rag_context(cves):
    """Deterministic fix context from the offline RAG store (/opt/aegis-rag). Returns (text, data).
    Fail-soft: if the store or module is unreachable, returns ('', {}) and the panel path is used."""
    if not cves:
        return "", {}
    try:
        sys.path.insert(0, os.path.join(ROOT, "rag"))
        import rag_db, rag_query
        db_path = os.environ.get("AEGIS_RAG_DB") or rag_db.DEFAULT_DB
        if not os.path.exists(db_path):
            # never auto-create an empty store on the host; RAG lives on the Kali side (/opt/aegis-rag)
            print(f"  [rag] store not present ({db_path}); using panel-only path")
            return "", {}
        conn = rag_db.connect(db_path)
        items = rag_query.cve_lookup(conn, cves, k=len(cves))
    except Exception as e:
        print(f"  [rag] lookup unavailable ({e}); using panel-only path")
        return "", {}
    if not items:
        return "", {}
    lines, data = [], []
    for it in items:
        parts = [f"{it.get('cve_id')}"]
        if it.get("severity") or it.get("cvss_v3"):
            parts.append(f"severity={it.get('severity')}/cvss={it.get('cvss_v3')}")
        if it.get("epss") is not None:
            parts.append(f"epss={it.get('epss')}")
        if it.get("kev"):
            parts.append(f"KEV=yes(due {it.get('kev_due') or '?'})")
        if it.get("exploitdb_ids"):
            parts.append(f"exploitdb={it.get('exploitdb_ids')}")
        if it.get("url"):
            parts.append(f"advisory={it.get('url')}")
        lines.append(" | ".join(str(p) for p in parts))
        data.append({k: it.get(k) for k in ("cve_id", "severity", "cvss_v3", "epss", "kev",
                                            "kev_due", "url", "exploitdb_ids")})
    return "\n".join(lines), {"cves": data}


# ---------------- load verified findings ----------------
def _load_from_store(path):
    """Read a shared FindingStore jsonl and return its verified findings."""
    try:
        from verified_findings import FindingStore  # shared/ is on sys.path
    except Exception as e:
        print(f"[warn] could not import shared verified_findings ({e}); reading raw jsonl")
        return _load_raw_jsonl(path)
    if not os.path.exists(path):
        return []
    return FindingStore(path).verified()


def _load_raw_jsonl(path):
    """Fallback: fold record/transition events by hand (no shared module)."""
    state = {}
    if not os.path.exists(path):
        return []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("type") == "record":
            fd = e["finding"]; state[fd["finding_id"]] = fd
        elif e.get("type") == "transition" and e.get("finding_id") in state:
            state[e["finding_id"]]["status"] = e.get("status")
    return [f for f in state.values() if f.get("status") == "verified"]


def _load_from_eg(results_dir):
    """Fold ExploitGym result_*.json scorecards -> their embedded verified_findings."""
    out = []
    for p in sorted(glob.glob(os.path.join(results_dir, "result_*.json"))):
        try:
            r = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        sc = r.get("scorecard") or {}
        for vf in (sc.get("verified_findings") or []):
            if isinstance(vf, dict):
                # a finding may carry an explicit null provenance; setdefault would return None ->
                # None['scenario'] TypeError, aborting the whole EG load. Coerce to a dict first.
                prov = vf.get("provenance")
                prov = prov if isinstance(prov, dict) else {}
                prov["scenario"] = r.get("scenario")
                vf["provenance"] = prov
                out.append(vf)
    return out


def collect(args):
    findings, seen = [], set()
    sources = []  # (label, path, findings, writeback_store_path_or_None)
    if args.findings:
        sources.append(("findings", args.findings, _load_from_store(args.findings), args.findings))
    else:
        default_jsonl = os.path.join(HERE, "aegis_operator_findings.jsonl")
        sources.append(("operator", default_jsonl, _load_from_store(default_jsonl), default_jsonl))
    if args.eg_results:
        # ExploitGym findings live inside result_*.json, not a single append-only store -> read-only.
        sources.append(("exploitgym", args.eg_results, _load_from_eg(args.eg_results), None))
    for label, path, fs, wb in sources:
        print(f"[load] {label}: {len(fs)} verified <- {path}")
        for f in fs:
            fid = f.get("finding_id") or json.dumps(f, sort_keys=True)
            if fid in seen:
                continue
            seen.add(fid); f["_src_store"] = wb; findings.append(f)
    return findings


# ---------------- weakness brief (sanitized) ----------------
def brief(f):
    lines = [f"WEAKNESS: {f.get('claim_type', '?')} (severity: {f.get('severity', 'unknown')})",
             f"SUMMARY: {_scrub(f.get('summary', ''))}"]
    tags = f.get("coverage_tags") or []
    if tags:
        lines.append("SURFACE/TECHNIQUE: " + ", ".join(str(t) for t in tags))
    prov = f.get("provenance") or {}
    ctx = {k: prov[k] for k in ("model", "provider", "source", "cve", "rag_ref", "component",
                                "installed_version", "fixed_version", "scenario", "engine") if prov.get(k)}
    if ctx:
        lines.append("CONTEXT: " + ", ".join(f"{k}={v}" for k, v in ctx.items()))
    # VERSION STATUS via cpe_match.ver_cmp (correct numeric compare, not naive string): is the installed
    # component actually below the fixed version (confirmed outdated) or already patched? Offline-safe.
    iv, fv = ctx.get("installed_version"), ctx.get("fixed_version")
    if iv and fv:
        try:
            sys.path.insert(0, os.path.join(ROOT, "rag"))
            import cpe_match
            c = cpe_match.ver_cmp(str(iv), str(fv))
            lines.append(f"VERSION STATUS: installed {iv} " +
                         ("< " + str(fv) + " (CONFIRMED OUTDATED -- update applies)" if c < 0
                          else ">= " + str(fv) + " (already at/after fixed -- verify the finding)"))
        except Exception:
            pass
    ev = f.get("evidence") or []
    for e in ev[:2]:                       # show up to 2 evidence entries (e.g. crash trace + testcase/bucket)
        detail = _scrub(e.get("detail", "") if isinstance(e, dict) else str(e))
        if detail.strip():
            lines.append("EVIDENCE (redacted): " + detail[:400])
    # PRIOR ANALYSIS: some findings arrive with an upstream board interpretation the oracle recorded
    # (e.g. the FUZZER's crash triage -- root cause / exploitability / suggested fix / harness note).
    # Surface it so the code writer/improver builds on it instead of re-deriving from scratch.
    rc = f.get("oracle_receipt") or {}
    interp = rc.get("verdict") or (f.get("interpretation") or {}).get("verdict") or ""
    if interp:
        lines.append("PRIOR ANALYSIS (upstream board interpretation, redacted):\n" + _scrub(str(interp))[:900])
    return "\n".join(lines)


# ---------------- panel members ----------------
def _post_openai_style(url, key, model, sysp, usr, maxtok, openai=False, think=True):
    body = {"model": model, "messages": [{"role": "system", "content": sysp},
                                         {"role": "user", "content": usr}],
            "max_tokens": maxtok, "temperature": 0.3}
    if openai:  # GPT-5-class reasoning models reject max_tokens + custom temperature
        body["max_completion_tokens"] = body.pop("max_tokens"); body.pop("temperature", None)
    elif not think and "deepseek" in url:
        # DeepSeek pro/flash are THINKING models (thinking:{type:enabled} by default). Left on, a
        # long chain-of-thought can outrun the token budget so `content` comes back empty and the
        # return below falls back to dumping raw `reasoning_content` -- that is exactly the CoT
        # pollution seen in the code-fix/synthesis output. For those answer-only paths we disable
        # thinking: pro stays high-quality, just non-verbose, reasoning_content is empty, and
        # `content` carries the whole reply (faster + cheaper too). See ThinkingOptions on
        # api.deepseek.com; `reasoning_effort:"none"` is an equivalent toggle.
        body["thinking"] = {"type": "disabled"}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=170))
    m = (r.get("choices") or [{}])[0].get("message", {})
    try:
        import cost_meter
        cost_meter.record(model, r.get("usage"), caller="remediation",
                          provider=("openai" if openai else "deepseek"),
                          raw_chars=len((m.get("content") or m.get("reasoning_content") or "")))
    except Exception:
        pass
    content = (m.get("content") or "").strip()
    if content:
        return content
    # No final answer (e.g. thinking left on and the budget ran out mid-reasoning). Surface the
    # reasoning, but LABEL it so a raw chain-of-thought is never mistaken for a clean fix/answer.
    reasoning = (m.get("reasoning_content") or "").strip()
    return f"[no final content -- raw reasoning follows]\n{reasoning}" if reasoning else ""


def ask_ds(usr, code_model):
    key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        return None
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
    return _post_openai_style(ep + "/chat/completions", key, code_model, REMEDIATION_SYS, usr, 1400, think=False)


def ask_sol(usr):
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        return None
    rf = "You are a senior software-quality / correctness reviewer for our OWN system (authorized). "
    return _post_openai_style("https://api.openai.com/v1/chat/completions", key, "gpt-5.6",
                              rf + REMEDIATION_SYS, rf + usr, 1400, openai=True)


def ask_cf(model, usr):
    return cf_agent.ask(model, REMEDIATION_SYS, usr, max_tokens=1200)


PANEL = {
    "ds": ("ds_direct", lambda usr, cm: ask_ds(usr, cm)),
    "sol": ("sol", lambda usr, cm: ask_sol(usr)),
    "gpt-oss-120b": ("cf_gpt-oss-120b", lambda usr, cm: ask_cf("gpt-oss-120b", usr)),
    "gpt-oss-20b": ("cf_gpt-oss-20b", lambda usr, cm: ask_cf("gpt-oss-20b", usr)),
    "qwen": ("qwen2.5-coder-32b", lambda usr, cm: ask_cf("qwen2.5-coder-32b", usr)),
}
CF_ALIASES = {"cf": ["gpt-oss-120b", "gpt-oss-20b"]}


def expand_panel(spec):
    want = []
    for x in (s.strip() for s in spec.split(",")):
        if x in CF_ALIASES:
            want += CF_ALIASES[x]
        elif x in PANEL:
            want.append(x)
        elif x == "all":
            want += list(PANEL)
    seen, out = set(), []
    for w in want:
        if w not in seen:
            seen.add(w); out.append(w)
    return out


def run_finding(f, idx, total, members, code_model, use_rag=True):
    fid = (f.get("finding_id") or "")[:12]
    b = brief(f)
    cves = _cves_in(f)
    rag_txt, rag_data = rag_context(cves) if use_rag else ("", {})
    path = "known-cve" if rag_txt else ("novel" if not cves else "known-cve-no-rag")
    print(f"\n== finding {idx}/{total} [{fid}] {f.get('claim_type', '?')}  path={path} ==")
    header = (f"Finding {fid} -- remediation requested (installed-framework fix)  [path: {path}]:\n\n{b}")
    if rag_txt:
        header += f"\n\nRAG FIX CONTEXT (deterministic, from the offline vuln store):\n{rag_txt}"
    board("RMD_REQUEST", "coordinator", header)
    if path == "novel":
        guide = ("This is a NOVEL weakness discovered here -- there is NO known CVE. Design the fix from "
                 "the root cause and the affected component: name the framework/component and give the "
                 "concrete code/config change (and a version bump only if a newer release fixes the class).")
    else:
        guide = ("Ground the fix in the CVE/advisory context below. State the exact fixed version if a bump "
                 "closes it, plus any config/patch needed.")
    usr = (f"Weakness (verified) on the owner's app twin:\n\n{b}\n\n{guide}\n"
           + (f"\nRAG FIX CONTEXT:\n{rag_txt}\n" if rag_txt else "")
           + "\nGive the installed-framework-side fix.")
    suggestions = {}
    # audience: dependency/CVE fixes are for ADMINS (framework/config updates); novel logic flaws are
    # code changes for the code writer/improver. (emit-fixes always also feeds the code-writer track.)
    audience = "admin" if path.startswith("known-cve") else "code"
    f["_rem_path"] = path
    f["_audience"] = audience
    f["_rag_txt"] = rag_txt
    f["_rag_data"] = rag_data
    f["_cves"] = cves

    def run_member(key):
        who, fn = PANEL[key]
        try:
            out = fn(usr, code_model)
        except urllib.error.HTTPError as e:
            out = f"[http {e.code}] {e}"
        except Exception as e:
            out = f"[error] {e}"
        if out is None:
            print(f"  [{who}] skipped (no key)"); return
        suggestions[who] = out
        board("RMD", who, f"Finding {fid}:\n\n{out}")

    ts = [threading.Thread(target=run_member, args=(k,)) for k in members]
    for t in ts: t.start()
    for t in ts: t.join()
    return fid, b, suggestions


def synthesize(fid, weakness_brief, suggestions, code_model):
    key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
    if not key or not suggestions:
        return
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
    panel_txt = "\n\n".join(f"### {who}\n{txt}" for who, txt in suggestions.items())
    sysp = ("You are the board coordinator. Merge the panel's remediation suggestions for one weakness "
            "into ONE consensus fix on the installed-framework side. State the single recommended change "
            "(component + exact version bump / config / patch), note where the panel agreed or diverged, "
            "and list references. Terse. Output only the consensus remediation.")
    usr = f"WEAKNESS:\n{weakness_brief}\n\nPANEL SUGGESTIONS:\n{panel_txt}"
    try:
        out = _post_openai_style(ep + "/chat/completions", key, code_model, sysp, usr, 1200, think=False)
        board("RMD_CONSENSUS", "consensus", f"Finding {fid}:\n\n{out}")
        return out
    except Exception as e:
        board("RMD_CONSENSUS", "consensus", f"Finding {fid}: [error] {e}")
        return None


FIX_WRITER_SYS = (
    "You are a code writer/improver on the owner's OWN codebase (authorized). You are handed a VERIFIED "
    "weakness and the panel's remediation. Produce the CONCRETE CODE FIX that closes the gap on the "
    "installed-framework side -- the smallest change that fixes root cause. Output exactly:\n"
    "  FILE: <path or component the change goes in (best guess is fine)>\n"
    "  PATCH: a unified diff, or a minimal before/after snippet, implementing the fix\n"
    "  NOTE: one line on why this closes THIS weakness + any version bump / config to pair with it.\n"
    "This is a DEFENSIVE fix, NOT an exploit. Do not include destructive operations. Output only that."
)
# The code writers work together (the board + the consultant/verifier bind them): DeepSeek-v4-pro
# (direct) + qwen2.5-coder-32b + KIMI-2.7-code + Llama-4-Scout + DeepSeek-R1-distill (all CF paid;
# each skips gracefully if unavailable). Scout & R1-distill were added after a code-review bake-off.
FIX_WRITERS = [("ds_code", None), ("qwen2.5-coder-32b", "cf"), ("kimi-k2.7-code", "cf"),
               ("llama-4-scout", "cf"), ("deepseek-r1-distill-32b", "cf")]


def emit_fix(f, brief, consensus, rag_txt, code_model, fixes_dir):
    """Hand the remediation to the code bench -> concrete patch per writer. Emits files + board posts;
    returns {writer: patch}. Non-destructive: proposes patches, never applies them to the target."""
    fid = (f.get("finding_id") or "")[:12]
    os.makedirs(fixes_dir, exist_ok=True)
    usr = (f"WEAKNESS:\n{brief}\n\n"
           + (f"CONSENSUS REMEDIATION:\n{consensus}\n\n" if consensus else "")
           + (f"RAG FIX CONTEXT:\n{rag_txt}\n\n" if rag_txt else "")
           + "Write the concrete code fix (FILE / PATCH / NOTE).")
    patches = {}

    def run(writer, kind):
        try:
            if kind == "cf":
                out = cf_agent.ask(writer, FIX_WRITER_SYS, usr, max_tokens=1600)
            else:
                key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
                if not key:
                    print(f"  [fix:{writer}] skipped (no DeepSeek key)"); return
                ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
                out = _post_openai_style(ep + "/chat/completions", key, code_model, FIX_WRITER_SYS, usr, 1600, think=False)
        except Exception as e:
            out = f"[error] {e}"
        patches[writer] = out
        open(os.path.join(fixes_dir, f"{fid}__{writer}.md"), "w", encoding="utf-8").write(
            f"# code fix for finding {fid} ({writer})\n\n{out}")
        board("RMD_FIX", writer, f"Finding {fid}:\n\n{out}")

    ts = [threading.Thread(target=run, args=(w, k)) for w, k in FIX_WRITERS]
    for t in ts: t.start()
    for t in ts: t.join()
    return patches


def writeback(f, suggestions, consensus, code_model, fix_patches=None):
    """Append the chosen remediation to the hash-chained findings ledger the finding came from.
    Append-only: the verified finding is never mutated; a `remediation` event is chained on."""
    store_path = f.get("_src_store")
    fid = f.get("finding_id")
    if not store_path or not fid:
        print(f"  [ledger] no writable store for {(fid or '?')[:12]} (e.g. ExploitGym result) -- skipped")
        return
    try:
        from verified_findings import FindingStore  # shared/ on sys.path
        store = FindingStore(store_path)
    except Exception as e:
        print(f"  [ledger] cannot open store ({e}) -- skipped"); return
    fix = consensus or (next(iter(suggestions.values()), "") if suggestions else "")
    rem = {
        "path": f.get("_rem_path", "novel"),
        "fix": fix,
        "component": (f.get("provenance") or {}).get("component", ""),
        "installed_version": (f.get("provenance") or {}).get("installed_version", ""),
        "fixed_version": (f.get("provenance") or {}).get("fixed_version", ""),
        "cves": f.get("_cves", []),
        "rag": f.get("_rag_data", {}),
        "audience": f.get("_audience", "code"),
        "sources": sorted(suggestions.keys()),
        "consensus_model": code_model if consensus else "",
    }
    if fix_patches:
        rem["fix_patches"] = fix_patches  # {writer: patch} from the code writer/improver hand-off
    try:
        store.record_remediation(fid, rem)
        print(f"  [ledger] remediation chained onto {fid[:12]} ({rem['path']})")
    except Exception as e:
        print(f"  [ledger] writeback failed ({e})")


def _fenced(text, lang=""):
    """Wrap text in a code fence longer than any backtick run inside it, so a model's own ``` fences
    (patches often contain them) don't prematurely close the block. Returns a list of lines."""
    text = text or ""
    longest = max([len(m) for m in re.findall(r"`+", text)] or [0])
    fence = "`" * max(3, longest + 1)
    return [fence + lang, text, fence]


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def write_report(rows, path, panel, code_model):
    """Emit the durable remediation report: every confirmed weakness + each agent's fix + consensus."""
    rows = sorted(rows, key=lambda r: _SEV_RANK.get(str(r["finding"].get("severity", "unknown")).lower(), 5))
    ts = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    admin_rows = [r for r in rows if r["finding"].get("_audience") == "admin"]
    code_rows = [r for r in rows if r["finding"].get("_audience") != "admin"]
    out = [f"# Remediation report", "",
           f"_Generated {ts} -- fixes for oracle-VERIFIED findings only, routed to the audience that owns them._",
           "",
           "> **Scope: MIRROR-side.** These fixes target the mirror twin (where the findings were confirmed), "
           "for review and further testing on the mirror. They are **proposed, never auto-applied**, and are "
           "**not** run against the real target. Apply + re-test on the mirror only.", "",
           f"- Confirmed weaknesses: **{len(rows)}**  (admin/framework updates: **{len(admin_rows)}**, "
           f"code-writer changes: **{len(code_rows)}**)",
           f"- Panel: {', '.join(panel) or '(none)'} (fix/synthesis model: {code_model})",
           f"- Scope: advisory only; contained mirror; every suggestion attributed to its source.", ""]

    # --- RUN COSTS (board cost meter): the estimated USD spend of the whole run's LLM API calls ---
    try:
        import cost_meter
        out += [cost_meter.report_md(), ""]
    except Exception:
        pass

    # --- Admin track: framework / dependency / config updates ---
    out += ["## Admin actions — framework / dependency / config updates", "",
            "_For ops/admins: update the installed framework/component (version bump, patch, config). "
            "Not code changes._", ""]
    if admin_rows:
        out += ["| # | severity | weakness | component | installed → fixed | KEV due | advisory |",
                "|---|---|---|---|---|---|---|"]
        for i, r in enumerate(admin_rows, 1):
            f = r["finding"]; prov = f.get("provenance") or {}
            rag = (f.get("_rag_data") or {}).get("cves") or [{}]
            kev_due = next((c.get("kev_due") for c in rag if c.get("kev")), "") or ""
            url = next((c.get("url") for c in rag if c.get("url")), "") or ""
            iv, fv = prov.get("installed_version", "?"), prov.get("fixed_version", "?")
            out.append(f"| {i} | {f.get('severity', 'unknown')} | {f.get('claim_type', '?')} "
                       f"| {prov.get('component', '?')} | {iv} → {fv} | {kev_due or '—'} "
                       f"| {url or '—'} |")
        out.append("")
    else:
        out += ["_None._", ""]

    # --- Code-writer track: source-code improvements ---
    out += ["## Code writer/improver — code changes", "",
            "_For the code writer/improver: source-level fixes to close the gap (novel logic flaws and any "
            "emitted patches). Apply after review — non-destructive, not auto-applied._", ""]
    if code_rows or any(r.get("fix_patches") for r in rows):
        out += ["| # | severity | weakness | path | patch emitted? |",
                "|---|---|---|---|---|"]
        for i, r in enumerate(rows, 1):
            f = r["finding"]
            if f.get("_audience") == "admin" and not r.get("fix_patches"):
                continue
            out.append(f"| {i} | {f.get('severity', 'unknown')} | {f.get('claim_type', '?')} "
                       f"| {f.get('_rem_path', 'novel')} | {'yes' if r.get('fix_patches') else '—'} |")
        out.append("")
    else:
        out += ["_None._", ""]

    out += ["## All findings — detail", "",
            "| # | severity | weakness (claim type) | audience | path | agents | consensus? |",
            "|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        f = r["finding"]
        out.append(f"| {i} | {f.get('severity', 'unknown')} | {f.get('claim_type', '?')} "
                   f"| {f.get('_audience', 'code')} | {f.get('_rem_path', 'novel')} "
                   f"| {len(r['suggestions'])} | {'yes' if r.get('consensus') else '—'} |")
    out += ["", "_Path: **known-cve** = fix grounded in the offline vuln store (RAG); "
            "**novel** = panel-designed fix for a weakness discovered here (no CVE). "
            "Audience: **admin** = framework/dependency update; **code** = code writer/improver._", ""]
    for i, r in enumerate(rows, 1):
        f = r["finding"]
        out += [f"## {i}. {f.get('claim_type', '?')}  ",
                f"**Severity:** {f.get('severity', 'unknown')} &nbsp; **Audience:** {f.get('_audience', 'code')}"
                f" &nbsp; **Path:** {f.get('_rem_path', 'novel')}"
                f" &nbsp; **Finding:** `{(f.get('finding_id') or '')[:12]}`", "",
                "**Confirmed weakness (sanitized):**", "", "```", r["brief"], "```", ""]
        if f.get("_rag_txt"):
            out += ["**RAG fix context (deterministic):**", "", "```", f["_rag_txt"], "```", ""]
        if r.get("consensus"):
            out += ["### Consensus remediation", "", r["consensus"], ""]
        out.append("### Per-agent remediation")
        if not r["suggestions"]:
            out += ["", "_No agent responded (keys unavailable?)._", ""]
        for who, txt in r["suggestions"].items():
            out += ["", f"**{who}:**", "", txt, ""]
        if r.get("fix_patches"):
            out += ["", "### Proposed code fix (code writer/improver hand-off)", "",
                    "_Concrete patch to close the gap; apply after review (non-destructive; not auto-applied)._"]
            for who, patch in r["fix_patches"].items():
                out += ["", f"**{who}:**", ""] + _fenced(patch) + [""]
        out.append("---")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))
    print(f"\n[remediation] report written -> {path}")
    return path


def main():
    ap = argparse.ArgumentParser(description="Stage-10 remediation round on the chat board + report.")
    ap.add_argument("--findings", help="verified-findings jsonl (default: operator/aegis_operator_findings.jsonl)")
    ap.add_argument("--eg-results", help="also fold ExploitGym result_*.json verified findings from this dir")
    ap.add_argument("--panel", default="ds,cf,qwen",   # Sol removed (booted: content-gated + priciest)
                    help="board members: ds,sol,cf,qwen (cf=gpt-oss-120b+20b) or 'all' (default: all)")
    ap.add_argument("--code-model", default="deepseek-v4-pro",
                    help="DeepSeek model for the concrete fix + synthesis (default: deepseek-v4-pro)")
    ap.add_argument("--claude-note", help="post the coordinator's (Claude's) own remediation take too")
    ap.add_argument("--synthesize", action="store_true", help="fold the panel into one consensus per finding")
    ap.add_argument("--report", default=os.path.join(HERE, "remediation_report.md"),
                    help="path for the durable remediation report (default: operator/remediation_report.md)")
    ap.add_argument("--no-report", action="store_true", help="post to the board only; skip the report file")
    ap.add_argument("--no-rag", action="store_true", help="skip the deterministic RAG/CVE fix lookup")
    ap.add_argument("--emit-fixes", action="store_true",
                    help="hand each finding to the CODE BENCH (deepseek-v4-pro + qwen-coder) to emit a "
                         "concrete fix patch (files under operator/remediation_fixes/, non-destructive)")
    ap.add_argument("--fixes-dir", default=os.path.join(HERE, "remediation_fixes"),
                    help="output dir for emitted code fixes (default: operator/remediation_fixes)")
    ap.add_argument("--write-ledger", action="store_true",
                    help="write the chosen remediation (and any emitted fix patches) into the hash-chained ledger")
    ap.add_argument("--max", type=int, default=0, help="cap number of findings (0 = all)")
    ap.add_argument("--dry-run", action="store_true", help="print the sanitized briefs; don't call the panel")
    a = ap.parse_args()

    findings = collect(a)
    if a.max:
        findings = findings[:a.max]
    if not findings:
        print("[remediation] no VERIFIED findings to remediate. Run the operator / ExploitGym first, "
              "or point --findings / --eg-results at the ledger."); return
    members = expand_panel(a.panel)
    print(f"[remediation] {len(findings)} verified finding(s); panel = {', '.join(members) or '(none)'}"
          f"{' + claude' if a.claude_note else ''}; board = {BOARD}")

    if a.dry_run:
        for i, f in enumerate(findings, 1):
            print(f"\n--- finding {i}/{len(findings)} (sanitized brief) ---\n{brief(f)}")
        print("\n[dry-run] no board posts, no panel calls.")
        return

    rows = []
    for i, f in enumerate(findings, 1):
        fid, wb, suggestions = run_finding(f, i, len(findings), members, a.code_model, use_rag=not a.no_rag)
        if a.claude_note:
            board("RMD", "claude", f"Finding {fid}:\n\n{a.claude_note}")
            suggestions["claude"] = a.claude_note
        consensus = synthesize(fid, wb, suggestions, a.code_model) if a.synthesize else None
        fix_patches = emit_fix(f, wb, consensus, f.get("_rag_txt", ""), a.code_model, a.fixes_dir) \
            if a.emit_fixes else None
        rows.append({"finding": f, "brief": wb, "suggestions": suggestions, "consensus": consensus,
                     "fix_patches": fix_patches})
        if a.write_ledger:
            writeback(f, suggestions, consensus, a.code_model, fix_patches)

    print(f"\n[remediation] done. Panel remediations are on the board -- watch: board/live_board.ps1")
    if not a.no_report:
        write_report(rows, a.report, members + (["claude"] if a.claude_note else []), a.code_model)


if __name__ == "__main__":
    main()
