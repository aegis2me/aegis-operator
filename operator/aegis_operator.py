#!/usr/bin/env python
r"""
aegis_operator.py -- DeepSeek (DS) as the OPERATOR CO-PILOT, with a human APPROVAL GATE.

DS is the brain; this harness is the hands. The stock `deepseek` CLI can only DECIDE
(it prints tool_calls as JSON, never executes them). This wrapper executes DS's tool
calls against the real aegis stack AND the codebase -- but every MUTATING action
(submit / resume / VPN change / shell / file write) must be approved by a human at the
terminal first. Read-only tools (status, read context, read file) run automatically.

Fail-closed: if no 'y' is given (including a non-interactive/EOF stdin), the action is
DENIED and DS is told so, so it can adapt or explain. Nothing touches a target, a
process, or a file without an explicit human 'y'.

Brain: deepseek-v4-pro in NON-thinking mode (the benchmarked co-pilot config). Use
--think to opt into deep reasoning; --model to override.

This is part of the DeepSeek-CLI project and can be run from its folder. It orchestrates
the aegis stack (on localhost) and, for code-ops, works against whatever repo you point
it at. It needs an API key (DEEPSEEK_API_KEY, else AEGIS_LLM_API_KEY, else aegis's
config) and the aegis stack running on localhost.

Usage:
  $env:DEEPSEEK_API_KEY = "sk-..."     # or dot-source aegis's set-env.local.ps1
  python aegis_operator.py --task "check whether ports 22 and 5000 on 203.0.113.10 are open"
Flags:
  --think            enable DS thinking mode (slower, deeper)
  --model NAME       override model (default: deepseek-v4-pro)
  --max-iter N       max reasoning/act cycles (default 20)
  --repo PATH        root for code-ops (read/list/search/write/edit); default: aegis-operator
  --aegis-operator P path to aegis-operator (checkpoints + aegis_cli.py); default: env/built-in
  --dry-run          show every proposed action but auto-DENY it (safe rehearsal)
  --auto-approve     DANGER: skip the gate, approve every action (unattended; off by default)
"""
import argparse, difflib, glob as _glob, hashlib, json, os, re, secrets, subprocess, sys, threading, time
from collections import deque
import requests

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from openai import OpenAI
try:
    from config import Master  # aegis's LLM config, if importable (optional)
except Exception:
    Master = None


# ---- provider adaptation: DeepSeek (default) vs OpenAI (direct api.openai.com) ----
def _provider() -> str:
    """Which LLM provider this run targets. AEGIS_PROVIDER wins; else inferred from the
    endpoint (api.openai.com -> openai). Default 'deepseek' (behavior unchanged)."""
    p = os.environ.get("AEGIS_PROVIDER", "").strip().lower()
    if p:
        return p
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or os.environ.get("DEEPSEEK_ENDPOINT") or "").lower()
    return "openai" if "openai.com" in ep else "deepseek"


def _create(client, **kw):
    """Provider-adapted chat.completions.create. The DeepSeek path is byte-for-byte unchanged.
    For OpenAI: drop DeepSeek's extra_body={'thinking':...} (OpenAI rejects it), rename
    max_tokens -> max_completion_tokens (forward-compatible, incl. reasoning models), and omit
    temperature (reasoning models reject a non-default value). Validate on the first OpenAI run."""
    if _provider() == "cloudflare":
        # Cloudflare Workers AI OpenAI-compatible endpoint: standard chat.completions with
        # max_tokens + temperature; no DeepSeek 'thinking' extra_body, no OpenAI reasoning_effort.
        # Model is a CF slug, e.g. @cf/qwen/qwen3-30b-a3b-fp8. See cf_models.json.
        kw.pop("extra_body", None)
        return client.chat.completions.create(**kw)
    if _provider() == "openai":
        kw.pop("extra_body", None)
        if "max_tokens" in kw:
            kw["max_completion_tokens"] = kw.pop("max_tokens")
        kw.pop("temperature", None)
        # GPT-5.6 Sol is a reasoning model: function tools via /chat/completions REQUIRE
        # reasoning_effort='none' (default effort + tools -> 400). This also matches the
        # co-pilot's thinking-OFF operator policy (fast, tool-focused). Override via
        # AEGIS_LLM_REASONING if a run wants low/medium/high on a tool-less call.
        kw.setdefault("reasoning_effort", os.environ.get("AEGIS_LLM_REASONING", "none"))
    return client.chat.completions.create(**kw)

HERE = os.path.dirname(os.path.abspath(__file__))
# Optional external task-tree scheduler (see orchestrator/). The harness runs fully
# standalone without it (direct tool-loop + planner_core); the scheduler tools simply
# report "unavailable" if nothing is listening here. Override with AEGIS_SCHEDULER_URL.
AEGIS = os.environ.get("AEGIS_SCHEDULER_URL", "http://127.0.0.1:37695")
# AEGIS_HOME is the project root (this file lives in <root>/operator/). Holds checkpoints.
# Override with the AEGIS_HOME env var if the project lives elsewhere.
AEGIS_HOME = os.environ.get("AEGIS_HOME", os.path.dirname(HERE))
CKPT_DIR = os.path.join(AEGIS_HOME, "checkpoints")
CLI = os.path.join(AEGIS_HOME, "aegis_cli.py")
AUDIT_LOG = os.path.join(HERE, "aegis_operator_audit.log")
# REPO is the root that code-ops (read/list/search/write/edit) resolve against.
# Defaults to the aegis stack; override with --repo. (Re)set in __main__.
REPO = AEGIS_HOME

# ---------------------------------------------------------------- approval gate
class Gate:
    def __init__(self, dry_run=False, auto_approve=False):
        self.dry_run = dry_run
        self.auto_approve = auto_approve

    def _log(self, tool, args, decision):
        try:
            # redact large string args (file contents, edits) so secrets don't land in the log
            safe = {k: (f"{v[:160]}...[{len(v)} chars, redacted]" if isinstance(v, str) and len(v) > 300 else v)
                    for k, v in (args or {}).items()}
            with open(AUDIT_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "tool": tool, "args": safe, "decision": decision}) + "\n")
        except Exception:
            pass

    def approve(self, tool, args, preview=None):
        border = "=" * 72
        print(f"\n{border}\n[APPROVAL REQUIRED] DS wants to run:  {tool}", flush=True)
        for k, v in args.items():
            vs = v if isinstance(v, str) else json.dumps(v)
            print(f"    {k}: {vs[:600]}", flush=True)
        if preview:
            print("  --- preview ---", flush=True)
            print("\n".join("    " + ln for ln in preview.splitlines()[:60]), flush=True)
        print(border, flush=True)
        if self.auto_approve:
            print("[auto-approve ON] -> APPROVED", flush=True); self._log(tool, args, "auto"); return True
        if self.dry_run:
            print("[dry-run] -> DENIED (rehearsal)", flush=True); self._log(tool, args, "dry-run-deny"); return False
        try:
            ans = input("Approve this action? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n[no input / interrupted] -> DENIED (fail-closed)", flush=True)
            self._log(tool, args, "eof-deny"); return False
        ok = ans in ("y", "yes")
        print(f"-> {'APPROVED' if ok else 'DENIED'}", flush=True)
        self._log(tool, args, "approved" if ok else "denied")
        return ok

# --------------------------------------------------------------- tool backends
def _aegis_up():
    try:
        requests.get(f"{AEGIS}/docs", timeout=3); return True
    except Exception:
        return False

# read-only
def t_get_status():
    r = requests.get(f"{AEGIS}/get/task/status", timeout=15)
    out = [{"task_id": x.get("token"), "status": x.get("status"),
            "abstract": (x.get("abstract") or "")[:60]} for x in r.json() if x.get("token")]
    return json.dumps(out[-15:])

def t_read_task_context(task_id, tail_chars=2500, poll_wait=10):
    def _snap():
        r = requests.get(f"{AEGIS}/get/task/status", timeout=15)
        return {x.get("token"): x for x in r.json() if x.get("token")}.get(task_id)
    t = _snap()
    # Pace babysitting: if still running, wait ~poll_wait s and re-read ONCE so each call
    # advances real time instead of spin-polling (a long command / slow planner is normal).
    if t and t.get("status") == "running":
        time.sleep(poll_wait)
        t = _snap()
    if not t:
        return json.dumps({"error": "task not found"})
    cp = os.path.join(CKPT_DIR, f"{task_id}.json")
    age = round(time.time() - os.path.getmtime(cp), 1) if os.path.exists(cp) else None
    ctx = t.get("context") or ""
    return json.dumps({"status": t.get("status"), "checkpoint_mtime_age_s": age,
                       "checkpoint_exists": os.path.exists(cp), "context_len": len(ctx),
                       "context_tail": ctx[-tail_chars:]})

# Credential-shaped files/dirs. Mirrors deepseek_cli.handlers.file_handler.is_sensitive
# (exact-name / suffix / parent-dir matching) rather than the old naive substring test,
# which both missed .ssh/config, .aws/config, modern SSH keys, .netrc, .pgpass, etc. AND
# false-positived on benign names like secretary_report.md or pubkey.pem.
_SECRET_EXTS = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".asc", ".gpg",
                ".kdbx", ".ovpn"}
_SECRET_NAMES = {".env", ".envrc", ".netrc", "_netrc", ".pgpass", ".htpasswd",
                 "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity",
                 "credentials", "shadow", ".git-credentials", ".npmrc", ".pypirc",
                 "authorized_keys", "set-env"}
_SECRET_DIRS = {".ssh", ".aws", ".gnupg", ".kube", ".docker"}

def _is_secret_path(abspath):
    """Heuristically flag paths that typically hold credentials or private keys."""
    parts = os.path.normpath(abspath).replace("\\", "/").split("/")
    name = os.path.basename(abspath).lower()
    _, ext = os.path.splitext(name)
    if name in _SECRET_NAMES or ext in _SECRET_EXTS:
        return True
    if name.startswith(".env."):  # .env.production and friends
        return True
    if name.startswith("set-env") or ("vpn" in name and "auth" in name):  # project secrets (e.g. a VPN auth file) carry suffixes
        return True
    return any(part.lower() in _SECRET_DIRS for part in parts)

def _safe_repo_path(path):
    """Confine code-ops to the REPO root and refuse credential-shaped files.
    Returns (abspath, None) on success, or (None, error) if the path is disallowed."""
    base = os.path.abspath(REPO)
    p = os.path.abspath(path if os.path.isabs(path) else os.path.join(base, path))
    try:
        inside = os.path.commonpath([base, p]) == base
    except ValueError:  # different drives on Windows
        inside = False
    if not inside:
        return None, f"path is outside the repo root ({REPO}); not allowed"
    if _is_secret_path(p):
        return None, "refusing to read/write a credential- or secret-shaped file"
    return p, None

def _safe_glob(pattern, base):
    """Expand a glob under REPO, dropping any match that escapes the root or is
    credential-shaped. os.path.join drops `base` when `pattern` is absolute, and
    glob follows `..`, so an unvalidated pattern like '/etc/*' or '../../etc/*'
    would otherwise read arbitrary files. Reject absolute/parent patterns up front
    for a clear error, then validate every concrete match via _safe_repo_path."""
    if os.path.isabs(pattern) or ".." in pattern.replace("\\", "/").split("/"):
        return None, "glob pattern must be relative to the repo root and contain no '..'"
    safe = []
    for m in _glob.glob(os.path.join(base, pattern), recursive=True):
        if not os.path.isfile(m) or "__pycache__" in m:
            continue
        ok, _err = _safe_repo_path(m)
        if ok:
            safe.append(ok)
    return safe, None

def t_read_file(path, start_line=1, end_line=None):
    p, err = _safe_repo_path(path)
    if err:
        return json.dumps({"error": err})
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})
    total = len(lines)
    s = max(1, int(start_line))
    e = total if end_line in (None, "", 0) else min(total, int(end_line))
    chunk = "".join(lines[s - 1:e])
    note = ""
    if len(chunk) > 11000:
        chunk = chunk[:11000]
        note = "DISPLAY-CAPPED at 11000 chars (NOT the end of file). Request a narrower start_line/end_line to read more."
    return json.dumps({"path": p, "total_lines": total, "returned_lines": f"{s}-{e}",
                       "more_after_this": e < total, "note": note, "content": chunk})

def t_list_files(pattern="**/*.py", limit=200):
    base = os.path.abspath(REPO)
    matches, err = _safe_glob(pattern, base)
    if err:
        return json.dumps({"error": err})
    rels = [os.path.relpath(m, base) for m in matches]
    return json.dumps({"count": len(rels), "files": sorted(rels)[:limit]})

def t_search_code(pattern, glob_pat="**/*.py", limit=80):
    try:
        rx = re.compile(pattern)
    except Exception as e:
        return json.dumps({"error": f"bad regex: {e}"})
    base = os.path.abspath(REPO)
    matches, err = _safe_glob(glob_pat, base)
    if err:
        return json.dumps({"error": err})
    hits = []
    for m in matches:
        try:
            with open(m, encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    if rx.search(line):
                        hits.append(f"{os.path.relpath(m, REPO)}:{i}: {line.rstrip()[:200]}")
                        if len(hits) >= limit:
                            break
        except Exception:
            continue
        if len(hits) >= limit:
            break
    return json.dumps({"count": len(hits), "matches": hits})

# actions (gated)
def t_submit(description, abstract="Task", verification="Task completed."):
    r = requests.post(f"{AEGIS}/task", params={"abstract": abstract,
                      "description": description, "verification": verification}, timeout=30)
    r.raise_for_status()
    return json.dumps({"task_id": r.json().get("task_id")})

def t_resume(task_id, note=""):
    cmd = [sys.executable, CLI, "resume", task_id] + (["--note", note] if note else [])
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    return json.dumps({"stdout": p.stdout[-1500:], "stderr": p.stderr[-600:], "rc": p.returncode})

def t_vpn_ctl(action, region="United Kingdom"):
    args = ["vpn-ctl", action] + ([region] if action in ("connect", "ensure") else [])
    p = subprocess.run(["wsl", "-d", "kali-linux", "-u", "root", "--"] + args,
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    return json.dumps({"stdout": p.stdout[-1500:], "stderr": p.stderr[-500:], "rc": p.returncode})

def t_run_command(command):
    p = subprocess.run(command, shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=180, cwd=REPO)
    return json.dumps({"stdout": p.stdout[-3000:], "stderr": p.stderr[-800:], "rc": p.returncode})

_BACKUPS = {}  # path -> content before the last write/edit this session (for revert)

def _backup(p):
    try:
        _BACKUPS[p] = open(p, "r", encoding="utf-8", errors="replace").read() if os.path.exists(p) else None
    except Exception:
        pass

def t_write_file(path, content):
    p, err = _safe_repo_path(path)
    if err:
        return json.dumps({"error": err})
    _backup(p)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return json.dumps({"written": p, "bytes": len(content), "revertable": True})

def t_apply_edit(path, old_string, new_string):
    p, err = _safe_repo_path(path)
    if err:
        return json.dumps({"error": err})
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})
    n = data.count(old_string)
    if n == 0:
        return json.dumps({"error": "old_string not found; re-read the file and copy it exactly"})
    if n > 1:
        return json.dumps({"error": f"old_string matches {n} times; add surrounding context to make it unique"})
    _backup(p)
    with open(p, "w", encoding="utf-8") as f:
        f.write(data.replace(old_string, new_string))
    return json.dumps({"edited": p, "occurrences": 1, "revertable": True})

def t_revert_file(path):
    p, err = _safe_repo_path(path)
    if err:
        return json.dumps({"error": err})
    if p not in _BACKUPS:
        return json.dumps({"error": "no backup for this file (only edits made this session are revertable)"})
    prev = _BACKUPS[p]
    if prev is None:
        try: os.remove(p)
        except Exception: pass
        return json.dumps({"reverted": p, "note": "file did not exist before; removed"})
    with open(p, "w", encoding="utf-8") as f:
        f.write(prev)
    return json.dumps({"reverted": p, "bytes": len(prev)})

_SUBAGENT_MAX = 8       # total sub-agents allowed per session (overspawn guard)
_SUBAGENT_COUNT = 0

def t_spawn_subagent(task, tools=None):
    # Delegate a focused sub-task to a nested agent (own context, scoped tools). Shares the SAME
    # approval gate, so its mutating actions still require a human 'y'. Depth-capped (no nesting, so
    # only one sub-agent runs at a time) AND total-count-capped (no runaway delegation).
    global _SUBAGENT_COUNT
    if not _CTX:
        return json.dumps({"error": "no agent context"})
    if _CTX.get("depth", 0) >= 1:
        return json.dumps({"error": "max delegation depth reached; do this sub-task yourself (no nested sub-agents)"})
    if _SUBAGENT_COUNT >= _SUBAGENT_MAX:
        return json.dumps({"error": f"sub-agent budget exhausted ({_SUBAGENT_MAX} max this session); "
                                    "do the remaining work yourself instead of delegating more"})
    _SUBAGENT_COUNT += 1
    allowed = tools or ["read_file", "list_files", "search_code", "search_docs", "get_status",
                        "read_task_context", "run_command", "run_background",
                        "read_process_output", "kill_process", "apply_edit", "write_file",
                        "revert_file", "finalize_report", "finish"]
    allowed = [t for t in allowed if t in TOOLS and t != "spawn_subagent"]
    if "finish" not in allowed:
        allowed.append("finish")
    sub_sys = ("You are a focused SUB-AGENT. Do ONLY the delegated task with the allowed tools, verify your work "
               "(run tests/commands where relevant), then call finish() with a concise summary of what you found "
               "or did. Mutating actions still require human approval; if denied, explain and stop.")
    summary = _agent_loop(_CTX["client"], _CTX["model"], _CTX["thinking"],
                          [{"role": "system", "content": sub_sys}, {"role": "user", "content": task}],
                          allowed, max_iter=_CTX.get("sub_max_iter", 8), gate=_CTX["gate"],
                          depth=_CTX.get("depth", 0) + 1, tag="  [sub")
    return json.dumps({"subagent_summary": summary or "(sub-agent produced no summary)"})

VERIFY_CMD = None  # optional project verify command (e.g. "pytest -q"), set via --verify-cmd

def _auto_verify(path):
    """Run automatically by the harness after every apply_edit/write_file: a py_compile syntax
    check for .py files, plus any configured --verify-cmd. The result is merged into the edit's
    tool response so the model always sees whether its change broke something."""
    p, err = _safe_repo_path(path)
    if err:
        return {"note": err}
    out = {}
    if p.endswith(".py"):
        try:
            c = subprocess.run([sys.executable, "-m", "py_compile", p],
                               capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            out["py_compile"] = "ok" if c.returncode == 0 else "FAIL: " + (c.stderr or "")[-500:]
        except Exception as e:
            out["py_compile"] = "error: " + repr(e)[:150]
    if VERIFY_CMD:
        try:
            v = subprocess.run(VERIFY_CMD, shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
                               timeout=300, cwd=REPO)
            out["verify_cmd"] = {"cmd": VERIFY_CMD, "rc": v.returncode,
                                 "tail": ((v.stdout or "") + (v.stderr or ""))[-800:]}
        except Exception as e:
            out["verify_cmd"] = {"error": repr(e)[:150]}
    if not out:
        out["note"] = "no auto-verify applicable (non-.py file and no --verify-cmd configured)"
    return out

_PROCS = {}  # proc_id -> {popen, buf, done, rc, cmd}

def _proc_reader(pid):
    pr = _PROCS[pid]; po = pr["popen"]
    try:
        for line in po.stdout:
            pr["buf"].append(line.rstrip("\n"))
    except Exception:
        pass
    try: po.wait()
    except Exception: pass
    pr["done"] = True; pr["rc"] = po.returncode

def t_run_background(command):
    pid = f"p{len(_PROCS) + 1}"
    po = subprocess.Popen(command, shell=True, cwd=REPO, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                          errors="replace", bufsize=1)
    _PROCS[pid] = {"popen": po, "buf": deque(maxlen=2000), "done": False, "rc": None, "cmd": command}
    threading.Thread(target=_proc_reader, args=(pid,), daemon=True).start()
    return json.dumps({"proc_id": pid, "started": command,
                       "note": "poll with read_process_output; stop with kill_process"})

def t_read_process_output(proc_id, tail_lines=60):
    pr = _PROCS.get(proc_id)
    if not pr:
        return json.dumps({"error": f"no such process {proc_id}"})
    return json.dumps({"proc_id": proc_id, "cmd": pr["cmd"], "running": not pr["done"],
                       "exit_code": pr["rc"], "lines": list(pr["buf"])[-int(tail_lines):]})

def t_kill_process(proc_id):
    pr = _PROCS.get(proc_id)
    if not pr:
        return json.dumps({"error": f"no such process {proc_id}"})
    try:
        pr["popen"].kill()
    except Exception as e:
        return json.dumps({"error": repr(e)[:150]})
    return json.dumps({"killed": proc_id})

_TODO = []  # the agent's live plan: list of {content, status in pending|in_progress|completed}

def _render_todos():
    sym = {"completed": "x", "in_progress": "~", "pending": " "}
    return "\n".join(f"  [{sym.get(t['status'],' ')}] {t['content']}" for t in _TODO) or "  (empty)"

def t_write_todos(todos):
    global _TODO
    norm = []
    for it in (todos or []):
        if isinstance(it, str):
            norm.append({"content": it, "status": "pending"})
        elif isinstance(it, dict):
            st = it.get("status", "pending")
            norm.append({"content": it.get("content", ""),
                         "status": st if st in ("pending", "in_progress", "completed") else "pending"})
    _TODO = norm
    print("[plan]\n" + _render_todos(), flush=True)
    return json.dumps({"todos": _TODO, "rendered": _render_todos()})

# ---- doctrine retrieval (removes the "spoon-feed the doctrine" dependence) ----
DOC_FILES = ["HELP.md", "RESILIENCE.md", os.path.join(".claude", "skills", "aegis", "SKILL.md")]

def t_search_docs(query, max_hits=6):
    """Search the project runbook/doctrine (HELP.md, RESILIENCE.md, the aegis SKILL) for a topic --
    e.g. planner-choke, kali_driver queueing, VPN, checkpoints, resume, reports. Read-only."""
    try:
        rx = re.compile(query, re.IGNORECASE)
    except Exception as e:
        return json.dumps({"error": f"bad regex: {e}"})
    hits = []
    per_doc = max(2, max_hits // max(1, len(DOC_FILES)))  # ensure every doc is represented
    for rel in DOC_FILES:
        p = os.path.join(AEGIS_HOME, rel)
        if not os.path.isfile(p):
            continue
        try:
            lines = open(p, encoding="utf-8", errors="replace").read().split("\n")
        except Exception:
            continue
        doc_hits = 0
        for i, ln in enumerate(lines):
            if rx.search(ln):
                hits.append({"doc": rel, "line": i + 1,
                             "context": "\n".join(lines[max(0, i - 2):i + 6])[:700]})
                doc_hits += 1
                if doc_hits >= per_doc:
                    break
    return json.dumps({"query": query, "hits": hits or "no matches in the runbook"})

# ---- report QA / finalize pass (catch bad/empty/fabricated reports; synthesis-led) ----
_REDFLAGS = [r"\[tool error", r"Timed out", r"Waited 600", r"no-response", r"NXDOMAIN",
             r'"stdout"\s*:\s*""', r"0 rows", r"no rows", r"Connection refused", r"could not resolve",
             r'timed_out"\s*:\s*true', r"\[interrupted\]",
             r'"rows"\s*:\s*\[\s*\]', r'"results"\s*:\s*\[\s*\]', r'"data"\s*:\s*\{\s*\}']  # specific empties, not bare {}

def _redflag_scan(text):
    flags = []
    for pat in _REDFLAGS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            s, e = max(0, m.start() - 40), min(len(text), m.end() + 70)
            flags.append({"pattern": pat, "example": text[s:e].replace("\n", " ")})
    return flags

def t_finalize_report(draft, task_id=None):
    """QA a draft report BEFORE finishing. Deterministically scans the raw transcript for failure/empty
    red flags, requires every claim to be evidence-backed (flags unsupported claims and failed/empty scans
    reported as results), and rewrites SYNTHESIS-LED (lead with the top systemic risk). Read-only analysis."""
    transcript, fetch_warning = "", None
    if task_id:
        try:
            r = requests.get(f"{AEGIS}/get/task/status", timeout=15)
            t = {x.get("token"): x for x in r.json() if x.get("token")}.get(task_id)
            if t is None:
                fetch_warning = f"task {task_id} not found on aegis -- transcript NOT examined"
            else:
                transcript = t.get("context") or ""
                if not transcript:
                    fetch_warning = "task found but its transcript is empty -- no evidence to check against"
        except Exception as e:
            fetch_warning = f"could not fetch transcript ({repr(e)[:70]}) -- evidence NOT examined"
    else:
        fetch_warning = "no task_id given -- claims cannot be checked against a transcript"
    flags = _redflag_scan(transcript) if transcript else []
    client = _CTX.get("client") if _CTX else None
    if client is None:
        return json.dumps({"redflags": flags, "transcript_examined": bool(transcript),
                           "warning": fetch_warning, "note": "no LLM client available for the QA pass"})
    excerpt = ((transcript[:6000] + "\n...[middle elided]...\n" + transcript[-6000:]) if len(transcript) > 12000
               else transcript) or ("[NO TRANSCRIPT AVAILABLE -- evidence could not be fetched; treat EVERY "
                                     "factual claim in the draft as UNVERIFIED and say so in the QA]")
    qa_sys = ("You are a STRICT QA reviewer for a penetration-test report. Do three things: "
              "(1) For EVERY claim/finding in the draft, check it is actually supported by the transcript; flag "
              "any unsupported or over-claimed statement -- especially specific CVEs/versions/exploit names -- and "
              "any 'finding' that is really NO DATA (a failed / empty / timed-out scan reported as a clean or "
              "positive result). (2) Reconcile the RED FLAGS listed below: does the draft honestly account for "
              "these failures/empties, or does it hide them? (3) Rewrite the report SYNTHESIS-LED: open with the "
              "single most important systemic risk / through-line (shared root cause, single point of failure), "
              "THEN the evidence-backed findings (each with its evidence), THEN what still must be verified. Be "
              "precise and honest; do not invent anything.")
    user = (f"RED FLAGS from a deterministic scan of the raw transcript:\n{json.dumps(flags, indent=2)[:2500]}\n\n"
            f"RAW TRANSCRIPT EXCERPT:\n{excerpt}\n\nDRAFT REPORT TO QA AND REWRITE:\n{draft}")
    try:
        resp = _create(client,
            model=_CTX.get("model", "deepseek-v4-pro"), temperature=0.2, max_tokens=2500,
            extra_body={"thinking": {"type": "disabled"}},  # non-thinking: avoids output starvation on QA
            messages=[{"role": "system", "content": qa_sys}, {"role": "user", "content": user}])
        qa = (resp.choices[0].message.content or "").strip()
    except Exception as e:
        return json.dumps({"redflags": flags, "error": repr(e)[:160]})
    return json.dumps({"redflags_found": len(flags), "redflags": flags[:8],
                       "transcript_examined": bool(transcript), "warning": fetch_warning,
                       "qa_and_final_report": qa})

def _diff_preview(path, new_content):
    p, err = _safe_repo_path(path)
    if err:
        return f"(cannot preview: {err})"
    old = ""
    if os.path.exists(p):
        try:
            old = open(p, "r", encoding="utf-8", errors="replace").read()
        except Exception:
            old = ""
    d = difflib.unified_diff(old.splitlines(), new_content.splitlines(),
                             fromfile=f"a/{os.path.basename(p)}", tofile=f"b/{os.path.basename(p)}",
                             lineterm="")
    return "\n".join(list(d)[:200]) or "(new file)"

# ---- cross-session memory (parity with Claude's persistent memory) ----
MEMORY_FILE = os.path.join(HERE, "aegis_operator_memory.json")

def _load_memory():
    try:
        m = json.load(open(MEMORY_FILE, encoding="utf-8"))
        return m if isinstance(m, list) else []
    except Exception:
        return []

def t_remember(note):
    """Save a durable fact/learning across sessions (a gotcha, a target detail, a decision)."""
    mem = _load_memory()
    mem.append({"ts": time.strftime("%Y-%m-%d %H:%M"), "note": str(note)[:1000]})
    mem = mem[-300:]
    try:
        tmp = MEMORY_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(mem, f, indent=2)
        os.replace(tmp, MEMORY_FILE)
    except Exception as e:
        return json.dumps({"error": repr(e)[:150]})
    return json.dumps({"remembered": note, "total_notes": len(mem)})

def t_recall(query=None):
    """Recall durable notes from past sessions, optionally filtered by a regex."""
    mem = _load_memory()
    if query:
        try:
            rx = re.compile(query, re.IGNORECASE)
            mem = [m for m in mem if rx.search(m.get("note", ""))]
        except Exception:
            pass
    return json.dumps({"count": len(mem), "notes": mem[-40:]})

def _memory_preface():
    mem = _load_memory()
    if not mem:
        return ""
    recent = "\n".join(f"- ({m.get('ts','')}) {m.get('note','')}" for m in mem[-25:])
    return "\n\nMEMORY (durable notes you saved in past sessions -- treat as known context):\n" + recent


def _skill_preface():
    """Preload the /aegis skill (the operator playbook) into the system prompt at startup, the same way
    Claude Code loads it on `/aegis` -- so the DS operator starts with the doctrine/pipeline/tools in
    context, not only reachable via search_docs. Fail-soft (empty if the skill file is absent); disable
    with AEGIS_SKILL_PRELOAD=0. search_docs still serves HELP.md/RESILIENCE.md and re-querying the skill."""
    if os.environ.get("AEGIS_SKILL_PRELOAD", "1").lower() in ("0", "false", "no"):
        return ""
    p = os.path.join(AEGIS_HOME, ".claude", "skills", "aegis", "SKILL.md")
    try:
        body = open(p, encoding="utf-8", errors="replace").read().strip()
    except Exception:
        return ""
    if not body:
        return ""
    return ("\n\n=== AEGIS SKILL (the operator playbook -- loaded at startup, same as Claude Code's /aegis) "
            "===\nThis is your authoritative runbook: the standalone architecture, the discovery pipeline "
            "(docs/PIPELINE.md), the tools, the board doctrine, and the gotchas. Follow it. Use search_docs "
            "to re-query it or HELP.md/RESILIENCE.md for more detail.\n\n" + body +
            "\n=== END AEGIS SKILL ===")

# ---- append-only findings / exploit-chain ledger (survives context compaction) ----
# The compactor summarizes older middle turns LOSSILY. Confirmed findings and multi-stage
# chain state must never be folded away, or a long compromise silently loses a mid-chain
# link (observed: run-1 forgot an /api/settings secret + route map after compaction). This
# ledger is an append-only file re-injected VERBATIM after every compaction (_maybe_compact)
# and into the report step, so record_finding()/chain_state() entries always persist.
LEDGER_FILE = os.path.join(HERE, "aegis_operator_ledger.json")
_RUN_ID = os.environ.get("AEGIS_RUN_ID") or time.strftime("run-%Y%m%d-%H%M%S")

# Shared verified-findings + oracle layer (additive, non-breaking). Every recorded finding is
# ALSO emitted as a CANDIDATE into an oracle-gated store; an out-of-band Verifier later moves it
# candidate -> verified/rejected via a ground-truth oracle, and reports/scores count only verified.
# See verified_findings.py (shared with ExploitGym). Falls back silently if unavailable.
try:
    from verified_findings import FindingStore as _VFStore, Finding as _VFFinding
    _VF = _VFStore(os.path.join(HERE, "aegis_operator_findings.jsonl"))
except Exception:
    _VF, _VFFinding = None, None

def _load_ledger():
    try:
        d = json.load(open(LEDGER_FILE, encoding="utf-8"))
        return d if isinstance(d, list) else []
    except Exception:
        return []

def _append_ledger(entry):
    entry = {"ts": time.strftime("%Y-%m-%d %H:%M"), "run": _RUN_ID, **entry}
    led = _load_ledger()
    led.append(entry)
    led = led[-2000:]
    try:
        tmp = LEDGER_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(led, f, indent=2)
        os.replace(tmp, LEDGER_FILE)
    except Exception as e:
        return {"error": repr(e)[:150]}
    return {"ok": True, "entries_this_run": sum(1 for e in led if e.get("run") == _RUN_ID)}

def t_record_finding(title, severity="unknown", principal="", endpoint="", evidence="", status="confirmed"):
    """Record ONE finding to the durable ledger the MOMENT you confirm it (do not wait for the report).
    Survives context compaction. severity=critical|high|medium|low|info; principal=who achieved it
    (unauth|technician|owner|external); status=confirmed|candidate|clean ('clean' = a vector you tested
    that HELD, worth recording so the final report can say what was checked)."""
    res = _append_ledger({"kind": "finding", "title": str(title)[:200], "severity": severity,
                          "principal": principal, "endpoint": str(endpoint)[:200],
                          "evidence": str(evidence)[:600], "status": status})
    # Also emit as a CANDIDATE into the oracle-gated store (verified separately, out-of-band).
    if _VF is not None:
        try:
            _VF.record_candidate(_VFFinding(
                claim_type=str(title)[:60], summary=str(title)[:200], severity=severity,
                run_id=_RUN_ID, evidence=[{"kind": "note", "detail": str(evidence)[:600]}],
                coverage_tags=([f"surface:{str(endpoint)[:120]}"] if endpoint else []),
                provenance={"provider": "deepseek", "principal": principal, "status_claimed": status}))
        except Exception:
            pass
    return json.dumps({"recorded": "finding", "title": title, **res,
                       "note": "also recorded as a candidate in the oracle-gated store; run the verifier to confirm"})

def t_chain_state(gained="", next_step="", note=""):
    """Record exploit-CHAIN progress: what access/privilege you currently HOLD (gained), the next pivot
    (next_step), and any linking detail (note). Call each time you gain access or complete a pivot so a
    multi-stage compromise survives context compaction and later steps can build on earlier ones."""
    res = _append_ledger({"kind": "chain", "gained": str(gained)[:400],
                          "next_step": str(next_step)[:300], "note": str(note)[:400]})
    return json.dumps({"recorded": "chain_state", **res})

def t_read_ledger(all_runs=False):
    """Return the findings/chain ledger for THIS assessment (all_runs=true for every run)."""
    led = _load_ledger()
    if not all_runs:
        led = [e for e in led if e.get("run") == _RUN_ID]
    return json.dumps({"count": len(led), "entries": led[-80:]})

def _ledger_block():
    """Verbatim ledger snapshot injected after compaction / into the report so nothing is folded away."""
    led = [e for e in _load_ledger() if e.get("run") == _RUN_ID]
    if not led:
        return ""
    finds = [e for e in led if e.get("kind") == "finding"]
    chain = [e for e in led if e.get("kind") == "chain"]
    lines = ["\n\n[LEDGER -- confirmed findings & chain state, PRESERVED across compaction; build on these, do NOT re-derive]"]
    for e in finds[-30:]:
        ev = f" :: {e.get('evidence','')}" if e.get("evidence") else ""
        lines.append(f"- FINDING [{e.get('severity','?')}/{e.get('status','?')}] "
                     f"{e.get('principal','')} {e.get('title','')} @ {e.get('endpoint','')}{ev}")
    if chain:
        c = chain[-1]
        lines.append(f"- CHAIN NOW: hold=[{c.get('gained','')}] next=[{c.get('next_step','')}] {c.get('note','')}")
    return "\n".join(lines)

# ---- atomic multi-spot edit (parity with robust editing) ----
def t_multi_edit(path, edits):
    """Apply several edits to ONE file atomically (all-or-nothing). edits = [{old_string, new_string}, ...];
    each old_string must match uniquely. Preferred over repeated apply_edit for multi-spot fixes."""
    p, err = _safe_repo_path(path)
    if err:
        return json.dumps({"error": err})
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})
    new = data
    for k, ed in enumerate(edits or []):
        old_s, new_s = ed.get("old_string", ""), ed.get("new_string", "")
        c = new.count(old_s) if old_s else 0
        if c == 0:
            return json.dumps({"error": f"edit #{k+1}: old_string not found (no changes applied)"})
        if c > 1:
            return json.dumps({"error": f"edit #{k+1}: old_string matches {c} times; add context to make it unique"})
        new = new.replace(old_s, new_s)
    _backup(p)
    with open(p, "w", encoding="utf-8") as f:
        f.write(new)
    return json.dumps({"edited": p, "edits_applied": len(edits or []), "revertable": True})

def _multi_edit_preview(path, edits):
    p, err = _safe_repo_path(path)
    if err:
        return f"(cannot preview: {err})"
    try:
        old = open(p, encoding="utf-8", errors="replace").read()
    except Exception:
        old = ""
    new = old
    for ed in (edits or []):
        os_, ns_ = ed.get("old_string", ""), ed.get("new_string", "")
        if os_ and new.count(os_) == 1:
            new = new.replace(os_, ns_)
    diff = "\n".join(difflib.unified_diff(old.splitlines(), new.splitlines(),
                                          fromfile="before", tofile="after", lineterm=""))
    return diff[:4000] or "(no change)"

# ---- parallel fan-out: run several READ-ONLY sub-agents concurrently (capable machine) ----
import concurrent.futures as _cf
_PARALLEL_MAX = 6
_READONLY_SUBAGENT_TOOLS = ["read_file", "list_files", "search_code", "search_docs", "get_status",
                            "read_task_context", "read_process_output", "recall", "finalize_report", "finish"]

def t_spawn_agents_parallel(tasks):
    """Fan out: run several READ-ONLY sub-agents CONCURRENTLY (parallel research / review / audit) and gather
    their summaries. Read-only only, so there is no approval-gate contention. Subject to the sub-agent budget."""
    global _SUBAGENT_COUNT
    if not _CTX:
        return json.dumps({"error": "no agent context"})
    if _CTX.get("depth", 0) >= 1:
        return json.dumps({"error": "parallel fan-out only from the top level (no nested fan-out)"})
    tasks = [str(t) for t in (tasks or []) if str(t).strip()][:_PARALLEL_MAX]
    if not tasks:
        return json.dumps({"error": "no tasks given"})
    budget_left = _SUBAGENT_MAX - _SUBAGENT_COUNT
    tasks = tasks[:max(0, budget_left)]
    if not tasks:
        return json.dumps({"error": f"sub-agent budget exhausted ({_SUBAGENT_MAX} max this session)"})
    _SUBAGENT_COUNT += len(tasks)
    sub_sys = ("You are a focused READ-ONLY research/review sub-agent. Investigate ONLY the delegated task with "
               "the read-only tools, then call finish() with a concise, evidence-cited summary. You cannot modify "
               "anything.")

    def _one(idx, task):
        msgs = [{"role": "system", "content": sub_sys}, {"role": "user", "content": task}]
        try:
            summ = _agent_loop(_CTX["client"], _CTX["model"], _CTX["thinking"], msgs,
                               _READONLY_SUBAGENT_TOOLS, max_iter=_CTX.get("sub_max_iter", 8),
                               gate=_CTX["gate"], depth=_CTX.get("depth", 0) + 1, tag=f"  [p{idx}", quiet=True)
        except Exception as e:
            summ = f"[error: {repr(e)[:120]}]"
        return {"task": task[:140], "summary": summ or "(no summary)"}

    print(f"[fan-out] running {len(tasks)} read-only sub-agents in parallel...", flush=True)
    with _cf.ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        results = list(ex.map(lambda a: _one(*a), list(enumerate(tasks, 1))))
    return json.dumps({"parallel_results": results})

# ---- web research (parity with WebFetch) -- gated GET-only, no data upload ----
def t_fetch_url(url, max_chars=6000):
    """GET a public URL and return readable text (JS NOT executed; use render_page for JS). Gated."""
    if not re.match(r'^https?://', str(url), re.I):
        return json.dumps({"error": "only http(s) URLs allowed"})
    try:
        r = requests.get(url, timeout=25, headers={"User-Agent": "aegis_operator/1.0 (+research)"})
        t = re.sub(r'<script.*?</script>', ' ', r.text, flags=re.S | re.I)
        t = re.sub(r'<style.*?</style>', ' ', t, flags=re.S | re.I)
        t = re.sub(r'<[^>]+>', ' ', t)
        t = re.sub(r'\s+', ' ', t).strip()
        return json.dumps({"url": url, "status": r.status_code,
                           "content_type": r.headers.get("content-type", ""), "text": t[:max_chars]})
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})

def t_render_page(url):
    """Render a JS page headlessly (Kali chromium) and return the DOM text. Gated (egress via VPN)."""
    if not re.match(r'^https?://', str(url), re.I):
        return json.dumps({"error": "only http(s) URLs allowed"})
    cmd = (f"timeout 40 chromium --headless --no-sandbox --disable-gpu --dump-dom '{url}' 2>/dev/null || "
           f"timeout 40 chromium-browser --headless --no-sandbox --disable-gpu --dump-dom '{url}' 2>/dev/null")
    try:
        p = subprocess.run(["wsl", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc", cmd],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=70)
        dom = re.sub(r'<[^>]+>', ' ', p.stdout)
        dom = re.sub(r'\s+', ' ', dom).strip()
        if not dom:
            return json.dumps({"note": "no DOM (chromium may be absent in Kali); fall back to fetch_url",
                               "stderr": (p.stderr or "")[-300:]})
        return json.dumps({"url": url, "dom_text": dom[:6000]})
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})

# ---- git (parity with git tooling): find culprits + safe checkpoints ----
def _git(args, timeout=60):
    return subprocess.run(["git", "-C", REPO] + args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)

def t_git_status():
    p = _git(["status", "-b", "--porcelain"])
    return json.dumps({"stdout": p.stdout[-3000:], "stderr": p.stderr[-300:], "rc": p.returncode})

def t_git_diff(path=None):
    p = _git(["diff"] + ([path] if path else []))
    return json.dumps({"stdout": p.stdout[-6000:], "rc": p.returncode})

def t_git_log(n=10, path=None):
    p = _git(["log", f"-n{int(n)}", "--oneline"] + (["--", path] if path else []))
    return json.dumps({"stdout": p.stdout[-4000:], "rc": p.returncode})

def t_git_commit(message):
    _git(["add", "-A"])
    c = _git(["commit", "-m", str(message)[:500]])
    return json.dumps({"stdout": (c.stdout + c.stderr)[-1500:], "rc": c.returncode})

# ---- Kali tool CO-CHECK (read-only; never installs) ----
def t_check_kali_tools(tools):
    """READ-ONLY co-check: report which CLI tools are present/missing in the Kali WSL distro, using a LOGIN
    shell so the PATH matches what the executor actually sees. This NEVER installs anything -- it only reports.
    If a task genuinely needs a missing tool, propose installing it with a GATED run_command; do not
    pre-install or overwrite tools before a test."""
    tl = [t for t in (str(x).strip() for x in (tools or [])) if re.fullmatch(r'[A-Za-z0-9._-]+', t or "")][:40]
    if not tl:
        return json.dumps({"error": "pass a list of plain tool names (letters/digits/._- only)"})
    inner = "; ".join(f'command -v {t} >/dev/null 2>&1 && echo "OK {t}" || echo "MISS {t}"' for t in tl)
    try:
        p = subprocess.run(["wsl", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc", inner],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})
    present = [ln[3:] for ln in p.stdout.splitlines() if ln.startswith("OK ")]
    missing = [ln[5:] for ln in p.stdout.splitlines() if ln.startswith("MISS ")]
    return json.dumps({"present": present, "missing": missing,
                       "note": ("read-only check; install a missing tool ONLY if a task needs it, via a gated "
                                "run_command (apt/pip/go) -- do not pre-install or overwrite before a test")})

# ---- custom tooling: run inside Kali + install a co-pilot-authored tool ----
def _win_to_wsl(p):
    p = os.path.abspath(p)
    drive, rest = os.path.splitdrive(p)
    return "/mnt/" + (drive[0].lower() if drive else "c") + rest.replace("\\", "/")

def t_run_in_kali(command):
    """Run a shell command INSIDE the Kali WSL distro (login shell, so PATH + VPN egress match the executor).
    Gated. Use this to TEST a custom PoC/checker against an AUTHORIZED target, or to build tooling in Kali."""
    try:
        p = subprocess.run(["wsl", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc", command],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=240)
        return json.dumps({"stdout": p.stdout[-4000:], "stderr": p.stderr[-1000:], "rc": p.returncode})
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})

def t_run_tool(tool, args=""):
    """Run an external pentest TOOL by name, AUTO-ROUTING to the distro that has it: present in Kali -> Kali;
    MISSING -> the BlackArch container (prebuilt via pacman, native env), NOT ported into Kali. Gated. Use for
    any off-the-shelf CLI security tool (feroxbuster, katana, dalfox, nuclei, sn0int, ...); `args` is the arg
    string (e.g. '-u https://target -k'). This is the LAZY tool-provisioning hook -- a missing tool is fetched
    on demand in BlackArch and run there. Non-destructive scope still applies to what you point it at."""
    try:
        import distro_backend
        r = distro_backend.run_tool(tool, args)
        return json.dumps({"backend": r["backend"], "rc": r["rc"],
                           "stdout": r["stdout"][-4000:], "stderr": r["stderr"][-1000:]})
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})


def t_install_kali_tool(name, content, interpreter="python3", pip_deps=None):
    """Install a co-pilot-AUTHORED tool into Kali's /usr/local/bin so it becomes a callable command. Stages the
    script in the repo (version-controllable), then copies it into Kali, strips CRLF, chmod +x, and optionally
    pip-installs deps. Gated -- for a novel checker/PoC when no off-the-shelf tool exists."""
    if not re.fullmatch(r'[A-Za-z0-9._-]+', str(name) or ""):
        return json.dumps({"error": "invalid tool name (letters/digits/._- only)"})
    shebang = {"python3": "#!/usr/bin/env python3", "bash": "#!/usr/bin/env bash",
               "sh": "#!/bin/sh"}.get(interpreter, "#!/usr/bin/env python3")
    body = content if str(content).startswith("#!") else shebang + "\n" + str(content)
    stage_dir = os.path.join(REPO, ".ds_kali_tools")
    try:
        os.makedirs(stage_dir, exist_ok=True)
        stage = os.path.join(stage_dir, name)
        with open(stage, "w", encoding="utf-8", newline="\n") as f:
            f.write(body)
    except Exception as e:
        return json.dumps({"error": f"stage write failed: {repr(e)[:150]}"})
    src = _win_to_wsl(stage)
    steps = [f"cp '{src}' /usr/local/bin/{name}", f"sed -i 's/\\r$//' /usr/local/bin/{name}",
             f"chmod +x /usr/local/bin/{name}"]
    if pip_deps:
        pkgs = " ".join(d for d in pip_deps if re.fullmatch(r'[A-Za-z0-9._\-\[\]=<>]+', str(d)))
        if pkgs:
            steps.append(f"pip install --quiet {pkgs} 2>&1 | tail -3")
    steps.append(f"command -v {name} && head -1 /usr/local/bin/{name}")
    try:
        p = subprocess.run(["wsl", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc", " && ".join(steps)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})
    return json.dumps({"installed": name, "staged_at": stage, "kali_path": f"/usr/local/bin/{name}",
                       "stdout": p.stdout[-1500:], "stderr": p.stderr[-500:], "rc": p.returncode})

def t_rag_search(query, k=5):
    """Search the local Kali-resident vulnerability RAG (NVD + CISA KEV + EPSS + Exploit-DB + the legacy
    Aegis corpus) at /opt/aegis-rag. FULLY OFFLINE: runs rag_query.py against local SQLite inside Kali,
    so the query never leaves the box. CVE id -> exact enriched record; keywords -> KEV/EPSS/CVSS-ranked search.
    Read-only, ungated."""
    try:
        k = int(k)
    except Exception:
        k = 5
    q = "'" + str(query).replace("'", "'\\''") + "'"   # POSIX single-quote escape
    cmd = f"python3 /opt/aegis-rag/rag_query.py --json --k {k} {q}"
    try:
        p = subprocess.run(["wsl", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc", cmd],
                           capture_output=True, timeout=120)
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})
    out = (p.stdout or b"").decode("utf-8", "replace").strip()
    err = (p.stderr or b"").decode("utf-8", "replace")
    if p.returncode != 0 or not out:
        return json.dumps({"error": (err or f"exit {p.returncode}")[:300], "raw": out[:300]})
    try:
        return json.dumps(json.loads(out.splitlines()[-1]), ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"bad JSON from rag_query: {e}", "raw": out[:300]})

def t_exploit_search(query, sources="rag,sploitus,searchsploit", k=6):
    """LIVE exploit search across aggregators, keyed on a fingerprinted product+version or a CVE.
    Complements rag_search (offline CVE store) with query-time exploit ENGINES. Sources:
      rag (offline local), searchsploit (local Exploit-DB CLI), sploitus (sploitus.com API),
      github (needs GITHUB_TOKEN), packetstorm (best-effort). 'rag'+'searchsploit' are OFFLINE
      (always work); the others reach the internet (blocked under ExploitGym containment unless
      that host is allow-listed for the run). Read-only reconnaissance against public exploit DBs.
    Use after fingerprinting a component: exploit_search("Apache Struts 2.5.10") or a CVE id."""
    try:
        k = int(k)
    except Exception:
        k = 6
    q = "'" + str(query).replace("'", "'\\''") + "'"
    srcs = re.sub(r"[^a-z,]", "", str(sources).lower()) or "rag,sploitus,searchsploit"
    cmd = f"python3 /opt/aegis-rag/exploit_search.py {q} --sources {srcs} --k {k} --json"
    try:
        p = subprocess.run(["wsl", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc", cmd],
                           capture_output=True, timeout=120)
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})
    out = (p.stdout or b"").decode("utf-8", "replace").strip()
    err = (p.stderr or b"").decode("utf-8", "replace")
    if not out:
        return json.dumps({"error": (err or f"exit {p.returncode}")[:300]})
    try:
        return json.dumps(json.loads(out), ensure_ascii=False)[:6000]
    except Exception:
        return json.dumps({"raw": out[:4000]})

_PLAN_DECOMPOSE_SYS = (
    "You are a penetration-test PLANNER. Break the objective into a SMALL number of SUBSTANTIVE "
    "sub-tasks (aim for 3-6 total, never more than 6 per level). "
    "Return ONLY a JSON array (no prose). Each element: "
    '{"abstract": short-name, "description": what-to-do, "verification": how-we-know-it-passed, '
    '"deps": [abstract-of-prerequisite, ...]}.\n'
    "CRITICAL -- each sub-task must be a MEANINGFUL testing goal that its executor accomplishes with "
    "MANY commands in one go, e.g. 'enumerate all /api/* endpoints and record each status+shape', "
    "'log in as owner then as a technician and map the full RBAC matrix', 'probe every user-controllable "
    "parameter for SQLi/NoSQLi/command injection', 'scan the origin host and test for direct-to-origin "
    "bypass'. A single executor can run dozens of commands (curl/nmap/etc.) itself.\n"
    "DO NOT emit trivial one-command micro-tasks -- NEVER make a sub-task out of: checking a URL's "
    "syntax, resolving DNS, opening a TCP socket, a reachability ping, creating a scratch directory, or "
    "a single fetch. Those are STEPS the executor does INSIDE a larger sub-task, never their own node. "
    "Return [] (atomic -- do it directly) whenever the whole objective can be done with a handful of "
    "commands. Only decompose when a task is genuinely large, and only re-decompose a child if IT is large.")

_PLAN_EXEC_SYS = (
    "You are a penetration-test EXECUTOR working ONE sub-task. Use the available tools "
    "(all behind the human approval gate) to accomplish it against the AUTHORIZED target, "
    "gather real evidence, and DO NOT fabricate. When done, call finish(summary=...) with the "
    "concrete evidence/result. If it cannot be done, finish() and say so honestly.\n"
    "GUARDRAILS (always apply):\n"
    "1. SHELL: for shell commands, curl, network requests, and Linux tooling against a target, "
    "use run_in_kali (a Linux bash shell). Do NOT use run_command for these -- it is the Windows "
    "host cmd shell and will echo bash syntax back instead of executing it. Reserve run_command "
    "for genuine Windows-host tasks (git, tests, restart scripts).\n"
    "2. CREDENTIALS: use ONLY the credentials, files, and paths the task explicitly provides. "
    "NEVER hunt the filesystem, registry, or environment for tokens/secrets, and never read or "
    "decode credential files you were not told to use. Never print secret values.\n"
    "3. NO THRASHING: if a command fails, fix that specific command; do not repeat the same "
    "failing approach or drift into unrelated exploration/credential-hunting.\n"
    "4. REMOTE TARGET, NOT THE LOCAL HOST: the target is the REMOTE system named in the objective/"
    "CONTEXT (a URL or IP). The Kali box you run commands on is only your attack PLATFORM -- never "
    "the target. Do NOT enumerate or 'test' the local machine (no pwd, id, whoami, sudo -l, mount, or "
    "poking /, /home, /var/www to orient yourself). If you're unsure what the target is, read it from "
    "the CONTEXT block; every action must hit the remote target (e.g. curl/nmap against that URL/IP).")

_PLAN_VERIFY_SYS = (
    "You judge whether a sub-task's result meets its acceptance criteria. Be strict and honest: "
    "'accepted' only if the evidence actually satisfies the criteria. Return ONLY JSON: "
    '{"accepted": bool, "need_turn": bool, "reason": str}. need_turn=true means "retry could help", '
    "false means a hard no / retry is pointless.")


def _ds_chat_json(system, user, default):
    """One non-thinking chat call that must return JSON; tolerant extraction. For planner
    decompose/verify. Returns parsed JSON or `default` on failure."""
    import re as _re
    if not _CTX or not _CTX.get("client"):
        return default
    try:
        resp = _create(_CTX["client"],
            model=_CTX.get("model", "deepseek-v4-pro"),
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=0.1, max_tokens=1200,
            extra_body={"thinking": {"type": "disabled"}},
        )
        txt = (resp.choices[0].message.content or "").strip()
    except Exception:
        return default
    # strip code fences, then grab the first {...} or [...] span
    txt = _re.sub(r"^```(?:json)?|```$", "", txt.strip(), flags=_re.MULTILINE).strip()
    for pat in (r"\[.*\]", r"\{.*\}"):
        m = _re.search(pat, txt, _re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                continue
    return default


def t_plan_and_execute(objective, verification="", bounded=False, exec_max_iter=6):
    """Decompose an objective into a verified task GRAPH and drive it: for each sub-task,
    run a gated executor sub-agent, then grade the result against its acceptance criteria and
    accept / retry / re-branch. Every action still passes the human approval gate.

    DeepSeek side runs UNBOUNDED by default (relaxed planning caps for benchmarking vs the
    bounded aegis side); only hard runaway guards (node ceiling + wall-clock) remain.
    Set bounded=True for an A/B run with the tight caps."""
    from planner_core import Planner, PlannerConfig
    cfg = PlannerConfig.bounded_profile() if bounded else PlannerConfig.unbounded_profile()

    def decompose(node, feedback):
        user = (f"Objective: {node.abstract}\nDetails: {node.description}\n"
                f"Acceptance: {node.verification}\n"
                + (f"Replan feedback: {feedback}\n" if feedback else "")
                + "Return the JSON array of sub-tasks (or [] if atomic).")
        arr = _ds_chat_json(_PLAN_DECOMPOSE_SYS, user, default=[])
        return arr if isinstance(arr, list) else []

    def execute(node, context=""):
        ctx_block = (f"\n\nCONTEXT (authoritative -- use it, do NOT re-derive it):\n{context}"
                     if context else "")
        msgs = [{"role": "system", "content": _PLAN_EXEC_SYS},
                {"role": "user", "content": f"Sub-task: {node.abstract}\nDetails: {node.description}\n"
                                            f"Acceptance criteria: {node.verification}{ctx_block}"}]
        allowed = [n for n in TOOLS if n not in
                   ("plan_and_execute", "spawn_subagent", "spawn_agents_parallel")]
        summ = _agent_loop(_CTX["client"], _CTX["model"], _CTX["thinking"], msgs, allowed,
                           max_iter=int(exec_max_iter), gate=_CTX["gate"],
                           depth=_CTX.get("depth", 0) + 1, tag="  [plan-exec")
        return summ or "(executor returned no summary)"

    def verify(node, result):
        user = (f"Sub-task: {node.abstract}\nAcceptance criteria: {node.verification}\n"
                f"Result/evidence:\n{result[:3000]}")
        v = _ds_chat_json(_PLAN_VERIFY_SYS, user, default={"accepted": False, "need_turn": True, "reason": "unverified"})
        if not isinstance(v, dict):
            v = {"accepted": False, "need_turn": True, "reason": "bad verifier output"}
        return v

    planner = Planner(cfg, decompose, execute, verify, logger=lambda m: print(m, flush=True))
    out = planner.run(objective, verification)
    # keep the payload lean for the tool channel: drop the full graph dump
    out.pop("config", None)
    slim_graph = [{"abstract": n["abstract"], "status": n["status"], "attempts": n["attempts"],
                   "depth": n["depth"], "reason": n["reason"][:160]} for n in out.get("graph", [])]
    out["graph"] = slim_graph
    return json.dumps(out, ensure_ascii=False)


def t_finish(summary=""):
    return json.dumps({"finished": True, "summary": summary})


def t_remediation(emit_fixes=True, panel="ds,sol,cf,qwen"):
    """STAGE 10 (END OF PIPELINE): run the remediation round over THIS run's oracle-VERIFIED findings.
    Posts each confirmed weakness to the board; the whole panel proposes the fix (attributed + consensus);
    routes known-cve -> ADMIN framework/dependency update, novel -> CODE writer/improver fix; --emit-fixes
    hands each to the code bench for a concrete patch. Writes the two-track remediation_report.md and chains
    the remediation onto the findings ledger. MIRROR-SIDE ONLY: fixes target the mirror twin (where findings
    were confirmed) for review + further testing there; proposed, NEVER auto-applied, NEVER run against the
    real target. Non-destructive/advisory. Call this once you have VERIFIED findings (typically before finish)."""
    ledger = os.path.join(HERE, "aegis_operator_findings.jsonl")
    script = os.path.join(HERE, "remediation_board.py")
    if not os.path.exists(ledger):
        return json.dumps({"ok": False, "note": "no findings ledger yet -- nothing verified to remediate"})
    cmd = [sys.executable, script, "--findings", ledger, "--panel", panel, "--synthesize", "--write-ledger"]
    if emit_fixes:
        cmd.append("--emit-fixes")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=1800)
    except Exception as e:
        return json.dumps({"ok": False, "error": str(e)})
    report = os.path.join(HERE, "remediation_report.md")
    return json.dumps({"ok": p.returncode == 0,
                       "report": report if os.path.exists(report) else "",
                       "stdout_tail": (p.stdout or "")[-1500:],
                       "stderr_tail": (p.stderr or "")[-400:]})


def t_port_fix_to_mirror(finding="", transport="wsl", container="", dest=""):
    """Deliver the code writer/improver's emitted patch (operator/remediation_fixes/) INTO the mirror so the
    improved code can be tested there. The mirror may run ANY distro (Ubuntu/openSUSE/Kali/...) or a Docker
    image. Transports: 'wsl' (copy into the WSL mirror distro -- set --distro / AEGIS_MIRROR_DISTRO), 'docker'
    (docker cp into a running mirror container -- needs container), 'dir' (copy to a staging dir / USB mount
    for hand-carry -- needs dest). MIRROR-side only: STAGES the patch (non-destructive); does NOT apply it and
    NEVER touches the real target. Returns the in-mirror paths + the apply command to run there, then re-run
    the finding's exploit/oracle to confirm the gap is closed. Run remediation(emit_fixes=true) first."""
    script = os.path.join(HERE, "remediation_port.py")
    cmd = [sys.executable, script, "--transport", transport]
    if finding:
        cmd += ["--finding", finding]
    if container:
        cmd += ["--container", container]
    if dest:
        cmd += ["--dest", dest]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=300)
    except Exception as e:
        return json.dumps({"ok": False, "error": str(e)})
    return json.dumps({"ok": p.returncode == 0, "stdout_tail": (p.stdout or "")[-1800:],
                       "stderr_tail": (p.stderr or "")[-400:]})


def t_verify_fix_on_mirror(transport="wsl", mirror_repo="", repro_map="", allow_download=False,
                           health_cmd="", repair=False, container="", extra=""):
    """STAGE-10 CLOSED LOOP (mirror-only): snapshot the mirror, APPLY the fix on it (code patch + system/
    framework bump), then RE-RUN each finding's exploit/oracle on the patched system -> CLOSED / STILL-OPEN /
    BROKE-AFTER-UPDATE, then restore the snapshot. allow_download permits fetching the framework update onto
    the mirror (authorized mirror-side egress). health_cmd checks the app still runs after the update; repair
    runs the board-driven DS-vs-Qwen fix if the update broke the code. Real target is NEVER patched/re-tested.
    Run remediation(emit_fixes=true) + port_fix_to_mirror first. extra = extra CLI flags string."""
    script = os.path.join(HERE, "remediation_verify.py")
    cmd = [sys.executable, script, "--transport", transport]
    if mirror_repo:
        cmd += ["--mirror-repo", mirror_repo]
    if repro_map:
        cmd += ["--repro-map", repro_map]
    if container:
        cmd += ["--container", container]
    if health_cmd:
        cmd += ["--health-cmd", health_cmd]
    if allow_download:
        cmd += ["--allow-download"]
    if repair:
        cmd += ["--repair"]
    if extra:
        cmd += extra.split()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=3600)
    except Exception as e:
        return json.dumps({"ok": False, "error": str(e)})
    return json.dumps({"ok": p.returncode == 0, "stdout_tail": (p.stdout or "")[-2200:],
                       "stderr_tail": (p.stderr or "")[-400:]})

# tool registry: name -> (fn, readonly, spec)
def _spec(name, desc, props, required):
    return {"type": "function", "function": {"name": name, "description": desc,
            "parameters": {"type": "object", "properties": props, "required": required}}}

# ================= TARGET MIRRORING (fingerprint an external stack -> local twin) =================
# Adds a "test the target" vs "test a local mirror of the target" choice. --target-mode selects it.
TARGET_MODE = "live"          # live | mirror | split  (set from --target-mode)
TWIN_BASE_PORT = 9000

def _twins_dir():
    d = os.path.join(REPO, ".ds_twins")
    os.makedirs(d, exist_ok=True)
    return d

def _kali(cmd, timeout=600):
    return subprocess.run(["wsl", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc", cmd],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)

def _mode_policy(mode):
    if mode == "mirror":
        return ("\n\nTARGET MODE = MIRROR: do NOT run intrusive tests against the live target. First "
                "fingerprint_target(url) the real host (light recon ONLY), then provision_twin(manifest) to "
                "build a LOCAL twin, then run ALL exploitation/chaining against the returned twin_url. The "
                "live host receives only the light fingerprint traffic.")
    if mode == "split":
        return ("\n\nTARGET MODE = SPLIT: recon/fingerprint the LIVE target (light, safe); build a twin with "
                "provision_twin and do all INTRUSIVE testing against the twin_url; then, only for findings "
                "worth confirming, run ONE minimal, non-destructive, gated check against the live target.")
    return ("\n\nTARGET MODE = LIVE: test the real target directly (VPN-gated; every mutating action gated). "
            "You may still use fingerprint_target/provision_twin to work against a safe twin instead.")

def t_fingerprint_target(url, deep=False):
    """LIGHT, non-intrusive fingerprint of an external target (browser-grade traffic only): server,
    language, framework/CMS + version, WordPress plugins, and PHP/Symfony tells. Egress goes through Kali
    (VPN). Writes a stack MANIFEST (.ds_twins/<host>/manifest.json) that provision_twin() rebuilds
    locally. Does NOT exploit, brute force, or aggressively scan -- it is safe recon."""
    if not re.match(r'^https?://', str(url), re.I):
        return json.dumps({"error": "only http(s) URLs allowed"})
    u = url.replace('"', '').replace('$', '').replace("'", "").rstrip('/')
    host = re.sub(r'^https?://', '', u).split('/')[0]
    # NOTE: bash $VAR expansion is unreliable inside `bash -lc "<string>"` via wsl.exe (it gets eaten),
    # so the URL is inlined literally into every curl and there are NO bash variables in this probe.
    probe = ("echo '<<<HDR>>>'; curl -sSL -m 20 -D - -o /tmp/fp.html '%(u)s' 2>&1\n"
             "echo '<<<BODY>>>'; head -c 60000 /tmp/fp.html\n"
             "echo; echo '<<<WPJSON>>>'; curl -sS -m 15 '%(u)s/wp-json' 2>/dev/null | head -c 1500\n"
             "echo; echo '<<<README>>>'; curl -sS -m 15 '%(u)s/readme.html' 2>/dev/null | grep -oi 'Version [0-9.]*' | head -1\n"
             "echo; echo '<<<PHPINFO>>>';"
             " echo '/phpinfo.php:'; curl -sS -m 12 '%(u)s/phpinfo.php' 2>/dev/null | grep -oiE 'PHP Version [0-9.]+' | head -1;"
             " echo '/p.php:'; curl -sS -m 12 '%(u)s/p.php' 2>/dev/null | grep -oiE 'PHP Version [0-9.]+' | head -1;"
             " echo '/info.php:'; curl -sS -m 12 '%(u)s/info.php' 2>/dev/null | grep -oiE 'PHP Version [0-9.]+' | head -1\n"
             "echo; echo '<<<SYMFONY>>>';"
             " echo -n '/app_dev.php:'; curl -sS -m 12 -o /dev/null -w '%%{http_code}' '%(u)s/app_dev.php' 2>/dev/null; echo;"
             " echo -n '/app.php:'; curl -sS -m 12 -o /dev/null -w '%%{http_code}' '%(u)s/app.php' 2>/dev/null; echo\n"
             "echo; echo '<<<ROBOTS>>>'; curl -sS -m 15 '%(u)s/robots.txt' 2>/dev/null | head -c 300\n") % {"u": u}
    try:
        raw = _kali(probe, timeout=160).stdout
    except Exception as e:
        return json.dumps({"error": repr(e)[:200]})
    def seg(a):
        try: return raw.split('<<<%s>>>' % a, 1)[1].split('<<<', 1)[0]
        except Exception: return ""
    hdr, body = seg('HDR'), seg('BODY')
    wpjson, readme, phpinfo, symfony, robots = seg('WPJSON'), seg('README'), seg('PHPINFO'), seg('SYMFONY'), seg('ROBOTS')
    def hv(n):
        m = re.search(r'(?im)^%s:\s*(.+)$' % re.escape(n), hdr); return m.group(1).strip() if m else ""
    server, powered = hv('Server'), hv('X-Powered-By')
    cookies = re.findall(r'(?im)^set-cookie:\s*([^=;]+)=', hdr)
    ck = ' '.join(cookies)
    tech, versions, cms, notes, exposures = set(), {}, {}, [], []
    ms = re.search(r'apache/([\d.]+)', server, re.I)
    if 'apache' in server.lower(): tech.add('apache'); versions['apache'] = ms.group(1) if ms else ''
    mn = re.search(r'nginx/([\d.]+)', server, re.I)
    if 'nginx' in server.lower(): tech.add('nginx'); versions['nginx'] = mn.group(1) if mn else ''
    # PHP version: header first, then exposed phpinfo
    mp = re.search(r'php/([\d.]+)', powered, re.I)
    pi = re.search(r'PHP Version ([\d.]+)', phpinfo, re.I)
    if mp or pi or 'PHPSESSID' in ck:
        tech.add('php'); versions['php'] = (mp.group(1) if mp else (pi.group(1) if pi else ''))
    if pi:
        for m in re.finditer(r'(/[a-z_]+\.php):\s*PHP Version', phpinfo, re.I):
            exposures.append('exposed phpinfo() at %s' % m.group(1))
    for m in re.finditer(r'(/app_dev\.php|/app\.php):(\d{3})', symfony):
        if m.group(2) == '200':
            tech.add('symfony'); exposures.append('Symfony front controller reachable at %s (profiler risk)' % m.group(1))
    if 'JSESSIONID' in ck or 'coyote' in server.lower() or 'tomcat' in (server + body).lower(): tech.add('java-tomcat')
    if 'csrftoken' in ck or ('sessionid' in ck and 'django' in body.lower()): tech.add('django')
    if 'express' in powered.lower() or 'connect.sid' in ck: tech.add('node-express')
    if 'laravel_session' in ck: tech.add('php-laravel')
    mg = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    gen = mg.group(1) if mg else hv('X-Generator')
    if ('wp-content' in body) or ('wp-includes' in body) or wpjson.strip().startswith('{') or 'wordpress' in gen.lower():
        tech.add('wordpress'); tech.add('php')
        wv = re.search(r'wordpress[ /]([\d.]+)', gen, re.I) or re.search(r'Version ([\d.]+)', readme, re.I)
        plugins = sorted(set(re.findall(r'/wp-content/plugins/([a-z0-9\-_]+)/', body, re.I)))
        pver = {}
        for m in re.finditer(r'/wp-content/plugins/([a-z0-9\-_]+)/[^"\']*?\?ver=([\d.]+)', body, re.I):
            pver.setdefault(m.group(1), m.group(2))
        cms = {'name': 'wordpress', 'version': (wv.group(1) if wv else ''),
               'plugins': [{'slug': s, 'version': pver.get(s, '')} for s in plugins][:25]}
    manifest = {'url': u, 'host': host, 'server': server, 'x_powered_by': powered, 'cookies': cookies,
                'generator': gen, 'tech': sorted(tech), 'versions': versions, 'cms': cms,
                'exposures': exposures, 'robots_excerpt': robots.strip()[:300], 'notes': notes,
                'fidelity_note': 'Stack/versions/CMS/exposures only; custom app code, data and any WAF ruleset are NOT visible externally.'}
    # --- RAG is part of the fingerprint: auto-check each identified component against the local vuln DB ---
    # (NVD/KEV/EPSS/Exploit-DB). This makes "look up what is KNOWN-vulnerable vs what is PRESENT" a
    # deterministic step of fingerprinting, not something the operator has to remember to do.
    rag_terms = []
    for prod, ver in versions.items():
        t = ("%s %s" % (prod, ver)).strip()
        if t:
            rag_terms.append(t)
    if isinstance(cms, dict) and cms.get('name'):
        rag_terms.append(("%s %s" % (cms.get('name'), cms.get('version', ''))).strip())
        for pl in (cms.get('plugins') or [])[:3]:
            rag_terms.append(("wordpress %s %s" % (pl.get('slug', ''), pl.get('version', ''))).strip())
    if 'symfony' in tech and not any('symfony' in x for x in rag_terms):
        rag_terms.append('symfony')
    _seen = set()
    rag_terms = [t for t in rag_terms if t and not (t in _seen or _seen.add(t))][:6]
    known = []
    for term in rag_terms:
        try:
            r = json.loads(t_rag_search(term, 5))
        except Exception:
            continue
        items = r.get('items', []) if isinstance(r, dict) else []
        top = [{'cve_id': i.get('cve_id'), 'severity': i.get('severity'),
                'cvss': i.get('cvss_v3') or i.get('cvss'), 'epss': i.get('epss'),
                'kev': i.get('kev'), 'exploitdb_ids': i.get('exploitdb_ids')} for i in items[:5]]
        if top:
            known.append({'query': term, 'hits': top})
    manifest['known_vulns'] = known
    manifest['rag_note'] = (
        'Auto-queried the local vuln RAG per fingerprinted component. PROBE THESE NEXT '
        '(non-destructive), prioritising KEV / high-EPSS / Exploit-DB-PoC hits.'
        if known else
        'RAG returned no matches for the fingerprinted components (or RAG unavailable).')
    tdir = os.path.join(_twins_dir(), re.sub(r'[^A-Za-z0-9_.-]', '_', host))
    os.makedirs(tdir, exist_ok=True)
    mpath = os.path.join(tdir, 'manifest.json')
    with open(mpath, 'w', encoding='utf-8') as f: json.dump(manifest, f, indent=2)
    manifest['_manifest_path'] = mpath
    return json.dumps(manifest)[:8000]

_APACHE_VHOST = ("grep -q '^Listen __PORT__' /etc/apache2/ports.conf || echo 'Listen __PORT__' >> /etc/apache2/ports.conf\n"
                 "cat > /etc/apache2/sites-available/twin___NAME__.conf <<'VH'\n"
                 "<VirtualHost *:__PORT__>\n"
                 "    DocumentRoot __DROOT__\n"
                 "    <Directory __DROOT__>\n"
                 "        AllowOverride All\n"
                 "        Require all granted\n"
                 "    </Directory>\n"
                 "</VirtualHost>\n"
                 "VH\n"
                 "a2enmod php8.4 rewrite >/dev/null 2>&1 || a2enmod php rewrite >/dev/null 2>&1 || true\n"
                 "a2ensite twin___NAME__ >/dev/null 2>&1 || true\n"
                 "service apache2 restart >/dev/null 2>&1 || service apache2 start >/dev/null 2>&1\n")

_WP_TPL = ("service mariadb start >/dev/null 2>&1 || true\n"
           "mkdir -p __DROOT__\n"
           "mysql -e \"CREATE DATABASE IF NOT EXISTS __DBN__; CREATE USER IF NOT EXISTS '__DBN__'@'localhost' IDENTIFIED BY '__DBPASS__'; GRANT ALL ON __DBN__.* TO '__DBN__'@'localhost'; FLUSH PRIVILEGES;\"\n"
           "command -v wp >/dev/null 2>&1 || { curl -s -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x /usr/local/bin/wp; }\n"
           "cd __DROOT__ && wp core download --allow-root --force __VERFLAG__ >/dev/null 2>&1\n"
           "wp config create --allow-root --path=__DROOT__ --dbname=__DBN__ --dbuser=__DBN__ --dbpass='__DBPASS__' --dbhost=localhost --force >/dev/null 2>&1\n"
           "wp core install --allow-root --path=__DROOT__ --url=http://127.0.0.1:__PORT__ --title='Twin of __HOST__' --admin_user=admin --admin_password='__ADMINPASS__' --admin_email=admin@twin.test --skip-email >/dev/null 2>&1\n"
           "__PLUGINS__"
           "chown -R www-data:www-data __DROOT__\n")

_NGINX_TPL = ("mkdir -p __DROOT__\n"
              "echo '<h1>twin of __HOST__</h1>' > __DROOT__/index.html\n"
              "cat > /etc/nginx/sites-available/twin___NAME__ <<'NG'\n"
              "server { listen __PORT__; server_name _; root __DROOT__; index index.html; location / { try_files $uri $uri/ =404; } }\n"
              "NG\n"
              "ln -sf /etc/nginx/sites-available/twin___NAME__ /etc/nginx/sites-enabled/twin___NAME__\n"
              "nginx -t >/dev/null 2>&1 && (pkill -x nginx 2>/dev/null; sleep 1; nginx) || true\n")

_PHP_TPL = ("mkdir -p __DROOT__\n"
            "echo '<?php echo \"twin of __HOST__\"; ?>' > __DROOT__/index.php\n")

# Legacy PHP/Symfony twin via Docker (faithfully pins EOL versions modern Kali can't run natively).
_DOCKER_LEGACY_TPL = ("command -v docker >/dev/null 2>&1 || { DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io >/dev/null 2>&1; }\n"
                      "service docker start >/dev/null 2>&1 || dockerd >/tmp/dockerd.log 2>&1 &\n"
                      "sleep 6\n"
                      "mkdir -p __DROOT__\n"
                      "cat > __DROOT__/phpinfo.php <<'PHP'\n<?php phpinfo();\nPHP\n"
                      "cp __DROOT__/phpinfo.php __DROOT__/p.php\n"
                      "mkdir -p __DROOT__/app\n"
                      "cat > __DROOT__/app_dev.php <<'PHP'\n<?php // Symfony dev front-controller stub (profiler exposed, as observed on the target)\nheader('X-Debug-Token: twin'); echo '<html><head><title>Symfony Profiler</title></head><body>';\necho '<h1>Symfony 2.7 (dev) - Web Profiler</h1><p>app_dev.php reachable in production; routes/config/internal state exposed.</p>';\necho '</body></html>';\nPHP\n"
                      "cat > __DROOT__/php.ini <<'INI'\ndisplay_errors = On\nsession.cookie_httponly = Off\nINI\n"
                      "docker rm -f twin___NAME__ >/dev/null 2>&1 || true\n"
                      "docker run -d --name twin___NAME__ -p __PORT__:80 -v __DROOT__:/var/www/html -v __DROOT__/php.ini:/usr/local/etc/php/conf.d/twin.ini __IMAGE__ >/dev/null 2>&1\n"
                      "sleep 5\n")

def t_provision_twin(manifest, name=None, port=None):
    """Build a LOCAL twin of a fingerprinted target inside Kali from a MANIFEST (a dict, a JSON string, or a
    path to a manifest.json from fingerprint_target). Installs the matching server/language/CMS(+plugins at
    the detected versions) on a local port so intrusive testing hits the TWIN, never production. For an EOL
    PHP/Symfony stack it pins the exact PHP major via a Docker legacy image (php:<ver>-apache). Gated
    (installs + runs in Kali). Returns the twin base URL + what was provisioned + fidelity gaps. Unknown
    custom app code, live data and any WAF ruleset are NOT reproduced."""
    man = None
    if isinstance(manifest, dict):
        man = manifest
    else:
        s = str(manifest)
        if os.path.exists(s):
            try: man = json.load(open(s, encoding='utf-8'))
            except Exception as e: return json.dumps({"error": "bad manifest file: %s" % e})
        else:
            try: man = json.loads(s)
            except Exception: return json.dumps({"error": "manifest must be a dict, a JSON string, or a path to manifest.json"})
    tech = set(man.get('tech', [])); cms = man.get('cms', {}) or {}; versions = man.get('versions', {})
    host = man.get('host', 'target')
    name = re.sub(r'[^A-Za-z0-9_.-]', '_', name or ('twin_' + host))
    port = int(port) if port else (TWIN_BASE_PORT + abs(hash(name)) % 800)
    droot = "/opt/bench/twins/%s" % name
    provisioned, gaps, body = [], [], ""
    php_ver = re.sub(r'[^0-9.]', '', str(versions.get('php', '')))
    php_major = '.'.join(php_ver.split('.')[:2]) if php_ver else ''
    legacy_php = bool(php_major) and php_major[:1] in ('4', '5') or php_major in ('7.0', '7.1')
    if ('symfony' in tech) or (legacy_php and 'wordpress' not in tech):
        # faithful EOL twin via Docker (pins the exact PHP major the modern distro can't run)
        image = ("php:%s-apache" % php_major) if php_major else "php:5.6-apache"
        body = _DOCKER_LEGACY_TPL.replace('__IMAGE__', image)
        provisioned.append("Legacy twin via Docker %s + exposed phpinfo()/p.php + Symfony app_dev.php profiler stub + display_errors/httponly" % image)
        gaps.append("Symfony app_dev.php is a profiler STUB (real routes/config need source); real mod_security WAF and config.php gate not mirrored")
        script = ("set -e\n" + body).replace('__DROOT__', droot).replace('__PORT__', str(port)).replace('__NAME__', name).replace('__HOST__', host)
    elif 'wordpress' in tech:
        dbn = "twin_%d" % (abs(hash(name)) % 99999)
        wpver = re.sub(r'[^0-9.]', '', (cms.get('version') or '').strip())
        plug = ""
        for pl in cms.get('plugins', []):
            slug = re.sub(r'[^a-z0-9\-_]', '', str(pl.get('slug', '')).lower())
            v = re.sub(r'[^0-9.]', '', str(pl.get('version', '')))
            if slug:
                plug += ("wp plugin install %s --allow-root --path=__DROOT__ %s--activate >/dev/null 2>&1 || true\n"
                         % (slug, ("--version=%s " % v if v else "")))
        # Twin creds: env-overridable, else a fresh RANDOM secret per build (no hardcoded password in
        # the repo). Local, loopback-only throwaway twin; set AEGIS_TWIN_ADMIN_PASS/AEGIS_TWIN_DB_PASS
        # if you need to log into it.
        tw_admin = os.environ.get("AEGIS_TWIN_ADMIN_PASS") or ("Twin-" + secrets.token_urlsafe(12))
        tw_db = os.environ.get("AEGIS_TWIN_DB_PASS") or secrets.token_urlsafe(12)
        body = (_WP_TPL.replace('__VERFLAG__', ('--version=%s' % wpver) if wpver else '')
                       .replace('__PLUGINS__', plug).replace('__DBN__', dbn)
                       .replace('__ADMINPASS__', tw_admin).replace('__DBPASS__', tw_db) + _APACHE_VHOST)
        provisioned.append("WordPress %s + %d plugin(s) on Apache/PHP" % (wpver or '(latest)', len(cms.get('plugins', []))))
        gaps.append("fresh DB + default content -- production posts/users/config not mirrored")
        script = ("set -e\n" + body).replace('__DROOT__', droot).replace('__PORT__', str(port)).replace('__NAME__', name).replace('__HOST__', host)
    elif 'php' in tech:
        body = _PHP_TPL + _APACHE_VHOST
        provisioned.append("Apache + PHP (placeholder app)")
        gaps.append("custom PHP application source is not externally visible -- only a placeholder provisioned")
        script = ("set -e\n" + body).replace('__DROOT__', droot).replace('__PORT__', str(port)).replace('__NAME__', name).replace('__HOST__', host)
    elif 'nginx' in tech:
        body = _NGINX_TPL
        provisioned.append("Nginx static site")
        gaps.append("backend app behind nginx is not externally visible -- static placeholder only")
        script = ("set -e\n" + body).replace('__DROOT__', droot).replace('__PORT__', str(port)).replace('__NAME__', name).replace('__HOST__', host)
    else:
        return json.dumps({"error": "no twin template for stack %s yet" % (sorted(tech) or ['unknown']),
                           "hint": "templated: wordpress, php/apache, nginx, legacy-php/symfony (docker). Extend for java-tomcat/django/node.",
                           "tech": sorted(tech)})
    tdir = os.path.join(_twins_dir(), re.sub(r'[^A-Za-z0-9_.-]', '_', host)); os.makedirs(tdir, exist_ok=True)
    spath = os.path.join(tdir, "build_%s.sh" % name)
    with open(spath, 'w', encoding='utf-8', newline='\n') as f: f.write(script)
    try:
        p = subprocess.run(["wsl", "-d", "kali-linux", "-u", "root", "--", "bash", _win_to_wsl(spath)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200)
    except Exception as e:
        return json.dumps({"error": repr(e)[:200], "build_script": spath})
    url = "http://127.0.0.1:%d" % port
    try:
        status = _kali("curl -s -o /dev/null -w '%%{http_code}' %s/ 2>/dev/null" % url, timeout=30).stdout.strip()
    except Exception:
        status = "?"
    return json.dumps({"twin_url": url, "http_status": status, "provisioned": provisioned,
                       "fidelity_gaps": gaps, "build_script": spath, "stdout_tail": p.stdout[-800:],
                       "stderr_tail": p.stderr[-400:],
                       "note": "Run intrusive tests against twin_url, NOT the live target. Fidelity is stack-level only."})

def t_crack_hashes(hashes, hash_format="raw-md5", wordlist=None, add_wordlist_url=None, rules=True, incremental_max=0):
    """Crack password hashes with john inside Kali. Tries standard wordlists (rockyou, john's password.lst),
    escalating dictionary -> +rules -> optional bounded incremental. Can ADD a dictionary on demand: fetch
    add_wordlist_url (gated egress via Kali) or apt-install seclists when wordlist='seclists'. hashes may be
    a string, a list, or 'user:hash' lines. Returns {cracked:{input:password}, uncracked:[...],
    wordlists_tried:[...]}. Gated. A strong/random password that does NOT crack is itself a finding."""
    if isinstance(hashes, (list, tuple)):
        lines = [str(h).strip() for h in hashes if str(h).strip()]
    else:
        lines = [ln.strip() for ln in str(hashes).splitlines() if ln.strip()]
    if not lines:
        return json.dumps({"error": "no hashes given"})
    try:
        inc = int(incremental_max or 0)
    except (TypeError, ValueError):
        inc = 0
    fmt = re.sub(r'[^A-Za-z0-9\-]', '', str(hash_format or "raw-md5")) or "raw-md5"
    tag = "%d" % (abs(hash((tuple(lines), fmt, time.time()))) % 1000000000)
    hf  = "/tmp/ds_crack_%s.hash" % tag
    pot = "/tmp/ds_crack_%s.pot" % tag   # per-run pot: never touch the shared ~/.john/john.pot
    _kali("umask 077; cat > %s <<'HASHES'\n%s\nHASHES\n" % (hf, "\n".join(lines)), timeout=30)
    prep = ("[ -f /usr/share/wordlists/rockyou.txt ] || { [ -f /usr/share/wordlists/rockyou.txt.gz ] && "
            "gunzip -kf /usr/share/wordlists/rockyou.txt.gz 2>/dev/null; }\n")
    cands, extra = [], None
    if add_wordlist_url and re.match(r'^https?://', str(add_wordlist_url), re.I):
        u = str(add_wordlist_url).replace("'", "")
        dest = "/usr/share/wordlists/ds_extra_%s.txt" % tag
        r = _kali("umask 077; curl -sSL -m 180 -o '%s' '%s' 2>/dev/null; [ -s '%s' ] && echo DLOK" % (dest, u, dest), timeout=240)
        if "DLOK" in (r.stdout or ""):          # only report/use it if the download actually produced a file
            extra = dest; cands.append(dest)
    if wordlist:
        w = str(wordlist).replace("'", "")       # strip quotes (parity with add_wordlist_url)
        if w.lower() == "seclists":
            prep += ("ls /usr/share/seclists >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive "
                     "apt-get install -y seclists >/dev/null 2>&1\n")
            cands.append("/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt")
        elif re.fullmatch(r'/[\w./-]+', w):      # explicit path: safe charset only (no shell metachars)
            cands.append(w)
    cands += ["/usr/share/wordlists/rockyou.txt", "/usr/share/john/password.lst"]
    rule_flag = "--rules" if rules else ""
    runs = ""
    for wl in cands:
        runs += ("if [ -f '%s' ]; then echo 'TRY %s'; john --format=%s --pot='%s' --wordlist='%s' %s '%s' 2>&1 | tail -1; fi\n"
                 % (wl, wl, fmt, pot, wl, rule_flag, hf))
    if inc > 0:
        runs += "john --format=%s --pot='%s' --incremental=ASCII --max-length=%d '%s' 2>&1 | tail -1\n" % (fmt, pot, inc, hf)
    runs += "echo '<<<POT>>>'; cat '%s' 2>/dev/null\n" % pot
    partial = False
    try:
        out = _kali(prep + runs, timeout=1200).stdout
    except Exception as e:                        # on timeout, still salvage whatever john already wrote to the pot
        partial = True
        try:
            out = "[timeout %s]\n<<<POT>>>%s" % (repr(e)[:60], _kali("cat '%s' 2>/dev/null" % pot, timeout=30).stdout)
        except Exception:
            out = ""
    potdata = out.split('<<<POT>>>', 1)[1] if '<<<POT>>>' in out else ""
    cracked = {}
    for ln in potdata.splitlines():
        if ':' in ln:
            h, pw = ln.rsplit(':', 1)
            cracked[h.strip().lower().lstrip('$').split('$')[-1]] = pw
    result, uncracked = {}, []
    for ln in lines:
        bare = ln.rsplit(':', 1)[-1].strip().lower()
        pw = cracked.get(bare)                    # EXACT match only -- no fuzzy substring misattribution
        (result.__setitem__(ln, pw) if pw is not None else uncracked.append(ln))
    _kali("rm -f '%s' '%s' 2>/dev/null" % (hf, pot), timeout=20)   # clean up the credential-bearing temp files
    return json.dumps({"cracked": result, "uncracked": uncracked, "wordlists_tried": cands,
                       "extra_fetched": extra, "format": fmt, "partial_timeout": partial,
                       "note": "offline john crack; a strong/random password that does NOT crack is itself a finding"})

TOOLS = {
 "get_status": (t_get_status, True, _spec("get_status", "List recent aegis tasks + status.", {}, [])),
 "read_task_context": (t_read_task_context, True, _spec("read_task_context",
    "Read a task's live status, checkpoint mtime age, and transcript tail (babysitting).",
    {"task_id": {"type": "string"}}, ["task_id"])),
 "read_file": (t_read_file, True, _spec("read_file",
    "Read a project file (for review/improvement). Optional start_line/end_line to page long files; "
    "response gives total_lines and more_after_this so you know if there's more.",
    {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, ["path"])),
 "list_files": (t_list_files, True, _spec("list_files",
    "List repo files matching a glob (default **/*.py). Read-only.",
    {"pattern": {"type": "string"}}, [])),
 "search_code": (t_search_code, True, _spec("search_code",
    "Regex-grep the repo; returns file:line matches. Read-only.",
    {"pattern": {"type": "string"}, "glob_pat": {"type": "string"}}, ["pattern"])),
 "submit_aegis_task": (t_submit, False, _spec("submit_aegis_task",
    "Submit a NEW scoped aegis pentest task. Returns task_id.",
    {"description": {"type": "string"}, "abstract": {"type": "string"}, "verification": {"type": "string"}},
    ["description"])),
 "resume_task": (t_resume, False, _spec("resume_task",
    "Plain resume-nudge a stalled/interrupted task (no VPN change).",
    {"task_id": {"type": "string"}, "note": {"type": "string"}}, ["task_id"])),
 "vpn_ctl": (t_vpn_ctl, False, _spec("vpn_ctl",
    "Control the VPN egress tunnel: action = status|connect|ensure|disconnect (status is safe).",
    {"action": {"type": "string"}, "region": {"type": "string"}}, ["action"])),
 "run_command": (t_run_command, False, _spec("run_command",
    "Run a shell command on the Windows host and wait for it (git, tests, restart scripts, etc.). "
    "For anything long-running or that must be watched, use run_background instead.",
    {"command": {"type": "string"}}, ["command"])),
 "run_background": (t_run_background, False, _spec("run_background",
    "Start a long-running command in the BACKGROUND (a server, a scan, a build). Returns a proc_id you "
    "then poll with read_process_output and stop with kill_process -- lets you watch errors as they happen.",
    {"command": {"type": "string"}}, ["command"])),
 "read_process_output": (t_read_process_output, True, _spec("read_process_output",
    "Read recent stdout/stderr of a background process, whether it is still running, and its exit code.",
    {"proc_id": {"type": "string"}, "tail_lines": {"type": "integer"}}, ["proc_id"])),
 "kill_process": (t_kill_process, False, _spec("kill_process",
    "Terminate a background process by proc_id.",
    {"proc_id": {"type": "string"}}, ["proc_id"])),
 "write_file": (t_write_file, False, _spec("write_file",
    "Overwrite a project file with new content (new files / full rewrites).",
    {"path": {"type": "string"}, "content": {"type": "string"}}, ["path", "content"])),
 "apply_edit": (t_apply_edit, False, _spec("apply_edit",
    "Apply a surgical fix: replace a UNIQUE old_string with new_string in a file (preferred for improvements). "
    "old_string must match the file exactly and uniquely.",
    {"path": {"type": "string"}, "old_string": {"type": "string"}, "new_string": {"type": "string"}},
    ["path", "old_string", "new_string"])),
 "revert_file": (t_revert_file, False, _spec("revert_file",
    "Undo the last write/edit to a file this session (restore pre-edit content). Use when a fix made things worse.",
    {"path": {"type": "string"}}, ["path"])),
 "search_docs": (t_search_docs, True, _spec("search_docs",
    "Search the project runbook/doctrine (HELP.md, RESILIENCE.md, the aegis SKILL) for project-specific "
    "behavior instead of guessing (planner-choke, kali_driver queueing, VPN, checkpoints, resume, reports).",
    {"query": {"type": "string"}}, ["query"])),
 "finalize_report": (t_finalize_report, True, _spec("finalize_report",
    "QA a draft report before finishing: scans the task's raw transcript for failure/empty red flags, flags "
    "unsupported/over-claimed findings and empty-data-as-result, and returns a synthesis-led rewrite. Pass your "
    "draft and the task_id whose transcript is the evidence.",
    {"draft": {"type": "string"}, "task_id": {"type": "string"}}, ["draft"])),
 "write_todos": (t_write_todos, True, _spec("write_todos",
    "Set/replace your working plan (todo list) so you stay on track on multi-step tasks. Pass items as "
    "{content, status} with status pending|in_progress|completed; keep exactly one in_progress.",
    {"todos": {"type": "array", "items": {"type": "object", "properties": {
        "content": {"type": "string"}, "status": {"type": "string"}}}}}, ["todos"])),
 "spawn_subagent": (t_spawn_subagent, True, _spec("spawn_subagent",
    "Delegate a focused sub-task to a fresh sub-agent (own context, scoped tools) that reports back a summary. "
    "'tools' optionally lists which tool names it may use (default: read + run + edit + finish).",
    {"task": {"type": "string"}, "tools": {"type": "array", "items": {"type": "string"}}}, ["task"])),
 "remember": (t_remember, True, _spec("remember",
    "Save a durable fact/learning across sessions (a gotcha, target detail, decision). Persists to memory.",
    {"note": {"type": "string"}}, ["note"])),
 "recall": (t_recall, True, _spec("recall",
    "Recall durable notes from past sessions, optionally filtered by a regex query.",
    {"query": {"type": "string"}}, [])),
 "record_finding": (t_record_finding, True, _spec("record_finding",
    "Record ONE confirmed/candidate finding to the durable LEDGER the moment you confirm it (do NOT wait for the "
    "final report). It SURVIVES context compaction, so nothing is lost on long runs. severity=critical|high|medium|"
    "low|info; principal=who achieved it (unauth|technician|owner|external); status=confirmed|candidate|clean "
    "('clean' records a vector you tested that HELD). Then write the report FROM read_ledger().",
    {"title": {"type": "string"}, "severity": {"type": "string"}, "principal": {"type": "string"},
     "endpoint": {"type": "string"}, "evidence": {"type": "string"}, "status": {"type": "string"}}, ["title"])),
 "chain_state": (t_chain_state, True, _spec("chain_state",
    "Record exploit-CHAIN progress to the durable LEDGER: what access/privilege you HOLD (gained), the next pivot "
    "(next_step), and linking detail (note). Call it EACH time you gain access or complete a pivot, so a multi-stage "
    "compromise survives context compaction and later steps build on earlier ones.",
    {"gained": {"type": "string"}, "next_step": {"type": "string"}, "note": {"type": "string"}}, [])),
 "read_ledger": (t_read_ledger, True, _spec("read_ledger",
    "Read back the durable findings/chain LEDGER for THIS assessment (all_runs=true for every run). Use it before "
    "finalize_report so the report reflects EVERY confirmed finding, including ones from before a compaction.",
    {"all_runs": {"type": "boolean"}}, [])),
 "multi_edit": (t_multi_edit, False, _spec("multi_edit",
    "Apply SEVERAL edits to one file atomically (all-or-nothing). edits = list of {old_string, new_string}, "
    "each unique. Preferred over repeated apply_edit for multi-spot fixes.",
    {"path": {"type": "string"}, "edits": {"type": "array", "items": {"type": "object", "properties": {
        "old_string": {"type": "string"}, "new_string": {"type": "string"}}}}}, ["path", "edits"])),
 "spawn_agents_parallel": (t_spawn_agents_parallel, True, _spec("spawn_agents_parallel",
    "Fan out: run several READ-ONLY sub-agents CONCURRENTLY (parallel research/review/audit) and gather their "
    "summaries. Pass tasks as a list of strings. Read-only; no gate prompts.",
    {"tasks": {"type": "array", "items": {"type": "string"}}}, ["tasks"])),
 "fetch_url": (t_fetch_url, False, _spec("fetch_url",
    "GET a public URL and return readable text (no JS). For research/OSINT (crt.sh, CVE pages, docs). Gated.",
    {"url": {"type": "string"}}, ["url"])),
 "render_page": (t_render_page, False, _spec("render_page",
    "Render a JavaScript page headlessly (Kali chromium) and return the DOM text. Gated.",
    {"url": {"type": "string"}}, ["url"])),
 "git_status": (t_git_status, True, _spec("git_status", "git status (branch + porcelain) of the code repo.", {}, [])),
 "git_diff": (t_git_diff, True, _spec("git_diff", "git diff of the repo (optionally one path).",
    {"path": {"type": "string"}}, [])),
 "git_log": (t_git_log, True, _spec("git_log", "git log --oneline (optionally for one path).",
    {"n": {"type": "integer"}, "path": {"type": "string"}}, [])),
 "git_commit": (t_git_commit, False, _spec("git_commit", "git add -A + commit with a message. Gated -- use to checkpoint.",
    {"message": {"type": "string"}}, ["message"])),
 "check_kali_tools": (t_check_kali_tools, True, _spec("check_kali_tools",
    "READ-ONLY co-check: report which CLI tools are present/missing in Kali (login PATH). Never installs.",
    {"tools": {"type": "array", "items": {"type": "string"}}}, ["tools"])),
 "run_in_kali": (t_run_in_kali, False, _spec("run_in_kali",
    "Run a shell command INSIDE Kali (login shell, VPN egress). Gated. Test a custom PoC against an authorized "
    "target, or build tooling in Kali.", {"command": {"type": "string"}}, ["command"])),
 "run_tool": (t_run_tool, False, _spec("run_tool",
    "Run an external pentest TOOL by name, AUTO-ROUTING to the distro that has it: present in Kali -> Kali; "
    "MISSING -> the BlackArch container (prebuilt via pacman, native), fetched on demand -- NOT ported into "
    "Kali. Gated. Prefer this over run_in_kali for any off-the-shelf CLI tool (feroxbuster, katana, dalfox, "
    "nuclei, sn0int, ...). args = the argument string.",
    {"tool": {"type": "string"}, "args": {"type": "string"}}, ["tool"])),
 "install_kali_tool": (t_install_kali_tool, False, _spec("install_kali_tool",
    "Install a co-pilot-authored tool into Kali's /usr/local/bin (staged in the repo first). Gated. For a novel "
    "checker/PoC when no off-the-shelf tool exists.",
    {"name": {"type": "string"}, "content": {"type": "string"}, "interpreter": {"type": "string"},
     "pip_deps": {"type": "array", "items": {"type": "string"}}}, ["name", "content"])),
 "rag_search": (t_rag_search, True, _spec("rag_search",
    "Search the local Kali-resident vulnerability RAG (NVD + CISA KEV + EPSS + Exploit-DB + legacy corpus) at "
    "/opt/aegis-rag. FULLY OFFLINE: the query runs against local SQLite inside Kali and never leaves the box. "
    "Pass a CVE id (exact enriched record) or keywords (ranked, surfacing actively-exploited KEV / high-EPSS / "
    "high-CVSS first). Returns {mode,count,items:[{cve_id,cvss,severity,epss,kev,kev_due,exploitdb_ids,url,snippet}]}. "
    "Read-only -- use it to check exploitability/PoC availability before choosing an approach.",
    {"query": {"type": "string"}, "k": {"type": "integer"}}, ["query"])),
 "exploit_search": (t_exploit_search, True, _spec("exploit_search",
    "LIVE exploit search across aggregators for a fingerprinted product+version or a CVE id -- complements "
    "rag_search (offline store) with query-time exploit ENGINES. sources (comma list): rag+searchsploit are "
    "OFFLINE (local, always work); sploitus/github/packetstorm reach the internet (blocked under ExploitGym "
    "containment unless the host is allow-listed for the run). Returns per-source hits (title/href/edb/repo). "
    "Read-only recon; use after fingerprinting a component to find a fitting PoC.",
    {"query": {"type": "string"}, "sources": {"type": "string"}, "k": {"type": "integer"}}, ["query"])),
 "plan_and_execute": (t_plan_and_execute, False, _spec("plan_and_execute",
    "Decompose an objective into a VERIFIED task graph and drive it: each sub-task runs a gated "
    "executor sub-agent, then its result is graded against explicit acceptance criteria and "
    "accepted / retried / re-branched. Every action still passes the approval gate. Runs UNBOUNDED "
    "by default (relaxed planning caps for benchmarking; hard node/time runaway guards remain); set "
    "bounded=true for the tight-caps A/B. Returns the objective status + the sub-task graph.",
    {"objective": {"type": "string"}, "verification": {"type": "string"},
     "bounded": {"type": "boolean"}, "exec_max_iter": {"type": "integer"}}, ["objective"])),
 "fingerprint_target": (t_fingerprint_target, False, _spec("fingerprint_target",
    "LIGHT non-intrusive fingerprint of an external target (server/language/CMS+version/plugins, PHP/Symfony "
    "exposures) via Kali (VPN egress). Writes a manifest for provision_twin. Safe recon -- no exploitation.",
    {"url": {"type": "string"}, "deep": {"type": "boolean"}}, ["url"])),
 "provision_twin": (t_provision_twin, False, _spec("provision_twin",
    "Build a LOCAL twin of a fingerprinted target in Kali from a manifest (dict / JSON / manifest.json path): "
    "installs the matching server/language/CMS(+plugins at detected versions; EOL PHP/Symfony via a Docker "
    "legacy image) on a local port so intrusive tests hit the TWIN, not production. Returns twin_url + "
    "fidelity gaps. Gated.",
    {"manifest": {"type": "string"}, "name": {"type": "string"}, "port": {"type": "integer"}}, ["manifest"])),
 "crack_hashes": (t_crack_hashes, False, _spec("crack_hashes",
    "Crack password hashes with john in Kali: standard wordlists (rockyou/password.lst), escalating "
    "dict -> +rules -> optional incremental. Can ADD a dictionary on demand (fetch add_wordlist_url, or "
    "wordlist='seclists' to apt-install it). hashes = string or list ('user:hash' ok). A hash that does "
    "NOT crack is itself a finding. Gated.",
    {"hashes": {"type": "array", "items": {"type": "string"}}, "hash_format": {"type": "string"},
     "wordlist": {"type": "string"}, "add_wordlist_url": {"type": "string"},
     "rules": {"type": "boolean"}, "incremental_max": {"type": "integer"}}, ["hashes"])),
 "remediation": (t_remediation, True, _spec("remediation",
    "STAGE 10 / end of pipeline: run the remediation round over this run's oracle-VERIFIED findings -- the "
    "whole board panel proposes the fix (attributed + consensus), routed known-cve -> ADMIN framework update "
    "vs novel -> CODE writer/improver fix; emit_fixes hands each to the code bench for a concrete patch. Writes "
    "remediation_report.md + chains it onto the ledger. Non-destructive. Call it once you have VERIFIED findings.",
    {"emit_fixes": {"type": "boolean"}, "panel": {"type": "string"}}, [])),
 "port_fix_to_mirror": (t_port_fix_to_mirror, True, _spec("port_fix_to_mirror",
    "Deliver the code writer/improver's emitted patch (remediation_fixes/) INTO the mirror for testing the "
    "improved code. Mirror may be ANY distro (Ubuntu/SUSE/Kali) or Docker. transport: wsl (WSL mirror distro, "
    "--distro/AEGIS_MIRROR_DISTRO) | docker (docker cp, needs container) | dir (USB/staging dir, needs dest). "
    "MIRROR-side only: STAGES the patch, never applies it, never touches the real "
    "target; returns the in-mirror path + apply command. Run remediation(emit_fixes=true) first.",
    {"finding": {"type": "string"}, "transport": {"type": "string"},
     "container": {"type": "string"}, "dest": {"type": "string"}}, [])),
 "verify_fix_on_mirror": (t_verify_fix_on_mirror, True, _spec("verify_fix_on_mirror",
    "STAGE-10 CLOSED LOOP (mirror-only): snapshot the mirror, APPLY the fix (code patch + framework bump), "
    "RE-RUN each finding's exploit/oracle on the patched system -> CLOSED/STILL-OPEN/BROKE-AFTER-UPDATE, then "
    "restore. allow_download fetches the framework update onto the mirror; health_cmd checks the app still "
    "runs; repair runs the board-driven DS-vs-Qwen fix if the update broke the code. Never patches/re-tests "
    "the real target. Run remediation(emit_fixes=true) + port_fix_to_mirror first.",
    {"transport": {"type": "string"}, "mirror_repo": {"type": "string"}, "repro_map": {"type": "string"},
     "allow_download": {"type": "boolean"}, "health_cmd": {"type": "string"}, "repair": {"type": "boolean"},
     "container": {"type": "string"}, "extra": {"type": "string"}}, [])),
 "finish": (t_finish, True, _spec("finish", "Finish: give the final operator conclusion for the human.",
    {"summary": {"type": "string"}}, ["summary"])),
}

SYSTEM = """You are DeepSeek acting as the OPERATOR CO-PILOT for the authorized 'aegis' pentest stack,
plus a code assistant for its repo. You are the same seat a human+Claude occupy. You ORCHESTRATE and BABYSIT
(you do not run scans yourself; aegis+bridge do), and when asked you IMPROVE the repo's code.

IMPORTANT -- APPROVAL GATE: every MUTATING tool (submit_aegis_task, resume_task, vpn_ctl connect/ensure/
disconnect, run_command, write_file) requires a HUMAN to approve it at the terminal before it runs. Read-only
tools (get_status, read_task_context, read_file, vpn_ctl status) run automatically. If an action is DENIED,
do NOT retry it blindly -- explain what you wanted and why, or propose a safer alternative, or ask the human.

Operator doctrine:
- Scope submitted tasks tightly: authorization + exact hosts/ports + explicit do-NOTs + a concrete 'done'
  verification. Keep prompts tight (the planner chokes on huge ones).
- Babysitting: checkpoint-mtime is the ground-truth liveness signal (NOT status). If the last checkpoint entry
  is an UNANSWERED tool_call, a long command is still running -- WAIT, don't act. A repeating
  '[tool error: Timed out ... 600.0s]' is kali_driver queueing, not a target block (VPN won't help). Plain-resume
  a genuine stall first; VPN-rotate only if a target blocks every source IP; else record the block.
- Planner-choke = instant 'failed' + empty transcript + no checkpoint (stale planner key / provider 402).
- Guardrails (never weaken): only touch explicitly authorized targets; never brute-force/bypass an auth or
  anti-bot gate; data never leaves this machine; anti-hallucination -- never assert a specific CVE/version/
  exploit unless evidence supports it.
- VULN INTELLIGENCE (RAG) -- REQUIRED GATE, not an optional extra. The moment you have fingerprinted ANY
  server / language+version / framework / CMS-bundle / library on the target, you MUST consult the offline
  Kali vuln DB (NVD + CISA KEV + EPSS + Exploit-DB) BEFORE you move on to exploitation-style probing. Two ways,
  both count: (a) call fingerprint_target(url) -- it now AUTO-runs the RAG per component and returns a
  `known_vulns` list in the manifest; or (b) if you fingerprinted by hand, call rag_search("<product>
  <version>") yourself for EACH identified component. Either way, explicitly MATCH what is KNOWN-vulnerable
  against what is PRESENT, and record it. Do NOT proceed to deeper exploitation of a component until you have
  its RAG result. Prioritise KEV (actively exploited) / high-EPSS / Exploit-DB-PoC hits, and let them steer the
  DEEPER probing -- test the applicable, in-scope CVEs NON-DESTRUCTIVELY (per the CUSTOM TOOLING rules; validate
  impact, never weaponise). rag_search is read-only, offline and ungated -- there is no reason to skip it.
  Anti-hallucination still binds: only assert a specific CVE/version/exploit when the RAG or direct evidence
  backs it, and cite the CVE id + source.
- Code REVIEW (read-only): use list_files/search_code to discover, read_file to read, then report findings
  ranked by severity -- each as [SEVERITY] file:line -- issue -- concrete suggested fix. Distinguish real
  correctness/security bugs from style/simplification. Do NOT propose write_file during a review unless the
  human explicitly asked you to APPLY fixes. Only claim a bug you can point to in code you actually read.
- Code changes / DEBUG-FIX loop: read the file first; make the SMALLEST correct change via apply_edit (a unique
  old_string -> new_string; the human sees a diff before approving). Then ALWAYS verify: run the relevant test or
  command via run_command, read stdout/stderr/exit-code, and iterate on the evidence. Find the culprit BEFORE
  rewriting -- read the traceback, search_code for the symbol, confirm the root cause. If an edit made things
  worse, or the test still fails after ~3 tries, revert_file(path) to the pre-edit state and rethink rather than
  piling edits on edits. NOTE: after every apply_edit/write_file the harness AUTO-VERIFIES (py_compile for .py
  plus any configured verify command) and returns 'auto_verify' in the tool result -- always read it; if it
  shows a FAIL, fix or revert before doing anything else.
- LONG-RUNNING programs (a server, a scan, a build, a test suite that runs a while): start it with
  run_background (returns a proc_id), then poll read_process_output to watch stdout/stderr as errors happen, and
  kill_process when done. Do NOT use run_command for something that will not exit promptly.
- DELEGATION: for a sizeable, separable sub-task (audit a module, write tests for X, isolate one bug), use
  spawn_subagent(task, tools) to run a focused sub-agent that reports back a summary -- this keeps your own
  context clean. The sub-agent shares the same approval gate.
- DOCTRINE RECALL: when unsure about a project-specific behavior (planner-choke, kali_driver queueing, VPN,
  checkpoints, resume, report conventions), call search_docs(query) to consult the runbook -- do NOT guess.
- REPORT QA: before you finish a task that produces a report or findings, call finalize_report(draft, task_id).
  It flags unsupported/over-claimed findings and failed-or-empty scans reported as results, and returns a
  synthesis-led rewrite that leads with the top systemic risk. Use its output as your final report; if it flags
  a claim as unsupported, fix or drop that claim -- never ship an evidence-free finding.
- REMEDIATION (STAGE 10, end of pipeline): once your run has produced oracle-VERIFIED findings, call
  remediation() BEFORE finish(). It fans each confirmed weakness to the board panel for the fix, routes
  known-CVE weaknesses to ADMINS (framework/dependency update) and novel ones to the CODE writer/improver
  (with emit_fixes it emits a concrete patch), writes the two-track remediation_report.md, and chains the fix
  onto the ledger. MIRROR-SIDE ONLY: the fixes target the mirror twin (where findings were confirmed), for
  review + further testing on the mirror; proposed, NEVER auto-applied, and NEVER run against the real target.
  Non-destructive/advisory. Skip it only if nothing was verified. To TEST an improved fix on the mirror, call
  port_fix_to_mirror(transport=wsl|docker|dir) to carry the code writer's patch into the mirror (Kali/Docker/
  USB), then apply it there and re-run the finding's exploit/oracle to confirm the gap is closed -- the
  mirror-only closed loop.
- PLAN: for any multi-step task, call write_todos FIRST to lay out the steps, keep exactly ONE item
  in_progress, mark items completed as you finish them, and revise the list as things change. This keeps you
  on track and stops you repeating or thrashing. Long sessions are auto-compacted, so the plan is your memory.
- LEDGER (record AS YOU GO -- critical): the ledger is the ONLY thing that survives context compaction.
  Anything left only in your reasoning/transcript is LOST the next time the context folds, and your final
  summary will then UNDER-REPORT it (this has happened). So record EVERY result the MOMENT you reach it --
  vulnerable, clean, OR inconclusive -- BEFORE moving to the next test, via record_finding(title, severity,
  principal, endpoint, evidence, status=confirmed|candidate|clean). Do NOT batch them for the end. Finished
  probing an endpoint or a vector (e.g. "parse endpoint ignores the filename -> no traversal", "test-sms uses a
  fixed provider URL -> no SSRF")? record_finding it NOW, even when the result is 'clean'. Each time you GAIN
  access or complete a pivot, call chain_state(gained, next_step, note). The ledger is re-injected VERBATIM
  after every compaction, so a long chain never loses a link and you never re-derive a proven fact. Before you
  finish, call read_ledger() and RECONCILE: anything you tested that is not yet in the ledger, record it before
  writing the report -- the report is built from the ledger, so an unrecorded result effectively does not exist.
- CUSTOM TOOLING (a vuln is APPARENT but NO tool exists to test it): (1) state precisely what the flaw is and
  what would PROVE it; (2) write a MINIMAL, SAFE proof-of-concept checker via write_file (the human reviews the
  exact requests in the diff); (3) test it INSIDE Kali against the AUTHORIZED target with run_in_kali (VPN
  egress; the human approves the run); (4) confirm ONLY if the PoC demonstrates the flaw with evidence, else
  report "not confirmed" -- never fabricate; (5) if reusable, install_kali_tool(name, content) to add it to
  Kali and git_commit it. Keep PoCs non-destructive and IN-SCOPE: validate impact, never weaponise, exfiltrate,
  or leave persistence.
- NOVEL / HYPOTHESIS-DRIVEN TESTING (a flaw that is APPARENT but not obvious and in NO database): treat any
  SURPRISING or inconsistent observation as a LEAD, not noise -- an unexpected 200/500, a timing delta, a field
  or header that should not be there, an error that leaks internal detail, a state change you did not expect, two
  endpoints that disagree, an input that is reflected or transformed oddly. Do NOT spray hundreds of payloads.
  Instead: (1) form ONE concrete hypothesis about the underlying mechanism; (2) design the SINGLE most-likely-to-
  succeed test that would prove or disprove it (write a minimal bespoke PoC via write_file when no off-the-shelf
  tool fits -- see CUSTOM TOOLING); (3) run it ONCE against the target (or against a provision_twin first for
  anything intrusive); (4) confirm only on real evidence, else discard the hypothesis and move on -- never
  fabricate; (5) record_finding / chain_state the outcome so the reasoning survives compaction. Reason your way to
  the exploit from what the app actually reveals -- bespoke logic/authz/state flaws are where you beat a scanner,
  and rag_search only covers the KNOWN ones.
- KALI TOOLS: before a task needs a specific CLI tool, call check_kali_tools([names]) -- a READ-ONLY co-check of
  what is installed in Kali. If a tool is missing AND the task genuinely needs it, propose installing it via a
  GATED run_command (apt/pip/go); never pre-install or overwrite tools before a test.
- WEB RESEARCH: use fetch_url(url) for public research/OSINT (crt.sh, CVE pages, docs) -- GET-only, gated; use
  render_page(url) when a page needs JavaScript. Stay within authorized/public research; the human approves each.
- GIT: use git_status/git_diff/git_log to find culprits and read history, and git_commit(message) to checkpoint
  your changes (gated) -- prefer a commit before a risky change so revert is easy.
- PARALLEL: for several INDEPENDENT read-only investigations (review N files, research M topics), use
  spawn_agents_parallel(tasks) to run them CONCURRENTLY and get all summaries back at once -- far faster than
  sequential spawn_subagent for fan-out work.
- MEMORY: use remember(note) to save a durable fact/learning (a gotcha you hit, a target detail, a decision)
  so future sessions have it, and recall(query) to look one up. Your saved memory is preloaded above.
Work step by step. When the objective is met (or provably blocked/denied), call finish() with a crisp summary."""

def _resolve_key_endpoint():
    if _provider() == "cloudflare":
        # Cloudflare Workers AI: token = CF_API_TOKEN (Workers-AI perm); endpoint interpolates the
        # account id. Kept SEPARATE from the DeepSeek/OpenAI keys. Adds open models (Qwen, QwQ,
        # gpt-oss, Kimi) to the roster via --provider cloudflare --model <@cf/... slug>.
        acct = (os.environ.get("CF_ACCOUNT_ID")
                or (Master.get("cf_account_id") if Master else None) or "")
        key = (os.environ.get("CF_API_TOKEN")
               or (Master.get("cf_api_token") if Master else None))
        endpoint = (os.environ.get("CF_ENDPOINT")
                    or f"https://api.cloudflare.com/client/v4/accounts/{acct}/ai/v1")
        return key, endpoint
    if _provider() == "openai":
        # Direct OpenAI (GPT-5.6 Sol): key kept SEPARATE from the DeepSeek key. Reads
        # OPENAI_API_KEY from the environment OR the gitignored secret.env (via Master). Does
        # NOT fall back to AEGIS_LLM_API_KEY -- that holds the DeepSeek key.
        key = (os.environ.get("OPENAI_API_KEY")
               or (Master.get("openai_direct_key") if Master else None))
        endpoint = (os.environ.get("OPENAI_ENDPOINT")
                    or (Master.get("openai_direct_endpoint") if Master else None)
                    or "https://api.openai.com/v1")
        return key, endpoint
    key = (os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("AEGIS_LLM_API_KEY")
           or (Master.get("openai_api_key") if Master else None))
    endpoint = (os.environ.get("DEEPSEEK_ENDPOINT") or os.environ.get("AEGIS_LLM_ENDPOINT")
                or (Master.get("openai_api_endpoint") if Master else None) or "https://api.deepseek.com/v1")
    return key, endpoint

_CTX = {}  # shared agent context (client/model/thinking/gate/depth) for sub-agents

COMPACT_THRESHOLD = int(os.environ.get("AEGIS_COMPACT_THRESHOLD", "60000"))  # transcript chars before we summarize older turns (env-overridable, e.g. to force/test compaction)
CHAT_MAX_ITER = 60         # max reason/act cycles per chat turn (room to babysit within a turn)
# tools where repeating the SAME call is thrash (polling tools like read_task_context are excluded)
_LOOP_GUARD_TOOLS = {"run_command", "run_background", "apply_edit", "write_file", "submit_aegis_task", "run_tool"}

def _save_session(path, messages):
    """Persist the chat transcript + plan so a session can be resumed later. Atomic write."""
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"messages": messages, "todos": _TODO, "run_id": _RUN_ID}, f)
        os.replace(tmp, path)
    except Exception as e:
        print(f"[session] save failed: {repr(e)[:120]}", flush=True)

def _load_session(path):
    global _TODO, _RUN_ID
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return None
    msgs = d.get("messages") or []
    _TODO = d.get("todos") or []
    if d.get("run_id"):
        _RUN_ID = d["run_id"]  # keep the same ledger view across resume
    # repair a dangling assistant-with-tool_calls (session saved/interrupted mid-turn)
    if msgs and msgs[-1].get("role") == "assistant" and msgs[-1].get("tool_calls"):
        for tc in msgs[-1]["tool_calls"]:
            msgs.append({"role": "tool", "tool_call_id": tc.get("id"), "content": "[interrupted]"})
    return msgs

def _transcript_size(messages):
    return sum(len(json.dumps(m, default=str)) for m in messages)

def _flatten_msg(m):
    parts = [f"[{m.get('role')}]"]
    if m.get("content"):
        parts.append(str(m["content"]))
    for tc in (m.get("tool_calls") or []):
        fn = tc.get("function", {}) if isinstance(tc, dict) else {}
        parts.append(f"(tool_call {fn.get('name')} {str(fn.get('arguments'))[:200]})")
    return " ".join(parts)

def _maybe_compact(messages, client, model):
    """When the transcript grows past COMPACT_THRESHOLD, summarize the older middle turns into
    one note so long sessions don't blow the context window. Keeps system[0] + a summary + the
    recent tail. Cut point never lands on a 'tool' message, so tool_call/tool pairing stays valid."""
    if len(messages) < 16 or _transcript_size(messages) < COMPACT_THRESHOLD:
        return messages
    keep = 8
    cut = len(messages) - keep
    while cut > 1 and messages[cut].get("role") == "tool":
        cut -= 1
    # Preserve system[0] AND the original task[1] VERBATIM so the objective + any required
    # finish/verdict contract can never be summarised away. (Observed failure mode: after a
    # compaction the operator forgot the goal and declared the STARTING foothold it was handed
    # a success, instead of the objective it was told to reach.)
    head = 2 if (len(messages) > 2 and messages[1].get("role") == "user") else 1
    if cut <= head:
        return messages
    blob = "\n".join(_flatten_msg(m) for m in messages[head:cut])[:24000]
    try:
        r = _create(client,
            model=model, temperature=0.2, max_tokens=700,
            extra_body={"thinking": {"type": "disabled"}},
            messages=[{"role": "system", "content":
                       "Summarize this operator/agent transcript compactly for continuation: key decisions, "
                       "findings, files read/edited and their state, commands run and results, and what remains. "
                       "Terse bullets, no fluff. The task/objective is preserved separately -- do NOT restate, "
                       "reinterpret, or replace it, and do NOT declare the task complete."},
                      {"role": "user", "content": blob}])
        summary = (r.choices[0].message.content or "").strip()
        if not summary:
            return messages
    except Exception:
        return messages  # never break the run on a summarization hiccup
    print(f"[compact] folded {cut-head} older messages into a {len(summary)}-char summary (task preserved)", flush=True)
    tail_note = ("\n\n[CURRENT PLAN -- still your memory]\n" + _render_todos()) if _TODO else ""
    reassert = ("[COMPACTED EARLIER CONTEXT -- the objective in the messages above STILL STANDS; you have NOT "
                "finished until THAT objective is met, not merely the starting foothold you were given]\n")
    return messages[:head] + [{"role": "user", "content": reassert + summary + tail_note + _ledger_block()}] + messages[cut:]

# ---- agent-quality mechanisms (board + coordinator review, 2026-09): transient-error auto-RECOVERY,
# per-step self-REFLECTION, VERIFY-before-finish, and a DOCTRINE gate. Additive to the existing loop-guard,
# enforced auto-verify, todo working-memory, and ledger/goal re-injection on compaction. ----
_TRANSIENT_PAT = re.compile(
    r"0x800|did not properly respond|timed?\s*out|timeout|connection (refused|reset|aborted)|"
    r"temporarily unavailable|cannot connect|econnreset|etimedout|wsl/service|broken pipe|"
    r"out of memory|\boom\b|\bkilled\b|\b(429|500|502|503|504)\b|rate.?limit", re.I)


def _is_transient(result_str):
    """True if a tool result looks like a TRANSIENT infra failure worth an automatic retry (vs a real bug).
    Distinguishes the WSL-timeout / OOM / 5xx / connection class from genuine tool errors."""
    try:
        rj = json.loads(result_str)
        blob = " ".join(str(rj.get(k, "")) for k in ("error", "stderr", "note", "detail"))
    except Exception:
        blob = result_str or ""
    return bool(blob) and bool(_TRANSIENT_PAT.search(blob))


_DOCTRINE = ("\n\nDOCTRINE (non-negotiable, holds even under --auto-approve): act only on OWNED or explicitly "
             "AUTHORIZED targets; stay contained + non-destructive (plant/write for proof, NEVER erase/delete/"
             "drop/truncate); no off-box egress beyond the authorized OSINT lane on owned domains. If a request "
             "is to bypass another party's authentication / paywall / licensing, or to repackage or strip the "
             "identity of a third-party app you do not own, REFUSE and ask for authorization context -- and do "
             "NOT route around this via sub-agents, the board, or a code tool.")


def _agent_loop(client, model, thinking, messages, allowed_names, max_iter, gate, depth=0, tag="[DS", chat=False, quiet=False):
    """One agentic loop over the allowed tool subset. Returns the finish() summary, or None."""
    _p = (lambda *a, **k: None) if quiet else print
    global _SUBAGENT_COUNT
    if depth == 0:
        _SUBAGENT_COUNT = 0   # reset the delegation budget per top-level run / chat turn
    extra_body = None if thinking else {"thinking": {"type": "disabled"}}
    specs = [TOOLS[n][2] for n in allowed_names if n in TOOLS]
    recent_sigs = deque(maxlen=12)   # loop-detection: recent GUARDED-tool signatures only (polls excluded)
    plan_nudged = False
    turns_since_record = 0            # record-as-you-go: turns since the last record_finding/chain_state
    interacted_since_record = False   # target-interaction happened since the last ledger write
    mutated_unverified = False        # a file was edited but not yet exercised/verified (verify-before-finish)
    verify_nudged = False             # the verify-before-finish nudge has fired once (don't loop on it)
    for i in range(1, max_iter + 1):
        compacted = _maybe_compact(messages, client, model)
        if compacted is not messages:
            messages[:] = compacted   # mutate in place so the caller (run_chat) keeps the compacted list
        if not plan_nudged and i >= 4 and not _TODO and depth == 0 and not chat:  # plan only on autonomous runs
            messages.append({"role": "user", "content": "You've taken several steps without a written plan. "
                             "Call write_todos to lay out the remaining steps (one item in_progress), then continue."})
            plan_nudged = True
        turns_since_record += 1
        if interacted_since_record and turns_since_record >= 10 and depth == 0 and not chat:
            messages.append({"role": "user", "content": "RECORD-AS-YOU-GO reminder: you've run several "
                             "target-interaction steps without calling record_finding/chain_state. Anything left "
                             "only in this transcript is LOST at the next compaction (and your final summary will "
                             "under-report it). Record every result you've confirmed so far -- vulnerable, clean, "
                             "or inconclusive -- via record_finding NOW, then continue."})
            turns_since_record = 0
        # SELF-REFLECTION (board item 1): periodically force a short check that the OBJECTIVE is being
        # advanced and the last step actually worked -- the single highest-uplift agentic habit.
        if depth == 0 and not chat and i > 1 and i % 6 == 0:
            messages.append({"role": "user", "content": "Reflect briefly (1-2 lines) before acting: is this "
                             "advancing the OBJECTIVE you were given (not just the starting point)? Did the last "
                             "step ACTUALLY work -- check the tool result, don't assume? If something failed "
                             "transiently, retry or route around it; if an approach is stuck, change it. Then act "
                             "or finish()."})
        kw = dict(model=model, messages=messages, tools=specs, tool_choice="auto",
                  temperature=0.2, max_tokens=1600)
        if extra_body is not None:
            kw["extra_body"] = extra_body
        resp = _create(client, **kw)
        msg = resp.choices[0].message
        if msg.content:
            _p(f"{tag} #{i}] {msg.content}\n", flush=True)
        messages.append(msg.model_dump(exclude_none=True))
        if not msg.tool_calls:
            if chat:
                return None  # a plain reply -> hand control back to the operator (REPL)
            messages.append({"role": "user", "content": "Continue: take the next action, or call finish()."})
            continue
        for tc in msg.tool_calls:
            name = tc.function.name
            if name in ("record_finding", "chain_state"):      # record-as-you-go tracking
                turns_since_record = 0
                interacted_since_record = False
            elif name in ("run_in_kali", "run_command", "run_background", "fetch_url", "render_page", "run_tool"):
                interacted_since_record = True
                mutated_unverified = False   # an exercise/verify step -> a prior edit is now being tested
            try:
                args = json.loads(tc.function.arguments or "{}")
            except Exception:
                args = {}
            entry = TOOLS.get(name)
            if entry is None or name not in allowed_names:
                result = json.dumps({"error": f"tool not available here: {name}"})
            else:
                fn, readonly, _spec_ = entry
                if name in _LOOP_GUARD_TOOLS:  # thrash guard: hash FULL args; track only guarded calls
                    sig = name + "|" + hashlib.md5(
                        json.dumps(args, sort_keys=True).encode("utf-8", "replace")).hexdigest()
                    if recent_sigs.count(sig) >= 2:
                        result = json.dumps({"loop_guard": True, "note": (
                            f"You have run {name} with identical arguments 3+ times with no progress. Do NOT repeat "
                            "it -- change approach, try something different, revert if a fix isn't working, or finish().")})
                        _p(f"{tag} [loop-guard] blocked a repeated {name}\n", flush=True)
                        recent_sigs.append(sig)
                        messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
                        continue
                    recent_sigs.append(sig)
                if name == "vpn_ctl" and args.get("action") == "status":
                    readonly = True  # status is safe
                if readonly:
                    _p(f"{tag} auto] {name}({json.dumps(args)[:160]})", flush=True)
                    # TRANSIENT-ERROR RECOVERY (board item 3): auto-retry a read-only/idempotent tool that
                    # hit an infra hiccup (WSL timeout / OOM / connection / 5xx) -- exactly the class that made
                    # a live run look dead today. Mutating tools are NOT auto-retried (re-approval owns those).
                    result = json.dumps({"error": "not run"})
                    for _attempt in range(3):
                        try: result = fn(**args)
                        except Exception as e: result = json.dumps({"error": repr(e)[:200]})
                        if _attempt < 2 and _is_transient(result):
                            _p(f"{tag}    [transient failure -- auto-retry {_attempt+1}/2 after backoff]\n", flush=True)
                            time.sleep(2 * (_attempt + 1)); continue
                        break
                else:
                    if name == "write_file":
                        preview = _diff_preview(args.get("path", ""), args.get("content", ""))
                    elif name == "apply_edit":
                        preview = "\n".join(difflib.unified_diff(
                            args.get("old_string", "").splitlines(), args.get("new_string", "").splitlines(),
                            fromfile="before", tofile="after", lineterm=""))
                    elif name == "multi_edit":
                        preview = _multi_edit_preview(args.get("path", ""), args.get("edits", []))
                    elif name == "install_kali_tool":
                        preview = args.get("content", "")[:3000]
                    else:
                        preview = None
                    if gate.approve(name, args, preview):
                        try:
                            result = fn(**args)
                            if name in ("apply_edit", "write_file", "multi_edit"):  # ENFORCED auto-verify
                                rj = json.loads(result)
                                if "error" not in rj:
                                    rj["auto_verify"] = _auto_verify(args.get("path", ""))
                                    result = json.dumps(rj)
                                    mutated_unverified = True   # static check done; FUNCTIONAL verify still owed
                        except Exception as e: result = json.dumps({"error": repr(e)[:200]})
                    else:
                        result = json.dumps({"denied_by_operator": True,
                                             "note": "Human declined this action. Do not retry blindly; explain or propose an alternative."})
            _p(f"{tag}    -> {result[:400]}\n", flush=True)
            # item 42: if the tool FAILED (its result JSON carries an 'error'/denied key), tag the tool
            # message so the model reads it as a failure, not a successful tool result. JSON is preserved.
            _tool_content = result
            try:
                _rj = json.loads(result)
                if isinstance(_rj, dict) and ("error" in _rj or _rj.get("denied_by_operator")):
                    _tool_content = "[tool-error] " + result
            except Exception:
                pass
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": _tool_content})
            if name == "finish":
                # VERIFY-BEFORE-FINISH (board item 4): don't accept finish() if a file was edited but never
                # exercised/verified. Nudge ONCE to verify; then honour the next finish() regardless.
                if mutated_unverified and not verify_nudged and not chat:
                    verify_nudged = True
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps({
                        "verify_before_finish": True, "note": "You edited files but have NOT functionally verified "
                        "the change achieves the goal (re-run the test / re-check the oracle / exercise the code "
                        "path -- static auto-verify is not enough). Do that now, then call finish() again. If you "
                        "already verified, say how in the summary."})})
                    _p(f"{tag} [verify-before-finish] nudged the agent to verify its edits\n", flush=True)
                    continue   # don't return the finish yet
                summ = json.loads(result).get("summary", "") or ""
                if not summ.strip():  # fall back to the last thing the agent said
                    for prev in reversed(messages):
                        if prev.get("role") == "assistant" and prev.get("content"):
                            summ = prev["content"]; break
                return summ
    # GUARDRAIL: max_iter reached WITHOUT finish() -- don't drop the work on the floor.
    # Force a best-effort, tool-less summary of what was accomplished / FOUND so far, so
    # evidence and partial findings survive (matters for pentest runs and plan-exec sub-agents
    # that exhaust exec_max_iter). Falls back to None only if even the summary call fails.
    if not chat:
        try:
            messages.append({"role": "user", "content":
                "You have reached the iteration limit WITHOUT calling finish(). Do NOT call any more "
                "tools. In plain text, honestly summarize what you accomplished and what you FOUND so "
                "far (with concrete evidence / HTTP status codes), what remains unfinished, and WHERE "
                "you stopped. Do not fabricate."})
            kw = dict(model=model, messages=messages, temperature=0.2, max_tokens=1200)
            if extra_body is not None:
                kw["extra_body"] = extra_body
            resp = _create(client, **kw)   # no tools -> must answer in text
            final = (resp.choices[0].message.content or "").strip()
            if final:
                _p(f"{tag} [max_iter reached -- forced best-effort summary]\n", flush=True)
                return "[hit max_iter without finish() -- best-effort summary of partial results]\n" + final
        except Exception as e:
            _p(f"{tag} max_iter summary failed: {e}\n", flush=True)
    return None

def _banner(model, endpoint, gate, mode="autonomous"):
    """Distinctive start banner so it's unmistakable this is the DeepSeek Coordinator (not Claude)."""
    appr = "AUTO-APPROVE" if getattr(gate, "auto_approve", False) else ("DRY-RUN" if getattr(gate, "dry_run", False) else "human-approval")
    print("\n" + "=" * 72, flush=True)
    print("   #============================================================#", flush=True)
    print("   #   D E E P S E E K   C O O R D I N A T O R   (aegis)        #", flush=True)
    print("   #============================================================#", flush=True)
    print(f"   brain={model}  seat=DeepSeek  mode={mode}  gate={appr}", flush=True)
    print(f"   target-mode={TARGET_MODE}  aegis_home={AEGIS_HOME}  repo={REPO}", flush=True)
    print(f"   endpoint={endpoint}  aegis-up={_aegis_up()}  audit={os.path.basename(AUDIT_LOG)}", flush=True)
    print("   doctrine: owned/authorized targets only · contained · non-destructive", flush=True)
    print("=" * 72 + "\n", flush=True)


def run(task_text, model, thinking, max_iter, gate, remediate_on_finish=False):
    key, endpoint = _resolve_key_endpoint()
    if not key:
        print("[ds-operator] No API key found. Set DEEPSEEK_API_KEY (or AEGIS_LLM_API_KEY).", flush=True)
        return
    client = OpenAI(api_key=key, base_url=endpoint)
    _CTX.update(client=client, model=model, thinking=thinking, gate=gate, depth=0, sub_max_iter=8)
    _banner(model, endpoint, gate)
    messages = [{"role": "system", "content": SYSTEM + _DOCTRINE + _skill_preface() + _mode_policy(TARGET_MODE) + _memory_preface() + _ledger_block()}, {"role": "user", "content": task_text}]
    summ = _agent_loop(client, model, thinking, messages, list(TOOLS.keys()), max_iter, gate, depth=0, tag="[DS")
    if summ is not None:
        print("=" * 72 + "\nDS-OPERATOR FINAL:\n" + summ + "\n" + "=" * 72)
    else:
        print("[ds-operator] hit max_iter without finish().")
    # STAGE-10 safety net: in a fully autonomous (no-human) run the operator may forget to call
    # remediation() before finishing. If enabled, deterministically run it over this run's VERIFIED
    # findings so the pipeline still completes. Non-destructive; no-op if nothing was verified.
    if remediate_on_finish:
        try:
            verified = len(_VF.verified()) if _VF else 0
        except Exception:
            verified = 1  # if we can't count, let remediation_board's own guard decide
        if verified:
            print(f"\n[ds-operator] --remediate-on-finish: running stage-10 remediation over "
                  f"{verified} verified finding(s)...", flush=True)
            print(t_remediation(emit_fixes=True))
        else:
            print("[ds-operator] --remediate-on-finish: no verified findings; skipping remediation.", flush=True)

CHAT_SYSTEM_ADDENDUM = """

INTERACTIVE SESSION: you are in a live chat with the operator. Converse in PLAIN TEXT -- ask
clarifying questions when scope/authorization/intent is unclear. When you have enough, state the
exact aegis task you will submit (scope + do-NOTs + verification), submit it, and BABYSIT it to
a result: poll read_task_context, watch checkpoint-mtime for real progress, catch stalls / stale or
hung processes, resume or VPN-rotate per doctrine, and report back. For code, use the debug-fix loop
(edit -> auto-verify -> run -> revert if worse) and run_background for anything long-running. Within
one turn, keep taking actions until you either NEED the operator's input or have something to report;
a plain-text message (no tool call) hands control back to the operator for their next message. Use
write_todos to track multi-step work; it and the conversation persist across the session."""

def run_chat(model, thinking, gate, session_path=None):
    key, endpoint = _resolve_key_endpoint()
    if not key:
        print("[ds-operator] No API key found. Set DEEPSEEK_API_KEY (or AEGIS_LLM_API_KEY).", flush=True)
        return
    client = OpenAI(api_key=key, base_url=endpoint)
    _CTX.update(client=client, model=model, thinking=thinking, gate=gate, depth=0, sub_max_iter=8)
    _banner(model, endpoint, gate, mode="interactive chat")
    chat_system = SYSTEM + _DOCTRINE + _skill_preface() + CHAT_SYSTEM_ADDENDUM + _mode_policy(TARGET_MODE) + _memory_preface() + _ledger_block()
    messages = None
    if session_path and os.path.exists(session_path):
        loaded = _load_session(session_path)
        if loaded:
            messages = loaded
            messages[0] = {"role": "system", "content": chat_system}  # refresh doctrine on resume
            print(f"[ds-operator CHAT] resumed {session_path} -- {len(messages)} messages, {len(_TODO)} todos", flush=True)
    if messages is None:
        messages = [{"role": "system", "content": chat_system}]
    print(f"[ds-operator CHAT] model={model} thinking={thinking} | aegis up: {_aegis_up()} | code-repo={REPO}", flush=True)
    if session_path:
        print(f"[ds-operator CHAT] session file: {session_path} (auto-saved after each turn)", flush=True)
    print("Type an instruction. 'exit'/'quit' to leave. Mutating actions still ask y/N.\n", flush=True)
    if _TODO:
        print("[plan]\n" + _render_todos() + "\n", flush=True)
    while True:
        try:
            user_in = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[ds-operator] bye."); break
        if not user_in:
            continue
        if user_in.lower() in ("exit", "quit", "/q", "/quit"):
            print("[ds-operator] bye."); break
        messages.append({"role": "user", "content": user_in})
        try:
            _agent_loop(client, model, thinking, messages, list(TOOLS.keys()),
                        max_iter=CHAT_MAX_ITER, gate=gate, depth=0, tag="[DS", chat=True)
        except Exception as e:
            print(f"[ds-operator] turn error: {repr(e)[:200]}", flush=True)
        if session_path:
            _save_session(session_path, messages)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", default=None, help="one-shot task (omit when using --chat)")
    ap.add_argument("--chat", action="store_true",
                    help="interactive REPL: converse and instruct across turns (keeps context)")
    ap.add_argument("--session", default=None,
                    help="session file to save/continue a --chat conversation (resume where you left off)")
    ap.add_argument("--model", default=os.environ.get("AEGIS_MODEL", "deepseek-v4-pro"),
                    help="model id (default: env AEGIS_MODEL, else deepseek-v4-pro)")
    ap.add_argument("--provider", choices=["deepseek", "openai", "cloudflare"], default=None,
                    help="LLM provider for a direct comparison run: 'deepseek' (default) or 'openai' "
                         "(GPT-5.6 Sol via OPENAI_API_KEY). Sets AEGIS_PROVIDER; 'openai' auto-selects "
                         "model gpt-5.6-sol unless --model is given.")
    ap.add_argument("--think", action="store_true", help="enable DS thinking mode (default off)")
    ap.add_argument("--max-iter", type=int, default=int(os.environ.get("AEGIS_MAX_ITER", "40")),
                    help="max reasoning/act cycles for a task run (default 40, or $AEGIS_MAX_ITER). "
                         "Deep engagements may need 60-120; the max_iter guardrail still emits a "
                         "best-effort summary if the budget is hit.")
    ap.add_argument("--repo", default=None,
                    help="root for code-ops (read/list/search/write/edit); default: aegis-operator")
    ap.add_argument("--aegis-home", dest="aegis_home", default=None,
                    help="path to the aegis-operator project root (holds checkpoints); default: env AEGIS_HOME or the repo dir")
    ap.add_argument("--verify-cmd", default=None,
                    help="command auto-run after each code edit to verify it (e.g. 'pytest -q')")
    ap.add_argument("--dry-run", action="store_true", help="show proposed actions but auto-deny them")
    ap.add_argument("--auto-approve", action="store_true", help="DANGER: approve every action without asking")
    ap.add_argument("--target-mode", choices=["live", "mirror", "split"], default="live",
                    help="live: test the real target; mirror: fingerprint + build a local twin and test that; "
                         "split: recon live, exploit the twin, one minimal confirm on live")
    ap.add_argument("--remediate-on-finish", action="store_true",
                    default=os.environ.get("AEGIS_REMEDIATE_ON_FINISH", "").lower() in ("1", "true", "yes"),
                    help="STAGE 10: after the run finishes, deterministically run the remediation round over "
                         "this run's VERIFIED findings (safety net for autonomous no-human runs). No-op if none.")
    a = ap.parse_args()
    if a.provider:
        os.environ["AEGIS_PROVIDER"] = a.provider
        if a.provider == "openai" and "deepseek" in a.model.lower():
            a.model = "gpt-5.6-sol"   # sensible default when switching provider without --model
    TARGET_MODE = a.target_mode
    VERIFY_CMD = a.verify_cmd
    if a.aegis_home:
        AEGIS_HOME = a.aegis_home
        CKPT_DIR = os.path.join(AEGIS_HOME, "checkpoints")
        CLI = os.path.join(AEGIS_HOME, "aegis_cli.py")
    REPO = a.repo or AEGIS_HOME
    gate = Gate(dry_run=a.dry_run, auto_approve=a.auto_approve)
    if a.chat:
        run_chat(a.model, a.think, gate, session_path=a.session)
    elif a.task:
        run(a.task, a.model, a.think, a.max_iter, gate, remediate_on_finish=a.remediate_on_finish)
    else:
        ap.error('provide --task "..." or --chat')
