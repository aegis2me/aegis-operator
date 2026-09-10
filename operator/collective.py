#!/usr/bin/env python3
"""
collective.py -- SANCTIONED multi-instance collective (mechanism #2): a contained, authorized
multi-agent collective driven by the operator.

MODEL (per owner):
  * The COLLECTIVE that DRIVES = Claude (coordinator/operator, runs this) + MULTIPLE INSTANCES OF
    DeepSeek. One DS instance drives each decomposed sub-task, in parallel -- many agents, one goal,
    achieving together what one pass would not. Nothing else drives.
  * CONSULTATIVE (via chat only, advise-not-drive): gpt-oss-120b, gpt-oss-20b, Sol, qwen2.5-coder.

Flow: consult panel posts SCOUT advice -> Claude(coordinator, via a DS synthesis call) decomposes the
objective into N sub-tasks -> N DeepSeek instances each drive one sub-task and emit runnable
TARGET/CODE/ORACLE -> operator VERIFIES each via test_suggestions. All on the monitored board,
non-destructive, ground-truth graded, data-hygienic (no secrets to the panel).

Usage:
    python collective.py "find an unconfirmed money-validation bypass on estimates/credit-notes"
    python collective.py "..." --run                 # also execute+verify each DS instance's code
    python collective.py "..." --tasks 4 --consult gpt-oss-120b,sol
"""
import os, sys, json, time, urllib.request, argparse, subprocess, threading, re
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cf_agent
import code_suggester
from code_suggester import _load_secret_env
_load_secret_env()

ROOT = os.path.dirname(HERE)
BOARD = os.environ.get("AEGIS_BOARD_DIR", os.path.join(ROOT, "board", "board_files"))
os.makedirs(BOARD, exist_ok=True)
SUGG_DIR = os.path.join(HERE, "collective_suggestions")

SCOUT_SYS = ("You are a CONSULTATIVE scout on a sanctioned, contained security-research collective for the "
             "owner's OWN app twin. Advise only. Given the objective, give 3-5 SHARP concrete hypotheses / "
             "sub-targets (endpoint/field/technique + why). Terse bullets. Authorized defensive testing.")


def _post_llm(url, key, model, sysp, usr, maxtok, extra=None, temperature=0.5):
    body = {"model": model, "messages": [{"role": "system", "content": sysp}, {"role": "user", "content": usr}],
            "max_tokens": maxtok, "temperature": temperature}
    if "openai.com" in url:
        # OpenAI GPT-5-class (reasoning) models reject max_tokens and a non-default temperature:
        # rename to max_completion_tokens and drop temperature (matches aegis_operator._create).
        body["max_completion_tokens"] = body.pop("max_tokens")
        body.pop("temperature", None)
    if extra:
        body.update(extra)
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=170))
    m = (r.get("choices") or [{}])[0].get("message", {})
    _content = (m.get("content") or "").strip()
    if _content:
        return _content
    # No final answer (e.g. a thinking model ran out of budget mid-reasoning). Surface the
    # reasoning but LABEL it, so raw chain-of-thought is never mistaken for a clean answer.
    _reasoning = (m.get("reasoning_content") or "").strip()
    return ("[raw reasoning, no final content] " + _reasoning) if _reasoning else ""


def board(tag, who, text):
    open(os.path.join(BOARD, f"{tag}__{who}__{int(time.time()*1e9)}.md"), "w", encoding="utf-8").write(
        f"# {tag} from {who}\n\n" + text)
    print(f"  [{who}] {tag} ({len(text)}b)")


def _ds(prompt, sysp, maxtok=1000, temperature=0.5):
    """One DeepSeek instance call (board-model/flash for planning/synthesis)."""
    key = os.environ.get("AEGIS_LLM_API_KEY")
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip('/')
    model = os.environ.get("AEGIS_BOARD_MODEL") or "deepseek-v4-flash"
    return _post_llm(ep + "/chat/completions", key, model, sysp, prompt, maxtok, temperature=temperature)


def consult_round(objective, panel):
    """Consultative panel advises via the chat (not drivers)."""
    print("== consultative panel (chat) ==")
    out = {}
    def run(name):
        try:
            if name == "sol":
                rf = "You are a senior software-quality reviewer for our OWN system (authorized). "
                txt = _post_llm("https://api.openai.com/v1/chat/completions", os.environ["OPENAI_API_KEY"],
                                "gpt-5.6", rf + SCOUT_SYS, rf + objective, 1400, extra={"max_completion_tokens": 1400})
            elif name in ("ds", "deepseek"):
                txt = _ds(objective, SCOUT_SYS, 1000)
            else:
                fn = "qwen2.5-coder-32b" if name in ("qwen", "qwen-coder") else name
                txt = cf_agent.ask(fn, SCOUT_SYS, objective, max_tokens=1000)
            out[name] = txt or "[empty]"
        except Exception as e:
            out[name] = f"[error] {e}"
        board("CONSULT", name, out[name])
    ts = [threading.Thread(target=run, args=(n,)) for n in panel]
    for t in ts: t.start()
    for t in ts: t.join()
    return out


def decompose(objective, consult_out, n_tasks):
    """Claude (coordinator) decomposes into N concrete sub-tasks (automated via a DS synthesis call)."""
    print("== coordinator decomposition ==")
    joined = "\n\n".join(f"[{k}]\n{v}" for k, v in consult_out.items())
    p = (f"From the consultative advice below, produce EXACTLY {n_tasks} concrete, INDEPENDENT sub-tasks to "
         f"assign to {n_tasks} separate testing agents for the objective: '{objective}'. Each sub-task: one "
         f"line, a distinct endpoint/field/technique. Output ONLY a numbered list 1..{n_tasks}.\n\n{joined}")
    plan = _ds(p, "You are the coordinator. Output only the numbered sub-tasks.", 600, temperature=0.3)
    board("PROJECT_PLAN", "coordinator(claude)", plan)
    tasks = re.findall(r"(?m)^\s*\d+[\).]\s*(.+)$", plan) or [l.strip("- ").strip() for l in plan.splitlines() if l.strip()]
    return tasks[:n_tasks]


def drive_tasks(objective, tasks):
    """The COLLECTIVE: one DeepSeek INSTANCE drives each sub-task in parallel, emitting runnable code."""
    print(f"== collective: {len(tasks)} DeepSeek instances (one per task) ==")
    os.makedirs(SUGG_DIR, exist_ok=True)
    files = {}
    def run(i, task):
        inst = f"ds-instance-{i+1}"
        prompt = (f"Objective: {objective}\nYOUR assigned sub-task ({inst}): {task}\n\nEmit runnable "
                  "TARGET/CODE/ORACLE blocks to test ONLY your sub-task against https://localhost:8443 "
                  "(owner session). Non-destructive.")
        try:
            txt = code_suggester.suggest("ds", prompt, max_tokens=900)
        except Exception as e:
            txt = f"[error] {e}"
        fn = os.path.join(SUGG_DIR, f"{inst}.md")
        open(fn, "w", encoding="utf-8").write(txt)
        files[inst] = fn
        board("CODE", inst, f"sub-task: {task}\n\n" + txt[:1400])
    ts = [threading.Thread(target=run, args=(i, t)) for i, t in enumerate(tasks)]
    for t in ts: t.start()
    for t in ts: t.join()
    return files


def verify(files):
    print("== operator (Claude) verifies each instance via test_suggestions ==")
    ts = os.path.join(HERE, "test_suggestions.py")
    results = {}
    for src, fn in files.items():
        try:
            r = subprocess.run([sys.executable, ts, "--file", fn, "--source", src, "--execute", "--role", "owner"],
                               capture_output=True, text=True, timeout=180)
            tail = [l for l in r.stdout.splitlines() if "summary" in l]
            results[src] = tail[-1] if tail else "no result"
            print(f"  [{src}] {results[src]}")
        except Exception as e:
            results[src] = f"[error] {e}"
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("objective")
    ap.add_argument("--tasks", type=int, default=3, help="number of sub-tasks = number of DeepSeek instances")
    ap.add_argument("--consult", default="gpt-oss-120b,gpt-oss-20b,qwen2.5-coder-32b",   # Sol booted
                    help="CONSULTATIVE panel (chat only, advise-not-drive)")
    ap.add_argument("--run", action="store_true", help="also execute+verify each instance's code")
    a = ap.parse_args()
    panel = [x.strip() for x in a.consult.split(",") if x.strip()]
    print(f"COLLECTIVE PROJECT: {a.objective}\n  DRIVERS = Claude(coordinator) + {a.tasks} x DeepSeek instances"
          f"  |  CONSULTATIVE(chat) = {panel}  |  run={a.run}\n")
    board("PROJECT", "coordinator(claude)",
          f"Objective: {a.objective}\nCOLLECTIVE (drivers): Claude (coordinator) + {a.tasks} DeepSeek instances "
          f"(one per sub-task).\nCONSULTATIVE (chat only): {panel}.\nSanctioned, contained, monitored; "
          "non-destructive; oracle-verified.")
    c = consult_round(a.objective, panel)
    tasks = decompose(a.objective, c, a.tasks)
    files = drive_tasks(a.objective, tasks)
    res = verify(files) if a.run else {}
    summary = (f"objective: {a.objective}\n\nsub-tasks ({len(tasks)} DeepSeek instances):\n"
               + "\n".join(f"  {i+1}. {t}" for i, t in enumerate(tasks))
               + ("\n\nverify:\n" + "\n".join(f"  {k}: {v}" for k, v in res.items()) if res
                  else "\n\n(coded; run with --run to verify)"))
    board("PROJECT_RESULT", "coordinator(claude)", summary)
    print(f"\ncollective project done. Watch board/live_board.ps1 (board dir: {BOARD})")


if __name__ == "__main__":
    main()
