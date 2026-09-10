#!/usr/bin/env python3
"""
board_feedback.py -- AUTOMATE the chat-feedback loop.

Instead of manually running a query, reading the board answers, and synthesizing, this does it in one
shot: post a QUESTION (or a run SUMMARY) -> fan out to the consultative panel -> auto-COLLECT their
ANSWERs -> auto-SYNTHESIZE into a deduped, prioritized action list (posted back as SYNTHESIS) ->
optionally auto-VERIFY any code the panel returned via test_suggestions. All on the monitored board;
board data-hygiene (no secrets in the prompt); board chat on deepseek-v4-flash for budget.

Usage:
    python board_feedback.py "what else should we test on the money layer to go deeper?"
    python board_feedback.py --summary-of ../.../findings.jsonl        # summarize a store, then ask+synthesize
    python board_feedback.py "..." --verify --role owner               # also run any code the panel emits
    python board_feedback.py "..." --panel gpt-oss-120b,ds --loop 1200 # re-run every 1200s (feedback loop)
"""
import os, sys, json, time, urllib.request, argparse, subprocess, threading, tempfile
try: sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception: pass
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import cf_agent
import code_suggester
from code_suggester import _load_secret_env
_load_secret_env()
ROOT = os.path.dirname(HERE)
BOARD = os.environ.get("AEGIS_BOARD_DIR", os.path.join(ROOT, "board", "board_files"))
os.makedirs(BOARD, exist_ok=True)

PANEL_SYS = ("You are a security-research analyst on our authorized, contained testing program. Answer the "
             "question concretely with prioritized, actionable bullets. If you propose a concrete test, give "
             "a runnable TARGET/CODE/ORACLE block. Output only your answer.")


def _post_llm(url, key, model, sysp, usr, maxtok, extra=None):
    body = {"model": model, "messages": [{"role": "system", "content": sysp}, {"role": "user", "content": usr}],
            "max_tokens": maxtok, "temperature": 0.4}
    if "openai.com" in url:
        # OpenAI GPT-5-class (reasoning) models reject max_tokens and a non-default temperature:
        # rename to max_completion_tokens and drop temperature (matches aegis_operator._create).
        body["max_completion_tokens"] = body.pop("max_tokens")
        body.pop("temperature", None)
    if extra: body.update(extra)
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


def _ds(prompt, sysp, maxtok=1200, model=None):
    key = os.environ.get("AEGIS_LLM_API_KEY")
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip('/')
    model = model or os.environ.get("AEGIS_BOARD_MODEL", "deepseek-v4-flash")
    return _post_llm(ep + "/chat/completions", key, model, sysp, prompt, maxtok)


def ask_panel(question, panel):
    print("== panel ==")
    ans = {}
    def run(name):
        try:
            if name == "sol":
                rf = "You are a senior software-quality reviewer for our OWN system (authorized). "
                ans[name] = _post_llm("https://api.openai.com/v1/chat/completions", os.environ["OPENAI_API_KEY"],
                                      "gpt-5.6", rf + PANEL_SYS, rf + question, 1400, extra={"max_completion_tokens": 1400})
            elif name in ("ds", "deepseek"):
                ans[name] = _ds(question, PANEL_SYS, 1200)
            else:
                fn = "qwen2.5-coder-32b" if name in ("qwen", "qwen-coder") else name
                ans[name] = cf_agent.ask(fn, PANEL_SYS, question, max_tokens=1200)
            ans[name] = ans[name] or "[empty]"
        except Exception as e:
            ans[name] = f"[error] {e}"
        board("ANSWER", name, ans[name])
    ts = [threading.Thread(target=run, args=(n,)) for n in panel]
    for t in ts: t.start()
    for t in ts: t.join()
    return ans


def synthesize(question, answers):
    print("== auto-synthesis ==")
    joined = "\n\n".join(f"[{k}]\n{v}" for k, v in answers.items())
    p = (f"Question: {question}\n\nPanel answers below. Synthesize into a DEDUPED, PRIORITIZED action list "
         "(most valuable first), noting where answers converged. Terse. Output only the synthesis.\n\n" + joined)
    syn = _ds(p, "You are the coordinator. Output ONLY the prioritized synthesis as bullets - no preamble, no meta-commentary.", 1200, model=os.environ.get("AEGIS_SYNTH_MODEL","deepseek-v4-pro"))
    board("SYNTHESIS", "coordinator(claude)", syn)
    return syn


def verify_panel_code(answers, role):
    print("== auto-verify panel code (test_suggestions) ==")
    # any answer containing a TARGET/CODE/ORACLE block gets run
    ts = os.path.join(HERE, "test_suggestions.py")
    results = {}
    for who, txt in answers.items():
        if "TARGET" not in txt.upper() or "ORACLE" not in txt.upper():
            continue
        fn = os.path.join(tempfile.gettempdir(), f"feedback_{who}.md")
        open(fn, "w", encoding="utf-8").write(txt)
        try:
            r = subprocess.run([sys.executable, ts, "--file", fn, "--source", who, "--execute", "--role", role],
                               capture_output=True, text=True, timeout=180)
            tail = [l for l in r.stdout.splitlines() if "summary" in l]
            results[who] = tail[-1] if tail else "no result"
            print(f"  [{who}] {results[who]}")
        except Exception as e:
            results[who] = f"[error] {e}"
    if results:
        board("VERIFY", "coordinator(claude)", "\n".join(f"{k}: {v}" for k, v in results.items()))
    else:
        print("  (no panel answer contained a runnable TARGET/CODE/ORACLE block)")
    return results


def summary_of(store_path):
    """Turn a findings store into a short SUMMARY to seed the question (the 'after a run, summarize' step)."""
    sys.path.insert(0, HERE)
    from verified_findings import FindingStore
    fs = FindingStore(store_path).findings()
    v = [f for f in fs.values() if f.get("status") == "verified"]
    lines = [f"- [{f.get('severity')}] {f.get('claim_type')}: {f.get('summary','')[:120]}" for f in v[:12]]
    return f"{len(v)} verified findings in {os.path.basename(store_path)}:\n" + "\n".join(lines)


def one_round(question, panel, verify, role):
    board("QUESTION", "coordinator(claude)", question)
    ans = ask_panel(question, panel)
    try:
        syn = synthesize(question, ans)
    except Exception as e:
        # A transient synth failure (timeout/5xx/auth) must not crash --loop or discard the
        # panel answers already collected+boarded this iteration.
        syn = f"[synthesis error] {e}"
        board("SYNTHESIS", "coordinator(claude)", syn)
    if verify:
        verify_panel_code(ans, role)
    print("\n--- SYNTHESIS ---\n" + syn)
    return syn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("question", nargs="?", default="")
    ap.add_argument("--summary-of", dest="store", help="seed the question from a findings store summary")
    ap.add_argument("--panel", default="gpt-oss-120b,gpt-oss-20b,ds")   # Sol booted
    ap.add_argument("--verify", action="store_true", help="auto-run any code the panel returns")
    ap.add_argument("--role", default="owner")
    ap.add_argument("--loop", type=int, default=0, help="re-run every N seconds (feedback loop); 0 = once")
    a = ap.parse_args()
    panel = [x.strip() for x in a.panel.split(",") if x.strip()]
    q = a.question
    if a.store:
        q = summary_of(a.store) + "\n\nGiven these, what else should we test to go deeper / find more gaps?"
    if not q:
        sys.exit("give a question or --summary-of <store>")
    while True:
        one_round(q, panel, a.verify, a.role)
        if not a.loop:
            break
        print(f"\n[feedback loop] sleeping {a.loop}s...")
        time.sleep(a.loop)


if __name__ == "__main__":
    main()
