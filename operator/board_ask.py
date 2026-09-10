#!/usr/bin/env python3
"""
board_ask.py -- the HUMAN's channel into the board, via the operator/co-pilot.

You frame a question; it is posted to the board and (unless --no-panel) fanned out to the panel;
each answer lands on the board, which you watch live in board/live_board.ps1 (20-30s refresh).

Board data-hygiene (PIPELINE v3): send NO secrets/credentials here -- the panel gets only your
framed question. External members (DeepSeek/Sol/CF) see sanitized prompts, nothing privileged.

The DEFAULT panel is ds + cf (gpt-oss-120b/20b) + the coder bench. Sol (GPT-5.6) is OPT-IN only
(content-gated + ~15-25x the coders' price); add it deliberately with `--panel sol` for a
distinct-lineage second opinion.
(kimi-k2.7-code, llama-3.3-70b, llama-4-scout, deepseek-r1-distill-32b) -- the coders answer here as
CONSULTANTS (their opinion), not as code writers. Narrow it with --panel when you want fewer voices.

Usage:
    python board_ask.py "should we prioritise the estimate->invoice copy path or the QB webhook next?"
    python board_ask.py "..." --no-panel          # just post the question to the board
    python board_ask.py "..." --panel ds,sol       # limit which panel members answer
    python board_ask.py "..." --panel ds,coders    # ds + the strong coder bench only
"""
import os, sys, json, time, urllib.request, argparse, threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cf_agent


def _load():
    p = os.path.join(HERE, "secret.env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1); k = k.strip()
                if not os.environ.get(k):
                    os.environ[k] = v.strip().strip('"').strip("'")


_load()
ROOT = os.path.dirname(HERE)
BOARD = os.environ.get("AEGIS_BOARD_DIR", os.path.join(ROOT, "board", "board_files"))
os.makedirs(BOARD, exist_ok=True)

PANEL_SYS = ("You are a security-research analyst on a shared board for the owner's OWN authorized, "
             "contained test. Answer the human's question concretely and concisely. Output only your answer.")


def _post(url, key, model, sysp, usr, maxtok, extra=None):
    body = {"model": model, "messages": [{"role": "system", "content": sysp},
                                         {"role": "user", "content": usr}],
            "max_tokens": maxtok, "temperature": 0.4}
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
    try:
        import cost_meter
        cost_meter.record(model, r.get("usage"), caller="board_ask",
                          provider=("openai" if "openai.com" in url else "deepseek"),
                          raw_chars=len((m.get("content") or m.get("reasoning_content") or "")))
    except Exception:
        pass
    _content = (m.get("content") or "").strip()
    if _content:
        return _content
    # No final answer (e.g. a thinking model ran out of budget mid-reasoning). Surface the
    # reasoning but LABEL it, so raw chain-of-thought is never mistaken for a clean answer.
    _reasoning = (m.get("reasoning_content") or "").strip()
    return ("[raw reasoning, no final content] " + _reasoning) if _reasoning else ""


def write(tag, who, text):
    fn = os.path.join(BOARD, f"{tag}__{who}__{int(time.time()*1e9)}.md")
    open(fn, "w", encoding="utf-8").write(f"# {tag} from {who}\n\n" + text)
    print(f"[{who}] {tag} ({len(text)}b)")


def ds(q):
    # board chat uses flash for budget (the operator BRAIN is pro; this Q&A path is separate)
    key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip('/')
    model = os.environ.get("AEGIS_BOARD_MODEL") or "deepseek-v4-flash"
    try:
        # answer-only path: DISABLE thinking so the token budget produces a FINAL answer instead of
        # burning out mid-reasoning (the raw-chain-of-thought pollution). Give it room, too.
        write("ANSWER", "ds_direct", _post(ep + "/chat/completions", key, model, PANEL_SYS, q, 2600,
                                           extra={"thinking": {"type": "disabled"}}) or "[empty]")
    except Exception as e:
        write("ANSWER", "ds_direct", f"[error] {e}")


def sol(q):
    rf = "You are a senior software-quality / correctness reviewer for our OWN system. "
    try:
        write("ANSWER", "sol", _post("https://api.openai.com/v1/chat/completions", os.environ["OPENAI_API_KEY"],
              "gpt-5.6", rf + "Output only your answer.", rf + q, 1400, extra={"max_completion_tokens": 1400}) or "[empty]")
    except Exception as e:
        write("ANSWER", "sol", f"[error] {e}")


def claude_note(text):
    """Claude is a first-class board member whose answer comes DIRECTLY from the coordinator (the Claude
    Code session driving the board) -- NOT via an API call/key. The coordinator passes Claude's take with
    --claude "..." and it lands as a first-class board ANSWER alongside the panel."""
    write("ANSWER", "claude", (text or "").strip() or "[empty]")


def cf(q):
    for m in ("gpt-oss-120b", "gpt-oss-20b", "mistral-small-24b"):
        try:
            write("ANSWER", f"cf_{m}", cf_agent.ask(m, PANEL_SYS, q, max_tokens=1200) or "[empty]")
        except Exception as e:
            write("ANSWER", f"cf_{m}", f"[error] {e}")


# The strong CODER bench, as board CONSULTANTS. Called via cf_agent._post so PANEL_SYS is sent verbatim
# (NOT the code-writer ROLE_PROMPTS role) -- we want their OPINION here, not TARGET/CODE/ORACLE blocks.
# Reasoning models (kimi, r1-distill) get a bigger budget so they land a FINAL answer, not raw CoT.
CODER_PANEL = [("kimi-k2.7-code", 2800), ("llama-3.3-70b", 1600),
               ("llama-4-scout", 1600), ("deepseek-r1-distill-32b", 4000)]


def coders(q):
    def one(m, tok):
        try:
            write("ANSWER", f"cf_{m}", cf_agent._post(m, PANEL_SYS, q, tok, 0.4) or "[empty]")
        except Exception as e:
            write("ANSWER", f"cf_{m}", f"[error] {e}")
    ts = [threading.Thread(target=one, args=(m, t)) for m, t in CODER_PANEL]
    for t in ts: t.start()
    for t in ts: t.join()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("question")
    ap.add_argument("--no-panel", action="store_true", help="just post the question; don't query the panel")
    ap.add_argument("--claude", help="Claude's own board answer, supplied by the coordinator session (Claude is a first-class member; answers directly, no API key)")
    ap.add_argument("--panel", default="ds,cf,coders",   # Sol OPT-IN only (cost/value): add sol explicitly
                    help="comma list of members to ask: ds, sol, cf (gpt-oss-120b/20b), coders "
                         "(kimi-k2.7-code + llama-3.3-70b + llama-4-scout + deepseek-r1-distill-32b). "
                         "Default = all.")
    a = ap.parse_args()
    write("QUESTION", "human", a.question)
    if getattr(a, "claude", None):
        claude_note(a.claude)   # Claude (coordinator) answers directly -- first-class board member

    print(f"posted your question to the board ({BOARD}).")
    if a.no_panel:
        print("watch it (and any replies) in board/live_board.ps1"); return
    want = {x.strip() for x in a.panel.split(",")}
    fns = [f for name, f in (("ds", ds), ("sol", sol), ("cf", cf), ("coders", coders)) if name in want]
    ts = [threading.Thread(target=f, args=(a.question,)) for f in fns]
    for t in ts: t.start()
    for t in ts: t.join()
    print(f"\npanel answered on the board. Watch live: board/live_board.ps1")


if __name__ == "__main__":
    main()
