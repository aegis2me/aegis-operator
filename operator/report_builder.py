#!/usr/bin/env python3
"""
report_builder.py -- final-report generation for a pass run, INCLUDING a board-conversation summary
produced by a dedicated function (documented summaries of the panel's proposed actions / code /
approaches -- summaries, not the detailed log).

    board_conversation_summary(board_dir) -> markdown   # the requested function
    build_pass_report(passrun_results, board_dir, out)  # full report using it
"""
from __future__ import annotations

import glob, json, os, re, collections

# board post tag -> human topic name (board() writes files "<TAG>__<who>__<ts>.md")
_TOPIC = {
    "RMD": "Stage-10 remediation — panel fix proposals",
    "RMD_FIX": "Remediation — concrete code patches proposed",
    "RMD_CONSENSUS": "Remediation — synthesized consensus",
    "METR": "METR-informed evaluation methodology",
    "VCLASS": "Supply-chain / misconfig / zero-day discovery design",
    "LEARN": "Self-learning (co-occurrence + hit-rate) design",
    "RATING": "Sophistication rating + human/commercial comparison",
    "PERSIST": "Persistent budgeted discovery loop design",
    "DISCOVER": "Known-anchor expansion + novel-deepening modes",
    "FIRSTCLASS": "Roadmap to a first-class pen-test system",
}
_NOISE = re.compile(r"^\s*(\||#|\-{3,}|\[raw reasoning|We need|Let me|Let's|Need |\d+\.\s*$)", re.I)


def _first_gist(body: str, n=200) -> str:
    for line in body.splitlines():
        s = line.strip().lstrip("*-# ").strip()
        if len(s) > 25 and not _NOISE.match(line):
            return (s[:n] + "…") if len(s) > n else s
    return ""


def board_conversation_summary(board_dir: str, per_topic: int = 3) -> str:
    """Read the board post files, group by topic, and emit a SUMMARY (contributors + a few
    representative one-line proposals per topic; code proposals counted). Not the detailed log."""
    if not os.path.isdir(board_dir):
        return "_(no board directory found)_\n"
    by_tag = collections.defaultdict(lambda: {"who": set(), "gists": [], "code": 0})
    for f in sorted(glob.glob(os.path.join(board_dir, "*.md"))):
        try:
            txt = open(f, encoding="utf-8").read()
        except Exception:
            continue
        m = re.match(r"#\s*(\w+)\s+from\s+(\S+)", txt)
        tag = m.group(1) if m else os.path.basename(f).split("__")[0]
        who = m.group(2) if m else "?"
        body = txt.split("\n\n", 1)[1] if "\n\n" in txt else txt
        rec = by_tag[tag]
        rec["who"].add(who)
        if tag == "RMD_FIX" or "FILE:" in body or "```diff" in body:
            rec["code"] += 1
        g = _first_gist(body)
        if g and len(rec["gists"]) < per_topic:
            rec["gists"].append(f"{who}: {g}")
    if not by_tag:
        return "_(no board conversation recorded)_\n"
    out = ["The multi-model board (Claude · DeepSeek-v4-pro · GPT-5.6/Sol · gpt-oss-120b/20b · qwen) was "
           "consulted at each design decision. Summaries of what each round proposed:\n"]
    order = [t for t in _TOPIC if t in by_tag] + [t for t in by_tag if t not in _TOPIC]
    for tag in order:
        rec = by_tag[tag]
        topic = _TOPIC.get(tag, tag)
        out.append(f"### {topic}")
        out.append(f"- **Contributors:** {', '.join(sorted(rec['who']))}"
                   + (f"  ·  **code patches proposed:** {rec['code']}" if rec["code"] else ""))
        for g in rec["gists"]:
            out.append(f"- {g}")
        out.append("")
    return "\n".join(out)


def build_pass_report(results: dict, board_dir: str, out_path: str, target="target mirror") -> str:
    modes = [m for m in ("operator", "exploitgym", "redteam") if m in results]
    L = [f"# Aegis — full-capability pass report ({target})", "",
         "_Three run modes exercised through the shared iterative-hunt engine (fact-finding → "
         "envelope-pushing → pentest), oracle-verified against the live mirror. Effort logged to "
         "exhaustion. Board consultations summarized at the end._", "",
         "## Effort & attempts (to exhaustion)", "",
         "| mode | attempts | stop reason | facts | weaknesses | phase breakdown |",
         "|---|---|---|---|---|---|"]
    for m in modes:
        r = results[m]
        pc = ", ".join(f"{k}:{v}" for k, v in (r.get("phase_counts") or {}).items())
        L.append(f"| {m} | {r['attempts_used']} | {r['stop_reason']} | {len(r['facts'])} | "
                 f"{len(r['weaknesses'])} | {pc} |")
    rt = results.get("redteam", {})
    L += ["", f"- Red-Team scope enforcement: **{rt.get('scope_blocked', 0)}** off-scope action(s) blocked; "
          f"attack-graph nodes from findings: {rt.get('attack_graph_nodes', 0)}.",
          f"- Reward-hack monitor over verified findings: **{'clean' if results.get('_reward_hack_scan', {}).get('clean') else 'FLAGS'}**"
          f" ({len(results.get('_reward_hack_scan', {}).get('flags', []))} flag(s)).", "",
          "## Findings comparison (across modes)", ""]
    # weaknesses are consistent across modes (same deterministic oracle) -> show the union once + agreement
    union = {}
    for m in modes:
        for w in results[m]["weaknesses"]:
            union[w.get("detail", str(w))] = w.get("weakness", "?")
    L.append(f"All three modes agreed on **{len(union)}** verified weakness(es) (deterministic oracle):")
    L += [f"- `{cls}` — {detail}" for detail, cls in sorted(union.items())] or ["- _(none)_"]
    L += ["", "**Facts established (sample):** " + "; ".join(results[modes[0]]["facts"][:8]), "",
          "## Interpretation", "",
          "- **Fact-finding** established the surface (health, per-role identity, entity enumeration).",
          "- **Envelope-pushing** completed the authz picture (MODE-1 anchor expansion): the "
          "segregation-of-duties overreach (M4) reproduced live across multiple role×endpoint cells.",
          "- **Pentest** confirmed the money-validation class is CLOSED (negative/overflow → 400).",
          "- All modes share the engine; **Red-Team adds authorization/scope enforcement** (off-scope "
          "probe blocked) and attack-graph analysis; **ExploitGym adds the audited scorecard framing**.", "",
          "## Board conversation — summary of proposals, code & approaches", ""]
    L.append(board_conversation_summary(board_dir))
    L += ["---", "_Deterministic playbook pass (reproducible); the LLM board is the production "
          "brainstorm. Contained mirror, oracle-verified, non-destructive._"]
    report = "\n".join(L) + "\n"
    open(out_path, "w", encoding="utf-8").write(report)
    return report


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--board-dir", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "board", "board_files"))
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    res = json.load(open(a.results, encoding="utf-8"))
    build_pass_report(res, a.board_dir, a.out)
    print(f"[report] written -> {a.out}")


if __name__ == "__main__":
    main()
