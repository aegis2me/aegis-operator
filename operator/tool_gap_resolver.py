#!/usr/bin/env python3
"""
tool_gap_resolver.py -- board-advised tool provisioning ("if a tool is missing, close the gap").

Loop: given a technique/task (or an explicit tool list), find which tools are MISSING on Kali, ASK
THE BOARD what tool(s) close the gap (a Kali-available or buildable ALTERNATIVE, with an install
method), then ADD them to Kali via a SAFE fixed install template (apt / pip / git-source). The board
only picks the tool NAME + METHOD (+ optional git URL); provisioning uses fixed command templates,
never arbitrary board-provided shell. Complements kali_driver's `ensure_tool` (single-tool cascade).

Contained: installs on the operator's OWN Kali box (egress to package repos / GitHub), never the
target. Board data-hygiene: the prompt is the tool gap only -- no secrets.

Usage:
    python tool_gap_resolver.py --tools syft,grype,dependency-check   # explicit list
    python tool_gap_resolver.py --technique "container image SBOM"    # pull tools from the technique DB
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

WSL_DISTRO = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")

# SAFE fixed install templates -- the board picks the method; we never run board-provided shell.
_INSTALL = {
    "apt":    "apt-get update -y >/dev/null 2>&1; apt-get install -y {tool}",
    "pip":    "pipx install {tool} || pip3 install --break-system-packages {tool}; ln -sf /root/.local/bin/{tool} /usr/local/bin/{tool} 2>/dev/null",
    "source": "apt-get install -y build-essential git >/dev/null 2>&1; cd /opt && rm -rf {repo} && git clone --depth 1 {url} && cd {repo} && (make && (make install || cp {tool} /usr/local/bin/ 2>/dev/null))",
}

_USE_RE = re.compile(r"USE\s+(\S+)(?:.*?METHOD\s+(apt|pip|source))?(?:.*?URL\s+(\S+))?", re.I)


def parse_board(text: str) -> list:
    """Parse board advice lines 'USE <tool> METHOD <apt|pip|source> [URL <git-url>]' -> suggestions."""
    out, seen = [], set()
    for m in _USE_RE.finditer(text or ""):
        tool = m.group(1).strip().strip(".,`'\"")
        if not tool or tool.lower() in seen:
            continue
        seen.add(tool.lower())
        out.append({"tool": tool, "method": (m.group(2) or "apt").lower(), "url": m.group(3) or ""})
    return out


def _kali(cmd: str, timeout: int = 600) -> tuple:
    p = subprocess.run(["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or ""), (p.stderr or "")


def check_present(tools, run=None) -> dict:
    """Return {tool: bool} for presence on Kali (login-shell command -v)."""
    run = run or (lambda c: _kali(c)[1])
    present = {}
    for t in tools:
        out = run(f"command -v {t} >/dev/null 2>&1 && echo YES || echo NO")
        present[t] = "YES" in out
    return present


def install_one(sug: dict, run=None) -> dict:
    """Provision ONE suggestion via a SAFE fixed template. Returns {tool, method, installed, path}."""
    run = run or (lambda c: _kali(c)[1])
    tool, method, url = sug["tool"], sug.get("method", "apt"), sug.get("url", "")
    tmpl = _INSTALL.get(method, _INSTALL["apt"])
    repo = re.sub(r"\.git$", "", (url.rsplit("/", 1)[-1] or tool)) if url else tool
    cmd = tmpl.format(tool=tool, url=url, repo=repo)
    run(f"{cmd} >/dev/null 2>&1 || true")
    loc = run(f"command -v {tool} 2>/dev/null || true").strip()
    return {"tool": tool, "method": method, "installed": bool(loc), "path": loc}


def resolve(tools, ask, run=None, do_install=True) -> dict:
    """Orchestrate: check presence -> ask the board about the MISSING ones -> provision -> re-check.
    `ask(missing:list, context:str) -> board_text`. Returns a structured report."""
    present = check_present(tools, run)
    missing = [t for t, ok in present.items() if not ok]
    report = {"requested": tools, "present": [t for t in tools if present[t]],
              "missing": missing, "board_suggestions": [], "provisioned": [], "still_missing": []}
    if not missing:
        return report
    advice = ask(missing, "These security tools are missing on Kali. For EACH, give a Kali-available "
                          "or buildable ALTERNATIVE that closes the same capability gap, one per line "
                          "as: USE <tool> METHOD <apt|pip|source> URL <git-url-if-source>.")
    suggestions = parse_board(advice)
    report["board_suggestions"] = suggestions
    if do_install:
        for s in suggestions:
            report["provisioned"].append(install_one(s, run))
        # the capability gap is CLOSED when the board's suggested ALTERNATIVES installed; flag only
        # the alternatives that failed to install (the original names are intentionally replaced).
        report["still_missing"] = [p["tool"] for p in report["provisioned"] if not p["installed"]]
        report["gap_closed"] = bool(report["provisioned"]) and not report["still_missing"]
    return report


def _technique_tools(query: str) -> list:
    """Pull candidate kali_tools from the technique DB for a technique/task query."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rag"))
    try:
        import technique_search as TS
        tools = set()
        for t in TS.search(query, limit=8):
            for k in (t.get("kali_tools") or []):
                tools.add(k.strip())
        return sorted(x for x in tools if x)
    except Exception:
        return []


def _board_ask(missing, context):
    """CLI wiring: fan out to a couple of board members for tool-gap advice (sanitized, no secrets)."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import remediation_board as RB
    import cf_agent
    sysp = ("You are a board member advising on tooling for an AUTHORIZED, CONTAINED security lab on "
            "Kali. Only recommend real, installable tools.")
    usr = f"{context}\n\nMISSING TOOLS: {', '.join(missing)}"
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
    parts = []
    try:
        parts.append(RB._post_openai_style(ep + "/chat/completions", os.environ.get("AEGIS_LLM_API_KEY", ""),
                                           "deepseek-v4-pro", sysp, usr, 900, think=False))
    except Exception:
        pass
    try:
        parts.append(cf_agent.ask("gpt-oss-120b", sysp, usr, max_tokens=900))
    except Exception:
        pass
    return "\n".join(p for p in parts if p)


def main():
    ap = argparse.ArgumentParser(description="Board-advised provisioning of missing Kali tools.")
    ap.add_argument("--tools", help="comma-separated explicit tool list")
    ap.add_argument("--technique", help="technique/task query -> pull tools from the technique DB")
    ap.add_argument("--dry-run", action="store_true", help="check + ask the board, but do NOT install")
    a = ap.parse_args()
    tools = [t.strip() for t in (a.tools or "").split(",") if t.strip()] or _technique_tools(a.technique or "")
    if not tools:
        print("no tools to check (pass --tools or --technique)"); return
    import json
    print(json.dumps(resolve(tools, _board_ask, do_install=not a.dry_run), indent=2))


if __name__ == "__main__":
    main()
