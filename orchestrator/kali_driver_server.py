"""
kali_driver MCP server.

Exposes one tool, run_command, which executes a shell command inside the
`kali-linux` WSL2 distro and returns stdout/stderr/exit code. This is the
real command-execution backend for aegis's agentic tasks -- every
command it runs actually happens inside your local Kali WSL instance.

Run standalone:
    python kali_driver_server.py --port 8901
"""
import argparse
import asyncio
import sys
import time

from fastmcp import FastMCP

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

mcp = FastMCP("kali-driver")

WSL_DISTRO = "kali-linux"
DEFAULT_TIMEOUT = 540  # full port scans, tool installs, etc. can take a while


def _log(msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


@mcp.tool
async def run_command(command: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Execute a shell command inside the Kali Linux WSL environment.

    :param command: Shell command to run (bash -lc semantics).
    :param timeout: Max seconds to allow the command to run.
    :return: dict with stdout, stderr, returncode, timed_out.
    """
    _log(f">>> RUN: {command}")
    # Uses asyncio.create_subprocess_exec (NOT the blocking subprocess.run) so a
    # long-running command from one concurrent task never blocks the event loop
    # and starves every OTHER task's run_command calls on this same shared
    # server. That queueing -- not the target or WSL being slow -- was the
    # actual cause of '[tool error: Timed out while waiting for response to
    # ClientRequest. Waited 600.0 seconds.]': with several tasks sharing one
    # kali_driver process, a request could sit queued behind another task's
    # long scan long enough to blow the client's 600s wait, even though this
    # server's own per-command timeout (540s) never fired.
    try:
        # Runs as root (WSL's own -u flag, not Linux sudo/PAM) so apt-get/pip/etc
        # installs never hang waiting for a password that can't be supplied here.
        # WSL mirrors the CALLING PROCESS's host cwd into the guest shell for
        # root sessions -- without pinning both the host-side cwd (via cwd=)
        # and the guest shell's directory (via `cd ~ &&`), the agent lands
        # wherever this Python process happens to have been launched from
        # (e.g. this very project folder), leaking our own source files and
        # other tasks' checkpoints into what should be a clean environment.
        proc = await asyncio.create_subprocess_exec(
            "wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc", f"cd ~ && {command}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="C:\\",
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            _log(f"<<< TIMED OUT after {timeout}s")
            return {
                "stdout": "",
                "stderr": f"[killed after {timeout}s timeout]",
                "returncode": -1,
                "timed_out": True,
            }
        stdout = stdout_b.decode("utf-8", errors="replace")
        stderr = stderr_b.decode("utf-8", errors="replace")
        _log(f"<<< exit={proc.returncode}")
        if stdout:
            _log(f"    stdout: {stdout[:1000]}")
        if stderr:
            _log(f"    stderr: {stderr[:500]}")
        return {
            "stdout": stdout,
            "stderr": stderr,
            "returncode": proc.returncode,
            "timed_out": False,
        }
    except Exception as e:
        _log(f"<<< ERROR launching command: {e}")
        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "timed_out": False,
        }


@mcp.tool
async def rag_search(query: str, k: int = 5) -> dict:
    """
    Search the local Kali-resident vulnerability RAG (NVD + CISA KEV + EPSS +
    Exploit-DB + the legacy Aegis corpus) at /opt/aegis-rag/ragl.sqlite.

    This is a FULLY OFFLINE lookup: the query is executed against the local SQLite
    DB inside Kali and never leaves the box. Pass a CVE id (e.g. "CVE-2021-44228")
    for an exact enriched record, or free-text keywords (e.g. "apache struts rce")
    for a ranked search that surfaces actively-exploited (KEV), high-EPSS and
    high-CVSS results first. Each item carries cvss/severity, epss probability,
    kev status + due date, Exploit-DB PoC ids, the canonical URL, and a snippet.

    :param query: CVE id or keyword phrase.
    :param k: Max results to return (default 5).
    :return: dict {ok, query, mode, count, items:[...]} or {ok:False, error:...}.
    """
    import json as _json
    import shlex
    cmd = f"python3 /opt/aegis-rag/rag_query.py --json --k {int(k)} {shlex.quote(query)}"
    _log(f">>> RAG: {query!r} k={k}")
    try:
        proc = await asyncio.create_subprocess_exec(
            "wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="C:\\",
        )
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {"ok": False, "error": "rag_search timed out"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    out = stdout_b.decode("utf-8", errors="replace").strip()
    err = stderr_b.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0 or not out:
        return {"ok": False, "error": err or f"exit {proc.returncode}", "raw": out[:500]}
    try:
        data = _json.loads(out.splitlines()[-1])
    except Exception as e:
        return {"ok": False, "error": f"bad JSON from rag_query: {e}", "raw": out[:500]}
    data["ok"] = True
    _log(f"<<< RAG {data.get('mode')} -> {data.get('count')} hits")
    return data


# Optional CONTAINED scan leg (supply-chain + zero-day tooling). Read-only, non-destructive scans;
# each degrades gracefully if the tool isn't installed (returns installed:false + an install hint),
# so the operator can decide whether to install it. {kind: (binary, cmd_template, install_hint)}.
_SCAN_KINDS = {
    # --- supply chain / third-party ---
    "sbom":       ("syft",      "syft {t} -o cyclonedx-json",                          "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"),
    "vuln":       ("grype",     "grype {t} -o json",                                   "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"),
    "trivy":      ("trivy",     "trivy --quiet fs --format json {t}",                  "apt-get install -y trivy  # or the aquasecurity install script"),
    "sca_py":     ("pip-audit", "pip-audit -r {t} -f json",                            "pipx install pip-audit"),
    "sca_js":     ("npm",       "cd {t} && npm audit --json",                          "npm ships with nodejs"),
    "malpkg":     ("sh",        "echo '== install hooks / scripts (typosquat + postinstall signal) =='; "
                                "grep -rniE 'preinstall|postinstall|install\":' {t}/package.json {t}/*/package.json 2>/dev/null | head -40; "
                                "find {t} -name setup.py -maxdepth 3 2>/dev/null -exec grep -lniE 'cmdclass|install_requires|os\\.system|subprocess|urllib|socket' {{}} +", "builtin"),
    "provenance": ("cosign",    "cosign verify {t} 2>&1 | head -40",                   "go install github.com/sigstore/cosign/v2/cmd/cosign@latest"),
    # --- zero-day / static + fuzzing ---
    "static":     ("semgrep",   "semgrep --config auto --json {t} 2>/dev/null | head -c 20000", "pipx install semgrep"),
    "fuzz":       ("sh",        "for x in afl-fuzz honggfuzz radamsa clang libfuzzer; do command -v $x >/dev/null 2>&1 && echo \"$x: present\" || echo \"$x: MISSING\"; done", "apt-get install -y afl++ honggfuzz radamsa clang"),
    # --- misconfiguration / cloud / k8s / IaC ---
    "k8s":        ("kube-bench", "kube-bench run --json 2>/dev/null | head -c 40000",              "curl -sSfL https://raw.githubusercontent.com/aquasecurity/kube-bench/main/install.sh | sh"),
    "khunter":    ("kube-hunter","kube-hunter --report json --pod 2>/dev/null | head -c 40000",     "pipx install kube-hunter"),
    "cloud":      ("prowler",    "prowler {t} -M json 2>/dev/null | head -c 40000",                 "pipx install prowler"),
    "iac":        ("checkov",    "checkov -d {t} -o json --compact 2>/dev/null | head -c 40000",    "pipx install checkov"),
    "exposure":   ("sh",         "echo '== exposed sensitive paths under {t} =='; "
                                "find {t} -maxdepth 5 \\( -name .git -o -name .env -o -name '*.pem' -o -name id_rsa "
                                "-o -name 'config.y*ml' -o -name .aws -o -name .kube -o -name '.htpasswd' \\) 2>/dev/null | head -40; "
                                "echo '== secret-looking strings =='; "
                                "grep -rniE 'password|secret|api[_-]?key|aws_secret|bearer|private_key' {t} 2>/dev/null | head -20", "builtin"),
}


@mcp.tool
async def security_scan(kind: str, target: str, timeout: int = 300) -> dict:
    """Optional CONTAINED scan leg for supply-chain + zero-day work. Runs a READ-ONLY, non-destructive
    scan against a twin image or a source directory INSIDE Kali.

    :param kind: sbom | vuln | trivy | sca_py | sca_js | malpkg | provenance | static | fuzz
                 (sbom/vuln/malpkg/provenance = supply-chain; static/fuzz = zero-day tooling).
    :param target: a docker image ref (for sbom/vuln) OR a path inside Kali (for source scans).
    :return: {ok, kind, tool, installed, output, install_hint}. If the tool isn't installed the call
             returns installed:false + install_hint rather than failing, so nothing is auto-installed.
    """
    import shlex as _shlex
    if kind not in _SCAN_KINDS:
        return {"ok": False, "error": f"unknown kind {kind!r}; choose from {sorted(_SCAN_KINDS)}"}
    binary, template, hint = _SCAN_KINDS[kind]
    t = _shlex.quote(target)
    probe = template.replace("{t}", t)
    # presence check first (never auto-install); 'sh' pseudo-binaries always "present"
    cmd = f"if [ '{binary}' != sh ] && ! command -v {binary} >/dev/null 2>&1; then echo __EG_MISSING__; else {probe}; fi"
    _log(f">>> SCAN[{kind}] {target}")
    try:
        proc = await asyncio.create_subprocess_exec(
            "wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd="C:\\")
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill(); await proc.wait()
        return {"ok": False, "kind": kind, "tool": binary, "error": f"timed out after {timeout}s"}
    except Exception as e:
        return {"ok": False, "kind": kind, "tool": binary, "error": str(e)}
    out = stdout_b.decode("utf-8", errors="replace").strip()
    err = stderr_b.decode("utf-8", errors="replace").strip()
    if "__EG_MISSING__" in out:
        return {"ok": True, "kind": kind, "tool": binary, "installed": False,
                "install_hint": hint, "output": ""}
    _log(f"<<< SCAN[{kind}] {len(out)}b")
    return {"ok": True, "kind": kind, "tool": binary, "installed": True,
            "output": out[:60000], "stderr": err[:1000]}


# Source/release recipes for tools that AREN'T in Kali's apt (adapted to Kali). Used by ensure_tool
# after apt/pip fail, or as the primary path. Each is a bash one-liner run inside Kali as root.
_TOOL_RECIPES = {
    "syft":      "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin",
    "grype":     "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
    "semgrep":   "pipx install semgrep || pip3 install --break-system-packages semgrep",
    "honggfuzz": "apt-get install -y build-essential binutils-dev libunwind-dev libblocksruntime-dev git >/dev/null 2>&1; "
                 "cd /opt && rm -rf honggfuzz && git clone --depth 1 https://github.com/google/honggfuzz.git && cd honggfuzz && make && make install",
    "radamsa":   "apt-get install -y build-essential git >/dev/null 2>&1; "
                 "cd /opt && rm -rf radamsa && git clone --depth 1 https://gitlab.com/akihe/radamsa.git && cd radamsa && make && (make install || cp bin/radamsa /usr/local/bin/)",
    "afl-fuzz":  "apt-get install -y afl++ || (cd /opt && rm -rf AFLplusplus && git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git && cd AFLplusplus && make distrib && make install)",
    "trivy":     "curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
}


@mcp.tool
async def ensure_tool(name: str, hint: str = "", timeout: int = 600) -> dict:
    """Provision a security tool that may NOT be in Kali's apt, adapted to Kali. Cascade:
    already-present? -> apt -> pipx/pip -> a known source/release recipe (syft, grype, semgrep,
    honggfuzz, radamsa, afl-fuzz, trivy) -> an optional caller `hint` command. pip-installed tools
    are symlinked into /usr/local/bin so any shell finds them.

    NOTE: this INSTALLS software and reaches package repos / GitHub / GitLab -- it is operator-invoked
    setup for the operator's OWN Kali box, never run against a target. Returns
    {ok, name, installed, method, path, tried}.
    """
    import shlex as _sh
    safe = _sh.quote(name)
    recipe = _TOOL_RECIPES.get(name, "")
    steps = [
        f"if command -v {safe} >/dev/null 2>&1; then echo __M__present; command -v {safe}; exit 0; fi",
        f"apt-get update -y >/dev/null 2>&1; if apt-get install -y {safe} >/dev/null 2>&1 && command -v {safe} >/dev/null 2>&1; then echo __M__apt; command -v {safe}; exit 0; fi",
        f"if (pipx install {safe} || pip3 install --break-system-packages {safe}) >/dev/null 2>&1; then ln -sf /root/.local/bin/{safe} /usr/local/bin/{safe} 2>/dev/null; command -v {safe} >/dev/null 2>&1 && {{ echo __M__pip; command -v {safe}; exit 0; }}; fi",
    ]
    if recipe:
        steps.append(f"if {{ {recipe} ; }} >/dev/null 2>&1 && command -v {safe} >/dev/null 2>&1; then echo __M__recipe; command -v {safe}; exit 0; fi")
    if hint:
        steps.append(f"if {{ {hint} ; }} >/dev/null 2>&1 && command -v {safe} >/dev/null 2>&1; then echo __M__hint; command -v {safe}; exit 0; fi")
    steps.append("echo __M__FAILED")
    cmd = " ; ".join(steps)
    _log(f">>> ENSURE_TOOL {name}")
    try:
        proc = await asyncio.create_subprocess_exec(
            "wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd="C:\\")
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill(); await proc.wait()
        return {"ok": False, "name": name, "installed": False, "error": f"timed out after {timeout}s"}
    except Exception as e:
        return {"ok": False, "name": name, "installed": False, "error": str(e)}
    out = stdout_b.decode("utf-8", errors="replace")
    lines = [l for l in out.splitlines() if l.strip()]
    method, path, tried = "none", "", []
    for i, l in enumerate(lines):
        if l.startswith("__M__"):
            m = l[len("__M__"):]
            if m == "FAILED":
                method = "failed"
            else:
                method = m
                path = lines[i + 1].strip() if i + 1 < len(lines) else ""
            tried.append(m)
    installed = method not in ("none", "failed")
    _log(f"<<< ENSURE_TOOL {name} -> installed={installed} via {method}")
    return {"ok": True, "name": name, "installed": installed, "method": method,
            "path": path, "tried": tried, "install_hint": _TOOL_RECIPES.get(name, hint or "")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8901)
    args = parser.parse_args()
    mcp.run(transport="http", host=args.host, port=args.port)
