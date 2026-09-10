"""distro_backend.py -- MULTI-DISTRO execution router for the orchestrator (board-converged design).

A probe/tool runs in the backend that has it, so a tool absent/awkward in Kali runs where it's native
(BlackArch ships ~2800 tools PREBUILT via pacman -- no source-build, which is what OOM'd Kali).

Backends:
  - kali      : the WSL Kali distro (default; where the loop already runs).
  - blackarch : a named docker container from blackarchlinux/blackarch. STOPPED WHEN IDLE (0 RAM) and
                started only for a probe, then stopped again -- key on a memory-tight host. Tools installed
                with pacman PERSIST in the container (installed once, not re-pulled each run).

Board-converged decisions (ds/qwq/qwen):
  (a) ROUTING   = static capability CATALOG + try/fallback (predictable; catalog is the trust anchor).
  (b) EXECUTION = container started per-probe, STOPPED when idle, with a memory cap (-m) -- protects the host.
  (c) REACH/IO  = --network host (the container reaches the mirror at localhost:8443) + a shared volume for IO.
  (d) REGISTRY  = kali_tool_extend catalog + this module's DISTRO_TOOLS map; refreshable.
  (e) ABSTRACT  = one run_tool()/run() API; the relay legs stay distro-AGNOSTIC.
  (f) DOCTRINE  = contained; egress only to install tooling; non-destructive; teardown; audited.
"""
from __future__ import annotations
import os, sys, json, subprocess, platform, time

HERE = os.path.dirname(os.path.abspath(__file__))
KALI = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
BLACKARCH_IMAGE = os.environ.get("AEGIS_BLACKARCH_IMAGE", "blackarchlinux/blackarch:latest")
BLACKARCH_CTR = os.environ.get("AEGIS_BLACKARCH_CTR", "aegis-blackarch")
BLACKARCH_MEM = os.environ.get("AEGIS_BLACKARCH_MEM", "1500m")   # container memory cap (host is small)
_VOL = os.environ.get("AEGIS_BLACKARCH_VOL", "aegis-ba-work")     # shared work volume
_AUDIT = os.path.join(HERE, "distro_run_audit.jsonl")

# static capability map: tools known to live natively in BlackArch (prebuilt via pacman). Extend freely;
# kali_tool_extend's catalog + a live pacman -Ss lookup fill the rest.
DISTRO_TOOLS = {
    "blackarch": {"dalfox", "katana", "gau", "waybackurls", "hakrawler", "gowitness", "x8", "sn0int",
                  "interactsh-client", "ligolo-ng", "cero", "xnLinkFinder", "sliver", "villain"},
}


def _run(argv, timeout=1800):
    env = dict(os.environ)
    if platform.system() == "Windows":
        env.update(MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    return r.returncode, r.stdout, r.stderr


def _kali(cmd, timeout=1800):
    base = ["wsl", "-d", KALI, "-u", "root", "--", "bash", "-lc", cmd] if platform.system() == "Windows" \
        else ["bash", "-lc", cmd]
    return _run(base, timeout)


def _audit(entry):
    try:
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(_AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


# ---------------- Kali backend ----------------
def have_kali(tool):
    # check the PRINTED PATH (non-empty), not $? -- exit-code capture is unreliable through host->wsl->bash.
    rc, out, _ = _kali(f"command -v {tool} 2>/dev/null; ls ~/.local/bin/{tool} 2>/dev/null", 60)
    return bool(out.strip())


# ---------------- BlackArch backend (docker, stopped-when-idle) ----------------
def blackarch_present():
    rc, out, _ = _kali(f"docker image inspect {BLACKARCH_IMAGE} >/dev/null 2>&1 && echo yes || echo no", 60)
    return "yes" in out


def pull_blackarch():
    """One-time pull of the BlackArch image (multi-GB; needs egress + disk). Idempotent."""
    if blackarch_present():
        print("[blackarch] image already present"); return True
    print(f"[blackarch] pulling {BLACKARCH_IMAGE} (multi-GB, one-time)...", flush=True)
    rc, out, err = _kali(f"docker pull {BLACKARCH_IMAGE} 2>&1 | tail -3", timeout=3600)
    print(out or err)
    ok = blackarch_present()
    _audit({"backend": "blackarch", "action": "pull", "image": BLACKARCH_IMAGE, "ok": ok})
    return ok


def _ensure_container():
    """Create the named container (stopped) if missing. sleep-infinity entrypoint so we can start+exec+stop.
    --network host -> reaches the mirror on localhost:8443; memory-capped; a shared work volume mounted at /work."""
    rc, out, _ = _kali(f"docker ps -a --format '{{{{.Names}}}}' | grep -qx {BLACKARCH_CTR} && echo yes || echo no", 60)
    if "yes" in out:
        return True
    if not blackarch_present():
        print("[blackarch] image not present -- run pull first"); return False
    rc, out, err = _kali(
        f"docker create --name {BLACKARCH_CTR} --network host -m {BLACKARCH_MEM} "
        f"-v {_VOL}:/work {BLACKARCH_IMAGE} sleep infinity 2>&1 | tail -2", 120)
    ok = "yes" in _kali(f"docker ps -a --format '{{{{.Names}}}}' | grep -qx {BLACKARCH_CTR} && echo yes || echo no", 60)[1]
    _audit({"backend": "blackarch", "action": "create", "ok": ok, "mem": BLACKARCH_MEM})
    return ok


def _start():
    _kali(f"docker start {BLACKARCH_CTR} >/dev/null 2>&1", 120)


def _stop():
    _kali(f"docker stop {BLACKARCH_CTR} >/dev/null 2>&1", 120)   # stopped => ~0 RAM on the host


def have_blackarch(tool):
    if not _ensure_container():
        return False
    _start()
    rc, out, _ = _kali(f"docker exec {BLACKARCH_CTR} bash -lc 'command -v {tool} 2>/dev/null'", 120)
    return bool(out.strip())


def run_in_blackarch(cmd, ensure_tools=None, keep_up=False, timeout=1800):
    """Run a command in the BlackArch container (started for the call, stopped after unless keep_up).
    ensure_tools: pacman -S them first (persist in the container)."""
    if not _ensure_container():
        return 127, "", "blackarch container unavailable (pull the image first)"
    _start()
    pre = ""
    if ensure_tools:
        tools = " ".join(ensure_tools) if isinstance(ensure_tools, (list, set, tuple)) else str(ensure_tools)
        pre = f"pacman -Sy --noconfirm --needed {tools} >/dev/null 2>&1; "
    rc, out, err = _kali(f"docker exec {BLACKARCH_CTR} bash -lc {json.dumps(pre + cmd)}", timeout)
    _audit({"backend": "blackarch", "action": "run", "cmd": cmd[:200], "ensure": list(ensure_tools or []),
            "rc": rc})
    if not keep_up:
        _stop()
    return rc, out, err


# ---------------- the router ----------------
def route(tool):
    """Decide the backend for a tool: kali if present there; else blackarch if native; else install-in-kali."""
    if have_kali(tool):
        return "kali"
    if tool in DISTRO_TOOLS.get("blackarch", set()):
        return "blackarch"
    return "install"   # let kali_tool_extend try to install it into Kali


def run_tool(tool, argv, timeout=1800):
    """Run `tool argv...` in the right backend (board abstraction: callers are distro-agnostic)."""
    backend = route(tool)
    line = f"{tool} {argv}" if isinstance(argv, str) else " ".join([tool] + list(argv))
    if backend == "kali":
        rc, out, err = _kali(line, timeout)
    elif backend == "blackarch":
        rc, out, err = run_in_blackarch(line, ensure_tools=[tool], timeout=timeout)
    else:
        # install-on-demand into Kali, then run
        try:
            sys.path.insert(0, HERE); import kali_tool_extend
            res = kali_tool_extend.install(tool)
            if res.get("status") in ("installed", "present"):
                rc, out, err = _kali(line, timeout); backend = "kali(installed)"
            else:
                # fall back to BlackArch container if Kali install didn't land
                rc, out, err = run_in_blackarch(line, ensure_tools=[tool], timeout=timeout); backend = "blackarch(fallback)"
        except Exception as e:
            rc, out, err = 127, "", f"router install failed: {e}"
    _audit({"router": True, "tool": tool, "backend": backend, "rc": rc})
    return {"tool": tool, "backend": backend, "rc": rc, "stdout": out[-4000:], "stderr": err[-1000:]}


def main():
    import argparse
    ap = argparse.ArgumentParser(description="multi-distro execution router (Kali + BlackArch container)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pull-blackarch")
    sub.add_parser("status")
    pr = sub.add_parser("route"); pr.add_argument("tool")
    rt = sub.add_parser("run"); rt.add_argument("tool"); rt.add_argument("args", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    if a.cmd == "pull-blackarch":
        print(json.dumps({"pulled": pull_blackarch()}))
    elif a.cmd == "status":
        print(json.dumps({"blackarch_image": blackarch_present(),
                          "container": _ensure_container() if blackarch_present() else False}, indent=2))
    elif a.cmd == "route":
        print(json.dumps({"tool": a.tool, "backend": route(a.tool)}))
    elif a.cmd == "run":
        print(json.dumps(run_tool(a.tool, a.args), indent=2, default=str))


if __name__ == "__main__":
    main()
