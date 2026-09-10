#!/usr/bin/env python3
"""
remediation_port.py -- deliver the code writer/improver's patch to the MIRROR for the closed loop.

Stage 10 produces fixes on the HOST (operator/remediation_fixes/), but the mirror twin lives in Kali
(WSL) or a Docker container. To run the mirror-only closed loop -- apply the fix, then re-run the
finding's exploit/oracle to confirm the gap is closed -- the patch has to be carried into the mirror.
This ports it, via a pluggable transport:

    wsl     -> copy into a WSL distro -- ANY distro (Kali, Ubuntu, openSUSE, ...) via --distro / AEGIS_MIRROR_DISTRO
    docker  -> `docker cp` into a running mirror container (--container NAME)
    dir     -> copy to a staging directory (a USB/removable-media mount, or a shared folder) for an
               air-gapped hand-carry

DOCTRINE: MIRROR-side only. This STAGES the patch into the mirror (non-destructive); it does NOT apply
it and NEVER touches the real target. Applying + re-testing is the operator's mirror-only follow-up; this
prints the exact apply command to run there. Owner's own contained mirror, authorized.

Usage:
    python remediation_port.py --transport wsl                      # port all emitted patches into Kali
    python remediation_port.py --finding 77a7588bfc18 --transport wsl
    python remediation_port.py --transport docker --container aegis-mirror
    python remediation_port.py --transport dir --dest E:/aegis-usb  # stage to removable media
    python remediation_port.py --transport wsl --dry-run            # show what would be ported
"""
import os, sys, glob, argparse, subprocess, json, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
# The mirror twin may run ANY distro (Kali, Ubuntu, openSUSE, ...). AEGIS_MIRROR_DISTRO names the WSL
# distro to port into; AEGIS_KALI_DISTRO is kept as a back-compat fallback.
MIRROR_DISTRO = os.environ.get("AEGIS_MIRROR_DISTRO") or os.environ.get("AEGIS_KALI_DISTRO") or "kali-linux"
DEFAULT_FIXES_DIR = os.path.join(HERE, "remediation_fixes")


def _patch_files(fixes_dir, finding=None):
    pats = sorted(glob.glob(os.path.join(fixes_dir, "*.md")))
    if finding:
        f = finding[:12]
        pats = [p for p in pats if os.path.basename(p).startswith(f)]
    return pats


# ---------------- transports ----------------
def port_wsl(hostfile, dest_dir, distro, dry):
    """Copy a host file into the Kali WSL fs by piping bytes to `tee` (no path-mangling)."""
    name = os.path.basename(hostfile)
    dest = f"{dest_dir.rstrip('/')}/{name}"
    if dry:
        return dest, "dry-run"
    data = open(hostfile, "rb").read()
    inner = f"mkdir -p {dest_dir!r} && cat > {dest!r}"
    p = subprocess.run(["wsl", "-d", distro, "-u", "root", "--", "bash", "-lc", inner],
                       input=data, capture_output=True, timeout=120)
    if p.returncode != 0:
        return dest, f"error: {(p.stderr or b'').decode('utf-8','replace')[:200]}"
    return dest, "ok"


def port_docker(hostfile, dest_dir, container, dry):
    name = os.path.basename(hostfile)
    dest = f"{dest_dir.rstrip('/')}/{name}"
    if dry:
        return dest, "dry-run"
    mk = subprocess.run(["docker", "exec", container, "mkdir", "-p", dest_dir],
                        capture_output=True, text=True, timeout=60)
    if mk.returncode != 0:
        return dest, f"error(mkdir): {mk.stderr[:200]}"
    p = subprocess.run(["docker", "cp", hostfile, f"{container}:{dest}"],
                       capture_output=True, text=True, timeout=120)
    return dest, ("ok" if p.returncode == 0 else f"error: {p.stderr[:200]}")


def port_dir(hostfile, dest_dir, dry):
    name = os.path.basename(hostfile)
    dest = os.path.join(dest_dir, name)
    if dry:
        return dest, "dry-run"
    try:
        os.makedirs(dest_dir, exist_ok=True)
        shutil.copy2(hostfile, dest)
        return dest, "ok"
    except Exception as e:
        return dest, f"error: {e}"


def default_dest(transport):
    return {"wsl": "/opt/aegis-mirror-fixes", "docker": "/tmp/aegis-fixes"}.get(transport, "")


def apply_hint(transport, dest, container=None, mirror_repo="<mirror-repo>"):
    """The command to APPLY a ported patch, run INSIDE the mirror (operator's follow-up). Each staged file
    is a FILE/PATCH/NOTE markdown from the code writer -- extract its diff (the PATCH block) and apply it."""
    f = f"{dest.rstrip('/')}/<finding>__<writer>.md"
    if transport == "wsl":
        return (f"wsl -d {MIRROR_DISTRO} -u root -- bash -lc "
                f"'cd {mirror_repo} && $EDITOR {f}; git apply <extracted.diff>   # or patch -p1 < <extracted.diff>'")
    if transport == "docker":
        return (f"docker exec {container or '<container>'} sh -lc "
                f"'cd {mirror_repo} && git apply <extracted.diff from {f}>'")
    return f"# hand-carry {dest} to the mirror, extract each {os.path.basename(f)} PATCH block, then git apply it in {mirror_repo}"


def port(fixes_dir, finding, transport, dest_dir, container, distro, dry):
    files = _patch_files(fixes_dir, finding)
    if not files:
        return {"ok": False, "note": f"no patch files in {fixes_dir}"
                + (f" for finding {finding[:12]}" if finding else "")
                + " -- run remediation_board.py --emit-fixes first", "ported": []}
    dest_dir = dest_dir or default_dest(transport)
    if transport in ("wsl", "docker") and not dest_dir:
        return {"ok": False, "note": f"no dest dir for transport {transport}", "ported": []}
    if transport == "docker" and not container:
        return {"ok": False, "note": "docker transport needs --container NAME", "ported": []}
    ported = []
    for hf in files:
        if transport == "wsl":
            d, st = port_wsl(hf, dest_dir, distro, dry)
        elif transport == "docker":
            d, st = port_docker(hf, dest_dir, container, dry)
        else:
            d, st = port_dir(hf, dest_dir, dry)
        ported.append({"host": os.path.basename(hf), "mirror_dest": d, "status": st})
        print(f"  [{st}] {os.path.basename(hf)} -> {d}")
    ok = all(x["status"] in ("ok", "dry-run") for x in ported)
    return {"ok": ok, "transport": transport, "dest_dir": dest_dir, "ported": ported,
            "apply_hint": apply_hint(transport, dest_dir, container),
            "note": "MIRROR-side only: patches STAGED, not applied. Apply + re-test on the mirror; never the real target."}


def main():
    ap = argparse.ArgumentParser(description="Port code-writer patches to the mirror (WSL/Docker/USB-dir).")
    ap.add_argument("--fixes-dir", default=DEFAULT_FIXES_DIR, help="dir of emitted patches (remediation_board --emit-fixes)")
    ap.add_argument("--finding", help="only this finding id (prefix ok)")
    ap.add_argument("--transport", choices=["wsl", "docker", "dir"], default="wsl")
    ap.add_argument("--dest", dest="dest_dir", default=None, help="destination dir in/for the mirror (transport default otherwise)")
    ap.add_argument("--container", default=None, help="docker transport: the running mirror container name")
    ap.add_argument("--distro", default=MIRROR_DISTRO, help=f"wsl transport: distro (default {MIRROR_DISTRO})")
    ap.add_argument("--dry-run", action="store_true", help="show what would be ported; copy nothing")
    a = ap.parse_args()
    print(f"[port] transport={a.transport} fixes={a.fixes_dir}"
          + (f" container={a.container}" if a.transport == "docker" else "")
          + (f" distro={a.distro}" if a.transport == "wsl" else ""))
    res = port(a.fixes_dir, a.finding, a.transport, a.dest_dir, a.container, a.distro, a.dry_run)
    print(json.dumps(res, indent=2))
    if res.get("ok") and res.get("ported"):
        print("\nAPPLY + RE-TEST ON THE MIRROR (operator follow-up, mirror-only):")
        print("  " + res["apply_hint"])
        print("  then re-run the finding's exploit/oracle to confirm the gap is CLOSED.")
    sys.exit(0 if res.get("ok") else 1)


if __name__ == "__main__":
    main()
