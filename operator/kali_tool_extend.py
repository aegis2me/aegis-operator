"""kali_tool_extend.py -- extend the Kali toolbox with tools that ship in other pentest distros
(BlackArch ~2800 tools, BackBox, Predator-OS) but are MISSING from this Kali, on demand for a specific probe.

Design (per the doctrine): we do NOT graft another distro's package repos (BlackArch is Arch/pacman -- can't
mix with Kali/Debian; BackBox/Predator .debs risk dependency breakage). Instead we install the SPECIFIC
missing tool from its upstream, trying sources in order until the binary appears:
    apt -> pipx -> pip -> go install -> cargo install -> gem -> npm -> git clone+build -> docker image
Installing tooling is the authorized-tooling lane (not target egress); contained in Kali.

  check           -- which CATALOG tools are missing on this Kali
  list            -- the curated cross-distro catalog
  install <name>  -- resolve + install one tool (best source), verify the binary lands
  diff            -- catalog vs Kali (present/missing table)
  refresh         -- (opt-in, AEGIS_TOOLS_ONLINE=1) pull the live BlackArch tool list to expand the catalog

The catalog seeds high-value tools commonly present in BlackArch and absent/older in a stock Kali; the
RESOLVER works for ANY name (the catalog is discovery + an install hint, not a hard dependency).
"""
from __future__ import annotations
import os, sys, json, subprocess, platform, re

HERE = os.path.dirname(os.path.abspath(__file__))
KALI = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
_CATALOG_PATH = os.path.join(HERE, "kali_tool_catalog.json")

# Curated seed: tools that BlackArch/BackBox/Predator ship and a stock Kali often lacks (or ships older).
# Each: {bin, distros, category, install:[(method, target)]}. `bin` is what we test with `command -v`.
_SEED = {
    # projectdiscovery / recon (go) -- some are in kali now; have() decides. BlackArch ships the full set.
    "dalfox":        {"bin": "dalfox", "distros": ["blackarch"], "category": "web/xss",
                       "install": [("go", "github.com/hahwul/dalfox/v2@latest")]},
    "gau":           {"bin": "gau", "distros": ["blackarch"], "category": "recon/urls",
                       "install": [("go", "github.com/lc/gau/v2/cmd/gau@latest")]},
    "waybackurls":   {"bin": "waybackurls", "distros": ["blackarch"], "category": "recon/urls",
                       "install": [("go", "github.com/tomnomnom/waybackurls@latest")]},
    "katana":        {"bin": "katana", "distros": ["blackarch"], "category": "web/crawler",
                       "install": [("apt", "katana"), ("go", "github.com/projectdiscovery/katana/cmd/katana@latest")]},
    "hakrawler":     {"bin": "hakrawler", "distros": ["blackarch"], "category": "web/crawler",
                       "install": [("go", "github.com/hakluke/hakrawler@latest")]},
    "gowitness":     {"bin": "gowitness", "distros": ["blackarch"], "category": "web/screenshot",
                       "install": [("go", "github.com/sensepost/gowitness@latest")]},
    "arjun":         {"bin": "arjun", "distros": ["blackarch"], "category": "web/params",
                       "install": [("pipx", "arjun")]},
    "xnLinkFinder":  {"bin": "xnLinkFinder", "distros": ["blackarch"], "category": "web/endpoints",
                       "install": [("pipx", "xnLinkFinder")]},
    "interactsh-client": {"bin": "interactsh-client", "distros": ["blackarch"], "category": "oob",
                       "install": [("go", "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")]},
    # post-exploit / C2 / pivot
    "pwncat-cs":     {"bin": "pwncat-cs", "distros": ["blackarch"], "category": "post-exploit",
                       "install": [("pipx", "pwncat-cs")]},
    "ligolo-ng":     {"bin": "ligolo-ng", "distros": ["blackarch"], "category": "pivot",
                       "install": [("go", "github.com/nicocha30/ligolo-ng/cmd/proxy@latest")]},
    "villain":       {"bin": "villain.py", "distros": ["blackarch"], "category": "c2",
                       "install": [("git", "https://github.com/t3l3machus/Villain")]},
    "sliver-server": {"bin": "sliver-server", "distros": ["blackarch"], "category": "c2",
                       "install": [("script", "curl https://sliver.sh/install|sudo bash")]},
    # osint / recon
    "sn0int":        {"bin": "sn0int", "distros": ["blackarch"], "category": "osint",
                       "install": [("apt", "sn0int"), ("cargo", "sn0int")]},
    "cero":          {"bin": "cero", "distros": ["blackarch"], "category": "recon/certs",
                       "install": [("go", "github.com/glebarez/cero@latest")]},
    # fuzz / brute
    "x8":            {"bin": "x8", "distros": ["blackarch"], "category": "web/params",
                       "install": [("cargo", "x8")]},
    "feroxbuster":   {"bin": "feroxbuster", "distros": ["blackarch", "backbox"], "category": "web/content",
                       "install": [("apt", "feroxbuster"), ("cargo", "feroxbuster")]},
    # mobile (relevant to the ANDROID work)
    "apkleaks":      {"bin": "apkleaks", "distros": ["blackarch"], "category": "mobile/secrets",
                       "install": [("pipx", "apkleaks")]},
    "objection":     {"bin": "objection", "distros": ["blackarch"], "category": "mobile/runtime",
                       "install": [("pipx", "objection")]},
}


def _kali(cmd, timeout=1800):
    if platform.system() == "Windows":
        full = ["wsl", "-d", KALI, "-u", "root", "--", "bash", "-lc", cmd]
        env = dict(os.environ, MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")
    else:
        full = ["bash", "-lc", cmd]
        env = dict(os.environ)
    r = subprocess.run(full, capture_output=True, text=True, timeout=timeout, env=env)
    return r.returncode, r.stdout, r.stderr


def _load_catalog():
    cat = dict(_SEED)
    if os.path.exists(_CATALOG_PATH):
        try:
            cat.update(json.load(open(_CATALOG_PATH, encoding="utf-8")))
        except Exception:
            pass
    return cat


def have(binname):
    rc, out, _ = _kali(f"command -v {binname} >/dev/null 2>&1 && echo YES || echo NO", timeout=60)
    return "YES" in out


def check():
    cat = _load_catalog()
    present, missing = [], []
    for name, spec in cat.items():
        (present if have(spec.get("bin", name)) else missing).append(name)
    print(f"[check] catalog={len(cat)}  present={len(present)}  MISSING={len(missing)}")
    for name in sorted(missing):
        spec = cat[name]
        print(f"  MISSING  {name:18} [{spec.get('category','?')}]  <- {','.join(spec.get('distros',[]))}  "
              f"install: {spec.get('install',[])[:1]}")
    return {"present": present, "missing": missing}


# ---- the multi-source resolver ----
def _try(method, target, binname):
    cmds = {
        "apt":   f"apt-get install -y {target} >/dev/null 2>&1",
        "pipx":  f"(command -v pipx || (apt-get install -y pipx >/dev/null 2>&1)); pipx install {target} >/dev/null 2>&1",
        "pip":   f"pip install --break-system-packages {target} >/dev/null 2>&1 || pip install {target} >/dev/null 2>&1",
        "go":    f"(command -v go || apt-get install -y golang-go >/dev/null 2>&1); GOBIN=/usr/local/bin go install {target} >/dev/null 2>&1",
        "cargo": f"(command -v cargo || apt-get install -y cargo >/dev/null 2>&1); cargo install {target} >/dev/null 2>&1 && cp ~/.cargo/bin/{binname} /usr/local/bin/ 2>/dev/null",
        "gem":   f"gem install {target} >/dev/null 2>&1",
        "npm":   f"(command -v npm || apt-get install -y npm >/dev/null 2>&1); npm install -g {target} >/dev/null 2>&1",
        "git":   f"cd /opt && git clone --depth 1 {target} >/dev/null 2>&1",
        "script":f"{target}",
        "docker":f"docker pull {target} >/dev/null 2>&1",
    }
    c = cmds.get(method)
    if not c:
        return False, f"unknown method {method}"
    rc, out, err = _kali(c, timeout=1200)
    return (rc == 0), (err or out)[-200:]


def install(name, methods=None):
    """Resolve + install one tool. Uses the catalog's install spec if present, else tries name-based sources."""
    cat = _load_catalog()
    spec = cat.get(name, {})
    binname = spec.get("bin", name)
    if have(binname):
        print(f"[install] {name}: already present ({binname})"); return {"name": name, "status": "present"}
    plan = methods or spec.get("install") or [("apt", name), ("pipx", name), ("pip", name),
                                              ("cargo", name), ("gem", name)]
    for method, target in plan:
        print(f"[install] {name}: trying {method} {target} ...", flush=True)
        ok, note = _try(method, target, binname)
        if ok and (have(binname) or method in ("git", "script", "docker")):
            print(f"[install] {name}: OK via {method}"); return {"name": name, "status": "installed", "method": method}
        print(f"[install] {name}: {method} did not land ({note[:120]})")
    print(f"[install] {name}: FAILED across {[m for m,_ in plan]} -- may need a manual recipe / docker image")
    return {"name": name, "status": "failed", "tried": [m for m, _ in plan]}


def refresh_blackarch():
    """OPT-IN (AEGIS_TOOLS_ONLINE=1): pull the live BlackArch tool list and merge names into the catalog
    (name-only entries -> the resolver tries name-based sources). Offline-safe; public data, tooling lane."""
    if os.environ.get("AEGIS_TOOLS_ONLINE") != "1":
        print("[refresh] set AEGIS_TOOLS_ONLINE=1 to fetch the BlackArch tool list (public data)."); return
    rc, out, err = _kali("curl -fsSL https://blackarch.org/tools.html 2>/dev/null | "
                         "grep -oE '<td>[a-z0-9][a-z0-9._-]+</td>' | sed 's/<[^>]*>//g' | sort -u", timeout=120)
    names = [n for n in out.splitlines() if n.strip()]
    if not names:
        print("[refresh] no names fetched (offline / blocked); catalog unchanged."); return
    cat = {}
    if os.path.exists(_CATALOG_PATH):
        try: cat = json.load(open(_CATALOG_PATH, encoding="utf-8"))
        except Exception: cat = {}
    added = 0
    for n in names:
        if n not in _SEED and n not in cat:
            cat[n] = {"bin": n, "distros": ["blackarch"], "category": "blackarch", "install": []}
            added += 1
    json.dump(cat, open(_CATALOG_PATH, "w", encoding="utf-8"), indent=1)
    print(f"[refresh] BlackArch list: {len(names)} tools; added {added} new names to the catalog "
          f"({_CATALOG_PATH}).")


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Extend Kali with tools missing vs BlackArch/BackBox/Predator-OS")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check"); sub.add_parser("list"); sub.add_parser("diff"); sub.add_parser("refresh")
    pi = sub.add_parser("install"); pi.add_argument("name")
    a = ap.parse_args()
    if a.cmd == "check" or a.cmd == "diff":
        check()
    elif a.cmd == "list":
        cat = _load_catalog()
        for n, s in sorted(cat.items()):
            print(f"  {n:18} [{s.get('category','?')}] <- {','.join(s.get('distros',[]))}")
    elif a.cmd == "install":
        print(json.dumps(install(a.name), indent=2))
    elif a.cmd == "refresh":
        refresh_blackarch()


if __name__ == "__main__":
    main()
