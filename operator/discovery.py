"""
discovery.py -- DISCOVERY-PARITY vectors: the capabilities the board flagged as needed to reach 5/5
parity with the union of Cobalt Strike + Metasploit + MITRE ATT&CK/Caldera + Prelude Operator, PLUS
the novel discovery techniques that go beyond all of them.

Every function here is a shared-vector LEG: `(move, ctx) -> {status, body, discovery, discovery_verified,
...}`. Like the supply_chain/ossfuzz/probe legs, each carries its OWN ground truth in `discovery_verified`
so the loop's oracle can record only what is actually confirmed. All are:
  * OFFLINE-SAFE / graceful-skip -- if a tool (ldapsearch, nmap, smbclient, az/gcloud) or an optional lib
    (boto3) or a credential is missing, the leg returns a clear "needs X" result instead of crashing
    (same doctrine as the recon/fuzz legs reporting "nmap missing").
  * NON-DESTRUCTIVE -- read/enumerate only; no writes, no deletes, no exploitation payloads.
  * OWNED-SCOPE -- OSINT legs (external surface, dependency-confusion) are for owned domains only, via the
    authorized OSINT/VPN lane; the Red-Team scope guard still gates them upstream.

Registered into vectors.LEGS; reachable by the Planner (see planner._class_to_action) and the board.

Consensus gaps  -> ldap · cloud · fingerprint · external · cred_harvest · sbom
Novel (beyond)  -> rag_infer · authz_fuzz · depconf · honeypot · attackpath
ATT&CK coverage -> attack_coverage.py (Navigator layer export) + rag/techniques_db.json entries.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time

WSL_DISTRO = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")


def _kali(cmd: str, timeout: int = 300) -> str:
    """Run a command in the Kali toolset (own copy of the vectors._kali shim to avoid a circular import).
    Runs `bash -lc` locally when already inside a Linux distro, else `wsl -d <distro>` on Windows."""
    try:
        if sys.platform == "win32":
            argv = ["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd]
        else:
            argv = ["bash", "-lc", cmd]
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
    except Exception as e:
        return f"[kali error: {e}]"


def _have(tool: str) -> bool:
    return "yes" in _kali(f"command -v {shlex.quote(tool)} >/dev/null 2>&1 && echo yes || echo no", 30)


def _res(kind, verified, summary, *, severity="medium", surface="", technique="",
         items=None, evidence=None, next_moves=None, status=None, needs=None):
    """Normalized discovery leg result. `needs` (a missing tool/cred) -> a non-verified, non-error skip."""
    body = summary if not needs else f"[needs {needs}] {summary}"
    return {
        "status": status if status is not None else (200 if verified else 404),
        "body": body[:2000],
        "discovery": {"kind": kind, "summary": summary[:400], "severity": severity,
                      "surface": surface, "technique": technique, "items": (items or [])[:50],
                      "evidence": (evidence or [])[:12], "next_moves": next_moves or [],
                      "needs": needs},
        "discovery_verified": bool(verified),
    }


# ------------------------------------------------------------------ consensus gaps

def ldap(move, ctx):
    """AD / LDAP / Kerberos enumeration (Cobalt Strike / BloodHound parity). Anonymous or credentialed
    bind via ldapsearch; surfaces SPNs (kerberoastable), adminCount=1, unconstrained delegation, trusts.
    move: target (DC host/ip), base_dn, bind_dn?, bind_pw?  -- read-only. ATT&CK T1087.002/T1069.002/T1018."""
    host = move.get("target") or move.get("host") or ""
    base_dn = move.get("base_dn") or ""
    if not host:
        return _res("ldap", False, "no target DC given (move['target'])", technique="T1087.002")
    if not _have("ldapsearch"):
        return _res("ldap", False, "install ldap-utils in Kali", needs="ldapsearch", technique="T1087.002")
    auth = ""
    if move.get("bind_dn"):
        auth = f"-D {shlex.quote(move['bind_dn'])} -w {shlex.quote(move.get('bind_pw',''))}"
    else:
        auth = "-x"                                    # anonymous simple bind
    b = f"-b {shlex.quote(base_dn)}" if base_dn else ""
    # 1) confirm a bind + pull the naming context; 2) pull SPNs / adminCount / delegation
    root = _kali(f"ldapsearch -x -H ldap://{shlex.quote(host)} -s base namingContexts 2>&1 | head -20", 60)
    if "namingContexts" not in root and not base_dn:
        return _res("ldap", False, f"no anonymous naming context from {host} (bind refused?)",
                    surface=host, technique="T1087.002", evidence=[root[:200]])
    q = (f"ldapsearch {auth} -H ldap://{shlex.quote(host)} {b} "
         "'(|(servicePrincipalName=*)(adminCount=1)(userAccountControl:1.2.840.113556.1.4.803:=524288))' "
         "sAMAccountName servicePrincipalName adminCount userAccountControl 2>&1 | head -200")
    out = _kali(q, 120)
    spns = re.findall(r"servicePrincipalName:\s*(.+)", out)
    admins = re.findall(r"adminCount:\s*1", out)
    delegs = out.count("userAccountControl")
    entries = len(re.findall(r"dn:\s", out))
    verified = entries > 0 or bool(spns)
    items = [f"SPN:{s.strip()}" for s in spns[:20]] + ([f"adminCount=1 x{len(admins)}"] if admins else [])
    summary = (f"AD enum on {host}: {entries} entr(y/ies), {len(spns)} SPN(s) (kerberoastable), "
               f"{len(admins)} adminCount=1, unconstrained-delegation candidates present={delegs>0}")
    return _res("ldap", verified, summary, severity="high" if spns else "medium", surface=host,
                technique="T1087.002/T1069.002", items=items, evidence=[out[:400]],
                next_moves=[{"action": "cred_harvest", "target": host}] if verified else [])


def cloud(move, ctx):
    """Cloud/container discovery (AWS/Azure/GCP IAM, buckets, instances) -- parity with CS/MSF cloud modules.
    Uses boto3 (AWS) or the az/gcloud CLIs if present + a credential in the environment. Read-only.
    move: provider (aws|azure|gcp). ATT&CK T1526 (Cloud Service Discovery)."""
    provider = (move.get("provider") or move.get("target") or "aws").lower()
    if provider == "aws":
        try:
            import boto3  # noqa
        except Exception:
            return _res("cloud", False, "pip install boto3 + configure AWS creds", needs="boto3", technique="T1526")
        try:
            import boto3
            who = boto3.client("sts").get_caller_identity()
            ident = who.get("Arn", "?")
            buckets = [b["Name"] for b in boto3.client("s3").list_buckets().get("Buckets", [])]
            try:
                roles = [r["RoleName"] for r in boto3.client("iam").list_roles(MaxItems=50).get("Roles", [])]
            except Exception:
                roles = []
            summary = f"AWS as {ident}: {len(buckets)} bucket(s), {len(roles)} IAM role(s)"
            return _res("cloud", True, summary, severity="high", surface="aws:"+ident,
                        technique="T1526/T1580", items=(buckets[:20] + [f"role:{r}" for r in roles[:20]]),
                        evidence=[ident])
        except Exception as e:
            return _res("cloud", False, f"AWS creds invalid / no access: {e}", needs="aws-creds", technique="T1526")
    cli = {"azure": "az", "gcp": "gcloud"}.get(provider)
    if not cli or not _have(cli):
        return _res("cloud", False, f"install/login the {provider} CLI ({cli})", needs=cli or provider, technique="T1526")
    if provider == "azure":
        out = _kali("az account show -o json 2>&1 | head -40; az resource list --query '[].name' -o tsv 2>&1 | head -40", 120)
    else:
        out = _kali("gcloud projects list --format='value(projectId)' 2>&1 | head -40", 120)
    verified = bool(out.strip()) and "ERROR" not in out and "not logged in" not in out.lower()
    items = [l.strip() for l in out.splitlines() if l.strip()][:30]
    return _res("cloud", verified, f"{provider} discovery: {len(items)} resource line(s)",
                severity="high", surface=provider, technique="T1526", items=items, evidence=[out[:400]],
                needs=None if verified else f"{provider}-login")


def fingerprint(move, ctx):
    """Mass service/version/TLS fingerprinting (Nmap/Masscan parity) -> feeds the RAG for CVE mapping.
    move: target (host/cidr), ports?  ATT&CK T1046 (Network Service Discovery). Read-only -sV scan."""
    tgt = move.get("target") or move.get("host") or ""
    if not tgt:
        return _res("fingerprint", False, "no target (move['target'])", technique="T1046")
    if not _have("nmap"):
        return _res("fingerprint", False, "install nmap in Kali", needs="nmap", technique="T1046")
    ports = move.get("ports") or "--top-ports 100"
    pflag = f"-p {shlex.quote(str(ports))}" if not str(ports).startswith("--") else str(ports)
    out = _kali(f"nmap -sV -T4 --version-light {pflag} {shlex.quote(tgt)} 2>/dev/null | grep -E '^[0-9]+/(tcp|udp)' | head -60", 300)
    svcs = [l.strip() for l in out.splitlines() if "/tcp" in l or "/udp" in l]
    openp = [s for s in svcs if " open " in s]
    # optional TLS/JARM-ish: cipher/cert enum on 443 if present
    tls = ""
    if any(":443" in tgt or "443/tcp" in s for s in svcs) or "443" in str(ports):
        tls = _kali(f"nmap -p443 --script ssl-enum-ciphers {shlex.quote(tgt)} 2>/dev/null | grep -iE 'TLSv|least strength' | head -8", 120)
    verified = bool(openp)
    services = [re.sub(r"\s+", " ", s) for s in openp[:25]]
    return _res("fingerprint", verified, f"{tgt}: {len(openp)} open service(s) fingerprinted",
                severity="medium", surface=tgt, technique="T1046", items=services,
                evidence=[out[:400]] + ([tls[:200]] if tls else []),
                next_moves=[{"action": "rag", "query": s} for s in services[:3]])


def external(move, ctx):
    """External / passive attack-surface mapping (Shodan/Censys/CT-log parity). Certificate-transparency
    (crt.sh) + optional resolve. OWNED DOMAINS ONLY -- authorized OSINT lane. ATT&CK T1590/T1596.
    move: domain."""
    dom = move.get("domain") or move.get("target") or ""
    if not dom or "." not in dom:
        return _res("external", False, "no owned domain (move['domain'])", technique="T1590")
    dom = dom.lstrip("*.").strip()
    out = _kali(f"curl -s --max-time 30 'https://crt.sh/?q=%25.{shlex.quote(dom)}&output=json' 2>/dev/null | head -c 200000", 60)
    subs = set()
    try:
        for row in json.loads(out or "[]"):
            for nm in str(row.get("name_value", "")).splitlines():
                nm = nm.strip().lstrip("*.").lower()
                if nm.endswith(dom):
                    subs.add(nm)
    except Exception:
        for m in re.findall(rf"[a-z0-9_.-]+\.{re.escape(dom)}", out or "", re.I):
            subs.add(m.lower().lstrip("*."))
    subs.discard(dom)
    verified = len(subs) > 0
    return _res("external", verified, f"{dom}: {len(subs)} subdomain(s) from CT logs",
                severity="low", surface=dom, technique="T1590/T1596", items=sorted(subs)[:40],
                evidence=[f"crt.sh returned {len(out)}b"],
                next_moves=[{"action": "fingerprint", "target": s} for s in sorted(subs)[:3]])


def cred_harvest(move, ctx):
    """Credentialed file/config/secret discovery over SMB shares (Enum4linux/CrackMapExec parity).
    Read-only: list shares, spider filenames, flag secret-looking files. NEVER downloads/writes.
    move: target, user?, password?  ATT&CK T1039/T1552.001."""
    host = move.get("target") or move.get("host") or ""
    if not host:
        return _res("cred_harvest", False, "no target (move['target'])", technique="T1552.001")
    if not _have("smbclient"):
        return _res("cred_harvest", False, "install smbclient in Kali", needs="smbclient", technique="T1552.001")
    u, p = move.get("user", ""), move.get("password", "")
    auth = f"-U {shlex.quote(u+'%'+p)}" if u else "-N"
    shares = _kali(f"smbclient -L //{shlex.quote(host)} {auth} 2>&1 | grep -iE 'Disk|IPC' | head -30", 60)
    names = re.findall(r"^\s*(\S+)\s+Disk", shares, re.M)
    hits = []
    for sh in names[:6]:
        ls = _kali(f"smbclient //{shlex.quote(host)}/{shlex.quote(sh)} {auth} -c 'recurse ON; ls' 2>/dev/null "
                   "| grep -iE '\\.(env|pem|key|config|xml|kdbx|ppk|pfx)|password|secret|credential' | head -10", 60)
        for l in ls.splitlines():
            if l.strip():
                hits.append(f"{sh}: {l.strip()[:80]}")
    verified = bool(names) and bool(hits)
    return _res("cred_harvest", verified,
                f"{host}: {len(names)} readable share(s), {len(hits)} secret-looking file(s)",
                severity="high" if hits else "low", surface=host, technique="T1039/T1552.001",
                items=hits[:25] or [f"share:{n}" for n in names[:25]], evidence=[shares[:300]])


def sbom(move, ctx):
    """Source-level supply-chain: parse a lockfile (requirements.txt / package-lock.json / go.sum) and
    query the offline RAG for known-vulnerable versions -- complements the image-level `supply_chain`
    (grype) leg. move: path_in_kali (lockfile). ATT&CK T1195.001."""
    path = move.get("path_in_kali") or move.get("path") or move.get("target") or ""
    if not path:
        return _res("sbom", False, "no lockfile path (move['path_in_kali'])", technique="T1195.001")
    raw = _kali(f"cat {shlex.quote(path)} 2>/dev/null | head -c 200000", 60)
    if not raw.strip() or "[kali error" in raw:
        return _res("sbom", False, f"cannot read {path}", technique="T1195.001")
    deps = []
    if path.endswith(".json"):
        try:
            j = json.loads(raw)
            for k, v in (j.get("dependencies") or j.get("packages") or {}).items():
                ver = v.get("version") if isinstance(v, dict) else v
                deps.append((k.split("node_modules/")[-1], str(ver)))
        except Exception:
            pass
    else:
        for line in raw.splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|@|\s+)v?([0-9][0-9A-Za-z.\-]*)", line)
            if m:
                deps.append((m.group(1), m.group(2)))
    vulns = []
    for name, ver in deps[:60]:
        q = _kali(f"python3 /opt/aegis-rag/rag_query.py --json --k 2 {shlex.quote(name+' '+ver)} 2>/dev/null | tail -1", 30)
        if re.search(r'"(cve|id)":\s*"CVE-', q, re.I) or "CVE-" in q:
            cve = (re.search(r"CVE-\d{4}-\d+", q) or [None])
            vulns.append(f"{name} {ver} -> {cve.group(0) if hasattr(cve,'group') else '?'}")
    verified = bool(vulns)
    return _res("sbom", verified, f"{path}: {len(deps)} dep(s), {len(vulns)} with a known CVE",
                severity="high" if vulns else "low", surface=path, technique="T1195.001",
                items=vulns[:25] or [f"{n} {v}" for n, v in deps[:25]], evidence=[f"{len(deps)} parsed"])


# ------------------------------------------------------------------ NOVEL (beyond all those tools)

def rag_infer(move, ctx):
    """NOVEL: cross-domain RAG inference. Correlate SEEMINGLY-UNRELATED signals already gathered this run
    (open services + a leaked key + a TLS cert SAN + a header) to INFER a hidden surface no single tool
    flags, then CONFIRM it by probing. Verified iff the inferred surface returns 2xx. ATT&CK T1592/T1595."""
    ctx = ctx or {}
    attempts = ctx.get("attempts") or []
    # gather corroborating signals from recent results
    hosts, hints = set(), []
    for a in attempts[-30:]:
        d = ((a.get("result") or {}).get("discovery")) or {}
        for it in (d.get("items") or []):
            hints.append(str(it))
            m = re.search(r"([a-z0-9-]+\.[a-z0-9.-]+)", str(it), re.I)
            if m:
                hosts.add(m.group(1))
    # inference: a SAN/subdomain seen in TLS/CT that was never probed -> candidate internal surface
    seen_surfaces = {str((a.get("move") or {}).get("surface") or "") for a in attempts}
    candidates = [h for h in hosts if h and h not in seen_surfaces][:5]
    guess = move.get("infer_url") or (("https://" + candidates[0]) if candidates else "")
    if not guess:
        return _res("rag_infer", False, "no corroborating signals yet to infer a hidden surface",
                    technique="T1592", items=hints[:10])
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
        r = requests.get(guess, verify=False, timeout=15)
        ok = 200 <= r.status_code < 400
    except Exception as e:
        return _res("rag_infer", False, f"inferred {guess} but unreachable: {e}", technique="T1592",
                    items=candidates)
    return _res("rag_infer", ok, f"inferred hidden surface {guess} from correlated signals -> HTTP {r.status_code}",
                severity="high" if ok else "low", surface=guess, technique="T1592/T1595",
                items=candidates, evidence=[f"signals={hints[:5]}"], status=r.status_code)


def authz_fuzz(move, ctx):
    """NOVEL: grey-box fuzzing of AUTH/AUTHZ LOGIC (not memory-safe parsers). Mutates a JWT (alg=none,
    stripped signature, tampered claims) and replays it to a protected path; a mutation that is ACCEPTED
    (2xx where a valid token is required) is a verified auth-bypass. move: path, token?  ATT&CK T1211/T1078."""
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET", "https://localhost:8443")
    path = move.get("path") or move.get("surface") or "/"
    token = move.get("token") or ""
    if not token:
        return _res("authz_fuzz", False, "no JWT to mutate (move['token']); capture one first",
                    technique="T1211")
    try:
        import base64
        import requests
        requests.packages.urllib3.disable_warnings()
    except Exception as e:
        return _res("authz_fuzz", False, f"requests unavailable: {e}", technique="T1211")

    def _b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")

    parts = token.split(".")
    muts = {}
    if len(parts) == 3:
        try:
            hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            pl = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            muts["alg_none"] = f"{_b64({**hdr,'alg':'none'})}.{_b64(pl)}."
            muts["sig_stripped"] = f"{parts[0]}.{parts[1]}."
            pl2 = {**pl, **(move.get("claim_tamper") or {"role": "admin", "isAdmin": True})}
            muts["claim_tamper"] = f"{parts[0]}.{_b64(pl2)}.{parts[2]}"
        except Exception:
            muts["sig_stripped"] = f"{parts[0]}.{parts[1]}."
    else:
        return _res("authz_fuzz", False, "token is not a 3-part JWT", technique="T1211")
    url = base.rstrip("/") + (path if path.startswith("/") else "/" + path)
    accepted = []
    for name, t in muts.items():
        try:
            import requests
            r = requests.get(url, headers={"Authorization": "Bearer " + t}, verify=False, timeout=15)
            if 200 <= r.status_code < 300:
                accepted.append(f"{name}->HTTP {r.status_code}")
        except Exception:
            pass
    verified = bool(accepted)
    return _res("authz_fuzz", verified,
                f"JWT logic fuzz on {path}: {len(accepted)}/{len(muts)} mutation(s) ACCEPTED",
                severity="critical" if accepted else "low", surface=path, technique="T1211/T1078",
                items=accepted or list(muts))


def depconf(move, ctx):
    """NOVEL: dependency-confusion / typosquat detection. For each INTERNAL-looking dependency in a
    lockfile, check whether the name is CLAIMABLE on the public registry (PyPI/npm) -- an unclaimed
    internal name is a confusion foothold no scanner flags. OWNED lockfile; OSINT lane. ATT&CK T1195.002.
    move: path_in_kali (lockfile), ecosystem (pypi|npm)."""
    path = move.get("path_in_kali") or move.get("path") or move.get("target") or ""
    eco = (move.get("ecosystem") or ("npm" if str(path).endswith(".json") else "pypi")).lower()
    if not path:
        return _res("depconf", False, "no lockfile path (move['path_in_kali'])", technique="T1195.002")
    raw = _kali(f"cat {shlex.quote(path)} 2>/dev/null | head -c 200000", 60)
    if not raw.strip() or "[kali error" in raw:
        return _res("depconf", False, f"cannot read {path}", technique="T1195.002")
    names = set()
    if eco == "npm":
        for m in re.findall(r'"([@A-Za-z0-9_./-]+)"\s*:\s*"', raw):
            if not m.startswith("@types") and "/" not in m.strip("@") or m.startswith("@"):
                names.add(m)
    else:
        for line in raw.splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.-]+)", line)
            if m:
                names.add(m.group(1))
    names = {n for n in names if n and not n.startswith((".", "-")) and len(n) > 1}
    claimable = []
    for n in list(names)[:40]:
        url = (f"https://registry.npmjs.org/{n}" if eco == "npm"
               else f"https://pypi.org/pypi/{shlex.quote(n)}/json")
        code = _kali(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 15 {shlex.quote(url)} 2>/dev/null", 30).strip()
        if code == "404":
            claimable.append(n)
    verified = bool(claimable)
    return _res("depconf", verified,
                f"{path} ({eco}): {len(claimable)}/{len(names)} dep name(s) UNCLAIMED on public registry (confusion risk)",
                severity="high" if claimable else "low", surface=path, technique="T1195.002",
                items=claimable[:25])


def honeypot(move, ctx):
    """NOVEL: deception-aware discovery. Baseline response TIMING + error-shape across a surface; a service
    that answers implausibly uniformly (near-zero variance, identical bodies for distinct inputs) is a
    likely honeypot/decoy -- so real attack surface can be told apart from bait. Informational unless the
    signal is strong. move: target/base, paths?  ATT&CK T1497 (Virtualization/Sandbox Evasion, defensive-aware)."""
    base = move.get("base") or (ctx or {}).get("base") or move.get("target") or os.environ.get("AEGIS_TARGET", "")
    if not base:
        return _res("honeypot", False, "no base/target", technique="T1497")
    if not str(base).startswith("http"):
        base = "https://" + base
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except Exception as e:
        return _res("honeypot", False, f"requests unavailable: {e}", technique="T1497")
    # Include API-style paths a REAL backend differentiates (JSON/401/404), so an SPA's history-fallback
    # (identical index.html for every non-API route) does NOT look uniform -- only a true decoy that
    # answers even the API path identically stays uniform and trips the signal.
    rnd = str(int(time.time()))
    paths = move.get("paths") or ["/", "/api/", "/api/zz-" + rnd, "/admin", "/.git/config", "/nope404-" + rnd]
    times, lens, codes = [], [], []
    for p in paths:
        try:
            import requests
            t0 = time.time()
            r = requests.get(base.rstrip("/") + p, verify=False, timeout=12)
            times.append(time.time() - t0); lens.append(len(r.content)); codes.append(r.status_code)
        except Exception:
            pass
    if len(times) < 3:
        return _res("honeypot", False, "not enough responses to baseline", technique="T1497", surface=base)
    import statistics
    tvar = statistics.pstdev(times) if len(times) > 1 else 0
    uniform_len = len(set(lens)) == 1
    uniform_code = len(set(codes)) == 1
    # strong signal: every distinct path (incl. random 404s) returns identical length AND code, with ~0 timing variance
    signal = uniform_len and uniform_code and tvar < 0.01
    return _res("honeypot", signal,
                f"deception baseline on {base}: timing_stdev={tvar:.4f}s, uniform_len={uniform_len}, "
                f"uniform_code={uniform_code} -> {'LIKELY HONEYPOT/decoy' if signal else 'looks real'}",
                severity="medium" if signal else "low", surface=base, technique="T1497",
                items=[f"codes={codes}", f"lens={lens}"])


def attackpath(move, ctx):
    """NOVEL: graph-based attack-path analysis over CONFIRMED discovery/findings this run. Builds a reach
    graph (hosts/surfaces as nodes, confirmed reach/over-reach as edges) and finds a path to move['goal'].
    Verified iff a path exists. Complements redteam/lateral.py (cross-host) at the discovery layer. T1069/T1018."""
    ctx = ctx or {}
    goal = str(move.get("goal") or "crown-jewel").lower()
    edges = {}
    nodes = set()
    for a in (ctx.get("attempts") or []):
        if a.get("verdict") != "verified":
            continue
        mv = a.get("move") or {}
        src = str(mv.get("role") or mv.get("host") or "start")
        dst = str(mv.get("surface") or mv.get("path") or mv.get("target") or "")
        if dst:
            nodes.add(src); nodes.add(dst)
            edges.setdefault(src, set()).add(dst)
    # BFS from every start-ish node to any node matching the goal keyword
    def _bfs():
        seen, q = set(), [[n] for n in nodes if "start" in n or "owner" in n or not any(n in v for v in edges.values())]
        q = q or [[n] for n in nodes]
        while q:
            path = q.pop(0)
            cur = path[-1]
            if goal in cur.lower():
                return path
            if cur in seen:
                continue
            seen.add(cur)
            for nxt in edges.get(cur, ()):
                q.append(path + [nxt])
        return None
    path = _bfs() if nodes else None
    verified = bool(path)
    return _res("attackpath", verified,
                (f"attack path to '{goal}': " + " -> ".join(path)) if path
                else f"no confirmed path to '{goal}' yet ({len(nodes)} node(s), {sum(len(v) for v in edges.values())} edge(s))",
                severity="high" if path else "low", surface=goal, technique="T1069/T1018",
                items=[" -> ".join(path)] if path else sorted(nodes)[:20])


# ------------------------------------------------------------------ DYNAMIC / open-ended (not static)

def ensure_tool(name, install_hint=None):
    """Make a tool available in the toolbox. Present -> (True, note). Missing -> install ON DEMAND when
    AEGIS_TOOL_INSTALL is enabled (best-effort across apt/pipx/pip/go/npm, or a board-provided
    move['install'] recipe), else report what's needed. This is what lets discovery reach BEYOND the Kali
    default set and beyond the built-in legs -- a tool that isn't present can be added/downloaded/installed.
    Gated (default off) to keep provisioning egress opt-in, consistent with the RAG-refresh / OSS-Fuzz-pull
    doctrine; set AEGIS_TOOL_INSTALL=1 to allow it."""
    if not name:
        return True, "no tool required"
    if _have(name):
        return True, "present"
    if str(os.environ.get("AEGIS_TOOL_INSTALL", "0")).lower() not in ("1", "true", "yes", "on"):
        return False, f"needs {name} (set AEGIS_TOOL_INSTALL=1 to auto-install, or install it in Kali)"
    recipes = ([install_hint] if install_hint else []) + [
        f"apt-get install -y {name}", f"pipx install {name}",
        f"pip install {name} --break-system-packages", f"go install {name}@latest",
        f"npm install -g {name}",
    ]
    for r in recipes:
        _kali(f"({r}) >/dev/null 2>&1", 400)
        if _have(name):
            return True, f"installed via: {r}"
    return False, f"could not install {name} (tried the board hint + apt/pipx/pip/go/npm)"


def tool(move, ctx):
    """OPEN-ENDED discovery leg -- run a BOARD-CHOSEN tool/command, so discovery is NOT limited to the
    built-in legs or a static class map. The board can pick ANY tool (Kali or installed on demand), MIX
    techniques, and adapt from MITRE/RAG intel. Non-destructive-guarded; confirmed by the move's prose
    `oracle` (a substring/regex the output must contain) or, absent one, a clean non-empty run.
    move: tool (name to ensure), cmd (the recon command), oracle?, install?, technique?, target?, seconds?"""
    name = move.get("tool") or ""
    cmd = move.get("cmd") or move.get("payload") or ""
    tech = move.get("technique", "")
    if not cmd:
        return _res("tool", False, "no command to run (move['cmd'])", technique=tech)
    try:                                                   # NON-DESTRUCTIVE doctrine (reuse the shared guard)
        import test_suggestions as TS
        okg, why = TS.guard(cmd)
    except Exception:
        okg = not re.search(r"\b(rm\s+-rf|DROP\s+(TABLE|DATABASE|SCHEMA)|DELETE\s+FROM|TRUNCATE|mkfs|dd\s+if=|:\(\)\{)\b", cmd, re.I)
        why = "destructive command"
    if not okg:
        return _res("tool", False, f"blocked by non-destructive doctrine: {why}", severity="low", technique=tech)
    okt, note = ensure_tool(name, move.get("install"))
    if not okt:
        return _res("tool", False, note, needs=name, technique=tech)
    secs = int(move.get("seconds") or 180)
    out = _kali(f"timeout {secs} bash -lc {shlex.quote(cmd)} 2>&1 | head -c 6000", secs + 20)
    oracle = move.get("oracle") or move.get("expected_oracle") or ""
    if oracle:
        try:
            verified = bool(re.search(oracle, out, re.I))
        except re.error:
            verified = oracle.lower() in out.lower()
    else:
        low = out.lower()
        verified = bool(out.strip()) and "[kali error" not in out and "command not found" not in low \
            and "not found" not in low[:40]
    return _res("tool", verified,
                f"{name or 'tool'} :: {cmd[:70]} -> {'confirmed' if verified else 'ran (no oracle match)'} ({note})",
                severity=move.get("severity", "medium"), surface=move.get("target", ""), technique=tech,
                items=[l.strip() for l in out.splitlines() if l.strip()][:20], evidence=[out[:400]])


def candidate_techniques(fp=None, limit=24):
    """DYNAMIC discovery-technique catalog for the board -- sourced LIVE (not a static list): the
    techniques_db discovery.* entries + the MITRE ATT&CK Discovery tactic (TA0007) pulled from the RAG
    (`technique_search.py`). The board picks, mixes, and may request a tool via action:'tool'. Offline-safe
    -> falls back to the local techniques_db if the RAG isn't reachable."""
    cands = []
    # 1) local techniques_db discovery.* (+ any mapped class) -- MERGE the deployed RAG copy AND the repo
    # copy (the deployed /opt copy can lag the repo until the RAG self-heal sync runs), dedup by id.
    for p in (os.path.join(os.environ.get("AEGIS_RAG_HOME", "/opt/aegis-rag"), "techniques_db.json"),
              os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rag", "techniques_db.json")):
        try:
            if not os.path.exists(p):
                continue
            for t in json.load(open(p, encoding="utf-8")).get("techniques", []):
                if str(t.get("id", "")).startswith("discovery.") or (t.get("class", "") or "").lower() in _LEG_ALIASES:
                    cands.append({"id": t.get("id"), "class": t.get("class"), "tools": t.get("kali_tools", []),
                                  "how": t.get("how_to_test", ""), "oracle": t.get("oracle", ""), "source": "techniques_db"})
        except Exception:
            continue
    # 2) MITRE Discovery tactic, live from the RAG
    try:
        out = _kali("cd " + shlex.quote(os.environ.get("AEGIS_RAG_HOME", "/opt/aegis-rag")) +
                    " && python3 technique_search.py --json --limit 30 'discovery enumeration' 2>/dev/null | tail -1", 60)
        for t in (json.loads(out[out.find("["):]) if "[" in out else []):
            cands.append({"id": t.get("id") or t.get("technique_id"), "class": "mitre",
                          "tools": t.get("tools") or t.get("kali_tools") or [], "how": t.get("desc", ""),
                          "source": "mitre"})
    except Exception:
        pass
    seen, uniq = set(), []
    for c in cands:
        k = c.get("id")
        if k and k not in seen:
            seen.add(k); uniq.append(c)
    return uniq[:limit]


def _parse_json_lines(text):
    out = []
    for line in (text or "").splitlines():
        line = line.strip().rstrip(",")
        if line.startswith("{"):
            try:
                o = json.loads(line)
                if isinstance(o, dict) and o.get("action"):
                    out.append(o)
            except Exception:
                pass
    if not out:                                            # tolerate a single [...] array
        i, j = (text or "").find("["), (text or "").rfind("]")
        if 0 <= i < j:
            try:
                out = [o for o in json.loads(text[i:j + 1]) if isinstance(o, dict) and o.get("action")]
            except Exception:
                out = []
    return out


def _board_compose(env, techs, present, acquired, missing, dom, role0):
    """BOARD-DRIVEN discovery plan: hand the ENV + surveyed technique CATALOG (MITRE/RAG) + TOOL STATUS to
    the board and let IT choose, compose, and MIX the discovery moves -- built-in legs, an open-ended
    action:'tool' with a specific command (install:true to provision it), or needs_code:true to have a probe
    written. Aims for the best discovery the board's current knowledge allows. Offline-safe: returns [] if
    the board/LLM is unreachable, so the caller falls back to the built-in legs. AEGIS_DISCOVERY_BOARD=0 skips."""
    if str(os.environ.get("AEGIS_DISCOVERY_BOARD", "1")).lower() in ("0", "false", "no", "off"):
        return []
    key = os.environ.get("AEGIS_LLM_API_KEY", "")
    ep = os.environ.get("AEGIS_LLM_ENDPOINT", "")
    if not key:                                            # resolve from secret.env via config (env may be bare)
        try:
            import config
            key = config.Master.get("openai_api_key") or ""
            ep = ep or config.Master.get("openai_api_endpoint") or ""
        except Exception:
            key = ""
    if not key:
        return []
    try:
        import remediation_board as RB
    except Exception:
        return []
    ep = (ep or "https://api.deepseek.com").rstrip("/")
    model = os.environ.get("AEGIS_BOARD_MODEL", "deepseek-v4-flash")
    legs = ("fingerprint,external,ldap,cloud,cred_harvest,sbom,rag_infer,authz_fuzz,depconf,honeypot,"
            "attackpath,tool,recon,web,supply_chain,misconfig,static,rag")
    catalog = [{"id": t.get("id"), "tools": t.get("tools"), "how": (t.get("how") or "")[:100]} for t in techs[:24]]
    sysp = ("You are the DISCOVERY PLANNER on an AUTHORIZED, contained security board. Given the ENVIRONMENT, "
            "the surveyed TECHNIQUE CATALOG (MITRE ATT&CK + RAG), and TOOL STATUS, choose and COMPOSE the BEST "
            "discovery moves the board's current knowledge allows for THIS environment. Include ONLY vectors, "
            "techniques and tools that are APPLICABLE to this environment + target, and DROP the rest -- e.g. "
            "skip AD/LDAP or cloud enumeration when no directory/cloud is in scope, skip web/auth-token fuzzing "
            "on a non-web host, skip SMB share spidering with no SMB. The ENVIRONMENT carries the detected "
            "stack, surfaces, and a 'scope' block: treat an ABSENT scope signal (scope.ad_dc / cloud / "
            "sbom_path / domain = null) as that class NOT being in scope, and match tools to the detected "
            "stack. Do NOT pad with inapplicable moves; fewer, on-target moves are better. Mix techniques freely; "
            "prefer PRESENT tools; for a missing tool either use action:'tool' with install:true, or set "
            "needs_code:true to have a contained probe WRITTEN. NON-DESTRUCTIVE only (enumerate/read/map -- "
            "never erase/drop/delete). Output JSON LINES, one move per line, each exactly: "
            '{"action":"<leg>","target":"","path":"","domain":"","provider":"","tool":"","cmd":"","oracle":"",'
            '"technique":"Txxxx","needs_code":false,"install":false,"why":"<=15 words grounded in the env"}. '
            f"Available leg actions: {legs}. Emit 6-12 DIVERSE moves; omit fields you don't use.")
    usr = json.dumps({"environment": env, "tool_status": {"present": present[:20], "acquired": acquired[:20],
                     "missing": missing[:20]}, "technique_catalog": catalog, "domain_target": dom})[:6000]
    try:
        raw = RB._post_openai_style(ep + "/chat/completions", key, model, sysp, usr, 1800, think=False) or ""
    except Exception:
        return []
    moves = _parse_json_lines(raw)
    for m in moves:
        m["role"] = m.get("role") or role0
        m["seed"] = "discovery-board"
        m.setdefault("intent", "map")
        m.setdefault("vuln_class", m.get("technique") or m.get("action"))
        # drop empty scaffolding fields the board left blank
        for k in [k for k, v in list(m.items()) if v == ""]:
            del m[k]
    return moves[:12]


def _env_probe(base):
    """Light TARGET ESTABLISHMENT when the Planner fingerprint isn't supplied: one HTTPS GET, read
    Server / X-Powered-By / Set-Cookie / body markers to name the stack. Offline-safe -> {}."""
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
        url = base if str(base).startswith("http") else "https://" + str(base)
        r = requests.get(url, verify=False, timeout=8, allow_redirects=True)
        sig = {"server": r.headers.get("Server", ""), "x_powered_by": r.headers.get("X-Powered-By", ""),
               "set_cookie": (r.headers.get("Set-Cookie", "") or "")[:120], "status": r.status_code}
        b = ((r.text or "")[:4000] + sig["set_cookie"] + sig["server"] + sig["x_powered_by"]).lower()
        stack = [k for k, tok in (("express", "connect.sid"), ("php", "phpsessid"), ("django", "csrftoken"),
                                  ("nextjs", "__next_data__"), ("react", "data-reactroot"), ("caddy", "caddy"),
                                  ("nginx", "nginx"), ("apache", "apache"), ("node", "express")) if tok in b]
        return {"signals": sig, "stack": sorted(set(stack))}
    except Exception:
        return {}


def survey(base, roles=None, host=None, fp=None):
    """The DYNAMIC discovery survey -- the long-standing 'don't get statically bound' flow, in order:
        1. SEE the environment (derive host/base; caller's fingerprint/stack ride along as intel),
        2. SURVEY techniques + tools LIVE (candidate_techniques(): MITRE ATT&CK + RAG + techniques_db),
        3. CHECK availability and ACQUIRE what's missing (ensure_tool, gated by AEGIS_TOOL_INSTALL),
        4. EMIT phase-1 discovery seed moves for the loop -- the built-in legs that apply here, PLUS the
           surveyed catalog + tool status as INTEL so the board can COMPOSE novel/mixed tool moves next.
    The board then decides/mixes/escalates through the normal loop (this only prepares the ground).
    Offline-safe: any failure -> minimal seeds. Runs before all three legs (Operator/ExploitGym/Red-Team).
    Kill-switch: AEGIS_DISCOVERY_SURVEY=0."""
    base = base or os.environ.get("AEGIS_TARGET", "")
    host = host or (re.sub(r"^https?://", "", str(base)).split("/")[0].split(":")[0] or "127.0.0.1")
    role0 = (roles or ["owner"])[0]
    techs = candidate_techniques()
    present, acquired, missing = [], [], []
    seen = set()
    for t in techs:
        for tl in (t.get("tools") or []):
            b = str(tl).split()[0].strip()
            if not b or b in seen:
                continue
            seen.add(b)
            ok, note = ensure_tool(b)
            (present if note == "present" else acquired if str(note).startswith("installed") else missing).append(b)
    is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", host))
    dom = host if ("." in host and not is_ip and host not in ("localhost",)) else ""
    # TARGET ESTABLISHMENT PRECEDES the board: give it the detected stack + surfaces + the in-scope signals
    # (from the target-specific env vars) so it judges applicability from the REAL environment, not a guess.
    est = fp or {}
    stack = est.get("stack_detected") or est.get("stack") or ((_env_probe(base) or {}).get("stack") if not fp else [])
    env = {"base": base, "host": host, "roles": roles or [], "stack": stack,
           "surfaces": est.get("surfaces") or [], "task_level": est.get("task_level"),
           "scope": {"domain": dom or None, "ad_dc": os.environ.get("AEGIS_DC_HOST") or None,
                     "cloud": os.environ.get("AEGIS_CLOUD") or None,
                     "sbom_path": os.environ.get("AEGIS_SBOM_PATH") or None,
                     "goal": os.environ.get("AEGIS_GOAL") or None}}
    # BOARD-DRIVEN first: the board composes + mixes the discovery moves from the live catalog + tool status,
    # aiming for the best discovery its current knowledge allows. Never statically bound.
    seeds = _board_compose(env, techs, present, acquired, missing, dom, role0)
    board_drove = bool(seeds)
    if not seeds:
        # OFFLINE-SAFE fallback only (board unreachable): the applicable built-in legs, each graceful-skipping.
        seeds = [
            {"action": "fingerprint", "target": host, "vuln_class": "fingerprint", "technique": "T1046", "surface": host},
            {"action": "rag_infer", "vuln_class": "rag_infer", "technique": "T1592", "surface": base},
            {"action": "honeypot", "base": base, "vuln_class": "honeypot", "technique": "T1497", "surface": base},
            {"action": "attackpath", "goal": (os.environ.get("AEGIS_GOAL") or "crown-jewel"), "vuln_class": "attackpath", "technique": "T1069"},
        ]
        if dom:
            seeds.append({"action": "external", "domain": dom, "vuln_class": "external", "technique": "T1590"})
        if os.environ.get("AEGIS_SBOM_PATH"):
            seeds.append({"action": "sbom", "path_in_kali": os.environ["AEGIS_SBOM_PATH"], "vuln_class": "sbom", "technique": "T1195.001"})
        if os.environ.get("AEGIS_DC_HOST"):
            seeds.append({"action": "ldap", "target": os.environ["AEGIS_DC_HOST"], "vuln_class": "ldap", "technique": "T1087.002"})
        if os.environ.get("AEGIS_CLOUD"):
            seeds.append({"action": "cloud", "provider": os.environ["AEGIS_CLOUD"], "vuln_class": "cloud", "technique": "T1526"})
    # SCAFFOLD direction (autonomous): always add a grype IMAGE dep-CVE scan when a stack image is
    # configured (AEGIS_MIRROR_IMAGE) -- the `sbom` leg is RAG/lockfile-based and COMPLEMENTS this, it is
    # not the image scan. Without this seed the scaffold CVE surface (e.g. multer/tar/curl) is never
    # examined by the engine (only ad-hoc). grype is the ground-truth oracle. Skipped if no image set.
    _img = os.environ.get("AEGIS_MIRROR_IMAGE")
    if _img and not any((s.get("action") == "supply_chain") for s in seeds):
        seeds.append({"action": "supply_chain", "image": _img, "layer": "scaffold",
                      "vuln_class": "supply-chain/known-cve", "technique": "deps.known_cve",
                      "surface": "stack", "severity": "high",
                      "why_novel": f"grype the stack image {_img} for vulnerable dependencies (SCAFFOLD)."})
    # CODE-ON-DEMAND -- OFFLINE FALLBACK ONLY (when the board did NOT drive selection). When the board drove,
    # it already chose the environment-APPLICABLE moves and set needs_code where it wants a probe written, so
    # we must NOT blanket-code every missing tool (that would be 'try all', incl. inapplicable ones). Only when
    # the board is unreachable do we fill gaps: for a surveyed technique whose tool(s) are all unavailable,
    # hand it to the novel-code writer to WRITE a contained probe the oracle then proves. Bounded.
    if (not board_drove) and str(os.environ.get("AEGIS_NOVEL_CODE", "1")).lower() not in ("0", "false", "no", "off"):
        cod = []
        for t in techs:
            tls = [str(x).split()[0] for x in (t.get("tools") or []) if str(x).split()]
            if tls and all(x in missing for x in tls):     # a real tool exists for it, but none is available here
                cod.append({"action": "probe", "needs_code": True, "vuln_class": t.get("class") or "discovery",
                            "technique": t.get("id"), "surface": host, "role": role0,
                            "new_code": (f"Fulfil discovery technique {t.get('id')} against {host} -- tool(s) "
                                         f"{tls} unavailable and not installable. Write a small, contained, "
                                         f"NON-DESTRUCTIVE probe achieving the same discovery ({t.get('how','')[:120]}) "
                                         "and prove it via its own oracle."),
                            "seed": "discovery-code-on-demand"})
        seeds += cod[:5]                                    # bounded so generated code never dominates
    for m in seeds:
        m.setdefault("role", role0); m["seed"] = "discovery-survey"; m.setdefault("intent", "map"); m.setdefault("layer", "scaffold")
    report = {"env": {"base": base, "host": host, "roles": roles or []}, "board_drove": board_drove,
              "surveyed": len(techs), "tools": {"present": present, "acquired": acquired, "missing": missing},
              "catalog": [{"id": t.get("id"), "tools": t.get("tools"), "source": t.get("source")} for t in techs[:20]]}
    return {"seed_moves": seeds, "report": report}


# class/alias -> a built-in leg (a FAST-PATH convenience, NOT the ceiling: the board can run ANY tool via
# action:'tool' with ensure_tool provisioning it, and pull techniques live via candidate_techniques()).
_LEG_ALIASES = {
    "ldap", "ad", "active_directory", "kerberos", "cloud", "aws", "azure", "gcp", "container",
    "fingerprint", "portscan", "port_scan", "external", "osint", "subdomain", "cred_harvest", "smb",
    "sbom", "rag_infer", "authz_fuzz", "jwt", "depconf", "honeypot", "attackpath",
}

# leg name -> function, merged into vectors.LEGS
LEGS = {
    "ldap": ldap, "cloud": cloud, "fingerprint": fingerprint, "external": external,
    "cred_harvest": cred_harvest, "sbom": sbom,
    "rag_infer": rag_infer, "authz_fuzz": authz_fuzz, "depconf": depconf,
    "honeypot": honeypot, "attackpath": attackpath,
    "tool": tool, "kali_tool": tool,                       # OPEN-ENDED: any board-chosen tool/technique
}
