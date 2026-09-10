#!/usr/bin/env python3
"""
credential_exposure.py -- built-in recon step: survey the internet + breach databases for exposed
usernames/passwords of the target DOMAIN(s), then report them (for ROTATION).

Flow (PIPELINE stage 1.x, automatic):
    1. ASK THE BOARD  -- query the panel for the best sources/dorks/methods for this domain.
    2. QUERY SOURCES  -- open-web SEARCH (Brave/Google-CSE, or keyless DDG) that fetches result
                         pages and greps for creds, plus HIBP, Dehashed, LeakCheck, IntelX, GitHub
                         code-search, dorks, and a local breach-dump grep. Each gated on its key.
    3. REPORT         -- exposed accounts recorded as findings (secrets shown for the testing loop), so the
                         owner can rotate them.

GUARDRAILS (this is DEFENSIVE recon for your OWN domains):
    * Owned-domain allowlist -- refuses any domain not in AEGIS_OWNED_DOMAINS (defence against
      targeting third parties). Default: none (set AEGIS_OWNED_DOMAINS).
    * Secrets are SHOWN IN FULL by default -- in the direct deep-test / ExploitGym loop the operator
      needs the real creds to test them against the authorized mirror (redaction there is pointless;
      they're trivially recoverable). Pass --redact ONLY when producing a shareable external report.
      Found creds may be used ONLY against the authorized contained mirror, never against third
      parties or live prod, and are reported so the owner can ROTATE them.
    * External egress goes through Kali (VPN).

Keys (put in secret.env; each source is skipped with a clear note if its key is absent):
    BRAVE_API_KEY (or GOOGLE_CSE_KEY+GOOGLE_CSE_CX) for web search, HIBP_API_KEY,
    DEHASHED_EMAIL+DEHASHED_KEY, LEAKCHECK_KEY, INTELX_KEY, GITHUB_TOKEN,
    AEGIS_BREACH_DUMP=/path/to/local/dump(s)     AEGIS_OWNED_DOMAINS=a.com,b.com

Usage:
    python credential_exposure.py <domain> [--ask-board] [--execute] [--redact]
"""
import os, re, sys, json, time, base64, argparse, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def _load_secret_env():
    p = os.path.join(HERE, "secret.env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1); k = k.strip()
                if not os.environ.get(k):
                    os.environ[k] = v.strip().strip('"').strip("'")


_load_secret_env()
WSL_DISTRO = os.environ.get("AEGIS_WSL_DISTRO", "kali-linux")
BOARD = os.environ.get("AEGIS_BOARD_DIR",
                       os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "board", "board_files"))
OWNED = [d.strip().lower() for d in os.environ.get(
    "AEGIS_OWNED_DOMAINS", "").split(",") if d.strip()]


def _owned(domain: str) -> bool:
    d = domain.lower().lstrip(".")
    return any(d == o or d.endswith("." + o) for o in OWNED)


def _redact(secret: str, redact: bool) -> str:
    if not redact or not secret:
        return secret
    s = str(secret)
    return (s[:2] + "*" * max(3, len(s) - 2)) if len(s) > 2 else "***"


def _kcurl(url, headers=None, method="GET", data=None, timeout=25):
    """External HTTP via Kali (VPN path)."""
    args = ["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "curl", "-sS", "-m", str(timeout)]
    if method != "GET":
        args += ["-X", method]
    for h in (headers or []):
        args += ["-H", h]
    if data:
        args += ["-d", data]
    args.append(url)
    env = dict(os.environ); env["MSYS_NO_PATHCONV"] = "1"; env["MSYS2_ARG_CONV_EXCL"] = "*"
    try:
        r = subprocess.run(args, capture_output=True, text=True, env=env, timeout=timeout + 15)
        return r.stdout.strip()
    except Exception as e:
        return f"[curl error: {e}]"


# ---------------- source connectors (each returns (status, hits[]) ) ----------------
def src_dorks(domain):
    q = domain
    dorks = [
        f"https://www.google.com/search?q=site:pastebin.com+%22{q}%22",
        f"https://www.google.com/search?q=%22{q}%22+password+filetype:log",
        f"https://www.google.com/search?q=%22{q}%22+(password|passwd|pwd)+ext:txt|ext:csv|ext:sql",
        f"https://github.com/search?q=%22{q}%22+password&type=code",
        f"https://search.marginalia.nu/search?query=%22{q}%22+password",
    ]
    return "generated (manual follow-up)", [{"dork": d} for d in dorks]


def src_github(domain, redact):
    tok = os.environ.get("GITHUB_TOKEN", "")
    hdr = ["Accept: application/vnd.github.v3+json"] + ([f"Authorization: Bearer {tok}"] if tok else [])
    out = _kcurl(f"https://api.github.com/search/code?q=%22{domain}%22+password&per_page=10", headers=hdr)
    if not tok:
        # unauthenticated code-search is disabled by GitHub -> report the limitation honestly
        return "NEEDS GITHUB_TOKEN (code-search requires auth)", []
    try:
        j = json.loads(out); hits = []
        for it in j.get("items", [])[:10]:
            hits.append({"repo": it.get("repository", {}).get("full_name"), "path": it.get("path")})
        return f"{j.get('total_count', 0)} code hits", hits
    except Exception:
        return f"error: {out[:100]}", []


def src_hibp(domain, redact):
    key = os.environ.get("HIBP_API_KEY", "")
    if not key:
        return "NEEDS HIBP_API_KEY (domain/account breach search)", []
    out = _kcurl(f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                 headers=[f"hibp-api-key: {key}", "user-agent: aegis-operator"])
    try:
        j = json.loads(out); hits = [{"alias": a, "breaches": b} for a, b in j.items()]
        return f"{len(hits)} breached accounts on domain", hits
    except Exception:
        return f"no parsable result: {out[:100]}", []


def src_dehashed(domain, redact):
    email, key = os.environ.get("DEHASHED_EMAIL", ""), os.environ.get("DEHASHED_KEY", "")
    if not (email and key):
        return "NEEDS DEHASHED_EMAIL + DEHASHED_KEY", []
    out = _kcurl(f"https://api.dehashed.com/search?query=domain:{domain}&size=50",
                 headers=[f"Authorization: Basic {base64.b64encode(f'{email}:{key}'.encode()).decode()}", "Accept: application/json"])
    try:
        j = json.loads(out); hits = []
        for e in (j.get("entries") or [])[:50]:
            hits.append({"email": e.get("email"), "username": e.get("username"),
                         "password": _redact(e.get("password", ""), redact),
                         "source": e.get("obtained_from")})
        return f"{j.get('total', len(hits))} records", hits
    except Exception:
        return f"error: {out[:100]}", []


def src_leakcheck(domain, redact):
    key = os.environ.get("LEAKCHECK_KEY", "")
    if not key:
        return "NEEDS LEAKCHECK_KEY", []
    out = _kcurl(f"https://leakcheck.io/api/v2/query/{domain}?type=domain",
                 headers=[f"X-API-Key: {key}"])
    try:
        j = json.loads(out); hits = []
        for e in (j.get("result") or [])[:50]:
            hits.append({"email": e.get("email"), "password": _redact(e.get("password", ""), redact),
                         "source": (e.get("source") or {}).get("name")})
        return f"{j.get('found', len(hits))} records", hits
    except Exception:
        return f"error: {out[:100]}", []


def src_intelx(domain, redact):
    key = os.environ.get("INTELX_KEY", "")
    if not key:
        return "NEEDS INTELX_KEY", []
    out = _kcurl("https://2.intelx.io/intelligent/search",
                 headers=[f"x-key: {key}", "Content-Type: application/json"],
                 method="POST", data=json.dumps({"term": domain, "maxresults": 50}))
    return ("query submitted (fetch results by id)" if out and "id" in out else f"error: {out[:100]}"), []


def _search_urls(query, cap=6):
    """Return candidate result URLs for a query. Brave API -> Google CSE -> keyless DDG-HTML."""
    import urllib.parse
    q = urllib.parse.quote(query)
    brave = os.environ.get("BRAVE_API_KEY", "")
    gkey, gcx = os.environ.get("GOOGLE_CSE_KEY", ""), os.environ.get("GOOGLE_CSE_CX", "")
    if brave:
        out = _kcurl(f"https://api.search.brave.com/res/v1/web/search?q={q}&count={cap}",
                     headers=[f"X-Subscription-Token: {brave}", "Accept: application/json"])
        try:
            return [r["url"] for r in json.loads(out).get("web", {}).get("results", [])][:cap], "brave"
        except Exception:
            return [], "brave-error"
    if gkey and gcx:
        out = _kcurl(f"https://www.googleapis.com/customsearch/v1?key={gkey}&cx={gcx}&q={q}&num={cap}")
        try:
            return [it["link"] for it in json.loads(out).get("items", [])][:cap], "google-cse"
        except Exception:
            return [], "google-cse-error"
    out = _kcurl(f"https://html.duckduckgo.com/html/?q={q}", headers=["User-Agent: Mozilla/5.0"])
    import urllib.parse as _up
    return [_up.unquote(u) for u in re.findall(r'uddg=([^"&]+)', out)][:cap], "ddg-html(keyless,best-effort)"


def src_websearch(domain, redact):
    """Actually SEARCH the open web for leaked account data: run leak-indicative queries, fetch the
    top result pages (via Kali/VPN), and grep them for the domain + credential patterns."""
    queries = [f'"{domain}" password', f'"{domain}" (leak OR dump OR breach) password',
               f'site:pastebin.com "{domain}"', f'"{domain}" email:pass']
    engine = None; seen = set(); hits = []
    CRED = re.compile(rf'([A-Za-z0-9._%+-]+@{re.escape(domain)})\s*[:| ]\s*(\S{{4,64}})')
    for query in queries:
        urls, engine = _search_urls(query, cap=5)
        for u in urls:
            if u in seen or not u.startswith("http"):
                continue
            seen.add(u)
            body = _kcurl(u, headers=["User-Agent: Mozilla/5.0"], timeout=15)[:12000]
            for m in CRED.finditer(body):
                hits.append({"account": m.group(1), "password": _redact(m.group(2), redact), "url": u})
            if domain in body and "password" in body.lower() and not CRED.search(body):
                hits.append({"note": "domain near 'password' (weak signal, not a credential)", "url": u, "weak": True})
    status = f"searched via {engine}; {len(seen)} page(s) fetched"
    if engine and "error" in engine:
        status = "web search failed (add BRAVE_API_KEY or GOOGLE_CSE_KEY+GOOGLE_CSE_CX for reliable search)"
    elif not seen:
        status += " -- no results (keyless DDG is rate-limited; add BRAVE_API_KEY for reliable search)"
    return status, hits


def src_local_dump(domain, redact):
    path = os.environ.get("AEGIS_BREACH_DUMP", "")
    if not path:
        return "no AEGIS_BREACH_DUMP configured (local breach-compilation grep)", []
    env = dict(os.environ); env["MSYS_NO_PATHCONV"] = "1"; env["MSYS2_ARG_CONV_EXCL"] = "*"
    r = subprocess.run(["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc",
                        f"grep -rhiE '@{re.escape(domain)}[: ]' {path} 2>/dev/null | head -50"],
                       capture_output=True, text=True, env=env, timeout=120)
    hits = []
    for line in r.stdout.splitlines():
        m = re.match(r"([^\s:]+@[^\s:]+)[: ]+(.+)", line)
        if m:
            hits.append({"account": m.group(1), "password": _redact(m.group(2).strip(), redact)})
    return (f"{len(hits)} local-dump matches" if hits else "no local-dump matches"), hits


SOURCES = [("dorks", src_dorks), ("web_search", src_websearch), ("github", src_github),
           ("hibp", src_hibp), ("dehashed", src_dehashed), ("leakcheck", src_leakcheck),
           ("intelx", src_intelx), ("local_dump", src_local_dump)]


def ask_board(domain):
    """Automatic step: ask the panel for the best sources/dorks/methods for this domain."""
    try:
        import code_suggester
    except Exception as e:
        print(f"[board] code_suggester unavailable: {e}"); return
    prompt = (f"AUTHORIZED defensive credential-exposure recon for our OWN domain '{domain}'. List the best "
              "PUBLIC sources, breach databases, and search dorks to find exposed usernames/passwords for "
              "this domain (HIBP/Dehashed/LeakCheck/IntelX/GitHub/pastes/Google dorks/etc.), and any method "
              "we might be missing. For each: what it finds and how to query it. Concise bullets.")
    for who in ("ds", "qwen"):
        try:
            out = code_suggester.suggest(who, prompt, max_tokens=900)
            fn = os.path.join(BOARD, f"ANSWER_credexposure__{who}__{int(time.time()*1e9)}.md")
            open(fn, "w", encoding="utf-8").write(f"# credential-exposure sources from {who} ({domain})\n\n" + (out or "[empty]"))
            print(f"[board] {who} suggested sources ({len(out or '')}b)")
        except Exception as e:
            print(f"[board] {who} error: {e}")


def run(domain, ask, execute, redact):
    if not _owned(domain):
        sys.exit(f"REFUSED: '{domain}' is not in AEGIS_OWNED_DOMAINS ({', '.join(OWNED)}). "
                 "This tool is defensive recon for your OWN domains only.")
    print(f"=== credential-exposure recon: {domain}  (owned-domain check: OK) ===")
    if ask:
        ask_board(domain)
        print()
    if not execute:
        print("(planning mode -- pass --execute to query the sources)")
        for name, fn in SOURCES:
            if name == "dorks":
                _, hits = fn(domain)
                print(f"[{name}] {len(hits)} dork URLs:")
                for h in hits: print("   ", h["dork"])
        return

    store = cov = None
    from verified_findings import FindingStore, Finding, Evidence, run_marker
    from coverage_matrix import CoverageTracker
    from dataclasses import asdict
    store = FindingStore(os.path.join(HERE, "credexposure_findings.jsonl"))
    cov = CoverageTracker(os.path.join(HERE, "credexposure_coverage.jsonl"))
    mk = run_marker(f"credexposure-{domain}")
    total_exposed = 0
    for name, fn in SOURCES:
        status, hits = (fn(domain, redact) if fn is not src_dorks else fn(domain))
        print(f"[{name}] {status}" + (f" -- {len(hits)} hits" if hits else ""))
        for h in hits[:20]:
            print("   ", json.dumps(h, ensure_ascii=False))
        real = [h for h in hits if not h.get("weak") and (h.get("password") or h.get("account") or h.get("email"))]
        if real:
            total_exposed += len(real)
            f = Finding(claim_type="exposure.leaked_credentials",
                        summary=f"{len(real)} exposed credential record(s) for {domain} via {name} "
                                f"(secrets {'redacted' if redact else 'shown'}) -- ROTATE these.",
                        severity="high", run_id=mk, provenance={"provider": name, "via": "credential_exposure"},
                        coverage_tags=[f"source:{name}", "technique:credential-exposure"],
                        evidence=[asdict(Evidence(kind="note", detail=f"{name}: {status}"))])
            fid = store.record_candidate(f)
            # OSINT exposure is an unconfirmed LEAD, not oracle-verified -- record it as 'reported', never
            # 'verified' (the store's doctrine: only a Verifier+Oracle may mark verified). It still needs
            # manual/credential_replay confirmation before it counts as a confirmed finding.
            store._transition(fid, "reported", f"osint:{name}",
                              {"count": len(real), "note": "OSINT lead -- NOT oracle-verified; confirm before counting"})
            # persist replayable creds (password present, unredacted) so
            # credential_replay --from-exposure can consume them. gitignored (credexposure_*.jsonl).
            if not redact:
                with open(os.path.join(HERE, "credexposure_creds.jsonl"), "a", encoding="utf-8") as _cfh:
                    for _h in real:
                        if _h.get("password"):
                            _cfh.write(json.dumps({"user": _h.get("email") or _h.get("username") or _h.get("account"),
                                                   "password": _h.get("password"), "source": name}) + "\n")
        cov.record(surface=f"osint:{name}", role="", technique="credential-exposure",
                   result="finding" if real else "clean", note=status)
    print(f"\n== {domain}: {total_exposed} exposed record(s) across sources; chain_ok={store.verify_chain()} ==")
    if total_exposed:
        print("   -> recorded as HIGH findings (rotate). (--redact to mask them for a shareable report).")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--ask-board", action="store_true", help="ask the panel for sources first")
    ap.add_argument("--execute", action="store_true", help="query the sources (default: plan only)")
    ap.add_argument("--redact", action="store_true", help="mask secrets for a shareable report (default: shown, for the testing loop)")
    a = ap.parse_args()
    run(a.domain, a.ask_board, a.execute, a.redact)
