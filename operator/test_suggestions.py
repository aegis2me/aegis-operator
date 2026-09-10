#!/usr/bin/env python3
"""
test_suggestions.py -- execute + verify the board's CODE-FLAVOURED attack suggestions.

The board's exploit-code specialists (qwen2.5-coder via its baked role, and DS when it uses the
same shape) emit suggestions as blocks of:
    TARGET  - HTTP method + endpoint + field
    CODE    - a runnable curl / SQL snippet
    ORACLE  - the check that proves pass/fail (an HTTP status/body assert, or a SELECT)

This harness parses those blocks, runs each against the CONTAINED twin, checks the oracle, and
records verified/rejected through the shared findings layer -- attributed to the source model, so
DS's and qwen's suggestions are tested through one pipeline and compared.

SAFETY: contained twin only (https://localhost:8443); a non-destructive guard blocks
DELETE / DROP / TRUNCATE / erase / rm etc.; DRY-RUN by default -- pass --execute to actually fire.

Usage:
    python test_suggestions.py --file suggestions.md --source qwen            # dry-run
    python test_suggestions.py --board eg_board --source qwen --execute       # run qwen's board posts
    python test_suggestions.py --file ds_suggestions.md --source ds --execute --role owner
"""
import os, re, sys, glob, json, argparse, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # vendored verified_findings / coverage_matrix
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except Exception:
    requests = None

BASE = os.environ.get("AEGIS_TARGET", "https://localhost:8443")
DB_CONTAINER = os.environ.get("AEGIS_DB_CONTAINER", "target-mirror-db-1")
DB_USER = os.environ.get("AEGIS_DB_USER", "appdb")
DB_NAME = os.environ.get("AEGIS_DB_NAME", "appdb")
DB_PASS = os.environ.get("AEGIS_DB_PASS", "mirror-db-pass")
WSL_DISTRO = os.environ.get("AEGIS_WSL_DISTRO", "kali-linux")

ACCOUNTS = {"owner": "owner-user", "dispatcher": "dispatcher-user", "finance": "finance-user",
            "warehouse": "warehouse-user", "technician": "technician-user"}

# ---- non-destructive guard (doctrine: plant/write OK, NEVER erase/delete) ----
DESTRUCTIVE = re.compile(r"\b(DELETE\s+FROM|DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE|--\s*drop|rm\s+-rf|"
                         r"mkfs|shutdown|:\s*>\s*/|del\s+/)\b", re.I)
def guard(code: str):
    if DESTRUCTIVE.search(code or ""):
        return False, "destructive pattern (erase/drop/truncate) -- blocked by non-destructive doctrine"
    if re.search(r"-X\s*DELETE\b", code or "", re.I):
        return False, "HTTP DELETE -- blocked by non-destructive doctrine"
    return True, ""

# ---- parse TARGET/CODE/ORACLE blocks out of free-form model output ----
def parse(text: str):
    # split on numbered items or on repeated TARGET labels
    chunks = re.split(r"(?m)^\s*(?:\d+[\).]|-)\s+(?=TARGET)", text)
    out = []
    for ch in chunks:
        if "TARGET" not in ch.upper():
            continue
        def grab(label, nxt):
            m = re.search(rf"{label}\s*[-:]?\s*(.*?)(?=\n\s*(?:{nxt})\b|\Z)", ch, re.I | re.S)
            return (m.group(1).strip() if m else "")
        target = grab("TARGET", "CODE|ORACLE")
        code = grab("CODE", "ORACLE")
        oracle = grab("ORACLE", "TARGET")
        if target or code:
            out.append({"target": target, "code": code, "oracle": oracle})
    return out

# ---- a tiny curl-line -> HTTP request replayer (forces host to the contained twin) ----
def parse_curl(code: str):
    # normalise a possibly multi-line, fenced, backslash-continued curl into one line
    raw = re.sub(r"```[a-zA-Z]*", "", code or "")
    raw = raw.replace("\\\r\n", " ").replace("\\\n", " ")
    line = " ".join(raw.split())
    if "curl" not in line.lower() and "http" not in line.lower():
        return None
    m_url = re.search(r"https?://[^\s'\"]+", line)
    if not m_url:
        return None
    path = re.sub(r"https?://[^/]+", "", m_url.group(0)) or "/"
    method = "GET"
    mm = re.search(r"-X\s*([A-Z]+)", line)
    if mm: method = mm.group(1).upper()
    data = None
    md = re.search(r"-d\s*'([^']*)'|-d\s*\"([^\"]*)\"|--data(?:-raw)?\s*'([^']*)'", line)
    if md:
        data = next(g for g in md.groups() if g is not None)
        if method == "GET": method = "POST"
    headers = {}
    for hm in re.finditer(r"-H\s*'([^']*)'|-H\s*\"([^\"]*)\"", line):
        h = hm.group(1) or hm.group(2)
        if ":" in h:
            k, v = h.split(":", 1)
            # the harness supplies its own authenticated session -- ignore model-placeholder auth headers
            if k.strip().lower() in ("cookie", "authorization"):
                continue
            headers[k.strip()] = v.strip()
    return {"method": method, "path": path, "data": data, "headers": headers}

def db(sql: str) -> str:
    env = dict(os.environ); env["MSYS_NO_PATHCONV"] = "1"; env["MSYS2_ARG_CONV_EXCL"] = "*"
    try:
        return subprocess.run(["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "docker", "exec",
                               "-e", f"PGPASSWORD={DB_PASS}", DB_CONTAINER, "psql", "-U", DB_USER,
                               "-d", DB_NAME, "-t", "-A", "-c", sql],
                              capture_output=True, text=True, env=env, timeout=30).stdout.strip()
    except Exception as e:
        return f"[db error: {e}]"

def login(role: str):
    s = requests.Session(); s.verify = False
    try:
        r = s.post(BASE + "/api/auth/login", json={"name": ACCOUNTS.get(role, ACCOUNTS["owner"]), "pin": os.environ.get("AEGIS_TEST_PIN", "000000")}, timeout=15)
        ok = r.status_code == 200
    except Exception:
        ok = False
    return s, ok

# ---- oracle evaluation ----
def check_oracle(oracle: str, resp, sess):
    """Evaluate a prose oracle. Handles relational conditions ('below 400', '>= 500', '2xx',
    'server error'), an exact status, body-contains, and a DB SELECT check."""
    o = oracle or ""
    low = o.lower()
    notes = []
    verdict = "manual"
    if resp is not None:
        st = resp.status_code
        notes.append(f"http={st} bytes={len(resp.content)}")
        m_rel = re.search(r"(?:below|under|less than|<=?)\s*(\d{3})", low)
        m_ge  = re.search(r"(?:>=|at least|greater than(?: or equal)?|more than|over)\s*(\d{3})", low)
        m_2xx = re.search(r"\b2xx\b|success|accepted|created|saved|persist|stored|below\s*400", low)
        m_5xx = re.search(r"\b5xx\b|server error|internal error|crash|\b500\b", low)
        m_exact = re.search(r"(?:http\s*|status\s*(?:code)?\s*(?:==|=|is|:)?\s*)(\d{3})", low)
        if m_rel:
            verdict = "pass" if st < int(m_rel.group(1)) else "fail"; notes.append(f"expect <{m_rel.group(1)}")
        elif m_ge:
            verdict = "pass" if st >= int(m_ge.group(1)) else "fail"; notes.append(f"expect >={m_ge.group(1)}")
        elif m_2xx:
            # 2xx/accept is the common PASS condition; check it BEFORE 5xx so an oracle that mentions
            # both ("pass if 2xx; a 500 means blocked") binds to the success clause, not the failure one.
            verdict = "pass" if 200 <= st < 300 else "fail"; notes.append("expect 2xx")
        elif m_5xx:
            verdict = "pass" if st >= 500 else "fail"; notes.append("expect 5xx")
        elif m_exact:
            exp = int(m_exact.group(1)); verdict = "pass" if st == exp else "fail"; notes.append(f"expect {exp}")
        elif not re.search(r"\bSELECT\b", o, re.I):
            # BARE status code with no http/status prefix (e.g. "200 OK", "returns 201") -- take the
            # first standalone 1xx-5xx token as the expected status. Loosened so coder-written probe
            # ORACLEs verify instead of falling to 'manual'. SKIP for a DB SELECT oracle: its numbers
            # (ids/amounts) are DATA, not a status, and a bogus 'fail' here would block the DB SELECT
            # branch below (which only overrides a still-'manual' verdict).
            m_bare = re.search(r"\b([1-5]\d\d)\b", low)
            if m_bare:
                exp = int(m_bare.group(1)); verdict = "pass" if st == exp else "fail"; notes.append(f"expect ~{exp}")
        # body-contains, quoted OR bare (contains 'x' | contains "x" | contains x)
        bm = re.search(r"contains?\s+['\"]([^'\"]+)['\"]", o, re.I) or re.search(r"contains?\s+([^\s'\";,.]+)", o, re.I)
        if bm:
            hit = bm.group(1) in (resp.text or "")
            if verdict == "manual":
                verdict = "pass" if hit else "fail"
            elif verdict == "pass" and not hit:
                # a REQUIRED body signal was specified but ABSENT -> the proof fails even on a 2xx,
                # so a bare-200 / SPA-shell response can't satisfy a "200 AND body contains X" oracle.
                verdict = "fail"
            notes.append(f"body~'{bm.group(1)}':{hit}")
    sel = re.search(r"(SELECT\b.+?;)", o, re.I | re.S)
    if sel:
        res = db(sel.group(1))
        notes.append(f"db -> {res[:70]}")
        if verdict == "manual":
            verdict = "pass" if res and not res.startswith("[db error") else "inconclusive"
    return verdict, "; ".join(notes)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="a suggestions file (md/txt)")
    ap.add_argument("--board", help="board dir to glob for suggestion posts")
    ap.add_argument("--source", default="unknown", help="attribution: qwen | ds | ...")
    ap.add_argument("--role", default="owner", choices=list(ACCOUNTS))
    ap.add_argument("--execute", action="store_true", help="actually fire (default: dry-run)")
    a = ap.parse_args()

    texts = []
    if a.file:
        texts.append(open(a.file, encoding="utf-8").read())
    if a.board:
        pat = "*" + a.source + "*" if a.source != "unknown" else "*"
        for f in glob.glob(os.path.join(a.board, pat + ".md")):
            texts.append(open(f, encoding="utf-8").read())
    if not texts:
        sys.exit("nothing to test -- pass --file or --board")

    suggestions = []
    for t in texts:
        suggestions += parse(t)
    print(f"parsed {len(suggestions)} suggestion(s) from source='{a.source}'  mode={'EXECUTE' if a.execute else 'DRY-RUN'}\n")

    store = cov = None
    if a.execute:
        from verified_findings import FindingStore, Finding, Evidence, run_marker
        from coverage_matrix import CoverageTracker
        from dataclasses import asdict
        store = FindingStore(os.path.join(HERE, "suggestion_test_findings.jsonl"))
        cov = CoverageTracker(os.path.join(HERE, "suggestion_test_coverage.jsonl"))
        mk = run_marker(f"suggtest-{a.source}")
        sess, authed = login(a.role)
        if not authed:
            sys.exit(f"[abort] login as role '{a.role}' failed (is the mirror up? do ACCOUNTS/PIN match?) -- "
                     "refusing to run the battery unauthenticated; results would be misleadingly 'refuted'.")

    passed = failed = blocked = manual = 0
    for i, sug in enumerate(suggestions, 1):
        ok, why = guard(sug["code"])
        print(f"[{i}] TARGET: {sug['target'][:90]}")
        if not ok:
            blocked += 1; print(f"    BLOCKED: {why}\n"); continue
        req = parse_curl(sug["code"])
        if not a.execute:
            print(f"    would run: {req['method'] if req else '(unparsed)'} {req['path'] if req else sug['code'][:60]}")
            print(f"    oracle: {sug['oracle'][:90]}\n"); continue
        resp = None
        if req:
            try:
                url = BASE + req["path"] if req["path"].startswith("/") else BASE + "/" + req["path"]
                kw = {"timeout": 20, "headers": req["headers"] or None}
                if req["data"]:
                    try: kw["json"] = json.loads(req["data"])
                    except Exception: kw["data"] = req["data"]
                resp = sess.request(req["method"], url, **kw)
            except Exception as e:
                print(f"    run error: {type(e).__name__}: {e}\n"); manual += 1; continue
        verdict, notes = check_oracle(sug["oracle"], resp, sess)
        print(f"    {verdict.upper()} -- {notes}")
        from dataclasses import asdict
        from verified_findings import Finding, Evidence
        f = Finding(claim_type=f"suggestion.{a.source}",
                    summary=f"[{a.source}] {sug['target'][:120]} | oracle: {sug['oracle'][:120]}",
                    severity="unknown", run_id=mk, provenance={"provider": a.source, "via": "test_suggestions"},
                    coverage_tags=[f"source:{a.source}", "technique:suggestion-test"],
                    evidence=[asdict(Evidence(kind="http", detail=notes))])
        fid = store.record_candidate(f)
        if verdict == "pass":
            store._transition(fid, "verified", f"oracle:{a.source}", {"notes": notes}); passed += 1
        elif verdict == "fail":
            store._transition(fid, "rejected", f"oracle:{a.source}", {"notes": notes}); failed += 1
        else:
            manual += 1
        cov.record(surface=sug["target"][:60], role=a.role, technique="suggestion-test",
                   result="finding" if verdict == "pass" else ("clean" if verdict == "fail" else "inconclusive"),
                   note=f"{a.source}:{verdict}")
        print()

    print(f"== summary ({a.source}): pass={passed} fail={failed} blocked={blocked} manual/inconclusive={manual} ==")
    if a.execute:
        print(f"chain_ok={store.verify_chain()}  findings->{os.path.join(HERE,'suggestion_test_findings.jsonl')}")

if __name__ == "__main__":
    main()
