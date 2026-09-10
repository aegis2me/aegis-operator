"""
vectors.py -- the SHARED fact-finding / attack-vector legs available to ALL THREE modes
(Operator, ExploitGym, Red-Team). Every mode dispatches through here, so none is blind to a class the
others can see; they differ ONLY in the doctrine wrapper each puts around dispatch():
    Operator   -> non-destructive guard
    ExploitGym -> + audit
    Red-Team   -> + authorization/scope guard

Vectors: web (HTTP), recon (nmap), supply_chain (syft/grype SBOM), static (semgrep), fuzz (afl/honggfuzz
presence+run), misconfig (exposed-file/k8s scan), rag (offline CVE lookup). Kali-backed legs shell into
the kali-linux distro; web uses requests. Each returns {status, body, ...} + the leg's structured data.
"""
from __future__ import annotations

import os, re, shlex, subprocess, sys

WSL_DISTRO = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")


def _kali(cmd: str, timeout: int = 600) -> str:
    """Run a command in the Kali toolset. PLATFORM SHIM (see memory nested-wsl-shim): when this code
    is ALREADY running inside a Linux distro (sys.platform != 'win32' -- e.g. the in-Kali ExploitGym
    HTTP path, where the Windows host can't reach the target's --internal network), run `bash -lc`
    locally; there is no wsl.exe inside the distro, so a bare ['wsl',...] call would fail with Errno 2
    and return a silent empty result. On Windows, wrap in `wsl -d <distro>` as before."""
    try:
        if sys.platform == "win32":
            argv = ["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd]
        else:
            argv = ["bash", "-lc", cmd]
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "")
    except Exception as e:
        return f"[kali error: {e}]"


def web(move, ctx):
    import requests
    try:
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass
    sf = ctx.get("session_for_role")
    sess = sf(move.get("role", "owner")) if sf else requests.Session()
    base = ctx.get("base", "https://localhost:8443")
    method = (move.get("method") or "GET").upper()
    path = move.get("path") or move.get("surface") or "/"
    url = base + (path if path.startswith("/") else "/" + path)
    r = sess.request(method, url, json=move.get("body"), verify=False, timeout=20)
    return {"status": r.status_code, "body": (r.text or "")[:2000]}


def recon(move, ctx):
    t = move.get("target") or move.get("host") or ""
    out = _kali(f"command -v nmap >/dev/null 2>&1 && nmap -sV -T4 --top-ports 50 {shlex.quote(t)} 2>/dev/null | head -40 || echo 'nmap missing'", 300)
    return {"status": 200, "body": out[:4000]}


def supply_chain(move, ctx):
    from supply_chain_scan import scan_image
    # SCAFFOLD direction: scan the STACK image for vulnerable deps. If the seed didn't name an image,
    # fall back to the configured mirror image (AEGIS_MIRROR_IMAGE) -> the ctx base host -> so the
    # scaffold CVE/SBOM pass runs AUTONOMOUSLY instead of scanning nothing (the reason a scaffold run
    # can silently report 0 deps). grype is the ground-truth oracle (version-range matching).
    image = (move.get("image") or move.get("target")
             or os.environ.get("AEGIS_MIRROR_IMAGE") or "")
    res = scan_image(image)
    # CVE CONFIRMATION (KEV/PoC/EPSS -> confidence, cuts false positives) is OPT-IN via ctx.cve_confirm
    # and runs ONLY in the co-pilot + benchmark legs. The RED-TEAM leg deliberately does NOT get it: it
    # is a conservative admin-track evidence pass, not live exploitation -- red-team instead goes as DEEP
    # as it can, non-destructively, through its own escalation/pivot.
    if (ctx or {}).get("cve_confirm"):
        try:
            from supply_chain_scan import confirm_all
            res = confirm_all(res, base=(ctx or {}).get("base"))
        except Exception:
            pass
    return {"status": 200, "supply_chain": res, "body": f"{res.get('count', 0)} HIGH/CRITICAL deps"}


def static(move, ctx):
    p = move.get("path_in_kali") or move.get("target") or ""
    out = _kali(f"command -v semgrep >/dev/null 2>&1 && semgrep --config auto --json {shlex.quote(p)} 2>/dev/null | head -c 8000 || echo 'semgrep missing'", 300)
    return {"status": 200, "body": out[:4000]}


def fuzz(move, ctx):
    # NB: a `for x in ... $x ...` shell loop does NOT survive the Windows->WSL->bash arg
    # marshalling (the loop var comes back empty), so name each fuzzer explicitly.
    checks = "; ".join(
        f"(command -v {t} >/dev/null 2>&1 && echo {t}:present || echo {t}:MISSING)"
        for t in ("afl-fuzz", "honggfuzz", "radamsa")
    )
    out = _kali(checks)
    return {"status": 200, "body": out.strip() or "(no fuzzers)"}


def ossfuzz(move, ctx):
    """GREY-BOX leg -- THE FUZZER (operator/fuzzer.py): coverage-guided fuzzing of the mirror's OWN
    buildable source via the OSS-Fuzz tooling, contained in Kali/Docker. Distinct from the black-box
    `fuzz` leg above (which probes the running mirror over the wire). A move names a scaffolded+built
    `project` and `fuzzer`; this runs it for a bounded time and triages crashes into candidate findings
    (each verified only when it REPRODUCES). Offline-safe: reports readiness if nothing is built yet."""
    try:
        import fuzzer
    except Exception as e:
        return {"status": -1, "body": f"[fuzzer import error] {e}"}
    project = move.get("project") or move.get("target")
    fz = move.get("fuzzer") or move.get("mechanism")
    if not project or not fz:
        return {"status": 200, "body": f"grey-box fuzzer readiness: {fuzzer.check()}",
                "ossfuzz": {"note": "supply move['project'] + move['fuzzer'] (scaffold+build first)"}}
    seconds = int(move.get("seconds") or ctx.get("fuzz_seconds") or 120)
    engine = move.get("engine") or "libfuzzer"
    r = fuzzer.run(project, fz, seconds=seconds, engine=engine)
    if r.get("error"):
        return {"status": 200, "ossfuzz": r, "body": f"fuzz not run: {r['error']}"}
    # board interprets each unique crash by default (root cause / severity / exploitability / fix);
    # set move['interpret']=False to skip the board round and just reproduce.
    tri = fuzzer.triage(project, fz, board=bool(move.get("interpret", True)))
    crashes = tri.get("reproduced", 0)
    return {"status": 200 if crashes == 0 else 500, "ossfuzz": {**r, **tri},
            "findings": tri.get("findings", []),
            "body": f"{tri.get('crash_count',0)} crash(es), {crashes} reproduced on {project}:{fz}"}


def misconfig(move, ctx):
    p = move.get("path_in_kali") or move.get("target") or "/"
    out = _kali(f"find {shlex.quote(p)} -maxdepth 4 \\( -name .git -o -name .env -o -name '*.pem' -o -name 'config.y*ml' -o -name .kube -o -name .aws \\) 2>/dev/null | head -20", 120)
    return {"status": 200, "body": out or "(no exposed sensitive paths)"}


def rag(move, ctx):
    q = move.get("query") or move.get("payload") or ""
    out = _kali(f"python3 /opt/aegis-rag/rag_query.py --json --k 5 {shlex.quote(q)} 2>/dev/null | tail -1", 120)
    return {"status": 200, "body": out[:2000]}


def probe(move, ctx):
    """NOVEL-CODE leg -- run a coder-WRITTEN probe (the board->code-bench 'bridge/foothold' path)
    NON-DESTRUCTIVELY against the contained mirror and evaluate ITS OWN oracle, so the loop can prove
    or discard it. Reuses test_suggestions' guard + curl-replayer + prose-oracle so novel code runs
    through the SAME established, guarded pipeline the co-pilot already uses; like grype/ossfuzz, the
    leg carries its own ground-truth (`probe_verified`). Two shapes:
      * HTTP probe (curl/http in the code) -> replayed as an authenticated request to ctx['base'] (the
        contained twin), then the prose ORACLE (status/body/SELECT) is evaluated.
      * shell/python probe -> run in the CONTAINED Kali sandbox (bounded timeout), stdout captured;
        a SELECT oracle (if any) is checked, else pass on a clean, non-empty, non-error run.
    Master kill-switch: AEGIS_NOVEL_CODE=0 disables execution (stages the code instead)."""
    code = move.get("code") or ""
    oracle_txt = move.get("oracle") or move.get("expected_oracle") or ""
    if os.environ.get("AEGIS_NOVEL_CODE", "1") == "0":
        return {"status": 0, "blocked": "novel-code execution disabled (AEGIS_NOVEL_CODE=0)",
                "body": "[staged, not executed]", "probe": {"code": code[:400], "staged": True}}
    if not code.strip():
        return {"status": 200, "body": "[probe: no code written]", "probe": {"staged": True}}
    try:
        import test_suggestions as TS               # reuse the established guard/replayer/oracle
    except Exception as e:
        return {"status": -1, "body": f"[probe: test_suggestions unavailable] {e}"}
    ok, why = TS.guard(code)                          # NON-DESTRUCTIVE doctrine (plant/read, never erase)
    if not ok:
        return {"status": 0, "blocked": why, "body": why, "probe": {"code": code[:400]}}
    base = (ctx or {}).get("base") or TS.BASE
    req = None
    try:
        req = TS.parse_curl(code)
    except Exception:
        req = None
    if req:                                          # HTTP-shaped probe -> replay against the twin
        try:
            import requests
            sf = (ctx or {}).get("session_for_role")
            sess = sf(move.get("role", "owner")) if sf else requests.Session()
            try:
                sess.verify = False
            except Exception:
                pass
            url = base.rstrip("/") + (req["path"] if req["path"].startswith("/") else "/" + req["path"])
            kw = {"timeout": 20, "headers": req["headers"] or None, "verify": False}
            if req["data"]:
                import json as _j
                try:
                    kw["json"] = _j.loads(req["data"])
                except Exception:
                    kw["data"] = req["data"]
            resp = sess.request(req["method"], url, **kw)
        except Exception as e:
            return {"status": -1, "body": f"[probe run error] {e}", "probe": {"code": code[:400]}}
        verdict, notes = TS.check_oracle(oracle_txt, resp, sess)
        if verdict == "pass" and 200 <= resp.status_code < 300:
            # SPA catch-all guard (mirrors HttpOracle's distinguishing-2xx fix, commit 4b73445): if this
            # 2xx is indistinguishable from a random nonexistent path (same status + identical body
            # shell), the app served its SPA/history fallback and the probe proved NOTHING -> reject.
            try:
                import uuid as _uuid
                bpath = base.rstrip("/") + "/zz-nonexistent-" + _uuid.uuid4().hex[:10]
                bresp = sess.request("GET", bpath, timeout=15, verify=False)
                if bresp.status_code == resp.status_code and (bresp.text or "") == (resp.text or ""):
                    verdict = "fail"
                    notes = (notes or "") + " | spa_fallback (2xx == nonexistent-path baseline)"
            except Exception:
                pass
        return {"status": resp.status_code, "body": (resp.text or "")[:2000],
                "probe": {"kind": "http", "verdict": verdict, "notes": notes, "code": code[:400]},
                "probe_verified": verdict == "pass"}
    # non-HTTP probe: run in the contained sandbox, bounded, then check a SELECT oracle if present.
    seconds = int(move.get("seconds") or (ctx or {}).get("probe_seconds") or 45)
    runner = "python3 -c" if re.search(r"\b(import|def |print\()", code) else "bash -lc"
    out = _kali(f"timeout {seconds} {runner} {shlex.quote(code)} 2>&1 | head -c 4000", seconds + 15)
    sel = re.search(r"(SELECT\b.+?;)", oracle_txt, re.I | re.S)
    verified = False
    notes = f"exit-captured; stdout={out[:120]!r}"
    if sel:
        try:
            db_out = TS.db(sel.group(1))
            verified = bool(db_out) and not db_out.startswith("[db error")
            notes = f"db -> {db_out[:120]}"
        except Exception as e:
            notes = f"[db oracle error] {e}"
    else:
        verified = bool(out.strip()) and "[kali error" not in out and "error" not in out.lower()[:40]
    return {"status": 200 if verified else 500, "body": out[:2000],
            "probe": {"kind": "shell", "verdict": "pass" if verified else "fail",
                      "notes": notes, "code": code[:400]}, "probe_verified": verified}


# action -> leg. Web-shaped fact/authz/money moves route to `web`; the rest are distinct vectors.
# `probe`/`code` run a coder-written novel-code probe (the reach bridge/foothold path).
# ---------- STATEFUL multi-step probing (replay / idempotency / invariant) ----------
def _sf_get(obj, path):
    """Tiny extractor: $.field, $[0], $[0].field, $.a.b -- returns None on miss."""
    if not path or not isinstance(path, str) or not path.startswith("$"):
        return obj
    cur = obj
    for idx, key in re.findall(r"\[(\d+)\]|\.([A-Za-z_][A-Za-z0-9_]*)", path):
        try:
            if idx != "":
                cur = cur[int(idx)]
            elif isinstance(cur, dict):
                cur = cur.get(key)
            else:
                return None
        except Exception:
            return None
    return cur


def _sf_sub(val, vars):
    """Substitute {{var}} tokens from `vars`, recursively through dict/list/str."""
    if isinstance(val, str):
        return re.sub(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}",
                      lambda m: str(vars.get(m.group(1))) if vars.get(m.group(1)) is not None else m.group(0), val)
    if isinstance(val, dict):
        return {k: _sf_sub(v, vars) for k, v in val.items()}
    if isinstance(val, list):
        return [_sf_sub(v, vars) for v in val]
    return val


def _sf_measure(sess, base, spec, vars):
    """GET a collection, filter items by field==captured-var, reduce count|sum(field) -> a number."""
    if not spec:
        return 0.0
    path = _sf_sub(spec.get("path", "/"), vars)
    try:
        r = sess.get(base.rstrip("/") + path, timeout=25, verify=False)
        data = r.json()
    except Exception:
        return 0.0
    if isinstance(data, dict):
        for k in ("data", "items", "creditNotes", "invoices", "results", "rows"):
            if isinstance(data.get(k), list):
                data = data[k]; break
        else:
            data = [data]
    if not isinstance(data, list):
        return 0.0
    filt = spec.get("filter")
    if filt:
        want = vars.get(filt.get("eq_var"))
        data = [it for it in data if isinstance(it, dict) and str(it.get(filt.get("field"))) == str(want)]
    if spec.get("reduce") == "sum":
        f = spec.get("field", "total")
        return round(sum(float(it.get(f) or 0) for it in data if isinstance(it, dict)), 2)
    return float(len(data))


def stateful(move, ctx):
    """STATEFUL multi-step probe: run setup steps (with {{var}} capture), MEASURE a business-state metric,
    REPLAY the action step N times, measure again, apply a relational oracle (invariant|idempotency).
    Non-destructive (plant/write, never delete). Carries its own ground truth in result['stateful']."""
    import json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    sess = sfr(move.get("role", "owner")) if sfr else _rq.Session()
    try: sess.verify = False
    except Exception: pass
    vars, trace = {}, []
    def _clone_session(src):
        # requests.Session is NOT thread-safe -> give each racing thread its own, carrying the
        # same auth (cookies + headers) so the race is genuine, not serialized on one connection.
        c = _rq.Session()
        try:
            c.verify = False
            c.headers.update(getattr(src, "headers", {}) or {})
            c.cookies.update(getattr(src, "cookies", {}) or {})
        except Exception:
            pass
        return c
    def _run(step, sess_override=None):
        use = sess_override or sess
        m = (step.get("method") or "GET").upper()
        if m == "DELETE":
            trace.append({"step": "DELETE blocked (non-destructive)", "status": 0}); return None
        path = _sf_sub(step.get("path", "/"), vars)
        body = _sf_sub(step.get("body"), vars) if step.get("body") is not None else None
        try:
            r = use.request(m, base.rstrip("/") + path, json=body, timeout=25, verify=False)
        except Exception as e:
            trace.append({"step": m + " " + str(path), "status": -1, "err": str(e)[:80]}); return None
        trace.append({"step": m + " " + str(path), "status": r.status_code})
        try: j = r.json()
        except Exception: j = None
        # PICK a specific list item before capture (F3: avoid reusing an already-consumed record, e.g. an
        # already-invoiced job). pick={"where_empty":"invoices"} -> first item whose field is empty/missing.
        pick = step.get("pick")
        if pick and j is not None:
            items = j
            if isinstance(j, dict):
                for _k in ("data", "items", "jobs", "results", "rows"):
                    if isinstance(j.get(_k), list):
                        items = j[_k]; break
            if isinstance(items, list) and items:
                we = pick.get("where_empty")
                sel = next((it for it in items if isinstance(it, dict) and we is not None and not it.get(we)), None)
                j = sel if sel is not None else (items[0] if isinstance(items[0], dict) else j)
        for var, jp in (step.get("capture") or {}).items():
            vars[var] = _sf_get(j, jp)
        return r
    for step in (move.get("setup") or []):
        _run(step)
    # ---- SCAFFOLD-STATEFUL: resource leak/exhaustion persistence (docker cgroup RSS, control-compared) ----
    if move.get("oracle") == "resource_persistence":
        import subprocess as _sp, time as _t
        surface = move.get("surface") or (move.get("action_step") or {}).get("path") or ""
        container = move.get("container", "fixflow-mirror-api-1")
        metric_path = move.get("metric_path", "/sys/fs/cgroup/memory.current")
        def _rss():
            vals = []
            for _ in range(3):
                try:
                    out = _sp.run(["docker", "exec", container, "cat", metric_path],
                                  capture_output=True, text=True, timeout=15).stdout.strip()
                    vals.append(int(out))
                except Exception:
                    pass
                _t.sleep(0.3)
            return max(vals) if vals else 0
        warm = int(move.get("warmup", 2)); cool = float(move.get("cooldown", 3)); reps = int(move.get("repeat", 8))
        heavy = move.get("action_step") or {}
        control = move.get("control_step") or heavy
        # MECH3 SCAFFOLD synth (resource_persistence x concurrency = LEAK-UNDER-LOAD): fire the heavy
        # requests CONCURRENTLY so a leak that a paced sequential run lets the GC keep up with shows up
        # under real load. Non-destructive (same heavy request); own session clone per thread.
        conc = int(move.get("concurrency", 1))
        def _run_batch(step, n):
            if conc > 1:
                import concurrent.futures as _cf
                def _one(_i):
                    try: return _run(step, _clone_session(sess))
                    except Exception: return None
                try:
                    with _cf.ThreadPoolExecutor(max_workers=min(conc, 16)) as ex:
                        list(ex.map(_one, range(n)))
                    return
                except Exception:
                    pass
            for _ in range(n): _run(step)
        for _ in range(warm): _run(heavy)                 # warmup (discard: pandas/JIT lazy-init spike)
        b_heavy = _rss()
        _run_batch(heavy, reps)
        _t.sleep(cool)                                    # GC/cooldown window before measuring
        a_heavy = _rss(); heavy_delta = a_heavy - b_heavy
        for _ in range(warm): _run(control)
        b_ctrl = _rss()
        _run_batch(control, reps)                         # same concurrency as heavy -> fair control
        _t.sleep(cool)
        a_ctrl = _rss(); control_delta = a_ctrl - b_ctrl
        from verified_findings import ResourcePersistenceOracle
        floor = float(move.get("floor", 40 * 1024 * 1024))   # 40MB absolute floor
        verdict, receipt = ResourcePersistenceOracle(heavy_delta, control_delta, floor=floor,
                                                     factor=float(move.get("factor", 2.0)), surface=surface).check()
        sf = {"oracle": "resource_persistence", "surface": surface, "container": container,
              "before": b_heavy, "after": a_heavy, "heavy_delta": heavy_delta, "control_delta": control_delta,
              "repeats": reps, "bound": None, "verdict": verdict, "receipt": receipt, "trace": trace[-6:]}
        return {"status": 200, "body": _json.dumps(sf)[:2000], "stateful": sf,
                "stateful_verified": verdict == "verified"}
    # ---- SCAFFOLD-STATEFUL: auth/session state (token not invalidated on logout) ----
    if move.get("oracle") == "auth_state":
        probe = move.get("probe_step") or {"method": "GET", "path": "/api/settings/details"}
        logout = move.get("logout_step") or {"method": "POST", "path": "/api/auth/logout"}
        r_pre = _run(probe)          # session_for_role is already authed -> expect 2xx
        # MECH3 SCAFFOLD synth (auth_state x timing = session-invalidation RACE): fire concurrent probes
        # on CLONED (same-auth) sessions right as logout runs, to catch a token still honoured inside the
        # revocation window -- a race a single sequential post-logout probe misses. Non-destructive.
        conc = int(move.get("concurrency", 1))
        if conc > 1:
            import concurrent.futures as _cf
            clones = [_clone_session(sess) for _ in range(conc)]
            _run(logout)
            def _reprobe(cs):
                try:
                    return _run(probe, cs)
                except Exception:
                    return None
            try:
                with _cf.ThreadPoolExecutor(max_workers=min(conc, 16)) as ex:
                    posts = list(ex.map(_reprobe, clones))
            except Exception:
                posts = [_run(probe)]
            # the WORST case (any clone still authorized) is the finding -> take the min status seen
            codes = [p.status_code for p in posts if p is not None] or [-1]
            r_post = None
            post_s = min(codes)      # a 2xx among post-logout probes = revocation-window reuse
        else:
            _run(logout)                 # explicit logout / invalidation
            r_post = _run(probe)         # same session -> expect 401/403 if invalidated
            post_s = r_post.status_code if r_post is not None else -1
        from verified_findings import AuthStateOracle
        surface = move.get("surface") or logout.get("path") or ""
        pre_s = r_pre.status_code if r_pre is not None else -1
        verdict, receipt = AuthStateOracle(pre_s, post_s, surface=surface,
                                           label=move.get("metric", "session-invalidation")).check()
        sf = {"oracle": "auth_state", "surface": surface, "before": pre_s, "after": post_s, "bound": None,
              "repeats": 1, "verdict": verdict, "receipt": receipt, "trace": trace}
        return {"status": 200, "body": _json.dumps(sf)[:2000], "stateful": sf,
                "stateful_verified": verdict == "verified"}
    before = _sf_measure(sess, base, move.get("measure") or {}, vars)
    bound = None
    bspec = move.get("bound") or {}
    if "const" in bspec:
        bound = float(bspec["const"])
    elif "var" in bspec:
        try: bound = float(vars.get(bspec["var"]))
        except Exception: bound = None
    reps = int(move.get("repeat", 2))
    action = move.get("action_step") or {}
    # MECH 3 synth: a CONCURRENCY>1 move (TOCTOU-on-invariant / double-effect race) fires the
    # action_step in parallel so a check-then-act window can breach a bound that holds under the
    # sequential replay already tested. Non-destructive (same action_step); falls back to
    # sequential on any threading error. Each thread uses its OWN session clone (requests
    # Sessions are not thread-safe) seeded from the same auth so the race is real, not serialized.
    conc = int(move.get("concurrency", 1))
    if conc > 1:
        import concurrent.futures as _cf
        n = max(reps, conc)
        def _one(_i):
            try:
                cs = _clone_session(sess)
                return _run(action, cs)
            except Exception:
                return None
        try:
            with _cf.ThreadPoolExecutor(max_workers=min(n, 16)) as ex:
                list(ex.map(_one, range(n)))
        except Exception:
            for _ in range(reps):
                _run(action)
    else:
        for _ in range(reps):
            _run(action)
    after = _sf_measure(sess, base, move.get("measure") or {}, vars)
    from verified_findings import InvariantOracle, IdempotencyOracle
    surface = move.get("surface") or action.get("path") or ""
    otype = move.get("oracle", "idempotency")
    if otype == "invariant" and bound is not None:
        verdict, receipt = InvariantOracle(before, after, bound, surface=surface,
                                           label=move.get("invariant", "measured<=bound")).check()
    else:
        otype = "idempotency"
        verdict, receipt = IdempotencyOracle(before, after, reps, unit=float(move.get("unit", 1.0)),
                                             surface=surface, label=move.get("metric", "state-count")).check()
    sf = {"oracle": otype, "surface": surface, "before": before, "after": after, "bound": bound,
          "repeats": reps, "verdict": verdict, "receipt": receipt, "trace": trace,
          "vars_captured": list(vars.keys())}
    return {"status": 200, "body": _json.dumps(sf)[:2000], "stateful": sf,
            "stateful_verified": verdict == "verified"}


# ---------- MECH 2: DIFFERENTIAL / oracle-diversity discovery (see deltas a human never computes) ----------
def _fingerprint_response(r, elapsed_ms):
    import hashlib, json as _j
    body = r.text or ""
    field_order = ""
    try:
        d = _j.loads(body)
        if isinstance(d, dict):
            field_order = ",".join(list(d.keys()))
    except Exception:
        field_order = ""
    return {"status": r.status_code, "latency_ms": elapsed_ms, "body_len": len(body),
            "body_sha": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16],
            "field_order": field_order}


def differential(move, ctx):
    """MECH 2: run the SAME request as N VARIANTS (roles/sessions) + k baseline repeats for a NOISE FLOOR,
    fingerprint each (status/latency/size/body-hash/field-order), and flag deltas a human never computes.
    Non-destructive (blocks DELETE; GET/idempotent by default). Emits LEADs (result['differential']), which
    make_oracle records as CANDIDATES to chase -- not verified findings (promote on a 2nd-oracle confirm)."""
    import time as _t, statistics as _st, json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    method = (move.get("method") or "GET").upper()
    if method == "DELETE":
        return {"status": 0, "blocked": "destructive (DELETE) -- blocked", "body": ""}
    path = move.get("surface") or move.get("path") or "/"
    url = base.rstrip("/") + (path if str(path).startswith("/") else "/" + str(path))
    variants = move.get("variants") or ["owner", "technician"]
    k = int(move.get("noise_k", 5))
    def _session(v):
        if sfr:
            return sfr(v)
        s = _rq.Session(); s.verify = False; return s
    def _hit(sess):
        t0 = _t.time()
        try:
            r = sess.request(method, url, json=move.get("body"), timeout=25, verify=False)
        except Exception:
            return None
        return _fingerprint_response(r, (_t.time() - t0) * 1000.0)
    # NOISE FLOOR: k repeats of the FIRST variant -> median + MAD of latency (statistical, not single-shot)
    bs = _session(variants[0]); lat = []
    for _ in range(max(2, k)):
        fp = _hit(bs)
        if fp: lat.append(fp["latency_ms"])
    med = _st.median(lat) if lat else 0.0
    mad = (_st.median([abs(x - med) for x in lat]) or 1.0) if lat else 1.0
    # one stabilized observation per variant (median latency over a few hits)
    obs = {}
    for v in variants:
        s = _session(v); reps = [x for x in (_hit(s) for _ in range(3)) if x]
        if not reps:
            continue
        o = dict(reps[-1]); o["latency_ms"] = _st.median([x["latency_ms"] for x in reps])
        obs[v] = o
    from verified_findings import DifferentialOracle
    verdict, receipt = DifferentialOracle(obs, {"latency_med": med, "latency_mad": mad}, surface=path).check()
    df = {"surface": path, "verdict": verdict, "leads": receipt.get("leads", []),
          "n_leads": receipt.get("n_leads", 0),
          "noise": {"latency_med": round(med, 1), "latency_mad": round(mad, 1)},
          "variants": receipt.get("variants", {})}
    return {"status": 200, "body": _json.dumps(df)[:2000], "differential": df,
            "differential_leads": df["n_leads"]}


def idor(move, ctx):
    """IDOR / BOLA sweep (object-level authz, commercial-parity). ENUMERATE object ids from a collection as
    the OWNER role, then try each object as ATTACKER role(s); an IdorOracle confirms object-level over-reach
    on distinguishing signals (attacker reads the SAME object bytes the owner sees + a nonexistent-id control
    is denied). READS ONLY by default (GET) -> non-destructive; a write/BOLA verb is opt-in and plant-for-
    proof (never erase). Carries its own ground truth in result['idor']."""
    import hashlib, json as _json, uuid as _uuid
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    def _sess(role):
        return sfr(role) if sfr else (lambda s: (setattr(s, "verify", False) or s))(_rq.Session())
    coll = move.get("collection") or move.get("surface") or "/"
    item_tpl = move.get("item") or (str(coll).rstrip("/") + "/{id}")
    id_field = move.get("id_field", "id")
    owner_role = move.get("owner_role") or move.get("role") or "owner"
    attackers = move.get("attacker_roles") or ["technician", "warehouse", "anon"]
    verb = (move.get("verb") or "GET").upper()
    if verb != "GET":                                    # non-destructive default: only reads sweep here
        return {"status": 0, "blocked": "idor write/BOLA verb requires explicit non-destructive plant path",
                "body": ""}
    sample = int(move.get("sample", 5))
    intended = {str(r).lower() for r in (move.get("intended_roles") or [])}

    def _sha(r):
        try:
            return hashlib.sha256((r.text or "").encode("utf-8", "replace")).hexdigest()[:16]
        except Exception:
            return ""
    owner = _sess(owner_role)
    try:
        lr = owner.request("GET", base.rstrip("/") + coll, timeout=25, verify=False)
        data = lr.json()
    except Exception as e:
        return {"status": -1, "body": f"[idor] enumerate failed: {e}", "idor": {"verdict": "rejected",
                "surface": coll, "note": "could not enumerate collection"}, "idor_verified": False}
    items = data
    if isinstance(data, dict):
        for k in ("data", "items", "results", "rows", "invoices", "jobs", "customers"):
            if isinstance(data.get(k), list):
                items = data[k]; break
    ids = [it.get(id_field) for it in items if isinstance(it, dict) and it.get(id_field) is not None][:sample] \
        if isinstance(items, list) else []
    if not ids:
        return {"status": 200, "body": "[idor] no object ids enumerated", "idor_verified": False,
                "idor": {"verdict": "rejected", "surface": coll, "note": "no ids to sweep"}}
    obs = []
    ctrl_id = "zzz-nonexistent-" + _uuid.uuid4().hex[:10]
    for role in attackers:
        if role.lower() in intended:
            continue
        atk = _sess(role)
        try:
            ctrl = atk.request("GET", base.rstrip("/") + item_tpl.format(id=ctrl_id), timeout=20, verify=False)
            ctrl_status = ctrl.status_code
        except Exception:
            ctrl_status = -1
        for _id in ids:
            url = base.rstrip("/") + item_tpl.format(id=_id)
            try:
                ov = owner.request("GET", url, timeout=20, verify=False)
                av = atk.request("GET", url, timeout=20, verify=False)
            except Exception:
                continue
            obs.append({"id": _id, "role": role, "owner_status": ov.status_code,
                        "attacker_status": av.status_code, "owner_sha": _sha(ov), "attacker_sha": _sha(av),
                        "control_status": ctrl_status, "verb": "GET"})
    from verified_findings import IdorOracle
    verdict, receipt = IdorOracle(obs, surface=coll).check()
    idr = {"verdict": verdict, "surface": coll, "owner_role": owner_role, "attackers": attackers,
           "ids_swept": len(ids), **receipt}
    return {"status": 200, "body": _json.dumps(idr)[:2000], "idor": idr, "idor_verified": verdict == "verified"}


def rate(move, ctx):
    """RATE-LIMIT / anti-automation probe on a SENSITIVE endpoint (login/reset/OTP). Fires a BOUNDED burst
    of identical requests using a NONEXISTENT identity (so no real account is locked -- non-destructive) and
    a RateLimitOracle confirms the weakness iff no throttle (429/423/503) appears. N is hard-capped so the
    burst can never be a DoS. Carries ground truth in result['rate']."""
    import json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    path = move.get("surface") or move.get("path") or "/api/auth/login"
    method = (move.get("method") or "POST").upper()
    if method in ("DELETE", "PUT"):                      # never a destructive verb for a rate probe
        return {"status": 0, "blocked": "rate probe restricted to GET/POST", "body": ""}
    n = min(int(move.get("n", 15)), int(os.environ.get("AEGIS_RATE_MAX", "25")))   # hard DoS cap
    # a NONEXISTENT identity so repeated failures can't lock a real account (non-destructive)
    body = move.get("body") or {"name": "zzz-nonexistent-" + __import__("uuid").uuid4().hex[:8],
                                "pin": "000000", "username": "zzz-nobody", "password": "x"}
    s = _rq.Session(); s.verify = False
    statuses = []
    url = base.rstrip("/") + (path if str(path).startswith("/") else "/" + str(path))
    for _ in range(n):
        try:
            r = s.request(method, url, json=(body if method == "POST" else None), timeout=15, verify=False)
            statuses.append(r.status_code)
        except Exception:
            statuses.append(-1)
    from verified_findings import RateLimitOracle
    verdict, receipt = RateLimitOracle(statuses, endpoint=path,
                                       min_attempts=int(move.get("min_attempts", 10))).check()
    rt = {"verdict": verdict, "surface": path, **receipt}
    return {"status": 200, "body": _json.dumps(rt)[:2000], "rate": rt, "rate_verified": verdict == "verified"}


def file_upload(move, ctx):
    """UNRESTRICTED FILE UPLOAD probe: multipart-upload a benign ACTIVE-CONTENT marker (an .svg carrying a
    script marker) to an upload endpoint, then retrieve it and check whether it is served with a RENDERABLE
    content-type (a FileUploadOracle confirms). Plants ONE small marker file -> non-destructive (never
    erases). Spec via move['upload']={path,field,filename,content,content_type}; else uses move.surface with
    field 'file'. Ground truth in result['upload']."""
    import json as _json, uuid as _uuid, re as _re
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    sess = sfr(move.get("role", "owner")) if sfr else _rq.Session()
    try: sess.verify = False
    except Exception: pass
    spec = move.get("upload") or {}
    path = spec.get("path") or move.get("surface") or move.get("path")
    if not path:
        return {"status": 0, "body": "[file_upload] no upload path", "upload_verified": False,
                "upload": {"verdict": "rejected", "note": "no upload endpoint"}}
    field = spec.get("field", "file")
    tok = "UP" + _uuid.uuid4().hex[:8]
    fn = spec.get("filename") or f"aegis-{tok}.svg"
    content = spec.get("content") or (
        f'<svg xmlns="http://www.w3.org/2000/svg" onload="window.__aegis_xss=\'{tok}\'"><text>{tok}</text></svg>')
    ctype = spec.get("content_type", "image/svg+xml")
    url = base.rstrip("/") + (path if str(path).startswith("/") else "/" + str(path))
    try:
        r = sess.post(url, files={field: (fn, content, ctype)}, timeout=25, verify=False)
    except Exception as e:
        return {"status": -1, "body": f"[file_upload] {e}", "upload_verified": False,
                "upload": {"verdict": "rejected", "note": "upload request error"}}
    # find the stored file URL/path in the response
    stored = None
    try:
        j = r.json()
        blob = _json.dumps(j)
        m = _re.search(r'"(?:url|path|location|src|file|href)"\s*:\s*"([^"]+)"', blob)
        if m:
            stored = m.group(1)
        elif isinstance(j, dict) and j.get("id"):
            stored = path.rstrip("/") + "/" + str(j["id"])
    except Exception:
        stored = None
    rs, rctype = 0, ""
    if stored:
        su = stored if stored.startswith("http") else base.rstrip("/") + (stored if stored.startswith("/") else "/" + stored)
        try:
            rr = sess.get(su, timeout=20, verify=False); rs = rr.status_code; rctype = rr.headers.get("content-type", "")
        except Exception:
            pass
    from verified_findings import FileUploadOracle
    verdict, receipt = FileUploadOracle(r.status_code, rs, rctype, fn, surface=path).check()
    up = {"verdict": verdict, "stored": stored, **receipt}
    return {"status": 200, "body": _json.dumps(up)[:2000], "upload": up, "upload_verified": verdict == "verified"}


def xss(move, ctx):
    """DOM / reflected XSS via a HEADLESS browser (commercial-parity; the biggest 'not Burp-grade' gap).
    Injects marker payloads that set window.__aegis_xss=<token> IF they execute, loads the page in headless
    chromium (authenticated if session_for_role), and an XssOracle confirms on EXECUTION (not reflection).
    Reflected (query param) + DOM (hash fragment). GET navigation only -> non-destructive. Offline-safe: if
    Playwright/chromium is unavailable the leg skips gracefully."""
    import json as _json, uuid as _uuid
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"status": -1, "body": f"[xss] playwright unavailable: {e}", "xss_verified": False,
                "xss": {"verdict": "rejected", "note": "headless browser (playwright) unavailable"}}
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    surface = move.get("surface") or move.get("path") or "/"
    url0 = base.rstrip("/") + (surface if str(surface).startswith("/") else "/" + str(surface))
    params = move.get("params") or ["q", "search", "s", "query", "name", "message", "comment", "title",
                                    "redirect", "return", "ref", "id", "filter", "term"]
    tok = "TOK" + _uuid.uuid4().hex[:8]
    G = "window.__aegis_xss='" + tok + "'"
    payloads = [f"<script>{G}</script>", f"\"><script>{G}</script>",
                f"<img src=x onerror=\"{G}\">", f"\"><img src=x onerror={G}>",
                f"<svg onload=\"{G}\">", f"';{G};//"]
    # auth cookies from the role session -> the headless context (so authed pages render)
    cookies = []
    try:
        if sfr:
            host = re.sub(r"^https?://", "", base).split("/")[0].split(":")[0]
            for c in sfr(move.get("role", "owner")).cookies:
                cookies.append({"name": c.name, "value": c.value, "domain": host, "path": "/"})
    except Exception:
        cookies = []
    hit = None
    try:
        with sync_playwright() as p:
            br = p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
            cx = br.new_context(ignore_https_errors=True)
            if cookies:
                try: cx.add_cookies(cookies)
                except Exception: pass
            pg = cx.new_page()
            pg.on("dialog", lambda d: d.dismiss())        # never block on alert()
            targets = []
            for pv in payloads:
                for pr in params:
                    targets.append(("reflected", pr, url0 + ("&" if "?" in url0 else "?") + pr + "=" + pv))
                targets.append(("dom-hash", "#", url0 + "#" + pv))
            for ctxt, pr, u in targets:
                try:
                    pg.goto(u, wait_until="domcontentloaded", timeout=15000)
                    val = pg.evaluate("window.__aegis_xss || null")
                except Exception:
                    val = None
                if val == tok:
                    hit = {"context": ctxt, "param": pr, "url": u[:200]}; break
                try: pg.evaluate("window.__aegis_xss=null")     # reset between probes
                except Exception: pass
            br.close()
    except Exception as e:
        return {"status": -1, "body": f"[xss] browser error: {e}", "xss_verified": False,
                "xss": {"verdict": "rejected", "note": "browser run error"}}
    from verified_findings import XssOracle
    if hit:
        v, rc = XssOracle(tok, tok, surface=surface, param=hit["param"], context=hit["context"]).check()
        xr = {"verdict": v, **rc, "url": hit["url"]}
        return {"status": 200, "body": _json.dumps(xr)[:2000], "xss": xr, "xss_verified": True}
    return {"status": 200, "body": "[xss] no execution across %d params" % len(params),
            "xss": {"verdict": "rejected", "surface": surface, "params_tried": len(params)}, "xss_verified": False}


def ssrf(move, ctx):
    """SSRF probe via an in-sandbox CANARY: inject `http://<canary>/c/<token>` into SSRF-prone params and,
    if the token is called back, the target made an outbound request we controlled -> confirmed. GET query
    injection by default (non-destructive); POST body only if move.method=POST. Ground truth = the callback
    (SsrfOracle). Contained OOB (owned canary, not off-box egress)."""
    import json as _json, time as _t
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    try:
        import canary
        canary.start()
    except Exception as e:
        return {"status": -1, "body": f"[ssrf] canary unavailable: {e}", "ssrf_verified": False,
                "ssrf": {"verdict": "rejected", "note": "canary listener unavailable"}}
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    sess = sfr(move.get("role", "owner")) if sfr else _rq.Session()
    try: sess.verify = False
    except Exception: pass
    surface = move.get("surface") or move.get("path") or "/"
    url = base.rstrip("/") + (surface if str(surface).startswith("/") else "/" + str(surface))
    params = move.get("params") or ["url", "uri", "redirect_uri", "callback", "webhook", "target", "dest",
                                    "destination", "image", "imageUrl", "image_url", "fetch", "feed", "proxy",
                                    "src", "link", "endpoint", "avatar", "document", "load", "u", "next", "host"]
    do_post = (move.get("method", "GET").upper() == "POST")
    tokmap = {}
    for p in params:
        tok = canary.token(); tokmap[tok] = p; cu = canary.url_for(tok)
        try:
            sess.get(url, params={p: cu}, timeout=12, verify=False, allow_redirects=False)
            if do_post:
                sess.post(url, json={p: cu}, timeout=12, verify=False, allow_redirects=False)
        except Exception:
            pass
    _t.sleep(float(move.get("wait", 4)))                  # allow async server-side fetch to call back
    from verified_findings import SsrfOracle
    for tok, p in tokmap.items():
        h = canary.hits(tok)
        if h:
            v, rc = SsrfOracle(h, surface=surface, param=p).check()
            sr = {"verdict": v, **rc}
            return {"status": 200, "body": _json.dumps(sr)[:2000], "ssrf": sr, "ssrf_verified": True}
    return {"status": 200, "body": "[ssrf] no OOB callback via %d params" % len(params),
            "ssrf": {"verdict": "rejected", "surface": surface, "params_tried": len(params),
                     "canary": canary.base_url()}, "ssrf_verified": False}


def csrf(move, ctx):
    """CSRF POSTURE probe (non-destructive -- no forged state change): log in to capture the session cookie
    + a page body, and a CsrfOracle flags exposure only when there is NO SameSite protection AND no anti-CSRF
    token mechanism. Ground truth in result['csrf']."""
    import json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    s = _rq.Session(); s.verify = False
    set_cookies, body, hdrs = [], "", {}
    try:
        url = os.environ.get("AEGIS_LOGIN_URL") or (base.rstrip("/") + "/api/auth/login")
        pin = os.environ.get("AEGIS_LOGIN_PIN") or os.environ.get("AEGIS_TEST_PIN") or "000000"
        idf = os.environ.get("AEGIS_LOGIN_ID_FIELD", "name"); pf = os.environ.get("AEGIS_LOGIN_PIN_FIELD", "pin")
        try:
            rmap = _json.loads(os.environ.get("AEGIS_ROLE_MAP", "{}")); ident = rmap.get("owner") or next(iter(rmap.values()), None)
        except Exception:
            ident = None
        def _grab(resp):
            if resp is None:
                return []
            if hasattr(resp, "raw") and hasattr(resp.raw, "headers"):
                cc = [v for k, v in resp.raw.headers.items() if k.lower() == "set-cookie"]
                if cc:
                    return cc
            return [resp.headers.get("set-cookie")] if resp.headers.get("set-cookie") else []
        if ident:
            lr = s.post(url, json={idf: ident, pf: pin}, timeout=20, verify=False)
            set_cookies = _grab(lr)
        gr = s.get(base.rstrip("/") + "/", timeout=20, verify=False)
        body = (gr.text or "")[:8000]; hdrs = dict(gr.headers)
        if not set_cookies:
            set_cookies = _grab(gr)
    except Exception:
        pass
    from verified_findings import CsrfOracle
    verdict, receipt = CsrfOracle(set_cookies, body, hdrs, surface=move.get("surface", "/")).check()
    cs = {"verdict": verdict, **receipt}
    return {"status": 200, "body": _json.dumps(cs)[:2000], "csrf": cs, "csrf_verified": verdict == "verified"}


def security_headers(move, ctx):
    """Cookie flags + security response headers (commercial-parity passive). Does a real login to capture a
    Set-Cookie (session-cookie flags) + a GET for response security headers, and a SecurityHeadersOracle
    flags missing HttpOnly/Secure/SameSite or absent CSP/HSTS/X-Content-Type-Options/X-Frame-Options.
    Reads only -- non-destructive. Ground truth in result['secheaders']."""
    import json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    over_https = str(base).lower().startswith("https")
    surface = move.get("surface") or "/"
    s = _rq.Session(); s.verify = False
    set_cookies, headers = [], {}
    # a real login to capture Set-Cookie (session-cookie flags)
    try:
        url = os.environ.get("AEGIS_LOGIN_URL") or (base.rstrip("/") + "/api/auth/login")
        pin = os.environ.get("AEGIS_LOGIN_PIN") or os.environ.get("AEGIS_TEST_PIN") or "000000"
        idf = os.environ.get("AEGIS_LOGIN_ID_FIELD", "name"); pf = os.environ.get("AEGIS_LOGIN_PIN_FIELD", "pin")
        ident = None
        try:
            rmap = _json.loads(os.environ.get("AEGIS_ROLE_MAP", "{}")); ident = (rmap.get("owner") or next(iter(rmap.values()), None))
        except Exception:
            ident = None
        lr = s.post(url, json={idf: ident, pf: pin}, timeout=20, verify=False) if ident else None
        if lr is not None:
            set_cookies = [v for k, v in lr.raw.headers.items() if k.lower() == "set-cookie"] \
                if hasattr(lr, "raw") and hasattr(lr.raw, "headers") else \
                ([lr.headers.get("set-cookie")] if lr.headers.get("set-cookie") else [])
    except Exception:
        pass
    try:
        gr = s.get(base.rstrip("/") + (surface if str(surface).startswith("/") else "/"), timeout=20, verify=False)
        headers = dict(gr.headers)
        if not set_cookies and gr.headers.get("set-cookie"):
            set_cookies = [gr.headers.get("set-cookie")]
    except Exception:
        pass
    from verified_findings import SecurityHeadersOracle
    verdict, receipt = SecurityHeadersOracle(headers, set_cookies, over_https=over_https, surface=surface).check()
    sh = {"verdict": verdict, **receipt}
    return {"status": 200, "body": _json.dumps(sh)[:2000], "secheaders": sh, "secheaders_verified": verdict == "verified"}


def session_fixation(move, ctx):
    """SESSION FIXATION probe: capture a pre-auth session id, log in within the SAME jar, and check the id
    did NOT rotate yet the session is now authenticated. Reads only (a normal login) -> non-destructive.
    Ground truth in result['sessfix']."""
    import json as _json
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    cookie_name = move.get("cookie") or os.environ.get("AEGIS_SESSION_COOKIE", "connect.sid")
    probe = move.get("probe_step") or {"method": "GET", "path": "/api/settings/details"}
    s = _rq.Session(); s.verify = False
    try:
        s.get(base.rstrip("/") + "/", timeout=20, verify=False)          # obtain a pre-auth session
        pre = s.cookies.get(cookie_name)
        url = os.environ.get("AEGIS_LOGIN_URL") or (base.rstrip("/") + "/api/auth/login")
        pin = os.environ.get("AEGIS_LOGIN_PIN") or os.environ.get("AEGIS_TEST_PIN") or "000000"
        idf = os.environ.get("AEGIS_LOGIN_ID_FIELD", "name"); pf = os.environ.get("AEGIS_LOGIN_PIN_FIELD", "pin")
        try:
            rmap = _json.loads(os.environ.get("AEGIS_ROLE_MAP", "{}")); ident = rmap.get("owner") or next(iter(rmap.values()), None)
        except Exception:
            ident = None
        if not ident:
            return {"status": 200, "body": "[sessfix] no login identity", "sessfix_verified": False,
                    "sessfix": {"verdict": "rejected", "note": "no login identity configured"}}
        s.post(url, json={idf: ident, pf: pin}, timeout=20, verify=False)
        post = s.cookies.get(cookie_name)
        pr = s.request(probe.get("method", "GET"), base.rstrip("/") + probe.get("path", "/"), timeout=20, verify=False)
        authed = 200 <= pr.status_code < 300
    except Exception as e:
        return {"status": -1, "body": f"[sessfix] {e}", "sessfix_verified": False,
                "sessfix": {"verdict": "rejected", "note": "probe error"}}
    from verified_findings import SessionFixationOracle
    verdict, receipt = SessionFixationOracle(pre, post, authed, surface="/api/auth/login", cookie=cookie_name).check()
    sfx = {"verdict": verdict, **receipt}
    return {"status": 200, "body": _json.dumps(sfx)[:2000], "sessfix": sfx, "sessfix_verified": verdict == "verified"}


def open_redirect(move, ctx):
    """OPEN REDIRECT probe: inject an external CANARY host into common redirect params and check whether the
    app redirects there (3xx Location or meta/JS body redirect). Reads only (GET, redirects NOT followed) ->
    non-destructive. Ground truth in result['openredir']."""
    import json as _json, re as _re
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    s = (sfr(move.get("role", "owner")) if sfr else _rq.Session());
    try: s.verify = False
    except Exception: pass
    target_host = _re.sub(r"^https?://", "", base).split("/")[0].split(":")[0]
    canary = move.get("canary") or "canary.aegis-oob.example"          # external, non-target host
    params = move.get("params") or ["url", "redirect", "redirect_uri", "next", "return", "returnUrl",
                                    "return_to", "dest", "destination", "continue", "callback", "r", "u"]
    surface = move.get("surface") or move.get("path") or "/"
    payloads = ["https://" + canary + "/x", "//" + canary + "/x"]      # absolute + scheme-relative
    for p in params:
        for pv in payloads:
            url = base.rstrip("/") + (surface if str(surface).startswith("/") else "/" + str(surface))
            try:
                r = s.get(url, params={p: pv}, timeout=15, verify=False, allow_redirects=False)
            except Exception:
                continue
            from verified_findings import OpenRedirectOracle
            v, rc = OpenRedirectOracle(r.status_code, r.headers.get("location"), (r.text or "")[:4000],
                                       canary, target_host=target_host, surface=surface, param=p).check()
            if v == "verified":
                orr = {"verdict": "verified", "param": p, "payload": pv, **rc}
                return {"status": 200, "body": _json.dumps(orr)[:2000], "openredir": orr, "openredir_verified": True}
    return {"status": 200, "body": "[open_redirect] no external redirect via " + str(len(params)) + " params",
            "openredir": {"verdict": "rejected", "surface": surface, "params_tried": len(params)},
            "openredir_verified": False}


def mass_assign(move, ctx):
    """MASS ASSIGNMENT probe: create an object WITH injected privileged fields (marker values) + a CONTROL
    create without them, and a MassAssignOracle confirms a privileged client-supplied field was accepted +
    persisted. PLANT-for-proof (creates records, never erases) -> non-destructive. Ground truth in
    result['massassign']."""
    import json as _json, uuid as _uuid
    import requests as _rq
    try: _rq.packages.urllib3.disable_warnings()
    except Exception: pass
    base = (ctx or {}).get("base") or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    sfr = (ctx or {}).get("session_for_role")
    sess = sfr(move.get("role", "owner")) if sfr else (lambda s: (setattr(s, "verify", False) or s))(_rq.Session())
    create = move.get("create") or {}
    path = create.get("path") or move.get("surface")
    if not path:
        return {"status": 0, "body": "[mass_assign] no create path", "massassign_verified": False,
                "massassign": {"verdict": "rejected", "note": "no create spec"}}
    method = (create.get("method") or "POST").upper()
    if method not in ("POST", "PUT", "PATCH"):
        return {"status": 0, "blocked": "mass_assign needs a create/update verb", "body": ""}
    body = dict(create.get("body") or {})
    marker = "aegis-" + _uuid.uuid4().hex[:8]
    inject = dict(move.get("inject") or {"role": "OWNER", "isAdmin": True, "approved": True,
                                         "status": "CLEARED", "balance": 999999, "id": marker})
    # resolve a reference id if the create needs one (e.g. customerId from /api/customers)
    ref = move.get("ref")
    if ref and ref.get("list"):
        try:
            rl = sess.request("GET", base.rstrip("/") + ref["list"], timeout=20, verify=False).json()
            items = rl if isinstance(rl, list) else next((rl[k] for k in ("data", "items", "customers",
                    "jobs", "results") if isinstance(rl.get(k), list)), [])
            if items:
                body[ref.get("as", "id")] = items[0].get(ref.get("id_field", "id"))
        except Exception:
            pass
    url = base.rstrip("/") + path

    def _create(extra):
        try:
            r = sess.request(method, url, json={**body, **extra}, timeout=25, verify=False)
            try: j = r.json()
            except Exception: j = {}
            if isinstance(j, dict):
                for k in ("data", "item", "result", "payment", "invoice", "record"):
                    if isinstance(j.get(k), dict):
                        j = j[k]; break
            return r.status_code, (j if isinstance(j, dict) else {})
        except Exception:
            return -1, {}
    cs, control_obj = _create({})
    ins, created_obj = _create(inject)
    from verified_findings import MassAssignOracle
    verdict, receipt = MassAssignOracle(created_obj, inject, control_obj=control_obj, surface=path).check()
    ma = {"verdict": verdict, "surface": path, "create_status": ins, "control_status": cs, **receipt}
    return {"status": 200, "body": _json.dumps(ma)[:2000], "massassign": ma, "massassign_verified": verdict == "verified"}


LEGS = {"web": web, "fact": web, "authz": web, "money": web, "stateful": stateful, "differential": differential,
        "idor": idor, "rate": rate, "security_headers": security_headers, "session_fixation": session_fixation,
        "open_redirect": open_redirect, "mass_assign": mass_assign, "csrf": csrf, "ssrf": ssrf, "xss": xss, "file_upload": file_upload,
        "recon": recon, "supply_chain": supply_chain, "static": static,
        "fuzz": fuzz, "ossfuzz": ossfuzz, "misconfig": misconfig, "rag": rag,
        "probe": probe, "code": probe}

# DISCOVERY-PARITY legs (AD/LDAP, cloud, fingerprint, external-surface, cred-harvest, sbom) + the NOVEL
# beyond-tooling techniques (rag_infer, authz_fuzz, depconf, honeypot, attackpath). Offline-safe: if the
# module can't import, the core vectors above still work unchanged.
try:
    import discovery as _discovery
    LEGS.update(_discovery.LEGS)
except Exception:
    _discovery = None


def vector_names():
    return sorted(set(LEGS) - {"fact", "authz", "money", "web"} | {"web"})


def dispatch(move, phase, ctx):
    """Run the vector for move['action'] (default web). Returns the leg result + the move."""
    leg = LEGS.get(move.get("action", "web"), web)
    try:
        res = leg(move, ctx)
    except Exception as e:
        res = {"status": -1, "body": f"[error] {e}"}
    res["move"] = move
    # PASSIVE SECRETS/PII SCAN (commercial-parity): scan EVERY response body for high-confidence secret/
    # stack-trace leakage -- like a commercial scanner's passive pass over all traffic. Only a verified
    # (high-confidence) hit is attached, to stay quiet; the oracle records it as a SIDE finding without
    # changing the move's own verdict. Cheap regex; offline-safe; gate AEGIS_SECRETS_SCAN=0.
    if str(os.environ.get("AEGIS_SECRETS_SCAN", "1")).lower() not in ("0", "false", "no", "off"):
        try:
            body = res.get("body")
            if isinstance(body, str) and body:
                from verified_findings import SecretsOracle
                v, rc = SecretsOracle(body, surface=(move.get("surface") or move.get("path") or ""),
                                      status=res.get("status")).check()
                if v == "verified":
                    res["secrets_scan"] = rc
        except Exception:
            pass
    # attach a normalized probe view (garak-pattern uniform schema) under a SEPARATE key so every leg's
    # result reads the same way downstream. It must NOT overwrite result['probe'], which the probe leg
    # sets with the genuine code-probe payload (verdict/notes/code) + probe_verified -- clobbering it
    # both empties genuine-probe evidence AND makes the schema view shadow the HTTP/DB/authz oracles
    # (every non-probe move would look like an unproven probe). Offline-safe -> skipped if unimportable.
    try:
        import probe_schema
        res["probe_schema"] = probe_schema.normalize({**move, **res}).as_dict()
    except Exception:
        pass
    return res
