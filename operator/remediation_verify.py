#!/usr/bin/env python3
"""
remediation_verify.py -- the STAGE-10 CLOSED LOOP: patch the mirror, then re-test on the patched system.

After the code writer/improver's fix is ported to the mirror (remediation_port.py), this:
  1. SNAPSHOT the mirror (mirror_snapshot.py) so everything is repeatable + non-destructive.
  2. APPLY the fix on the mirror -- BOTH tracks:
       * CODE  : extract the unified diff from each ported patch and `git apply` it in the mirror repo.
       * ADMIN : the system/framework update (dependency version bump) via the mirror OS's package manager
                 (npm/pip/apt/zypper/dnf/composer), derived from the finding's component + fixed_version.
  3. RE-RUN the finding's exploit/oracle on the now-patched system+code (test_suggestions.py re-runs the
     original TARGET/CODE/ORACLE against the mirror; a custom repro command is also supported).
  4. CLASSIFY: exploit still fires -> STILL-OPEN; exploit no longer fires (oracle now fails) -> CLOSED.
  5. RESTORE the snapshot so the mirror is clean for the next iteration.

A framework update usually has to be DOWNLOADED to the mirror -- opt in with --allow-download (an authorized
mirror-side egress exception; off by default). Such an update can BREAK the app code: --health-cmd checks the
patched app still runs, and --repair hands the breakage to the code writer/improver to rewrite the code until
it runs again (bounded by --repair-max) before the re-test. Verdicts: CLOSED | STILL-OPEN | BROKE-AFTER-UPDATE
| NO-REPRO.

DOCTRINE: MIRROR-side only. Every apply + re-run happens on the mirror twin; the real target is NEVER
patched or re-tested. Snapshot/restore keeps it repeatable. Owner's own contained mirror, authorized.

Re-check source per finding, from a --repro-map JSON (or finding.remediation.repro if present):
    {"<finding_id>": {"type":"suggestion","file":"suggestions/ds.md","role":"owner"}}
    {"<finding_id>": {"type":"command","cmd":"curl -sk https://localhost:8443/...","expect_closed_regex":"400"}}
A finding with no repro is reported NO-REPRO (re-test it by hand).

Usage:
    python remediation_verify.py --transport wsl --mirror-repo /opt/aegis-mirror --repro-map repro.json
    python remediation_verify.py --transport docker --container aegis-mirror --mirror-repo /srv/app --repro-map repro.json
    python remediation_verify.py ... --write-ledger        # chain the verdict onto the findings ledger
    python remediation_verify.py ... --dry-run             # print the plan; change nothing
"""
import os, sys, re, json, glob, argparse, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "shared"))
MIRROR_DISTRO = os.environ.get("AEGIS_MIRROR_DISTRO") or os.environ.get("AEGIS_KALI_DISTRO") or "kali-linux"
DEFAULT_FIXES_DIR = os.path.join(HERE, "remediation_fixes")


# ---------- patch + bump derivation ----------
def extract_diff(patch_md_text):
    """Pull a unified diff out of a code-writer FILE/PATCH/NOTE markdown. Prefer a fenced ```diff block;
    else the text after 'PATCH:' up to NOTE:; return '' if nothing diff-shaped is found."""
    m = re.search(r"```(?:diff|patch)?\s*\n(.*?)```", patch_md_text, re.DOTALL)
    if m and ("---" in m.group(1) or "@@" in m.group(1) or m.group(1).lstrip().startswith(("+", "-"))):
        return m.group(1).strip()
    m = re.search(r"PATCH:\s*(.*?)(?:\nNOTE:|\Z)", patch_md_text, re.DOTALL)
    if m:
        body = m.group(1).strip()
        body = re.sub(r"^```(?:diff|patch)?\s*|\s*```$", "", body).strip()
        if "---" in body or "@@" in body or body.startswith(("+", "-", "diff ")):
            return body
    return ""


_ECOSYSTEM_CMD = {
    "npm": "npm install {name}@{fixed}",
    "pip": "pip install '{name}=={fixed}'",
    "composer": "composer require {name}:{fixed}",
    "gem": "gem install {name} -v {fixed}",
    "apt": "apt-get install -y --only-upgrade {name}",
    "zypper": "zypper install -y '{name}>={fixed}'",
    "dnf": "dnf install -y {name}-{fixed}",
}


def admin_bump_cmd(component, installed, fixed, ecosystem=None):
    """Derive the system/framework update command from the remediation's component + fixed version, for the
    mirror OS's package manager. ecosystem forces the manager; else guessed from the component string."""
    name = (component or "").split()[0].strip() or component or ""
    if not name or not fixed:
        return None, "no component/fixed_version -> ADMIN step is manual"
    eco = ecosystem
    if not eco:
        c = (component or "").lower()
        eco = ("npm" if any(k in c for k in ("node", "express", "npm", "js")) else
               "pip" if any(k in c for k in ("python", "pip", "django", "flask")) else
               "composer" if any(k in c for k in ("php", "composer", "symfony", "laravel")) else
               "gem" if any(k in c for k in ("ruby", "rails", "gem")) else None)
    if not eco:
        return None, f"ecosystem unknown for '{component}' -> pass --ecosystem (npm/pip/apt/...)"
    return _ECOSYSTEM_CMD[eco].format(name=name, fixed=fixed), eco


# ---------- mirror execution (transport) ----------
def mirror_exec(transport, cmd, *, distro=MIRROR_DISTRO, container=None, cwd=None, stdin=None, timeout=300):
    """Run a shell command INSIDE the mirror. transport: wsl | docker | local (local = the mirror is this
    host, e.g. tests). Returns (rc, combined_output)."""
    full = f"cd {cwd} && {cmd}" if cwd else cmd
    if transport == "wsl":
        argv = ["wsl", "-d", distro, "-u", "root", "--", "bash", "-lc", full]
    elif transport == "docker":
        argv = ["docker", "exec", "-i", container or "", "sh", "-lc", full]
    else:
        argv = ["bash", "-lc", full]
    try:
        # binary mode: passing stdin as bytes avoids Windows \n->\r\n translation, which would corrupt a
        # piped unified diff (CRLF context lines no longer match an LF file -> "patch does not apply").
        inp = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
        p = subprocess.run(argv, input=inp, capture_output=True, timeout=timeout)
        return p.returncode, ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")[-4000:]
    except Exception as e:
        return 999, f"[exec error] {e}"


def apply_diff(diff, transport, distro, container, mirror_repo):
    """git apply a unified diff inside the mirror. Ensures a trailing newline (git rejects a patch without
    one as 'corrupt') and uses --recount so slightly-off hunk headers still apply. Returns (rc, out)."""
    d = diff if diff.endswith("\n") else diff + "\n"
    return mirror_exec(transport, "git apply --whitespace=nowarn --recount -",
                       distro=distro, container=container, cwd=mirror_repo, stdin=d)


def host_snapshot(action, name):
    """snapshot|restore the mirror via the host-side mirror_snapshot.py (DB-level)."""
    script = os.path.join(HERE, "mirror_snapshot.py")
    try:
        p = subprocess.run([sys.executable, script, action, name], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300)
        return p.returncode == 0, ((p.stdout or "") + (p.stderr or ""))[-600:]
    except Exception as e:
        return False, f"[snapshot error] {e}"


# ---------- re-run the exploit/oracle ----------
def rerun_repro(repro, transport, distro, container, dry, mirror_repo=None):
    """Re-run the finding's exploit/oracle on the patched mirror. Returns (exploit_still_works: bool|None,
    detail). test_suggestions re-runs TARGET/CODE/ORACLE; a 'command' repro uses expect_closed_regex."""
    if dry:
        return None, "[dry-run] would re-run repro"
    if repro.get("type") == "suggestion":
        f = repro.get("file")
        if not f or not os.path.exists(f):
            return None, f"repro suggestion file missing: {f}"
        role = repro.get("role", "owner")
        try:
            p = subprocess.run([sys.executable, os.path.join(HERE, "test_suggestions.py"),
                                "--file", f, "--source", "verify", "--role", role, "--execute"],
                               capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
            out = ((p.stdout or "") + (p.stderr or ""))
        except Exception as e:
            return None, f"[repro error] {e}"
        # test_suggestions.py prints '== summary (src): pass=N fail=... =='. The exploit STILL works iff
        # at least one oracle PASSED -- parse the COUNT. (Do NOT regex the word 'pass': it matches
        # 'pass=0' and would report STILL-OPEN unconditionally.)
        m = re.search(r"pass=(\d+)", out)
        still = bool(m and int(m.group(1)) > 0)
        return still, out[-1500:]
    if repro.get("type") == "command":
        cmd = repro.get("cmd", "")
        rc, out = mirror_exec(transport, cmd, distro=distro, container=container, cwd=mirror_repo)
        rx = repro.get("expect_closed_regex")
        if rx:  # if the 'closed' signature appears, the exploit no longer works
            return (not re.search(rx, out)), out[-1500:]
        # else: exit 0 == exploit still works
        return (rc == 0), out[-1500:]
    return None, "unknown repro type"


# ---------- repair: board-driven fix for code the framework update broke ----------
# Doctrine: same as the remediation board -- the OPERATOR diagnoses, the BOARD PANEL suggests (differences
# captured), then the CODE BENCH (DS/Qwen) writes the actual patch. A post-update report says what must be
# done after the update to get things running.
DIAGNOSE_SYS = (
    "You are the operator (DeepSeek) on the owner's OWN app (authorized). A framework/dependency UPDATE on the "
    "mirror BROKE the app. From the update and the build/run error, state concisely: (1) WHAT broke and the "
    "root cause (which API/import/signature the update changed), (2) WHAT fix makes it run again. Terse.")
BREAK_PANEL_SYS = (
    "You are on the board. A framework update broke the owner's app on the mirror. Given the update, the error, "
    "and the operator's diagnosis, suggest the concrete code change to make it run again. Terse; note if you "
    "disagree with the diagnosis.")
BREAK_CODE_SYS = (
    "You are the code writer/improver. A framework update broke the app. Given the update, the error, the "
    "diagnosis and the board's suggestions, output ONLY a unified diff (git apply-able, a/ b/ headers) that "
    "adapts the code to the new framework so it RUNS again. Smallest change. No prose, no fences -- just the diff.")


def _deepseek(system, user, model, maxtok=1800):
    import urllib.request
    key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        return ""
    ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
    body = {"model": model, "messages": [{"role": "system", "content": system},
                                         {"role": "user", "content": user}], "max_tokens": maxtok, "temperature": 0.2}
    req = urllib.request.Request(ep + "/chat/completions", data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=170))
    m = (r.get("choices") or [{}])[0].get("message", {})
    _content = (m.get("content") or "").strip()
    if _content:
        return _content
    # No final answer (e.g. a thinking model ran out of budget mid-reasoning). Surface the
    # reasoning but LABEL it, so raw chain-of-thought is never mistaken for a clean answer.
    _reasoning = (m.get("reasoning_content") or "").strip()
    return ("[raw reasoning, no final content] " + _reasoning) if _reasoning else ""


def _board(tag, who, text):
    """Best-effort board post (reuses remediation_board.board); no-op if the board isn't importable."""
    try:
        import remediation_board
        remediation_board.board(tag, who, text)
    except Exception:
        pass


def _break_panel(brief, model):
    """Board round on the breakage: DS + Sol + CF panel suggest the fix; each posts to the board. Returns
    {who: suggestion} (the differences)."""
    import cf_agent
    out = {}
    try:
        ds = _deepseek(BREAK_PANEL_SYS, brief, os.environ.get("AEGIS_BOARD_MODEL") or "deepseek-v4-flash", 900)
        if ds:
            out["ds_direct"] = ds; _board("BREAK_FIX", "ds_direct", ds)
    except Exception as e:
        out["ds_direct"] = f"[error] {e}"
    if os.environ.get("OPENAI_API_KEY"):
        try:
            import urllib.request
            body = {"model": "gpt-5.6", "messages": [{"role": "system", "content": BREAK_PANEL_SYS},
                    {"role": "user", "content": brief}], "max_completion_tokens": 900}
            req = urllib.request.Request("https://api.openai.com/v1/chat/completions", data=json.dumps(body).encode(),
                    method="POST", headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}", "Content-Type": "application/json"})
            r = json.load(urllib.request.urlopen(req, timeout=170))
            sol = ((r.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()
            if sol:
                out["sol"] = sol; _board("BREAK_FIX", "sol", sol)
        except Exception as e:
            out["sol"] = f"[error] {e}"
    for m in ("gpt-oss-120b", "qwen2.5-coder-32b"):
        try:
            t = cf_agent.ask(m, BREAK_PANEL_SYS, brief, max_tokens=900)
            if t:
                out[m] = t; _board("BREAK_FIX", m, t)
        except Exception as e:
            out[m] = f"[error] {e}"
    return out


def _diff_sig(diff):
    """The set of changed (added/removed) code lines, normalized -- for the convergence metric."""
    return set(l[1:].strip() for l in (diff or "").splitlines()
               if l[:1] in "+-" and l[:2] not in ("++", "--") and l[1:].strip())


def _convergence(diff_a, diff_b):
    """Jaccard overlap of the two writers' changed lines: 1.0 = identical fix, 0 = disjoint."""
    a, b = _diff_sig(diff_a), _diff_sig(diff_b)
    if not a and not b:
        return 0.0
    return round(len(a & b) / len(a | b), 2)


def _rate(bench):
    """Score a writer's patch: heals dominates, then applies, then smaller diff. Higher = better."""
    if not bench.get("diff"):
        return 0.0
    return round(2.0 * bench.get("heals", False) + 1.0 * bench.get("applies", False)
                 + 0.5 * (1.0 / (1 + bench.get("size", 0) / 200.0)), 3)


# The PRIMARY code writers for repairing the mirror -- the coders work together (gpt-oss/Sol stay
# advisory on the board). All CF ones skip gracefully if unavailable. Scout & R1-distill added after
# a code-review bake-off (Scout topped it; R1-distill is a solid reasoning-coder).
CODE_WRITERS = ("ds", "qwen", "kimi", "scout", "r1")
# writer name -> CF model slug for the non-DeepSeek coders (DeepSeek goes direct).
_CF_WRITER = {"qwen": "qwen2.5-coder-32b", "kimi": "kimi-k2.7-code",
              "scout": "llama-4-scout", "r1": "deepseek-r1-distill-32b"}


def repair_break(rem, health_cmd, health_out, transport, distro, container, mirror_repo, model, max_attempts):
    """Board-driven repair with a MULTI-CODER benchmark. Operator diagnoses -> board panel suggests
    (differences) -> the PRIMARY code writers (DS, Qwen, KIMI) each emit a patch; each is applied against
    the same checkpoint and RATED (applies / heals / size), with a DS<->Qwen CONVERGENCE score; the
    best-rated healthy patch is kept. Returns (healthy, log) -- log carries the diagnosis, panel,
    per-writer benchmark, convergence, and winner. Writers that are unavailable simply don't contribute."""
    import cf_agent
    brief = (f"UPDATE APPLIED: {rem.get('component','?')} {rem.get('installed_version','?')} -> "
             f"{rem.get('fixed_version','?')}\n\nBUILD/RUN ERROR after the update:\n{(health_out or '')[-2200:]}")
    # 1) operator diagnoses -> board
    diagnosis = _deepseek(DIAGNOSE_SYS, brief, model) or "[no diagnosis]"
    _board("BREAK_DIAGNOSIS", "operator", diagnosis)
    print("    [repair] operator diagnosed the breakage; board panel suggesting fixes...")
    # 2) advisory board panel -> board (differences captured)
    panel = _break_panel(brief + "\n\nOPERATOR DIAGNOSIS:\n" + diagnosis, model)
    panel_txt = "\n\n".join(f"### {w}\n{t}" for w, t in panel.items())
    log = {"diagnosis": diagnosis, "panel": panel, "bench": {}, "convergence": None, "winner": None}

    # checkpoint the broken state so each writer starts from the SAME point
    mirror_exec(transport, "git add -A && git commit -q -m aegis-broken-checkpoint || true",
                distro=distro, container=container, cwd=mirror_repo)

    def _reset():
        mirror_exec(transport, "git reset -q --hard HEAD && git clean -fdq || true",
                    distro=distro, container=container, cwd=mirror_repo)

    user = (brief + "\n\nOPERATOR DIAGNOSIS:\n" + diagnosis + "\n\nBOARD SUGGESTIONS:\n" + panel_txt
            + "\n\nOutput the unified diff to make the app run again.")

    # 3) BENCHMARK the primary code writers (DS, Qwen, KIMI) on the same broken checkpoint
    for w in CODE_WRITERS:
        raw = (_deepseek(BREAK_CODE_SYS, user, model) if w == "ds"
               else cf_agent.ask(_CF_WRITER.get(w, w), BREAK_CODE_SYS, user, max_tokens=1800))
        diff = extract_diff(raw) or (raw or "")
        b = {"writer": w, "diff": diff, "size": len(diff), "applies": False, "heals": False, "health_out": ""}
        if diff.strip():
            _reset()
            rc, out = apply_diff(diff, transport, distro, container, mirror_repo)
            b["applies"] = rc == 0
            if b["applies"]:
                hrc, hout = mirror_exec(transport, health_cmd, distro=distro, container=container, cwd=mirror_repo)
                b["heals"] = hrc == 0; b["health_out"] = hout[-300:]
            else:
                b["health_out"] = out[-200:]
            _reset()
        b["rating"] = _rate(b)
        log["bench"][w] = b
        _board("BREAK_PATCH", f"{w}", f"applies={b['applies']} heals={b['heals']} size={b['size']} "
               f"rating={b['rating']}\n\n{diff[:1500]}")
        print(f"    [bench] {w}: applies={b['applies']} heals={b['heals']} size={b['size']} rating={b['rating']}")

    # convergence between DS and Qwen (headline pair; kimi is rated alongside but not in this metric)
    if log["bench"].get("ds", {}).get("diff") and log["bench"].get("qwen", {}).get("diff"):
        log["convergence"] = _convergence(log["bench"]["ds"]["diff"], log["bench"]["qwen"]["diff"])
        print(f"    [bench] DS<->Qwen convergence: {log['convergence']}")

    # 4) pick the winner (highest rating; must at least apply) and KEEP it applied
    ranked = sorted(log["bench"].values(), key=lambda b: b["rating"], reverse=True)
    winner = next((b for b in ranked if b["heals"]), None) or next((b for b in ranked if b["applies"]), None)
    if winner:
        _reset()
        apply_diff(winner["diff"], transport, distro, container, mirror_repo)
        log["winner"] = {"writer": winner["writer"], "heals": winner["heals"], "rating": winner["rating"]}
        log["healthy"] = winner["heals"]
        return winner["heals"], log
    log["healthy"] = False
    return False, log


def write_post_update_report(fid, rem, log, path):
    """Hand a report of what must be done after the update to get things running (the breakage + diagnosis +
    panel differences + the fix that was tried)."""
    healthy = log.get("healthy")
    out = [f"# Post-update remediation — finding {fid[:12]}", "",
           f"_A framework/dependency update ({rem.get('component','?')} → {rem.get('fixed_version','?')}) broke "
           f"the app on the mirror. Status after repair: **{'RUNNING again' if healthy else 'STILL BROKEN'}**._", "",
           "## What broke (operator diagnosis)", "", log.get("diagnosis", "—"), "",
           "## Board panel suggestions (differences)", ""]
    for who, txt in (log.get("panel") or {}).items():
        out += [f"**{who}:**", "", txt, ""]
    out += ["## Code writers benchmarked (DS vs Qwen — primary)", "",
            "| writer | applies | heals | size | rating |", "|---|---|---|---|---|"]
    for w, b in (log.get("bench") or {}).items():
        out.append(f"| {w} | {b.get('applies')} | {b.get('heals')} | {b.get('size')} | {b.get('rating')} |")
    conv = log.get("convergence")
    if conv is not None:
        out += ["", f"**Convergence (DS↔Qwen changed-line overlap): {conv}** "
                + ("— they agree on the fix." if conv >= 0.6 else
                   "— partial agreement." if conv >= 0.3 else "— they diverge; the winner was chosen by rating.")]
    win = log.get("winner")
    if win:
        out += ["", f"**Winner: `{win['writer']}`** (rating {win['rating']}, "
                f"{'HEALS' if win['heals'] else 'applies but still broken'}) — kept applied on the mirror."]
    for w, b in (log.get("bench") or {}).items():
        if b.get("diff"):
            out += ["", f"### {w} patch", "", "```diff", b["diff"][:2000], "```", ""]
    if not healthy:
        out += ["", "> **Still broken.** Do this after the update to get it running: apply the diagnosis above "
                "by hand (adapt the code to the new framework API), re-port, and re-run the verifier; or raise "
                "`--repair-max`. The verified weakness could NOT be re-tested until the app runs."]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))
    return path


# ---------- orchestration ----------
def _patch_files(fixes_dir, finding):
    f = finding[:12]
    return sorted(p for p in glob.glob(os.path.join(fixes_dir, "*.md")) if os.path.basename(p).startswith(f))


def verify_one(f, repro, fixes_dir, transport, distro, container, mirror_repo, ecosystem, dry,
               allow_download=False, health_cmd=None, repair=False, repair_max=2, code_model="deepseek-v4-pro"):
    fid = f.get("finding_id", "")
    rem = f.get("remediation") or {}
    steps = {"apply_code": [], "apply_admin": None, "health": None, "repair": None, "rerun": None}

    # 2a. CODE track -> git apply each ported patch's diff on the mirror
    for pf in _patch_files(fixes_dir, fid):
        diff = extract_diff(open(pf, encoding="utf-8", errors="replace").read())
        if not diff:
            steps["apply_code"].append({"patch": os.path.basename(pf), "status": "no-diff-found"}); continue
        if dry:
            steps["apply_code"].append({"patch": os.path.basename(pf), "status": "dry-run"}); continue
        rc, out = apply_diff(diff, transport, distro, container, mirror_repo)
        steps["apply_code"].append({"patch": os.path.basename(pf),
                                    "status": "applied" if rc == 0 else f"apply-failed: {out[-200:]}"})

    # 2b. ADMIN track -> system/framework bump via the mirror package manager
    if rem.get("audience") == "admin" or rem.get("fixed_version"):
        cmd, eco = admin_bump_cmd(rem.get("component", ""), rem.get("installed_version", ""),
                                  rem.get("fixed_version", ""), ecosystem)
        if not cmd:
            steps["apply_admin"] = {"status": "skipped", "note": eco}
        elif not allow_download:
            # a framework/dependency bump usually fetches from a package repo == off-box egress. Doctrine
            # keeps the mirror offline unless the owner opts in, so require an explicit --allow-download.
            steps["apply_admin"] = {"status": "needs-download", "cmd": cmd, "ecosystem": eco,
                                    "note": "would fetch from a package repo; re-run with --allow-download"}
        elif dry:
            steps["apply_admin"] = {"status": "dry-run", "cmd": cmd, "ecosystem": eco}
        else:
            # authorized mirror-side egress: download + apply the system/framework update ON THE MIRROR only.
            rc, out = mirror_exec(transport, cmd, distro=distro, container=container, cwd=mirror_repo, timeout=900)
            steps["apply_admin"] = {"status": "ok" if rc == 0 else "failed", "cmd": cmd,
                                    "ecosystem": eco, "out": out[-300:]}

    # 2c. HEALTH / regression check -- a framework update can BREAK the app code (API changes, deprecations).
    # Confirm the patched mirror still builds/runs before trusting the verdict; a break must be surfaced.
    hc = health_cmd or (repro.get("health_cmd") if repro else None)
    broke = False; health_out = ""
    if hc and not dry:
        rc, health_out = mirror_exec(transport, hc, distro=distro, container=container, cwd=mirror_repo)
        broke = rc != 0
        steps["health"] = {"cmd": hc, "status": "ok" if rc == 0 else "BROKE", "out": health_out[-400:]}
    elif hc and dry:
        steps["health"] = {"cmd": hc, "status": "dry-run"}

    # 2d. REPAIR: if the update broke the code, run the board-driven repair (operator diagnoses -> panel
    # suggests -> DS/Qwen benchmarked -> winner kept) until it runs again, and hand a post-update report.
    if broke and repair and not dry:
        print(f"  app broke after update -- board-driven repair (DS vs Qwen)...")
        healthy, rlog = repair_break(rem, hc, health_out, transport, distro, container,
                                     mirror_repo, code_model, repair_max)
        rpt = os.path.join(HERE, f"post_update_report_{fid[:12]}.md")
        try:
            write_post_update_report(fid, rem, rlog, rpt)
        except Exception as e:
            rpt = f"(report error: {e})"
        steps["repair"] = {"healthy": healthy, "winner": rlog.get("winner"),
                           "convergence": rlog.get("convergence"), "bench": {w: {k: b[k] for k in
                           ("applies", "heals", "size", "rating")} for w, b in (rlog.get("bench") or {}).items()},
                           "post_update_report": rpt}
        broke = not healthy

    # 3-4. RE-RUN the exploit/oracle on the patched system+code -> classify
    if broke:
        steps["rerun"] = {"note": "skipped -- app broke after the update and was not repaired"}
        return "BROKE-AFTER-UPDATE", steps
    if not repro:
        verdict = "NO-REPRO"; steps["rerun"] = {"note": "no repro provided; re-test by hand"}
    else:
        still, detail = rerun_repro(repro, transport, distro, container, dry, mirror_repo)
        steps["rerun"] = {"exploit_still_works": still, "detail": detail}
        verdict = ("DRY" if dry else "STILL-OPEN" if still else "CLOSED" if still is False else "INCONCLUSIVE")
    return verdict, steps


def verify(findings, repro_map, fixes_dir, transport, distro, container, mirror_repo, ecosystem,
           snap_name, dry, keep, write_ledger, allow_download=False, health_cmd=None,
           repair=False, repair_max=2, code_model="deepseek-v4-pro", findings_path=None):
    results = []
    snap_ok, snap_note = (True, "dry-run") if dry else host_snapshot("snapshot", snap_name)
    print(f"[verify] snapshot '{snap_name}': {'ok' if snap_ok else 'FAILED -- '+snap_note}")
    if not snap_ok and not dry:
        print("[verify] refusing to patch the mirror without a snapshot to restore. Aborting.")
        return results
    try:
        for i, f in enumerate(findings, 1):
            fid = f.get("finding_id", "")
            repro = repro_map.get(fid) or (f.get("remediation") or {}).get("repro")
            print(f"\n== verify {i}/{len(findings)} [{fid[:12]}] {f.get('claim_type','?')} ==")
            verdict, steps = verify_one(f, repro, fixes_dir, transport, distro, container,
                                        mirror_repo, ecosystem, dry, allow_download, health_cmd,
                                        repair, repair_max, code_model)
            print(f"  verdict: {verdict}")
            results.append({"finding_id": fid, "claim_type": f.get("claim_type"), "verdict": verdict, "steps": steps})
            if write_ledger and not dry and verdict in ("CLOSED", "STILL-OPEN", "BROKE-AFTER-UPDATE"):
                _writeback_verdict(f, verdict, steps, findings_path)
    finally:
        if dry:
            print("\n[verify] dry-run: no snapshot restore.")
        elif keep:
            print(f"\n[verify] --keep: leaving the patched mirror; restore later with "
                  f"mirror_snapshot.py restore {snap_name}")
        else:
            ok, note = host_snapshot("restore", snap_name)
            print(f"\n[verify] restore '{snap_name}': {'ok' if ok else 'FAILED -- '+note}")
    return results


def _writeback_verdict(f, verdict, steps, findings_path=None):
    try:
        from verified_findings import FindingStore
        # write back to the SAME ledger the findings were read from (--findings), not a hardcoded one.
        store = FindingStore(findings_path or os.path.join(HERE, "aegis_operator_findings.jsonl"))
        rem = dict(f.get("remediation") or {})
        _status = {"CLOSED": "closed", "STILL-OPEN": "open", "BROKE-AFTER-UPDATE": "broke-after-update"}
        rem["verification"] = {"status": _status.get(verdict, "unknown"),
                               "verdict": verdict, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        store.record_remediation(f["finding_id"], rem)
        print(f"  [ledger] verification chained onto {f['finding_id'][:12]}: {rem['verification']['status']}")
    except Exception as e:
        print(f"  [ledger] verification writeback failed: {e}")


def write_report(results, path, transport, mirror_repo):
    ts = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    n_closed = sum(1 for r in results if r["verdict"] == "CLOSED")
    n_open = sum(1 for r in results if r["verdict"] == "STILL-OPEN")
    n_broke = sum(1 for r in results if r["verdict"] == "BROKE-AFTER-UPDATE")
    out = ["# Remediation verification report", "",
           f"_Generated {ts} -- fixes APPLIED + re-tested on the MIRROR twin ({transport}:{mirror_repo}); "
           f"real target never patched or re-tested._", "",
           f"- Findings re-tested: **{len(results)}** -- **CLOSED: {n_closed}**, STILL-OPEN: {n_open}, "
           f"BROKE-AFTER-UPDATE: {n_broke}, other: {len(results)-n_closed-n_open-n_broke}", "",
           "| # | verdict | weakness | code applied | admin bump | health | repair | re-run |",
           "|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(results, 1):
        s = r["steps"]
        code = ", ".join(x["status"] for x in s.get("apply_code", [])) or "—"
        adm = (s.get("apply_admin") or {}).get("status", "—")
        hh = (s.get("health") or {}).get("status", "—")
        rp = s.get("repair")
        repair = ("—" if not rp else "repaired" if rp.get("healthy") else f"failed({len(rp.get('bench') or {})})")
        rr = (s.get("rerun") or {})
        run = ("still-works" if rr.get("exploit_still_works") else
               "blocked" if rr.get("exploit_still_works") is False else rr.get("note", "—")[:24])
        out.append(f"| {i} | **{r['verdict']}** | {r['claim_type']} | {code} | {adm} | {hh} | {repair} | {run} |")
    if n_broke:
        out += ["", f"> **{n_broke} fix(es) broke the app after the update and were not (fully) repaired.** "
                "Hand these back to the code writer/improver: inspect the health error in the finding detail, "
                "rewrite for the new framework API, re-port, and re-run this verifier."]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))
    print(f"\n[verify] report -> {path}")
    return path


def main():
    ap = argparse.ArgumentParser(description="Stage-10 closed loop: patch the mirror + re-test on it.")
    ap.add_argument("--findings", default=os.path.join(HERE, "aegis_operator_findings.jsonl"))
    ap.add_argument("--fixes-dir", default=DEFAULT_FIXES_DIR)
    ap.add_argument("--repro-map", help="JSON: finding_id -> {type:suggestion|command, ...}")
    ap.add_argument("--transport", choices=["wsl", "docker", "local"], default="wsl")
    ap.add_argument("--distro", default=MIRROR_DISTRO, help="wsl transport distro (any: Ubuntu/SUSE/Kali)")
    ap.add_argument("--container", help="docker transport container")
    ap.add_argument("--mirror-repo", default=os.environ.get("AEGIS_MIRROR_REPO", "/opt/aegis-mirror"),
                    help="path to the app repo INSIDE the mirror (where patches apply)")
    ap.add_argument("--ecosystem", choices=list(_ECOSYSTEM_CMD), help="force the package manager for ADMIN bumps")
    ap.add_argument("--allow-download", action="store_true",
                    help="permit the ADMIN bump to fetch the system/framework update from a package repo ON THE "
                         "MIRROR (authorized mirror-side egress; off by default to keep the mirror offline)")
    ap.add_argument("--health-cmd", help="command run on the mirror AFTER patching to check the app still "
                    "runs (a framework update can break the code); non-zero exit = BROKE-AFTER-UPDATE")
    ap.add_argument("--repair", action="store_true",
                    help="if the update breaks the code, hand the error to the code writer to rewrite it until "
                         "the app runs again (bounded by --repair-max), then continue the re-test")
    ap.add_argument("--repair-max", type=int, default=2, help="max repair attempts (default 2)")
    ap.add_argument("--code-model", default=os.environ.get("AEGIS_MODEL", "deepseek-v4-pro"),
                    help="code writer/improver model for repairs (default deepseek-v4-pro)")
    ap.add_argument("--snapshot-name", default=f"rem-verify-{int(time.time())}")
    ap.add_argument("--report", default=os.path.join(HERE, "remediation_verify_report.md"))
    ap.add_argument("--write-ledger", action="store_true", help="chain the closed/open verdict onto the ledger")
    ap.add_argument("--keep", action="store_true", help="do NOT restore the snapshot (leave the patched mirror)")
    ap.add_argument("--dry-run", action="store_true", help="print the plan; patch/re-test nothing")
    a = ap.parse_args()

    try:
        from verified_findings import FindingStore
        findings = FindingStore(a.findings).verified()
    except Exception as e:
        print(f"[verify] cannot read findings ({e})"); sys.exit(1)
    if not findings:
        print("[verify] no VERIFIED findings to verify."); return
    repro_map = {}
    if a.repro_map and os.path.exists(a.repro_map):
        repro_map = json.load(open(a.repro_map, encoding="utf-8"))
    print(f"[verify] {len(findings)} verified finding(s); transport={a.transport} "
          f"mirror-repo={a.mirror_repo}; repro entries={len(repro_map)}")
    results = verify(findings, repro_map, a.fixes_dir, a.transport, a.distro, a.container,
                     a.mirror_repo, a.ecosystem, a.snapshot_name, a.dry_run, a.keep, a.write_ledger,
                     a.allow_download, a.health_cmd, a.repair, a.repair_max, a.code_model,
                     findings_path=a.findings)
    if results:
        write_report(results, a.report, a.transport, a.mirror_repo)


if __name__ == "__main__":
    main()
