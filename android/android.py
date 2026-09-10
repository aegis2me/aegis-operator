"""android/android.py -- the ANDROID DE/COMPILER: a STANDALONE function with NOTHING to do with the test side
(operator / exploitgym / redteam). It does not hunt, score, or produce findings. Its only job:

    look into an APK  ->  decompile it  ->  modify the code (board decides, ONE coder executes,
                          a human/coordinator oversees)  ->  recompile back into an installable APK.

Owned APKs only, contained. Decompile / recompile / sign run in Kali (jadx + apktool + zipalign + apksigner);
the board + one-coder calls run here (keys in secret.env). The input .apk is never modified -- all work is on a
copy in Kali under /root/apk_work/<name>/.

Roles in the modification loop:
  - the BOARD (panel) DECIDES how to make the requested change so the app still recompiles (consensus plan);
  - ONE code writer (--coder, default deepseek-v4-pro) EXECUTES it -- emits the exact edited file;
  - a coordinator (you, or Claude in the seat) OVERSEES: states the request, picks the target, approves rebuild.

Pipeline
--------
1. decompile <apk>            -- apktool d (smali + AndroidManifest + resources, RECOMPILABLE) + jadx (readable
                                Java, so the board/coordinator can READ what the app does).
2. explore   --name app       -- describe the decompiled app (package, components, permissions, entry points,
                                file tree) so the coordinator + board can decide what to change. Descriptive only.
3. plan      --name app --request "..."  -- the BOARD decides HOW to implement the requested change so it still
                                recompiles (which files, what edits). Consensus plan.
4. rewrite   --name app --request "..." [--coder ..] [--target ..]  -- ONE coder EXECUTES the plan: emits the
                                complete edited file, written into the apktool tree.
5. rebuild   --name app [--no-sign]  -- apktool b -> zipalign -> apksigner (generated debug keystore) ->
                                <name>.patched.apk, installable.

Which coder for decompiled Android code: deepseek-v4-pro + qwen2.5-coder-32b are strongest at Java/Kotlin/smali;
r1-distill reasons over obfuscated logic; llama-4-scout for breadth. gpt-oss stay board reviewers, not executor.

Usage:
    python android/android.py decompile /path/app.apk [--name app]
    python android/android.py explore   --name app
    python android/android.py plan      --name app --request "disable the analytics upload on startup"
    python android/android.py rewrite   --name app --request "..." [--coder deepseek-v4-pro] [--target <file>]
    python android/android.py rebuild   --name app

  Or hand the whole loop to a coordinator LLM (DeepSeek in the seat instead of a human/Claude):
    python android/android.py coordinate --name app --goal "<what to change>" [--coordinator deepseek-v4-pro] [--coder ..]
  The coordinator turns the goal into a concrete change, has the board plan it, picks the target, runs the one
  coder, and reviews the rebuild -- overseeing, not writing the final code itself.
"""
from __future__ import annotations
import os, sys, json, subprocess, re, base64, platform

HERE = os.path.dirname(os.path.abspath(__file__))            # android/  (its own function, not the operator)
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "operator"))           # reuse ONLY board_ask / cf_agent (LLM plumbing)

KALI = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
WORK = "/root/apk_work"                                       # in-Kali working root


# ---------------- Kali shell ----------------
def _kali(cmd, timeout=1800):
    if platform.system() == "Windows":
        full = ["wsl", "-d", KALI, "-u", "root", "--", "bash", "-lc", cmd]
        env = dict(os.environ, MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")
    else:
        full = ["bash", "-lc", cmd]                           # already inside Kali
        env = dict(os.environ)
    r = subprocess.run(full, capture_output=True, text=True, timeout=timeout, env=env)
    return r.returncode, r.stdout, r.stderr


def _win_to_kali_path(p):
    if platform.system() != "Windows":
        return p
    p = p.replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", p)
    return f"/mnt/{m.group(1).lower()}/{m.group(2)}" if m else p


def _read_kali_file(path, max_bytes=200000):
    rc, out, err = _kali(f"head -c {max_bytes} '{path}' 2>/dev/null", timeout=120)
    return out if rc == 0 else ""


# ---------------- 1. decompile ----------------
def decompile(apk_path, name=None, jadx=True):
    """apktool (smali/res, recompilable -- always) + jadx (readable Java, OPTIONAL). jadx is memory-hungry
    on large apps; pass jadx=False (--no-jadx) on a constrained host -- the coordinator only needs smali."""
    name = name or re.sub(r"\.apk$", "", os.path.basename(apk_path), flags=re.I)
    kapk = _win_to_kali_path(apk_path)
    wd = f"{WORK}/{name}"
    # if the apk is already at wd/orig.apk (pre-copied), don't re-copy from a (possibly mangled) path.
    cp = (f"cp '{kapk}' {wd}/orig.apk; " if kapk not in (f"{wd}/orig.apk",) else "")
    jadx_step = (
        f"echo '[jadx] decompiling Java (readable)...'; "
        f"rm -rf {wd}/jadx; timeout 900 jadx -j 1 -d {wd}/jadx {wd}/orig.apk >/dev/null 2>{wd}/jadx.log || "
        f"  (echo JADX_PARTIAL; tail -3 {wd}/jadx.log); "
    ) if jadx else "echo '[jadx] SKIPPED (--no-jadx: apktool smali is the recompilable surface)'; "
    script = (
        f"set -e; mkdir -p {wd}; {cp}"
        f"echo '[apktool] decompiling smali+resources (recompilable)...'; "
        f"rm -rf {wd}/apktool; apktool d -f -o {wd}/apktool {wd}/orig.apk >/dev/null 2>{wd}/apktool.log || "
        f"  (echo APKTOOL_FAIL; tail -5 {wd}/apktool.log); "
        f"{jadx_step}"
        f"echo '--- layout ---'; "
        f"echo manifest: $(test -f {wd}/apktool/AndroidManifest.xml && echo yes || echo NO); "
        f"echo smali_files: $(find {wd}/apktool -name '*.smali' 2>/dev/null | wc -l); "
        f"echo java_files: $(find {wd}/jadx -name '*.java' 2>/dev/null | wc -l)"
    )
    rc, out, err = _kali(script, timeout=1800)
    print(out)
    if err.strip():
        print("[stderr]", err.strip()[-400:])
    return {"name": name, "workdir": wd, "ok": "APKTOOL_FAIL" not in out}


# ---------------- 2. explore (descriptive -- NOT security testing) ----------------
def explore(name):
    """Describe the decompiled app so the coordinator + board can decide what to change. No findings, no scoring."""
    wd = f"{WORK}/{name}"
    manifest = _read_kali_file(f"{wd}/apktool/AndroidManifest.xml", max_bytes=200000)
    pkg = (re.search(r'package="([^"]+)"', manifest) or [None, "?"])[1]
    perms = re.findall(r'uses-permission[^>]*android:name="([^"]+)"', manifest)
    comps = {k: re.findall(rf'<{k}\b[^>]*android:name="([^"]+)"', manifest)
             for k in ("activity", "service", "receiver", "provider")}
    launch = re.search(r'<activity\b[^>]*android:name="([^"]+)"[^>]*>(?:(?!</activity>).)*'
                       r'android.intent.action.MAIN', manifest, re.S)
    rc, tree, _ = _kali(f"cd {wd}/jadx/sources 2>/dev/null && find . -name '*.java' 2>/dev/null | "
                        f"sed 's#/[^/]*$##' | sort -u | head -40", timeout=180)
    info = {"name": name, "workdir": wd, "package": pkg,
            "launch_activity": launch.group(1) if launch else "?",
            "permissions": perms, "components": {k: v for k, v in comps.items() if v},
            "source_packages": [t for t in tree.splitlines() if t.strip()]}
    out_path = os.path.join(HERE, f"apk_explore_{name}.json")
    json.dump(info, open(out_path, "w", encoding="utf-8"), indent=2)
    print(f"[explore] {name}: package={pkg}")
    print(f"  launch activity: {info['launch_activity']}")
    print(f"  permissions: {len(perms)}   components: " +
          ", ".join(f"{k}={len(v)}" for k, v in info['components'].items()))
    print(f"  source packages (top): {len(info['source_packages'])}  -> {out_path}")
    return info


# ---------------- board + one-coder calls ----------------
def _ask(model, system, user, maxtok=2600):
    """One synchronous LLM call. DeepSeek-direct for ds/deepseek*, Cloudflare for the rest."""
    ml = model.lower()
    if ml.startswith("ds") or "deepseek-v4" in ml or ml == "deepseek":
        import board_ask
        key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
        ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
        mdl = "deepseek-v4-pro" if ("pro" in ml or ml in ("ds", "deepseek")) else model
        return board_ask._post(ep + "/chat/completions", key, mdl, system, user, maxtok,
                               extra={"thinking": {"type": "disabled"}})
    import cf_agent
    return cf_agent.ask(cf_agent.resolve(model), system, user, max_tokens=maxtok, temperature=0.3)


_PANEL = os.environ.get("AEGIS_APK_PANEL", "deepseek-v4-pro,qwen2.5-coder-32b,llama-4-scout").split(",")


# ---------------- 3. plan (board DECIDES how to make the change, recompilably) ----------------
def plan(name, request, panel=None):
    wd = f"{WORK}/{name}"
    manifest = _read_kali_file(f"{wd}/apktool/AndroidManifest.xml", max_bytes=8000)
    sysp = ("You are on a board modifying the owner's OWN Android app. The coordinator wants a change. Decide "
            "HOW to make it so the DECOMPILED app still RECOMPILES with apktool: the edit must land in the "
            "apktool tree (smali / res / AndroidManifest.xml), not un-recompilable jadx Java. Be concrete: name "
            "the exact file(s) and the change. Output a short numbered plan only.")
    brief = f"REQUESTED CHANGE:\n{request}\n\nAndroidManifest.xml (head):\n{manifest[:6000]}"
    takes, panel = {}, (panel or _PANEL)
    for m in panel:
        try:
            takes[m] = _ask(m, sysp, brief, maxtok=1200); print(f"  [{m}] plan ({len(takes[m])}b)")
        except Exception as e:
            print(f"  [{m}] plan skipped: {e}")
    syn = _ask(panel[0], "Merge the panel plans into ONE concrete, minimal, recompilable plan. Numbered steps; "
                         "name exact files. Output only the plan.",
               "\n\n".join(f"## {k}\n{v}" for k, v in takes.items()), maxtok=1400)
    plan_path = os.path.join(HERE, f"apk_plan_{name}.md")
    open(plan_path, "w", encoding="utf-8").write(f"# Change plan for {name}\n\nREQUEST: {request}\n\n"
                                                 f"## Consensus\n{syn}\n\n"
                                                 + "\n".join(f"## {k}\n{v}" for k, v in takes.items()))
    print(f"[plan] board consensus -> {plan_path}")
    return {"request": request, "plan": syn, "plan_path": plan_path}


# ---------------- 4. rewrite (ONE coder EXECUTES) ----------------
def rewrite(name, request, coder=None, target_file=None):
    coder = coder or os.environ.get("AEGIS_APK_CODER", "deepseek-v4-pro")
    wd = f"{WORK}/{name}"
    plan_path = os.path.join(HERE, f"apk_plan_{name}.md")
    plan_txt = open(plan_path, encoding="utf-8").read()[:4000] if os.path.exists(plan_path) else \
        f"REQUEST: {request} (no board plan on file; execute directly)"
    tgt = target_file or _infer_target(plan_txt, wd)
    if not tgt:
        print("[rewrite] could not infer a recompilable target file; pass --target <smali/xml path in Kali>")
        return None
    cur = _read_kali_file(tgt, max_bytes=14000)
    sysp = (f"You are the single code writer for the owner's OWN app. Apply the board plan / request to this file "
            f"so it RECOMPILES with apktool. Output ONLY the complete new content of {os.path.basename(tgt)} in a "
            f"single ``` code block -- no prose.")
    usr = f"PLAN / REQUEST:\n{plan_txt}\n\nCURRENT FILE {tgt}:\n```\n{cur}\n```"
    resp = _ask(coder, sysp, usr, maxtok=4000)
    newc = _extract_code(resp)
    if not newc:
        print("[rewrite] coder returned no code block"); return None
    fixes = os.path.join(HERE, "apk_edits"); os.makedirs(fixes, exist_ok=True)
    local = os.path.join(fixes, f"{name}_{os.path.basename(tgt)}")
    open(local, "w", encoding="utf-8").write(newc)
    rc, out, err = _kali(f"echo {base64.b64encode(newc.encode()).decode()} | base64 -d > '{tgt}' && echo WROTE",
                         timeout=120)
    ok = "WROTE" in out
    print(f"[rewrite] {coder} -> {tgt} ({'written' if ok else 'FAILED'}); local copy: {local}")
    return {"target": tgt, "coder": coder, "ok": ok, "local": local}


# ---------------- 5. rebuild + sign ----------------
def rebuild(name, sign=True):
    wd = f"{WORK}/{name}"
    ks, out_apk = f"{wd}/debug.keystore", f"{wd}/{name}.patched.apk"
    # board-flagged: use aapt2 (newer targetSdk), and warn on .aab/split (apktool can't rebuild those).
    steps = [f"set -e; cd {wd}",
             f"echo '[apktool b] recompiling (aapt2)...'; apktool b --use-aapt2 -f -o {wd}/unsigned.apk apktool "
             f">{wd}/build.log 2>&1 || apktool b -f -o {wd}/unsigned.apk apktool >>{wd}/build.log 2>&1 "
             f"|| (echo BUILD_FAIL; tail -8 {wd}/build.log; exit 1)",
             f"zipalign -f -p 4 {wd}/unsigned.apk {wd}/aligned.apk >/dev/null 2>&1 || cp {wd}/unsigned.apk {wd}/aligned.apk"]
    if sign:
        steps += [f"test -f {ks} || keytool -genkeypair -keystore {ks} -storepass android -keypass android "
                  f"-alias a -keyalg RSA -keysize 2048 -validity 3650 -dname 'CN=aegis-apk' >/dev/null 2>&1",
                  f"apksigner sign --ks {ks} --ks-pass pass:android --key-pass pass:android --out {out_apk} "
                  f"{wd}/aligned.apk >/dev/null 2>&1 && echo SIGNED",
                  f"apksigner verify {out_apk} >/dev/null 2>&1 && echo VERIFIED || echo VERIFY_FAIL"]
    else:
        steps += [f"cp {wd}/aligned.apk {out_apk}; echo UNSIGNED"]
    steps.append(f"ls -la {out_apk} 2>/dev/null && echo OUT={out_apk}")
    rc, out, err = _kali("; ".join(steps), timeout=1800)
    print(out)
    if "BUILD_FAIL" in out:
        print("[rebuild] apktool build FAILED (see build.log in the workdir)"); return {"ok": False}
    print(f"[rebuild] patched APK -> {out_apk} (in Kali)")
    return {"ok": True, "apk": out_apk, "signed": sign}


# ---------------- coordinator (DeepSeek in the seat instead of a human/Claude) ----------------
def coordinate(name, goal, coder=None, coordinator="deepseek-v4-pro", auto_rebuild=True):
    """Put an LLM (default DeepSeek) in the COORDINATOR seat: it turns the goal into a concrete recompilable
    change, has the BOARD plan it, picks the target file, has ONE coder execute, then reviews the rebuild.
    The coordinator OVERSEES; it does not write the final code itself (that stays the single coder's job)."""
    print(f"[coordinate] coordinator={coordinator}  coder={coder or 'deepseek-v4-pro'}  goal={goal!r}")
    ov = explore(name)
    wd = ov["workdir"]
    # 1. coordinator turns the goal into a concrete change request + a target hint (JSON).
    sysp = ("You are the COORDINATOR overseeing a modification of the owner's OWN decompiled Android app. You do "
            "NOT write the final code -- the board plans and ONE coder executes; you decide WHAT to change, WHERE, "
            "and whether the rebuild is acceptable. Given the app overview and the goal, output ONLY JSON: "
            '{"request": "<concrete change to make in the apktool smali/res/manifest tree>", '
            '"target_hint": "<class or file name to locate>"}.')
    dec = _ask(coordinator, sysp, f"GOAL:\n{goal}\n\nAPP OVERVIEW:\n{json.dumps(ov)[:3500]}", 900)
    d = _parse_json(dec)
    request = d.get("request") or goal
    hint = d.get("target_hint") or ""
    print(f"[coordinate] -> request: {request}\n[coordinate] -> target hint: {hint}")
    # 2. board decides the recompilable plan.
    plan(name, request)
    # 3. coordinator locates the concrete target file (from its hint, else the plan infers it).
    tgt = ""
    if hint:
        rc, out, err = _kali(f"find {wd}/apktool -iname '*{re.sub(r'[^A-Za-z0-9_.-]','',hint)}*' "
                             f"\\( -name '*.smali' -o -name '*.xml' \\) 2>/dev/null | head -1", timeout=120)
        tgt = out.strip().splitlines()[0] if out.strip() else ""
    # 4. one coder executes.
    rw = rewrite(name, request, coder=coder, target_file=tgt or None)
    if not rw or not rw.get("ok"):
        print("[coordinate] coder step did not land -- stopping before rebuild."); return {"ok": False, "stage": "rewrite"}
    # 5. rebuild + coordinator review.
    if not auto_rebuild:
        print("[coordinate] change written; rebuild skipped (auto_rebuild=False). Run `rebuild` to finish.")
        return {"ok": True, "stage": "rewrite", "target": rw["target"]}
    rb = rebuild(name)
    verdict = _ask(coordinator, "You are the coordinator. In ONE line say whether the change looks complete and "
                                "the APK rebuilt, or what to do next.",
                   f"request: {request}\nrewrite target: {rw['target']}\nrebuild ok: {rb.get('ok')} "
                   f"apk: {rb.get('apk','-')}", 300)
    print(f"[coordinate] verdict: {verdict.strip()[:400]}")
    return {"ok": rb.get("ok"), "target": rw["target"], "apk": rb.get("apk"), "verdict": verdict.strip()}


# ---------------- helpers ----------------
def _parse_json(txt):
    m = re.search(r"\{.*\}", txt or "", re.S)
    try:
        return json.loads(m.group(0)) if m else {}
    except Exception:
        return {}


def _extract_code(txt):
    m = re.search(r"```[a-zA-Z0-9_+-]*\n(.*?)```", txt or "", re.S)
    return (m.group(1) if m else "").strip()


def _infer_target(plan_txt, wd):
    m = re.search(r"([\w./-]+\.(?:smali|xml))", plan_txt or "")
    if not m:
        return ""
    cand = m.group(1)
    if cand.startswith("/"):
        return cand
    rc, out, err = _kali(f"find {wd}/apktool -path '*{cand}' 2>/dev/null | head -1", timeout=120)
    return out.strip().splitlines()[0] if out.strip() else ""


def main():
    import argparse
    ap = argparse.ArgumentParser(description="ANDROID de/compiler -- decompile, board-assisted modify, recompile")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("decompile"); p.add_argument("apk"); p.add_argument("--name"); p.add_argument("--no-jadx", action="store_true")
    p = sub.add_parser("explore"); p.add_argument("--name", required=True)
    p = sub.add_parser("plan"); p.add_argument("--name", required=True); p.add_argument("--request", required=True)
    p = sub.add_parser("rewrite"); p.add_argument("--name", required=True); p.add_argument("--request", required=True)
    p.add_argument("--coder"); p.add_argument("--target")
    p = sub.add_parser("rebuild"); p.add_argument("--name", required=True); p.add_argument("--no-sign", action="store_true")
    p = sub.add_parser("coordinate", help="DeepSeek (or --coordinator) in the seat: goal -> board plan -> one coder -> rebuild")
    p.add_argument("--name", required=True); p.add_argument("--goal", required=True)
    p.add_argument("--coder"); p.add_argument("--coordinator", default="deepseek-v4-pro")
    p.add_argument("--no-rebuild", action="store_true")
    a = ap.parse_args()
    if a.cmd == "decompile":
        print(json.dumps(decompile(a.apk, a.name, jadx=not a.no_jadx), indent=2))
    elif a.cmd == "explore":
        explore(a.name)
    elif a.cmd == "plan":
        plan(a.name, a.request)
    elif a.cmd == "rewrite":
        rewrite(a.name, a.request, coder=a.coder, target_file=a.target)
    elif a.cmd == "rebuild":
        rebuild(a.name, sign=not a.no_sign)
    elif a.cmd == "coordinate":
        print(json.dumps(coordinate(a.name, a.goal, coder=a.coder, coordinator=a.coordinator,
                                    auto_rebuild=not a.no_rebuild), indent=2, default=str))


if __name__ == "__main__":
    main()
