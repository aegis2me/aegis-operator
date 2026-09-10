"""android/android.py -- the ANDROID function: a STANDALONE aegis capability (peer to operator / exploitgym /
redteam, NOT wired into the operator hunt). Static analysis of an OWNED .apk, plus a board-driven fix loop that
recompiles the decompiled app back into an installable APK.

Doctrine, same as the rest of the suite: OWNED app only, contained, non-destructive to the original (we work
on a COPY in Kali; the input .apk is never modified). Decompile/recompile/sign run in Kali (jadx + apktool +
zipalign + apksigner); board/oracle calls run here (keys live in secret.env on this host).

Pipeline
--------
1. decompile   -- apktool d (smali + AndroidManifest + resources, RECOMPILABLE) + jadx (readable Java, for the
                  board to READ). Work in /root/apk_work/<name>/.
2. inspect     -- oracle-gated findings: SecretsOracle over the decompiled tree (hardcoded keys/tokens),
                  ManifestOracle (exported components / debuggable / allowBackup / cleartext), grype (bundled
                  dependency CVEs). Only verified findings count.
3. plan        -- the BOARD (panel) decides HOW to modify + recompile to fix a finding (consensus). The panel
                  reasons over the jadx Java (readable) but targets the apktool smali/resources (recompilable).
4. rewrite     -- ONE code writer (--coder, default deepseek-v4-pro) EXECUTES the board's plan: it emits the
                  exact edited smali/resource/manifest file, which is written into the apktool tree.
5. rebuild     -- apktool b -> zipalign -> apksigner (with a generated debug keystore) -> a patched, installable
                  <name>.patched.apk.

So: the board decides, one coder executes, and the decompiled files compile back into an APK -- exactly the
mobile analogue of the mirror-side remediation code-writer loop.

Which coders (board self-ranks per app; these are the defaults): decompiled Android code is messy (jadx synthetic
names, smali). deepseek-v4-pro + qwen2.5-coder-32b are strongest at Java/Kotlin/smali generation; r1-distill for
reasoning over obfuscated logic; llama-4-scout for breadth. gpt-oss stay REVIEWERS, not the executor.

Usage:
    python android/android.py all      /path/app.apk
    python android/android.py decompile /path/app.apk [--name app]
    python android/android.py inspect   --name app
    python android/android.py plan      --name app --finding <id>
    python android/android.py rewrite   --name app --finding <id> --coder deepseek-v4-pro
    python android/android.py rebuild   --name app [--sign]
"""
from __future__ import annotations
import os, sys, json, subprocess, re, time, platform

HERE = os.path.dirname(os.path.abspath(__file__))        # android/  (ANDROID is its own function, not the operator)
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "operator"))       # reuse board_ask / cf_agent (board + one-coder calls)
sys.path.insert(0, os.path.join(ROOT, "shared"))         # reuse verified_findings oracles (SecretsOracle)

KALI = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
WORK = "/root/apk_work"                                   # in-Kali working root
_TEXT_EXT = (".smali", ".java", ".xml", ".json", ".properties", ".txt", ".kt", ".cfg", ".gradle", ".pro")


# ---------------- Kali shell ----------------
def _kali(cmd, timeout=1800):
    """Run a bash command in the Kali distro. Handles nested-wsl (already inside Kali) vs host->wsl."""
    if platform.system() == "Windows":
        full = ["wsl", "-d", KALI, "-u", "root", "--", "bash", "-lc", cmd]
        env = dict(os.environ, MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")
    else:
        full = ["bash", "-lc", cmd]                       # already in Kali
        env = dict(os.environ)
    r = subprocess.run(full, capture_output=True, text=True, timeout=timeout, env=env)
    return r.returncode, r.stdout, r.stderr


def _win_to_kali_path(p):
    """C:\\x\\y -> /mnt/c/x/y so a Windows-path .apk is reachable inside Kali."""
    if platform.system() != "Windows":
        return p
    p = p.replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", p)
    return f"/mnt/{m.group(1).lower()}/{m.group(2)}" if m else p


# ---------------- 1. decompile ----------------
def decompile(apk_path, name=None):
    name = name or re.sub(r"\.apk$", "", os.path.basename(apk_path), flags=re.I)
    kapk = _win_to_kali_path(apk_path)
    wd = f"{WORK}/{name}"
    script = (
        f"set -e; mkdir -p {wd}; cp '{kapk}' {wd}/orig.apk; "
        f"echo '[apktool] decompiling smali+resources (recompilable)...'; "
        f"rm -rf {wd}/apktool; apktool d -f -o {wd}/apktool {wd}/orig.apk >/dev/null 2>{wd}/apktool.log || "
        f"  (echo APKTOOL_FAIL; tail -5 {wd}/apktool.log); "
        f"echo '[jadx] decompiling Java (readable, for the board)...'; "
        f"rm -rf {wd}/jadx; jadx -d {wd}/jadx {wd}/orig.apk >/dev/null 2>{wd}/jadx.log || "
        f"  (echo JADX_PARTIAL; tail -3 {wd}/jadx.log); "
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


# ---------------- 2. inspect (oracle-gated) ----------------
def _read_kali_file(path, max_bytes=200000):
    rc, out, err = _kali(f"head -c {max_bytes} '{path}' 2>/dev/null", timeout=120)
    return out if rc == 0 else ""


def _list_kali(pattern, wd, limit=4000):
    rc, out, err = _kali(f"find {wd} -type f \\( {pattern} \\) 2>/dev/null | head -{limit}", timeout=180)
    return [l for l in out.splitlines() if l.strip()]


def inspect(name):
    wd = f"{WORK}/{name}"
    findings = []

    # 2a. SECRETS -- scan the readable Java + resources for hardcoded keys/tokens.
    try:
        from verified_findings import SecretsOracle
    except Exception as e:
        SecretsOracle = None
        print(f"[warn] SecretsOracle unavailable: {e}")
    scanned = 0
    if SecretsOracle:
        cand = _list_kali(r"-name '*.java' -o -name '*.xml' -o -name '*.properties' -o -name '*.json'",
                          f"{wd}/jadx {wd}/apktool/res {wd}/apktool/assets", limit=3000)
        # prioritise likely-secret files first, cap the number we pull across the wsl boundary
        cand.sort(key=lambda p: (("strings.xml" not in p) and ("BuildConfig" not in p) and
                                 ("config" not in p.lower()) and ("secret" not in p.lower())))
        for f in cand[:250]:
            body = _read_kali_file(f)
            if not body:
                continue
            scanned += 1
            try:
                ok, receipt = SecretsOracle(body, surface=f, oracle_id="apk.secrets@1").check()
                if ok:
                    findings.append({"class": "hardcoded-secret", "severity": "high", "surface": f,
                                     "oracle": "apk.secrets", "receipt": receipt})
            except Exception:
                pass

    # 2b. MANIFEST -- exported components / debuggable / allowBackup / cleartext.
    manifest = _read_kali_file(f"{wd}/apktool/AndroidManifest.xml", max_bytes=400000)
    findings += _manifest_findings(manifest, f"{wd}/apktool/AndroidManifest.xml")

    # 2c. DEPENDENCY CVEs -- grype the original apk (bundled libs).
    rc, out, err = _kali(f"command -v grype >/dev/null && grype {wd}/orig.apk -o json 2>/dev/null | "
                         f"python3 -c \"import sys,json;d=json.load(sys.stdin);m=d.get('matches',[]);"
                         f"print(json.dumps({{'count':len(m),'top':[{{'pkg':x['artifact']['name'],"
                         f"'ver':x['artifact']['version'],'cve':x['vulnerability']['id'],"
                         f"'sev':x['vulnerability']['severity']}} for x in m[:8]]}}))\" || echo '{{}}'",
                         timeout=600)
    try:
        g = json.loads((out or "{}").strip().splitlines()[-1]) if out.strip() else {}
    except Exception:
        g = {}
    if g.get("count"):
        findings.append({"class": "supply-chain/known-cve", "severity": "high",
                         "surface": f"{name}.apk (bundled deps)", "oracle": "grype", "receipt": g})

    # persist
    out_path = os.path.join(HERE, f"apk_findings_{name}.json")
    for i, f in enumerate(findings):
        f["id"] = f"apk-{name}-{i+1}"
    json.dump({"name": name, "workdir": wd, "scanned_files": scanned, "findings": findings},
              open(out_path, "w", encoding="utf-8"), indent=2)
    print(f"[inspect] {name}: {len(findings)} finding(s) over {scanned} scanned files -> {out_path}")
    for f in findings:
        print(f"  [{f['id']}] {f['severity'].upper():5} {f['class']:24} {f['surface']}")
    return {"name": name, "findings": findings, "out": out_path}


_EXPORTED = re.compile(r"<(activity|service|receiver|provider)\b[^>]*android:exported=\"true\"[^>]*>", re.I)
_NAME_ATTR = re.compile(r'android:name="([^"]+)"')


def _manifest_findings(manifest, surface):
    out = []
    if not manifest or "<manifest" not in manifest:
        return out
    if re.search(r'android:debuggable="true"', manifest, re.I):
        out.append({"class": "android/debuggable", "severity": "high", "surface": surface,
                    "oracle": "manifest", "receipt": {"flag": "android:debuggable=true"}})
    if re.search(r'android:allowBackup="true"', manifest, re.I) or ("allowBackup" not in manifest):
        out.append({"class": "android/backup-allowed", "severity": "medium", "surface": surface,
                    "oracle": "manifest", "receipt": {"flag": "allowBackup not disabled"}})
    if re.search(r'android:usesCleartextTraffic="true"', manifest, re.I):
        out.append({"class": "android/cleartext-traffic", "severity": "medium", "surface": surface,
                    "oracle": "manifest", "receipt": {"flag": "usesCleartextTraffic=true"}})
    for m in _EXPORTED.finditer(manifest):
        blk = m.group(0)
        if "android:permission=" not in blk:                # exported AND unprotected
            nm = _NAME_ATTR.search(blk)
            out.append({"class": "android/exported-component", "severity": "medium", "surface": surface,
                        "oracle": "manifest",
                        "receipt": {"component": m.group(1), "name": nm.group(1) if nm else "?",
                                    "note": "exported=true with no android:permission guard"}})
    return out


# ---------------- board + coder calls ----------------
def _ask(model, system, user, maxtok=2600):
    """One synchronous LLM call. DeepSeek-direct for ds/deepseek*, Cloudflare for the rest."""
    ml = model.lower()
    if ml.startswith("ds") or "deepseek-v4" in ml or ml == "deepseek":
        import board_ask
        key = os.environ.get("AEGIS_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
        ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
        mdl = "deepseek-v4-pro" if "pro" in ml or ml in ("ds", "deepseek") else model
        return board_ask._post(ep + "/chat/completions", key, mdl, system, user, maxtok,
                               extra={"thinking": {"type": "disabled"}})
    import cf_agent
    return cf_agent.ask(cf_agent.resolve(model), system, user, max_tokens=maxtok, temperature=0.3)


_PLAN_PANEL = os.environ.get("AEGIS_APK_PANEL", "deepseek-v4-pro,qwen2.5-coder-32b,llama-4-scout").split(",")


def plan(name, finding_id, panel=None):
    """The BOARD decides HOW to modify + recompile to fix the finding (per-model takes + a consensus)."""
    data = json.load(open(os.path.join(HERE, f"apk_findings_{name}.json"), encoding="utf-8"))
    f = next((x for x in data["findings"] if x["id"] == finding_id), None)
    if not f:
        print(f"[plan] no finding {finding_id}"); return None
    wd = data["workdir"]
    # give the board the readable Java around the finding (jadx), but tell it to target smali (recompilable)
    ctx = _read_kali_file(f["surface"], max_bytes=6000) if f["surface"].endswith((".java", ".xml")) else ""
    sysp = ("You are on a mobile-security board reviewing the owner's OWN app (authorized, contained). Decide "
            "HOW to fix the finding so the DECOMPILED app can be RECOMPILED with apktool. The readable code is "
            "jadx Java, but the edit must land in the apktool tree (smali or res/AndroidManifest). Be concrete: "
            "which file, what change, and any manifest/resource change. Output a short numbered plan only.")
    brief = (f"FINDING {finding_id}: {f['class']} (severity {f['severity']}) at {f['surface']}\n"
             f"receipt: {json.dumps(f.get('receipt',{}))[:500]}\n\ncode context (jadx):\n{ctx[:4000]}")
    takes = {}
    panel = panel or _PLAN_PANEL
    for m in panel:
        try:
            takes[m] = _ask(m, sysp, brief, maxtok=1200)
            print(f"  [{m}] plan ({len(takes[m])}b)")
        except Exception as e:
            print(f"  [{m}] plan skipped: {e}")
    # consensus (one synthesis call)
    syn = _ask(panel[0], "Synthesize the panel plans into ONE concrete, minimal, recompilable fix plan. "
                         "Numbered steps; name exact files. Output only the plan.",
               "\n\n".join(f"## {k}\n{v}" for k, v in takes.items()), maxtok=1400)
    plan_path = os.path.join(HERE, f"apk_plan_{name}_{finding_id}.md")
    open(plan_path, "w", encoding="utf-8").write(f"# Fix plan {finding_id} ({f['class']})\n\n## Consensus\n{syn}\n\n"
                                                 + "\n".join(f"## {k}\n{v}" for k, v in takes.items()))
    print(f"[plan] consensus -> {plan_path}")
    return {"finding": f, "plan": syn, "plan_path": plan_path}


def rewrite(name, finding_id, coder=None, target_file=None):
    """ONE code writer EXECUTES the board's plan: emit the exact edited apktool file, write it into the tree."""
    coder = coder or os.environ.get("AEGIS_APK_CODER", "deepseek-v4-pro")
    data = json.load(open(os.path.join(HERE, f"apk_findings_{name}.json"), encoding="utf-8"))
    wd = data["workdir"]
    plan_path = os.path.join(HERE, f"apk_plan_{name}_{finding_id}.md")
    if not os.path.exists(plan_path):
        print(f"[rewrite] no plan for {finding_id}; run `plan` first"); return None
    plan_txt = open(plan_path, encoding="utf-8").read()[:4000]
    # the executor targets a smali/manifest/res file (recompilable). If the plan names one, use it.
    tgt = target_file or _infer_target(plan_txt, wd)
    if not tgt:
        print("[rewrite] could not infer a recompilable target file; pass --target"); return None
    cur = _read_kali_file(tgt, max_bytes=12000)
    sysp = (f"You are the single code writer for the owner's OWN app. Apply the board's plan to this file so it "
            f"RECOMPILES with apktool. Output ONLY the complete new file content for {os.path.basename(tgt)} "
            f"inside a single ``` code block -- no prose.")
    usr = f"BOARD PLAN:\n{plan_txt}\n\nCURRENT FILE {tgt}:\n```\n{cur}\n```"
    resp = _ask(coder, sysp, usr, maxtok=4000)
    newc = _extract_code(resp)
    if not newc:
        print("[rewrite] coder returned no code block"); return None
    # write into the apktool tree (in Kali) via a heredoc
    fixes_dir = os.path.join(HERE, "apk_fixes"); os.makedirs(fixes_dir, exist_ok=True)
    local_copy = os.path.join(fixes_dir, f"{name}_{finding_id}_{os.path.basename(tgt)}")
    open(local_copy, "w", encoding="utf-8").write(newc)
    b64 = _b64(newc)
    rc, out, err = _kali(f"echo {b64} | base64 -d > '{tgt}' && echo WROTE", timeout=120)
    ok = "WROTE" in out
    print(f"[rewrite] {coder} -> {tgt} ({'written' if ok else 'FAILED'}); copy: {local_copy}")
    return {"target": tgt, "coder": coder, "ok": ok, "local": local_copy}


# ---------------- 5. rebuild + sign ----------------
def rebuild(name, sign=True):
    wd = f"{WORK}/{name}"
    ks = f"{wd}/debug.keystore"
    out_apk = f"{wd}/{name}.patched.apk"
    steps = [f"set -e; cd {wd}",
             f"echo '[apktool b] recompiling...'; apktool b -f -o {wd}/unsigned.apk apktool >{wd}/build.log 2>&1 || "
             f"  (echo BUILD_FAIL; tail -8 {wd}/build.log; exit 1)",
             f"zipalign -f -p 4 {wd}/unsigned.apk {wd}/aligned.apk >/dev/null 2>&1 || cp {wd}/unsigned.apk {wd}/aligned.apk"]
    if sign:
        steps += [
            f"test -f {ks} || keytool -genkeypair -keystore {ks} -storepass android -keypass android "
            f"-alias a -keyalg RSA -keysize 2048 -validity 3650 -dname 'CN=aegis-apk-test' >/dev/null 2>&1",
            f"apksigner sign --ks {ks} --ks-pass pass:android --key-pass pass:android "
            f"--out {out_apk} {wd}/aligned.apk >/dev/null 2>&1 && echo SIGNED",
            f"apksigner verify {out_apk} >/dev/null 2>&1 && echo VERIFIED || echo VERIFY_FAIL"]
    else:
        steps += [f"cp {wd}/aligned.apk {out_apk}; echo UNSIGNED"]
    steps.append(f"ls -la {out_apk} 2>/dev/null && echo OUT={out_apk}")
    rc, out, err = _kali("; ".join(steps), timeout=1800)
    print(out)
    if "BUILD_FAIL" in out:
        print("[rebuild] apktool build FAILED (see build.log in the workdir)")
        return {"ok": False}
    print(f"[rebuild] patched APK -> {out_apk}  (in Kali; copy out with: docker cp / wsl cp as needed)")
    return {"ok": True, "apk": out_apk, "signed": sign}


# ---------------- helpers ----------------
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


def _b64(s):
    import base64
    return base64.b64encode(s.encode()).decode()


def main():
    import argparse
    ap = argparse.ArgumentParser(description="AEGIS Android leg: decompile/inspect + board-decides/one-coder-executes recompile")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("decompile"); p.add_argument("apk"); p.add_argument("--name")
    p = sub.add_parser("inspect"); p.add_argument("--name", required=True)
    p = sub.add_parser("plan"); p.add_argument("--name", required=True); p.add_argument("--finding", required=True)
    p = sub.add_parser("rewrite"); p.add_argument("--name", required=True); p.add_argument("--finding", required=True)
    p.add_argument("--coder"); p.add_argument("--target")
    p = sub.add_parser("rebuild"); p.add_argument("--name", required=True); p.add_argument("--sign", action="store_true", default=True)
    p = sub.add_parser("all"); p.add_argument("apk"); p.add_argument("--name")
    a = ap.parse_args()
    if a.cmd == "decompile":
        print(json.dumps(decompile(a.apk, a.name), indent=2))
    elif a.cmd == "inspect":
        inspect(a.name)
    elif a.cmd == "plan":
        plan(a.name, a.finding)
    elif a.cmd == "rewrite":
        rewrite(a.name, a.finding, coder=a.coder, target_file=a.target)
    elif a.cmd == "rebuild":
        rebuild(a.name, sign=a.sign)
    elif a.cmd == "all":
        d = decompile(a.apk, a.name); inspect(d["name"])
        print("\nNext: `plan --finding <id>` -> `rewrite --finding <id>` -> `rebuild`.")


if __name__ == "__main__":
    main()
