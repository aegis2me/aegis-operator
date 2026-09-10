#!/usr/bin/env python3
"""
fuzzer.py -- THE FUZZER: grey-box, coverage-guided fuzzing for the Aegis stack.

Distinct from the black-box `fuzz` vector (operator/vectors.py, which probes a RUNNING mirror over the
wire). THE FUZZER is GREY-BOX: it needs the mirror's BUILDABLE SOURCE and drives Google's OSS-Fuzz
tooling -- the same open-source engines + build harness OSS-Fuzz/ClusterFuzzLite use -- entirely inside
our contained Kali/Docker sandbox. Google's HOSTED OSS-Fuzz is NOT used (it only accepts public OSS);
we self-host the tooling on the owner's OWN private mirror. (Board-consulted; see the OSS-Fuzz thread.)

Pipeline (the standard OSS-Fuzz local flow, mirroring infra/helper.py):
    scaffold  -> write a project (Dockerfile + build.sh + a harness template + project.yaml)
    build     -> base-builder image `compile`s the harness into fuzz-target binaries ($OUT)
    run       -> base-runner `run_fuzzer` for a BOUNDED time; crashes captured via -artifact_prefix
    triage    -> `reproduce` each crash deterministically -> candidate findings for the shared oracle
    interpret -> (board=True) each UNIQUE crash goes to the BOARD: coders propose root-cause/fix/harness
                 improvement, the qwq-32b consultant consolidates severity + exploitability + dedup.
                 The oracle owns TRUTH (does it crash?); the board owns MEANING (what / how bad / fix).

Engines: libFuzzer (default) | AFL++ (`afl`) | Honggfuzz (`honggfuzz`). Sanitizers: address | undefined |
memory. Languages: c++ (base-builder) | python (base-builder-python + Atheris) | go | rust | jvm (Jazzer) |
**js/ts (Jazzer.js -- native npm, no OSS-Fuzz image; scaffold/build/run via node)**. Proven grey-box on
a real Node/JS parser (the mirror's own).

DOCTRINE: contained (all Docker inside Kali); NON-DESTRUCTIVE (fuzzes a harness in a throwaway container,
never the real target); a crash is EVIDENCE, verified only when it REPRODUCES. The ONE egress is pulling
the `gcr.io/oss-fuzz-base/*` base images -- gated by AEGIS_OSSFUZZ_PULL=1 (off by default: images must be
pre-pulled, so a run never reaches out unexpectedly). Grey-box -> only where we have buildable source.

CLI:
    python fuzzer.py check
    python fuzzer.py scaffold myapp --language c++            # writes a project skeleton to fill in
    python fuzzer.py build    myapp --engine libfuzzer
    python fuzzer.py run      myapp parse_fuzzer --seconds 120
    python fuzzer.py triage   myapp parse_fuzzer --json
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys

WSL_DISTRO = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
WORK = os.environ.get("AEGIS_OSSFUZZ_WORK", "/opt/aegis-ossfuzz")   # Kali-side workspace
PULL_OK = os.environ.get("AEGIS_OSSFUZZ_PULL") == "1"              # allow pulling base images (egress)

BASE_BUILDER = {"c++": "gcr.io/oss-fuzz-base/base-builder",
                "c": "gcr.io/oss-fuzz-base/base-builder",
                "python": "gcr.io/oss-fuzz-base/base-builder-python",
                "go": "gcr.io/oss-fuzz-base/base-builder-go",
                "rust": "gcr.io/oss-fuzz-base/base-builder-rust",
                "jvm": "gcr.io/oss-fuzz-base/base-builder-jvm"}
BASE_RUNNER = "gcr.io/oss-fuzz-base/base-runner"
ENGINES = ("libfuzzer", "afl", "honggfuzz")
SANITIZERS = ("address", "undefined", "memory")

# JavaScript/TypeScript grey-box fuzzing uses Jazzer.js (npm), NOT the OSS-Fuzz base images -- it runs
# natively with node (proven against a real dependency-free Node parser). Different build/run path.
_JS_LANGS = {"js", "javascript", "node", "ts", "typescript"}
_JS_HARNESS = '''// Jazzer.js fuzz harness. Import the module under test (drop it beside this file, or point the
// import at a compiled dist file) and exercise ONE untrusted-input entry point with the fuzzer bytes.
// Uncaught exceptions AND slow units (ReDoS) are reported as findings.
import { parseFreeText } from "./target.js";   // TODO: import your real target module + function

export function fuzz(data) {
  const s = data.toString();
  parseFreeText(s, 2026);                        // TODO: call the function(s) under test
}
'''


def _kali(cmd: str, timeout: int = 900) -> tuple:
    """Run a shell command inside Kali WSL (root). Returns (rc, combined_output)."""
    try:
        p = subprocess.run(["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd],
                           capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout)   # utf-8 pinned: text=True defaults to cp1252 on Windows
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return -1, f"[kali error: {e}]"


# ------------------------------------------------------------------ scaffolding templates
_HARNESS_CPP = r'''// Fuzz harness (libFuzzer/AFL++/Honggfuzz compatible). Build in build.sh.
// Exercise ONE entry point of the target with the fuzzer-provided bytes.
#include <stdint.h>
#include <stddef.h>

// TODO: include your target's headers and call the function under test.
// extern "C" int target_parse(const uint8_t *buf, size_t len);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    // TODO: feed `data`/`size` into the code path you want to fuzz.
    // target_parse(data, size);
    return 0;  // non-zero is reserved; return 0
}
'''

_HARNESS_PY = r'''#!/usr/bin/env python3
# Atheris (Python) fuzz harness. build.sh compiles this with `compile_python_fuzzer`.
import atheris
import sys

# TODO: import the module under test (installed into $SRC by build.sh / the Dockerfile)
# import mytarget

def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    s = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    # TODO: call the function under test with `s` / structured inputs from fdp.
    # mytarget.parse(s)

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
'''

_BUILD_CPP = r'''#!/bin/bash -eu
# OSS-Fuzz build script. $CC/$CXX/$CFLAGS/$CXXFLAGS/$LIB_FUZZING_ENGINE/$OUT are set by the base image.
# 1) build the target (its own build system), then 2) compile the harness and LINK the fuzzing engine.

# --- 1) build the target library under test (edit to match your project) ---
# cd $SRC/PROJECT && make -j$(nproc) libtarget.a

# --- 2) build each fuzz target ---
$CXX $CXXFLAGS -std=c++17 -I"$SRC/PROJECT" \
    "$SRC/PROJECT/harness.cc" -o "$OUT/parse_fuzzer" \
    $LIB_FUZZING_ENGINE  # add: "$SRC/PROJECT/libtarget.a"

# --- 3) (optional) ship a seed corpus + dictionary next to the binary ---
# cp "$SRC/PROJECT/seeds.zip" "$OUT/parse_fuzzer_seed_corpus.zip"
# cp "$SRC/PROJECT/parse.dict" "$OUT/parse_fuzzer.dict"
'''

_BUILD_PY = r'''#!/bin/bash -eu
# OSS-Fuzz Python build script (Atheris). Installs the target, then compiles the harness.
pip3 install --no-cache-dir "$SRC/PROJECT"          # install the module under test
compile_python_fuzzer "$SRC/PROJECT/harness.py"     # -> $OUT/harness (Atheris-instrumented)
# cp "$SRC/PROJECT/seeds.zip" "$OUT/harness_seed_corpus.zip"
'''

_DOCKERFILE = '''# The Fuzzer -- OSS-Fuzz project image. Grey-box: builds the owner's OWN mirror source, contained.
FROM {base}
# TODO: install the target's build deps, e.g.:
# RUN apt-get update && apt-get install -y libssl-dev && rm -rf /var/lib/apt/lists/*
COPY . $SRC/{name}
WORKDIR $SRC/{name}
COPY build.sh $SRC/
'''

_PROJECT_YAML = '''# The Fuzzer project config (subset of OSS-Fuzz project.yaml). LOCAL/contained use only --
# NOT submitted to Google's hosted OSS-Fuzz (private target).
homepage: "local-mirror"
language: {language}
primary_contact: "owner@local"
main_repo: "local"
sanitizers:
  - address
fuzzing_engines:
  - libfuzzer
'''


# $OUT also collects toolchain/helper binaries (llvm-symbolizer; the whole afl-*/*.so suite for AFL++) --
# filter them so only real fuzz targets are listed.
_HELPER_PREFIXES = ("afl-", "llvm-", "jazzer_")
_HELPER_SUFFIXES = (".so", ".bash", ".py", ".a", ".o", ".txt", ".options", ".dict", ".zip")
_HELPER_EXACT = {"llvm-symbolizer", "sancov", "afl-fuzz"}


def _is_fuzz_target(fn: str) -> bool:
    return not (fn in _HELPER_EXACT or fn.startswith(_HELPER_PREFIXES) or fn.endswith(_HELPER_SUFFIXES))


def _proj_dir(name: str) -> str:
    return f"{WORK}/projects/{name}"


def _out_dir(name: str) -> str:
    return f"{WORK}/build/out/{name}"


def scaffold(name: str, language: str = "c++") -> dict:
    """Write a project skeleton (Dockerfile + build.sh + harness + project.yaml) into the Kali
    workspace for the operator/board to fill in against a specific mirror entry point."""
    if language in _JS_LANGS:
        pdir = _proj_dir(name)
        import base64
        files = {"package.json": '{"name":"%s-fuzz","type":"module","private":true}\n' % name,
                 "harness.js": _JS_HARNESS}
        cmds = [f"mkdir -p {shlex.quote(pdir + '/corpus')}"]
        for fn, content in files.items():
            cmds.append(f"echo {base64.b64encode(content.encode()).decode()} | base64 -d > {shlex.quote(pdir + '/' + fn)}")
        rc, out = _kali(" && ".join(cmds), 120)
        if rc != 0:
            return {"error": f"scaffold failed: {out[-300:]}", "project_dir": pdir}
        return {"ok": True, "project_dir": pdir, "language": "js", "files": list(files),
                "next": f"put the target module (or a compiled dist .js) in {pdir}, fix the import in "
                        f"harness.js, then `build {name} --language js`"}
    if language not in BASE_BUILDER:
        return {"error": f"unsupported language {language!r}; pick one of {sorted(BASE_BUILDER)}"}
    pdir = _proj_dir(name)
    harness_name, harness = (("harness.py", _HARNESS_PY) if language == "python"
                             else ("harness.cc", _HARNESS_CPP))
    build = _BUILD_PY if language == "python" else _BUILD_CPP
    dockerfile = _DOCKERFILE.format(base=BASE_BUILDER[language], name=name)
    project_yaml = _PROJECT_YAML.format(language=language)
    # write each file in Kali via a base64 pipe (avoids host<->WSL quoting issues)
    import base64
    files = {"Dockerfile": dockerfile, "build.sh": build.replace("PROJECT", name),
             harness_name: harness, "project.yaml": project_yaml}
    cmds = [f"mkdir -p {shlex.quote(pdir)}"]
    for fn, content in files.items():
        b64 = base64.b64encode(content.encode()).decode()
        cmds.append(f"echo {b64} | base64 -d > {shlex.quote(pdir + '/' + fn)}")
    cmds.append(f"chmod +x {shlex.quote(pdir + '/build.sh')}")
    rc, out = _kali(" && ".join(cmds), 120)
    if rc != 0:
        return {"error": f"scaffold failed: {out[-300:]}", "project_dir": pdir}
    return {"ok": True, "project_dir": pdir, "files": list(files),
            "next": f"edit {pdir}/build.sh + {pdir}/{harness_name} for a real entry point, then `build {name}`"}


def check() -> dict:
    """Report grey-box fuzzing readiness inside Kali (docker + native engines + base images). NB each
    tool is named EXPLICITLY -- a `for t in ...; do echo $t ...` loop's var does not survive the
    Windows->WSL->bash marshalling (it comes back empty), same gotcha as vectors.fuzz()."""
    tool_checks = "; ".join(
        f"echo {t}=$(command -v {t} >/dev/null 2>&1 && echo present || echo MISSING)"
        for t in ("clang", "afl-fuzz", "honggfuzz"))
    rc, out = _kali(
        "echo docker=$(command -v docker >/dev/null 2>&1 && docker --version 2>/dev/null | head -c40 || echo MISSING); "
        f"{tool_checks}; "
        f"echo builder_img=$(docker image inspect {BASE_BUILDER['c++']} >/dev/null 2>&1 && echo present || echo not-pulled); "
        f"echo runner_img=$(docker image inspect {BASE_RUNNER} >/dev/null 2>&1 && echo present || echo not-pulled)", 60)
    info = dict(line.split("=", 1) for line in out.split("\n") if "=" in line)
    info["pull_allowed"] = PULL_OK
    info["work"] = WORK
    return info


def _ensure_image(image: str) -> tuple:
    """Make sure a base image is present; pull only if AEGIS_OSSFUZZ_PULL=1 (the one authorized egress)."""
    rc, _ = _kali(f"docker image inspect {shlex.quote(image)} >/dev/null 2>&1 && echo yes", 60)
    if "yes" in _:
        return True, "present"
    if not PULL_OK:
        return False, (f"{image} not pulled and AEGIS_OSSFUZZ_PULL!=1 (offline-safe: pre-pull it with "
                       f"`docker pull {image}` in Kali, or set AEGIS_OSSFUZZ_PULL=1 to allow the pull)")
    rc, out = _kali(f"docker pull {shlex.quote(image)}", 900)
    return (rc == 0), (out[-200:] if rc else "pulled")


def build(name: str, engine: str = "libfuzzer", sanitizer: str = "address", language: str = "c++") -> dict:
    """OSS-Fuzz local build: build the project image, then `compile` the harness into $OUT. JS builds
    are native (Jazzer.js via npm), no docker/base image."""
    if language in _JS_LANGS:
        pdir = _proj_dir(name)
        rc, _ = _kali(f"test -f {shlex.quote(pdir + '/harness.js')} && echo yes", 30)
        if "yes" not in _:
            return {"error": f"no JS project at {pdir}; run `scaffold {name} --language js` first"}
        rc, out = _kali(f"cd {shlex.quote(pdir)} && npm i --no-audit --no-fund --save-dev @jazzer.js/core 2>&1 | tail -3", 600)
        ok = "added" in out or "up to date" in out
        rc2, has = _kali(f"test -x {shlex.quote(pdir + '/node_modules/.bin/jazzer')} && echo yes", 30)
        if "yes" not in has:
            return {"error": f"jazzer.js not installed: {out[-300:]}"}
        return {"ok": True, "language": "js", "project": pdir, "fuzzers": ["harness"], "engine": "jazzer.js"}
    if engine not in ENGINES:
        return {"error": f"engine must be one of {ENGINES}"}
    if sanitizer not in SANITIZERS:
        return {"error": f"sanitizer must be one of {SANITIZERS}"}
    pdir = _proj_dir(name)
    rc, _ = _kali(f"test -f {shlex.quote(pdir + '/Dockerfile')} && echo yes", 30)
    if "yes" not in _:
        return {"error": f"no project at {pdir}; run `scaffold {name}` first"}
    base = BASE_BUILDER.get(language, BASE_BUILDER["c++"])
    ok, why = _ensure_image(base)
    if not ok:
        return {"error": f"base builder image: {why}", "offline_safe": True}
    img = f"aegis-fuzzer/{name}"
    odir = _out_dir(name)
    rc, out = _kali(f"docker build -t {shlex.quote(img)} -f {shlex.quote(pdir + '/Dockerfile')} {shlex.quote(pdir)}", 1800)
    if rc != 0:
        return {"error": f"image build failed: {out[-400:]}"}
    lang_env = "python" if language == "python" else ("c++" if language in ("c", "c++") else language)
    compile_cmd = (
        f"mkdir -p {shlex.quote(odir)} && docker run --rm "
        f"-e FUZZING_ENGINE={engine} -e SANITIZER={sanitizer} -e ARCHITECTURE=x86_64 "
        f"-e FUZZING_LANGUAGE={lang_env} -v {shlex.quote(odir)}:/out {shlex.quote(img)} compile")
    rc, out = _kali(compile_cmd, 1800)
    if rc != 0:
        return {"error": f"compile failed: {out[-500:]}", "image": img}
    rc, listing = _kali(f"find {shlex.quote(odir)} -maxdepth 1 -type f -executable -printf '%f\\n' 2>/dev/null", 60)
    fuzzers = [f for f in listing.split("\n") if f.strip() and _is_fuzz_target(f.strip())]
    return {"ok": True, "image": img, "out": odir, "fuzzers": fuzzers, "engine": engine, "sanitizer": sanitizer}


def _js_run(name: str, fuzzer: str, seconds: int) -> dict:
    """Native Jazzer.js run for a JS project (no docker). Bounded time + a per-unit timeout so ReDoS
    shows as a finding; crashes land as crash-* in the project dir (only NEW ones are reported)."""
    pdir = _proj_dir(name)
    _, pre = _kali(f"find {shlex.quote(pdir)} -maxdepth 1 -name 'crash-*' -printf '%f\\n' 2>/dev/null", 60)
    pre_set = {c for c in pre.split("\n") if c.strip()}
    cmd = (f"cd {shlex.quote(pdir)} && mkdir -p corpus && timeout {int(seconds)+90} "
           f"./node_modules/.bin/jazzer {shlex.quote(fuzzer)} corpus --sync -- "
           f"-max_total_time={int(seconds)} -timeout=5 -rss_limit_mb=2048 2>&1 | tail -35")
    rc, out = _kali(cmd, int(seconds) + 150)
    _, crash_ls = _kali(f"find {shlex.quote(pdir)} -maxdepth 1 -name 'crash-*' -printf '%f\\n' 2>/dev/null", 60)
    crashes = [c for c in crash_ls.split("\n") if c.strip() and c not in pre_set]
    return {"ok": True, "fuzzer": fuzzer, "seconds": seconds, "engine": "jazzer.js",
            "crashes": crashes, "crash_count": len(crashes), "log_tail": out[-1200:]}


def run(name: str, fuzzer: str, seconds: int = 120, engine: str = "libfuzzer",
        sanitizer: str = "address", corpus: str = None) -> dict:
    """Run one fuzz target for a BOUNDED time. JS projects use native Jazzer.js; others use base-runner
    (crashes captured via -artifact_prefix)."""
    _, isjs = _kali(f"test -x {shlex.quote(_proj_dir(name) + '/node_modules/.bin/jazzer')} && echo yes", 30)
    if "yes" in isjs:
        return _js_run(name, fuzzer, seconds)
    ok, why = _ensure_image(BASE_RUNNER)
    if not ok:
        return {"error": f"base runner image: {why}", "offline_safe": True}
    odir = _out_dir(name)
    rc, _ = _kali(f"test -x {shlex.quote(odir + '/' + fuzzer)} && echo yes", 30)
    if "yes" not in _:
        return {"error": f"fuzzer {fuzzer!r} not built in {odir}; run `build {name}` first"}
    cdir = corpus or f"{WORK}/corpus/{name}/{fuzzer}"
    # AUTO-SEED (OSS-Fuzz-Gen pattern via seed_gen): if the corpus is empty, drop in structure-aware
    # seeds so the fuzzer starts from meaningful inputs instead of empty (reaches deep paths far sooner).
    _, have = _kali(f"find {shlex.quote(cdir)} -type f 2>/dev/null | head -1", 30)
    if not have.strip():
        try:
            import seed_gen
            seed_gen.write_corpus(name, fuzzer, seed_gen.default_seeds(), distro=WSL_DISTRO)
        except Exception:
            pass
    # SNAPSHOT pre-existing crash artifacts so we report only crashes from THIS run (a leftover crash-*
    # from a prior run must NOT be counted as a new find -- that was a false positive across engines).
    _, pre = _kali(f"find {shlex.quote(odir)} -maxdepth 1 -name 'crash-*' -printf '%f\\n' 2>/dev/null", 60)
    pre_set = {c for c in pre.split("\n") if c.strip()}
    # ENGINE-AWARE args: -max_total_time / -artifact_prefix / -print_final_stats are libFuzzer-only and
    # make AFL++/Honggfuzz abort ("Bad syntax used for -m"). For those, drive the time via MAX_TOTAL_TIME
    # env (the OSS-Fuzz run_fuzzer wrapper reads it) and pass no libFuzzer flags.
    if engine == "libfuzzer":
        run_args = f"-max_total_time={int(seconds)} -artifact_prefix=/out/ -print_final_stats=1"
        time_env = ""
    else:
        run_args = ""
        time_env = f"-e MAX_TOTAL_TIME={int(seconds)} "
    cmd = (f"mkdir -p {shlex.quote(cdir)} && docker run --rm "
           f"-e FUZZING_ENGINE={engine} -e SANITIZER={sanitizer} -e ARCHITECTURE=x86_64 "
           f"-e RUN_FUZZER_MODE=interactive -e HELPER=True {time_env}"
           f"-v {shlex.quote(odir)}:/out -v {shlex.quote(cdir)}:/corpus "
           f"{BASE_RUNNER} run_fuzzer {shlex.quote(fuzzer)} {run_args} /corpus")
    rc, out = _kali(cmd, seconds + 300)
    # AFL++ writes crashes under /out/crashes/ (or the corpus); libFuzzer writes /out/crash-*. Scan both,
    # and count only NEW artifacts (not in the pre-run snapshot).
    _, crash_ls = _kali(f"find {shlex.quote(odir)} -maxdepth 2 \\( -name 'crash-*' -o -path '*/crashes/id*' \\) "
                        f"-printf '%f\\n' 2>/dev/null", 60)
    crashes = [c for c in crash_ls.split("\n") if c.strip() and c not in pre_set]
    aborted = "PROGRAM ABORT" in out or "unbound variable" in out
    return {"ok": not aborted, "fuzzer": fuzzer, "seconds": seconds, "engine": engine,
            "aborted": aborted, "crashes": crashes, "crash_count": len(crashes), "log_tail": out[-1200:]}


def reproduce(name: str, fuzzer: str, testcase: str) -> dict:
    """Deterministically re-run one crashing testcase (the fuzzing ORACLE). The base-runner `reproduce`
    reads the input from the mounted /testcase (NOT a positional arg), so we bind the crash file there.
    `reproduced` requires BOTH a non-zero exit AND a real sanitizer/crash signature -- a plain non-zero
    (e.g. an infra error like '/testcase not found') must NOT be mistaken for a reproduced crash."""
    ok, why = _ensure_image(BASE_RUNNER)
    if not ok:
        return {"error": f"base runner image: {why}", "offline_safe": True}
    odir = _out_dir(name)
    tc = f"{odir}/{testcase}"
    cmd = (f"docker run --rm -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e ARCHITECTURE=x86_64 "
           f"-e HELPER=True -v {shlex.quote(odir)}:/out -v {shlex.quote(tc)}:/testcase "
           f"{BASE_RUNNER} reproduce {shlex.quote(fuzzer)}")
    rc, out = _kali(cmd, 300)
    infra_err = "/testcase" in out and "not found" in out
    crash_sig = any(s in out for s in ("AddressSanitizer", "ERROR:", "SUMMARY:", "SEGV", "runtime error",
                                       "libFuzzer: deadly signal", "UndefinedBehaviorSanitizer", "abort"))
    reproduced = (rc != 0) and crash_sig and not infra_err
    # keep the meaningful crash lines (type / faulting op / SUMMARY) up front -- the raw tail is the
    # verbose ASan redzone legend, which would otherwise push the crash-type header out of the window.
    key = [ln for ln in out.splitlines()
           if any(s in ln for s in ("ERROR: ", "SUMMARY: ", "READ of size", "WRITE of size",
                                    "overflow", "in parse_", " in LLVMFuzzer", "#0 ", "#1 ", "#2 "))]
    trace = ("\n".join(key[:10]) + ("\n...\n" + out[-500:] if key else out[-900:])) if key else out[-900:]
    return {"testcase": testcase, "reproduced": reproduced, "signal": rc, "infra_error": infra_err,
            "trace_tail": trace[-1200:]}


def triage(name: str, fuzzer: str, board: bool = False) -> dict:
    """Reproduce every captured crash and emit CANDIDATE findings for the shared oracle. With
    board=True, each UNIQUE crash bucket is also sent to the board for INTERPRETATION (root cause /
    severity / exploitability / fix / harness improvement), attached to every finding in that bucket."""
    odir = _out_dir(name)
    rc, crash_ls = _kali(f"find {shlex.quote(odir)} -maxdepth 1 -name 'crash-*' -printf '%f\\n' 2>/dev/null", 60)
    crashes = [c for c in crash_ls.split("\n") if c.strip()]
    findings, by_bucket = [], {}
    for c in crashes:
        rep = reproduce(name, fuzzer, c)
        f = to_finding(name, fuzzer, c, rep)
        if board and f["reproduced"]:
            b = f["bucket"]
            if b not in by_bucket:                       # interpret ONCE per unique defect, not per dupe
                by_bucket[b] = interpret(name, fuzzer, c, rep)
            f["interpretation"] = by_bucket[b]
        findings.append(f)
    return {"fuzzer": fuzzer, "crash_count": len(crashes), "buckets": len(by_bucket) or None,
            "reproduced": sum(1 for f in findings if f["reproduced"]), "findings": findings}


# ------------------------------------------------------------------ board interpretation of a crash
_PROPOSER_SYS = (
    "You are a security engineer on the Aegis board triaging a GREY-BOX FUZZING crash in the owner's OWN "
    "code (an authorized, contained mirror). Given the sanitizer stack trace, the crash-bucket, the "
    "crashing-input SHAPE (bytes redacted for hygiene), and the harnessed source, give: ROOT CAUSE (the "
    "line/operation at fault), SEVERITY (info|low|med|high|critical), EXPLOITABILITY (is the faulting op an "
    "attacker-controllable WRITE / influenced length or index -> potential RCE, or a DoS-only abort, or "
    "benign?), a minimal CODE FIX, and a HARNESS/CORPUS improvement to reach deeper. Concise prose or short "
    "bullets; a tiny fix snippet is fine. This is DEFENSIVE triage -- no exploit code.")
_CONSULTANT_SYS = (
    "You are the board's CONSULTANT/VERIFIER. Consolidate the proposers' crash triage below into ONE verdict. "
    "Output MARKDOWN with exactly these headings: **Root cause**, **Severity** (info|low|med|high|critical + "
    "one-line why), **Exploitability** (controllable-write | DoS-only | benign), **Fix** (concrete), "
    "**Harness/corpus improvement**, **Dedup note**. Be decisive; drop speculation.")


def _sanitized_source(name: str) -> str:
    """Read the harnessed source (our OWN mirror code) for context, scrubbed of secret-looking lines."""
    pdir = _proj_dir(name)
    rc, src = _kali(f"for f in {shlex.quote(pdir)}/*.cc {shlex.quote(pdir)}/*.c {shlex.quote(pdir)}/*.py; "
                    f"do [ -f \"$f\" ] && echo \"### $f\" && sed -n '1,120p' \"$f\"; done 2>/dev/null", 60)
    try:
        import code_review
        return code_review._scrub(src)[:4000]
    except Exception:
        return src[:4000]


def interpret(name: str, fuzzer: str, testcase: str, rep: dict, panel=None,
              consultant: str = None) -> dict:
    """BOARD INTERPRETATION of a reproduced crash: coders propose root-cause/fix/harness-improvement, the
    qwq-32b consultant consolidates severity + exploitability + dedup. Offline-safe (a model that errors
    just doesn't contribute); posts each contribution to the file-blackboard. The DETERMINISTIC oracle
    still owns truth (does it crash?); the board owns MEANING (what / how bad / how to fix)."""
    panel = panel or ["ds", "qwen2.5-coder-32b", "llama-4-scout"]
    consultant = consultant or os.environ.get("AEGIS_ANALYST_MODEL", "qwq-32b")
    try:
        from code_review import _ask   # reuses the no-code-role router (DeepSeek thinking-off + CF-normalize)
    except Exception as e:
        return {"error": f"board unavailable: {e}"}
    trace = rep.get("trace_tail", "") or ""
    bucket = _bucket(trace)
    odir = _out_dir(name)
    rc, size = _kali(f"stat -c %s {shlex.quote(odir + '/' + testcase)} 2>/dev/null", 30)
    brief = (f"CRASH BUCKET: {bucket}\nFUZZER: {name}:{fuzzer}\n"
             f"CRASHING INPUT: {size.strip() or '?'} bytes (contents REDACTED for board hygiene)\n\n"
             f"SANITIZER STACK TRACE:\n{trace[-1800:]}\n\n"
             f"HARNESSED SOURCE (our own mirror code):\n{_sanitized_source(name)}")
    _board_post("FUZZ_CRASH", "operator", brief)
    from concurrent.futures import ThreadPoolExecutor

    def _one(m):
        try:
            out = _ask(m, _PROPOSER_SYS, brief, max_tokens=1400)
        except Exception as e:
            out = f"[error] {e}"
        _board_post("FUZZ_TRIAGE", m, out or "[empty]")
        return m, out
    proposals = {}
    with ThreadPoolExecutor(max_workers=max(1, len(panel))) as ex:   # proposers run concurrently
        for m, out in ex.map(_one, panel):
            proposals[m] = out
    blob = "\n\n".join(f"### {m}\n{t}" for m, t in proposals.items() if t and not t.startswith("[error]"))
    verdict = ""
    if blob:
        try:
            verdict = _ask(consultant, _CONSULTANT_SYS, "Proposer triage:\n" + blob, max_tokens=2200)
        except Exception as e:
            verdict = f"[error] {e}"
        _board_post("FUZZ_VERDICT", consultant, verdict or "[empty]")
    return {"bucket": bucket, "input_bytes": (size.strip() or None), "panel": panel,
            "consultant": consultant, "proposals": proposals, "verdict": verdict}


def _board_post(tag: str, who: str, text: str) -> None:
    """Post a contribution to the file-blackboard (same board_files/ the panel + live_board.ps1 use)."""
    import time
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    d = os.environ.get("AEGIS_BOARD_DIR", os.path.join(root, "board", "board_files"))
    try:
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"{tag}__{who}__{int(time.time()*1e9)}.md"), "w", encoding="utf-8") as fh:
            fh.write(f"# {tag} from {who}\n\n{text}")
    except Exception:
        pass


def _bucket(trace: str) -> str:
    """Crash-bucket key = hash of the top ~5 sanitizer stack frames -> dedup identical defects so the
    board interprets each UNIQUE crash once, not every duplicate testcase."""
    import hashlib, re
    frames = []
    for ln in (trace or "").splitlines():
        m = re.search(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+([^\s(]+)", ln)   # ASan "#N 0x.. in func" frame
        if m:
            frames.append(m.group(1))
        if len(frames) >= 5:
            break
    key = "|".join(frames) or (trace or "")[:120]
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def to_finding(name: str, fuzzer: str, testcase: str, rep: dict) -> dict:
    """Map a reproduced crash to a candidate-finding shape the shared oracle/ledger understands."""
    trace = rep.get("trace_tail", "") or ""
    cls = "memory-safety" if any(s in trace for s in ("AddressSanitizer", "heap-", "stack-", "SEGV",
                                                       "UndefinedBehaviorSanitizer", "runtime error")) else "crash"
    return {
        "action": "ossfuzz", "surface": f"{name}:{fuzzer}", "vuln_class": cls,
        "mechanism": f"grey-box fuzzing crash ({fuzzer})", "technique": "ossfuzz",
        "testcase": testcase, "reproduced": bool(rep.get("reproduced")), "bucket": _bucket(trace),
        "expected_oracle": "the crashing input reproduces the fault deterministically",
        "evidence": trace[-600:], "why_novel": f"fuzzer {fuzzer} found a reproducible crash",
        "seed": "fuzzer",
    }


def main():
    ap = argparse.ArgumentParser(description="The Fuzzer -- grey-box OSS-Fuzz tooling, contained in Kali.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    sp = sub.add_parser("scaffold"); sp.add_argument("name"); sp.add_argument("--language", default="c++")
    sp = sub.add_parser("build"); sp.add_argument("name"); sp.add_argument("--engine", default="libfuzzer")
    sp.add_argument("--sanitizer", default="address"); sp.add_argument("--language", default="c++")
    sp = sub.add_parser("run"); sp.add_argument("name"); sp.add_argument("fuzzer")
    sp.add_argument("--seconds", type=int, default=120); sp.add_argument("--engine", default="libfuzzer")
    sp.add_argument("--sanitizer", default="address"); sp.add_argument("--corpus", default=None)
    sp = sub.add_parser("triage"); sp.add_argument("name"); sp.add_argument("fuzzer")
    sp.add_argument("--board", action="store_true", help="also send each unique crash to the board to INTERPRET")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if a.cmd == "check":
        r = check()
    elif a.cmd == "scaffold":
        r = scaffold(a.name, a.language)
    elif a.cmd == "build":
        r = build(a.name, a.engine, a.sanitizer, a.language)
    elif a.cmd == "run":
        r = run(a.name, a.fuzzer, a.seconds, a.engine, a.sanitizer, a.corpus)
    elif a.cmd == "triage":
        r = triage(a.name, a.fuzzer, board=a.board)
    else:
        ap.error("unknown command")
    print(json.dumps(r, indent=2))
    sys.exit(1 if isinstance(r, dict) and r.get("error") else 0)


if __name__ == "__main__":
    main()
