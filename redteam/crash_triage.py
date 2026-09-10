"""
crash_triage.py -- crash -> exploitability pipeline for RED-TEAM mode (binary leg).

The fuzzers (afl++/honggfuzz) + ASAN are validated to FIND crashes; this turns a pile of crashes into
ranked, deduplicated, exploitability-scored findings -- the step elite researchers / commercial
fuzzing stacks do and that raw fuzzing does not. Exercised on the OWNED binary mirror; PoC
WEAPONIZATION is a separate, RoE-gated step (this only SCORES likely exploitability).

Pure + dependency-free; unit-testable from parsed ASAN/crash records.

A crash record: {"id","asan_error","access":"read|write|exec","faulting_func","pc_controlled":bool,"input":path}
"""
from __future__ import annotations

from collections import defaultdict

# ASAN/crash class -> (base exploitability 0-1, note). Writes/PC-control rank above reads/exhaustion.
_CLASS = {
    "heap-buffer-overflow": (0.75, "OOB heap access; write is likely exploitable"),
    "stack-buffer-overflow": (0.80, "OOB stack access; return-address overwrite likely"),
    "global-buffer-overflow": (0.55, "OOB global access"),
    "use-after-free": (0.85, "UAF; strong primitive (tcache/vtable) potential"),
    "double-free": (0.70, "double free; allocator corruption"),
    "SEGV": (0.60, "segfault; depends on control of the faulting address/PC"),
    "heap-use-after-return": (0.65, "use-after-return"),
    "stack-overflow": (0.15, "stack exhaustion (recursion); usually DoS, not control"),
    "null-deref": (0.10, "null-pointer deref; usually DoS"),
    "FPE": (0.10, "arithmetic fault; usually DoS"),
}


def signature(crash: dict) -> str:
    """Dedup signature: crash class + faulting function (the 'bucket' a triager groups by)."""
    return f"{crash.get('asan_error', '?')}::{crash.get('faulting_func', '?')}"


def exploitability(crash: dict) -> dict:
    base, note = _CLASS.get(crash.get("asan_error", ""), (0.3, "unknown class"))
    score = base
    if crash.get("access") == "write":
        score = min(1.0, score + 0.15)               # a controlled WRITE is the strong primitive
    elif crash.get("access") == "read":
        score = max(0.0, score - 0.15)
    if crash.get("pc_controlled"):
        score = min(1.0, score + 0.20)               # control of the instruction pointer
    label = "HIGH" if score >= 0.7 else "MEDIUM" if score >= 0.4 else "LOW"
    return {"score": round(score, 2), "label": label, "note": note}


def triage(crashes: list) -> dict:
    """Dedup by signature, keep the highest-exploitability representative per bucket, rank them."""
    buckets = defaultdict(list)
    for c in crashes:
        buckets[signature(c)].append(c)
    findings = []
    for sig, group in buckets.items():
        scored = sorted(((exploitability(c), c) for c in group), key=lambda x: -x[0]["score"])
        rep_score, rep = scored[0]
        findings.append({"signature": sig, "count": len(group), "representative": rep.get("id"),
                         "asan_error": rep.get("asan_error"), "access": rep.get("access"),
                         "exploitability": rep_score["score"], "label": rep_score["label"],
                         "note": rep_score["note"],
                         "next_step": ("minimize -> build PoC (RoE-gated weaponization)"
                                       if rep_score["label"] == "HIGH" else
                                       "minimize -> confirm reachability" if rep_score["label"] == "MEDIUM"
                                       else "likely DoS-only; deprioritize")})
    findings.sort(key=lambda f: -f["exploitability"])
    return {"total_crashes": len(crashes), "unique_buckets": len(buckets),
            "high": sum(1 for f in findings if f["label"] == "HIGH"), "findings": findings}
