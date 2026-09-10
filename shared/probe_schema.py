#!/usr/bin/env python3
"""
probe_schema.py -- a uniform PROBE result schema + taxonomy (adopted from NVIDIA garak's probe/report
design, NOT the dependency). garak's value is a battle-tested probe taxonomy and a single consistent
results structure that one detector/reporter parses uniformly. Here it gives every tester (deterministic
methods, vectors, the fuzzer) ONE canonical result shape the oracle + ledger + reports consume the same
way -- instead of each leg inventing its own dict. Stdlib-only, offline.

    from probe_schema import ProbeResult, normalize, to_finding_shape
    r = ProbeResult(probe="idor.cross_account", category="authz", target="/api/invoices/{id}",
                    status="hit", detail="read another tenant's invoice", severity="high")
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

# garak-style probe categories, mapped to OUR vuln classes/angles (the discovery loop already speaks these).
CATEGORIES = [
    "recon", "web", "injection", "authz", "auth", "ssrf", "ssti", "xxe", "traversal", "deserialization",
    "race", "csrf", "business_logic", "info_disclosure", "mass_assignment", "supply_chain", "misconfig",
    "memory-safety", "crash", "static", "fuzz", "rag",
]
STATUSES = ["hit", "miss", "error", "blocked", "inconclusive"]   # hit = the probe fired (candidate finding)


@dataclass
class ProbeResult:
    probe: str                              # dotted id, e.g. "sqli.error_based" or "ossfuzz.invoice_fuzzer"
    category: str                           # one of CATEGORIES (best-effort)
    target: str                             # surface / path / host / project:fuzzer
    status: str = "miss"                    # one of STATUSES
    detail: str = ""                        # short human detail
    severity: str = "med"                   # info|low|med|high|critical (a suggestion; oracle/scorer refine)
    evidence: str = ""                      # raw signal (trace/response snippet) -- redact secrets upstream
    attempt: int = 0                        # which attempt/iteration produced it
    tags: list = field(default_factory=list)
    provenance: dict = field(default_factory=dict)   # {provider, model, engine, cve, ...}

    def is_candidate(self) -> bool:
        return self.status == "hit"

    def as_dict(self) -> dict:
        return asdict(self)


def normalize(raw: dict) -> ProbeResult:
    """Coerce a leg's ad-hoc result dict into a ProbeResult (unknown fields ignored; sane defaults)."""
    raw = raw or {}
    cat = str(raw.get("category") or raw.get("vuln_class") or raw.get("angle") or "web").lower()
    status = raw.get("status")
    if status not in STATUSES:                       # infer from common shapes
        if raw.get("blocked"):
            status = "blocked"
        elif raw.get("reproduced") or raw.get("verified") or raw.get("hit"):
            status = "hit"
        elif isinstance(raw.get("status"), int):     # an HTTP code, not a probe status
            status = "miss"
        else:
            status = "miss"
    return ProbeResult(
        probe=str(raw.get("probe") or raw.get("technique") or raw.get("mechanism") or cat),
        category=cat if cat in CATEGORIES else "web",
        target=str(raw.get("target") or raw.get("surface") or raw.get("path") or raw.get("host") or ""),
        status=status,
        detail=str(raw.get("detail") or raw.get("summary") or raw.get("why_novel") or "")[:300],
        severity=str(raw.get("severity") or "med"),
        evidence=str(raw.get("evidence") or raw.get("body") or "")[:600],
        attempt=int(raw.get("attempt") or raw.get("iteration") or 0),
        tags=list(raw.get("tags") or raw.get("coverage_tags") or []),
        provenance=dict(raw.get("provenance") or {}),
    )


def to_finding_shape(pr: ProbeResult) -> dict:
    """Map a hit ProbeResult onto the candidate-finding shape the shared oracle/ledger expects."""
    return {"claim_type": pr.probe, "vuln_class": pr.category, "surface": pr.target,
            "severity": pr.severity, "summary": pr.detail, "evidence": pr.evidence,
            "coverage_tags": [f"surface:{pr.target}", f"technique:{pr.probe}", f"category:{pr.category}"],
            "provenance": pr.provenance}


def _selftest():
    # infers status/category from an ad-hoc vector result
    r = normalize({"vuln_class": "authz", "surface": "/api/x", "reproduced": True,
                   "why_novel": "cross-account read", "severity": "high"})
    assert r.status == "hit" and r.category == "authz" and r.is_candidate(), r
    b = normalize({"blocked": "scope", "action": "recon", "target": "10.0.0.1"})
    assert b.status == "blocked", b
    fs = to_finding_shape(r)
    assert fs["claim_type"] and fs["vuln_class"] == "authz" and "technique:" in fs["coverage_tags"][1], fs
    print("probe_schema selftest: OK (normalize infers hit/blocked; to_finding_shape maps cleanly)")
    return True


if __name__ == "__main__":
    import sys
    sys.exit(0 if _selftest() else 1)
