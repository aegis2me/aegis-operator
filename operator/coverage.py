"""coverage.py -- COVERAGE-COMPLETENESS GATE (commercial-parity scheduler). Commercial suites are judged on
COVERAGE, so before the loop spends its budget DEEPENING a few hot leads (Phase B), it must first probe EVERY
parity class at least once (Phase A breadth). This is the mechanism that makes a 5/5-coverage claim
defensible: no depth on any class until every class has had >=1 real probe.

Maps a move to its parity CLASS (by leg action, then vuln-class keywords), tracks which classes have been
probed this run, and tells the scheduler which classes are still UNCOVERED so _pick can force them first.
"""
from __future__ import annotations

# The parity class set = OWASP Top 10 (2021) + API Top 10 (2023), as covered by our legs/oracles.
PARITY_CLASSES = {
    "idor", "authz", "injection", "xss", "ssrf", "csrf", "open_redirect", "mass_assign",
    "rate_limit", "security_headers", "auth_session", "file_upload", "supply_chain",
    "business_logic", "differential", "recon",
}

# leg action -> parity class (primary signal).
_ACTION_CLASS = {
    "idor": "idor", "rate": "rate_limit", "security_headers": "security_headers",
    "session_fixation": "auth_session", "open_redirect": "open_redirect", "mass_assign": "mass_assign",
    "csrf": "csrf", "ssrf": "ssrf", "xss": "xss", "file_upload": "file_upload",
    "supply_chain": "supply_chain", "stateful": "business_logic", "differential": "differential",
    "recon": "recon", "misconfig": "security_headers", "fuzz": "injection", "ossfuzz": "injection",
}
# vuln-class keyword -> parity class (fallback when the action is generic 'web').
_KEYWORD_CLASS = [
    ("idor", "idor"), ("bola", "idor"), ("object-level", "idor"),
    ("authz", "authz"), ("access-control", "authz"), ("access control", "authz"), ("over-reach", "authz"),
    ("overreach", "authz"), ("privesc", "authz"), ("segregation", "authz"),
    ("sqli", "injection"), ("injection", "injection"), ("nosql", "injection"), ("command", "injection"),
    ("ssti", "injection"), ("xxe", "injection"), ("deserial", "injection"),
    ("xss", "xss"), ("cross-site-scripting", "xss"),
    ("ssrf", "ssrf"), ("request-forgery", "ssrf"),
    ("csrf", "csrf"),
    ("redirect", "open_redirect"),
    ("mass-assign", "mass_assign"), ("mass_assign", "mass_assign"), ("auto-binding", "mass_assign"),
    ("rate", "rate_limit"), ("anti-automation", "rate_limit"), ("brute", "rate_limit"),
    ("header", "security_headers"), ("misconfig", "security_headers"), ("cookie", "security_headers"),
    ("auth", "auth_session"), ("session", "auth_session"), ("jwt", "auth_session"), ("fixation", "auth_session"),
    ("upload", "file_upload"), ("traversal", "file_upload"),
    ("supply", "supply_chain"), ("cve", "supply_chain"), ("dependency", "supply_chain"),
    ("business", "business_logic"), ("idempot", "business_logic"), ("invariant", "business_logic"),
    ("toctou", "business_logic"), ("race", "business_logic"), ("logic", "business_logic"),
    ("secret", "security_headers"), ("pii", "security_headers"), ("disclosure", "security_headers"),
]


def class_of(move) -> str:
    move = move if isinstance(move, dict) else {}
    a = str(move.get("action", "web"))
    if a in _ACTION_CLASS:
        return _ACTION_CLASS[a]
    blob = " ".join(str(move.get(k, "")) for k in ("vuln_class", "class", "technique", "why_novel")).lower()
    for kw, cls in _KEYWORD_CLASS:
        if kw in blob:
            return cls
    return "authz" if a in ("web", "fact", "authz", "money") else (a if a in PARITY_CLASSES else "recon")


def uncovered(covered) -> set:
    return PARITY_CLASSES - set(covered or ())


def summary(covered) -> dict:
    cov = set(covered or ()) & PARITY_CLASSES
    return {"covered": sorted(cov), "uncovered": sorted(PARITY_CLASSES - cov),
            "n_covered": len(cov), "n_total": len(PARITY_CLASSES),
            "complete": len(cov) >= len(PARITY_CLASSES)}
