"""trust.py -- TRUST-TIER model: guard against assumed-access false positives (board-converged). The rule:
'crawl with all creds; verdict with none.' A finding is EXPLOITABLE only when the LOWEST tier that reaches it
is BELOW the tier the surface is INTENDED for -- so admin-doing-admin is INTENDED (never a finding), while
technician->admin-data (privesc) or anon->user-data (auth-bypass) is real.

Tiers: anon(0) < user(1) < admin(2). `intended_tier(surface)` is derived from route/namespace heuristics +
sensitivity (zero-config; the AuthzOracle's deny-baseline is the authoritative override when present) -- NOT
from 'whoever we logged in as' and NOT from 'the lowest tier that happens to succeed' (a mis-gated endpoint
must not excuse itself). Every finding is tagged reachable/intended/exploitable so the human is never misled.
"""
from __future__ import annotations
import re

ANON, USER, ADMIN = 0, 1, 2
_NAME = {ANON: "anon", USER: "user", ADMIN: "admin"}

_ADMIN_ROLES = ("owner", "admin", "superuser", "root")
_USER_ROLES = ("technician", "warehouse", "finance", "dispatcher", "staff", "user", "employee", "member")

# route/namespace -> intended MINIMUM tier (the app's expectation, privilege-independent).
_ADMIN_PAT = re.compile(r"/(admin|internal|audit|payroll|config|settings|role-access|users?|backup|"
                        r"system|superuser|management|billing/config)\b", re.I)
_USER_PAT = re.compile(r"/(me|account|profile|mine|my|dashboard|auth/(logout|me|refresh))\b", re.I)
_ANON_PAT = re.compile(r"/(public|login|signup|register|health|status|auth/login|forgot|reset|\.well-known)\b", re.I)
# sensitivity keywords -> a surface exposing these should be at least USER, and money/secret-ish -> ADMIN-ish.
_SENSITIVE = ("payment", "payroll", "invoice", "credit", "refund", "secret", "token", "key", "audit",
              "backup", "user", "role", "permission", "ssn", "salary")


def tier_of(role) -> int:
    r = str(role or "").lower().strip()
    if not r or r in ("anon", "anonymous", "public", "none", "guest"):
        return ANON
    if any(a in r for a in _ADMIN_ROLES):
        return ADMIN
    if any(u in r for u in _USER_ROLES):
        return USER
    return USER                                     # an authenticated-but-unknown role is a user tier


def tier_name(t) -> str:
    return _NAME.get(int(t) if t is not None else USER, "user")


def intended_tier(surface, *, sensitivity=True) -> int:
    """The MINIMUM tier the surface is intended for, from route heuristics + sensitivity. Defaults to USER
    for a generic /api/* (authenticated app data). The AuthzOracle deny-baseline overrides this when known."""
    s = str(surface or "")
    if _ADMIN_PAT.search(s):
        return ADMIN
    if _ANON_PAT.search(s):
        return ANON
    if _USER_PAT.search(s):
        return USER
    base = USER if s.startswith("/api") or s.startswith("/") and s != "/" else ANON
    if sensitivity and any(k in s.lower() for k in _SENSITIVE):
        base = max(base, USER)                       # a sensitive surface is never anon-intended
    return base


def classify(reachable_tier, intended_tier_) -> str:
    """EXPLOITABLE iff a tier BELOW the intended one reaches it; INTENDED iff at/above; else UNREACHABLE."""
    if reachable_tier is None:
        return "unreachable"
    if reachable_tier < intended_tier_:
        return "exploitable"
    return "intended"


# ACCESS-CONTROL classes: for these the finding IS the tier violation, so the reachable<intended rule
# applies. For every OTHER class (xss/ssrf/secrets/rate/supply-chain/upload/injection/...), the oracle already
# confirmed a real gap that is exploitable at WHATEVER tier can trigger it -- the tier is CONTEXT (who can
# trigger it), not an intended-vs-reachable comparison. So those are 'confirmed', never demoted to 'intended'.
_ACCESS_CONTROL = ("idor", "bola", "authz", "access-control", "access_control", "over-reach", "overreach",
                   "over-read", "broken-access", "broken_access", "broken-object", "privesc", "segregation",
                   "object-level", "property-level", "authorization")


def _is_access_control(move) -> bool:
    blob = " ".join(str(move.get(k, "")) for k in ("vuln_class", "class", "technique", "action")).lower()
    return any(k in blob for k in _ACCESS_CONTROL)


def finding_trust(move, *, baseline_intended=None):
    """Trust-tier attribution. reachable_tier = the tier that triggered it. For ACCESS-CONTROL findings the
    exploitability rule reachable<intended applies (admin-doing-admin = intended, not a gap). For all OTHER
    classes the oracle already confirmed a real gap -> verdict 'confirmed' (exploitable), with the tier as
    context (who can trigger it) -- so a dep-CVE/XSS/secret is never mislabelled 'intended'."""
    move = move if isinstance(move, dict) else {}
    surface = move.get("surface") or move.get("path") or ""
    rt = tier_of(move.get("role") or move.get("trust"))
    it = int(baseline_intended) if baseline_intended is not None else intended_tier(surface)
    if _is_access_control(move):
        v = classify(rt, it)
        exploitable = (v == "exploitable")
    else:
        v = "confirmed"                              # a verified non-authz gap is exploitable at its tier
        exploitable = True
    return {"reachable_tier": rt, "reachable": tier_name(rt), "intended_tier": it,
            "intended": tier_name(it), "verdict": v, "exploitable": exploitable,
            "access_control": _is_access_control(move)}


def tags(move, baseline_intended=None):
    """coverage_tags for a finding so the report/view group by trust tier + never mislead."""
    t = finding_trust(move, baseline_intended=baseline_intended)
    return [f"trust-reachable:{t['reachable']}", f"trust-intended:{t['intended']}",
            f"trust-verdict:{t['verdict']}"]
