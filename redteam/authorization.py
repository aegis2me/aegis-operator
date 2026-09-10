"""
authorization.py -- the fail-closed enforcement core for RED-TEAM mode.

Red-Team relaxes containment (live owned targets, scoped egress, network + post-exploitation). This
module is what makes that responsible: it loads a signed authorization artifact and enforces, in
code, that every action is (1) authorized, (2) against an OWNED in-scope target, (3) an allowed RoE
action, and (4) non-destructive unless a specific destructive test is named with a rollback plan.

DEFAULT-DENY: no artifact / expired / unparseable / off-scope / disallowed ⇒ refuse. Nothing in the
red-team run may act without passing `guard()`.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re


class NotAuthorized(Exception):
    """Raised when an action is attempted without a valid, in-scope, RoE-permitted authorization."""


_DESTRUCTIVE = re.compile(
    r"\b(DELETE\s+FROM|DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE|rm\s+-rf|mkfs|dd\s+if=|"
    r"shutdown|reboot|:\(\)\{|fork\s*bomb|wipe|format\s+[A-Za-z]:)\b", re.I)


def _host_of(target: str) -> str:
    t = (target or "").strip()
    t = re.sub(r"^\w+://", "", t)          # strip scheme
    t = t.split("/")[0].split(":")[0]      # strip path + port
    return t


class Authorization:
    """Loaded + validated engagement authorization. All checks are conservative (deny on doubt)."""

    def __init__(self, data: dict):
        self.data = data or {}
        self.scope = self.data.get("scope") or {}
        self.roe = self.data.get("rules_of_engagement") or {}
        self._validate()

    # ---- loading ----
    @staticmethod
    def load(path: str) -> "Authorization":
        if not path or not os.path.exists(path):
            raise NotAuthorized(f"no authorization artifact at {path!r} -- red-team mode refuses to run")
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception as e:
            raise NotAuthorized(f"authorization artifact unparseable ({e}) -- refusing")
        return Authorization(data)

    def _validate(self):
        for req in ("owner", "engagement", "approver", "authorized_at", "expires_at"):
            if not self.data.get(req):
                raise NotAuthorized(f"authorization missing required field '{req}' -- refusing")
        try:
            exp = datetime.date.fromisoformat(str(self.data["expires_at"]))
        except Exception:
            raise NotAuthorized("authorization expires_at is not a valid ISO date -- refusing")
        if exp < datetime.date.today():
            raise NotAuthorized(f"authorization expired on {exp.isoformat()} -- refusing")
        if not (self.scope.get("hosts") or self.scope.get("cidrs") or self.scope.get("domains")):
            raise NotAuthorized("authorization scope is empty -- refusing (owned scope is mandatory)")
        if not self.roe.get("allowed_actions"):
            raise NotAuthorized("authorization has no allowed_actions -- refusing")

    # ---- scope ----
    def in_scope(self, target: str) -> bool:
        host = _host_of(target)
        if not host:
            return False
        for h in self.scope.get("hosts", []):
            if host == h:
                return True
        for d in self.scope.get("domains", []):
            if host == d or host.endswith("." + d):
                return True
        # CIDR match (only if the host is an IP literal)
        try:
            ip = ipaddress.ip_address(host)
            for c in self.scope.get("cidrs", []):
                if ip in ipaddress.ip_network(c, strict=False):
                    return True
        except ValueError:
            pass
        return False

    def egress_allowed(self, target: str) -> bool:
        """Scoped egress: in-scope targets + explicitly authorized research hosts."""
        if self.in_scope(target):
            return True
        host = _host_of(target)
        return host in (self.roe.get("extra_research_hosts") or [])

    # ---- actions ----
    def action_allowed(self, action: str) -> bool:
        return action in (self.roe.get("allowed_actions") or [])

    def is_destructive(self, blob: str) -> bool:
        return bool(_DESTRUCTIVE.search(str(blob or "")))

    def destructive_permitted(self, test_id: str) -> bool:
        return bool(self.roe.get("destructive")) and test_id in (self.roe.get("allowed_destructive_tests") or [])

    def evasion_allowed(self) -> bool:
        return self.roe.get("evasion", "none") == "detection-test"

    def persistence_allowed(self) -> bool:
        return self.roe.get("persistence", "none") not in ("none", "", None)

    # read-only / scan actions -- observe, never change state. The "safe" probe class.
    _RECON_ACTIONS = {"recon", "rag", "static", "supply_chain", "sbom", "misconfig", "fact", "osint"}

    def classify_probe(self, action: str, payload: str = "") -> str:
        """Safety class of a probe -- ORTHOGONAL to scope. 'destructive' = erases/drops/deletes;
        'recon' = read-only observation/scan (safe); 'active' = state-changing but non-destructive
        (plant/write for proof). Getting MORE done safely means treating 'recon' generously while still
        refusing 'destructive'."""
        if self.is_destructive(f"{action} {payload}"):
            return "destructive"
        return "recon" if (action or "").lower() in self._RECON_ACTIONS else "active"

    def safe_recon_allowed(self, target: str) -> bool:
        """Read-only recon may run against an OWNER-AUTHORIZED research host even if it isn't a primary
        target -- the doctrine's OSINT/recon exception (owned domains only), never arbitrary hosts."""
        host = _host_of(target)
        allow = (self.roe.get("safe_recon_hosts") or []) + (self.roe.get("extra_research_hosts") or [])
        if host in allow:
            return True
        for d in (self.roe.get("safe_recon_domains") or []):
            if host == d or host.endswith("." + d):
                return True
        return False

    # ---- the one gate every red-team action passes ----
    def guard(self, action: str, target: str, payload: str = "", test_id: str = "") -> tuple:
        """Return (ok, reason). TWO ORTHOGONAL controls, fail-closed:
          * SAFETY  -- destructive (erase/drop/delete) is blocked unless it's an authorized, rolled-back
                       destructive-test. Non-destructiveness is necessary but NEVER sufficient.
          * SCOPE   -- you may only touch OWNED/AUTHORIZED targets. A read-only probe of an UNAUTHORIZED
                       host is still unauthorized; non-destructiveness does not grant authorization.
        Within these bounds we get MORE done: safe read-only RECON is allowed in-scope AND against
        owner-authorized research hosts (the OSINT exception); 'active' (non-destructive write) is allowed
        in-scope; only destructive or genuinely out-of-scope probes are refused."""
        cls = self.classify_probe(action, payload)
        if cls == "destructive" and not self.destructive_permitted(test_id):
            return False, f"UNSAFE: destructive probe ({action!r}) without an authorized destructive-test id + rollback -- blocked"
        if self.in_scope(target):
            if not self.action_allowed(action):
                return False, f"action {action!r} not in allowed_actions {self.roe.get('allowed_actions')} -- blocked"
            return True, f"authorized: in-scope, {cls} (non-destructive)"
        # out of scope: the ONLY thing allowed is SAFE read-only recon on an owner-authorized research host
        if cls == "recon" and self.safe_recon_allowed(target):
            return True, f"authorized: safe read-only recon on research host {target!r} (OSINT exception)"
        return False, (f"OUT OF SCOPE: {target!r} is not an owned/authorized target -- blocked. "
                       f"(A {cls} probe is still unauthorized off-scope; non-destructiveness does not grant access.)")

    def summary(self) -> dict:
        return {"owner": self.data.get("owner"), "engagement": self.data.get("engagement"),
                "expires_at": self.data.get("expires_at"),
                "scope": self.scope, "allowed_actions": self.roe.get("allowed_actions"),
                "destructive": bool(self.roe.get("destructive")),
                "evasion": self.roe.get("evasion", "none"), "persistence": self.roe.get("persistence", "none")}
