"""
verified_findings.py - SHARED verified-findings + oracle layer.

Used by BOTH the aegis_operator co-pilot and the ExploitGym benchmark. The design point
(converged on independently by Claude and Sol): a finding is not a model's prose claim -
it is an immutable, evidence-bearing object whose status can only be moved
candidate -> verified/rejected by an out-of-band VERIFIER running a ground-truth ORACLE.
Reports and benchmark scores count ONLY `verified`. This kills over-claiming, removes the
manual-verification bottleneck, and gives dedup + scoring + tamper-evident replay.

Storage is an append-only, hash-chained JSONL event log (event-sourced): findings and
their status transitions are appended as events, never mutated in place - which also makes
concurrent multi-agent writes safe (no lost updates) and the audit tamper-evident.

Stdlib only, except `requests` is used by HttpOracle (optional). No network at import time.
"""
from __future__ import annotations
import json, hashlib, os, tempfile, time, uuid, subprocess, re
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional
from contextlib import contextmanager

# ---------- hashing / ids ----------
def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def new_id() -> str:
    return uuid.uuid4().hex

def run_marker(prefix: str = "vf") -> str:
    """A globally-unique marker for RUN-SCOPED oracles. Plant this exact value in a writable
    field and assert on IT, so the oracle is robust to accumulated state across re-runs. LESSON:
    never assert an absolute table count (e.g. `count(*)==1`) - twin state accumulates and the
    assertion flips. Assert existence of a per-run marker/artifact instead."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"

# ---------- finding schema ----------
VALID_STATUS = {"candidate", "verified", "rejected", "inconclusive"}

@dataclass
class Evidence:
    kind: str                 # "http" | "db" | "file" | "note"
    detail: str               # human-readable
    artifact_sha256: str = "" # hash of the raw artifact (response body, query result, file)
    tool_call_id: str = ""
    timestamp: str = field(default_factory=_now)

@dataclass
class Finding:
    claim_type: str           # taxonomy id, e.g. "money.unbounded_field"
    summary: str
    target_id: str = "target-mirror"
    run_id: str = ""
    finding_id: str = field(default_factory=new_id)
    status: str = "candidate"
    severity: str = "unknown"
    evidence: list = field(default_factory=list)         # list[Evidence-as-dict]
    oracle_id: str = ""
    oracle_receipt: dict = field(default_factory=dict)
    coverage_tags: list = field(default_factory=list)    # ["surface:/api/parts","technique:boundary"]
    provenance: dict = field(default_factory=dict)       # {provider,model,...}
    remediation: dict = field(default_factory=dict)      # stage-10 fix, appended post-verify (never at
                                                         # discovery). {path,fix,component,fixed_version,
                                                         # references,sources,consensus_model,ts}. "path"
                                                         # = "known-cve" (RAG-filled) | "novel" (panel-designed).

# ---------- cross-process append lock (keeps the hash chain intact under concurrent writers) ----------
@contextmanager
def _append_lock(path: str, timeout: float = 10.0, poll: float = 0.02):
    lockpath = path + ".lock"
    os.makedirs(os.path.dirname(os.path.abspath(lockpath)), exist_ok=True)
    fd = None; start = time.time()
    while True:
        try:
            fd = os.open(lockpath, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            break
        except (FileExistsError, PermissionError):
            # lock is held -> retry. (POSIX raises FileExistsError on O_EXCL; WINDOWS raises
            # PermissionError for a contended/held/being-unlinked lockfile -- both just mean "try
            # again", never crash the writer, or a concurrent writer would lose its update.)
            # stale-lock recovery: a lock older than `timeout` almost certainly belongs to a CRASHED
            # writer. STEAL it (unlink) and retry the acquire so we still end up HOLDING the lock --
            # never proceed unlocked, which would let concurrent writers fork/lose the hash chain.
            if time.time() - start > timeout:
                try:
                    if time.time() - os.path.getmtime(lockpath) > timeout:
                        os.unlink(lockpath)
                        start = time.time()
                        continue                 # retry the acquire immediately
                except FileNotFoundError:
                    continue                     # another waiter already cleared it; retry
                except Exception:
                    pass
            time.sleep(poll)
    try:
        yield
    finally:
        if fd is not None:
            try: os.close(fd)
            except Exception: pass
            try: os.unlink(lockpath)
            except Exception: pass


# ---------- append-only hash-chained store ----------
class FindingStore:
    """Event-sourced: every record/transition is an appended, hash-chained JSONL event.
    Current finding state = fold of its events (latest transition wins)."""
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def _last_hash(self) -> str:
        # Read only the TAIL of the append-only log to find the last event_hash -- O(1) per append
        # instead of re-parsing the whole (growing) file on every write (which was O(n^2) over a run
        # and held the cross-process lock ever longer). Falls back to a full scan only if the tail
        # doesn't contain a parseable line (e.g. one huge final event).
        if not os.path.exists(self.path):
            return "GENESIS"
        try:
            with open(self.path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    return "GENESIS"
                span = min(size, 262144)                 # last 256 KB is plenty for the final JSON line
                f.seek(size - span)
                tail = f.read().decode("utf-8", "replace")
            for line in reversed(tail.splitlines()):
                line = line.strip()
                if line:
                    try:
                        return json.loads(line)["event_hash"]
                    except Exception:
                        continue
            if span >= size:                             # whole file scanned via the tail, nothing valid
                return "GENESIS"
        except Exception:
            pass
        # fallback: last valid line via a full scan (rare -- only if the final event exceeds the tail span)
        h = "GENESIS"
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            h = json.loads(line)["event_hash"]
                        except Exception:
                            pass
        except Exception:
            pass
        return h

    def _append(self, event: dict) -> dict:
        event = dict(event)
        event.setdefault("ts", _now())
        # read-head + append under a cross-process lock so concurrent writers cannot
        # both chain off the same prev_hash and fork the chain.
        with _append_lock(self.path):
            event["prev_hash"] = self._last_hash()
            # hash binds the event content to the chain -> tamper-evident
            event["event_hash"] = _sha256(json.dumps(event, sort_keys=True))
            line = json.dumps(event)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n"); f.flush(); os.fsync(f.fileno())
        return event

    def record_candidate(self, finding: Finding) -> str:
        finding.status = "candidate"
        self._append({"type": "record", "finding": asdict(finding)})
        return finding.finding_id

    def _transition(self, finding_id: str, status: str, oracle_id: str, receipt: dict) -> None:
        assert status in VALID_STATUS
        self._append({"type": "transition", "finding_id": finding_id,
                      "status": status, "oracle_id": oracle_id, "oracle_receipt": receipt})

    def record_remediation(self, finding_id: str, remediation: dict) -> None:
        """Attach a stage-10 remediation to a finding, append-only (the hash chain stays intact; the
        finding object is never mutated in place). Only meaningful for an already-verified finding -
        remediation is the END of the pipeline, after found -> worked -> tested -> confirmed."""
        rem = dict(remediation); rem.setdefault("ts", _now())
        self._append({"type": "remediation", "finding_id": finding_id, "remediation": rem})

    def events(self) -> list:
        out = []
        if not os.path.exists(self.path): return out
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try: out.append(json.loads(line))
                    except Exception: pass
        return out

    def verify_chain(self) -> bool:
        """Re-derive the hash chain to detect tampering."""
        prev = "GENESIS"
        for e in self.events():
            body = {k: v for k, v in e.items() if k != "event_hash"}
            if e.get("prev_hash") != prev: return False
            if e.get("event_hash") != _sha256(json.dumps(body, sort_keys=True)): return False
            prev = e["event_hash"]
        return True

    def findings(self) -> dict:
        """Fold events into current finding states."""
        state: dict = {}
        for e in self.events():
            if e["type"] == "record":
                fd = e["finding"]; state[fd["finding_id"]] = fd
            elif e["type"] == "transition":
                fid = e["finding_id"]
                if fid in state:
                    state[fid]["status"] = e["status"]
                    state[fid]["oracle_id"] = e["oracle_id"]
                    state[fid]["oracle_receipt"] = e["oracle_receipt"]
            elif e["type"] == "remediation":
                fid = e["finding_id"]
                if fid in state:
                    state[fid]["remediation"] = e["remediation"]
        return state

    def verified(self) -> list:
        return [f for f in self.findings().values() if f["status"] == "verified"]

    def coverage(self) -> dict:
        tags: dict = {}
        for f in self.findings().values():
            for t in f.get("coverage_tags", []):
                tags[t] = tags.get(t, 0) + 1
        return tags

# ---------- oracles ----------
class Oracle:
    """Given a Finding, return (status, receipt). Only a Verifier may apply the result."""
    id = "base@0"
    def check(self, finding: Finding):  # -> (status, receipt)
        raise NotImplementedError

class CallableOracle(Oracle):
    """Wrap any function fn(finding)->(bool_or_status, receipt_dict)."""
    def __init__(self, fn: Callable, oracle_id: str):
        self._fn = fn; self.id = oracle_id
    def check(self, finding: Finding):
        res, receipt = self._fn(finding)
        status = res if isinstance(res, str) else ("verified" if res else "rejected")
        return status, receipt

class HttpOracle(Oracle):
    """Re-issue an HTTP request and assert on the response (status code + body regex).
    expected_status: int or None; body_regex: pattern that MUST match for 'verified'."""
    def __init__(self, base, method, path, *, cookie=None, json_body=None,
                 expected_status=None, body_regex=None, absent_regex=None, oracle_id="http@1"):
        import requests  # local import so module loads without requests
        self._requests = requests
        self.base, self.method, self.path = base, method, path
        self.cookie, self.json_body = cookie, json_body
        self.expected_status, self.body_regex, self.absent_regex = expected_status, body_regex, absent_regex
        self.id = oracle_id
    def check(self, finding: Finding):
        try:
            r = self._requests.request(self.method, self.base + self.path,
                                       headers=({"Cookie": self.cookie} if self.cookie else {}),
                                       json=self.json_body, verify=False, timeout=25)
        except Exception as e:
            # target unreachable / transport error: we CANNOT confirm the claim (this is not a
            # refutation -- we never got to test), so return 'inconclusive' with the error on the
            # receipt. Crucially this never raises: an oracle that raised would abort the whole hunt.
            return ("inconclusive", {"error": str(e)[:200], "unreachable": True})
        body = r.text or ""
        ok = True
        if self.expected_status is not None: ok = ok and (r.status_code == self.expected_status)
        if self.body_regex is not None:      ok = ok and bool(re.search(self.body_regex, body))
        if self.absent_regex is not None:    ok = ok and not bool(re.search(self.absent_regex, body))
        receipt = {"status_code": r.status_code, "body_sha256": _sha256(body),
                   "body_head": body[:160], "checked": {"expected_status": self.expected_status,
                   "body_regex": self.body_regex, "absent_regex": self.absent_regex}}
        # SPA / catch-all GUARD: a bare 2xx with no distinguishing body assertion can be an SPA history-
        # fallback (the app serves the SAME shell for every path) -- a 200 there confirms NOTHING. Require a
        # DISTINGUISHING response: hit a random nonexistent path; if the target's 2xx is indistinguishable
        # from that baseline (same status + same body shell), reject it as a fallback rather than over-claim.
        if ok and self.body_regex is None and 200 <= (r.status_code or 0) < 300:
            try:
                import random as _rnd
                bpath = "/__aegis_nx_%d" % _rnd.randint(10 ** 6, 10 ** 7 - 1)
                b = self._requests.request("GET", self.base + bpath,
                                           headers=({"Cookie": self.cookie} if self.cookie else {}),
                                           verify=False, timeout=15)
                bbody = b.text or ""
                same_shell = (_sha256(bbody) == _sha256(body)) or (
                    abs(len(bbody) - len(body)) <= max(16, int(0.02 * len(body))) and bbody[:80] == body[:80])
                if b.status_code == r.status_code and same_shell:
                    ok = False
                    receipt["spa_fallback"] = {
                        "baseline_path": bpath, "baseline_status": b.status_code,
                        "note": "2xx indistinguishable from a nonexistent path (SPA/catch-all fallback) -- "
                                "not a finding; use a body_regex/expected content to confirm a real hit"}
            except Exception:
                pass
        return ("verified" if ok else "rejected"), receipt

class AuthzOracle(Oracle):
    """BROKEN-ACCESS / OVER-REACH oracle (cross-role, FP-resistant). A plain status check cannot express
    over-reach: 200 is only a finding when a role that SHOULD be denied gets it. This oracle re-issues
    the SAME request as TWO roles and confirms over-reach only on TWO independent signals:
      (1) the TESTED role gets a success (2xx)  AND
      (2) a BASELINE role (one that must be denied) gets 401/403 on the same surface -- proving the
          surface is genuinely access-controlled (so we never flag a public endpoint).
    It also never flags a role listed in `intended_roles` (e.g. a business-intended privileged role),
    so a legitimately-allowed role isn't reported as a bug. Needs session_for_role(role)->Session."""
    def __init__(self, base, method, path, role, baseline_role, session_for_role, *,
                 json_body=None, intended_roles=None, denied=(401, 403), oracle_id="authz@1"):
        self.base, self.method, self.path = base, method, path
        self.role, self.baseline_role = role, baseline_role
        self.session_for_role, self.json_body = session_for_role, json_body
        # F5: intended_roles may be a FLAT list (global -- backward-compatible) OR a PER-SURFACE dict
        # {surface_glob: [roles]}, so a role intended on /api/invoices/* is NOT excused on /api/settings/*
        # (a coarse global list over-excuses a legitimately-privileged-elsewhere role and hides real bugs).
        self.intended_roles = intended_roles or []
        self.denied = set(denied)
        self.id = oracle_id

    def _intended_for(self, path):
        """Roles business-intended-privileged FOR THIS SURFACE (never flagged as over-reach). A dict maps
        surface glob/substring -> roles; a flat list is treated as global (all surfaces)."""
        ir = self.intended_roles
        if isinstance(ir, dict):
            import fnmatch
            out = set()
            for pat, roles in ir.items():
                p = str(pat)
                if fnmatch.fnmatch(path or "", p) or (p and p in (path or "")):
                    out |= {str(r).lower() for r in (roles or [])}
            return out
        return {str(r).lower() for r in (ir or [])}

    def check(self, finding: Finding):
        role = str(self.role or "").lower()
        intended = self._intended_for(self.path)
        if role in intended:
            return "rejected", {"note": f"role {role!r} is intended-privileged on {self.path} -- not over-reach",
                                "tested_role": role, "surface": self.path}
        try:
            st = self.session_for_role(self.role)
            sb = self.session_for_role(self.baseline_role)
            ar = st.request(self.method, self.base + self.path, json=self.json_body, verify=False, timeout=25)
            br = sb.request(self.method, self.base + self.path, json=self.json_body, verify=False, timeout=25)
        except Exception as e:
            return "inconclusive", {"error": str(e)[:200], "unreachable": True}
        tested_ok = 200 <= ar.status_code < 300
        baseline_denied = br.status_code in self.denied
        # DISTINGUISHING-2xx guard (mirrors HttpOracle's SPA-200 fix): a tested 2xx is only real,
        # role-gated ACCESS if it differs both from an UNAUTHENTICATED request (else the surface is
        # public / an SPA shell, not attributable to the role) and from a random nonexistent path
        # (else it's the SPA/catch-all fallback). Without this, a public/SPA 200 + a baseline 401/403
        # (e.g. a role-account lockout that returns 403 while anon gets the SPA 200) reads as over-reach.
        spa_or_public = False; guard_note = ""
        if tested_ok:
            try:
                import requests as _rq, uuid as _uuid
                anon = _rq.Session(); anon.verify = False
                ur = anon.request(self.method, self.base + self.path, json=self.json_body, verify=False, timeout=20)
                if 200 <= ur.status_code < 300 and (ur.text or "") == (ar.text or ""):
                    spa_or_public = True
                    guard_note = " | rejected-guard: tested 2xx identical to an UNAUTHENTICATED request (public/SPA, not role-gated)"
                else:
                    npath = "/zz-nonexistent-" + _uuid.uuid4().hex[:10]
                    nr = st.request("GET", self.base + npath, verify=False, timeout=20)
                    if nr.status_code == ar.status_code and (nr.text or "") == (ar.text or ""):
                        spa_or_public = True
                        guard_note = " | rejected-guard: tested 2xx identical to a nonexistent-path baseline (SPA catch-all)"
            except Exception:
                pass
        over_reach = tested_ok and baseline_denied and not spa_or_public
        return ("verified" if over_reach else "rejected"), {
            "over_reach": over_reach, "surface": self.path,
            "tested_role": role, "tested_status": ar.status_code,
            "baseline_role": str(self.baseline_role).lower(), "baseline_status": br.status_code,
            "spa_or_public": spa_or_public,
            "note": ("access-controlled surface (baseline denied) reached by a role that should be denied"
                     if over_reach else
                     "not over-reach: tested role not granted, surface not access-controlled, or public/SPA 2xx") + guard_note}


class InvariantOracle(Oracle):
    """A numeric DOMAIN INVARIANT that must hold (measured <= bound). Verified (a BUG) iff the invariant
    HELD before the action and is VIOLATED after -- e.g. sum(issued credit notes) <= invoice.total held
    at 0<=78, then 156>78 after replaying a full credit. Numbers are pre-measured by the stateful leg;
    the oracle applies the rule (re-running the stateful move re-measures, so it stays re-verifiable)."""
    def __init__(self, before, after, bound, *, oracle_id="invariant@1", label="", surface=""):
        self.before, self.after, self.bound = float(before), float(after), float(bound)
        self.id, self.label, self.surface = oracle_id, label, surface
    def check(self, finding=None):
        eps = 1e-9
        held = self.before <= self.bound + eps
        violated = self.after > self.bound + eps
        ok = held and violated
        return ("verified" if ok else "rejected"), {
            "invariant": self.label or "measured<=bound", "surface": self.surface,
            "before": self.before, "after": self.after, "bound": self.bound,
            "held_before": held, "violated_after": violated}


class IdempotencyOracle(Oracle):
    """Replaying a mutation N>1 times must be a NO-OP after the first (idempotent). Verified (a BUG) iff a
    business-state metric grew by MORE than one unit-effect across the replays (e.g. credit-note count
    0 -> 2 on a double POST). Distinguishes an allowed duplicate (delta<=unit) from a real replay bug."""
    def __init__(self, before, after, repeats, *, unit=1.0, oracle_id="idempotency@1", label="", surface=""):
        self.before, self.after, self.repeats, self.unit = float(before), float(after), int(repeats), float(unit)
        self.id, self.label, self.surface = oracle_id, label, surface
    def check(self, finding=None):
        delta = self.after - self.before
        non_idempotent = (self.repeats > 1) and (delta > self.unit + 1e-9)
        return ("verified" if non_idempotent else "rejected"), {
            "metric": self.label or "state-count", "surface": self.surface,
            "metric_before": self.before, "metric_after": self.after, "delta": delta,
            "repeats": self.repeats, "unit_effect": self.unit, "non_idempotent": non_idempotent}


class ResourcePersistenceOracle(Oracle):
    """SCAFFOLD/stack resource LEAK or exhaustion: a HEAVY request run must not leave a resource metric
    (container RSS, temp-file count, DB connections) elevated after a cooldown BEYOND what a benign CONTROL
    run leaves. Verified (a BUG) iff the heavy-run delta exceeds the control-run delta by `factor` AND an
    absolute `floor` -- so warmup / GC / JIT jitter (which the control incurs too) is subtracted out and
    not mistaken for a leak. Numbers are measured by the stateful leg (docker cgroup / exec / sql / fs)."""
    def __init__(self, heavy_delta, control_delta, *, floor=0.0, factor=2.0, unit="bytes",
                 oracle_id="resource-persistence@1", surface=""):
        self.heavy_delta = float(heavy_delta); self.control_delta = float(control_delta)
        self.floor = float(floor); self.factor = float(factor); self.unit = unit
        self.id = oracle_id; self.surface = surface
    def check(self, finding=None):
        leak = (self.heavy_delta > self.floor) and                (self.heavy_delta > self.control_delta * self.factor + self.floor)
        return ("verified" if leak else "rejected"), {
            "metric": "resource-persistence", "unit": self.unit, "surface": self.surface,
            "heavy_delta": self.heavy_delta, "control_delta": self.control_delta,
            "floor": self.floor, "factor": self.factor, "leak": leak}


class AuthStateOracle(Oracle):
    """Auth/session STATE at the stack layer. After an explicit logout/invalidation the SAME session must no
    longer reach a protected resource. Verified (a BUG) iff the resource was authorized BEFORE logout (2xx)
    AND is STILL authorized AFTER (2xx) -- server-side session invalidation failed (token_not_invalidated).
    (Also the shape for session-fixation: pre = a pre-seeded id becoming authenticated.)"""
    def __init__(self, pre_status, post_status, *, denied=(401, 403), oracle_id="auth-state@1",
                 surface="", label=""):
        self.pre = int(pre_status); self.post = int(post_status); self.denied = set(denied)
        self.id = oracle_id; self.surface = surface; self.label = label
    def check(self, finding=None):
        was_authed = 200 <= self.pre < 300
        still_authed = 200 <= self.post < 300
        bug = was_authed and still_authed
        return ("verified" if bug else "rejected"), {
            "metric": self.label or "session-invalidation", "surface": self.surface,
            "pre_logout_status": self.pre, "post_logout_status": self.post,
            "invalidated": (not still_authed), "bug": bug}


class MassAssignOracle(Oracle):
    """MASS ASSIGNMENT / auto-binding -- the server accepts+persists a client-supplied PRIVILEGED field it
    should ignore (role/isAdmin/status/approved/balance/ownerId/id...). VERIFIED iff, after a create/update
    that INJECTED such a field with a distinctive MARKER value, the returned/read-back object carries that
    field == our marker (persisted), AND a CONTROL object (created without the injection) does NOT have that
    value -- so a legitimate default can't masquerade as acceptance. Non-destructive: plant-for-proof."""
    _PRIVILEGED = ("role", "isadmin", "is_admin", "admin", "approved", "verified", "status", "balance",
                   "ownerid", "owner_id", "userid", "user_id", "id", "createdby", "created_by", "amount",
                   "price", "total", "discount", "iscleared", "paid")

    def __init__(self, created_obj, injected, *, control_obj=None, oracle_id="massassign@1", surface=""):
        self.obj = created_obj if isinstance(created_obj, dict) else {}
        self.injected = injected or {}
        self.control = control_obj if isinstance(control_obj, dict) else None
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        leads = []
        for k, v in self.injected.items():
            if k.lower() not in self._PRIVILEGED:
                continue
            got = self.obj.get(k)
            if got is None or str(got) != str(v):
                continue                                   # our marker did NOT persist
            if self.control is not None and str(self.control.get(k)) == str(v):
                continue                                   # a legitimate default equals our value -> not a bug
            leads.append({"field": k, "injected": v, "persisted": got})
        verdict = "verified" if leads else "rejected"
        return verdict, {"surface": self.surface, "n_leads": len(leads), "leads": leads[:8],
                         "note": ("privileged client-supplied field(s) accepted+persisted (mass assignment)"
                                  if leads else "no injected privileged field persisted")}


class OpenRedirectOracle(Oracle):
    """OPEN REDIRECT -- a redirect parameter sends the user to an attacker-controlled EXTERNAL host.
    VERIFIED iff a 3xx Location header (or a meta/JS redirect in the body) points to the injected CANARY
    host. FP guard: the canary must be an EXTERNAL host (not the target's own), and it must appear as the
    redirect TARGET (host position), not merely echoed elsewhere. Reads only (GET) -- non-destructive."""
    def __init__(self, status, location, body, canary_host, *, target_host="", oracle_id="openredir@1", surface="", param=""):
        self.status = int(status or 0); self.location = str(location or ""); self.body = str(body or "")
        self.canary = str(canary_host or "").lower(); self.target = str(target_host or "").lower()
        self.id = oracle_id; self.surface = surface; self.param = param
    def check(self, finding=None):
        import re as _re
        loc = self.location.lower()
        # Location points at the canary host (scheme-relative //canary, https://canary, or ...@canary)
        in_location = bool(self.canary) and (self.status in (301, 302, 303, 307, 308)) and (
            _re.search(r"(?://|https?:/{2}|@)" + _re.escape(self.canary), loc) is not None
            or loc.startswith(self.canary) or loc.startswith("//" + self.canary))
        # meta-refresh / JS redirect in body -> the canary as a url= / location= target
        in_body = bool(self.canary) and _re.search(
            r"(?:url=|location(?:\.href)?\s*=\s*[\"']?)\s*(?://|https?:/{2})?" + _re.escape(self.canary),
            self.body.lower()) is not None
        verdict = "verified" if (in_location or in_body) else "rejected"
        return verdict, {"surface": self.surface, "param": self.param, "status": self.status,
                         "location": self.location[:200], "canary": self.canary, "via": ("location" if in_location else ("body" if in_body else None)),
                         "note": ("open redirect to external canary" if verdict == "verified" else "no external redirect")}


class SessionFixationOracle(Oracle):
    """SESSION FIXATION -- the session id must ROTATE on privilege change (login). VERIFIED (a bug) iff a
    pre-auth session id existed, it did NOT change after a successful login (same id value), AND that same
    session is now AUTHENTICATED -- an attacker-fixed id survives authentication. Reads only (a normal
    login); non-destructive."""
    def __init__(self, pre_id, post_id, authed_after, *, oracle_id="sessfix@1", surface="", cookie=""):
        self.pre = pre_id; self.post = post_id; self.authed = bool(authed_after)
        self.id = oracle_id; self.surface = surface; self.cookie = cookie
    def check(self, finding=None):
        had_pre = bool(self.pre)
        not_rotated = had_pre and self.pre == self.post
        bug = not_rotated and self.authed
        return ("verified" if bug else "rejected"), {
            "surface": self.surface, "cookie": self.cookie, "pre_id_present": had_pre,
            "rotated_on_login": (not not_rotated), "authenticated_after": self.authed, "bug": bug,
            "note": ("session id NOT rotated on login and is authenticated (fixation)" if bug else
                     ("session id rotated on login (ok)" if had_pre else "no pre-auth session id to fix"))}


class FileUploadOracle(Oracle):
    """UNRESTRICTED / dangerous FILE UPLOAD. VERIFIED iff a file with ACTIVE-CONTENT type/extension (html,
    svg, xhtml, js, php, phtml, svg-with-script) was ACCEPTED (upload 2xx) AND is RETRIEVABLE and served with
    a RENDERABLE content-type (text/html, image/svg+xml, application/xhtml) -- i.e. it could execute in a
    victim's browser (stored XSS / RCE-adjacent). If `executed` is set (a headless check confirmed the marker
    ran) that is the strongest signal. FP guard: the file must actually be retrievable + served renderable,
    not merely 200-on-upload. Non-destructive: plants ONE benign marker file, never erases."""
    _RENDERABLE = ("text/html", "image/svg+xml", "application/xhtml", "application/xml", "text/xml")
    _DANGEROUS_EXT = (".html", ".htm", ".svg", ".xhtml", ".js", ".php", ".phtml", ".php5", ".jsp", ".asp")

    def __init__(self, upload_status, retrieve_status, retrieve_ctype, filename, *, executed=False,
                 oracle_id="upload@1", surface=""):
        self.up = int(upload_status or 0); self.rs = int(retrieve_status or 0)
        self.ctype = str(retrieve_ctype or "").lower(); self.fn = str(filename or "")
        self.executed = bool(executed); self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        accepted = 200 <= self.up < 300
        retrievable = 200 <= self.rs < 300
        dangerous_ext = any(self.fn.lower().endswith(e) for e in self._DANGEROUS_EXT)
        renderable = any(c in self.ctype for c in self._RENDERABLE)
        bug = accepted and dangerous_ext and (self.executed or (retrievable and renderable))
        sev = "high" if (self.executed or renderable) else "medium"
        return ("verified" if bug else "rejected"), {
            "surface": self.surface, "filename": self.fn, "upload_status": self.up,
            "retrieve_status": self.rs, "retrieve_ctype": self.ctype, "renderable": renderable,
            "executed": self.executed, "severity": sev,
            "note": ("active-content upload accepted + served renderable" + (" + EXECUTED" if self.executed else "")
                     if bug else "no dangerous upload confirmed")}


class XssOracle(Oracle):
    """XSS (reflected / DOM / stored) confirmed by EXECUTION, not reflection. The probe injects a marker
    payload that, IF it executes in the browser, sets `window.__aegis_xss` to a unique TOKEN. VERIFIED iff a
    headless browser load of the target shows `window.__aegis_xss === token` -- i.e. the script actually RAN
    (a real, FP-free signal; mere reflection of the string is NOT enough). Non-destructive (reads/loads)."""
    def __init__(self, executed_token, expected_token, *, surface="", param="", context="", oracle_id="xss@1"):
        self.executed = executed_token; self.expected = expected_token
        self.surface = surface; self.param = param; self.context = context; self.id = oracle_id
    def check(self, finding=None):
        fired = bool(self.expected) and self.executed == self.expected
        return ("verified" if fired else "rejected"), {
            "surface": self.surface, "param": self.param, "context": self.context,
            "executed": bool(fired), "note": ("payload EXECUTED in the browser (XSS confirmed)" if fired
                                              else "payload did not execute (no XSS via this vector)")}


class SsrfOracle(Oracle):
    """SSRF / blind OOB -- the target made an outbound request to our in-sandbox CANARY. VERIFIED iff the
    unique token we injected was CALLED BACK (a hit recorded by the canary). Ground truth is the callback
    itself (like grype/ossfuzz-reproduce), so this is unambiguous and FP-free. Non-destructive (a GET to an
    owned in-sandbox sink)."""
    def __init__(self, token_hits, *, surface="", param="", oracle_id="ssrf@1"):
        self.hits = list(token_hits or [])
        self.surface = surface; self.param = param; self.id = oracle_id
    def check(self, finding=None):
        verdict = "verified" if self.hits else "rejected"
        return verdict, {"surface": self.surface, "param": self.param, "n_hits": len(self.hits),
                         "hits": self.hits[:4],
                         "note": ("target called back the canary (SSRF confirmed)" if self.hits else
                                  "no OOB callback (no SSRF via this param)")}


class CsrfOracle(Oracle):
    """CSRF POSTURE (non-destructive -- assesses defenses, does not forge a state-changing request).
    VERIFIED (exposed) iff the session cookie provides NO cross-site protection (SameSite absent or =None)
    AND no anti-CSRF token mechanism is evident (no csrf/xsrf token in the session cookies, response body,
    or a X-CSRF/X-XSRF header). If SameSite is Lax/Strict OR a token mechanism exists -> rejected (mitigated).
    Conservative by design: a real forged-request test would modify state, so we assess posture only."""
    def __init__(self, set_cookies=None, body="", resp_headers=None, *, oracle_id="csrf@1", surface=""):
        self.cookies = list(set_cookies or [])
        self.body = str(body or "")
        self.h = {str(k).lower() for k in dict(resp_headers or {}).keys()}
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        import re as _re
        session_cookies = [c for c in self.cookies
                           if any(t in c.split("=", 1)[0].lower() for t in ("session", "sess", "sid", "auth", "jwt", "token"))]
        samesite_protected = any(_re.search(r"samesite\s*=\s*(lax|strict)", c, _re.I) for c in session_cookies)
        # anti-CSRF token evidence: a csrf/xsrf cookie, a token in the body, or a csrf header exposed
        token_cookie = any(_re.search(r"(csrf|xsrf)", c, _re.I) for c in self.cookies)
        token_body = _re.search(r"(csrf|xsrf)[-_]?token", self.body, _re.I) is not None
        token_header = any("csrf" in h or "xsrf" in h for h in self.h)
        has_token = token_cookie or token_body or token_header
        exposed = bool(session_cookies) and (not samesite_protected) and (not has_token)
        return ("verified" if exposed else "rejected"), {
            "surface": self.surface, "samesite_protected": samesite_protected, "anti_csrf_token": has_token,
            "session_cookie_seen": bool(session_cookies),
            "note": ("no SameSite protection and no anti-CSRF token (CSRF exposed)" if exposed else
                     ("SameSite Lax/Strict on the session cookie (mitigated)" if samesite_protected else
                      ("anti-CSRF token present" if has_token else "no session cookie to assess")))}


class SecurityHeadersOracle(Oracle):
    """Missing cookie flags + security response headers (commercial-parity passive check). VERIFIED (a
    weakness) iff a SESSION cookie is missing HttpOnly/Secure/SameSite, OR >=2 key security headers are
    absent (CSP, HSTS, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy). A single
    missing header alone is reported but does NOT verify (too noisy / low value). Reads only."""
    _SESSION_COOKIE_HINTS = ("session", "sess", "sid", "connect.sid", "token", "auth", "jwt", "csrftoken")

    def __init__(self, headers, set_cookies=None, *, over_https=True, oracle_id="secheaders@1", surface=""):
        # headers: case-insensitive dict-like; set_cookies: list of raw Set-Cookie header values
        self.h = {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}
        self.cookies = list(set_cookies or [])
        self.over_https = over_https
        self.id = oracle_id
        self.surface = surface

    def check(self, finding=None):
        # GUARD: no response captured (leg failed / target down) -> CANNOT ASSESS, not "all headers missing".
        # Without this an empty headers dict counts all 5 as absent and FALSELY verifies a misconfig.
        if not self.h and not self.cookies:
            return "rejected", {"surface": self.surface, "note": "no response headers/cookies to assess",
                                "n_issues": 0, "missing_headers": []}
        issues = []
        # 1) session-cookie flags
        for c in self.cookies:
            name = c.split("=", 1)[0].strip().lower()
            if not any(h in name for h in self._SESSION_COOKIE_HINTS):
                continue
            low = c.lower()
            miss = [flag for flag, tok in (("HttpOnly", "httponly"), ("SameSite", "samesite"),
                                           ("Secure", "secure")) if tok not in low]
            if not self.over_https and "Secure" in miss:
                miss.remove("Secure")                    # Secure is only meaningful over HTTPS
            for m in miss:
                issues.append({"kind": "cookie_flag", "detail": f"session cookie {name!r} missing {m}",
                               "severity": "medium"})
        # 2) security headers
        header_checks = [("content-security-policy", "CSP"), ("strict-transport-security", "HSTS"),
                         ("x-content-type-options", "X-Content-Type-Options"),
                         ("x-frame-options", "X-Frame-Options"), ("referrer-policy", "Referrer-Policy")]
        missing_headers = [label for key, label in header_checks if key not in self.h
                           and not (label == "X-Frame-Options" and "frame-ancestors" in self.h.get("content-security-policy", ""))]
        for label in missing_headers:
            issues.append({"kind": "missing_header", "detail": f"missing {label}", "severity": "low"})
        cookie_issue = any(i["kind"] == "cookie_flag" for i in issues)
        weakness = cookie_issue or (len(missing_headers) >= 2)
        sev = "medium" if cookie_issue else ("low" if weakness else "info")
        return ("verified" if weakness else "rejected"), {
            "surface": self.surface, "severity": sev, "n_issues": len(issues),
            "missing_headers": missing_headers, "issues": issues[:10],
            "note": ("session-cookie flag(s) missing" if cookie_issue else
                     (f"{len(missing_headers)} security headers missing" if weakness else "headers acceptable"))}


class RateLimitOracle(Oracle):
    """MISSING RATE-LIMIT / anti-automation on a SENSITIVE endpoint (auth/login/reset/OTP) -- enables
    brute-force / credential-stuffing. Given the statuses of N rapid IDENTICAL requests, VERIFIED (a
    weakness) iff: the endpoint is sensitive, the server PROCESSED all N (each got a real handled status,
    not a transport error) and NONE was a throttle/lockout signal (429 Too Many Requests, 503 with
    Retry-After, or 423 Locked). FP guard: needs >= min_attempts processed; a single 429 anywhere ->
    rejected (throttling present). Non-destructive: the caller uses a NONEXISTENT identity so no real
    account is locked; N is bounded so the burst can't be a DoS."""
    _THROTTLE = {429, 423, 503}

    def __init__(self, statuses, *, endpoint="", min_attempts=10, oracle_id="ratelimit@1"):
        self.statuses = [int(s) for s in (statuses or [])]
        self.endpoint = endpoint
        self.min_attempts = min_attempts
        self.id = oracle_id

    def check(self, finding=None):
        processed = [s for s in self.statuses if s and s > 0]
        throttled = [s for s in processed if s in self._THROTTLE]
        enough = len(processed) >= self.min_attempts
        weakness = enough and not throttled
        return ("verified" if weakness else "rejected"), {
            "endpoint": self.endpoint, "attempts": len(self.statuses), "processed": len(processed),
            "throttle_seen": bool(throttled), "throttle_statuses": sorted(set(throttled)),
            "status_histogram": {s: processed.count(s) for s in sorted(set(processed))},
            "note": ("no throttle after %d rapid requests to a sensitive endpoint (brute-force feasible)"
                     % len(processed) if weakness else
                     ("throttled (rate-limit present)" if throttled else "not enough processed attempts"))}


class SecretsOracle(Oracle):
    """SECRETS / PII / stack-traces leaked in a RESPONSE (commercial-parity passive check). Deterministic
    regex over a response body; verified iff >=1 HIGH-confidence secret pattern matches (private keys, AWS/
    cloud keys, JWTs, bearer/api tokens, connection strings) or a clear server stack-trace. Low-confidence
    PII (emails) is reported but does NOT alone verify (too noisy). Reads only -- non-destructive."""
    # (name, regex, high_confidence). Kept tight to limit false positives.
    _PATTERNS = [
        ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", True),
        ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", True),
        ("aws_secret", r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+]{40}", True),
        ("gcp_key", r"\bAIza[0-9A-Za-z\-_]{35}\b", True),
        ("slack_token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}", True),
        ("github_pat", r"\bghp_[0-9A-Za-z]{36}\b", True),
        ("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", True),
        ("bearer_token", r"(?i)\b(?:authorization|bearer|api[_-]?key|secret|token|password)\b\s*[=:]\s*[\"']?[A-Za-z0-9\-_./+]{16,}", True),
        ("conn_string", r"(?i)(?:postgres|mysql|mongodb|redis|amqp)://[^\s:@/]+:[^\s:@/]+@", True),
        ("stack_trace", r"(?:Traceback \(most recent call last\)|\bat [\w.$]+\([\w.]+\.java:\d+\)|\b[\w./]+\.(?:py|js|ts|rb|go):\d+\b.{0,40}(?:Error|Exception))", True),
        ("pii_email", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", False),
    ]

    def __init__(self, body, *, surface="", status=None, oracle_id="secrets@1", allow_pii_only=False):
        self.body = body or ""
        self.surface = surface
        self.status = status
        self.id = oracle_id
        self.allow_pii_only = allow_pii_only

    def check(self, finding=None):
        import re as _re
        hits, high = [], False
        for name, rx, hi in self._PATTERNS:
            try:
                m = _re.search(rx, self.body)
            except Exception:
                m = None
            if m:
                snip = (m.group(0) or "")[:12]
                hits.append({"kind": name, "high_confidence": hi, "sample": snip + "..."})
                high = high or hi
        verdict = "verified" if (high or (self.allow_pii_only and hits)) else "rejected"
        return verdict, {"surface": self.surface, "status": self.status, "n_hits": len(hits),
                         "kinds": sorted({h["kind"] for h in hits}), "hits": hits[:8],
                         "note": ("high-confidence secret/PII leaked in response" if high else
                                  ("only low-confidence PII (not verified alone)" if hits else "no secrets found"))}


class IdorOracle(Oracle):
    """BROKEN OBJECT-LEVEL AUTHZ (IDOR / BOLA) -- object-level, not surface-level (that is AuthzOracle). A
    non-owner role reads/writes a SPECIFIC object it should not, even on a surface it may generally reach.
    Verified only on FP-resistant, distinguishing signals per object:
      (1) the OWNER role gets the object (2xx)                  -- the object exists,
      (2) the ATTACKER role gets 2xx for the SAME object AND its body MATCHES the owner's body
          (same object id -> same bytes)                        -- the attacker actually read THAT object,
      (3) a CONTROL request (a nonexistent object id) as the attacker is DENIED/404
          (not a blanket 2xx)                                   -- the endpoint distinguishes existence,
          so a catch-all/SPA 200 cannot masquerade as access.
    `observations` = [{id, role, owner_status, attacker_status, owner_sha, attacker_sha, control_status}].
    Non-destructive: reads by default (GET); a write/BOLA variant plants-for-proof, never erases."""
    def __init__(self, observations, *, denied=(401, 403, 404), oracle_id="idor@1", surface=""):
        self.obs = observations or []
        self.denied = set(denied)
        self.id = oracle_id
        self.surface = surface

    def check(self, finding=None):
        leads = []
        for o in self.obs:
            owner_ok = 200 <= int(o.get("owner_status", 0)) < 300
            atk_ok = 200 <= int(o.get("attacker_status", 0)) < 300
            same_obj = bool(o.get("owner_sha")) and o.get("owner_sha") == o.get("attacker_sha")
            control_denied = int(o.get("control_status", 0)) in self.denied
            if owner_ok and atk_ok and same_obj and control_denied:
                leads.append({"id": o.get("id"), "role": o.get("role"),
                              "attacker_status": o.get("attacker_status"),
                              "owner_status": o.get("owner_status"),
                              "control_status": o.get("control_status"),
                              "verb": o.get("verb", "GET")})
        verdict = "verified" if leads else "rejected"
        return verdict, {"surface": self.surface, "n_leads": len(leads), "leads": leads[:8],
                         "checked": len(self.obs),
                         "note": ("object-level over-reach confirmed (attacker read the owner's object; "
                                  "control id denied)" if leads else
                                  "no object-level over-reach above the FP guards")}


class DifferentialOracle(Oracle):
    """MECH 2 -- oracle-diversity / DIFFERENTIAL discovery: read MANY signals on the SAME interaction across
    VARIANTS (role/session/order/concurrency) and flag a DELTA a human never computes -- status, body-hash,
    body-SIZE, JSON field-ORDER, response LATENCY (timing side-channel). NOISE-FLOOR gated: a latency delta
    counts only if it exceeds the baseline variant's own k-sample noise (median + MAD) AND a fraction of the
    median; a size delta only if it exceeds a fraction of the body. Emits a LEAD (not a verified finding) --
    per board doctrine, a lead promotes to verified only when a SECOND oracle confirms."""
    def __init__(self, observations, noise, *, latency_k_mad=6.0, size_floor_frac=0.05,
                 oracle_id="differential@1", surface=""):
        self.obs = observations or {}       # {variant: {status, latency_ms, body_len, body_sha, field_order}}
        self.noise = noise or {}            # {latency_med, latency_mad} from k baseline repeats
        self.latency_k_mad = latency_k_mad; self.size_floor_frac = size_floor_frac
        self.id = oracle_id; self.surface = surface

    def check(self, finding=None):
        vs = list(self.obs.items())
        leads = []
        med = float(self.noise.get("latency_med", 0.0))
        mad = max(float(self.noise.get("latency_mad", 0.0)), 1.0)
        for i in range(len(vs)):
            for j in range(i + 1, len(vs)):
                (va, oa), (vb, ob) = vs[i], vs[j]
                if oa.get("status") != ob.get("status"):
                    leads.append({"metric": "status", "a": va, "b": vb,
                                  "va": oa.get("status"), "vb": ob.get("status")})
                if oa.get("body_sha") != ob.get("body_sha"):
                    da = abs((oa.get("body_len") or 0) - (ob.get("body_len") or 0))
                    if da > self.size_floor_frac * max(oa.get("body_len") or 1, ob.get("body_len") or 1):
                        leads.append({"metric": "body_size", "a": va, "b": vb, "delta_bytes": da})
                    elif oa.get("field_order") != ob.get("field_order"):
                        leads.append({"metric": "field_order", "a": va, "b": vb})
                dl = abs((oa.get("latency_ms") or 0) - (ob.get("latency_ms") or 0))
                if dl > self.latency_k_mad * mad and dl > 0.2 * med:      # timing side-channel, noise-gated
                    leads.append({"metric": "latency", "a": va, "b": vb, "delta_ms": round(dl, 1),
                                  "noise_mad": round(mad, 1)})
        verdict = "lead" if leads else "rejected"
        return verdict, {"surface": self.surface, "leads": leads[:8], "n_leads": len(leads),
                         "noise": {"latency_med": round(med, 1), "latency_mad": round(mad, 1)},
                         "variants": {v: {"status": o.get("status"),
                                          "latency_ms": round(o.get("latency_ms") or 0, 1),
                                          "body_len": o.get("body_len")} for v, o in self.obs.items()}}


class DbOracle(Oracle):
    """Run a SQL query via docker-exec psql and assert the single scalar result matches.
    'verified' iff the returned value matches expected_regex."""
    def __init__(self, container, user, db, sql, expected_regex, *,
                 pgpassword="", oracle_id="db@1"):
        self.container, self.user, self.db, self.sql = container, user, db, sql
        self.expected_regex, self.pgpassword, self.id = expected_regex, pgpassword, oracle_id
    def check(self, finding: Finding):
        cmd = ["docker", "exec", "-e", f"PGPASSWORD={self.pgpassword}", self.container,
               "psql", "-U", self.user, "-d", self.db, "-t", "-A", "-c", self.sql]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()
        except Exception as e:
            return "inconclusive", {"error": repr(e)[:200]}
        ok = bool(re.search(self.expected_regex, out))
        return ("verified" if ok else "rejected"), {"query": self.sql, "result": out[:200],
                                                     "expected_regex": self.expected_regex}

# ---------- verifier ----------
class Verifier:
    """The ONLY component that transitions a finding to verified/rejected. Agents submit
    candidates + evidence; the verifier runs an out-of-band oracle and records the receipt."""
    def __init__(self, store: FindingStore):
        self.store = store
    @staticmethod
    def _build(fd: dict) -> Finding:
        """Construct a Finding from a (possibly malformed) store entry without a cryptic TypeError:
        keep only known fields and ensure the two REQUIRED ones exist (item 41)."""
        data = {k: fd[k] for k in fd if k in Finding.__dataclass_fields__}
        data.setdefault("claim_type", "unknown")
        data.setdefault("summary", "")
        return Finding(**data)

    @staticmethod
    def _dedupe_oracles(oracles: list) -> list:
        """Distinct oracles by id -- so CONSENSUS cannot be gamed by passing the same oracle twice (item 18)."""
        seen, uniq = set(), []
        for o in oracles:
            oid = getattr(o, "id", None) or id(o)
            if oid in seen:
                continue
            seen.add(oid); uniq.append(o)
        return uniq

    @staticmethod
    def _safe_check(oracle, finding):
        """Run one oracle's check; a failing oracle becomes an 'inconclusive' receipt, never an abort
        of the whole run (item 40)."""
        try:
            return oracle.check(finding)
        except Exception as e:
            return "inconclusive", {"error": str(e)[:200], "oracle_error": True,
                                    "oracle": getattr(oracle, "id", "?")}

    def verify(self, finding_id: str, oracle: Oracle) -> dict:
        fd = self.store.findings().get(finding_id)
        if not fd: raise KeyError(finding_id)
        finding = self._build(fd)
        status, receipt = self._safe_check(oracle, finding)
        self.store._transition(finding_id, status, oracle.id, receipt)
        return self.store.findings()[finding_id]

    def verify_consensus(self, finding_id: str, oracles: list, min_confirm: int = 2) -> dict:
        """Multi-oracle CONSENSUS gate (v3): a HIGH/CRITICAL finding is moved to `verified` ONLY when
        at least `min_confirm` INDEPENDENT oracles agree; lower severities need one. Every oracle's
        receipt is recorded. Oracles are DEDUPED by id (no gaming with duplicates) and each check is
        isolated (one failing oracle can't abort consensus). Stops one lucky/gamed oracle verifying HIGH."""
        fd = self.store.findings().get(finding_id)
        if not fd: raise KeyError(finding_id)
        finding = self._build(fd)
        oracles = self._dedupe_oracles(oracles)
        sev = (getattr(finding, "severity", "") or "").lower()
        need = min_confirm if sev in ("high", "critical") else 1
        confirms, receipts = 0, []
        confirm_classes = set()                       # DISTINCT oracle CLASSES that confirmed
        for oracle in oracles:
            st, rc = self._safe_check(oracle, finding)
            receipts.append({"oracle": getattr(oracle, "id", "?"), "status": st, "receipt": rc})
            if st == "verified":
                confirms += 1
                confirm_classes.add(type(oracle).__name__)
        # CLASS-INDEPENDENT consensus (board fix): a HIGH/CRITICAL needs `need` confirmations from DISTINCT
        # oracle CLASSES -- two checks of the SAME class (or a re-run/echo) are ONE independent signal, not
        # two. Lower severities still need one. This stops a single signal self-confirming a HIGH.
        independent = len(confirm_classes)
        status = "verified" if (independent >= need if sev in ("high", "critical") else confirms >= need) else "rejected"
        oid = "+".join(getattr(o, "id", "?") for o in oracles) or "consensus"
        self.store._transition(finding_id, status, oid,
                               {"confirms": confirms, "independent_classes": sorted(confirm_classes),
                                "need": need, "severity": sev, "receipts": receipts})
        return self.store.findings()[finding_id]
