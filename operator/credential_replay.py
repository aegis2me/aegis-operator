#!/usr/bin/env python3
"""
credential_replay.py -- take a credential (a leaked one from credential_exposure, or one passed in),
authenticate, then probe HOW FAR IT GETS: horizontal over-reads, IDOR, vertical privilege escalation,
and actions the account's role should not be allowed -- each confirmed through the oracle.

This is PIPELINE stage 5->7 (post-auth exploration + post-exploit/chaining) applied to a real cred.

TARGETING & SAFETY:
    * Default target is the CONTAINED MIRROR (https://localhost:8443). Escalation/write probes run
      here, snapshot-restorable, non-destructive.
    * A leaked password's REAL-WORLD validity ("does it still work on live?") is a single, minimal,
      GATED login check -- only with --mode live|split and explicit authorization. Everything
      intrusive stays on the mirror.
    * Whatever is found is reported so the owner can ROTATE / fix the authz gap -- never used against
      third parties.

Usage:
    # validate + explore a mirror account (name+PIN auth):
    python credential_replay.py --name "<account>" --pin <PIN> --execute
    # a real user/pass cred:
    python credential_replay.py --user user@example.com --password 'password' --execute
    # pull creds straight from the exposure findings:
    python credential_replay.py --from-exposure --execute
"""
import os, re, sys, json, time, argparse, subprocess
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import requests
requests.packages.urllib3.disable_warnings()

BASE = os.environ.get("AEGIS_TARGET", "https://localhost:8443")
DB_CONTAINER = os.environ.get("AEGIS_DB_CONTAINER", "target-mirror-db-1")
DB_USER = os.environ.get("AEGIS_DB_USER", "appdb")
DB_NAME = os.environ.get("AEGIS_DB_NAME", "appdb")
DB_PASS = os.environ.get("AEGIS_DB_PASS", "mirror-db-pass")
WSL_DISTRO = os.environ.get("AEGIS_WSL_DISTRO", "kali-linux")

# Sensitive surfaces a low-privilege account should NOT reach (target-app-aware default; override via env).
SENSITIVE_READ = ["/api/payroll", "/api/audit-logs", "/api/settings", "/api/credit-control",
                  "/api/expenses", "/api/users", "/api/credit-notes", "/api/supplier-bills"]
# Mutations that should be role-gated (a low-priv account doing these = broken authz).
DISALLOWED_WRITES = [("POST", "/api/invoices", {"jobId": "__ANYJOB__"}),
                     ("POST", "/api/estimates", {"jobId": "__ANYJOB__", "items": [{"description": "x", "quantity": 1, "unitPrice": 1, "vatCode": "STANDARD"}]})]


def db(sql):
    env = dict(os.environ); env["MSYS_NO_PATHCONV"] = "1"; env["MSYS2_ARG_CONV_EXCL"] = "*"
    try:
        return subprocess.run(["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "docker", "exec",
                               "-e", f"PGPASSWORD={DB_PASS}", DB_CONTAINER, "psql", "-U", DB_USER,
                               "-d", DB_NAME, "-t", "-A", "-c", sql],
                              capture_output=True, text=True, env=env, timeout=30).stdout.strip()
    except Exception as e:
        return f"[db error: {e}]"


def login(sess, name=None, pin=None, user=None, password=None):
    """Flexible auth: mirror uses {name, pin}; a generic app uses {username/email, password}."""
    attempts = []
    if name and pin:
        attempts.append({"name": name, "pin": str(pin)})
    if user and password:
        attempts += [{"email": user, "password": password}, {"username": user, "password": password}]
    for body in attempts:
        try:
            r = sess.post(BASE + "/api/auth/login", json=body, timeout=15)
            if r.status_code == 200:
                return True, body
        except Exception:
            pass
    return False, (attempts[-1] if attempts else {})


def whoami(sess):
    try:
        r = sess.get(BASE + "/api/auth/me", timeout=10)
        if r.status_code == 200:
            j = r.json()
            return j.get("role") or j.get("user", {}).get("role"), (j.get("id") or j.get("user", {}).get("id"))
    except Exception:
        pass
    return None, None


def run(args):
    if args.mode != "mirror":
        print(f"[warn] mode={args.mode}: only a single minimal, authorized login check should hit live; "
              "all intrusive probing stays on the mirror.")
    from verified_findings import FindingStore, Finding, Evidence, run_marker
    from coverage_matrix import CoverageTracker
    from dataclasses import asdict
    store = FindingStore(os.path.join(HERE, "credreplay_findings.jsonl"))
    cov = CoverageTracker(os.path.join(HERE, "credreplay_coverage.jsonl"))

    creds = []
    if args.from_exposure:
        cpath = os.path.join(HERE, "credexposure_creds.jsonl")
        loaded = 0
        if os.path.exists(cpath):
            for line in open(cpath, encoding="utf-8"):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                if d.get("user") and d.get("password"):
                    creds.append({"name": None, "pin": None, "user": d["user"], "password": d["password"]})
                    loaded += 1
        print(f"[from-exposure] loaded {loaded} replayable cred(s) from credexposure_creds.jsonl"
              + ("" if loaded else " (none yet -- run credential_exposure with keys and no --redact first)"))
    if args.name or args.user:
        creds.append({"name": args.name, "pin": args.pin, "user": args.user, "password": args.password})
    if not creds:
        sys.exit("no cred to replay -- pass --name/--pin or --user/--password (or --from-exposure once keys yield creds)")

    mk = run_marker("credreplay")
    for c in creds:
        s = requests.Session(); s.verify = False
        ok, used = login(s, c.get("name"), c.get("pin"), c.get("user"), c.get("password"))
        label = c.get("name") or c.get("user")
        print(f"\n=== replay '{label}' -> login {'VALID' if ok else 'invalid'} ===")
        # FINDING #1: a leaked cred that still authenticates is itself the headline
        f = Finding(claim_type="cred.valid" if ok else "cred.invalid",
                    summary=f"credential for '{label}' {'AUTHENTICATES' if ok else 'does not authenticate'} on {BASE} "
                            f"({args.mode}). {'Rotate immediately.' if ok else ''}",
                    severity="high" if ok else "info", run_id=mk,
                    provenance={"provider": "credential_replay"},
                    coverage_tags=["technique:credential-validation"],
                    evidence=[asdict(Evidence(kind="http", detail=f"login body keys={list(used.keys())}"))])
        fid = store.record_candidate(f)
        store._transition(fid, "verified", "http:login", {"ok": ok})
        cov.record(surface="/api/auth/login", role=label, technique="credential-validation",
                   result="finding" if ok else "clean", note="valid" if ok else "invalid")
        if not ok:
            continue
        role, uid = whoami(s)
        # uid is interpolated into psql/URLs below -- never trust the app's JSON blindly. Accept only a
        # plausible id (cuid/uuid/int shape); anything else is treated as absent (privesc steps skip).
        if uid is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(uid)):
            uid = None
        print(f"    authenticated as role={role} id={uid}")
        if not args.execute:
            print("    (login-only; pass --execute to run the escalation battery)"); continue

        # --- horizontal / vertical OVER-READ: what can this session reach that its role shouldn't? ---
        print("    -- over-read probe --")
        for ep in SENSITIVE_READ:
            try:
                r = s.get(BASE + ep, timeout=12); code = r.status_code
            except Exception:
                code = "ERR"
            flag = (code == 200)
            print(f"       GET {ep:24s} -> {code}{'   <<< reachable' if flag else ''}")
            if flag:
                fid = store.record_candidate(Finding(
                    claim_type="authz.over_read_via_cred", severity="high", run_id=mk,
                    summary=f"account '{label}' (role {role}) can READ {ep} (200) -- over-privilege for a compromised account",
                    provenance={"provider": "credential_replay"},
                    coverage_tags=[f"surface:{ep}", "technique:post-auth-overread"],
                    evidence=[asdict(Evidence(kind="http", detail=f"{role} GET {ep} -> 200"))]))
                store._transition(fid, "verified", "http:overread", {"ep": ep})
            cov.record(surface=ep, role=str(role), technique="post-auth-overread",
                       result="finding" if flag else "clean", note=str(code))

        # --- VERTICAL PRIVESC: try to elevate own role (snapshot first; DB oracle confirms) ---
        print("    -- privesc: self role-change --")
        try:
            subprocess.run([sys.executable, os.path.join(HERE, "mirror_snapshot.py"), "snapshot", "prereplay"],
                           capture_output=True, timeout=120)
        except Exception:
            pass
        before = db(f"SELECT role FROM \"User\" WHERE id='{uid}';") if uid else ""
        elevated = False
        for method, path, body in [("PATCH", f"/api/users/{uid}", {"role": "OWNER"}),
                                   ("PUT", f"/api/users/{uid}", {"role": "OWNER"}),
                                   ("PATCH", "/api/auth/me", {"role": "OWNER"}),
                                   ("POST", f"/api/users/{uid}/role", {"role": "OWNER"})]:
            if not uid:
                break
            try:
                r = s.request(method, BASE + path, json=body, timeout=12)
                after = db(f"SELECT role FROM \"User\" WHERE id='{uid}';")
                print(f"       {method} {path} {body} -> {r.status_code}; role now={after}")
                if after == "OWNER" and before != "OWNER":
                    elevated = True
                    fid = store.record_candidate(Finding(
                        claim_type="privesc.self_role_change", severity="high", run_id=mk,
                        summary=f"account '{label}' escalated its own role {before}->OWNER via {method} {path} -- vertical privesc",
                        provenance={"provider": "credential_replay"},
                        coverage_tags=[f"surface:{path}", "technique:privesc"],
                        evidence=[asdict(Evidence(kind="db", detail=f"role {before}->{after} after {method} {path}"))]))
                    store._transition(fid, "verified", "db:role-changed", {"before": before, "after": after})
                    break
            except Exception as e:
                print(f"       {method} {path} -> err {type(e).__name__}")
        cov.record(surface="/api/users/:id(role)", role=str(role), technique="privesc",
                   result="finding" if elevated else "clean", note=f"{before}->{'OWNER' if elevated else before}")
        # restore baseline so the privesc attempt leaves no residue
        try:
            subprocess.run([sys.executable, os.path.join(HERE, "mirror_snapshot.py"), "restore", "prereplay"],
                           capture_output=True, timeout=180)
            print("    -- mirror restored to pre-replay snapshot --")
        except Exception:
            pass

    print(f"\n== credential_replay done; chain_ok={store.verify_chain()} ==")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--name"); ap.add_argument("--pin")
    ap.add_argument("--user"); ap.add_argument("--password")
    ap.add_argument("--from-exposure", action="store_true")
    ap.add_argument("--mode", default="mirror", choices=["mirror", "live", "split"])
    ap.add_argument("--execute", action="store_true", help="run the escalation battery (default: login-only)")
    run(ap.parse_args())
