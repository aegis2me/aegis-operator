#!/usr/bin/env python3
"""
rag_update.py -- ONLINE refresh of the aegis-rag CVE store, with a strict OFFLINE-SAFE contract.

Makes the store "offline AND online": before a run it can pull deltas from the PUBLIC vulnerability
feeds (CISA-KEV, EPSS, NVD lastMod-delta, Exploit-DB, Metasploit, nuclei) so findings reflect the
current CVE/KEV/EPSS state -- but it NEVER blocks a run: if disabled, offline, or a feed errors, the
existing local store is kept and everything proceeds fully offline. These are public vuln feeds (the
authorized-OSINT lane), never anything about the target.

Contract:
  * OPT-IN         -- does nothing unless --online (or AEGIS_RAG_ONLINE=1).
  * STALENESS-GATED -- skips the network if the store was refreshed within --max-age-hours.
  * ROLLBACK       -- backs the store up first; if integrity fails after a fetch, restores the backup.
  * PER-FEED ISOLATED -- a feed that errors/times out is logged and skipped; the others still apply.

Runs on the Kali box (where /opt/aegis-rag + the authorized egress live), from that directory:
  python3 rag_update.py --online --max-age-hours 12
  python3 rag_update.py --online --feeds kev,epss,nvd
"""
import argparse
import datetime
import glob
import json
import os
import shutil
import subprocess
import sys
import time

import rag_db

HERE = os.path.dirname(os.path.abspath(__file__))


# --- VPN egress gate (doctrine: external OSINT/feed egress goes via the VPN, never the box's own IP) --
def _tun_up() -> bool:
    try:
        out = subprocess.run(["ip", "-br", "addr"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return False
    return any(line.split() and line.split()[0].startswith(("tun", "wg")) for line in out.splitlines())


def _egress_country(timeout=10) -> str:
    try:
        return subprocess.run(["curl", "-s", "--max-time", str(timeout), "https://ifconfig.co/country-iso"],
                              capture_output=True, text=True, timeout=timeout + 2).stdout.strip()
    except Exception:
        return ""


def _egress_gate():
    """(ok, info). By DEFAULT the online fetch uses WHATEVER egress is up -- no fixed country/server, so a
    working exit (e.g. the host's VyprVPN client on any location) is never blocked by a mismatched rule.
    Enforcement is OPT-IN: AEGIS_VPN_REQUIRED=1 requires a VPN to be up; AEGIS_VPN_COUNTRY=<ISO> pins a
    specific exit (use "any" or leave unset for no country check). When required and a Kali tunnel isn't
    up yet, AEGIS_VPN_WG_CONF (WireGuard) or AEGIS_VPN_CONFIG (openvpn) is started first. FAIL-CLOSED:
    when a specific country/VPN IS required but not satisfied, online is SKIPPED (offline-safe) rather
    than leaking over the box's own IP."""
    want_cc = os.environ.get("AEGIS_VPN_COUNTRY", "").strip()
    pin_country = bool(want_cc) and want_cc.lower() != "any"        # "any"/unset = no fixed exit
    required = os.environ.get("AEGIS_VPN_REQUIRED") == "1" or pin_country
    if not required:
        return True, "vpn not required (using whatever egress is up)"
    wg = os.environ.get("AEGIS_VPN_WG_CONF", "").strip()   # WireGuard .conf (key-based, NO password)
    cfg = os.environ.get("AEGIS_VPN_CONFIG", "").strip()   # OpenVPN .ovpn (username/password)
    if not _tun_up():
        if wg:                                             # PREFERRED: WireGuard, no AUTH_FAILED risk
            try:
                subprocess.run(["wg-quick", "up", wg], capture_output=True, text=True, timeout=60)
            except Exception as e:
                return False, f"wg-quick up failed: {e}"
            for _ in range(12):
                if _tun_up():
                    break
                time.sleep(1)
        elif cfg:                                          # fallback: OpenVPN (needs a valid password)
            try:
                subprocess.Popen(["openvpn", "--config", cfg, "--daemon", "--log", "/tmp/aegis-vpn.log"])
                for _ in range(30):
                    if _tun_up():
                        break
                    time.sleep(2)
            except Exception as e:
                return False, f"vpn start failed: {e}"
    if not _tun_up():
        return False, "VPN required but no tunnel is up (set AEGIS_VPN_WG_CONF for WireGuard, or AEGIS_VPN_CONFIG for OpenVPN, or start it)"
    if pin_country:
        cc = _egress_country()
        if cc and cc.upper() != want_cc.upper():
            return False, f"egress country {cc!r} != pinned {want_cc!r} -- refusing (fail-closed)"
        return True, f"vpn up, egress={cc or '?'}"
    return True, "vpn tunnel up"

# feed -> argv for its ingest (fast/incremental variants; heavy backfills are deliberately excluded)
FEEDS = {
    "kev":       [sys.executable, "ingest_kev.py"],           # tiny daily catalog (exploited-in-wild)
    "epss":      [sys.executable, "ingest_epss.py"],          # exploit-probability scores
    "nvd":       [sys.executable, "ingest_nvd.py", "--since-last"],  # DELTA (lastMod), not backfill
    "exploitdb": [sys.executable, "ingest_exploitdb.py"],
    "msf":       [sys.executable, "ingest_msf.py"],
    "nuclei":    [sys.executable, "ingest_nuclei.py"],
    "cisa":      [sys.executable, "ingest_cisa.py"],
    "mitre":     [sys.executable, "ingest_mitre.py"],  # ATT&CK technique DB (Planner); self-staleness-gated
}
DEFAULT_FEEDS = ["kev", "epss", "nvd"]   # fast + highest-signal for "fresh before a run" (mitre = opt-in)


def _age_hours(conn):
    row = rag_db.get_state(conn, "refresh")     # -> (last_run, cursor, note) or None
    if not row:
        return None
    ts = (row[1] or row[0])                     # cursor (set by refresh) else last_run
    if not ts:
        return None
    try:
        return (datetime.datetime.now()
                - datetime.datetime.fromisoformat(str(ts).replace("Z", ""))).total_seconds() / 3600.0
    except Exception:
        return None


def _latest_backup(db):
    bks = sorted(glob.glob(os.path.join(os.path.dirname(db) or ".", "backups", "ragl-*.sqlite")))
    return bks[-1] if bks else None


def refresh(online, feeds=None, max_age_hours=12.0, db_path=None, per_feed_timeout=90):
    """Refresh the store from the feeds. Returns a summary dict; NEVER raises for a network/feed
    problem (offline-safe) -- the caller can always fall back to the existing local store."""
    if not online:
        return {"online": False, "skipped": "offline mode (pass --online or set AEGIS_RAG_ONLINE=1)"}
    feeds = feeds or list(DEFAULT_FEEDS)
    db = db_path or rag_db.DEFAULT_DB

    try:
        conn = rag_db.connect(db)
        before = rag_db.stats(conn)
        age = _age_hours(conn)
        conn.close()
    except Exception as e:
        return {"online": True, "error": f"cannot open store: {e}", "offline_fallback": True}

    if age is not None and age < max_age_hours:
        return {"online": True, "skipped": f"fresh ({age:.1f}h < {max_age_hours}h)", "stats": before}

    # VPN egress gate: external CVE-feed downloads go via the VPN, never the box's own IP.
    vpn_ok, vpn_info = _egress_gate()
    if not vpn_ok:
        return {"online": True, "skipped": f"vpn gate: {vpn_info}", "offline_fallback": True, "stats": before}

    # rollback point before touching the store online
    backup_path = None
    try:
        import rag_maint
        args = argparse.Namespace(db=db, keep=5, export=None)
        rag_maint.backup(args)
        backup_path = _latest_backup(db)
    except Exception as e:
        print(f"[update] backup skipped: {e}", file=sys.stderr)

    updated, failed = [], []
    for name in feeds:
        argv = FEEDS.get(name)
        if not argv:
            failed.append((name, "unknown feed")); continue
        print(f"[update] feed {name} ...")
        try:
            p = subprocess.run(argv, cwd=HERE, capture_output=True, text=True, timeout=per_feed_timeout)
            if p.returncode == 0:
                updated.append(name)
            else:
                failed.append((name, (p.stderr or p.stdout or "nonzero exit").strip()[-200:]))
        except Exception as e:
            failed.append((name, str(e)[:200]))          # network down / timeout -> keep going offline

    # integrity: if the store got corrupted mid-fetch, restore the pre-refresh backup
    conn = rag_db.connect(db)
    try:
        ok = conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    except Exception:
        ok = False
    if not ok and backup_path and os.path.exists(backup_path):
        conn.close()
        for ext in ("", "-wal", "-shm"):
            try:
                os.remove(db + ext)
            except FileNotFoundError:
                pass
        shutil.copy(backup_path, db)
        conn = rag_db.connect(db)
        failed.append(("_integrity", "store failed quick_check after fetch -> restored last backup"))

    rag_db.set_state(conn, "refresh", cursor=datetime.datetime.now().isoformat(),
                     note=f"updated={updated} failed={[f[0] for f in failed]}")
    conn.commit()          # persist the refresh timestamp so the staleness gate can read it next run
    after = rag_db.stats(conn)
    conn.close()
    return {"online": True, "updated": updated, "failed": failed,
            "rows_before": before, "rows_after": after, "backup": backup_path}


def main():
    ap = argparse.ArgumentParser(description="Online (offline-safe) refresh of the aegis-rag store.")
    ap.add_argument("--online", action="store_true", default=(os.environ.get("AEGIS_RAG_ONLINE") == "1"))
    ap.add_argument("--feeds", default=",".join(DEFAULT_FEEDS))
    ap.add_argument("--max-age-hours", type=float, default=float(os.environ.get("AEGIS_RAG_MAX_AGE_H", "12")))
    ap.add_argument("--db", default=None)
    ap.add_argument("--per-feed-timeout", type=int, default=90)
    a = ap.parse_args()
    feeds = [f.strip() for f in a.feeds.split(",") if f.strip()]
    print(json.dumps(refresh(a.online, feeds, a.max_age_hours, a.db, a.per_feed_timeout), indent=2, default=str))


if __name__ == "__main__":
    main()
