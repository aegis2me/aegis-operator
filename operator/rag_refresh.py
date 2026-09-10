#!/usr/bin/env python3
"""
rag_refresh.py -- host-side trigger to UPDATE THE CVE DB BEFORE A RUN (offline AND online).

`ensure_fresh()` is called at the start of a hunt in every mode. By default it is a fast no-op: the
store is used offline. When AEGIS_RAG_ONLINE=1 (opt-in), it shells into Kali and runs the offline-safe
`rag_update.py`, which pulls public-feed deltas (KEV/EPSS/NVD-delta/...) only if the store is older
than the staleness window, backs up first, and rolls back on any integrity problem. It NEVER blocks a
run: a network failure or timeout is caught and the run proceeds on the existing local store.

    from rag_refresh import ensure_fresh
    ensure_fresh()          # honours AEGIS_RAG_ONLINE / AEGIS_RAG_MAX_AGE_H
"""
from __future__ import annotations

import json
import os
import subprocess


def ensure_fresh(online: bool = None, max_age_hours=None, distro: str = None, timeout: int = 360) -> dict:
    """Update the CVE RAG before a run. Returns a summary dict; offline-safe (never raises)."""
    if online is None:
        online = os.environ.get("AEGIS_RAG_ONLINE") == "1"
    if not online:
        return {"online": False, "skipped": "offline mode (set AEGIS_RAG_ONLINE=1 to refresh)"}
    distro = distro or os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
    mah = str(max_age_hours if max_age_hours is not None else os.environ.get("AEGIS_RAG_MAX_AGE_H", "12"))
    home = os.environ.get("AEGIS_RAG_HOME", "/opt/aegis-rag")
    cmd = f"cd {home} && python3 rag_update.py --online --max-age-hours {mah}"
    try:
        p = subprocess.run(["wsl", "-d", distro, "-u", "root", "--", "bash", "-lc", cmd],
                           capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        # network/Kali unreachable -> keep going on the existing offline store
        return {"online": True, "error": str(e)[:200], "offline_fallback": True}
    out = p.stdout or ""
    i = out.find("{")
    if i >= 0:
        try:
            return json.loads(out[i:])
        except Exception:
            pass
    return {"online": True, "raw": out[-400:], "stderr": (p.stderr or "")[-200:]}


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Update the CVE RAG before a run (offline-safe, opt-in).")
    ap.add_argument("--online", action="store_true", default=None)
    ap.add_argument("--max-age-hours", type=float, default=None)
    a = ap.parse_args()
    print(json.dumps(ensure_fresh(online=(a.online if a.online else None),
                                  max_age_hours=a.max_age_hours), indent=2, default=str))


if __name__ == "__main__":
    main()
