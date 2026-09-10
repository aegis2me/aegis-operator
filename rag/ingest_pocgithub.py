#!/usr/bin/env python3
"""
Ingest the nomi-sec/PoC-in-GitHub dataset -> per-CVE GitHub proof-of-concept repos.

This is the offline, bulk, CVE-keyed answer to "is there a public PoC on GitHub for this
CVE?". The upstream repo is a tree of <year>/CVE-YYYY-NNNN.json files, each a JSON array
of GitHub repos ({html_url, description, stargazers_count, created_at}). We clone it once
(shallow) to a cache on Kali, then attach the top PoC repo URLs (by stars) to each CVE row
as references with source 'poc-github'. Offline after the clone; a re-run does `git pull`.

Usage:
  ingest_pocgithub.py [db] [--years 2023,2024,2025,2026] [--min-stars 0] [--top 5]
  ingest_pocgithub.py --repo /opt/aegis-rag/cache/PoC-in-GitHub   # custom clone dir

Source: https://github.com/nomi-sec/PoC-in-GitHub
"""
import json
import os
import subprocess
import sys

import rag_db

REPO_URL = os.environ.get("POCGH_REPO_URL", "https://github.com/nomi-sec/PoC-in-GitHub")
CACHE = os.environ.get("POCGH_CACHE", "/opt/aegis-rag/cache/PoC-in-GitHub")


def _ensure_repo(repo_dir):
    if os.path.isdir(os.path.join(repo_dir, ".git")):
        print(f"[pocgh] updating {repo_dir}")
        subprocess.run(["git", "-C", repo_dir, "pull", "--depth", "1", "--ff-only"],
                       check=False, capture_output=True)
    else:
        os.makedirs(os.path.dirname(repo_dir), exist_ok=True)
        print(f"[pocgh] cloning {REPO_URL} (shallow) -> {repo_dir}")
        r = subprocess.run(["git", "clone", "--depth", "1", REPO_URL, repo_dir],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[pocgh] clone failed: {r.stderr[:300]}", file=sys.stderr)
            return False
    return True


def run(db_path=None, repo_dir=None, years=None, min_stars=0, top=5):
    repo_dir = repo_dir or CACHE
    if not _ensure_repo(repo_dir):
        print("[pocgh] no repo; nothing ingested", file=sys.stderr)
        return
    conn = rag_db.connect(db_path)

    if years:
        year_dirs = [os.path.join(repo_dir, y) for y in years]
    else:
        year_dirs = [os.path.join(repo_dir, d) for d in sorted(os.listdir(repo_dir))
                     if d.isdigit() and len(d) == 4]

    n = 0
    for yd in year_dirs:
        if not os.path.isdir(yd):
            continue
        files = [f for f in os.listdir(yd) if f.startswith("CVE-") and f.endswith(".json")]
        for f in files:
            cve = f[:-5].upper()
            try:
                repos = json.load(open(os.path.join(yd, f), encoding="utf-8", errors="replace"))
            except Exception:
                continue
            if not isinstance(repos, list) or not repos:
                continue
            repos = [r for r in repos if isinstance(r, dict)]
            repos.sort(key=lambda r: r.get("stargazers_count", 0), reverse=True)
            picks = [r for r in repos if r.get("stargazers_count", 0) >= min_stars][:top]
            if not picks:
                picks = repos[:1]
            refs = "\n".join(
                f"PoC: {r.get('html_url','')} ({r.get('stargazers_count',0)}*) {(r.get('description') or '')[:80]}"
                for r in picks if r.get("html_url"))
            if not refs:
                continue
            rag_db.upsert_vuln(
                conn, cve, source="poc-github",
                refs=refs,
                # fill-only description so a PoC-only CVE (no NVD row yet) is still searchable
                fill_only=("description",),
                description=f"Public PoC(s) on GitHub: {len(repos)} repo(s). Top: "
                            + "; ".join(r.get('html_url', '') for r in picks[:3]),
            )
            n += 1
            if n % 500 == 0:
                conn.commit()
                print(f"[pocgh]   {n} CVEs...")
    conn.commit()
    rag_db.set_state(conn, "poc-github", note=f"{n} CVEs with GitHub PoC")
    print(f"[pocgh] attached GitHub PoC repos to {n} CVEs")
    print("[pocgh] stats:", rag_db.stats(conn))
    conn.close()


if __name__ == "__main__":
    args = sys.argv[1:]
    years = min_stars = None
    top = 5
    repo_dir = None
    if "--years" in args:
        years = args[args.index("--years") + 1].split(",")
    if "--min-stars" in args:
        min_stars = int(args[args.index("--min-stars") + 1])
    if "--top" in args:
        top = int(args[args.index("--top") + 1])
    if "--repo" in args:
        repo_dir = args[args.index("--repo") + 1]
    db = next((a for a in args if not a.startswith("--") and not a.isdigit()
               and "," not in a and not a.startswith("/opt")), None)
    run(db, repo_dir=repo_dir, years=years, min_stars=min_stars or 0, top=top)
