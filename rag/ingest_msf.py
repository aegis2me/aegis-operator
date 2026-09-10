#!/usr/bin/env python3
"""
Map CISA/NVD CVEs -> Metasploit Framework modules, from the LOCAL Kali install (offline).

"Is there a Metasploit module, and what's its rank?" is one of the strongest
exploitability signals. Kali ships the full module tree; we parse each .rb for its
CVE references + rank and attach `MSF: <module fullname> (<Rank>)` to those CVE rows
with source 'msf'. No network.

Module dirs (first that exists; env MSF_MODULES to override):
  /usr/share/metasploit-framework/modules
  /opt/metasploit-framework/embedded/framework/modules
Source: https://github.com/rapid7/metasploit-framework
"""
import os
import re
import sys
from collections import defaultdict

import rag_db

CANDIDATES = [
    os.environ.get("MSF_MODULES", ""),
    "/usr/share/metasploit-framework/modules",
    "/opt/metasploit-framework/embedded/framework/modules",
]
CVE_REF_RE = re.compile(r"""['"]CVE['"]\s*,\s*['"](\d{4}-\d{4,7})['"]""", re.IGNORECASE)
RANK_RE = re.compile(r"\bRank\s*=\s*(\w+Ranking)\b")


def _find_dir():
    for d in CANDIDATES:
        if d and os.path.isdir(d):
            return d
    return None


def run(db_path=None):
    root = _find_dir()
    if not root:
        print("[msf] metasploit modules dir not found; is metasploit-framework installed?", file=sys.stderr)
        return
    conn = rag_db.connect(db_path)
    print(f"[msf] scanning {root}")

    cve_mods = defaultdict(set)
    scanned = 0
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".rb"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                txt = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            cves = {m.upper() for m in CVE_REF_RE.findall(txt)}
            if not cves:
                continue
            scanned += 1
            rank_m = RANK_RE.search(txt)
            rank = rank_m.group(1) if rank_m else "NormalRanking"
            full = os.path.relpath(path, root)[:-3]  # strip .rb -> e.g. exploit/multi/http/...
            for c in cves:
                cve_mods[f"CVE-{c}"].add(f"{full} ({rank})")

    n = 0
    for cve, mods in cve_mods.items():
        refs = "\n".join(f"MSF: {m}" for m in sorted(mods))
        rag_db.upsert_vuln(
            conn, cve, source="msf",
            refs=refs,
            fill_only=("description",),
            description=f"Metasploit module(s): {', '.join(sorted(mods))}",
        )
        n += 1
        if n % 500 == 0:
            conn.commit()
    conn.commit()
    rag_db.set_state(conn, "msf", note=f"{n} CVEs mapped from {scanned} modules")
    print(f"[msf] mapped {n} CVEs from {scanned} CVE-bearing modules")
    print("[msf] stats:", rag_db.stats(conn))
    conn.close()


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else None)
