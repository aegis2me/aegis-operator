#!/usr/bin/env python3
"""
Map CVEs -> nuclei templates from the LOCAL nuclei-templates checkout (offline).

nuclei ships a large, community-maintained set of CVE-tagged detection/exploitation
templates -- especially strong for WEB apps (directly relevant to target-app). We map each
CVE-tagged template to its CVE row with source 'nuclei', so a RAG/exploit lookup can say
"nuclei template available: http/cves/2021/CVE-2021-44228.yaml" and the operator can run
it live against the target.

Template dirs (first that exists; env NUCLEI_TEMPLATES to override):
  ~/nuclei-templates, ~/.local/nuclei-templates, /root/nuclei-templates,
  /usr/share/nuclei-templates
Source: https://github.com/projectdiscovery/nuclei-templates
"""
import os
import re
import sys
from collections import defaultdict

import rag_db

HOME = os.path.expanduser("~")
CANDIDATES = [
    os.environ.get("NUCLEI_TEMPLATES", ""),
    os.path.join(HOME, "nuclei-templates"),
    os.path.join(HOME, ".local", "nuclei-templates"),
    "/root/nuclei-templates",
    "/usr/share/nuclei-templates",
]
CVE_RE = rag_db.CVE_RE
FNAME_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\.ya?ml$", re.IGNORECASE)
IDLINE_RE = re.compile(r"(?im)^\s*(?:id|cve-id)\s*:\s*['\"]?(CVE-\d{4}-\d{4,7})")


def _find_dir():
    for d in CANDIDATES:
        if d and os.path.isdir(d):
            return d
    return None


def run(db_path=None):
    root = _find_dir()
    if not root:
        print("[nuclei] nuclei-templates dir not found; run `nuclei -update-templates`", file=sys.stderr)
        return
    conn = rag_db.connect(db_path)
    print(f"[nuclei] scanning {root}")

    cve_tpls = defaultdict(set)
    scanned = 0
    for dirpath, _, files in os.walk(root):
        if os.sep + ".git" in dirpath:
            continue
        for fn in files:
            if not fn.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            cve = None
            m = FNAME_RE.search(fn)
            if m:
                cve = m.group(1).upper()
            else:
                # cheap scan of the id / classification for a CVE id
                try:
                    head = open(path, encoding="utf-8", errors="replace").read(4000)
                except OSError:
                    continue
                im = IDLINE_RE.search(head) or CVE_RE.search(head)
                if im:
                    cve = (im.group(1) if im.re is IDLINE_RE else im.group(0)).upper()
            if not cve:
                continue
            scanned += 1
            cve_tpls[cve].add(rel.replace("\\", "/"))

    n = 0
    for cve, tpls in cve_tpls.items():
        refs = "\n".join(f"nuclei: {t}" for t in sorted(tpls))
        rag_db.upsert_vuln(
            conn, cve, source="nuclei",
            refs=refs,
            fill_only=("description",),
            description=f"nuclei template(s): {', '.join(sorted(tpls)[:3])}",
        )
        n += 1
        if n % 500 == 0:
            conn.commit()
    conn.commit()
    rag_db.set_state(conn, "nuclei", note=f"{n} CVEs from {scanned} templates")
    print(f"[nuclei] mapped {n} CVEs from {scanned} CVE-tagged templates")
    print("[nuclei] stats:", rag_db.stats(conn))
    conn.close()


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else None)
