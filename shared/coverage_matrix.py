"""
coverage_matrix.py - SHARED coverage tracker for both the co-pilot and ExploitGym.

Verified findings tell you what was FOUND; they don't tell you what was CHECKED-and-clean, so
gaps are invisible (the socket-survives-logout finding was missed for exactly this reason - no
one had a view of which surface x method x role x technique cells had been exercised). This
records every tested cell (append-only, hash-free - it's not security-critical, just coverage)
and reports the gaps against an expected matrix.

Usage:
    cov = CoverageTracker("cov.jsonl")
    cov.record(surface="/api/invoices/:id/payments", method="POST", role="owner", technique="race", result="clean")
    print(cov.report(surfaces=[...], roles=["owner","dispatcher","technician"], techniques=["authz","race","boundary"]))
"""
from __future__ import annotations
import os, json, time

# severity order for collapsing a cell: a 'finding' outranks 'clean'/'tested' and is never hidden.
_RESULT_RANK = {"tested": 1, "clean": 2, "finding": 3}


class CoverageTracker:
    def __init__(self, path: str):
        self.path = path
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)

    def record(self, surface: str, method: str = "", role: str = "", technique: str = "",
               result: str = "tested", note: str = "") -> None:
        """result: tested | clean | finding | inconclusive. Append-only."""
        ev = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "surface": surface, "method": method, "role": role,
              "technique": technique, "result": result, "note": note}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")

    def cells(self) -> set:
        out = set()
        if not os.path.exists(self.path):
            return out
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    out.add((e.get("surface", ""), e.get("method", ""), e.get("role", ""), e.get("technique", "")))
                except Exception:
                    pass
        return out

    def results_by_cell(self) -> dict:
        res = {}
        if not os.path.exists(self.path):
            return res
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    key = (e.get("surface", ""), e.get("role", ""), e.get("technique", ""))
                    val = e.get("result", "tested")
                    # `method` is intentionally collapsed for this surface x role x technique view, but a
                    # 'finding' must NEVER be overwritten by a later 'clean'/'tested' on the same cell
                    # (e.g. GET found a bug, POST was clean) -- keep the MOST SEVERE result seen.
                    if _RESULT_RANK.get(val, 0) >= _RESULT_RANK.get(res.get(key), -1):
                        res[key] = val
                except Exception:
                    pass
        return res

    def report(self, surfaces=None, roles=None, techniques=None) -> str:
        """Matrix of surface x (role,technique). '.'=untested, 'o'=tested/clean, 'X'=finding.
        Untested cells are the actionable gaps. Pass the EXPECTED axes to expose what's missing."""
        done = self.results_by_cell()
        surfaces = surfaces or sorted({s for (s, _r, _t) in done})
        roles = roles or sorted({r for (_s, r, _t) in done if r})
        techniques = techniques or sorted({t for (_s, _r, t) in done if t})
        sym = {"finding": "X", "clean": "o", "tested": "o", "inconclusive": "?"}
        cols = [f"{r}:{t}" for r in roles for t in techniques]
        lines = ["coverage matrix (o=tested  X=finding  ?=inconclusive  .=GAP)", "",
                 "surface".ljust(40) + " | " + " | ".join(cols),
                 "-" * (40 + 3 + len(" | ".join(cols)))]
        gaps = 0
        for s in surfaces:
            row = []
            for r in roles:
                for t in techniques:
                    v = done.get((s, r, t))
                    if v is None:
                        row.append("."); gaps += 1
                    else:
                        row.append(sym.get(v, "o"))
            lines.append(s.ljust(40) + " | " + " | ".join(c.center(len(c2)) for c, c2 in zip(row, cols)))
        lines += ["", f"GAPS (untested cells): {gaps} of {len(surfaces)*len(roles)*len(techniques)}"]
        return "\n".join(lines)
