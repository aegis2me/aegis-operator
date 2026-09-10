"""
lateral.py -- cross-host LATERAL MOVEMENT / post-exploitation chaining for RED-TEAM mode.

The base iterative-hunt loop deepens ONE confirmed foothold (novelty-over-convergence keeps that
bounded). Real red-team work also PIVOTS: web RCE -> internal service -> domain admin. This module
adds that, contained + authorization-gated:

  * On an ORACLE-CONFIRMED foothold, the host is marked OWNED in an AttackGraph (attack_graph.py).
  * From an owned host we enumerate the in-scope hosts reachable FROM it -- from an explicit internal
    topology (`pivot_map` in the RoE) if given, else a flat model where every other in-scope host is a
    pivot candidate -- and emit those as new hunt moves (a fresh HOST = a new surface, so the loop's
    depth gate accepts them as legitimate escalation, and they count as novel cross-host hops, not
    convergence on one bug).
  * Every pivot target still passes `Authorization.guard` in the executor (out-of-scope hosts blocked),
    and the whole thing stays non-destructive.
  * The chain to a crown-jewel `goal` host (e.g. the domain controller) is reconstructed from the
    graph and scored (reached? how many hops?).

Pure + dependency-free (imports only attack_graph); unit-testable without a live network.
"""
from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_graph import AttackGraph


def host_of(target: str) -> str:
    """Bare host from a URL / host:port / host."""
    t = str(target or "").strip()
    if not t:
        return ""
    if "://" in t:
        t = urlparse(t).hostname or ""
    else:
        t = t.split("/")[0].split(":")[0]
    return t.lower()


class PivotExpander:
    """Tracks owned hosts + the attack graph, and proposes scope-gated cross-host pivot moves."""

    def __init__(self, auth, pivot_map: dict = None, goal: str = None):
        self.auth = auth
        # host -> [hosts reachable once you own it]; empty => flat internal network model
        self.pivot_map = {host_of(k): [host_of(x) for x in v] for k, v in (pivot_map or {}).items()}
        self.goal = host_of(goal) if goal else None
        self.graph = AttackGraph()
        self.owned = set()
        self.owned_order = []
        self.entry = None

    def own(self, host, via=None, relation="has_session"):
        h = host_of(host)
        if not h or h in self.owned:
            return
        self.graph.add_node(h, "host", owned=True)
        if self.entry is None:
            self.entry = h
        v = host_of(via)
        if v and v != h:
            self.graph.add_edge(v, h, relation)
        self.owned.add(h)
        self.owned_order.append(h)

    def reachable_from(self, host):
        h = host_of(host)
        if h in self.pivot_map:
            cands = self.pivot_map[h]
        else:                                    # flat model: any other in-scope host is a candidate
            cands = [host_of(x) for x in self.auth.scope.get("hosts", [])]
        # only in-scope, not-yet-owned hosts (dedup, order-stable)
        out, seen = [], set()
        for c in cands:
            if c and c not in self.owned and c not in seen and self.auth.in_scope(c):
                seen.add(c); out.append(c)
        return out

    def pivot_moves(self, from_host, hop: int):
        """New cross-host moves from an owned host to its reachable in-scope neighbours."""
        moves = []
        for h in self.reachable_from(from_host):
            moves.append({
                "action": "recon", "target": h, "host": h, "surface": f"net:{h}",
                "vuln_class": "lateral", "mechanism": "pivot-recon", "trust": "internal",
                "expected_oracle": "reachable internal service", "pivot_from": from_host, "hop": hop,
                "why_novel": f"cross-host pivot {from_host} -> {h} (hop {hop})",
            })
        return moves

    def goal_reached(self) -> bool:
        return bool(self.goal) and self.goal in self.owned

    def chain(self) -> dict:
        """Reconstruct + score the pivot chain (entry -> ... -> goal)."""
        path = None
        if self.goal and self.entry:
            path = self.graph.best_path(self.entry, self.goal)
        return {
            "entry": self.entry, "goal": self.goal, "reached_goal": self.goal_reached(),
            "owned_hosts": list(self.owned_order),
            "hops": (len(path["edges"]) if path else 0),
            "path": (self.graph.describe(path) if path else None),
        }
