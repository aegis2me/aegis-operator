"""
Verified task-graph planner (harness-agnostic core).

This is a GATED, BOUNDED autonomous task planner: it decomposes an objective into
a dependency-ordered sub-task graph, executes each node, and has the result graded
against explicit acceptance criteria -- accepting, retrying, or re-branching. Its
defining property is control:

  * The core never executes anything itself. It calls an injected `execute`
    callable; in every real harness that callable runs tools BEHIND THE HUMAN
    APPROVAL GATE. The planner cannot bypass the gate.
  * It is BOUNDED by PlannerConfig. Even the "unbounded" profile (used only for
    benchmarking the DeepSeek co-pilot against the bounded aegis side) keeps
    hard RUNAWAY GUARDS -- a total-node ceiling and a wall-clock budget -- so a
    self-correcting loop can never spin forever burning API credits or hammering
    a target. "Unbounded" means the *planning* caps (depth / attempts / re-branch)
    are relaxed, not that safety is removed.

Injected callables (provided by each harness adapter):
  decompose(node, feedback) -> Optional[list[dict]]
      Break `node` into ordered sub-tasks: [{abstract, description, verification,
      deps:[abstract,...]}] or None/[] if the node is atomic (do it directly).
  execute(node) -> str
      Actually perform an ATOMIC node (runs the harness's gated agent loop/tools).
      Returns a result/evidence string.
  verify(node, result) -> dict
      Grade `result` against node.verification. Returns
      {accepted: bool, need_turn: bool, reason: str}.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


class TaskImpossible(Exception):
    """Raised when a node cannot be satisfied within its bounds."""


class RunawayGuard(Exception):
    """Raised when a hard safety ceiling (node count / wall-clock) is hit."""


@dataclass
class PlannerConfig:
    bounded: bool = True
    max_depth: int = 3        # re-branch recursion depth
    max_attempts: int = 3     # direct-execute attempts per atomic node
    max_rebranch: int = 2     # times an internal node may re-decompose on failure
    # Hard runaway guards -- ALWAYS enforced, even unbounded:
    max_nodes: int = 60       # total nodes the whole run may create
    time_budget_s: int = 1800 # wall-clock ceiling for the whole run

    @classmethod
    def bounded_profile(cls) -> "PlannerConfig":
        # aegis / this project: tight, predictable.
        return cls(bounded=True, max_depth=3, max_attempts=3, max_rebranch=2,
                   max_nodes=60, time_budget_s=1800)

    @classmethod
    def unbounded_profile(cls) -> "PlannerConfig":
        # DeepSeek side: relaxed planning caps for benchmarking; runaway guards remain.
        return cls(bounded=False, max_depth=12, max_attempts=12, max_rebranch=8,
                   max_nodes=500, time_budget_s=7200)


@dataclass
class SubTask:
    abstract: str
    description: str = ""
    verification: str = ""
    deps: List[str] = field(default_factory=list)          # abstracts this depends on
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    parent: Optional[str] = None
    depth: int = 0
    status: str = "pending"   # pending|running|accepted|failed|impossible|blocked|skipped
    attempts: int = 0
    rebranches: int = 0
    result: str = ""
    reason: str = ""
    children: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        return d


class Planner:
    def __init__(self, config: PlannerConfig,
                 decompose: Callable[[SubTask, str], Optional[List[dict]]],
                 execute: Callable[["SubTask", str], str],
                 verify: Callable[[SubTask, str], dict],
                 logger: Optional[Callable[[str], None]] = None):
        self.cfg = config
        self._root_objective = ""
        self._root_verification = ""
        self._decompose = decompose
        self._execute = execute
        self._verify = verify
        self._log = logger or (lambda m: None)
        self.nodes: Dict[str, SubTask] = {}
        self._t0 = 0.0

    # ---- guards -------------------------------------------------------------
    def _check_runaway(self):
        if len(self.nodes) > self.cfg.max_nodes:
            raise RunawayGuard(f"node ceiling {self.cfg.max_nodes} exceeded")
        if self.cfg.time_budget_s and (time.time() - self._t0) > self.cfg.time_budget_s:
            raise RunawayGuard(f"time budget {self.cfg.time_budget_s}s exceeded")

    def _register(self, node: SubTask):
        self.nodes[node.id] = node
        self._check_runaway()

    # ---- public entry -------------------------------------------------------
    def run(self, objective: str, verification: str = "") -> dict:
        self._t0 = time.time()
        self._root_objective = objective
        self._root_verification = verification
        root = SubTask(abstract=objective, description=objective,
                       verification=verification or "Objective is satisfied with evidence.")
        self._register(root)
        try:
            self._execute_node(root)
            status = root.status
        except RunawayGuard as e:
            root.status = "failed"
            root.reason = f"runaway guard: {e}"
            status = root.status
            self._log(f"[planner] RUNAWAY: {e}")
        except TaskImpossible as e:
            root.status = "impossible"
            root.reason = str(e)
            status = root.status
        return self._summary(root, status)

    # ---- core recursion -----------------------------------------------------
    def _execute_node(self, node: SubTask, feedback: str = ""):
        self._check_runaway()
        node.status = "running"

        # Decide whether to decompose. Forced-atomic at the depth ceiling.
        subs = None
        if node.depth < self.cfg.max_depth:
            subs = self._decompose(node, feedback)
        if subs:
            self._run_children(node, subs)
        else:
            self._direct_execute(node)

    def _run_children(self, node: SubTask, sub_specs: List[dict]):
        # Materialize children.
        children: List[SubTask] = []
        for spec in sub_specs:
            child = SubTask(
                abstract=spec.get("abstract") or spec.get("description", "")[:80],
                description=spec.get("description", ""),
                verification=spec.get("verification", "Sub-task complete with evidence."),
                deps=list(spec.get("deps", [])),
                parent=node.id, depth=node.depth + 1,
            )
            self._register(child)
            node.children.append(child.id)
            children.append(child)

        by_abstract = {c.abstract: c for c in children}
        done: set = set()
        # Dependency-ordered execution: run a child once all its deps are accepted.
        remaining = list(children)
        progressed = True
        while remaining and progressed:
            progressed = False
            for child in list(remaining):
                unmet = [d for d in child.deps if d in by_abstract and by_abstract[d].abstract not in done]
                blocked = [d for d in child.deps if d in by_abstract and by_abstract[d].status in ("impossible", "failed", "blocked")]
                if blocked:
                    child.status = "blocked"
                    child.reason = f"blocked by failed dep(s): {blocked}"
                    remaining.remove(child)
                    progressed = True
                    continue
                if unmet:
                    continue
                # deps satisfied -> execute
                remaining.remove(child)
                progressed = True
                try:
                    self._execute_node(child)
                    if child.status == "accepted":
                        done.add(child.abstract)
                except TaskImpossible as e:
                    child.status = "impossible"
                    child.reason = str(e)

        # Any children still remaining are cyclically blocked.
        for child in remaining:
            child.status = "blocked"
            child.reason = "unresolved dependency (possible cycle)"

        accepted = [c for c in children if c.status == "accepted"]
        failed = [c for c in children if c.status in ("impossible", "failed", "blocked")]

        if not failed:
            node.status = "accepted"
            node.result = self._digest(node, accepted)
            node.reason = f"{len(accepted)}/{len(children)} sub-tasks accepted"
            return

        # Some children failed -> re-branch this node with feedback, up to the cap.
        if node.rebranches < self.cfg.max_rebranch:
            node.rebranches += 1
            fb = "Previous decomposition left these unsatisfied: " + \
                 "; ".join(f"{c.abstract} ({c.reason})" for c in failed)
            self._log(f"[planner] re-branch {node.rebranches}/{self.cfg.max_rebranch} of {node.abstract!r}")
            # Reset children linkage for a fresh decomposition attempt.
            node.children = []
            self._execute_node(node, feedback=fb)
            return

        node.status = "impossible"
        node.reason = "re-branch budget exhausted with failing sub-tasks"
        raise TaskImpossible(f"{node.abstract}: {node.reason}")

    def _direct_execute(self, node: SubTask):
        last_reason = ""
        for _ in range(self.cfg.max_attempts):
            self._check_runaway()
            node.attempts += 1
            result = self._execute(node, self._build_context(node))   # <-- gated tools happen here
            verdict = self._verify(node, result)
            if verdict.get("accepted"):
                node.status = "accepted"
                node.result = result
                node.reason = verdict.get("reason", "accepted")
                return
            last_reason = verdict.get("reason", "not accepted")
            node.result = result
            node.reason = last_reason
            if not verdict.get("need_turn", True):
                # Verifier says this is a hard no, not a "try again" -> stop early.
                break
        node.status = "impossible"
        node.reason = f"not satisfied after {node.attempts} attempt(s): {last_reason}"
        raise TaskImpossible(f"{node.abstract}: {node.reason}")

    # ---- helpers ------------------------------------------------------------
    def _build_context(self, node: SubTask) -> str:
        """
        The context threaded into every leaf executor so a sub-task stays ORIENTED:
        the overall objective/target, its ancestor chain, and the results of siblings
        already accepted. Without this each leaf spawns context-blind and drifts into
        re-deriving where it is (local-host enumeration, etc.).
        """
        lines = [f"OVERALL OBJECTIVE (this is what the whole plan is for): {self._root_objective}"]
        if self._root_verification:
            lines.append(f"OVERALL ACCEPTANCE: {self._root_verification}")
        # ancestor chain (parent -> ... -> root)
        chain, p = [], node.parent
        while p and p in self.nodes:
            chain.append(self.nodes[p].abstract)
            p = self.nodes[p].parent
        if chain:
            lines.append("PARENT TASK CHAIN: " + " <- ".join(chain))
        # already-accepted siblings under the same parent
        if node.parent and node.parent in self.nodes:
            done = [self.nodes[c] for c in self.nodes[node.parent].children
                    if c in self.nodes and c != node.id and self.nodes[c].status == "accepted"]
            if done:
                lines.append("ALREADY ESTABLISHED (results of sibling sub-tasks -- build on these, do not redo):")
                for s in done:
                    lines.append(f"  - {s.abstract}: {(s.result or s.reason or '')[:200]}")
        return "\n".join(lines)

    def _digest(self, node: SubTask, accepted: List[SubTask]) -> str:
        parts = [f"- {c.abstract}: {(c.result or c.reason)[:200]}" for c in accepted]
        return f"{node.abstract} -> completed via:\n" + "\n".join(parts)

    def _summary(self, root: SubTask, status: str) -> dict:
        counts: Dict[str, int] = {}
        for n in self.nodes.values():
            counts[n.status] = counts.get(n.status, 0) + 1
        return {
            "objective": root.abstract,
            "status": status,
            "result": root.result,
            "reason": root.reason,
            "nodes_total": len(self.nodes),
            "status_counts": counts,
            "elapsed_s": round(time.time() - self._t0, 1),
            "bounded": self.cfg.bounded,
            "config": self.cfg.__dict__,
            "graph": [n.to_dict() for n in self.nodes.values()],
        }
