#!/usr/bin/env python3
"""
scoring.py -- graded scoring for findings (adopted PATTERN from Microsoft PyRIT's scorer design, NOT the
dependency). PyRIT separates attack *generation* from *scoring* and grades on a scale (float / Likert)
rather than a single hardcoded verdict. Here that COMPLEMENTS -- never replaces -- the deterministic
oracle: the ORACLE still owns TRUTH (verified/rejected); the scorer adds an auditable, graded CONFIDENCE
and a SEVERITY suggestion from observable signals, so downstream ranking/reporting is not all-or-nothing.

Stdlib-only, offline. Scorers are pluggable: implement Scorer.score(signals) -> Score.

    from scoring import LikertSeverityScorer, ThresholdScorer, score_finding
    s = score_finding({"reproduced": True, "cross_account": True, "controllable_write": True})
    # -> Score(value=0.9, label='high', rationale='reproduced; cross-account; controllable write')
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Score:
    value: float                       # 0.0 - 1.0 graded confidence/impact
    label: str                         # info | low | med | high | critical
    rationale: str
    signals: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"value": round(self.value, 3), "label": self.label, "rationale": self.rationale,
                "signals": self.signals}


class Scorer:
    """Base scorer -- separate from generation (PyRIT pattern). Subclasses map signals -> a Score."""
    def score(self, signals: dict) -> Score:                       # pragma: no cover - interface
        raise NotImplementedError


_BANDS = [(0.85, "critical"), (0.7, "high"), (0.45, "med"), (0.2, "low"), (0.0, "info")]


def band(value: float) -> str:
    for thr, label in _BANDS:
        if value >= thr:
            return label
    return "info"


class ThresholdScorer(Scorer):
    """Turn one continuous signal into a pass/graded score against a threshold (PyRIT FloatScoreThreshold)."""
    def __init__(self, key: str, threshold: float = 0.5):
        self.key, self.threshold = key, threshold

    def score(self, signals: dict) -> Score:
        v = float(signals.get(self.key, 0.0) or 0.0)
        return Score(v, band(v), f"{self.key}={v:.2f} vs threshold {self.threshold}", {self.key: v})


# weighted evidence signals -> a Likert-style graded severity. Weights encode impact; presence of a
# signal contributes its weight. Tuned for the kinds of confirmations the oracle emits.
_SIGNAL_WEIGHTS = {
    "reproduced": 0.35,            # deterministically reproduced (fuzzer/oracle) -- strong
    "controllable_write": 0.30,    # attacker-controlled memory/data write -> potential RCE
    "cross_account": 0.25,         # IDOR / over-read across trust boundary
    "auth_bypass": 0.30,
    "rce": 0.40,
    "data_exfil": 0.25,
    "consensus": 0.15,             # >=2 independent oracle confirmations
    "info_only": -0.15,            # observation with no impact -> down-weight
    "dos_only": -0.10,             # crash but not controllable -> down-weight vs RCE
}


class LikertSeverityScorer(Scorer):
    """Combine boolean/float evidence signals into a graded severity (PyRIT LikertScale pattern)."""
    def __init__(self, weights: dict = None):
        self.weights = weights or _SIGNAL_WEIGHTS

    def score(self, signals: dict) -> Score:
        val, why = 0.0, []
        for k, w in self.weights.items():
            s = signals.get(k)
            if s:
                contrib = w * (float(s) if not isinstance(s, bool) else 1.0)
                val += contrib
                why.append(k.replace("_", " "))
        val = max(0.0, min(1.0, val))
        return Score(val, band(val), "; ".join(why) or "no impact signals", dict(signals))


def score_finding(signals: dict, scorer: Scorer = None) -> Score:
    """Convenience: grade a finding's evidence signals. Default = weighted Likert severity."""
    return (scorer or LikertSeverityScorer()).score(signals)


def _selftest():
    hi = score_finding({"reproduced": True, "controllable_write": True, "consensus": True})
    lo = score_finding({"reproduced": True, "dos_only": True, "info_only": True})
    mid = score_finding({"cross_account": True})
    print(f"  high-impact  -> {hi.value:.2f} {hi.label} ({hi.rationale})")
    print(f"  dos/info     -> {lo.value:.2f} {lo.label}")
    print(f"  idor-only    -> {mid.value:.2f} {mid.label}")
    t = ThresholdScorer("epss", 0.5).score({"epss": 0.94})
    print(f"  epss 0.94    -> {t.value:.2f} {t.label}")
    ok = hi.label in ("high", "critical") and hi.value > mid.value > lo.value and t.label == "critical"
    print("scoring selftest:", "OK" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if _selftest() else 1)
