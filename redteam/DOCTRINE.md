# Aegis — RED-TEAM mode doctrine (the third option)

Aegis has three run options:

| Mode | Doctrine | Purpose |
|---|---|---|
| **Operator** | contained mirror, non-destructive, no egress | co-pilot assessment of a mirror twin |
| **ExploitGym** | contained disposable twin, per-episode reset | benchmark autonomous exploitation, scored from ground truth |
| **Red-Team** (this) | **authorization-gated, RoE-bound, richer INTERNAL MIRROR environments** | first-class pen-test DEPTH (network / cloud / AD / binary / post-exploit) on owned, contained mirror twins |

Red-Team **broadens capability** — network-service exploitation, cloud/k8s/AD analysis, binary
exploit-dev, post-exploitation and lateral movement — and runs against **richer, multi-host INTERNAL
MIRROR environments** (still owned and contained), so it can prove full attack chains **without
touching production**. The relaxation is *capability + environment richness*, **not** "go live on
prod". It does **not** relax authorization or safety. The guardrails below are enforced in code
(`redteam/authorization.py`) and are **fail-closed** (no valid authorization ⇒ nothing runs).

## What changes vs the contained (Operator/ExploitGym) doctrine
- **Richer mirror environments** — a mirrored network / cloud / AD twin (multi-host), not a single app
  twin — still **owned and contained**, no live-prod egress.
- **Full exploitation breadth** — network-service exploitation, post-exploitation, lateral movement,
  binary exploit-dev, and cloud/k8s/AD attack-graph analysis — exercised **within the mirror**.
- **Scoped egress** — only within the mirror environment + explicitly authorized research hosts (e.g.
  the offline RAG). **No production egress.**

## What does NOT change (hard guardrails, enforced)
1. **Mandatory authorization.** A signed authorization artifact is required before any action:
   owner, engagement, approver, `authorized_at`/`expires_at`, scope allowlist, and Rules of Engagement.
   Missing / expired / unparseable ⇒ **refuse everything** (default-deny).
2. **Owned scope only.** Every target is checked against the scope allowlist (host suffix / exact /
   CIDR). Anything off-list is **blocked and audited** — no third-party systems, ever. No mass or
   indiscriminate targeting. **Cross-host lateral movement** (`redteam/lateral.py`) is bound by this
   too: a PIVOT to a newly reachable host re-checks that host against the same allowlist before any
   move against it, so a chain can only ever extend *within* scope.
3. **Non-destructive by default.** Erase / drop / truncate / DoS / data-destruction are blocked unless
   the RoE names that specific test in `allowed_destructive_tests` **with a rollback plan**. No
   supply-chain compromise of third parties.
   - **Two orthogonal controls (do NOT conflate them).** SAFETY (destructive vs non-destructive) is
     *what* you do; SCOPE (authorized vs not) is *which* target you may touch. `guard()` classifies every
     probe as `recon` (read-only/scan = safe), `active` (non-destructive state change) or `destructive`.
     Non-destructiveness is **necessary but never sufficient** — a read-only probe of an *unauthorized*
     host is still unauthorized and stays blocked. To get MORE done *cautiously*: safe `recon` runs
     freely on in-scope targets **and** on owner-authorized research hosts (`safe_recon_hosts` /
     `extra_research_hosts` / `safe_recon_domains` — the OSINT-recon exception, owned only); `active`
     writes run in-scope; only `destructive` or genuinely out-of-scope probes are refused.
4. **No persistence beyond the engagement.** Any implant/foothold is inventoried and removed at
   engagement end (`persistence: none` by default); nothing is left behind.
5. **Evasion is off** unless the RoE explicitly sets `evasion: "detection-test"` (a legitimate
   blue-team detection exercise for the owner) — never to evade the owner or hide activity from them.
6. **Full audit + kill-switch.** Every action is hash-chained to the audit log; a single flag halts the
   run. Findings are used only for the authorized report.
7. **Oracle-verified, attributed.** Same as the other modes: ground-truth verification (consensus for
   HIGH), every finding attributed to its source.

## Authorization artifact (`redteam/authorization.json`, gitignored)
```jsonc
{
  "owner": "Example Corp",
  "engagement": "example-app live pen-test 2026-Q3",
  "approver": "authorized-signer@owner",
  "authorized_at": "2026-09-07",
  "expires_at":   "2026-09-30",
  "scope": { "hosts": ["app.example-owned.tld"], "cidrs": ["10.0.5.0/24"], "domains": ["example-owned.tld"] },
  "rules_of_engagement": {
    "allowed_actions": ["recon", "web_exploit", "network_exploit", "post_exploit_lateral"],
    "destructive": false,
    "allowed_destructive_tests": [],
    "egress": "scoped",
    "persistence": "none",
    "evasion": "none",
    "extra_research_hosts": []
  }
}
```

## How to run
```
python redteam/redteam.py --auth redteam/authorization.json --objective "..." --target <in-scope host>
```
The run loads + validates the authorization, wires the iterative-hunt loop with a **scope-enforcing
executor** (every move's target + action + destructiveness is checked; violations are blocked and
audited), the recon/ASM leg, and the (pluggable) network-exploitation driver — all fail-closed.

> Everything here is for the owner's **own, authorized** systems. Off-scope, unauthorized, expired, or
> destructive-without-RoE actions are refused by design.
