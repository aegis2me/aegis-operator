# 3-Tier Neutral Hunt Report — FixFlow mirror (https://localhost:8443)

_Neutral run: the crawler mapped surface with all creds, but every verdict is rendered at the LOWEST tier that reaches the finding. Owner/admin access was never used as a testing path. Tiers: **anon** (no creds) < **user** (any logged-in role) < **admin**._

## Severity summary (oracle-verified, deduplicated)

- **All passes (merged):** critical 0 · high 1 · medium 2 · low 0 · info 0  — 3 distinct findings
- **Pass A-technician(user):** critical 0 · high 2 · medium 1 · low 0 · info 0  — 3 findings
- **Pass B-anon:** critical 0 · high 1 · medium 1 · low 0 · info 0  — 2 findings

## Trust-tier delta (anon vs logged-in vs admin)

- **anon-reachable** (unauthenticated attacker surface): **3**
- **user-reachable** (any authenticated role — the 'logged-in gains'): **0**
- **admin-only** (reachable only at admin tier): **0**

> The anon block is what an attacker with **no account** can reach; the step up to the user block is the extra surface a login grants. These are genuinely different attack surfaces — a gap present at anon tier is strictly more severe than the same gap gated behind a login.

## Anon tier — reachable WITHOUT credentials  (3)

| Severity | Verdict | Surface | Finding | Oracle/Source | Pass |
|---|---|---|---|---|---|
| HIGH | confirmed | `image:fixflow-mirror-api:latest` | 191 HIGH/CRITICAL vulnerable deps in fixflow-mirror-api:latest | grype | A-technician(user)+B-anon |
| MEDIUM | confirmed | `/api/auth/logout` | No rate-limit/anti-automation on /api/auth/logout: 15 rapid requests, no throttle (brute-f | rate | A-technician(user) |
| MEDIUM | confirmed | `/api/auth/me` | No rate-limit/anti-automation on /api/auth/me: 15 rapid requests, no throttle (brute-force | rate | B-anon |

## Run context & variance

- Both passes ran NEUTRAL: crawler mapped surface with all creds (owner/admin excluded from the crawl set — AEGIS_CRAWL_ROLES=technician,anon), verdicts rendered at the lowest reaching tier. Owner/admin was never used as a testing path.
- Full parity coverage BOTH passes: 16/16 OWASP+API-Top-10 classes touched; both reach directions (app-code + scaffold/stack) exercised; pass B breached scaffold→code (1 bridge, depth 4). Pass B stopped at the MECH5 try-ceiling (50 real / 80 noise attempts).
- Anon vs user delta THIS run: every confirmed gap is anon-reachable pre-auth/scaffold surface (missing rate-limit on /api/auth/{logout,me}; 191 dep-CVEs in the stack image). No authenticated-only gap surfaced this run.
- VARIANCE (by design — novelty + randomized-tail mechanisms): pass A's user-tier budget went to MITRE recon (T1087/T1592/T1069/T1213) + 22 novel-code probes and did NOT re-trigger the stateful money-integrity findings (credit-note over-credit; deposit non-idempotent race) confirmed in PRIOR user-tier runs and documented in the remediation reports. A re-run, or a money-template-seeded user pass, surfaces those; run-to-run divergence is the intended behaviour of the discovery mechanisms.
- Run cost (cost-meter): pass B ≈ $0.012 (19 API calls; DeepSeek-v4-pro + CF qwen/llama-4-scout). Local compute (grype/crawler/oracles) is free.

---
_Only oracle-verified findings are listed. `EXPLOITABLE` = a tier below the intended one reaches an access-control gap; `confirmed` = a verified non-authz gap (dep-CVE / rate / secret / injection) exploitable at whatever tier can trigger it; `intended` = admin-doing-admin, listed for completeness, not a finding._
