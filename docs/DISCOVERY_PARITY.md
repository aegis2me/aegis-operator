# DISCOVERY PARITY — reaching the union of Cobalt Strike / Metasploit / MITRE ATT&CK+Caldera / Prelude

Goal: Aegis's **discovery** side as strong as the *combined* capability of the leading commercial + open-source
offense tooling, and beyond it on the novel axes. Driven by the multi-model board (see `board_ask.py`), built
into the shared discovery engine so it works across all three run modes (Operator / ExploitGym / Red-Team).

**Not statically bound.** Discovery is dynamic: *see the environment → survey techniques & tools live from
MITRE ATT&CK + the RAG + the techniques DB → check what's present → acquire what's missing (install-on-demand)
or write it (code-on-demand) → run the phases, consulting the board throughout.* The class→leg alias table is a
convenience fast-path, never the ceiling — the board can run **any** tool via `action:"tool"`.

## The dynamic survey (`operator/discovery.py: survey()`), run by the Planner before every mode
1. **See the env** — derive host/base; the Planner's fingerprint/stack ride along as intel.
2. **Survey (live, not a fixed list)** — `candidate_techniques()` merges the techniques-DB `discovery.*` entries
   with the **MITRE ATT&CK Discovery tactic** pulled from the RAG (`technique_search.py`).
3. **Check + acquire** — `ensure_tool()` checks presence; missing tools are installed on demand across
   apt/pipx/pip/go/npm (or a board-supplied recipe) when `AEGIS_TOOL_INSTALL=1` (gated, opt-in egress).
4. **Code-on-demand fallback** — for a technique whose tool(s) can't be provisioned, a `needs_code` probe is
   seeded so the **novel-code writer** (the code bench, `AEGIS_NOVEL_CODE`) *writes* a contained probe that
   fulfils the same discovery and the oracle proves it. The toolkit completes itself.
5. **Board composes the plan** — the env + live catalog + tool status go to the board, which **chooses,
   composes, and mixes** the actual discovery moves (built-in legs, `action:"tool"` with a specific command,
   or `needs_code` probes), aiming for the best discovery its current knowledge allows. The built-in legs are
   only an **offline fallback** when the board is unreachable. The loop's per-round board then keeps
   deciding/escalating. Kill-switches `AEGIS_DISCOVERY_SURVEY=0` (skip survey), `AEGIS_DISCOVERY_BOARD=0`
   (survey but don't board-compose). **Nothing here is a fixed list — it changes with the board every run.**

## Discovery vectors added (all shared legs in `operator/discovery.py`; oracle-verified, non-destructive)
| Leg / action | Parity with | ATT&CK | Verified when |
|---|---|---|---|
| `ldap` | Cobalt Strike / BloodHound AD recon | T1087.002, T1069.002, T1018 | bind ok + entries/SPNs returned |
| `cloud` | CS/MSF cloud modules (AWS/Azure/GCP) | T1526, T1580 | cloud API returns identity + resources |
| `fingerprint` | Nmap/Masscan service/version/TLS | T1046 | open service with a version banner |
| `external` | Shodan/Censys/CT-log surface mapping | T1590, T1596 | subdomains discovered from CT logs |
| `cred_harvest` | Enum4linux/CrackMapExec share spider | T1039, T1552.001 | readable share + a secret-looking file |
| `sbom` | source-level SCA (lockfile → CVE) | T1195.001 | a lockfile dep matches a known CVE |
| **`tool`** (open-ended) | **any tool, board-chosen, installed on demand** | (per technique) | prose oracle matches / clean run |

## Novel — beyond all of those tools
| Leg | Idea (none of the listed tools do this) | Verified when |
|---|---|---|
| `rag_infer` | cross-domain RAG inference: correlate uncorrelated signals (TLS SAN + leaked key + header) to infer a hidden surface, then confirm | inferred surface returns 2xx |
| `authz_fuzz` | grey-box fuzzing of **auth/authz logic** (JWT alg=none / stripped sig / tampered claims), not memory-safe parsers | a tampered token is accepted |
| `depconf` | dependency-confusion / typosquat vs live registry metadata | an internal dep name is unclaimed publicly (404) |
| `honeypot` | deception-aware discovery: response timing/error baselining tells real surface from decoys (API-path aware, so SPAs don't false-positive) | uniform code+length across distinct paths incl. an API path, ~0 timing variance |
| `attackpath` | graph attack-path over **oracle-confirmed** edges (BloodHound-style, but from verified reach) | a confirmed path to the goal exists |

## Coverage reporting (Caldera/Navigator-heatmap parity)
`operator/attack_coverage.py` emits a **MITRE ATT&CK Navigator layer**: capability techniques scored 1
(available) and oracle-verified techniques scored 2 (confirmed this run) — open it at the ATT&CK Navigator to
see coverage and gaps. `python operator/attack_coverage.py hunt_findings.jsonl --out attack_layer.json`.

## Config
- `AEGIS_DISCOVERY_SURVEY=0` — skip the dynamic survey; `AEGIS_DISCOVERY_BOARD=0` — survey but skip board-compose (built-in legs).
- `AEGIS_TOOL_INSTALL=1` — allow install-on-demand (default off; opt-in egress, contained Kali).
- `AEGIS_NOVEL_CODE=0` — disable code-on-demand.
- `AEGIS_SBOM_PATH`, `AEGIS_DC_HOST`, `AEGIS_CLOUD` (aws|azure|gcp), `AEGIS_GOAL` — feed the optional anchors.
- The board can always request a specific tool/technique via `action:"tool"` with `{tool, cmd, oracle, install?}`.

## Status (board's own rating, 2026-09-09)
Discovery ≈ **3/5** vs the union before this work (strong on the iterative hypothesis loop, oracle-verified
findings, grey-box fuzzing, RAG/technique-DB, credentialed web-logic; weak on AD/cloud/mass-fingerprint/external
breadth). These vectors + the dynamic survey close the named gaps and add the novel axes; parity is reached as
the acquired/coded tools verify per environment. Full per-member board answers: `board/board_files/ANSWER__*.md`.
