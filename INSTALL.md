# Aegis Operator — Installation Guide

Fresh-machine setup. Target platform: **Windows 11 + WSL2 (Kali) + Docker Desktop + Python 3.12**. This is the shape the toolkit is built and tested on.

---

## 1. Prerequisites

| Requirement | Why | Check |
|---|---|---|
| **Windows 11** (10 works) with virtualization enabled in BIOS | hosts WSL2 + Docker | `systeminfo \| findstr /i "Hyper-V"` |
| **WSL2** with a **Kali** distro (`kali-linux`) | the offensive toolset + RAG store + target containers run here | `wsl -l -v` shows `kali-linux` `2` |
| **Docker Desktop** (WSL2 backend) | runs the disposable target twin | `docker version` |
| **Python 3.12+** on Windows | runs the operator, ExploitGym, report renderers | `python --version` |
| **Git** | version control / export | `git --version` |
| An **LLM API key** (DeepSeek or any OpenAI-compatible endpoint) | the operator's brain | — |

Optional: an **OpenAI** key (adds GPT as a board analyst), a **Cloudflare Workers AI** token (adds open models to the board), a VPN with `vpn-ctl` inside Kali (egress control for live targets).

### 1a. Install WSL2 + Kali (if not present)
```powershell
wsl --install
wsl --install -d kali-linux
wsl --set-default-version 2
```
Open the Kali distro once to create a user, then update it:
```bash
sudo apt update && sudo apt -y full-upgrade
```

### 1b. Install Docker Desktop
Install Docker Desktop, enable **Settings → Resources → WSL Integration → kali-linux**, and confirm `docker version` works from both PowerShell and inside Kali.

---

## 2. Get the project onto the machine

Copy the whole `aegis-operator/` folder over (zip/USB/`git clone` from your own remote). Then:

```powershell
cd aegis-operator
python -m venv .venv ; .\.venv\Scripts\Activate.ps1   # optional but recommended
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium                  # only if you use browser_use
```

---

## 3. Configure secrets

**Never put real keys in any file but the two gitignored ones below.**

```powershell
copy secret.env.example secret.env                     # for python/bash consumers
copy set-env.local.ps1.example set-env.local.ps1       # for the PowerShell launchers
```
Edit both and set at minimum:
- `AEGIS_LLM_API_KEY`, `AEGIS_LLM_ENDPOINT`, `AEGIS_MODEL` (e.g. DeepSeek).

Optional: `OPENAI_API_KEY`, `CF_ACCOUNT_ID` + `CF_API_TOKEN` (the paid Cloudflare Workers AI plan unlocks the extra coders — kimi-k2.7-code, llama-4-scout, deepseek-r1-distill-32b).

Optional planning / RAG knobs:
- `AEGIS_PLANNER=0` disables the pre-execution **Planner** (see **docs/PLANNER.md**); left unset, each mode plans before it runs.
- `AEGIS_RAG_ONLINE=1` lets a run refresh the vuln store **and the MITRE ATT&CK techniques** from public feeds before hunting — offline-safe and staleness-gated (`AEGIS_MITRE_MAX_AGE_DAYS`, default 30).

**VPN egress gate (for the online feed/OSINT lane).** When the online refresh reaches out to the *public* vuln feeds, that egress can be forced through a VPN so it never leaves via the box's own IP (doctrine: OSINT/feed egress via the VPN). It is **opt-in and fail-closed** (`rag/rag_update.py::_egress_gate`): by default a run uses whatever egress is up; set **`AEGIS_VPN_REQUIRED=1`** to require a tunnel (and **`AEGIS_VPN_COUNTRY=<ISO>`** to pin a specific exit — `"any"`/unset = no country check). If a tunnel isn't up, it starts one from **`AEGIS_VPN_WG_CONF`** (a WireGuard `.conf` — key-based, no password, **preferred**) or falls back to **`AEGIS_VPN_CONFIG`** (an OpenVPN `.ovpn`). If a required/pinned VPN can't be established, the online refresh is **skipped** (the run continues fully offline) rather than leaking. **All VPN config files are gitignored** (`*.ovpn`, `wg*.conf`, `*wireguard*.conf`, `vpn-auth*`, `.config/vyprvpn/`) and the values live only in the gitignored `secret.env` — never in the repo.

If Python isn't on PATH, set `AEGIS_PYTHON` to the full `python.exe` path in `set-env.local.ps1`.

---

## 4. (Optional) Build the offline vuln RAG store

The RAG store lives inside Kali at `/opt/aegis-rag`. To install it:

```bash
# inside Kali
sudo mkdir -p /opt/aegis-rag && sudo chown $USER /opt/aegis-rag
cp /mnt/c/…/aegis-operator/rag/*.py /opt/aegis-rag/
cp /mnt/c/…/aegis-operator/rag/rag-ensure.sh /opt/aegis-rag/
python3 -m pip install requests            # rag deps (see rag/ scripts)
bash /opt/aegis-rag/rag-ensure.sh          # seeds/refreshes the store
```
To run it as a boot service, install the units in `rag/systemd/` (`rag-db.service`, `rag-backup.service`, `rag-backup.timer`) with `systemctl --user` or system-wide, then `systemctl enable --now rag-db`. The operator's `rag_search` tool queries this store; it degrades gracefully if the store is absent.

The same store also holds the **techniques DB** the Planner reads (curated + learned + **MITRE ATT&CK**). Populate/refresh the ATT&CK techniques with `python3 ingest_mitre.py` (or the `mitre` feed in `rag_update.py`); like the CVE feeds it is opt-in (`AEGIS_RAG_ONLINE=1`), staleness-gated (`AEGIS_MITRE_MAX_AGE_DAYS`), backed up with rollback, and offline-safe.

---

## 5. Stand up a target twin

Aegis tests a **disposable twin**, never production. Point it at any app you own running in Docker inside Kali (e.g. `https://localhost:8443`). Bring your target up with its own compose file; note its URL and any test credentials for your scenarios. Shape the twin from your app's **real code paths** with **synthetic data** and **no network egress**, run it in Docker inside Kali, and note its URL + any test credentials your scenarios need.

---

## 6. Run

```powershell
# from aegis-operator\
./start-all.ps1        # kali_driver (8901) + browser_use (8902) + bridge (8765)
```
Then, in a new shell:
```powershell
cd operator
python aegis_operator.py --task "<your mission>"      # add --auto-approve only in the sandbox
# or
cd ..\exploitgym ; python -m exploitgym.cli run <scenario>
# or watch the board
cd ..\board ; ./live_board.ps1
```

---

## 7. Verify the install

```powershell
cd operator  ; python -c "import config, verified_findings, coverage_matrix, planner_core, planner, cf_agent, code_suggester, code_review; print('operator OK')"
cd ..\exploitgym ; python -c "import sys; sys.path.insert(0,'exploitgym'); import verified_findings, coverage_matrix; print('exploitgym OK')"
```
Both should print `OK`. Then confirm the servers: after `start-all.ps1`, `http://127.0.0.1:8765` (bridge) should respond.

---

## 8. Exporting to another machine

The project is path-portable (no hardcoded user paths in code — everything resolves relative to the repo or reads an env var). To move it:
1. Copy the `aegis-operator/` folder (exclude `.venv/`, `__pycache__/`, `secret.env`, `set-env.local.ps1`, and the `*.jsonl` run stores — they're gitignored).
2. On the new machine, repeat **§1–§6**. Re-create `secret.env` / `set-env.local.ps1` there (secrets never travel in the repo).
3. If you use the RAG store, rebuild it inside that machine's Kali (**§4**) — it's large and machine-local.

---

## Troubleshooting

- **`python` not found in a launcher** → set `$env:AEGIS_PYTHON` in `set-env.local.ps1`.
- **Operator can't reach the LLM** → check `AEGIS_LLM_API_KEY`/`ENDPOINT`; a reasoning model may need `AEGIS_LLM_REASONING` and a larger token budget.
- **`rag_search` returns nothing** → the store isn't built (§4); it's optional and fails soft.
- **Target unreachable / TLS errors** → the twin uses a self-signed cert; use `-k`/`verify=False` in your probes, and confirm the container is up in Kali.
- **Board viewer empty** → set `AEGIS_BOARD_DIR` to the directory your board agents write to.
