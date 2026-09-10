#!/usr/bin/env python3
"""
planner.py -- THE PLANNER (stage 2): the prior-success Ranker + plan core that runs BEFORE the
iterative-hunt loop (see docs/PLANNER.md). It:

  1. FINGERPRINTS the target (surfaces / stack / roles / task-level).
  2. Queries the ALREADY-BUILT techniques DB (curated + learned + MITRE ATT&CK) via
     rag/technique_search.py for the best PRIOR-SUCCESSFUL (technique, tool) combos -- ranked by the
     DB's keyword x learned-EV scoring, enriched with the learned co-occurrence ("if A worked, also
     try B").
  3. Emits those as ranked MODE-1 anchor `seed_moves` for the 40-attempt loop (so the hunt STARTS from
     what worked before + ATT&CK-informed anchors, then diversifies per the loop's own rules).
  4. On an oracle-VERIFIED success, WRITES BACK the winning technique+tool+scenario to the learned DB
     so the next plan ranks it higher (closed-loop learning).

Read-only DB query (shelled into Kali where /opt/aegis-rag lives) + append-only learn. No target action
happens here -- the Planner only proposes; the loop + oracle + doctrine gates still govern execution.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WSL_DISTRO = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
RAG_HOME = os.environ.get("AEGIS_RAG_HOME", "/opt/aegis-rag")


def _shell_argv(distro, cmd):
    """Platform shim (see memory nested-wsl-shim): the RAG/techniques DB lives in Kali. On Windows we
    reach it via `wsl -d <distro>`; but when this code ALREADY runs INSIDE the Linux distro (the in-Kali
    hunt path -- sys.platform != 'win32'), there is no wsl.exe, so a bare ['wsl',...] call fails with
    Errno 2 and the Planner silently returns [] (no MITRE/techniques intel reaches the board). Run
    `bash -lc` locally in that case."""
    if sys.platform == "win32":
        return ["wsl", "-d", distro or WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd]
    return ["bash", "-lc", cmd]

# technique class -> which shared vector (vectors.py) an anchor move should use.
_NONWEB = {"recon", "supply_chain", "static", "fuzz", "misconfig", "rag"}
_WEB_FAMILIES = {"authz", "injection", "xss", "ssrf", "ssti", "xxe", "traversal", "auth",
                 "mass_assignment", "race", "csrf", "deserialization", "rate_enum",
                 "business_logic", "info_disclosure"}
# ATT&CK tactic-classes map to a reconnaissance/enumeration starting probe by default.
_ATTACK_RECON = {"reconnaissance", "discovery", "resource_development", "collection",
                 "credential_access", "lateral_movement", "privilege_escalation", "execution",
                 "persistence", "defense_evasion", "command_and_control", "exfiltration", "impact",
                 "initial_access"}


# DISCOVERY-PARITY vectors (operator/discovery.py): technique-class synonym -> discovery leg action.
_DISCOVERY = {
    "ldap": "ldap", "ad": "ldap", "active_directory": "ldap", "kerberos": "ldap", "bloodhound": "ldap",
    "cloud": "cloud", "aws": "cloud", "azure": "cloud", "gcp": "cloud", "container": "cloud",
    "fingerprint": "fingerprint", "portscan": "fingerprint", "port_scan": "fingerprint",
    "network_service_discovery": "fingerprint", "nmap": "fingerprint", "service_discovery": "fingerprint",
    "external": "external", "osint": "external", "subdomain": "external", "attack_surface": "external",
    "cert_transparency": "external", "passive_dns": "external",
    "cred_harvest": "cred_harvest", "smb": "cred_harvest", "share_enum": "cred_harvest", "secrets": "cred_harvest",
    "sbom": "sbom", "supply_chain_source": "sbom", "lockfile": "sbom",
    "rag_infer": "rag_infer", "cross_domain": "rag_infer", "inference": "rag_infer",
    "authz_fuzz": "authz_fuzz", "jwt": "authz_fuzz", "auth_bypass": "authz_fuzz", "token_fuzz": "authz_fuzz",
    "depconf": "depconf", "dependency_confusion": "depconf", "typosquat": "depconf",
    "honeypot": "honeypot", "deception": "honeypot",
    "attackpath": "attackpath", "attack_path": "attackpath", "path_analysis": "attackpath",
}


def _class_to_action(cls: str) -> str:
    c = (cls or "").lower()
    if c in _DISCOVERY:
        return _DISCOVERY[c]
    if c in _NONWEB:
        return c
    if c in _WEB_FAMILIES:
        return "web"
    if c in _ATTACK_RECON:
        return "recon"
    return "web"


# CANDIDATE-PLAN SCENARIOS (stage 3): each varies technique ORDER, novel-probe budget, surface
# priority. `fit` weights which scenario leads per task-level (fact-finding favours covert/thorough;
# a pentest favours fast-track). The board can still devise novel moves inside every scenario.
_SCENARIOS = [
    {"name": "fast-track",
     "desc": "highest-impact injection/authz/logic classes first, few novel probes -- reach a foothold fast",
     "emphasis": ["injection", "sql", "authz", "auth", "business_logic", "idor", "command"],
     "novel": 2, "fit": {"pentest": 3, "envelope-pushing": 2, "fact-finding": 1}},
    {"name": "thorough",
     "desc": "full breadth across every relevant class plus the most board-novel approaches",
     "emphasis": [],
     "novel": 5, "fit": {"pentest": 2, "envelope-pushing": 3, "fact-finding": 2}},
    {"name": "covert",
     "desc": "low-noise recon / misconfig / info-disclosure weighting -- map before you push",
     "emphasis": ["recon", "misconfig", "supply_chain", "information disclosure",
                  "info_disclosure", "discovery", "collection"],
     "novel": 3, "fit": {"pentest": 1, "envelope-pushing": 2, "fact-finding": 3}},
]


class Planner:
    def __init__(self, kali_distro: str = None, rag_home: str = None):
        self.distro = kali_distro or WSL_DISTRO
        self.rag_home = rag_home or RAG_HOME
        # Drive Kali up front: the RAG DB + toolset live inside it, so every RAG query / tool check
        # below needs it running. Boots a stopped distro (fail-safe; AEGIS_KALI_AUTOSTART=0 to skip).
        self.kali_up = ensure_kali(self.distro)

    # ---- techniques-DB query (shelled into Kali, JSON) ----
    def _ts(self, query: str, cls: str = None, limit: int = 12) -> list:
        cmd = f"cd {self.rag_home} && python3 technique_search.py --json --limit {int(limit)}"
        if cls:
            cmd += f" --class {cls}"
        cmd += f" {json.dumps(query)}"          # quoted query
        try:
            p = subprocess.run(_shell_argv(self.distro, cmd),
                               capture_output=True, text=True, timeout=120)
            out = (p.stdout or "").strip()
            i = out.find("[")
            return json.loads(out[i:]) if i >= 0 else []
        except Exception:
            return []

    def _cooccur(self, cls: str, limit: int = 6) -> list:
        cmd = (f"cd {self.rag_home} && python3 technique_search.py --json --cooccur {cls} "
               f"--limit {int(limit)}")
        try:
            p = subprocess.run(_shell_argv(self.distro, cmd),
                               capture_output=True, text=True, timeout=60)
            out = (p.stdout or "").strip()
            i = out.find("{")
            return (json.loads(out[i:]).get("related_techniques", []) if i >= 0 else [])
        except Exception:
            return []

    # ---- plan building ----
    # ---- RECON auto-detect: derive the ACTUAL stack from the live target (so relevance is data-driven) ----
    # Signal -> stack-term maps. Kept small + high-signal; extend as needed.
    _RECON_SERVER = {"caddy": ["caddy"], "nginx": ["nginx"], "apache": ["apache"],
                     "werkzeug": ["python", "flask"], "gunicorn": ["python"], "uvicorn": ["python", "asgi"],
                     "express": ["node", "express"], "kestrel": ["dotnet"], "iis": ["dotnet", "windows"]}
    _RECON_XPB = {"express": ["node", "express"], "php": ["php"], "asp.net": ["dotnet"],
                  "next.js": ["node", "nextjs", "react"], "servlet": ["java"]}
    _RECON_COOKIE = {"connect.sid": ["node", "express"], "laravel_session": ["php", "laravel"],
                     "jsessionid": ["java"], "phpsessid": ["php"], "csrftoken": ["python", "django"],
                     "sessionid": ["python", "django"], "_rails": ["ruby", "rails"]}
    _RECON_BODY = {"__next_data__": ["node", "nextjs", "react"], "/_next/": ["node", "nextjs", "react"],
                   "ng-version": ["angular"], "data-reactroot": ["react"], "id=\"root\"": ["spa"],
                   "wp-content": ["php", "wordpress"], "csrfmiddlewaretoken": ["python", "django"],
                   "prisma": ["node", "prisma"], "fielderrors": ["node", "zod"], "/assets/index-": ["vite"]}

    def _detect_stack(self, base: str, timeout: int = 5) -> list:
        """Infer the target's stack from live HTTP signals (Server / X-Powered-By / Set-Cookie / body).
        In-process (portable: Windows or inside Kali). Fail-safe: any error -> [] (fall back to generic
        terms). Disable with AEGIS_PLANNER_RECON=0."""
        if not base or os.environ.get("AEGIS_PLANNER_RECON", "1") == "0":
            return []
        if not str(base).lower().startswith("http"):
            base = "https://" + str(base)
        try:
            import requests
            try:
                requests.packages.urllib3.disable_warnings()
            except Exception:
                pass
        except Exception:
            return []
        found = set()
        for path in ("/", "/api", "/api/auth/login"):
            try:
                r = requests.get(base.rstrip("/") + path, verify=False, timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            srv = (r.headers.get("Server") or "").lower()
            for k, v in self._RECON_SERVER.items():
                if k in srv:
                    found.update([k] + v)
            xpb = (r.headers.get("X-Powered-By") or "").lower()
            for k, v in self._RECON_XPB.items():
                if k in xpb:
                    found.update(v)
            sc = (r.headers.get("Set-Cookie") or "").lower()
            for k, v in self._RECON_COOKIE.items():
                if k in sc:
                    found.update(v)
            ct = (r.headers.get("Content-Type") or "").lower()
            if "json" in ct:
                found.update(["api", "json"])
            body = (r.text or "")[:20000].lower()
            for k, v in self._RECON_BODY.items():
                if k in body:
                    found.update(v)
        return sorted(found)

    def fingerprint(self, target: str, surfaces=None, roles=None, stack=None,
                    task_level: str = "fact-finding") -> dict:
        # RELEVANCE IS DATA-DRIVEN: if the caller didn't pin a stack, auto-detect it from the live target
        # (recon), then MERGE with anything passed -- so ranked techniques + board novelty stay ON-STACK.
        detected = self._detect_stack(target)
        stk = sorted(set(list(stack or [])) | set(detected))
        return {"target": target, "surfaces": surfaces or [], "roles": roles or ["owner"],
                "stack": stk, "stack_detected": detected, "task_level": task_level,
                "terms": " ".join([task_level] + stk + list(surfaces or []))}

    def rank(self, fp: dict, limit: int = 12) -> list:
        """Ranked prior-successful techniques for the fingerprint. DB order (keyword x learned-EV) is
        kept; co-occurring techniques for the top class are appended as 'test-next' anchors."""
        seen, ranked = set(), []
        # a query per surface (falls back to the fingerprint terms) surfaces the most relevant techniques
        queries = [fp["terms"]] + [f"{fp['terms']} {s}" for s in (fp.get("surfaces") or [])]
        for q in queries:
            for t in self._ts(q, limit=limit):
                tid = t.get("id")
                if tid and tid not in seen:
                    seen.add(tid); ranked.append(t)
        # enrich: if the top technique's class has learned co-occurrence, pull those techniques too
        if ranked:
            for t in self._cooccur(ranked[0].get("class", ""), limit=4):
                tid = t.get("id")
                if tid and tid not in seen:
                    seen.add(tid); t["_via"] = "cooccurrence"; ranked.append(t)
        return ranked[:max(limit, 12)]

    # ---- RELEVANCE: not every DB/ATT&CK technique applies to THIS environment ----
    _STACK_PLATFORMS = {
        "linux": "Linux", "ubuntu": "Linux", "debian": "Linux", "kali": "Linux", "nginx": "Linux",
        "windows": "Windows", "iis": "Windows", ".net": "Windows", "active directory": "Windows",
        "ad": "Windows", "macos": "macOS", "docker": "Containers", "kubernetes": "Containers",
        "k8s": "Containers", "container": "Containers", "aws": "IaaS", "gcp": "IaaS", "azure": "IaaS",
        "web": "Web", "http": "Web", "api": "Web", "node": "Linux", "django": "Linux", "flask": "Linux",
        "php": "Linux", "symfony": "Linux", "postgres": "Linux", "mysql": "Linux",
    }

    def _target_platforms(self, fp: dict) -> set:
        """Best-effort ATT&CK platforms for the target from its stack/surfaces. Empty => unknown
        (then we DON'T deterministically drop -- we let the board decide)."""
        plats = set()
        for term in (fp.get("stack") or []) + (fp.get("surfaces") or []) + [fp.get("target", "")]:
            for k, v in self._STACK_PLATFORMS.items():
                if k in str(term).lower():
                    plats.add(v)
        return plats

    def _platform_ok(self, t: dict, plats: set) -> bool:
        ap = set(t.get("applies_to") or [])
        if not ap or not plats:
            return True                                # no constraint / unknown target -> keep
        return bool(ap & plats)                        # keep only if platforms overlap

    def _board(self, sysp: str, user: str, max_tokens: int = 1400) -> str:
        import sys as _s
        _s.path.insert(0, HERE)
        try:
            import remediation_board as RB
            ep = (os.environ.get("AEGIS_LLM_ENDPOINT") or "https://api.deepseek.com").rstrip("/")
            return RB._post_openai_style(ep + "/chat/completions", os.environ.get("AEGIS_LLM_API_KEY", ""),
                                         os.environ.get("AEGIS_BOARD_MODEL", "deepseek-v4-flash"),
                                         sysp, user, max_tokens, think=False) or ""
        except Exception:
            return ""

    def select(self, ranked: list, fp: dict, board: bool = True, keep: int = 12) -> list:
        """Filter DB candidates down to what's RELEVANT to this environment: a deterministic platform
        pre-filter, then the BOARD picks the applicable techniques (drops e.g. Windows/AD techniques on a
        Linux web app). Offline-safe: if the board is unavailable, keep the platform-filtered set."""
        plats = self._target_platforms(fp)
        cands = [t for t in ranked if self._platform_ok(t, plats)]
        if not board or not cands:
            return cands[:keep]
        brief = [{"id": t.get("id"), "class": t.get("class"), "platforms": t.get("applies_to"),
                  "tactics": t.get("mitre_tactics"), "desc": (t.get("desc", "") or "")[:120]} for t in cands]
        sysp = ("You are the Planner's RELEVANCE FILTER on an AUTHORIZED, contained assessment. Given the "
                "TARGET ENVIRONMENT and CANDIDATE techniques (from the techniques DB + MITRE ATT&CK), select "
                "ONLY techniques that are APPLICABLE to THIS environment -- platform/stack/surface + task "
                "level must fit. DROP anything irrelevant (e.g. Windows/Active-Directory or mobile/cloud "
                "techniques against a Linux web app, or techniques whose platform doesn't match). Output "
                "ONLY a JSON array, best-first: [{\"id\":\"..\",\"reason\":\"<=12 words why it applies here\"}]. "
                "No prose, no fenced block.")
        raw = self._board(sysp, json.dumps({"environment": fp, "candidates": brief})[:8000])
        chosen = {}
        try:
            i, j = raw.find("["), raw.rfind("]")
            for it in (json.loads(raw[i:j + 1]) if i >= 0 and j > i else []):
                if isinstance(it, dict) and it.get("id"):
                    chosen[it["id"]] = it.get("reason", "")
        except Exception:
            chosen = {}
        if not chosen:                                 # board unavailable/unparseable -> platform set
            return cands[:keep]
        by_id = {t.get("id"): t for t in cands}
        out = []
        for tid, reason in chosen.items():             # board order = relevance order
            t = by_id.get(tid)
            if t:
                out.append({**t, "_relevance": reason})
        return out[:keep]

    def board_novel(self, fp: dict, known_ids: list, n: int = 4) -> list:
        """The DB never CAGES the board. Beyond the known/DB+ATT&CK techniques, the board devises NOVEL
        approaches for THIS environment -- a new technique, a creative MIX of existing ones, or a NEW
        TOOL / new code -- IN ADDITION to the accepted approach. These become anchor seed_moves too, and
        a novel approach that later verifies is written back to the learned DB (so it stops being novel)."""
        sysp = ("You are the Planner's CREATIVE strategist on an AUTHORIZED, contained assessment. The "
                "techniques DB + MITRE ATT&CK already proposed the KNOWN techniques listed. Propose up to "
                f"{n} NOVEL approaches to try IN ADDITION -- nothing in the DB constrains you: a novel "
                "technique, a creative MIX of existing approaches, or a NEW TOOL / NEW CODE you would "
                "write -- each tailored to THIS environment (stack/surfaces) and the task level. Output "
                "ONLY a JSON array: [{\"approach\":\"short name\",\"vuln_class\":\"..\",\"mechanism\":\"how "
                "it works\",\"surface\":\"/..\",\"tool_or_code\":\"an existing tool OR 'new-code: <what to "
                "build>'\",\"expected_oracle\":\"the observable that proves it\",\"why_novel\":\"why this "
                "is new/creative here\"}]. Concrete, no prose, no fenced block.")
        raw = self._board(sysp, json.dumps({"environment": fp, "known_techniques": known_ids})[:6000])
        moves = []
        try:
            i, j = raw.find("["), raw.rfind("]")
            arr = json.loads(raw[i:j + 1]) if i >= 0 and j > i else []
        except Exception:
            arr = []
        roles = fp.get("roles") or ["owner"]
        for k, m in enumerate(arr):
            if not isinstance(m, dict):
                continue
            cls = (m.get("vuln_class") or "novel").lower().strip()
            toc = str(m.get("tool_or_code") or "")
            is_code = toc.lower().startswith("new-code")
            surface = m.get("surface") or "/"
            moves.append({
                "action": _class_to_action(cls),
                "surface": surface, "path": surface if _class_to_action(cls) == "web" else None,
                "vuln_class": cls, "mechanism": m.get("mechanism", "")[:80],
                "technique": "novel:" + (m.get("approach") or f"n{k}").lower().replace(" ", "-")[:32],
                "tool": ("" if is_code else toc), "new_code": ([toc] if is_code else []),
                "role": roles[k % len(roles)], "trust": roles[k % len(roles)],
                "expected_oracle": m.get("expected_oracle", "confirm the observable"),
                "why_novel": "board-novel: " + (m.get("why_novel") or m.get("approach") or "new approach")[:100],
                "seed": "planner:novel",
            })
        return moves

    def seed_moves(self, ranked: list, base: str, roles=None, mode: str = "operator") -> list:
        """Turn ranked techniques into MODE-1 anchor moves for iterative_hunt (one per technique)."""
        roles = roles or ["owner"]
        moves = []
        for i, t in enumerate(ranked):
            cls = t.get("class", "") or "web"
            action = _class_to_action(cls)
            tools = t.get("kali_tools") or []
            surface = (t.get("applies_to") or ["/"])[0] if action != "web" else "/"
            moves.append({
                "action": action,
                "surface": surface,
                "path": surface if action == "web" else None,
                "vuln_class": cls,
                "mechanism": (t.get("mitre_id") or t.get("id") or t.get("desc", "")[:40]),
                "technique": t.get("id", ""),
                "tool": (tools[0] if tools else ""),
                "role": roles[i % len(roles)],
                "trust": roles[i % len(roles)],
                "expected_oracle": t.get("oracle", "confirm the technique's observable"),
                "why_novel": f"planner anchor: {t.get('id','')} [{cls}]"
                             + (f" via {t['_via']}" if t.get("_via") else "")
                             + (f" -- {t['_relevance']}" if t.get("_relevance") else "")
                             + (f" (prior-success/EV)" if t.get("learned") else ""),
                "seed": "planner",
                "mitre_id": t.get("mitre_id", ""),
                "planner_rank": i,
            })
        return moves

    def plan(self, objective: str, target: str, surfaces=None, roles=None, stack=None,
             task_level: str = "fact-finding", base: str = None, limit: int = 12, board: bool = True,
             novel: int = 4) -> dict:
        fp = self.fingerprint(target, surfaces, roles, stack, task_level)
        ranked = self.rank(fp, limit=limit * 2)                     # over-fetch candidates
        relevant = self.select(ranked, fp, board=board, keep=limit)  # board keeps only what applies here
        seeds = self.seed_moves(relevant, base or target, roles=roles)   # DB/ATT&CK-known anchors
        novel_moves = self.board_novel(fp, [t.get("id") for t in relevant], n=novel) if (board and novel) else []
        return {"objective": objective, "fingerprint": fp, "candidates": len(ranked),
                "relevant": relevant, "novel_moves": novel_moves,
                "seed_moves": seeds + novel_moves}          # known + board-novel, both feed the loop

    # ---- multi-scenario candidate plans (stage 3): several genuinely different plans, re-open queue ---
    @staticmethod
    def _emphasis_sort(relevant: list, emphasis: list) -> list:
        """Stable-sort the relevant techniques so an emphasis scenario's classes float to the front
        (fast-track = injection/logic first; covert = recon/misconfig first). Empty emphasis = as-is."""
        if not emphasis:
            return list(relevant)
        def key(t):
            cls = (t.get("class", "") or "").lower()
            for i, e in enumerate(emphasis):
                if e in cls or cls in e:
                    return (0, i)
            return (1, 0)
        return sorted(relevant, key=key)

    def stateful_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """AUTO-SEED stateful probes (no hand-seeding): instantiate the stateful TEMPLATE library against
        the target. CODE templates (replay/idempotency/invariant on money paths) are high-value defaults;
        SCAFFOLD templates (resource persistence) seed when a keyword matches the objective/surfaces/stack.
        Budget-capped (AEGIS_STATEFUL_SEED_CAP, default 4). Gate: AEGIS_STATEFUL_SEED=0. Offline-safe."""
        if str(os.environ.get("AEGIS_STATEFUL_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        try:
            import copy as _copy, stateful_templates as _st
            tmpls = _st.templates(base, roles)
        except Exception:
            return []
        fp = fp or {}
        hay = " ".join([str(objective or ""), str(fp.get("terms", "")),
                        " ".join(fp.get("surfaces") or []), " ".join(fp.get("stack") or [])]).lower()
        picked = []
        for t in tmpls:
            applies = [a.lower() for a in (t.get("applies") or [])]
            matched = any(a in hay for a in applies)
            # CODE templates seed by default (high-value + self-validating); SCAFFOLD needs a keyword hit.
            if matched or t.get("layer") == "code":
                m = _copy.deepcopy({k: v for k, v in t.items() if k != "applies"})
                m.setdefault("seed", "planner")
                picked.append(m)
        cap = int(os.environ.get("AEGIS_STATEFUL_SEED_CAP", "4"))
        return picked[:cap]

    def idor_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """COMMERCIAL-PARITY: auto-seed IDOR/BOLA object-level authz sweeps for REST COLLECTION surfaces
        (a /api/<plural> that lists objects). For each, the idor leg enumerates ids as the owner role then
        cross-tests them as lower-privileged roles (reads-only -> non-destructive). Collections come from
        the fingerprint's surfaces (collection-shaped) + AEGIS_IDOR_COLLECTIONS; capped (AEGIS_IDOR_SEED_CAP,
        default 6). Gate: AEGIS_IDOR_SEED=0. Offline-safe."""
        if str(os.environ.get("AEGIS_IDOR_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        import re as _re
        fp = fp or {}
        surfaces = [str(s) for s in (fp.get("surfaces") or [])]
        # a REST collection = /api/<word(s)> with NO trailing {id}/param and not an obvious action verb
        colls = [s for s in surfaces if _re.match(r"^/api/[a-z0-9\-_/]+$", s or "", _re.I)
                 and not _re.search(r"\{|:|/(login|logout|refresh|search|export|report)$", s or "", _re.I)]
        env_colls = [c.strip() for c in (os.environ.get("AEGIS_IDOR_COLLECTIONS", "").split(",")) if c.strip()]
        colls = list(dict.fromkeys(env_colls + colls))                       # de-dup, env first
        if not colls:
            colls = ["/api/invoices", "/api/customers", "/api/jobs", "/api/payments", "/api/credit-notes"]
        owner = (roles or ["owner"])[0]
        attackers = [r for r in (roles or []) if r != owner][:2] or ["technician", "warehouse"]
        attackers = list(dict.fromkeys(attackers + ["anon"]))
        cap = int(os.environ.get("AEGIS_IDOR_SEED_CAP", "6"))
        out = []
        for c in colls[:cap]:
            out.append({"action": "idor", "collection": c, "surface": c, "owner_role": owner,
                        "attacker_roles": attackers, "sample": int(os.environ.get("AEGIS_IDOR_SAMPLE", "5")),
                        "vuln_class": "broken-object-level-authz", "technique": "idor.sweep", "layer": "code",
                        "severity": "high", "seed": "planner",
                        "why_novel": f"IDOR/BOLA: sweep {c} object ids across roles (object-level authz)."})
        return out

    def rate_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """COMMERCIAL-PARITY: seed a bounded, non-destructive RATE-LIMIT probe for auth-SENSITIVE
        surfaces (login/reset/OTP) discovered in the fingerprint (+ AEGIS_RATE_SURFACES). Gate:
        AEGIS_RATE_SEED=0. Uses a nonexistent identity so no real account locks."""
        if str(os.environ.get("AEGIS_RATE_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        import re as _re
        fp = fp or {}
        surfaces = [str(x) for x in (fp.get("surfaces") or [])]
        sens = [x for x in surfaces if _re.search(r"login|auth|reset|otp|verify|token|signin|sign-in", x or "", _re.I)]
        env = [c.strip() for c in os.environ.get("AEGIS_RATE_SURFACES", "").split(",") if c.strip()]
        sens = list(dict.fromkeys(env + sens)) or ["/api/auth/login"]
        cap = int(os.environ.get("AEGIS_RATE_SEED_CAP", "3"))
        return [{"action": "rate", "surface": x, "method": "POST", "n": int(os.environ.get("AEGIS_RATE_N", "15")),
                 "vuln_class": "improper-anti-automation", "technique": "rate.probe", "layer": "code",
                 "severity": "medium", "seed": "planner",
                 "why_novel": f"rate-limit/anti-automation probe on {x} (brute-force feasibility)."}
                for x in sens[:cap]]

    def synth_seeds(self, base, roles=None, fp=None, objective="") -> list:
        """MECH 3: AUTO-SEED a few DETERMINISTIC synthetic techniques (cross-products of known classes:
        replay-as-another-identity, TOCTOU-on-invariant, double-effect race, privilege-field-back-door).
        No LLM in the path. Anchored on the stateful-template surfaces at plan time (no confirmed foothold
        yet); the loop re-composes on confirmed footholds later. Capped (AEGIS_SYNTH_SEED_CAP, default 3)
        so it never crowds out breadth. Gate: AEGIS_SYNTH_SEED=0. Offline-safe."""
        if str(os.environ.get("AEGIS_SYNTH_SEED", "1")).lower() in ("0", "false", "no", "off"):
            return []
        try:
            import technique_synth as _ts, stateful_templates as _st
            tmpls = _st.templates(base, roles)
            cap = int(os.environ.get("AEGIS_SYNTH_SEED_CAP", "3"))
            return _ts.synthesize(templates=tmpls, fp=fp, limit=cap)
        except Exception:
            return []

    def candidate_plans(self, objective: str, target: str, surfaces=None, roles=None, stack=None,
                        task_level: str = "fact-finding", base: str = None, n_scenarios: int = 3,
                        limit: int = 12, board: bool = True, novel: int = 4) -> list:
        """Generate N CANDIDATE PLANS (scenarios) that vary technique ORDER, novel-probe budget and
        surface priority -- e.g. fast-track / thorough / covert (PLANNER.md component 4). The DB rank +
        board relevance filter run ONCE (shared); each scenario then re-orders that relevant set by its
        emphasis and draws its OWN fresh batch of board-novel approaches, so the plans are genuinely
        different, not re-labels. Scored `scenario_fit(task_level) + emphasis_coverage + novelty + breadth`
        and returned best-first: plans[0] seeds the run, the rest are the mid-run RE-OPEN queue.
        Offline-safe: board off/unreachable -> scenarios still differ by emphasis ordering."""
        fp = self.fingerprint(target, surfaces, roles, stack, task_level)
        # ACTIVE CRAWL (commercial-parity): discover the REAL surface (the SPA's live XHR/API endpoints) as
        # each role and MERGE it into the fingerprint, so every oracle (idor/xss/rate/mass-assign/secrets)
        # seeds against discovered endpoints -- not just guessed paths (the false-parity trap). One crawl
        # per plan; gate AEGIS_CRAWL=0; offline-safe (no browser -> unchanged).
        try:
            import crawler, session_factory
            _neutral = [r for r in (roles or []) if str(r).lower() not in ('owner','admin')] or None
            _cr = crawler.crawl(base or target, session_for_role=session_factory.from_env(base or target),
                                roles=_neutral)   # NEUTRALITY: crawl as non-privileged roles only
            _disc = _cr.get("surfaces") or []
            if _disc:
                merged = list(dict.fromkeys((fp.get("surfaces") or []) + _disc))
                fp["surfaces"] = merged
                fp["crawled_surfaces"] = _disc
                fp["crawled_by_role"] = _cr.get("by_role")   # per-trust-level surface delta (anon vs authed)
        except Exception:
            pass
        ranked = self.rank(fp, limit=limit * 2)
        relevant = self.select(ranked, fp, board=board, keep=limit)
        known_ids = [t.get("id") for t in relevant]
        # DYNAMIC discovery survey: SEE the env -> SURVEY techniques+tools live (MITRE/RAG) -> CHECK/ACQUIRE
        # (install-on-demand) or WRITE a probe (code-on-demand) -> phase-1 discovery seed moves. The board
        # then decides/mixes/escalates downstream. Not statically bound. AEGIS_DISCOVERY_SURVEY=0 to skip.
        disco_seeds = []
        if str(os.environ.get("AEGIS_DISCOVERY_SURVEY", "1")).lower() not in ("0", "false", "no", "off"):
            try:
                import discovery as _disco
                disco_seeds = _disco.survey(base or target, roles=roles, fp=fp).get("seed_moves", [])
            except Exception:
                disco_seeds = []
        st_seeds = self.stateful_seeds(base or target, roles=roles, fp=fp, objective=objective)
        sy_seeds = self.synth_seeds(base or target, roles=roles, fp=fp, objective=objective)
        id_seeds = self.idor_seeds(base or target, roles=roles, fp=fp, objective=objective)
        rt_seeds = self.rate_seeds(base or target, roles=roles, fp=fp, objective=objective)
        # one passive cookie/security-header probe per run (commercial-parity); gate AEGIS_SECHEADERS_SEED=0
        sh_seeds = ([] if str(os.environ.get('AEGIS_SECHEADERS_SEED','1')).lower() in ('0','false','no','off')
                    else [{'action':'security_headers','surface':'/','vuln_class':'security-misconfiguration',
                           'technique':'security-headers','layer':'scaffold','severity':'low','seed':'planner',
                           'why_novel':'cookie flags + security response headers (passive)'}])
        sfx_seeds = ([] if str(os.environ.get('AEGIS_SESSFIX_SEED','1')).lower() in ('0','false','no','off')
                     else [{'action':'session_fixation','surface':'/api/auth/login','vuln_class':'broken-authentication',
                            'technique':'session-fixation','layer':'code','severity':'high','seed':'planner',
                            'why_novel':'session id rotation on login (fixation)'}])
        or_surfaces = ['/','/login','/api/auth/login'] + [x for x in (fp.get('surfaces') or [])
                       if any(k in str(x).lower() for k in ('login','redirect','oauth','sso','callback','logout','return'))]
        up_surfaces = [x for x in (fp.get('surfaces') or []) if any(k in str(x).lower() for k in
                       ('upload','photo','file','document','attachment','image','signature','avatar','media'))]
        up_seeds = ([] if (str(os.environ.get('AEGIS_UPLOAD_SEED','1')).lower() in ('0','false','no','off') or not up_surfaces)
                    else [{'action':'file_upload','surface':u,'vuln_class':'unrestricted-file-upload',
                           'technique':'file-upload','layer':'code','severity':'high','seed':'planner',
                           'why_novel':f'active-content upload probe on {u}'} for u in list(dict.fromkeys(up_surfaces))[:int(os.environ.get('AEGIS_UPLOAD_CAP','3'))]])
        xss_surfaces = ['/'] + [x for x in (fp.get('surfaces') or []) if any(k in str(x).lower() for k in
                        ('search','q','list','view','detail','profile','comment','message','note','report'))]
        xss_seeds = ([] if str(os.environ.get('AEGIS_XSS_SEED','1')).lower() in ('0','false','no','off')
                     else [{'action':'xss','surface':u,'vuln_class':'cross-site-scripting',
                            'technique':'xss-headless','layer':'code','severity':'high','seed':'planner','headless':True,
                            'why_novel':f'DOM/reflected XSS (headless) on {u}'} for u in list(dict.fromkeys(xss_surfaces))[:int(os.environ.get('AEGIS_XSS_CAP','3'))]])
        ss_surfaces = ['/'] + [x for x in (fp.get('surfaces') or []) if any(k in str(x).lower() for k in
                       ('fetch','url','image','webhook','proxy','import','preview','avatar','route','geometry','callback'))]
        ss_seeds = ([] if str(os.environ.get('AEGIS_SSRF_SEED','1')).lower() in ('0','false','no','off')
                    else [{'action':'ssrf','surface':u,'vuln_class':'server-side-request-forgery',
                           'technique':'ssrf-canary','layer':'code','severity':'high','seed':'planner',
                           'why_novel':f'SSRF OOB canary probe on {u}'} for u in list(dict.fromkeys(ss_surfaces))[:int(os.environ.get('AEGIS_SSRF_CAP','3'))]])
        cs_seeds = ([] if str(os.environ.get('AEGIS_CSRF_SEED','1')).lower() in ('0','false','no','off')
                    else [{'action':'csrf','surface':'/','vuln_class':'cross-site-request-forgery',
                           'technique':'csrf-posture','layer':'code','severity':'medium','seed':'planner',
                           'why_novel':'CSRF posture (SameSite + anti-CSRF token)'}])
        or_seeds = ([] if str(os.environ.get('AEGIS_OPENREDIR_SEED','1')).lower() in ('0','false','no','off')
                    else [{'action':'open_redirect','surface':u,'vuln_class':'unvalidated-redirect',
                           'technique':'open-redirect','layer':'code','severity':'medium','seed':'planner',
                           'why_novel':f'open-redirect probe on {u}'} for u in list(dict.fromkeys(or_surfaces))[:int(os.environ.get('AEGIS_OPENREDIR_CAP','3'))]])
        ma_seeds = ([] if str(os.environ.get('AEGIS_MASSASSIGN_SEED','1')).lower() in ('0','false','no','off') else [
            {'action':'mass_assign','role':os.environ.get('AEGIS_NEUTRAL_ROLE','technician'),'surface':'/api/payments/deposit','layer':'code',
             'create':{'method':'POST','path':'/api/payments/deposit','body':{'amount':50,'method':'CARD'}},
             'ref':{'list':'/api/customers','id_field':'id','as':'customerId'},
             'inject':{'status':'CLEARED','approved':True,'balance':999999,'id':'aegis-forced'},
             'vuln_class':'mass-assignment','technique':'mass-assign','severity':'high','seed':'planner',
             'why_novel':'inject privileged fields into a deposit create (mass assignment)'},
            {'action':'mass_assign','role':os.environ.get('AEGIS_NEUTRAL_ROLE','technician'),'surface':'/api/invoices','layer':'code',
             'create':{'method':'POST','path':'/api/invoices','body':{}},
             'ref':{'list':'/api/jobs','id_field':'id','as':'jobId'},
             'inject':{'status':'PAID','total':0.01,'approved':True,'id':'aegis-forced'},
             'vuln_class':'mass-assignment','technique':'mass-assign','severity':'high','seed':'planner',
             'why_novel':'inject privileged fields into an invoice create (mass assignment)'}])
        import copy as _copy
        plans = []
        for prof in _SCENARIOS[:max(1, n_scenarios)]:
            ordered = self._emphasis_sort(relevant, prof["emphasis"])
            seeds = (disco_seeds + _copy.deepcopy(st_seeds) + _copy.deepcopy(sy_seeds)
                     + _copy.deepcopy(id_seeds) + _copy.deepcopy(rt_seeds) + _copy.deepcopy(sh_seeds)
                     + _copy.deepcopy(sfx_seeds) + _copy.deepcopy(or_seeds) + _copy.deepcopy(ma_seeds)
                     + _copy.deepcopy(cs_seeds) + _copy.deepcopy(ss_seeds) + _copy.deepcopy(xss_seeds)
                     + _copy.deepcopy(up_seeds)
                     + self.seed_moves(ordered, base or target, roles=roles))
            nmoves = self.board_novel(fp, known_ids, n=prof["novel"]) if (board and prof["novel"]) else []
            for m in seeds + nmoves:                      # tag scenario for the audit/report
                m["scenario"] = prof["name"]
            emphasis_hit = sum(1 for t in ordered
                               if any(e in (t.get("class", "") or "").lower() for e in prof["emphasis"]))
            score = (prof["fit"].get(task_level, 1) * 3.0 + emphasis_hit
                     + len(nmoves) * 1.0 + len(ordered) * 0.25)
            plans.append({"name": prof["name"], "desc": prof["desc"], "score": round(score, 2),
                          "seed_moves": seeds + nmoves, "relevant": ordered, "novel_moves": nmoves,
                          "fingerprint": fp})           # carry the stack/surface fp so the board keeps novelty ON-STACK
        plans.sort(key=lambda pl: -pl["score"])
        return plans

    # ---- closed-loop learning: write a verified win back to the learned DB ----
    def record_success(self, technique_id: str, tool: str, scenario: str, target_fp: str,
                       cls: str = "", desc: str = "") -> dict:
        """Append a learned technique entry (technique + tool + scenario + target fingerprint) to
        learned_techniques.json on the box, so the ranker boosts this combo next run. Idempotent-ish:
        merges a new _wins record onto an existing id."""
        entry = {"id": technique_id, "class": cls, "desc": desc or technique_id, "learned": True,
                 "kali_tools": ([tool] if tool else []),
                 "real_world_basis": f"verified on this stack ({scenario})",
                 "_win": {"scenario": scenario, "target": target_fp, "tool": tool,
                          "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}
        payload = json.dumps(entry)
        # merge into learned_techniques.json inside Kali (where the DB lives), atomically
        py = (
            "import json,os,sys;"
            "p=os.path.join('" + self.rag_home + "','learned_techniques.json');"
            "d=json.load(open(p,encoding='utf-8')) if os.path.exists(p) else {'techniques':[]};"
            "d.setdefault('techniques',[]);"
            "e=json.loads(sys.argv[1]);"
            "cur=next((x for x in d['techniques'] if x.get('id')==e['id']),None);"
            "(cur.setdefault('_wins',[]).append(e['_win']) or cur.__setitem__('kali_tools',sorted(set((cur.get('kali_tools') or [])+e['kali_tools']))))"
            " if cur else d['techniques'].append(dict(e,_wins=[e.pop('_win')]));"
            "json.dump(d,open(p+'.tmp','w',encoding='utf-8'));os.replace(p+'.tmp',p);"
            "print('learned',e['id'])"
        )
        try:
            p = subprocess.run(_shell_argv(self.distro,
                                f"cd {self.rag_home} && python3 -c {json.dumps(py)} {json.dumps(payload)}"),
                               capture_output=True, text=True, timeout=60)
            return {"ok": p.returncode == 0, "out": (p.stdout or p.stderr).strip()[:200]}
        except Exception as e:
            return {"ok": False, "error": str(e)[:160]}


def ensure_kali(distro=None, timeout=60):
    """DRIVE KALI: ensure the distro is RUNNING before the Planner queries the RAG or checks the toolset
    -- the techniques/ATT&CK DB (/opt/aegis-rag) AND the offensive toolset both live inside Kali, and the
    resolver for anything missing is there too. A `wsl` command auto-starts a stopped distro; we issue a
    bounded readiness probe so a cold boot completes before the first RAG call (rather than that call
    timing out). Idempotent + fail-safe: any error -> False and callers degrade to offline planning.
    Disable with AEGIS_KALI_AUTOSTART=0."""
    if os.environ.get("AEGIS_KALI_AUTOSTART", "1") == "0":
        return False
    try:
        p = subprocess.run(_shell_argv(distro, "echo aegis-kali-ready"),
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return "aegis-kali-ready" in (p.stdout or "")
    except Exception:
        return False


def _kali_present(tools, distro=None, timeout=15):
    """OBSERVATORY: which of `tools` (DB `kali_tools` entries) are actually INSTALLED in Kali -- so the
    board composes novel approaches from tools that EXIST here (else it writes a custom probe). One
    bounded `command -v` sweep; fail-safe: Kali unreachable / disabled -> [] (unknown; the board still
    has the tool NAMES from the ATT&CK toolset). Disable with AEGIS_KALI_TOOLCHECK=0."""
    import re as _re
    bins = sorted({(t or "").strip().split()[0] for t in (tools or []) if (t or "").strip()})
    bins = [b for b in bins if _re.fullmatch(r"[A-Za-z0-9._-]{1,40}", b)]      # trusted-ish, but sanitize
    if not bins or os.environ.get("AEGIS_KALI_TOOLCHECK", "1") == "0":
        return []
    inner = "; ".join(f"command -v {b} >/dev/null 2>&1 && echo {b}" for b in bins)
    try:
        p = subprocess.run(_shell_argv(distro, inner),
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return [ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip()]
    except Exception:
        return []


class PlannerSession:
    """Holds the ranked candidate plans (scenarios) for ONE run. plans[0] seeds the 40-attempt loop;
    on a mid-run stall the loop's `reopen` callback pops the NEXT scenario's moves (the Planner
    loop-back, PLANNER.md component 6). The loop itself filters those to whatever is still novel and
    bounds how many re-opens can happen (max_reopens), so re-planning can never thrash the budget."""
    def __init__(self, plans):
        self.plans = plans or []
        self.i = 0                      # index of the scenario currently in play (0 = initial)
        self.log = []                   # [{scenario, why, score}] per re-open (audit/report)
        self._kali_present_cache = None # cached "which ranked tools are installed in Kali" (observatory)

    # OBSERVATORY ROLE AT THE DISCOVERY STAGE: the Planner EXECUTES only its DETERMINISTIC anchors
    # (prior-successful / ATT&CK-ranked replays, tag "planner"). Its board_novel speculation
    # (tag "planner:novel") was frozen at plan time against ONLY the fingerprint -- executing it blind
    # mid-run is what produced unmoored moves; instead it becomes ADVISORY `intel()` the LIVE board
    # reads each round (the board, seeing deltas + footholds, chooses the actual moves).
    @staticmethod
    def _anchors(plan):
        return [m for m in (plan.get("seed_moves") or []) if m.get("seed") != "planner:novel"]

    def initial_seeds(self):
        return self._anchors(self.plans[0]) if self.plans else []

    def initial_name(self):
        return self.plans[0]["name"] if self.plans else ""

    def scenario_names(self):
        return [p["name"] for p in self.plans]

    def intel(self, context=None):
        """OBSERVATORY-ONLY context for the live board: the current scenario's FACTUAL ranked
        technique classes (from the curated + learned + ATT&CK DB) -- knowledge, not moves. NOVELTY
        at the discovery stage is the LIVE BOARD's job (it sees the deltas + footholds); the Planner
        deliberately supplies NO novel approaches here -- its `board_novel` (frozen at plan time
        against only the fingerprint) is intentionally omitted. Injected as `planner_intel` in the
        loop's board context. Empty when no plan (offline-safe)."""
        if not self.plans:
            return {}
        p = self.plans[self.i]
        # Hand the board the RICH, COMBINABLE ATT&CK / technique-DB material the Planner already
        # retrieved + ranked for this fingerprint (RAG: curated + learned + MITRE ATT&CK): each entry's
        # tools, how-to-test, tactics and platforms -- so the board can COMBINE / CHAIN / adapt them into
        # novel approaches (not just see a label). This is the raw material for the board's novelty;
        # the Planner supplies it (observe/retrieve), the board composes it (create).
        toolset = [{"id": t.get("id"), "class": t.get("class") or t.get("cls"),
                    "desc": (t.get("desc") or "")[:120],
                    "tools": (t.get("kali_tools") or [])[:6],
                    "how_to_test": (t.get("how_to_test") or "")[:140],
                    "mitre_tactics": t.get("mitre_tactics") or t.get("tactics") or [],
                    "mitre_id": t.get("mitre_id") or "",
                    "applies_to": (t.get("applies_to") or [])[:4],
                    "learned": bool(t.get("learned"))}
                   for t in (p.get("relevant") or [])[:10]]
        # OBSERVATORY: check ONCE which of the ranked tools are installed in Kali (cached; fail-safe).
        if self._kali_present_cache is None:
            self._kali_present_cache = _kali_present(
                [tt for t in (p.get("relevant") or [])[:10] for tt in (t.get("kali_tools") or [])])
        fp = p.get("fingerprint") or {}
        stack = {"stack": fp.get("stack") or [], "surfaces": fp.get("surfaces") or [],
                 "roles": fp.get("roles") or []}
        return {"planner_scenario": p.get("name"),
                "target_stack": stack,                 # the ACTUAL code/stack -> keep novelty RELEVANT
                "attack_toolset": toolset,
                "kali_tools_present": self._kali_present_cache,
                "note": ("MITRE ATT&CK / technique-DB material (from the RAG), already relevance-filtered "
                         "and ranked for THIS target's stack (`target_stack`), plus which of their tools are "
                         "INSTALLED here (`kali_tools_present`). Propose ONLY approaches RELEVANT to this "
                         "actual code/stack -- no off-stack techniques. COMBINE and CHAIN the toolset (mix "
                         "techniques, chain tactics, compose/adapt their tools) into NOVEL approaches; when "
                         "no installed tool fits, write a custom probe (`new_code`) that targets a gap in "
                         "THIS code's behaviour (a zero-day-style hypothesis). Go beyond the DB with new "
                         "ideas too. Ground everything in the live oracle deltas + confirmed footholds; "
                         "raw material, NOT moves to run verbatim.")}

    def reopen(self, context=None, why=""):
        """Return the NEXT candidate scenario's DETERMINISTIC anchors (novel speculation stays in
        intel(), not executed). [] when the queue is exhausted."""
        self.i += 1
        if self.i < len(self.plans):
            p = self.plans[self.i]
            self.log.append({"scenario": p["name"], "why": why, "score": p["score"]})
            return self._anchors(p)
        return []


def plan_session(objective, target, *, roles=None, surfaces=None, stack=None,
                 task_level="fact-finding", mode="operator", base=None, limit=12,
                 board=True, novel=4, n_scenarios=3):
    """OFFLINE-SAFE factory: build the multi-scenario PlannerSession for a run, or None. None => the
    runner falls back to plan_seed_moves (single plan) or the board brainstorm alone. Every failure
    (planner error, Kali/DB unreachable, board offline) yields None -- it can never block a run.
    Opt-out with AEGIS_PLANNER=0."""
    if os.environ.get("AEGIS_PLANNER", "1") == "0":
        return None
    try:
        plans = Planner().candidate_plans(objective, target, surfaces=surfaces, roles=roles,
                                          stack=stack, task_level=task_level, base=base, limit=limit,
                                          board=board, novel=novel, n_scenarios=n_scenarios)
        for pl in plans:
            for m in pl["seed_moves"]:
                m.setdefault("_planner_mode", mode)
        # PRE-FLIGHT tool provisioning (board-converged): tools the plan needs that are MISSING in Kali are
        # provisioned in the BLACKARCH container up front (prebuilt via pacman -- not ported into Kali), so a
        # probe never stalls mid-run to fetch a tool. Offline-safe + opt-out (AEGIS_TOOL_PREFLIGHT=0); a
        # no-op when every needed tool is already in Kali; NEVER blocks a run.
        if plans and os.environ.get("AEGIS_TOOL_PREFLIGHT", "1") != "0":
            try:
                tools = set()
                for pl in plans:
                    for m in pl.get("seed_moves", []):
                        t = str(m.get("tool") or "").strip()
                        if t and not t.lower().startswith("new-code") and not m.get("new_code"):
                            tools.add(t)
                if tools:
                    import distro_backend
                    distro_backend.preflight(sorted(tools))
            except Exception:
                pass
        return PlannerSession(plans) if plans else None
    except Exception:
        return None


def plan_seed_moves(objective, target, *, roles=None, surfaces=None, stack=None,
                    task_level="fact-finding", mode="operator", base=None, limit=12,
                    board=True, novel=4):
    """OFFLINE-SAFE bridge from the Planner into the 40-attempt iterative-hunt loop: returns the
    merged MODE-1 anchor `seed_moves` -- DB/ATT&CK prior-successful anchors PLUS the board-devised
    NOVEL approaches (novel technique / mix / new-code) -- to hand IterativeHunt(seed_moves=...).
    So the "retry / try-again / what-else-can-be-done" loop STARTS already carrying the novel board
    ideas, then diversifies per its own rules. NEVER raises and never blocks a run: on any failure
    (planner error, Kali/DB unreachable, board offline) it returns [] and the loop just starts from
    the board's own brainstorm as before. Opt-out with AEGIS_PLANNER=0."""
    if os.environ.get("AEGIS_PLANNER", "1") == "0":
        return []
    try:
        plan = Planner().plan(objective, target, surfaces=surfaces, roles=roles, stack=stack,
                              task_level=task_level, base=base, limit=limit, board=board, novel=novel)
        moves = plan.get("seed_moves") or []
        for m in moves:
            m.setdefault("_planner_mode", mode)
        return moves
    except Exception:
        return []


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Planner: rank prior-successful techniques + emit seed_moves.")
    ap.add_argument("objective")
    ap.add_argument("--target", required=True)
    ap.add_argument("--surfaces", nargs="*", default=None)
    ap.add_argument("--roles", nargs="*", default=None)
    ap.add_argument("--stack", nargs="*", default=None)
    ap.add_argument("--task-level", default="fact-finding")
    ap.add_argument("--limit", type=int, default=12)
    ap.add_argument("--no-board", action="store_true", help="skip board relevance filter (platform pre-filter only)")
    ap.add_argument("--novel", type=int, default=4, help="how many NOVEL board approaches to add (0 = none)")
    ap.add_argument("--scenarios", type=int, default=1,
                    help="emit N candidate plans (fast-track/thorough/covert) -- the mid-run RE-OPEN queue")
    a = ap.parse_args()
    if a.scenarios > 1:
        plans = Planner().candidate_plans(a.objective, a.target, a.surfaces, a.roles, a.stack,
                                          a.task_level, n_scenarios=a.scenarios, limit=a.limit,
                                          board=not a.no_board, novel=a.novel)
        print(json.dumps([{"name": pl["name"], "score": pl["score"], "desc": pl["desc"],
                           "seed_count": len(pl["seed_moves"]),
                           "novel": [m["technique"] for m in pl["novel_moves"]]} for pl in plans],
                         indent=2))
        return
    plan = Planner().plan(a.objective, a.target, a.surfaces, a.roles, a.stack, a.task_level,
                          limit=a.limit, board=not a.no_board, novel=a.novel)
    print(json.dumps({"fingerprint": plan["fingerprint"], "candidates_considered": plan["candidates"],
                      "relevant": [{"id": t.get("id"), "class": t.get("class"),
                                    "tools": t.get("kali_tools"), "mitre": t.get("mitre_id"),
                                    "relevance": t.get("_relevance")} for t in plan["relevant"]],
                      "novel_moves": [{"technique": m["technique"], "vuln_class": m["vuln_class"],
                                       "tool": m.get("tool"), "new_code": m.get("new_code"),
                                       "why": m["why_novel"]} for m in plan["novel_moves"]],
                      "seed_count": len(plan["seed_moves"])}, indent=2))


if __name__ == "__main__":
    main()
