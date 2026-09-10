"""crawler.py -- ACTIVE per-role surface discovery (commercial-parity). Commercial scanners CRAWL first to
discover the real attack surface; seeding from a few known routes misses undocumented endpoints (a
false-parity trap). For a SPA + JSON API (like the mirror), the real surface is what the frontend actually
CALLS, so this drives a HEADLESS browser as each authenticated role, captures every XHR/fetch request URL
(the live API endpoints), clicks discoverable in-app links to reach more views, and also enumerates the API
collections it finds to learn nested-resource path templates. Reads only (GET navigation) -> non-destructive.

Returns {"surfaces": [...api paths...], "endpoints": [...full urls...], "by_role": {...}}. The planner merges
`surfaces` into the fingerprint so EVERY oracle (idor/xss/rate/mass-assign/...) gets seeded for the discovered
surface, not just guessed paths. Offline-safe: no Playwright/chromium -> {} (the loop still uses seeds).
"""
from __future__ import annotations
import os, re, time
from urllib.parse import urlparse


def _norm_path(u, host):
    try:
        pr = urlparse(u)
        if pr.netloc and host and host not in pr.netloc:
            return None                                 # off-target -> ignore (no off-box)
        p = pr.path or "/"
        # collapse concrete ids to a template so /api/jobs/<uuid> -> /api/jobs/{id}
        p = re.sub(r"/(c[a-z0-9]{20,}|[0-9a-f]{8}-[0-9a-f-]{27}|\d+)(?=/|$)", "/{id}", p)
        return p
    except Exception:
        return None


def crawl(base, session_for_role=None, roles=None, max_clicks=12, per_role_seconds=25):
    """Headless per-role crawl. Returns discovered surfaces (api-path templates) + endpoints."""
    if str(os.environ.get("AEGIS_CRAWL", "1")).lower() in ("0", "false", "no", "off"):
        return {}
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return {}
    base = base or os.environ.get("AEGIS_TARGET") or "https://localhost:8443"
    host = re.sub(r"^https?://", "", base).split("/")[0].split(":")[0]
    # NEUTRALITY: never crawl AS owner/admin -- a realistic test must not assume privileged access. Use
    # non-privileged roles (AEGIS_CRAWL_ROLES, default technician,anon). Owner is only ever the IDOR
    # victim/baseline reference elsewhere, never the discovery/attack identity.
    if not roles:
        roles = [r.strip() for r in os.environ.get("AEGIS_CRAWL_ROLES", "technician,anon").split(",") if r.strip()]
    roles = [r for r in roles if str(r).lower() not in ("owner", "admin")] or ["technician", "anon"]
    surfaces, endpoints, by_role = set(), set(), {}
    try:
        with sync_playwright() as pw:
            br = pw.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
            for role in roles:
                found = set()
                try:
                    cx = br.new_context(ignore_https_errors=True)
                    if session_for_role:
                        try:
                            cx.add_cookies([{"name": c.name, "value": c.value, "domain": host, "path": "/"}
                                            for c in session_for_role(role).cookies])
                        except Exception:
                            pass
                    pg = cx.new_page()
                    pg.on("dialog", lambda d: d.dismiss())
                    # capture EVERY network request URL (the real API/XHR surface)
                    pg.on("request", lambda req: found.add(req.url))
                    deadline = time.time() + per_role_seconds
                    pg.goto(base, wait_until="networkidle", timeout=20000)
                    # click discoverable in-app nav to reach more views (SPA routing -> more XHR)
                    clicks = 0
                    for sel in ("a[href]", "nav a", "[role=link]", "button"):
                        for el in pg.query_selector_all(sel):
                            if clicks >= max_clicks or time.time() > deadline:
                                break
                            try:
                                el.click(timeout=1500, no_wait_after=True); clicks += 1
                                pg.wait_for_timeout(400)
                            except Exception:
                                pass
                    cx.close()
                except Exception:
                    pass
                rp = set()
                for u in found:
                    p = _norm_path(u, host)
                    if p and (p.startswith("/api/") or "/api/" in p):
                        rp.add(p); endpoints.add(u.split("?")[0])
                by_role[role] = sorted(rp)
                surfaces |= rp
            br.close()
    except Exception:
        return {"surfaces": sorted(surfaces), "endpoints": sorted(endpoints), "by_role": by_role}
    return {"surfaces": sorted(surfaces), "endpoints": sorted(endpoints), "by_role": by_role}
