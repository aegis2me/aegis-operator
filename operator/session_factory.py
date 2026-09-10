"""Generic, env-configured session factory so the relay (and any mode) can AUTHENTICATE to the target
without hardcoding client creds in the engine. Fixes relay F1: exploitgym/redteam built the vectors ctx
without session_for_role, so resumed stateful footholds ran unauthenticated (and got falsely refuted).

Config via env (point at the mirror on the box, NOT in code -- same doctrine as AEGIS_DB_USER etc.):
  AEGIS_ROLE_MAP        JSON {role: identity}, e.g. {"owner":"Alex Morgan","finance":"Fiona Clarke",...}
  AEGIS_LOGIN_URL       login endpoint (default {base}/api/auth/login)
  AEGIS_LOGIN_PIN       shared PIN (default AEGIS_TEST_PIN, else 000000)
  AEGIS_LOGIN_ID_FIELD  login body field for the identity (default "name")
  AEGIS_LOGIN_PIN_FIELD login body field for the PIN (default "pin")

from_env(base) -> session_for_role(role)->requests.Session (cached), or None if no AEGIS_ROLE_MAP
(offline-safe: no map -> no factory -> modes behave exactly as before). An unknown/anon role gets an
UNAUTHENTICATED session (never a silent fallback to a privileged identity)."""
import os, json


def from_env(base):
    try:
        role_map = json.loads(os.environ.get("AEGIS_ROLE_MAP", "") or "{}")
    except Exception:
        role_map = {}
    if not isinstance(role_map, dict) or not role_map:
        return None
    role_map = {str(k).lower(): v for k, v in role_map.items()}
    import requests
    try:
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass
    url = os.environ.get("AEGIS_LOGIN_URL") or ((base or "https://localhost:8443").rstrip("/") + "/api/auth/login")
    pin = os.environ.get("AEGIS_LOGIN_PIN") or os.environ.get("AEGIS_TEST_PIN") or "000000"
    id_field = os.environ.get("AEGIS_LOGIN_ID_FIELD", "name")
    pin_field = os.environ.get("AEGIS_LOGIN_PIN_FIELD", "pin")
    cache = {}

    def session_for_role(role):
        role = (role or "").lower().strip()
        if role in cache:
            return cache[role]
        s = requests.Session()
        s.verify = False
        ident = role_map.get(role)
        if ident:                                   # KNOWN role -> authenticate; unknown/anon -> stay anon
            try:
                s.post(url, json={id_field: ident, pin_field: pin}, timeout=20, verify=False)
            except Exception:
                pass
        cache[role] = s
        return s

    return session_for_role
