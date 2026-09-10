"""canary.py -- an in-sandbox OUT-OF-BAND (OOB) sink for confirming BLIND vulnerabilities (SSRF, blind XXE,
blind injection, webhook/callback abuse) NON-DESTRUCTIVELY. It stands up a tiny HTTP listener that records
which unique TOKEN was called back; a leg injects `http://<canary>/c/<token>` into a suspect parameter and,
if the token is HIT, the target made an outbound request we controlled -> confirmed (the ground-truth oracle
signal). Contained: the canary is an owned in-sandbox host, not off-box egress.

Reachability: the TARGET (e.g. the mirror's api container) must be able to reach the canary. Set
AEGIS_CANARY_URL to a target-reachable base (e.g. http://172.17.0.1:9099 -- the docker bridge gateway when
the mirror runs in Kali docker); the listener binds 0.0.0.0:<that port>. If unset, a best-effort local URL
is used (works when the engine + target share a host). Pure-stdlib, offline-safe.
"""
from __future__ import annotations
import http.server, threading, time, os, uuid, socket
from urllib.parse import urlparse

_HITS = {}                 # token -> [ {ts, path, method, ua, src} ]
_LOCK = threading.Lock()
_SERVER = None
_PORT = None


class _Handler(http.server.BaseHTTPRequestHandler):
    def _hit(self):
        try:
            tok = None
            parts = [p for p in (self.path or "").split("/") if p]
            if len(parts) >= 2 and parts[0] == "c":
                tok = parts[1].split("?")[0]
            elif parts:
                tok = parts[-1].split("?")[0]
            if tok:
                with _LOCK:
                    _HITS.setdefault(tok, []).append({
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "path": self.path, "method": self.command,
                        "ua": self.headers.get("User-Agent", ""),
                        "src": self.client_address[0] if self.client_address else ""})
        except Exception:
            pass
        try:
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            self.wfile.write(b"ok")
        except Exception:
            pass
    do_GET = do_POST = do_PUT = do_HEAD = _hit

    def log_message(self, *a):
        return                                 # silent


def _default_port():
    try:
        return int(os.environ.get("AEGIS_CANARY_PORT") or (urlparse(os.environ["AEGIS_CANARY_URL"]).port or 9099))
    except Exception:
        return 9099


def start(port=None):
    """Start the canary listener once (idempotent). Returns the bound port."""
    global _SERVER, _PORT
    if _SERVER is not None:
        return _PORT
    _PORT = int(port or _default_port())
    try:
        srv = http.server.ThreadingHTTPServer(("0.0.0.0", _PORT), _Handler)
    except Exception:
        # port busy -> assume an earlier canary is already listening; reuse it
        return _PORT
    _SERVER = srv
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return _PORT


def token():
    return "aegis" + uuid.uuid4().hex[:12]


def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "127.0.0.1"


def base_url():
    """A TARGET-reachable base for the canary. AEGIS_CANARY_URL wins (operator sets it to a mirror-reachable
    address, e.g. the docker bridge gateway); else best-effort local ip:port."""
    env = os.environ.get("AEGIS_CANARY_URL")
    if env:
        return env.rstrip("/")
    return f"http://{_local_ip()}:{_PORT or _default_port()}"


def url_for(tok, base=None):
    return (base or base_url()).rstrip("/") + "/c/" + tok


def hits(tok, wait=0.0, poll=0.3):
    """Return recorded hits for a token, optionally WAITING up to `wait` seconds for an async callback."""
    deadline = time.time() + max(0.0, wait)
    while True:
        with _LOCK:
            h = list(_HITS.get(tok, []))
        if h or time.time() >= deadline:
            return h
        time.sleep(poll)
