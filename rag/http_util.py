"""
Minimal HTTP helper for the aegis-rag ingestors.

Uses `requests` (already present on Kali). Honors HTTP_PROXY/HTTPS_PROXY from the
environment automatically -- so routing fetches through the pentest VPN is just a
matter of exporting those before calling refresh.sh. Sends a normal browser-ish
User-Agent (some feeds 403 the default python-requests UA).
"""
import time
import requests

UA = ("Mozilla/5.0 (X11; Linux x86_64) aegis-rag/1.0 "
      "(+authorized security research)")


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    return s


def get(session, url, params=None, headers=None, timeout=60, retries=4, backoff=3.0):
    """GET with simple exponential backoff on network errors / 429 / 5xx."""
    last = None
    for attempt in range(retries):
        try:
            r = session.get(url, params=params, headers=headers, timeout=timeout)
            if r.status_code in (429, 500, 502, 503, 504):
                last = f"HTTP {r.status_code}"
                time.sleep(backoff * (attempt + 1))
                continue
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            last = str(e)
            time.sleep(backoff * (attempt + 1))
    raise RuntimeError(f"GET failed after {retries} attempts: {url} :: {last}")
