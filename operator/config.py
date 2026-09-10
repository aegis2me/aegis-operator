"""Local LLM config for the DeepSeek co-pilot.

`Master` exposes the API key / endpoint / model so `from config import Master`
works WITHOUT dot-sourcing a shell env script (set-env.local.ps1). Secrets are
NOT hardcoded here -- they load, in order:
    1. real environment variables (DEEPSEEK_* / AEGIS_LLM_*), then
    2. a gitignored `secret.env` next to this file (KEY=VALUE lines).
So the value is imported at runtime; the actual key lives only in secret.env,
which is gitignored (never committed, never sent to a cloud review).
"""
import os

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_secret_env(path):
    vals = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1); k = k.strip()
                vals[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return vals


_FILE = _load_secret_env(os.path.join(_HERE, "secret.env"))


def _get(*names, default=None):
    for n in names:                       # env wins
        v = os.environ.get(n)
        if v:
            return v
    for n in names:                       # then gitignored secret.env
        v = _FILE.get(n)
        if v:
            return v
    return default


Master = {
    "openai_api_key": _get("DEEPSEEK_API_KEY", "AEGIS_LLM_API_KEY"),
    "openai_api_endpoint": _get("DEEPSEEK_ENDPOINT", "AEGIS_LLM_ENDPOINT",
                                default="https://api.deepseek.com/v1"),
    "default_model": _get("AEGIS_MODEL", default="deepseek-v4-pro"),
    "executor_model": _get("AEGIS_EXECUTOR_MODEL", "AEGIS_MODEL",
                           default="deepseek-v4-pro"),
    # Direct OpenAI (GPT-5.6 Sol) -- kept SEPARATE from the DeepSeek key above so the two
    # never collide. Put OPENAI_API_KEY=... in secret.env (gitignored) to enable Sol runs.
    "openai_direct_key": _get("OPENAI_API_KEY"),
    "openai_direct_endpoint": _get("OPENAI_ENDPOINT", default="https://api.openai.com/v1"),
}
