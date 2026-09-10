#!/usr/bin/env python3
"""
Smoke test for the direct-OpenAI (GPT-5.6 Sol) path. Exercises the REAL aegis_operator code:
key resolution from secret.env, provider detection, and _create()'s param branching
(drops the DeepSeek thinking param, renames max_tokens->max_completion_tokens, omits
temperature), plus a tool-calling round-trip (the whole agentic loop depends on tool_calls).

Run:  python test_sol.py
Cost: one tiny call to gpt-5.6-sol (fractions of a cent).
"""
import os
os.environ["AEGIS_PROVIDER"] = "openai"   # force the OpenAI branch for this test

import aegis_operator as d
from openai import OpenAI

key, endpoint = d._resolve_key_endpoint()
print(f"provider   : {d._provider()}")
print(f"endpoint   : {endpoint}")
print(f"key set    : {bool(key)}  (source: secret.env / env)")
if not key:
    print("\n[FAIL] No OpenAI key resolved. Add  OPENAI_API_KEY=sk-...  to DeepSeek-CLI/secret.env")
    raise SystemExit(1)

model = os.environ.get("AEGIS_MODEL") or "gpt-5.6-sol"
print(f"model      : {model}\n")

client = OpenAI(api_key=key, base_url=endpoint)
tools = [{"type": "function", "function": {
    "name": "report_status", "description": "Report a one-word status.",
    "parameters": {"type": "object",
                   "properties": {"status": {"type": "string"}},
                   "required": ["status"]}}}]

try:
    # goes through aegis_operator._create -> for openai: no thinking, max_completion_tokens, no temperature
    resp = d._create(
        client, model=model,
        messages=[{"role": "system", "content": "You are a test harness."},
                  {"role": "user", "content": "Call report_status with status='ok'."}],
        tools=tools, tool_choice="auto",
        temperature=0.2, max_tokens=1000,   # _create strips/renames these for openai
    )
except Exception as e:
    print(f"[FAIL] chat.completions.create errored: {type(e).__name__}: {e}")
    raise SystemExit(1)

msg = resp.choices[0].message
calls = [tc.function.name for tc in (msg.tool_calls or [])]
print(f"content    : {(msg.content or '')[:200]!r}")
print(f"tool_calls : {calls}")
print(f"usage      : {getattr(resp, 'usage', None)}")
print()
if calls:
    print("[PASS] OpenAI path works AND tool-calling works -> aegis_operator can drive GPT-5.6 Sol.")
else:
    print("[WARN] Connected + params OK, but the model returned NO tool_call. The agentic loop "
          "needs tool-calling; check that this model supports OpenAI function calling.")
