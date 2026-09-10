"""
The bridge server -- the executor at the heart of the orchestrator.

It receives {prompt, mcp_servers, task_id}, drives an LLM (configured from the
same config / secret.env as the operator, so one source of truth for the
model/key) in a tool-calling loop against the kali_driver and browser_use MCP
servers, and streams back newline-delimited JSON chunks:
    {"content": "...", "new_msg": bool}   (repeated)
    {"done": true}                        (final line)

Checkpoint/pause/resume: after every LLM turn and every tool call, the full
message history is saved to checkpoints/<task_id>.json. If a .pause flag file
(checkpoints/<task_id>.pause) appears, the loop stops cleanly at the next
iteration boundary and the checkpoint is kept. A later request with the same
task_id picks the checkpoint back up and continues the same conversation
instead of starting over. On natural completion the checkpoint is deleted.

Run standalone (after kali_driver_server.py and browser_use_server.py are up):
    python bridge_server.py --port 8765
"""
import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from fastmcp import Client
from langchain_openai import ChatOpenAI

from config import Master  # reuse the shared LLM config

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MAX_ITERATIONS = 40

CHECKPOINT_DIR = Path(__file__).parent / "checkpoints"
CHECKPOINT_DIR.mkdir(exist_ok=True)

app = FastAPI()

# Per-task_id lock, held for the ENTIRE duration of one request's streaming
# response (checkpoint load through final save). Without this, two requests
# for the same task_id -- e.g. an external scheduler re-dispatching a
# subtask (resume=false) while a manual `resume` (resume=true) from
# aegis_cli.py is still actively running -- can interleave their
# checkpoint load/save calls with no coordination, and whichever one saves
# last silently wins. Observed in practice as real, unrecoverable data loss
# (a task's full transcript reset to a fresh start mid-assessment). Waiting
# for the lock is always the safe choice here: by the time it's free, the
# previous request has already saved a complete, consistent checkpoint
# (finished, paused, or errored), so the next request -- resume or fresh
# redispatch -- always builds on real, current state instead of racing it.
_task_locks: dict[str, asyncio.Lock] = {}


def _get_task_lock(task_id: str) -> asyncio.Lock:
    # prune finished tasks' locks (unlocked + checkpoint already deleted) so the map
    # does not grow unbounded over a long-lived server. Safe: a task with no checkpoint
    # has nothing to clobber, so re-creating its lock later is harmless.
    if len(_task_locks) > 64:
        for _tid in [t for t, l in list(_task_locks.items())
                     if t != task_id and not l.locked() and not _checkpoint_path(t).exists()]:
            _task_locks.pop(_tid, None)
    lock = _task_locks.get(task_id)
    if lock is None:
        lock = asyncio.Lock()
        _task_locks[task_id] = lock
    return lock


def _log(req_id: str, msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] [{req_id}] {msg}", flush=True)


def _checkpoint_path(task_id: str) -> Path:
    return CHECKPOINT_DIR / f"{task_id}.json"


def _pause_flag_path(task_id: str) -> Path:
    return CHECKPOINT_DIR / f"{task_id}.pause"


def _save_checkpoint(task_id: str, messages: list):
    # Atomic write: Path.write_text() truncates then writes, so a crash/kill
    # mid-write leaves a truncated/corrupt JSON file that _load_checkpoint
    # silently treats as "no checkpoint" -- resetting a task's full transcript
    # to a fresh start. Write to a temp file and os.replace() it into place
    # instead, which is atomic on both POSIX and Windows.
    path = _checkpoint_path(task_id)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(messages, indent=2), encoding="utf-8")
    # os.replace is atomic, but on Windows it raises PermissionError/[WinError 5]
    # if the destination is momentarily locked (antivirus scanning the .json, a
    # reader holding a handle, an indexer). That failure used to bubble up as a
    # "checkpoint save failed" bridge error, which a planner treated as
    # a subtask failure and re-branched on -- a real source of runaway growth.
    # Retry the rename a few times with a short backoff before giving up.
    for _attempt in range(6):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.25 * (_attempt + 1))
    # Last resort: one final try that surfaces the error if it still cannot rename.
    os.replace(tmp, path)


def _load_checkpoint(task_id: str) -> list | None:
    path = _checkpoint_path(task_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _repair_dangling_tool_calls(messages: list) -> list:
    """If the process got killed/restarted between saving an assistant
    message (with tool_calls) and executing+saving those tools' results,
    the checkpoint ends with one or more unresolved tool_calls -- the
    OpenAI-format API rejects that outright on the next call. This can happen
    partway through a multi-tool-call batch too (each tool response is
    checkpointed individually as it completes), so scan back to the most
    recent assistant-with-tool_calls, find which of ITS call ids already have
    a matching tool response after it, and synthesize an "interrupted,
    please retry" placeholder only for the ones still missing."""
    for i in range(len(messages) - 1, -1, -1):
        m = messages[i]
        if m.get("role") != "assistant" or not m.get("tool_calls"):
            continue
        answered = {
            mm.get("tool_call_id")
            for mm in messages[i + 1:]
            if mm.get("role") == "tool"
        }
        for call in m["tool_calls"]:
            if call["id"] not in answered:
                messages.append({
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "content": "[interrupted before this tool call could execute -- retry it if still needed]",
                })
        break
    return messages


def _delete_checkpoint(task_id: str):
    _checkpoint_path(task_id).unlink(missing_ok=True)
    _pause_flag_path(task_id).unlink(missing_ok=True)


def _archive_checkpoint_if_present(task_id: str) -> str | None:
    """a caller can reuse the same task_id for an unrelated fresh subtask/retry
    right after a pause -- never silently clobber a paused checkpoint. Rename it
    aside so it stays resumable under its own archived name."""
    path = _checkpoint_path(task_id)
    if not path.exists():
        return None
    archived = CHECKPOINT_DIR / f"{task_id}.paused-{int(time.time())}.json"
    path.rename(archived)
    return str(archived)


def _mcp_tool_to_openai(tool, server_key: str) -> dict:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description or "",
            "parameters": tool.inputSchema or {"type": "object", "properties": {}},
        },
    }, server_key


async def _collect_tools(clients: dict) -> tuple[list, dict]:
    """Returns (openai_tool_specs, {tool_name: server_key})"""
    specs = []
    owner = {}
    for server_key, client in clients.items():
        tools = await client.list_tools()
        for t in tools:
            spec, key = _mcp_tool_to_openai(t, server_key)
            specs.append(spec)
            owner[t.name] = key
    return specs, owner


@app.post("/")
async def run_prompt(request: Request):
    body = await request.json()
    prompt = body.get("prompt", "")
    mcp_servers = body.get("mcp_servers", {})
    task_id = body.get("task_id") or uuid.uuid4().hex
    # Resuming must be explicitly requested (only the CLI's `resume` command sets this).
    # an external scheduler reuses the same task_id across sequential subtask calls
    # and retries -- those must never be misread as a user-initiated resume, or separate
    # subtasks would get concatenated into one runaway conversation.
    resume_requested = bool(body.get("resume", False))
    req_id = uuid.uuid4().hex[:8]

    kali_url = mcp_servers.get("kali_driver")
    browser_url = mcp_servers.get("browser_use")

    # Generous timeout -- a full port scan or slow tool install can take
    # minutes, and fastmcp's Client default was cutting those off with a
    # ReadTimeout that crashed the whole request.
    MCP_CLIENT_TIMEOUT = 600
    clients = {}
    if kali_url:
        clients["kali_driver"] = Client(kali_url, timeout=MCP_CLIENT_TIMEOUT)
    if browser_url:
        clients["browser_use"] = Client(browser_url, timeout=MCP_CLIENT_TIMEOUT)

    async def generate():
        lock = _get_task_lock(task_id)
        if lock.locked():
            _log(req_id, f"task_id={task_id} is busy with another request -- waiting for it to finish/pause before proceeding")
        async with lock:
            checkpoint = _load_checkpoint(task_id) if resume_requested else None
            resuming = checkpoint is not None
            _log(req_id, f"{'RESUMING' if resuming else 'NEW'} task_id={task_id}: {prompt[:200]!r}")

            opened = []
            try:
                for c in clients.values():
                    await c.__aenter__()
                    opened.append(c)

                tool_specs, tool_owner = await _collect_tools(clients)

                llm = ChatOpenAI(
                    # executor keeps its own model (default v4-pro, thinking on),
                    # independent of the planner's AEGIS_MODEL, so the
                    # planner can run a fast model without downgrading the executor.
                    model=os.environ.get("AEGIS_EXECUTOR_MODEL") or Master.get("default_model"),
                    base_url=Master.get("openai_api_endpoint"),
                    api_key=Master.get("openai_api_key"),
                    temperature=0.2,
                    timeout=300,  # no explicit timeout was hitting a shorter httpx default under load
                    max_retries=2,
                )
                bound_llm = llm.bind_tools(tool_specs) if tool_specs else llm

                system_message = {
                    "role": "system",
                    "content": (
                        "The run_command tool executes as root inside a Kali Linux environment.\n"
                        "\n"
                        "Tooling: if a tool you need is missing, install it yourself first "
                        "(apt-get install -y <pkg>, pip install <pkg>). If nothing installed "
                        "already does the job, genuinely search for one that does -- official "
                        "package repos first, but also unofficial sources (GitHub repos, etc.) "
                        "if that's what it takes to find a tool that actually serves the "
                        "purpose. Download and install it yourself (git clone, curl, wget, "
                        "pip install from a repo, build from source if needed). The same goes "
                        "for wordlists/dictionary files or other resources a tool needs to "
                        "actually probe something (e.g. for directory brute-forcing, password "
                        "lists, etc.) -- fetch what's needed. Don't ask for permission to do "
                        "any of this -- just do it as part of completing the task.\n"
                        "\n"
                        "If a target is running WordPress, use multiple complementary "
                        "WordPress-specific scanners rather than just generic web tools, since "
                        "they cover different angles and don't fully overlap: WPScan "
                        "(https://github.com/wpscanteam/wpscan, apt-get install -y wpscan or "
                        "gem install wpscan) for core/plugin/theme vulnerability scanning, "
                        "Plecost for plugin version fingerprinting, and WP-Scanner "
                        "(https://github.com/Triotion/WP-Scanner, git clone) as an additional "
                        "pass. Install whichever aren't already present.\n"
                        "\n"
                        "If a target stops responding partway through an assessment that was "
                        "previously working (repeated connection timeouts/refusals to a host "
                        "that answered fine earlier, not a host that was never reachable), this "
                        "is most likely the target's own WAF/rate-limiting reacting to scan "
                        "volume from this source IP -- that is itself a legitimate finding to "
                        "record (their defenses are working). You may switch egress IP via "
                        "'vpn-ctl connect \"<Country Name>\"' (run 'vpn-ctl list' for options; "
                        "'vpn-ctl status' shows the current public IP; 'vpn-ctl disconnect' tears "
                        "it down) to continue the SAME non-intrusive recon/scanning that was "
                        "already in scope -- not to attempt anything newly intrusive. Follow "
                        "real pentest practice, not noisy IP-hopping: try at most ONE alternate "
                        "server if the first is also blocked, then stop and report the block as "
                        "a finding rather than continuing to rotate. Never use this to bypass "
                        "an authentication gate, brute-force protection, or rate-limit that is "
                        "specifically guarding a login/auth endpoint -- that changes the nature "
                        "of the test and is out of scope. Always note in your final result which "
                        "checks (if any) were performed over the VPN and why, so the report "
                        "reflects it. If 'vpn-ctl connect' errors that no credentials file "
                        "exists, that means the account owner hasn't set one up -- do not try to "
                        "create or guess credentials; just report the target as blocked and move "
                        "on to whatever else can still be tested.\n"
                        "\n"
                        "Data boundary: by default, nothing leaves this local machine except "
                        "requests to the target(s) you were explicitly asked to test. Never "
                        "upload, paste, or transmit scan results, findings, files, credentials, "
                        "or any other data to any third-party service, server, or endpoint "
                        "(no pastebins, no external APIs, no 'let me save this online' -- "
                        "nothing outside this machine and the project's own files)."
                    ),
                }

                if resuming:
                    messages = _repair_dangling_tool_calls(checkpoint)
                    _log(req_id, f"loaded checkpoint with {len(messages)} messages")
                    original_task = next(
                        (m["content"] for m in messages if m.get("role") == "user"), ""
                    )
                    extra = f" Additional instruction: {prompt.strip()}" if prompt.strip() else ""
                    resume_note = (
                        "This is a RESUME of a paused task, not a new one. Do not explore "
                        "the environment, do not re-read your own source files or unrelated "
                        "checkpoints -- those are internal tooling, not part of your task. "
                        "Your original task was:\n\n"
                        f"{original_task}\n\n"
                        "Review the messages above to see exactly what you already did, then "
                        "continue immediately with whatever step comes next. Do not repeat "
                        f"steps you already completed.{extra}"
                    )
                    messages.append({"role": "user", "content": resume_note})
                else:
                    archived = _archive_checkpoint_if_present(task_id)
                    if archived:
                        _log(req_id, f"NOTE: an existing paused checkpoint for this task_id was archived to {archived} instead of being overwritten")
                    messages = [system_message, {"role": "user", "content": prompt}]

                _save_checkpoint(task_id, messages)

                for step in range(MAX_ITERATIONS):
                    if _pause_flag_path(task_id).exists():
                        _pause_flag_path(task_id).unlink(missing_ok=True)
                        _save_checkpoint(task_id, messages)
                        _log(req_id, "PAUSED (checkpoint kept)")
                        yield json.dumps(
                            {"content": "\n[PAUSED -- task checkpointed, resume it to continue]\n", "new_msg": False}
                        ) + "\n"
                        return

                    ai_msg = await bound_llm.ainvoke(messages)
                    has_tool_calls = bool(getattr(ai_msg, "tool_calls", None))

                    assistant_msg = {"role": "assistant", "content": ai_msg.content or ""}
                    if has_tool_calls:
                        assistant_msg["tool_calls"] = [
                            {
                                "id": tc["id"],
                                "type": "function",
                                "function": {"name": tc["name"], "arguments": json.dumps(tc["args"])},
                            }
                            for tc in ai_msg.tool_calls
                        ]
                    messages.append(assistant_msg)
                    _save_checkpoint(task_id, messages)

                    if ai_msg.content:
                        _log(req_id, f"LLM (step {step}): {ai_msg.content[:300]}")

                    # the client does: final_content += content; if new_msg: final_content = ''
                    # i.e. new_msg means "this chunk is scratch, wipe it before the real answer".
                    # Only the LAST content (no further tool calls) must survive, so only it gets
                    # new_msg=False; every interim/narration/tool-result chunk gets new_msg=True.
                    if ai_msg.content:
                        yield json.dumps({"content": ai_msg.content, "new_msg": has_tool_calls}) + "\n"

                    if not has_tool_calls:
                        _log(req_id, "DONE (final answer)")
                        _delete_checkpoint(task_id)
                        break

                    for call in ai_msg.tool_calls:
                        server_key = tool_owner.get(call["name"])
                        _log(req_id, f"TOOL CALL -> {server_key}.{call['name']}({call['args']})")
                        result_text = f"[no such tool: {call['name']}]"
                        if server_key:
                            try:
                                result = await clients[server_key].call_tool(call["name"], call["args"])
                                result_text = "\n".join(
                                    getattr(block, "text", str(block)) for block in result.content
                                )
                            except Exception as e:
                                result_text = f"[tool error: {e}]"

                        _log(req_id, f"TOOL RESULT <- {call['name']}: {result_text[:300]}")

                        yield json.dumps(
                            {"content": f"\n[{call['name']} -> {result_text[:2000]}]\n", "new_msg": True}
                        ) + "\n"

                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": call["id"],
                                "content": result_text,
                            }
                        )
                        _save_checkpoint(task_id, messages)
                else:
                    _log(req_id, "STOPPED: max iterations reached (checkpoint kept, resumable)")
                    yield json.dumps(
                        {"content": "\n[stopped: max iterations reached -- resume to continue]\n", "new_msg": False}
                    ) + "\n"

            except Exception as e:
                _log(req_id, f"ERROR: {e}")
                yield json.dumps({"content": f"\n[bridge error: {e}]\n", "new_msg": False}) + "\n"
            finally:
                for c in opened:
                    try:
                        await c.__aexit__(None, None, None)
                    except Exception:
                        pass
                yield json.dumps({"done": True}) + "\n"

    return StreamingResponse(generate(), media_type="application/x-ndjson")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port)
