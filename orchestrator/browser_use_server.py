"""
browser_use MCP server.

A minimal Playwright-backed browser automation MCP server: navigate, read
text, click, fill forms, screenshot. Keeps a single persistent browser
context across calls within one process.

Uses Playwright's ASYNC API deliberately -- FastMCP's tool handlers run
inside an already-running asyncio event loop, and Playwright's sync API
cannot be used there (it raises "Sync API inside the asyncio loop").

Run standalone:
    python browser_use_server.py --port 8902
"""
import argparse
import base64
import sys
import time

from fastmcp import FastMCP
from playwright.async_api import async_playwright

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

mcp = FastMCP("browser-use")

_state = {"playwright": None, "browser": None, "page": None}


def _log(msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


async def _ensure_page():
    if _state["page"] is None:
        _state["playwright"] = await async_playwright().start()
        _state["browser"] = await _state["playwright"].chromium.launch(headless=True)
        _state["page"] = await _state["browser"].new_page()
    return _state["page"]


@mcp.tool
async def browser_goto(url: str) -> str:
    """Navigate the browser to a URL and return the page title."""
    _log(f">>> GOTO: {url}")
    page = await _ensure_page()
    await page.goto(url, wait_until="domcontentloaded", timeout=30000)
    title = await page.title()
    _log(f"<<< title: {title}")
    return title


@mcp.tool
async def browser_get_text() -> str:
    """Return the visible text content of the current page."""
    _log(">>> GET_TEXT")
    page = await _ensure_page()
    text = await page.inner_text("body")
    _log(f"<<< {len(text)} chars")
    return text


@mcp.tool
async def browser_click(selector: str) -> str:
    """Click an element matched by a CSS selector."""
    _log(f">>> CLICK: {selector}")
    page = await _ensure_page()
    await page.click(selector, timeout=10000)
    return f"clicked {selector}"


@mcp.tool
async def browser_fill(selector: str, text: str) -> str:
    """Fill a form field matched by a CSS selector with text."""
    _log(f">>> FILL: {selector} <- {text!r}")
    page = await _ensure_page()
    await page.fill(selector, text, timeout=10000)
    return f"filled {selector}"


@mcp.tool
async def browser_screenshot() -> str:
    """Take a screenshot of the current page, returned as base64 PNG."""
    _log(">>> SCREENSHOT")
    page = await _ensure_page()
    png_bytes = await page.screenshot()
    return base64.b64encode(png_bytes).decode("ascii")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8902)
    args = parser.parse_args()
    mcp.run(transport="http", host=args.host, port=args.port)
