#!/usr/bin/env python3
"""Render the contained multi-agent blackboard (any *.md), oldest->newest."""
import os, glob, time
# Board directory: $AEGIS_BOARD_DIR wins, else ./board_files next to this script.
BOARD=os.environ.get("AEGIS_BOARD_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)),"board_files")
posts=sorted(glob.glob(os.path.join(BOARD,"*.md")), key=os.path.getmtime)
if not posts:
    print("[board empty -- no messages yet]"); raise SystemExit
print(f"=== BLACKBOARD: {len(posts)} messages ===")
for p in posts:
    ts=time.strftime("%H:%M:%S", time.localtime(os.path.getmtime(p)))
    body=open(p,encoding="utf-8",errors="replace").read().strip()
    print(f"\n--- [{ts}] {os.path.basename(p)} ---\n{body}")
