#!/usr/bin/env python3
"""
Maintenance for the aegis-rag store: integrity check + safe online backup.

Both operations are safe to run WHILE the DB is being written (e.g. during an NVD
backfill): the backup uses SQLite's online backup API, which copies pages under a
read lock and retries busy pages, producing a consistent snapshot without stopping
writers. Integrity uses PRAGMA integrity_check.

Subcommands:
  integrity            -> PRAGMA integrity_check; exit 0 if "ok", else 1 (+ prints issues)
  backup [--keep N]    -> consolidated snapshot to <db_dir>/backups/ragl-<ts>.sqlite,
         [--export DIR]    pruned to the last N (default 5); optional static copy to DIR
                           (e.g. a /mnt/c path -- fine as a COPY; never open the live DB there)
"""
import argparse
import datetime
import glob
import os
import shutil
import sqlite3
import sys

import rag_db


def _db_path(args):
    return args.db or rag_db.DEFAULT_DB


def integrity(args) -> int:
    path = _db_path(args)
    conn = sqlite3.connect(path, timeout=120)
    try:
        rows = conn.execute("PRAGMA integrity_check").fetchall()
    finally:
        conn.close()
    msgs = [r[0] for r in rows] if rows else ["<no result>"]
    if msgs == ["ok"]:
        print(f"[maint] integrity OK: {path}")
        return 0
    print(f"[maint] INTEGRITY FAILED for {path}:", file=sys.stderr)
    for m in msgs[:20]:
        print(f"   - {m}", file=sys.stderr)
    return 1


def backup(args) -> int:
    path = _db_path(args)
    bdir = os.path.join(os.path.dirname(path) or ".", "backups")
    os.makedirs(bdir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dst_path = os.path.join(bdir, f"ragl-{ts}.sqlite")

    src = sqlite3.connect(path, timeout=120)
    try:
        # Fold the WAL back into the main file so the snapshot is a single, complete DB.
        src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        dst = sqlite3.connect(dst_path)
        try:
            with dst:
                src.backup(dst)          # atomic online backup (safe under concurrent writes)
        finally:
            dst.close()
    finally:
        src.close()
    size = os.path.getsize(dst_path)
    print(f"[maint] backup -> {dst_path} ({size/1_048_576:.1f} MB)")

    # Rotate: keep the most recent N snapshots.
    snaps = sorted(glob.glob(os.path.join(bdir, "ragl-*.sqlite")))
    for old in snaps[:-args.keep] if args.keep > 0 else []:
        try:
            os.remove(old)
            print(f"[maint] pruned {os.path.basename(old)}")
        except OSError as e:
            print(f"[maint] could not prune {old}: {e}", file=sys.stderr)

    # Optional static copy off-box (e.g. a /mnt/c path). A COPY over DrvFs is fine.
    if args.export:
        os.makedirs(args.export, exist_ok=True)
        out = os.path.join(args.export, os.path.basename(dst_path))
        shutil.copy2(dst_path, out)
        print(f"[maint] exported copy -> {out}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="aegis-rag maintenance")
    ap.add_argument("--db", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("integrity")
    b = sub.add_parser("backup")
    b.add_argument("--keep", type=int, default=5)
    b.add_argument("--export", default=None)
    args = ap.parse_args()

    if args.cmd == "integrity":
        sys.exit(integrity(args))
    elif args.cmd == "backup":
        sys.exit(backup(args))


if __name__ == "__main__":
    main()
