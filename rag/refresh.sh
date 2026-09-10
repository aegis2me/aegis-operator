#!/usr/bin/env bash
# Online (offline-safe) refresh of the aegis-rag store before a run.
# No-op unless --online is passed or AEGIS_RAG_ONLINE=1 -- the store stays fully usable offline.
# Pulls deltas from public vuln feeds (KEV/EPSS/NVD-delta/... ) via rag_update.py, which backs up
# first and rolls back on an integrity failure. Extra args pass straight through to rag_update.py.
set -uo pipefail
HOME_DIR="${AEGIS_RAG_HOME:-/opt/aegis-rag}"
PY="${PYTHON:-python3}"
cd "$HOME_DIR" 2>/dev/null || { echo "[refresh] $HOME_DIR not found -- skipping"; exit 0; }
exec "$PY" "$HOME_DIR/rag_update.py" "$@"
