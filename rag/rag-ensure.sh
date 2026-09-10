#!/usr/bin/env bash
# Boot-time readiness for the Kali-resident aegis-rag store.
# Runs as a systemd oneshot at every Kali (WSL) start. It does NOT go to the
# network -- it only guarantees the local DB is PRESENT and CONSISTENT so that
# rag_search works the moment Kali is up. Network refresh stays manual (refresh.sh).
#
#   - if ragl.sqlite is missing OR fails a quick integrity check, restore the
#     newest snapshot from backups/ (single, WAL-folded file);
#   - fold any leftover WAL back into the main DB (TRUNCATE checkpoint);
#   - log everything to rag-ensure.log. Never fails the boot (exit 0).
set -uo pipefail
HOME_DIR="${AEGIS_RAG_HOME:-/opt/aegis-rag}"
DB="$HOME_DIR/ragl.sqlite"
BK="$HOME_DIR/backups"
LOG="$HOME_DIR/rag-ensure.log"
PY="${PYTHON:-python3}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }

quick_ok() {
  # 0 if DB exists and quick_check says ok, else non-zero
  [ -f "$DB" ] || return 1
  local r
  r="$("$PY" - "$DB" <<'PYEOF'
import sqlite3, sys
try:
    c = sqlite3.connect(sys.argv[1], timeout=30)
    v = c.execute("PRAGMA quick_check").fetchone()[0]
    c.close()
    print(v)
except Exception as e:
    print("ERR:%s" % e)
PYEOF
)"
  [ "$r" = "ok" ]
}

restore_latest() {
  local snap
  snap="$(ls -1t "$BK"/ragl-*.sqlite 2>/dev/null | head -1 || true)"
  if [ -z "$snap" ]; then
    log "RESTORE FAILED: DB bad/missing and NO snapshot in $BK -- rag_search will be unavailable until a rebuild"
    return 1
  fi
  log "restoring DB from snapshot: $snap"
  rm -f "$DB" "$DB-wal" "$DB-shm"
  cp "$snap" "$DB"
  log "restore complete ($(du -h "$DB" | cut -f1))"
}

mkdir -p "$HOME_DIR" "$BK"

if quick_ok; then
  # fold any stale WAL into the main file so the store is single-file clean
  "$PY" - "$DB" >>"$LOG" 2>&1 <<'PYEOF' || true
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=60)
c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
c.close()
PYEOF
  n="$("$PY" - "$DB" <<'PYEOF' 2>/dev/null || echo '?'
import sqlite3, sys
c=sqlite3.connect(sys.argv[1]); print(c.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]); c.close()
PYEOF
)"
  log "OK: DB present and consistent (${n} vulns)"
else
  log "DB missing or failed quick_check -- attempting restore"
  restore_latest || true
fi
exit 0
