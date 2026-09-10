#!/usr/bin/env python3
"""
mirror_snapshot.py -- snapshot / restore the mirror's database (PIPELINE stage 2 + stage 8 reset).

The mirror is a disposable twin, but testing PLANTS data (estimates, invoices, credit-notes...). To
keep runs clean and to reset between ExploitGym episodes, snapshot the baseline DB and restore it
afterwards. This is a DB-level reset (fast, undoes all planted rows) via pg_dump/psql inside the
target's Postgres container in Kali.

Usage:
    python mirror_snapshot.py snapshot [name]     # default name: "baseline"
    python mirror_snapshot.py restore  [name]
    python mirror_snapshot.py list

Config (env, with mirror defaults):
    AEGIS_DB_CONTAINER=target-mirror-db-1  AEGIS_DB_USER=appdb  AEGIS_DB_NAME=appdb
    AEGIS_DB_PASS=mirror-db-pass      AEGIS_WSL_DISTRO=kali-linux
    AEGIS_SNAPSHOT_DIR=<this dir>/mirror_snapshots
"""
import os, sys, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
DB_CONTAINER = os.environ.get("AEGIS_DB_CONTAINER", "target-mirror-db-1")
DB_USER = os.environ.get("AEGIS_DB_USER", "appdb")
DB_NAME = os.environ.get("AEGIS_DB_NAME", "appdb")
DB_PASS = os.environ.get("AEGIS_DB_PASS", "mirror-db-pass")
WSL_DISTRO = os.environ.get("AEGIS_WSL_DISTRO", "kali-linux")
SNAP_DIR = os.environ.get("AEGIS_SNAPSHOT_DIR", os.path.join(HERE, "mirror_snapshots"))


def _env():
    e = dict(os.environ); e["MSYS_NO_PATHCONV"] = "1"; e["MSYS2_ARG_CONV_EXCL"] = "*"
    return e


def _wsl(args, **kw):
    return subprocess.run(["wsl", "-d", WSL_DISTRO, "-u", "root", "--"] + args,
                          env=_env(), capture_output=True, **kw)


def snapshot(name="baseline"):
    os.makedirs(SNAP_DIR, exist_ok=True)
    path = os.path.join(SNAP_DIR, f"{name}.sql")
    # pg_dump with --clean --if-exists -> a self-contained restore script (drops+recreates objects)
    r = _wsl(["docker", "exec", "-e", f"PGPASSWORD={DB_PASS}", DB_CONTAINER,
              "pg_dump", "-U", DB_USER, "-d", DB_NAME, "--clean", "--if-exists", "--no-owner"],
             timeout=300)
    if r.returncode != 0:
        sys.exit(f"snapshot failed: {r.stderr.decode('utf-8','replace')[:300]}")
    open(path, "wb").write(r.stdout)
    kb = len(r.stdout) // 1024
    print(f"snapshot '{name}' -> {path} ({kb} KB)")


def restore(name="baseline"):
    path = os.path.join(SNAP_DIR, f"{name}.sql")
    if not os.path.exists(path):
        sys.exit(f"no snapshot '{name}' at {path} (run: mirror_snapshot.py snapshot {name})")
    data = open(path, "rb").read()
    # terminate other connections so DROPs don't block, then replay the dump via psql stdin
    _wsl(["docker", "exec", "-e", f"PGPASSWORD={DB_PASS}", DB_CONTAINER, "psql", "-U", DB_USER,
          "-d", DB_NAME, "-c",
          f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{DB_NAME}' AND pid<>pg_backend_pid();"],
         timeout=60)
    r = _wsl(["docker", "exec", "-i", "-e", f"PGPASSWORD={DB_PASS}", DB_CONTAINER, "psql", "-U", DB_USER,
              "-d", DB_NAME, "-v", "ON_ERROR_STOP=0", "-q"], input=data, timeout=300)
    err = r.stderr.decode("utf-8", "replace")
    # psql prints NOTICEs on --if-exists drops; only surface real ERRORs
    real = [l for l in err.splitlines() if "ERROR" in l]
    print(f"restored '{name}' from {path}" + (f" ({len(real)} psql errors — first: {real[0][:120]})" if real else " (clean)"))


def _list():
    if not os.path.isdir(SNAP_DIR):
        print("(no snapshots yet)"); return
    rows = sorted(os.listdir(SNAP_DIR))
    for f in rows:
        if f.endswith(".sql"):
            p = os.path.join(SNAP_DIR, f)
            print(f"  {f[:-4]:20s} {os.path.getsize(p)//1024:>6} KB  {time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(p)))}")
    if not rows:
        print("(no snapshots yet)")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    name = sys.argv[2] if len(sys.argv) > 2 else "baseline"
    if cmd == "snapshot": snapshot(name)
    elif cmd == "restore": restore(name)
    elif cmd == "list": _list()
    else: sys.exit(__doc__)
