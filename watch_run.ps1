# Open the AEGIS live run view (suite HEALTH + FINDINGS table) in THIS window, refreshing.
# Run in a SEPARATE terminal so the board/main session stays uncluttered:
#   powershell -NoExit -File .\watch_run.ps1
$py = $env:AEGIS_PYTHON; if (-not $py) { $py = "python" }
& $py "$PSScriptRoot\operator\run_monitor.py" findings --follow
