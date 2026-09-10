# Live view of the multi-model board -- your default window onto the chat.
# Refresh: $env:AEGIS_BOARD_REFRESH seconds (default 25; 20-30 recommended).
# Board dir: $env:AEGIS_BOARD_DIR (default ./board_files next to this script).
# You post questions INTO the board via the co-pilot: operator/board_ask.py "<your question>".
$py = $env:AEGIS_PYTHON
if ([string]::IsNullOrEmpty($py)) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cmd.Source } else { $py = "py" }
}
$view = Join-Path $PSScriptRoot "board_view.py"
$refresh = $env:AEGIS_BOARD_REFRESH
if ([string]::IsNullOrEmpty($refresh)) { $refresh = 25 }
$Host.UI.RawUI.WindowTitle = "Aegis TEAM BLACKBOARD (live)"
while ($true) {
  Clear-Host
  Write-Host ("=== LIVE BLACKBOARD  " + (Get-Date -Format "HH:mm:ss") + "  (refresh ${refresh}s, Ctrl+C to close) ===") -ForegroundColor Cyan
  Write-Host "post a question:  operator/board_ask.py `"<your question>`"" -ForegroundColor DarkGray
  & $py $view
  Start-Sleep -Seconds ([int]$refresh)
}
