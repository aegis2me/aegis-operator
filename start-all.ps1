# Starts the Aegis infrastructure: the kali_driver + browser_use MCP tool servers
# and the bridge orchestrator -- each in its own titled PowerShell window.
#
# This is the STANDALONE stack: there is no external task scheduler. You drive it
# with the operator directly (operator\aegis_operator.py) or the ExploitGym runner
# (exploitgym\...), both of which use the bridge's tools via the servers below.
#
# Real secrets (LLM API key etc.) live in set-env.local.ps1, which is gitignored --
# edit the key/endpoint/model there, not in this file. Copy it from
# set-env.local.ps1.example first.

$root = $PSScriptRoot

# --- Python: $env:AEGIS_PYTHON wins, else the py launcher, else python on PATH ---
$py = $env:AEGIS_PYTHON
if ([string]::IsNullOrEmpty($py)) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cmd.Source } else { $py = "py" }
}

$localEnv = Join-Path $root "set-env.local.ps1"
if (-not (Test-Path $localEnv)) {
    Write-Output "Missing $localEnv -- copy it from set-env.local.ps1.example and fill in your own LLM API key."
    exit 1
}
. $localEnv

$tmpDir = Join-Path $env:TEMP "aegis-launch"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

function Start-TitledWindow {
    param([string]$Title, [string[]]$Lines, [string]$ScriptName)
    $scriptPath = Join-Path $tmpDir $ScriptName
    $safeTitle = $Title -replace "'", "''"
    $full = @("`$Host.UI.RawUI.WindowTitle = '$safeTitle'") + $Lines
    Set-Content -Path $scriptPath -Value $full -Encoding UTF8
    Start-Process powershell -ArgumentList "-NoExit", "-File", $scriptPath
}

Write-Output "== 1/4 Starting kali-linux WSL distro =="
wsl -d kali-linux -- true
Write-Output "wsl: $(((wsl -l -v | Out-String) -replace "`0","" -replace '\s+',' '))"

# --- Optional VPN preflight (off by default; a lab convenience, needs vpn-ctl in Kali) ---
$vpnRequire = $env:AEGIS_REQUIRE_VPN
if ($vpnRequire -match '^(?i)(1|true|yes|on)$') {
    $vpnRegion = $env:AEGIS_VPN_REGION   # no country baked in -- must be set explicitly by the user
    if ([string]::IsNullOrEmpty($vpnRegion)) {
        Write-Warning "[vpn] AEGIS_REQUIRE_VPN=1 but AEGIS_VPN_REGION is unset -- set it to use a region, or leave off."
    }
    Write-Output "[vpn] ensuring tunnel$(if($vpnRegion){" (region=$vpnRegion)"})..."
    wsl -d kali-linux -u root -- vpn-ctl ensure @($vpnRegion | Where-Object { $_ }) 2>&1 | Out-Null
    $vpnStatus = (wsl -d kali-linux -u root -- vpn-ctl status 2>&1 | Out-String)
    if ($vpnStatus -match 'VPN:\s*active') { Write-Output "[vpn] tunnel UP" }
    else { Write-Warning "[vpn] tunnel did NOT come up -- start it manually if your target needs it." }
} else {
    Write-Output "[vpn] preflight off (set AEGIS_REQUIRE_VPN=1 to enable; needs vpn-ctl in Kali)"
}

Write-Output "== 2/4 kali_driver MCP server (port 8901) =="
Start-TitledWindow -Title "Aegis - kali_driver (8901)" -ScriptName "kali_driver.ps1" -Lines @(
    "& '$py' '$root\orchestrator\kali_driver_server.py' --port 8901"
)
Start-Sleep -Seconds 2

Write-Output "== 3/4 browser_use MCP server (port 8902) =="
Start-TitledWindow -Title "Aegis - browser_use (8902)" -ScriptName "browser_use.ps1" -Lines @(
    "& '$py' '$root\orchestrator\browser_use_server.py' --port 8902"
)
Start-Sleep -Seconds 2

Write-Output "== 4/4 bridge orchestrator (port 8765) =="
Start-TitledWindow -Title "Aegis - bridge (8765)" -ScriptName "bridge.ps1" -Lines @(
    ". '$localEnv'",
    "& '$py' '$root\orchestrator\bridge_server.py' --port 8765"
)
Start-Sleep -Seconds 1

Write-Output "== live board viewer (your default window onto the chat, ~25s refresh) =="
Start-TitledWindow -Title "Aegis - LIVE BOARD" -ScriptName "board.ps1" -Lines @(
    "& '$root\board\live_board.ps1'"
)

Write-Output ""
Write-Output "Infra up. Drive it from a new shell:"
Write-Output "  cd '$root\operator'   ; & '$py' aegis_operator.py --task '<mission>'   [--auto-approve]"
Write-Output "  cd '$root\exploitgym' ; & '$py' -m exploitgym.cli run <scenario>"
Write-Output "  cd '$root\board'      ; ./live_board.ps1        # watch the multi-model board"
