# start_android.ps1 -- launch the ANDROID de/compiler with DeepSeek in the COORDINATOR seat.
#
# Run it FROM the android folder. If PowerShell blocks scripts ("running scripts is disabled"), start it as:
#     powershell -ExecutionPolicy Bypass -File .\start_android.ps1
# or pass everything on one line, e.g.:
#     powershell -ExecutionPolicy Bypass -File .\start_android.ps1 -Apk "C:\path\app.apk" -Goal "disable analytics upload on startup"
#
# What it does: decompile (apktool + jadx) -> explore -> hand the whole loop to DeepSeek as coordinator
# (DeepSeek decides the concrete change, the board plans it, ONE coder executes the smali/res edit, then it
# rebuilds+signs the APK). Owned apps only; the input .apk is never modified (work is on a copy in Kali).

param(
    [string]$Apk,                                   # path to the .apk (prompted if omitted)
    [string]$Name,                                  # working name (defaults to the apk file name)
    [string]$Goal,                                  # what to change (prompted if omitted)
    [string]$Coordinator = "deepseek-v4-pro",       # the LLM in the coordinator seat
    [string]$Coder       = "deepseek-v4-pro",       # the single code writer that executes the edit
    [switch]$NoRebuild,                             # write the change but don't rebuild the APK
    [switch]$SkipDecompile                          # reuse an already-decompiled --Name workdir
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot                          # the android/ folder
$py = $env:AEGIS_PYTHON; if (-not $py) { $py = "python" }
if (-not $env:AEGIS_KALI_DISTRO) { $env:AEGIS_KALI_DISTRO = "kali-linux" }

Write-Host "=== AEGIS ANDROID de/compiler ===" -ForegroundColor Cyan
Write-Host "coordinator = $Coordinator   coder = $Coder" -ForegroundColor DarkCyan

# ---- gather inputs ----
if (-not $Apk -and -not $SkipDecompile) { $Apk = Read-Host "Path to the .apk" }
if (-not $Name) {
    if ($Apk) { $Name = [System.IO.Path]::GetFileNameWithoutExtension($Apk) }
    else      { $Name = Read-Host "Working name of the already-decompiled app" }
}
if (-not $Goal) { $Goal = Read-Host "What should DeepSeek change? (goal)" }

Write-Host ""
Write-Host "app name : $Name"
Write-Host "goal     : $Goal"
Write-Host ""

# ---- 1. decompile ----
if (-not $SkipDecompile) {
    if (-not (Test-Path $Apk)) { Write-Host "APK not found: $Apk" -ForegroundColor Red; exit 1 }
    if ($Apk -match '\.aab$') {
        Write-Host "NOTE: this looks like an .aab (App Bundle). apktool can't rebuild .aab/split APKs directly --" -ForegroundColor Yellow
        Write-Host "      merge to a single .apk first (e.g. with APKEditor). Continuing to decompile anyway." -ForegroundColor Yellow
    }
    Write-Host "[1/3] decompiling (apktool + jadx)..." -ForegroundColor Green
    & $py "android.py" decompile "$Apk" --name "$Name"
    if ($LASTEXITCODE -ne 0) { Write-Host "decompile failed" -ForegroundColor Red; exit 1 }
}

# ---- 2. explore ----
Write-Host "[2/3] exploring the decompiled app..." -ForegroundColor Green
& $py "android.py" explore --name "$Name"

# ---- 3. hand to DeepSeek as coordinator ----
Write-Host "[3/3] handing the loop to $Coordinator (coordinator)..." -ForegroundColor Green
$coordArgs = @("android.py", "coordinate", "--name", "$Name", "--goal", "$Goal",
               "--coordinator", "$Coordinator", "--coder", "$Coder")
if ($NoRebuild) { $coordArgs += "--no-rebuild" }
& $py @coordArgs

Write-Host ""
Write-Host "Done. Patched APK (if rebuilt) is in Kali: /root/apk_work/$Name/$Name.patched.apk" -ForegroundColor Cyan
Write-Host "Copy it out with:  wsl -d $($env:AEGIS_KALI_DISTRO) -u root -- cp /root/apk_work/$Name/$Name.patched.apk /mnt/c/Users/<you>/Desktop/" -ForegroundColor DarkCyan
