# real-server-test.ps1 - drive a full real-server RDP session and report the reached phase.
#
# Usage (credentials are read from the environment so they are never written to disk):
#   $env:RTSC_HOST="192.168.1.7"; $env:RTSC_PORT="3389"
#   $env:RTSC_DOMAIN="MicrosoftAccount"; $env:RTSC_USER="user@host"; $env:RTSC_PASS="..."
#   .\scripts\real-server-test.ps1
#
# The script runs the existing tools in order and prints the phase reached by each:
#   1. rtsc_connect  - X.224 / MCS / TLS / CredSSP / licensing / session setup
#   2. rtsc_gui      - the interactive client (headless backend when RTSC_UI_BACKEND=headless)
# It exits non-zero if a prerequisite is missing or the build is stale.

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$build = Join-Path $root "build\Release"
$cmake = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

if (-not (Test-Path (Join-Path $build "rtsc_connect.exe"))) {
    Write-Host "rtsc_connect.exe not found; building..." -ForegroundColor Yellow
    & $cmake --build (Join-Path $root "build") --config Release | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
}

$rdpHost = if ($env:RTSC_HOST) { $env:RTSC_HOST } else { "192.168.1.7" }
$rdpPort  = if ($env:RTSC_PORT) { $env:RTSC_PORT } else { "3389" }
$domain = $env:RTSC_DOMAIN
$user   = $env:RTSC_USER
$pass   = $env:RTSC_PASS

Write-Host "=== phase 1: rtsc_connect ${rdpHost}:$rdpPort ===" -ForegroundColor Cyan
if ($user -and $pass) {
    & (Join-Path $build "rtsc_connect.exe") $rdpHost $rdpPort $domain $user $pass
} else {
    Write-Host "RTSC_USER / RTSC_PASS not set; running without credentials (expected to stop at the NTLM challenge)." -ForegroundColor Yellow
    & (Join-Path $build "rtsc_connect.exe") $rdpHost $rdpPort
}
$connectExit = $LASTEXITCODE
Write-Host "rtsc_connect exit=$connectExit" -ForegroundColor Cyan

if ($connectExit -eq 0) {
    Write-Host "=== phase 2: rtsc_gui (interactive) ===" -ForegroundColor Cyan
    if (-not $env:RTSC_UI_BACKEND) { $env:RTSC_UI_BACKEND = "headless" }
    # The run is bounded explicitly: rtsc_gui no longer stops on its own (a real
    # session renders until the window closes). --seconds keeps the script's
    # headless phase finite.
    & (Join-Path $build "rtsc_gui.exe") $rdpHost $rdpPort $domain $user $pass --seconds 20
    Write-Host "rtsc_gui exit=$LASTEXITCODE" -ForegroundColor Cyan
}

Write-Host "=== reach summary ===" -ForegroundColor Cyan
Write-Host "rtsc_connect exit = $connectExit  (0 = reached session setup / active session)"
exit $connectExit
