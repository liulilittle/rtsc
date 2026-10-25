# perf-gate.ps1 - render-loop performance and continuity gate.
#
# Verifies the three properties the performance work must hold on a real server:
#   1. frame rate  : a headless session sustains >= $FpsFloor loop FPS;
#   2. no bounded exit : a win32 session is still running after $Win32Seconds
#      (the old build stopped after 30 frames / 20 s, which looked like a frozen
#      screenshot);
#   3. CPU         : an idle session (the desktop painted, no inbound data)
#      stays under $CpuCeilingPercent% of a core. The render loop must not
#      re-render when nothing changed.
#
# Usage (credentials come from the environment so they are never written here):
#   $env:RTSC_HOST="192.168.1.7"; $env:RTSC_PORT="3389"
#   $env:RTSC_DOMAIN="MicrosoftAccount"; $env:RTSC_USER="..."; $env:RTSC_PASS="..."
#   .\scripts\perf-gate.ps1
#
# Exits 0 when every check passes, 1 otherwise.

param(
    [string]$GuiPath = "",
    [int]$FpsFloor = 20,
    [int]$Win32Seconds = 3,
    [int]$CpuSeconds = 10,
    [double]$CpuCeilingPercent = 5.0
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$build = Join-Path $root "build\Release"
$gui = if ($GuiPath -ne "") { $GuiPath } else { Join-Path $build "rtsc_gui.exe" }
if (-not (Test-Path $gui)) { throw "rtsc_gui.exe not found: $gui" }

$rdpHost = if ($env:RTSC_HOST) { $env:RTSC_HOST } else { "192.168.1.7" }
$rdpPort = if ($env:RTSC_PORT) { $env:RTSC_PORT } else { "3389" }
$domain = $env:RTSC_DOMAIN
$user = $env:RTSC_USER
$pass = $env:RTSC_PASS

$failures = New-Object System.Collections.Generic.List[string]
function Fail($msg) { $script:failures.Add($msg); Write-Host "FAIL: $msg" -ForegroundColor Red }
function Info($msg) { Write-Host "  $msg" }

# ---------------------------------------------------------------- check 1 + 3
# A time-bounded headless run. The per-second "fps:" line reports the loop rate;
# the CPU sample over the tail of the run is the idle cost.
$headlessOut = Join-Path $env:TEMP "rtsc-perf-headless.txt"
$headlessErr = "$headlessOut.err"
Remove-Item -LiteralPath $headlessOut, $headlessErr -ErrorAction SilentlyContinue

Write-Host "=== check 1+3: headless frame rate and idle CPU ===" -ForegroundColor Cyan
$p = Start-Process -FilePath $gui `
    -ArgumentList @($rdpHost, $rdpPort, $domain, $user, $pass, "1280", "1024", "headless", "--seconds", "$CpuSeconds") `
    -RedirectStandardOutput $headlessOut -RedirectStandardError $headlessErr -PassThru

# Sample the process CPU just before the run ends, so the measured window is the
# idle tail (the desktop is painted within the first second or two).
$cpuAtStart = $null
$cpuAtEnd = $null
$wallStart = Get-Date
$guiPid = $p.Id
while (-not $p.HasExited) {
    if ($null -eq $cpuAtStart -and ((Get-Date) - $wallStart).TotalSeconds -ge ($CpuSeconds - 4)) {
        $cpuAtStart = (Get-Process -Id $guiPid).TotalProcessorTime
    }
    Start-Sleep -Milliseconds 250
}
$cpuAtEnd = (Get-Process -Id $guiPid -ErrorAction SilentlyContinue).TotalProcessorTime
if ($null -eq $cpuAtEnd) { $cpuAtEnd = $p.TotalProcessorTime }
$p.WaitForExit()
$wall = ((Get-Date) - $wallStart).TotalSeconds

if (-not (Test-Path $headlessOut)) { Fail "headless run produced no output" }
$lines = Get-Content -LiteralPath $headlessOut -ErrorAction SilentlyContinue
$loopFps = $null
foreach ($ln in $lines) {
    if ($ln -match 'fps:\s*([\d.]+)\s*loop') { $loopFps = [double]$Matches[1] }
}
$summary = $lines | Where-Object { $_ -match 'loop frames' } | Select-Object -Last 1
Info "summary: $summary"

if ($null -eq $loopFps) {
    Fail "no 'fps: ... loop' line in the headless output"
} else {
    Info "loop fps: $loopFps (floor $FpsFloor)"
    if ($loopFps -lt $FpsFloor) { Fail "loop fps $loopFps < floor $FpsFloor" }
}

# Byte-level lossless 1:1: the default view must be a bit-exact copy of the
# remote surface. main.cpp prints this for the default zoom=100%/fit=false view;
# the unit-level guarantee also lives in ctest (view_scale_1to1_is_bit_exact).
$lossless = $lines | Where-Object { $_ -match 'lossless 1:1' } | Select-Object -Last 1
if ($null -eq $lossless) {
    Fail "no 'lossless 1:1' line in the headless output (default view is not 1:1)"
} else {
    Info "lossless: $lossless"
    if ($lossless -notmatch 'bit-exact') { Fail "1:1 view is not bit-exact: $lossless" }
}

if ($null -ne $cpuAtStart) {
    $cores = [Environment]::ProcessorCount
    $cpuSecondsUsed = ($cpuAtEnd - $cpuAtStart).TotalSeconds
    if ($cpuSecondsUsed -lt 0) { $cpuSecondsUsed = 0 }
    $window = $wall - ($CpuSeconds - 4)
    if ($window -le 0) { $window = $wall }
    $cpuPct = 100.0 * $cpuSecondsUsed / $window / $cores
    Info ("idle CPU: {0:F2}% of one core over {1:F1}s ({2} cores)" -f $cpuPct, $window, $cores)
    if ($cpuPct -gt $CpuCeilingPercent) {
        Fail ("idle CPU {0:F2}% > ceiling {1:F1}%" -f $cpuPct, $CpuCeilingPercent)
    }
} else {
    Info "run too short to sample idle CPU"
}

# ---------------------------------------------------------------- check 2
# The win32 backend must not stop on its own: after $Win32Seconds it should still
# be alive (the old build exited after 30 frames / 20 s).
Write-Host "=== check 2: win32 has no bounded exit ===" -ForegroundColor Cyan
$win32Out = Join-Path $env:TEMP "rtsc-perf-win32.txt"
$win32Err = "$win32Out.err"
Remove-Item -LiteralPath $win32Out, $win32Err -ErrorAction SilentlyContinue

$w = Start-Process -FilePath $gui `
    -ArgumentList @($rdpHost, $rdpPort, $domain, $user, $pass, "1280", "1024", "win32") `
    -RedirectStandardOutput $win32Out -RedirectStandardError $win32Err -PassThru
Start-Sleep -Seconds $Win32Seconds
if ($w.HasExited) {
    Fail "win32 session exited after $Win32Seconds s (bounded exit is back); code=$($w.ExitCode)"
} else {
    Info "win32 session still running after $Win32Seconds s (no bounded exit)"
    $w.Kill()
    $w.WaitForExit(5000) | Out-Null
}

# ---------------------------------------------------------------- verdict
Write-Host ""
if ($failures.Count -eq 0) {
    Write-Host "perf-gate: PASS (fps >= $FpsFloor, no bounded exit, idle CPU <= $CpuCeilingPercent%)" -ForegroundColor Green
    exit 0
}
Write-Host "perf-gate: FAIL ($($failures.Count) check(s))" -ForegroundColor Red
foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
exit 1
