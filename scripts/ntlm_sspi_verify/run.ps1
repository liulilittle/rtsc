# run.ps1 - offline cross-check of rtsc's NTLMv2/MIC against the local
# Microsoft NTLMSSP (msv1_0). No network, no RDP server involved.
#
# It creates a temporary local SAM account, drives the rtsc client messages
# into Microsoft's AcceptSecurityContext as the server, and asserts:
#   * correct password  -> ACCEPTED (exit 0)
#   * wrong password    -> REJECTED (exit 1)
# Then it removes the temporary account.
#
# Requires: Administrator (to create/delete the local account), a Release build
# of rtsc_credssp / rtsc_crypto under <repo>\build\Release, and MSVC.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts\ntlm_sspi_verify\run.ps1

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$out = Join-Path $root "build\ntlm_sspi_verify"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$user = "rtsc_sspi_tmp"
$good = "RtscTmp!Pw2026"
$bad = "RtscTmp!Wrong"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "must run as Administrator (creates a temporary local account)"
    exit 1
}

Write-Host "== create temporary local account =="
# Remove any leftover from an aborted earlier run so /add cannot fail.
cmd /c "net user $user /delete >nul 2>&1" | Out-Null
cmd /c "net user $user $good /add" | Out-Null

$libCredssp = Join-Path $root "build\Release\rtsc_credssp.lib"
$libCrypto = Join-Path $root "build\Release\rtsc_crypto.lib"
if (-not (Test-Path $libCredssp) -or -not (Test-Path $libCrypto)) {
    cmd /c "net user $user /delete >nul 2>&1" | Out-Null
    Write-Error "missing build\Release libs; run: cmake --build build --config Release"
    exit 1
}

try {
    Write-Host "== build harness =="
    $vs = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    $src = Join-Path $PSScriptRoot "sspi_verify_ours.cpp"
    $libs = (Join-Path $root "build\Release\rtsc_credssp.lib") + " " +
            (Join-Path $root "build\Release\rtsc_crypto.lib")
    $cl = "call `"$vs`" >nul 2>&1 && cl /nologo /std:c++17 /MD /EHsc /W3 " +
          "/I `"$root\include`" /Fe:`"$out\sspi_verify_ours.exe`" /Fo:`"$out\\`" " +
          "`"$src`" $libs secur32.lib"
    cmd /c $cl
    if ($LASTEXITCODE -ne 0) { throw "compile failed" }

    Write-Host "== correct password (expect ACCEPTED) =="
    & "$out\sspi_verify_ours.exe" $user $good
    $rcGood = $LASTEXITCODE

    Write-Host "== wrong password (expect REJECTED) =="
    & "$out\sspi_verify_ours.exe" $user $bad
    $rcBad = $LASTEXITCODE

    Write-Host ""
    if ($rcGood -eq 0 -and $rcBad -ne 0) {
        Write-Host "PASS: rtsc NTLMv2/MIC accepted iff the password is correct"
        exit 0
    } else {
        Write-Host "FAIL: good=$rcGood bad=$rcBad (expected 0 and non-zero)"
        exit 1
    }
} finally {
    Write-Host "== remove temporary account =="
    cmd /c "net user $user /delete" | Out-Null
}
