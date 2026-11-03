# verify.ps1 - one-shot verification: clean configure + build + ctest (+ crash guard check).
# Usage: pwsh verify.ps1 [-Clean] [-CrashCheck] [-DocLint] [-PseudoLint]
#   -Clean       build into an isolated timestamped directory.
#   -CrashCheck  additionally run rtsc_crashtest for each crash mode and assert
#                that a minidump + text report were produced without any dialog.
#   -DocLint     additionally run the documentation consistency checks
#                (evidence/doc/doc_lint.py, see docs/spec/doc-lint.plan.md).
#                Skipped when python is unavailable.
#   -TlsRedTest additionally mutate the SChannel backend one rule at a time and
#                assert the TLS test suite fails for every mutation
#                (evidence/tls/red_test_tls.py). Requires a prior build.
#   -CredsspRedTest
#                the same for the CredSSP/NTLM layer
#                (evidence/credssp/red_test_credssp.py). Requires a prior build.
#   -PseudoLint  additionally run the pseudocode STRUCTURAL checks
#                (evidence/tls/pseudo_lint.py + pseudo_lint_redtest.py).
#                These catch control-flow defects that regex text checks cannot:
#                missing loop back-edge, undefined identifiers, else bound to the
#                wrong `if`, exit-table drift. See docs/spec/tls-backend.design-a.md
#                section 3.4.2 and 8.10.
#   -PreBatch1   additionally run the one-shot batch-1 pre-fix pre-flight
#   -PostBatch2  additionally run the batch-2 delivery gate (required tests
#                by name + the S23 tls.h contract)
#                (only meaningful BEFORE batch 1 lands; it asserts the
#                defects are still present, so it fails by design after)
#   -DocCite     additionally run the documentation citation gate (semantic
#                anchors + two red tests)
#   -LinuxBuild  additionally run scripts/linux-build-gate.sh under WSL and
#                assert the Linux build succeeds with zero warnings and zero
#                windows.h hits (the S21 regression signature).
#                Environment missing (no wsl) is a FAIL, not a skip: the whole
#                point is that a Windows-only green build must not hide a Linux
#                break (audit B0-01/B0-02).
# All temporary files stay inside the repository (.tmp / build / crashes).

param([switch]$Clean, [switch]$CrashCheck, [switch]$DocLint, [switch]$PseudoLint,
      [switch]$TlsRedTest, [switch]$CredsspRedTest, [switch]$LinuxBuild, [switch]$DocCite,
      [switch]$PreBatch1, [switch]$PerfGate,
    [switch]$PostBatch2)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$buildDir = if ($Clean) { Join-Path $root "build\verify-$stamp" } else { Join-Path $root "build\verify" }

# Ninja decides what to recompile by mtime. Any tool that restores a file with
# its old timestamp (Copy-Item, git checkout of an older blob) makes a source
# travel backwards in time, so Ninja keeps the object built from the OLD bytes
# and never recompiles it (.opencode/discover.md examples 36/62). The run then
# measures code that is not in the working tree: it reported three tls failures
# that vanished after one forced rebuild. Fingerprint the tree instead of the
# clock: when the tree changed since the build directory was last completed,
# throw the build directory away so the result cannot be stale.
# git writes advice to stderr (e.g. "LF will be replaced by CRLF"), and this
# script runs with $ErrorActionPreference = "Stop", which turns native stderr
# into a terminating error. Relax it for the queries only.
$eapBefore = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$fpParts = @()
$fpParts += (& git -C $root rev-parse HEAD 2>&1 | Out-String)
$fpParts += (& git -C $root status --porcelain 2>&1 | Out-String)
$fpParts += (& git -C $root diff --numstat HEAD 2>&1 | Out-String)
$files = @(& git -C $root ls-files -- src include tests tools CMakeLists.txt 2>&1)
$ErrorActionPreference = $eapBefore
# Content alone is not enough: a mutation that is built and then reverted leaves
# the tree byte-identical while the build directory still holds the mutant's
# objects. Timestamps catch that, because reverting a file always changes its
# mtime (Copy-Item keeps the OLD one, an editor writes a NEW one -- either way it
# differs from the state that was stamped). Size is included so a same-mtime
# rewrite is still noticed.
foreach ($f in $files) {
    $full = Join-Path $root $f
    if (Test-Path -LiteralPath $full) {
        $it = Get-Item -LiteralPath $full
        $fpParts += "$f|$($it.Length)|$($it.LastWriteTimeUtc.Ticks)"
    }
}
$fpText = ($fpParts -join "`n")
$sha = [System.Security.Cryptography.SHA256]::Create()
$fp = [System.BitConverter]::ToString(
    $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fpText))).Replace("-", "")
$fpFile = Join-Path $buildDir ".verify-tree-fingerprint"
if (-not $Clean -and (Test-Path $buildDir) -and (Test-Path $fpFile)) {
    $recorded = (Get-Content -LiteralPath $fpFile -Raw).Trim()
    if ($recorded -ne $fp) {
        Write-Host "== stale build directory =="
        Write-Host "  the tree changed since $buildDir was last completed; rebuilding from scratch"
        Remove-Item -LiteralPath $buildDir -Recurse -Force
    }
} elseif (-not $Clean -and (Test-Path $buildDir) -and -not (Test-Path $fpFile)) {
    Write-Host "== stale build directory =="
    Write-Host "  $buildDir has no fingerprint (built before this gate existed); rebuilding from scratch"
    Remove-Item -LiteralPath $buildDir -Recurse -Force
}

$env:TEMP = Join-Path $root ".tmp"
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null

$vsRoot = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
$vcvars = Join-Path $vsRoot "VC\Auxiliary\Build\vcvars64.bat"
$cmake = Join-Path $vsRoot "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$ctest = Join-Path $vsRoot "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe"

if (-not (Test-Path $cmake)) { Write-Error "cmake not found at $cmake"; exit 1 }

Write-Host "== mutation residue gate =="
# A mutation that was not reverted before building produces a binary that does
# not correspond to the sources; the test run then measures the mutant and the
# real defect hides behind a green build (.opencode/discover.md examples 36/39).
#
# The check is deliberately dumb: ANY occurrence of the mutation token in the
# covered trees fails. An earlier version tried to exempt "comment-only" lines
# by looking at the first character, which is unsound in C++ -- `// log();` (a
# commented-out call, the most common leftover), `#define X 1` (a preprocessor
# directive) and `*p = 5;` (a dereference) were all treated as prose, so exactly
# the B2 residue form passed (audit V, D5). Do not reintroduce a comment
# heuristic or a file:line allowlist: sources are expected to keep the token out
# of prose, so no exemption is needed.
#
# Two more traps this gate must not fall into itself (audit W, D3/D4/D6):
#   * a bare `git grep` resolves the repository from the process CWD, so running
#     this script from anywhere else greps nothing and "passes" -- anchor it with
#     -C $root (the rest of this script already uses $PSScriptRoot the same way);
#   * `git grep` skips untracked files by default, and a leftover mutation is
#     often a brand-new file -- pass --untracked.
# Exit status: 0 = matches, 1 = no match (both normal), >1 = the grep failed.
# Scope: the trees that hold product and test sources. CMakeLists.txt, this
# script and scripts/ are excluded on purpose (no MUT- token has ever appeared
# there: `git log --all -S'MUT-' -- CMakeLists.txt verify.ps1 scripts cmake` is
# empty); widen the list if that changes.
$mutHits = @(git -C $root grep -n --untracked 'MUT-' -- src include tools tests 2>$null)
if ($LASTEXITCODE -gt 1) {
    Write-Host "  mutation residue gate could not run (git grep exit $LASTEXITCODE)"
    exit 1
}
if ($mutHits.Count -gt 0) {
    Write-Host "  mutation residue found (revert before building):"
    $mutHits | ForEach-Object { Write-Host "    $_" }
    exit 1
}
Write-Host "  mutation residue gate passed"

Write-Host "== configure =="
$configure = "call `"$vcvars`" >nul 2>&1 && `"$cmake`" -S `"$root`" -B `"$buildDir`" -G Ninja -DCMAKE_BUILD_TYPE=Debug"
cmd /c $configure
if ($LASTEXITCODE -ne 0) { Write-Error "configure failed"; exit 1 }

Write-Host "== build =="
$build = "call `"$vcvars`" >nul 2>&1 && `"$cmake`" --build `"$buildDir`""
cmd /c $build
if ($LASTEXITCODE -ne 0) { Write-Error "build failed"; exit 1 }

Write-Host "== ctest =="
& $ctest --test-dir $buildDir --output-on-failure
$ctestExit = $LASTEXITCODE
if ($ctestExit -ne 0) { exit $ctestExit }

# Only a completed run (build + tests) may stamp the tree, so a directory that
# still holds objects from an older tree can never be trusted on the next run.
Set-Content -LiteralPath $fpFile -Value $fp -NoNewline -Encoding ASCII
Write-Host "  tree fingerprint recorded"

if ($CrashCheck) {
    Write-Host "== crash guard =="
    $exe = Join-Path $buildDir "rtsc_crashtest.exe"
    if (-not (Test-Path $exe)) { Write-Error "rtsc_crashtest.exe not built"; exit 1 }
    $crashDir = Join-Path $buildDir "crashes"
    $env:RTSC_CRASH_DIR = $crashDir

    $failures = 0
    foreach ($mode in @("null", "abort", "terminate")) {
        # A fresh directory per mode: proves each mode writes its own artifacts
        # instead of reusing a stale dump from a previous run.
        $modeDir = Join-Path $crashDir $mode
        if (Test-Path $modeDir) { Remove-Item $modeDir -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $modeDir | Out-Null
        $env:RTSC_CRASH_DIR = $modeDir

        # A 60s cap is the actual regression test: a WER dialog would never return.
        # System.Diagnostics.Process is used directly because Start-Process
        # -PassThru does not reliably expose ExitCode under PowerShell 5.1.
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe
        $psi.Arguments = $mode
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        $finished = $proc.WaitForExit(60000)
        if (-not $finished) {
            try { $proc.Kill() } catch { }
            Write-Host "  [$mode] FAIL: hung for 60s (WER dialog still blocking)"
            ++$failures
            continue
        }
        $proc.WaitForExit()
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $exitCode = $proc.ExitCode
        $proc.Dispose()
        if ($stdout.Trim().Length -gt 0) { Write-Host "        stdout: $($stdout.Trim())" }
        if ($stderr.Trim().Length -gt 0) { Write-Host "        stderr: $($stderr.Trim())" }
        $dumps = @(Get-ChildItem -Path $modeDir -Filter "*.dmp" -ErrorAction SilentlyContinue |
                   Where-Object { $_.Length -gt 0 })
        $texts = @(Get-ChildItem -Path $modeDir -Filter "*.txt" -ErrorAction SilentlyContinue |
                   Where-Object { $_.Length -gt 0 })

        if ($exitCode -eq 0) {
            Write-Host "  [$mode] FAIL: exit code $exitCode (expected non-zero)"
            ++$failures
            continue
        }
        if ($dumps.Count -lt 1) { Write-Host "  [$mode] FAIL: no .dmp produced"; ++$failures; continue }
        if ($texts.Count -lt 1) { Write-Host "  [$mode] FAIL: no .txt report produced"; ++$failures; continue }

        $report = Get-Content $texts[0].FullName -TotalCount 6
        $reasonLine = $report | Where-Object { $_ -like "reason=*" }
        $expected = @{ "null" = "unhandled-seh"; "abort" = "abort"; "terminate" = "std::terminate" }[$mode]
        if ($reasonLine -ne "reason=$expected") {
            Write-Host "  [$mode] FAIL: expected reason=$expected, got '$reasonLine'"
            ++$failures
            continue
        }

        Write-Host ("  [$mode] OK  exit={0}  dump={1} ({2} bytes)  reason={3}" -f `
            $exitCode, $dumps[0].Name, $dumps[0].Length, $expected)
        foreach ($line in $report) { Write-Host "        $line" }
    }
    if ($failures -ne 0) { Write-Error "crash guard check failed ($failures mode(s))"; exit 1 }
    Write-Host "  all crash modes captured without blocking"
}

if ($DocLint) {
    Write-Host "== doc lint =="
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $py) {
        Write-Warning "python not found: doc lint skipped (environment issue, not a pass)"
    } else {
        $lint = Join-Path $root "evidence\doc\doc_lint.py"
        if (-not (Test-Path $lint)) { Write-Error "doc_lint.py not found at $lint"; exit 1 }
        # PowerShell 5.1 mangles UTF-8 stdout; force UTF-8 for the child process.
        $env:PYTHONIOENCODING = "utf-8"
        & $py $lint --root $root
        if ($LASTEXITCODE -ne 0) { Write-Error "doc lint failed"; exit 1 }
        Write-Host "  doc lint passed"
    }
}

if ($PseudoLint) {
    Write-Host "== pseudo lint =="
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $py) {
        Write-Warning "python not found: pseudo lint skipped (environment issue, not a pass)"
    } else {
        $env:PYTHONIOENCODING = "utf-8"
        $plint = Join-Path $root "evidence\tls\pseudo_lint.py"
        $pred  = Join-Path $root "evidence\tls\pseudo_lint_redtest.py"
        $sem   = Join-Path $root "evidence\tls\verify_elif_semantics.py"
        $side  = Join-Path $root "evidence\tls\verify_sideeffect_leaf.py"
        $csr   = Join-Path $root "evidence\tls\count_sec_refs.py"
        $state = Join-Path $root "evidence\tls\state_snapshot.py"
        $g13   = Join-Path $root "evidence\tls\verify_g13.py"
        # Precheck EVERY gate file. Missing file must FAIL, never silently skip
        # (consult-b step 14 G9: deleting a checker used to disable it silently).
        foreach ($f in @($plint, $pred, $sem, $side, $csr, $state, $g13)) {
            if (-not (Test-Path $f)) { Write-Error "missing $f"; exit 1 }
        }
        $gateExits = @()

        # 1) structural checks (target document must be fail=0)
        & $py $plint --file (Join-Path $root "docs\spec\tls-backend.design-a.md")
        $gateExits += "S1_struct=$LASTEXITCODE"
        if ($LASTEXITCODE -ne 0) { Write-Error "pseudo lint failed"; exit 1 }

        # 2) red test: the checker must catch every injected defect
        & $py $pred
        $gateExits += "S2_redtest=$LASTEXITCODE"
        if ($LASTEXITCODE -ne 0) { Write-Error "pseudo lint red test failed"; exit 1 }

        # 3) semantics: run the pseudocode as a program, assert each state
        & $py $sem
        $gateExits += "S3_semantics=$LASTEXITCODE"
        if ($LASTEXITCODE -ne 0) { Write-Error "elif semantics verification failed"; exit 1 }

        # 4) regression: known defects in each historical snapshot must still be caught
        # Snapshots are version-controlled inputs of the regression gate.
        # They must NOT live in .tmp (consult-b step 16: .tmp is a scratch area
        # any cleanup tool may wipe; missing snapshots disable the whole gate).
        $snaps = @(
            "design-a.bak.md",
            "design-a.step7.snapshot.md",
            "design-a.step7.v2.md",
            "design-a.step8.base.md"
        )
        $snapArgs = @()
        foreach ($sn in $snaps) {
            $sp = Join-Path $root "evidence\tls\snapshots\$sn"
            if (-not (Test-Path $sp)) {
                Write-Error "missing snapshot $sp - regression gate cannot run"
                exit 1
            }
            $snapArgs += $sp
        }
        & $py $plint --regress @snapArgs --current (Join-Path $root "docs\spec\tls-backend.design-a.md")
        $gateExits += "S4_regress=$LASTEXITCODE"
        if ($LASTEXITCODE -ne 0) { Write-Error "pseudo lint regression failed"; exit 1 }

        # 4b) side-effect leaf classification (closed_ flag consistency)
        & $py $side
        $gateExits += "S5_sideeffect=$LASTEXITCODE"
        if ($LASTEXITCODE -ne 0) { Write-Error "side-effect leaf check failed"; exit 1 }

        # 4c) metric accuracy: the structural counters must exclude docstrings
        # (consult-b step 18 G13: a docstring-only edit used to shift the metric,
        #  which made the recorded trajectory lie about the code).
        & $py $g13
        $gateExits += "S7_g13=$LASTEXITCODE"
        if ($LASTEXITCODE -ne 0) { Write-Error "G13 metric accuracy check failed"; exit 1 }

        # 5) cross-reference counts: the doc claim must equal caliber B
        & $py $csr --check
        $gateExits += "S6_secrefs=$LASTEXITCODE"
        if ($LASTEXITCODE -ne 0) { Write-Error "section reference count mismatch"; exit 1 }

        # 6) record a machine-generated state snapshot (evidence, not a gate).
        # consult-b step 17 rule F: before/after states must be machine generated.
        & $py $state --step gate --phase after --exit-codes ($gateExits -join ",") | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Error "state snapshot failed"; exit 1 }

        Write-Host "  pseudo lint passed"
    }
}

if ($TlsRedTest) {
    Write-Host "== tls red test =="
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $py) {
        Write-Warning "python not found: tls red test skipped (environment issue, not a pass)"
    } else {
        $env:PYTHONIOENCODING = "utf-8"
        $red = Join-Path $root "evidence\tls\red_test_tls.py"
        $buildBat = Join-Path $root ".tmp\build_tls.bat"
        if (-not (Test-Path $red)) { Write-Error "missing $red"; exit 1 }
        if (-not (Test-Path $buildBat)) { Write-Error "missing $buildBat"; exit 1 }
        & $py $red
        if ($LASTEXITCODE -ne 0) { Write-Error "tls red test failed"; exit 1 }
        Write-Host "  tls red test passed"
    }
}

if ($CredsspRedTest) {
    Write-Host "== credssp red test =="
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $py) {
        Write-Warning "python not found: credssp red test skipped (environment issue, not a pass)"
    } else {
        $env:PYTHONIOENCODING = "utf-8"
        $red = Join-Path $root "evidence\credssp\red_test_credssp.py"
        $buildBat = Join-Path $root ".tmp\build_tls.bat"
        if (-not (Test-Path $red)) { Write-Error "missing $red"; exit 1 }
        if (-not (Test-Path $buildBat)) { Write-Error "missing $buildBat"; exit 1 }
        & $py $red
        if ($LASTEXITCODE -ne 0) { Write-Error "credssp red test failed"; exit 1 }
        Write-Host "  credssp red test passed"
    }
}

if ($DocCite) {
    Write-Host "== doc citation gate =="
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $py) {
        Write-Error "python not found: citation gate cannot run (not a pass)"
        exit 1
    }
    $env:PYTHONIOENCODING = "utf-8"
    $vc  = Join-Path $root "evidence\exec\verify_citations.py"
    $rd  = Join-Path $root "evidence\exec\citations_redtest.py"
    $rdb = Join-Path $root "evidence\exec\semantic_redtest.py"
    $anc = Join-Path $root "evidence\exec\verify_anchors.py"
    # Missing gate file must FAIL, never silently skip.
    foreach ($f in @($vc, $rd, $rdb, $anc)) {
        if (-not (Test-Path $f)) { Write-Error "missing $f"; exit 1 }
    }

    # 1) the citations must resolve semantically
    & $py $vc
    if ($LASTEXITCODE -ne 0) { Write-Error "citation check failed"; exit 1 }

    # 2) structural invariant: every tls_schannel citation must carry a
    #    Select-String-able source anchor (auditor B round 6). This covers all
    #    such citations in the executor-facing sections, not a hand-picked list.
    & $py $anc
    if ($LASTEXITCODE -ne 0) { Write-Error "anchor-required gate failed"; exit 1 }

    # 2) red test A: restoring old numbers in the DOC must be caught
    & $py $rd
    if ($LASTEXITCODE -ne 0) { Write-Error "citation red test (doc) failed"; exit 1 }

    # 3) red test B: document untouched, only the SOURCE perturbed. This proves
    #    the semantic comparison runs, rather than the anchor lookup alone
    #    (auditor A's R-2: red test A cannot distinguish the two, because the
    #    anchor text itself contains the line number).
    & $py $rdb
    if ($LASTEXITCODE -ne 0) { Write-Error "citation semantic red test (source) failed"; exit 1 }

    # 4) red test for the anchor gate itself: stripping one anchor must fail it.
    $ancred = Join-Path $root "evidence\exec\anchors_redtest.py"
    if (-not (Test-Path $ancred)) { Write-Error "missing $ancred"; exit 1 }
    & $py $ancred
    if ($LASTEXITCODE -ne 0) { Write-Error "anchor gate red test failed"; exit 1 }

    # 5) pre-flight: the anchors the executor is told to Select-String must each
    #    still hit the documented number of lines. If one drifts to 0 or 2+,
    #    batch 2 blocks on an instruction that cannot be followed.
    $pf = Join-Path $root "evidence\exec\batch2_preflight.py"
    if (-not (Test-Path $pf)) { Write-Error "missing $pf"; exit 1 }
    & $py $pf
    if ($LASTEXITCODE -ne 0) { Write-Error "batch-2 anchor pre-flight failed"; exit 1 }

    # 5b) batch-1 pre-flight. This is a ONE-SHOT gate: it proves the defects are
    #     still present BEFORE batch 1 lands (otherwise the red test cannot go
    #     red). Once batch 1 is implemented, every row legitimately flips and the
    #     script reports BLOCKED -- so running it unconditionally would make
    #     -DocCite fail forever after a correct fix, and would push the executor
    #     into "report failure / tamper with the gate / revert the fix".
    #
    #     Gate it behind -PreBatch1. The post-batch-1 verdict is the test suites
    #     plus the OTHER gates below (citations / anchors / N6), not this one.
    if ($PreBatch1) {
        $pf1 = Join-Path $root "evidence\exec\batch1_preflight.py"
        if (-not (Test-Path $pf1)) { Write-Error "missing $pf1"; exit 1 }
        & $py $pf1
        if ($LASTEXITCODE -ne 0) { Write-Error "batch-1 anchor pre-flight failed"; exit 1 }
    } else {
        Write-Host "  batch-1 pre-flight skipped (one-shot pre-fix gate; pass -PreBatch1 before batch 1 lands)"
    }

    # 5c) batch-2 delivery gate. This is the POST-fix counterpart of 5b: it checks
    #     that each of the 8 required tests exists BY NAME (a total count cannot
    #     detect "skip S10, add a filler") and that tls.h's kPeerAlert comment no
    #     longer promises an alert description (S23 is a contract defect: the code
    #     is correct, the comment lies).
    #
    #     Gate it behind -PostBatch2: before batch 2 lands the tree legitimately
    #     has 0/8 tests and the old comment, so running it unconditionally would
    #     make -DocCite fail forever before the work is even started.
    if ($PostBatch2) {
        $bg = Join-Path $root "evidence\exec\batch2_gate.py"
        if (-not (Test-Path $bg)) { Write-Error "missing $bg"; exit 1 }
        & $py $bg
        if ($LASTEXITCODE -ne 0) { Write-Error "batch-2 delivery gate failed"; exit 1 }
    } else {
        Write-Host "  batch-2 delivery gate skipped (post-fix gate; pass -PostBatch2 after batch 2 lands)"
    }

    # 6) N6 weak-RNG gate (doc:4010-4012). The nonce test only proves the two
    #    nonces DIFFER; rand()/srand()/time-seeded generators also differ, so the
    #    test stays green with a weak RNG. The doc therefore requires a second,
    #    code-level gate: no weak randomness may appear in the RNG path at all.
    #
    #    Scope: credssp.cpp (the caller) AND the CSPRNG implementation. After
    #    batch 1 the actual generation lives in src/crypto/random_*.cpp, so
    #    scanning credssp.cpp alone would miss a `rand()` written there -- the
    #    exact regression this gate exists to catch. Auditor B round 12.
    #    This must produce NO output; any hit is a failure.
    $cc = Join-Path $root "src\credssp\credssp.cpp"
    if (-not (Test-Path $cc)) { Write-Error "missing $cc"; exit 1 }
    $rngFiles = @($cc)
    $rngGlob = Get-ChildItem -Path (Join-Path $root "src\crypto") -Filter "random_*.cpp" -ErrorAction SilentlyContinue
    if ($rngGlob) { $rngFiles += ($rngGlob | ForEach-Object { $_.FullName }) }
    $weak = Select-String -LiteralPath $rngFiles -Pattern '\brand\(|\bsrand\(|std::random_device|mt19937'
    if ($weak) {
        $weak | ForEach-Object { Write-Host ("    " + $_.Filename + ": " + $_.Line.Trim()) }
        Write-Error "weak RNG found in the CSPRNG path (doc:4010-4012 N6)"
        exit 1
    }

    Write-Host "  doc citation gate passed"
}

if ($LinuxBuild) {
    Write-Host "== linux build gate =="
    $gate = Join-Path $root "scripts\linux-build-gate.sh"
    if (-not (Test-Path $gate)) { Write-Error "missing $gate"; exit 1 }
    $wsl = Get-Command wsl -ErrorAction SilentlyContinue
    if (-not $wsl) {
        # A missing toolchain is NOT a pass: the gate exists to prove the Linux
        # build works, so an absent WSL means the proof was not obtained.
        Write-Error "wsl not found: cannot verify the Linux build (environment missing, treated as FAIL)"
        exit 1
    }
    # Convert the Windows path to the /mnt/<drive>/... form WSL understands.
    $drive = $root.Substring(0, 1).ToLowerInvariant()
    $rest = $root.Substring(2).Replace("\", "/")
    $gateWsl = "/mnt/$drive$rest/scripts/linux-build-gate.sh"
    # Capture the output so the gate can be checked positively, not just by
    # exit code (audit B0-07). A gate that exits 0 without printing its PASS
    # line has been neutered, and an exit-code-only check would not notice.
    # A blocking `& wsl ...` has no timeout: if WSL hangs (systemd user session
    # failure, a wedged 9p mount, a stuck build) this script waits forever and
    # the whole verification silently never finishes. The gate now runs two
    # builds (Debug + RelWithDebInfo), so its wall time grew from ~79s to ~129s
    # and the margin for "hangs vs slow" narrowed. Run it under an explicit
    # timeout and treat expiry as a FAIL, not a skip -- same rule as a missing
    # toolchain above (audit Y).
    $gateTimeoutSec = 900
    $gateOut = (& wsl -e timeout --signal=TERM --kill-after=30 $gateTimeoutSec bash $gateWsl 2>&1 | Out-String)
    $gateExit = $LASTEXITCODE
    Write-Host $gateOut
    if ($gateExit -eq 124) {
        Write-Error "linux build gate exceeded ${gateTimeoutSec}s (treated as FAIL; a hung WSL is not a pass)"
        exit 1
    }
    if ($gateExit -eq 137) {
        Write-Error "linux build gate had to be SIGKILLed after it outlived ${gateTimeoutSec}s + the 30s grace (treated as FAIL)"
        exit 1
    }
    if ($gateExit -ne 0) { Write-Error "linux build gate failed"; exit 1 }
    if ($gateOut -notmatch 'LINUX GATE PASS') {
        Write-Error "linux build gate exited 0 but never printed LINUX GATE PASS (gate is not doing its job)"
        exit 1
    }
    # Line-anchored, not substring (audit A20-6). A substring test would accept
    # "FAILED_COUNT=01" or a future "FAILED_COUNT=0 (tolerated 1 warning)", i.e.
    # exactly the class of weak-signal bug B0-07 was about.
    foreach ($needle in @('FAILED_COUNT=0', 'WINDOWS_H_COUNT=0', 'FACTORY_SYMBOL=present', 'REQUIRED_TESTS=present', 'P0_REGRESSION=executed', 'VIEW_BUDGETS=executed', 'UI_RATIO=executed')) {
        $anchored = '(?m)^' + [regex]::Escape($needle) + '\r?$'
        if ($gateOut -notmatch $anchored) {
            Write-Error "linux build gate output missing an exact '$needle' line"
            exit 1
        }
    }
    Write-Host "  linux build gate passed"
}

if ($PerfGate) {
    Write-Host "== perf gate (real server) =="
    $gui = Join-Path $buildDir "rtsc_gui.exe"
    if (-not (Test-Path $gui)) { Write-Error "rtsc_gui.exe not built"; exit 1 }
    $perf = Join-Path $root "scripts\perf-gate.ps1"
    if (-not (Test-Path $perf)) { Write-Error "missing $perf"; exit 1 }
    if (-not $env:RTSC_HOST -or -not $env:RTSC_USER -or -not $env:RTSC_PASS) {
        Write-Error "PerfGate requires RTSC_HOST / RTSC_USER / RTSC_PASS in the environment"
        exit 1
    }
    & $perf -GuiPath $gui
    if ($LASTEXITCODE -ne 0) { Write-Error "perf gate failed"; exit 1 }
}

exit 0
