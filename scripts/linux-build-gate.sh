#!/bin/bash
# Linux build gate for RTSC.
#
# Why this file exists (audit B0-02): the batch-0 Linux green certificate was
# produced by an ad-hoc script that was deleted afterwards, so the result could
# not be replayed. This script is the permanent, re-runnable form.
#
# Contract (aligned with verify.ps1's G9 rule: a missing environment must FAIL,
# not silently skip):
#   * exit 0  -> Linux build succeeded, zero warnings, ctest green
#   * exit 1  -> a real defect: compile error, -Werror, failing test
#   * exit 2  -> environment missing (no cmake / no ninja / no compiler)
#
# It also asserts two things that the exit code alone cannot prove:
#   * FAILED_COUNT == 0   (ninja can report success while emitting warnings)
#   * WINDOWS_H_COUNT == 0 (the exact S21 regression signature)
#
# 9p convention: the build tree MUST live on a native FS (ext4/overlay), never
# on a 9p mount such as /mnt/f. The source stays read-only on /mnt/f (9p read
# jitter is small); only the build tree does dense mkdir/rm and is therefore
# moved out of 9p. 9p has transient consistency hiccups under concurrent
# mkdir/rm, which can surface as `ninja: mkdir ... No such file or directory`
# (rc=1) even with zero source changes -- re-running then passes.
# Diagnostic rule: if you see `mkdir ... No such file` / `BUILD_EXIT=1` while
# `FAILED_COUNT=0`, treat it as suspected 9p jitter, re-run once to distinguish
# it from a real product defect -- do NOT report it as a product bug.
#
# Usage: bash scripts/linux-build-gate.sh [build-dir]

set -u

# Explicit first arg wins; the caller is responsible for making an explicitly
# passed build-dir unique. The default below is PID-suffixed (.$$) and lives on
# a native FS (TMPDIR, /tmp on WSL ext4/overlay), NOT on the /mnt/f 9p mount.
BUILD_DIR="${1:-${TMPDIR:-/tmp}/rtsc-gate-build.$$}"
SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Bound log growth: keep the newest LOG_KEEP PID-suffixed log dirs (including
# this run). The legacy "linux-gate-logs" (no PID suffix) is historical
# evidence and is never removed.
LOG_KEEP=5

fail_env() {
    echo "LINUX GATE ENV: $1" >&2
    exit 2
}

command -v cmake >/dev/null 2>&1 || fail_env "cmake not found"
command -v ninja >/dev/null 2>&1 || fail_env "ninja not found"
command -v c++   >/dev/null 2>&1 || fail_env "c++ not found"

cd "$SRC_ROOT" || fail_env "cannot cd to $SRC_ROOT"

LOG_PREFIX="linux-gate-logs"
LOG_DIR="$PWD/.tmp/$LOG_PREFIX.$$"
mkdir -p "$LOG_DIR"

# Delete all but the newest LOG_KEEP-1 *other* PID-suffixed log dirs; this run's
# own dir and the legacy (suffix-less) dir are always preserved.
rotate_logs() {
    local parent prefix d suf i=0
    parent="$(dirname "$LOG_DIR")"
    prefix="$LOG_PREFIX"
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        [ -d "$d" ] || continue
        [ "$d" = "$LOG_DIR" ] && continue
        suf="${d##*.}"
        case "$suf" in *[!0-9]*) continue ;; esac
        i=$((i + 1))
        [ "$i" -gt "$((LOG_KEEP - 1))" ] && rm -rf -- "$d"
    done < <(ls -1dt -- "$parent/$prefix".* 2>/dev/null)
}

# The build tree is re-creatable; remove it on every exit (success or failure).
# Failure evidence lives in the gate logs, not in the build tree, so removing
# the tree never destroys the evidence. Logs are evidence and are never
# removed wholesale, only rotated above.
cleanup() {
    rotate_logs
    rm -rf -- "$BUILD_DIR" "${BUILD_DIR}-rel"
}
trap cleanup EXIT
CFG_LOG="$LOG_DIR/configure.log"
BUILD_LOG="$LOG_DIR/build.log"
TEST_LOG="$LOG_DIR/ctest.log"

rm -rf "$BUILD_DIR"

# RTSC_TLS_OPENSSL is OFF by default (design-a D5: a REQUIRED find_package
# would break configure on hosts without OpenSSL). But this gate exists to
# prove the Linux build, and without the flag the OpenSSL TLS backend is never
# compiled and the P0 coalesced-handshake regression test is guarded out -- the
# gate would certify a configuration nobody ships. Enable it explicitly; the
# environment contract above already makes a missing toolchain a hard FAIL.
cmake -S . -B "$BUILD_DIR" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DRTSC_TLS_OPENSSL=ON >"$CFG_LOG" 2>&1
CFG_EXIT=$?
echo "CONFIGURE_EXIT=$CFG_EXIT"
if [ "$CFG_EXIT" -ne 0 ]; then
    echo "--- configure log tail ---"
    tail -40 "$CFG_LOG"
    exit 1
fi

cmake --build "$BUILD_DIR" >"$BUILD_LOG" 2>&1
BUILD_EXIT=$?
echo "BUILD_EXIT=$BUILD_EXIT"

FAILED_COUNT=$(grep -cE '^FAILED:' "$BUILD_LOG")
WINDOWS_H_COUNT=$(grep -c 'windows\.h' "$BUILD_LOG")
echo "FAILED_COUNT=$FAILED_COUNT"
echo "WINDOWS_H_COUNT=$WINDOWS_H_COUNT"

if [ "$BUILD_EXIT" -ne 0 ]; then
    echo "--- build log tail ---"
    tail -60 "$BUILD_LOG"
fi

if [ "$FAILED_COUNT" -ne 0 ] || [ "$WINDOWS_H_COUNT" -ne 0 ]; then
    echo "LINUX GATE FAIL: FAILED=$FAILED_COUNT WINDOWS_H=$WINDOWS_H_COUNT"
    exit 1
fi
if [ "$BUILD_EXIT" -ne 0 ]; then
    echo "LINUX GATE FAIL: BUILD_EXIT=$BUILD_EXIT"
    exit 1
fi

LIB=$(find "$BUILD_DIR" -name 'librtsc_tls.a' -print -quit)
if [ -z "$LIB" ]; then
    echo "LINUX GATE FAIL: librtsc_tls.a not produced"
    exit 1
fi
echo "LIB_BYTES=$(stat -c %s "$LIB")"

# The platform-neutral factory must exist even when no backend does.
if ! nm -C "$LIB" 2>/dev/null | grep -q 'rtsc::tls::CreateTlsTransport'; then
    echo "LINUX GATE FAIL: CreateTlsTransport missing from librtsc_tls.a"
    exit 1
fi
echo "FACTORY_SYMBOL=present"


# The exit code alone cannot prove *which* tests ran: a guarded-out test still lets
# ctest report 100% success. That is exactly how the OpenSSL P0 regression went
# missing (Linux ran 7/45 instead of 8/67 while the gate stayed green), so assert
# the identity of the tests, not only their aggregate result.
LIST_LOG="$LOG_DIR/ctest-list.log"
(cd "$BUILD_DIR" && ctest -N) >"$LIST_LOG" 2>&1
echo "CTEST_LIST_EXIT=$?"

REQUIRED_TESTS="tls_openssl server_security desktop_input host_cli_periodic_stats_line"
MISSING_TESTS=""
for required in $REQUIRED_TESTS; do
    grep -qE "^ *Test +#[0-9]+: ${required}\$" "$LIST_LOG" || MISSING_TESTS="$MISSING_TESTS $required"
done
if [ -n "$MISSING_TESTS" ]; then
    echo "LINUX GATE FAIL: required tests missing:$MISSING_TESTS"
    exit 1
fi
echo "REQUIRED_TESTS=present"

# tls_openssl existing is not enough: the P0 regression lives inside
# server_security under #if defined(RTSC_TLS_OPENSSL). Run that binary directly
# so a silently-compiled-out case cannot pass as a green suite.
SEC_BIN=$(find "$BUILD_DIR" -name "rtsc_server_security_tests*" -type f -print -quit)
if [ -z "$SEC_BIN" ]; then
    echo "LINUX GATE FAIL: rtsc_server_security_tests not produced"
    exit 1
fi
P0_CASE=tls_server_regression_coalesced_first_record_no_stall
SEC_LOG="$LOG_DIR/server_security.log"
"$SEC_BIN" >"$SEC_LOG" 2>&1
# Printf'ing "skipped: ..." and returning from the case body is still reported as
# "[  OK  ] <name>" by tests/test_main.h, so an OK line alone does not prove the
# body ran -- a TLS-less or guard-weakened build satisfies it (audit X, D1: a
# body rewritten to `if (true) { skipped; return; }` still produced
# P0_REGRESSION=executed and LINUX GATE PASS before this check existed).
# Require all three: the case ran, nothing skipped, and at least the checks the
# real body produces.
if ! grep -q "OK .* ${P0_CASE}\$" "$SEC_LOG"; then
    echo "LINUX GATE FAIL: ${P0_CASE} did not execute (OpenSSL backend compiled out?)"
    grep -E "tests?, .*checks?" "$SEC_LOG" | tail -2
    exit 1
fi
# Scoped to this one suite on purpose: the check count is a lower bound, not an
# equality, so adding assertions to this file does not break the gate. Other
# suites are known to be unstable here (rtsc_server_tests oscillates 655-657
# because two checks run conditionally, audit X), so do NOT copy this pattern.
if grep -q "skipped:" "$SEC_LOG"; then
    echo "LINUX GATE FAIL: ${P0_CASE} suite self-skipped; an OK line does not prove the body ran"
    grep -n "skipped:" "$SEC_LOG" | tail -5
    exit 1
fi
# A check count cannot prove this body ran (swapping the real CHECKs for
# `CHECK(true)` keeps the total at 67 while the drain regression goes untested --
# measured). Require the marker the success path prints.
#
# COVERAGE BOUNDARY (audit X, measured twice): this marker proves the success
# PATH was reached; it does NOT prove the CHECK statement is still there.
# Deleting `CHECK(got_challenge)` while leaving the printf keeps the marker and
# the exit code at 0. Any "produced output" assertion has this limit, because
# CHECK only calls report_failure and does not change control flow
# (tests/test_framework.h:47-53). Detecting a deleted assertion needs review, not
# a gate. Do not claim otherwise here or in the commit message.
if ! grep -q "drain: challenge surfaced after coalesced record" "$SEC_LOG"; then
    echo "LINUX GATE FAIL: ${P0_CASE} body did not reach its success path (drain marker missing)"
    grep -E "tests?, .*checks?" "$SEC_LOG" | tail -2
    exit 1
fi
SEC_SUMMARY=$(grep -E "^[0-9]+ tests, [0-9]+ checks, " "$SEC_LOG" | tail -1)
SEC_TESTS=$(printf '%s' "$SEC_SUMMARY" | sed -E 's/^([0-9]+) tests,.*/\1/')
SEC_CHECKS=$(printf '%s' "$SEC_SUMMARY" | sed -E 's/^[0-9]+ tests, ([0-9]+) checks,.*/\1/')
if [ "${SEC_TESTS:-0}" -lt 8 ] || [ "${SEC_CHECKS:-0}" -lt 67 ]; then
    echo "LINUX GATE FAIL: ${P0_CASE} suite ran less than the full body (tests=${SEC_TESTS:-?} checks=${SEC_CHECKS:-?}, want >=8 tests / >=67 checks)"
    printf '%s\n' "$SEC_SUMMARY"
    exit 1
fi
echo "P0_REGRESSION=executed"
(cd "$BUILD_DIR" && ctest --output-on-failure >"$TEST_LOG" 2>&1)
CTEST_EXIT=$?
echo "CTEST_EXIT=$CTEST_EXIT"
grep -E 'tests passed|tests failed' "$TEST_LOG" | tail -2

if [ "$CTEST_EXIT" -ne 0 ]; then
    echo "--- ctest log tail ---"
    tail -40 "$TEST_LOG"
    echo "LINUX GATE FAIL: ctest"
    exit 1
fi

# Debug-only coverage hides optimized-build-only assertions. tests/test_view.cpp
# wraps its timing budgets in `#if defined(NDEBUG)` (batch 33), so the Debug run
# above never evaluates them -- the algorithm budget was deleted from the only
# automated gate rather than made build-aware (audit X D3 / Y P1). Build the same
# tree once more with optimization so those checks actually execute. Only the
# view suite is run: the rest of the tree was already exercised in Debug, and the
# Release build's job here is to prove the budget assertions are live.
REL_BUILD_DIR="${BUILD_DIR}-rel"
REL_CFG_LOG="$LOG_DIR/configure-release.log"
REL_BUILD_LOG="$LOG_DIR/build-release.log"
REL_TEST_LOG="$LOG_DIR/ctest-release-view.log"
echo "RELEASE_BUILD_DIR=$REL_BUILD_DIR"

if ! cmake -S . -B "$REL_BUILD_DIR" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DRTSC_TLS_OPENSSL=ON >"$REL_CFG_LOG" 2>&1; then
    echo "--- release configure log tail ---"
    tail -40 "$REL_CFG_LOG"
    echo "LINUX GATE FAIL: release configure"
    exit 1
fi
if ! cmake --build "$REL_BUILD_DIR" --target rtsc_view_tests rtsc_ui_tests >"$REL_BUILD_LOG" 2>&1; then
    echo "--- release build log tail ---"
    tail -60 "$REL_BUILD_LOG"
    echo "LINUX GATE FAIL: release build"
    exit 1
fi
VIEW_LOG="$LOG_DIR/view-release.log"
# Seven bench cases each contribute exactly one CHECK under NDEBUG. Debug
# evaluates 7341 checks, optimized evaluates 7348; the delta IS the proof that
# the budget bodies ran. A lower bound, so adding assertions to test_view.cpp
# does not break the gate. If test_view.cpp gains or loses a bench case this
# number must be re-derived from the two runs.
VIEW_MIN_CHECKS=7348
"$REL_BUILD_DIR/rtsc_view_tests" >"$VIEW_LOG" 2>&1
VIEW_EXIT=$?
echo "VIEW_RELEASE_EXIT=$VIEW_EXIT"
if [ "$VIEW_EXIT" -ne 0 ]; then
    tail -40 "$VIEW_LOG"
    echo "LINUX GATE FAIL: view budget under optimization"
    exit 1
fi
# "No string called `skipped: timing budgets`" is a proxy for "the budget body ran",
# and it is exactly the proxy that failed for D1 above: renaming the message,
# an early return, or wrapping the block in `#if 0` all leave the string absent
# while the assertions never execute (audit X, V8: a ninja-ed `#if 0` still
# produced VIEW_BUDGETS=executed + LINUX GATE PASS). Assert the observable that
# only the real bodies produce: the optimized run evaluates 7 more checks than
# the Debug run (7341 -> 7348), one per bench case. Printing that number is not
# enough -- it has to be asserted.
if grep -q "skipped: timing budgets" "$VIEW_LOG"; then
    echo "LINUX GATE FAIL: view budgets still skipped in an optimized build"
    exit 1
fi
# A checks count is NOT proof the bodies ran: it counts CHECK executions, so an
# unrelated CHECK added elsewhere in the file keeps the total at or above the
# bound while the budget bodies are compiled out (audit X measured this: `#if 0`
# on the bench loop plus 7 padded CHECKs still reported 7348 and passed). Assert
# the line each bench iteration prints instead -- it exists only if the body ran.
VIEW_BENCH_LINES=$(grep -c "\[bench\]" "$VIEW_LOG")
if [ "${VIEW_BENCH_LINES:-0}" -lt 7 ]; then
    echo "LINUX GATE FAIL: view budget bodies did not run (bench lines=${VIEW_BENCH_LINES:-0}, want 7; the count comes from the printf inside the loop)"
    exit 1
fi
VIEW_SUMMARY=$(grep -E "^[0-9]+ tests, [0-9]+ checks, " "$VIEW_LOG" | tail -1)
VIEW_CHECKS=$(printf '%s' "$VIEW_SUMMARY" | sed -E 's/^[0-9]+ tests, ([0-9]+) checks,.*/\1/')
if [ "${VIEW_CHECKS:-0}" -lt "$VIEW_MIN_CHECKS" ]; then
    echo "LINUX GATE FAIL: view suite ran fewer checks than expected (checks=${VIEW_CHECKS:-?}, want >=${VIEW_MIN_CHECKS})"
    printf '%s\n' "$VIEW_SUMMARY"
    exit 1
fi
printf '%s\n' "$VIEW_SUMMARY"
echo "VIEW_BUDGETS=executed"

# Second optimized-only assertion: tests/test_ui.cpp compares the vectorised
# RgbaToBgra against a scalar reference loop by RATIO (0.60). In a -Od build that
# ratio is ~0.78 deterministically (three runs measured), so the case cannot pass
# unoptimized -- it was failing the whole Debug build that verify.ps1 uses as its
# default. Same treatment as the view budgets: assert it where it is meaningful,
# and prove the body ran (2 more checks than the Debug run) instead of trusting
# an exit code.
UI_LOG="$LOG_DIR/ui-release.log"
# Linux values measured on this tree: RelWithDebInfo 20 tests / 86 checks,
# Debug 20 tests / 84 checks -- the delta of 2 is exactly the two timing CHECKs
# in rgba_to_bgra_present_faster_than_the_old_per_pixel_loop. (Windows reports
# 50 tests / 265 checks because the Win32-only cases in this file are compiled
# in there; do not reuse that number here.) Lower bound, so adding assertions to
# test_ui.cpp does not break the gate.
UI_MIN_CHECKS=86
"$REL_BUILD_DIR/rtsc_ui_tests" >"$UI_LOG" 2>&1
UI_EXIT=$?
echo "UI_RELEASE_EXIT=$UI_EXIT"
if [ "$UI_EXIT" -ne 0 ]; then
    tail -40 "$UI_LOG"
    echo "LINUX GATE FAIL: ui present-path ratio under optimization"
    exit 1
fi
if grep -q "skipped: relative timing" "$UI_LOG"; then
    echo "LINUX GATE FAIL: ui ratio still skipped in an optimized build"
    exit 1
fi
# Same reasoning as the view block above: assert the measurement line the ratio
# body prints, not a checks total that unrelated CHECKs can top up.
if ! grep -q "rgba->bgra 1280x1024:" "$UI_LOG"; then
    echo "LINUX GATE FAIL: ui ratio body did not run (its 'rgba->bgra 1280x1024:' measurement line is missing)"
    exit 1
fi
UI_SUMMARY=$(grep -E "^[0-9]+ tests, [0-9]+ checks, " "$UI_LOG" | tail -1)
UI_CHECKS=$(printf '%s' "$UI_SUMMARY" | sed -E 's/^[0-9]+ tests, ([0-9]+) checks,.*/\1/')
if [ "${UI_CHECKS:-0}" -lt "$UI_MIN_CHECKS" ]; then
    echo "LINUX GATE FAIL: ui suite ran fewer checks than expected (checks=${UI_CHECKS:-?}, want >=${UI_MIN_CHECKS})"
    printf '%s\n' "$UI_SUMMARY"
    exit 1
fi
printf '%s\n' "$UI_SUMMARY"
echo "UI_RATIO=executed"
rm -rf -- "$REL_BUILD_DIR"

echo "LINUX GATE PASS"
exit 0
