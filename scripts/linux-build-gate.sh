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
    rm -rf -- "$BUILD_DIR"
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
grep -q "OK .* ${P0_CASE}\$" "$SEC_LOG" || {
    echo "LINUX GATE FAIL: ${P0_CASE} did not execute (OpenSSL backend compiled out?)"
    grep -E "tests?, .*checks?" "$SEC_LOG" | tail -2
    exit 1
}
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

echo "LINUX GATE PASS"
exit 0
