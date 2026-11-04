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
echo "LIB_BYTES=$(stat -c %s "$LIB")"  # output only, not asserted

# The platform-neutral factory must exist even when no backend does.
if ! nm -C --defined-only "$LIB" 2>/dev/null | grep -q 'rtsc::tls::CreateTlsTransport'; then
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
if ! grep -qE "^\[  OK  \] ${P0_CASE}\$" "$SEC_LOG"; then
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
# PATH was reached; the drain that makes the path reachable is the CredSSP-phase
# loop in src/security/server_security_layer.cpp:194, and disabling it is what
# turns this case red. It does NOT prove the CHECK statement is still there.
# Deleting `CHECK(got_challenge)` while leaving the printf keeps the marker and
# the exit code at 0. Any "produced output" assertion has this limit, because
# CHECK only calls report_failure and does not change control flow
# (tests/test_framework.h:47-53). Detecting a deleted assertion needs review, not
# a gate. Do not claim otherwise here or in the commit message.
# Scoped to the CASE BLOCK, not the whole log. A whole-log grep accepts the same
# string printed by any other case: measured with a synthetic log where P0 prints
# nothing and `some_other_case` prints the marker -- the old check exited 0.
# NOTE on detecting the batch-67 apostrophe mistake statically: do not try.
# A guard was written and it was DEAD -- it scanned its own file for apostrophes
# inside awk programs while the scanner's own header line (`awk -v q="'"`) carried
# two apostrophes, so it never entered the program body and always reported clean.
# Measured: re-injecting the exact batch-67 mistake left the guard silent.
# bash -n is also not a semantic gate (audit Y2 built a case where `''` inside a
# regex deletes whitespace, bash -n rc=0, regex silently wrong). The semantic gate
# is selftest_marker_extractor below: every one of these mistakes turns a healthy
# log into a reject, which the self-test catches. Deleting a dead check beats
# keeping a green one.

p0_block_has_marker() {
    # Any case boundary resets the flag, including "[ FAIL ]": a failed case
    # never prints "[  OK  ]", so keying the reset on OK alone would leak the
    # block into whatever follows.
    awk -v want="${P0_CASE}" '
        # The tag whitelist is spelled out in both cases. A lowercase ok would
        # otherwise fail to close the block, and a marker printed after it was
        # accepted (measured). Do NOT widen this to any bracketed line: real logs
        # carry [rtsc-server] WARNING: ... and [GCC] static channels: ... INSIDE a
        # case block, so that truncates the block and rejects honest logs
        # (measured: bracket-inside-block accept -> reject).
        # NOTE: no apostrophes in this comment -- it is inside a single-quoted awk
        # program, and one would close the quote while bash -n still balanced.
        /^\[[[:space:]]+(RUN|OK|FAIL|[Oo][Kk]|[Ff][Aa][Ii][Ll]|[Rr][Uu][Nn])[[:space:]]+\]/ {
            name = $0
            tag = name
            sub(/^\[[[:space:]]+/, "", tag)
            sub(/[[:space:]]+\].*$/, "", tag)
            sub(/^\[[[:space:]]+[A-Za-z]+[[:space:]]+\][[:space:]]*/, "", name)
            sub(/[[:space:]]+$/, "", name)
            inb = (tolower(tag) == "run" && name == want) ? 1 : 0; next
        }
        inb && /drain: challenge surfaced after coalesced record/ { found = 1 }
        END { exit found ? 0 : 1 }' "$SEC_LOG"
}
# Self-test a case-block extractor before trusting it. Three shipped revisions of
# these extractors were broken while `bash -n` passed, and each failure mode was
# invisible to a weaker test:
#   1. regex had an extra space      -> nothing matched          (healthy REJECTED)
#   2. `awk -v case=`                -> gawk fatal on builtin    (healthy REJECTED)
#   3. only the "accept" direction measured -> `return 0` passed (fail-OPEN: the
#      marker gate is dead and the gate still prints PASS; measured on HEAD
#      0f4fcfa: ALWAYS_ACCEPT gave selftest=ACCEPT AND real_attack=ACCEPT)
# A block that never closes is a fourth hole with the same shape: the target
# case's own OK/FAIL line keeps `inb` set, so anything printed after it is
# attributed to that case. Measured before the fix: marker-after-OK and
# marker-after-FAIL were both accepted.
#
# So pin all four boundaries at once. Args: helper-name case-name marker logvar.
selftest_marker_extractor() {
    local fn="$1" case_name="$2" marker="$3" logvar="$4"
    local probe rc=0 saved
    # The helper writes the probe path through $logvar, so a name that the probe
    # cannot own silently disconnects the data path. Measured: logvar=rc writes the
    # helper's own return code and restore() puts the entry value back, so a
    # permanently broken extractor still returned 0 -- fail-OPEN. logvar=probe /
    # saved / fn / case_name similarly clobber helper locals. Reject anything that
    # is not a caller-owned plain variable before doing any work.
    case "$logvar" in
        ''|*[!A-Za-z0-9_]*|[0-9]*) echo "  logvar '$logvar' is not a valid variable name" >&2; return 1 ;;
    esac
    case "$logvar" in
        fn|case_name|marker|logvar|probe|rc|saved|reset|restore|expect_accept|expect_reject)
            echo "  logvar '$logvar' collides with a helper local; pass the caller's log variable" >&2
            return 1 ;;
    esac
    # One check for every way the target can fail to be a plain scalar:
    #   r flag  -> readonly, printf -v refuses (fail-closed, but the message used
    #             to blame the extractor)
    #   a / A   -> array. printf -v writes element [0] and leaves $logvar empty,
    #             so every probe runs against an empty path. Measured: the
    #             self-test still returned 0 on a HEALTHY extractor (vacuous),
    #             though a broken one was still caught, so this is a
    #             vacuous-pass rather than a false green -- reject it anyway,
    #             same standard as logvar=rc.
    local flags
    flags="$(declare -p "$logvar" 2>/dev/null | head -1 | cut -d" " -f2)"
    case "$flags" in
        *r*) echo "  logvar '$logvar' is readonly; the probe cannot be written" >&2; return 1 ;;
        *a*|*A*) echo "  logvar '$logvar' is an array; pass a plain string variable" >&2; return 1 ;;
    esac
    # The truncation probes below cut a proportion of the marker and strip its
    # first six characters. Below that size the cuts stop being informative, so
    # require enough length. Both call sites pass long literals; this guards a
    # future short one rather than a live path.
    if [ "${#marker}" -le 12 ]; then
        echo "  marker '$marker' is too short for the truncation probes (need more than 12 chars)" >&2
        return 1
    fi
    # Indirect read/write by NAME, not eval. `eval "$logvar=..."` executes the
    # name: passing `EVIL; echo INJECTED` ran the echo (measured). printf -v
    # rejects a non-identifier instead, which is the behaviour we want and
    # costs the same two lines. The call sites pass literals today, but a
    # parameterised helper must not carry a live injection surface.
    printf -v saved '%s' "${!logvar:-}"
    probe="$(mktemp)" || { echo "  cannot create probe file (TMPDIR unset or full?)" >&2; return 1; }
    reset() { printf -v "$logvar" '%s' "$probe" || { echo "  cannot write log var '$logvar'" >&2; return 1; }; }
    restore() { printf -v "$logvar" '%s' "$saved" || { echo "  cannot restore log var '$logvar'" >&2; return 1; }; }
    expect_accept() {
        reset || { rc=1; return 1; }
        "$fn" || { echo "  rejected a healthy log" >&2; rc=1; }
    }
    expect_reject() {
        reset || { rc=1; return 1; }
        if "$fn"; then echo "  accepted $1" >&2; rc=1; fi
    }
    printf '[ RUN  ] %s\n%s\n[  OK  ] %s\n' \
        "$case_name" "$marker" "$case_name" >"$probe"
    expect_accept
    printf '[ RUN  ] %s\n[  OK  ] %s\n[ RUN  ] some_other_case\n%s\n[  OK  ] some_other_case\n' \
        "$case_name" "$case_name" "$marker" >"$probe"
    expect_reject "a marker that another case printed (case scoping is gone)"
    printf '[ RUN  ] %s\n[  OK  ] %s\n%s\n[ RUN  ] some_other_case\n' \
        "$case_name" "$case_name" "$marker" >"$probe"
    expect_reject "a marker printed after the case's own OK line (block never closed)"
    printf '[ RUN  ] %s\n[ FAIL ] %s\n%s\n[ RUN  ] some_other_case\n' \
        "$case_name" "$case_name" "$marker" >"$probe"
    expect_reject "a marker printed after the case's own FAIL line (block never closed)"
    # A lowercase tag still has to close the block.
    printf '[ RUN  ] %s\n[ ok ] %s\n%s\n[ RUN  ] some_other_case\n' \
        "$case_name" "$case_name" "$marker" >"$probe"
    expect_reject "a marker printed after a lowercase close tag (block never closed)"
    # Honest logs carry bracketed non-harness lines INSIDE a case block; those must
    # not be treated as boundaries or the block gets truncated (false reject).
    printf '[ RUN  ] %s\n[rtsc-server] WARNING: x\n[GCC] static channels: 1\n%s\n[  OK  ] %s\n' \
        "$case_name" "$marker" "$case_name" >"$probe"
    expect_accept
    # The marker match must not be loose. Cut the TAIL (append a suffix instead and
    # the string still contains the whole marker, making the probe vacuous and the
    # baseline itself red). Cut a PROPORTION, not a fixed six characters: %??????
    # returns the input unchanged when it is shorter than six and collapses to ""
    # at exactly six, so a fixed count silently turns this probe into a no-op.
    printf '[ RUN  ] %s\n%s\n[  OK  ] %s\n' \
        "$case_name" "${marker:0:${#marker}*2/3}" "$case_name" >"$probe"
    expect_reject "a tail-truncated marker (the marker regex only matched its tail)"
    # Cutting the HEAD is a separate hole: a regex that only matches the tail of the
    # marker still passes the tail-truncation probe. Measured: /record/ stayed green
    # against the seven boundaries. Cutting the head also covers "only matches a
    # middle fragment", since that string is missing its head too.
    printf '[ RUN  ] %s\n%s\n[  OK  ] %s\n' \
        "$case_name" "${marker#??????}" "$case_name" >"$probe"
    expect_reject "a head-truncated marker (the marker regex only matched its tail)"
    # Case is a third independent axis, and it has two shapes that need separate
    # probes: fully case-insensitive matching (caught by the upper-case probe) and
    # per-character classes like [Dd]rain (NOT caught by it -- DRAIN does not match
    # [Dd]rain, only Drain does). The alternating-case probe catches the second
    # shape because its first letter is upper-case while the rest is not.
    printf '[ RUN  ] %s\n%s\n[  OK  ] %s\n' \
        "$case_name" "$(printf '%s' "$marker" | tr '[:lower:]' '[:upper:]')" "$case_name" >"$probe"
    expect_reject "an upper-cased marker (the marker regex ignored case)"
    printf '[ RUN  ] %s\n%s\n[  OK  ] %s\n' \
        "$case_name" "$(printf '%s' "$marker" | awk '{ out=""; for (i=1;i<=length($0);i++) { c=substr($0,i,1); out = out ((i%2)?toupper(c):tolower(c)) } print out }')" "$case_name" >"$probe"
    expect_reject "an alternating-case marker (the marker regex accepts some case variants)"
    # The case name must match EXACTLY, not as a prefix.
    printf '[ RUN  ] %s_extra\n%s\n[  OK  ] %s_extra\n' \
        "$case_name" "$marker" "$case_name" >"$probe"
    expect_reject "a marker printed by a case whose name merely starts with the wanted one"
    restore
    rm -f "$probe"
    unset -f reset restore expect_accept expect_reject
    return "$rc"
}
if ! selftest_marker_extractor p0_block_has_marker "${P0_CASE}" \
        'drain: challenge surfaced after coalesced record' SEC_LOG; then
    echo "LINUX GATE FAIL: p0_block_has_marker is itself broken (regex, awk variable name, case scoping, or block closure); this is a gate bug, not a build failure"
    exit 1
fi
if ! p0_block_has_marker; then
    echo "LINUX GATE FAIL: ${P0_CASE} case block did not print the drain marker (another case's marker does not count)"
    grep -E "tests?, .*checks?" "$SEC_LOG" | tail -2
    exit 1
fi
SEC_SUMMARY=$(grep -E "^[0-9]+ tests, [0-9]+ checks, " "$SEC_LOG" | tail -1)
SEC_TESTS=$(printf '%s' "$SEC_SUMMARY" | sed -E 's/^([0-9]+) tests,.*/\1/')
SEC_CHECKS=$(printf '%s' "$SEC_SUMMARY" | sed -E 's/^[0-9]+ tests, ([0-9]+) checks,.*/\1/')
if [ "${SEC_TESTS:-0}" -ne 9 ] || [ "${SEC_CHECKS:-0}" -lt 79 ]; then
    echo "LINUX GATE FAIL: ${P0_CASE} suite ran a different body than expected (tests=${SEC_TESTS:-?} checks=${SEC_CHECKS:-?}, want exactly 9 tests / >=79 checks; add/remove a case => update this gate)"
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
# Count the RESULT lines only. The retry line printed by the same loop is tagged
# `[bench-retry]`, not `[bench]`: when both carried the marker, one compiled-out
# case plus one retry kept the count at 7 and the gate passed (measured: a log
# with 6 result lines + 1 retry line exited 0). A count alone is also padable, so
# the real assertion is per-case identity below.
VIEW_BENCH_LINES=$(grep -c "\[bench\]" "$VIEW_LOG")
# Equality, not ">=": adding an eighth bench case must force someone to update
# this gate. With "-lt 7" an extra case passed silently (measured: 7 old lines +
# 1 new line -> exit 0), which violates the fail-closed rule the rest of this
# script follows.
if [ "${VIEW_BENCH_LINES:-0}" -ne 7 ]; then
    echo "LINUX GATE FAIL: view bench result lines=${VIEW_BENCH_LINES:-0}, want exactly 7 (add/remove a case => update this gate and VIEW_MIN_CHECKS)"
    exit 1
fi
# Per-case identity: every bench case must print its OWN result line. This is the
# same reasoning as REQUIRED_TESTS -- a count can be padded by a retry or an extra
# case, a named row cannot. The patterns require a digit run immediately after the
# label, so `1:1` does not match the `1:1 letterbox` row.
VIEW_MISSING=""
for pat in \
    '\[bench\] 1:1 +[0-9]+x' \
    '\[bench\] 1:1 letterbox +[0-9]+x' \
    '\[bench\] 2x +[0-9]+x' \
    '\[bench\] 0\.8x +[0-9]+x' \
    '\[bench\] 0\.5x 4K +[0-9]+x' \
    '\[bench\] 1\.33x +[0-9]+x' \
    '\[bench\] 0\.4x 4K +[0-9]+x'; do
    if ! grep -Eq "$pat" "$VIEW_LOG"; then
        VIEW_MISSING="$VIEW_MISSING ${pat}"
    fi
done
if [ -n "$VIEW_MISSING" ]; then
    echo "LINUX GATE FAIL: view bench case(s) produced no result line:$VIEW_MISSING"
    exit 1
fi
# The identity checks above prove the label was printed; they do NOT prove the
# resampler ran. Measured attack: replacing measure() with `return 0.01;` kept
# all 7 labels, 7 result lines and 7348 checks, and the gate passed -- the gate
# never looked at what the line claimed. The test now prints the real number of
# ScaleSurface calls per case; require the lower bound (10 reps x iters).
VIEW_CALLS=$(grep -c "^  \[bench-calls\] " "$VIEW_LOG")
if [ "${VIEW_CALLS:-0}" -ne 7 ]; then
    echo "LINUX GATE FAIL: view bench call counters=${VIEW_CALLS:-0}, want exactly 7"
    exit 1
fi
# Fail closed on a malformed line too. `sed` leaves a non-matching line untouched,
# and awk then saw its fields as ("[bench-calls]", <label>): with the current
# labels that happened to trip the check, but a label starting with 0 or a
# non-digit would have slipped through. Require both extracted fields to be
# numeral before comparing.
if grep "^  \[bench-calls\] " "$VIEW_LOG" |
       sed -E 's/.* calls=([0-9]+) want=([0-9]+).*/\1 \2/' |
       awk 'NF != 2 { bad = 1; next }
            $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ { bad = 1; next }
            $1 + 0 < $2 + 0 { bad = 1 }
            END { exit bad ? 0 : 1 }'; then
    echo "LINUX GATE FAIL: a view bench case made fewer ScaleSurface calls than its sample requires:"
    grep "^  \[bench-calls\] " "$VIEW_LOG"
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
# Same case-block scoping as the P0 marker above: the measurement line only counts
# if it was printed by the ratio case itself. A whole-log grep accepts the string
# from any case, so a body that stopped running while another case echoed the
# same text would still pass.
# Case name for the ratio body; also used by the self-test below.
UI_CASE="rgba_to_bgra_present_faster_than_the_old_per_pixel_loop"

ui_block_has_marker() {
    awk -v want="${UI_CASE}" '
        /^\[[[:space:]]+(RUN|OK|FAIL|[Oo][Kk]|[Ff][Aa][Ii][Ll]|[Rr][Uu][Nn])[[:space:]]+\]/ {
            name = $0
            tag = name
            sub(/^\[[[:space:]]+/, "", tag)
            sub(/[[:space:]]+\].*$/, "", tag)
            sub(/^\[[[:space:]]+[A-Za-z]+[[:space:]]+\][[:space:]]*/, "", name)
            sub(/[[:space:]]+$/, "", name)
            inb = (tolower(tag) == "run" && name == want) ? 1 : 0; next
        }
        inb && /rgba->bgra 1280x1024:/ { found = 1 }
        END { exit found ? 0 : 1 }' "$UI_LOG"
}
# Same four-boundary self-test as the P0 extractor, via the shared helper.
if ! selftest_marker_extractor ui_block_has_marker "${UI_CASE}" \
        'rgba->bgra 1280x1024:' UI_LOG; then
    echo "LINUX GATE FAIL: ui_block_has_marker is itself broken (regex, awk variable name, case scoping, or block closure); this is a gate bug, not a build failure"
    exit 1
fi
if ! ui_block_has_marker; then
    echo "LINUX GATE FAIL: ui ratio case block did not print its 'rgba->bgra 1280x1024:' line (another case's line does not count)"
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
