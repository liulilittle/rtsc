cmake_minimum_required(VERSION 3.20)

# Behavioural checks for the rtsc_server_host command line.
#
# The host binary is not linked into any test executable: it owns its own
# main(), so a ctest can only observe it as a process. These cases assert its
# exit status and the text it prints, which is the only thing an operator ever
# sees. The two refusal cases guard a security contract -- desktop input
# injection may not be combined silently with a credential policy that
# verifies nothing -- and before this file existed nothing at all exercised it.
#
# Invoked as:
#   cmake -DHOST=<path to rtsc_server_host> -DCASE=<case> -P host_cli_check.cmake

if(NOT DEFINED HOST OR NOT DEFINED CASE)
    message(FATAL_ERROR "host_cli_check.cmake requires -DHOST= and -DCASE=")
endif()
if(NOT EXISTS "${HOST}")
    message(FATAL_ERROR "host binary not found: ${HOST}")
endif()

set(must_have "")
set(must_not_have "")
set(exactly_once "")

if(CASE STREQUAL "help")
    # --help must be free of side effects: it prints usage and exits 0 even
    # though the host would otherwise refuse to run without a port.
    set(args --help)
    set(expect_exit 0)
    list(APPEND must_have "--allow-input")
    list(APPEND must_have "--allow-input-unverified")
    list(APPEND must_not_have "refusing to start")
elseif(CASE STREQUAL "refuse_no_enhanced")
    # --no-enhanced performs no password check at all.
    set(args --allow-input --no-enhanced)
    set(expect_exit 2)
    list(APPEND must_have "refusing to start")
    list(APPEND must_have "conflicting option --no-enhanced")
    list(APPEND must_have "--allow-input-unverified")
elseif(CASE STREQUAL "refuse_any_credentials")
    # --allow-any-credentials accepts every account.
    set(args --allow-input --allow-any-credentials)
    set(expect_exit 2)
    list(APPEND must_have "refusing to start")
    list(APPEND must_have "conflicting option --allow-any-credentials")
    list(APPEND must_not_have "conflicting option --no-enhanced")
elseif(CASE STREQUAL "acknowledged_start")
    # The escape hatch must actually let the host start: it has to reach the
    # listening state with input enabled and then exit on its own, and it must
    # not print the refusal. Port 0 keeps this from colliding with a real run
    # and --seconds bounds the run so the case needs no external kill.
    set(args --allow-input --allow-input-unverified --port 0 --seconds 1)
    set(expect_exit 0)
    list(APPEND must_have "listening on")
    list(APPEND must_have "input=on")
    list(APPEND must_have "WARNING: desktop input injection is ENABLED")
    list(APPEND must_not_have "refusing to start")
elseif(CASE STREQUAL "stats_line")
    # The shutdown line is the only place an operator ever sees the cumulative
    # injection counters, and it is assembled by main() calling
    # FormatInputStats(). Asserting the function in isolation says nothing
    # about that call site: deleting the call left every test green (this was
    # the batch 24 residual gap R7). Running the real host is the only way to
    # exercise it, and --seconds makes the run bounded.
    set(args --allow-input --allow-input-unverified --port 0 --seconds 1)
    set(expect_exit 0)
    list(APPEND must_have "input stats (final): input_injected=")
    list(APPEND must_have "input_dropped_queue=")
    list(APPEND must_have "input_rate_limited=")
    list(APPEND must_have "input_send_failures=")
    list(APPEND must_have "input_release_failures=")
    list(APPEND must_have "input_worker_failures=")
    list(APPEND must_have "input_dropped_unmapped=")
elseif(CASE STREQUAL "periodic_stats_line")
    # The periodic sampler prints a baseline line on its first tick and then
    # only on change. Running longer than the 5 s sampling interval with no
    # peer therefore yields exactly one `periodic` line and nothing more, which
    # is what makes the call site itself observable: deleting the call, or
    # returning early from the lambda, removes that line (batch 27 closed the
    # batch 26 F5 residual this way, without adding a test-only backend to the
    # production host).
    # The window must cover AT LEAST TWO sampling ticks (kInputStatsInterval is
    # 5 s): with --seconds 7 only one tick fires, so a host that printed on
    # every tick was indistinguishable from one that printed the baseline and
    # then stayed quiet -- the flood assertion below passed either way. 12 s
    # guarantees two ticks at 5 s and 10 s.
    set(args --allow-input --allow-input-unverified --port 0 --seconds 12)
    set(expect_exit 0)
    list(APPEND must_have "input stats (final): input_injected=")
    # Exactly one periodic line: the baseline prints once, and the remaining
    # samples are unchanged so they must print nothing. "at least one" alone
    # would pass a host that logs every tick (the flood the sampler exists to
    # prevent), and so would a window shorter than the sampling interval.
    list(APPEND exactly_once "input stats (periodic): input_injected=")
else()
    message(FATAL_ERROR "unknown CASE '${CASE}'")
endif()

execute_process(
    COMMAND "${HOST}" ${args}
    RESULT_VARIABLE rc
    OUTPUT_VARIABLE out
    ERROR_VARIABLE err
    TIMEOUT 25)

set(text "${out}${err}")

if(NOT rc STREQUAL "${expect_exit}")
    message(FATAL_ERROR
            "CASE ${CASE}: exit status '${rc}', expected '${expect_exit}'. "
            "Output:\n${text}")
endif()

foreach(need IN LISTS must_have)
    string(FIND "${text}" "${need}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
                "CASE ${CASE}: output is missing '${need}'. Output:\n${text}")
    endif()
endforeach()

foreach(once IN LISTS exactly_once)
    # Count plain substring occurrences. REGEX MATCHALL cannot be used here:
    # the needle contains '(' and ')' (and the host wraps long lines), so a
    # regex would either mis-match or fail to match at all.
    set(remaining "${text}")
    set(hit_count 0)
    while(TRUE)
        string(FIND "${remaining}" "${once}" at)
        if(at EQUAL -1)
            break()
        endif()
        math(EXPR hit_count "${hit_count} + 1")
        math(EXPR next "${at} + 1")
        string(SUBSTRING "${remaining}" ${next} -1 remaining)
    endwhile()
    if(NOT hit_count EQUAL 1)
        message(FATAL_ERROR
                "CASE ${CASE}: expected exactly one '${once}', found "
                "${hit_count}. Output:\n${text}")
    endif()
endforeach()

foreach(bad IN LISTS must_not_have)
    string(FIND "${text}" "${bad}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
                "CASE ${CASE}: output must not contain '${bad}'. "
                "Output:\n${text}")
    endif()
endforeach()

message(STATUS "CASE ${CASE}: OK (rc='${rc}')")
