#pragma once

// Shared entry point for every test executable.
//
// InstallCrashGuard() runs before any test so that a crash inside a test case
// produces a minidump plus a symbolized text report instead of a Windows Error
// Reporting dialog. The dialog is what used to hang automated runs: the process
// stayed alive waiting for a click, so the harness saw a timeout rather than a
// failure.
//
// RTSC_TEST_FILTER selects a subset of cases by substring match on the case
// name (for example RTSC_TEST_FILTER=gateway_tunnel_end_to_end runs exactly
// that case). It exists so a memory-hungry suite can be probed one case at a
// time under an external watchdog instead of loading every case at once. When
// the variable is unset or empty every registered case runs, exactly as before.

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "rtsc/util/crash_guard.h"
#include "test_framework.h"

namespace rtsc::test {

inline std::string filter_from_env() {
#if defined(_MSC_VER)
    // getenv() is flagged as unsafe by the MSVC CRT and the test targets build
    // with warnings as errors, so use the checked variant here.
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, "RTSC_TEST_FILTER") != 0 || buf == nullptr) {
        return std::string();
    }
    std::string value(buf);
    std::free(buf);
    return value;
#else
    const char* value = std::getenv("RTSC_TEST_FILTER");
    return value != nullptr ? std::string(value) : std::string();
#endif
}

inline int run_all(const char* app_name) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    ::rtsc::util::InstallCrashGuard(app_name);

    const std::string filter = filter_from_env();
    if (!filter.empty()) {
        std::printf("filter: %s\n", filter.c_str());
    }

    int failed_tests = 0;
    int ran_tests = 0;
    for (const auto& tc : registry()) {
        if (!filter.empty() &&
            std::string(tc.name).find(filter) == std::string::npos) {
            continue;
        }
        ++ran_tests;
        const int before = failure_count();
        std::printf("[ RUN  ] %s\n", tc.name);
        tc.fn();
        const bool ok = failure_count() == before;
        if (!ok) ++failed_tests;
        std::printf("[ %s ] %s\n", ok ? " OK " : "FAIL", tc.name);
    }
    std::printf("\n%d tests, %d checks, %d failing tests, %d failed checks\n",
                ran_tests, check_count(), failed_tests, failure_count());
    if (failure_count() != 0) {
        std::printf("crash dumps (if any): %s\n", ::rtsc::util::CrashDumpDirectory());
    }
    return failed_tests == 0 ? 0 : 1;
}

}  // namespace rtsc::test