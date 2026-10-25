#pragma once

// Shared entry point for every test executable.
//
// InstallCrashGuard() runs before any test so that a crash inside a test case
// produces a minidump plus a symbolized text report instead of a Windows Error
// Reporting dialog. The dialog is what used to hang automated runs: the process
// stayed alive waiting for a click, so the harness saw a timeout rather than a
// failure.

#include <cstdio>

#include "rtsc/util/crash_guard.h"
#include "test_framework.h"

namespace rtsc::test {

inline int run_all(const char* app_name) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    ::rtsc::util::InstallCrashGuard(app_name);

    int failed_tests = 0;
    for (const auto& tc : registry()) {
        const int before = failure_count();
        std::printf("[ RUN  ] %s\n", tc.name);
        tc.fn();
        const bool ok = failure_count() == before;
        if (!ok) ++failed_tests;
        std::printf("[ %s ] %s\n", ok ? " OK " : "FAIL", tc.name);
    }
    std::printf("\n%d tests, %d checks, %d failing tests, %d failed checks\n",
                static_cast<int>(registry().size()), check_count(), failed_tests,
                failure_count());
    if (failure_count() != 0) {
        std::printf("crash dumps (if any): %s\n", ::rtsc::util::CrashDumpDirectory());
    }
    return failed_tests == 0 ? 0 : 1;
}

}  // namespace rtsc::test
