// Deliberately crashes so the crash guard can be verified end to end.
//
// Not part of ctest: it must exit non-zero and leave a dump behind, which is a
// failure by ctest's definition. `verify.ps1 -CrashCheck` runs it and asserts
// that a .dmp and a .txt appeared and that no dialog blocked the run.

#include <cstdio>
#include <cstring>
#include <exception>
#include <string>

#include "rtsc/util/crash_guard.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {

[[noreturn]] void CrashNullWrite() {
    volatile int* p = nullptr;
    *p = 1;
    std::abort();
}

[[noreturn]] void CrashAbort() { std::abort(); }

[[noreturn]] void CrashTerminate() { std::terminate(); }

}  // namespace

int main(int argc, char** argv) {
    rtsc::util::InstallCrashGuard("rtsc_crashtest");
    const char* mode = (argc >= 2) ? argv[1] : "null";
    std::printf("[crash] dir=%s mode=%s\n", rtsc::util::CrashDumpDirectory(), mode);
    std::fflush(stdout);

    if (std::strcmp(mode, "null") == 0) CrashNullWrite();
    if (std::strcmp(mode, "abort") == 0) CrashAbort();
    if (std::strcmp(mode, "terminate") == 0) CrashTerminate();

    std::printf("unknown mode: %s\n", mode);
    return 2;
}
