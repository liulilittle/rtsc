#include "rtsc/util/crash_guard.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <dbghelp.h>
#include <signal.h>
#include <crtdbg.h>

#pragma comment(lib, "dbghelp.lib")

namespace rtsc::util {
namespace {

constexpr size_t kMaxPath = 512;
constexpr size_t kMaxFrames = 48;

char g_app_name[64] = "rtsc";
char g_dump_dir[kMaxPath] = {0};
bool g_installed = false;
LONG g_dumping = 0;  // re-entrancy guard

void CopyAscii(char* dst, size_t cap, const char* src) {
    if (cap == 0) return;
    size_t i = 0;
    for (; src[i] != '\0' && i + 1 < cap; ++i) dst[i] = src[i];
    dst[i] = '\0';
}

void ResolveDumpDirectory() {
    const DWORD n = GetEnvironmentVariableA("RTSC_CRASH_DIR", g_dump_dir,
                                            static_cast<DWORD>(kMaxPath));
    if (n > 0 && n < kMaxPath) {
        CreateDirectoryA(g_dump_dir, nullptr);
        return;
    }

    char exe[kMaxPath] = {0};
    const DWORD len = GetModuleFileNameA(nullptr, exe, static_cast<DWORD>(kMaxPath));
    if (len == 0 || len >= kMaxPath) {
        CopyAscii(g_dump_dir, kMaxPath, "crashes");
        CreateDirectoryA(g_dump_dir, nullptr);
        return;
    }

    char* slash = std::strrchr(exe, '\\');
    if (slash != nullptr) *slash = '\0';
    std::snprintf(g_dump_dir, kMaxPath, "%s\\crashes", exe);
    CreateDirectoryA(g_dump_dir, nullptr);
}

void BuildStamp(char* out, size_t cap) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::snprintf(out, cap, "%04u%02u%02u-%02u%02u%02u-%lu", st.wYear, st.wMonth,
                  st.wDay, st.wHour, st.wMinute, st.wSecond,
                  static_cast<unsigned long>(GetCurrentProcessId()));
}

const char* ModuleNameFor(DWORD64 addr, char* buf, size_t cap) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(addr)), &mbi,
                     sizeof(mbi)) == 0) {
        std::snprintf(buf, cap, "?");
        return buf;
    }
    char path[kMaxPath] = {0};
    if (GetModuleFileNameA(static_cast<HMODULE>(mbi.AllocationBase), path,
                           static_cast<DWORD>(kMaxPath)) == 0) {
        std::snprintf(buf, cap, "?");
        return buf;
    }
    const char* base = std::strrchr(path, '\\');
    base = (base != nullptr) ? base + 1 : path;
    const uintptr_t delta = static_cast<uintptr_t>(addr) -
                            reinterpret_cast<uintptr_t>(mbi.AllocationBase);
    std::snprintf(buf, cap, "%s+0x%llX", base,
                  static_cast<unsigned long long>(delta));
    return buf;
}

void WriteTextReport(const char* path, EXCEPTION_POINTERS* ep, const char* reason,
                     void* const* frames, unsigned frame_count) {
    HANDLE f = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;

    char line[1024];
    int n = std::snprintf(line, sizeof(line), "app=%s\nreason=%s\n", g_app_name, reason);
    DWORD wrote = 0;
    WriteFile(f, line, static_cast<DWORD>(n), &wrote, nullptr);

    if (ep != nullptr && ep->ExceptionRecord != nullptr) {
        const EXCEPTION_RECORD* er = ep->ExceptionRecord;
        n = std::snprintf(line, sizeof(line),
                          "exception_code=0x%08lX\nexception_address=%p\n"
                          "exception_flags=0x%08lX\n",
                          static_cast<unsigned long>(er->ExceptionCode),
                          er->ExceptionAddress,
                          static_cast<unsigned long>(er->ExceptionFlags));
        WriteFile(f, line, static_cast<DWORD>(n), &wrote, nullptr);

        char mod[256];
        n = std::snprintf(line, sizeof(line), "exception_module=%s\n",
                          ModuleNameFor(reinterpret_cast<DWORD64>(er->ExceptionAddress),
                                        mod, sizeof(mod)));
        WriteFile(f, line, static_cast<DWORD>(n), &wrote, nullptr);

        for (DWORD i = 0; i < er->NumberParameters && i < 8; ++i) {
            n = std::snprintf(line, sizeof(line), "param[%lu]=0x%llX\n",
                              static_cast<unsigned long>(i),
                              static_cast<unsigned long long>(er->ExceptionInformation[i]));
            WriteFile(f, line, static_cast<DWORD>(n), &wrote, nullptr);
        }
    }

    unsigned count = frame_count;
    if (count > kMaxFrames) count = static_cast<unsigned>(kMaxFrames);
    n = std::snprintf(line, sizeof(line), "frames=%u\n", count);
    WriteFile(f, line, static_cast<DWORD>(n), &wrote, nullptr);

    HANDLE proc = GetCurrentProcess();
    const bool sym = SymInitialize(proc, nullptr, TRUE) != FALSE;
    for (unsigned i = 0; i < count; ++i) {
        const DWORD64 addr = reinterpret_cast<DWORD64>(frames[i]);
        char name_buf[sizeof(SYMBOL_INFO) + 256] = {0};
        SYMBOL_INFO* si = reinterpret_cast<SYMBOL_INFO*>(name_buf);
        si->SizeOfStruct = sizeof(SYMBOL_INFO);
        si->MaxNameLen = 255;

        DWORD64 disp = 0;
        if (sym && SymFromAddr(proc, addr, &disp, si)) {
            n = std::snprintf(line, sizeof(line), "  #%u %p %s+0x%llX\n",
                              static_cast<unsigned>(i), frames[i], si->Name,
                              static_cast<unsigned long long>(disp));
        } else {
            n = std::snprintf(line, sizeof(line), "  #%u %p\n",
                              static_cast<unsigned>(i), frames[i]);
        }
        WriteFile(f, line, static_cast<DWORD>(n), &wrote, nullptr);
    }
    if (sym) SymCleanup(proc);

    CloseHandle(f);
}

// Writes <dir>\<app>-<stamp>.dmp and .txt, then terminates the process.
// Never returns. Uses only stack buffers and Win32 calls so it is safe to run
// from inside an exception filter.
//
// `skip` frames are dropped from the captured stack so the report starts at the
// caller's caller (the real crash site) rather than at the guard itself.
void CaptureAndDie(EXCEPTION_POINTERS* ep, const char* reason, unsigned skip) {
    // Capture here, before any heavy call, so the stack still reflects the
    // crash path. CaptureStackBackTrace(skip+1) also drops this frame.
    void* frames[kMaxFrames] = {0};
    const USHORT captured =
        CaptureStackBackTrace(skip + 1, static_cast<DWORD>(kMaxFrames), frames, nullptr);
    if (InterlockedExchange(&g_dumping, 1) != 0) {
        // Another thread is already dumping; just die without a dialog.
        TerminateProcess(GetCurrentProcess(), 3);
    }

    char stamp[64];
    BuildStamp(stamp, sizeof(stamp));

    char dmp_path[kMaxPath];
    char txt_path[kMaxPath];
    std::snprintf(dmp_path, sizeof(dmp_path), "%s\\%s-%s.dmp", g_dump_dir, g_app_name,
                  stamp);
    std::snprintf(txt_path, sizeof(txt_path), "%s\\%s-%s.txt", g_dump_dir, g_app_name,
                  stamp);

    HANDLE f = CreateFileA(dmp_path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION info;
        info.ThreadId = GetCurrentThreadId();
        info.ExceptionPointers = ep;
        info.ClientPointers = FALSE;
        const MINIDUMP_TYPE type = static_cast<MINIDUMP_TYPE>(
            MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules |
            MiniDumpWithProcessThreadData);
        if (ep != nullptr) {
            MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), f, type,
                              &info, nullptr, nullptr);
        } else {
            MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), f, type,
                              nullptr, nullptr, nullptr);
        }
        CloseHandle(f);
    }

    WriteTextReport(txt_path, ep, reason, frames, captured);

    char msg[kMaxPath * 2];
    const int n = std::snprintf(msg, sizeof(msg),
                                "[crash] %s: %s\n  dump: %s\n  text: %s\n", g_app_name,
                                reason, dmp_path, txt_path);
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    if (err != nullptr && err != INVALID_HANDLE_VALUE) {
        DWORD wrote = 0;
        WriteFile(err, msg, static_cast<DWORD>(n), &wrote, nullptr);
    }

    TerminateProcess(GetCurrentProcess(), 3);
}

LONG WINAPI SehFilter(EXCEPTION_POINTERS* ep) {
    CaptureAndDie(ep, "unhandled-seh", 1);
    return EXCEPTION_EXECUTE_HANDLER;  // unreachable
}

void AbortHandler(int) { CaptureAndDie(nullptr, "abort", 1); }

void TerminateHandler() { CaptureAndDie(nullptr, "std::terminate", 1); }

void PurecallHandler() { CaptureAndDie(nullptr, "pure-virtual-call", 1); }

void InvalidParameterHandler(const wchar_t*, const wchar_t*, const wchar_t*, unsigned int,
                             uintptr_t) {
    CaptureAndDie(nullptr, "invalid-parameter", 1);
}

}  // namespace

bool InstallCrashGuard(const char* app_name) {
    if (g_installed) return true;
    if (app_name != nullptr) CopyAscii(g_app_name, sizeof(g_app_name), app_name);

    // Keep every byte of the report; nothing goes to a modal dialog.
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                 SEM_NOOPENFILEERRORBOX);
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);

    // CRT assert must go to stderr instead of the abort/retry/ignore dialog.
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);

    ResolveDumpDirectory();

    SetUnhandledExceptionFilter(SehFilter);
    std::set_terminate(TerminateHandler);
    _set_purecall_handler(PurecallHandler);
    _set_invalid_parameter_handler(InvalidParameterHandler);
    signal(SIGABRT, AbortHandler);

    g_installed = true;
    return true;
}

const char* CrashDumpDirectory() { return g_installed ? g_dump_dir : ""; }

}  // namespace rtsc::util

#else  // !_WIN32

namespace rtsc::util {

bool InstallCrashGuard(const char*) { return false; }

const char* CrashDumpDirectory() { return ""; }

}  // namespace rtsc::util

#endif
