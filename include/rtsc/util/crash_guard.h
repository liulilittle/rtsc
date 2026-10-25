#pragma once

// Process-wide crash capture for Windows.
//
// Why this exists: an unhandled SEH exception or C++ terminate() normally hands
// the process to Windows Error Reporting, which shows a modal dialog and blocks
// the whole build/test pipeline. InstallCrashGuard() suppresses that dialog and
// instead writes a minidump plus a symbolized text report, then lets the process
// die with a non-zero exit code so ctest reports the failure immediately.
//
// On non-Windows platforms InstallCrashGuard() is a no-op that returns false.

namespace rtsc::util {

// Installs the crash handlers. Safe to call once from main().
// Returns true when handlers were installed.
bool InstallCrashGuard(const char* app_name);

// Directory where dumps are written. Empty when the guard is not installed.
const char* CrashDumpDirectory();

}  // namespace rtsc::util
