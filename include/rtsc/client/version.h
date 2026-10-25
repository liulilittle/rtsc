// rtsc version macros.
//
// One source of truth for the client version string. tools/rtsc_gui uses it
// for the window title and the "Connection information" dialog, and CMakeLists
// mirrors it in project(VERSION ...). Keep both in step when bumping.
//
// This header is deliberately platform neutral: it must not include windows.h.

#pragma once

#define RTSC_VERSION_MAJOR 0
#define RTSC_VERSION_MINOR 1
#define RTSC_VERSION_PATCH 0

#define RTSC_VERSION_STRING "0.1.0"
