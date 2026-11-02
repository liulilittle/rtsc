// Windows GDI desktop capture for the RTSC RDP server.
//
// The server role serves a desktop framebuffer through the platform-neutral
// rtsc::server::DesktopSource seam (include/rtsc/server/server.h). The default
// source in src/server/server.cpp is a synthetic test pattern; this is the real
// desktop: it copies the Windows virtual screen (all monitors) or a chosen
// monitor and hands the pixels back in the server's RGBA layout (R at the
// lowest address).
//
// This header is Windows-only and leaks no Win32 type: the only exported symbol
// is the factory, and every parameter is a plain integer.

#pragma once

#ifdef _WIN32

#include <cstdint>
#include <memory>
#include <string>

#include "rtsc/server/server.h"

namespace rtsc::server {

// Creates a GDI desktop capture source.
//
//   monitor_index  -1 (default) captures the whole virtual desktop (every
//                  monitor); >= 0 captures the monitor at that index, with 0
//                  the primary.
//   x, y           Origin offset of the capture rectangle, relative to the
//                  chosen display's top-left corner.
//   width, height  Capture size in pixels. <= 0 means the full size of the
//                  chosen display.
//   error          Receives a human-readable reason when the factory returns
//                  nullptr (no interactive desktop, unknown monitor, ...). May
//                  be null.
//
// Capture(width, height, rgba) then produces exactly width * height * 4 bytes
// for the negotiated desktop geometry, scaling the captured rectangle into it.
std::unique_ptr<DesktopSource> MakeGdiDesktopSource(
    int monitor_index = -1, int32_t x = 0, int32_t y = 0, int32_t width = 0,
    int32_t height = 0, std::string* error = nullptr);

// True when the SM_* metrics are physical pixels.
//
// `primary_width`/`primary_height` are SM_CXSCREEN/SM_CYSCREEN (the PRIMARY
// monitor's size) and `physical_width`/`physical_height` are
// DESKTOPHORZRES/DESKTOPVERTRES. The virtual-screen bounding box must NOT be
// used here: on a multi-monitor system it is larger than the primary monitor,
// while GetDeviceCaps on the desktop DC reports the primary monitor's physical
// size, so comparing the two would always fail and disable absolute movement.
// `dpi_ok` is the result of EnablePerMonitorDpiAwareness().
bool PixelsArePhysical(bool dpi_ok, int primary_width, int primary_height,
                       int physical_width, int physical_height);

}  // namespace rtsc::server

#endif  // _WIN32
