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

// The metric lookups the physical-pixel decision needs, behind an interface so
// the decision's CHOICE of metric can be tested behaviorally instead of by
// reading this file's source text.
//
// A single-monitor host cannot distinguish SM_CXSCREEN from SM_CXVIRTUALSCREEN
// at runtime (they are equal), so a test that only drove the real factory could
// never catch the defect that matters: feeding the virtual-screen box to a
// comparison against the primary monitor's physical size. A fake source makes
// the two values differ on any host, so pointing the decision at the wrong
// metric flips the result and turns the test red.
class MetricSource {
 public:
    virtual ~MetricSource() = default;
    // GetSystemMetrics(index): SM_CXSCREEN, SM_CYSCREEN, SM_CXVIRTUALSCREEN,
    // SM_CYVIRTUALSCREEN. Returns 0 for an index a source does not model.
    virtual int SystemMetric(int index) const = 0;
    // GetDeviceCaps(desktop DC, DESKTOPHORZRES / DESKTOPVERTRES).
    virtual int PhysicalWidth() const = 0;
    virtual int PhysicalHeight() const = 0;
};

// The production decision, reading every metric through `metrics`:
//
//   dpi_ok && primary (SM_CXSCREEN/SM_CYSCREEN)
//              == physical (DESKTOPHORZRES/DESKTOPVERTRES) and both > 0
//
// Kept separate from the raw 5-argument predicate so the metric selection is
// covered by a behavioural test (see MetricSource).
bool PixelsArePhysicalFromMetrics(bool dpi_ok, const MetricSource& metrics);

// Test-only factory entry: the same assembly as MakeGdiDesktopSource
// (capture-rect resolution, desktop snapshot, physical-pixel decision) but
// reading the decision's metrics from `metrics` instead of the live Win32
// source. dpi_ok is taken as true; the caller supplies the metric snapshot.
//
// The production factory and this overload both funnel through the same
// assembly function, so a defect at the assembly point -- e.g. feeding the
// virtual-screen box to PixelsArePhysicalFromMetrics instead of the primary
// monitor's size -- flips Geometry().pixels_are_physical and turns the test
// red. Driving only PixelsArePhysicalFromMetrics directly would not cover that
// wiring (see .opencode/discover.md example 35).
std::unique_ptr<DesktopSource> MakeGdiDesktopSourceWithMetrics(
    const MetricSource& metrics, int monitor_index = -1, int32_t x = 0,
    int32_t y = 0, int32_t width = 0, int32_t height = 0,
    std::string* error = nullptr);

}  // namespace rtsc::server

#endif  // _WIN32
