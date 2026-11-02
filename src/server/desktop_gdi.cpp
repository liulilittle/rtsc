// Windows GDI desktop capture for the RTSC RDP server.
//
// Implements include/rtsc/server/desktop_gdi.h. The capture pipeline is the
// classic GDI screen grab:
//
//   CreateDC("DISPLAY") -> GetSystemMetrics(SM_*VIRTUALSCREEN) ->
//   CreateCompatibleDC -> CreateDIBSection (32bpp, top-down BI_RGB) ->
//   BitBlt / StretchBlt -> copy into the server's RGBA buffer.
//
// Platform notes:
//   * No window station or desktop handle is opened. CreateDC("DISPLAY") is the
//     lowest-level entry point and works as long as the process can reach the
//     interactive display; in session 0 (a service) it fails, which the factory
//     reports as "no interactive desktop".
//   * The process is switched to per-monitor-v2 DPI awareness so the metrics
//     above report physical pixels. The call is best effort: a manifest or an
//     earlier call may already have fixed the mode.
//   * The DIB is created at the *requested* size. When the capture rectangle is
//     the same size the copy is a plain BitBlt; otherwise it is stretched, so
//     the negotiated desktop geometry never has to match the physical display.
//   * A 32bpp BI_RGB DIB keeps B, G, R, A in memory order (the DWORD is
//     0xAARRGGBB). The server wants R at the lowest address, so red and blue are
//     swapped, and alpha is forced opaque because BI_RGB leaves it undefined.

#include "rtsc/server/desktop_gdi.h"

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace rtsc::server {

namespace {

// The desktop rectangle this source captures, in virtual-screen coordinates.
struct CaptureRect {
    int left = 0;
    int top = 0;
    int right = 0;
    int bottom = 0;
};

struct MonitorEntry {
    RECT rect;
    bool primary;
};

// Every SM_* lookup goes through the injected MetricSource so that the whole
// assembly (capture-rect resolution, desktop snapshot, physical-pixel decision)
// can be driven by a fake on a single-monitor host. Reading the real metrics in
// some branches and the injected ones in others left the branches nobody could
// reach unguarded: changing the desktop snapshot to the primary monitor's size
// stayed green (see .opencode/discover.md example 37).

// Switches the process to per-monitor-v2 DPI awareness so GetSystemMetrics and
// the GDI DC report physical pixels. Best effort: the call fails when a
// manifest or an earlier call already fixed the mode, or on pre-Win10-1607, and
// in both cases the process keeps whatever mode it has.
//
// Returns true when the process is per-monitor aware after the call. A failed
// SetProcessDpiAwarenessContext is not by itself "unaware": re-setting an
// already fixed mode fails with ERROR_ACCESS_DENIED while the mode stays
// per-monitor (measured; see docs/spec/input-geometry-design-N.md 4.3). The
// return value feeds InjectGeometry::pixels_are_physical, so it must describe
// the process, not whether this particular call won.
bool EnablePerMonitorDpiAwareness() {
    if (::SetProcessDpiAwarenessContext(
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
        return true;
    }
    return ::GetAwarenessFromDpiAwarenessContext(
               ::GetThreadDpiAwarenessContext()) ==
           DPI_AWARENESS_PER_MONITOR_AWARE;
}

BOOL CALLBACK CollectMonitor(HMONITOR monitor, HDC, LPRECT, LPARAM data) {
    auto* out = reinterpret_cast<std::vector<MonitorEntry>*>(data);
    MONITORINFO info{};
    info.cbSize = sizeof(info);
    if (!::GetMonitorInfo(monitor, &info)) return TRUE;
    MonitorEntry entry;
    entry.rect = info.rcMonitor;
    entry.primary = (info.dwFlags & MONITORINFOF_PRIMARY) != 0;
    out->push_back(entry);
    return TRUE;
}

bool ResolveCaptureRect(const MetricSource& metrics, int monitor_index,
                        int32_t x, int32_t y, int32_t width, int32_t height,
                        CaptureRect& rect, std::string& error) {
    if (monitor_index >= 0) {
        std::vector<MonitorEntry> monitors;
        ::EnumDisplayMonitors(nullptr, nullptr, CollectMonitor,
                              reinterpret_cast<LPARAM>(&monitors));
        if (monitors.empty()) {
            error = "EnumDisplayMonitors reported no monitors";
            return false;
        }
        if (monitor_index >= static_cast<int>(monitors.size())) {
            error = "monitor index " + std::to_string(monitor_index) +
                    " is out of range (" + std::to_string(monitors.size()) +
                    " monitor(s))";
            return false;
        }
        // Enumeration order is not guaranteed to put the primary first; make
        // index 0 the primary so the parameter is predictable.
        std::stable_sort(monitors.begin(), monitors.end(),
                         [](const MonitorEntry& a, const MonitorEntry& b) {
                             return a.primary && !b.primary;
                         });
        const RECT& r = monitors[static_cast<size_t>(monitor_index)].rect;
        rect.left = r.left;
        rect.top = r.top;
        rect.right = r.right;
        rect.bottom = r.bottom;
    } else {
        rect.left = metrics.SystemMetric(SM_XVIRTUALSCREEN);
        rect.top = metrics.SystemMetric(SM_YVIRTUALSCREEN);
        rect.right = rect.left + metrics.SystemMetric(SM_CXVIRTUALSCREEN);
        rect.bottom = rect.top + metrics.SystemMetric(SM_CYVIRTUALSCREEN);
        if (rect.right <= rect.left || rect.bottom <= rect.top) {
            error = "no interactive desktop: the virtual screen is empty";
            return false;
        }
    }

    const int base_w = rect.right - rect.left;
    const int base_h = rect.bottom - rect.top;
    rect.left += static_cast<int>(x);
    rect.top += static_cast<int>(y);
    int w = width > 0 ? static_cast<int>(width) : base_w;
    int h = height > 0 ? static_cast<int>(height) : base_h;

    // Clamp to the virtual desktop so the blit never reads off-screen.
    const int vx = metrics.SystemMetric(SM_XVIRTUALSCREEN);
    const int vy = metrics.SystemMetric(SM_YVIRTUALSCREEN);
    const int max_x = vx + metrics.SystemMetric(SM_CXVIRTUALSCREEN);
    const int max_y = vy + metrics.SystemMetric(SM_CYVIRTUALSCREEN);
    if (rect.left < vx) rect.left = vx;
    if (rect.top < vy) rect.top = vy;
    if (rect.left > max_x) rect.left = max_x;
    if (rect.top > max_y) rect.top = max_y;
    if (rect.left + w > max_x) w = max_x - rect.left;
    if (rect.top + h > max_y) h = max_y - rect.top;
    if (w <= 0 || h <= 0) {
        error = "the requested capture rectangle is empty";
        return false;
    }
    rect.right = rect.left + w;
    rect.bottom = rect.top + h;
    return true;
}

}  // namespace

bool PixelsArePhysical(bool dpi_ok, int primary_width, int primary_height,
                       int physical_width, int physical_height) {
    return dpi_ok && physical_width > 0 && physical_height > 0 &&
           primary_width == physical_width &&
           primary_height == physical_height;
}

bool PixelsArePhysicalFromMetrics(bool dpi_ok, const MetricSource& metrics) {
    // The PRIMARY monitor's logical size (SM_CXSCREEN/SM_CYSCREEN) is the only
    // correct left-hand side: the desktop DC's DESKTOPHORZRES/VERTRES describe
    // the primary monitor too (Microsoft Learn, GetDeviceCaps: "if hdc is the
    // desktop, GetDeviceCaps returns the capabilities of the primary monitor").
    // Using SM_CX*VIRTUALSCREEN here compares the whole bounding box against
    // one monitor and reports "not physical" on every multi-monitor system,
    // which disables absolute movement exactly where --monitor N matters.
    return PixelsArePhysical(dpi_ok, metrics.SystemMetric(SM_CXSCREEN),
                             metrics.SystemMetric(SM_CYSCREEN),
                             metrics.PhysicalWidth(), metrics.PhysicalHeight());
}

namespace {

// Reads the real system metrics. The display DC is created once (in the
// constructor) so the two capability lookups are a snapshot of the same
// moment; a source that cannot reach a display reports 0, which the decision
// rejects as untrustworthy.
class Win32MetricSource final : public MetricSource {
 public:
    Win32MetricSource() : probe_(::CreateDC(TEXT("DISPLAY"), nullptr, nullptr,
                                            nullptr)) {
        if (probe_ != nullptr) {
            physical_w_ = ::GetDeviceCaps(probe_, DESKTOPHORZRES);
            physical_h_ = ::GetDeviceCaps(probe_, DESKTOPVERTRES);
        }
    }

    ~Win32MetricSource() override {
        if (probe_ != nullptr) (void)::DeleteDC(probe_);
    }

    Win32MetricSource(const Win32MetricSource&) = delete;
    Win32MetricSource& operator=(const Win32MetricSource&) = delete;

    int SystemMetric(int index) const override {
        return ::GetSystemMetrics(index);
    }
    int PhysicalWidth() const override { return physical_w_; }
    int PhysicalHeight() const override { return physical_h_; }

    bool has_display() const { return probe_ != nullptr; }

 private:
    HDC probe_ = nullptr;
    int physical_w_ = 0;
    int physical_h_ = 0;
};

}  // namespace

class GdiDesktopSourceImpl : public DesktopSource {
 public:
    GdiDesktopSourceImpl(CaptureRect rect, CaptureRect desktop,
                         bool pixels_are_physical)
        : rect_(rect),
          desktop_(desktop),
          pixels_are_physical_(pixels_are_physical) {}

    DesktopGeometry Geometry() const override {
        DesktopGeometry geometry;
        geometry.capture_x = rect_.left;
        geometry.capture_y = rect_.top;
        geometry.capture_width = rect_.right - rect_.left;
        geometry.capture_height = rect_.bottom - rect_.top;
        geometry.desktop_x = desktop_.left;
        geometry.desktop_y = desktop_.top;
        geometry.desktop_width = desktop_.right - desktop_.left;
        geometry.desktop_height = desktop_.bottom - desktop_.top;
        geometry.mapped = geometry.capture_width > 0 &&
                          geometry.capture_height > 0 &&
                          geometry.desktop_width > 1 &&
                          geometry.desktop_height > 1;
        geometry.pixels_are_physical = pixels_are_physical_;
        return geometry;
    }

    bool Capture(uint16_t width, uint16_t height,
                 std::vector<uint8_t>& rgba) override {
        if (width == 0 || height == 0) {
            error_ = "capture requested a zero dimension";
            return false;
        }
        rgba.assign(static_cast<size_t>(width) * height * 4, 0);

        const HDC screen = ::CreateDC(TEXT("DISPLAY"), nullptr, nullptr, nullptr);
        if (screen == nullptr) {
            error_ = "CreateDC(\"DISPLAY\") failed: no interactive desktop";
            return false;
        }
        const HDC memory = ::CreateCompatibleDC(screen);
        if (memory == nullptr) {
            (void)::DeleteDC(screen);
            error_ = "CreateCompatibleDC failed";
            return false;
        }

        BITMAPINFO info{};
        info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        info.bmiHeader.biWidth = static_cast<LONG>(width);
        info.bmiHeader.biHeight = -static_cast<LONG>(height);  // top-down
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB;

        void* bits = nullptr;
        const HBITMAP bitmap =
            ::CreateDIBSection(memory, &info, DIB_RGB_COLORS, &bits, nullptr, 0);
        if (bitmap == nullptr || bits == nullptr) {
            (void)::DeleteDC(memory);
            (void)::DeleteDC(screen);
            error_ = "CreateDIBSection failed";
            return false;
        }

        const HGDIOBJ previous = ::SelectObject(memory, bitmap);
        if (previous == nullptr) {
            (void)::DeleteObject(bitmap);
            (void)::DeleteDC(memory);
            (void)::DeleteDC(screen);
            error_ = "SelectObject failed";
            return false;
        }

        const int src_w = rect_.right - rect_.left;
        const int src_h = rect_.bottom - rect_.top;
        BOOL copied = FALSE;
        if (src_w == static_cast<int>(width) && src_h == static_cast<int>(height)) {
            copied = ::BitBlt(memory, 0, 0, static_cast<int>(width),
                              static_cast<int>(height), screen, rect_.left,
                              rect_.top, SRCCOPY);
        } else {
            (void)::SetStretchBltMode(memory, COLORONCOLOR);
            copied = ::StretchBlt(memory, 0, 0, static_cast<int>(width),
                                  static_cast<int>(height), screen, rect_.left,
                                  rect_.top, src_w, src_h, SRCCOPY);
        }
        (void)::SelectObject(memory, previous);

        if (!copied) {
            (void)::DeleteObject(bitmap);
            (void)::DeleteDC(memory);
            (void)::DeleteDC(screen);
            error_ = "the screen blit failed";
            return false;
        }

        // A 32bpp BI_RGB DIB keeps B, G, R, A in memory order; the server wants
        // R at the lowest address, so swap red and blue. Alpha is forced opaque
        // because BI_RGB leaves it undefined (a zero alpha would render as
        // transparent in a 32bpp client).
        const uint8_t* src = static_cast<const uint8_t*>(bits);
        const size_t count = static_cast<size_t>(width) * height;
        for (size_t i = 0; i < count; ++i) {
            rgba[i * 4 + 0] = src[i * 4 + 2];
            rgba[i * 4 + 1] = src[i * 4 + 1];
            rgba[i * 4 + 2] = src[i * 4 + 0];
            rgba[i * 4 + 3] = 0xFF;
        }

        (void)::DeleteObject(bitmap);
        (void)::DeleteDC(memory);
        (void)::DeleteDC(screen);
        return true;
    }

    const std::string& last_error() const { return error_; }

 private:
    CaptureRect rect_;
    CaptureRect desktop_;
    bool pixels_are_physical_ = false;
    std::string error_;
};

namespace {

// Shared assembly for both factory entries. The capture rectangle is resolved
// first (it needs the same metrics); everything from the desktop snapshot
// through the physical-pixel decision is identical here. Routing the test seam
// through this function is what covers the assembly point: a wrong metric
// choice below shows up in Geometry().
std::unique_ptr<DesktopSource> AssembleGdiDesktopSource(
    bool dpi_ok, const MetricSource& metrics, int monitor_index, int32_t x,
    int32_t y, int32_t width, int32_t height, std::string* error) {
    CaptureRect rect;
    std::string local_error;
    if (!ResolveCaptureRect(metrics, monitor_index, x, y, width, height, rect,
                            local_error)) {
        if (error != nullptr) *error = local_error;
        return nullptr;
    }

    // Snapshot the virtual desktop: it is the domain MOUSEEVENTF_VIRTUALDESK
    // normalizes against, independent of which monitor was captured.
    CaptureRect desktop;
    desktop.left = metrics.SystemMetric(SM_XVIRTUALSCREEN);
    desktop.top = metrics.SystemMetric(SM_YVIRTUALSCREEN);
    desktop.right = desktop.left + metrics.SystemMetric(SM_CXVIRTUALSCREEN);
    desktop.bottom = desktop.top + metrics.SystemMetric(SM_CYVIRTUALSCREEN);

    // The SM_* metrics are only physical pixels when the process is
    // per-monitor aware; compare the PRIMARY monitor's size with the display's
    // real pixel size. The metric selection lives in
    // PixelsArePhysicalFromMetrics (see the comment there and in the header):
    // it is the one place that must name SM_CXSCREEN/SM_CYSCREEN, and the seam
    // makes that choice behaviourally testable on a single-monitor host.
    const bool pixels_are_physical =
        PixelsArePhysicalFromMetrics(dpi_ok, metrics);

    if (error != nullptr) error->clear();
    return std::make_unique<GdiDesktopSourceImpl>(rect, desktop,
                                                  pixels_are_physical);
}

}  // namespace

std::unique_ptr<DesktopSource> MakeGdiDesktopSource(int monitor_index, int32_t x,
                                                    int32_t y, int32_t width,
                                                    int32_t height,
                                                    std::string* error) {
    // One line of glue over the injectable entry: the only thing this adds is
    // WHICH probe is used. Everything else (metric snapshot, capture-rect
    // resolution, assembly) is shared, so the DPI wiring cannot drift between
    // what ships and what the tests drive.
    return MakeGdiDesktopSourceWithDpiProbe(
        &EnablePerMonitorDpiAwareness, monitor_index, x, y, width, height,
        error);
}

std::unique_ptr<DesktopSource> MakeGdiDesktopSourceWithMetrics(
    const MetricSource& metrics, bool dpi_ok, int monitor_index, int32_t x,
    int32_t y, int32_t width, int32_t height, std::string* error) {
    return AssembleGdiDesktopSource(dpi_ok, metrics, monitor_index, x, y, width,
                                    height, error);
}

std::unique_ptr<DesktopSource> MakeGdiDesktopSourceWithDpiProbe(
    DpiAwarenessProbe probe, int monitor_index, int32_t x, int32_t y,
    int32_t width, int32_t height, std::string* error) {
    // The same body as MakeGdiDesktopSource with exactly one substitution: the
    // DPI probe. Keeping the two in step is what makes the wiring testable --
    // the production entry is one line of glue over this function, so a test
    // that drives this one covers "probe result reaches the assembly" without
    // needing a real display or a fake DPI context.
    const bool dpi_ok = (probe != nullptr) ? probe() : false;

    Win32MetricSource metrics;
    if (!metrics.has_display()) {
        if (error != nullptr) {
            *error = "CreateDC(\"DISPLAY\") failed: no interactive desktop";
        }
        return nullptr;
    }

    return AssembleGdiDesktopSource(dpi_ok, metrics, monitor_index, x, y, width,
                                    height, error);
}

}  // namespace rtsc::server

#endif  // _WIN32
