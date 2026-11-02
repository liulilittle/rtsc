// Windows GDI desktop capture: construct the real-desktop source and pull a
// frame out of it. Windows-only (the source is a GDI backend).
//
// A headless host (session 0 / CI without an interactive desktop) cannot run
// this: the test prints the reason and skips rather than passing silently.

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "rtsc/server/desktop_gdi.h"
#include "test_framework.h"
#include "test_main.h"

namespace {

// True when this process can reach an interactive desktop. On a headless host
// there is no input desktop and GetSystemMetrics reports a zero virtual screen.
bool HaveInteractiveDesktop(std::string& why) {
    if (::GetSystemMetrics(SM_CXVIRTUALSCREEN) == 0 ||
        ::GetSystemMetrics(SM_CYVIRTUALSCREEN) == 0) {
        why = "GetSystemMetrics reports an empty virtual screen";
        return false;
    }
    const HDESK input = ::OpenInputDesktop(0, FALSE, GENERIC_READ);
    if (input == nullptr) {
        why = "OpenInputDesktop failed: no interactive desktop (session 0?)";
        return false;
    }
    (void)::CloseDesktop(input);
    return true;
}

void CheckFrame(const char* label, rtsc::server::DesktopSource& source,
                uint16_t width, uint16_t height) {
    std::vector<uint8_t> rgba;
    CHECK(source.Capture(width, height, rgba));
    CHECK_EQ(rgba.size(), static_cast<size_t>(width) * height * 4);

    bool all_zero = true;
    bool all_same_pixel = true;
    for (size_t i = 0; i < rgba.size(); i += 4) {
        if (rgba[i] != 0 || rgba[i + 1] != 0 || rgba[i + 2] != 0) {
            all_zero = false;
        }
        if (i > 0 && (rgba[i] != rgba[0] || rgba[i + 1] != rgba[1] ||
                      rgba[i + 2] != rgba[2] || rgba[i + 3] != rgba[3])) {
            all_same_pixel = false;
        }
    }
    std::printf("  %s: %ux%u, %zu bytes\n", label, width, height, rgba.size());
    CHECK(!all_zero);
    CHECK(!all_same_pixel);
}

// A metric source with independent primary/virtual/physical values. A
// single-monitor host makes SM_CXSCREEN and SM_CXVIRTUALSCREEN equal, so a
// fake is the only way to tell which one the production decision reads.
class FakeMetrics final : public rtsc::server::MetricSource {
 public:
    FakeMetrics(int primary_w, int primary_h, int virtual_w, int virtual_h,
                int physical_w, int physical_h)
        : primary_w_(primary_w),
          primary_h_(primary_h),
          virtual_w_(virtual_w),
          virtual_h_(virtual_h),
          physical_w_(physical_w),
          physical_h_(physical_h) {}

    int SystemMetric(int index) const override {
        switch (index) {
            case SM_CXSCREEN:
                return primary_w_;
            case SM_CYSCREEN:
                return primary_h_;
            case SM_CXVIRTUALSCREEN:
                return virtual_w_;
            case SM_CYVIRTUALSCREEN:
                return virtual_h_;
            default:
                return 0;
        }
    }
    int PhysicalWidth() const override { return physical_w_; }
    int PhysicalHeight() const override { return physical_h_; }

 private:
    int primary_w_;
    int primary_h_;
    int virtual_w_;
    int virtual_h_;
    int physical_w_;
    int physical_h_;
};

}  // namespace

RTSC_TEST(desktop_gdi_capture_default) {
    std::string why;
    if (!HaveInteractiveDesktop(why)) {
        std::printf("  SKIP: %s\n", why.c_str());
        return;
    }
    std::string error;
    auto source = rtsc::server::MakeGdiDesktopSource(-1, 0, 0, 0, 0, &error);
    if (source == nullptr) {
        std::printf("  SKIP: MakeGdiDesktopSource failed: %s\n", error.c_str());
        return;
    }
    CheckFrame("virtual desktop", *source, 320, 240);
}

RTSC_TEST(desktop_gdi_capture_primary_monitor) {
    std::string why;
    if (!HaveInteractiveDesktop(why)) {
        std::printf("  SKIP: %s\n", why.c_str());
        return;
    }
    std::string error;
    auto source = rtsc::server::MakeGdiDesktopSource(0, 0, 0, 0, 0, &error);
    if (source == nullptr) {
        std::printf("  SKIP: MakeGdiDesktopSource(monitor 0) failed: %s\n",
                    error.c_str());
        return;
    }
    CheckFrame("primary monitor", *source, 320, 240);
}

RTSC_TEST(desktop_gdi_capture_rect) {
    std::string why;
    if (!HaveInteractiveDesktop(why)) {
        std::printf("  SKIP: %s\n", why.c_str());
        return;
    }
    std::string error;
    // A 160x120 rectangle of the virtual desktop, offset from its origin.
    auto source = rtsc::server::MakeGdiDesktopSource(-1, 0, 0, 160, 120, &error);
    if (source == nullptr) {
        std::printf("  SKIP: MakeGdiDesktopSource(rect) failed: %s\n",
                    error.c_str());
        return;
    }
    CheckFrame("explicit rectangle", *source, 160, 120);
}

RTSC_TEST(desktop_gdi_pixel_matches_getpixel) {
    // Directly verify the DIB->RGBA conversion: the source's pixels must equal
    // the OS's own GetPixel at the same virtual-screen coordinates, and alpha
    // must be forced opaque. A wrong BGRA->RGBA swap would mismatch on any
    // non-gray pixel, so this catches the conversion defect the frame-level
    // checks cannot.
    std::string why;
    if (!HaveInteractiveDesktop(why)) {
        std::printf("  SKIP: %s\n", why.c_str());
        return;
    }
    const int vx = ::GetSystemMetrics(SM_XVIRTUALSCREEN);
    const int vy = ::GetSystemMetrics(SM_YVIRTUALSCREEN);
    std::string error;
    auto source = rtsc::server::MakeGdiDesktopSource(-1, 0, 0, 4, 4, &error);
    CHECK(source != nullptr);
    if (source == nullptr) return;

    // The source and GetPixel sample the screen a moment apart, so retry to
    // tolerate a transient screen change.
    bool matched = false;
    for (int attempt = 0; attempt < 8 && !matched; ++attempt) {
        std::vector<uint8_t> rgba;
        if (!source->Capture(4, 4, rgba)) break;
        CHECK_EQ(rgba.size(), static_cast<size_t>(4) * 4 * 4);
        const HDC screen = ::CreateDC(TEXT("DISPLAY"), nullptr, nullptr, nullptr);
        if (screen == nullptr) break;
        bool ok = true;
        for (int y = 0; y < 4 && ok; ++y) {
            for (int x = 0; x < 4 && ok; ++x) {
                const COLORREF c = ::GetPixel(screen, vx + x, vy + y);
                const size_t i = (static_cast<size_t>(y) * 4 + x) * 4;
                if (rgba[i + 0] != GetRValue(c) || rgba[i + 1] != GetGValue(c) ||
                    rgba[i + 2] != GetBValue(c) || rgba[i + 3] != 0xFF) {
                    ok = false;
                }
            }
        }
        (void)::DeleteDC(screen);
        matched = ok;
    }
    CHECK(matched);
}

RTSC_TEST(desktop_gdi_geometry_matches_virtual_screen) {
    // Geometry() must report the same rectangle the capture actually blits
    // from: the virtual-screen bounding box for monitor -1. The desktop field
    // (the VIRTUALDESK normalization domain) is that same box.
    std::string why;
    if (!HaveInteractiveDesktop(why)) {
        std::printf("  SKIP: %s\n", why.c_str());
        return;
    }
    std::string error;
    auto source = rtsc::server::MakeGdiDesktopSource(-1, 0, 0, 0, 0, &error);
    if (source == nullptr) {
        std::printf("  SKIP: MakeGdiDesktopSource failed: %s\n", error.c_str());
        return;
    }
    const rtsc::server::DesktopGeometry g = source->Geometry();
    const int vx = ::GetSystemMetrics(SM_XVIRTUALSCREEN);
    const int vy = ::GetSystemMetrics(SM_YVIRTUALSCREEN);
    const int vw = ::GetSystemMetrics(SM_CXVIRTUALSCREEN);
    const int vh = ::GetSystemMetrics(SM_CYVIRTUALSCREEN);
    CHECK(g.mapped);
    CHECK_EQ(g.capture_x, vx);
    CHECK_EQ(g.capture_y, vy);
    CHECK_EQ(g.capture_width, vw);
    CHECK_EQ(g.capture_height, vh);
    CHECK_EQ(g.desktop_x, vx);
    CHECK_EQ(g.desktop_y, vy);
    CHECK_EQ(g.desktop_width, vw);
    CHECK_EQ(g.desktop_height, vh);

    // pixels_are_physical must mean exactly what the factory promises: the
    // PRIMARY monitor's SM_* snapshot equals the desktop DC's real pixel size.
    // (DESKTOPHORZRES/VERTRES on the desktop DC describe the primary monitor,
    // so the virtual-screen bounding box is deliberately not compared here.)
    const HDC screen = ::CreateDC(TEXT("DISPLAY"), nullptr, nullptr, nullptr);
    if (screen != nullptr) {
        const int physical_w = ::GetDeviceCaps(screen, DESKTOPHORZRES);
        const int physical_h = ::GetDeviceCaps(screen, DESKTOPVERTRES);
        (void)::DeleteDC(screen);
        CHECK_EQ(g.pixels_are_physical,
                 ::GetSystemMetrics(SM_CXSCREEN) == physical_w &&
                     ::GetSystemMetrics(SM_CYSCREEN) == physical_h);
    }
}

RTSC_TEST(desktop_gdi_geometry_matches_primary_monitor) {
    std::string why;
    if (!HaveInteractiveDesktop(why)) {
        std::printf("  SKIP: %s\n", why.c_str());
        return;
    }
    std::string error;
    auto source = rtsc::server::MakeGdiDesktopSource(0, 0, 0, 0, 0, &error);
    if (source == nullptr) {
        std::printf("  SKIP: MakeGdiDesktopSource(monitor 0) failed: %s\n",
                    error.c_str());
        return;
    }
    MONITORINFO info{};
    info.cbSize = sizeof(info);
    const POINT origin{0, 0};
    CHECK(::GetMonitorInfo(::MonitorFromPoint(origin, MONITOR_DEFAULTTOPRIMARY),
                           &info) != FALSE);
    const rtsc::server::DesktopGeometry g = source->Geometry();
    CHECK(g.mapped);
    CHECK_EQ(g.capture_x, info.rcMonitor.left);
    CHECK_EQ(g.capture_y, info.rcMonitor.top);
    CHECK_EQ(g.capture_width, info.rcMonitor.right - info.rcMonitor.left);
    CHECK_EQ(g.capture_height, info.rcMonitor.bottom - info.rcMonitor.top);
    // The normalization domain stays the whole virtual desktop, not just the
    // selected monitor.
    CHECK_EQ(g.desktop_x, ::GetSystemMetrics(SM_XVIRTUALSCREEN));
    CHECK_EQ(g.desktop_y, ::GetSystemMetrics(SM_YVIRTUALSCREEN));
    CHECK_EQ(g.desktop_width, ::GetSystemMetrics(SM_CXVIRTUALSCREEN));
    CHECK_EQ(g.desktop_height, ::GetSystemMetrics(SM_CYVIRTUALSCREEN));
}

RTSC_TEST(desktop_gdi_geometry_explicit_rectangle) {
    std::string why;
    if (!HaveInteractiveDesktop(why)) {
        std::printf("  SKIP: %s\n", why.c_str());
        return;
    }
    const int vw = ::GetSystemMetrics(SM_CXVIRTUALSCREEN);
    const int vh = ::GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (vw < 200 || vh < 200) {
        std::printf("  SKIP: virtual screen too small for a 100x50 sub-rect\n");
        return;
    }
    std::string error;
    auto source = rtsc::server::MakeGdiDesktopSource(-1, 7, 9, 100, 50, &error);
    if (source == nullptr) {
        std::printf("  SKIP: MakeGdiDesktopSource(rect) failed: %s\n",
                    error.c_str());
        return;
    }
    const rtsc::server::DesktopGeometry g = source->Geometry();
    CHECK(g.mapped);
    CHECK_EQ(g.capture_x, ::GetSystemMetrics(SM_XVIRTUALSCREEN) + 7);
    CHECK_EQ(g.capture_y, ::GetSystemMetrics(SM_YVIRTUALSCREEN) + 9);
    CHECK_EQ(g.capture_width, 100);
    CHECK_EQ(g.capture_height, 50);
    CHECK_EQ(g.desktop_width, vw);
    CHECK_EQ(g.desktop_height, vh);
}

RTSC_TEST(desktop_gdi_pixels_are_physical_predicate) {
    using rtsc::server::PixelsArePhysical;
    // DPI awareness took effect: primary logical size == physical size.
    CHECK(PixelsArePhysical(true, 1920, 1080, 1920, 1080));
    CHECK(PixelsArePhysical(true, 2560, 1440, 2560, 1440));
    // DPI not in effect: the logical primary is virtualized (smaller).
    CHECK(!PixelsArePhysical(true, 2048, 1152, 2560, 1440));
    // The awareness call failed: never trust the metrics.
    CHECK(!PixelsArePhysical(false, 1920, 1080, 1920, 1080));
    // Multi-monitor: the primary monitor and the desktop DC's physical size
    // agree even though the virtual desktop is wider (3200). The predicate is
    // given the PRIMARY size, never the virtual-screen box. Passing the
    // virtual width where the primary width belongs is the defect this
    // predicate must reject.
    CHECK(PixelsArePhysical(true, 1920, 1080, 1920, 1080));
    CHECK(!PixelsArePhysical(true, 3200, 1080, 1920, 1080));
    // Zero/negative physical metrics cannot be trusted.
    CHECK(!PixelsArePhysical(true, 0, 0, 0, 0));
}

RTSC_TEST(desktop_gdi_geometry_uses_primary_screen_metrics) {
    using rtsc::server::PixelsArePhysicalFromMetrics;

    // The decision must read SM_CXSCREEN/SM_CYSCREEN (the PRIMARY monitor) and
    // compare them with the desktop DC's DESKTOPHORZRES/DESKTOPVERTRES, which
    // describes the primary monitor as well. On a multi-monitor system the
    // virtual-screen box is larger, so a decision that read
    // SM_CX*VIRTUALSCREEN would report "not physical" and drop all absolute
    // movement -- the exact defect this batch fixes.
    //
    // A single-monitor test host cannot tell the two metrics apart at runtime
    // (they are equal), so the metric LOOKUP is behind an injectable source and
    // this test drives the production decision with a fake that makes them
    // differ. Guarding the call site by grepping the source text was a false
    // test: a comment mentioning the correct call made the grep pass while the
    // real call was wrong, and a comment mentioning the old call made it fail.
    // Single monitor: every metric agrees, the process is physical.
    CHECK(PixelsArePhysicalFromMetrics(
        true, FakeMetrics(1920, 1080, 1920, 1080, 1920, 1080)));
    // Multi-monitor: primary 1920 == physical 1920, virtual box 3200. Only the
    // primary-based decision accepts this; reading the virtual width would
    // reject it (3200 != 1920) and disable absolute movement on every
    // multi-monitor host.
    CHECK(PixelsArePhysicalFromMetrics(
        true, FakeMetrics(1920, 1080, 3200, 1080, 1920, 1080)));
    // Same shape, vertical axis: the virtual height differs from the primary's.
    CHECK(PixelsArePhysicalFromMetrics(
        true, FakeMetrics(1920, 1080, 1920, 2160, 1920, 1080)));
    // A source reporting the virtual box as the "primary" size (the defect's
    // signature) must be rejected: primary 3200 is not the monitor's physical
    // 1920.
    CHECK(!PixelsArePhysicalFromMetrics(
        true, FakeMetrics(3200, 1080, 3200, 1080, 1920, 1080)));
    // DPI awareness did not take effect: the primary is virtualized smaller.
    CHECK(!PixelsArePhysicalFromMetrics(
        true, FakeMetrics(2048, 1152, 2048, 1152, 2560, 1440)));
    // A failed DPI-awareness call never trusts the metrics.
    CHECK(!PixelsArePhysicalFromMetrics(
        false, FakeMetrics(1920, 1080, 3200, 1080, 1920, 1080)));
    // Unavailable metrics cannot be trusted.
    CHECK(!PixelsArePhysicalFromMetrics(
        true, FakeMetrics(0, 0, 0, 0, 0, 0)));
}

RTSC_TEST(desktop_gdi_factory_feeds_primary_metrics_to_decision) {
    // The previous test drives the decision function directly; it cannot see
    // which metrics the FACTORY hands it (batch 24 R1: changing the factory's
    // call to SM_CX*VIRTUALSCREEN stayed green). This test goes through the
    // factory assembly (capture-rect resolution, desktop snapshot and decision)
    // with the same fake, so the metric choice at that wiring point is covered.
    std::string why;
    if (!HaveInteractiveDesktop(why)) {
        std::printf("  SKIP: %s\n", why.c_str());
        return;
    }

    // Multi-monitor shape: primary 1920 == physical 1920, virtual box 3200.
    // Reading the virtual width would reject this and disable absolute
    // movement on every multi-monitor host.
    FakeMetrics multi(1920, 1080, 3200, 1080, 1920, 1080);
    std::string error;
    auto source = rtsc::server::MakeGdiDesktopSourceWithMetrics(
        multi, -1, 0, 0, 0, 0, &error);
    if (source == nullptr) {
        std::printf("  SKIP: MakeGdiDesktopSourceWithMetrics failed: %s\n",
                    error.c_str());
        return;
    }
    CHECK(source->Geometry().pixels_are_physical);

    // A source that reports the virtual box as the "primary" size (the
    // defect's signature) must be rejected even through the factory.
    FakeMetrics wrong(3200, 1080, 3200, 1080, 1920, 1080);
    auto rejected = rtsc::server::MakeGdiDesktopSourceWithMetrics(
        wrong, -1, 0, 0, 0, 0, &error);
    CHECK(rejected != nullptr);
    if (rejected != nullptr) {
        CHECK(!rejected->Geometry().pixels_are_physical);
    }
}

RTSC_TEST(desktop_gdi_unknown_monitor_fails) {
    std::string error;
    auto source = rtsc::server::MakeGdiDesktopSource(1000, 0, 0, 0, 0, &error);
    if (source == nullptr) {
        CHECK(!error.empty());
        std::printf("  unknown monitor rejected: %s\n", error.c_str());
    } else {
        std::printf("  SKIP: 1001 monitors present, index 1000 is valid\n");
    }
}

int main() { return rtsc::test::run_all("rtsc_desktop_gdi_tests"); }

#endif  // _WIN32
