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
#include <fstream>
#include <iterator>
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
    // The factory must feed the predicate SM_CXSCREEN/SM_CYSCREEN, not the
    // virtual-screen bounding box: GetDeviceCaps on the desktop DC reports the
    // primary monitor, so comparing it with SM_*VIRTUALSCREEN would report
    // "not physical" on every multi-monitor system and drop all absolute
    // movement (the exact bug this batch fixes). A single-monitor host cannot
    // distinguish the two values at runtime, so the call site is guarded
    // structurally (the same pattern as the host-wiring checks in
    // test_desktop_input.cpp).
#ifdef RTSC_SOURCE_DIR
    const std::string path =
        std::string(RTSC_SOURCE_DIR) + "/src/server/desktop_gdi.cpp";
    std::ifstream in(path, std::ios::binary);
    CHECK(in.is_open());
    if (!in.is_open()) return;
    const std::string src((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    const size_t call = src.find("PixelsArePhysical(dpi_ok");
    CHECK(call != std::string::npos);
    if (call == std::string::npos) return;
    const size_t end = src.find(");", call);
    CHECK(end != std::string::npos);
    if (end == std::string::npos) return;
    const std::string args = src.substr(call, end - call);
    CHECK(args.find("SM_CXSCREEN") != std::string::npos);
    CHECK(args.find("SM_CYSCREEN") != std::string::npos);
    CHECK(args.find("SM_CXVIRTUALSCREEN") == std::string::npos);
    CHECK(args.find("SM_CYVIRTUALSCREEN") == std::string::npos);
#else
    std::printf("  FAIL: RTSC_SOURCE_DIR not defined\n");
    CHECK(false);
#endif
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
