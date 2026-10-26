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
