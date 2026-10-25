// UI surface and window abstraction.

#include "rtsc/ui/surface.h"
#include "rtsc/ui/window.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::ui;

RTSC_TEST(surface_fill_and_get_pixel) {
    Surface s(4, 3);
    CHECK_EQ(s.width(), static_cast<uint16_t>(4));
    CHECK_EQ(s.height(), static_cast<uint16_t>(3));
    CHECK_EQ(s.size(), static_cast<size_t>(48));
    s.Fill(0x11, 0x22, 0x33, 0xFF);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK_EQ(g, static_cast<uint8_t>(0x22));
    CHECK_EQ(b, static_cast<uint8_t>(0x33));
    CHECK_EQ(a, static_cast<uint8_t>(0xFF));
    CHECK(!s.GetPixel(4, 0, r, g, b, a));  // out of bounds
    CHECK(!s.GetPixel(-1, 0, r, g, b, a));
}

RTSC_TEST(surface_blit_in_bounds) {
    Surface s(4, 4);
    // 2x2 red source.
    const std::vector<uint8_t> src(2 * 2 * 4, 0);
    std::vector<uint8_t> red = src;
    for (size_t i = 0; i < red.size(); i += 4) red[i] = 0xFF;  // R
    s.Blit(red.data(), 2, 2, 1, 1);

    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(1, 1, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xFF));
    CHECK(s.GetPixel(2, 2, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xFF));
    // Outside the blit is untouched (0).
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(3, 3, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(surface_blit_clips_to_surface) {
    Surface s(2, 2);
    // 4x4 green source placed at (-1,-1): the source covers the whole surface.
    std::vector<uint8_t> green(4 * 4 * 4, 0);
    for (size_t i = 0; i < green.size(); i += 4) green[i + 1] = 0x80;  // G
    s.Blit(green.data(), 4, 4, -1, -1);

    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 2; ++y) {
        for (int x = 0; x < 2; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(g, static_cast<uint8_t>(0x80));
        }
    }

    // A 1x1 red source placed at (1,1) overwrites just that pixel.
    std::vector<uint8_t> red = {0xFF, 0, 0, 0xFF};
    s.Blit(red.data(), 1, 1, 1, 1);
    CHECK(s.GetPixel(1, 1, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xFF));
    CHECK_EQ(g, static_cast<uint8_t>(0));

    // Fully off-screen blit is a no-op and must not crash.
    s.Blit(green.data(), 4, 4, 100, 100);
    s.Blit(nullptr, 4, 4, 0, 0);
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(g, static_cast<uint8_t>(0x80));  // unchanged
}

RTSC_TEST(window_headless_present_and_events) {
    std::string why;
    auto w = CreateWindow(8, 8, "headless", why);
    CHECK(w != nullptr);
    CHECK(why.empty());
    CHECK(std::string(w->backend_name()) == "headless");
    CHECK_EQ(w->surface().width(), static_cast<uint16_t>(8));

    w->surface().Fill(1, 2, 3, 4);
    w->Present();

    InputEvent ev;
    CHECK(!w->PollEvent(ev));  // empty queue

    InputEvent k;
    k.kind = InputEvent::Kind::kKey;
    k.scancode = 0x1E;
    w->PushEventForTest(k);
    CHECK(w->PollEvent(ev));
    CHECK(ev.kind == InputEvent::Kind::kKey);
    CHECK_EQ(ev.scancode, static_cast<uint8_t>(0x1E));
    CHECK(!w->PollEvent(ev));  // drained
}

RTSC_TEST(window_resize_changes_the_surface) {
    std::string why;
    auto w = CreateWindow(8, 8, "headless", why);
    CHECK(w != nullptr);
    CHECK_EQ(w->surface().width(), static_cast<uint16_t>(8));
    CHECK_EQ(w->surface().height(), static_cast<uint16_t>(8));

    w->Resize(16, 12);
    CHECK_EQ(w->surface().width(), static_cast<uint16_t>(16));
    CHECK_EQ(w->surface().height(), static_cast<uint16_t>(12));
    CHECK_EQ(w->surface().size(), static_cast<size_t>(16 * 12 * 4));

    // A zero size is rejected, not applied.
    w->Resize(0, 5);
    CHECK_EQ(w->surface().width(), static_cast<uint16_t>(16));
}

RTSC_TEST(window_rejects_unknown_backend_and_zero_size) {
    std::string why;
    auto w = CreateWindow(8, 8, "bogus-backend", why);
    CHECK(w == nullptr);
    CHECK(!why.empty());

    why.clear();
    auto z = CreateWindow(0, 8, "headless", why);
    CHECK(z == nullptr);
    CHECK(!why.empty());
}

RTSC_TEST(window_win32_backend_creates_a_window) {
#if defined(_WIN32)
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        // A session without an interactive desktop must fail with a reason, not
        // silently return a headless window.
        CHECK(!why.empty());
        return;
    }
    CHECK(std::string(w->backend_name()) == "win32");
    w->SetTitle("RTSC - zoom 100%");
    w->surface().Fill(10, 20, 30, 255);
    w->Present();
    // Resize must recreate the native backing store and keep Present working.
    w->Resize(80, 70);
    CHECK_EQ(w->surface().width(), static_cast<uint16_t>(80));
    CHECK_EQ(w->surface().height(), static_cast<uint16_t>(70));
    w->surface().Fill(1, 2, 3, 255);
    w->Present();
    w->Close();
    CHECK(w->closed());
#endif
}

RTSC_TEST(window_x11_backend_creates_a_window_or_reports_why) {
#if !defined(_WIN32) && defined(RTSC_UI_X11)
    std::string why;
    auto w = CreateWindow(64, 64, "x11", why);
    if (w == nullptr) {
        // No X server (headless CI): must fail with a reason, never silently
        // fall back to headless.
        CHECK(!why.empty());
        return;
    }
    CHECK(std::string(w->backend_name()) == "x11");
    w->surface().Fill(1, 2, 3, 4);
    w->Present();
    w->Close();
    CHECK(w->closed());
#endif
}

RTSC_TEST(window_wayland_backend_creates_a_window_or_reports_why) {
#if !defined(_WIN32) && defined(RTSC_UI_WAYLAND)
    std::string why;
    auto w = CreateWindow(64, 64, "wayland", why);
    if (w == nullptr) {
        // No Wayland compositor (headless CI): must fail with a reason.
        CHECK(!why.empty());
        return;
    }
    CHECK(std::string(w->backend_name()) == "wayland");
    w->surface().Fill(1, 2, 3, 4);
    w->Close();
    CHECK(w->closed());
#endif
}

int main() { return ::rtsc::test::run_all("rtsc_ui_tests"); }
