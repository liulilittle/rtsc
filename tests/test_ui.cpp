// UI surface and window abstraction.

#include "rtsc/ui/clipboard_bind.h"
#include "rtsc/ui/surface.h"
#include "rtsc/ui/window.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
// The windows.h CreateWindow{A,W} macro would shadow rtsc::ui::CreateWindow
// in the tests below; the raw PostMessageW/WMsg constants are all we need.
#undef CreateWindow
#endif

using namespace rtsc::ui;

namespace {

// A Window that records its clipboard callback so a test can prove which
// windows the GUI bound it to (the headless backend discards the callback).
class RecordingWindow final : public Window {
  public:
    RecordingWindow(int width, int height)
        : surface_(static_cast<uint16_t>(width),
                   static_cast<uint16_t>(height)) {}

    Surface& surface() override { return surface_; }
    void Present() override {}
    bool PollEvent(InputEvent&) override { return false; }
    void Close() override { closed_ = true; }
    bool closed() const override { return closed_; }
    const char* backend_name() const override { return "recording"; }
    void PushEventForTest(const InputEvent&) override {}

    void SetClipboardChangeCallback(std::function<void()> callback) override {
        clipboard_callback_ = std::move(callback);
        ++bind_count_;
    }

    // Fires the callback exactly as WM_CLIPBOARDUPDATE would.
    void FireClipboardChange() {
        if (clipboard_callback_) clipboard_callback_();
    }

    size_t bind_count() const { return bind_count_; }

  private:
    Surface surface_;
    std::function<void()> clipboard_callback_;
    bool closed_ = false;
    size_t bind_count_ = 0;
};

}  // namespace

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

#if defined(_WIN32)
RTSC_TEST(window_win32_key_input_reports_set1_scancodes) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        // A session without an interactive desktop must fail with a reason,
        // not silently return a headless window.
        CHECK(!why.empty());
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    // Real keyboard messages carry the set-1 scancode in lParam bits 16..23.
    // The RDP fast-path keyboard event needs that scancode, not the virtual
    // key code ('A' is VK 0x41 but its set-1 scancode is 0x1E; a VK sent as a
    // scancode types a different key on the remote desktop, e.g. 0x41 is F7).
    const WPARAM vk_a = 0x41;
    // WM_KEYDOWN 'A': repeat=1, scancode 0x1E, no context/previous/transition.
    const LPARAM lp_down = static_cast<LPARAM>(0x00000001u | (0x1Eu << 16));
    // WM_KEYUP: previous state + transition bits set, same scancode.
    const LPARAM lp_up = static_cast<LPARAM>(0xC0000001u | (0x1Eu << 16));
    PostMessageW(hwnd, WM_KEYDOWN, vk_a, lp_down);
    PostMessageW(hwnd, WM_KEYUP, vk_a, lp_up);

    // Automation may post VK-only messages whose lParam scancode field is 0.
    // The backend must fall back to the layout mapping (MapVirtualKey), which
    // for letters is layout-stable.
    const WPARAM vk_b = 0x42;  // 'B', set-1 scancode 0x30
    PostMessageW(hwnd, WM_KEYDOWN, vk_b, static_cast<LPARAM>(0xC0000001u));
    PostMessageW(hwnd, WM_KEYUP, vk_b, static_cast<LPARAM>(0xC0000001u));

    InputEvent ev;
    bool saw_a_down = false;
    bool saw_a_up = false;
    bool saw_b_down = false;
    while (w->PollEvent(ev)) {
        if (ev.kind != InputEvent::Kind::kKey) continue;
        if (ev.scancode == 0x1E && !ev.key_release) {
            saw_a_down = true;
            CHECK(!ev.key_extended);
        } else if (ev.scancode == 0x1E && ev.key_release) {
            saw_a_up = true;
        } else if (!ev.key_release) {
            // The VK-only 'B' press: scancode must come from the layout
            // mapping, never the VK code itself.
            saw_b_down = true;
            CHECK_EQ(ev.scancode, static_cast<uint8_t>(0x30));
            CHECK(ev.scancode != 0x42);
        }
    }
    CHECK(saw_a_down);
    CHECK(saw_a_up);
    CHECK(saw_b_down);
    w->Close();
    CHECK(w->closed());
}
#endif  // defined(_WIN32)

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

RTSC_TEST(clipboard_callback_binds_to_the_single_window) {
    std::vector<std::unique_ptr<Window>> windows;
    windows.push_back(std::make_unique<RecordingWindow>(1280, 1024));

    int fired = 0;
    BindClipboardToWindows(windows, [&] { ++fired; });

    CHECK_EQ(static_cast<RecordingWindow*>(windows[0].get())->bind_count(),
             static_cast<size_t>(1));
    static_cast<RecordingWindow*>(windows[0].get())->FireClipboardChange();
    CHECK_EQ(fired, 1);
}

RTSC_TEST(clipboard_callback_binds_to_every_window_after_a_rebuild) {
    // The multi-monitor path: the initial window is destroyed and one window per
    // monitor is created. The GUI binds after this rebuild, so every live window
    // must carry the callback.
    std::vector<std::unique_ptr<Window>> windows;
    windows.push_back(std::make_unique<RecordingWindow>(1280, 1024));

    int fired = 0;
    BindClipboardToWindows(windows, [&] { ++fired; });

    windows.clear();
    windows.push_back(std::make_unique<RecordingWindow>(1920, 1080));
    windows.push_back(std::make_unique<RecordingWindow>(1920, 1080));
    BindClipboardToWindows(windows, [&] { ++fired; });

    for (const auto& w : windows) {
        CHECK_EQ(static_cast<const RecordingWindow*>(w.get())->bind_count(),
                 static_cast<size_t>(1));
        static_cast<RecordingWindow*>(w.get())->FireClipboardChange();
    }
    CHECK_EQ(fired, 2);
}

RTSC_TEST(clipboard_callback_bound_before_a_rebuild_is_lost) {
    // RED (the defect this fixes): binding to windows[0] and then rebuilding the
    // window set leaves the live windows without a callback. This is why the
    // GUI binds after the rebuild, not before.
    std::vector<std::unique_ptr<Window>> windows;
    windows.push_back(std::make_unique<RecordingWindow>(1280, 1024));

    int fired = 0;
    BindClipboardToWindows(windows, [&] { ++fired; });

    windows.clear();
    windows.push_back(std::make_unique<RecordingWindow>(1920, 1080));
    static_cast<RecordingWindow*>(windows[0].get())->FireClipboardChange();

    CHECK_EQ(fired, 0);  // the rebuilt window never received the callback
}

int main() { return ::rtsc::test::run_all("rtsc_ui_tests"); }
