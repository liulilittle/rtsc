// UI surface and window abstraction.

#include "rtsc/ui/clipboard_bind.h"
#include "rtsc/ui/surface.h"
#include "rtsc/ui/window.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <string>
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

// An explicit, visible skip. A test case that cannot create a window (no
// interactive desktop, no display) must never read as a silent pass: the reason
// is asserted non-empty and printed with the SKIP marker so the log shows the
// case was not exercised. The harness still prints [ OK ] (nothing failed), so
// SKIP is the only signal -- which is the point.
[[maybe_unused]] void SkipTest(const char* test_name, const std::string& why) {
    CHECK(!why.empty());
    std::printf("  SKIP %s: %s\n", test_name, why.c_str());
}

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

RTSC_TEST(rgba_to_bgra_swaps_red_and_blue_and_preserves_green_alpha) {
    // A single pixel pair: bytes 0 (R) and 2 (B) swap, G and A stay put. The
    // vector path writes two pixels (8 bytes) per 64-bit word, so these two
    // pixels must cover the block path exactly.
    const uint8_t src[8] = {
        0x11, 0x22, 0x33, 0x44,  // pixel 0: R G B A
        0xAA, 0xBB, 0xCC, 0xDD,  // pixel 1
    };
    uint8_t dst[8] = {0};
    rtsc::ui::RgbaToBgra(dst, src, 2);
    CHECK_EQ(dst[0], static_cast<uint8_t>(0x33));  // B lands in byte 0
    CHECK_EQ(dst[1], static_cast<uint8_t>(0x22));  // G stays
    CHECK_EQ(dst[2], static_cast<uint8_t>(0x11));  // R lands in byte 2
    CHECK_EQ(dst[3], static_cast<uint8_t>(0x44));  // A stays
    CHECK_EQ(dst[4], static_cast<uint8_t>(0xCC));
    CHECK_EQ(dst[5], static_cast<uint8_t>(0xBB));
    CHECK_EQ(dst[6], static_cast<uint8_t>(0xAA));
    CHECK_EQ(dst[7], static_cast<uint8_t>(0xDD));

    // Zero pixels is a no-op and must not crash.
    rtsc::ui::RgbaToBgra(dst, src, 0);
    CHECK_EQ(dst[0], static_cast<uint8_t>(0x33));
}

RTSC_TEST(rgba_to_bgra_matches_the_per_pixel_reference_and_aliases_in_place) {
    // The vectorized conversion must be bit-identical to the old Present()
    // per-pixel loop over a full-size buffer, and must work on a buffer in
    // place (dst aliasing src is the DIB-backing-store reuse case).
    constexpr size_t kPx = 1280 * 1024;
    std::vector<uint8_t> src(kPx * 4);
    for (size_t i = 0; i < src.size(); ++i) {
        src[i] = static_cast<uint8_t>(i * 13 + 7);
    }
    std::vector<uint8_t> ref(kPx * 4);
    for (size_t i = 0; i + 3 < ref.size(); i += 4) {
        ref[i + 0] = src[i + 2];
        ref[i + 1] = src[i + 1];
        ref[i + 2] = src[i + 0];
        ref[i + 3] = src[i + 3];
    }
    std::vector<uint8_t> out(kPx * 4);
    rtsc::ui::RgbaToBgra(out.data(), src.data(), kPx);
    CHECK(out == ref);

    std::vector<uint8_t> inplace(src);
    rtsc::ui::RgbaToBgra(inplace.data(), inplace.data(), kPx);
    CHECK(inplace == ref);
}

RTSC_TEST(rgba_to_bgra_present_faster_than_the_old_per_pixel_loop) {
    // Performance regression guard for the Win32 Present() hot path. The real
    // check is RELATIVE: the vectorised RgbaToBgra must beat the old per-byte
    // reference loop on the same buffers in the same process, so the result is
    // load-independent (a slow or loaded CI host slows both equally) and a
    // rollback to the old scalar loop (measured ~0.8-1.0 ms) can never satisfy
    // it. The reference writes through a volatile pointer so no compiler can
    // auto-vectorise it into the fast path, which would make the baseline
    // unfairly fast on some toolchains. A coarse 5 ms absolute ceiling stays as
    // a sanity bound for unusably slow hosts only.
    constexpr size_t kPx = 1280 * 1024;
    constexpr size_t kBytes = kPx * 4;
    std::vector<uint8_t> src(kBytes);
    std::vector<uint8_t> dst_new(kBytes);
    std::vector<uint8_t> dst_ref(kBytes);
    for (size_t i = 0; i < src.size(); ++i) {
        src[i] = static_cast<uint8_t>(i * 3);
    }

#if defined(NDEBUG)
    // Median of kIters runs after a short warm-up.
    const auto median_us = [](auto&& fn) {
        for (int i = 0; i < 3; ++i) fn();
        constexpr int kIters = 30;
        std::vector<double> us;
        us.reserve(static_cast<size_t>(kIters));
        for (int i = 0; i < kIters; ++i) {
            const auto t0 = std::chrono::steady_clock::now();
            fn();
            const auto t1 = std::chrono::steady_clock::now();
            us.push_back(
                std::chrono::duration<double, std::micro>(t1 - t0).count());
        }
        std::sort(us.begin(), us.end());
        return us[kIters / 2];
    };

    const double ref_us = median_us([&] {
        volatile uint8_t* dv = dst_ref.data();
        const uint8_t* sv = src.data();
        for (size_t i = 0; i + 3 < kBytes; i += 4) {
            dv[i + 0] = sv[i + 2];
            dv[i + 1] = sv[i + 1];
            dv[i + 2] = sv[i + 0];
            dv[i + 3] = sv[i + 3];
        }
    });
    const double new_us = median_us([&] {
        rtsc::ui::RgbaToBgra(dst_new.data(), src.data(), kPx);
    });

    std::printf(
        "  rgba->bgra 1280x1024: reference %.1f us, vectorised %.1f us "
        "(ratio %.2f, limit 0.60)\n",
        ref_us, new_us, new_us / ref_us);
    CHECK(new_us <= 0.6 * ref_us);
    CHECK(new_us < 5000.0);
#else
    // Unoptimized build: -Od makes the scalar reference loop comparatively fast
    // (measured ratio ~0.78 against the 0.60 limit, three runs, deterministic),
    // so the RELATIVE claim this case exists to make is not observable here. It
    // is a build-type property, not a defect: say so instead of reporting a
    // pass, and keep the coverage in the optimized runs (ctest -C Release and
    // the gate's RelWithDebInfo phase, which runs this binary).
    std::printf("  skipped: relative timing requires an optimized build (NDEBUG)\n");
#endif  // NDEBUG
}

RTSC_TEST(rgba_to_bgra_mixes_64bit_block_and_32bit_tail) {
    // 3 pixels = 12 bytes: the 16-byte fast path cannot start, so the whole
    // buffer is processed by the 32-bit word tail (expected bytes come from the
    // old per-pixel reference: 0<->2 of each pixel swap).
    const std::vector<uint8_t> src3 = {1,  2,  3,  4,  5,  6,  7,  8,
                                       9,  10, 11, 12};
    std::vector<uint8_t> out3(12, 0);
    rtsc::ui::RgbaToBgra(out3.data(), src3.data(), 3);
    CHECK_BYTES(out3, 3, 2, 1, 4, 7, 6, 5, 8, 11, 10, 9, 12);

    // 5 pixels = 20 bytes: one 16-byte block and then a 4-byte 32-bit tail.
    const std::vector<uint8_t> src5 = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                       11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    std::vector<uint8_t> out5(20, 0);
    rtsc::ui::RgbaToBgra(out5.data(), src5.data(), 5);
    CHECK_BYTES(out5, 3, 2, 1, 4, 7, 6, 5, 8, 11, 10, 9, 12, 15, 14,
                13, 16, 19, 18, 17, 20);
}

RTSC_TEST(rgba_to_bgra_odd_pixel_count_in_place) {
    // Odd pixel counts exercise the trailing tail path with dst aliasing src
    // (the DIB Present path never converts in place, but in-place reuse is a
    // documented property of RgbaToBgra and must not corrupt the tail).
    std::vector<uint8_t> buf = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    const std::vector<uint8_t> ref = {3,  2,  1,  4,  7,  6,  5,  8,  11, 10,
                                      9,  12, 15, 14, 13, 16, 19, 18, 17, 20};
    rtsc::ui::RgbaToBgra(buf.data(), buf.data(), 5);
    CHECK(buf == ref);
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

RTSC_TEST(window_fullscreen_default_is_false) {
    // The base Window contract: fullscreen() is false until a backend flips it.
    // RecordingWindow does not override it, so this exercises the interface
    // default; the headless backend has no native window and keeps it too.
    std::string why;
    auto headless = CreateWindow(8, 8, "headless", why);
    CHECK(headless != nullptr);
    CHECK(!headless->fullscreen());

    std::vector<std::unique_ptr<Window>> windows;
    windows.push_back(std::make_unique<RecordingWindow>(8, 8));
    CHECK(!windows[0]->fullscreen());
    windows.pop_back();
    windows.push_back(std::move(headless));
    CHECK(!windows[0]->fullscreen());

    // Toggling over a backend with no native window is a safe no-op: it must
    // not crash and must not claim a state it cannot reach.
    rtsc::ui::ToggleFullscreen(windows);
    CHECK(!windows[0]->fullscreen());
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
        // silently return a headless window -- and the skip must be VISIBLE.
        SkipTest("window_win32_backend_creates_a_window", why);
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
RTSC_TEST(window_win32_fullscreen_tracks_state) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        // No interactive desktop: the backend cannot create a real window, so
        // the state tracking cannot be exercised either. The skip is VISIBLE.
        SkipTest("window_win32_fullscreen_tracks_state", why);
        return;
    }
    CHECK(!w->fullscreen());
    w->SetFullscreen(true);
    CHECK(w->fullscreen());
    w->SetFullscreen(false);
    CHECK(!w->fullscreen());
    // Re-entering fullscreen after a plain restore lands back on the state it
    // started from; asking for the same state again is a guarded no-op.
    w->SetFullscreen(true);
    CHECK(w->fullscreen());
    w->SetFullscreen(true);
    CHECK(w->fullscreen());
    w->Close();
    CHECK(w->closed());
}

RTSC_TEST(window_win32_toggle_fullscreen_flips_both_ways) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("window_win32_toggle_fullscreen_flips_both_ways", why);
        return;
    }
    // The front-end command dispatch (tools/rtsc_gui/main.cpp) toggles every
    // window from its own state on kCmdToggleFullscreen. Two toggles must land
    // back on the initial state, or the menu item cannot round-trip.
    std::vector<std::unique_ptr<Window>> windows;
    windows.push_back(std::move(w));
    CHECK(!windows[0]->fullscreen());
    rtsc::ui::ToggleFullscreen(windows);
    CHECK(windows[0]->fullscreen());
    rtsc::ui::ToggleFullscreen(windows);
    CHECK(!windows[0]->fullscreen());
    windows[0]->Close();
    CHECK(windows[0]->closed());
}
#endif  // defined(_WIN32)

#if defined(_WIN32)
namespace {

uint32_t VkToScancodeFake(uint32_t vk) {
    return vk == 0x42 ? 0x70u : 0u;  // 'B' -> a deliberately non-real scancode
}

uint32_t VkToScancodeNone(uint32_t) { return 0u; }

// The wire byte pair a translated key becomes in a Fast-Path keyboard event:
// eventHeader = eventFlags (eventCode 0, low 5 bits) then keyCode. test_ui
// links only rtsc_ui, so it cannot call rtsc::proto::EncodeKeyboardEvent; this
// mirrors that encoder's header layout ([MS-RDPBCGR] 2.2.8.1.2.2.1) for the
// input events the window backend emits.
std::string InputKeyBytes(const InputEvent& e) {
    const unsigned flags = (e.key_release ? 0x01u : 0u) |
                           (e.key_extended ? 0x02u : 0u);
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%02x%02x", flags, e.scancode);
    return buf;
}

// A real WM_KEY* message for set-1 scancode `sc`. Win keys are extended, so
// bit24 is set; key-up also carries the previous-state/transition bits.
LPARAM KeyLParam(uint8_t sc, bool extended, bool up) {
    uint32_t lp = (up ? 0xC0000001u : 1u) | (static_cast<uint32_t>(sc) << 16);
    if (extended) lp |= (1u << 24);
    return static_cast<LPARAM>(lp);
}

// Alt is a WM_SYSKEY* message with the context bit (bit 29) set.
LPARAM AltKeyLParam(bool up) {
    uint32_t lp = (up ? 0xC0000001u : 1u) | (0x38u << 16) | (1u << 29);
    return static_cast<LPARAM>(lp);
}

}  // namespace

RTSC_TEST(win32_key_translation_uses_the_lparam_scancode) {
    // WM_KEYDOWN 'A': repeat=1, set-1 scancode 0x1E, no extended bit.
    const KeyTranslation a = TranslateWin32KeyMessage(
        kWin32WmKeyDown, 0x41, static_cast<uint32_t>(0x1Eu << 16));
    CHECK(a.forward);
    CHECK_EQ(a.scancode, static_cast<uint8_t>(0x1E));
    CHECK(!a.extended);
    CHECK(!a.release);
    // Never the virtual-key code: 0x41 sent as a scancode types another key
    // (F7) on the remote.
    CHECK(a.scancode != 0x41);

    // WM_KEYUP carries the same scancode plus previous-state/transition bits.
    const KeyTranslation a_up = TranslateWin32KeyMessage(
        kWin32WmKeyUp, 0x41, 0xC0000001u | (0x1Eu << 16));
    CHECK(a_up.forward);
    CHECK_EQ(a_up.scancode, static_cast<uint8_t>(0x1E));
    CHECK(a_up.release);
}

RTSC_TEST(win32_key_translation_falls_back_to_the_layout_mapping) {
    // A VK-only synthetic message (lParam scancode field 0) falls back to the
    // layout mapper: MapVirtualKeyW(VK_TO_VSC) is layout-stable for letters, so
    // 'B' -> 0x30.
    const KeyTranslation b = TranslateWin32KeyMessage(kWin32WmKeyDown, 0x42, 0);
    CHECK(b.forward);
    CHECK_EQ(b.scancode, static_cast<uint8_t>(0x30));
    CHECK(b.scancode != 0x42);

    // The injected mapper is the one consulted when the field is 0.
    const KeyTranslation fake = TranslateWin32KeyMessage(
        kWin32WmKeyDown, 0x42, 0, &VkToScancodeFake);
    CHECK(fake.forward);
    CHECK_EQ(fake.scancode, static_cast<uint8_t>(0x70));

    // A mapper that cannot translate must DROP the event: forwarding scancode 0
    // would send a meaningless key instead of failing closed.
    const KeyTranslation none = TranslateWin32KeyMessage(
        kWin32WmKeyDown, 0x42, 0, &VkToScancodeNone);
    CHECK(!none.forward);
    CHECK_EQ(none.scancode, static_cast<uint8_t>(0));
}

RTSC_TEST(win32_key_translation_sets_the_extended_bit) {
    // Right Ctrl (VK_RCONTROL) is scancode 0x1D + extended; it must NOT be
    // confused with the AltGr pseudo Ctrl and dropped.
    const KeyTranslation rc = TranslateWin32KeyMessage(
        kWin32WmKeyDown, 0xA3, (0x1Du << 16) | (1u << 24));
    CHECK(rc.forward);
    CHECK_EQ(rc.scancode, static_cast<uint8_t>(0x1D));
    CHECK(rc.extended);

    // Left arrow: VK_LEFT, scancode 0x4B + extended.
    const KeyTranslation left = TranslateWin32KeyMessage(
        kWin32WmKeyDown, 0x25, (0x4Bu << 16) | (1u << 24));
    CHECK(left.forward);
    CHECK_EQ(left.scancode, static_cast<uint8_t>(0x4B));
    CHECK(left.extended);

    // A non-extended key keeps the flag clear.
    const KeyTranslation plain = TranslateWin32KeyMessage(
        kWin32WmKeyDown, 0x41, static_cast<uint32_t>(0x1Eu << 16));
    CHECK(!plain.extended);
}

RTSC_TEST(win32_real_numpad_keys_respect_lparam_bit24) {
    // A real message's bit24 is authoritative: numpad-off Home is scancode 0x47
    // WITHOUT the 0xE0 prefix even though the nav-cluster Home shares the
    // scancode. Previously the inherent-extended table forced ext=1 for every
    // VK_HOME regardless of the message, so numpad-off Home was remoted as a
    // nav-cluster Home and NumLock (0x45) as an extended key.
    const KeyTranslation home = TranslateWin32KeyMessage(
        kWin32WmKeyDown, VK_HOME, static_cast<uint32_t>(0x47u << 16));
    CHECK(home.forward);
    CHECK_EQ(home.scancode, static_cast<uint8_t>(0x47));
    CHECK(!home.extended);

    // numpad-on numpad7 reports the same scancode (0x47) with no extended bit.
    const KeyTranslation num7 = TranslateWin32KeyMessage(
        kWin32WmKeyDown, VK_NUMPAD7, static_cast<uint32_t>(0x47u << 16));
    CHECK(num7.forward);
    CHECK_EQ(num7.scancode, static_cast<uint8_t>(0x47));
    CHECK(!num7.extended);

    // A real NumLock press is scancode 0x45 (shared with Pause) and is never
    // extended.
    const KeyTranslation numlock = TranslateWin32KeyMessage(
        kWin32WmKeyDown, VK_NUMLOCK, static_cast<uint32_t>(0x45u << 16));
    CHECK(numlock.forward);
    CHECK_EQ(numlock.scancode, static_cast<uint8_t>(0x45));
    CHECK(!numlock.extended);

    // The nav-cluster End with bit24 set is extended.
    const KeyTranslation nav_end = TranslateWin32KeyMessage(
        kWin32WmKeyDown, VK_END, static_cast<uint32_t>((0x4Fu << 16) | (1u << 24)));
    CHECK(nav_end.forward);
    CHECK_EQ(nav_end.scancode, static_cast<uint8_t>(0x4F));
    CHECK(nav_end.extended);
}

RTSC_TEST(win32_synthetic_nav_keys_use_the_extended_table) {
    // A synthetic VK-only message (lParam scancode field 0) has no bit24, so it
    // falls back to the inherent-extended table: nav-cluster keys are extended,
    // NumLock and numpad digits are not.
    const KeyTranslation del = TranslateWin32KeyMessage(
        kWin32WmKeyDown, VK_DELETE, 0);
    CHECK(del.forward);
    CHECK(del.extended);

    const KeyTranslation home = TranslateWin32KeyMessage(
        kWin32WmKeyDown, VK_HOME, 0);
    CHECK(home.forward);
    CHECK_EQ(home.scancode, static_cast<uint8_t>(0x47));
    CHECK(home.extended);

    // Synthetic numpad7 (VK_NUMPAD7 maps to scancode 0x47) must stay
    // non-extended: it is the numpad digit, not the nav-cluster Home.
    const KeyTranslation num7 = TranslateWin32KeyMessage(
        kWin32WmKeyDown, VK_NUMPAD7, 0);
    CHECK(num7.forward);
    CHECK_EQ(num7.scancode, static_cast<uint8_t>(0x47));
    CHECK(!num7.extended);

    // Synthetic NumLock is never extended either (it was removed from the
    // inherent-extended table).
    const KeyTranslation numlock = TranslateWin32KeyMessage(
        kWin32WmKeyDown, VK_NUMLOCK, 0);
    CHECK(numlock.forward);
    CHECK_EQ(numlock.scancode, static_cast<uint8_t>(0x45));
    CHECK(!numlock.extended);
}

RTSC_TEST(win32_key_translation_altgr) {
    // AltGr = pseudo Ctrl + right Alt. The pseudo Ctrl (VK_CONTROL and
    // VK_LCONTROL with the extended bit) is suppressed so the remote does not
    // see Ctrl+AltGr chords.
    const KeyTranslation pseudo_ctrl = TranslateWin32KeyMessage(
        kWin32WmKeyDown, 0x11, (0x1Du << 16) | (1u << 24));
    CHECK(!pseudo_ctrl.forward);
    const KeyTranslation pseudo_lctrl = TranslateWin32KeyMessage(
        kWin32WmKeyUp, 0xA2, 0xC0000001u | (0x1Du << 16) | (1u << 24));
    CHECK(!pseudo_lctrl.forward);

    // Right Alt arrives as WM_SYSKEYDOWN(VK_RMENU) and is forwarded as set-1
    // 0x38 + extended.
    const KeyTranslation ralt = TranslateWin32KeyMessage(
        kWin32WmSysKeyDown, 0xA5, (0x38u << 16) | (1u << 24));
    CHECK(ralt.forward);
    CHECK_EQ(ralt.scancode, static_cast<uint8_t>(0x38));
    CHECK(ralt.extended);
    CHECK(!ralt.release);

    // The same key reported as VK_MENU + extended (WM_SYSKEYUP path).
    const KeyTranslation ralt_menu = TranslateWin32KeyMessage(
        kWin32WmSysKeyUp, 0x12, 0xC0000001u | (0x38u << 16) | (1u << 24));
    CHECK(ralt_menu.forward);
    CHECK_EQ(ralt_menu.scancode, static_cast<uint8_t>(0x38));
    CHECK(ralt_menu.extended);
    CHECK(ralt_menu.release);

    // Left Alt must stay non-extended 0x38.
    const KeyTranslation lalt = TranslateWin32KeyMessage(
        kWin32WmSysKeyDown, 0x12, static_cast<uint32_t>(0x38u << 16));
    CHECK(lalt.forward);
    CHECK_EQ(lalt.scancode, static_cast<uint8_t>(0x38));
    CHECK(!lalt.extended);

    // Alt+Tab is a WM_SYSKEYDOWN(VK_TAB) with the context bit; the generic
    // path must forward it as plain 0x0F.
    const KeyTranslation alt_tab = TranslateWin32KeyMessage(
        kWin32WmSysKeyDown, 0x09, 0x20000001u | (0x0Fu << 16));
    CHECK(alt_tab.forward);
    CHECK_EQ(alt_tab.scancode, static_cast<uint8_t>(0x0F));
    CHECK(!alt_tab.extended);

    // Alt+F4 (VK_F4 + context bit) is deliberately NOT forwarded: the backend
    // lets DefWindowProc turn it into the local WM_CLOSE, like mstsc does.
    const KeyTranslation alt_f4 = TranslateWin32KeyMessage(
        kWin32WmSysKeyDown, 0x73, 0x20000001u | (0x3Eu << 16));
    CHECK(!alt_f4.forward);

    // The bare F4 (no Alt) is an ordinary key and must be forwarded.
    const KeyTranslation f4 = TranslateWin32KeyMessage(
        kWin32WmKeyDown, 0x73, static_cast<uint32_t>(0x3Eu << 16));
    CHECK(f4.forward);
    CHECK_EQ(f4.scancode, static_cast<uint8_t>(0x3E));
}

RTSC_TEST(window_win32_forwards_system_keys_and_suppresses_altgr_ctrl) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("window_win32_forwards_system_keys_and_suppresses_altgr_ctrl",
                 why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    // AltGr, as Windows synthesises it: pseudo Ctrl down, right Alt down/up
    // (WM_SYSKEY*), pseudo Ctrl up.
    PostMessageW(hwnd, WM_KEYDOWN, VK_CONTROL,
                 static_cast<LPARAM>((0x1Du << 16) | (1u << 24)));
    PostMessageW(hwnd, WM_SYSKEYDOWN, VK_RMENU,
                 static_cast<LPARAM>((0x38u << 16) | (1u << 24)));
    PostMessageW(hwnd, WM_SYSKEYUP, VK_RMENU,
                 static_cast<LPARAM>(0xC0000001u | (0x38u << 16) | (1u << 24)));
    PostMessageW(hwnd, WM_KEYUP, VK_CONTROL,
                 static_cast<LPARAM>(0xC0000001u | (0x1Du << 16) | (1u << 24)));

    InputEvent ev;
    bool saw_ctrl = false;
    bool saw_ralt_down = false;
    bool saw_ralt_up = false;
    while (w->PollEvent(ev)) {
        if (ev.kind != InputEvent::Kind::kKey) continue;
        if (ev.scancode == 0x1D) saw_ctrl = true;
        if (ev.scancode == 0x38 && ev.key_extended) {
            if (ev.key_release) {
                saw_ralt_up = true;
            } else {
                saw_ralt_down = true;
            }
        }
    }
    CHECK(!saw_ctrl);      // pseudo Ctrl never reaches the remote
    CHECK(saw_ralt_down);  // right Alt does, so the remote sees AltGr
    CHECK(saw_ralt_up);
    w->Close();
}

#endif  // defined(_WIN32)

#if defined(_WIN32)
RTSC_TEST(window_win32_key_input_reports_set1_scancodes) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        // A session without an interactive desktop must fail with a reason,
        // not silently return a headless window.
        SkipTest("window_win32_key_input_reports_set1_scancodes", why);
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

RTSC_TEST(win32_ui_command_ids_are_distinct) {
    // The clash that shipped: "帮助" (kCmdHelp) and Ctrl+Alt+End
    // (kCmdSendCtrlAltDel) were both 19, so the Help item raised a SAS.
    // volatile keeps these out of constant-expression context so /W4 /WX does
    // not flag the checked condition as C4127.
    const volatile uint8_t help = kCmdHelp;
    const volatile uint8_t sas = kCmdSendCtrlAltDel;
    const volatile uint8_t win_mode = kCmdToggleWinKeyRemote;
    CHECK(help != sas);
    CHECK(help != win_mode);
    CHECK(sas != win_mode);
}

RTSC_TEST(win32_win_key_mode_gates_forwarding) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_win_key_mode_gates_forwarding", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    // kLocal: the Windows key belongs to the local shell; nothing is sent.
    w->SetWinKeyMode(WinKeyMode::kLocal);
    CHECK(w->win_key_mode() == WinKeyMode::kLocal);
    PostMessageW(hwnd, WM_KEYDOWN, VK_LWIN, KeyLParam(0x5B, true, false));
    PostMessageW(hwnd, WM_KEYUP, VK_LWIN, KeyLParam(0x5B, true, true));
    InputEvent ev;
    bool saw_win = false;
    while (w->PollEvent(ev)) {
        if (ev.kind == InputEvent::Kind::kKey && ev.scancode == 0x5B) {
            saw_win = true;
        }
    }
    CHECK(!saw_win);

    // kRemote: forward the key. The translated events must encode as the
    // set-1 extended scancode: 02 5B (down) / 03 5B (up).
    w->SetWinKeyMode(WinKeyMode::kRemote);
    CHECK(w->win_key_mode() == WinKeyMode::kRemote);
    PostMessageW(hwnd, WM_KEYDOWN, VK_LWIN, KeyLParam(0x5B, true, false));
    PostMessageW(hwnd, WM_KEYUP, VK_LWIN, KeyLParam(0x5B, true, true));
    std::string down_bytes;
    std::string up_bytes;
    while (w->PollEvent(ev)) {
        if (ev.kind != InputEvent::Kind::kKey || ev.scancode != 0x5B) continue;
        (ev.key_release ? up_bytes : down_bytes) = InputKeyBytes(ev);
    }
    CHECK(down_bytes == "025b");
    CHECK(up_bytes == "035b");
    w->Close();
}

RTSC_TEST(win32_focus_loss_releases_held_modifiers) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_focus_loss_releases_held_modifiers", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);
    w->SetWinKeyMode(WinKeyMode::kRemote);

    PostMessageW(hwnd, WM_KEYDOWN, VK_LCONTROL, KeyLParam(0x1D, false, false));
    PostMessageW(hwnd, WM_KEYDOWN, VK_SHIFT, KeyLParam(0x2A, false, false));
    InputEvent ev;
    while (w->PollEvent(ev)) {
    }
    PostMessageW(hwnd, WM_KILLFOCUS, 0, 0);

    bool ctrl_up = false;
    bool shift_up = false;
    while (w->PollEvent(ev)) {
        if (ev.kind != InputEvent::Kind::kKey || !ev.key_release) continue;
        if (ev.scancode == 0x1D) ctrl_up = true;
        if (ev.scancode == 0x2A) shift_up = true;
    }
    CHECK(ctrl_up);
    CHECK(shift_up);
    w->Close();
}

RTSC_TEST(win32_win_down_without_up_is_released_on_focus_loss) {
    // The shell consumes WM_KEYUP for the Windows key (probe: only the down
    // reaches the window), so a remote session would latch Win forever unless
    // the backend releases every forwarded-down key on focus loss.
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_win_down_without_up_is_released_on_focus_loss", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);
    w->SetWinKeyMode(WinKeyMode::kRemote);

    PostMessageW(hwnd, WM_KEYDOWN, VK_LWIN, KeyLParam(0x5B, true, false));
    InputEvent ev;
    while (w->PollEvent(ev)) {
    }
    PostMessageW(hwnd, WM_KILLFOCUS, 0, 0);

    std::string up_bytes;
    while (w->PollEvent(ev)) {
        if (ev.kind == InputEvent::Kind::kKey && ev.scancode == 0x5B &&
            ev.key_release) {
            up_bytes = InputKeyBytes(ev);
        }
    }
    CHECK(up_bytes == "035b");
    w->Close();
}

RTSC_TEST(win32_close_releases_held_alt) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_close_releases_held_alt", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    PostMessageW(hwnd, WM_SYSKEYDOWN, VK_MENU, AltKeyLParam(false));
    InputEvent ev;
    while (w->PollEvent(ev)) {
    }
    PostMessageW(hwnd, WM_CLOSE, 0, 0);

    bool alt_up = false;
    while (w->PollEvent(ev)) {
        if (ev.kind == InputEvent::Kind::kKey && ev.scancode == 0x38 &&
            ev.key_release) {
            alt_up = true;
        }
    }
    CHECK(alt_up);
}

RTSC_TEST(win32_ctrl_alt_end_raises_sas_and_swallows_end) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_ctrl_alt_end_raises_sas_and_swallows_end", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);
    w->SetWinKeyMode(WinKeyMode::kRemote);

    PostMessageW(hwnd, WM_KEYDOWN, VK_LCONTROL, KeyLParam(0x1D, false, false));
    PostMessageW(hwnd, WM_SYSKEYDOWN, VK_MENU, AltKeyLParam(false));
    PostMessageW(hwnd, WM_KEYDOWN, VK_END, KeyLParam(0x4F, true, false));
    PostMessageW(hwnd, WM_KEYUP, VK_END, KeyLParam(0x4F, true, true));
    PostMessageW(hwnd, WM_SYSKEYUP, VK_MENU, AltKeyLParam(true));
    PostMessageW(hwnd, WM_KEYUP, VK_LCONTROL, KeyLParam(0x1D, false, true));

    int sas_commands = 0;
    bool saw_end = false;
    InputEvent ev;
    while (w->PollEvent(ev)) {
        if (ev.kind == InputEvent::Kind::kUiCommand &&
            ev.command == kCmdSendCtrlAltDel) {
            ++sas_commands;
        }
        if (ev.kind == InputEvent::Kind::kKey && ev.scancode == 0x4F) {
            saw_end = true;
        }
    }
    CHECK_EQ(sas_commands, 1);
    CHECK(!saw_end);
    w->Close();
}

RTSC_TEST(win32_synthetic_win_key_is_extended) {
    // A synthetic VK-only WM_KEYDOWN (lParam scancode field 0) must still mark
    // the Windows key extended: its 0xE0 prefix is inherent to the key, not
    // carried in bit24 of a message Windows synthesised.
    const KeyTranslation win = TranslateWin32KeyMessage(kWin32WmKeyDown, VK_LWIN, 0);
    CHECK(win.forward);
    CHECK_EQ(win.scancode, static_cast<uint8_t>(0x5B));
    CHECK(win.extended);
}

RTSC_TEST(win32_non_keyboard_messages_are_ignored) {
    // WM_CHAR / WM_MOUSEMOVE are not keyboard transitions and must never be
    // forwarded as key-downs (they would type or latch keys on the remote).
    const KeyTranslation chr = TranslateWin32KeyMessage(
        0x0102u, 'A', static_cast<uint32_t>(0x1Eu << 16));
    CHECK(!chr.forward);
    const KeyTranslation mouse = TranslateWin32KeyMessage(0x0200u, 0, 0);
    CHECK(!mouse.forward);
}

RTSC_TEST(win32_ime_processkey_uses_the_lparam_scancode) {
    // With an IME active Windows may report VK_PROCESSKEY (0xE5) as wParam;
    // the real key is still in lParam bits 16..23.
    const KeyTranslation ime = TranslateWin32KeyMessage(
        kWin32WmKeyDown, 0xE5u, static_cast<uint32_t>(0x1Eu << 16));
    CHECK(ime.forward);
    CHECK_EQ(ime.scancode, static_cast<uint8_t>(0x1E));

    // With no scancode in lParam there is nothing real to send: never map
    // VK_PROCESSKEY through the layout mapper (it yields garbage).
    const KeyTranslation none =
        TranslateWin32KeyMessage(kWin32WmKeyDown, 0xE5u, 0);
    CHECK(!none.forward);
}
#endif  // defined(_WIN32)

#if defined(_WIN32)
RTSC_TEST(win32_mouse_negative_coordinates_clamp_to_zero) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_mouse_negative_coordinates_clamp_to_zero", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    // A pointer at (-5,-3): the 16-bit lParam fields read as 0xFFFB/0xFFFD,
    // which wrapped to 65531/65533 when cast straight to uint16_t.
    const LPARAM lp = MAKELPARAM(-5, -3);
    PostMessageW(hwnd, WM_MOUSEMOVE, 0, lp);

    InputEvent ev;
    bool saw_move = false;
    while (w->PollEvent(ev)) {
        if (ev.kind != InputEvent::Kind::kMouseMove) continue;
        saw_move = true;
        CHECK_EQ(ev.x, static_cast<uint16_t>(0));
        CHECK_EQ(ev.y, static_cast<uint16_t>(0));
    }
    CHECK(saw_move);
    w->Close();
}

RTSC_TEST(win32_button_negative_coordinates_clamp_to_zero) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_button_negative_coordinates_clamp_to_zero", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    PostMessageW(hwnd, WM_LBUTTONDOWN,
                 static_cast<WPARAM>(MK_LBUTTON),
                 static_cast<LPARAM>(MAKELPARAM(-2, -4)));
    PostMessageW(hwnd, WM_LBUTTONUP, 0,
                 static_cast<LPARAM>(MAKELPARAM(-2, -4)));

    InputEvent ev;
    bool down = false;
    bool up = false;
    while (w->PollEvent(ev)) {
        if (ev.kind != InputEvent::Kind::kMouseButton || ev.button != 1) continue;
        if (ev.button_down) {
            down = true;
            CHECK_EQ(ev.x, static_cast<uint16_t>(0));
            CHECK_EQ(ev.y, static_cast<uint16_t>(0));
        } else {
            up = true;
        }
    }
    CHECK(down);
    CHECK(up);
    w->Close();
}

RTSC_TEST(win32_capture_released_after_last_button_up) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_capture_released_after_last_button_up", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    // The first press installs the capture; the last release drops it.
    PostMessageW(hwnd, WM_LBUTTONDOWN, MK_LBUTTON,
                 static_cast<LPARAM>(MAKELPARAM(10, 10)));
    // Poll the down so the message is dispatched (the capture calls happen in
    // the backend, not on PostMessageW).
    InputEvent ev;
    while (w->PollEvent(ev)) {
    }
    CHECK(::GetCapture() == hwnd);

    PostMessageW(hwnd, WM_LBUTTONUP, 0, static_cast<LPARAM>(MAKELPARAM(10, 10)));
    while (w->PollEvent(ev)) {
    }
    CHECK(::GetCapture() != hwnd);

    // Two buttons held at once: capture stays until the second one is up.
    PostMessageW(hwnd, WM_LBUTTONDOWN, MK_LBUTTON,
                 static_cast<LPARAM>(MAKELPARAM(10, 10)));
    PostMessageW(hwnd, WM_RBUTTONDOWN, MK_RBUTTON,
                 static_cast<LPARAM>(MAKELPARAM(12, 12)));
    while (w->PollEvent(ev)) {
    }
    CHECK(::GetCapture() == hwnd);
    PostMessageW(hwnd, WM_RBUTTONUP, 0, static_cast<LPARAM>(MAKELPARAM(12, 12)));
    while (w->PollEvent(ev)) {
    }
    CHECK(::GetCapture() == hwnd);  // left is still held
    PostMessageW(hwnd, WM_LBUTTONUP, 0, static_cast<LPARAM>(MAKELPARAM(10, 10)));
    while (w->PollEvent(ev)) {
    }
    CHECK(::GetCapture() != hwnd);
    w->Close();
}

RTSC_TEST(win32_capture_changed_synthesises_missing_button_up) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_capture_changed_synthesises_missing_button_up", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    // A drag that ends because the capture is stolen (another window took it)
    // never delivers the release; the backend must synthesise the up so the
    // remote does not stay in a drag.
    const LPARAM down_lp = static_cast<LPARAM>(MAKELPARAM(10, 10));
    PostMessageW(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, down_lp);
    InputEvent ev;
    bool left_down = false;
    bool left_up = false;
    while (w->PollEvent(ev)) {
        if (ev.kind != InputEvent::Kind::kMouseButton || ev.button != 1) continue;
        if (ev.button_down) left_down = true;
        else left_up = true;
    }
    PostMessageW(hwnd, WM_CAPTURECHANGED, 0, 0);
    PostMessageW(hwnd, WM_XBUTTONDOWN, MAKEWPARAM(MK_XBUTTON1, XBUTTON1),
                 static_cast<LPARAM>(MAKELPARAM(20, 20)));

    bool x1_down = false;
    InputEvent e;
    while (w->PollEvent(e)) {
        if (e.kind != InputEvent::Kind::kMouseButton) continue;
        if (e.button == 1 && e.button_down) {
            left_down = true;
        } else if (e.button == 1) {
            left_up = true;
        } else if (e.button == 4 && e.button_down) {
            x1_down = true;
        }
    }
    CHECK(left_down);
    CHECK(left_up);   // synthesised by WM_CAPTURECHANGED
    CHECK(x1_down);   // a fresh press still works after the capture change
    w->Close();
}

RTSC_TEST(win32_focus_loss_releases_held_mouse_buttons) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_focus_loss_releases_held_mouse_buttons", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    PostMessageW(hwnd, WM_LBUTTONDOWN, MK_LBUTTON,
                 static_cast<LPARAM>(MAKELPARAM(10, 10)));
    InputEvent ev;
    bool left_down = false;
    bool left_up = false;
    while (w->PollEvent(ev)) {
        if (ev.kind != InputEvent::Kind::kMouseButton || ev.button != 1) continue;
        if (ev.button_down) left_down = true;
        else left_up = true;
    }
    PostMessageW(hwnd, WM_ACTIVATE, static_cast<WPARAM>(WA_INACTIVE), 0);

    while (w->PollEvent(ev)) {
        if (ev.kind != InputEvent::Kind::kMouseButton || ev.button != 1) continue;
        if (ev.button_down) left_down = true;
        else left_up = true;
    }
    CHECK(left_down);
    CHECK(left_up);
    w->Close();
}

RTSC_TEST(win32_wheel_event_reads_coordinates_from_lparam) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_wheel_event_reads_coordinates_from_lparam", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    // WM_MOUSEWHEEL/HWHEEL carry the *screen* position in lParam; the backend
    // converts it back to client coordinates. Reading wp instead produced
    // (0,0) for every wheel event. A client point 100,100 -> screen must come
    // back as exactly 100,100 regardless of where the window sits.
    POINT pt{100, 100};
    CHECK(::ClientToScreen(hwnd, &pt) != 0);
    PostMessageW(hwnd, WM_MOUSEWHEEL,
                 static_cast<WPARAM>(MAKEWPARAM(0, WHEEL_DELTA)),
                 static_cast<LPARAM>(MAKELPARAM(pt.x, pt.y)));
    PostMessageW(hwnd, WM_MOUSEHWHEEL,
                 static_cast<WPARAM>(MAKEWPARAM(0, WHEEL_DELTA)),
                 static_cast<LPARAM>(MAKELPARAM(pt.x, pt.y)));

    bool saw_vertical = false;
    bool saw_horizontal = false;
    InputEvent e;
    while (w->PollEvent(e)) {
        if (e.kind != InputEvent::Kind::kMouseWheel) continue;
        CHECK_EQ(e.x, static_cast<uint16_t>(100));
        CHECK_EQ(e.y, static_cast<uint16_t>(100));
        CHECK_EQ(e.wheel_delta, static_cast<int16_t>(1));
        if (e.horizontal) saw_horizontal = true;
        else saw_vertical = true;
    }
    CHECK(saw_vertical);
    CHECK(saw_horizontal);
    w->Close();
}

RTSC_TEST(win32_xbuttons_forward_as_buttons_four_and_five) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_xbuttons_forward_as_buttons_four_and_five", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    PostMessageW(hwnd, WM_XBUTTONDOWN, MAKEWPARAM(MK_XBUTTON1, XBUTTON1),
                 static_cast<LPARAM>(MAKELPARAM(5, 6)));
    PostMessageW(hwnd, WM_XBUTTONUP, MAKEWPARAM(MK_XBUTTON1, XBUTTON1),
                 static_cast<LPARAM>(MAKELPARAM(5, 6)));
    PostMessageW(hwnd, WM_XBUTTONDOWN, MAKEWPARAM(MK_XBUTTON2, XBUTTON2),
                 static_cast<LPARAM>(MAKELPARAM(7, 8)));
    PostMessageW(hwnd, WM_XBUTTONUP, MAKEWPARAM(MK_XBUTTON2, XBUTTON2),
                 static_cast<LPARAM>(MAKELPARAM(7, 8)));

    bool x1_down = false, x1_up = false, x2_down = false, x2_up = false;
    InputEvent e;
    while (w->PollEvent(e)) {
        if (e.kind != InputEvent::Kind::kMouseButton) continue;
        if (e.button == 4) {
            if (e.button_down) x1_down = true;
            else x1_up = true;
        } else if (e.button == 5) {
            if (e.button_down) x2_down = true;
            else x2_up = true;
        }
    }
    CHECK(x1_down);
    CHECK(x1_up);
    CHECK(x2_down);
    CHECK(x2_up);
    w->Close();
}
#endif  // defined(_WIN32)

#if defined(_WIN32)
RTSC_TEST(win32_pause_command_repeats_after_focus_loss) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_pause_command_repeats_after_focus_loss", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    // First Pause press without a release: the command is raised once and
    // pause_down_ is set.
    PostMessageW(hwnd, WM_KEYDOWN, VK_PAUSE, KeyLParam(0x45, false, false));
    InputEvent ev;
    int commands = 0;
    while (w->PollEvent(ev)) {
        if (ev.kind == InputEvent::Kind::kUiCommand && ev.command == kCmdSendPause) {
            ++commands;
        }
    }
    CHECK_EQ(commands, 1);

    // Focus is lost while Pause is still "down"; the backend must reset its
    // press latch so the next Pause after refocus raises the command again
    // (ReleaseHeldKeys previously left pause_down_ stuck true).
    PostMessageW(hwnd, WM_KILLFOCUS, 0, 0);
    while (w->PollEvent(ev)) {
    }
    PostMessageW(hwnd, WM_KEYDOWN, VK_PAUSE, KeyLParam(0x45, false, false));
    while (w->PollEvent(ev)) {
        if (ev.kind == InputEvent::Kind::kUiCommand && ev.command == kCmdSendPause) {
            ++commands;
        }
    }
    CHECK_EQ(commands, 2);
    w->Close();
}

RTSC_TEST(win32_wheel_accumulates_sub_notch_deltas) {
    std::string why;
    auto w = CreateWindow(64, 64, "win32", why);
    if (w == nullptr) {
        SkipTest("win32_wheel_accumulates_sub_notch_deltas", why);
        return;
    }
    const HWND hwnd = static_cast<HWND>(w->native_handle());
    CHECK(hwnd != nullptr);

    POINT origin{0, 0};
    CHECK(::ClientToScreen(hwnd, &origin) != 0);
    const LPARAM lp = static_cast<LPARAM>(MAKELPARAM(origin.x, origin.y));

    int events = 0;
    int last_delta = 0;
    const auto drain = [&]() {
        InputEvent e;
        while (w->PollEvent(e)) {
            if (e.kind != InputEvent::Kind::kMouseWheel) continue;
            ++events;
            last_delta = e.wheel_delta;
        }
    };

    // Two sub-notch ticks (40 + 40 < 120) must not emit anything: the old
    // integer division truncated 40/120 to 0.
    PostMessageW(hwnd, WM_MOUSEWHEEL, static_cast<WPARAM>(MAKEWPARAM(0, 40)), lp);
    PostMessageW(hwnd, WM_MOUSEWHEEL, static_cast<WPARAM>(MAKEWPARAM(0, 40)), lp);
    drain();
    CHECK_EQ(events, 0);

    // A third tick crosses the notch: exactly one event, delta +1.
    PostMessageW(hwnd, WM_MOUSEWHEEL, static_cast<WPARAM>(MAKEWPARAM(0, 40)), lp);
    drain();
    CHECK_EQ(events, 1);
    CHECK_EQ(last_delta, 1);

    // A full notch arrives as one event too.
    PostMessageW(hwnd, WM_MOUSEWHEEL, static_cast<WPARAM>(MAKEWPARAM(0, 120)), lp);
    drain();
    CHECK_EQ(events, 2);
    CHECK_EQ(last_delta, 1);

    // Downward sub-notch accumulation produces a negative event only when the
    // full -120 is crossed.
    PostMessageW(hwnd, WM_MOUSEWHEEL, static_cast<WPARAM>(MAKEWPARAM(0, -40)), lp);
    PostMessageW(hwnd, WM_MOUSEWHEEL, static_cast<WPARAM>(MAKEWPARAM(0, -40)), lp);
    drain();
    CHECK_EQ(events, 2);
    PostMessageW(hwnd, WM_MOUSEWHEEL, static_cast<WPARAM>(MAKEWPARAM(0, -40)), lp);
    drain();
    CHECK_EQ(events, 3);
    CHECK_EQ(last_delta, -1);
    w->Close();
}

RTSC_TEST(win32_key_state_sas_repeat_does_not_raise_sas) {
    // Pre-pressed End (already forwarded, tracked in down_), then Ctrl+Alt join
    // the chord, then the hardware auto-repeat of End arrives. The repeat must
    // NOT raise a second SAS, and the genuine release must still forward the
    // End up so the tracking set is drained (the old code latched sas_end_held_
    // on the repeat, swallowed the up and left a stale End in down_).
    Win32KeyState ks;
    KeyTranslation end_down;
    end_down.forward = true;
    end_down.scancode = kWin32ScancodeEnd;
    end_down.extended = true;
    KeyTranslation end_up = end_down;
    end_up.release = true;
    KeyTranslation ctrl;
    ctrl.forward = true;
    ctrl.scancode = kWin32ScancodeCtrl;
    KeyTranslation alt;
    alt.forward = true;
    alt.scancode = kWin32ScancodeAlt;

    CHECK(ks.Process(end_down) == Win32KeyAction::kForward);  // pre-pressed
    CHECK(ks.Process(ctrl) == Win32KeyAction::kForward);
    CHECK(ks.Process(alt) == Win32KeyAction::kForward);
    CHECK(ks.Process(end_down) == Win32KeyAction::kForward);  // repeat: not SAS
    CHECK_EQ(ks.down_count(), static_cast<size_t>(3));        // End+Ctrl+Alt held
    CHECK(ks.Process(end_up) == Win32KeyAction::kForward);    // real release passes
    CHECK_EQ(ks.down_count(), static_cast<size_t>(2));        // Ctrl+Alt only: no leak
}

RTSC_TEST(win32_key_state_sas_swallows_only_fresh_end_press) {
    // The standard chord: Ctrl+Alt down first, then a fresh End down raises the
    // SAS command and its up is swallowed (the key was never forwarded, so no
    // up must reach the remote either).
    Win32KeyState ks;
    KeyTranslation end_down;
    end_down.forward = true;
    end_down.scancode = kWin32ScancodeEnd;
    end_down.extended = true;
    KeyTranslation end_up = end_down;
    end_up.release = true;
    KeyTranslation ctrl;
    ctrl.forward = true;
    ctrl.scancode = kWin32ScancodeCtrl;
    KeyTranslation alt;
    alt.forward = true;
    alt.scancode = kWin32ScancodeAlt;

    CHECK(ks.Process(ctrl) == Win32KeyAction::kForward);
    CHECK(ks.Process(alt) == Win32KeyAction::kForward);
    CHECK(ks.Process(end_down) == Win32KeyAction::kSendCtrlAltDel);
    CHECK_EQ(ks.down_count(), static_cast<size_t>(2));  // End was not forwarded
    CHECK(ks.Process(end_up) == Win32KeyAction::kIgnore);
}
#endif  // defined(_WIN32)

RTSC_TEST(window_x11_backend_creates_a_window_or_reports_why) {
#if !defined(_WIN32) && defined(RTSC_UI_X11)
    std::string why;
    auto w = CreateWindow(64, 64, "x11", why);
    if (w == nullptr) {
        // No X server (headless CI): must fail with a reason, never silently
        // fall back to headless -- and the skip must be VISIBLE.
        SkipTest("window_x11_backend_creates_a_window_or_reports_why", why);
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
        // No Wayland compositor (headless CI): must fail with a reason -- and
        // the skip must be VISIBLE.
        SkipTest("window_wayland_backend_creates_a_window_or_reports_why", why);
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

RTSC_TEST(gui_dispatch_explicitly_consumes_fullscreen_command) {
    // The rtsc_gui executable cannot be linked into the suite (its main() runs
    // a full RDP client, network included), so its input dispatch is guarded
    // structurally: the kUiCommand branch must explicitly own
    // kCmdToggleFullscreen and run the window toggle, or the command silently
    // falls through EncodeInput's {}-returning default and the "目标" menu item
    // becomes the N1 no-op. This is the regression guard for that dispatch.
    std::ifstream in(RTSC_SOURCE_DIR "/tools/rtsc_gui/main.cpp");
    if (!in) {
        SkipTest("gui_dispatch_explicitly_consumes_fullscreen_command",
                 "cannot open tools/rtsc_gui/main.cpp");
        return;
    }
    const std::string src((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    CHECK(src.find("kCmdToggleFullscreen") != std::string::npos);
    CHECK(src.find("ToggleFullscreen(") != std::string::npos);
}

RTSC_TEST(gui_dispatch_explicitly_consumes_connection_info_command) {
    // The rtsc_gui executable cannot be linked into the suite (its main() runs
    // a full RDP client, network included), so its input dispatch is guarded
    // structurally: the kUiCommand branch must explicitly own
    // kCmdConnectionInfo and run the dialog, or the command silently falls
    // through EncodeInput's {}-returning default and the "连接信息(C)" menu
    // item becomes the N2 no-op. This is the regression guard for that
    // dispatch: the command must appear before the dialog call in the branch
    // body, followed by the continue that keeps it off the send path.
    std::ifstream in(RTSC_SOURCE_DIR "/tools/rtsc_gui/main.cpp");
    if (!in) {
        SkipTest("gui_dispatch_explicitly_consumes_connection_info_command",
                 "cannot open tools/rtsc_gui/main.cpp");
        return;
    }
    const std::string src((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    const size_t cmd = src.find("kCmdConnectionInfo");
    const size_t call = src.find("ShowConnectionInfoDialog(nullptr");
    const size_t collect = src.find("CollectSessionInfo(");
    const size_t cont = src.find("continue", call);
    CHECK(cmd != std::string::npos);
    CHECK(call != std::string::npos);
    CHECK(collect != std::string::npos);
    CHECK(cont != std::string::npos);
    CHECK(cmd < call);  // the command gates the dialog call in the branch
    CHECK(call < cont);  // the dialog/send path is skipped with a continue
}

RTSC_TEST(conninfo_dialog_wndproc_passes_real_hwnd_to_defwindowproc) {
    // Regression for a window that never appeared: the connection-information
    // dialog's WndProc forwarded messages to DefWindowProcW using the *member*
    // hwnd_, which is still nullptr while WM_NCCREATE is being handled (the
    // assignment only happens after CreateWindowExW returns). DefWindowProcW
    // with a null HWND returns FALSE for WM_NCCREATE, which aborts creation,
    // so CreateWindowExW returned nullptr with ERROR_INVALID_WINDOW_HANDLE
    // (1400) and the "连接信息(C)" menu item looked like a no-op.
    //
    // The dialog cannot be linked into this suite (it lives in the rtsc_gui
    // executable), so the guard is structural: the message handler must take
    // the HWND it was given and forward THAT to DefWindowProcW. Both properties
    // are checked because either alone can regress silently.
    std::ifstream in(RTSC_SOURCE_DIR
                     "/tools/rtsc_gui/connection_info_dialog_win32.cpp");
    if (!in) {
        SkipTest("conninfo_dialog_wndproc_passes_real_hwnd_to_defwindowproc",
                 "cannot open connection_info_dialog_win32.cpp");
        return;
    }
    const std::string src((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    // The handler must accept the window handle as a parameter...
    CHECK(src.find("Handle(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)") !=
          std::string::npos);
    // ...and that parameter (not the member) must reach DefWindowProcW.
    CHECK(src.find("DefWindowProcW(hwnd, msg, wp, lp)") !=
          std::string::npos);
    CHECK(src.find("DefWindowProcW(hwnd_, msg, wp, lp)") == std::string::npos);
    // The WndProc above it must forward the handle it received.
    CHECK(src.find("self->Handle(hwnd, msg, wp, lp)") != std::string::npos);
}

RTSC_TEST(gui_dispatch_explicitly_consumes_help_command) {
    // The View/title-bar menu raises kCmdHelp for "帮助(H)". Until this batch
    // the command had NO consumer anywhere in the GUI: the menu item pushed the
    // event and it was dropped on the send path (EncodeInput turns kUiCommand
    // into nothing), so clicking Help did nothing at all.
    //
    // The dialog cannot be linked into this suite (it lives in rtsc_gui), so the
    // dispatch is guarded structurally, the same way the fullscreen and
    // connection-info commands are: the branch must appear, it must come before
    // the generic send path, and it must end with a continue so a UI command
    // never reaches EncodeInput.
    std::ifstream in(RTSC_SOURCE_DIR "/tools/rtsc_gui/main.cpp");
    if (!in) {
        SkipTest("gui_dispatch_explicitly_consumes_help_command",
                 "cannot open tools/rtsc_gui/main.cpp");
        return;
    }
    const std::string src((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    const size_t cmd = src.find("kCmdHelp");
    const size_t call = src.find("ShowHelpDialog(");
    CHECK(cmd != std::string::npos);
    CHECK(call != std::string::npos);
    CHECK(cmd < call);  // the command gates the dialog call
    // The branch must be skipped from the generic send path.
    const size_t cont = src.find("continue", call);
    CHECK(cont != std::string::npos);
    // And it must be reachable before the send call, not after it.
    const size_t send = src.find("client.SendInput(", call);
    CHECK(send == std::string::npos || cont < send);
}

int main() { return ::rtsc::test::run_all("rtsc_ui_tests"); }
