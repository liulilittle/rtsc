// Pure mapping tests for the desktop input injection seam.
//
// TranslateInput() is platform neutral by design: it never includes
// <windows.h> and never calls SendInput, so these cases run on every platform
// and pin the wire semantics that the Win32 backend relies on. Expected values
// come from docs/spec/input-injection-seam.md (P-1..P-8) and
// docs/spec/input-injection-evidence.md (1.3-1.7).

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "rtsc/server/desktop_input_map.h"
#include "test_framework.h"
#include "test_main.h"

#if defined(RTSC_DESKTOP_INPUT_TESTING)
#include "desktop_input_win32_test_hooks.h"
#endif

namespace {

using rtsc::server::AdmitAndTrack;
using rtsc::server::AdmitInput;
using rtsc::server::AdmitOutcome;
using rtsc::server::DecideEnqueue;
using rtsc::server::EnqueueAction;
using rtsc::server::EnqueueState;
using rtsc::server::FormatInputStats;
using rtsc::server::InjectGeometry;
using rtsc::server::InjectRect;
using rtsc::server::InputEvent;
using rtsc::server::InputStats;
using rtsc::server::InputStatsChanged;
using rtsc::server::IsHeldRelease;
using rtsc::server::IsInjectable;
using rtsc::server::IsReleaseInput;
using rtsc::server::KeyId;
using rtsc::server::MakeWin32DesktopInputSink;
using rtsc::server::PlatformInput;
using rtsc::server::PauseSequenceFilter;
using rtsc::server::PeriodicInputStatsLine;
using rtsc::server::PressedInputs;
using rtsc::server::TranslateInput;

InputEvent KeyEvent(uint8_t scancode, bool extended, bool release) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kKey;
    ev.scancode = scancode;
    ev.extended = extended;
    ev.release = release;
    return ev;
}

// Geometry whose captured pixels are physical virtual-screen pixels and whose
// framebuffer is a 1:1 view: capture == desktop == framebuffer. This is what
// the GDI source reports when the capture rectangle equals the virtual desktop
// (the BitBlt path, no resampling), and it is the minimum geometry an absolute
// move needs to be injectable at all.
InjectGeometry PhysicalGeometry(uint16_t width, uint16_t height) {
    InjectGeometry g;
    g.width = width;
    g.height = height;
    g.capture = InjectRect{0, 0, static_cast<int32_t>(width),
                           static_cast<int32_t>(height)};
    g.desktop = g.capture;
    g.mapped = true;
    g.pixels_are_physical = true;
    return g;
}

// Independent oracle for where the OS puts the cursor. This is the decoding
// semantics used by Wine/ReactOS (floor(n * extent / 65536) plus the desktop
// origin), not a copy of the encoder: it only checks the landing point, so an
// encoder bug cannot make its own expectation pass.
int64_t DecodeAxis(int normalized, int32_t origin, int32_t extent) {
    return static_cast<int64_t>(origin) +
           (static_cast<int64_t>(normalized) * extent) / 65536;
}

// Step 1 of the mapping as the design fixes it: the framebuffer pixel is
// sampled at the CENTER of its cell inside the capture rectangle, with integer
// floor (docs/spec/input-geometry-design-M.md 2.5 / 3.2, adopted after the GDI
// StretchBlt(COLORONCOLOR) measurement). This is the specification, used as an
// oracle; it is not derived from the implementation.
int64_t SpecCapturePixel(int64_t f, int64_t fb, int64_t cap) {
    if (fb <= 1 || cap <= 0) return 0;
    const int64_t local = ((2 * f + 1) * cap) / (2 * fb);
    return local > cap - 1 ? cap - 1 : local;
}

// The two formulas the design rejected for step 1 (endpoint anchoring and
// window start), kept here only so the dense table can prove it distinguishes
// them instead of merely agreeing with one implementation.
int64_t EndpointCapturePixel(int64_t f, int64_t fb, int64_t cap) {
    if (fb <= 1) return 0;
    return (2 * f * (cap - 1) + (fb - 1)) / (2 * (fb - 1));
}

int64_t WindowStartCapturePixel(int64_t f, int64_t fb, int64_t cap) {
    return (f * cap) / fb;
}

bool WaitUntil(const std::function<bool()>& pred, int timeout_ms = 5000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

}  // namespace

RTSC_TEST(desktop_input_key_a_down) {
    const std::vector<PlatformInput> out =
        TranslateInput(KeyEvent(0x1E, false, false), InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kKey);
    CHECK_EQ(out[0].scancode, 0x1E);
    CHECK_EQ(out[0].unicode, 0u);
    CHECK(!out[0].release);
    CHECK(!out[0].extended);
}

RTSC_TEST(desktop_input_key_release) {
    const std::vector<PlatformInput> out =
        TranslateInput(KeyEvent(0x1E, false, true), InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kKey);
    CHECK_EQ(out[0].scancode, 0x1E);
    CHECK(out[0].release);
    CHECK(!out[0].extended);
}

RTSC_TEST(desktop_input_extended_key_keeps_scancode) {
    // The 0xE0 prefix is a flag on the wire and a flag in Win32; the scan code
    // itself must not be offset by 0x100.
    const std::vector<PlatformInput> out =
        TranslateInput(KeyEvent(0x1D, true, false), InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kKey);
    CHECK_EQ(out[0].scancode, 0x1D);
    CHECK(out[0].extended);
    CHECK(!out[0].release);
}

RTSC_TEST(desktop_input_extended1_is_not_injected) {
    // The 0xE1 prefix (FASTPATH_INPUT_KBDFLAGS_EXTENDED1) belongs to the PAUSE
    // sequence: its CTRL down/up carry it on the wire. SendInput has no
    // KEYEVENTF_EXTENDED1, so injecting the bare scan code would press a
    // DIFFERENT physical key -- the plain CTRL and NumLock, which really
    // toggles the local keyboard state. The event cannot be expressed and must
    // produce no platform input at all (P-6 item 4).
    InputEvent ev = KeyEvent(0x1D, false, false);
    ev.extended1 = true;
    CHECK(TranslateInput(ev, InjectGeometry{}).empty());
    CHECK(!IsInjectable(ev));
    // Both halves of the sequence are refused, not just the down.
    InputEvent up = KeyEvent(0x1D, false, true);
    up.extended1 = true;
    CHECK(TranslateInput(up, InjectGeometry{}).empty());
    CHECK(!IsInjectable(up));
    // Control: the same scan code without the E1 flag is an ordinary key.
    const InputEvent plain = KeyEvent(0x1D, false, false);
    CHECK_EQ(TranslateInput(plain, InjectGeometry{}).size(), 1u);
    CHECK(IsInjectable(plain));
    // Off-by-one guard: the 0xE0 flag (`extended`) is NOT the 0xE1 flag and
    // must keep being injected.
    const InputEvent e0 = KeyEvent(0x1D, true, false);
    CHECK_EQ(TranslateInput(e0, InjectGeometry{}).size(), 1u);
    CHECK(IsInjectable(e0));
}

RTSC_TEST(desktop_input_pause_sequence_is_fully_suppressed) {
    // P-6: Pause is the 0xE1 envelope 04 1D / 00 45 / 05 1D / 01 45. Only the
    // two CTRL halves carry the 0x1E1 prefix on the wire; the NUMLOCK(0x45)
    // halves are unflagged but belong to the same sequence. Dropping only the
    // flagged events leaves a bare NumLock down/up, which toggles the local
    // NumLock -- exactly what P-6 item 4 forbids. PauseSequenceFilter must
    // consume all four, and must not consume a real NumLock key.
    InputEvent ctrl_down = KeyEvent(0x1D, false, false);
    ctrl_down.extended1 = true;
    InputEvent num_down = KeyEvent(0x45, false, false);
    InputEvent ctrl_up = KeyEvent(0x1D, false, true);
    ctrl_up.extended1 = true;
    InputEvent num_up = KeyEvent(0x45, false, true);
    const std::vector<InputEvent> pause = {ctrl_down, num_down, ctrl_up, num_up};

    const InjectGeometry usable{1920, 1080};
    PauseSequenceFilter filter;
    bool all_dropped = true;
    size_t actions = 0;
    for (const InputEvent& ev : pause) {
        const bool drop = filter.ShouldDrop(ev);
        all_dropped = all_dropped && drop;
        if (!drop) actions += TranslateInput(ev, usable).size();
    }
    // Every event of the sequence is dropped (not just the two CTRL halves).
    CHECK(all_dropped);
    // And nothing of the sequence can reach the platform.
    CHECK_EQ(actions, static_cast<size_t>(0));

    // Control 1: a standalone NumLock tap is a real key and must survive.
    PauseSequenceFilter tap_filter;
    const std::vector<InputEvent> tap = {KeyEvent(0x45, false, false),
                                         KeyEvent(0x45, false, true)};
    size_t tap_actions = 0;
    bool tap_kept = true;
    for (const InputEvent& ev : tap) {
        if (tap_filter.ShouldDrop(ev)) {
            tap_kept = false;
        } else {
            tap_actions += TranslateInput(ev, usable).size();
        }
    }
    CHECK(tap_kept);
    CHECK_EQ(tap_actions, static_cast<size_t>(2));

    // Control 2: a lone E1 opens the window only until the following NumLock
    // up. A second tap is an ordinary NumLock and must be injected (bounded
    // suppression, never an "eat every 0x45" rule).
    PauseSequenceFilter lone_filter;
    bool lone_dropped = lone_filter.ShouldDrop(ctrl_up);
    CHECK(lone_dropped);
    size_t lone_actions = 0;
    for (const InputEvent& ev : {num_down, num_up, num_down, num_up}) {
        if (!lone_filter.ShouldDrop(ev)) {
            lone_actions += TranslateInput(ev, usable).size();
        }
    }
    CHECK_EQ(lone_actions, static_cast<size_t>(2));

    // Reset closes an open window (ReleaseInput reuses the session).
    PauseSequenceFilter reset_filter;
    CHECK(reset_filter.ShouldDrop(ctrl_down));
    reset_filter.Reset();
    CHECK(!reset_filter.ShouldDrop(num_down));
}

RTSC_TEST(desktop_input_pause_window_closed_by_sync) {
    // P-7: a kSync event declares the keyboard state and resets every key to
    // "up", so it terminates an open PAUSE window. Without that, a lost 0xE1
    // half followed by a SYNC would leave the filter armed and swallow the next
    // real NumLock tap -- the same "eat a live key" failure mode that bounds the
    // suppression. The wire form is: E1 CTRL down, SYNC, then a NumLock tap.
    const InjectGeometry usable{1920, 1080};
    InputEvent ctrl_down = KeyEvent(0x1D, false, false);
    ctrl_down.extended1 = true;
    InputEvent sync;
    sync.kind = InputEvent::Kind::kSync;
    sync.sync_flags = 0x06;  // NumLock + CapsLock
    const std::vector<InputEvent> tap = {KeyEvent(0x45, false, false),
                                         KeyEvent(0x45, false, true)};

    PauseSequenceFilter filter;
    CHECK(filter.ShouldDrop(ctrl_down));  // window opens
    // The SYNC itself is not part of the envelope: it must be injected normally
    // (it translates to nothing, but ShouldDrop must not claim it).
    CHECK(!filter.ShouldDrop(sync));
    // The state reset closes the window, so the following tap is a real key.
    size_t actions = 0;
    bool all_kept = true;
    for (const InputEvent& ev : tap) {
        const bool drop = filter.ShouldDrop(ev);
        all_kept = all_kept && !drop;
        if (!drop) actions += TranslateInput(ev, usable).size();
    }
    CHECK(all_kept);
    CHECK_EQ(actions, static_cast<size_t>(2));
}

RTSC_TEST(desktop_input_zero_scancode_is_not_injected) {
    // A kKey event carrying scan code 0 has no valid Win32 scan code: SendInput
    // would be asked for wScan=0, which the system does not turn into a key
    // (only KEYEVENTF_UNICODE uses a zero scan code). The pure mapper must drop
    // it instead of enqueueing an unusable platform event.
    const std::vector<PlatformInput> down =
        TranslateInput(KeyEvent(0x00, false, false), InjectGeometry{});
    CHECK(down.empty());
    const std::vector<PlatformInput> up =
        TranslateInput(KeyEvent(0x00, false, true), InjectGeometry{});
    CHECK(up.empty());
    // An extended zero scan code is equally unusable.
    const std::vector<PlatformInput> extended =
        TranslateInput(KeyEvent(0x00, true, false), InjectGeometry{});
    CHECK(extended.empty());
}

RTSC_TEST(desktop_input_unicode) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kUnicode;
    ev.unicode_code = 0x6F22;
    ev.release = false;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kKey);
    CHECK_EQ(out[0].unicode, 0x6F22u);
    CHECK_EQ(out[0].scancode, 0u);
    CHECK(!out[0].release);
}

RTSC_TEST(desktop_input_absolute_move_full_range) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = true;
    ev.x = 0;
    ev.y = 0;
    std::vector<PlatformInput> out =
        TranslateInput(ev, PhysicalGeometry(1920, 1080));
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    CHECK_EQ(out[0].x, 0);
    CHECK_EQ(out[0].y, 0);

    ev.x = 1920;
    ev.y = 1080;
    out = TranslateInput(ev, PhysicalGeometry(1920, 1080));
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    CHECK_EQ(out[0].x, 65535);
    CHECK_EQ(out[0].y, 65535);
}

RTSC_TEST(desktop_input_absolute_move_cross_monitor) {
    // --monitor 1: the captured screen is the second 1280x1024 monitor at
    // x=1920 in a 3200x1024 virtual desktop. Client pixel (640,512) must land
    // at capture_origin + pixel = (2560,512), i.e. on the second monitor, not
    // on the first one. The wire value is pinned too: the desktop extent (not
    // extent-1) is the normalization denominator.
    InjectGeometry g;
    g.width = 1280;
    g.height = 1024;
    g.capture = InjectRect{1920, 0, 1280, 1024};
    g.desktop = InjectRect{0, 0, 3200, 1024};
    g.mapped = true;
    g.pixels_are_physical = true;

    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = true;
    ev.x = 640;
    ev.y = 512;
    const std::vector<PlatformInput> out = TranslateInput(ev, g);
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    CHECK_EQ(out[0].x, 52429);
    CHECK_EQ(out[0].y, 32768);
    CHECK_EQ(DecodeAxis(out[0].x, g.desktop.x, g.desktop.width),
             static_cast<int64_t>(2560));
    CHECK_EQ(DecodeAxis(out[0].y, g.desktop.y, g.desktop.height),
             static_cast<int64_t>(512));
}

RTSC_TEST(desktop_input_absolute_move_cross_monitor_scaled) {
    // Same second monitor, but the framebuffer (640x512) is half the capture
    // size (1280x1024), i.e. the StretchBlt path. The top-left client pixel is
    // sampled from the CENTER of the first framebuffer cell, so it lands one
    // physical pixel inside the capture rectangle: (1921,1), not (1920,0).
    // This is the case that distinguishes center sampling from endpoint
    // anchoring (endpoint maps 0 to 0).
    InjectGeometry g;
    g.width = 640;
    g.height = 512;
    g.capture = InjectRect{1920, 0, 1280, 1024};
    g.desktop = InjectRect{0, 0, 3200, 1024};
    g.mapped = true;
    g.pixels_are_physical = true;

    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = true;
    ev.x = 0;
    ev.y = 0;
    const std::vector<PlatformInput> out = TranslateInput(ev, g);
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    CHECK_EQ(out[0].x, 39343);
    CHECK_EQ(out[0].y, 64);
    CHECK_EQ(DecodeAxis(out[0].x, g.desktop.x, g.desktop.width),
             static_cast<int64_t>(1921));
    CHECK_EQ(DecodeAxis(out[0].y, g.desktop.y, g.desktop.height),
             static_cast<int64_t>(1));
}

RTSC_TEST(desktop_input_absolute_move_one_to_one_is_identity) {    // capture == desktop == framebuffer: BitBlt copies pixels 1:1, so every
    // framebuffer pixel is the same physical pixel. The visible behaviour must
    // be pointwise identity (the old 1:1 path had no resampling); the oracle
    // decodes the wire value independently.
    const InjectGeometry g = PhysicalGeometry(1920, 1080);
    int mismatches = 0;
    for (int x = 0; x < 1920; x += 37) {
        for (int y = 0; y < 1080; y += 41) {
            InputEvent ev;
            ev.kind = InputEvent::Kind::kMouse;
            ev.is_move = true;
            ev.x = static_cast<uint16_t>(x);
            ev.y = static_cast<uint16_t>(y);
            const std::vector<PlatformInput> out = TranslateInput(ev, g);
            if (out.size() != 1 ||
                out[0].kind != PlatformInput::Kind::kMouseMove ||
                DecodeAxis(out[0].x, g.desktop.x, g.desktop.width) != x ||
                DecodeAxis(out[0].y, g.desktop.y, g.desktop.height) != y) {
                ++mismatches;
            }
        }
    }
    CHECK_EQ(mismatches, 0);
}

RTSC_TEST(desktop_input_absolute_move_normalizes_against_extent) {
    // The denominator is the desktop extent, with ceil: the second pixel of a
    // 1280-wide desktop is 52, not 51 (extent-1) and not 51 (round). This is
    // the minimal case that distinguishes the three formulas.
    const InjectGeometry g = PhysicalGeometry(1280, 1024);
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = true;
    ev.x = 1;
    ev.y = 0;
    const std::vector<PlatformInput> out = TranslateInput(ev, g);
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    CHECK_EQ(out[0].x, 52);
    CHECK_EQ(DecodeAxis(out[0].x, g.desktop.x, g.desktop.width),
             static_cast<int64_t>(1));
}

RTSC_TEST(desktop_input_absolute_move_last_pixel_is_65535) {
    // The last pixel keeps the documented wire endpoint (65535 maps onto the
    // lower-right corner) while the interior uses ceil(rel*65536/extent).
    const InjectGeometry g = PhysicalGeometry(1280, 1024);
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = true;
    ev.x = 1279;
    ev.y = 1023;
    const std::vector<PlatformInput> out = TranslateInput(ev, g);
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    CHECK_EQ(out[0].x, 65535);
    CHECK_EQ(out[0].y, 65535);
}

RTSC_TEST(desktop_input_absolute_move_translates_desktop_origin) {
    // A monitor LEFT of the primary puts the virtual-desktop origin at a
    // negative x: desktop{-1280,0,3200,1024} is a 1920-wide primary at x=0
    // plus a 1280-wide monitor at x=-1280, and capture{0,0,1280,1024} is that
    // LEFT monitor. The client pixel (640,512) is physical (640,512), which is
    // 1920 px into a domain that starts at -1280.
    //
    // Step 3 must subtract the DESKTOP origin before normalizing. Dropping
    // "- desktop_origin" normalizes 640 as if the domain started at 0, so the
    // landing point moves 1280 px to the right of where the client pointed.
    InjectGeometry g;
    g.width = 1280;
    g.height = 1024;
    g.capture = InjectRect{0, 0, 1280, 1024};
    g.desktop = InjectRect{-1280, 0, 3200, 1024};
    g.mapped = true;
    g.pixels_are_physical = true;

    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = true;
    ev.x = 640;
    ev.y = 512;
    const std::vector<PlatformInput> out = TranslateInput(ev, g);
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    // rel = 0 + 640 - (-1280) = 1920 of 3200 -> ceil(1920*65536/3200) = 39322.
    CHECK_EQ(out[0].x, 39322);
    CHECK_EQ(DecodeAxis(out[0].x, g.desktop.x, g.desktop.width),
             static_cast<int64_t>(640));
    CHECK_EQ(DecodeAxis(out[0].y, g.desktop.y, g.desktop.height),
             static_cast<int64_t>(512));
}

RTSC_TEST(desktop_input_absolute_move_axes_are_independent) {
    // Each axis must use ITS OWN origin and ITS OWN extent: x from
    // desktop.{x,width}, y from desktop.{y,height}. Every wrong pairing is
    // made observably different by this geometry:
    //   desktop.x (-900) != desktop.y (150)
    //   capture.height (600) != desktop.height (768)
    // so a y axis that reads desktop.x as its origin, or capture.height as its
    // extent, lands somewhere else.
    InjectGeometry g;
    g.width = 1280;
    g.height = 600;
    g.capture = InjectRect{0, 300, 1280, 600};
    g.desktop = InjectRect{-900, 150, 3200, 768};
    g.mapped = true;
    g.pixels_are_physical = true;

    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = true;
    ev.x = 640;
    ev.y = 300;
    const std::vector<PlatformInput> out = TranslateInput(ev, g);
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    // x: physical 640 -> rel 1540 of 3200 -> ceil(1540*65536/3200) = 31540.
    CHECK_EQ(out[0].x, 31540);
    // y: physical 300+300 = 600 -> rel 450 of 768 -> 450*65536/768 = 38400.
    CHECK_EQ(out[0].y, 38400);
    CHECK_EQ(DecodeAxis(out[0].x, g.desktop.x, g.desktop.width),
             static_cast<int64_t>(640));
    CHECK_EQ(DecodeAxis(out[0].y, g.desktop.y, g.desktop.height),
             static_cast<int64_t>(600));
}

RTSC_TEST(desktop_input_absolute_move_samples_center_of_each_cell) {
    // Dense phase table: EVERY framebuffer pixel of both axes is compared with
    // the specified center sampling, for upscaling (cap > fb) and for
    // downscaling (cap < fb). The old scaled case only probed the single pixel
    // x=0, where endpoint anchoring and window start also agree with center
    // sampling, so a phase change could stay green.
    //
    // The 1:1 capture/desktop domain makes the landing point equal the sampled
    // capture pixel, so the comparison is exact (no normalization rounding).
    struct DenseCase {
        uint16_t fbw;
        uint16_t fbh;
        int32_t capw;
        int32_t caph;
    };
    const DenseCase cases[] = {
        {640, 512, 1280, 1024},    // 2x upscale
        {1920, 1024, 1280, 1024},  // downsample 1.5:1
        {800, 600, 1920, 1080},    // non-integer ratio both ways
    };
    for (const DenseCase& c : cases) {
        // The table is discriminating: both rejected formulas differ from the
        // specification on this many source pixels. (Design 2.5: 640->1280
        // differs on 320/640 for endpoint anchoring and for window start.)
        size_t endpoint_diff = 0;
        size_t start_diff = 0;
        for (int f = 0; f < c.fbw; ++f) {
            const int64_t center = SpecCapturePixel(f, c.fbw, c.capw);
            if (center != EndpointCapturePixel(f, c.fbw, c.capw)) {
                ++endpoint_diff;
            }
            if (center != WindowStartCapturePixel(f, c.fbw, c.capw)) {
                ++start_diff;
            }
        }
        CHECK(endpoint_diff > 0);
        CHECK(start_diff > 0);

        InjectGeometry g;
        g.width = c.fbw;
        g.height = c.fbh;
        g.capture = InjectRect{0, 0, c.capw, c.caph};
        g.desktop = g.capture;
        g.mapped = true;
        g.pixels_are_physical = true;

        size_t mismatches = 0;
        for (int f = 0; f < c.fbw; ++f) {
            InputEvent ev;
            ev.kind = InputEvent::Kind::kMouse;
            ev.is_move = true;
            ev.x = static_cast<uint16_t>(f);
            ev.y = static_cast<uint16_t>((c.fbh - 1) / 2);
            const std::vector<PlatformInput> out = TranslateInput(ev, g);
            if (out.size() != 1 ||
                out[0].kind != PlatformInput::Kind::kMouseMove ||
                DecodeAxis(out[0].x, 0, c.capw) !=
                    SpecCapturePixel(f, c.fbw, c.capw)) {
                ++mismatches;
            }
        }
        for (int f = 0; f < c.fbh; ++f) {
            InputEvent ev;
            ev.kind = InputEvent::Kind::kMouse;
            ev.is_move = true;
            ev.x = static_cast<uint16_t>((c.fbw - 1) / 2);
            ev.y = static_cast<uint16_t>(f);
            const std::vector<PlatformInput> out = TranslateInput(ev, g);
            if (out.size() != 1 ||
                out[0].kind != PlatformInput::Kind::kMouseMove ||
                DecodeAxis(out[0].y, 0, c.caph) !=
                    SpecCapturePixel(f, c.fbh, c.caph)) {
                ++mismatches;
            }
        }
        CHECK_EQ(mismatches, static_cast<size_t>(0));
    }
}

RTSC_TEST(desktop_input_absolute_move_dense_table) {
    // Exhaustive per-pixel table for the common desktop widths/heights, in two
    // shapes:
    //
    //   A. 1:1 (capture == desktop == framebuffer): every pixel must decode
    //      back to itself. The old identity case sampled every 37th/41st pixel,
    //      so an interior off-by-one in the normalization could hide between
    //      the samples.
    //   B. scaled (framebuffer = half the capture size): every framebuffer
    //      pixel must land on the SPECIFIED center-sampled capture pixel. This
    //      is the dense table that distinguishes the sampling phase: with a
    //      1:1 shape endpoint anchoring is the identity and cannot be told
    //      apart, so the scaled shape is what makes a phase change red.
    //
    // Axes are independent, so covering every x and every y covers every pixel.
    const int32_t widths[] = {1280, 1920, 3200, 3840};
    const int32_t heights[] = {720, 1080, 1024, 1200};
    for (size_t i = 0; i < 4; ++i) {
        // A. 1:1 identity.
        const InjectGeometry identity =
            PhysicalGeometry(static_cast<uint16_t>(widths[i]),
                             static_cast<uint16_t>(heights[i]));
        size_t identity_mismatches = 0;
        for (int32_t f = 0; f < widths[i]; ++f) {
            InputEvent ev;
            ev.kind = InputEvent::Kind::kMouse;
            ev.is_move = true;
            ev.x = static_cast<uint16_t>(f);
            ev.y = static_cast<uint16_t>(heights[i] / 2);
            const std::vector<PlatformInput> out = TranslateInput(ev, identity);
            if (out.size() != 1 ||
                DecodeAxis(out[0].x, identity.desktop.x,
                           identity.desktop.width) != f) {
                ++identity_mismatches;
            }
        }
        for (int32_t f = 0; f < heights[i]; ++f) {
            InputEvent ev;
            ev.kind = InputEvent::Kind::kMouse;
            ev.is_move = true;
            ev.x = static_cast<uint16_t>(widths[i] / 2);
            ev.y = static_cast<uint16_t>(f);
            const std::vector<PlatformInput> out = TranslateInput(ev, identity);
            if (out.size() != 1 ||
                DecodeAxis(out[0].y, identity.desktop.y,
                           identity.desktop.height) != f) {
                ++identity_mismatches;
            }
        }
        CHECK_EQ(identity_mismatches, static_cast<size_t>(0));

        // B. Scaled: framebuffer half the capture, capture == desktop.
        const uint16_t fbw = static_cast<uint16_t>(widths[i] / 2);
        const uint16_t fbh = static_cast<uint16_t>(heights[i] / 2);
        InjectGeometry scaled;
        scaled.width = fbw;
        scaled.height = fbh;
        scaled.capture = InjectRect{0, 0, widths[i], heights[i]};
        scaled.desktop = scaled.capture;
        scaled.mapped = true;
        scaled.pixels_are_physical = true;

        size_t scaled_mismatches = 0;
        for (int32_t f = 0; f < fbw; ++f) {
            InputEvent ev;
            ev.kind = InputEvent::Kind::kMouse;
            ev.is_move = true;
            ev.x = static_cast<uint16_t>(f);
            ev.y = static_cast<uint16_t>((fbh - 1) / 2);
            const std::vector<PlatformInput> out = TranslateInput(ev, scaled);
            if (out.size() != 1 ||
                out[0].kind != PlatformInput::Kind::kMouseMove ||
                DecodeAxis(out[0].x, 0, widths[i]) !=
                    SpecCapturePixel(f, fbw, widths[i])) {
                ++scaled_mismatches;
            }
        }
        for (int32_t f = 0; f < fbh; ++f) {
            InputEvent ev;
            ev.kind = InputEvent::Kind::kMouse;
            ev.is_move = true;
            ev.x = static_cast<uint16_t>((fbw - 1) / 2);
            ev.y = static_cast<uint16_t>(f);
            const std::vector<PlatformInput> out = TranslateInput(ev, scaled);
            if (out.size() != 1 ||
                out[0].kind != PlatformInput::Kind::kMouseMove ||
                DecodeAxis(out[0].y, 0, heights[i]) !=
                    SpecCapturePixel(f, fbh, heights[i])) {
                ++scaled_mismatches;
            }
        }
        CHECK_EQ(scaled_mismatches, static_cast<size_t>(0));

        // The scaled shape is discriminating: endpoint anchoring disagrees with
        // center sampling on many of these framebuffer pixels.
        size_t endpoint_diff = 0;
        for (int32_t f = 0; f < fbw; ++f) {
            if (SpecCapturePixel(f, fbw, widths[i]) !=
                EndpointCapturePixel(f, fbw, widths[i])) {
                ++endpoint_diff;
            }
        }
        CHECK(endpoint_diff > 0);
    }
}

RTSC_TEST(desktop_input_absolute_move_requires_trusted_geometry) {
    // Either trust bit being false drops the MOVE only: a button still has to
    // reach the desktop or the peer's click is lost and its later release
    // leaves the local button stuck.
    InjectGeometry g;
    g.width = 1280;
    g.height = 1024;
    g.capture = InjectRect{1920, 0, 1280, 1024};
    g.desktop = InjectRect{0, 0, 3200, 1024};
    g.mapped = true;
    g.pixels_are_physical = true;

    InputEvent move;
    move.kind = InputEvent::Kind::kMouse;
    move.is_move = true;
    move.x = 640;
    move.y = 512;

    g.mapped = false;
    CHECK(TranslateInput(move, g).empty());

    g.mapped = true;
    g.pixels_are_physical = false;
    CHECK(TranslateInput(move, g).empty());

    InputEvent click = move;
    click.button = 1;
    click.button_down = true;
    g.mapped = false;
    const std::vector<PlatformInput> clicked = TranslateInput(click, g);
    CHECK_EQ(clicked.size(), 1u);
    if (clicked.size() != 1) return;
    CHECK(clicked[0].kind == PlatformInput::Kind::kMouseButton);
    CHECK_EQ(clicked[0].button, 1);
    CHECK(clicked[0].button_down);
}

RTSC_TEST(desktop_input_absolute_move_degenerate_geometry) {
    // Even a geometry marked "trusted" cannot map a move when the framebuffer
    // has no span, the capture is empty, or the desktop has no span.
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = true;
    ev.x = 0;
    ev.y = 0;

    InjectGeometry g = PhysicalGeometry(2, 2);
    g.width = 1;
    CHECK(TranslateInput(ev, g).empty());

    g = PhysicalGeometry(2, 2);
    g.height = 1;
    CHECK(TranslateInput(ev, g).empty());

    g = PhysicalGeometry(2, 2);
    g.capture.width = 0;
    CHECK(TranslateInput(ev, g).empty());

    g = PhysicalGeometry(2, 2);
    g.desktop.width = 1;
    CHECK(TranslateInput(ev, g).empty());

    g = PhysicalGeometry(2, 2);
    g.desktop.height = 1;
    CHECK(TranslateInput(ev, g).empty());

    // The capture rectangle must lie INSIDE the desktop box. Step 2/3 turn a
    // capture pixel into a physical point and then normalize it against the
    // desktop, so a capture that starts outside the box or runs past its right
    // or bottom edge would produce a normalized value for a point the client
    // never pointed at (clamping cannot repair it: the point is wrong).
    g = PhysicalGeometry(2, 2);
    g.capture.x = -1;  // left of the desktop origin
    CHECK(TranslateInput(ev, g).empty());

    g = PhysicalGeometry(2, 2);
    g.capture.x = 2;  // x + width = 3 > desktop 0 + 2
    CHECK(TranslateInput(ev, g).empty());

    g = PhysicalGeometry(2, 2);
    g.capture.y = -1;  // above the desktop origin
    CHECK(TranslateInput(ev, g).empty());

    g = PhysicalGeometry(2, 2);
    g.capture.height = 3;  // y + height = 3 > desktop 0 + 2
    CHECK(TranslateInput(ev, g).empty());

    // Exactly one pixel past the right edge. The case above overshoots by two
    // (x=2 + width 2 vs desktop 2), so it cannot distinguish "<=" from "<=" with
    // a one-pixel allowance; this one pins the boundary itself.
    g = PhysicalGeometry(2, 2);
    g.capture.x = 1;  // x + width = 3 == desktop right + 1
    CHECK(TranslateInput(ev, g).empty());

    // An empty capture height is degenerate even when marked mapped: without
    // this case a "<0" rewrite of the "<= 0" check would stay green.
    g = PhysicalGeometry(2, 2);
    g.capture.height = 0;
    CHECK(TranslateInput(ev, g).empty());

    // MOUSEINPUT absolute coordinates have 65536 steps per axis, so a desktop
    // box larger than that cannot be addressed pixel by pixel: a wire step
    // would skip pixels. Treat it as unusable rather than silently imprecise.
    g = PhysicalGeometry(2, 2);
    g.desktop.width = 65537;
    g.capture.width = 2;
    CHECK(TranslateInput(ev, g).empty());

    g = PhysicalGeometry(2, 2);
    g.desktop.height = 65537;
    g.capture.height = 2;
    CHECK(TranslateInput(ev, g).empty());

    // Control: exactly 65536 is the largest addressable box and still maps.
    g = PhysicalGeometry(2, 2);
    g.desktop.width = 65536;
    g.capture.width = 2;
    const std::vector<PlatformInput> addressable = TranslateInput(ev, g);
    CHECK_EQ(addressable.size(), 1u);
    if (addressable.size() == 1) {
        CHECK(addressable[0].kind == PlatformInput::Kind::kMouseMove);
    }

    // Same control on the vertical axis. Without it a ">= 65536" rewrite of the
    // height check would only be exercised by the 65537 rejection above.
    g = PhysicalGeometry(2, 2);
    g.desktop.height = 65536;
    g.capture.height = 2;
    const std::vector<PlatformInput> addressable_h = TranslateInput(ev, g);
    CHECK_EQ(addressable_h.size(), 1u);
    if (addressable_h.size() == 1) {
        CHECK(addressable_h[0].kind == PlatformInput::Kind::kMouseMove);
    }
}

RTSC_TEST(desktop_input_absolute_move_requires_usable_geometry) {
    // A geometry built from the negotiated size alone -- the shape
    // InjectGeometry had before the capture/desktop rectangles were added, and
    // the shape an embedder still gets by aggregate-initializing only
    // width/height -- carries mapped=false. The move is therefore rejected by
    // the TRUST gate, not by the span rule: an unknown capture rectangle is
    // exactly as unusable as a degenerate one.
    //
    // The span rule itself (width/height of 0 or 1 with a trusted geometry) is
    // deliberately exercised in desktop_input_absolute_move_degenerate_geometry,
    // which uses PhysicalGeometry so mapped stays true and only the span is
    // broken. Keeping the two reasons apart means breaking either one alone
    // turns a case red.
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = true;
    ev.x = 0;
    ev.y = 0;
    CHECK(TranslateInput(ev, InjectGeometry{0, 0}).empty());
    CHECK(TranslateInput(ev, InjectGeometry{1, 1}).empty());
    // One usable axis does not help: the other one is still not normalizable.
    CHECK(TranslateInput(ev, InjectGeometry{2, 1}).empty());
    CHECK(TranslateInput(ev, InjectGeometry{1, 2}).empty());
    // Control: both axes have a span AND the geometry is trusted.
    const std::vector<PlatformInput> out =
        TranslateInput(ev, PhysicalGeometry(2, 2));
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);

    // Only the unmappable MOVE is suppressed: a button press carries no
    // coordinates and still has to reach the desktop, or the peer's click is
    // lost (and its later release leaves the local button stuck).
    InputEvent click = ev;
    click.button = 1;
    click.button_down = true;
    const std::vector<PlatformInput> clicked =
        TranslateInput(click, InjectGeometry{0, 0});
    CHECK_EQ(clicked.size(), 1u);
    if (clicked.size() != 1) return;
    CHECK(clicked[0].kind == PlatformInput::Kind::kMouseButton);
    CHECK_EQ(clicked[0].button, 1);
    CHECK(clicked[0].button_down);
}

RTSC_TEST(desktop_input_button_left_down) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = false;
    ev.button = 1;
    ev.button_down = true;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseButton);
    CHECK_EQ(out[0].button, 1);
    CHECK(out[0].button_down);
}

RTSC_TEST(desktop_input_button_left_up_keeps_identity) {
    // A release carries the button bit without PTRFLAGS_DOWN; the identity must
    // survive, otherwise the local button stays pressed forever.
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = false;
    ev.button = 1;
    ev.button_down = false;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseButton);
    CHECK_EQ(out[0].button, 1);
    CHECK(!out[0].button_down);
}

RTSC_TEST(desktop_input_wheel_positive_is_wire_units) {
    // wheel_delta is already WHEEL_DELTA units (120 per notch); multiplying by
    // 120 here would send 14400.
    InputEvent ev;
    ev.kind = InputEvent::Kind::kWheel;
    ev.wheel_delta = 120;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kWheel);
    CHECK_EQ(out[0].wheel, 120);
    CHECK(!out[0].horizontal);
}

RTSC_TEST(desktop_input_wheel_negative_is_wire_units) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kWheel;
    ev.wheel_delta = -120;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kWheel);
    CHECK_EQ(out[0].wheel, -120);
    CHECK(!out[0].horizontal);
}

RTSC_TEST(desktop_input_zero_wheel_is_not_injected) {
    // T10: a zero delta rotates nothing. Enqueueing it would spend a queue
    // slot and a rate-limit token on a no-op, and a peer could flood zero
    // wheels to evict queued movement and starve real input.
    InputEvent ev;
    ev.kind = InputEvent::Kind::kWheel;
    ev.wheel_delta = 0;
    CHECK(TranslateInput(ev, InjectGeometry{}).empty());
    CHECK(!IsInjectable(ev));
    // A zero horizontal wheel is equally a no-op.
    ev.horizontal = true;
    CHECK(TranslateInput(ev, InjectGeometry{}).empty());
    CHECK(!IsInjectable(ev));
    // Control: one notch in each direction still produces exactly one action.
    ev.horizontal = false;
    ev.wheel_delta = 120;
    CHECK_EQ(TranslateInput(ev, InjectGeometry{}).size(), 1u);
    ev.wheel_delta = -120;
    CHECK_EQ(TranslateInput(ev, InjectGeometry{}).size(), 1u);
}

RTSC_TEST(desktop_input_horizontal_wheel) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kWheel;
    ev.wheel_delta = 120;
    ev.horizontal = true;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kWheel);
    CHECK_EQ(out[0].wheel, 120);
    CHECK(out[0].horizontal);
}

RTSC_TEST(desktop_input_mouse_relative_not_injected) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouseRel;
    ev.rel_x = 10;
    ev.rel_y = -5;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK(out.empty());
}

RTSC_TEST(desktop_input_sync_not_injected) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kSync;
    ev.sync_flags = 0x06;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK(out.empty());
}

RTSC_TEST(desktop_input_wheel_ignores_xy) {
    // [MS-RDPBCGR] says xPos/yPos must be ignored for a wheel event; carrying
    // them into an absolute move would jump the pointer to the wheel origin.
    InputEvent ev;
    ev.kind = InputEvent::Kind::kWheel;
    ev.wheel_delta = 120;
    ev.x = 123;
    ev.y = 456;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kWheel);
    CHECK_EQ(out[0].x, 0);
    CHECK_EQ(out[0].y, 0);
    CHECK_EQ(out[0].wheel, 120);
}

RTSC_TEST(desktop_input_mouse_without_move_or_button_is_empty) {
    // A plain kMouse without PTRFLAGS_MOVE and without a button bit must not
    // become an absolute move to (0, 0).
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = false;
    ev.button = 0;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK(out.empty());
}

// ---- Bounded injection queue policy (DecideEnqueue / AdmitInput) ------------
//
// The Win32 sink cannot be exercised here (it posts real SendInput calls from a
// worker thread), so the admission decision and the held-key bookkeeping live in
// platform-neutral functions. These cases pin the fail-closed rule: a press may
// grow the queue past the soft limit but never past the hard limit, and only
// the release of a key/button the session actually holds is exempt.

EnqueueState QueueState(size_t size, bool movable_move, bool incoming_is_move,
                        bool incoming_is_held_release = false) {
    EnqueueState state;
    state.size = size;
    state.soft_limit = 4;
    state.hard_limit = 16;
    state.has_movable_move = movable_move;
    state.incoming_is_move = incoming_is_move;
    state.incoming_is_held_release = incoming_is_held_release;
    return state;
}

PlatformInput KeyDown(uint8_t scancode, bool extended = false) {
    PlatformInput input;
    input.kind = PlatformInput::Kind::kKey;
    input.scancode = scancode;
    input.extended = extended;
    input.release = false;
    return input;
}

PlatformInput KeyUp(uint8_t scancode, bool extended = false) {
    PlatformInput input = KeyDown(scancode, extended);
    input.release = true;
    return input;
}

RTSC_TEST(desktop_input_queue_accepts_below_soft_limit) {
    CHECK(DecideEnqueue(QueueState(0, false, true)) == EnqueueAction::kAccept);
    CHECK(DecideEnqueue(QueueState(3, false, false)) == EnqueueAction::kAccept);
}

RTSC_TEST(desktop_input_queue_evicts_move_when_available) {
    // Above the soft limit the oldest movement is the preferred victim, both
    // for a moving and for a non-moving incoming event.
    CHECK(DecideEnqueue(QueueState(4, true, true)) ==
          EnqueueAction::kEvictMove);
    CHECK(DecideEnqueue(QueueState(10, true, false)) ==
          EnqueueAction::kEvictMove);
    CHECK(DecideEnqueue(QueueState(16, true, false)) ==
          EnqueueAction::kEvictMove);
}

RTSC_TEST(desktop_input_queue_drops_move_without_victim) {
    // A movement is disposable: with nothing older to evict it is dropped
    // instead of displacing key/button state, at any size.
    CHECK(DecideEnqueue(QueueState(4, false, true)) == EnqueueAction::kDrop);
    CHECK(DecideEnqueue(QueueState(15, false, true)) == EnqueueAction::kDrop);
}

RTSC_TEST(desktop_input_queue_grows_between_limits_for_key) {
    // Above the soft limit, a key/button is still accepted while the hard limit
    // leaves room: an eventual key-up must not be lost.
    CHECK(DecideEnqueue(QueueState(4, false, false)) ==
          EnqueueAction::kAccept);
    CHECK(DecideEnqueue(QueueState(15, false, false)) ==
          EnqueueAction::kAccept);
}

RTSC_TEST(desktop_input_queue_hard_limit_drops_key) {
    // At the hard limit with no movement to evict, a key/button press MUST be
    // dropped: the queue is bounded, a dropped press was never recorded as held
    // (AdmitInput tracks only accepted events), and an unbounded queue would
    // let a hostile peer exhaust memory.
    CHECK(DecideEnqueue(QueueState(16, false, false)) ==
          EnqueueAction::kDrop);
    CHECK(DecideEnqueue(QueueState(17, false, false)) ==
          EnqueueAction::kDrop);
}

RTSC_TEST(desktop_input_queue_accepts_held_release_at_hard_limit) {
    // F1: only the release of a key/button the session actually holds is
    // bounded by the pressed set, and losing it leaves the peer's key stuck.
    // That held release is accepted even at (and above) the hard limit.
    CHECK(DecideEnqueue(QueueState(16, false, false, true)) ==
          EnqueueAction::kAccept);
    CHECK(DecideEnqueue(QueueState(17, false, false, true)) ==
          EnqueueAction::kAccept);
    // A held release arriving while a movement can be evicted still succeeds
    // (the eviction keeps the queue size unchanged).
    CHECK(DecideEnqueue(QueueState(16, true, false, true)) ==
          EnqueueAction::kEvictMove);
}

RTSC_TEST(desktop_input_queue_unheld_release_is_dropped_at_hard_limit) {
    // F1: a release that does not lift a held key/button gets no exemption.
    // Without this, one 32 KiB input PDU carrying thousands of key-ups for keys
    // that were never pressed would grow the queue without bound.
    PressedInputs pressed;  // nothing is held
    const EnqueueState full = QueueState(16, false, false);
    const PlatformInput up = KeyUp(0x1E);
    CHECK(IsReleaseInput(up));
    CHECK(!IsHeldRelease(up, pressed));
    CHECK(AdmitInput(full, pressed, up, IsHeldRelease(up, pressed)) ==
          EnqueueAction::kDrop);
    // A flood of such releases stays refused; the queue cannot grow.
    size_t accepted = 0;
    for (int i = 0; i < 5000; ++i) {
        if (AdmitInput(full, pressed, up, IsHeldRelease(up, pressed)) !=
            EnqueueAction::kDrop) {
            ++accepted;
        }
    }
    CHECK_EQ(accepted, static_cast<size_t>(0));
    CHECK(pressed.keys.empty());
}

RTSC_TEST(desktop_input_queue_held_release_is_accepted_and_untracked) {
    PressedInputs pressed;
    const PlatformInput down = KeyDown(0x1D, false);
    CHECK(!IsReleaseInput(down));
    // Below the soft limit the press is accepted and becomes held.
    CHECK(AdmitInput(QueueState(0, false, false), pressed, down,
                     IsHeldRelease(down, pressed)) == EnqueueAction::kAccept);
    CHECK_EQ(pressed.keys.size(), static_cast<size_t>(1));
    CHECK(IsHeldRelease(KeyUp(0x1D, false), pressed));
    // The matching up is exempt at the hard limit and clears the held key.
    CHECK(AdmitInput(QueueState(16, false, false), pressed, KeyUp(0x1D, false),
                     IsHeldRelease(KeyUp(0x1D, false), pressed)) ==
          EnqueueAction::kAccept);
    CHECK(pressed.keys.empty());
    // A repeated up is no longer held, so at the hard limit it is disposable.
    CHECK(AdmitInput(QueueState(16, false, false), pressed, KeyUp(0x1D, false),
                     IsHeldRelease(KeyUp(0x1D, false), pressed)) ==
          EnqueueAction::kDrop);
}

RTSC_TEST(desktop_input_queue_extended_identity_is_not_confused) {
    // The identity includes the 0xE0 flag: an extended key is not the same
    // physical key as the non-extended scan code. The pressed set must be
    // non-empty, otherwise "not held" is trivially true for every key and the
    // assertion protects nothing (the previous version of this check ran on an
    // empty set and survived a mutation that ignored `extended`).
    PressedInputs pressed;
    const PlatformInput down = KeyDown(0x1D, false);
    CHECK(AdmitInput(QueueState(0, false, false), pressed, down,
                     IsHeldRelease(down, pressed)) == EnqueueAction::kAccept);
    CHECK_EQ(pressed.keys.size(), static_cast<size_t>(1));
    // The extended 0x1D up lifts a DIFFERENT physical key, so it is not held.
    CHECK(!IsHeldRelease(KeyUp(0x1D, true), pressed));
    // The non-extended up is the one that lifts the press we made.
    CHECK(IsHeldRelease(KeyUp(0x1D, false), pressed));

    // Reverse direction: a held extended key is not lifted by the plain code.
    PressedInputs extended_pressed;
    const PlatformInput extended_down = KeyDown(0x1D, true);
    CHECK(AdmitInput(QueueState(0, false, false), extended_pressed,
                     extended_down,
                     IsHeldRelease(extended_down, extended_pressed)) ==
          EnqueueAction::kAccept);
    CHECK(!IsHeldRelease(KeyUp(0x1D, false), extended_pressed));
    CHECK(IsHeldRelease(KeyUp(0x1D, true), extended_pressed));
}

RTSC_TEST(desktop_input_queue_evict_move_still_tracks_press) {
    // Above the soft limit a press is accepted by evicting a movable movement.
    // It is still injected, so it must be recorded as held: if the evict path
    // skipped TrackInput, its up would no longer be exempt at the hard limit
    // and the key would stay stuck for the rest of the session.
    PressedInputs pressed;
    const PlatformInput down = KeyDown(0x1E);
    CHECK(AdmitInput(QueueState(4, true, false), pressed, down,
                     IsHeldRelease(down, pressed)) ==
          EnqueueAction::kEvictMove);
    CHECK_EQ(pressed.keys.size(), static_cast<size_t>(1));
    CHECK(IsHeldRelease(KeyUp(0x1E), pressed));
}

RTSC_TEST(desktop_input_queue_held_button_release_is_exempt) {
    PressedInputs pressed;
    PlatformInput down;
    down.kind = PlatformInput::Kind::kMouseButton;
    down.button = 1;
    down.button_down = true;
    CHECK(AdmitInput(QueueState(0, false, false), pressed, down,
                     IsHeldRelease(down, pressed)) == EnqueueAction::kAccept);
    CHECK_EQ(pressed.buttons.size(), static_cast<size_t>(1));
    PlatformInput up = down;
    up.button_down = false;
    CHECK(IsReleaseInput(up));
    CHECK(IsHeldRelease(up, pressed));
    CHECK(AdmitInput(QueueState(16, false, false), pressed, up,
                     IsHeldRelease(up, pressed)) == EnqueueAction::kAccept);
    CHECK(pressed.buttons.empty());
    // Button 2 was never pressed, so its up is not exempt.
    PlatformInput other = up;
    other.button = 2;
    CHECK(!IsHeldRelease(other, pressed));
    CHECK(AdmitInput(QueueState(16, false, false), pressed, other,
                     IsHeldRelease(other, pressed)) == EnqueueAction::kDrop);
}

RTSC_TEST(desktop_input_queue_unicode_release_is_not_exempt) {
    // A unicode key event types a character (KEYEVENTF_UNICODE, wVk = 0); it
    // presses no physical key, so it is never tracked and its release cannot
    // leave a key stuck. At the hard limit it is dropped like a press.
    PressedInputs pressed;
    PlatformInput down;
    down.kind = PlatformInput::Kind::kKey;
    down.unicode = 0x6F22;
    down.release = false;
    CHECK(IsReleaseInput(KeyUp(0x1E)));  // scan-code up is a release ...
    CHECK(!IsReleaseInput(down));
    CHECK(AdmitInput(QueueState(0, false, false), pressed, down,
                     IsHeldRelease(down, pressed)) == EnqueueAction::kAccept);
    CHECK(pressed.keys.empty());  // unicode presses are not tracked
    PlatformInput up = down;
    up.release = true;
    CHECK(IsReleaseInput(up));
    CHECK(!IsHeldRelease(up, pressed));
    CHECK(AdmitInput(QueueState(16, false, false), pressed, up,
                     IsHeldRelease(up, pressed)) == EnqueueAction::kDrop);
}

RTSC_TEST(desktop_input_queue_dropped_press_is_not_tracked) {
    // F1 regression guard: a press the hard limit dropped was never injected,
    // so it must not enter the held set. If tracking moved before the
    // admission decision, the key would look held, its later up would be
    // exempt, and the queue could grow with events for a key that was never
    // pressed.
    PressedInputs pressed;
    const EnqueueState full = QueueState(16, false, false);
    const PlatformInput down = KeyDown(0x1E);
    CHECK(AdmitInput(full, pressed, down, IsHeldRelease(down, pressed)) ==
          EnqueueAction::kDrop);
    CHECK(pressed.keys.empty());
    // The release of the dropped press is therefore not held: also dropped.
    const PlatformInput up = KeyUp(0x1E);
    CHECK(!IsHeldRelease(up, pressed));
    CHECK(AdmitInput(full, pressed, up, IsHeldRelease(up, pressed)) ==
          EnqueueAction::kDrop);
    CHECK(pressed.keys.empty());
}

// ---- Sink admission pipeline (AdmitAndTrack) -------------------------------
//
// The Win32 sink does not run any of this logic itself any more: it only builds
// the queue snapshot and applies the returned action to its container. Keeping
// "decide held release -> rate gate -> queue policy -> track" here means the
// wiring is covered by these platform-neutral tests instead of being untested
// code in desktop_input_win32.cpp.

RTSC_TEST(desktop_input_queue_rate_gate_gets_held_release_flag) {
    PressedInputs pressed;
    const auto allow = [](bool) { return true; };
    const PlatformInput down = KeyDown(0x1E);
    CHECK(AdmitAndTrack(QueueState(0, false, false), pressed, down, allow)
              .action == EnqueueAction::kAccept);
    CHECK_EQ(pressed.keys.size(), static_cast<size_t>(1));

    // The gate must be told the HELD flag (not "is a release"): the rate
    // limiter's exemption is exactly the queue's exemption.
    bool called = false;
    bool seen = false;
    const auto probe = [&](bool held_release) {
        called = true;
        seen = held_release;
        return true;
    };
    CHECK(AdmitAndTrack(QueueState(16, false, false), pressed, KeyUp(0x1E),
                        probe)
              .action == EnqueueAction::kAccept);
    CHECK(called);
    CHECK(seen);  // held up -> exempt candidate
    CHECK(pressed.keys.empty());

    // An up for a key that is not held is told false, so the limiter treats it
    // like a press (and the queue hard limit still applies to it).
    called = false;
    seen = true;
    CHECK(AdmitAndTrack(QueueState(16, false, false), pressed, KeyUp(0x1F),
                        probe)
              .action == EnqueueAction::kDrop);
    CHECK(called);
    CHECK(!seen);

    // Unicode key-ups carry no physical state: never held.
    PlatformInput unicode_up;
    unicode_up.kind = PlatformInput::Kind::kKey;
    unicode_up.unicode = 0x6F22;
    unicode_up.release = true;
    seen = true;
    AdmitAndTrack(QueueState(16, false, false), pressed, unicode_up, probe);
    CHECK(!seen);
}

RTSC_TEST(desktop_input_queue_rate_limited_input_is_not_tracked) {
    // E2: the rate gate runs BEFORE the queue bookkeeping. A press the limiter
    // refused was never queued or injected, so it must not enter the held set
    // (otherwise its up would be exempt even though no press ever happened).
    PressedInputs pressed;
    const auto deny = [](bool) { return false; };
    const AdmitOutcome refused =
        AdmitAndTrack(QueueState(0, false, false), pressed, KeyDown(0x1E),
                      deny);
    CHECK(refused.rate_limited);
    CHECK(refused.action == EnqueueAction::kDrop);
    CHECK(!refused.held_release);
    CHECK(pressed.keys.empty());
    // Its later up is therefore not held and is dropped at the hard limit.
    bool seen = true;
    const auto probe = [&](bool held_release) {
        seen = held_release;
        return true;
    };
    const AdmitOutcome up = AdmitAndTrack(QueueState(16, false, false),
                                          pressed, KeyUp(0x1E), probe);
    CHECK(!seen);
    CHECK(!up.held_release);
    CHECK(up.action == EnqueueAction::kDrop);

    // A HELD release refused by the limiter stays held: it was not injected,
    // so the key/button must still be released later (teardown or next up).
    PressedInputs held;
    const auto allow = [](bool) { return true; };
    CHECK(AdmitAndTrack(QueueState(0, false, false), held, KeyDown(0x1D),
                        allow)
              .action == EnqueueAction::kAccept);
    const AdmitOutcome denied_up =
        AdmitAndTrack(QueueState(16, false, false), held, KeyUp(0x1D), deny);
    CHECK(denied_up.rate_limited);
    CHECK(denied_up.held_release);
    CHECK_EQ(held.keys.size(), static_cast<size_t>(1));
}

// ---- Injection rate limiting (token buckets) -------------------------------
//
// The Win32 sink applies the limiter inside Inject(), under the same mutex as
// the queue. These cases drive it with explicit timestamps so the 400 evt/s +
// 800 burst session bucket and the 1000 evt/s + 2000 burst global bucket are
// pinned exactly, without sleeping.

namespace {
using RateClock = std::chrono::steady_clock;
using rtsc::server::InputRateLimiter;

RateClock::time_point RateTime(int seconds) {
    return RateClock::time_point() + std::chrono::seconds(seconds);
}
}  // namespace

RTSC_TEST(desktop_input_rate_limit_session_bucket) {
    // One session: a burst of 800 is accepted at once, the 801st event is
    // dropped, and exactly 400 more are accepted after one second of refill
    // (400 evt/s).
    InputRateLimiter limiter;
    const RateClock::time_point t0 = RateTime(1000);
    size_t allowed = 0;
    for (int i = 0; i < 800; ++i) {
        if (limiter.Allow(1, false, t0)) ++allowed;
    }
    CHECK_EQ(allowed, static_cast<size_t>(800));
    CHECK(!limiter.Allow(1, false, t0));
    CHECK_EQ(limiter.dropped(), static_cast<size_t>(1));

    allowed = 0;
    const RateClock::time_point t1 = t0 + std::chrono::seconds(1);
    for (int i = 0; i < 401; ++i) {
        if (limiter.Allow(1, false, t1)) ++allowed;
    }
    CHECK_EQ(allowed, static_cast<size_t>(400));
    CHECK_EQ(limiter.dropped(), static_cast<size_t>(2));
}

RTSC_TEST(desktop_input_rate_limit_release_is_exempt) {
    // A release (key-up / button-up) must never be rate limited: dropping one
    // leaves the local key or button stuck. Releases also consume no token, so
    // a burst of releases cannot starve the presses that follow.
    InputRateLimiter limiter;
    const RateClock::time_point t0 = RateTime(2000);
    size_t allowed = 0;
    for (int i = 0; i < 800; ++i) {
        if (limiter.Allow(1, false, t0)) ++allowed;
    }
    CHECK_EQ(allowed, static_cast<size_t>(800));
    CHECK(!limiter.Allow(1, false, t0));

    allowed = 0;
    for (int i = 0; i < 5000; ++i) {
        if (limiter.Allow(1, true, t0)) ++allowed;
    }
    CHECK_EQ(allowed, static_cast<size_t>(5000));
    // The press is still limited: releases did not replenish the bucket.
    CHECK(!limiter.Allow(1, false, t0));
    CHECK_EQ(limiter.dropped(), static_cast<size_t>(2));
}

RTSC_TEST(desktop_input_rate_limit_unheld_release_is_limited) {
    // E1: only a HELD release is exempt. A key-up for a key the session never
    // pressed is an ordinary platform action: it spends a token and is dropped
    // once the bucket is empty (previously every key-up was exempt, so one
    // session could inject an unbounded stream of up events).
    InputRateLimiter limiter;
    PressedInputs pressed;  // nothing held
    const RateClock::time_point t0 = RateTime(7000);
    for (int i = 0; i < 800; ++i) {
        CHECK(limiter.Allow(1, false, t0));
    }
    CHECK(!limiter.Allow(1, false, t0));

    size_t allowed = 0;
    for (int i = 0; i < 5000; ++i) {
        const bool held_release = IsHeldRelease(KeyUp(0x1E), pressed);
        CHECK(!held_release);
        if (limiter.Allow(1, held_release, t0)) ++allowed;
    }
    CHECK_EQ(allowed, static_cast<size_t>(0));

    // A held release is still exempt and spends no token.
    pressed.keys.insert(KeyId{0x1D, false});
    CHECK(IsHeldRelease(KeyUp(0x1D), pressed));
    CHECK(limiter.Allow(1, IsHeldRelease(KeyUp(0x1D), pressed), t0));
    // Unicode ups are not held either, so they are limited too.
    PlatformInput unicode_up;
    unicode_up.kind = PlatformInput::Kind::kKey;
    unicode_up.unicode = 0x6F22;
    unicode_up.release = true;
    CHECK(!IsHeldRelease(unicode_up, pressed));
    CHECK(!limiter.Allow(1, IsHeldRelease(unicode_up, pressed), t0));
}

RTSC_TEST(desktop_input_rate_limit_held_release_keeps_token) {
    // E1-T: a HELD release is not merely "allowed", it spends no token. Drain
    // the session bucket to exactly one of its 800 tokens, then lift 100 keys
    // that are genuinely held (each was pressed and tracked earlier). All 100
    // ups pass, nothing is dropped, and the one token left is still spendable:
    // if the exemption had charged a token, the final press would be refused.
    InputRateLimiter limiter;
    PressedInputs pressed;
    const RateClock::time_point t0 = RateTime(8000);
    const auto gate = [&](bool held_release) {
        return limiter.Allow(1, held_release, t0);
    };

    // Press 100 keys; AdmitAndTrack records them in `pressed`.
    for (int i = 0; i < 100; ++i) {
        const AdmitOutcome down = AdmitAndTrack(
            QueueState(0, false, false), pressed,
            KeyDown(static_cast<uint8_t>(i + 1)), gate);
        CHECK(down.action == EnqueueAction::kAccept);
        CHECK(!down.rate_limited);
    }
    // 699 more presses leave exactly 1 of the 800 burst tokens.
    for (int i = 0; i < 699; ++i) {
        CHECK(limiter.Allow(1, false, t0));
    }
    CHECK_EQ(pressed.keys.size(), static_cast<size_t>(100));

    const size_t dropped_before = limiter.dropped();
    size_t allowed_ups = 0;
    for (int i = 0; i < 100; ++i) {
        const AdmitOutcome up = AdmitAndTrack(
            QueueState(0, false, false), pressed,
            KeyUp(static_cast<uint8_t>(i + 1)), gate);
        CHECK(up.held_release);
        CHECK(!up.rate_limited);
        CHECK(up.action == EnqueueAction::kAccept);
        if (!up.rate_limited) ++allowed_ups;
    }
    CHECK_EQ(allowed_ups, static_cast<size_t>(100));
    CHECK_EQ(limiter.dropped(), dropped_before);
    CHECK(pressed.keys.empty());

    // The kept token is still there: one press is allowed, the next is not.
    CHECK(limiter.Allow(1, false, t0));
    CHECK(!limiter.Allow(1, false, t0));

    // Control: an UNHELD up is limited like a press and DOES spend the last
    // token. Without this the test could not tell "exempt" from "free".
    InputRateLimiter unheld;
    PressedInputs nothing_held;
    const auto unheld_gate = [&](bool held_release) {
        return unheld.Allow(2, held_release, t0);
    };
    for (int i = 0; i < 799; ++i) {
        CHECK(unheld.Allow(2, false, t0));
    }
    const AdmitOutcome stray_up = AdmitAndTrack(
        QueueState(0, false, false), nothing_held, KeyUp(0x2A), unheld_gate);
    CHECK(!stray_up.held_release);
    CHECK(!stray_up.rate_limited);
    CHECK_EQ(unheld.dropped(), static_cast<size_t>(0));
    CHECK(!unheld.Allow(2, false, t0));
    CHECK_EQ(unheld.dropped(), static_cast<size_t>(1));

    // The same must hold for the GLOBAL bucket: a held up must not spend the
    // shared token either. Exhaust the global bucket to exactly one token
    // (800 + 800 + 399 = 1999 of 2000), lift 100 held keys of session 4, and
    // prove the shared token still buys one press.
    InputRateLimiter shared;
    PressedInputs shared_pressed;
    shared_pressed.keys.insert(KeyId{0x1D, false});
    for (int i = 0; i < 800; ++i) CHECK(shared.Allow(1, false, t0));
    for (int i = 0; i < 800; ++i) CHECK(shared.Allow(2, false, t0));
    for (int i = 0; i < 399; ++i) CHECK(shared.Allow(3, false, t0));
    const size_t shared_dropped_before = shared.dropped();
    for (int i = 0; i < 100; ++i) {
        CHECK(shared.Allow(4, IsHeldRelease(KeyUp(0x1D), shared_pressed), t0));
    }
    CHECK_EQ(shared.dropped(), shared_dropped_before);
    CHECK(shared.Allow(4, false, t0));   // the kept global token survived
    CHECK(!shared.Allow(4, false, t0));  // ...and it was only one
}

RTSC_TEST(desktop_input_rate_limit_global_bucket) {
    // The global bucket (1000 evt/s, burst 2000) caps the sum over sessions:
    // 8 sessions x 250 events = 2000 accepted, the next event is dropped even
    // though every session bucket still has room. After one second exactly
    // 1000 more are accepted.
    InputRateLimiter limiter;
    const RateClock::time_point t0 = RateTime(3000);
    size_t allowed = 0;
    for (uint32_t session = 1; session <= 8; ++session) {
        for (int i = 0; i < 250; ++i) {
            if (limiter.Allow(session, false, t0)) ++allowed;
        }
    }
    CHECK_EQ(allowed, static_cast<size_t>(2000));
    CHECK(!limiter.Allow(9, false, t0));
    CHECK_EQ(limiter.dropped(), static_cast<size_t>(1));

    allowed = 0;
    const RateClock::time_point t1 = t0 + std::chrono::seconds(1);
    for (uint32_t session = 1; session <= 8; ++session) {
        for (int i = 0; i < 126; ++i) {
            if (limiter.Allow(session, false, t1)) ++allowed;
        }
    }
    // 8 x 126 = 1008 offered, the global refill is 1000.
    CHECK_EQ(allowed, static_cast<size_t>(1000));
    CHECK_EQ(limiter.dropped(), static_cast<size_t>(9));
}

RTSC_TEST(desktop_input_rate_limit_global_drop_keeps_session_token) {
    // A global-bucket denial must not spend the session's token: otherwise a
    // busy peer would silently drain every session's allowance. Session 1 is
    // left with exactly one token while the global bucket is empty; after one
    // second session 1 can still spend 401 events (400 refilled + the one it
    // kept), and the 402nd is denied by its own bucket.
    InputRateLimiter limiter;
    const RateClock::time_point t0 = RateTime(4000);
    for (int i = 0; i < 799; ++i) {
        CHECK(limiter.Allow(1, false, t0));
    }
    for (int i = 0; i < 800; ++i) {
        CHECK(limiter.Allow(2, false, t0));
    }
    for (int i = 0; i < 401; ++i) {
        CHECK(limiter.Allow(3, false, t0));
    }
    // 799 + 800 + 401 = 2000: the global bucket is empty, session 1 has 1 left.
    CHECK(!limiter.Allow(1, false, t0));

    const RateClock::time_point t1 = t0 + std::chrono::seconds(1);
    size_t allowed = 0;
    for (int i = 0; i < 401; ++i) {
        if (limiter.Allow(1, false, t1)) ++allowed;
    }
    CHECK_EQ(allowed, static_cast<size_t>(401));
    CHECK(!limiter.Allow(1, false, t1));
}

RTSC_TEST(desktop_input_rate_limit_is_per_session) {
    // One exhausted session must not affect another session's allowance.
    InputRateLimiter limiter;
    const RateClock::time_point t0 = RateTime(5000);
    for (int i = 0; i < 800; ++i) {
        CHECK(limiter.Allow(7, false, t0));
    }
    CHECK(!limiter.Allow(7, false, t0));
    CHECK(limiter.Allow(8, false, t0));
}

RTSC_TEST(desktop_input_rate_limit_forget_resets_session) {
    // ReleaseSession forgets the session's bucket, so a later session that
    // reuses the id starts with a full burst instead of inheriting a drained
    // bucket from the previous holder.
    InputRateLimiter limiter;
    const RateClock::time_point t0 = RateTime(6000);
    for (int i = 0; i < 800; ++i) {
        CHECK(limiter.Allow(1, false, t0));
    }
    CHECK(!limiter.Allow(1, false, t0));
    limiter.Forget(1);
    CHECK(limiter.Allow(1, false, t0));
}

RTSC_TEST(desktop_input_is_injectable_matches_translation) {
    // F4-A3: the server must only take the single desktop input lease for an
    // event that can actually produce a platform input. IsInjectable() is the
    // gate, so it must agree with TranslateInput() for every event kind.
    std::vector<InputEvent> events;
    events.push_back(KeyEvent(0x1E, false, false));  // key down
    events.push_back(KeyEvent(0x1E, false, true));   // key up
    events.push_back(KeyEvent(0x00, false, false));  // zero scancode
    InputEvent extended1_key = KeyEvent(0x1D, false, false);
    extended1_key.extended1 = true;  // PAUSE half (0xE1 prefix)
    events.push_back(extended1_key);

    InputEvent unicode;
    unicode.kind = InputEvent::Kind::kUnicode;
    unicode.unicode_code = 0x6F22;
    events.push_back(unicode);
    InputEvent zero_unicode;
    zero_unicode.kind = InputEvent::Kind::kUnicode;
    zero_unicode.unicode_code = 0;
    events.push_back(zero_unicode);

    InputEvent bare_mouse;
    bare_mouse.kind = InputEvent::Kind::kMouse;
    events.push_back(bare_mouse);  // no move, no button
    InputEvent mouse_move;
    mouse_move.kind = InputEvent::Kind::kMouse;
    mouse_move.is_move = true;
    events.push_back(mouse_move);
    InputEvent mouse_button;
    mouse_button.kind = InputEvent::Kind::kMouse;
    mouse_button.button = 1;
    mouse_button.button_down = true;
    events.push_back(mouse_button);

    InputEvent wheel;
    wheel.kind = InputEvent::Kind::kWheel;
    wheel.wheel_delta = 120;
    events.push_back(wheel);
    InputEvent zero_wheel;
    zero_wheel.kind = InputEvent::Kind::kWheel;
    zero_wheel.wheel_delta = 0;  // no-op: must not take the lease
    events.push_back(zero_wheel);

    InputEvent mouse_rel;
    mouse_rel.kind = InputEvent::Kind::kMouseRel;
    mouse_rel.rel_x = 10;
    events.push_back(mouse_rel);

    InputEvent sync;
    sync.kind = InputEvent::Kind::kSync;
    events.push_back(sync);

    // The one-argument form answers "can this event ever become an action",
    // independent of geometry, so it is cross-checked against a usable
    // geometry. The geometry-aware form must agree with TranslateInput for the
    // very same geometry, including the case where a pure move is fail-closed
    // and only a button survives.
    const InjectGeometry usable = PhysicalGeometry(1920, 1080);
    for (const InputEvent& ev : events) {
        CHECK(IsInjectable(ev) == !TranslateInput(ev, usable).empty());
        CHECK(IsInjectable(ev, usable) == !TranslateInput(ev, usable).empty());
    }
    // Pin the non-injectable kinds explicitly so a change to TranslateInput
    // cannot silently make them take the lease.
    CHECK(!IsInjectable(sync));
    CHECK(!IsInjectable(mouse_rel));
    CHECK(!IsInjectable(KeyEvent(0x00, false, false)));
    CHECK(!IsInjectable(zero_unicode));
    CHECK(!IsInjectable(bare_mouse));
    CHECK(!IsInjectable(extended1_key));
    CHECK(!IsInjectable(zero_wheel));

    // With untrusted geometry a pure move can never become an action, so the
    // geometry-aware form must reject it (the one-argument form still reports
    // "in principle yes"). A click keeps its button and stays injectable.
    const InjectGeometry untrusted;
    CHECK(!IsInjectable(mouse_move, untrusted));
    CHECK(IsInjectable(mouse_button, untrusted));
}

RTSC_TEST(desktop_input_stats_line_reports_every_counter) {
    // The shipped host builds its periodic line with FormatInputStats(). The
    // four queue/rate/failure counters and dropped_unmapped are otherwise
    // invisible to an operator, so every field must appear with its own value.
    // Asserting the function's return value replaces the old source-text grep,
    // which a rename plus a comment could satisfy without printing anything.
    InputStats stats;
    stats.injected = 11;
    stats.dropped_queue_full = 22;
    stats.dropped_rate_limited = 33;
    stats.send_failures = 44;
    stats.release_failures = 55;
    stats.worker_failures = 66;
    stats.dropped_unmapped = 77;
    const std::string line = FormatInputStats("periodic", stats);
    CHECK_EQ(line.compare(0, 24, "input stats (periodic): "), 0);
    CHECK(line.find("input_injected=11 ") != std::string::npos);
    CHECK(line.find("input_dropped_queue=22 ") != std::string::npos);
    CHECK(line.find("input_rate_limited=33 ") != std::string::npos);
    CHECK(line.find("input_send_failures=44 ") != std::string::npos);
    CHECK(line.find("input_release_failures=55 ") != std::string::npos);
    CHECK(line.find("input_worker_failures=66 ") != std::string::npos);
    CHECK(line.size() >= 25);
    CHECK_EQ(line.compare(line.size() - 25, 25, "input_dropped_unmapped=77"),
             0);
    // A different reason is carried through verbatim.
    CHECK_EQ(FormatInputStats("final", stats).compare(0, 21,
                                                     "input stats (final): "),
             0);
}

RTSC_TEST(desktop_input_stats_change_detection_covers_all_counters) {
    // The host only logs a periodic line when InputStatsChanged() says so. If a
    // counter is missing from the comparison, a session whose only fault is
    // that counter never produces a line (the batch 24 R3 case was
    // dropped_unmapped). Each field is bumped alone here, in BOTH directions:
    // only `injected` used to be checked both ways, so turning `!=` into `<` on
    // any other field stayed green (audit U, batch 26 U-1).
    const InputStats base;
    CHECK(!InputStatsChanged(base, base));
    auto bump = [&base](const char* which) {
        InputStats next = base;
        if (std::strcmp(which, "injected") == 0) next.injected = 1;
        if (std::strcmp(which, "queue") == 0) next.dropped_queue_full = 1;
        if (std::strcmp(which, "rate") == 0) next.dropped_rate_limited = 1;
        if (std::strcmp(which, "send") == 0) next.send_failures = 1;
        if (std::strcmp(which, "release") == 0) next.release_failures = 1;
        if (std::strcmp(which, "worker") == 0) next.worker_failures = 1;
        if (std::strcmp(which, "unmapped") == 0) next.dropped_unmapped = 1;
        return next;
    };
    for (const char* field :
         {"injected", "queue", "rate", "send", "release", "worker", "unmapped"}) {
        const InputStats moved = bump(field);
        // Forward (a counter grew) and reverse (the arguments are swapped: the
        // caller's snapshot is the larger one after a restart or a reset).
        CHECK(InputStatsChanged(base, moved));
        CHECK(InputStatsChanged(moved, base));
    }
}

RTSC_TEST(desktop_input_stats_line_field_order_is_stable) {
    // Asserting that each `key=value` substring exists says nothing about the
    // order they appear in, so swapping two whole segments (keys and values
    // moved together) stayed green (audit U, batch 26 U-2). Operators and log
    // scrapers match on position, so the order is part of the contract: pin it
    // once, completely, against a hand-written expected line.
    InputStats stats;
    stats.injected = 1;
    stats.dropped_queue_full = 2;
    stats.dropped_rate_limited = 3;
    stats.send_failures = 4;
    stats.release_failures = 5;
    stats.worker_failures = 6;
    stats.dropped_unmapped = 7;
    const std::string expected =
        "input stats (periodic): input_injected=1 "
        "input_dropped_queue=2 input_rate_limited=3 "
        "input_send_failures=4 input_release_failures=5 "
        "input_worker_failures=6 input_dropped_unmapped=7";
    CHECK(FormatInputStats("periodic", stats) == expected);
}

RTSC_TEST(desktop_input_stats_line_handles_null_reason) {
    // The host always passes a literal reason, so a null one is only reachable
    // from a future caller. It must not crash and must not print the word
    // "null": the prefix is empty (audit U, batch 26 U-3).
    const InputStats stats;
    CHECK_EQ(FormatInputStats(nullptr, stats).compare(0, 16, "input stats (): "),
             0);
    CHECK(FormatInputStats(nullptr, stats).find("null") == std::string::npos);
}


RTSC_TEST(desktop_input_periodic_line_is_empty_until_a_counter_moves) {
    // Requirements, in order:
    //   1. no baseline (first sample)  -> print
    //   2. baseline equal to current   -> nothing (no log flood)
    //   3. a counter moved             -> print `periodic`
    //   4. back to the printed values  -> nothing
    //   5. a counter going backwards   -> print
    // Case 1 is what makes the host periodic call site observable from a
    // plain `--seconds` run (batch 27): without it the only guaranteed line
    // was the unconditional `final` one, so deleting the whole call site
    // stayed green (batch 26 F5 residual, reported OPEN).
    const InputStats base;
    const std::string first = PeriodicInputStatsLine(nullptr, base);
    CHECK(!first.empty());
    CHECK_EQ(first.compare(0, 24, "input stats (periodic): "), 0);

    CHECK(PeriodicInputStatsLine(&base, base).empty());

    InputStats moved = base;
    moved.dropped_unmapped = 3;
    const std::string line = PeriodicInputStatsLine(&base, moved);
    CHECK(!line.empty());
    CHECK_EQ(line.compare(0, 24, "input stats (periodic): "), 0);
    CHECK(line.find("input_dropped_unmapped=3") != std::string::npos);
    // A `final` line is a different reason and must never be mistaken for one.
    CHECK(line.find("(final)") == std::string::npos);

    // Going back to the printed values produces nothing again: the caller keeps
    // the last printed snapshot, so an intermediate change does not stick.
    CHECK(PeriodicInputStatsLine(&moved, moved).empty());
    CHECK(PeriodicInputStatsLine(&moved, base).empty() == false);
}

RTSC_TEST(desktop_input_null_sink_stats_count_injections) {
    // This test target links the null sink on every platform (see
    // CMakeLists.txt), so Stats() accounting is asserted without touching the
    // local desktop. The null sink accepts each event and drops it.
    auto sink = MakeWin32DesktopInputSink();
    CHECK(sink != nullptr);
    if (!sink) return;
    CHECK_EQ(sink->Stats().injected, static_cast<size_t>(0));
    InputEvent ev;
    ev.kind = InputEvent::Kind::kKey;
    ev.scancode = 0x1E;
    sink->Inject(1, ev);
    CHECK_EQ(sink->Stats().injected, static_cast<size_t>(1));
    sink->Inject(1, ev);
    CHECK_EQ(sink->Stats().injected, static_cast<size_t>(2));
    CHECK_EQ(sink->Stats().dropped_queue_full, static_cast<size_t>(0));
    // The null backend has no queue, so it never rate-limits; the counter is
    // present so a host can read it uniformly from DesktopInputSink::Stats().
    CHECK_EQ(sink->Stats().dropped_rate_limited, static_cast<size_t>(0));
    CHECK_EQ(sink->Stats().send_failures, static_cast<size_t>(0));
    // The null backend has no queue, so a teardown release can never fail to
    // be queued: the counter is explicitly zero, not merely defaulted.
    CHECK_EQ(sink->Stats().release_failures, static_cast<size_t>(0));
    // ... and it has no worker, so a worker iteration can never fail either.
    CHECK_EQ(sink->Stats().worker_failures, static_cast<size_t>(0));
    // The null backend has no geometry, so it never fail-closes a move; the
    // server-side note (a pure move refused before Inject) is a no-op too.
    sink->NoteUnmappableMove(1);
    CHECK_EQ(sink->Stats().dropped_unmapped, static_cast<size_t>(0));
    sink->ReleaseSession(1);
    CHECK_EQ(sink->Stats().injected, static_cast<size_t>(2));
}

#if defined(RTSC_DESKTOP_INPUT_TESTING)
// Forces one worker iteration to throw before it reaches SendInput, so a case
// can drive the mappable-move accounting without touching the real desktop.
namespace {
bool AlwaysFailDispatch(uint32_t /*session_id*/) { return true; }
}  // namespace

RTSC_TEST(desktop_input_unmapped_move_is_counted_separately) {
    // A move with untrusted geometry is fail-closed: it never reaches the
    // queue/worker (no SendInput) and its drop is visible in its own counter,
    // so an operator can distinguish "geometry untrusted" from an
    // unrepresentable event.
    std::unique_ptr<rtsc::server::DesktopInputSink> sink =
        rtsc::server::MakeWin32DesktopInputSinkForTest();
    CHECK(sink != nullptr);
    if (!sink) return;
    InputEvent move;
    move.kind = InputEvent::Kind::kMouse;
    move.is_move = true;
    move.x = 640;
    move.y = 512;
    InjectGeometry untrusted;
    untrusted.width = 1280;
    untrusted.height = 1024;
    sink->SetGeometry(1, untrusted);
    sink->Inject(1, move);
    CHECK_EQ(sink->Stats().dropped_unmapped, static_cast<size_t>(1));
    CHECK_EQ(sink->Stats().injected, static_cast<size_t>(0));
}

RTSC_TEST(desktop_input_note_unmappable_move_counts_without_inject) {
    // Batch 24 S1: the server fail-closes a pure move before taking the lease,
    // so Inject() is never called for it. The sink must still count the drop
    // when the server reports it through NoteUnmappableMove(), otherwise
    // dropped_unmapped stays 0 for exactly the session an operator needs to
    // diagnose (untrusted geometry, no lease).
    std::unique_ptr<rtsc::server::DesktopInputSink> sink =
        rtsc::server::MakeWin32DesktopInputSinkForTest();
    CHECK(sink != nullptr);
    if (!sink) return;
    CHECK_EQ(sink->Stats().dropped_unmapped, static_cast<size_t>(0));
    sink->NoteUnmappableMove(1);
    CHECK_EQ(sink->Stats().dropped_unmapped, static_cast<size_t>(1));
    sink->NoteUnmappableMove(1);
    CHECK_EQ(sink->Stats().dropped_unmapped, static_cast<size_t>(2));
    // Nothing was injected and no session state was needed for the note.
    CHECK_EQ(sink->Stats().injected, static_cast<size_t>(0));
}

RTSC_TEST(desktop_input_unmapped_move_is_not_double_counted) {
    // The two drop counters answer DIFFERENT questions and must not overlap:
    //   dropped_unmapped    = a move fail-closed because the geometry is not
    //                         trusted (an operator can fix the capture side)
    //   dropped_unsupported = an event with no platform form at all (nothing
    //                         the operator can do)
    // Double counting would make them indistinguishable, and counting every
    // move as unmapped would report a fault on a healthy session.
    std::unique_ptr<rtsc::server::DesktopInputSink> sink =
        rtsc::server::MakeWin32DesktopInputSinkForTest();
    CHECK(sink != nullptr);
    if (!sink) return;

    InputEvent move;
    move.kind = InputEvent::Kind::kMouse;
    move.is_move = true;
    move.x = 640;
    move.y = 512;

    InjectGeometry untrusted;
    untrusted.width = 1280;
    untrusted.height = 1024;
    sink->SetGeometry(1, untrusted);
    sink->Inject(1, move);
    CHECK_EQ(sink->Stats().dropped_unmapped, static_cast<size_t>(1));
    // ... and NOT additionally as unsupported.
    CHECK_EQ(rtsc::server::DesktopInputTestDroppedUnsupported(sink.get()),
             static_cast<size_t>(0));

    // A move that IS mappable must not raise dropped_unmapped at all. The
    // dispatch hook makes the worker iteration throw before it reaches
    // SendInput, so the real desktop is never touched while the Inject()-side
    // accounting is still exercised.
    rtsc::server::SetDesktopInputDispatchFailureHook(&AlwaysFailDispatch);
    sink->SetGeometry(2, PhysicalGeometry(1280, 1024));
    sink->Inject(2, move);
    const bool dispatched = WaitUntil(
        [&sink]() { return sink->Stats().worker_failures >= 1; });
    rtsc::server::SetDesktopInputDispatchFailureHook(nullptr);
    CHECK(dispatched);
    CHECK_EQ(sink->Stats().dropped_unmapped, static_cast<size_t>(1));
    CHECK_EQ(rtsc::server::DesktopInputTestDroppedUnsupported(sink.get()),
             static_cast<size_t>(0));
}

RTSC_TEST(desktop_input_release_session_clears_state_when_append_throws) {
    // N-1: the synthetic ups for a released session are queued by
    // AppendReleasesLocked, which can throw (a deque allocation). Before the
    // fix that exception skipped both sessions_.erase and cv_.notify_one:
    // the session stayed half-alive, and because Inject() early-returns for a
    // forgotten id without notifying, the worker could sleep forever and the
    // next session (ids restart at 1) would have all its input dropped.
    std::unique_ptr<rtsc::server::DesktopInputSink> sink =
        rtsc::server::MakeWin32DesktopInputSinkForTest();
    CHECK(sink != nullptr);
    if (!sink) return;
    // Deterministic precondition: the worker must already be parked in the
    // queue wait. Otherwise its first loop drains the forget request by itself
    // and a removed notify_one still looks green (J-3b: the mechanism behind
    // the 30/20/100-run false-green mutation).
    CHECK(WaitUntil([&sink]() {
        return rtsc::server::DesktopInputTestWorkerWaiting(sink.get());
    }));
    rtsc::server::DesktopInputTestSeedPressedKey(sink.get(), 7, 0x1E, false);
    CHECK_EQ(rtsc::server::DesktopInputTestSessionCount(sink.get()),
             static_cast<size_t>(1));
    rtsc::server::SetDesktopInputAppendFailureHook(
        [](uint32_t, size_t) { return true; });
    sink->ReleaseSession(7);
    rtsc::server::SetDesktopInputAppendFailureHook(nullptr);
    // Unconditional teardown, even though appending the ups failed.
    CHECK_EQ(rtsc::server::DesktopInputTestSessionCount(sink.get()),
             static_cast<size_t>(0));
    CHECK_EQ(sink->Stats().release_failures, static_cast<size_t>(1));
    // The lost release must be observable and the worker must still be woken:
    // the forget request is drained by the worker under the mutex. The worker
    // was parked before ReleaseSession ran, so only notify_one can wake it.
    CHECK(WaitUntil([&sink]() {
        return rtsc::server::DesktopInputTestPendingForgetCount(sink.get()) == 0;
    }));
}

RTSC_TEST(desktop_input_test_hooks_reject_foreign_sink) {
    // J-2: the test hooks used to `static_cast` a DesktopInputSink* down to
    // Win32DesktopInputSink*. Feeding them anything else -- a null pointer, or
    // the null sink this suite's own factory returns -- was undefined
    // behaviour (observed: wrong values, 0xC0000005, 0xC0000409, a hang). The
    // hooks must detect a foreign dynamic type and report "not a Win32 sink".
    // All calls must return 0/empty and not touch anything.
    CHECK_EQ(rtsc::server::DesktopInputTestSessionCount(nullptr),
             static_cast<size_t>(0));
    CHECK_EQ(rtsc::server::DesktopInputTestPendingForgetCount(nullptr),
             static_cast<size_t>(0));
    CHECK(!rtsc::server::DesktopInputTestWorkerJoinable(nullptr));
    CHECK(!rtsc::server::DesktopInputTestWorkerWaiting(nullptr));
    rtsc::server::DesktopInputTestSeedPressedKey(nullptr, 1, 0x1E, false);
    rtsc::server::DesktopInputTestShutdown(nullptr);

    std::unique_ptr<rtsc::server::DesktopInputSink> foreign =
        rtsc::server::MakeWin32DesktopInputSink();
    CHECK(foreign != nullptr);
    if (!foreign) return;
    CHECK_EQ(rtsc::server::DesktopInputTestSessionCount(foreign.get()),
             static_cast<size_t>(0));
    CHECK_EQ(rtsc::server::DesktopInputTestPendingForgetCount(foreign.get()),
             static_cast<size_t>(0));
    CHECK(!rtsc::server::DesktopInputTestWorkerJoinable(foreign.get()));
    CHECK(!rtsc::server::DesktopInputTestWorkerWaiting(foreign.get()));
    rtsc::server::DesktopInputTestSeedPressedKey(foreign.get(), 1, 0x1E, false);
    rtsc::server::DesktopInputTestShutdown(foreign.get());
    // Shutdown on a foreign sink is a no-op: the object is still usable.
    CHECK_EQ(foreign->Stats().injected, static_cast<size_t>(0));
}

RTSC_TEST(desktop_input_shutdown_joins_worker_when_append_throws) {
    // N-2: Shutdown appends the synthetic ups for every live session before
    // joining the worker. If that append throws and the join is skipped,
    // ~Win32DesktopInputSink leaves a joinable std::thread behind and the
    // std::thread destructor calls std::terminate -- teardown kills the
    // process. Shutdown must be noexcept: join runs no matter what.
    std::unique_ptr<rtsc::server::DesktopInputSink> sink =
        rtsc::server::MakeWin32DesktopInputSinkForTest();
    CHECK(sink != nullptr);
    if (!sink) return;
    rtsc::server::DesktopInputTestSeedPressedKey(sink.get(), 3, 0x2A, false);
    rtsc::server::SetDesktopInputAppendFailureHook(
        [](uint32_t, size_t) { return true; });
    rtsc::server::DesktopInputTestShutdown(sink.get());
    rtsc::server::SetDesktopInputAppendFailureHook(nullptr);
    CHECK(!rtsc::server::DesktopInputTestWorkerJoinable(sink.get()));
    CHECK_EQ(sink->Stats().release_failures, static_cast<size_t>(1));
    CHECK_EQ(sink->Stats().worker_failures, static_cast<size_t>(0));
    CHECK_EQ(rtsc::server::DesktopInputTestSessionCount(sink.get()),
             static_cast<size_t>(0));
    if (rtsc::server::DesktopInputTestWorkerJoinable(sink.get())) {
        // A broken shutdown left the worker unjoined: keep the sink alive so
        // this test's failure is reported instead of becoming std::terminate.
        static rtsc::server::DesktopInputSink* leaked = sink.release();
        (void)leaked;
    }
}
RTSC_TEST(desktop_input_worker_failures_counts_a_failed_dispatch) {
    // J-3a: every existing assertion pinned worker_failures == 0, so deleting
    // the count point (desktop_input_win32.cpp WorkerMain's catch) or the
    // catch itself left the suite green. Force one worker iteration to throw
    // and prove the counter actually rises -- the only visible signal that a
    // queued platform action was dropped.
    std::unique_ptr<rtsc::server::DesktopInputSink> sink =
        rtsc::server::MakeWin32DesktopInputSinkForTest();
    CHECK(sink != nullptr);
    if (!sink) return;
    // Deterministic precondition: the worker must be parked, so the injected
    // event is drained by exactly one Dispatch after the hook is armed.
    CHECK(WaitUntil([&sink]() {
        return rtsc::server::DesktopInputTestWorkerWaiting(sink.get());
    }));
    CHECK_EQ(sink->Stats().worker_failures, static_cast<size_t>(0));

    rtsc::server::SetDesktopInputDispatchFailureHook(
        [](uint32_t) { return true; });
    rtsc::server::InputEvent ev;
    ev.kind = rtsc::server::InputEvent::Kind::kKey;
    ev.scancode = 0x1E;
    sink->Inject(1, ev);
    const bool counted = WaitUntil([&sink]() {
        return sink->Stats().worker_failures >= 1;
    });
    rtsc::server::SetDesktopInputDispatchFailureHook(nullptr);
    CHECK(counted);
    CHECK(sink->Stats().worker_failures >= 1);
    // The worker survived the throw and still drains: a later event is
    // dispatched normally (no failure hook armed) instead of the thread dying.
    rtsc::server::InputEvent ev2;
    ev2.kind = rtsc::server::InputEvent::Kind::kKey;
    ev2.scancode = 0x1F;
    sink->Inject(2, ev2);
    rtsc::server::DesktopInputTestShutdown(sink.get());
    CHECK(!rtsc::server::DesktopInputTestWorkerJoinable(sink.get()));
    if (rtsc::server::DesktopInputTestWorkerJoinable(sink.get())) {
        // Keep the object alive so a broken join is reported, not terminate.
        static rtsc::server::DesktopInputSink* leaked = sink.release();
        (void)leaked;
    }
}

#endif  // RTSC_DESKTOP_INPUT_TESTING

int main() { return rtsc::test::run_all("rtsc_desktop_input_tests"); }
