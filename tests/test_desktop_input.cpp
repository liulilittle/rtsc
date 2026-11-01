// Pure mapping tests for the desktop input injection seam.
//
// TranslateInput() is platform neutral by design: it never includes
// <windows.h> and never calls SendInput, so these cases run on every platform
// and pin the wire semantics that the Win32 backend relies on. Expected values
// come from docs/spec/input-injection-seam.md (P-1..P-8) and
// docs/spec/input-injection-evidence.md (1.3-1.7).

#include <chrono>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "rtsc/server/desktop_input_map.h"
#include "test_framework.h"
#include "test_main.h"

namespace {

using rtsc::server::AdmitAndTrack;
using rtsc::server::AdmitInput;
using rtsc::server::AdmitOutcome;
using rtsc::server::DecideEnqueue;
using rtsc::server::EnqueueAction;
using rtsc::server::EnqueueState;
using rtsc::server::InjectGeometry;
using rtsc::server::InputEvent;
using rtsc::server::IsHeldRelease;
using rtsc::server::IsReleaseInput;
using rtsc::server::KeyId;
using rtsc::server::MakeWin32DesktopInputSink;
using rtsc::server::PlatformInput;
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
    std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{1920, 1080});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    CHECK_EQ(out[0].x, 0);
    CHECK_EQ(out[0].y, 0);

    ev.x = 1920;
    ev.y = 1080;
    out = TranslateInput(ev, InjectGeometry{1920, 1080});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    CHECK_EQ(out[0].x, 65535);
    CHECK_EQ(out[0].y, 65535);
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

    InputEvent mouse_rel;
    mouse_rel.kind = InputEvent::Kind::kMouseRel;
    mouse_rel.rel_x = 10;
    events.push_back(mouse_rel);

    InputEvent sync;
    sync.kind = InputEvent::Kind::kSync;
    events.push_back(sync);

    for (const InputEvent& ev : events) {
        CHECK(IsInjectable(ev) ==
              !TranslateInput(ev, InjectGeometry{}).empty());
    }
    // Pin the non-injectable kinds explicitly so a change to TranslateInput
    // cannot silently make them take the lease.
    CHECK(!IsInjectable(sync));
    CHECK(!IsInjectable(mouse_rel));
    CHECK(!IsInjectable(KeyEvent(0x00, false, false)));
    CHECK(!IsInjectable(zero_unicode));
    CHECK(!IsInjectable(bare_mouse));
}

RTSC_TEST(desktop_input_host_reports_input_state_and_lease_denial) {
    // tools/rtsc_server/main.cpp owns a full server process and cannot be
    // linked into this suite, so the two observability points are guarded
    // structurally (the same way tests/test_ui.cpp guards the GUI dispatch).
    //   1. the startup line carries "input=on|off" and "input_max_sessions=N";
    //   2. the first denied input lease logs a WARNING that includes the
    //      running input_lease_denied_count(), and the count is summarized
    //      periodically afterwards -- never one line per event;
    //   3. the host actually reads DesktopInputSink::Stats() and prints the
    //      four counters (otherwise dropped_rate_limited is invisible in the
    //      shipped binary).
#ifdef RTSC_SOURCE_DIR
    const std::string path =
        std::string(RTSC_SOURCE_DIR) + "/tools/rtsc_server/main.cpp";
    std::ifstream in(path, std::ios::binary);
    CHECK(in.is_open());
    if (!in.is_open()) {
        std::printf("  FAIL: cannot open %s\n", path.c_str());
        return;
    }
    const std::string src((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    CHECK(src.find("\" input=\"") != std::string::npos);
    CHECK(src.find("(opt.allow_input ? \"on\" : \"off\")") !=
          std::string::npos);
    CHECK(src.find("\" input_max_sessions=\"") != std::string::npos);
    CHECK(src.find("input_lease_denied_count()") != std::string::npos);
    CHECK(src.find("WARNING: input lease denied") != std::string::npos);
    // Periodic lease-denied summary (not only the first denial).
    CHECK(src.find("input lease denied summary") != std::string::npos);
    // Production call site of Stats() and the four printed counters.
    CHECK(src.find("->Stats()") != std::string::npos);
    CHECK(src.find("input_injected=") != std::string::npos);
    CHECK(src.find("input_dropped_queue=") != std::string::npos);
    CHECK(src.find("input_rate_limited=") != std::string::npos);
    CHECK(src.find("input_send_failures=") != std::string::npos);
    // The final value is printed before the process exits.
    CHECK(src.find("\"final\"") != std::string::npos);
#else
    std::printf(
        "  FAIL: RTSC_SOURCE_DIR not defined; cannot locate main.cpp\n");
    CHECK(false);
#endif
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
    sink->ReleaseSession(1);
    CHECK_EQ(sink->Stats().injected, static_cast<size_t>(2));
}

int main() { return rtsc::test::run_all("rtsc_desktop_input_tests"); }
