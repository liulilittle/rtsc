// Pure mapping tests for the desktop input injection seam.
//
// TranslateInput() is platform neutral by design: it never includes
// <windows.h> and never calls SendInput, so these cases run on every platform
// and pin the wire semantics that the Win32 backend relies on. Expected values
// come from docs/spec/input-injection-seam.md (P-1..P-8) and
// docs/spec/input-injection-evidence.md (1.3-1.7).

#include <cstdint>
#include <vector>

#include "rtsc/server/desktop_input_map.h"
#include "test_framework.h"
#include "test_main.h"

namespace {

using rtsc::server::DecideEnqueue;
using rtsc::server::EnqueueAction;
using rtsc::server::EnqueueState;
using rtsc::server::InjectGeometry;
using rtsc::server::InputEvent;
using rtsc::server::MakeWin32DesktopInputSink;
using rtsc::server::PlatformInput;
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

// ---- Bounded injection queue policy (DecideEnqueue) -------------------------
//
// The Win32 sink cannot be exercised here (it posts real SendInput calls from a
// worker thread), so the queue decision is a pure function. These cases pin the
// fail-closed rule: key/button events may grow the queue past the soft limit
// (losing an up event leaves a stuck key) but never past the hard limit.

EnqueueState QueueState(size_t size, bool movable_move, bool incoming_is_move,
                        bool incoming_is_release = false) {
    EnqueueState state;
    state.size = size;
    state.soft_limit = 4;
    state.hard_limit = 16;
    state.has_movable_move = movable_move;
    state.incoming_is_move = incoming_is_move;
    state.incoming_is_release = incoming_is_release;
    return state;
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
    // (TrackPressedLocked runs only after a successful enqueue), and an
    // unbounded queue would let a hostile peer exhaust memory.
    CHECK(DecideEnqueue(QueueState(16, false, false)) ==
          EnqueueAction::kDrop);
    CHECK(DecideEnqueue(QueueState(17, false, false)) ==
          EnqueueAction::kDrop);
}

RTSC_TEST(desktop_input_queue_accepts_release_at_hard_limit) {
    // F1: a release must never be dropped. Releases are bounded by the set of
    // keys/buttons the session actually holds down, and losing one leaves the
    // peer's key stuck: TrackPressedLocked has already erased it from the
    // pressed set, so teardown would have nothing left to release. Even at (and
    // above) the hard limit a release is accepted.
    CHECK(DecideEnqueue(QueueState(16, false, false, true)) ==
          EnqueueAction::kAccept);
    CHECK(DecideEnqueue(QueueState(17, false, false, true)) ==
          EnqueueAction::kAccept);
    // A release arriving while a movement can be evicted still succeeds (the
    // eviction keeps the queue size unchanged).
    CHECK(DecideEnqueue(QueueState(16, true, false, true)) ==
          EnqueueAction::kEvictMove);
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
    CHECK_EQ(sink->Stats().send_failures, static_cast<size_t>(0));
    sink->ReleaseSession(1);
    CHECK_EQ(sink->Stats().injected, static_cast<size_t>(2));
}

int main() { return rtsc::test::run_all("rtsc_desktop_input_tests"); }
