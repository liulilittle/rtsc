// RDP InputEvent -> platform-neutral injected-input description.
//
// This layer deliberately does not include <windows.h>: the translation rules
// (scan codes, absolute coordinate normalization, wheel units, button
// identities) are the part that must be testable on every platform, while the
// Win32 backend only turns each PlatformInput into one INPUT and calls
// SendInput.
//
// Units and identities follow [MS-RDPBCGR] and the Win32 input documentation;
// the decisions and their evidence live in docs/spec/input-injection-seam.md
// (P-1..P-8) and docs/spec/input-injection-evidence.md (sections 1.3-1.7).

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <vector>

#include "rtsc/server/desktop_input.h"

namespace rtsc::server {

// One platform input action. `kind` selects which fields are meaningful.
struct PlatformInput {
    enum class Kind {
        kKey,          // keyboard: scancode (+extended/release), or unicode
        kMouseMove,    // absolute pointer movement (namespaced 0..65535)
        kMouseButton,  // button press/release, identity kept on both
        kWheel,        // vertical or horizontal wheel
    };

    Kind kind = Kind::kKey;

    // kKey. When `unicode` is non-zero this is a KEYEVENTF_UNICODE event and
    // `scancode` is unused; otherwise it is a scan-code key event.
    uint16_t scancode = 0;
    bool extended = false;
    bool release = false;
    uint32_t unicode = 0;

    // kMouseMove: absolute coordinates normalized to 0..65535.
    int x = 0;
    int y = 0;

    // kMouseButton: 1 = left, 2 = right, 3 = middle, 4 = X1, 5 = X2.
    bool button_down = false;
    uint8_t button = 0;

    // kWheel: the delta is already in wire units (WHEEL_DELTA = 120 per notch)
    // and must not be scaled again by the backend.
    int wheel = 0;
    bool horizontal = false;
};

// True when an absolute movement can be mapped with `g` without guessing.
//
// The mapping needs a trusted capture rectangle inside a known physical
// virtual desktop, a framebuffer with a real span, and a non-degenerate
// capture/desktop. When this is false TranslateInput emits no kMouseMove
// (fail closed): buttons, wheels and keys still translate normally.
inline bool AbsoluteMoveMappable(const InjectGeometry& g) {
    return g.mapped && g.pixels_are_physical && g.width > 1 && g.height > 1 &&
           g.capture.width > 0 && g.capture.height > 0 &&
           g.desktop.width > 1 && g.desktop.height > 1;
}

// Translates one decoded RDP input event into zero or more platform actions.
//
//   kKey      -> one kKey (scancode copied verbatim, never offset by 0x100);
//                a zero scan code is dropped (SendInput has no wScan=0 key)
//                and so is the 0xE1 (extended1) prefix: PAUSE has no
//                KEYEVENTF_EXTENDED1, and its bare scan code would inject a
//                plain CTRL/NumLock pair
//   kUnicode  -> one kKey with `unicode` set (drops a zero code point)
//   kMouse    -> kMouseMove when is_move is set AND AbsoluteMoveMappable(g),
//                and/or kMouseButton when a button identity is present;
//                neither -> empty
//   kWheel    -> one kWheel (x/y are ignored, the wire sends them but they are
//                meaningless for a wheel event); a zero delta -> empty
//   kMouseRel -> empty (relative injection is subject to mouse acceleration and
//                is deliberately not injected in v1)
//   kSync     -> empty (there is no Win32 toggle-state event; injecting a key
//                would invert the state instead of setting it)
std::vector<PlatformInput> TranslateInput(const InputEvent& ev,
                                          const InjectGeometry& g);

// Per-session PAUSE (0xE1) envelope. Only the two CTRL halves carry 0x04 on the
// wire; the NUMLOCK(0x45) halves belong to the same sequence but are unflagged,
// so dropping only the flagged events would still inject a bare NumLock pair and
// toggle the local NumLock. Expects the 4 wire events in order:
//   04 1D / 00 45 / 05 1D / 01 45
class PauseSequenceFilter {
 public:
    // true = this event is part of an unrepresentable PAUSE sequence; drop it.
    bool ShouldDrop(const InputEvent& ev) {
        // kSync declares the keyboard state and resets every key to "up"
        // (P-7), so it terminates any open envelope: a SYNC after a lost 0xE1
        // half must not let the stale arm swallow the next real NumLock tap.
        // It is not part of the envelope itself, so it is not dropped here
        // (TranslateInput maps it to no platform action).
        if (ev.kind == InputEvent::Kind::kSync) {
            ctrl_armed_ = false;
            return false;
        }
        // Only key events are part of the envelope. A mouse/wheel event between
        // the halves must be injected and must NOT close an open window (the
        // wire sequence does not interleave, but a lost PDU must not swallow a
        // following NumLock).
        if (ev.kind != InputEvent::Kind::kKey) return false;
        // Arm on the CTRL down AND on the CTRL up: the 0x45 up comes after the
        // CTRL up on the wire, so the window has to survive that second flag.
        if (ev.extended1) {
            ctrl_armed_ = true;
            return true;
        }
        if (ctrl_armed_ && ev.scancode == 0x45 && !ev.extended) {
            // The window closes on the NumLock up; the down must keep it open.
            if (ev.release) ctrl_armed_ = false;
            return true;
        }
        // Any other key closes a stale window and is injected normally. This is
        // what bounds the suppression: a lone 0xE1 can eat at most one NumLock
        // tap, never every 0x45.
        ctrl_armed_ = false;
        return false;
    }
    void Reset() { ctrl_armed_ = false; }

 private:
    bool ctrl_armed_ = false;
};

// True for a platform input that lifts a previously pressed state: a key-up
// (scan code or unicode) or a mouse-button-up. This is only the "is an up"
// half of the question: neither the queue exemption nor the rate-limiter
// exemption uses it, because both exempt only a HELD release
// (IsHeldRelease below). A release for a key/button this session never pressed
// is treated like a press by both gates.
inline bool IsReleaseInput(const PlatformInput& input) {
    if (input.kind == PlatformInput::Kind::kKey) return input.release;
    if (input.kind == PlatformInput::Kind::kMouseButton) {
        return !input.button_down;
    }
    return false;
}

// Identity of a held key: the set-1 scan code plus the 0xE0 prefix flag. This
// is exactly what TrackInput stores, so a release is matched against the press
// it actually lifts (a 0xE0 key and the same non-extended scan code are two
// different physical keys).
struct KeyId {
    uint16_t scancode = 0;
    bool extended = false;

    bool operator<(const KeyId& other) const {
        if (scancode != other.scancode) return scancode < other.scancode;
        return extended < other.extended;
    }
};

// Keys and buttons a session has injected a press for and not yet released.
// The sink tracks ONLY events that passed both gates: a press refused by the
// rate limiter or by the queue hard limit was never injected, so it must never
// be "held" or released later.
struct PressedInputs {
    std::set<KeyId> keys;
    std::set<uint8_t> buttons;
};

// Records an accepted press/release in `pressed`. Unicode key events carry no
// physical key state (KEYEVENTF_UNICODE injects a character with wVk = 0, not a
// scan-code key), so they are deliberately not tracked.
void TrackInput(PressedInputs& pressed, const PlatformInput& input);

// True when `input` lifts a key/button this session currently holds down. Such
// a release is the only kind that may exceed the queue's hard limit: it is
// bounded by the pressed set and losing it leaves the peer's key stuck. A
// release for something not held (a repeated up, or the up of a press the hard
// limit dropped) gets no exemption -- there is no physical state to clear.
bool IsHeldRelease(const PlatformInput& input, const PressedInputs& pressed);

// True when TranslateInput would produce at least one platform action for
// `ev`. The server uses this before taking the (single) desktop input lease:
// an event that can never be injected must not be able to hold the lease and
// starve a session that actually controls the desktop.
//
// Keep this predicate in lock step with TranslateInput; the tests cross-check
// the two for every InputEvent kind. Defined inline so a caller (the server)
// does not need to link the mapping library just for this predicate.
inline bool IsInjectable(const InputEvent& ev) {
    switch (ev.kind) {
        case InputEvent::Kind::kKey:
            return ev.scancode != 0 && !ev.extended1;
        case InputEvent::Kind::kUnicode:
            return ev.unicode_code != 0;
        case InputEvent::Kind::kMouse:
            return ev.is_move || ev.button != 0;
        case InputEvent::Kind::kWheel:
            return ev.wheel_delta != 0;
        case InputEvent::Kind::kMouseRel:
        case InputEvent::Kind::kSync:
            return false;
    }
    return false;
}

// What the bounded injection queue must do with one incoming platform input.
// This decision is platform neutral and pure so the fail-closed policy can be
// unit tested without SendInput or the Win32 worker thread.
enum class EnqueueAction {
    kAccept,     // push the incoming event onto the queue
    kEvictMove,  // erase the oldest pure movement, then push the incoming event
    kDrop,       // refuse the incoming event (counted as dropped_queue_full)
};

// Snapshot of the queue relevant to one EnqueueLocked decision. `size` and the
// two limits are in queued events; `has_movable_move` is true when the queue
// currently holds a pure movement that may be evicted; `incoming_is_move` is
// true when the event being enqueued is itself pure movement.
struct EnqueueState {
    size_t size = 0;
    size_t soft_limit = 0;  // evict/refuse disposables above this
    size_t hard_limit = 0;  // absolute cap: never grow past this
    bool has_movable_move = false;
    bool incoming_is_move = false;
    // True when the incoming event lifts a key/button the session is CURRENTLY
    // holding down (IsHeldRelease), not merely "is a release". Only a held
    // release may exceed the hard limit: the pressed set bounds how many such
    // events can exist, and losing one leaves the peer's key stuck. A release
    // for something not held gets no exemption, so a flood of key-ups for keys
    // that were never pressed cannot grow the queue past the hard limit.
    bool incoming_is_held_release = false;
};

// Queue policy (see desktop_input_win32.cpp for the rationale):
//   * below the soft limit: accept;
//   * at/above the soft limit: evict the oldest pure movement when one exists;
//   * with no movement to evict: a pure movement is disposable and is dropped;
//   * with no movement to evict and a key/button/wheel press arriving: accept
//     while the queue is below the hard limit, but DROP at the hard limit
//     (fail closed: a bound on injection memory beats an unbounded queue);
//   * a HELD release (the up of a press this session actually holds) is
//     accepted even at the hard limit: it is bounded by the pressed set and
//     losing one is what leaves the peer's key stuck. Any other release is
//     treated like a press: dropped at the hard limit.
EnqueueAction DecideEnqueue(const EnqueueState& state);

// Admits one platform input: fills the incoming-event flags from `input`,
// applies DecideEnqueue, and updates `pressed` ONLY when the queue accepted the
// event (kAccept or kEvictMove). `held_release` must be computed by the caller
// immediately before this call, against the pressed set it passes in (the sink
// uses AdmitAndTrack below, which does exactly that).
//
// The "track only when accepted" rule is load bearing: tracking a press the
// hard limit dropped would make its later release look held, so the sink would
// exempt it and "release" a key that was never pressed -- and the queue would
// gain an unbounded stream of exempt events.
EnqueueAction AdmitInput(EnqueueState state, PressedInputs& pressed,
                         const PlatformInput& input, bool held_release);

// Outcome of one trip through AdmitAndTrack.
struct AdmitOutcome {
    EnqueueAction action = EnqueueAction::kDrop;
    // True when the input lifts a key/button the session currently holds.
    bool held_release = false;
    // True when the caller's rate gate refused the input. Nothing was queued
    // and nothing was tracked in that case.
    bool rate_limited = false;
};

// The sink's entire per-input pipeline, kept platform neutral so it is covered
// by the mapping tests instead of living untested in desktop_input_win32.cpp:
//
//   1. decide `held_release` against the pressed set as it stands now;
//   2. ask the caller's rate gate (the token-bucket limiter) whether this
//      platform action may be injected at all;
//   3. only when the gate allows it, apply DecideEnqueue and the held-key
//      bookkeeping (AdmitInput).
//
// Ordering is load bearing: the rate gate runs BEFORE any tracking, so a press
// the limiter refuses never enters `pressed` (it was never injected, so its up
// must not be treated as held). The gate receives the held flag, not "is a
// release": an up for a key the session never pressed is limited like a press.
template <typename RateGate>
AdmitOutcome AdmitAndTrack(EnqueueState state, PressedInputs& pressed,
                           const PlatformInput& input, RateGate&& rate_gate) {
    AdmitOutcome outcome;
    outcome.held_release = IsHeldRelease(input, pressed);
    if (!rate_gate(outcome.held_release)) {
        outcome.rate_limited = true;
        return outcome;
    }
    outcome.action = AdmitInput(state, pressed, input, outcome.held_release);
    return outcome;
}

// Token-bucket rate limiter for the injection queue (docs/spec/
// input-injection-seam.md 2.3). It is called from the sink's Inject() under the
// same mutex that guards the queue, so it needs no lock of its own; `now` is
// caller-supplied steady_clock time so the policy is unit testable without
// sleeping.
//
//   * one session: 400 platform actions/s, burst 800 (two seconds of traffic);
//   * all sessions together: 1000 platform actions/s, burst 2000.
//
// One exemption mirrors the queue policy: a HELD release (the up of a key or
// button this session actually holds down) is never limited and spends no
// token, because losing one leaves the local key or button stuck and the
// number of such releases is bounded by the pressed set. Any other up (a
// repeated up, or the up of a press that was never injected) is limited like a
// press. An event refused by the GLOBAL bucket does not spend the session's
// token either, so one busy peer cannot drain another session's allowance.
class InputRateLimiter {
 public:
    using Clock = std::chrono::steady_clock;

    static constexpr double kSessionEventsPerSecond = 400.0;
    static constexpr double kSessionBurst = 800.0;
    static constexpr double kGlobalEventsPerSecond = 1000.0;
    static constexpr double kGlobalBurst = 2000.0;

    // Returns true when one platform action may be injected. `held_release`
    // must be IsHeldRelease(input, pressed) -- not IsReleaseInput(input). A
    // refusal is counted here (InputStats::dropped_rate_limited reads
    // dropped()); the caller must not count it again.
    bool Allow(uint32_t session_id, bool held_release, Clock::time_point now);

    // Forgets a session's bucket (ReleaseSession), so a later session that
    // reuses the id starts with a full burst instead of inheriting a drained
    // bucket from the previous holder.
    void Forget(uint32_t session_id);

    // Events refused so far. A relaxed atomic because Stats() is documented as
    // callable from any thread while the worker writes.
    size_t dropped() const;

 private:
    struct Bucket {
        double tokens = 0.0;
        Clock::time_point last{};
        bool started = false;
    };

    static void Refill(Bucket& bucket, double per_second, double burst,
                       Clock::time_point now);

    Bucket global_;
    std::map<uint32_t, Bucket> sessions_;
    mutable std::atomic<uint64_t> dropped_{0};
};

}  // namespace rtsc::server
