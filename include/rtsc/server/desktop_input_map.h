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

// Translates one decoded RDP input event into zero or more platform actions.
//
//   kKey      -> one kKey (scancode copied verbatim, never offset by 0x100);
//                a zero scan code is dropped (SendInput has no wScan=0 key)
//   kUnicode  -> one kKey with `unicode` set (drops a zero code point)
//   kMouse    -> kMouseMove when is_move is set, and/or kMouseButton when a
//                button identity is present; neither -> empty
//   kWheel    -> one kWheel (x/y are ignored, the wire sends them but they are
//                meaningless for a wheel event)
//   kMouseRel -> empty (relative injection is subject to mouse acceleration and
//                is deliberately not injected in v1)
//   kSync     -> empty (there is no Win32 toggle-state event; injecting a key
//                would invert the state instead of setting it)
std::vector<PlatformInput> TranslateInput(const InputEvent& ev,
                                          const InjectGeometry& g);

// True for a platform input that lifts a previously pressed state: a key-up
// (scan code or unicode) or a mouse-button-up. This is the rate limiter's
// exemption and the first half of the queue's held-release test.
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
// The sink tracks ONLY events the queue accepted: a press refused by the hard
// limit was never injected, so it must never be "held" or released later.
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
            return ev.scancode != 0;
        case InputEvent::Kind::kUnicode:
            return ev.unicode_code != 0;
        case InputEvent::Kind::kMouse:
            return ev.is_move || ev.button != 0;
        case InputEvent::Kind::kWheel:
            return true;
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
// does exactly that in Inject()).
//
// The "track only when accepted" rule is load bearing: tracking a press the
// hard limit dropped would make its later release look held, so the sink would
// exempt it and "release" a key that was never pressed -- and the queue would
// gain an unbounded stream of exempt events.
EnqueueAction AdmitInput(EnqueueState state, PressedInputs& pressed,
                         const PlatformInput& input, bool held_release);

// Token-bucket rate limiter for the injection queue (docs/spec/
// input-injection-seam.md 2.3). It runs on the sink's single worker thread, so
// it takes no lock; `now` is caller-supplied steady_clock time so the policy is
// unit testable without sleeping.
//
//   * one session: 400 events/s, burst 800 (two seconds of traffic);
//   * all sessions together: 1000 events/s, burst 2000.
//
// Two exemptions mirror the queue policy: a RELEASE (key-up / button-up) is
// never limited and spends no token, because losing one leaves the local key or
// button stuck and the number of releases is bounded by what the session holds
// down. An event refused by the GLOBAL bucket does not spend the session's
// token either, so one busy peer cannot drain another session's allowance.
class InputRateLimiter {
 public:
    using Clock = std::chrono::steady_clock;

    static constexpr double kSessionEventsPerSecond = 400.0;
    static constexpr double kSessionBurst = 800.0;
    static constexpr double kGlobalEventsPerSecond = 1000.0;
    static constexpr double kGlobalBurst = 2000.0;

    // Returns true when one event may be injected. Only the worker thread calls
    // this; a false result is expected to be counted by the caller (the sink
    // adds it to InputStats::dropped_rate_limited).
    bool Allow(uint32_t session_id, bool is_release, Clock::time_point now);

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
