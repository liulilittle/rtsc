// Pure translation from a decoded RDP InputEvent to platform input actions.
// No platform header is included here on purpose: tests/test_desktop_input.cpp
// exercises these rules on every platform, without SendInput.

#include "rtsc/server/desktop_input_map.h"

#include <algorithm>
#include <cstdint>

namespace rtsc::server {
namespace {

// Maps one absolute coordinate into Win32's normalized 0..65535 range.
//
// The negotiated framebuffer has `extent` pixels per axis; the client's last
// valid pixel is extent-1, which maps onto 65535. Values at or beyond the last
// pixel are clamped rather than allowed to overflow the wire range (the RDP
// coordinate is a uint16 and may legally carry 65535). Callers reject a
// geometry whose extent is 0 (not known yet) or 1 (no span) before asking for
// absolute movement; the guard here only keeps a future caller from dividing by
// zero.
int NormalizeAxis(uint16_t value, uint16_t extent) {
    if (extent <= 1) return static_cast<int>(value);
    const int last = static_cast<int>(extent) - 1;
    if (value >= last) return 65535;
    const int64_t scaled = static_cast<int64_t>(value) * 65535 + last / 2;
    return static_cast<int>(scaled / last);
}

}  // namespace

std::vector<PlatformInput> TranslateInput(const InputEvent& ev,
                                          const InjectGeometry& g) {
    std::vector<PlatformInput> out;
    switch (ev.kind) {
        case InputEvent::Kind::kKey: {
            // A zero scan code has no platform meaning: SendInput takes wScan=0
            // only for a KEYEVENTF_UNICODE event, and this branch is the scan
            // code path. Dropping it keeps an unusable INPUT out of the queue.
            if (ev.scancode == 0) return out;
            // The 0xE1 prefix (FASTPATH_INPUT_KBDFLAGS_EXTENDED1) belongs to
            // the PAUSE sequence, whose CTRL down/up carry it on the wire.
            // SendInput has no KEYEVENTF_EXTENDED1, so injecting the bare scan
            // code would press/release a DIFFERENT physical key -- the plain
            // CTRL and NumLock, which toggles the local keyboard state. The
            // event has no faithful platform form, so it produces nothing.
            if (ev.extended1) return out;
            // The RDP keyCode is already the set-1 scan code; the 0xE0 prefix
            // is a separate flag, so the value must never be offset by 0x100.
            PlatformInput key;
            key.kind = PlatformInput::Kind::kKey;
            key.scancode = ev.scancode;
            key.extended = ev.extended;
            key.release = ev.release;
            out.push_back(key);
            return out;
        }
        case InputEvent::Kind::kUnicode: {
            // KEYEVENTF_UNICODE with a zero scan code carries no character.
            if (ev.unicode_code == 0) return out;
            PlatformInput key;
            key.kind = PlatformInput::Kind::kKey;
            key.unicode = ev.unicode_code;
            key.release = ev.release;
            out.push_back(key);
            return out;
        }
        case InputEvent::Kind::kMouse: {
            // Only PTRFLAGS_MOVE moves the absolute pointer; a release carries
            // the button bit without MOVE. Treating every kMouse as a move
            // would teleport the cursor to (0, 0) on each button release.
            // Normalization needs a real pixel span on both axes. With a
            // geometry of 0 (not negotiated yet) or 1 (no span) the old 1:1
            // pass-through sent the raw wire value as a normalized coordinate,
            // which puts the pointer at the wrong place (or leaves it pinned
            // at the top-left corner). Drop the move rather than inject a
            // position that cannot be derived.
            if (ev.is_move && g.width > 1 && g.height > 1) {
                PlatformInput move;
                move.kind = PlatformInput::Kind::kMouseMove;
                move.x = NormalizeAxis(ev.x, g.width);
                move.y = NormalizeAxis(ev.y, g.height);
                out.push_back(move);
            }
            // The button identity is present on presses AND releases; dropping
            // it on release would leave the local button stuck down.
            if (ev.button != 0) {
                PlatformInput button;
                button.kind = PlatformInput::Kind::kMouseButton;
                button.button = static_cast<uint8_t>(ev.button);
                button.button_down = ev.button_down;
                out.push_back(button);
            }
            return out;
        }
        case InputEvent::Kind::kWheel: {
            // wheel_delta is already in wire units (WHEEL_DELTA = 120 per
            // notch); the backend must not multiply it by 120 again. x/y are
            // ignored: [MS-RDPBCGR] requires a wheel event to carry no pointer
            // movement.
            //
            // A zero delta rotates nothing: enqueueing it would spend a queue
            // slot and a rate-limit token on a no-op, and a peer could flood
            // zero wheels to evict queued movement and starve real input.
            if (ev.wheel_delta == 0) return out;
            PlatformInput wheel;
            wheel.kind = PlatformInput::Kind::kWheel;
            wheel.wheel = ev.wheel_delta;
            wheel.horizontal = ev.horizontal;
            out.push_back(wheel);
            return out;
        }
        // kMouseRel: relative motion is scaled by the system mouse speed and
        // the two threshold values (up to 4x), so an injected displacement
        // would not equal what the client sent. kSync: a toggle-state event
        // has no Win32 "set" form -- injecting a keypress would invert the
        // physical state instead of correcting it. Neither is injected in v1;
        // the caller counts them as unsupported.
        case InputEvent::Kind::kMouseRel:
        case InputEvent::Kind::kSync:
            return out;
    }
    return out;
}

EnqueueAction DecideEnqueue(const EnqueueState& state) {
    if (state.size < state.soft_limit) return EnqueueAction::kAccept;
    if (state.has_movable_move) return EnqueueAction::kEvictMove;
    if (state.incoming_is_move) return EnqueueAction::kDrop;
    // A HELD release is bounded by the set of keys/buttons the session holds
    // down, so accepting it can never grow the queue without bound. It must win
    // over the hard-limit drop: the press was already accepted (and tracked),
    // and dropping its release is what leaves a key stuck. A release for
    // something not held has no such bound and falls through to the hard limit.
    if (state.incoming_is_held_release) return EnqueueAction::kAccept;
    if (state.size >= state.hard_limit) return EnqueueAction::kDrop;
    return EnqueueAction::kAccept;
}

void TrackInput(PressedInputs& pressed, const PlatformInput& input) {
    if (input.kind == PlatformInput::Kind::kKey) {
        // Unicode events are KEYEVENTF_UNICODE key events (wVk = 0): they type
        // a character, they do not press a scan-code key, so they cannot leave
        // a physical key stuck and are deliberately not tracked.
        if (input.unicode != 0) return;
        const KeyId key{input.scancode, input.extended};
        if (input.release) {
            pressed.keys.erase(key);
        } else {
            pressed.keys.insert(key);
        }
        return;
    }
    if (input.kind == PlatformInput::Kind::kMouseButton) {
        if (input.button_down) {
            pressed.buttons.insert(input.button);
        } else {
            pressed.buttons.erase(input.button);
        }
    }
}

bool IsHeldRelease(const PlatformInput& input, const PressedInputs& pressed) {
    if (input.kind == PlatformInput::Kind::kKey) {
        // Unicode key-ups carry no physical state, so they are never a held
        // release even if a unicode key-down was sent earlier.
        if (!input.release || input.unicode != 0) return false;
        return pressed.keys.count(KeyId{input.scancode, input.extended}) != 0;
    }
    if (input.kind == PlatformInput::Kind::kMouseButton) {
        if (input.button_down) return false;
        return pressed.buttons.count(input.button) != 0;
    }
    return false;
}

EnqueueAction AdmitInput(EnqueueState state, PressedInputs& pressed,
                         const PlatformInput& input, bool held_release) {
    // The incoming-event flags are derived here so a caller cannot disagree
    // with the bookkeeping this function performs.
    state.incoming_is_move =
        input.kind == PlatformInput::Kind::kMouseMove;
    state.incoming_is_held_release = held_release;
    const EnqueueAction action = DecideEnqueue(state);
    // Track only what the queue accepted. Tracking a press that the hard limit
    // dropped would make its later release look held: the sink would exempt an
    // event for a key it never pressed, and the "bounded by the pressed set"
    // argument behind the release exemption would no longer hold.
    if (action != EnqueueAction::kDrop) TrackInput(pressed, input);
    return action;
}

void InputRateLimiter::Refill(Bucket& bucket, double per_second, double burst,
                              Clock::time_point now) {
    if (!bucket.started) {
        bucket.started = true;
        bucket.last = now;
        bucket.tokens = burst;
        return;
    }
    // steady_clock is monotonic, so a non-positive delta is only the "two
    // events at the same instant" case; leaving the bucket untouched is right.
    if (now <= bucket.last) return;
    const double elapsed =
        std::chrono::duration<double>(now - bucket.last).count();
    bucket.last = now;
    bucket.tokens = std::min(burst, bucket.tokens + elapsed * per_second);
}

bool InputRateLimiter::Allow(uint32_t session_id, bool held_release,
                             Clock::time_point now) {
    // Only a HELD release is exempt and spends no token (see the header); any
    // other up is limited like a press.
    if (held_release) return true;

    Refill(global_, kGlobalEventsPerSecond, kGlobalBurst, now);
    Bucket& session = sessions_[session_id];
    Refill(session, kSessionEventsPerSecond, kSessionBurst, now);
    // Decide before spending: a denial by either bucket must leave both
    // buckets untouched, or a global-congested event would cost the session a
    // token it never got to use.
    if (session.tokens < 1.0 || global_.tokens < 1.0) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    session.tokens -= 1.0;
    global_.tokens -= 1.0;
    return true;
}

void InputRateLimiter::Forget(uint32_t session_id) {
    sessions_.erase(session_id);
}

size_t InputRateLimiter::dropped() const {
    return static_cast<size_t>(dropped_.load(std::memory_order_relaxed));
}

}  // namespace rtsc::server
