// Pure translation from a decoded RDP InputEvent to platform input actions.
// No platform header is included here on purpose: tests/test_desktop_input.cpp
// exercises these rules on every platform, without SendInput.

#include "rtsc/server/desktop_input_map.h"

#include <cstdint>

namespace rtsc::server {
namespace {

// Maps one absolute coordinate into Win32's normalized 0..65535 range.
//
// The negotiated framebuffer has `extent` pixels per axis; the client's last
// valid pixel is extent-1, which maps onto 65535. Values at or beyond the last
// pixel are clamped rather than allowed to overflow the wire range (the RDP
// coordinate is a uint16 and may legally carry 65535). An extent of 0 (geometry
// not known yet) or 1 (no span) degrades to a 1:1 pass-through instead of
// dividing by zero.
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
            if (ev.is_move) {
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
    if (state.size >= state.hard_limit) return EnqueueAction::kDrop;
    return EnqueueAction::kAccept;
}

}  // namespace rtsc::server
