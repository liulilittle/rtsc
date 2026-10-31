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

#include <cstdint>
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
//   kKey      -> one kKey (scancode copied verbatim, never offset by 0x100)
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

}  // namespace rtsc::server
