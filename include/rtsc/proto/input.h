// Client fast-path input events ([MS-RDPBCGR] 2.2.8.1.2).
//
// Reference: docs/spec/share-data.md section 3.6.
//
// A fast-path input PDU replaces the TPKT / X.224 / MCS / security headers with
// a 1-byte fpInputHeader, a length, and a packed array of events. Under Enhanced
// RDP Security the fipsInformation and dataSignature fields are absent and the
// flags field is zero.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace rtsc::proto {

// eventFlags for TS_FP_KEYBOARD_EVENT ([MS-RDPBCGR] 2.2.8.1.2.2.1).
enum FastPathKbdFlag : uint8_t {
    kKbdRelease = 0x01,    // key-up (absence = key-down)
    kKbdExtended = 0x02,   // extended scancode (right ALT/CTRL, nav cluster...)
    kKbdExtended1 = 0x04,  // used by the PAUSE key sequence
};

// eventFlags for TS_FP_SYNC_EVENT ([MS-RDPBCGR] 2.2.8.1.2.2.5).
enum FastPathSyncFlag : uint8_t {
    kSyncScrollLock = 0x01,
    kSyncNumLock = 0x02,
    kSyncCapsLock = 0x04,
    kSyncKanaLock = 0x08,
};

// pointerFlags for TS_FP_POINTER_EVENT / TS_FP_POINTERX_EVENT
// ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.3).
enum PointerFlag : uint16_t {
    kPtrDown = 0x8000,
    kPtrButton3 = 0x4000,
    kPtrButton2 = 0x2000,
    kPtrButton1 = 0x1000,
    kPtrMove = 0x0800,
    kPtrHwheel = 0x0400,
    kPtrWheel = 0x0200,
    // kPtrWheelNegative is the sign bit INSIDE the 9-bit two's-complement
    // kPtrWheelRotationMask field, not a separate "negative" flag: it MUST NOT
    // be OR'ed in independently of the rotation value ([MS-RDPBCGR]
    // 2.2.8.1.1.3.1.1.1). Kept under its historical name for source
    // compatibility.
    kPtrWheelNegative = 0x0100,
    kPtrWheelRotationMask = 0x01FF,
};

// pointerFlags for TS_FP_POINTERX_EVENT ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.4): the
// button bits are PTRXFLAGS, NOT the PTRFLAGS above. X1/X2 are 0x0001/0x0002;
// a 0x1000/0x2000 X event would be decoded as left/right by a PTRFLAGS reader.
enum PointerXFlag : uint16_t {
    kPtrXButton1 = 0x0001,
    kPtrXButton2 = 0x0002,
};

// ---- individual event encoders --------------------------------------------
// Each returns the complete event bytes (eventHeader included).

// TS_FP_KEYBOARD_EVENT: eventHeader(1) + keyCode(1) = 2 bytes. `extended1`
// sets FASTPATH_INPUT_KBDFLAGS_EXTENDED1 (0x04), which the PAUSE key sequence
// carries on its CTRL events ([MS-RDPBCGR] 2.2.8.1.2.2.1).
std::vector<uint8_t> EncodeKeyboardEvent(uint8_t key_code, bool release,
                                         bool extended, bool extended1 = false);

// TS_FP_UNICODE_KEYBOARD_EVENT: eventHeader(1) + unicodeCode(2) = 3 bytes.
std::vector<uint8_t> EncodeUnicodeEvent(uint16_t unicode_code, bool release);

// TS_FP_POINTER_EVENT / TS_FP_POINTERX_EVENT: eventHeader(1) + pointerFlags(2)
// + xPos(2) + yPos(2) = 7 bytes. `extended` selects MOUSEX (code 2).
std::vector<uint8_t> EncodeMouseEvent(uint16_t pointer_flags, uint16_t x,
                                      uint16_t y, bool extended = false);

// TS_FP_RELPOINTER_EVENT: eventHeader(1) + pointerFlags(2) + xDelta(2) +
// yDelta(2) = 7 bytes. The deltas are SIGNED, unlike the absolute positions.
std::vector<uint8_t> EncodeRelativeMouseEvent(uint16_t pointer_flags,
                                              int16_t dx, int16_t dy);

// TS_FP_SYNC_EVENT: eventHeader(1) = 1 byte.
std::vector<uint8_t> EncodeSyncEvent(uint8_t toggle_flags);

// TS_FP_QOETIMESTAMP_EVENT: eventHeader(1) + timestamp(4) = 5 bytes.
std::vector<uint8_t> EncodeQoeTimestampEvent(uint32_t timestamp);

// ---- named scancodes -------------------------------------------------------
// The RDP keyCode is the low byte of the 8042 set-1 scancode. For the extended
// keys the 0xE0 prefix is NOT a separate byte: it is implied by kKbdExtended
// ([MS-RDPBCGR] 2.2.8.1.2.2.1). So the left/right Windows keys are 0x5B / 0x5C
// with kKbdExtended set, matching the 0xE0 0x5B / 0xE0 0x5C hardware scancodes.
constexpr uint8_t kScancodeLControl = 0x1D;
constexpr uint8_t kScancodeLShift = 0x2A;
constexpr uint8_t kScancodeLAlt = 0x38;
constexpr uint8_t kScancodePause = 0x45;   // shares the NumLock scancode
constexpr uint8_t kScancodeEnd = 0x4F;     // extended (0xE0 0x4F)
constexpr uint8_t kScancodeDelete = 0x53;  // extended (0xE0 0x53)
constexpr uint8_t kScancodeLWin = 0x5B;    // extended (0xE0 0x5B)
constexpr uint8_t kScancodeRWin = 0x5C;    // extended (0xE0 0x5C)

// The Secure Attention Sequence (Ctrl+Alt+Del) as a Fast-Path keyboard event
// sequence. [MS-RDPBCGR] defines no dedicated SAS input event: the client sends
// the same six scancode events a real keyboard would (Ctrl down, Alt down,
// Delete down, Delete up, Alt up, Ctrl up) and the server injects them into the
// session, where winlogon raises the SAS. Raising this from Ctrl+Alt+End is a
// product requirement, NOT mstsc binary evidence (input-evidence.md leaves that
// mapping unverified).
std::vector<std::vector<uint8_t>> EncodeCtrlAltDel();

// Pause/Break as the CTRL(EXTENDED1) + NUMLOCK two-key sequence
// ([MS-RDPBCGR] 2.2.8.1.2.2.1; docs/spec/share-data.md 3.6.1): CTRL down,
// NUMLOCK down, CTRL up, NUMLOCK up. Pause shares NumLock's set-1 scancode
// 0x45, so a bare 0x45 event is NOT a Pause press.
std::vector<std::vector<uint8_t>> EncodePauseKey();

// ---- PDU framing -----------------------------------------------------------

// Encodes a complete fast-path input PDU: fpInputHeader, length, and the
// concatenated `events`. `events` must hold 1..255 events (a count above 15
// uses the extended numEvents byte). The flags field is zero (Enhanced RDP
// Security has no per-PDU signature).
std::vector<uint8_t> EncodeFastPathInputPdu(
    const std::vector<std::vector<uint8_t>>& events);

}  // namespace rtsc::proto
