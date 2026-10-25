// Client fast-path input events ([MS-RDPBCGR] 2.2.8.1.2).

#include "rtsc/proto/input.h"

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/share.h"

namespace rtsc::proto {

namespace {

// The event header byte is eventFlags in the low 5 bits and eventCode in the
// high 3 bits ([MS-RDPBCGR] 2.2.8.1.2.2). Verified against the 4.7 dump:
// 0x20 -> eventCode = 1 (MOUSE), eventFlags = 0.
uint8_t EventHeader(FastPathInputEventCode code, uint8_t flags) {
    return static_cast<uint8_t>((static_cast<uint8_t>(code) << 5) | (flags & 0x1F));
}

}  // namespace

std::vector<uint8_t> EncodeKeyboardEvent(uint8_t key_code, bool release,
                                         bool extended) {
    uint8_t flags = 0;
    if (release) flags |= kKbdRelease;
    if (extended) flags |= kKbdExtended;
    ByteWriter w;
    w.u8(EventHeader(FastPathInputEventCode::kScancode, flags));
    w.u8(key_code);
    return w.take();
}

std::vector<uint8_t> EncodeUnicodeEvent(uint16_t unicode_code, bool release) {
    const uint8_t flags = release ? kKbdRelease : 0;
    ByteWriter w;
    w.u8(EventHeader(FastPathInputEventCode::kUnicode, flags));
    w.u16le(unicode_code);
    return w.take();
}

std::vector<uint8_t> EncodeMouseEvent(uint16_t pointer_flags, uint16_t x,
                                      uint16_t y, bool extended) {
    const FastPathInputEventCode code =
        extended ? FastPathInputEventCode::kMouseX
                 : FastPathInputEventCode::kMouse;
    ByteWriter w;
    w.u8(EventHeader(code, 0));  // eventFlags MUST be 0 for pointer events
    w.u16le(pointer_flags);
    w.u16le(x);
    w.u16le(y);
    return w.take();
}

std::vector<uint8_t> EncodeRelativeMouseEvent(uint16_t pointer_flags,
                                              int16_t dx, int16_t dy) {
    ByteWriter w;
    w.u8(EventHeader(FastPathInputEventCode::kMouseRel, 0));
    w.u16le(pointer_flags);
    w.u16le(static_cast<uint16_t>(dx));  // two's complement
    w.u16le(static_cast<uint16_t>(dy));
    return w.take();
}

std::vector<uint8_t> EncodeSyncEvent(uint8_t toggle_flags) {
    ByteWriter w;
    w.u8(EventHeader(FastPathInputEventCode::kSync, toggle_flags));
    return w.take();
}

std::vector<uint8_t> EncodeQoeTimestampEvent(uint32_t timestamp) {
    ByteWriter w;
    w.u8(EventHeader(FastPathInputEventCode::kQoeTimestamp, 0));
    w.u32le(timestamp);
    return w.take();
}

std::vector<std::vector<uint8_t>> EncodeCtrlAltDel() {
    // Ctrl down, Alt down, Delete down, Delete up, Alt up, Ctrl up. The Delete
    // key is extended (0xE0 0x53), so its two events carry kKbdExtended.
    return {
        EncodeKeyboardEvent(kScancodeLControl, false, false),
        EncodeKeyboardEvent(kScancodeLAlt, false, false),
        EncodeKeyboardEvent(kScancodeDelete, false, true),
        EncodeKeyboardEvent(kScancodeDelete, true, true),
        EncodeKeyboardEvent(kScancodeLAlt, true, false),
        EncodeKeyboardEvent(kScancodeLControl, true, false),
    };
}

std::vector<uint8_t> EncodeFastPathInputPdu(
    const std::vector<std::vector<uint8_t>>& events) {
    if (events.empty() || events.size() > 255) return {};

    std::vector<uint8_t> body;
    for (const auto& e : events) {
        body.insert(body.end(), e.begin(), e.end());
    }

    const size_t count = events.size();
    const bool extended_count = count > 15;
    const size_t ext = extended_count ? 1 : 0;

    // total = fpInputHeader(1) + length field + [numEvents(1)] + events.
    size_t total = 1 + 1 + ext + body.size();
    size_t length_bytes = 1;
    if (total > 127) {
        length_bytes = 2;
        total = 1 + 2 + ext + body.size();
    }
    if (total > 16383) return {};  // FastPathLength::kMax

    // fpInputHeader: action(2) = FASTPATH (0), numEvents(4), flags(2) = 0
    // (Enhanced RDP Security has no fipsInformation or dataSignature).
    const uint8_t header =
        static_cast<uint8_t>(((extended_count ? 0u : static_cast<uint32_t>(count)) &
                              0x0Fu)
                             << 2);

    ByteWriter w;
    w.u8(header);
    if (length_bytes == 1) {
        w.u8(static_cast<uint8_t>(total));
    } else {
        w.u8(static_cast<uint8_t>(0x80 | ((total >> 8) & 0x7F)));
        w.u8(static_cast<uint8_t>(total & 0xFF));
    }
    if (extended_count) w.u8(static_cast<uint8_t>(count));
    if (!body.empty()) w.bytes(body.data(), body.size());
    return w.take();
}

}  // namespace rtsc::proto
