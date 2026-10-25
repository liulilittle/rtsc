#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// [T123] section 8. All multi-byte fields are network byte order.
struct TpktHeader {
    static constexpr uint8_t kVersion = 3;
    static constexpr size_t kSize = 4;
    static constexpr uint16_t kMaxLength = 0xFFFF;
    // Default maximum X.224 data payload when no TPDU size parameter is
    // negotiated (see [MS-RDPBCGR] 2.2.1.1 sending notes).
    static constexpr size_t kMaxPayload = 65528;

    uint16_t length = 0;  // includes the 4-byte header

    // Reads a TPKT header from the start of `data`.
    // NeedMoreData when fewer than 4 bytes are available.
    static Status parse(const uint8_t* data, size_t size, TpktHeader& out);

    // Validates version, reserved and length consistency for a fully
    // received PDU whose total size is `available`.
    Status validate(size_t available) const;

    std::vector<uint8_t> encode() const;

    size_t payload_size() const { return length >= kSize ? length - kSize : 0; }
};

}  // namespace rtsc::proto
