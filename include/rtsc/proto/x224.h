#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// [X224] section 13.3 (CRQ) / 13.4 (CCF) / 13.5 (DR).
// Common Class 0 TPDU layout (7 bytes):
//   LI(1) | code(1) | dst-ref(2) | src-ref(2) | class+options(1)
struct X224Tpdu {
    enum Code : uint8_t {
        kConnectionRequest = 0xE0,
        kConnectionConfirm = 0xD0,
        kDisconnectRequest = 0x80,
        kData = 0xF0,
    };

    static constexpr size_t kSize = 7;
    static constexpr uint8_t kClass0 = 0x00;
    // Source reference value mandated for Connection Confirm ([MS-RDPBCGR] 2.2.1.2).
    static constexpr uint16_t kCcfSourceReference = 0x1234;

    uint8_t length_indicator = 6;
    uint8_t code = kConnectionRequest;
    uint16_t destination_reference = 0;
    uint16_t source_reference = 0;
    uint8_t class_options = kClass0;

    static Status parse(const uint8_t* data, size_t size, X224Tpdu& out);
    Status validate() const;
    std::vector<uint8_t> encode() const;

    static X224Tpdu make_connection_request();
    static X224Tpdu make_connection_confirm(uint16_t source_reference = kCcfSourceReference);
    static X224Tpdu make_disconnect_request();
};

// X.224 Data TPDU prefix used inside MCS Send Data Request: 02 F0 80.
struct X224DataPrefix {
    static constexpr size_t kSize = 3;
    static constexpr uint8_t kLengthIndicator = 0x02;
    static constexpr uint8_t kCode = 0xF0;
    static constexpr uint8_t kEot = 0x80;

    static Status parse(const uint8_t* data, size_t size);
    static void encode(ByteWriter& w);
};

}  // namespace rtsc::proto
