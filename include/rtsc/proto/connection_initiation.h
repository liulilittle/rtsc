#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/rdp_neg.h"
#include "rtsc/proto/tpkt.h"
#include "rtsc/proto/x224.h"

namespace rtsc::proto {

// [MS-RDPBCGR] 2.2.1.1.2 Correlation Info (36 bytes)
struct CorrelationInfo {
    static constexpr size_t kSize = 36;
    static constexpr uint32_t kSupportedVersion = 0x00000001;

    uint32_t version = kSupportedVersion;  // 1 byte in the wire format
    uint64_t id = 0;

    std::vector<uint8_t> encode() const;
};

// [MS-RDPBCGR] 2.2.1.1 Client X.224 Connection Request PDU
struct X224ConnectionRequest {
    std::string cookie;        // "Cookie: mstshash=<id>" (without CRLF)
    std::string routing_token; // mutually exclusive with cookie
    bool include_neg_req = true;
    RdpNegReq neg_req;
    bool include_correlation_info = false;
    CorrelationInfo correlation_info;

    // Builds the complete TPKT-framed PDU.
    std::vector<uint8_t> encode() const;
};

// [MS-RDPBCGR] 2.2.1.2 Server X.224 Connection Confirm PDU
struct X224ConnectionConfirm {
    X224Tpdu x224;
    RdpNegData neg_data;

    static Status parse(const uint8_t* data, size_t size, X224ConnectionConfirm& out);
};

// Streaming decoder helper: reads one TPKT-framed PDU from a byte buffer.
struct FramedPdu {
    std::vector<uint8_t> payload;  // bytes after the TPKT header
};

// Returns NeedMoreData when the buffer does not yet hold a full PDU.
Status read_framed_pdu(const uint8_t* data, size_t size, FramedPdu& out, size_t& consumed);

}  // namespace rtsc::proto
