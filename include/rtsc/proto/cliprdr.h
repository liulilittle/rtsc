// Clipboard virtual channel (cliprdr) structure layer ([MS-RDPECLIP] 2.2).
//
// Reference: [MS-RDPECLIP] 2.2.1 (header) and 2.2.2 (message payloads).
//
// This module covers the CLIPRDR_HEADER, the format list, the format data
// request / response, and the capability exchange payload. The channel runs
// over a static virtual channel, so each PDU here is the channel data that a
// ChannelPduHeader wraps.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// CLIPRDR_HEADER.msgType ([MS-RDPECLIP] 2.2.1).
enum class CliprdrMsgType : uint16_t {
    kMonitorReady = 0x0001,
    kFormatList = 0x0002,
    kFormatListResponse = 0x0003,
    kFormatDataRequest = 0x0004,
    kFormatDataResponse = 0x0005,
    kTempDirectory = 0x0006,
    kClipCaps = 0x0007,
    kFileContentsRequest = 0x0008,
    kFileContentsResponse = 0x0009,
    kLockClipData = 0x000A,
    kUnlockClipData = 0x000B,
};

const char* to_string(CliprdrMsgType type);

// CLIPRDR_HEADER.msgFlags.
enum CliprdrMsgFlag : uint16_t {
    kClipResponseOk = 0x0001,
    kClipResponseFail = 0x0002,
    kClipAsciiNames = 0x0004,
};

// Standard clipboard format IDs ([MS-RDPECLIP] 2.2.3.1).
enum CliprdrFormat : uint32_t {
    kCfText = 1,
    kCfBitmap = 2,
    kCfDib = 8,
    kCfUnicodeText = 13,
    kCfHdrop = 15,
    kCfDibV5 = 17,
};

// CLIPRDR_HEADER ([MS-RDPECLIP] 2.2.1), 8 bytes.
struct CliprdrHeader {
    static constexpr size_t kSize = 8;

    CliprdrMsgType msg_type = CliprdrMsgType::kMonitorReady;
    uint16_t msg_flags = 0;
    uint32_t data_len = 0;

    static Status parse(const uint8_t* data, size_t size, CliprdrHeader& out);
    void write(ByteWriter& w) const;
};

// A parsed cliprdr PDU: header + payload.
struct CliprdrPdu {
    CliprdrHeader header;
    std::vector<uint8_t> data;

    static Status parse(const uint8_t* data, size_t size, CliprdrPdu& out);
};

// Builds a complete cliprdr PDU (header + payload).
std::vector<uint8_t> BuildCliprdrPdu(CliprdrMsgType type, uint16_t flags,
                                     const std::vector<uint8_t>& data);

// CB_FORMAT_LIST: a sequence of little-endian u32 format IDs.
struct CliprdrFormatList {
    std::vector<uint32_t> formats;

    static Status parse(const std::vector<uint8_t>& data, CliprdrFormatList& out);
    std::vector<uint8_t> encode() const;
};

// CB_FORMAT_DATA_REQUEST: a single requested format ID.
struct CliprdrFormatDataRequest {
    uint32_t format_id = 0;

    static Status parse(const std::vector<uint8_t>& data,
                        CliprdrFormatDataRequest& out);
    std::vector<uint8_t> encode() const;
};

}  // namespace rtsc::proto
