// Dynamic virtual channel (drdynvc) structure layer ([MS-RDPEDYC] 2.2).
//
// Every drdynvc PDU shares a 1-byte header (cbId / Sp / Cmd) followed by a
// variable-width ChannelId and then command-specific fields. This module covers
// the header, the channel-id decoding and the generic framing; the per-command
// payloads (Create, DataFirst, Capability, ...) are decoded by the caller.
//
// The channel runs over a static virtual channel, so the bytes here are the
// channel data that a ChannelPduHeader wraps.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// DYNVC_HEADER.Cmd ([MS-RDPEDYC] 2.2).
enum class DynvcCmd : uint8_t {
    kCreate = 0x1,
    kDataFirst = 0x2,
    kData = 0x3,
    kClose = 0x4,
    kCapability = 0x5,
    kDataFirstCompressed = 0x6,
    kDataCompressed = 0x7,
    kSoftSyncRequest = 0x8,
    kSoftSyncResponse = 0x9,
};

const char* to_string(DynvcCmd cmd);

// DYNVC_HEADER (1 byte): cbId (2 bits, low) | Sp (2 bits) | Cmd (4 bits).
struct DynvcHeader {
    static constexpr size_t kSize = 1;

    DynvcCmd cmd = DynvcCmd::kData;
    uint8_t sp = 0;
    uint8_t cb_id = 0;  // 0 -> 1 byte, 1 -> 2 bytes, 2 -> 4 bytes

    static Status parse(const uint8_t* data, size_t size, DynvcHeader& out);
    void write(ByteWriter& w) const;

    // Width of the ChannelId field in bytes (1, 2 or 4).
    size_t channel_id_size() const { return static_cast<size_t>(1) << cb_id; }
    bool valid() const { return cb_id <= 2; }
};

// Parses the variable-width ChannelId that follows the header.
Status ParseDynvcChannelId(const DynvcHeader& header, const uint8_t* data,
                           size_t size, uint32_t& out);

// A parsed drdynvc PDU: header + channel id + command data.
struct DynvcPdu {
    DynvcHeader header;
    uint32_t channel_id = 0;
    std::vector<uint8_t> data;

    static Status parse(const uint8_t* data, size_t size, DynvcPdu& out);
};

// Builds a drdynvc PDU, picking the smallest ChannelId width that fits.
std::vector<uint8_t> BuildDynvcPdu(DynvcCmd cmd, uint8_t sp, uint32_t channel_id,
                                   const std::vector<uint8_t>& data);

}  // namespace rtsc::proto
