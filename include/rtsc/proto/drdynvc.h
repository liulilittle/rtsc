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
#include <map>
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
    // DYNVC_DATA_FIRST.Length ([MS-RDPEDYC] 2.2.2.1): total size of the
    // logical message. Zero for every other command.
    uint32_t length = 0;
    // Payload after the ChannelId (and after Length for DYNVC_DATA_FIRST).
    std::vector<uint8_t> data;

    static Status parse(const uint8_t* data, size_t size, DynvcPdu& out);
};

// Builds a drdynvc PDU, picking the smallest ChannelId width that fits.
//
// DYNVC_DATA_FIRST always carries a 4-byte Length field ([MS-RDPEDYC]
// 2.2.3.1). This convenience builder sets it to data.size(), i.e. it encodes a
// message that is COMPLETE in this single frame. It must NOT be used for the
// first fragment of a multi-PDU message: use BuildDynvcDataFirstPdu(sp,
// channel_id, total_length, fragment) there, or BuildDynvcDataPdus() to encode
// a whole message with the correct framing.
std::vector<uint8_t> BuildDynvcPdu(DynvcCmd cmd, uint8_t sp, uint32_t channel_id,
                                   const std::vector<uint8_t>& data);

// Builds a DYNVC_DATA_FIRST PDU whose Length field is `total_length`, allowing
// a message whose first fragment is shorter than the whole message.
std::vector<uint8_t> BuildDynvcDataFirstPdu(uint8_t sp, uint32_t channel_id,
                                            uint32_t total_length,
                                            const std::vector<uint8_t>& data);

// Largest message payload sent as a single DYNVC_DATA PDU ([MS-RDPEDYC]
// 2.2.3.2 / 3.1.5.2).
inline constexpr size_t kMaxSingleDataPduPayload = 1590;

// Encodes one channel message for the wire: at most 1,590 bytes becomes a
// single DYNVC_DATA PDU; a larger message becomes DYNVC_DATA_FIRST (Length set
// to the whole message) followed by DYNVC_DATA PDUs.
std::vector<std::vector<uint8_t>> BuildDynvcDataPdus(
    uint32_t channel_id, const std::vector<uint8_t>& data,
    size_t max_fragment = 1500);

// Reassembles the fragments of one logical channel message. DYNVC_DATA_FIRST
// starts a message on its ChannelId and DYNVC_DATA continues it; the state of
// each channel is independent ([MS-RDPEDYC] 2.2.2.1 / 2.2.2.2).
class DynvcReassembler {
 public:
    // Bounds that keep a hostile peer from pinning unbounded memory: a single
    // logical message, the number of half-assembled channels, and the total
    // bytes buffered across all channels.
    static constexpr size_t kMaxMessageLength = 16u * 1024u * 1024u;
    static constexpr size_t kMaxPendingChannels = 64;
    static constexpr size_t kMaxBufferedBytes = kMaxMessageLength;

    // Feeds one parsed DYNVC_DATA_FIRST / DYNVC_DATA PDU. Returns true and
    // fills `message` only when a whole channel message is available;
    // `message` is untouched otherwise. Any other command returns false.
    bool Feed(const DynvcPdu& pdu, std::vector<uint8_t>& message);

    // Drops the half-assembled message of one channel, if any.
    void Reset(uint32_t channel_id);
    void ResetAll();

    size_t pending_channels() const { return state_.size(); }
    size_t buffered_bytes() const { return buffered_bytes_; }

 private:
    struct State {
        uint32_t expected_length = 0;
        std::vector<uint8_t> data;
    };
    std::map<uint32_t, State> state_;
    size_t buffered_bytes_ = 0;
};

}  // namespace rtsc::proto
