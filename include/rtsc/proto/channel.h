// Static virtual channel PDU framing ([MS-RDPBCGR] 2.2.6.1).
//
// Reference: docs/spec/mcs-domain.md section 2.2.6.1.
//
// Every opaque virtual channel chunk is preceded by a CHANNEL_PDU_HEADER that
// carries the total uncompressed length of the message and the chunk flags. A
// message larger than the chunk size is split across several chunks and must be
// reassembled in order. This module is the framing only; the per-channel
// protocols (cliprdr, rdpdr, rdpsnd, drdynvc) sit on top.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// CHANNEL_PDU_HEADER.flags ([MS-RDPBCGR] 2.2.6.1.1).
enum ChannelFlag : uint32_t {
    kChannelFirst = 0x00000001,
    kChannelLast = 0x00000002,
    kChannelShowProtocol = 0x00000010,
    kChannelSuspend = 0x00000020,
    kChannelResume = 0x00000040,
    kChannelShadowPersistent = 0x00000080,
    kChannelPacketCompressed = 0x00200000,
    kChannelPacketAtFront = 0x00400000,
    kChannelPacketFlushed = 0x00800000,
    kChannelCompressionTypeMask = 0x000F0000,
};

// The default chunk size when VCChunkSize is not negotiated.
inline constexpr size_t kDefaultChannelChunkSize = 1600;

// Upper bound for one reassembled virtual channel message, 16 MiB. Aligned
// with drdynvc's kMaxMessageLength (include/rtsc/proto/drdynvc.h): each static
// virtual channel has the same unbounded sum of chunk payloads for
// ChannelReassembler, so a hostile peer declaring a 4 GiB CHANNEL_PDU_HEADER
// length must not be allowed to pin unbounded memory.
inline constexpr size_t kMaxChannelMessageBytes = 16u * 1024u * 1024u;

// CHANNEL_PDU_HEADER ([MS-RDPBCGR] 2.2.6.1.1), 8 bytes.
struct ChannelPduHeader {
    static constexpr size_t kSize = 8;

    // Total length of the *uncompressed* channel data, excluding this header.
    // The same value appears in every chunk of one message.
    uint32_t length = 0;
    uint32_t flags = 0;

    static Status parse(const uint8_t* data, size_t size, ChannelPduHeader& out);
};

// Reassembles a chunked virtual channel message.
class ChannelReassembler {
 public:
    // Feeds one chunk (header + payload). Sets `complete` when the LAST flag
    // arrives; `message` then holds the whole message. A chunk without FIRST
    // that has no open sequence is rejected.
    Status Feed(const ChannelPduHeader& header, const uint8_t* data, size_t size,
                bool& complete, std::vector<uint8_t>& message);

    void Reset();
    size_t buffered() const { return buffer_.size(); }

 private:
    std::vector<uint8_t> buffer_;
    uint32_t expected_length_ = 0;
    bool started_ = false;
};

// Splits `message` into chunks of at most `chunk_size` bytes. Each returned
// vector is a complete CHANNEL_PDU_HEADER + data. All chunks carry
// CHANNEL_FLAG_SHOW_PROTOCOL, as required for reassembly.
std::vector<std::vector<uint8_t>> FragmentChannelMessage(
    const std::vector<uint8_t>& message,
    size_t chunk_size = kDefaultChannelChunkSize);

}  // namespace rtsc::proto
