// Static virtual channel PDU framing ([MS-RDPBCGR] 2.2.6.1).

#include "rtsc/proto/channel.h"

#include <algorithm>

namespace rtsc::proto {

Status ChannelPduHeader::parse(const uint8_t* data, size_t size,
                               ChannelPduHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ByteReader r(data, size);
    r.u32le(out.length);
    r.u32le(out.flags);
    return Status::Ok;
}

Status ChannelReassembler::Feed(const ChannelPduHeader& header,
                                const uint8_t* data, size_t size, bool& complete,
                                std::vector<uint8_t>& message) {
    complete = false;
    message.clear();

    if ((header.flags & kChannelFirst) != 0) {
        // A new message begins; discard any half-assembled previous one. A
        // declared total above the cap is rejected before a single byte is
        // buffered: the sequence could otherwise stay open forever with a
        // 4 GiB header while the sum of chunk payloads grows unbounded.
        buffer_.clear();
        if (header.length > kMaxChannelMessageBytes) {
            Reset();
            return Status::InvalidLength;
        }
        expected_length_ = header.length;
        started_ = true;
    } else if (!started_) {
        // A middle/last chunk with no open sequence cannot be placed.
        return Status::InvalidField;
    }

    if (data != nullptr && size > 0) {
        // The sum of buffered payloads must stay within the cap. Check with
        // subtraction so size + buffered cannot wrap around size_t.
        if (size > kMaxChannelMessageBytes ||
            buffer_.size() > kMaxChannelMessageBytes - size) {
            Reset();
            return Status::InvalidLength;
        }
        buffer_.insert(buffer_.end(), data, data + size);
    }

    if ((header.flags & kChannelLast) != 0) {
        if (buffer_.size() != expected_length_) {
            Reset();
            return Status::InvalidLength;
        }
        message = std::move(buffer_);
        buffer_.clear();
        started_ = false;
        complete = true;
    }
    return Status::Ok;
}

void ChannelReassembler::Reset() {
    buffer_.clear();
    expected_length_ = 0;
    started_ = false;
}

std::vector<std::vector<uint8_t>> FragmentChannelMessage(
    const std::vector<uint8_t>& message, size_t chunk_size) {
    std::vector<std::vector<uint8_t>> chunks;
    if (message.empty() || chunk_size == 0) return chunks;

    const size_t total = message.size();
    size_t pos = 0;
    while (pos < total) {
        const size_t n = std::min(chunk_size, total - pos);
        uint32_t flags = kChannelShowProtocol;
        if (pos == 0) flags |= kChannelFirst;
        if (pos + n == total) flags |= kChannelLast;

        ByteWriter w;
        w.u32le(static_cast<uint32_t>(total));
        w.u32le(flags);
        w.bytes(message.data() + pos, n);
        chunks.push_back(w.take());
        pos += n;
    }
    return chunks;
}

}  // namespace rtsc::proto
