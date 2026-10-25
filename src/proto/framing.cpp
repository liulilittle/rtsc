#include "rtsc/proto/framing.h"

namespace rtsc::proto {

namespace {

// A TPKT header is 4 bytes and must be followed by at least one byte of
// payload for the PDU to be meaningful, so the smallest legal length is 4.
// Length 4 (header only) is accepted because some servers emit zero-length
// keepalive frames; the caller sees an empty payload and decides.
constexpr size_t kTpktHeaderSize = TpktHeader::kSize;
constexpr size_t kMinTpktLength = kTpktHeaderSize;

}  // namespace

void TpktStream::Append(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0) return;
    Compact();
    buf_.insert(buf_.end(), data, data + size);
}

void TpktStream::Compact() {
    if (read_ == 0) return;
    if (read_ == buf_.size()) {
        buf_.clear();
        read_ = 0;
        return;
    }
    // Only pay for the move once the consumed prefix dominates the buffer;
    // erasing on every PDU would make the framer quadratic in PDU count.
    if (read_ >= buf_.size() / 2) {
        buf_.erase(buf_.begin(), buf_.begin() + static_cast<ptrdiff_t>(read_));
        read_ = 0;
    }
}

size_t TpktStream::SkipToNextCandidate() {
    // A candidate header is: version 3, reserved 0, and a plausible big-endian
    // length. Scanning byte by byte is correct here because the caller only
    // reaches this path after the stream already desynchronised.
    size_t skipped = 0;
    while (read_ + kTpktHeaderSize <= buf_.size()) {
        const uint8_t* p = buf_.data() + read_;
        const uint16_t len =
            static_cast<uint16_t>((static_cast<uint16_t>(p[2]) << 8) | p[3]);
        if (p[0] == TpktHeader::kVersion && p[1] == 0 && len >= kMinTpktLength) {
            break;
        }
        ++read_;
        ++skipped;
    }
    dropped_ += skipped;
    return skipped;
}

Status TpktStream::Next(std::vector<uint8_t>& payload) {
    payload.clear();
    if (buffered() < kTpktHeaderSize) return Status::NeedMoreData;

    const uint8_t* p = buf_.data() + read_;
    if (p[0] != TpktHeader::kVersion || p[1] != 0) {
        // Lost sync: advance to the next byte that could start a header.
        if (SkipToNextCandidate() == 0 && buffered() >= kTpktHeaderSize) {
            // The current position already looks like a header but failed the
            // version/reserved test above, so force one byte of progress.
            ++read_;
            ++dropped_;
        }
        if (buffered() < kTpktHeaderSize) return Status::NeedMoreData;
        p = buf_.data() + read_;
        if (p[0] != TpktHeader::kVersion || p[1] != 0) {
            return Status::NeedMoreData;
        }
    }

    const uint16_t length =
        static_cast<uint16_t>((static_cast<uint16_t>(p[2]) << 8) | p[3]);
    if (length < kMinTpktLength) {
        // Not a real header; drop one byte so the caller can retry.
        ++read_;
        ++dropped_;
        return Status::InvalidLength;
    }
    if (buffered() < length) return Status::NeedMoreData;

    payload.assign(buf_.begin() + static_cast<ptrdiff_t>(read_ + kTpktHeaderSize),
                   buf_.begin() + static_cast<ptrdiff_t>(read_ + length));
    read_ += length;
    Compact();
    return Status::Ok;
}

void TpktStream::Clear() {
    buf_.clear();
    read_ = 0;
    dropped_ = 0;
}

std::vector<uint8_t> WrapTpkt(const uint8_t* payload, size_t size) {
    if (size > TpktHeader::kMaxPayload) return {};
    ByteWriter w;
    w.u8(TpktHeader::kVersion);
    w.u8(0);
    w.u16be(static_cast<uint16_t>(kTpktHeaderSize + size));
    if (size != 0) w.bytes(payload, size);
    return w.take();
}

}  // namespace rtsc::proto
