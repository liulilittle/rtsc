#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/tpkt.h"

namespace rtsc::proto {

// Incremental TPKT (T.123) stream framer.
//
// TCP is a byte stream: a single recv() can return half a PDU, or three PDUs
// glued together. TpktStream buffers whatever arrives and hands back exactly
// one complete PDU payload at a time (the 4-byte TPKT header is stripped).
//
// Resynchronisation: if a PDU does not start with TPKT version 3 the framer
// scans forward for the next plausible header and counts the bytes it skipped,
// instead of desynchronising permanently. Skipped bytes are exposed through
// dropped_bytes() so a caller can log or abort on them.
class TpktStream {
public:
    // Appends received bytes to the buffer.
    void Append(const uint8_t* data, size_t size);

    // Extracts the next complete PDU.
    //   Status::Ok            -> `payload` holds the PDU body (header removed)
    //   Status::NeedMoreData  -> not enough bytes yet, nothing consumed
    //   Status::InvalidLength -> a header claimed a length below the minimum;
    //                            one byte is dropped and the caller may retry
    Status Next(std::vector<uint8_t>& payload);

    // Bytes currently buffered and not yet returned by Next().
    size_t buffered() const { return buf_.size() - read_; }

    // Total bytes discarded while resynchronising.
    size_t dropped_bytes() const { return dropped_; }

    // Drops all buffered bytes and the drop counter.
    void Clear();

private:
    void Compact();
    size_t SkipToNextCandidate();

    std::vector<uint8_t> buf_;
    size_t read_ = 0;
    size_t dropped_ = 0;
};

// Wraps `size` payload bytes in a TPKT header.
// Returns an empty vector when the payload cannot fit (size > kMaxPayload).
std::vector<uint8_t> WrapTpkt(const uint8_t* payload, size_t size);

}  // namespace rtsc::proto
