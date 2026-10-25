#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// BER/DER subset required by T.125 (MCS) and T.124 (GCC) as used by RDP.
// Only definite-length primitive/constructed forms are accepted: RDP peers
// never emit indefinite length in the connection sequence.
enum BerTag : uint8_t {
    kBerBoolean = 0x01,
    kBerInteger = 0x02,
    kBerOctetString = 0x04,
    kBerNull = 0x05,
    kBerEnumerated = 0x0A,
    kBerSequence = 0x30,
    kBerChoice = 0x80,  // context-specific primitive, not used for RDP
};

class BerWriter {
public:
    void boolean(bool v);
    void integer(int64_t v);
    void enumerated(int64_t v);
    void octet_string(const uint8_t* p, size_t n);
    void octet_string(const std::vector<uint8_t>& v) { octet_string(v.data(), v.size()); }
    void octet_string(const std::string& s) {
        octet_string(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    // Appends one raw byte. Needed for the second byte of multi-byte tags
    // (e.g. the MCS Connect Initial application tag 0x7F 0x65).
    void raw_byte(uint8_t v) { buf_.push_back(v); }

    // Begins a constructed SEQUENCE; call end_constructed() with its tag.
    // Returns the offset of the length placeholder for end_constructed().
    size_t begin_sequence();
    // Begins an arbitrary constructed element (e.g. 0xA0 application wrapper).
    size_t begin_constructed(uint8_t tag);
    void end_constructed(size_t mark, uint8_t tag);

    size_t size() const { return buf_.size(); }
    const std::vector<uint8_t>& data() const { return buf_; }
    std::vector<uint8_t> take() { return std::move(buf_); }

private:
    void write_length(size_t len);

    std::vector<uint8_t> buf_;
};

class BerReader {
public:
    BerReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    size_t offset() const { return offset_; }
    size_t remaining() const { return size_ - offset_; }
    bool empty() const { return offset_ >= size_; }

    // Peeks the next tag without consuming it.
    bool peek_tag(uint8_t& tag) const;

    // Reads a TLV header and returns the value span. Rejects indefinite
    // length, non-minimal long-form lengths and out-of-bounds lengths.
    Status read_header(uint8_t& tag, const uint8_t*& value, size_t& value_len);

    Status read_boolean(bool& out);
    Status read_integer(int64_t& out);
    Status read_octet_string(std::vector<uint8_t>& out);
    Status read_octet_string_view(const uint8_t*& p, size_t& n);

    // Consumes a constructed header and returns a sub-reader over its value.
    Status read_constructed(uint8_t expected_tag, BerReader& out);

private:
    const uint8_t* data_;
    size_t size_;
    size_t offset_ = 0;
};

}  // namespace rtsc::proto
