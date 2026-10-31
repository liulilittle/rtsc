#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace rtsc::proto {

enum class Status {
    Ok,
    NeedMoreData,
    InvalidVersion,
    InvalidReserved,
    InvalidLength,
    InvalidType,
    InvalidField,
};

const char* to_string(Status s);

// Bounds-checked little/big endian reader over a caller-owned byte span.
class ByteReader {
public:
    ByteReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    size_t offset() const { return offset_; }
    size_t remaining() const { return size_ - offset_; }
    bool empty() const { return offset_ >= size_; }

    bool u8(uint8_t& out);
    bool u16be(uint16_t& out);
    bool u16le(uint16_t& out);
    bool u32be(uint32_t& out);
    bool u32le(uint32_t& out);
    bool bytes(uint8_t* out, size_t n);
    bool skip(size_t n);

    const uint8_t* cursor() const { return data_ + offset_; }

private:
    const uint8_t* data_;
    size_t size_;
    size_t offset_ = 0;
};

// Bounds-checked little/big endian writer.
class ByteWriter {
public:
    void u8(uint8_t v) { buf_.push_back(v); }
    void u16be(uint16_t v);
    void u16le(uint16_t v);
    void u32be(uint32_t v);
    void u32le(uint32_t v);
    void u64be(uint64_t v);
    void bytes(const uint8_t* p, size_t n) {
        if (n == 0) return;
        const size_t at = buf_.size();
        buf_.resize(at + n);
        std::memcpy(buf_.data() + at, p, n);
    }

    size_t size() const { return buf_.size(); }
    const std::vector<uint8_t>& data() const { return buf_; }
    std::vector<uint8_t> take() { return std::move(buf_); }

private:
    std::vector<uint8_t> buf_;
};

}  // namespace rtsc::proto
