#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

const char* to_string(Status s) {
    switch (s) {
        case Status::Ok: return "Ok";
        case Status::NeedMoreData: return "NeedMoreData";
        case Status::InvalidVersion: return "InvalidVersion";
        case Status::InvalidReserved: return "InvalidReserved";
        case Status::InvalidLength: return "InvalidLength";
        case Status::InvalidType: return "InvalidType";
        case Status::InvalidField: return "InvalidField";
    }
    return "Unknown";
}

bool ByteReader::u8(uint8_t& out) {
    if (remaining() < 1) return false;
    out = data_[offset_++];
    return true;
}

bool ByteReader::u16be(uint16_t& out) {
    if (remaining() < 2) return false;
    out = static_cast<uint16_t>((static_cast<uint16_t>(data_[offset_]) << 8) |
                                static_cast<uint16_t>(data_[offset_ + 1]));
    offset_ += 2;
    return true;
}

bool ByteReader::u16le(uint16_t& out) {
    if (remaining() < 2) return false;
    out = static_cast<uint16_t>(static_cast<uint16_t>(data_[offset_]) |
                                (static_cast<uint16_t>(data_[offset_ + 1]) << 8));
    offset_ += 2;
    return true;
}

bool ByteReader::u32be(uint32_t& out) {
    if (remaining() < 4) return false;
    out = (static_cast<uint32_t>(data_[offset_]) << 24) |
          (static_cast<uint32_t>(data_[offset_ + 1]) << 16) |
          (static_cast<uint32_t>(data_[offset_ + 2]) << 8) |
          static_cast<uint32_t>(data_[offset_ + 3]);
    offset_ += 4;
    return true;
}

bool ByteReader::u32le(uint32_t& out) {
    if (remaining() < 4) return false;
    out = static_cast<uint32_t>(data_[offset_]) |
          (static_cast<uint32_t>(data_[offset_ + 1]) << 8) |
          (static_cast<uint32_t>(data_[offset_ + 2]) << 16) |
          (static_cast<uint32_t>(data_[offset_ + 3]) << 24);
    offset_ += 4;
    return true;
}

bool ByteReader::bytes(uint8_t* out, size_t n) {
    if (remaining() < n) return false;
    for (size_t i = 0; i < n; ++i) out[i] = data_[offset_ + i];
    offset_ += n;
    return true;
}

bool ByteReader::skip(size_t n) {
    if (remaining() < n) return false;
    offset_ += n;
    return true;
}

void ByteWriter::u16be(uint16_t v) {
    buf_.push_back(static_cast<uint8_t>(v >> 8));
    buf_.push_back(static_cast<uint8_t>(v & 0xFF));
}

void ByteWriter::u16le(uint16_t v) {
    buf_.push_back(static_cast<uint8_t>(v & 0xFF));
    buf_.push_back(static_cast<uint8_t>(v >> 8));
}

void ByteWriter::u32be(uint32_t v) {
    buf_.push_back(static_cast<uint8_t>(v >> 24));
    buf_.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf_.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf_.push_back(static_cast<uint8_t>(v & 0xFF));
}

void ByteWriter::u32le(uint32_t v) {
    buf_.push_back(static_cast<uint8_t>(v & 0xFF));
    buf_.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf_.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf_.push_back(static_cast<uint8_t>(v >> 24));
}

}  // namespace rtsc::proto
