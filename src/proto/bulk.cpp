// RDP 8.0 bulk decompressor ([MS-RDPEGFX] 3.1.9.1 / [MS-RDPEDYC] 2.2.3.3).
// Supports RDP 8.0 Lite segments as carried by DYNVC_DATA_FIRST_COMPRESSED and
// DYNVC_DATA_COMPRESSED: SINGLE descriptor, compression type 0x06, an 8,192-byte
// history and an 8,192-byte per-segment ceiling.

#include "rtsc/proto/bulk.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace rtsc::proto {
namespace {

constexpr uint8_t kSegmentedSingle = 0xE0;
constexpr uint8_t kCompressTypeLite = 0x06;
constexpr uint8_t kPacketCompressed = 0x20;

// Reads bits most-significant first, bounded by `end` bits ([MS-RDPEGFX]
// 3.1.9.1.2.4: the trailer byte declares how many trailing bits are unused).
class BitReader {
 public:
  BitReader(const std::vector<uint8_t>& data, size_t first, size_t end_bits)
      : data_(data), start_(first), position_(0), end_(end_bits) {}

  size_t remaining() const { return end_ - position_; }

  bool Peek(size_t count, uint32_t* value) const {
    if (count > remaining()) return false;
    if (count == 0) {
      *value = 0;
      return true;
    }
    uint64_t window = 0;
    const size_t first = (position_ / 8) + start_;
    for (size_t i = 0; i < 5; ++i) {
      const size_t index = first + i;
      window = (window << 8) |
               (index < data_.size() ? static_cast<uint64_t>(data_[index]) : 0);
    }
    const size_t shift = 40 - (position_ % 8) - count;
    const uint64_t mask = (uint64_t{1} << count) - 1;
    *value = static_cast<uint32_t>((window >> shift) & mask);
    return true;
  }

  bool Read(size_t count, uint32_t* value) {
    if (!Peek(count, value)) return false;
    position_ += count;
    return true;
  }

  void Skip(size_t count) { position_ += count; }

  // Number of consecutive one bits starting at the current position.
  size_t LeadingOnes() const {
    size_t count = 0;
    for (size_t bit = position_; bit < end_; ++bit) {
      const uint8_t byte = data_[start_ + (bit / 8)];
      if ((byte & (0x80u >> (bit % 8))) == 0) break;
      ++count;
    }
    return count;
  }

  bool AlignToByte() {
    const size_t padding = (8 - (position_ % 8)) % 8;
    uint32_t ignored = 0;
    return Read(padding, &ignored);
  }

  // Reads `count` whole bytes; the reader must be byte-aligned.
  bool ReadBytes(size_t count, std::vector<uint8_t>* out) {
    if (position_ % 8 != 0) return false;
    if (count * 8 > remaining()) return false;
    const size_t first = start_ + (position_ / 8);
    out->insert(out->end(), data_.begin() + static_cast<std::ptrdiff_t>(first),
                data_.begin() + static_cast<std::ptrdiff_t>(first + count));
    position_ += count * 8;
    return true;
  }

 private:
  const std::vector<uint8_t>& data_;
  size_t start_;
  size_t position_;
  size_t end_;
};

enum class TokenKind {
  kNullLiteral,  // prefix "0", followed by an 8-bit literal value
  kLiteral,      // self-contained literal byte
  kMatch,        // distance code; distance 0 introduces an unencoded run
};

struct Token {
  uint16_t prefix;
  uint8_t prefix_len;
  TokenKind kind;
  uint8_t literal;
  uint8_t distance_bits;
  uint32_t distance_base;
};

constexpr Token kNullLiteral{0b0, 1, TokenKind::kNullLiteral, 0, 0, 0};

constexpr Token Literal(uint16_t prefix, uint8_t len, uint8_t value) {
  return Token{prefix, len, TokenKind::kLiteral, value, 0, 0};
}

constexpr Token Match(uint16_t prefix, uint8_t len, uint8_t distance_bits,
                      uint32_t distance_base) {
  return Token{prefix, len, TokenKind::kMatch, 0, distance_bits,
               distance_base};
}

// [MS-RDPEGFX] 3.1.9.1.2.1 token table. The prefixes form a prefix-free code.
// The 9-bit match prefixes are included for completeness of the RDP 8.0 table;
// RDP 8.0 Lite rejects every distance beyond its 8,192-byte history anyway.
constexpr Token kTokens[] = {
    kNullLiteral,
    Literal(0b11000, 5, 0x00),
    Literal(0b11001, 5, 0x01),
    Literal(0b110100, 6, 0x02),
    Literal(0b110101, 6, 0x03),
    Literal(0b110110, 6, 0xFF),
    Literal(0b1101110, 7, 0x04),
    Literal(0b1101111, 7, 0x05),
    Literal(0b1110000, 7, 0x06),
    Literal(0b1110001, 7, 0x07),
    Literal(0b1110010, 7, 0x08),
    Literal(0b1110011, 7, 0x09),
    Literal(0b1110100, 7, 0x0A),
    Literal(0b1110101, 7, 0x0B),
    Literal(0b1110110, 7, 0x3A),
    Literal(0b1110111, 7, 0x3B),
    Literal(0b1111000, 7, 0x3C),
    Literal(0b1111001, 7, 0x3D),
    Literal(0b1111010, 7, 0x3E),
    Literal(0b1111011, 7, 0x3F),
    Literal(0b1111100, 7, 0x40),
    Literal(0b1111101, 7, 0x80),
    Literal(0b11111100, 8, 0x0C),
    Literal(0b11111101, 8, 0x38),
    Literal(0b11111110, 8, 0x39),
    Literal(0b11111111, 8, 0x66),
    Match(0b10001, 5, 5, 0),
    Match(0b10010, 5, 7, 32),
    Match(0b10011, 5, 9, 160),
    Match(0b10100, 5, 10, 672),
    Match(0b10101, 5, 12, 1696),
    Match(0b101100, 6, 14, 5792),
    Match(0b101101, 6, 15, 22176),
    Match(0b1011100, 7, 18, 54944),
    Match(0b1011101, 7, 20, 317088),
    Match(0b10111100, 8, 20, 1365664),
    Match(0b10111101, 8, 21, 2414240),
    Match(0b101111100, 9, 22, 4511392),
    Match(0b101111101, 9, 23, 8705696),
    Match(0b101111110, 9, 24, 17094304),
};

}  // namespace

BulkDecompressor::BulkDecompressor() : history_(kHistorySize) {}

size_t BulkDecompressor::Decompress(const std::vector<uint8_t>& input,
                                    std::vector<uint8_t>* output) {
  if (input.size() < 2) return 0;
  if (input[0] != kSegmentedSingle) return 0;  // MULTIPART is not valid here
  const uint8_t header = input[1];
  if ((header & 0x0F) != kCompressTypeLite) return 0;

  if ((header & kPacketCompressed) == 0) {
    const size_t data_size = input.size() - 2;
    if (data_size > kMaxSegmentSize) return 0;
    AppendRaw(input, 2, data_size, output);
    return data_size;
  }

  // Compressed segment: the last byte is the trailer; its low three bits count
  // the unused bits of the preceding byte ([MS-RDPEGFX] 3.1.9.1.2.4).
  if (input.size() < 3) return 0;
  const uint8_t trailer = input.back();
  const size_t unused_bits = trailer & 0x07;
  const size_t encoded_bytes = input.size() - 3;
  const size_t total_bits = encoded_bytes * 8;
  if (unused_bits > total_bits) return 0;
  const size_t bit_count = total_bits - unused_bits;

  BitReader bits(input, 2, bit_count);
  size_t written = 0;

  while (bits.remaining() > 0) {
    const Token* token = nullptr;
    for (const Token& candidate : kTokens) {
      uint32_t prefix = 0;
      if (!bits.Peek(candidate.prefix_len, &prefix)) continue;
      if (prefix == candidate.prefix) {
        token = &candidate;
        break;
      }
    }
    if (token == nullptr) return 0;  // reserved or truncated token
    bits.Skip(token->prefix_len);

    if (token->kind == TokenKind::kNullLiteral) {
      uint32_t value = 0;
      if (!bits.Read(8, &value)) return 0;
      if (written + 1 > kMaxSegmentSize) return 0;
      PushLiteral(static_cast<uint8_t>(value), output);
      ++written;
      continue;
    }
    if (token->kind == TokenKind::kLiteral) {
      if (written + 1 > kMaxSegmentSize) return 0;
      PushLiteral(token->literal, output);
      ++written;
      continue;
    }

    uint32_t offset = 0;
    if (!bits.Read(token->distance_bits, &offset)) return 0;
    const uint32_t distance = offset + token->distance_base;
    if (distance == 0) {
      uint32_t run_length = 0;
      if (!bits.Read(15, &run_length)) return 0;
      if (run_length > kMaxSegmentSize - written) return 0;
      if (!bits.AlignToByte()) return 0;
      if (!bits.ReadBytes(run_length, output)) return 0;
      for (size_t i = 0; i < run_length; ++i) {
        history_[position_] = (*output)[output->size() - run_length + i];
        position_ = (position_ + 1) % history_.size();
      }
      written += run_length;
      continue;
    }
    if (distance > history_.size()) return 0;

    // Length: N one bits, a zero bit, then N+1 value bits; N == 0 means 3.
    const size_t ones = bits.LeadingOnes();
    if (ones > 14) return 0;  // reserved prefix
    uint32_t ignored = 0;
    if (!bits.Read(static_cast<size_t>(ones) + 1, &ignored)) return 0;
    size_t length = 3;
    if (ones > 0) {
      const size_t value_bits = ones + 1;
      uint32_t value = 0;
      if (!bits.Read(value_bits, &value)) return 0;
      length = (size_t{1} << value_bits) + value;
    }
    if (length > kMaxSegmentSize - written) return 0;
    CopyMatch(distance, length, output);
    written += length;
  }

  return written;
}

void BulkDecompressor::AppendRaw(const std::vector<uint8_t>& input,
                                 size_t offset, size_t count,
                                 std::vector<uint8_t>* output) {
  output->insert(output->end(),
                 input.begin() + static_cast<std::ptrdiff_t>(offset),
                 input.begin() + static_cast<std::ptrdiff_t>(offset + count));
  for (size_t i = 0; i < count; ++i) {
    history_[position_] = input[offset + i];
    position_ = (position_ + 1) % history_.size();
  }
}

void BulkDecompressor::PushLiteral(uint8_t value,
                                   std::vector<uint8_t>* output) {
  history_[position_] = value;
  position_ = (position_ + 1) % history_.size();
  output->push_back(value);
}

void BulkDecompressor::CopyMatch(uint32_t distance, size_t length,
                                 std::vector<uint8_t>* output) {
  const size_t history_size = history_.size();
  size_t source = (position_ + history_size - distance) % history_size;
  for (size_t i = 0; i < length; ++i) {
    const uint8_t value = history_[source];
    history_[position_] = value;
    position_ = (position_ + 1) % history_size;
    output->push_back(value);
    source = (source + 1) % history_size;
  }
}

}  // namespace rtsc::proto
