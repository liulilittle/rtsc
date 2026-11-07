// RDP 8.0 bulk decompressor tests ([MS-RDPEGFX] 3.1.9.1 / [MS-RDPEDYC] 2.2.3.3).
// This is the first phase: segment parsing, history buffer, and bounds checking.
// Non-compressed segments are passed through; Huffman token tables and bitstream
// decoding will be implemented in phase two.

#include "test_main.h"
#include "rtsc/proto/bulk.h"
#include <vector>

RTSC_TEST(bulk_uncompressed_single_segment) {
  // SINGLE (0xE0), uncompressed, header type 0x06 (RDP 8.0 Lite).
  const std::vector<uint8_t> input = {0xE0, 0x06, 'h', 'e', 'l', 'l', 'o'};
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  size_t written = decompressor.Decompress(input, &output);
  CHECK_EQ(written, static_cast<size_t>(5));
  CHECK_EQ(output.size(), static_cast<size_t>(5));
  CHECK_EQ(output[0], static_cast<uint8_t>('h'));
  CHECK_EQ(output[1], static_cast<uint8_t>('e'));
  CHECK_EQ(output[2], static_cast<uint8_t>('l'));
  CHECK_EQ(output[3], static_cast<uint8_t>('l'));
  CHECK_EQ(output[4], static_cast<uint8_t>('o'));
}

RTSC_TEST(bulk_compressed_literal_and_null_literal) {
  // [MS-RDPEGFX] 3.1.9.1.2.5 style vectors: literal 0x01 then a null-preceded
  // literal 0x65. Trailer byte is the trailing unused-bit count.
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  const std::vector<uint8_t> one = {0xE0, 0x26, 0b11001000, 0x03};
  CHECK_EQ(decompressor.Decompress(one, &output), static_cast<size_t>(1));
  CHECK_EQ(output.size(), static_cast<size_t>(1));
  CHECK_EQ(output[0], static_cast<uint8_t>(0x01));

  rtsc::proto::BulkDecompressor second;
  std::vector<uint8_t> output2;
  const std::vector<uint8_t> null_literal = {0xE0, 0x26, 0b00110010,
                                             0b10000000, 0x07};
  CHECK_EQ(second.Decompress(null_literal, &output2), static_cast<size_t>(1));
  CHECK_EQ(output2[0], static_cast<uint8_t>(0x65));
}

RTSC_TEST(bulk_compressed_multiple_literals) {
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  const std::vector<uint8_t> input = {0xE0, 0x26, 0b11001110, 0b10011011,
                                      0b00011001, 0b01000000, 0x06};
  CHECK_EQ(decompressor.Decompress(input, &output), static_cast<size_t>(4));
  CHECK_EQ(output.size(), static_cast<size_t>(4));
  CHECK_EQ(output[0], static_cast<uint8_t>(0x01));
  CHECK_EQ(output[1], static_cast<uint8_t>(0x02));
  CHECK_EQ(output[2], static_cast<uint8_t>(0xFF));
  CHECK_EQ(output[3], static_cast<uint8_t>(0x65));
}

RTSC_TEST(bulk_compressed_overlapping_match) {
  // Literal 0x65 then a match at distance 1, length 4: the copy overlaps itself.
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  const std::vector<uint8_t> input = {0xE0, 0x26, 0b00110010, 0b11000100,
                                      0b00110000, 0x01};
  CHECK_EQ(decompressor.Decompress(input, &output), static_cast<size_t>(5));
  CHECK_EQ(output.size(), static_cast<size_t>(5));
  for (size_t i = 0; i < output.size(); ++i) {
    CHECK_EQ(output[i], static_cast<uint8_t>(0x65));
  }
}

RTSC_TEST(bulk_compressed_unencoded_run) {
  const char text[] = "The quick brown fox jumps over the lazy dog";
  std::vector<uint8_t> input = {0xE0, 0x26, 0b10001000, 0b00000000,
                                0b00010101, 0b10000000};
  for (const char* p = text; *p != '\0'; ++p) {
    input.push_back(static_cast<uint8_t>(*p));
  }
  input.push_back(0x00);  // trailer: all bits used
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  CHECK_EQ(decompressor.Decompress(input, &output),
           static_cast<size_t>(sizeof(text) - 1));
  CHECK_EQ(output.size(), sizeof(text) - 1);
  for (size_t i = 0; i < output.size(); ++i) {
    CHECK_EQ(output[i], static_cast<uint8_t>(text[i]));
  }
}

RTSC_TEST(bulk_compressed_sample_abc_repeated) {
  // [MS-RDPEGFX] 4.2.1.1.3: "ABC" repeated 20 times.
  const std::vector<uint8_t> input = {0xE0, 0x26, 0x20, 0x90,
                                      0x88, 0x71, 0x1F, 0xB2, 0x01};
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  CHECK_EQ(decompressor.Decompress(input, &output), static_cast<size_t>(60));
  CHECK_EQ(output.size(), static_cast<size_t>(60));
  bool matches = true;
  for (size_t i = 0; i < output.size(); ++i) {
    if (output[i] != static_cast<uint8_t>("ABC"[i % 3])) matches = false;
  }
  CHECK(matches);
}

RTSC_TEST(bulk_lite_samples_share_history) {
  // [MS-RDPEDYC] 4.3.3 / 4.3.4: two RDP 8.0 Lite segments; the second matches
  // bytes produced by the first.
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  const std::vector<uint8_t> first = {0xE0, 0x26, 0x38, 0xC4, 0x3F,
                                      0xF4, 0x74, 0x01};
  CHECK_EQ(decompressor.Decompress(first, &output), static_cast<size_t>(1595));
  bool all_q = true;
  for (size_t i = 0; i < output.size(); ++i) {
    if (output[i] != static_cast<uint8_t>('q')) all_q = false;
  }
  CHECK(all_q);
  output.clear();
  const std::vector<uint8_t> second = {0xE0, 0x26, 0x88, 0x7F, 0xE8,
                                       0xF4, 0x02};
  CHECK_EQ(decompressor.Decompress(second, &output), static_cast<size_t>(1597));
  all_q = true;
  for (size_t i = 0; i < output.size(); ++i) {
    if (output[i] != static_cast<uint8_t>('q')) all_q = false;
  }
  CHECK(all_q);
}

RTSC_TEST(bulk_compressed_trailer_beyond_bitstream_rejected) {
  // Trailer claims 7 unused bits but the segment carries no whole byte.
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  const std::vector<uint8_t> input = {0xE0, 0x26, 0x07};
  CHECK_EQ(decompressor.Decompress(input, &output), static_cast<size_t>(0));
}

RTSC_TEST(bulk_compressed_unknown_type_rejected) {
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  const std::vector<uint8_t> input = {0xE0, 0x21, 0b11001000, 0x03};
  CHECK_EQ(decompressor.Decompress(input, &output), static_cast<size_t>(0));
}


RTSC_TEST(bulk_multipart_rejected) {
  // MULTIPART (0xE1), not supported for RDP 8.0 Lite.
  const std::vector<uint8_t> input = {0xE1, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x06, 'a', 'b'};
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  size_t written = decompressor.Decompress(input, &output);
  CHECK_EQ(written, static_cast<size_t>(0));
}

RTSC_TEST(bulk_unknown_descriptor_rejected) {
  // Unknown descriptor (0x00), not supported.
  const std::vector<uint8_t> input = {0x00};
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  size_t written = decompressor.Decompress(input, &output);
  CHECK_EQ(written, static_cast<size_t>(0));
}

RTSC_TEST(bulk_uncompressed_segment_exceeds_limit_rejected) {
  // SINGLE (0xE0), uncompressed, but data size > kMaxSegmentSize (65535).
  std::vector<uint8_t> input(65536 + 2, 0);  // 65536 data bytes + 2-byte header
  input[0] = 0xE0;
  input[1] = 0x06;
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  size_t written = decompressor.Decompress(input, &output);
  CHECK_EQ(written, static_cast<size_t>(0));
}
RTSC_TEST(bulk_malformed_inputs_never_crash) {
  // Deterministic sweep over short inputs: every call must return a count that
  // matches the bytes actually appended and must never read out of bounds.
  uint32_t state = 0x12345678u;
  for (size_t length = 0; length <= 32; ++length) {
    for (int iteration = 0; iteration < 16; ++iteration) {
      std::vector<uint8_t> input(length);
      for (size_t i = 0; i < length; ++i) {
        state = state * 1103515245u + 12345u;
        input[i] = static_cast<uint8_t>(state >> 16);
      }
      rtsc::proto::BulkDecompressor decompressor;
      std::vector<uint8_t> output;
      const size_t written = decompressor.Decompress(input, &output);
      CHECK(written == output.size());
      CHECK(written <= rtsc::proto::BulkDecompressor::kMaxSegmentSize);
    }
  }
}

RTSC_TEST(bulk_match_distance_beyond_history_rejected) {
  // Literal 'A', then a match whose distance exceeds the 8,192-byte history.
  rtsc::proto::BulkDecompressor decompressor;
  std::vector<uint8_t> output;
  // 10111110 01100100 0001 : 22-bit distance 100000 (32768+?) base 4,511,392
  // is far beyond the Lite history, so the segment must be rejected.
  const std::vector<uint8_t> input = {0xE0, 0x26, 0b10111110, 0b01100100,
                                      0b00010000, 0x04};
  CHECK_EQ(decompressor.Decompress(input, &output), static_cast<size_t>(0));
}
int main() { return ::rtsc::test::run_all("rtsc_bulk_tests"); }
