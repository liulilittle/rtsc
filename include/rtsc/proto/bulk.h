// RDP 8.0 bulk decompressor ([MS-RDPEGFX] 3.1.9.1 / [MS-RDPEDYC] 2.2.3.3).
// Decodes the RDP 8.0 Lite flavour carried by DYNVC_DATA_FIRST_COMPRESSED and
// DYNVC_DATA_COMPRESSED: SINGLE descriptor (0xE0), compression type 0x06, an
// 8,192-byte history and an 8,192-byte per-segment ceiling.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace rtsc::proto {

class BulkDecompressor {
 public:
  BulkDecompressor();

  // Decompresses one RDP 8.0 Lite RDP_SEGMENTED_DATA structure, appending the
  // result to `output`. Returns the number of bytes appended, or 0 when the
  // input is malformed or uses an unsupported descriptor/compression type.
  size_t Decompress(const std::vector<uint8_t>& input,
                    std::vector<uint8_t>* output);

  // Maximum uncompressed bytes in a single RDP 8.0 Lite segment
  // ([MS-RDPEDYC] 2.2.3.3 / [MS-RDPEGFX] 3.1.9.1).
  static constexpr size_t kMaxSegmentSize = 8192;
  // RDP 8.0 Lite history window, which bounds the maximum match distance.
  static constexpr size_t kHistorySize = 8192;

 private:
  void AppendRaw(const std::vector<uint8_t>& input, size_t offset,
                 size_t count, std::vector<uint8_t>* output);
  void PushLiteral(uint8_t value, std::vector<uint8_t>* output);
  void CopyMatch(uint32_t distance, size_t length,
                 std::vector<uint8_t>* output);

  std::vector<uint8_t> history_;
  size_t position_ = 0;
};

}  // namespace rtsc::proto
