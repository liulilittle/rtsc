// NSCodec compressed bitmap stream ([MS-RDPNSC] 2.2.2 / 3.1.8).
//
// The stream starts with a 20-byte header: four plane byte counts (Y, Co, Cg,
// A), the color loss level, the chroma subsampling level, and two reserved
// bytes. Each plane is then either raw (when its byte count equals the plane
// size), RLE-compressed, or absent (byte count 0 -> filled with 0xFF).
//
// Cross-checked against FreeRDP libfreerdp/codec/nsc.c (nsc_stream_initialize,
// nsc_rle_decode, nsc_decode).

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/bitmap.h"

namespace rtsc::proto {

// NSCodec bitmap stream header ([MS-RDPNSC] 2.2.2), 20 bytes.
struct NscHeader {
    static constexpr size_t kSize = 20;

    // Plane byte counts, in stream order: Y, Co, Cg, A.
    uint32_t plane_byte_count[4] = {0, 0, 0, 0};
    uint8_t color_loss_level = 0;         // 1..7
    uint8_t chroma_subsampling_level = 0; // 0 or 1

    static Status parse(const uint8_t* data, size_t size, NscHeader& out);
};

// NSCodec RLE decode ([MS-RDPNSC] 3.1.8.2). Expands the RLE data into exactly
// `original_size` bytes. `out_size` is the capacity of `out`.
Status NscRleDecode(const uint8_t* data, size_t size, uint8_t* out,
                    size_t out_size, size_t original_size);

// Decodes a complete NSCodec bitmap stream into an RGBA bitmap.
Status NscDecodeBitmap(const uint8_t* data, size_t size, uint16_t width,
                       uint16_t height, DecodedBitmap& out);

}  // namespace rtsc::proto
