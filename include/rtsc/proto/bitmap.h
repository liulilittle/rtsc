// Bitmap decoding for update payloads ([MS-RDPBCGR] 2.2.9.1.1.3.1.2).
//
// Reference: docs/spec/share-data.md section 3.9.2; [MS-RDPBCGR] 2.2.9.1.1.3.1.2.3.
//
// This module covers the framing around a bitmap rectangle (the compression
// flags and the optional Compressed Data Header) and the decoding of
// UNCOMPRESSED data. The Interleaved RLE stream (2.2.9.1.1.3.1.2.4) and the
// RDP 6.0 (NSCodec) stream are separate decoders.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// TS_BITMAP_DATA.flags ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.3).
enum BitmapFlag : uint16_t {
    kBitmapCompression = 0x0001,
    kNoBitmapCompressionHdr = 0x0400,
};

// Compressed Data Header ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.2), 8 bytes. Present
// when BITMAP_COMPRESSION is set and NO_BITMAP_COMPRESSION_HDR is not.
struct BitmapCompressedHeader {
    static constexpr size_t kSize = 8;

    uint16_t first_row_size = 0;
    uint16_t main_body_size = 0;
    uint16_t scan_width = 0;
    uint16_t uncompressed_size = 0;

    static Status parse(const uint8_t* data, size_t size,
                        BitmapCompressedHeader& out);
};

// A decoded bitmap: RGBA8888, top-down, row-major, 4 bytes per pixel.
struct DecodedBitmap {
    uint16_t width = 0;
    uint16_t height = 0;
    std::vector<uint8_t> pixels;  // width * height * 4
};

// Decodes an UNCOMPRESSED bitmap rectangle. On the wire the rows are bottom-up
// and each row is padded to a multiple of four bytes; the output is top-down.
//
// Supported bitsPerPixel: 8 (needs `palette`, 256 * 3 RGB bytes), 15 (RGB555),
// 16 (RGB565), 24 (BGR), 32 (BGRA). Returns InvalidField otherwise.
Status DecodeRawBitmap(const uint8_t* data, size_t size, uint16_t width,
                       uint16_t height, uint16_t bits_per_pixel,
                       DecodedBitmap& out,
                       const std::vector<uint8_t>* palette = nullptr);

// Decodes an Interleaved RLE bitmap stream ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.4).
// `data` is the bitmapDataStream (after the Compressed Data Header, if any).
// Supported bitsPerPixel: 8 (needs `palette`), 15, 16, 24. Returns InvalidField
// for 32 bpp (which uses RDP 6.0 compression) or an unknown order.
Status DecodeRleBitmap(const uint8_t* data, size_t size, uint16_t width,
                       uint16_t height, uint16_t bits_per_pixel,
                       DecodedBitmap& out,
                       const std::vector<uint8_t>* palette = nullptr);

}  // namespace rtsc::proto
