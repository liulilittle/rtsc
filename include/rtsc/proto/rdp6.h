// RDP 6.0 bitmap compression framing ([MS-RDPEGDI] 2.2.2.5).
//
// Reference: [MS-RDPEGDI] 2.2.2.5.1 (RDP6_BITMAP_STREAM format header) and
// 2.2.2.5.1.2 (RDP6_RLE_SEGMENT).
//
// RDP6_BITMAP_STREAM = FormatHeader(1) + AlphaPlane? + Luma/RedPlane +
// Orange/GreenPlane + Green/BluePlane + Pad?. Each plane is either raw bytes or
// an RDP6_RLE_SEGMENTS stream. This module decodes the format header and the
// RLE segments; the plane assembly and the AYCoCg -> ARGB transform sit on top.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/bitmap.h"

namespace rtsc::proto {

// RDP6_BITMAP_STREAM.FormatHeader ([MS-RDPEGDI] 2.2.2.5.1).
struct Rdp6FormatHeader {
    // Color Loss Level: 0 -> ARGB, 1..7 -> AYCoCg.
    uint8_t cll = 0;
    bool chroma_subsampling = false;  // CS
    bool rle = false;                 // B
    bool no_alpha = false;            // C: no alpha plane present
    uint8_t reserved = 0;

    static Status parse(uint8_t b, Rdp6FormatHeader& out);
    uint8_t encode() const;
};

// Decodes an RDP6_RLE_SEGMENTS stream into exactly `count` bytes.
// `consumed` receives the number of input bytes used. Returns InvalidField when
// a segment's controlByte is zero or a run has no preceding byte.
Status DecodeRdp6RleSegments(const uint8_t* data, size_t size, size_t count,
                             std::vector<uint8_t>& out, size_t& consumed);

// Decodes an RDP6_BITMAP_STREAM into an RGBA bitmap. Only the ARGB color space
// (CLL == 0) is supported here: four 8-bit planes (alpha optional), each either
// raw or RLE + delta. AYCoCg (CLL > 0) returns InvalidField.
Status DecodeRdp6Bitmap(const uint8_t* data, size_t size, uint16_t width,
                        uint16_t height, DecodedBitmap& out);

}  // namespace rtsc::proto
