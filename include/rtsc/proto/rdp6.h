// RDP 6.0 bitmap compression framing ([MS-RDPEGDI] 2.2.2.5).
//
// Reference: [MS-RDPEGDI] 2.2.2.5.1 (RDP6_BITMAP_STREAM format header) and
// 2.2.2.5.1.2 (RDP6_RLE_SEGMENT).
//
// RDP6_BITMAP_STREAM = FormatHeader(1) + AlphaPlane? + Luma/RedPlane +
// Orange/GreenPlane + Green/BluePlane + Pad?. Each plane is either raw bytes or
// an RDP6_RLE_SEGMENTS stream decoded row by row (the plane's segments never
// cross a scanline). This module decodes the format header and the RLE planes;
// the plane assembly and the AYCoCg -> ARGB transform sit on top.

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

// Decodes an RDP6_BITMAP_STREAM into an RGBA bitmap. Only the ARGB color space
// (CLL == 0) is supported here: four 8-bit planes (alpha optional), each either
// raw or RLE. AYCoCg (CLL > 0) is transformed on top; the RLE planes use the
// per-scanline state machine of [MS-RDPEGDI] 2.2.2.5.1.2 / FreeRDP planar.c
// (row 0 absolute; rows >= 1 signed deltas against the row above; the running
// pixel resets to 0 per row and runs repeat it).
Status DecodeRdp6Bitmap(const uint8_t* data, size_t size, uint16_t width,
                        uint16_t height, DecodedBitmap& out);

}  // namespace rtsc::proto
