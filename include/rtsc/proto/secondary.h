// RDP secondary drawing orders: the SECONDARY_DRAWING_ORDER_HEADER framing and
// the Cache Brush order ([MS-RDPEGDI] 2.2.2.2.1.2.1 and 2.2.2.2.1.2.7).
//
// Primary orders carry their length implicitly (the fieldFlags tell the decoder
// how many bytes follow), so a primary order cannot be skipped without decoding
// it. Secondary orders instead carry an explicit length, which makes them
// skippable -- and the Cache Brush order is what populates the brush cache that
// a later PatBlt references through TS_CACHED_BRUSH.
//
// This module is pure parsing: it lives in rtsc_proto and has no UI dependency.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/orders.h"

namespace rtsc::proto {

// Secondary drawing order types ([MS-RDPEGDI] 2.2.2.2.1.2.1).
enum SecondaryOrderType : uint8_t {
    kCacheBitmapUncompressed = 0x00,
    kCacheColorTable = 0x01,
    kCacheBitmapCompressed = 0x02,
    kCacheGlyph = 0x03,
    kCacheBitmapUncompressedRev2 = 0x04,
    kCacheBitmapCompressedRev2 = 0x05,
    kCacheBrushOrder = 0x07,  // TS_CACHE_BRUSH
    kCacheBitmapCompressedRev3 = 0x08,
};

// CACHE_BRUSH_ORDER.iBitmapFormat ([MS-RDPEGDI] 2.2.2.2.1.2.7).
enum BrushBitmapFormat : uint8_t {
    kBMF1BPP = 0x01,
    kBMF8BPP = 0x03,
    kBMF16BPP = 0x04,
    kBMF24BPP = 0x05,
    kBMF32BPP = 0x06,
};

// SECONDARY_DRAWING_ORDER_HEADER ([MS-RDPEGDI] 2.2.2.2.1.2.1.1):
//   controlFlags(1B) + orderLength(2B LE, signed) + extraFlags(2B LE) +
//   orderType(1B) + orderData.
//
// `order_length` is 13 less than the actual order length, so the caller derives
// actual = order_length + 13 ([MS-RDPEGDI] 2.2.2.2.1.2.1: "the orderLength field
// MUST be adjusted by adding 13 bytes").
struct SecondaryOrderHeader {
    uint8_t control_flags = 0;
    int16_t order_length = 0;
    uint16_t extra_flags = 0;
    uint8_t order_type = 0;
};

// True when `control_flags` identifies an alternate secondary order: only
// TS_SECONDARY is set, without TS_STANDARD. Its header is a single byte with no
// length field ([MS-RDPEGDI] 2.2.2.2.1.3.1.1; see docs/spec/orders-cache.md), so
// it cannot be skipped without decoding it -- callers must fail closed rather
// than guess a length.
inline bool IsAlternateSecondaryOrder(uint8_t control_flags) {
    return (control_flags & (TS_STANDARD | TS_SECONDARY)) == TS_SECONDARY;
}

// Parses a SECONDARY_DRAWING_ORDER_HEADER. `consumed` is 6 (the header bytes).
// Fail-closed: requires the TS_STANDARD|TS_SECONDARY flag combination (a
// primary-only or alternate-secondary-only control byte is rejected) and an
// order_length whose adjusted length is at least the 6-byte header; NeedMoreData
// when fewer than 6 bytes are available. `actual_length` is left to the caller
// (order_length + 13).
Status ParseSecondaryOrderHeader(const uint8_t* data, size_t size,
                                 SecondaryOrderHeader& out, size_t& consumed);

// The decoded form of CACHE_BRUSH_ORDER.brushData ([MS-RDPEGDI]
// 2.2.2.2.1.2.7 / 2.2.2.2.1.2.7.1). The wire carries three possible encodings
// of the same 8x8 brush bitmap; the form decides how brushData is expanded.
enum class BrushForm : uint8_t {
    kMono,         // BMF_1BPP: 8 bytes, one bit per pixel (bit 0 = foreground)
    kCompressed4,  // COMPRESSED_COLOR_BRUSH: 16 bytes of 2-bit indices
                   // (P1..P64) followed by 4 packed colors
    kUncompressed, // >4 colors: 64 * bytes_per_pixel, one packed color per pixel
};

// Maps CACHE_BRUSH_ORDER.iBitmapFormat to bytes per pixel. Returns 0 for a
// format that is not a defined color depth so callers fail closed.
uint8_t BrushBytesPerPixel(uint8_t format);

// Classifies the brush form from iBitmapFormat and iBytes. `bytes` is a
// 16-bit quantity so the uncompressed 32BPP form (64*4 = 256) can be
// classified even though the wire iBytes field is one byte (so that form is
// unreachable from a parsed order). Fail-closed: a BMF_1BPP brush must be 8
// bytes; otherwise bytes must equal 16 + 4 * bpp_bytes (4-color compressed) or
// 64 * bpp_bytes (uncompressed), and an unknown format or a bytes matching
// neither returns InvalidField.
Status ClassifyBrushForm(uint8_t format, uint16_t bytes, BrushForm& out);

// CACHE_BRUSH_ORDER ([MS-RDPEGDI] 2.2.2.2.1.2.7):
//   cacheEntry(1B) + iBitmapFormat(1B) + cx(1B) + cy(1B) + Style(1B) +
//   iBytes(1B) + brushData(iBytes).
struct CacheBrushOrder {
    uint8_t cache_entry = 0;
    uint8_t bitmap_format = 0;
    uint8_t cx = 0;
    uint8_t cy = 0;
    uint8_t style = 0;
    uint8_t bytes = 0;
    std::vector<uint8_t> brush_data;
};

// Parses a CACHE_BRUSH_ORDER body (everything after the 6-byte secondary order
// header). `consumed` is 6 + iBytes. Fail-closed: cacheEntry must be 0..63
// ([MS-RDPEGDI] 2.2.2.2.1.2.7), cx/cy must be 8 (only an 8x8 brush is defined),
// the declared iBytes must match the available data, and the (iBitmapFormat,
// iBytes) pair must name a defined brush form (see ClassifyBrushForm).
Status ParseCacheBrushOrder(const uint8_t* data, size_t size,
                            CacheBrushOrder& out, size_t& consumed);

}  // namespace rtsc::proto
