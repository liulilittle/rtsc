// RDP secondary drawing orders: SECONDARY_DRAWING_ORDER_HEADER and Cache Brush
// ([MS-RDPEGDI] 2.2.2.2.1.2.1 / 2.2.2.2.1.2.7).

#include "rtsc/proto/secondary.h"

namespace rtsc::proto {

uint8_t BrushBytesPerPixel(uint8_t format) {
    switch (format) {
        case kBMF8BPP: return 1;
        case kBMF16BPP: return 2;
        case kBMF24BPP: return 3;
        case kBMF32BPP: return 4;
        default: return 0;
    }
}

Status ClassifyBrushForm(uint8_t format, uint16_t bytes, BrushForm& out) {
    out = BrushForm::kMono;
    // BMF_1BPP is the monochrome brush: 8 rows of one bit each.
    if (format == kBMF1BPP) {
        if (bytes != 8) return Status::InvalidField;
        out = BrushForm::kMono;
        return Status::Ok;
    }
    const uint8_t bpp = BrushBytesPerPixel(format);
    if (bpp == 0) return Status::InvalidField;  // unknown color depth
    // COMPRESSED_COLOR_BRUSH: 16 bytes of 2-bit pixel indices + 4 colors.
    if (bytes == 16 + 4 * bpp) {
        out = BrushForm::kCompressed4;
        return Status::Ok;
    }
    // More than 4 colors: one packed color per pixel, uncompressed.
    if (bytes == 64 * bpp) {
        out = BrushForm::kUncompressed;
        return Status::Ok;
    }
    return Status::InvalidField;  // matches no defined form
}

Status ParseSecondaryOrderHeader(const uint8_t* data, size_t size,
                                 SecondaryOrderHeader& out, size_t& consumed) {
    consumed = 0;
    out = SecondaryOrderHeader{};
    if (data == nullptr || size < 1) return Status::NeedMoreData;
    out.control_flags = data[0];
    // A secondary order sets both TS_STANDARD and TS_SECONDARY. A primary-only
    // (0x01) or alternate-secondary-only (0x02) control byte is a different
    // header and is rejected here, before the length is considered, so a real
    // ALTSEC control byte is recognised and refused rather than read as a
    // secondary order.
    if ((out.control_flags & (TS_STANDARD | TS_SECONDARY)) !=
        (TS_STANDARD | TS_SECONDARY)) {
        return Status::InvalidField;
    }
    if (size < 6) return Status::NeedMoreData;
    out.order_length = static_cast<int16_t>(
        static_cast<uint16_t>(data[1]) | (static_cast<uint16_t>(data[2]) << 8));
    out.extra_flags = static_cast<uint16_t>(data[3]) |
                      (static_cast<uint16_t>(data[4]) << 8);
    out.order_type = data[5];
    // [MS-RDPEGDI] 2.2.2.2.1.2.1: the encoded length is 13 less than the actual
    // length, so the adjusted length must at least cover this 6-byte header.
    if (static_cast<int>(out.order_length) + 13 < 6) return Status::InvalidField;
    consumed = 6;
    return Status::Ok;
}

Status ParseCacheBrushOrder(const uint8_t* data, size_t size,
                            CacheBrushOrder& out, size_t& consumed) {
    consumed = 0;
    out = CacheBrushOrder{};
    if (data == nullptr || size < 6) return Status::NeedMoreData;
    out.cache_entry = data[0];
    out.bitmap_format = data[1];
    out.cx = data[2];
    out.cy = data[3];
    out.style = data[4];
    out.bytes = data[5];
    // cacheEntry MUST be 0..63 ([MS-RDPEGDI] 2.2.2.2.1.2.7).
    if (out.cache_entry > 63) return Status::InvalidField;
    // Only an 8x8 brush is defined.
    if (out.cx != 8 || out.cy != 8) return Status::InvalidField;
    // iBytes must match the available brushData length exactly.
    const size_t avail = size - 6;
    if (avail != out.bytes) return Status::InvalidField;
    out.brush_data.assign(data + 6, data + 6 + out.bytes);
    // Fail-closed: (iBitmapFormat, iBytes) must name a defined brush form
    // ([MS-RDPEGDI] 2.2.2.2.1.2.7.1).
    BrushForm form;
    if (ClassifyBrushForm(out.bitmap_format, static_cast<uint16_t>(out.bytes),
                          form) != Status::Ok) {
        return Status::InvalidField;
    }
    consumed = 6 + out.bytes;
    return Status::Ok;
}

}  // namespace rtsc::proto
