// Secondary drawing order parsing: SECONDARY_DRAWING_ORDER_HEADER and
// CACHE_BRUSH_ORDER ([MS-RDPEGDI] 2.2.2.2.1.2.1 / 2.2.2.2.1.2.7).
//
// The length facts are checked against the official annotated dumps recorded in
// docs/spec/orders-cache.md (orderLength 0x37 -> actual 68; the Cache Brush dump
// 00 01 08 08 81 08 aa55...).

#include "rtsc/proto/secondary.h"

#include <cstdint>

#include "test_framework.h"

using namespace rtsc::proto;

namespace {

// The official Cache Bitmap Rev3 dump header: 03 37 00 30 0c 08.
//   controlFlags 0x03, orderLength 0x37 (=55), extraFlags 0x0c30, orderType 0x08.
const uint8_t kOfficialHeader[] = {0x03, 0x37, 0x00, 0x30, 0x0c, 0x08};

// The official Cache Brush dump body: 00 01 08 08 81 08 aa 55 aa 55 aa 55 aa 55.
const uint8_t kOfficialBrush[] = {0x00, 0x01, 0x08, 0x08, 0x81, 0x08,
                                 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
                                 0xaa, 0x55};

}  // namespace

RTSC_TEST(secondary_header_length_plus_13) {
    SecondaryOrderHeader h;
    size_t used = 0;
    CHECK(ParseSecondaryOrderHeader(kOfficialHeader, sizeof(kOfficialHeader), h,
                                    used) == Status::Ok);
    CHECK_EQ(used, static_cast<size_t>(6));
    CHECK_EQ(h.control_flags, static_cast<uint8_t>(0x03));
    CHECK_EQ(h.order_length, static_cast<int16_t>(0x37));
    CHECK_EQ(h.extra_flags, static_cast<uint16_t>(0x0c30));
    CHECK_EQ(h.order_type, static_cast<uint8_t>(0x08));
    // The spec: actual = orderLength + 13.
    CHECK_EQ(static_cast<size_t>(h.order_length) + 13, static_cast<size_t>(68));
}

RTSC_TEST(secondary_header_rejects_primary_only) {
    const uint8_t b[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    SecondaryOrderHeader h;
    size_t used = 0;
    CHECK(ParseSecondaryOrderHeader(b, sizeof(b), h, used) == Status::InvalidField);
}

RTSC_TEST(secondary_header_rejects_alternate_only) {
    // A real alternate secondary order: controlFlags 0x02 is the 1-byte ALTSEC
    // header, followed by the order data. The ALTSEC header is not modelled, so
    // it is rejected regardless of how many bytes follow.
    const uint8_t b[] = {0x02, 0x01, 0x02, 0x03};
    SecondaryOrderHeader h;
    size_t used = 0;
    CHECK(ParseSecondaryOrderHeader(b, sizeof(b), h, used) == Status::InvalidField);
}

RTSC_TEST(secondary_header_alternate_single_byte_rejected) {
    // A lone ALTSEC control byte at the end of the buffer is still recognised and
    // refused: the flag check precedes the length check.
    const uint8_t b[] = {0x02};
    SecondaryOrderHeader h;
    size_t used = 0;
    CHECK(ParseSecondaryOrderHeader(b, sizeof(b), h, used) == Status::InvalidField);
}

RTSC_TEST(secondary_header_needs_more_data) {
    const uint8_t b[] = {0x03, 0x00};
    SecondaryOrderHeader h;
    size_t used = 0;
    CHECK(ParseSecondaryOrderHeader(b, sizeof(b), h, used) == Status::NeedMoreData);
}

RTSC_TEST(secondary_header_rejects_short_adjusted_length) {
    // orderLength = -7 -> actual = 6; one less (-8 -> 5) is invalid.
    const uint8_t b[] = {0x03, 0xF8, 0xFF, 0x00, 0x00, 0x00};
    SecondaryOrderHeader h;
    size_t used = 0;
    CHECK(ParseSecondaryOrderHeader(b, sizeof(b), h, used) == Status::InvalidField);
}

RTSC_TEST(cache_brush_parse_official_dump) {
    CacheBrushOrder o;
    size_t used = 0;
    CHECK(ParseCacheBrushOrder(kOfficialBrush, sizeof(kOfficialBrush), o, used) ==
          Status::Ok);
    CHECK_EQ(used, sizeof(kOfficialBrush));
    CHECK_EQ(o.cache_entry, static_cast<uint8_t>(0x00));
    CHECK_EQ(o.bitmap_format, static_cast<uint8_t>(kBMF1BPP));
    CHECK_EQ(o.cx, static_cast<uint8_t>(8));
    CHECK_EQ(o.cy, static_cast<uint8_t>(8));
    CHECK_EQ(o.style, static_cast<uint8_t>(0x81));
    CHECK_EQ(o.bytes, static_cast<uint8_t>(8));
    CHECK_EQ(o.brush_data.size(), static_cast<size_t>(8));
    CHECK_EQ(o.brush_data[0], static_cast<uint8_t>(0xaa));
    CHECK_EQ(o.brush_data[7], static_cast<uint8_t>(0x55));
}

RTSC_TEST(cache_brush_rejects_non_8x8) {
    // cx = 4 is not an 8x8 brush.
    const uint8_t b[] = {0x00, 0x01, 0x04, 0x08, 0x81, 0x08,
                         0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55};
    CacheBrushOrder o;
    size_t used = 0;
    CHECK(ParseCacheBrushOrder(b, sizeof(b), o, used) == Status::InvalidField);
}

RTSC_TEST(cache_brush_rejects_bytes_mismatch) {
    // iBytes declares 4 but 8 bytes are present.
    const uint8_t b[] = {0x00, 0x01, 0x08, 0x08, 0x81, 0x04,
                         0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55};
    CacheBrushOrder o;
    size_t used = 0;
    CHECK(ParseCacheBrushOrder(b, sizeof(b), o, used) == Status::InvalidField);
}

RTSC_TEST(cache_brush_rejects_entry_out_of_range) {
    // cacheEntry MUST be 0..63.
    const uint8_t b[] = {0x40, 0x01, 0x08, 0x08, 0x81, 0x08,
                         0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55};
    CacheBrushOrder o;
    size_t used = 0;
    CHECK(ParseCacheBrushOrder(b, sizeof(b), o, used) == Status::InvalidField);
}

RTSC_TEST(alternate_secondary_order_flag) {
    CHECK(IsAlternateSecondaryOrder(0x02));  // only TS_SECONDARY
    CHECK(!IsAlternateSecondaryOrder(0x01));  // primary
    CHECK(!IsAlternateSecondaryOrder(0x03));  // secondary
    CHECK(!IsAlternateSecondaryOrder(0x00));
    CHECK(IsAlternateSecondaryOrder(0x82));  // TS_SECONDARY | orderType bits
}

RTSC_TEST(cache_brush_needs_more_data) {
    const uint8_t b[] = {0x00, 0x01, 0x08, 0x08, 0x81, 0x20, 0xaa, 0x55};
    CacheBrushOrder o;
    size_t used = 0;
    CHECK(ParseCacheBrushOrder(b, sizeof(b), o, used) == Status::InvalidField);
}

// ---------------------------------------------------------------------------
// Brush form classification ([MS-RDPEGDI] 2.2.2.2.1.2.7 / 2.2.2.2.1.2.7.1)
// ---------------------------------------------------------------------------

RTSC_TEST(brush_bytes_per_pixel_map) {
    CHECK_EQ(BrushBytesPerPixel(kBMF8BPP), static_cast<uint8_t>(1));
    CHECK_EQ(BrushBytesPerPixel(kBMF16BPP), static_cast<uint8_t>(2));
    CHECK_EQ(BrushBytesPerPixel(kBMF24BPP), static_cast<uint8_t>(3));
    CHECK_EQ(BrushBytesPerPixel(kBMF32BPP), static_cast<uint8_t>(4));
    // BMF_1BPP is monochrome, not a byte-packed color depth.
    CHECK_EQ(BrushBytesPerPixel(kBMF1BPP), static_cast<uint8_t>(0));
    CHECK_EQ(BrushBytesPerPixel(0x00), static_cast<uint8_t>(0));
    CHECK_EQ(BrushBytesPerPixel(0xFF), static_cast<uint8_t>(0));
}

RTSC_TEST(classify_brush_form_mono) {
    BrushForm f = BrushForm::kUncompressed;
    CHECK(ClassifyBrushForm(kBMF1BPP, 8, f) == Status::Ok);
    CHECK(f == BrushForm::kMono);
    // A monochrome brush that is not exactly 8 bytes is invalid.
    CHECK(ClassifyBrushForm(kBMF1BPP, 7, f) == Status::InvalidField);
    CHECK(ClassifyBrushForm(kBMF1BPP, 9, f) == Status::InvalidField);
}

RTSC_TEST(classify_brush_form_compressed4) {
    BrushForm f = BrushForm::kMono;
    // 8BPP:  16 + 4*1 = 20
    CHECK(ClassifyBrushForm(kBMF8BPP, 20, f) == Status::Ok);
    CHECK(f == BrushForm::kCompressed4);
    // 16BPP: 16 + 4*2 = 24
    CHECK(ClassifyBrushForm(kBMF16BPP, 24, f) == Status::Ok);
    CHECK(f == BrushForm::kCompressed4);
    // 24BPP: 16 + 4*3 = 28
    CHECK(ClassifyBrushForm(kBMF24BPP, 28, f) == Status::Ok);
    CHECK(f == BrushForm::kCompressed4);
    // 32BPP: 16 + 4*4 = 32
    CHECK(ClassifyBrushForm(kBMF32BPP, 32, f) == Status::Ok);
    CHECK(f == BrushForm::kCompressed4);
}

RTSC_TEST(classify_brush_form_uncompressed) {
    BrushForm f = BrushForm::kMono;
    // 8BPP:  64*1 = 64
    CHECK(ClassifyBrushForm(kBMF8BPP, 64, f) == Status::Ok);
    CHECK(f == BrushForm::kUncompressed);
    // 16BPP: 64*2 = 128
    CHECK(ClassifyBrushForm(kBMF16BPP, 128, f) == Status::Ok);
    CHECK(f == BrushForm::kUncompressed);
    // 24BPP: 64*3 = 192
    CHECK(ClassifyBrushForm(kBMF24BPP, 192, f) == Status::Ok);
    CHECK(f == BrushForm::kUncompressed);
    // 32BPP: 64*4 = 256
    CHECK(ClassifyBrushForm(kBMF32BPP, 256, f) == Status::Ok);
    CHECK(f == BrushForm::kUncompressed);
}

RTSC_TEST(classify_brush_form_fail_closed) {
    BrushForm f = BrushForm::kMono;
    // Unknown color depths.
    CHECK(ClassifyBrushForm(0x00, 8, f) == Status::InvalidField);
    CHECK(ClassifyBrushForm(0x02, 8, f) == Status::InvalidField);
    CHECK(ClassifyBrushForm(0x07, 8, f) == Status::InvalidField);
    // 24BPP iBytes that matches neither 28 nor 192.
    CHECK(ClassifyBrushForm(kBMF24BPP, 27, f) == Status::InvalidField);
    CHECK(ClassifyBrushForm(kBMF24BPP, 29, f) == Status::InvalidField);
    CHECK(ClassifyBrushForm(kBMF24BPP, 100, f) == Status::InvalidField);
    CHECK(ClassifyBrushForm(kBMF24BPP, 191, f) == Status::InvalidField);
}

// Hand-computed COMPRESSED_COLOR_BRUSH: 24BPP, iBytes = 16 + 4*3 = 28. The 16
// index bytes are all zero (P1..P64 -> color1) and the four colors follow.
RTSC_TEST(cache_brush_parse_compressed_color_24bpp) {
    const uint8_t b[] = {
        0x00, 0x05, 0x08, 0x08, 0x81, 0x1C,  // header, iBytes = 28
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // P1..P64 = 0
        0x11, 0x22, 0x33,  // color1
        0x44, 0x55, 0x66,  // color2
        0x77, 0x88, 0x99,  // color3
        0xAA, 0xBB, 0xCC,  // color4
    };
    CacheBrushOrder o;
    size_t used = 0;
    CHECK(ParseCacheBrushOrder(b, sizeof(b), o, used) == Status::Ok);
    CHECK_EQ(used, sizeof(b));
    CHECK_EQ(o.bitmap_format, static_cast<uint8_t>(kBMF24BPP));
    CHECK_EQ(o.bytes, static_cast<uint8_t>(28));
    CHECK_EQ(o.brush_data.size(), static_cast<size_t>(28));
}

RTSC_TEST(cache_brush_parse_uncompressed_24bpp) {
    // iBytes = 64*3 = 192.
    std::vector<uint8_t> b(6 + 192, 0x00);
    b[0] = 0x00;
    b[1] = kBMF24BPP;
    b[2] = 8;
    b[3] = 8;
    b[4] = 0x81;
    b[5] = 192;
    CacheBrushOrder o;
    size_t used = 0;
    CHECK(ParseCacheBrushOrder(b.data(), b.size(), o, used) == Status::Ok);
    CHECK_EQ(used, static_cast<size_t>(198));
    CHECK_EQ(o.bytes, static_cast<uint8_t>(192));
}

RTSC_TEST(cache_brush_rejects_unknown_form) {
    // 24BPP with iBytes = 100 matches neither the compressed (28) nor the
    // uncompressed (192) encoding: fail closed.
    std::vector<uint8_t> b(6 + 100, 0x00);
    b[0] = 0x00;
    b[1] = kBMF24BPP;
    b[2] = 8;
    b[3] = 8;
    b[4] = 0x81;
    b[5] = 100;
    CacheBrushOrder o;
    size_t used = 0;
    CHECK(ParseCacheBrushOrder(b.data(), b.size(), o, used) ==
          Status::InvalidField);
}
