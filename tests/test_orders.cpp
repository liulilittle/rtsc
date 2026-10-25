// RDP drawing orders: variable-length encodings and Cache Bitmap Rev2.
//
// The four-byte unsigned encoding ([MS-RDPEGDI] 2.2.2.2.1.2.1.4) stores the
// number of extra bytes in the high 2 bits of the first byte: c = (b0 >> 6),
// so the total byte count is c + 1 (1..4). The low 6 bits of b0 hold the most
// significant bits of the value. These tests pin every branch (c = 0, 1, 2, 3)
// plus the truncation cases and the value boundaries.

#include "rtsc/proto/orders.h"
#include "rtsc/proto/secondary.h"
#include "rtsc/render/orders_apply.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;
using rtsc::render::ApplyDstBlt;
using rtsc::render::ApplyOpaqueRect;
using rtsc::render::ApplyPatBlt;
using rtsc::render::ApplyScrBlt;
using rtsc::render::BrushCacheView;
using rtsc::render::PatBltResult;
using rtsc::ui::Surface;

RTSC_TEST(two_byte_unsigned_short_and_long_forms) {
    uint16_t v = 0;
    size_t used = 0;
    // High bit clear -> 1 byte.
    const std::vector<uint8_t> a = {0x7F};
    CHECK(ReadTwoByteUnsigned(a.data(), a.size(), v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<uint16_t>(0x7F));
    CHECK_EQ(used, static_cast<size_t>(1));

    // High bit set -> 2 bytes, value = (b0 & 0x7F) << 8 | b1.
    const std::vector<uint8_t> b = {0x81, 0x00};
    CHECK(ReadTwoByteUnsigned(b.data(), b.size(), v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<uint16_t>(0x0100));
    CHECK_EQ(used, static_cast<size_t>(2));

    const std::vector<uint8_t> c = {0x81};
    CHECK(ReadTwoByteUnsigned(c.data(), c.size(), v, used) == Status::NeedMoreData);
}

// c = 0 (high 2 bits clear): a single byte, value = b0.
RTSC_TEST(four_byte_unsigned_c0_one_byte) {
    uint32_t v = 0;
    size_t used = 0;
    const std::vector<uint8_t> a = {0x00};
    CHECK(ReadFourByteUnsigned(a.data(), a.size(), v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<uint32_t>(0x00));
    CHECK_EQ(used, static_cast<size_t>(1));

    const std::vector<uint8_t> b = {0x3F};
    CHECK(ReadFourByteUnsigned(b.data(), b.size(), v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<uint32_t>(0x3F));
    CHECK_EQ(used, static_cast<size_t>(1));
}

// c = 1: two bytes, value = (b0 & 0x3F) << 8 | b1.
RTSC_TEST(four_byte_unsigned_c1_two_bytes) {
    uint32_t v = 0;
    size_t used = 0;
    const std::vector<uint8_t> a = {0x40, 0xDC};
    CHECK(ReadFourByteUnsigned(a.data(), a.size(), v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<uint32_t>(0x00DC));
    CHECK_EQ(used, static_cast<size_t>(2));

    const std::vector<uint8_t> b = {0x7F, 0xFF};
    CHECK(ReadFourByteUnsigned(b.data(), b.size(), v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<uint32_t>(0x3FFF));
    CHECK_EQ(used, static_cast<size_t>(2));
}

// c = 2: three bytes, value = (b0 & 0x3F) << 16 | b1 << 8 | b2.
RTSC_TEST(four_byte_unsigned_c2_three_bytes) {
    uint32_t v = 0;
    size_t used = 0;
    const std::vector<uint8_t> a = {0x80, 0x01, 0x02};
    CHECK(ReadFourByteUnsigned(a.data(), a.size(), v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<uint32_t>(0x000102));
    CHECK_EQ(used, static_cast<size_t>(3));

    const std::vector<uint8_t> b = {0x9A, 0x1B, 0x1C};
    CHECK(ReadFourByteUnsigned(b.data(), b.size(), v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<uint32_t>(0x1A1B1C));
    CHECK_EQ(used, static_cast<size_t>(3));

    const std::vector<uint8_t> c = {0xBF, 0xFF, 0xFF};
    CHECK(ReadFourByteUnsigned(c.data(), c.size(), v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<uint32_t>(0x3FFFFF));
    CHECK_EQ(used, static_cast<size_t>(3));
}

// c = 3: four bytes, value = (b0 & 0x3F) << 24 | b1 << 16 | b2 << 8 | b3.
RTSC_TEST(four_byte_unsigned_c3_four_bytes) {
    uint32_t v = 0;
    size_t used = 0;
    const std::vector<uint8_t> a = {0xC0, 0x01, 0x02, 0x03};
    CHECK(ReadFourByteUnsigned(a.data(), a.size(), v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<uint32_t>(0x00010203));
    CHECK_EQ(used, static_cast<size_t>(4));

    const std::vector<uint8_t> b = {0xFF, 0xFF, 0xFF, 0xFF};
    CHECK(ReadFourByteUnsigned(b.data(), b.size(), v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<uint32_t>(0x3FFFFFFF));
    CHECK_EQ(used, static_cast<size_t>(4));
}

// Truncated inputs must report NeedMoreData (the old implementation wrongly
// accepted c = 1 as a single byte and rejected c = 2 outright).
RTSC_TEST(four_byte_unsigned_truncated_is_need_more_data) {
    uint32_t v = 0;
    size_t used = 0;
    const std::vector<uint8_t> a = {0x40};
    CHECK(ReadFourByteUnsigned(a.data(), a.size(), v, used) == Status::NeedMoreData);

    const std::vector<uint8_t> b = {0x80, 0x01};
    CHECK(ReadFourByteUnsigned(b.data(), b.size(), v, used) == Status::NeedMoreData);

    const std::vector<uint8_t> c = {0xC0, 0x01, 0x02};
    CHECK(ReadFourByteUnsigned(c.data(), c.size(), v, used) == Status::NeedMoreData);
}

// Empty / null input.
RTSC_TEST(four_byte_unsigned_empty_is_need_more_data) {
    uint32_t v = 0;
    size_t used = 0;
    CHECK(ReadFourByteUnsigned(nullptr, 0, v, used) == Status::NeedMoreData);
    const std::vector<uint8_t> empty;
    CHECK(ReadFourByteUnsigned(empty.data(), empty.size(), v, used) ==
          Status::NeedMoreData);
}

RTSC_TEST(cache_bitmap_rev2_parses) {
    // extraFlags: cacheId=1, bitsPerPixelId=0x5 (24bpp), flags=0.
    //   extraFlags = 1 | (0x5 << 3) = 0x29.
    const uint16_t extra = 0x29;
    const std::vector<uint8_t> body = {0x0A, 0x14, 0x04, 0x05,
                                       0xAA, 0xBB, 0xCC, 0xDD};

    CacheBitmapRev2Order o;
    CHECK(CacheBitmapRev2Order::parse(extra, body.data(), body.size(), o) == Status::Ok);
    CHECK_EQ(o.cache_id, static_cast<uint8_t>(1));
    CHECK_EQ(o.bits_per_pixel_id, static_cast<uint8_t>(0x5));
    CHECK_EQ(o.bits_per_pixel(), static_cast<uint16_t>(24));
    CHECK_EQ(o.bitmap_width, static_cast<uint16_t>(10));
    CHECK_EQ(o.bitmap_height, static_cast<uint16_t>(20));
    CHECK_EQ(o.bitmap_length, static_cast<uint32_t>(4));
    CHECK_EQ(o.cache_index, static_cast<uint16_t>(5));
    CHECK_EQ(o.bitmap_data.size(), static_cast<size_t>(4));
    CHECK_EQ(o.bitmap_data[0], static_cast<uint8_t>(0xAA));
}

RTSC_TEST(cache_bitmap_rev2_height_same_as_width) {
    // flags = CBR2_HEIGHT_SAME_AS_WIDTH (0x01) -> height field absent.
    const uint16_t extra = static_cast<uint16_t>(0x29 | (0x01 << 7));
    const std::vector<uint8_t> body = {0x0A, 0x00, 0x05};
    CacheBitmapRev2Order o;
    CHECK(CacheBitmapRev2Order::parse(extra, body.data(), body.size(), o) == Status::Ok);
    CHECK_EQ(o.bitmap_width, static_cast<uint16_t>(10));
    CHECK_EQ(o.bitmap_height, static_cast<uint16_t>(10));
    CHECK_EQ(o.bitmap_length, static_cast<uint32_t>(0));
    CHECK_EQ(o.cache_index, static_cast<uint16_t>(5));
}

RTSC_TEST(cache_bitmap_rev2_persistent_key) {
    // flags = CBR2_PERSISTENT_KEY_PRESENT (0x02) -> key1/key2 present.
    const uint16_t extra = static_cast<uint16_t>(0x29 | (0x02 << 7));
    const std::vector<uint8_t> body = {
        0x01, 0x00, 0x00, 0x00,  // key1
        0x02, 0x00, 0x00, 0x00,  // key2
        0x0A, 0x14, 0x00, 0x05};
    CacheBitmapRev2Order o;
    CHECK(CacheBitmapRev2Order::parse(extra, body.data(), body.size(), o) == Status::Ok);
    CHECK_EQ(o.key1, static_cast<uint32_t>(1));
    CHECK_EQ(o.key2, static_cast<uint32_t>(2));
    CHECK_EQ(o.bitmap_width, static_cast<uint16_t>(10));
}

RTSC_TEST(cache_bitmap_rev2_rejects_truncated_data) {
    const uint16_t extra = 0x29;
    // bitmapLength = 4 but no data follows.
    const std::vector<uint8_t> body = {0x0A, 0x14, 0x04, 0x05};
    CacheBitmapRev2Order o;
    CHECK(CacheBitmapRev2Order::parse(extra, body.data(), body.size(), o) ==
          Status::NeedMoreData);
}

// ---------------------------------------------------------------------------
// TS_ORDER_HEADER ([MS-RDPEGDI] 2.2.2.2.1.1.2)
// ---------------------------------------------------------------------------

RTSC_TEST(order_type_field_counts_match_spec) {
    CHECK_EQ(OrderTypeFieldCount(TS_ENC_DSTBLT_ORDER), static_cast<uint8_t>(5));
    CHECK_EQ(OrderTypeFieldCount(TS_ENC_MULTIDSTBLT_ORDER), static_cast<uint8_t>(7));
    CHECK_EQ(OrderTypeFieldCount(TS_ENC_PATBLT_ORDER), static_cast<uint8_t>(12));
    CHECK_EQ(OrderTypeFieldCount(TS_ENC_MEM3BLT_ORDER), static_cast<uint8_t>(16));
    CHECK_EQ(OrderTypeFieldCount(TS_ENC_INDEX_ORDER), static_cast<uint8_t>(22));
    // Unknown types report 0.
    CHECK_EQ(OrderTypeFieldCount(0x03), static_cast<uint8_t>(0));
    CHECK_EQ(OrderTypeFieldCount(0x0C), static_cast<uint8_t>(0));
    CHECK_EQ(OrderTypeFieldCount(0xFF), static_cast<uint8_t>(0));
}

RTSC_TEST(order_header_minimal_patblt) {
    // controlFlags = TS_STANDARD only; no type change -> the initial orderType
    // (PatBlt 0x01) is used. PatBlt has 12 fields -> 2 flag bytes.
    const std::vector<uint8_t> buf = {0x01, 0x03, 0x00};
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK_EQ(h.order_type, static_cast<uint8_t>(TS_ENC_PATBLT_ORDER));
    CHECK_EQ(h.field_flags.size(), static_cast<size_t>(2));
    CHECK_EQ(h.field_flags[0], static_cast<uint8_t>(0x03));
    CHECK_EQ(h.field_flags[1], static_cast<uint8_t>(0x00));
    CHECK_EQ(h.field_flags_bytes, static_cast<size_t>(2));
    CHECK_EQ(used, static_cast<size_t>(3));
    CHECK(!h.has_bounds);
}

RTSC_TEST(order_header_type_change_updates_state) {
    // TS_TYPE_CHANGE -> orderType byte present (MemBlt 0x0D, 9 fields -> 2 bytes).
    const std::vector<uint8_t> buf = {0x09, 0x0D, 0x00, 0x00};
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK_EQ(h.order_type, static_cast<uint8_t>(TS_ENC_MEMBLT_ORDER));
    CHECK_EQ(st.order_type, static_cast<uint8_t>(TS_ENC_MEMBLT_ORDER));
    CHECK_EQ(h.field_flags.size(), static_cast<size_t>(2));
    CHECK_EQ(used, static_cast<size_t>(4));

    // Without TS_TYPE_CHANGE the previous orderType (MemBlt) is reused.
    const std::vector<uint8_t> b2 = {0x01, 0x11, 0x00};
    OrderHeader h2;
    CHECK(ParseOrderHeader(b2.data(), b2.size(), st, h2, used) == Status::Ok);
    CHECK_EQ(h2.order_type, static_cast<uint8_t>(TS_ENC_MEMBLT_ORDER));
    CHECK_EQ(h2.field_flags.size(), static_cast<size_t>(2));
    CHECK_EQ(used, static_cast<size_t>(3));
}

RTSC_TEST(order_header_zero_field_bytes_omitted) {
    // A 9-field order (MemBlt) has 2 flag bytes. The full value is {0x20, 0x00};
    // one trailing zero byte is omitted, so controlFlags carries 0x40 and the
    // wire holds only 0x20.
    const std::vector<uint8_t> buf = {0x01 | 0x08 | 0x40, 0x0D, 0x20};
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK_EQ(h.field_flags.size(), static_cast<size_t>(2));
    CHECK_EQ(h.field_flags[0], static_cast<uint8_t>(0x20));
    CHECK_EQ(h.field_flags[1], static_cast<uint8_t>(0x00));
    CHECK_EQ(h.field_flags_bytes, static_cast<size_t>(1));
    CHECK_EQ(used, static_cast<size_t>(3));
}

// Discriminating test for the fieldFlags width formula ceil((N+1)/8): Mem3Blt
// has 16 fields, so the correct width is ceil(17/8) = 3 bytes, while the wrong
// ceil(16/8) = 2 would accept a 2-byte input.
RTSC_TEST(order_header_mem3blt_field_flags_width) {
    const uint8_t control = static_cast<uint8_t>(0x01 | 0x08);  // STANDARD|TYPE_CHANGE
    const std::vector<uint8_t> three = {control, 0x0E, 0xAA, 0xBB, 0xCC};
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(three.data(), three.size(), st, h, used) == Status::Ok);
    CHECK_EQ(h.order_type, static_cast<uint8_t>(TS_ENC_MEM3BLT_ORDER));
    CHECK_EQ(h.field_flags.size(), static_cast<size_t>(3));
    CHECK_EQ(h.field_flags[0], static_cast<uint8_t>(0xAA));
    CHECK_EQ(h.field_flags[1], static_cast<uint8_t>(0xBB));
    CHECK_EQ(h.field_flags[2], static_cast<uint8_t>(0xCC));
    CHECK_EQ(h.field_flags_bytes, static_cast<size_t>(3));
    CHECK_EQ(used, static_cast<size_t>(5));

    // With only 2 fieldFlags bytes the 3-byte width must demand one more byte.
    const std::vector<uint8_t> two = {control, 0x0E, 0xAA, 0xBB};
    OrderHeader h2;
    used = 0;
    CHECK(ParseOrderHeader(two.data(), two.size(), st, h2, used) ==
          Status::NeedMoreData);
}

RTSC_TEST(order_header_bounds_all_eight_flags) {
    // desc = 0xFF: all four bounds present as 1-byte signed deltas (the delta
    // form wins when both flags are set).
    const std::vector<uint8_t> buf = {0x05, 0x00, 0x00, 0xFF, 1, 2, 3, 4};
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK(h.has_bounds);
    CHECK_EQ(h.bounds_left, 1);
    CHECK_EQ(h.bounds_top, 2);
    CHECK_EQ(h.bounds_right, 3);
    CHECK_EQ(h.bounds_bottom, 4);
    CHECK_EQ(used, static_cast<size_t>(8));
}

RTSC_TEST(order_header_bounds_absolute) {
    // desc = 0x0F (LEFT|TOP|RIGHT|BOTTOM), 2-byte little-endian each.
    const std::vector<uint8_t> buf = {0x05, 0x00, 0x00, 0x0F,
                                      0x01, 0x00,  // left = 1
                                      0x02, 0x00,  // top = 2
                                      0x03, 0x00,  // right = 3
                                      0x04, 0x00};  // bottom = 4
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK_EQ(h.bounds_left, 1);
    CHECK_EQ(h.bounds_top, 2);
    CHECK_EQ(h.bounds_right, 3);
    CHECK_EQ(h.bounds_bottom, 4);
    CHECK_EQ(used, static_cast<size_t>(12));
}

RTSC_TEST(order_header_zero_bounds_deltas_reuses_previous) {
    OrderParserState st;
    st.bounds_left = 10;
    st.bounds_top = 20;
    st.bounds_right = 30;
    st.bounds_bottom = 40;
    // TS_STANDARD | TS_BOUNDS | TS_ZERO_BOUNDS_DELTAS = 0x25.
    const std::vector<uint8_t> buf = {0x25, 0x00, 0x00};
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK(h.has_bounds);
    CHECK_EQ(h.bounds_left, 10);
    CHECK_EQ(h.bounds_top, 20);
    CHECK_EQ(h.bounds_right, 30);
    CHECK_EQ(h.bounds_bottom, 40);
    CHECK_EQ(used, static_cast<size_t>(3));
}

RTSC_TEST(order_header_bounds_delta_accumulates) {
    OrderParserState st;
    st.bounds_left = 100;
    st.bounds_top = 100;
    // desc = DELTA_LEFT | DELTA_TOP = 0x30; deltas +5 and -5.
    const std::vector<uint8_t> buf = {0x05, 0x00, 0x00, 0x30, 0x05, 0xFB};
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK_EQ(h.bounds_left, 105);
    CHECK_EQ(h.bounds_top, 95);
    CHECK_EQ(h.bounds_right, 0);
    CHECK_EQ(h.bounds_bottom, 0);
    // State is updated so the next order continues from here.
    CHECK_EQ(st.bounds_left, 105);
    CHECK_EQ(st.bounds_top, 95);
    CHECK_EQ(used, static_cast<size_t>(6));
}

RTSC_TEST(order_header_truncated_is_need_more_data) {
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    const std::vector<uint8_t> empty;
    CHECK(ParseOrderHeader(empty.data(), empty.size(), st, h, used) ==
          Status::NeedMoreData);
    const std::vector<uint8_t> only_flag = {0x01};
    CHECK(ParseOrderHeader(only_flag.data(), only_flag.size(), st, h, used) ==
          Status::NeedMoreData);
    const std::vector<uint8_t> cut_flags = {0x01, 0x03};  // needs 2 flag bytes
    CHECK(ParseOrderHeader(cut_flags.data(), cut_flags.size(), st, h, used) ==
          Status::NeedMoreData);
    const std::vector<uint8_t> cut_bounds = {0x05, 0x00, 0x00, 0x0F, 0x01};
    CHECK(ParseOrderHeader(cut_bounds.data(), cut_bounds.size(), st, h, used) ==
          Status::NeedMoreData);
}

RTSC_TEST(order_header_unknown_and_secondary_fail_closed) {
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    // TS_STANDARD not set.
    const std::vector<uint8_t> no_std = {0x04, 0x00, 0x00};
    CHECK(ParseOrderHeader(no_std.data(), no_std.size(), st, h, used) ==
          Status::InvalidField);
    // TS_SECONDARY set.
    const std::vector<uint8_t> secondary = {0x03, 0x00, 0x00};
    CHECK(ParseOrderHeader(secondary.data(), secondary.size(), st, h, used) ==
          Status::InvalidField);
    // Unknown order type.
    const std::vector<uint8_t> unknown = {0x09, 0x63, 0x00, 0x00};
    CHECK(ParseOrderHeader(unknown.data(), unknown.size(), st, h, used) ==
          Status::InvalidField);
    // TS_ZERO_BOUNDS_DELTAS without TS_BOUNDS.
    const std::vector<uint8_t> bad_zero = {0x21, 0x00, 0x00};
    CHECK(ParseOrderHeader(bad_zero.data(), bad_zero.size(), st, h, used) ==
          Status::InvalidField);
}

RTSC_TEST(coord_field_absolute_and_delta) {
    int16_t v = 0;
    size_t used = 0;
    // 2-byte little-endian absolute value.
    const std::vector<uint8_t> abs = {0x34, 0x12};
    CHECK(ReadCoordField(abs.data(), abs.size(), false, 0, v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<int16_t>(0x1234));
    CHECK_EQ(used, static_cast<size_t>(2));

    // 1-byte signed delta accumulates onto the previous value.
    const std::vector<uint8_t> d1 = {0x05};
    CHECK(ReadCoordField(d1.data(), d1.size(), true, v, v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<int16_t>(0x1234 + 5));
    CHECK_EQ(used, static_cast<size_t>(1));
    const std::vector<uint8_t> d2 = {0xFB};  // -5
    CHECK(ReadCoordField(d2.data(), d2.size(), true, v, v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<int16_t>(0x1234));

    // Negative absolute value.
    const std::vector<uint8_t> neg = {0xFF, 0xFF};
    CHECK(ReadCoordField(neg.data(), neg.size(), false, 0, v, used) == Status::Ok);
    CHECK_EQ(v, static_cast<int16_t>(-1));
    CHECK_EQ(used, static_cast<size_t>(2));

    // Truncated absolute value.
    const std::vector<uint8_t> cut = {0x01};
    CHECK(ReadCoordField(cut.data(), cut.size(), false, 0, v, used) ==
          Status::NeedMoreData);
}

// ---------------------------------------------------------------------------
// DstBlt / OpaqueRect / ScrBlt ([MS-RDPEGDI] 2.2.2.2.1.1.2)
// ---------------------------------------------------------------------------

// Hand-computed byte stream: controlFlags = TS_STANDARD|TS_TYPE_CHANGE = 0x09,
// orderType = DstBlt 0x00, fieldFlags = 0x1F (all 5 fields), then
// left=1, top=2, width=3, height=4 (2-byte LE) and bRop = 0xCC.
RTSC_TEST(dstblt_parses_hand_computed_bytes) {
    const std::vector<uint8_t> buf = {0x09, 0x00, 0x1F, 0x01, 0x00, 0x02, 0x00,
                                      0x03, 0x00, 0x04, 0x00, 0xCC};
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK_EQ(h.order_type, static_cast<uint8_t>(TS_ENC_DSTBLT_ORDER));
    CHECK_EQ(h.field_flags_bytes, static_cast<size_t>(1));
    CHECK_EQ(used, static_cast<size_t>(3));

    OrderBodyState bs;
    DstBltOrder o;
    size_t body_used = 0;
    CHECK(ParseDstBltBody(h, buf.data() + used, buf.size() - used, bs, o,
                          body_used) == Status::Ok);
    CHECK_EQ(o.n_left, 1);
    CHECK_EQ(o.n_top, 2);
    CHECK_EQ(o.n_width, 3);
    CHECK_EQ(o.n_height, 4);
    CHECK_EQ(o.b_rop, static_cast<uint8_t>(0xCC));
    CHECK_EQ(body_used, static_cast<size_t>(9));
}

RTSC_TEST(dstblt_parses_delta_coordinates) {
    // controlFlags adds TS_DELTA_COORDINATES (0x10) -> 1-byte signed deltas.
    const std::vector<uint8_t> buf = {0x19, 0x00, 0x1F, 0x01, 0x02, 0x03, 0x04,
                                      0xCC};
    OrderParserState st;
    OrderBodyState bs;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    DstBltOrder o;
    size_t bu = 0;
    CHECK(ParseDstBltBody(h, buf.data() + used, buf.size() - used, bs, o, bu) ==
          Status::Ok);
    CHECK_EQ(o.n_left, 1);
    CHECK_EQ(o.n_top, 2);
    CHECK_EQ(o.n_width, 3);
    CHECK_EQ(o.n_height, 4);
    CHECK_EQ(o.b_rop, static_cast<uint8_t>(0xCC));
    CHECK_EQ(bu, static_cast<size_t>(5));

    // A second order with +1 deltas accumulates onto the previous values.
    const std::vector<uint8_t> second = {0x19, 0x00, 0x1F, 0x01, 0x01, 0x01, 0x01,
                                         0xCC};
    OrderHeader h2;
    used = 0;
    CHECK(ParseOrderHeader(second.data(), second.size(), st, h2, used) ==
          Status::Ok);
    DstBltOrder o2;
    bu = 0;
    CHECK(ParseDstBltBody(h2, second.data() + used, second.size() - used, bs, o2,
                          bu) == Status::Ok);
    CHECK_EQ(o2.n_left, 2);
    CHECK_EQ(o2.n_top, 3);
    CHECK_EQ(o2.n_width, 4);
    CHECK_EQ(o2.n_height, 5);
}

// Hand-computed: OpaqueRect 0x0A, fieldFlags = 0x7F, left=5, top=6, width=2,
// height=2, then R=0x11 G=0x22 B=0x33.
RTSC_TEST(opaquerect_parses_hand_computed_bytes) {
    const std::vector<uint8_t> buf = {0x09, 0x0A, 0x7F, 0x05, 0x00, 0x06, 0x00,
                                      0x02, 0x00, 0x02, 0x00, 0x11, 0x22, 0x33};
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK_EQ(h.order_type, static_cast<uint8_t>(TS_ENC_OPAQUERECT_ORDER));
    CHECK_EQ(used, static_cast<size_t>(3));

    OrderBodyState bs;
    OpaqueRectOrder o;
    size_t body_used = 0;
    CHECK(ParseOpaqueRectBody(h, buf.data() + used, buf.size() - used, bs, o,
                              body_used) == Status::Ok);
    CHECK_EQ(o.n_left, 5);
    CHECK_EQ(o.n_top, 6);
    CHECK_EQ(o.n_width, 2);
    CHECK_EQ(o.n_height, 2);
    CHECK_EQ(o.red, static_cast<uint8_t>(0x11));
    CHECK_EQ(o.green, static_cast<uint8_t>(0x22));
    CHECK_EQ(o.blue, static_cast<uint8_t>(0x33));
    CHECK_EQ(body_used, static_cast<size_t>(11));
}

// Hand-computed: ScrBlt 0x02, fieldFlags = 0x7F, left=0, top=0, width=4,
// height=4, bRop=0xCC, nXSrc=2, nYSrc=3.
RTSC_TEST(scrblt_parses_hand_computed_bytes) {
    const std::vector<uint8_t> buf = {0x09, 0x02, 0x7F, 0x00, 0x00, 0x00, 0x00,
                                      0x04, 0x00, 0x04, 0x00, 0xCC, 0x02, 0x00,
                                      0x03, 0x00};
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK_EQ(h.order_type, static_cast<uint8_t>(TS_ENC_SCRBLT_ORDER));
    CHECK_EQ(used, static_cast<size_t>(3));

    OrderBodyState bs;
    ScrBltOrder o;
    size_t body_used = 0;
    CHECK(ParseScrBltBody(h, buf.data() + used, buf.size() - used, bs, o,
                          body_used) == Status::Ok);
    CHECK_EQ(o.n_left, 0);
    CHECK_EQ(o.n_top, 0);
    CHECK_EQ(o.n_width, 4);
    CHECK_EQ(o.n_height, 4);
    CHECK_EQ(o.b_rop, static_cast<uint8_t>(0xCC));
    CHECK_EQ(o.n_x_src, 2);
    CHECK_EQ(o.n_y_src, 3);
    CHECK_EQ(body_used, static_cast<size_t>(13));
}

RTSC_TEST(order_body_absent_field_reuses_previous) {
    const std::vector<uint8_t> first = {0x09, 0x00, 0x1F, 0x01, 0x00, 0x02, 0x00,
                                        0x03, 0x00, 0x04, 0x00, 0xCC};
    OrderParserState st;
    OrderBodyState bs;
    OrderHeader h1;
    size_t used = 0;
    CHECK(ParseOrderHeader(first.data(), first.size(), st, h1, used) ==
          Status::Ok);
    DstBltOrder o1;
    size_t bu = 0;
    CHECK(ParseDstBltBody(h1, first.data() + used, first.size() - used, bs, o1,
                          bu) == Status::Ok);
    CHECK_EQ(o1.n_left, 1);
    CHECK_EQ(o1.b_rop, static_cast<uint8_t>(0xCC));

    // Only the bRop field is present this time (fieldFlags = 0x10).
    const std::vector<uint8_t> second = {0x09, 0x00, 0x10, 0xFF};
    OrderHeader h2;
    used = 0;
    CHECK(ParseOrderHeader(second.data(), second.size(), st, h2, used) ==
          Status::Ok);
    CHECK_EQ(h2.field_flags[0], static_cast<uint8_t>(0x10));
    DstBltOrder o2;
    bu = 0;
    CHECK(ParseDstBltBody(h2, second.data() + used, second.size() - used, bs, o2,
                          bu) == Status::Ok);
    CHECK_EQ(o2.n_left, 1);  // reused
    CHECK_EQ(o2.n_top, 2);
    CHECK_EQ(o2.n_width, 3);
    CHECK_EQ(o2.n_height, 4);
    CHECK_EQ(o2.b_rop, static_cast<uint8_t>(0xFF));  // updated
    CHECK_EQ(bu, static_cast<size_t>(1));
}

RTSC_TEST(dstblt_apply_rops) {
    const uint8_t rops[4] = {0xCC, 0x00, 0xFF, 0x55};
    for (uint8_t rop : rops) {
        Surface s(8, 8);
        s.Fill(0x10, 0x20, 0x30, 0xFF);
        DstBltOrder o;
        o.n_left = 2;
        o.n_top = 2;
        o.n_width = 3;
        o.n_height = 3;
        o.b_rop = rop;
        ApplyDstBlt(s, o);
        uint8_t r = 0, g = 0, b = 0, a = 0;
        CHECK(s.GetPixel(3, 3, r, g, b, a));
        CHECK_EQ(a, static_cast<uint8_t>(0xFF));  // alpha passes through
        if (rop == 0xCC || rop == 0x00) {         // SRCCOPY with S=0 / BLACKNESS
            CHECK_EQ(r, static_cast<uint8_t>(0));
            CHECK_EQ(g, static_cast<uint8_t>(0));
            CHECK_EQ(b, static_cast<uint8_t>(0));
        } else if (rop == 0xFF) {  // WHITENESS
            CHECK_EQ(r, static_cast<uint8_t>(0xFF));
            CHECK_EQ(g, static_cast<uint8_t>(0xFF));
            CHECK_EQ(b, static_cast<uint8_t>(0xFF));
        } else {  // DSTINVERT
            CHECK_EQ(r, static_cast<uint8_t>(~0x10));
            CHECK_EQ(g, static_cast<uint8_t>(~0x20));
            CHECK_EQ(b, static_cast<uint8_t>(~0x30));
        }
        // Outside the rectangle is untouched.
        CHECK(s.GetPixel(1, 1, r, g, b, a));
        CHECK_EQ(r, static_cast<uint8_t>(0x10));
    }
}

RTSC_TEST(opaquerect_apply_fills_rect) {
    Surface s(8, 8);
    s.Fill(0, 0, 0, 0);
    OpaqueRectOrder o;
    o.n_left = 1;
    o.n_top = 1;
    o.n_width = 3;
    o.n_height = 2;
    o.red = 0x11;
    o.green = 0x22;
    o.blue = 0x33;
    ApplyOpaqueRect(s, o);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 1; y < 3; ++y) {
        for (int x = 1; x < 4; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, static_cast<uint8_t>(0x11));
            CHECK_EQ(g, static_cast<uint8_t>(0x22));
            CHECK_EQ(b, static_cast<uint8_t>(0x33));
            CHECK_EQ(a, static_cast<uint8_t>(0xFF));
        }
    }
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(4, 1, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(scrblt_apply_translate) {
    Surface s(8, 8);
    s.Fill(0, 0, 0, 0xFF);
    s.SetPixel(5, 5, 0xAA, 0, 0, 0xFF);
    s.SetPixel(6, 5, 0xBB, 0, 0, 0xFF);
    s.SetPixel(5, 6, 0xCC, 0, 0, 0xFF);
    s.SetPixel(6, 6, 0xDD, 0, 0, 0xFF);
    ScrBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 2;
    o.n_height = 2;
    o.b_rop = 0xCC;  // SRCCOPY
    o.n_x_src = 5;
    o.n_y_src = 5;
    ApplyScrBlt(s, o);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xAA));
    CHECK(s.GetPixel(1, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xBB));
    CHECK(s.GetPixel(0, 1, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xCC));
    CHECK(s.GetPixel(1, 1, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xDD));
}

// A right-shift by 3 overlaps; without a source snapshot the copy smears.
RTSC_TEST(scrblt_apply_overlap_no_smear) {
    Surface s(8, 8);
    for (int y = 0; y < 8; ++y)
        for (int x = 0; x < 8; ++x)
            s.SetPixel(x, y, static_cast<uint8_t>(x), 0, 0, 0xFF);
    ScrBltOrder o;
    o.n_left = 3;
    o.n_top = 0;
    o.n_width = 5;
    o.n_height = 8;
    o.b_rop = 0xCC;
    o.n_x_src = 0;
    o.n_y_src = 0;
    ApplyScrBlt(s, o);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    const uint8_t want[5] = {0, 1, 2, 3, 4};
    for (int i = 0; i < 5; ++i) {
        CHECK(s.GetPixel(3 + i, 0, r, g, b, a));
        CHECK_EQ(r, want[i]);
    }
    // Columns 0..2 are unchanged.
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(2, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(2));
}

// Clean per-pixel assertion for the overlap case: a right-shift by 3 must copy
// the source region's ORIGINAL pixels, so dropping the snapshot (or copying
// nothing) fails the assertion rather than crashing.
RTSC_TEST(scrblt_overlap_right_shift_preserves_source_pixels) {
    Surface s(12, 12);
    for (int y = 0; y < 12; ++y) {
        for (int x = 0; x < 12; ++x) {
            s.SetPixel(x, y, static_cast<uint8_t>((x * 7 + y * 3) & 0xFF),
                       static_cast<uint8_t>((x + y) & 0xFF),
                       static_cast<uint8_t>((x * 3) & 0xFF), 0xFF);
        }
    }
    struct Px {
        uint8_t r, g, b, a;
    };
    std::vector<Px> orig(8 * 12);
    for (int y = 0; y < 12; ++y) {
        for (int x = 0; x < 8; ++x) {
            uint8_t r = 0, g = 0, b = 0, a = 0;
            CHECK(s.GetPixel(x, y, r, g, b, a));
            orig[static_cast<size_t>(y) * 8 + x] = {r, g, b, a};
        }
    }
    ScrBltOrder o;
    o.n_left = 3;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 12;
    o.b_rop = 0xCC;
    o.n_x_src = 0;
    o.n_y_src = 0;
    ApplyScrBlt(s, o);
    for (int y = 0; y < 12; ++y) {
        for (int i = 0; i < 8; ++i) {
            uint8_t r = 0, g = 0, b = 0, a = 0;
            CHECK(s.GetPixel(3 + i, y, r, g, b, a));
            const Px& w = orig[static_cast<size_t>(y) * 8 + i];
            CHECK_EQ(r, w.r);
            CHECK_EQ(g, w.g);
            CHECK_EQ(b, w.b);
        }
    }
}

RTSC_TEST(apply_clips_partially_out_of_bounds) {
    uint8_t r = 0, g = 0, b = 0, a = 0;

    Surface s(8, 8);
    s.Fill(0, 0, 0, 0);
    DstBltOrder d;
    d.n_left = 6;
    d.n_top = 6;
    d.n_width = 5;
    d.n_height = 5;
    d.b_rop = 0xFF;  // WHITENESS
    ApplyDstBlt(s, d);
    CHECK(s.GetPixel(6, 6, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xFF));
    CHECK(s.GetPixel(7, 7, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xFF));
    CHECK(s.GetPixel(5, 6, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(6, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));

    Surface s2(8, 8);
    s2.Fill(0, 0, 0, 0);
    OpaqueRectOrder o;
    o.n_left = -2;
    o.n_top = -2;
    o.n_width = 4;
    o.n_height = 4;
    o.red = 0x11;
    o.green = 0x22;
    o.blue = 0x33;
    ApplyOpaqueRect(s2, o);
    CHECK(s2.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s2.GetPixel(1, 1, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s2.GetPixel(2, 2, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));

    Surface s3(8, 8);
    s3.Fill(0, 0, 0, 0);
    s3.SetPixel(0, 0, 0xAA, 0, 0, 0xFF);
    ScrBltOrder sc;
    sc.n_left = 6;
    sc.n_top = 0;
    sc.n_width = 4;
    sc.n_height = 1;
    sc.b_rop = 0xCC;
    sc.n_x_src = 0;
    sc.n_y_src = 0;
    ApplyScrBlt(s3, sc);
    CHECK(s3.GetPixel(6, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xAA));
    CHECK(s3.GetPixel(7, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(apply_zero_and_negative_size_is_noop) {
    Surface s(8, 8);
    s.Fill(0x7F, 0x7F, 0x7F, 0x7F);

    DstBltOrder d;
    d.n_left = 1;
    d.n_top = 1;
    d.n_width = 0;
    d.n_height = 3;
    d.b_rop = 0x00;
    ApplyDstBlt(s, d);
    DstBltOrder d2;
    d2.n_left = 1;
    d2.n_top = 1;
    d2.n_width = 3;
    d2.n_height = -2;
    d2.b_rop = 0x00;
    ApplyDstBlt(s, d2);

    OpaqueRectOrder o;
    o.n_left = 1;
    o.n_top = 1;
    o.n_width = 0;
    o.n_height = 3;
    ApplyOpaqueRect(s, o);

    ScrBltOrder sc;
    sc.n_left = 1;
    sc.n_top = 1;
    sc.n_width = 0;
    sc.n_height = 3;
    sc.b_rop = 0xCC;
    ApplyScrBlt(s, sc);

    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 8; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, static_cast<uint8_t>(0x7F));
            CHECK_EQ(g, static_cast<uint8_t>(0x7F));
            CHECK_EQ(b, static_cast<uint8_t>(0x7F));
            CHECK_EQ(a, static_cast<uint8_t>(0x7F));
        }
    }
}

// Hand-computed: PatBlt 0x01, fieldFlags = 0xFF 0x07 (fields 0..10 present,
// BrushExtra absent -> BS_SOLID). left=1 top=2 width=3 height=4, bRop=0xF0,
// BackColor=11 22 33, ForeColor=AA BB CC, BrushOrgX/Y=0, BrushStyle=0, Hatch=0.
RTSC_TEST(patblt_parses_solid_hand_computed_bytes) {
    const std::vector<uint8_t> buf = {
        0x09, 0x01, 0xFF, 0x07, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
        0x04, 0x00, 0xF0, 0x11, 0x22, 0x33, 0xAA, 0xBB, 0xCC,
        0x00, 0x00, 0x00, 0x00};
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK_EQ(h.order_type, static_cast<uint8_t>(TS_ENC_PATBLT_ORDER));
    CHECK_EQ(h.field_flags.size(), static_cast<size_t>(2));
    CHECK_EQ(h.field_flags[0], static_cast<uint8_t>(0xFF));
    CHECK_EQ(h.field_flags[1], static_cast<uint8_t>(0x07));
    CHECK_EQ(used, static_cast<size_t>(4));

    OrderBodyState bs;
    PatBltOrder o;
    size_t bu = 0;
    CHECK(ParsePatBltBody(h, buf.data() + used, buf.size() - used, bs, o, bu) ==
          Status::Ok);
    CHECK_EQ(o.n_left, 1);
    CHECK_EQ(o.n_top, 2);
    CHECK_EQ(o.n_width, 3);
    CHECK_EQ(o.n_height, 4);
    CHECK_EQ(o.b_rop, static_cast<uint8_t>(0xF0));
    CHECK_EQ(o.back_red, static_cast<uint8_t>(0x11));
    CHECK_EQ(o.back_green, static_cast<uint8_t>(0x22));
    CHECK_EQ(o.back_blue, static_cast<uint8_t>(0x33));
    CHECK_EQ(o.fore_red, static_cast<uint8_t>(0xAA));
    CHECK_EQ(o.fore_green, static_cast<uint8_t>(0xBB));
    CHECK_EQ(o.fore_blue, static_cast<uint8_t>(0xCC));
    CHECK_EQ(o.brush_org_x, static_cast<int8_t>(0));
    CHECK_EQ(o.brush_org_y, static_cast<int8_t>(0));
    CHECK_EQ(o.brush_style, static_cast<uint8_t>(BS_SOLID));
    CHECK_EQ(o.brush_hatch, static_cast<uint8_t>(0));
    CHECK_EQ(bu, static_cast<size_t>(19));
}

RTSC_TEST(patblt_parses_null_hand_computed_bytes) {
    // Same layout but BrushStyle = BS_NULL (0x01) and BrushOrgX/Y = 1.
    const std::vector<uint8_t> buf = {
        0x09, 0x01, 0xFF, 0x07, 0x05, 0x00, 0x06, 0x00, 0x02, 0x00,
        0x02, 0x00, 0xCC, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
        0x01, 0x01, 0x01, 0x00};
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    OrderBodyState bs;
    PatBltOrder o;
    size_t bu = 0;
    CHECK(ParsePatBltBody(h, buf.data() + used, buf.size() - used, bs, o, bu) ==
          Status::Ok);
    CHECK_EQ(o.n_left, 5);
    CHECK_EQ(o.n_top, 6);
    CHECK_EQ(o.n_width, 2);
    CHECK_EQ(o.n_height, 2);
    CHECK_EQ(o.b_rop, static_cast<uint8_t>(0xCC));
    CHECK_EQ(o.fore_red, static_cast<uint8_t>(0x40));
    CHECK_EQ(o.fore_green, static_cast<uint8_t>(0x50));
    CHECK_EQ(o.fore_blue, static_cast<uint8_t>(0x60));
    CHECK_EQ(o.brush_org_x, static_cast<int8_t>(1));
    CHECK_EQ(o.brush_org_y, static_cast<int8_t>(1));
    CHECK_EQ(o.brush_style, static_cast<uint8_t>(BS_NULL));
    CHECK_EQ(o.brush_hatch, static_cast<uint8_t>(0));
    CHECK_EQ(bu, static_cast<size_t>(19));
}

RTSC_TEST(patblt_parses_pattern_with_brush_extra) {
    // BrushStyle = BS_PATTERN (0x03) -> BrushExtra (field 11) present:
    // fieldFlags = 0xFF 0x0F.
    const std::vector<uint8_t> buf = {
        0x09, 0x01, 0xFF, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x02, 0x00, 0xF0, 0x11, 0x22, 0x33, 0xAA, 0xBB, 0xCC,
        0x00, 0x00, 0x03, 0x01,
        0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    OrderParserState st;
    OrderHeader h;
    size_t used = 0;
    CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
    CHECK_EQ(h.field_flags[1], static_cast<uint8_t>(0x0F));
    OrderBodyState bs;
    PatBltOrder o;
    size_t bu = 0;
    CHECK(ParsePatBltBody(h, buf.data() + used, buf.size() - used, bs, o, bu) ==
          Status::Ok);
    CHECK_EQ(o.brush_style, static_cast<uint8_t>(BS_PATTERN));
    CHECK_EQ(o.brush_hatch, static_cast<uint8_t>(0x01));
    const uint8_t want[7] = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    for (int i = 0; i < 7; ++i) CHECK_EQ(o.brush_extra[i], want[i]);
    CHECK_EQ(bu, static_cast<size_t>(26));
}

RTSC_TEST(patblt_brush_extra_flag_must_match_pattern_style) {
    OrderParserState st;
    OrderBodyState bs;
    // BS_SOLID but the BrushExtra flag is set -> inconsistent.
    {
        const std::vector<uint8_t> buf = {
            0x09, 0x01, 0xFF, 0x0F, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
            0x04, 0x00, 0xF0, 0x11, 0x22, 0x33, 0xAA, 0xBB, 0xCC,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        OrderHeader h;
        size_t used = 0;
        CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
        PatBltOrder o;
        size_t bu = 0;
        CHECK(ParsePatBltBody(h, buf.data() + used, buf.size() - used, bs, o, bu) ==
              Status::InvalidField);
    }
    // BS_PATTERN but the BrushExtra flag is clear -> inconsistent.
    {
        const std::vector<uint8_t> buf = {
            0x09, 0x01, 0xFF, 0x07, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
            0x04, 0x00, 0xF0, 0x11, 0x22, 0x33, 0xAA, 0xBB, 0xCC,
            0x00, 0x00, 0x03, 0x00};
        OrderHeader h;
        size_t used = 0;
        CHECK(ParseOrderHeader(buf.data(), buf.size(), st, h, used) == Status::Ok);
        PatBltOrder o;
        size_t bu = 0;
        CHECK(ParsePatBltBody(h, buf.data() + used, buf.size() - used, bs, o, bu) ==
              Status::InvalidField);
    }
}

RTSC_TEST(patblt_apply_solid_rops) {
    struct Case {
        uint8_t rop;
        uint8_t want_r, want_g, want_b;
    };
    const Case cases[4] = {
        {0xF0, 0xAA, 0xBB, 0xCC},                        // PATCOPY: P
        {0x5A, static_cast<uint8_t>(0x10 ^ 0xAA),
         static_cast<uint8_t>(0x20 ^ 0xBB),
         static_cast<uint8_t>(0x30 ^ 0xCC)},              // PATINVERT: D^P
        {0x00, 0x00, 0x00, 0x00},                        // BLACKNESS
        {0xFF, 0xFF, 0xFF, 0xFF},                        // WHITENESS
    };
    for (const Case& c : cases) {
        Surface s(8, 8);
        s.Fill(0x10, 0x20, 0x30, 0xFF);
        PatBltOrder o;
        o.n_left = 2;
        o.n_top = 2;
        o.n_width = 3;
        o.n_height = 3;
        o.b_rop = c.rop;
        o.brush_style = BS_SOLID;
        o.fore_red = 0xAA;
        o.fore_green = 0xBB;
        o.fore_blue = 0xCC;
        CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
        uint8_t r = 0, g = 0, b = 0, a = 0;
        CHECK(s.GetPixel(3, 3, r, g, b, a));
        CHECK_EQ(r, c.want_r);
        CHECK_EQ(g, c.want_g);
        CHECK_EQ(b, c.want_b);
        // Outside the rectangle is untouched.
        CHECK(s.GetPixel(1, 1, r, g, b, a));
        CHECK_EQ(r, static_cast<uint8_t>(0x10));
    }
}

RTSC_TEST(patblt_apply_null_is_noop) {
    Surface s(8, 8);
    s.Fill(0x7F, 0x7F, 0x7F, 0x7F);
    PatBltOrder o;
    o.n_left = 1;
    o.n_top = 1;
    o.n_width = 3;
    o.n_height = 3;
    o.b_rop = 0xF0;
    o.brush_style = BS_NULL;
    o.fore_red = 0xAA;
    o.fore_green = 0xBB;
    o.fore_blue = 0xCC;
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kNoOp);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 8; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, static_cast<uint8_t>(0x7F));
        }
    }
}

RTSC_TEST(patblt_apply_pattern_and_hatch_supported) {
    // BS_PATTERN is implemented (3b3b).
    {
        Surface s(8, 8);
        s.Fill(0x10, 0x20, 0x30, 0xFF);
        PatBltOrder o;
        o.n_left = 0;
        o.n_top = 0;
        o.n_width = 8;
        o.n_height = 8;
        o.b_rop = 0xF0;
        o.brush_style = BS_PATTERN;
        o.brush_hatch = 0x01;     // bottom row set at px 7
        o.brush_extra[6] = 0x80;  // top row set at px 0
        o.fore_red = 0xAA;
        o.fore_green = 0xBB;
        o.fore_blue = 0xCC;
        o.back_red = 0x11;
        o.back_green = 0x22;
        o.back_blue = 0x33;
        CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
        uint8_t r = 0, g = 0, b = 0, a = 0;
        CHECK(s.GetPixel(0, 0, r, g, b, a));
        CHECK_EQ(r, static_cast<uint8_t>(0x11));  // top row px 0 set
    }
    // BS_HATCHED is implemented (3b3a).
    {
        Surface s(8, 8);
        s.Fill(0, 0, 0, 0xFF);
        PatBltOrder o;
        o.n_left = 0;
        o.n_top = 0;
        o.n_width = 8;
        o.n_height = 8;
        o.b_rop = 0xF0;
        o.brush_style = BS_HATCHED;
        o.brush_hatch = 0x00;
        o.fore_red = 0xAA;
        o.fore_green = 0xBB;
        o.fore_blue = 0xCC;
        o.back_red = 0x11;
        o.back_green = 0x22;
        o.back_blue = 0x33;
        CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
    }
}

RTSC_TEST(patblt_apply_clips_partially_out_of_bounds) {
    Surface s(8, 8);
    s.Fill(0, 0, 0, 0);
    PatBltOrder o;
    o.n_left = 6;
    o.n_top = 6;
    o.n_width = 5;
    o.n_height = 5;
    o.b_rop = 0xF0;  // PATCOPY
    o.brush_style = BS_SOLID;
    o.fore_red = 0xAA;
    o.fore_green = 0xBB;
    o.fore_blue = 0xCC;
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(6, 6, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xAA));
    CHECK(s.GetPixel(7, 7, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xAA));
    CHECK(s.GetPixel(5, 6, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(patblt_apply_zero_negative_size_noop) {
    Surface s(8, 8);
    s.Fill(0x7F, 0x7F, 0x7F, 0x7F);
    PatBltOrder o;
    o.n_left = 1;
    o.n_top = 1;
    o.n_width = 0;
    o.n_height = 3;
    o.b_rop = 0xF0;
    o.brush_style = BS_SOLID;
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kNoOp);
    PatBltOrder o2;
    o2.n_left = 1;
    o2.n_top = 1;
    o2.n_width = 3;
    o2.n_height = -2;
    o2.b_rop = 0xF0;
    o2.brush_style = BS_SOLID;
    CHECK(ApplyPatBlt(s, o2) == PatBltResult::kNoOp);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(2, 2, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x7F));
}

// Independent expected hatch table (bit 0 = foreground line, MSB = leftmost).
// Written from the spec semantics (a hatch is one line / cross / X), not from
// the implementation table.
RTSC_TEST(patblt_apply_hatched_patterns) {
    static const uint8_t kExpect[6][8] = {
        {0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},  // HS_HORIZONTAL
        {0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7},  // HS_VERTICAL
        {0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F},  // HS_FDIAGONAL
        {0x7F, 0xBF, 0xDF, 0xEF, 0xF7, 0xFB, 0xFD, 0xFE},  // HS_BDIAGONAL
        {0xF7, 0xF7, 0xF7, 0x00, 0xF7, 0xF7, 0xF7, 0xF7},  // HS_CROSS
        {0x7E, 0xBD, 0xDB, 0xE7, 0xE7, 0xDB, 0xBD, 0x7E},  // HS_DIAGCROSS
    };
    const uint8_t hatches[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    for (int h = 0; h < 6; ++h) {
        Surface s(8, 8);
        s.Fill(0, 0, 0, 0xFF);
        PatBltOrder o;
        o.n_left = 0;
        o.n_top = 0;
        o.n_width = 8;
        o.n_height = 8;
        o.b_rop = 0xF0;  // PATCOPY
        o.brush_style = BS_HATCHED;
        o.brush_hatch = hatches[h];
        o.fore_red = 0xAA;
        o.fore_green = 0xBB;
        o.fore_blue = 0xCC;
        o.back_red = 0x11;
        o.back_green = 0x22;
        o.back_blue = 0x33;
        CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
        uint8_t r = 0, g = 0, b = 0, a = 0;
        for (int y = 0; y < 8; ++y) {
            for (int x = 0; x < 8; ++x) {
                CHECK(s.GetPixel(x, y, r, g, b, a));
                const int bit = (kExpect[h][y] >> (7 - x)) & 1;
                const uint8_t er = bit == 0 ? static_cast<uint8_t>(0xAA)
                                            : static_cast<uint8_t>(0x11);
                const uint8_t eg = bit == 0 ? static_cast<uint8_t>(0xBB)
                                            : static_cast<uint8_t>(0x22);
                const uint8_t eb = bit == 0 ? static_cast<uint8_t>(0xCC)
                                            : static_cast<uint8_t>(0x33);
                CHECK_EQ(r, er);
                CHECK_EQ(g, eg);
                CHECK_EQ(b, eb);
            }
        }
    }
}

RTSC_TEST(patblt_apply_hatched_brush_org_positive_and_negative) {
    // +3: pattern row = (y - 3) mod 8; foreground where the row is 3.
    Surface s(16, 16);
    s.Fill(0, 0, 0, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 16;
    o.n_height = 16;
    o.b_rop = 0xF0;
    o.brush_style = BS_HATCHED;
    o.brush_hatch = 0x00;  // HORIZONTAL
    o.brush_org_x = 3;
    o.brush_org_y = 3;
    o.fore_red = 0xAA;
    o.fore_green = 0xBB;
    o.fore_blue = 0xCC;
    o.back_red = 0x11;
    o.back_green = 0x22;
    o.back_blue = 0x33;
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 16; ++y) {
        const int py = ((y - 3) % 8 + 8) % 8;
        const uint8_t er = py == 3 ? static_cast<uint8_t>(0xAA)
                                   : static_cast<uint8_t>(0x11);
        for (int x = 0; x < 16; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, er);
        }
    }

    // -3 (stored 0xFD): pattern row = (y + 3) mod 8.
    Surface s2(16, 16);
    s2.Fill(0, 0, 0, 0xFF);
    PatBltOrder o2;
    o2.n_left = 0;
    o2.n_top = 0;
    o2.n_width = 16;
    o2.n_height = 16;
    o2.b_rop = 0xF0;
    o2.brush_style = BS_HATCHED;
    o2.brush_hatch = 0x00;
    o2.brush_org_x = -3;
    o2.brush_org_y = -3;
    o2.fore_red = 0xAA;
    o2.fore_green = 0xBB;
    o2.fore_blue = 0xCC;
    o2.back_red = 0x11;
    o2.back_green = 0x22;
    o2.back_blue = 0x33;
    CHECK(ApplyPatBlt(s2, o2) == PatBltResult::kApplied);
    for (int y = 0; y < 16; ++y) {
        const int py = ((y + 3) % 8 + 8) % 8;
        const uint8_t er = py == 3 ? static_cast<uint8_t>(0xAA)
                                   : static_cast<uint8_t>(0x11);
        for (int x = 0; x < 16; ++x) {
            CHECK(s2.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, er);
        }
    }
}

RTSC_TEST(patblt_apply_hatched_patinvert) {
    Surface s(8, 8);
    s.Fill(0x10, 0x20, 0x30, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 8;
    o.b_rop = 0x5A;  // PATINVERT: D ^ P
    o.brush_style = BS_HATCHED;
    o.brush_hatch = 0x00;  // HORIZONTAL: line at pattern row 3
    o.fore_red = 0xAA;
    o.fore_green = 0xBB;
    o.fore_blue = 0xCC;
    o.back_red = 0x11;
    o.back_green = 0x22;
    o.back_blue = 0x33;
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 8; ++y) {
        const bool fore = (y == 3);
        const uint8_t er =
            fore ? static_cast<uint8_t>(0x10 ^ 0xAA) : static_cast<uint8_t>(0x10 ^ 0x11);
        const uint8_t eg =
            fore ? static_cast<uint8_t>(0x20 ^ 0xBB) : static_cast<uint8_t>(0x20 ^ 0x22);
        const uint8_t eb =
            fore ? static_cast<uint8_t>(0x30 ^ 0xCC) : static_cast<uint8_t>(0x30 ^ 0x33);
        for (int x = 0; x < 8; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, er);
            CHECK_EQ(g, eg);
            CHECK_EQ(b, eb);
        }
    }
}

RTSC_TEST(patblt_apply_hatched_invalid_hatch_unsupported) {
    Surface s(8, 8);
    s.Fill(0x7F, 0x7F, 0x7F, 0x7F);
    PatBltOrder o;
    o.n_left = 1;
    o.n_top = 1;
    o.n_width = 3;
    o.n_height = 3;
    o.b_rop = 0xF0;
    o.brush_style = BS_HATCHED;
    o.brush_hatch = 0x06;  // out of range (0..5)
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kUnsupported);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(2, 2, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x7F));
}

RTSC_TEST(patblt_apply_hatched_clips) {
    Surface s(12, 12);
    s.Fill(0, 0, 0, 0);
    PatBltOrder o;
    o.n_left = 9;
    o.n_top = 9;
    o.n_width = 5;
    o.n_height = 5;
    o.b_rop = 0xF0;
    o.brush_style = BS_HATCHED;
    o.brush_hatch = 0x00;  // HORIZONTAL: line at pattern row 3
    o.fore_red = 0xAA;
    o.fore_green = 0xBB;
    o.fore_blue = 0xCC;
    o.back_red = 0x11;
    o.back_green = 0x22;
    o.back_blue = 0x33;
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    // Rect (9,9)-(13,13) clipped to (9,9)-(11,11). Pattern row = y mod 8:
    // y=11 -> row 3 -> foreground; y=9 -> row 1 -> background.
    CHECK(s.GetPixel(9, 11, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xAA));
    CHECK(s.GetPixel(11, 11, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xAA));
    CHECK(s.GetPixel(9, 9, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s.GetPixel(8, 9, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(patblt_apply_pattern_official_vector) {
    // [MS-RDPEGDI] 2.2.2.2.1.1.2.3 official example: a 45-degree downward
    // left-to-right line encoded as BrushExtra {0x02,0x04,0x08,0x10,0x20,0x40,
    // 0x80} with BrushHatch = 0x01. The set bits form the diagonal (row i, px i).
    Surface s(8, 8);
    s.Fill(0, 0, 0, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 8;
    o.b_rop = 0xF0;  // PATCOPY
    o.brush_style = BS_PATTERN;
    o.brush_hatch = 0x01;
    o.brush_extra[0] = 0x02;
    o.brush_extra[1] = 0x04;
    o.brush_extra[2] = 0x08;
    o.brush_extra[3] = 0x10;
    o.brush_extra[4] = 0x20;
    o.brush_extra[5] = 0x40;
    o.brush_extra[6] = 0x80;
    o.fore_red = 0xAA;
    o.fore_green = 0xBB;
    o.fore_blue = 0xCC;
    o.back_red = 0x11;
    o.back_green = 0x22;
    o.back_blue = 0x33;
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 8; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            if (x == y) {  // diagonal: set bit -> BackColor
                CHECK_EQ(r, static_cast<uint8_t>(0x11));
                CHECK_EQ(g, static_cast<uint8_t>(0x22));
                CHECK_EQ(b, static_cast<uint8_t>(0x33));
            } else {  // unset -> ForeColor
                CHECK_EQ(r, static_cast<uint8_t>(0xAA));
                CHECK_EQ(g, static_cast<uint8_t>(0xBB));
                CHECK_EQ(b, static_cast<uint8_t>(0xCC));
            }
        }
    }
}

RTSC_TEST(patblt_apply_pattern_bottom_row_alternating) {
    // BrushHatch encodes the bottom row: 0xAA = 10101010 -> Back,Fore,Back,...
    for (uint8_t hatch : {static_cast<uint8_t>(0xAA), static_cast<uint8_t>(0x55)}) {
        Surface s(8, 8);
        s.Fill(0, 0, 0, 0xFF);
        PatBltOrder o;
        o.n_left = 0;
        o.n_top = 0;
        o.n_width = 8;
        o.n_height = 8;
        o.b_rop = 0xF0;
        o.brush_style = BS_PATTERN;
        o.brush_hatch = hatch;
        o.fore_red = 0xAA;
        o.fore_green = 0xBB;
        o.fore_blue = 0xCC;
        o.back_red = 0x11;
        o.back_green = 0x22;
        o.back_blue = 0x33;
        CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
        uint8_t r = 0, g = 0, b = 0, a = 0;
        for (int x = 0; x < 8; ++x) {
            CHECK(s.GetPixel(x, 7, r, g, b, a));
            const int bit = (hatch >> (7 - x)) & 1;
            if (bit == 0) {  // ForeColor
                CHECK_EQ(r, static_cast<uint8_t>(0xAA));
            } else {  // BackColor
                CHECK_EQ(r, static_cast<uint8_t>(0x11));
            }
        }
    }
}

RTSC_TEST(patblt_apply_pattern_brush_org) {
    // +3: pattern row = (y - 3) mod 8; top row (row 0) at y=3.
    Surface s(16, 16);
    s.Fill(0, 0, 0, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 16;
    o.n_height = 16;
    o.b_rop = 0xF0;
    o.brush_style = BS_PATTERN;
    o.brush_hatch = 0x01;     // bottom row set at px 7
    o.brush_extra[6] = 0x80;  // top row set at px 0
    o.brush_org_x = 3;
    o.brush_org_y = 3;
    o.fore_red = 0xAA;
    o.fore_green = 0xBB;
    o.fore_blue = 0xCC;
    o.back_red = 0x11;
    o.back_green = 0x22;
    o.back_blue = 0x33;
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(3, 3, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));  // top row px 0 set at x=3
    CHECK(s.GetPixel(4, 3, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xAA));
    CHECK(s.GetPixel(10, 10, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));  // bottom row px 7 set at x=10
    CHECK(s.GetPixel(9, 10, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xAA));

    // -3 (stored 0xFD): pattern row = (y + 3) mod 8; top row at y=5.
    Surface s2(16, 16);
    s2.Fill(0, 0, 0, 0xFF);
    PatBltOrder o2;
    o2.n_left = 0;
    o2.n_top = 0;
    o2.n_width = 16;
    o2.n_height = 16;
    o2.b_rop = 0xF0;
    o2.brush_style = BS_PATTERN;
    o2.brush_hatch = 0x01;
    o2.brush_extra[6] = 0x80;
    o2.brush_org_x = -3;
    o2.brush_org_y = -3;
    o2.fore_red = 0xAA;
    o2.fore_green = 0xBB;
    o2.fore_blue = 0xCC;
    o2.back_red = 0x11;
    o2.back_green = 0x22;
    o2.back_blue = 0x33;
    CHECK(ApplyPatBlt(s2, o2) == PatBltResult::kApplied);
    CHECK(s2.GetPixel(5, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));  // top row px 0 set at x=5
    CHECK(s2.GetPixel(6, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xAA));
}

RTSC_TEST(patblt_apply_pattern_cached_brush_unsupported) {
    Surface s(8, 8);
    s.Fill(0x7F, 0x7F, 0x7F, 0x7F);
    PatBltOrder o;
    o.n_left = 1;
    o.n_top = 1;
    o.n_width = 3;
    o.n_height = 3;
    o.b_rop = 0xF0;
    o.brush_style = 0x80;  // TS_CACHED_BRUSH
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kUnsupported);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(2, 2, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x7F));
    // Any other unknown style is also unsupported.
    o.brush_style = 0x07;
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kUnsupported);
}

RTSC_TEST(patblt_apply_pattern_patinvert) {
    Surface s(8, 8);
    s.Fill(0x10, 0x20, 0x30, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 8;
    o.b_rop = 0x5A;  // PATINVERT: D ^ P
    o.brush_style = BS_PATTERN;
    o.brush_hatch = 0x01;     // bottom row set at px 7
    o.brush_extra[6] = 0x80;  // top row set at px 0
    o.fore_red = 0xAA;
    o.fore_green = 0xBB;
    o.fore_blue = 0xCC;
    o.back_red = 0x11;
    o.back_green = 0x22;
    o.back_blue = 0x33;
    CHECK(ApplyPatBlt(s, o) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x10 ^ 0x11));  // set -> BackColor
    CHECK(s.GetPixel(1, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x10 ^ 0xAA));  // unset -> ForeColor
}

// ---------------------------------------------------------------------------
// TS_CACHED_BRUSH rendering ([MS-RDPEGDI] 2.2.2.2.1.2.7.1)
// ---------------------------------------------------------------------------

// A test-only BrushCacheView that always resolves to one fixed brush,
// ignoring the cache index. It lets the render layer be exercised directly
// with a hand-computed brushData stream.
class StaticBrushCache : public BrushCacheView {
 public:
    void Set(const uint8_t* data, size_t len, uint8_t format) {
        format_ = format;
        len_ = static_cast<uint8_t>(len);
        for (size_t i = 0; i < len && i < sizeof(data_); ++i) {
            data_[i] = data[i];
        }
    }
    const uint8_t* Lookup(uint8_t index, uint8_t& format,
                          uint8_t& length) const override {
        (void)index;  // the index is ignored on purpose
        format = format_;
        length = len_;
        return data_;
    }

 private:
    uint8_t format_ = 0;
    uint8_t len_ = 0;
    uint8_t data_[256] = {};
};

// Hand-computed COMPRESSED_COLOR_BRUSH, 24BPP: iBytes = 16 + 4*3 = 28, all 16
// index bytes zero (P1..P64 -> color1), color1 = (11,22,33).
RTSC_TEST(cached_brush_compressed_color_all_color1) {
    const uint8_t brush[28] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // P1..P64 = 0
        0x11, 0x22, 0x33,  // color1
        0x44, 0x55, 0x66,  // color2
        0x77, 0x88, 0x99,  // color3
        0xAA, 0xBB, 0xCC,  // color4
    };
    StaticBrushCache cache;
    cache.Set(brush, sizeof(brush), kBMF24BPP);
    Surface s(8, 8);
    s.Fill(0x00, 0x00, 0x00, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 8;
    o.b_rop = 0xF0;       // PATCOPY
    o.brush_style = 0x85;  // TS_CACHED_BRUSH | BMF_24BPP
    CHECK(ApplyPatBlt(s, o, cache) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 8; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, static_cast<uint8_t>(0x11));
            CHECK_EQ(g, static_cast<uint8_t>(0x22));
            CHECK_EQ(b, static_cast<uint8_t>(0x33));
        }
    }
}

// Two-color pattern: P1=0, P2=1, P3=0, P4=1 -> each byte 00 01 00 01 = 0x11,
// so every row is 0,1,0,1,0,1,0,1 (row reversal is a no-op here). Even x -> P=0
// -> color1, odd x -> P=1 -> color2.
RTSC_TEST(cached_brush_compressed_color_alternating) {
    uint8_t brush[28] = {};
    for (int i = 0; i < 16; ++i) brush[i] = 0x11;
    brush[16] = 0x11; brush[17] = 0x22; brush[18] = 0x33;  // color1
    brush[19] = 0x44; brush[20] = 0x55; brush[21] = 0x66;  // color2
    brush[22] = 0x77; brush[23] = 0x88; brush[24] = 0x99;  // color3
    brush[25] = 0xAA; brush[26] = 0xBB; brush[27] = 0xCC;  // color4
    StaticBrushCache cache;
    cache.Set(brush, sizeof(brush), kBMF24BPP);
    Surface s(8, 8);
    s.Fill(0x00, 0x00, 0x00, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 8;
    o.b_rop = 0xF0;
    o.brush_style = 0x85;
    CHECK(ApplyPatBlt(s, o, cache) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 8; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            const bool color1 = (x % 2 == 0);  // P=0 -> color1, P=1 -> color2
            CHECK_EQ(r, color1 ? static_cast<uint8_t>(0x11)
                               : static_cast<uint8_t>(0x44));
            CHECK_EQ(g, color1 ? static_cast<uint8_t>(0x22)
                               : static_cast<uint8_t>(0x55));
            CHECK_EQ(b, color1 ? static_cast<uint8_t>(0x33)
                               : static_cast<uint8_t>(0x66));
        }
    }
}

// Row-order discriminator for the compressed form: P1..P8 = 1 (color2) and
// P9..P64 = 0 (color1). The wire stores rows bottom-first, so the bottom row
// is color2 and every other row is color1; without the reversal the top row
// would be color2 instead.
RTSC_TEST(cached_brush_compressed_color_row_order) {
    uint8_t brush[28] = {};
    brush[0] = 0x55;  // P1..P4 = 1 (01 01 01 01)
    brush[1] = 0x55;  // P5..P8 = 1
    // brush[2..15] = 0 -> P9..P64 = 0
    brush[16] = 0x11; brush[17] = 0x22; brush[18] = 0x33;  // color1
    brush[19] = 0x44; brush[20] = 0x55; brush[21] = 0x66;  // color2
    brush[22] = 0x77; brush[23] = 0x88; brush[24] = 0x99;  // color3
    brush[25] = 0xAA; brush[26] = 0xBB; brush[27] = 0xCC;  // color4
    StaticBrushCache cache;
    cache.Set(brush, sizeof(brush), kBMF24BPP);
    Surface s(8, 8);
    s.Fill(0x00, 0x00, 0x00, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 8;
    o.b_rop = 0xF0;
    o.brush_style = 0x85;
    CHECK(ApplyPatBlt(s, o, cache) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 8; ++y) {
        // y=7 (bottom) is the wire first row (P1..P8=1 -> color2); the other
        // rows are color1.
        const bool color2 = (y == 7);
        for (int x = 0; x < 8; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, color2 ? static_cast<uint8_t>(0x44)
                               : static_cast<uint8_t>(0x11));
            CHECK_EQ(g, color2 ? static_cast<uint8_t>(0x55)
                               : static_cast<uint8_t>(0x22));
            CHECK_EQ(b, color2 ? static_cast<uint8_t>(0x66)
                               : static_cast<uint8_t>(0x33));
        }
    }
}

// Uncompressed 24BPP: iBytes = 64*3 = 192. Wire pixel i has R=i, G=0xFF-i,
// B=i; the wire rows are bottom-first, so image (x, y) reads wire index
// i = (7 - y) * 8 + x.
RTSC_TEST(cached_brush_uncompressed_color) {
    uint8_t brush[192];
    for (int i = 0; i < 64; ++i) {
        brush[i * 3 + 0] = static_cast<uint8_t>(i);
        brush[i * 3 + 1] = static_cast<uint8_t>(0xFF - i);
        brush[i * 3 + 2] = static_cast<uint8_t>(i);
    }
    StaticBrushCache cache;
    cache.Set(brush, sizeof(brush), kBMF24BPP);
    Surface s(8, 8);
    s.Fill(0x00, 0x00, 0x00, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 8;
    o.b_rop = 0xF0;
    o.brush_style = 0x85;
    CHECK(ApplyPatBlt(s, o, cache) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 8; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            const int i = (7 - y) * 8 + x;
            CHECK_EQ(r, static_cast<uint8_t>(i));
            CHECK_EQ(g, static_cast<uint8_t>(0xFF - i));
            CHECK_EQ(b, static_cast<uint8_t>(i));
        }
    }
}

// 16BPP R5G6B5 packing: 16 + 4*2 = 24 bytes. All P = 0 -> color1 = 0xF800
// (pure red). The 5/6/5 expansion must yield R=0xFF, G=0, B=0.
RTSC_TEST(cached_brush_compressed_color_16bpp_r5g6b5) {
    uint8_t brush[24] = {};
    brush[16] = 0x00; brush[17] = 0xF8;  // color1 = 0xF800 = red
    brush[18] = 0xE0; brush[19] = 0x07;  // color2 = 0x07E0 = green
    brush[20] = 0x1F; brush[21] = 0x00;  // color3 = 0x001F = blue
    brush[22] = 0xFF; brush[23] = 0xFF;  // color4 = 0xFFFF = white
    StaticBrushCache cache;
    cache.Set(brush, sizeof(brush), kBMF16BPP);
    Surface s(8, 8);
    s.Fill(0x00, 0x00, 0x00, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 8;
    o.b_rop = 0xF0;
    o.brush_style = 0x84;  // TS_CACHED_BRUSH | BMF_16BPP
    CHECK(ApplyPatBlt(s, o, cache) == PatBltResult::kApplied);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xFF));
    CHECK_EQ(g, static_cast<uint8_t>(0x00));
    CHECK_EQ(b, static_cast<uint8_t>(0x00));
}

// Fail-closed: 24BPP with iBytes = 100 matches no form -> kUnsupported and
// nothing drawn.
RTSC_TEST(cached_brush_invalid_form_unsupported) {
    const uint8_t brush[100] = {};
    StaticBrushCache cache;
    cache.Set(brush, sizeof(brush), kBMF24BPP);
    Surface s(8, 8);
    s.Fill(0x7F, 0x7F, 0x7F, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 8;
    o.b_rop = 0xF0;
    o.brush_style = 0x85;
    CHECK(ApplyPatBlt(s, o, cache) == PatBltResult::kUnsupported);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x7F));
}

// BMF_8BPP is a palette index; with no color-table context the brush is
// unsupported rather than drawn with a guessed color.
RTSC_TEST(cached_brush_8bpp_needs_palette_unsupported) {
    const uint8_t brush[20] = {};  // 16 + 4*1
    StaticBrushCache cache;
    cache.Set(brush, sizeof(brush), kBMF8BPP);
    Surface s(8, 8);
    s.Fill(0x7F, 0x7F, 0x7F, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 8;
    o.b_rop = 0xF0;
    o.brush_style = 0x83;  // TS_CACHED_BRUSH | BMF_8BPP
    CHECK(ApplyPatBlt(s, o, cache) == PatBltResult::kUnsupported);
}

// The PatBlt's low nibble must name the cached brush's color depth; a mismatch
// is unsupported rather than drawn with the wrong depth.
RTSC_TEST(cached_brush_depth_mismatch_unsupported) {
    const uint8_t brush[28] = {};
    StaticBrushCache cache;
    cache.Set(brush, sizeof(brush), kBMF24BPP);
    Surface s(8, 8);
    s.Fill(0x7F, 0x7F, 0x7F, 0xFF);
    PatBltOrder o;
    o.n_left = 0;
    o.n_top = 0;
    o.n_width = 8;
    o.n_height = 8;
    o.b_rop = 0xF0;
    o.brush_style = 0x81;  // TS_CACHED_BRUSH | BMF_1BPP (mismatch)
    CHECK(ApplyPatBlt(s, o, cache) == PatBltResult::kUnsupported);
}

int main() { return ::rtsc::test::run_all("rtsc_orders_tests"); }
