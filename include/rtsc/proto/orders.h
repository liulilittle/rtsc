// RDP drawing orders: variable-length encodings and the Cache Bitmap - Revision
// 2 secondary drawing order ([MS-RDPEGDI] 2.2.2.2.1.2).
//
// Secondary drawing orders are carried inside an Orders Update
// ([MS-RDPEGDI] 2.2.2.2). This module covers the two variable-length integer
// encodings used by those orders and the Rev2 cache order structure; the Orders
// Update framing and the other orders are a separate layer.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

// wingdi.h (pulled in by windows.h) defines BS_* brush-style macros with these
// exact names. Undefine them so the BrushStyle enum below keeps its identifiers;
// without this, any translation unit that includes windows.h before this header
// fails to parse the enum.
#ifdef BS_SOLID
#undef BS_SOLID
#endif
#ifdef BS_NULL
#undef BS_NULL
#endif
#ifdef BS_HATCHED
#undef BS_HATCHED
#endif
#ifdef BS_PATTERN
#undef BS_PATTERN
#endif

namespace rtsc::proto {

// TS_SECONDARY_ORDER_2_BYTE_UNSIGNED_ENCODING ([MS-RDPEGDI] 2.2.2.2.1.2.1.2).
// One byte when the high bit is clear, two bytes otherwise. `consumed` is set to
// 1 or 2.
Status ReadTwoByteUnsigned(const uint8_t* data, size_t size, uint16_t& value,
                           size_t& consumed);

// TS_SECONDARY_ORDER_4_BYTE_UNSIGNED_ENCODING ([MS-RDPEGDI] 2.2.2.2.1.2.1.4).
// One byte when the high bit is clear, four bytes otherwise.
Status ReadFourByteUnsigned(const uint8_t* data, size_t size, uint32_t& value,
                            size_t& consumed);

// CACHE_BITMAP_REV2_ORDER.extraFlags ([MS-RDPEGDI] 2.2.2.2.1.2.3).
enum CacheBitmapRev2Flag : uint16_t {
    kCbr2HeightSameAsWidth = 0x01,
    kCbr2PersistentKeyPresent = 0x02,
    kCbr2NoBitmapCompressionHdr = 0x08,
    kCbr2DoNotCache = 0x10,
};

// CACHE_BITMAP_REV2_ORDER ([MS-RDPEGDI] 2.2.2.2.1.2.3).
//
// `extra_flags` comes from the 2-byte extraFlags of the secondary drawing order
// header (cacheId / bitsPerPixelId / flags); the remaining fields follow it.
struct CacheBitmapRev2Order {
    uint8_t cache_id = 0;         // extraFlags bits 0..2
    uint8_t bits_per_pixel_id = 0;  // extraFlags bits 3..6 (CBR2_*BPP)
    uint16_t flags = 0;           // extraFlags bits 7..15

    uint32_t key1 = 0;  // present when kCbr2PersistentKeyPresent
    uint32_t key2 = 0;
    uint16_t bitmap_width = 0;
    uint16_t bitmap_height = 0;
    uint32_t bitmap_length = 0;
    uint16_t cache_index = 0;
    // bitmapComprHdr (8 bytes when compressed and not NO_BITMAP_COMPRESSION_HDR)
    // followed by bitmapDataStream.
    std::vector<uint8_t> bitmap_data;

    // Decodes the order body (everything after the 6-byte secondary order
    // header). `extra_flags` is that header's extraFlags field.
    static Status parse(uint16_t extra_flags, const uint8_t* data, size_t size,
                        CacheBitmapRev2Order& out);

    // bitsPerPixel derived from bits_per_pixel_id (CBR2_8BPP -> 8, ...).
    uint16_t bits_per_pixel() const;
};

// TS_ORDER_HEADER.controlFlags ([MS-RDPEGDI] 2.2.2.2.1.1.2).
enum OrderControlFlag : uint8_t {
    TS_STANDARD = 0x01,                // primary order; MUST be set
    TS_SECONDARY = 0x02,               // secondary order (different header)
    TS_BOUNDS = 0x04,                  // order carries a bounding rectangle
    TS_TYPE_CHANGE = 0x08,             // orderType byte is present
    TS_DELTA_COORDINATES = 0x10,       // COORD_FIELDs are 1-byte signed deltas
    TS_ZERO_BOUNDS_DELTAS = 0x20,      // reuse the previous bounds (no field)
    TS_ZERO_FIELD_BYTE_BIT0 = 0x40,    // LSB of the trailing-zero-flag-bytes count
    TS_ZERO_FIELD_BYTE_BIT1 = 0x80,    // MSB of that count
};

// Bounds description byte flags ([MS-RDPEGDI] 2.2.2.2.1.1.2). When both a
// TS_BOUND_* and its TS_BOUND_DELTA_* are set, the delta form wins.
enum OrderBoundFlag : uint8_t {
    TS_BOUND_LEFT = 0x01,         // 2-byte little-endian
    TS_BOUND_TOP = 0x02,
    TS_BOUND_RIGHT = 0x04,
    TS_BOUND_BOTTOM = 0x08,
    TS_BOUND_DELTA_LEFT = 0x10,   // 1-byte signed delta from the previous value
    TS_BOUND_DELTA_TOP = 0x20,
    TS_BOUND_DELTA_RIGHT = 0x40,
    TS_BOUND_DELTA_BOTTOM = 0x80,
};

// Primary drawing order types ([MS-RDPEGDI] 2.2.2.2.1.1.2). The initial
// orderType agreed by server and client is TS_ENC_PATBLT_ORDER (0x01).
enum OrderType : uint8_t {
    TS_ENC_DSTBLT_ORDER = 0x00,
    TS_ENC_PATBLT_ORDER = 0x01,
    TS_ENC_SCRBLT_ORDER = 0x02,
    TS_ENC_DRAWNINEGRID_ORDER = 0x07,
    TS_ENC_MULTI_DRAWNINEGRID_ORDER = 0x08,
    TS_ENC_LINETO_ORDER = 0x09,
    TS_ENC_OPAQUERECT_ORDER = 0x0A,
    TS_ENC_SAVEBITMAP_ORDER = 0x0B,
    TS_ENC_MEMBLT_ORDER = 0x0D,
    TS_ENC_MEM3BLT_ORDER = 0x0E,
    TS_ENC_MULTIDSTBLT_ORDER = 0x0F,
    TS_ENC_MULTIPATBLT_ORDER = 0x10,
    TS_ENC_MULTISCRBLT_ORDER = 0x11,
    TS_ENC_MULTIOPAQUERECT_ORDER = 0x12,
    TS_ENC_FAST_INDEX_ORDER = 0x13,
    TS_ENC_POLYGON_SC_ORDER = 0x14,
    TS_ENC_POLYGON_CB_ORDER = 0x15,
    TS_ENC_POLYLINE_ORDER = 0x16,
    TS_ENC_FAST_GLYPH_ORDER = 0x18,
    TS_ENC_ELLIPSE_SC_ORDER = 0x19,
    TS_ENC_ELLIPSE_CB_ORDER = 0x1A,
    TS_ENC_INDEX_ORDER = 0x1B,
};

// Field count for a known primary order type, or 0 when the type is unknown.
// The fieldFlags byte count is ceil((field_count + 1) / 8) ([MS-RDPEGDI]
// 2.2.2.2.1.1.2).
uint8_t OrderTypeFieldCount(uint8_t order_type);

// State that persists across primary drawing orders: the current orderType and
// the previous bounding rectangle ([MS-RDPEGDI] 2.2.2.2.1.1.2).
struct OrderParserState {
    uint8_t order_type = TS_ENC_PATBLT_ORDER;  // initial value 0x01
    int bounds_left = 0;
    int bounds_top = 0;
    int bounds_right = 0;
    int bounds_bottom = 0;
};

// A parsed TS_ORDER_HEADER ([MS-RDPEGDI] 2.2.2.2.1.1.2).
struct OrderHeader {
    uint8_t control_flags = 0;
    uint8_t order_type = 0;
    std::vector<uint8_t> field_flags;  // full 1..3 bytes, trailing zeros restored
    size_t field_flags_bytes = 0;      // number of bytes present on the wire
    int bounds_left = 0;
    int bounds_top = 0;
    int bounds_right = 0;
    int bounds_bottom = 0;
    bool has_bounds = false;
};

// Parses a TS_ORDER_HEADER. `state` carries orderType and bounds across
// orders; it is updated in place. Fail-closed: returns InvalidField for an
// unknown orderType, a missing TS_STANDARD flag, a secondary order, or an
// inconsistent zero-flag count; NeedMoreData for truncation.
Status ParseOrderHeader(const uint8_t* data, size_t size, OrderParserState& state,
                        OrderHeader& out, size_t& consumed);

// Decodes a COORD_FIELD ([MS-RDPEGDI] 2.2.2.2.1.1.1.1). When `delta` is set
// (TS_DELTA_COORDINATES) the wire value is a signed 1-byte delta added to
// `previous`; otherwise it is a signed 2-byte little-endian absolute value.
Status ReadCoordField(const uint8_t* data, size_t size, bool delta,
                      int16_t previous, int16_t& value, size_t& consumed);

// ---------------------------------------------------------------------------
// Primary drawing orders: DstBlt / OpaqueRect / ScrBlt
// ([MS-RDPEGDI] 2.2.2.2.1.1.2).
// ---------------------------------------------------------------------------

// Previous body-field values, carried across orders so that a field absent
// from the current fieldFlags reuses the last value sent for that order.
//
// Note: each Parse*Body writes fields back through the helper's reference
// parameters (e.g. ReadByteIfPresent(..., uint8_t& previous, ...) does
// `previous = value` internally; ReadCoordIfPresent is isomorphic). So the
// absence of an explicit `state.xxx = ...` here does NOT mean the value was not
// written back: an absent field (fieldFlags bit clear) relies on that mechanism
// to reuse the previous order's value.
struct OrderBodyState {
    // DstBlt
    int dstblt_left = 0;
    int dstblt_top = 0;
    int dstblt_width = 0;
    int dstblt_height = 0;
    uint8_t dstblt_rop = 0;
    // OpaqueRect
    int opaque_left = 0;
    int opaque_top = 0;
    int opaque_width = 0;
    int opaque_height = 0;
    uint8_t opaque_red = 0;
    uint8_t opaque_green = 0;
    uint8_t opaque_blue = 0;
    // ScrBlt
    int scr_left = 0;
    int scr_top = 0;
    int scr_width = 0;
    int scr_height = 0;
    uint8_t scr_rop = 0;
    int scr_x_src = 0;
    int scr_y_src = 0;
    // PatBlt
    int patblt_left = 0;
    int patblt_top = 0;
    int patblt_width = 0;
    int patblt_height = 0;
    uint8_t patblt_rop = 0;
    uint8_t patblt_back_red = 0;
    uint8_t patblt_back_green = 0;
    uint8_t patblt_back_blue = 0;
    uint8_t patblt_fore_red = 0;
    uint8_t patblt_fore_green = 0;
    uint8_t patblt_fore_blue = 0;
    uint8_t patblt_brush_org_x = 0;
    uint8_t patblt_brush_org_y = 0;
    uint8_t patblt_brush_style = 0;
    uint8_t patblt_brush_hatch = 0;
};

// DstBlt (orderType 0x00, 5 fields): four COORD_FIELDs + bRop.
struct DstBltOrder {
    int n_left = 0;
    int n_top = 0;
    int n_width = 0;
    int n_height = 0;
    uint8_t b_rop = 0;
};

// OpaqueRect (orderType 0x0A, 7 fields): four COORD_FIELDs + R/G/B bytes.
struct OpaqueRectOrder {
    int n_left = 0;
    int n_top = 0;
    int n_width = 0;
    int n_height = 0;
    uint8_t red = 0;
    uint8_t green = 0;
    uint8_t blue = 0;
};

// ScrBlt (orderType 0x02, 7 fields): four COORD_FIELDs + bRop + two COORD_FIELDs.
struct ScrBltOrder {
    int n_left = 0;
    int n_top = 0;
    int n_width = 0;
    int n_height = 0;
    uint8_t b_rop = 0;
    int n_x_src = 0;
    int n_y_src = 0;
};

// Brush styles ([MS-RDPEGDI] 2.2.2.2.1.1.2.3).
enum BrushStyle : uint8_t {
    BS_SOLID = 0x00,
    BS_NULL = 0x01,
    BS_HATCHED = 0x02,
    BS_PATTERN = 0x03,
};

// PatBlt (orderType 0x01, 12 fields): four COORD_FIELDs + bRop + BackColor +
// ForeColor (3 bytes each, R/G/B) + BrushOrgX/Y (1-byte signed) + BrushStyle +
// BrushHatch + BrushExtra (7 bytes, present only for BS_PATTERN).
struct PatBltOrder {
    int n_left = 0;
    int n_top = 0;
    int n_width = 0;
    int n_height = 0;
    uint8_t b_rop = 0;
    uint8_t back_red = 0;
    uint8_t back_green = 0;
    uint8_t back_blue = 0;
    uint8_t fore_red = 0;
    uint8_t fore_green = 0;
    uint8_t fore_blue = 0;
    int8_t brush_org_x = 0;
    int8_t brush_org_y = 0;
    uint8_t brush_style = 0;
    uint8_t brush_hatch = 0;
    uint8_t brush_extra[7] = {0, 0, 0, 0, 0, 0, 0};
};

// Parses the primaryOrderData body of a DstBlt / OpaqueRect / ScrBlt. The
// fields present are governed by `header.field_flags`; absent fields reuse the
// last value held in `state`. Fail-closed on truncation.
Status ParseDstBltBody(const OrderHeader& header, const uint8_t* data,
                       size_t size, OrderBodyState& state, DstBltOrder& out,
                       size_t& consumed);
Status ParseOpaqueRectBody(const OrderHeader& header, const uint8_t* data,
                           size_t size, OrderBodyState& state,
                           OpaqueRectOrder& out, size_t& consumed);
Status ParseScrBltBody(const OrderHeader& header, const uint8_t* data,
                       size_t size, OrderBodyState& state, ScrBltOrder& out,
                       size_t& consumed);
Status ParsePatBltBody(const OrderHeader& header, const uint8_t* data,
                       size_t size, OrderBodyState& state, PatBltOrder& out,
                       size_t& consumed);

}  // namespace rtsc::proto
