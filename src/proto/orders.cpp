// RDP drawing orders: variable-length encodings and Cache Bitmap Rev2.

#include "rtsc/proto/orders.h"

namespace rtsc::proto {

Status ReadTwoByteUnsigned(const uint8_t* data, size_t size, uint16_t& value,
                           size_t& consumed) {
    consumed = 0;
    if (data == nullptr || size < 1) return Status::NeedMoreData;
    if ((data[0] & 0x80) == 0) {
        value = data[0];
        consumed = 1;
        return Status::Ok;
    }
    if (size < 2) return Status::NeedMoreData;
    value = static_cast<uint16_t>(((data[0] & 0x7F) << 8) | data[1]);
    consumed = 2;
    return Status::Ok;
}

Status ReadFourByteUnsigned(const uint8_t* data, size_t size, uint32_t& value,
                            size_t& consumed) {
    consumed = 0;
    if (data == nullptr || size < 1) return Status::NeedMoreData;
    // TS_SECONDARY_ORDER_4_BYTE_UNSIGNED_ENCODING ([MS-RDPEGDI]
    // 2.2.2.2.1.2.1.4): the high 2 bits of the first byte are a count of the
    // extra bytes c (0..3), so the total is c + 1 (1..4); the low 6 bits are the
    // most significant bits of the value.
    const size_t count = static_cast<size_t>(data[0] >> 6) + 1;
    if (size < count) return Status::NeedMoreData;
    uint32_t v = static_cast<uint32_t>(data[0] & 0x3F);
    for (size_t i = 1; i < count; ++i) v = (v << 8) | data[i];
    value = v;
    consumed = count;
    return Status::Ok;
}

uint16_t CacheBitmapRev2Order::bits_per_pixel() const {
    switch (bits_per_pixel_id) {
        case 0x3: return 8;
        case 0x4: return 16;
        case 0x5: return 24;
        case 0x6: return 32;
        default: return 0;
    }
}

Status CacheBitmapRev2Order::parse(uint16_t extra_flags, const uint8_t* data,
                                   size_t size, CacheBitmapRev2Order& out) {
    out.cache_id = static_cast<uint8_t>(extra_flags & 0x07);
    out.bits_per_pixel_id = static_cast<uint8_t>((extra_flags >> 3) & 0x0F);
    out.flags = static_cast<uint16_t>((extra_flags >> 7) & 0x01FF);

    size_t pos = 0;
    if ((out.flags & kCbr2PersistentKeyPresent) != 0) {
        if (pos + 8 > size) return Status::NeedMoreData;
        ByteReader r(data, size);
        r.u32le(out.key1);
        r.u32le(out.key2);
        pos += 8;
    }

    size_t used = 0;
    Status s = ReadTwoByteUnsigned(data + pos, size - pos, out.bitmap_width, used);
    if (s != Status::Ok) return s;
    pos += used;

    if ((out.flags & kCbr2HeightSameAsWidth) != 0) {
        out.bitmap_height = out.bitmap_width;
    } else {
        s = ReadTwoByteUnsigned(data + pos, size - pos, out.bitmap_height, used);
        if (s != Status::Ok) return s;
        pos += used;
    }

    s = ReadFourByteUnsigned(data + pos, size - pos, out.bitmap_length, used);
    if (s != Status::Ok) return s;
    pos += used;

    s = ReadTwoByteUnsigned(data + pos, size - pos, out.cache_index, used);
    if (s != Status::Ok) return s;
    pos += used;

    if (pos + out.bitmap_length > size) return Status::NeedMoreData;
    out.bitmap_data.assign(data + pos, data + pos + out.bitmap_length);
    return Status::Ok;
}

uint8_t OrderTypeFieldCount(uint8_t order_type) {
    switch (order_type) {
        case TS_ENC_DSTBLT_ORDER: return 5;
        case TS_ENC_MULTIDSTBLT_ORDER: return 7;        case TS_ENC_PATBLT_ORDER: return 12;
        case TS_ENC_MULTIPATBLT_ORDER: return 14;
        case TS_ENC_OPAQUERECT_ORDER: return 7;
        case TS_ENC_MULTIOPAQUERECT_ORDER: return 9;
        case TS_ENC_SCRBLT_ORDER: return 7;
        case TS_ENC_MULTISCRBLT_ORDER: return 9;
        case TS_ENC_MEMBLT_ORDER: return 9;
        case TS_ENC_MEM3BLT_ORDER: return 16;
        case TS_ENC_LINETO_ORDER: return 10;
        case TS_ENC_SAVEBITMAP_ORDER: return 6;
        case TS_ENC_INDEX_ORDER: return 22;
        case TS_ENC_FAST_INDEX_ORDER: return 15;
        case TS_ENC_FAST_GLYPH_ORDER: return 15;
        case TS_ENC_POLYGON_SC_ORDER: return 7;
        case TS_ENC_POLYGON_CB_ORDER: return 13;
        case TS_ENC_POLYLINE_ORDER: return 7;
        case TS_ENC_ELLIPSE_SC_ORDER: return 7;
        case TS_ENC_ELLIPSE_CB_ORDER: return 13;
        case TS_ENC_DRAWNINEGRID_ORDER: return 5;
        case TS_ENC_MULTI_DRAWNINEGRID_ORDER: return 7;
        default: return 0;
    }
}

Status ParseOrderHeader(const uint8_t* data, size_t size, OrderParserState& state,
                        OrderHeader& out, size_t& consumed) {
    consumed = 0;
    out = OrderHeader{};
    if (data == nullptr || size < 1) return Status::NeedMoreData;

    out.control_flags = data[0];
    // A primary order MUST set TS_STANDARD; a secondary order uses a
    // different header. Anything else is rejected (fail-closed).
    if ((out.control_flags & TS_STANDARD) == 0) return Status::InvalidField;
    if ((out.control_flags & TS_SECONDARY) != 0) return Status::InvalidField;
    if ((out.control_flags & TS_ZERO_BOUNDS_DELTAS) != 0 &&
        (out.control_flags & TS_BOUNDS) == 0) {
        return Status::InvalidField;
    }

    size_t pos = 1;
    if ((out.control_flags & TS_TYPE_CHANGE) != 0) {
        if (pos >= size) return Status::NeedMoreData;
        state.order_type = data[pos++];
    }
    out.order_type = state.order_type;

    const uint8_t num_fields = OrderTypeFieldCount(state.order_type);
    if (num_fields == 0) return Status::InvalidField;
    const size_t total_flag_bytes =
        static_cast<size_t>((num_fields + 1 + 7) / 8);
    const size_t zero_count = static_cast<size_t>((out.control_flags >> 6) & 0x03);
    if (zero_count > total_flag_bytes) return Status::InvalidField;
    const size_t wire_bytes = total_flag_bytes - zero_count;
    if (pos + wire_bytes > size) return Status::NeedMoreData;
    // The omitted bytes are trailing zero bytes; the wire carries the low-order
    // bytes first.
    out.field_flags.assign(total_flag_bytes, 0);
    for (size_t i = 0; i < wire_bytes; ++i) out.field_flags[i] = data[pos + i];
    out.field_flags_bytes = wire_bytes;
    pos += wire_bytes;

    if ((out.control_flags & TS_BOUNDS) != 0) {
        if ((out.control_flags & TS_ZERO_BOUNDS_DELTAS) != 0) {
            // Reuse the previous bounding rectangle; no bounds field present.
            out.bounds_left = state.bounds_left;
            out.bounds_top = state.bounds_top;
            out.bounds_right = state.bounds_right;
            out.bounds_bottom = state.bounds_bottom;
            out.has_bounds = true;
        } else {
            if (pos >= size) return Status::NeedMoreData;
            const uint8_t desc = data[pos++];
            int l = state.bounds_left;
            int t = state.bounds_top;
            int r = state.bounds_right;
            int b = state.bounds_bottom;
            if (desc & (TS_BOUND_LEFT | TS_BOUND_DELTA_LEFT)) {
                if (desc & TS_BOUND_DELTA_LEFT) {
                    if (pos >= size) return Status::NeedMoreData;
                    l += static_cast<int8_t>(data[pos++]);
                } else {
                    if (pos + 2 > size) return Status::NeedMoreData;
                    l = static_cast<int16_t>(
                        static_cast<uint16_t>(data[pos]) |
                        (static_cast<uint16_t>(data[pos + 1]) << 8));
                    pos += 2;
                }
            }
            if (desc & (TS_BOUND_TOP | TS_BOUND_DELTA_TOP)) {
                if (desc & TS_BOUND_DELTA_TOP) {
                    if (pos >= size) return Status::NeedMoreData;
                    t += static_cast<int8_t>(data[pos++]);
                } else {
                    if (pos + 2 > size) return Status::NeedMoreData;
                    t = static_cast<int16_t>(
                        static_cast<uint16_t>(data[pos]) |
                        (static_cast<uint16_t>(data[pos + 1]) << 8));
                    pos += 2;
                }
            }
            if (desc & (TS_BOUND_RIGHT | TS_BOUND_DELTA_RIGHT)) {
                if (desc & TS_BOUND_DELTA_RIGHT) {
                    if (pos >= size) return Status::NeedMoreData;
                    r += static_cast<int8_t>(data[pos++]);
                } else {
                    if (pos + 2 > size) return Status::NeedMoreData;
                    r = static_cast<int16_t>(
                        static_cast<uint16_t>(data[pos]) |
                        (static_cast<uint16_t>(data[pos + 1]) << 8));
                    pos += 2;
                }
            }
            if (desc & (TS_BOUND_BOTTOM | TS_BOUND_DELTA_BOTTOM)) {
                if (desc & TS_BOUND_DELTA_BOTTOM) {
                    if (pos >= size) return Status::NeedMoreData;
                    b += static_cast<int8_t>(data[pos++]);
                } else {
                    if (pos + 2 > size) return Status::NeedMoreData;
                    b = static_cast<int16_t>(
                        static_cast<uint16_t>(data[pos]) |
                        (static_cast<uint16_t>(data[pos + 1]) << 8));
                    pos += 2;
                }
            }
            out.bounds_left = l;
            out.bounds_top = t;
            out.bounds_right = r;
            out.bounds_bottom = b;
            out.has_bounds = true;
            state.bounds_left = l;
            state.bounds_top = t;
            state.bounds_right = r;
            state.bounds_bottom = b;
        }
    }

    consumed = pos;
    return Status::Ok;
}

Status ReadCoordField(const uint8_t* data, size_t size, bool delta,
                      int16_t previous, int16_t& value, size_t& consumed) {
    consumed = 0;
    if (data == nullptr || size < 1) return Status::NeedMoreData;
    if (delta) {
        value = static_cast<int16_t>(
            previous + static_cast<int16_t>(static_cast<int8_t>(data[0])));
        consumed = 1;
        return Status::Ok;
    }
    if (size < 2) return Status::NeedMoreData;
    value = static_cast<int16_t>(static_cast<uint16_t>(data[0]) |
                                 (static_cast<uint16_t>(data[1]) << 8));
    consumed = 2;
    return Status::Ok;
}

namespace {

// True when field `index` is present in the parsed fieldFlags.
bool FieldPresent(const OrderHeader& h, int index) {
    return (h.field_flags[index / 8] &
            static_cast<uint8_t>(1u << (index % 8))) != 0;
}

// Reads a coordinate field when present; otherwise reuses `previous`.
Status ReadCoordIfPresent(const uint8_t* data, size_t size, bool present,
                          bool delta, int& previous, int& value,
                          size_t& consumed) {
    consumed = 0;
    if (!present) {
        value = previous;
        return Status::Ok;
    }
    int16_t v = 0;
    size_t used = 0;
    Status s = ReadCoordField(data, size, delta, static_cast<int16_t>(previous), v,
                              used);
    if (s != Status::Ok) return s;
    value = v;
    previous = v;
    consumed = used;
    return Status::Ok;
}

// Reads a 1-byte field when present; otherwise reuses `previous`.
Status ReadByteIfPresent(const uint8_t* data, size_t size, bool present,
                         uint8_t& previous, uint8_t& value, size_t& consumed) {
    consumed = 0;
    if (!present) {
        value = previous;
        return Status::Ok;
    }
    if (size < 1) return Status::NeedMoreData;
    value = data[0];
    previous = value;
    consumed = 1;
    return Status::Ok;
}

}  // namespace

Status ParseDstBltBody(const OrderHeader& header, const uint8_t* data,
                       size_t size, OrderBodyState& state, DstBltOrder& out,
                       size_t& consumed) {
    consumed = 0;
    out = DstBltOrder{};
    const bool delta = (header.control_flags & TS_DELTA_COORDINATES) != 0;
    size_t pos = 0;
    int* prev[4] = {&state.dstblt_left, &state.dstblt_top, &state.dstblt_width,
                    &state.dstblt_height};
    int vals[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        size_t used = 0;
        Status s = ReadCoordIfPresent(data + pos, size - pos,
                                      FieldPresent(header, i), delta, *prev[i],
                                      vals[i], used);
        if (s != Status::Ok) return s;
        pos += used;
    }
    out.n_left = vals[0];
    out.n_top = vals[1];
    out.n_width = vals[2];
    out.n_height = vals[3];
    size_t used = 0;
    Status s = ReadByteIfPresent(data + pos, size - pos, FieldPresent(header, 4),
                                 state.dstblt_rop, out.b_rop, used);
    if (s != Status::Ok) return s;
    pos += used;
    consumed = pos;
    return Status::Ok;
}

Status ParseOpaqueRectBody(const OrderHeader& header, const uint8_t* data,
                           size_t size, OrderBodyState& state,
                           OpaqueRectOrder& out, size_t& consumed) {
    consumed = 0;
    out = OpaqueRectOrder{};
    const bool delta = (header.control_flags & TS_DELTA_COORDINATES) != 0;
    size_t pos = 0;
    int* prev[4] = {&state.opaque_left, &state.opaque_top, &state.opaque_width,
                    &state.opaque_height};
    int vals[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        size_t used = 0;
        Status s = ReadCoordIfPresent(data + pos, size - pos,
                                      FieldPresent(header, i), delta, *prev[i],
                                      vals[i], used);
        if (s != Status::Ok) return s;
        pos += used;
    }
    out.n_left = vals[0];
    out.n_top = vals[1];
    out.n_width = vals[2];
    out.n_height = vals[3];
    uint8_t* cprev[3] = {&state.opaque_red, &state.opaque_green,
                         &state.opaque_blue};
    uint8_t* cval[3] = {&out.red, &out.green, &out.blue};
    for (int i = 0; i < 3; ++i) {
        size_t used = 0;
        Status s = ReadByteIfPresent(data + pos, size - pos,
                                     FieldPresent(header, 4 + i), *cprev[i],
                                     *cval[i], used);
        if (s != Status::Ok) return s;
        pos += used;
    }
    consumed = pos;
    return Status::Ok;
}

Status ParseScrBltBody(const OrderHeader& header, const uint8_t* data,
                       size_t size, OrderBodyState& state, ScrBltOrder& out,
                       size_t& consumed) {
    consumed = 0;
    out = ScrBltOrder{};
    const bool delta = (header.control_flags & TS_DELTA_COORDINATES) != 0;
    size_t pos = 0;
    int* prev[4] = {&state.scr_left, &state.scr_top, &state.scr_width,
                    &state.scr_height};
    int vals[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        size_t used = 0;
        Status s = ReadCoordIfPresent(data + pos, size - pos,
                                      FieldPresent(header, i), delta, *prev[i],
                                      vals[i], used);
        if (s != Status::Ok) return s;
        pos += used;
    }
    out.n_left = vals[0];
    out.n_top = vals[1];
    out.n_width = vals[2];
    out.n_height = vals[3];
    size_t used = 0;
    Status s = ReadByteIfPresent(data + pos, size - pos, FieldPresent(header, 4),
                                 state.scr_rop, out.b_rop, used);
    if (s != Status::Ok) return s;
    pos += used;
    int* sprev[2] = {&state.scr_x_src, &state.scr_y_src};
    int svals[2] = {0, 0};
    for (int i = 0; i < 2; ++i) {
        size_t u = 0;
        Status st = ReadCoordIfPresent(data + pos, size - pos,
                                       FieldPresent(header, 5 + i), delta,
                                       *sprev[i], svals[i], u);
        if (st != Status::Ok) return st;
        pos += u;
    }
    out.n_x_src = svals[0];
    out.n_y_src = svals[1];
    consumed = pos;
    return Status::Ok;
}

Status ParsePatBltBody(const OrderHeader& header, const uint8_t* data,
                       size_t size, OrderBodyState& state, PatBltOrder& out,
                       size_t& consumed) {
    consumed = 0;
    out = PatBltOrder{};
    const bool delta = (header.control_flags & TS_DELTA_COORDINATES) != 0;
    size_t pos = 0;
    int* prev[4] = {&state.patblt_left, &state.patblt_top, &state.patblt_width,
                    &state.patblt_height};
    int vals[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        size_t used = 0;
        Status s = ReadCoordIfPresent(data + pos, size - pos,
                                      FieldPresent(header, i), delta, *prev[i],
                                      vals[i], used);
        if (s != Status::Ok) return s;
        pos += used;
    }
    out.n_left = vals[0];
    out.n_top = vals[1];
    out.n_width = vals[2];
    out.n_height = vals[3];

    size_t used = 0;
    Status s = ReadByteIfPresent(data + pos, size - pos, FieldPresent(header, 4),
                                 state.patblt_rop, out.b_rop, used);
    if (s != Status::Ok) return s;
    pos += used;

    // BackColor (field 5) then ForeColor (field 6), each R/G/B.
    uint8_t* cols[6] = {&out.back_red, &out.back_green, &out.back_blue,
                        &out.fore_red,  &out.fore_green, &out.fore_blue};
    uint8_t* cprev[6] = {&state.patblt_back_red, &state.patblt_back_green,
                         &state.patblt_back_blue, &state.patblt_fore_red,
                         &state.patblt_fore_green, &state.patblt_fore_blue};
    for (int i = 0; i < 6; ++i) {
        size_t u = 0;
        Status st = ReadByteIfPresent(data + pos, size - pos,
                                      FieldPresent(header, 5 + (i / 3)),
                                      *cprev[i], *cols[i], u);
        if (st != Status::Ok) return st;
        pos += u;
    }

    uint8_t org[2] = {state.patblt_brush_org_x, state.patblt_brush_org_y};
    for (int i = 0; i < 2; ++i) {
        size_t u = 0;
        Status st = ReadByteIfPresent(data + pos, size - pos,
                                      FieldPresent(header, 7 + i), org[i],
                                      org[i], u);
        if (st != Status::Ok) return st;
        pos += u;
    }
    out.brush_org_x = static_cast<int8_t>(org[0]);
    out.brush_org_y = static_cast<int8_t>(org[1]);
    state.patblt_brush_org_x = org[0];
    state.patblt_brush_org_y = org[1];

    uint8_t style = state.patblt_brush_style;
    size_t u = 0;
    Status st = ReadByteIfPresent(data + pos, size - pos,
                                  FieldPresent(header, 9),
                                  state.patblt_brush_style, style, u);
    if (st != Status::Ok) return st;
    pos += u;
    out.brush_style = style;

    uint8_t hatch = state.patblt_brush_hatch;
    u = 0;
    st = ReadByteIfPresent(data + pos, size - pos, FieldPresent(header, 10),
                           state.patblt_brush_hatch, hatch, u);
    if (st != Status::Ok) return st;
    pos += u;
    out.brush_hatch = hatch;

    // BrushExtra is present if and only if BrushStyle == BS_PATTERN.
    const bool extra_present = FieldPresent(header, 11);
    if (extra_present != (style == BS_PATTERN)) return Status::InvalidField;
    if (extra_present) {
        if (pos + 7 > size) return Status::NeedMoreData;
        for (int i = 0; i < 7; ++i) out.brush_extra[i] = data[pos + i];
        pos += 7;
    }

    consumed = pos;
    return Status::Ok;
}

}  // namespace rtsc::proto
