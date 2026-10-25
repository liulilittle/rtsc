// Server fast-path output updates ([MS-RDPBCGR] 2.2.9.1.2).

#include "rtsc/proto/output.h"

namespace rtsc::proto {

const char* to_string(FastPathUpdateCode code) {
    switch (code) {
        case FastPathUpdateCode::kOrders: return "orders";
        case FastPathUpdateCode::kBitmap: return "bitmap";
        case FastPathUpdateCode::kPalette: return "palette";
        case FastPathUpdateCode::kSynchronize: return "synchronize";
        case FastPathUpdateCode::kSurfaceCommands: return "surface-commands";
        case FastPathUpdateCode::kPtrNull: return "pointer-null";
        case FastPathUpdateCode::kPtrDefault: return "pointer-default";
        case FastPathUpdateCode::kPtrPosition: return "pointer-position";
        case FastPathUpdateCode::kColorPointer: return "color-pointer";
        case FastPathUpdateCode::kCachedPointer: return "cached-pointer";
        case FastPathUpdateCode::kPointer: return "pointer";
        case FastPathUpdateCode::kLargePointer: return "large-pointer";
    }
    return "unknown";
}

namespace {

// Parses one TS_FP_UPDATE and reports the bytes consumed. A zero-length update
// is legal (synchronize, pointer hide/default).
Status ParseUpdate(const uint8_t* data, size_t size, FastPathUpdate& out,
                   size_t& consumed) {
    if (data == nullptr || size < 1) return Status::NeedMoreData;
    const uint8_t h = data[0];
    out.code = static_cast<FastPathUpdateCode>(h & 0x0F);
    out.fragmentation = static_cast<FastPathFragmentation>((h >> 4) & 0x03);
    out.compression = static_cast<uint8_t>((h >> 6) & 0x03);

    size_t pos = 1;
    if (out.compression == 0x2) {
        if (pos >= size) return Status::NeedMoreData;
        out.has_compression_flags = true;
        out.compression_flags = data[pos++];
    }

    if (pos + 2 > size) return Status::NeedMoreData;
    const uint16_t len = static_cast<uint16_t>(data[pos]) |
                         (static_cast<uint16_t>(data[pos + 1]) << 8);
    pos += 2;

    if (pos + len > size) return Status::NeedMoreData;
    out.data.assign(data + pos, data + pos + len);
    pos += len;
    consumed = pos;
    return Status::Ok;
}

}  // namespace

Status FastPathOutputPdu::parse(const uint8_t* data, size_t size,
                                FastPathOutputPdu& out) {
    out.updates.clear();
    if (data == nullptr || size < 2) return Status::NeedMoreData;

    FastPathHeader hdr;
    Status s = FastPathHeader::parse(data, size, /*input=*/false, hdr);
    if (s != Status::Ok) return s;
    if (hdr.action != FastPathAction::kFastPath) return Status::InvalidType;
    out.flags = hdr.flags;

    FastPathLength len;
    s = FastPathLength::parse(data + 1, size - 1, len);
    if (s != Status::Ok) return s;
    const size_t len_bytes = len.two_byte ? 2 : 1;
    if (len.value < 1 + len_bytes || len.value > size) {
        return Status::InvalidLength;
    }

    size_t pos = 1 + len_bytes;
    while (pos < len.value) {
        FastPathUpdate up;
        size_t consumed = 0;
        s = ParseUpdate(data + pos, len.value - pos, up, consumed);
        if (s != Status::Ok) return s;
        if (consumed == 0) return Status::InvalidLength;  // cannot advance
        out.updates.push_back(std::move(up));
        pos += consumed;
    }
    return Status::Ok;
}

Status UpdateBitmapData::parse(const uint8_t* data, size_t size,
                               UpdateBitmapData& out) {
    out.rectangles.clear();
    if (data == nullptr || size < 4) return Status::NeedMoreData;

    ByteReader r(data, size);
    uint16_t update_type = 0;
    if (!r.u16le(update_type)) return Status::NeedMoreData;
    if (update_type != 0x0001) return Status::InvalidType;  // UPDATETYPE_BITMAP
    if (!r.u16le(out.number_rectangles)) return Status::NeedMoreData;

    for (uint16_t i = 0; i < out.number_rectangles; ++i) {
        if (r.remaining() < BitmapData::kHeaderSize) return Status::NeedMoreData;
        BitmapData bd;
        r.u16le(bd.dest_left);
        r.u16le(bd.dest_top);
        r.u16le(bd.dest_right);
        r.u16le(bd.dest_bottom);
        r.u16le(bd.width);
        r.u16le(bd.height);
        r.u16le(bd.bits_per_pixel);
        r.u16le(bd.flags);
        r.u16le(bd.bitmap_length);
        if (r.remaining() < bd.bitmap_length) return Status::NeedMoreData;
        bd.bitmap_data.assign(r.cursor(), r.cursor() + bd.bitmap_length);
        if (!r.skip(bd.bitmap_length)) return Status::NeedMoreData;
        out.rectangles.push_back(std::move(bd));
    }
    return Status::Ok;
}

Status UpdatePaletteData::parse(const uint8_t* data, size_t size,
                                UpdatePaletteData& out) {
    out.entries.clear();
    if (data == nullptr || size < 8) return Status::NeedMoreData;

    ByteReader r(data, size);
    uint16_t update_type = 0;
    if (!r.u16le(update_type)) return Status::NeedMoreData;
    if (update_type != 0x0002) return Status::InvalidType;  // UPDATETYPE_PALETTE
    uint16_t pad = 0;
    r.u16le(pad);
    if (!r.u16le(out.number_colors)) return Status::NeedMoreData;

    const size_t need = static_cast<size_t>(out.number_colors) * 3;
    if (r.remaining() < need) return Status::NeedMoreData;
    out.entries.assign(r.cursor(), r.cursor() + need);
    if (!r.skip(need)) return Status::NeedMoreData;
    return Status::Ok;
}

Status SlowPathGraphicsUpdate::parse(const uint8_t* data, size_t size,
                                     SlowPathGraphicsUpdate& out) {
    out.update_data.clear();
    if (data == nullptr || size < ShareDataHeader::kSize + 2) {
        return Status::NeedMoreData;
    }

    ShareDataHeader hdr;
    Status s = ShareDataHeader::parse(data, size, hdr);
    if (s != Status::Ok) return s;
    if (hdr.pdu_type2 != ShareDataPduType::kUpdate) return Status::InvalidType;

    ByteReader r(data + ShareDataHeader::kSize,
                 size - ShareDataHeader::kSize);
    if (!r.u16le(out.update_type)) return Status::NeedMoreData;
    out.update_data.assign(r.cursor(), r.cursor() + r.remaining());
    return Status::Ok;
}

}  // namespace rtsc::proto
