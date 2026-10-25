// NSCodec compressed bitmap stream ([MS-RDPNSC] 2.2.2 / 3.1.8).

#include "rtsc/proto/nsc.h"

#include <cstring>

namespace rtsc::proto {

Status NscHeader::parse(const uint8_t* data, size_t size, NscHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ByteReader r(data, size);
    for (int i = 0; i < 4; ++i) r.u32le(out.plane_byte_count[i]);
    r.u8(out.color_loss_level);
    r.u8(out.chroma_subsampling_level);
    // 2 reserved bytes follow.
    return Status::Ok;
}

Status NscRleDecode(const uint8_t* data, size_t size, uint8_t* out,
                    size_t out_size, size_t original_size) {
    if (data == nullptr || out == nullptr) return Status::InvalidField;

    size_t in_pos = 0;
    size_t out_pos = 0;
    size_t left = original_size;

    while (left > 4) {
        if (in_pos >= size) return Status::NeedMoreData;
        const uint8_t value = data[in_pos++];

        if (left == 5) {
            if (out_pos >= out_size) return Status::InvalidLength;
            out[out_pos++] = value;
            --left;
        } else if (in_pos >= size) {
            return Status::NeedMoreData;
        } else if (value == data[in_pos]) {
            // Run: the same byte twice introduces a length.
            ++in_pos;
            if (in_pos >= size) return Status::NeedMoreData;
            uint32_t len = 0;
            if (data[in_pos] < 0xFF) {
                len = static_cast<uint32_t>(data[in_pos++]) + 2;
            } else {
                if (in_pos + 5 > size) return Status::NeedMoreData;
                ++in_pos;  // skip the 0xFF marker
                len = static_cast<uint32_t>(data[in_pos]) |
                      (static_cast<uint32_t>(data[in_pos + 1]) << 8) |
                      (static_cast<uint32_t>(data[in_pos + 2]) << 16) |
                      (static_cast<uint32_t>(data[in_pos + 3]) << 24);
                in_pos += 4;
            }
            if (out_pos + len > out_size || left < len) {
                return Status::InvalidLength;
            }
            std::memset(out + out_pos, value, len);
            out_pos += len;
            left -= len;
        } else {
            if (out_pos >= out_size) return Status::InvalidLength;
            out[out_pos++] = value;
            --left;
        }
    }

    if (out_pos + 4 > out_size || left < 4) return Status::InvalidLength;
    if (in_pos + 4 > size) return Status::NeedMoreData;
    std::memcpy(out + out_pos, data + in_pos, 4);
    return Status::Ok;
}

namespace {

uint8_t ClampByte(int v) {
    if (v < 0) return 0;
    if (v > 255) return 255;
    return static_cast<uint8_t>(v);
}

uint16_t RoundUp(uint16_t v, uint16_t align) {
    return static_cast<uint16_t>((v + align - 1) / align * align);
}

}  // namespace

Status NscDecodeBitmap(const uint8_t* data, size_t size, uint16_t width,
                       uint16_t height, DecodedBitmap& out) {
    if (data == nullptr || width == 0 || height == 0) {
        return Status::InvalidField;
    }

    NscHeader h;
    Status s = NscHeader::parse(data, size, h);
    if (s != Status::Ok) return s;
    if (h.color_loss_level < 1 || h.color_loss_level > 7) {
        return Status::InvalidField;
    }
    const uint16_t cs = h.chroma_subsampling_level;

    // The luma plane stride is rounded up to 8 (and its height to 2).
    const uint16_t rw = RoundUp(width, 8);
    const uint16_t rh = RoundUp(height, 2);

    // Per-plane decoded sizes, in stream order Y, Co, Cg, A.
    size_t org[4];
    org[3] = static_cast<size_t>(width) * height;
    if (cs) {
        org[0] = static_cast<size_t>(rw) * height;
        org[1] = static_cast<size_t>(rw >> 1) * (rh >> 1);
        org[2] = org[1];
    } else {
        org[0] = static_cast<size_t>(width) * height;
        org[1] = org[0];
        org[2] = org[0];
    }

    const size_t cap = static_cast<size_t>(rw) * rh;
    std::vector<uint8_t> planes[4];
    for (int i = 0; i < 4; ++i) planes[i].assign(cap, 0);

    size_t pos = NscHeader::kSize;
    for (int i = 0; i < 4; ++i) {
        const uint32_t plane_size = h.plane_byte_count[i];
        if (pos + plane_size > size) return Status::NeedMoreData;
        if (plane_size == 0) {
            std::memset(planes[i].data(), 0xFF, org[i]);
        } else if (plane_size < org[i]) {
            s = NscRleDecode(data + pos, plane_size, planes[i].data(), cap, org[i]);
            if (s != Status::Ok) return s;
        } else {
            if (org[i] > cap) return Status::InvalidLength;
            std::memcpy(planes[i].data(), data + pos, org[i]);
        }
        pos += plane_size;
    }

    out.width = width;
    out.height = height;
    out.pixels.assign(static_cast<size_t>(width) * height * 4, 0);

    const uint8_t shift = static_cast<uint8_t>(h.color_loss_level - 1);
    for (size_t y = 0; y < height; ++y) {
        const uint8_t* ap = planes[3].data() + y * width;
        const uint8_t* yp;
        const uint8_t* cop;
        const uint8_t* cgp;
        if (cs) {
            yp = planes[0].data() + y * rw;
            cop = planes[1].data() + (y >> 1) * (rw >> 1);
            cgp = planes[2].data() + (y >> 1) * (rw >> 1);
        } else {
            yp = planes[0].data() + y * width;
            cop = planes[1].data() + y * width;
            cgp = planes[2].data() + y * width;
        }
        for (size_t x = 0; x < width; ++x) {
            const size_t ci = cs ? x / 2 : x;
            const int16_t yv = yp[x];
            const int16_t co = static_cast<int16_t>(
                static_cast<int8_t>(static_cast<uint8_t>(cop[ci] << shift)));
            const int16_t cg = static_cast<int16_t>(
                static_cast<int8_t>(static_cast<uint8_t>(cgp[ci] << shift)));
            uint8_t* px = out.pixels.data() + (y * width + x) * 4;
            px[0] = ClampByte(yv + co - cg);  // R
            px[1] = ClampByte(yv + cg);       // G
            px[2] = ClampByte(yv - co - cg);  // B
            px[3] = ap[x];
        }
    }
    return Status::Ok;
}

}  // namespace rtsc::proto
