// RDP 6.0 bitmap compression framing ([MS-RDPEGDI] 2.2.2.5).

#include "rtsc/proto/rdp6.h"

namespace rtsc::proto {

Status Rdp6FormatHeader::parse(uint8_t b, Rdp6FormatHeader& out) {
    out.cll = static_cast<uint8_t>(b & 0x07);
    out.chroma_subsampling = ((b >> 3) & 0x01) != 0;
    out.rle = ((b >> 4) & 0x01) != 0;
    out.no_alpha = ((b >> 5) & 0x01) != 0;
    out.reserved = static_cast<uint8_t>((b >> 6) & 0x03);
    // Chroma subsampling applies only to AYCoCg (CLL > 0).
    if (out.chroma_subsampling && out.cll == 0) return Status::InvalidField;
    return Status::Ok;
}

uint8_t Rdp6FormatHeader::encode() const {
    return static_cast<uint8_t>((cll & 0x07) | (chroma_subsampling ? 0x08 : 0) |
                                (rle ? 0x10 : 0) | (no_alpha ? 0x20 : 0) |
                                ((reserved & 0x03) << 6));
}

Status DecodeRdp6RleSegments(const uint8_t* data, size_t size, size_t count,
                             std::vector<uint8_t>& out, size_t& consumed) {
    out.clear();
    consumed = 0;
    if (data == nullptr) return Status::NeedMoreData;

    size_t pos = 0;
    while (out.size() < count) {
        if (pos >= size) return Status::NeedMoreData;
        const uint8_t cb = data[pos++];
        if (cb == 0) return Status::InvalidField;  // controlByte MUST be nonzero

        // controlByte = nRunLength (low nibble) | cRawBytes (high nibble).
        // Cross-checked against FreeRDP's PLANAR_CONTROL_BYTE_* macros; the
        // spec's bitmask diagram is drawn low-bit first.
        uint8_t n_run = static_cast<uint8_t>(cb & 0x0F);
        uint8_t c_raw = static_cast<uint8_t>((cb >> 4) & 0x0F);

        uint32_t run = 0;
        uint32_t raw = c_raw;
        if (n_run == 1) {
            run = 16u + c_raw;  // extended long run
            raw = 0;
        } else if (n_run == 2) {
            run = 32u + c_raw;  // extended long run
            raw = 0;
        } else {
            run = n_run;
        }

        if (raw > 0) {
            if (pos + raw > size) return Status::NeedMoreData;
            out.insert(out.end(), data + pos, data + pos + raw);
            pos += raw;
        }
        if (run > 0) {
            if (out.empty()) return Status::InvalidField;  // run with no base byte
            out.insert(out.end(), run, out.back());
        }
    }
    consumed = pos;
    return Status::Ok;
}

namespace {

uint8_t ClampToByte(int v) {
    if (v < 0) return 0;
    if (v > 255) return 255;
    return static_cast<uint8_t>(v);
}

// YCoCg chroma: left-shift by (CLL - 1), then read as a signed byte.
int16_t ConvertChroma(uint8_t raw, uint8_t cll) {
    const int shift = static_cast<int>(cll) - 1;
    return static_cast<int16_t>(static_cast<int8_t>(
        static_cast<uint8_t>(raw << shift)));
}

// Decodes one 8-bit plane (raw, or RLE followed by the row-delta pass).
Status DecodeRdp6Plane(const uint8_t* data, size_t size, size_t plane_size,
                       bool rle, uint16_t width, uint16_t height,
                       std::vector<uint8_t>& out, size_t& consumed) {
    consumed = 0;
    if (rle) {
        Status s = DecodeRdp6RleSegments(data, size, plane_size, out, consumed);
        if (s != Status::Ok) return s;
        // Row 0 is absolute; each later row stores a SIGNED-MAGNITUDE delta
        // relative to the reconstructed row above (bit 0 is the sign).
        for (size_t y = 1; y < height; ++y) {
            for (size_t x = 0; x < width; ++x) {
                const size_t i = y * width + x;
                const uint8_t d = out[i];
                const int delta = (d & 1) ? -static_cast<int>((d >> 1) + 1)
                                          : static_cast<int>(d >> 1);
                out[i] = static_cast<uint8_t>(out[i - width] + delta);
            }
        }
    } else {
        if (size < plane_size) return Status::NeedMoreData;
        out.assign(data, data + plane_size);
        consumed = plane_size;
    }
    return Status::Ok;
}

}  // namespace

Status DecodeRdp6Bitmap(const uint8_t* data, size_t size, uint16_t width,
                        uint16_t height, DecodedBitmap& out) {
    if (data == nullptr || width == 0 || height == 0) return Status::InvalidField;
    if (size < 1) return Status::NeedMoreData;

    Rdp6FormatHeader h;
    Status s = Rdp6FormatHeader::parse(data[0], h);
    if (s != Status::Ok) return s;

    const size_t plane_size = static_cast<size_t>(width) * height;
    const size_t chroma_w = h.chroma_subsampling ? (width + 1) / 2 : width;
    const size_t chroma_h = h.chroma_subsampling ? (height + 1) / 2 : height;
    const size_t chroma_size = chroma_w * chroma_h;
    size_t pos = 1;

    // The stream order is Alpha (optional), Luma/Red, Orange/Green, Green/Blue.
    std::vector<uint8_t> alpha;
    std::vector<uint8_t> plane0;  // Y or R
    std::vector<uint8_t> plane1;  // Co or G
    std::vector<uint8_t> plane2;  // Cg or B

    if (!h.no_alpha) {
        size_t used = 0;
        s = DecodeRdp6Plane(data + pos, size - pos, plane_size, h.rle, width,
                            height, alpha, used);
        if (s != Status::Ok) return s;
        pos += used;
    } else {
        alpha.assign(plane_size, 0xFF);
    }

    const size_t sizes[3] = {plane_size, chroma_size, chroma_size};
    const uint16_t widths[3] = {width, static_cast<uint16_t>(chroma_w),
                                static_cast<uint16_t>(chroma_w)};
    const uint16_t heights[3] = {height, static_cast<uint16_t>(chroma_h),
                                 static_cast<uint16_t>(chroma_h)};
    std::vector<uint8_t>* planes[3] = {&plane0, &plane1, &plane2};
    for (int i = 0; i < 3; ++i) {
        if (pos > size) return Status::NeedMoreData;
        size_t used = 0;
        s = DecodeRdp6Plane(data + pos, size - pos, sizes[i], h.rle, widths[i],
                            heights[i], *planes[i], used);
        if (s != Status::Ok) return s;
        pos += used;
    }

    out.width = width;
    out.height = height;
    out.pixels.assign(plane_size * 4, 0);

    if (h.cll == 0) {
        // ARGB: three colour planes map straight to R, G, B.
        for (size_t i = 0; i < plane_size; ++i) {
            out.pixels[i * 4 + 0] = plane0[i];
            out.pixels[i * 4 + 1] = plane1[i];
            out.pixels[i * 4 + 2] = plane2[i];
            out.pixels[i * 4 + 3] = alpha[i];
        }
        return Status::Ok;
    }

    // AYCoCg: expand the (possibly subsampled) chroma, then apply the inverse
    // transform. Verified against FreeRDP prim_YCoCg.c general_YCoCgToRGB.
    for (size_t y = 0; y < height; ++y) {
        for (size_t x = 0; x < width; ++x) {
            const size_t i = y * width + x;
            const size_t ci = h.chroma_subsampling
                                  ? (y / 2) * chroma_w + (x / 2)
                                  : i;
            const int16_t cg = ConvertChroma(plane2[ci], h.cll);
            const int16_t co = ConvertChroma(plane1[ci], h.cll);
            const int16_t yy = plane0[i];
            const int16_t t = static_cast<int16_t>(yy - cg);
            out.pixels[i * 4 + 0] = ClampToByte(t - co);  // R
            out.pixels[i * 4 + 1] = ClampToByte(yy + cg);  // G
            out.pixels[i * 4 + 2] = ClampToByte(t + co);  // B
            out.pixels[i * 4 + 3] = alpha[i];
        }
    }
    return Status::Ok;
}

}  // namespace rtsc::proto
