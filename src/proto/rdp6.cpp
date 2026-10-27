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

// Decodes one 8-bit plane: raw bytes, or an RDP6_RLE_SEGMENTS stream run
// through the per-scanline state machine.
Status DecodeRdp6Plane(const uint8_t* data, size_t size, bool rle,
                       uint16_t width, uint16_t height,
                       std::vector<uint8_t>& out, size_t& consumed) {
    consumed = 0;
    const size_t plane_size = static_cast<size_t>(width) * height;
    if (!rle) {
        if (size < plane_size) return Status::NeedMoreData;
        out.assign(plane_size, 0);
        // Bottom-up: the first stream scanline is the BOTTOM image row
        // (FreeRDP planar_decompress passes vFlip=TRUE for bitmap updates;
        // its own compressor walks source rows bottom-up).
        for (uint16_t s = 0; s < height; ++s) {
            const uint8_t* src_row = data + static_cast<size_t>(s) * width;
            uint8_t* dst_row =
                out.data() + static_cast<size_t>(height - 1 - s) * width;
            std::memcpy(dst_row, src_row, width);
        }
        consumed = plane_size;
        return Status::Ok;
    }

    // Per-scanline state machine ([MS-RDPEGDI] 2.2.2.5.1.2; the oracle is
    // FreeRDP's planar_decompress_plane_rle in libfreerdp/codec/planar.c).
    // NOT a whole-plane RLE stream:
    //   * row 0 carries absolute plane values;
    //   * rows >= 1 carry signed-magnitude deltas (bit 0 = sign) against the
    //     same x of the reconstructed row above: value = previous[x] + pixel;
    //   * the running `pixel` resets to 0 at every row start and persists
    //     across segments within a row: a raw byte sets it (row 0: the plane
    //     value itself, rows >= 1: the signed delta), a run repeats it, so a
    //     run with no preceding raw byte in the row fills with 0 (row 0) or
    //     with previous[x] (rows >= 1);
    //   * a segment must not cross a row boundary (FreeRDP rejects it with
    //     "too many pixels in scanline").
    out.assign(plane_size, 0);
    if (plane_size == 0) return Status::Ok;
    const uint8_t* src = data;
    const uint8_t* const end = data + size;
    const uint8_t* previous = nullptr;  // previous reconstructed scanline

    // Bottom-up: the first stream scanline is the BOTTOM image row (FreeRDP
    // planar_decompress_plane_rle runs its vFlip=TRUE branch from
    // nHeight-1 downwards for bitmap updates). The delta chain still
    // references the previous STREAM scanline, which is the image row below.
    for (uint16_t s = 0; s < height; ++s) {
        uint8_t* row =
            out.data() + static_cast<size_t>(height - 1 - s) * width;
        int pixel = 0;  // running pixel; FreeRDP resets it to 0 every scanline
        size_t x = 0;
        while (x < width) {
            if (src == end) return Status::NeedMoreData;
            const uint8_t cb = *src++;
            if (cb == 0) {
                // An empty segment can never advance the scanline: FreeRDP
                // would burn input bytes without moving x and eventually fail
                // on source exhaustion. Failing fast keeps InvalidField for
                // the malformed stream.
                return Status::InvalidField;
            }

            // controlByte = nRunLength (low nibble) | cRawBytes (high nibble).
            // Cross-checked against FreeRDP's PLANAR_CONTROL_BYTE_* macros; the
            // spec's bitmask diagram is drawn low-bit first.
            uint32_t n_run = cb & 0x0F;
            uint32_t c_raw = (cb >> 4) & 0x0F;
            if (n_run == 1) {
                n_run = c_raw + 16;  // extended long run
                c_raw = 0;
            } else if (n_run == 2) {
                n_run = c_raw + 32;  // extended long run
                c_raw = 0;
            }
            if (x + c_raw + n_run > width) {
                return Status::InvalidField;  // segment crosses the row
            }

            if (previous == nullptr) {
                // Row 0: raw bytes are absolute values; a run repeats the
                // running pixel (0 when the segment has no raw bytes).
                for (uint32_t i = 0; i < c_raw; ++i) {
                    if (src == end) return Status::NeedMoreData;
                    pixel = *src++;
                    row[x] = static_cast<uint8_t>(pixel);
                    ++x;
                }
                for (uint32_t i = 0; i < n_run; ++i) {
                    row[x] = static_cast<uint8_t>(pixel);
                    ++x;
                }
            } else {
                // Rows >= 1: raw bytes are signed-magnitude deltas; a run
                // repeats the running delta. FreeRDP clamps via a plain cast
                // ((UINT8)(INT16)value), i.e. modulo 256, not saturation.
                for (uint32_t i = 0; i < c_raw; ++i) {
                    if (src == end) return Status::NeedMoreData;
                    const uint8_t d = *src++;
                    if (d & 1) {
                        pixel = -(static_cast<int>(d >> 1) + 1);
                    } else {
                        pixel = static_cast<int>(d >> 1);
                    }
                    row[x] = static_cast<uint8_t>(
                        static_cast<int16_t>(previous[x] + pixel));
                    ++x;
                }
                for (uint32_t i = 0; i < n_run; ++i) {
                    row[x] = static_cast<uint8_t>(
                        static_cast<int16_t>(previous[x] + pixel));
                    ++x;
                }
            }
        }
        previous = row;
    }
    consumed = static_cast<size_t>(src - data);
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
    size_t pos = 1;

    // The stream order is Alpha (optional), Luma/Red, Orange/Green, Green/Blue.
    std::vector<uint8_t> alpha;
    std::vector<uint8_t> plane0;  // Y or R
    std::vector<uint8_t> plane1;  // Co or G
    std::vector<uint8_t> plane2;  // Cg or B

    if (!h.no_alpha) {
        size_t used = 0;
        s = DecodeRdp6Plane(data + pos, size - pos, h.rle, width, height, alpha,
                            used);
        if (s != Status::Ok) return s;
        pos += used;
    } else {
        alpha.assign(plane_size, 0xFF);
    }

    const uint16_t widths[3] = {width, static_cast<uint16_t>(chroma_w),
                                static_cast<uint16_t>(chroma_w)};
    const uint16_t heights[3] = {height, static_cast<uint16_t>(chroma_h),
                                 static_cast<uint16_t>(chroma_h)};
    std::vector<uint8_t>* planes[3] = {&plane0, &plane1, &plane2};
    for (int i = 0; i < 3; ++i) {
        if (pos > size) return Status::NeedMoreData;
        size_t used = 0;
        s = DecodeRdp6Plane(data + pos, size - pos, h.rle, widths[i], heights[i],
                            *planes[i], used);
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
