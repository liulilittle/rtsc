// Bitmap decoding ([MS-RDPBCGR] 2.2.9.1.1.3.1.2).

#include "rtsc/proto/bitmap.h"

#include <cstring>

namespace rtsc::proto {

Status BitmapCompressedHeader::parse(const uint8_t* data, size_t size,
                                     BitmapCompressedHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ByteReader r(data, size);
    r.u16le(out.first_row_size);
    r.u16le(out.main_body_size);
    r.u16le(out.scan_width);
    r.u16le(out.uncompressed_size);
    return Status::Ok;
}

namespace {

uint8_t Scale5(uint8_t v) { return static_cast<uint8_t>((v << 3) | (v >> 2)); }
uint8_t Scale6(uint8_t v) { return static_cast<uint8_t>((v << 2) | (v >> 4)); }

// Converts one raw pixel (bp bytes) to RGBA8888 using the bpp-specific layout.
void PixelToRgba(const uint8_t* s, uint16_t bpp,
                 const std::vector<uint8_t>* palette, uint8_t* dst) {
    dst[3] = 0xFF;
    switch (bpp) {
        case 8: {
            const size_t idx = static_cast<size_t>(s[0]) * 3;
            dst[0] = (*palette)[idx];
            dst[1] = (*palette)[idx + 1];
            dst[2] = (*palette)[idx + 2];
            break;
        }
        case 15: {
            const uint16_t v = static_cast<uint16_t>(s[0] | (s[1] << 8));
            dst[0] = Scale5(static_cast<uint8_t>((v >> 10) & 0x1F));
            dst[1] = Scale5(static_cast<uint8_t>((v >> 5) & 0x1F));
            dst[2] = Scale5(static_cast<uint8_t>(v & 0x1F));
            break;
        }
        case 16: {
            const uint16_t v = static_cast<uint16_t>(s[0] | (s[1] << 8));
            dst[0] = Scale5(static_cast<uint8_t>((v >> 11) & 0x1F));
            dst[1] = Scale6(static_cast<uint8_t>((v >> 5) & 0x3F));
            dst[2] = Scale5(static_cast<uint8_t>(v & 0x1F));
            break;
        }
        default:  // 24 / 32 bpp are BGR(A) on the wire
            dst[0] = s[2];
            dst[1] = s[1];
            dst[2] = s[0];
            break;
    }
}

size_t BytesPerPixel(uint16_t bpp) {
    if (bpp == 8) return 1;
    if (bpp == 24) return 3;
    if (bpp == 32) return 4;
    return 2;  // 15 / 16
}

uint32_t GetPix(const uint8_t* p, size_t bp) {
    uint32_t v = 0;
    for (size_t i = 0; i < bp; ++i) {
        v |= static_cast<uint32_t>(p[i]) << (8 * i);
    }
    return v;
}

void SetPix(uint8_t* p, size_t bp, uint32_t v) {
    for (size_t i = 0; i < bp; ++i) {
        p[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
    }
}

// Converts a bottom-up raw pixel buffer to a top-down RGBA bitmap.
void ConvertToRgba(const std::vector<uint8_t>& buf, uint16_t width,
                   uint16_t height, uint16_t bpp,
                   const std::vector<uint8_t>* palette, DecodedBitmap& out) {
    const size_t bp = BytesPerPixel(bpp);
    out.width = width;
    out.height = height;
    out.pixels.assign(static_cast<size_t>(width) * height * 4, 0xFF);
    for (size_t y = 0; y < height; ++y) {
        const uint8_t* src = buf.data() + y * width * bp;
        uint8_t* dst = out.pixels.data() +
                       (static_cast<size_t>(height) - 1 - y) *
                           static_cast<size_t>(width) * 4;
        for (size_t x = 0; x < width; ++x) {
            PixelToRgba(src + x * bp, bpp, palette, dst + x * 4);
        }
    }
}

}  // namespace

Status DecodeRawBitmap(const uint8_t* data, size_t size, uint16_t width,
                       uint16_t height, uint16_t bits_per_pixel,
                       DecodedBitmap& out,
                       const std::vector<uint8_t>* palette) {
    if (data == nullptr || width == 0 || height == 0) {
        return Status::InvalidField;
    }

    size_t bytes_per_pixel = 0;
    switch (bits_per_pixel) {
        case 8: bytes_per_pixel = 1; break;
        case 15:
        case 16: bytes_per_pixel = 2; break;
        case 24: bytes_per_pixel = 3; break;
        case 32: bytes_per_pixel = 4; break;
        default: return Status::InvalidField;
    }
    if (bits_per_pixel == 8 && (palette == nullptr || palette->size() < 768)) {
        return Status::InvalidField;
    }

    const size_t row_bytes = static_cast<size_t>(width) * bytes_per_pixel;
    const size_t stride = (row_bytes + 3) & ~static_cast<size_t>(3);  // 4-byte rows
    if (size < stride * height) return Status::NeedMoreData;

    // Re-pack into a tight buffer so the shared converter can be used.
    std::vector<uint8_t> buf(static_cast<size_t>(width) * height * bytes_per_pixel);
    for (size_t y = 0; y < height; ++y) {
        std::memcpy(buf.data() + y * width * bytes_per_pixel, data + y * stride,
                    row_bytes);
    }
    ConvertToRgba(buf, width, height, bits_per_pixel, palette, out);
    return Status::Ok;
}

namespace {

struct RleReader {
    const uint8_t* data;
    size_t size;
    size_t pos = 0;
    bool ok = true;

    uint8_t u8() {
        if (pos >= size) { ok = false; return 0; }
        return data[pos++];
    }
    uint16_t u16() {
        if (pos + 2 > size) { ok = false; return 0; }
        const uint16_t v = static_cast<uint16_t>(data[pos] | (data[pos + 1] << 8));
        pos += 2;
        return v;
    }
    uint32_t pixel(size_t bp) {
        if (pos + bp > size) { ok = false; return 0; }
        const uint32_t v = GetPix(data + pos, bp);
        pos += bp;
        return v;
    }
};

}  // namespace

Status DecodeRleBitmap(const uint8_t* data, size_t size, uint16_t width,
                       uint16_t height, uint16_t bits_per_pixel,
                       DecodedBitmap& out,
                       const std::vector<uint8_t>* palette) {
    if (data == nullptr || width == 0 || height == 0) return Status::InvalidField;
    if (bits_per_pixel != 8 && bits_per_pixel != 15 && bits_per_pixel != 16 &&
        bits_per_pixel != 24) {
        return Status::InvalidField;  // 32 bpp uses RDP 6.0 compression
    }
    if (bits_per_pixel == 8 && (palette == nullptr || palette->size() < 768)) {
        return Status::InvalidField;
    }

    const size_t bp = BytesPerPixel(bits_per_pixel);
    const size_t total = static_cast<size_t>(width) * height;
    std::vector<uint8_t> buf(total * bp, 0);

    const uint32_t white = (bits_per_pixel == 8)   ? 0xFFu
                           : (bits_per_pixel == 15) ? 0x7FFFu
                           : (bits_per_pixel == 16) ? 0xFFFFu
                                                    : 0xFFFFFFu;
    uint32_t fg = white;

    RleReader r{data, size};

    // The run length is a pixel count and a run may cross scanline boundaries
    // ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.4), so every order fills a linear pixel
    // index `i` over the whole bitmap rather than being clamped to one row. A
    // background/foreground order refers to the pixel directly above (i - width)
    // when the current pixel is not on the first scanline.
    auto set_px = [&](size_t i, uint32_t c) {
        SetPix(buf.data() + i * bp, bp, c);
    };
    auto get_px = [&](size_t i) { return GetPix(buf.data() + i * bp, bp); };

    auto do_bg = [&](size_t& i, uint32_t run, bool first_line) {
        for (uint32_t k = 0; k < run && i < total; ++k, ++i) {
            set_px(i, first_line ? 0u : get_px(i - width));
        }
    };
    auto do_fg = [&](size_t& i, uint32_t run, bool first_line) {
        for (uint32_t k = 0; k < run && i < total; ++k, ++i) {
            set_px(i, first_line ? fg : (get_px(i - width) ^ fg));
        }
    };
    auto do_color_run = [&](size_t& i, uint32_t run, uint32_t color) {
        for (uint32_t k = 0; k < run && i < total; ++k, ++i) set_px(i, color);
    };
    auto do_color_image = [&](size_t& i, uint32_t run) {
        for (uint32_t k = 0; k < run && i < total; ++k, ++i) {
            if (r.pos + bp > r.size) { r.ok = false; return; }
            std::memcpy(buf.data() + i * bp, r.data + r.pos, bp);
            r.pos += bp;
        }
    };
    auto do_dither = [&](size_t& i, uint32_t run, uint32_t c1, uint32_t c2) {
        for (uint32_t k = 0; k < run; ++k) {  // run = pixel pairs
            if (i < total) set_px(i, c1);
            ++i;
            if (i < total) set_px(i, c2);
            ++i;
        }
    };
    // Writes `count` pixels of a foreground/background image from one mask
    // byte (bit 0 is the leftmost pixel). On the first scanline the background
    // is black and the foreground is the current fgPel; afterwards both are
    // copied/XORed from the pixel directly above. The first-line decision is
    // fixed once per order, as in the reference decompressor.
    auto apply_fgbg = [&](size_t& i, uint32_t count, uint8_t mask,
                          bool first_line) {
        for (uint32_t bit = 0; bit < count && i < total; ++bit, ++i) {
            const bool set = (mask & (1u << bit)) != 0;
            if (first_line) {
                set_px(i, set ? fg : 0u);
            } else {
                set_px(i, set ? (get_px(i - width) ^ fg) : get_px(i - width));
            }
        }
    };
    auto do_fgbg = [&](size_t& i, uint32_t run, bool first_line) {
        uint32_t written = 0;
        while (written < run && r.ok) {
            if (r.pos >= r.size) { r.ok = false; return; }
            const uint8_t mask = r.data[r.pos++];
            const uint32_t remaining = run - written;
            const uint32_t n = remaining > 8 ? 8 : remaining;
            apply_fgbg(i, n, mask, first_line);
            written += n;
            if (i >= total) return;
        }
    };

    // The reference decompressor decides "first line" and the foreground
    // insertion state at order boundaries, because a run may cross scanline
    // boundaries. A background run is followed by a one-pixel foreground run
    // when the next order is also a background run, except when the first run
    // ended on the first scanline and the second starts on the next one.
    bool first_line = true;
    bool insert_fg = false;

    size_t i = 0;
    while (i < total && r.ok) {
        if (first_line && i >= width) {
            first_line = false;
            insert_fg = false;
        }
        const uint8_t h = r.u8();
        if (!r.ok) break;

        if (h == 0xF0) {  // MEGA_MEGA_BG_RUN
            uint32_t run = r.u16();
            if (insert_fg && i < total) {
                set_px(i, first_line ? fg : (get_px(i - width) ^ fg));
                ++i;
                if (run > 0) --run;
            }
            do_bg(i, run, first_line);
            insert_fg = true;
        } else if (h == 0xF1) {  // MEGA_MEGA_FG_RUN
            do_fg(i, r.u16(), first_line);
            insert_fg = false;
        } else if (h == 0xF2) {  // MEGA_MEGA_FGBG_IMAGE
            do_fgbg(i, r.u16(), first_line);
            insert_fg = false;
        } else if (h == 0xF3) {  // MEGA_MEGA_COLOR_RUN
            const uint32_t run = r.u16();
            do_color_run(i, run, r.pixel(bp));
            insert_fg = false;
        } else if (h == 0xF4) {  // MEGA_MEGA_COLOR_IMAGE
            do_color_image(i, r.u16());
            insert_fg = false;
        } else if (h == 0xF6) {  // MEGA_MEGA_SET_FG_RUN
            const uint32_t run = r.u16();
            fg = r.pixel(bp);
            do_fg(i, run, first_line);
            insert_fg = false;
        } else if (h == 0xF7) {  // MEGA_MEGA_SET_FGBG_IMAGE
            const uint32_t run = r.u16();
            fg = r.pixel(bp);
            do_fgbg(i, run, first_line);
            insert_fg = false;
        } else if (h == 0xF8) {  // MEGA_MEGA_DITHERED_RUN
            const uint32_t run = r.u16();
            const uint32_t c1 = r.pixel(bp);
            const uint32_t c2 = r.pixel(bp);
            do_dither(i, run, c1, c2);
            insert_fg = false;
        } else if (h == 0xF9) {  // SPECIAL_FGBG_1: implicit mask 0x03
            apply_fgbg(i, 8, 0x03, first_line);
            insert_fg = false;
        } else if (h == 0xFA) {  // SPECIAL_FGBG_2: implicit mask 0x05
            apply_fgbg(i, 8, 0x05, first_line);
            insert_fg = false;
        } else if (h == 0xFD) {  // WHITE
            if (i < total) { set_px(i, white); ++i; }
            insert_fg = false;
        } else if (h == 0xFE) {  // BLACK
            if (i < total) { set_px(i, 0); ++i; }
            insert_fg = false;
        } else if ((h & 0xF0) == 0xE0) {  // LITE_DITHERED_RUN
            uint32_t run = h & 0x0F;
            if (run == 0) run = static_cast<uint32_t>(r.u8()) + 16;
            const uint32_t c1 = r.pixel(bp);
            const uint32_t c2 = r.pixel(bp);
            do_dither(i, run, c1, c2);
            insert_fg = false;
        } else if ((h & 0xF0) == 0xD0) {  // LITE_SET_FG_FGBG_IMAGE
            uint32_t run = (h & 0x0F) * 8;
            if (run == 0) run = static_cast<uint32_t>(r.u8()) + 1;
            fg = r.pixel(bp);
            do_fgbg(i, run, first_line);
            insert_fg = false;
        } else if ((h & 0xF0) == 0xC0) {  // LITE_SET_FG_FG_RUN
            uint32_t run = h & 0x0F;
            if (run == 0) run = static_cast<uint32_t>(r.u8()) + 16;
            fg = r.pixel(bp);
            do_fg(i, run, first_line);
            insert_fg = false;
        } else {
            const uint8_t code = h >> 5;  // regular form, 3-bit code
            const uint32_t run5 = h & 0x1F;
            switch (code) {
                case 0x0: {  // REGULAR_BG_RUN
                    uint32_t run =
                        run5 ? run5 : static_cast<uint32_t>(r.u8()) + 32;
                    if (insert_fg && i < total) {
                        set_px(i, first_line ? fg : (get_px(i - width) ^ fg));
                        ++i;
                        if (run > 0) --run;
                    }
                    do_bg(i, run, first_line);
                    insert_fg = true;
                    break;
                }
                case 0x1:  // REGULAR_FG_RUN
                    do_fg(i, run5 ? run5 : static_cast<uint32_t>(r.u8()) + 32,
                          first_line);
                    insert_fg = false;
                    break;
                case 0x2:  // REGULAR_FGBG_IMAGE
                    do_fgbg(i, run5 ? run5 * 8
                                    : static_cast<uint32_t>(r.u8()) + 1,
                            first_line);
                    insert_fg = false;
                    break;
                case 0x3: {  // REGULAR_COLOR_RUN
                    const uint32_t run =
                        run5 ? run5 : static_cast<uint32_t>(r.u8()) + 32;
                    do_color_run(i, run, r.pixel(bp));
                    insert_fg = false;
                    break;
                }
                case 0x4:  // REGULAR_COLOR_IMAGE
                    do_color_image(i, run5 ? run5
                                           : static_cast<uint32_t>(r.u8()) + 32);
                    insert_fg = false;
                    break;
                default:
                    return Status::InvalidField;  // unknown order
            }
        }
    }

    if (!r.ok) return Status::NeedMoreData;

    ConvertToRgba(buf, width, height, bits_per_pixel, palette, out);
    return Status::Ok;
}

}  // namespace rtsc::proto
