// Application of the DstBlt / OpaqueRect / ScrBlt primary drawing orders
// ([MS-RDPEGDI] 2.2.2.2.1.1.2) to a ui::Surface.

#include "rtsc/render/orders_apply.h"

#include "rtsc/proto/rop.h"
#include "rtsc/proto/secondary.h"

#include <vector>

namespace rtsc::render {

namespace {

uint32_t PackRgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
    return (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(r) << 16) |
           (static_cast<uint32_t>(g) << 8) | static_cast<uint32_t>(b);
}

// Non-negative modulo 8 (C++ % keeps the sign of the dividend).
int Mod8(int v) { return ((v % 8) + 8) % 8; }

// Unpacks one packed brush color from `p` into a 0xAARRGGBB RGBA value for the
// given iBitmapFormat. Returns false when the format needs a context the
// renderer does not carry.
//
// Packing basis (per color depth):
//   BMF_8BPP  ([MS-RDPEGDI] 2.2.2.2.1.2.7.1): the byte is a PALETTE INDEX into
//     the cache color table ([MS-RDPEGDI] 2.2.2.2.1.2.7, the palette is
//     delivered by TS_CACHE_COLOR_TABLE). This renderer has no color-table
//     context, so it cannot resolve the index and fails closed.
//   BMF_16BPP: a 16-bit GenericColor, R5G6B5 (R = bits 15..11, G = bits 10..5,
//     B = bits 4..0; bit 15 is unused). Expanded to 8 bits per channel.
//   BMF_24BPP: three bytes R, G, B ([MS-RDPEGDI] GenericColor 24bpp).
//   BMF_32BPP: R, G, B; the fourth byte is ignored because the surface is an
//     opaque RGBA target (alpha is written as 0xFF).
bool UnpackBrushColor(uint8_t format, const uint8_t* p, uint32_t& rgba) {
    switch (format) {
        case rtsc::proto::kBMF8BPP:
            // Palette index: needs the color-table context, which is not
            // plumbed into this layer. Fail closed rather than guess.
            return false;
        case rtsc::proto::kBMF16BPP: {
            const uint16_t v = static_cast<uint16_t>(p[0]) |
                                (static_cast<uint16_t>(p[1]) << 8);
            const uint8_t r5 = static_cast<uint8_t>((v >> 11) & 0x1F);
            const uint8_t g6 = static_cast<uint8_t>((v >> 5) & 0x3F);
            const uint8_t b5 = static_cast<uint8_t>(v & 0x1F);
            // Expand 5/6/5 to 8 bits by replicating the high bits.
            const uint8_t r = static_cast<uint8_t>((r5 << 3) | (r5 >> 2));
            const uint8_t g = static_cast<uint8_t>((g6 << 2) | (g6 >> 4));
            const uint8_t b = static_cast<uint8_t>((b5 << 3) | (b5 >> 2));
            rgba = PackRgba(r, g, b, 0xFF);
            return true;
        }
        case rtsc::proto::kBMF24BPP:
            rgba = PackRgba(p[0], p[1], p[2], 0xFF);
            return true;
        case rtsc::proto::kBMF32BPP:
            // R, G, B; the 4th byte is ignored (opaque surface).
            rgba = PackRgba(p[0], p[1], p[2], 0xFF);
            return true;
        default:
            return false;
    }
}

// Expands a cached brush into 64 per-pixel RGBA colors in image order (row 0 =
// top, px 0 = left). The wire brushData carries rows bottom-first
// ([MS-RDPEGDI] 2.2.2.2.1.2.7), so the reversal is applied here. Returns false
// when a color cannot be resolved (e.g. BMF_8BPP needs a palette).
bool DecodeBrushPattern(rtsc::proto::BrushForm form, uint8_t format,
                        const uint8_t* data, uint32_t fore, uint32_t back,
                        uint32_t out[64]) {
    if (form == rtsc::proto::BrushForm::kMono) {
        // 8 rows, one bit per pixel, MSB = leftmost; bit 0 = foreground.
        for (int r = 0; r < 8; ++r) {
            const uint8_t row = data[7 - r];  // wire rows are bottom-first
            for (int px = 0; px < 8; ++px) {
                const int bit = (row >> (7 - px)) & 1;
                out[r * 8 + px] = (bit == 0) ? fore : back;
            }
        }
        return true;
    }
    if (form == rtsc::proto::BrushForm::kCompressed4) {
        // COMPRESSED_COLOR_BRUSH: 16 bytes of 2-bit indices P1..P64 (P1 is the
        // high 2 bits of byte 0) followed by 4 packed colors.
        const uint8_t bpp = rtsc::proto::BrushBytesPerPixel(format);
        if (bpp == 0) return false;
        uint32_t colors[4] = {0, 0, 0, 0};
        for (int c = 0; c < 4; ++c) {
            if (!UnpackBrushColor(
                    format, data + 16 + static_cast<size_t>(c) * bpp,
                    colors[c])) {
                return false;
            }
        }
        for (int i = 0; i < 64; ++i) {
            const int byte = i >> 2;
            const int shift = 6 - 2 * (i & 3);  // P1 -> bits 7..6
            const int idx = (data[byte] >> shift) & 3;
            const int row = 7 - (i >> 3);       // wire rows are bottom-first
            const int px = i & 7;
            out[row * 8 + px] = colors[idx];
        }
        return true;
    }
    // kUncompressed: one packed color per pixel, wire rows bottom-first.
    const uint8_t bpp = rtsc::proto::BrushBytesPerPixel(format);
    if (bpp == 0) return false;
    for (int i = 0; i < 64; ++i) {
        if (!UnpackBrushColor(format, data + static_cast<size_t>(i) * bpp,
                              out[(7 - (i >> 3)) * 8 + (i & 7)])) {
            return false;
        }
    }
    return true;
}

// Hatched brush patterns, 8 image rows each, MSB = leftmost pixel.
// Bit 0 = foreground (the hatch line), bit 1 = background.
// Provenance: byte-for-byte identical to FreeRDP libfreerdp/gdi/gdi.c
// GDI_BS_HATCHED_PATTERNS. [MS-RDPEGDI] 2.2.2.2.1.1.2.3 Figures 2-7 are
// images, so the DOCX text cannot be extracted; FreeRDP's authoritative
// implementation is used instead, pending end-to-end cross-validation against
// a real session's hatch brush rendering.
// Self-checks: HS_HORIZONTAL has exactly one all-zero row (row 3) -> a single
// horizontal line, so 0 = foreground; HS_VERTICAL has bit 3 clear in every row
// -> a single vertical line; HS_CROSS is the vertical plus the horizontal line;
// HS_DIAGCROSS (spelled HS_DIACROSS in FreeRDP) is the X shape.
static const uint8_t kHatch[6][8] = {
    {0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},  // HS_HORIZONTAL 0x00
    {0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7, 0xF7},  // HS_VERTICAL   0x01
    {0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F},  // HS_FDIAGONAL  0x02
    {0x7F, 0xBF, 0xDF, 0xEF, 0xF7, 0xFB, 0xFD, 0xFE},  // HS_BDIAGONAL  0x03
    {0xF7, 0xF7, 0xF7, 0x00, 0xF7, 0xF7, 0xF7, 0xF7},  // HS_CROSS      0x04
    {0x7E, 0xBD, 0xDB, 0xE7, 0xE7, 0xDB, 0xBD, 0x7E},  // HS_DIAGCROSS  0x05
};

}  // namespace

void ApplyDstBlt(rtsc::ui::Surface& surface,
                 const rtsc::proto::DstBltOrder& order) {
    if (order.n_width <= 0 || order.n_height <= 0) return;
    for (int y = order.n_top; y < order.n_top + order.n_height; ++y) {
        for (int x = order.n_left; x < order.n_left + order.n_width; ++x) {
            uint8_t r = 0, g = 0, b = 0, a = 0;
            if (!surface.GetPixel(x, y, r, g, b, a)) continue;
            const uint32_t dst = PackRgba(r, g, b, a);
            // The spec requires the DstBlt result not to depend on S or P.
            const uint32_t out = rtsc::proto::rop3_apply_per_channel(order.b_rop, 0,
                                                                    dst, 0);
            surface.SetPixel(x, y, static_cast<uint8_t>(out >> 16),
                             static_cast<uint8_t>(out >> 8),
                             static_cast<uint8_t>(out),
                             static_cast<uint8_t>(out >> 24));
        }
    }
}

void ApplyOpaqueRect(rtsc::ui::Surface& surface,
                     const rtsc::proto::OpaqueRectOrder& order) {
    if (order.n_width <= 0 || order.n_height <= 0) return;
    // Palette mode (RedOrPaletteIndex as a palette index) is out of scope here;
    // the RGB interpretation is used. See 3d.
    for (int y = order.n_top; y < order.n_top + order.n_height; ++y) {
        for (int x = order.n_left; x < order.n_left + order.n_width; ++x) {
            surface.SetPixel(x, y, order.red, order.green, order.blue, 0xFF);
        }
    }
}

void ApplyScrBlt(rtsc::ui::Surface& surface,
                 const rtsc::proto::ScrBltOrder& order) {
    if (order.n_width <= 0 || order.n_height <= 0) return;
    // Snapshot the source rectangle first so an overlapping self-copy cannot
    // smear (reading a pixel that an earlier iteration already overwrote).
    std::vector<uint32_t> snapshot(
        static_cast<size_t>(order.n_width) * order.n_height, 0);
    for (int j = 0; j < order.n_height; ++j) {
        for (int i = 0; i < order.n_width; ++i) {
            uint8_t r = 0, g = 0, b = 0, a = 0;
            if (surface.GetPixel(order.n_x_src + i, order.n_y_src + j, r, g, b,
                                 a)) {
                snapshot[static_cast<size_t>(j) * order.n_width + i] =
                    PackRgba(r, g, b, a);
            }
        }
    }
    for (int j = 0; j < order.n_height; ++j) {
        for (int i = 0; i < order.n_width; ++i) {
            const int dx = order.n_left + i;
            const int dy = order.n_top + j;
            uint8_t dr = 0, dg = 0, db = 0, da = 0;
            if (!surface.GetPixel(dx, dy, dr, dg, db, da)) continue;
            const uint32_t src =
                snapshot[static_cast<size_t>(j) * order.n_width + i];
            const uint32_t dst = PackRgba(dr, dg, db, da);
            const uint32_t out = rtsc::proto::rop3_apply_per_channel(order.b_rop,
                                                                    src, dst, 0);
            surface.SetPixel(dx, dy, static_cast<uint8_t>(out >> 16),
                             static_cast<uint8_t>(out >> 8),
                             static_cast<uint8_t>(out),
                             static_cast<uint8_t>(out >> 24));
        }
    }
}

PatBltResult ApplyHatchedPatBlt(rtsc::ui::Surface& surface,
                                const rtsc::proto::PatBltOrder& order) {
    const uint8_t hatch = order.brush_hatch;
    if (hatch > 0x05) return PatBltResult::kUnsupported;  // fail-closed
    const uint8_t* pat = kHatch[hatch];
    const int org_x = static_cast<int>(order.brush_org_x);
    const int org_y = static_cast<int>(order.brush_org_y);
    const uint32_t fore =
        PackRgba(order.fore_red, order.fore_green, order.fore_blue, 0xFF);
    const uint32_t back =
        PackRgba(order.back_red, order.back_green, order.back_blue, 0xFF);
    for (int y = order.n_top; y < order.n_top + order.n_height; ++y) {
        const int py = Mod8(y - org_y);
        for (int x = order.n_left; x < order.n_left + order.n_width; ++x) {
            const int px = Mod8(x - org_x);
            const int bit = (pat[py] >> (7 - px)) & 1;
            const uint32_t p = (bit == 0) ? fore : back;  // 0 = foreground
            uint8_t r = 0, g = 0, b = 0, a = 0;
            if (!surface.GetPixel(x, y, r, g, b, a)) continue;
            const uint32_t dst = PackRgba(r, g, b, a);
            const uint32_t out =
                rtsc::proto::rop3_apply_per_channel(order.b_rop, 0, dst, p);
            surface.SetPixel(x, y, static_cast<uint8_t>(out >> 16),
                             static_cast<uint8_t>(out >> 8),
                             static_cast<uint8_t>(out),
                             static_cast<uint8_t>(out >> 24));
        }
    }
    return PatBltResult::kApplied;
}

PatBltResult ApplyPatternPatBlt(rtsc::ui::Surface& surface,
                                const rtsc::proto::PatBltOrder& order) {
    // Build the 8x8 pattern in image row order. [MS-RDPEGDI] 2.2.2.2.1.1.2.3:
    // BrushExtra[0] = penultimate row ... BrushExtra[6] = top row, and the
    // bottom row is BrushHatch. MSB = leftmost pixel. Bit 0 = ForeColor.
    // Chain: spec encoding -> image row order -> FreeRDP monochrome render
    // (bit 0 -> foreColor, bit 1 -> backColor). The FreeRDP order-parse chain
    // (libfreerdp/core/update.c) was not obtainable here, so this follows the
    // spec text plus FreeRDP's monochrome polarity.
    uint8_t pat[8];
    for (int i = 0; i < 7; ++i) pat[i] = order.brush_extra[6 - i];
    pat[7] = order.brush_hatch;
    const int org_x = static_cast<int>(order.brush_org_x);
    const int org_y = static_cast<int>(order.brush_org_y);
    const uint32_t fore =
        PackRgba(order.fore_red, order.fore_green, order.fore_blue, 0xFF);
    const uint32_t back =
        PackRgba(order.back_red, order.back_green, order.back_blue, 0xFF);
    for (int y = order.n_top; y < order.n_top + order.n_height; ++y) {
        const int py = Mod8(y - org_y);
        for (int x = order.n_left; x < order.n_left + order.n_width; ++x) {
            const int px = Mod8(x - org_x);
            const int bit = (pat[py] >> (7 - px)) & 1;
            const uint32_t p = (bit == 0) ? fore : back;  // 0 = foreground
            uint8_t r = 0, g = 0, b = 0, a = 0;
            if (!surface.GetPixel(x, y, r, g, b, a)) continue;
            const uint32_t dst = PackRgba(r, g, b, a);
            const uint32_t out =
                rtsc::proto::rop3_apply_per_channel(order.b_rop, 0, dst, p);
            surface.SetPixel(x, y, static_cast<uint8_t>(out >> 16),
                             static_cast<uint8_t>(out >> 8),
                             static_cast<uint8_t>(out),
                             static_cast<uint8_t>(out >> 24));
        }
    }
    return PatBltResult::kApplied;
}

PatBltResult ApplyCachedBrushPatBlt(rtsc::ui::Surface& surface,
                                    const rtsc::proto::PatBltOrder& order,
                                    const BrushCacheView* cache) {
    // [MS-RDPEGDI] 2.2.2.2.1.1.2.3: when TS_CACHED_BRUSH (0x80) is set in the
    // BrushStyle high bit, BrushHatch holds the Brush Cache index and the low
    // nibble of BrushStyle holds the cached brush's color depth.
    const uint8_t index = order.brush_hatch;
    const uint8_t depth = static_cast<uint8_t>(order.brush_style & 0x0F);
    uint8_t format = 0;
    uint8_t length = 0;
    const uint8_t* data =
        cache ? cache->Lookup(index, format, length) : nullptr;
    // A cache miss is unsupported rather than drawn.
    if (data == nullptr) return PatBltResult::kUnsupported;
    // The PatBlt's low nibble names the cached brush's color depth, so a
    // mismatch means the reference is inconsistent: fail closed.
    if (depth != format) return PatBltResult::kUnsupported;
    // Classify the wire encoding; an iBytes matching no defined form is
    // rejected rather than guessed.
    rtsc::proto::BrushForm form;
    if (rtsc::proto::ClassifyBrushForm(format, static_cast<uint16_t>(length),
                                      form) != rtsc::proto::Status::Ok) {
        return PatBltResult::kUnsupported;
    }
    const int org_x = static_cast<int>(order.brush_org_x);
    const int org_y = static_cast<int>(order.brush_org_y);
    const uint32_t fore =
        PackRgba(order.fore_red, order.fore_green, order.fore_blue, 0xFF);
    const uint32_t back =
        PackRgba(order.back_red, order.back_green, order.back_blue, 0xFF);
    uint32_t pattern[64];
    if (!DecodeBrushPattern(form, format, data, fore, back, pattern)) {
        return PatBltResult::kUnsupported;  // e.g. BMF_8BPP needs a palette
    }
    for (int y = order.n_top; y < order.n_top + order.n_height; ++y) {
        const int py = Mod8(y - org_y);
        for (int x = order.n_left; x < order.n_left + order.n_width; ++x) {
            const int px = Mod8(x - org_x);
            const uint32_t p = pattern[py * 8 + px];
            uint8_t r = 0, g = 0, b = 0, a = 0;
            if (!surface.GetPixel(x, y, r, g, b, a)) continue;
            const uint32_t dst = PackRgba(r, g, b, a);
            const uint32_t out =
                rtsc::proto::rop3_apply_per_channel(order.b_rop, 0, dst, p);
            surface.SetPixel(x, y, static_cast<uint8_t>(out >> 16),
                             static_cast<uint8_t>(out >> 8),
                             static_cast<uint8_t>(out),
                             static_cast<uint8_t>(out >> 24));
        }
    }
    return PatBltResult::kApplied;
}

PatBltResult ApplyPatBltImpl(rtsc::ui::Surface& surface,
                             const rtsc::proto::PatBltOrder& order,
                             const BrushCacheView* cache) {
    if (order.n_width <= 0 || order.n_height <= 0) return PatBltResult::kNoOp;
    if (order.brush_style == rtsc::proto::BS_NULL) return PatBltResult::kNoOp;
    if (order.brush_style == rtsc::proto::BS_PATTERN) {
        return ApplyPatternPatBlt(surface, order);
    }
    if (order.brush_style == rtsc::proto::BS_HATCHED) {
        return ApplyHatchedPatBlt(surface, order);
    }
    if ((order.brush_style & 0x80) != 0) {
        return ApplyCachedBrushPatBlt(surface, order, cache);
    }
    if (order.brush_style != rtsc::proto::BS_SOLID) {
        // Any other style: not implemented yet.
        return PatBltResult::kUnsupported;
    }
    // BS_SOLID: the pattern is the ForeColor, S = 0.
    const uint32_t fore = PackRgba(order.fore_red, order.fore_green,
                                   order.fore_blue, 0xFF);
    for (int y = order.n_top; y < order.n_top + order.n_height; ++y) {
        for (int x = order.n_left; x < order.n_left + order.n_width; ++x) {
            uint8_t r = 0, g = 0, b = 0, a = 0;
            if (!surface.GetPixel(x, y, r, g, b, a)) continue;
            const uint32_t dst = PackRgba(r, g, b, a);
            const uint32_t out =
                rtsc::proto::rop3_apply_per_channel(order.b_rop, 0, dst, fore);
            surface.SetPixel(x, y, static_cast<uint8_t>(out >> 16),
                             static_cast<uint8_t>(out >> 8),
                             static_cast<uint8_t>(out),
                             static_cast<uint8_t>(out >> 24));
        }
    }
    return PatBltResult::kApplied;
}

PatBltResult ApplyPatBlt(rtsc::ui::Surface& surface,
                         const rtsc::proto::PatBltOrder& order) {
    return ApplyPatBltImpl(surface, order, nullptr);
}

PatBltResult ApplyPatBlt(rtsc::ui::Surface& surface,
                         const rtsc::proto::PatBltOrder& order,
                         const BrushCacheView& cache) {
    return ApplyPatBltImpl(surface, order, &cache);
}

}  // namespace rtsc::render
