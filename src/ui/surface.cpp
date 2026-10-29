// UI surface: an RGBA8888 pixel buffer with clipping blits.

#include "rtsc/ui/surface.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>

namespace rtsc::ui {

Surface::Surface(uint16_t width, uint16_t height)
    : width_(width), height_(height) {
    pixels_.assign(static_cast<size_t>(width) * height * 4, 0);
}

void Surface::Fill(uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
    FillRect(0, 0, width_, height_, r, g, b, a);
}

void Surface::FillRect(int x, int y, int w, int h, uint8_t r, uint8_t g,
                       uint8_t b, uint8_t a) {
    if (w <= 0 || h <= 0) return;
    // Clip to the surface.
    const int x0 = std::max(0, x);
    const int y0 = std::max(0, y);
    const int x1 = std::min<int>(width_, x + w);
    const int y1 = std::min<int>(height_, y + h);
    if (x0 >= x1 || y0 >= y1) return;

    // One RGBA pixel as a little-endian 32-bit word (R is the low byte), so a
    // run of pixels is a std::fill over words rather than a per-byte loop.
    const uint32_t px = static_cast<uint32_t>(r) |
                        (static_cast<uint32_t>(g) << 8) |
                        (static_cast<uint32_t>(b) << 16) |
                        (static_cast<uint32_t>(a) << 24);
    const int n = x1 - x0;
    for (int row = y0; row < y1; ++row) {
        uint32_t* d = reinterpret_cast<uint32_t*>(
            pixels_.data() + (static_cast<size_t>(row) * width_ + x0) * 4);
        std::fill_n(d, n, px);
    }
}

void Surface::Blit(const uint8_t* src, uint16_t src_w, uint16_t src_h, int dst_x,
                   int dst_y) {
    if (src == nullptr || src_w == 0 || src_h == 0) return;

    // Clip the source rectangle to the destination surface.
    const int x0 = std::max(0, dst_x);
    const int y0 = std::max(0, dst_y);
    const int x1 = std::min<int>(width_, static_cast<int>(dst_x) + src_w);
    const int y1 = std::min<int>(height_, static_cast<int>(dst_y) + src_h);
    if (x0 >= x1 || y0 >= y1) return;

    for (int y = y0; y < y1; ++y) {
        const int sy = y - dst_y;
        const int sx = x0 - dst_x;
        const int n = x1 - x0;
        const uint8_t* s = src + (static_cast<size_t>(sy) * src_w + sx) * 4;
        uint8_t* d = pixels_.data() + (static_cast<size_t>(y) * width_ + x0) * 4;
        std::memcpy(d, s, static_cast<size_t>(n) * 4);
    }
}

bool Surface::GetPixel(int x, int y, uint8_t& r, uint8_t& g, uint8_t& b,
                       uint8_t& a) const {
    if (x < 0 || y < 0 || x >= width_ || y >= height_) return false;
    const uint8_t* p = pixels_.data() + (static_cast<size_t>(y) * width_ + x) * 4;
    r = p[0];
    g = p[1];
    b = p[2];
    a = p[3];
    return true;
}

void Surface::SetPixel(int x, int y, uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
    if (x < 0 || y < 0 || x >= width_ || y >= height_) return;
    uint8_t* p = pixels_.data() + (static_cast<size_t>(y) * width_ + x) * 4;
    p[0] = r;
    p[1] = g;
    p[2] = b;
    p[3] = a;
}

void Surface::Line(int x0, int y0, int x1, int y1, uint8_t r, uint8_t g,
                   uint8_t b, uint8_t a) {
    if (width_ == 0 || height_ == 0) return;

    // Clip the segment to [0, width-1] x [0, height-1] with Liang-Barsky.
    const double xmin = 0.0;
    const double ymin = 0.0;
    const double xmax = static_cast<double>(width_ - 1);
    const double ymax = static_cast<double>(height_ - 1);
    const double dx = static_cast<double>(x1) - static_cast<double>(x0);
    const double dy = static_cast<double>(y1) - static_cast<double>(y0);
    double t0 = 0.0;
    double t1 = 1.0;
    const double p[4] = {-dx, dx, -dy, dy};
    const double q[4] = {static_cast<double>(x0) - xmin,
                         xmax - static_cast<double>(x0),
                         static_cast<double>(y0) - ymin,
                         ymax - static_cast<double>(y0)};
    for (int i = 0; i < 4; ++i) {
        if (p[i] == 0.0) {
            if (q[i] < 0.0) return;  // parallel to the edge and outside it
        } else {
            const double t = q[i] / p[i];
            if (p[i] < 0.0) {
                if (t > t1) return;
                if (t > t0) t0 = t;
            } else {
                if (t < t0) return;
                if (t < t1) t1 = t;
            }
        }
    }
    if (t0 > t1) return;

    const int cx0 =
        static_cast<int>(std::lround(static_cast<double>(x0) + t0 * dx));
    const int cy0 =
        static_cast<int>(std::lround(static_cast<double>(y0) + t0 * dy));
    const int cx1 =
        static_cast<int>(std::lround(static_cast<double>(x0) + t1 * dx));
    const int cy1 =
        static_cast<int>(std::lround(static_cast<double>(y0) + t1 * dy));

    // Integer Bresenham over the clipped segment.
    const int step_x = cx0 < cx1 ? 1 : -1;
    const int step_y = cy0 < cy1 ? 1 : -1;
    const int dx_i = std::abs(cx1 - cx0);
    const int dy_i = -std::abs(cy1 - cy0);
    int x = cx0;
    int y = cy0;
    int err = dx_i + dy_i;
    for (;;) {
        SetPixel(x, y, r, g, b, a);
        if (x == cx1 && y == cy1) break;
        const int e2 = 2 * err;
        if (e2 >= dy_i) {
            err += dy_i;
            x += step_x;
        }
        if (e2 <= dx_i) {
            err += dx_i;
            y += step_y;
        }
    }
}

void RgbaToBgra(uint8_t* dst_bgra, const uint8_t* src_rgba, size_t pixel_count) {
    const size_t n = pixel_count * 4;
    // Two pixels per 64-bit word. A little-endian RGBA8888 pixel reads as
    // R | G<<8 | B<<16 | A<<24; swapping bytes 0 and 2 (and 4 and 6 of the
    // second pixel) yields B | G<<8 | R<<16 | A<<24 = BGRA8888. The three
    // mask-and-shift terms move the R bytes up and the B bytes down in one pass
    // and keep G/A in place; the compiler widens this to SIMD on x86-64.
    size_t o = 0;
    for (; o + 16 <= n; o += 16) {
        uint64_t v0;
        std::memcpy(&v0, src_rgba + o, 8);
        uint64_t v1;
        std::memcpy(&v1, src_rgba + o + 8, 8);
        const uint64_t w0 = ((v0 & 0x000000FF000000FFull) << 16) |
                            ((v0 & 0x00FF000000FF0000ull) >> 16) |
                            (v0 & 0xFF00FF00FF00FF00ull);
        const uint64_t w1 = ((v1 & 0x000000FF000000FFull) << 16) |
                            ((v1 & 0x00FF000000FF0000ull) >> 16) |
                            (v1 & 0xFF00FF00FF00FF00ull);
        std::memcpy(dst_bgra + o, &w0, 8);
        std::memcpy(dst_bgra + o + 8, &w1, 8);
    }
    // One pixel per 32-bit word tail (n % 16 != 0).
    for (; o + 4 <= n; o += 4) {
        uint32_t v;
        std::memcpy(&v, src_rgba + o, 4);
        const uint32_t w = ((v & 0x000000FFu) << 16) |
                           ((v & 0x00FF0000u) >> 16) | (v & 0xFF00FF00u);
        std::memcpy(dst_bgra + o, &w, 4);
    }
    // Trailing bytes of a partial pixel (cannot occur for RGBA) copy as-is.
    for (; o < n; ++o) dst_bgra[o] = src_rgba[o];
}

}  // namespace rtsc::ui
