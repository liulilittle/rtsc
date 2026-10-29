// UI surface: an RGBA8888 pixel buffer with clipping blits.
//
// This is the platform-neutral target the graphics layer draws into. It is the
// bridge between decoded RDP bitmaps (RGBA8888, top-down, from
// rtsc::proto::DecodedBitmap) and whatever eventually presents them (a Win32
// window, an X11/Wayland surface, or nothing at all in headless tests).
//
// All coordinates are top-down pixels; (0,0) is the top-left corner.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace rtsc::ui {

class Surface {
 public:
    Surface(uint16_t width, uint16_t height);

    uint16_t width() const noexcept { return width_; }
    uint16_t height() const noexcept { return height_; }
    size_t size() const noexcept { return pixels_.size(); }

    uint8_t* data() noexcept { return pixels_.data(); }
    const uint8_t* data() const noexcept { return pixels_.data(); }

    // Fills the whole surface with one RGBA colour.
    void Fill(uint8_t r, uint8_t g, uint8_t b, uint8_t a);

    // Fills an axis-aligned rectangle (clipped to the surface) with one RGBA
    // colour. Used to clear only the letterbox bars around a scaled image, so a
    // 1:1 frame costs one blit instead of a full-screen fill plus a blit.
    void FillRect(int x, int y, int w, int h, uint8_t r, uint8_t g, uint8_t b,
                  uint8_t a);

    // Copies an RGBA8888 source (src_w x src_h) to (dst_x, dst_y). The source
    // and destination rectangles are clipped to the surface; out-of-range pixels
    // are ignored rather than wrapping.
    void Blit(const uint8_t* src, uint16_t src_w, uint16_t src_h, int dst_x,
              int dst_y);

    // Reads one pixel as RGBA. Returns false when out of bounds.
    bool GetPixel(int x, int y, uint8_t& r, uint8_t& g, uint8_t& b,
                  uint8_t& a) const;

    // Sets one pixel. Out-of-bounds coordinates are ignored (no write, no wrap).
    void SetPixel(int x, int y, uint8_t r, uint8_t g, uint8_t b, uint8_t a);

    // Draws a line with integer Bresenham, clipped to the surface. Pixels
    // outside the surface are ignored; a zero-length line draws a single point.
    // The Liang-Barsky pre-clip is a performance optimization only: correctness
    // (out-of-bounds pixels are never written) is guaranteed by SetPixel's own
    // bounds check, so removing the pre-clip cannot change the visible result.
    void Line(int x0, int y0, int x1, int y1, uint8_t r, uint8_t g, uint8_t b,
              uint8_t a);

 private:
    uint16_t width_ = 0;
    uint16_t height_ = 0;
    std::vector<uint8_t> pixels_;  // width * height * 4
};

// Converts `pixel_count` RGBA8888 pixels (top-down, the Surface layout) into
// BGRA8888, the byte order a 32-bit top-down DIB expects (bytes 0 and 2 of each
// pixel are swapped; alpha is untouched). `dst_bgra` and `src_rgba` may alias.
//
// This is the hot path of the Win32 Present(): it runs once per rendered frame
// over the whole client area, so it is deliberately vectorised (two pixels per
// 64-bit word, three masks/shifts per word) instead of a per-byte loop -- a
// 1280x1024 frame measures ~0.36 ms instead of ~0.97 ms on the same Release
// build. Kept a free function so it is testable off-platform and measurable
// headlessly.
void RgbaToBgra(uint8_t* dst_bgra, const uint8_t* src_rgba, size_t pixel_count);

}  // namespace rtsc::ui
