// Resampling kernels used by rtsc::client::ScaleSurface.
//
// Private to src/client: not part of the public API. The rules they implement
// are the ones recorded in docs/spec/scaling-evidence.md.

#pragma once

#include <cstdint>

namespace rtsc::client::detail {

// One scale operation: source size, scaled-image size, the scaled image's
// origin inside the destination surface, and the visible clip rectangle (in
// destination coordinates, half-open).
struct ScaleRect {
    int sw = 0;
    int sh = 0;
    int dw = 0;
    int dh = 0;
    int dx = 0;
    int dy = 0;
    int x0 = 0;
    int y0 = 0;
    int x1 = 0;
    int y1 = 0;
};

// 1:1: destination size equals source size, so every visible pixel is a copy.
// Reads and writes both carry the view offset (a centred view with letterbox
// bars is still an exact copy).
void CopyExact(const uint8_t* src, const ScaleRect& r, uint8_t* dst,
               int dst_stride_px);

// Enlargement of either axis: nearest-neighbour. Every destination pixel is an
// exact copy of one source pixel, chosen by the measured phase rule (E8). An
// integer factor additionally takes a k x k block fast path with identical
// output.
void ResampleNearest(const uint8_t* src, const ScaleRect& r, uint8_t* dst,
                     int dst_stride_px);

// Reduction of either axis: separable coverage-weighted area average over all
// four channels, integer weights normalised to 2^16, round half up. Documented
// deviations D-1 (exact box, unlike GDI's approximate one) and D-2 (alpha uses
// the same weights; GDI leaves alpha untouched).
void ResampleArea(const uint8_t* src, const ScaleRect& r, uint8_t* dst,
                  int dst_stride_px);

}  // namespace rtsc::client::detail