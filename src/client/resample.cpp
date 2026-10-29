// Resampling kernels for ScaleSurface (rtsc::client).
//
// The sampling rules come from the measured mstsc/GDI behaviour recorded in
// docs/spec/scaling-evidence.md; do not "improve" them without updating that
// file first.

#include "resample.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace rtsc::client::detail {

namespace {

// Exact floor(num / den) for the numerators this file produces (num < 255 * den),
// via a 44-bit reciprocal plus one corrective compare.
//
// This is not premature optimisation: a plain integer division per channel per
// pixel dominated the frame budget, while a floating-point reciprocal is *not*
// exact at the rounding boundary. An earlier version used `1.0/total` and lost
// half-up ties to the low side -- 0.75x of a single 56 grey pixel (total
// 1296000, weight 729000, exact 31.5) came out as 31 instead of 32.
struct ExactDivider {
    uint64_t den = 1;
    uint64_t recip = 1;
    int pow2_shift = -1;  // >= 0 when den is a power of two

    void Reset(uint64_t d) {
        den = (d > 0) ? d : 1;
        recip = ((1ULL << 44) + den - 1) / den;  // ceil(2^44 / den)
        pow2_shift = -1;
        if ((den & (den - 1)) == 0) {
            int s = 0;
            while ((1ULL << s) < den) ++s;
            pow2_shift = s;
        }
    }
    inline uint32_t FloorDiv(uint64_t num) const {
        if (pow2_shift >= 0) return static_cast<uint32_t>(num >> pow2_shift);
        uint64_t q = (num * recip) >> 44;
        if (q * den > num) --q;  // the ceil reciprocal can overshoot by one
        return static_cast<uint32_t>(q);
    }
    // Round half up: (num + den/2) / den. For an odd den an exact .5 tie cannot
    // occur (num/den = k + 1/2 needs den to divide 2*num but not num), so
    // truncating den/2 is equivalent to round-half-up for every den.
    inline uint32_t RoundDiv(uint64_t num) const {
        return FloorDiv(num + den / 2);
    }
};

// Source index sampled for destination index `d` when scaling S -> D pixels.
//
// This is the rule measured for GDI HALFTONE on low-frequency content
// (docs/spec/scaling-evidence.md E8): sample at the destination pixel centre,
// integer division, ties resolve downwards. Zero mismatch over 44 size pairs,
// including 3->5, 8->11 and 8->13 where the naive corner mapping floor(d*S/D)
// picks a whole column of wrong pixels. At an integer factor it degenerates to
// plain block replication, which is why the block fast path exists.
inline int NearestIndex(int d, int s, int den) {
    long long v = ((2LL * d + 1) * s - 1) / (2LL * den);
    if (v < 0) v = 0;
    if (v > s - 1) v = s - 1;
    return static_cast<int>(v);
}

// One tap of one axis. `w` is an exact integer coverage count in units of 1/dn
// of a source pixel, so all weights of a destination index sum to sn and the
// joint denominator of the two axes is exactly sw * sh.
struct Tap {
    int src;
    uint32_t w;
};

// Coverage taps for scaling sn -> dn.
//
// A shrinking axis uses the overlap between the destination footprint
// [d*sn/dn, (d+1)*sn/dn) and each source pixel. A growing axis must not blend
// (the reference replicates when enlarging), so it gets a single full-weight tap
// picked by the measured phase rule. Either way the weights of one destination
// pixel sum to sn.
//
// When dn divides sn the pattern is a constant box of k adjacent source pixels,
// which lets the inner loop run as plain additions and is by far the common case
// (0.5x, 0.25x, and the equal axis of a mixed transform).
struct Axis {
    std::vector<int> start;
    std::vector<int> count;
    std::vector<Tap> taps;
    std::vector<int> uniform_first;  // first source index, when uniform
    bool uniform = false;
    int uniform_count = 1;
    int sum = 1;
};

Axis BuildAxis(int sn, int dn) {
    Axis a;
    a.sum = sn;
    a.start.resize(static_cast<size_t>(dn));
    a.count.resize(static_cast<size_t>(dn));
    a.taps.reserve(static_cast<size_t>(dn) * 2);
    a.uniform_first.resize(static_cast<size_t>(dn));

    if (dn >= sn) {
        for (int d = 0; d < dn; ++d) {
            const int src = NearestIndex(d, sn, dn);
            a.start[static_cast<size_t>(d)] = static_cast<int>(a.taps.size());
            a.count[static_cast<size_t>(d)] = 1;
            a.taps.push_back({src, static_cast<uint32_t>(sn)});
            a.uniform_first[static_cast<size_t>(d)] = src;
        }
        a.uniform = true;
        a.uniform_count = 1;
        return a;
    }

    for (int d = 0; d < dn; ++d) {
        const long long lo = static_cast<long long>(d) * sn;
        const long long hi = static_cast<long long>(d + 1) * sn;
        const int s0 = static_cast<int>(lo / dn);
        const int s1 = static_cast<int>((hi - 1) / dn);
        a.start[static_cast<size_t>(d)] = static_cast<int>(a.taps.size());
        for (int s = s0; s <= s1 && s < sn; ++s) {
            const long long ov = std::min(hi, static_cast<long long>(s + 1) * dn) -
                                 std::max(lo, static_cast<long long>(s) * dn);
            if (ov <= 0) continue;
            a.taps.push_back({s, static_cast<uint32_t>(ov)});
        }
        a.count[static_cast<size_t>(d)] =
            static_cast<int>(a.taps.size()) - a.start[static_cast<size_t>(d)];
        a.uniform_first[static_cast<size_t>(d)] =
            a.taps[static_cast<size_t>(a.start[static_cast<size_t>(d)])].src;
    }

    // A constant box of k adjacent source pixels with equal weight is by far the
    // common reduction (0.5x, 0.25x, and the equal axis of a mixed transform), so
    // it is detected once here and takes a tight branch in the inner loops.
    if (sn % dn == 0) {
        const int k = sn / dn;
        bool same = true;
        for (int d = 0; d < dn && same; ++d) {
            if (a.count[static_cast<size_t>(d)] != k) {
                same = false;
                break;
            }
            const int b = a.start[static_cast<size_t>(d)];
            for (int t = 1; t < k && same; ++t) {
                if (a.taps[static_cast<size_t>(b + t)].src !=
                    a.taps[static_cast<size_t>(b + t - 1)].src + 1) {
                    same = false;
                }
            }
        }
        if (same) {
            a.uniform = true;
            a.uniform_count = k;
        }
    }
    return a;
}

// Taps depend only on the image shape, and a session resizes rarely, so the last
// shape per axis is cached and a steady-state frame builds nothing.
struct AxisCache {
    int sn = -1;
    int dn = -1;
    Axis axis;
};

const Axis& CachedAxis(AxisCache& cache, int sn, int dn) {
    if (cache.sn != sn || cache.dn != dn) {
        cache.axis = BuildAxis(sn, dn);
        cache.sn = sn;
        cache.dn = dn;
    }
    return cache.axis;
}

std::vector<uint64_t>& AccScratch() {
    static thread_local std::vector<uint64_t> buf;
    return buf;
}

// Weighted horizontal sum of destination columns [x0, x0 + n), for one source
// row, into `out` (4 accumulators per column).
void HorzRow(const uint8_t* row, const Axis& ax, int x0, int n, uint32_t* out) {
    if (ax.uniform) {
        const int k = ax.uniform_count;
        // Every tap of a uniform box carries the same weight, so the sum of k
        // source pixels is scaled once instead of once per tap.
        const uint32_t w = static_cast<uint32_t>(ax.sum / k);
        for (int x = 0; x < n; ++x) {
            const uint8_t* p =
                row + static_cast<size_t>(ax.uniform_first[static_cast<size_t>(x0 + x)]) * 4;
            uint32_t a0 = 0, a1 = 0, a2 = 0, a3 = 0;
            for (int t = 0; t < k; ++t) {
                a0 += p[0];
                a1 += p[1];
                a2 += p[2];
                a3 += p[3];
                p += 4;
            }
            out[x * 4 + 0] = a0 * w;
            out[x * 4 + 1] = a1 * w;
            out[x * 4 + 2] = a2 * w;
            out[x * 4 + 3] = a3 * w;
        }
        return;
    }
    for (int x = 0; x < n; ++x) {
        const int b = ax.start[static_cast<size_t>(x0 + x)];
        const int e = b + ax.count[static_cast<size_t>(x0 + x)];
        uint32_t a0 = 0, a1 = 0, a2 = 0, a3 = 0;
        for (int t = b; t < e; ++t) {
            const Tap& tp = ax.taps[static_cast<size_t>(t)];
            const uint8_t* p = row + static_cast<size_t>(tp.src) * 4;
            a0 += static_cast<uint32_t>(p[0]) * tp.w;
            a1 += static_cast<uint32_t>(p[1]) * tp.w;
            a2 += static_cast<uint32_t>(p[2]) * tp.w;
            a3 += static_cast<uint32_t>(p[3]) * tp.w;
        }
        out[x * 4 + 0] = a0;
        out[x * 4 + 1] = a1;
        out[x * 4 + 2] = a2;
        out[x * 4 + 3] = a3;
    }
}

}  // namespace

void CopyExact(const uint8_t* src, const ScaleRect& r, uint8_t* dst,
               int dst_stride_px) {
    const int n = r.x1 - r.x0;
    if (n <= 0) return;
    const size_t bytes = static_cast<size_t>(n) * 4;
    // Both the read and the write carry the view offset: a centred 1:1 view is a
    // copy with letterbox bars, not a resample. Dropping the offset on the source
    // side would read rows past the end of the source (D-4 in
    // docs/spec/scaling-evidence.md).
    const int sx = r.x0 - r.dx;
    for (int y = r.y0; y < r.y1; ++y) {
        const uint8_t* s = src + (static_cast<size_t>(y - r.dy) * r.sw + sx) * 4;
        uint8_t* d = dst + (static_cast<size_t>(y) * dst_stride_px + r.x0) * 4;
        std::memcpy(d, s, bytes);
    }
}

void ResampleNearest(const uint8_t* src, const ScaleRect& r, uint8_t* dst,
                     int dst_stride_px) {
    // Integer factor on both axes: expand one source row, then blit it k times.
    // Identical output to the per-pixel rule below; this is only the fast shape
    // of it and is kept deliberately (D-3 in docs/spec/scaling-evidence.md).
    if (r.sw > 0 && r.sh > 0 && r.dw % r.sw == 0 && r.dh % r.sh == 0) {
        const int kx = r.dw / r.sw;
        const int ky = r.dh / r.sh;
        if (kx == ky && kx >= 2 && kx <= 64) {
            const int k = kx;
            const int cx0 = r.x0 - r.dx;
            const int cx1 = r.x1 - r.dx;
            std::vector<uint8_t> row(static_cast<size_t>(r.dw) * 4);
            for (int sy = 0; sy < r.sh; ++sy) {
                const int block0 = r.dy + sy * k;
                const int dy0 = std::max(r.y0, block0);
                const int dy1 = std::min(r.y1, block0 + k);
                if (dy0 >= dy1) continue;
                const uint8_t* s = src + static_cast<size_t>(sy) * r.sw * 4;
                for (int sx = 0; sx < r.sw; ++sx) {
                    const uint8_t* p = s + static_cast<size_t>(sx) * 4;
                    uint8_t* q = row.data() + static_cast<size_t>(sx) * k * 4;
                    for (int i = 0; i < k; ++i) std::memcpy(q + i * 4, p, 4);
                }
                const uint8_t* from = row.data() + static_cast<size_t>(cx0) * 4;
                const size_t bytes = static_cast<size_t>(cx1 - cx0) * 4;
                uint8_t* d =
                    dst + (static_cast<size_t>(dy0) * dst_stride_px + r.x0) * 4;
                for (int dy = dy0; dy < dy1; ++dy) {
                    std::memcpy(d, from, bytes);
                    d += static_cast<size_t>(dst_stride_px) * 4;
                }
            }
            return;
        }
    }

    const int w = r.x1 - r.x0;
    const int h = r.y1 - r.y0;
    std::vector<int> xmap(static_cast<size_t>(w));
    std::vector<int> ymap(static_cast<size_t>(h));
    for (int i = 0; i < w; ++i) {
        xmap[static_cast<size_t>(i)] = NearestIndex(r.x0 - r.dx + i, r.sw, r.dw);
    }
    for (int j = 0; j < h; ++j) {
        ymap[static_cast<size_t>(j)] = NearestIndex(r.y0 - r.dy + j, r.sh, r.dh);
    }
    for (int j = 0; j < h; ++j) {
        const uint8_t* srow =
            src + static_cast<size_t>(ymap[static_cast<size_t>(j)]) * r.sw * 4;
        uint8_t* drow =
            dst + (static_cast<size_t>(r.y0 + j) * dst_stride_px + r.x0) * 4;
        for (int i = 0; i < w; ++i) {
            const uint8_t* p =
                srow + static_cast<size_t>(xmap[static_cast<size_t>(i)]) * 4;
            std::memcpy(drow + static_cast<size_t>(i) * 4, p, 4);
        }
    }
}

void ResampleArea(const uint8_t* src, const ScaleRect& r, uint8_t* dst,
                  int dst_stride_px) {
    // Exact coverage box on each axis (D-1: GDI's own box is approximate) with
    // all four channels weighted identically (D-2: GDI ignores alpha). A growing
    // axis contributes one full-weight tap chosen by the phase rule, so a mixed
    // transform such as 8x8 -> 4x16 is handled here without blending the
    // enlarged axis.
    //
    // The two passes are fused per destination row: the horizontal sums of the
    // few source rows that feed one destination row are computed on demand and
    // accumulated immediately, so no full-size intermediate is written and read
    // (that buffer alone was ~33 MB per 4K frame).
    static thread_local AxisCache xcache;
    static thread_local AxisCache ycache;
    const Axis& ax = CachedAxis(xcache, r.sw, r.dw);
    const Axis& ay = CachedAxis(ycache, r.sh, r.dh);

    const int nw = r.x1 - r.x0;
    if (nw <= 0 || r.y1 <= r.y0) return;
    const int cx = r.x0 - r.dx;  // first visible destination column

    // Fast path for an exact integer reduction on both axes (0.5x, 0.25x, and
    // any kx x ky box): sum the kx * ky source pixels of each destination pixel
    // and divide once. This is the shape a window-sized 4K view uses every frame,
    // so it avoids both the intermediate row sums and the generic tap walk.
    if (ax.uniform && ay.uniform && ax.uniform_count > 1 &&
        ay.uniform_count > 1) {
        const int kx = ax.uniform_count;
        const int ky = ay.uniform_count;
        const uint32_t area = static_cast<uint32_t>(kx * ky);
        // Round half up on (sum + area/2) / area, in integers: a float
        // reciprocal loses the exact .5 ties (F1).
        ExactDivider div;
        div.Reset(area);
        for (int y = r.y0; y < r.y1; ++y) {
            const int d = y - r.dy;
            const int y0 = ay.taps[static_cast<size_t>(ay.start[static_cast<size_t>(d)])].src;
            uint8_t* drow =
                dst + (static_cast<size_t>(y) * dst_stride_px + r.x0) * 4;
            for (int i = 0; i < nw; ++i) {
                const int x0 = ax.uniform_first[static_cast<size_t>(cx + i)];
                uint32_t a0 = 0, a1 = 0, a2 = 0, a3 = 0;
                for (int sy = 0; sy < ky; ++sy) {
                    const uint8_t* p =
                        src + (static_cast<size_t>(y0 + sy) * r.sw + x0) * 4;
                    for (int sx = 0; sx < kx; ++sx) {
                        a0 += p[0];
                        a1 += p[1];
                        a2 += p[2];
                        a3 += p[3];
                        p += 4;
                    }
                }
                drow[i * 4 + 0] = static_cast<uint8_t>(div.RoundDiv(a0));
                drow[i * 4 + 1] = static_cast<uint8_t>(div.RoundDiv(a1));
                drow[i * 4 + 2] = static_cast<uint8_t>(div.RoundDiv(a2));
                drow[i * 4 + 3] = static_cast<uint8_t>(div.RoundDiv(a3));
            }
        }
        return;
    }

    std::vector<uint64_t>& acc = AccScratch();
    acc.resize(static_cast<size_t>(nw) * 4);

    // Cached horizontal sums for the source rows feeding the current destination
    // row. A reduction band spans a handful of rows and consecutive destination
    // rows share them, so caching them is the difference between ~12 ms and
    // ~19 ms at 0.8x. The cache is deliberately local: the sums are derived from
    // pixel data, so anything surviving the call would be stale for the next
    // surface or frame.
    constexpr int kRing = 4;
    std::vector<uint32_t> sums[kRing];
    int sums_src[kRing];
    for (int i = 0; i < kRing; ++i) {
        sums_src[i] = -1;
        sums[i].resize(static_cast<size_t>(nw) * 4);
    }

    // The horizontal weights of one destination column sum to sw and the
    // vertical ones to sh, so dividing the 2-D accumulator by sw * sh gives the
    // exact average.
    const uint64_t total =
        static_cast<uint64_t>(r.sw) * static_cast<uint64_t>(r.sh);
    // Integer round-half-up, not a float reciprocal: (acc + total/2) / total.
    // A double reciprocal is off by one ulp at the .5 boundary and truncated the
    // wrong way (F1: 0.75x of a 56 grey pixel produced 31 instead of 32).
    ExactDivider div;
    div.Reset(total);

    for (int y = r.y0; y < r.y1; ++y) {
        const int d = y - r.dy;
        const int b = ay.start[static_cast<size_t>(d)];
        const int n = ay.count[static_cast<size_t>(d)];
        std::fill(acc.begin(), acc.end(), 0ULL);
        for (int t = b; t < b + n; ++t) {
            const Tap& tp = ay.taps[static_cast<size_t>(t)];
            const int slot = static_cast<int>(tp.src) % kRing;
            if (sums_src[slot] != tp.src) {
                HorzRow(src + static_cast<size_t>(tp.src) * r.sw * 4, ax, cx, nw,
                        sums[slot].data());
                sums_src[slot] = tp.src;
            }
            const uint32_t* hs = sums[slot].data();
            const uint64_t w = tp.w;
            for (int i = 0; i < nw * 4; ++i) {
                acc[static_cast<size_t>(i)] += static_cast<uint64_t>(hs[i]) * w;
            }
        }
        uint8_t* drow =
            dst + (static_cast<size_t>(y) * dst_stride_px + r.x0) * 4;
        for (int i = 0; i < nw * 4; ++i) {
            drow[i] = static_cast<uint8_t>(div.RoundDiv(acc[static_cast<size_t>(i)]));
        }
    }
}

}  // namespace rtsc::client::detail
