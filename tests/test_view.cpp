// View scaling: ComputeViewTransform / ScaleSurface, the zoom input controller,
// and GraphicsPipeline::RenderTo.

#include "rtsc/client/graphics.h"
#include "rtsc/client/view.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "rtsc/ui/surface.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc;
using namespace rtsc::client;
using namespace rtsc::ui;
using rtsc::ui::Surface;

namespace {

// Counts the red pixels in a surface (R != 0, G == 0, B == 0).
int CountRed(const Surface& s) {
    int n = 0;
    for (int y = 0; y < s.height(); ++y) {
        for (int x = 0; x < s.width(); ++x) {
            uint8_t r = 0, g = 0, b = 0, a = 0;
            if (s.GetPixel(x, y, r, g, b, a) && r != 0 && g == 0 && b == 0) {
                ++n;
            }
        }
    }
    return n;
}

bool IsRed(const Surface& s, int x, int y) {
    uint8_t r = 0, g = 0, b = 0, a = 0;
    return s.GetPixel(x, y, r, g, b, a) && r != 0 && g == 0 && b == 0;
}

bool IsBlack(const Surface& s, int x, int y) {
    uint8_t r = 0, g = 0, b = 0, a = 0;
    return s.GetPixel(x, y, r, g, b, a) && r == 0 && g == 0 && b == 0;
}

// ---------------------------------------------------------------------------
// Independent references for the rescale contract. These exist so a test can
// state an expected value derived from the documented rule instead of from the
// production output (writing the expectation from ScaleSurface's own result
// would make every test tautological).
// ---------------------------------------------------------------------------

// E8 (docs/spec/scaling-evidence.md): the source index GDI HALFTONE samples for
// destination index d when upscaling S -> D. Measured over 44 size pairs with
// zero mismatch; the "plain floor" variant is wrong at 3->5 and 8->13.
int E8Index(int d, int S, int D) { return ((2 * d + 1) * S - 1) / (2 * D); }

// Builds the transform for an explicit destination size (used by the one-axis
// cases, which a single uniform zoom factor cannot express).
ViewTransform MakeVT(int sw, int sh, int dw, int dh) {
    ViewTransform vt;
    vt.width = dw;
    vt.height = dh;
    vt.scale = static_cast<double>(dw) / static_cast<double>(sw);
    (void)sh;
    (void)dh;
    return vt;
}

// Independent reference for the downscale path: exact coverage-weighted box,
// half-pixel centred, separable, round-half-up, all four channels. Pure double
// arithmetic, so it shares no code with the integer-weight implementation.
void BoxPass(const std::vector<double>& in, int sn, int dn, int rows,
             std::vector<double>& out) {
    out.assign(static_cast<size_t>(dn) * rows, 0.0);
    for (int r = 0; r < rows; ++r) {
        for (int d = 0; d < dn; ++d) {
            const double lo = static_cast<double>(d) * sn / dn;
            const double hi = static_cast<double>(d + 1) * sn / dn;
            double acc = 0.0, wsum = 0.0;
            for (int s = 0; s < sn; ++s) {
                const double a = std::max(lo, static_cast<double>(s));
                const double b = std::min(hi, static_cast<double>(s) + 1.0);
                if (b > a) {
                    acc += in[static_cast<size_t>(r) * sn + s] * (b - a);
                    wsum += b - a;
                }
            }
            out[static_cast<size_t>(r) * dn + d] = acc / wsum;
        }
    }
}

std::vector<uint8_t> ReferenceArea(const Surface& src, int dw, int dh, int c) {
    const int sw = src.width();
    const int sh = src.height();
    std::vector<double> chan(static_cast<size_t>(sw) * sh);
    for (int y = 0; y < sh; ++y) {
        for (int x = 0; x < sw; ++x) {
            uint8_t r = 0, g = 0, b = 0, a = 0;
            src.GetPixel(x, y, r, g, b, a);
            chan[static_cast<size_t>(y) * sw + x] =
                c == 0 ? r : c == 1 ? g : c == 2 ? b : a;
        }
    }
    std::vector<double> horiz;
    BoxPass(chan, sw, dw, sh, horiz);
    // Transpose so the vertical pass is the same 1-D box.
    std::vector<double> tr(static_cast<size_t>(sh) * dw);
    for (int y = 0; y < sh; ++y)
        for (int x = 0; x < dw; ++x)
            tr[static_cast<size_t>(x) * sh + y] = horiz[static_cast<size_t>(y) * dw + x];
    std::vector<double> vert;
    BoxPass(tr, sh, dh, dw, vert);
    std::vector<uint8_t> out(static_cast<size_t>(dw) * dh);
    for (int y = 0; y < dh; ++y)
        for (int x = 0; x < dw; ++x) {
            const double v = vert[static_cast<size_t>(x) * dh + y];
            out[static_cast<size_t>(y) * dw + x] =
                static_cast<uint8_t>(v + 0.5);
        }
    return out;
}

uint8_t ChannelOf(const Surface& s, int x, int y, int c) {
    uint8_t r = 0, g = 0, b = 0, a = 0;
    s.GetPixel(x, y, r, g, b, a);
    return c == 0 ? r : c == 1 ? g : c == 2 ? b : a;
}

}  // namespace
RTSC_TEST(view_downscale_contract_literals_hand_computed) {
    // Contract literals (E13). All three are hand-computable, non-integer or
    // single-axis reductions that the uniform 2-D box does not cover.

    // 0.8x ramp 5 -> 4, source 51*i = 0,51,102,153,204. Coverage weights are
    // exact overlaps with denominator 5:
    //   d=0: (0*4 + 51*1)/5 =  10.2 -> 10
    //   d=1: (51*3 + 102*2)/5 = 71.4 -> 71
    //   d=2: (102*2 + 153*3)/5 = 132.6 -> 133
    //   d=3: (153*1 + 204*4)/5 = 193.8 -> 194
    {
        Surface src(5, 1);
        for (int x = 0; x < 5; ++x) {
            const uint8_t v = static_cast<uint8_t>(51 * x);
            src.SetPixel(x, 0, v, v, v, 255);
        }
        Surface dst(4, 1);
        ScaleSurface(src, dst, MakeVT(5, 1, 4, 1));
        static const uint8_t expect[4] = {10, 71, 133, 194};
        for (int x = 0; x < 4; ++x) CHECK_EQ(ChannelOf(dst, x, 0, 0), expect[x]);
    }

    // 7x5 -> 3x2 with the x ramp 36*i (0,36,72,108,144,180,216), constant in y:
    //   d=0: (3/7)*(0 + 36 + 72/3)   = 25.71 -> 26
    //   d=1: (3/7)*(72*2/3 + 108 + 144*2/3) = 108
    //   d=2: (3/7)*(144/3 + 180 + 216)      = 190.29 -> 190
    // The vertical 5 -> 2 pass sees identical rows, so both output rows match.
    {
        Surface src(7, 5);
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 7; ++x) {
                const uint8_t v = static_cast<uint8_t>(36 * x);
                src.SetPixel(x, y, v, v, v, 255);
            }
        }
        Surface dst(3, 2);
        ScaleSurface(src, dst, MakeVT(7, 5, 3, 2));
        static const uint8_t expect[3] = {26, 108, 190};
        for (int y = 0; y < 2; ++y)
            for (int x = 0; x < 3; ++x) CHECK_EQ(ChannelOf(dst, x, y, 0), expect[x]);
    }
    // 1x8 -> 1x3 with a constant column of 28 in the middle band. The middle
    // destination row covers source rows ~2.67..5.33, so a constant column must
    // reproduce 28 exactly there (weights sum to the axis length). The band
    // edges prove the same for the partially covered rows.
    {
        Surface src(1, 8);
        src.Fill(28, 28, 28, 255);
        Surface dst(1, 3);
        ScaleSurface(src, dst, MakeVT(1, 8, 1, 3));
        for (int y = 0; y < 3; ++y) CHECK_EQ(ChannelOf(dst, 0, y, 0), 28);
    }
}

RTSC_TEST(view_downscale_2x2_to_1x1_averages_all_four) {
    // (0 + 100 + 128 + 255) / 4 = 120.75 -> 121 with round-half-up.
    // Hand-computed; the two-pass separable form also yields 121.
    Surface src(2, 2);
    src.SetPixel(0, 0, 0, 0, 0, 255);
    src.SetPixel(1, 0, 100, 100, 100, 255);
    src.SetPixel(0, 1, 128, 128, 128, 255);
    src.SetPixel(1, 1, 255, 255, 255, 255);

    Surface dst(1, 1);
    const auto vt = ComputeViewTransform(2, 2, 1, 1, 0.5, false);
    CHECK_EQ(vt.width, 1);
    CHECK_EQ(vt.height, 1);
    ScaleSurface(src, dst, vt);

    const uint8_t r = ChannelOf(dst, 0, 0, 0);
    CHECK_EQ(r, 121);  // contract value: (0+100+128+255)/4 = 120.75 -> 121
    CHECK_EQ(ChannelOf(dst, 0, 0, 1), r);  // grey: all colour channels agree
}

RTSC_TEST(view_downscale_1px_stripes_average_to_half) {
    // 16 alternating black/white pixels -> 8. Each destination pixel covers one
    // black + one white source pixel: (0 + 255) / 2 = 127.5 -> 128. A point
    // sampler would output 0 (it only ever hits the even, black source pixel).
    Surface src(16, 1);
    for (int x = 0; x < 16; ++x) {
        const uint8_t v = (x % 2) ? 255 : 0;
        src.SetPixel(x, 0, v, v, v, 255);
    }
    Surface dst(8, 1);
    ScaleSurface(src, dst, MakeVT(16, 1, 8, 1));
    for (int x = 0; x < 8; ++x) CHECK_EQ(ChannelOf(dst, x, 0, 0), 128);
}

RTSC_TEST(view_downscale_checkerboard_averages_to_mid_grey) {
    // 32x32 one-pixel checker -> 4x4. Every destination pixel covers 8x8 = 64
    // source pixels, exactly 32 black + 32 white: (0*32 + 255*32) / 64 = 127.5
    // -> 128 for all 16 output pixels.
    Surface src(32, 32);
    for (int y = 0; y < 32; ++y) {
        for (int x = 0; x < 32; ++x) {
            const uint8_t v = ((x + y) % 2) ? 255 : 0;
            src.SetPixel(x, y, v, v, v, 255);
        }
    }
    Surface dst(4, 4);
    ScaleSurface(src, dst, MakeVT(32, 32, 4, 4));
    for (int y = 0; y < 4; ++y)
        for (int x = 0; x < 4; ++x) CHECK_EQ(ChannelOf(dst, x, y, 0), 128);
}

RTSC_TEST(view_downscale_single_axis_also_rounds_half_up) {
    // A reduction on one axis only must average that axis. E14 records that GDI
    // yields 127 for the single-axis shapes (16xH -> 8xH) and 128 for the
    // two-axis ones; this project rounds half up everywhere, so both give 128.
    // That difference from GDI is a documented rounding convention (D-1), not a
    // claim of byte equality.
    struct Case {
        int sw, sh, dw, dh;
    };
    static const Case cases[] = {{16, 8, 8, 8}, {16, 16, 8, 16}, {16, 32, 8, 32},
                                 {16, 8, 8, 4}, {16, 16, 8, 8},  {16, 32, 8, 16}};
    for (const Case& c : cases) {
        Surface src(static_cast<uint16_t>(c.sw), static_cast<uint16_t>(c.sh));
        for (int y = 0; y < c.sh; ++y) {
            for (int x = 0; x < c.sw; ++x) {
                const uint8_t v = (x % 2) ? 255 : 0;
                src.SetPixel(x, y, v, v, v, 255);
            }
        }
        Surface dst(static_cast<uint16_t>(c.dw), static_cast<uint16_t>(c.dh));
        ScaleSurface(src, dst, MakeVT(c.sw, c.sh, c.dw, c.dh));
        for (int y = 0; y < c.dh; ++y)
            for (int x = 0; x < c.dw; ++x) CHECK_EQ(ChannelOf(dst, x, y, 0), 128);
    }
}

RTSC_TEST(view_upscale_never_invents_a_colour) {
    // Mutation guard that does not depend on any measured value: enlargement is
    // nearest, so the destination palette is a subset of the source palette and
    // no new colour appears. An interpolating implementation fails this on a
    // non-integer factor (1.33x / 1.37x), where it must blend.
    struct Case {
        int sw, sh, dw, dh;
    };
    static const Case cases[] = {{1920, 1080, 2560, 1440}, {100, 100, 137, 137},
                                 {37, 23, 51, 31}};
    for (const Case& c : cases) {
        Surface src(static_cast<uint16_t>(c.sw), static_cast<uint16_t>(c.sh));
        for (int y = 0; y < c.sh; ++y) {
            for (int x = 0; x < c.sw; ++x) {
                // Low-frequency ramp with a hard palette, so a blend would be
                // obvious; the checker of different colours also proves the
                // guard is not accidentally trivially satisfiable.
                const uint8_t v = static_cast<uint8_t>((x * 7 + y * 13) % 5 * 63);
                src.SetPixel(x, y, v, static_cast<uint8_t>(255 - v), 17, 255);
            }
        }
        // E13(B): compare whole colour tuples, not individual channel values.
        // A per-channel subset test is weaker: a blend of two source colours can
        // land on values that each exist somewhere in the source palette while
        // the (R,G,B,A) tuple itself is new.
        std::vector<uint64_t> src_colours;
        for (int y = 0; y < c.sh; ++y) {
            for (int x = 0; x < c.sw; ++x) {
                uint64_t key = 0;
                for (int ch = 0; ch < 4; ++ch) {
                    key = (key << 8) | ChannelOf(src, x, y, ch);
                }
                src_colours.push_back(key);
            }
        }
        std::sort(src_colours.begin(), src_colours.end());
        src_colours.erase(std::unique(src_colours.begin(), src_colours.end()),
                          src_colours.end());

        Surface dst(static_cast<uint16_t>(c.dw), static_cast<uint16_t>(c.dh));
        ScaleSurface(src, dst, MakeVT(c.sw, c.sh, c.dw, c.dh));
        int invented = 0;
        for (int y = 0; y < c.dh; ++y) {
            for (int x = 0; x < c.dw; ++x) {
                uint64_t key = 0;
                for (int ch = 0; ch < 4; ++ch) {
                    key = (key << 8) | ChannelOf(dst, x, y, ch);
                }
                if (!std::binary_search(src_colours.begin(),
                                        src_colours.end(), key)) {
                    ++invented;
                }
            }
        }
        CHECK_EQ(invented, 0);
    }
}

RTSC_TEST(view_letterbox_1to1_does_not_read_outside_the_source) {
    // D-4: widening the exact-copy test to "destination size == source size"
    // is only correct if both the read and the write carry the view offset. A
    // 16x8 source placed at y = 2 in a 16x12 viewport previously read source
    // rows 2..9 (two rows past the end) and copied the wrong pixels.
    Surface src(16, 8);
    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 16; ++x) {
            src.SetPixel(x, y, static_cast<uint8_t>(x), static_cast<uint8_t>(y),
                         static_cast<uint8_t>(x ^ y), 255);
        }
    }
    Surface dst(16, 12);
    dst.Fill(0xAA, 0xAA, 0xAA, 0xAA);  // marker: untouched rows must stay 0xAA
    ViewTransform vt;
    vt.x = 0;
    vt.y = 2;
    vt.width = 16;
    vt.height = 8;
    CHECK(ChooseResample(vt, 16, 8) == Resample::kExact);
    ScaleSurface(src, dst, vt);

    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 16; ++x) {
            for (int c = 0; c < 4; ++c) {
                CHECK_EQ(ChannelOf(dst, x, y + 2, c), ChannelOf(src, x, y, c));
            }
        }
    }
    // The bars (rows 0..1 and 10..11) must not have been written.
    for (int y : {0, 1, 10, 11}) {
        for (int x = 0; x < 16; ++x) {
            for (int c = 0; c < 4; ++c) CHECK_EQ(ChannelOf(dst, x, y, c), 0xAA);
        }
    }
}

RTSC_TEST(view_downscale_ramp_matches_hand_computed_area) {
    // 16x1 ramp v[i] = 3*i + 1 (1 .. 46) -> 8x1. Destination pixel d covers
    // sources 2d and 2d+1, so the value is the mean of two odd-spaced samples,
    // always x.5 and rounded up:
    //   (1+4)/2=2.5->3   (7+10)/2=8.5->9   (13+16)/2=14.5->15  (19+22)/2=20.5->21
    //   (25+28)/2=26.5->27 (31+34)/2=32.5->33 (37+40)/2=38.5->39 (43+46)/2=44.5->45
    Surface src(16, 1);
    for (int x = 0; x < 16; ++x) {
        const uint8_t v = static_cast<uint8_t>(3 * x + 1);
        src.SetPixel(x, 0, v, v, v, 255);
    }
    Surface dst(8, 1);
    ScaleSurface(src, dst, MakeVT(16, 1, 8, 1));
    static const uint8_t expect[8] = {3, 9, 15, 21, 27, 33, 39, 45};
    for (int x = 0; x < 8; ++x) CHECK_EQ(ChannelOf(dst, x, 0, 0), expect[x]);
}

RTSC_TEST(view_downscale_keeps_odd_single_pixel_line) {
    // White 16x4 field with a single black column at x = 7 (an odd column, so a
    // point sampler drops it entirely). At 0.5x destination column 3 covers
    // sources 6 and 7: (255 + 0) / 2 = 127.5 -> 128, i.e. a visible grey line
    // in [96, 160]; it must never stay pure white.
    Surface src(16, 4);
    src.Fill(255, 255, 255, 255);
    for (int y = 0; y < 4; ++y) src.SetPixel(7, y, 0, 0, 0, 255);

    Surface dst(8, 4);
    ScaleSurface(src, dst, MakeVT(16, 4, 8, 4));
    for (int y = 0; y < 4; ++y) {
        const uint8_t v = ChannelOf(dst, 3, y, 0);
        CHECK_EQ(v, 128);  // contract value: (255+0)/2 = 127.5 -> 128 (round half up)
        CHECK(v != 255);
        CHECK_EQ(ChannelOf(dst, 0, y, 0), 255);  // untouched white stays white
    }
}

RTSC_TEST(view_downscale_alpha_uses_the_same_weights) {
    // Alpha is resampled exactly like R/G/B here (deliberate improvement D-2;
    // GDI leaves alpha untouched). Source alpha 0,0,0,255,255,255,255,255 at
    // 0.5x -> (0+0)/2=0, (0+255)/2=127.5->128, 255, 255.
    // This shape is one row, so it exercises the generic tap path only; the 2-D
    // uniform fast path has its own case right below.
    Surface src(8, 1);
    for (int x = 0; x < 8; ++x) {
        src.SetPixel(x, 0, 200, 100, 50, x < 3 ? 0 : 255);
    }
    Surface dst(4, 1);
    ScaleSurface(src, dst, MakeVT(8, 1, 4, 1));
    static const uint8_t expect[4] = {0, 128, 255, 255};
    for (int x = 0; x < 4; ++x) CHECK_EQ(ChannelOf(dst, x, 0, 3), expect[x]);
}

RTSC_TEST(view_downscale_2d_fast_path_averages_alpha) {
    // Regression guard for the kx x ky uniform fast path (the specialisation
    // that used to be the only untested branch): 8x2 -> 4x1 shrinks both axes, so
    // it takes that path. A mutant that copies the block's corner alpha instead
    // of averaging it produces 0 0 255 255 here while the 1-D case above still
    // passes -- which is exactly why this case must exist.
    Surface src(8, 2);
    for (int y = 0; y < 2; ++y) {
        for (int x = 0; x < 8; ++x) {
            src.SetPixel(x, y, 200, 100, 50, x < 3 ? 0 : 255);
        }
    }
    Surface dst(4, 1);
    ScaleSurface(src, dst, MakeVT(8, 2, 4, 1));
    static const uint8_t expect[4] = {0, 128, 255, 255};
    for (int x = 0; x < 4; ++x) CHECK_EQ(ChannelOf(dst, x, 0, 3), expect[x]);
}

RTSC_TEST(view_downscale_1x2_to_1x1_tie_rounds_up) {
    // total = 2, exact tie: (0 + 255) / 2 = 127.5 must round half up to 128
    // (D-1). A truncating implementation gives 127; this is the smallest shape
    // that still discriminates the rounding convention.
    Surface src(1, 2);
    src.SetPixel(0, 0, 0, 0, 0, 255);
    src.SetPixel(0, 1, 255, 255, 255, 255);
    Surface dst(1, 1);
    ScaleSurface(src, dst, MakeVT(1, 2, 1, 1));
    CHECK_EQ(ChannelOf(dst, 0, 0, 0), 128);
    CHECK_EQ(ChannelOf(dst, 0, 0, 3), 255);
}

RTSC_TEST(view_downscale_2x3_matches_reference) {
    // An explicit non-uniform 2x3 -> 1x2 reduction, verified both against the
    // independent double reference and against hand-computed literals, so a
    // coverage-weighting regression cannot hide behind the round 2:1 figures.
    // Values R = 10*x + y: acc(0,0) = ((0+10)*1 + (1+11)*0.5)/3 = 16/3 -> 5,
    // acc(0,1) = ((1+11)*0.5 + (2+12)*1)/3 = 20/3 -> 7.
    Surface src(2, 3);
    for (int y = 0; y < 3; ++y) {
        for (int x = 0; x < 2; ++x) {
            const uint8_t v = static_cast<uint8_t>(10 * x + y);
            src.SetPixel(x, y, v, static_cast<uint8_t>(y * 7),
                         static_cast<uint8_t>(x * 3),
                         static_cast<uint8_t>(64 + 64 * y));
        }
    }
    Surface dst(1, 2);
    ScaleSurface(src, dst, MakeVT(2, 3, 1, 2));
    CHECK_EQ(ChannelOf(dst, 0, 0, 0), 5);
    CHECK_EQ(ChannelOf(dst, 0, 1, 0), 7);
    for (int c = 0; c < 4; ++c) {
        const std::vector<uint8_t> ref = ReferenceArea(src, 1, 2, c);
        CHECK_EQ(ChannelOf(dst, 0, 0, c), ref[0]);
        CHECK_EQ(ChannelOf(dst, 0, 1, c), ref[1]);
    }
}

RTSC_TEST(view_downscale_semi_transparent_alpha_averages) {
    // D-2: alpha is averaged with the same weights as R/G/B even when it is
    // semi-transparent, not only on the 0/255 hard edges of the alpha cases
    // above. 2x2 -> 1x1 gives every weight 1, so each channel is the mean.
    Surface src(2, 2);
    src.SetPixel(0, 0, 200, 100, 50, 64);
    src.SetPixel(1, 0, 100, 200, 25, 128);
    src.SetPixel(0, 1, 150, 50, 200, 192);
    src.SetPixel(1, 1, 50, 150, 100, 255);
    Surface dst(1, 1);
    ScaleSurface(src, dst, MakeVT(2, 2, 1, 1));
    // R: (200+100+150+50)/4 = 125; G = 125; B: 375/4 = 93.75 -> 94;
    // A: (64+128+192+255)/4 = 159.75 -> 160.
    CHECK_EQ(ChannelOf(dst, 0, 0, 0), 125);
    CHECK_EQ(ChannelOf(dst, 0, 0, 1), 125);
    CHECK_EQ(ChannelOf(dst, 0, 0, 2), 94);
    CHECK_EQ(ChannelOf(dst, 0, 0, 3), 160);
}

RTSC_TEST(view_scale_zero_source_is_safe) {
    // A 0-sized source must be a no-op, not a crash or an out-of-bounds read:
    // ScaleSurface's size guard returns before any resample choice is made.
    // The destination rectangle is deliberately non-trivial so it is the source
    // guard -- not the viewport guard -- that must do the work.
    Surface src(0, 0);
    Surface dst(8, 8);
    dst.Fill(0x11, 0x22, 0x33, 0xFF);
    ViewTransform vt;
    vt.width = 8;
    vt.height = 8;
    vt.scale = 1.0;
    vt.scale_x = 1.0;
    vt.scale_y = 1.0;
    ScaleSurface(src, dst, vt);  // must not crash
    // The whole viewport is untouched: no copy, no resample writes anything.
    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 8; ++x) {
            CHECK_EQ(ChannelOf(dst, x, y, 0), static_cast<uint8_t>(0x11));
            CHECK_EQ(ChannelOf(dst, x, y, 3), static_cast<uint8_t>(0xFF));
        }
    }
}

RTSC_TEST(view_downscale_exact_half_tie_rounds_up) {
    // F1 regression guard: an exact .5 average must round up. 1440x900 downscaled
    // by the standard 75% preset gives vt = 1080x675 at (180,112); destination
    // pixel (0,0) then covers 1.3333x1.3333 source pixels, so a single grey 56
    // source pixel at (0,0) contributes 56 * (0.75*0.75) = 31.5 exactly.
    //   exact half-up            -> 32
    //   double acc * (1/total)   -> 31.499999999999996 + 0.5 -> trunc 31  (F1)
    // total = 1440*900 = 1296000, weight = 729000 = 1296000 * 0.5625.
    Surface src(1440, 900);
    src.Fill(0, 0, 0, 255);
    src.SetPixel(0, 0, 56, 56, 56, 255);

    Surface dst(1440, 900);
    const auto vt = ComputeViewTransform(1440, 900, 1440, 900, 0.75, false);
    CHECK_EQ(vt.width, 1080);
    CHECK_EQ(vt.height, 675);
    CHECK_EQ(vt.x, 180);
    CHECK_EQ(vt.y, 112);
    ScaleSurface(src, dst, vt);
    CHECK_EQ(ChannelOf(dst, 180, 112, 0), 32);

    // The neighbours are pure black, so the tie is not contaminated by them.
    CHECK_EQ(ChannelOf(dst, 181, 112, 0), 0);
    CHECK_EQ(ChannelOf(dst, 180, 113, 0), 0);
}

RTSC_TEST(view_downscale_non_integer_08x_matches_reference) {
    // 5 -> 4 is not an integer ratio. The expectations below are hand-computed
    // coverage averages (denominator is the source pixel count, 5):
    //   d=0: (0*4 + 64*1)/5 = 12.8  -> 13
    //   d=1: (64*3 + 128*2)/5 = 89.6 -> 90
    //   d=2: (128*2 + 192*3)/5 = 166.4 -> 166
    //   d=3: (192*1 + 255*4)/5 = 242.4 -> 242
    Surface src(5, 1);
    static const uint8_t ramp[5] = {0, 64, 128, 192, 255};
    for (int x = 0; x < 5; ++x) src.SetPixel(x, 0, ramp[x], ramp[x], ramp[x], 255);

    Surface dst(4, 1);
    ScaleSurface(src, dst, MakeVT(5, 1, 4, 1));
    static const uint8_t expect[4] = {13, 90, 166, 242};
    for (int x = 0; x < 4; ++x) CHECK_EQ(ChannelOf(dst, x, 0, 0), expect[x]);

    // Cross-check against the independent double-precision reference.
    const std::vector<uint8_t> ref = ReferenceArea(src, 4, 1, 0);
    for (int x = 0; x < 4; ++x) CHECK_EQ(ChannelOf(dst, x, 0, 0), ref[static_cast<size_t>(x)]);
}

RTSC_TEST(view_upscale_non_integer_uses_e8_index_map) {
    // 3 -> 5 and 8 -> 13 are the two sizes that distinguish the measured E8
    // map from a plain floor(d*S/D). E8: 0 0 1 2 2  vs floor: 0 0 1 1 2, and
    // E8: 0 0 1 2 2 3 3 4 5 5 6 7 7 vs floor: 0 0 1 1 2 3 3 4 4 5 6 6 7.
    Surface a(3, 1);
    for (int x = 0; x < 3; ++x) {
        const uint8_t v = static_cast<uint8_t>(x);
        a.SetPixel(x, 0, v, v, v, 255);
    }
    Surface da(5, 1);
    ScaleSurface(a, da, MakeVT(3, 1, 5, 1));
    static const uint8_t expect_a[5] = {0, 0, 1, 2, 2};
    for (int x = 0; x < 5; ++x) CHECK_EQ(ChannelOf(da, x, 0, 0), expect_a[x]);

    Surface b(8, 1);
    for (int x = 0; x < 8; ++x) {
        const uint8_t v = static_cast<uint8_t>(x);
        b.SetPixel(x, 0, v, v, v, 255);
    }
    Surface db(13, 1);
    ScaleSurface(b, db, MakeVT(8, 1, 13, 1));
    for (int x = 0; x < 13; ++x)
        CHECK_EQ(ChannelOf(db, x, 0, 0), static_cast<uint8_t>(E8Index(x, 8, 13)));

    // 8 -> 11 (1.375x) is the third discriminating size: E8 gives
    // 0 1 1 2 3 3 4 5 6 6 7 here.
    Surface dc(11, 1);
    ScaleSurface(b, dc, MakeVT(8, 1, 11, 1));
    static const uint8_t expect_c[11] = {0, 1, 1, 2, 3, 3, 4, 5, 6, 6, 7};
    for (int x = 0; x < 11; ++x) {
        CHECK_EQ(ChannelOf(dc, x, 0, 0), static_cast<uint8_t>(E8Index(x, 8, 11)));
        CHECK_EQ(ChannelOf(dc, x, 0, 0), expect_c[x]);
    }
}

RTSC_TEST(view_choose_resample_covers_every_axis_combination) {
    // The rule is per axis, not per "zoom factor": a view that shrinks on one
    // axis must average even when the other axis is unchanged or growing, while
    // a view that only grows or keeps a size must replicate.
    struct Case {
        int sw, sh, dw, dh;
        Resample want;
    };
    static const Case cases[] = {
        {8, 8, 8, 8, Resample::kExact},    // 1:1
        {8, 8, 4, 4, Resample::kArea},     // both shrink
        {8, 8, 4, 8, Resample::kArea},     // one shrinks, one unchanged
        {8, 8, 4, 16, Resample::kArea},    // one shrinks, one grows
        {8, 8, 10, 8, Resample::kNearest}, // one grows, one unchanged
        {8, 8, 12, 12, Resample::kNearest},
        {8, 8, 16, 16, Resample::kNearest},
        {1, 200, 1, 333, Resample::kNearest},
    };
    for (const Case& c : cases) {
        CHECK(ChooseResample(MakeVT(c.sw, c.sh, c.dw, c.dh), c.sw, c.sh) == c.want);
    }
    // A centred 1:1 view is still exact: the size matches, only the origin moved.
    ViewTransform centred;
    centred.x = 2;
    centred.y = 2;
    centred.width = 4;
    centred.height = 4;
    CHECK(ChooseResample(centred, 4, 4) == Resample::kExact);
}

RTSC_TEST(view_integer_2x_equals_reference_nearest) {
    // Regression guard: 2x must stay an exact block copy equal to an
    // independently computed nearest-neighbour image (E8 at an integer factor).
    // If the upscale path is ever "improved" to interpolate, this fails.
    Surface src(4, 4);
    for (int y = 0; y < 4; ++y) {
        for (int x = 0; x < 4; ++x) {
            const uint8_t v = static_cast<uint8_t>(x * 16 + y);
            src.SetPixel(x, y, v, static_cast<uint8_t>(255 - v), v / 2, 255);
        }
    }
    Surface dst(8, 8);
    ScaleSurface(src, dst, MakeVT(4, 4, 8, 8));

    Surface ref(8, 8);
    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 8; ++x) {
            uint8_t r = 0, g = 0, b = 0, a = 0;
            src.GetPixel(E8Index(x, 4, 8), E8Index(y, 4, 8), r, g, b, a);
            ref.SetPixel(x, y, r, g, b, a);
        }
    }
    CHECK(std::memcmp(dst.data(), ref.data(), ref.size()) == 0);
}

RTSC_TEST(view_upscale_1x200_to_1x333_is_monotone) {
    // A vertical 0..199 ramp enlarged to 333 rows must stay non-decreasing and
    // keep its endpoints: nearest sampling never reorders and never invents a
    // value outside the source set.
    Surface src(1, 200);
    for (int y = 0; y < 200; ++y) {
        const uint8_t v = static_cast<uint8_t>(y);
        src.SetPixel(0, y, v, v, v, 255);
    }
    Surface dst(1, 333);
    ScaleSurface(src, dst, MakeVT(1, 200, 1, 333));
    CHECK_EQ(ChannelOf(dst, 0, 0, 0), 0);
    CHECK_EQ(ChannelOf(dst, 0, 332, 0), 199);
    for (int y = 1; y < 333; ++y) {
        CHECK(ChannelOf(dst, 0, y, 0) >= ChannelOf(dst, 0, y - 1, 0));
    }
}

RTSC_TEST(view_upscale_1x1_replicates_the_pixel) {
    // A single source pixel must fill the whole destination at every upscale
    // factor (2, 7, 31), all four channels included.
    for (int n : {2, 7, 31}) {
        Surface src(1, 1);
        src.SetPixel(0, 0, 77, 88, 99, 255);
        Surface dst(static_cast<uint16_t>(n), static_cast<uint16_t>(n));
        ScaleSurface(src, dst, MakeVT(1, 1, n, n));
        for (int y = 0; y < n; ++y) {
            for (int x = 0; x < n; ++x) {
                CHECK_EQ(ChannelOf(dst, x, y, 0), 77);
                CHECK_EQ(ChannelOf(dst, x, y, 1), 88);
                CHECK_EQ(ChannelOf(dst, x, y, 2), 99);
                CHECK_EQ(ChannelOf(dst, x, y, 3), 255);
            }
        }
    }
}

RTSC_TEST(view_letterbox_1to1_is_bit_exact) {
    // A 1:1 view that is merely offset (letterbox bars) must still be an exact
    // copy, not a resample: the source is 4x4 and the destination 8x8 places it
    // at (2,2), so the image area has to be byte-identical to the source.
    Surface src(4, 4);
    for (int y = 0; y < 4; ++y) {
        for (int x = 0; x < 4; ++x) {
            src.SetPixel(x, y, static_cast<uint8_t>(x * 60 + 3),
                         static_cast<uint8_t>(y * 60 + 7),
                         static_cast<uint8_t>(x * y + 11), 200);
        }
    }
    Surface dst(8, 8);
    const auto vt = ComputeViewTransform(4, 4, 8, 8, 1.0, false);
    CHECK_EQ(vt.width, 4);
    CHECK_EQ(vt.height, 4);
    CHECK_EQ(vt.x, 2);
    CHECK_EQ(vt.y, 2);
    ScaleSurface(src, dst, vt);
    for (int y = 0; y < 4; ++y) {
        for (int x = 0; x < 4; ++x) {
            for (int c = 0; c < 4; ++c) {
                CHECK_EQ(ChannelOf(dst, vt.x + x, vt.y + y, c), ChannelOf(src, x, y, c));
            }
        }
    }
}

RTSC_TEST(view_integer_2x_is_exact_block_copy) {
    Surface src(4, 4);
    src.Fill(0, 0, 0, 255);
    src.SetPixel(1, 2, 0xFF, 0, 0, 0xFF);  // one red source pixel

    Surface dst(8, 8);
    const auto vt = ComputeViewTransform(4, 4, 8, 8, 2.0, false);
    CHECK_EQ(vt.width, 8);
    CHECK_EQ(vt.height, 8);
    CHECK_EQ(vt.x, 0);
    CHECK_EQ(vt.y, 0);

    ScaleSurface(src, dst, vt);
    // Source (1,2) must fill destination (2,3) x (4,5).
    for (int y = 4; y <= 5; ++y) {
        for (int x = 2; x <= 3; ++x) {
            CHECK(IsRed(dst, x, y));
        }
    }
    CHECK_EQ(CountRed(dst), 4);
    CHECK(IsBlack(dst, 0, 0));
    CHECK(IsBlack(dst, 3, 3));
}

RTSC_TEST(view_fit_preserves_aspect_ratio_with_letterbox) {
    Surface src(8, 4);
    src.Fill(0xFF, 0, 0, 0xFF);

    Surface dst(8, 8);
    const auto vt = ComputeViewTransform(8, 4, 8, 8, 1.0, true);
    CHECK_EQ(vt.width, 8);
    CHECK_EQ(vt.height, 4);
    CHECK_EQ(vt.x, 0);
    CHECK_EQ(vt.y, 2);

    ScaleSurface(src, dst, vt);
    for (int y = 2; y <= 5; ++y) {
        for (int x = 0; x < 8; ++x) CHECK(IsRed(dst, x, y));
    }
    // Letterbox bars above and below are untouched (black).
    for (int x = 0; x < 8; ++x) {
        CHECK(IsBlack(dst, x, 0));
        CHECK(IsBlack(dst, x, 1));
        CHECK(IsBlack(dst, x, 6));
        CHECK(IsBlack(dst, x, 7));
    }
}

RTSC_TEST(view_fit_uses_the_smaller_axis) {
    // 4x8 source in an 8x8 viewport: the vertical axis limits the scale to 1.
    Surface src(4, 8);
    src.Fill(0xFF, 0, 0, 0xFF);

    Surface dst(8, 8);
    const auto vt = ComputeViewTransform(4, 8, 8, 8, 1.0, true);
    CHECK_EQ(vt.width, 4);
    CHECK_EQ(vt.height, 8);
    CHECK_EQ(vt.x, 2);
    CHECK_EQ(vt.y, 0);

    ScaleSurface(src, dst, vt);
    for (int y = 0; y < 8; ++y) {
        for (int x = 2; x <= 5; ++x) CHECK(IsRed(dst, x, y));
    }
    // Columns outside the centred 4-wide image are black.
    for (int y = 0; y < 8; ++y) {
        CHECK(IsBlack(dst, 0, y));
        CHECK(IsBlack(dst, 1, y));
        CHECK(IsBlack(dst, 6, y));
        CHECK(IsBlack(dst, 7, y));
    }
}

RTSC_TEST(view_zoom_mode_centres_the_source) {
    Surface src(4, 4);
    src.Fill(0xFF, 0, 0, 0xFF);

    Surface dst(8, 8);
    const auto vt = ComputeViewTransform(4, 4, 8, 8, 1.0, false);
    CHECK_EQ(vt.width, 4);
    CHECK_EQ(vt.height, 4);
    CHECK_EQ(vt.x, 2);
    CHECK_EQ(vt.y, 2);

    ScaleSurface(src, dst, vt);
    for (int y = 2; y <= 5; ++y) {
        for (int x = 2; x <= 5; ++x) CHECK(IsRed(dst, x, y));
    }
    CHECK(IsBlack(dst, 0, 0));
    CHECK(IsBlack(dst, 7, 7));
}

RTSC_TEST(view_fit_upscales_to_fill_the_viewport) {
    Surface src(4, 4);
    src.Fill(0xFF, 0, 0, 0xFF);

    Surface dst(8, 8);
    const auto vt = ComputeViewTransform(4, 4, 8, 8, 1.0, true);
    CHECK_EQ(vt.scale, 2.0);
    CHECK_EQ(vt.width, 8);
    CHECK_EQ(vt.height, 8);

    ScaleSurface(src, dst, vt);
    CHECK_EQ(CountRed(dst), 64);
}

RTSC_TEST(view_map_viewport_point_round_trips) {
    // src 4x4 -> dst 8x8 at scale 2 (zoom mode): viewport (0,0) -> remote (0,0),
    // viewport (2,2) -> remote (1,1), viewport (7,7) -> remote (3,3).
    const auto vt = ComputeViewTransform(4, 4, 8, 8, 2.0, false);
    int rx = -1, ry = -1;
    MapViewportPoint(vt, 4, 4, 0, 0, rx, ry);
    CHECK_EQ(rx, 0);
    CHECK_EQ(ry, 0);
    MapViewportPoint(vt, 4, 4, 2, 2, rx, ry);
    CHECK_EQ(rx, 1);
    CHECK_EQ(ry, 1);
    MapViewportPoint(vt, 4, 4, 7, 7, rx, ry);
    CHECK_EQ(rx, 3);
    CHECK_EQ(ry, 3);
}

RTSC_TEST(view_map_viewport_point_clamps_letterbox) {
    // src 8x4 -> dst 8x8 fit: vt is 8x4 at (0,2). Rows 0..1 and 6..7 are bars.
    const auto vt = ComputeViewTransform(8, 4, 8, 8, 1.0, true);
    int rx = -1, ry = -1;
    MapViewportPoint(vt, 8, 4, 4, 0, rx, ry);
    CHECK_EQ(ry, 0);  // clamped to the top row
    MapViewportPoint(vt, 8, 4, 4, 7, rx, ry);
    CHECK_EQ(ry, 3);  // clamped to the bottom row
}

RTSC_TEST(view_map_viewport_point_uses_render_phase_3_to_5) {
    // T7: 3 -> 5 upscale. The renderer samples the centre of each destination
    // pixel's footprint (resample.cpp NearestIndex), so viewport column 3 was
    // painted from source column 2. The left-edge mapping returned 1, which is
    // a whole pixel off from what the user sees under the cursor.
    const auto vt = ComputeViewTransform(3, 3, 5, 5, 5.0 / 3.0, false);
    CHECK_EQ(vt.width, 5);
    CHECK_EQ(vt.height, 5);
    int rx = -1, ry = -1;
    MapViewportPoint(vt, 3, 3, 3, 3, rx, ry);
    CHECK_EQ(rx, 2);
    CHECK_EQ(ry, 2);
    // Every viewport column/row must map to the source pixel ScaleSurface
    // sampled there.
    for (int d = 0; d < vt.width; ++d) {
        MapViewportPoint(vt, 3, 3, d, d, rx, ry);
        CHECK_EQ(rx, E8Index(d, 3, 5));
        CHECK_EQ(ry, E8Index(d, 3, 5));
    }
}

RTSC_TEST(view_map_viewport_point_uses_render_phase_100_to_4) {
    // T8: 100 -> 4 reduction. The centre phase puts viewport column 1 on source
    // column 37; the left-edge mapping produced 25 (12 pixels off).
    const auto vt = ComputeViewTransform(100, 100, 4, 4, 0.04, false);
    CHECK_EQ(vt.width, 4);
    CHECK_EQ(vt.height, 4);
    int rx = -1, ry = -1;
    MapViewportPoint(vt, 100, 100, 1, 1, rx, ry);
    CHECK_EQ(rx, 37);
    CHECK_EQ(ry, 37);
    for (int d = 0; d < vt.width; ++d) {
        MapViewportPoint(vt, 100, 100, d, d, rx, ry);
        CHECK_EQ(rx, E8Index(d, 100, 4));
        CHECK_EQ(ry, E8Index(d, 100, 4));
    }
}

RTSC_TEST(view_map_viewport_point_uses_render_phase_y_axis) {
    // 7x5 -> 3x2 (fit). x and y are both non-integer ratios; the y axis is the
    // one the parent's T7/T8 cases did not cover. Viewport (2,1) is source
    // (5,3): left-edge would give (4,2).
    const auto vt = ComputeViewTransform(7, 5, 3, 2, 1.0, true);
    CHECK_EQ(vt.width, 3);
    CHECK_EQ(vt.height, 2);
    int rx = -1, ry = -1;
    MapViewportPoint(vt, 7, 5, 2, 1, rx, ry);
    CHECK_EQ(rx, 5);
    CHECK_EQ(ry, 3);
    CHECK_EQ(ry, E8Index(1, 5, 2));
}

RTSC_TEST(view_wheel_event_coordinates_map_through_viewport) {
    // T10 (input contract level): a wheel event carries the client-area
    // pointer position (the Win32 backend fills it from ScreenToClient on
    // WM_MOUSEWHEEL -- the window backend lives in the UI batch and is not
    // linked into this suite). The render loop maps ev.x/ev.y exactly like a
    // pointer move, so a wheel on viewport (1,3) of a 100 -> 4 view must
    // resolve to source (37,87), not the left-edge (25,75).
    const auto vt = ComputeViewTransform(100, 100, 4, 4, 0.04, false);
    ui::InputEvent wheel;
    wheel.kind = ui::InputEvent::Kind::kMouseWheel;
    wheel.wheel_delta = 120;
    wheel.x = 1;
    wheel.y = 3;
    int rx = -1, ry = -1;
    MapViewportPoint(vt, 100, 100, wheel.x, wheel.y, rx, ry);
    CHECK_EQ(rx, 37);
    CHECK_EQ(ry, 87);
    // A zero x/y (what the backend used to report for every wheel) lands on
    // the top-left source pixel; that is why the backend must fill them.
    MapViewportPoint(vt, 100, 100, 0, 0, rx, ry);
    CHECK_EQ(rx, 12);
    CHECK_EQ(ry, 12);
}

RTSC_TEST(view_fit_rounds_size_and_centres_within_bounds) {
    // 8x4 source in a 9x8 viewport: scale 1.125 -> 9x5, centred at x=0, y=1.
    // The odd leftover row lands below the image (floor((8-5)/2) == 1).
    Surface src(8, 4);
    src.Fill(0xFF, 0, 0, 0xFF);

    Surface dst(9, 8);
    const auto vt = ComputeViewTransform(8, 4, 9, 8, 1.0, true);
    CHECK_EQ(vt.scale, 1.125);
    CHECK_EQ(vt.width, 9);
    CHECK_EQ(vt.height, 5);
    CHECK_EQ(vt.x, 0);
    CHECK_EQ(vt.y, 1);

    ScaleSurface(src, dst, vt);
    for (int y = 1; y <= 5; ++y) {
        for (int x = 0; x < 9; ++x) CHECK(IsRed(dst, x, y));
    }
    CHECK(IsBlack(dst, 0, 0));
    CHECK(IsBlack(dst, 0, 6));
    CHECK(IsBlack(dst, 0, 7));
    CHECK_EQ(CountRed(dst), 9 * 5);
}

RTSC_TEST(view_clamp_zoom_bounds) {
    CHECK_EQ(ClampZoom(0.0), 1.0);
    CHECK_EQ(ClampZoom(-1.0), 1.0);
    CHECK_EQ(ClampZoom(0.1), 0.5);
    CHECK_EQ(ClampZoom(10.0), 5.0);
    CHECK_EQ(ClampZoom(1.5), 1.5);
}

RTSC_TEST(view_empty_viewport_is_safe) {
    const auto vt = ComputeViewTransform(4, 4, 0, 8, 1.0, true);
    CHECK_EQ(vt.width, 0);
    CHECK_EQ(vt.height, 0);

    Surface src(4, 4);
    src.Fill(0xFF, 0, 0, 0xFF);
    Surface dst(8, 8);
    ScaleSurface(src, dst, vt);  // must not crash
    CHECK_EQ(CountRed(dst), 0);
}

RTSC_TEST(zoom_wheel_in_and_out) {
    ZoomState zs;
    CHECK_EQ(zs.zoom, 1.0);
    CHECK(!zs.fit);  // the default view is 1:1, smart sizing off

    ui::InputEvent wheel;
    wheel.kind = ui::InputEvent::Kind::kMouseWheel;
    wheel.wheel_delta = 120;
    CHECK(ApplyZoomInput(wheel, zs));
    CHECK(zs.zoom > 1.0);
    CHECK(zs.zoom < 1.2);
    CHECK(!zs.fit);

    wheel.wheel_delta = -120;
    CHECK(ApplyZoomInput(wheel, zs));
    CHECK(zs.zoom > 0.9);
    CHECK(zs.zoom < 1.1);
}

RTSC_TEST(zoom_ctrl_wheel_is_fine) {
    ZoomState zs;
    ui::InputEvent ctrl;
    ctrl.kind = ui::InputEvent::Kind::kKey;
    ctrl.scancode = 0x1D;  // VK_CONTROL
    ctrl.key_release = false;
    CHECK(!ApplyZoomInput(ctrl, zs));  // Ctrl itself is not consumed
    CHECK(zs.ctrl);

    ui::InputEvent wheel;
    wheel.kind = ui::InputEvent::Kind::kMouseWheel;
    wheel.wheel_delta = 120;
    CHECK(ApplyZoomInput(wheel, zs));
    CHECK(zs.zoom > 1.0);
    CHECK(zs.zoom < 1.05);
}

RTSC_TEST(zoom_wheel_clamps_at_max) {
    ZoomState zs;
    zs.zoom = 5.0;
    zs.fit = false;
    ui::InputEvent wheel;
    wheel.kind = ui::InputEvent::Kind::kMouseWheel;
    wheel.wheel_delta = 120;
    // Already at the maximum: the wheel must be CONSUMED (so the front-end does
    // not forward it as a remote-desktop scroll), and the zoom must not change.
    CHECK(ApplyZoomInput(wheel, zs));
    CHECK_EQ(zs.zoom, 5.0);
}

RTSC_TEST(zoom_wheel_at_both_limits_is_consumed) {
    ZoomState zs;
    zs.zoom = 5.0;
    zs.fit = false;
    ui::InputEvent wheel;
    wheel.kind = ui::InputEvent::Kind::kMouseWheel;
    wheel.wheel_delta = 120;   // would zoom past the 500% ceiling
    CHECK(ApplyZoomInput(wheel, zs));
    CHECK_EQ(zs.zoom, 5.0);

    zs.zoom = 0.5;             // at the 50% floor
    wheel.wheel_delta = -120;  // would zoom past it
    CHECK(ApplyZoomInput(wheel, zs));
    CHECK_EQ(zs.zoom, 0.5);
}

RTSC_TEST(zoom_wheel_zero_delta_is_ignored) {
    ZoomState zs;
    zs.zoom = 2.0;
    zs.fit = false;
    ui::InputEvent wheel;
    wheel.kind = ui::InputEvent::Kind::kMouseWheel;
    wheel.wheel_delta = 0;
    CHECK(!ApplyZoomInput(wheel, zs));  // not consumed, zoom untouched
    CHECK_EQ(zs.zoom, 2.0);

    // Same with Ctrl held (the fine step): a zero delta must not move zoom to
    // 1.975 as a negative step would.
    ZoomState c;
    c.zoom = 2.0;
    c.ctrl = true;
    CHECK(!ApplyZoomInput(wheel, c));
    CHECK_EQ(c.zoom, 2.0);
}

RTSC_TEST(view_map_monitor_point_clamps_into_union) {
    // The documented contract (view.h): the resulting desktop point is clamped
    // to the monitors' union. The old implementation voided union_w/union_h and
    // passed oversized or wrapped locals straight through, so a monitor left of
    // the primary wrapped the pointer to ~65531.
    int dx = 0, dy = 0;
    MapMonitorPointToDesktop(0, 0, 0, 0, 1920, 1080, 5000, 9000, dx, dy);
    CHECK_EQ(dx, 1919);
    CHECK_EQ(dy, 1079);

    // The 16-bit wire wrap: -5/-3 arrive as 65531/65533 unsigned and are
    // clamped back into the union.
    MapMonitorPointToDesktop(0, 0, 0, 0, 1920, 1080, 65531, 65533, dx, dy);
    CHECK_EQ(dx, 1919);
    CHECK_EQ(dy, 1079);

    // Negative values clamp to the union origin.
    MapMonitorPointToDesktop(0, 0, 0, 0, 1920, 1080, -50, -20, dx, dy);
    CHECK_EQ(dx, 0);
    CHECK_EQ(dy, 0);

    // A monitor left of the primary (origin at -1920, union 3840 wide): valid
    // local points still map through the union offset.
    MapMonitorPointToDesktop(-1920, 0, -1920, 0, 3840, 1080, 0, 0, dx, dy);
    CHECK_EQ(dx, 0);   // -1920 - (-1920) + 0
    CHECK_EQ(dy, 0);
    MapMonitorPointToDesktop(-1920, 0, -1920, 0, 3840, 1080, 4000, 5000, dx, dy);
    CHECK_EQ(dx, 3839);  // clamped into the union
    CHECK_EQ(dy, 1079);
}

RTSC_TEST(zoom_menu_presets) {
    ZoomState zs;
    ui::InputEvent e;
    e.kind = ui::InputEvent::Kind::kUiCommand;

    e.command = static_cast<uint8_t>(kCmdZoomPresetFirst + 3);  // 125%
    CHECK(ApplyZoomInput(e, zs));
    CHECK_EQ(zs.zoom, 1.25);
    CHECK(!zs.fit);

    e.command = kCmdFit;
    CHECK(ApplyZoomInput(e, zs));
    CHECK(zs.fit);

    e.command = 99;  // unknown: ignored
    CHECK(!ApplyZoomInput(e, zs));
    CHECK(zs.fit);
}

RTSC_TEST(zoom_smart_sizing_command_toggles_fit) {
    ZoomState zs;
    ui::InputEvent e;
    e.kind = ui::InputEvent::Kind::kUiCommand;

    zs.fit = true;
    e.command = kCmdToggleSmartSizing;
    CHECK(ApplyZoomInput(e, zs));
    CHECK(!zs.fit);
    CHECK(ApplyZoomInput(e, zs));
    CHECK(zs.fit);
}

RTSC_TEST(zoom_presets_cover_the_full_mstsc_range) {
    CHECK_EQ(rtsc::client::ZoomPresetCount(), 13);
    CHECK_EQ(rtsc::client::ZoomPresetZoom(0), 0.5);
    CHECK_EQ(rtsc::client::ZoomPresetZoom(1), 0.75);
    CHECK_EQ(rtsc::client::ZoomPresetZoom(2), 1.0);
    CHECK_EQ(rtsc::client::ZoomPresetZoom(12), 5.0);
    CHECK(std::string(rtsc::client::ZoomPresetLabel(0)) == "50%");
    CHECK(std::string(rtsc::client::ZoomPresetLabel(1)) == "75%");
    CHECK(std::string(rtsc::client::ZoomPresetLabel(2)) == "100%");
    CHECK(std::string(rtsc::client::ZoomPresetLabel(12)) == "500%");
    CHECK_EQ(rtsc::client::ZoomPresetIndex(1.25), 3);
    CHECK_EQ(rtsc::client::ZoomPresetIndex(2.0), 6);
    CHECK_EQ(rtsc::client::ZoomPresetIndex(1.1), -1);  // a wheel value is not a preset
    CHECK_EQ(rtsc::client::ZoomPresetZoom(-1), 1.0);   // out of range is safe
    CHECK_EQ(rtsc::client::ZoomPresetZoom(99), 1.0);
}

RTSC_TEST(zoom_presets_map_through_compute_view_transform) {
    // Every preset must reach ComputeViewTransform as its own scale factor.
    for (int i = 0; i < rtsc::client::kZoomPresetCount; ++i) {
        const double zoom = rtsc::client::ZoomPresetZoom(i);
        const auto vt = ComputeViewTransform(100, 100, 1000, 1000, zoom, false);
        CHECK_EQ(vt.scale, zoom);
        CHECK_EQ(vt.width, static_cast<int>(std::lround(100 * zoom)));
        CHECK_EQ(vt.height, static_cast<int>(std::lround(100 * zoom)));
    }
    // The two values the acceptance criteria name explicitly.
    CHECK_EQ(ComputeViewTransform(100, 100, 1000, 1000, 0.5, false).scale, 0.5);
    CHECK_EQ(ComputeViewTransform(100, 100, 1000, 1000, 5.0, false).scale, 5.0);
}

RTSC_TEST(zoom_menu_command_selects_each_preset) {
    for (int i = 0; i < rtsc::client::kZoomPresetCount; ++i) {
        ZoomState zs;
        ui::InputEvent e;
        e.kind = ui::InputEvent::Kind::kUiCommand;
        e.command = static_cast<uint8_t>(kCmdZoomPresetFirst + i);
        CHECK(ApplyZoomInput(e, zs));
        CHECK_EQ(zs.zoom, rtsc::client::ZoomPresetZoom(i));
        CHECK(!zs.fit);
    }
}

RTSC_TEST(zoom_ctrl_digit_presets) {
    ZoomState zs;
    ui::InputEvent ctrl;
    ctrl.kind = ui::InputEvent::Kind::kKey;
    ctrl.scancode = 0x1D;
    ctrl.key_release = false;
    ApplyZoomInput(ctrl, zs);

    ui::InputEvent digit;
    digit.kind = ui::InputEvent::Kind::kKey;
    digit.scancode = 0x03;  // RDP scancode for '2'
    digit.key_release = false;
    CHECK(ApplyZoomInput(digit, zs));
    CHECK_EQ(zs.zoom, 1.25);
    CHECK(!zs.fit);

    // The Win32 backend reports the virtual-key code instead (VK_2 == 0x32).
    ZoomState vk;
    ApplyZoomInput(ctrl, vk);
    ui::InputEvent vk_digit;
    vk_digit.kind = ui::InputEvent::Kind::kKey;
    vk_digit.scancode = 0x32;  // VK_2
    vk_digit.key_release = false;
    CHECK(ApplyZoomInput(vk_digit, vk));
    CHECK_EQ(vk.zoom, 1.25);

    ui::InputEvent release;
    release.kind = ui::InputEvent::Kind::kKey;
    release.scancode = 0x03;
    release.key_release = true;
    CHECK(!ApplyZoomInput(release, zs));  // a key release is not a preset
}

RTSC_TEST(zoom_ignores_non_view_events) {
    ZoomState zs;
    ui::InputEvent move;
    move.kind = ui::InputEvent::Kind::kMouseMove;
    move.x = 3;
    move.y = 4;
    CHECK(!ApplyZoomInput(move, zs));
    CHECK_EQ(zs.zoom, 1.0);
    CHECK(!zs.fit);
}

RTSC_TEST(graphics_defaults_to_1to1) {
    GraphicsPipeline g(8, 8);
    CHECK_EQ(g.zoom(), 1.0);
    CHECK(!g.fit());  // the default pipeline view is 1:1, smart sizing off
}

RTSC_TEST(graphics_render_to_scales_2x) {
    GraphicsPipeline g(4, 4);
    g.surface().Fill(0xFF, 0, 0, 0xFF);
    g.set_zoom(2.0);
    g.set_fit(false);

    Surface dst(8, 8);
    g.RenderTo(dst);
    CHECK_EQ(CountRed(dst), 64);
}

RTSC_TEST(graphics_render_to_fit_clears_letterbox) {
    GraphicsPipeline g(4, 4);
    g.surface().Fill(0xFF, 0, 0, 0xFF);
    g.set_zoom(1.0);
    g.set_fit(true);

    // 4x4 source in an 8x4 viewport: the vertical axis limits the scale to 1,
    // so the image is centred with black bars left and right.
    Surface dst(8, 4);
    g.RenderTo(dst);
    CHECK_EQ(CountRed(dst), 16);
    CHECK(IsBlack(dst, 0, 0));
    CHECK(IsBlack(dst, 1, 0));
    CHECK(IsBlack(dst, 6, 0));
    CHECK(IsBlack(dst, 7, 0));
}

RTSC_TEST(smartsizing_off_1to1_scale_contract) {
    // A6 gate: EnableSmartSizing=0 must render the desktop 1:1 and clip it to a
    // smaller viewport (no fit, no scaling). This locks the decided semantics:
    // fit=false + zoom=1.0 -> scale 1.0, natural size, origin at (0,0).
    Surface src(1920, 1080);
    for (int y = 0; y < src.height(); ++y) {
        for (int x = 0; x < src.width(); ++x) {
            src.SetPixel(x, y, static_cast<uint8_t>(x), static_cast<uint8_t>(y),
                         0x80, 0xFF);
        }
    }
    const auto vt = ComputeViewTransform(1920, 1080, 800, 600, 1.0, false);
    CHECK_EQ(vt.scale, 1.0);
    CHECK_EQ(vt.width, 1920);
    CHECK_EQ(vt.height, 1080);
    CHECK_EQ(vt.x, 0);
    CHECK_EQ(vt.y, 0);

    Surface dst(800, 600);
    ScaleSurface(src, dst, vt);
    // The whole 800x600 viewport is the source's top-left 800x600 region, byte
    // for byte (1:1 clip: no scaling, no fit).
    for (int y = 0; y < dst.height(); ++y) {
        const size_t src_off = static_cast<size_t>(y) * src.width() * 4;
        const size_t dst_off = static_cast<size_t>(y) * dst.width() * 4;
        CHECK(std::memcmp(src.data() + src_off, dst.data() + dst_off,
                          static_cast<size_t>(dst.width()) * 4) == 0);
    }
}

RTSC_TEST(smartsizing_off_1to1_pipeline_clips) {
    // The same gate through GraphicsPipeline::RenderTo: a 2x2 viewport shows
    // the source's top-left 2x2, unchanged (1:1 clip, no scaling).
    GraphicsPipeline g(4, 4);
    g.set_fit(false);
    g.set_zoom(1.0);
    for (int y = 0; y < 4; ++y) {
        for (int x = 0; x < 4; ++x) {
            g.surface().SetPixel(x, y, static_cast<uint8_t>(x * 40),
                                 static_cast<uint8_t>(y * 40), 0x80, 0xFF);
        }
    }
    Surface dst(2, 2);
    const auto vt = g.view_transform(dst.width(), dst.height());
    CHECK_EQ(vt.scale, 1.0);
    CHECK_EQ(vt.width, 4);
    CHECK_EQ(vt.height, 4);
    g.RenderTo(dst);
    // The 2x2 viewport is the source's top-left 2x2 region, byte for byte.
    for (int y = 0; y < dst.height(); ++y) {
        const size_t src_off = static_cast<size_t>(y) * g.surface().width() * 4;
        const size_t dst_off = static_cast<size_t>(y) * dst.width() * 4;
        CHECK(std::memcmp(g.surface().data() + src_off, dst.data() + dst_off,
                          static_cast<size_t>(dst.width()) * 4) == 0);
    }
}

RTSC_TEST(smartsizing_off_resize_keeps_semantics) {
    // A6 gate: resizing the viewport does not change the view model. The same
    // pipeline, unchanged, rendered into different viewports keeps scale 1.0;
    // only the destination rectangle is recomputed (a 1:1 image sits at (0,0)
    // in a source-sized viewport and is centred in a larger one).
    GraphicsPipeline g(4, 4);
    g.set_fit(false);
    g.set_zoom(1.0);
    g.surface().Fill(0xFF, 0, 0, 0xFF);

    {
        const auto vt = g.view_transform(4, 4);
        CHECK_EQ(vt.scale, 1.0);
        CHECK_EQ(vt.x, 0);
        CHECK_EQ(vt.y, 0);
    }
    Surface a(800, 600);
    const auto vta = g.view_transform(a.width(), a.height());
    CHECK_EQ(vta.scale, 1.0);
    CHECK_EQ(vta.x, (800 - 4) / 2);
    CHECK_EQ(vta.y, (600 - 4) / 2);
    g.RenderTo(a);
    CHECK_EQ(CountRed(a), 16);

    Surface b(2560, 1440);
    const auto vtb = g.view_transform(b.width(), b.height());
    CHECK_EQ(vtb.scale, 1.0);
    CHECK_EQ(vtb.x, (2560 - 4) / 2);
    CHECK_EQ(vtb.y, (1440 - 4) / 2);
    g.RenderTo(b);
    CHECK_EQ(CountRed(b), 16);
}

RTSC_TEST(view_scale_1to1_is_bit_exact) {
    // The default view is 1:1, so the scaled surface must be a byte-for-byte
    // copy of the remote surface (no scaling loss).
    Surface src(8, 6);
    for (int y = 0; y < src.height(); ++y) {
        for (int x = 0; x < src.width(); ++x) {
            src.SetPixel(x, y, static_cast<uint8_t>(x * 3),
                         static_cast<uint8_t>(y * 5),
                         static_cast<uint8_t>(x + y), 0xFF);
        }
    }
    Surface dst(8, 6);
    const auto vt = ComputeViewTransform(8, 6, 8, 6, 1.0, false);
    CHECK_EQ(vt.width, 8);
    CHECK_EQ(vt.height, 6);
    ScaleSurface(src, dst, vt);
    CHECK(dst.size() == src.size());
    CHECK(std::memcmp(dst.data(), src.data(), src.size()) == 0);
}

RTSC_TEST(view_scale_integer_2x_is_exact) {
    // A 2x zoom is an exact 2x2 block per source pixel, including a non-uniform
    // source. This is mstsc behaviour, not an implementation detail: GDI
    // HALFTONE was measured to replicate blocks at every integer factor
    // (docs/spec/scaling-evidence.md E7), so a change that "smooths" 2x is a
    // regression against the reference, not an improvement.
    Surface src(2, 2);
    src.SetPixel(0, 0, 0x11, 0x22, 0x33, 0xFF);
    src.SetPixel(1, 0, 0x44, 0x55, 0x66, 0xFF);
    src.SetPixel(0, 1, 0x77, 0x88, 0x99, 0xFF);
    src.SetPixel(1, 1, 0xAA, 0xBB, 0xCC, 0xFF);

    Surface dst(4, 4);
    const auto vt = ComputeViewTransform(2, 2, 4, 4, 2.0, false);
    ScaleSurface(src, dst, vt);
    const uint8_t expect[4][4][3] = {
        {{0x11, 0x22, 0x33}, {0x11, 0x22, 0x33}, {0x44, 0x55, 0x66}, {0x44, 0x55, 0x66}},
        {{0x11, 0x22, 0x33}, {0x11, 0x22, 0x33}, {0x44, 0x55, 0x66}, {0x44, 0x55, 0x66}},
        {{0x77, 0x88, 0x99}, {0x77, 0x88, 0x99}, {0xAA, 0xBB, 0xCC}, {0xAA, 0xBB, 0xCC}},
        {{0x77, 0x88, 0x99}, {0x77, 0x88, 0x99}, {0xAA, 0xBB, 0xCC}, {0xAA, 0xBB, 0xCC}},
    };
    for (int y = 0; y < 4; ++y) {
        for (int x = 0; x < 4; ++x) {
            uint8_t r = 0, g = 0, b = 0, a = 0;
            CHECK(dst.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, expect[y][x][0]);
            CHECK_EQ(g, expect[y][x][1]);
            CHECK_EQ(b, expect[y][x][2]);
        }
    }
}

RTSC_TEST(view_scale_non_integer_upscale_is_nearest) {
    // A non-integer upscale is nearest-neighbour, not interpolating: mstsc's
    // StretchBlt runs with GDI HALFTONE, which was measured to replicate source
    // pixels at 1.37x as well as at 2x/3x (docs/spec/scaling-evidence.md E7).
    // Source-index map for 2 -> 3 measured and derived as
    //     C(d) = ((2d + 1) * S - 1) / (2 * D)  =  0 0 1
    // (E8, independently re-derived here from the formula, not from the
    // implementation's output). So the centre destination pixel samples source
    // (0,0), which is the red corner -- the old bilinear value was (142,170,170).
    Surface src(2, 2);
    src.SetPixel(0, 0, 255, 0, 0, 255);
    src.SetPixel(1, 0, 0, 255, 0, 255);
    src.SetPixel(0, 1, 0, 0, 255, 255);
    src.SetPixel(1, 1, 255, 255, 255, 255);

    Surface dst(3, 3);
    const auto vt = ComputeViewTransform(2, 2, 3, 3, 1.5, false);  // scale 1.5
    CHECK_EQ(vt.width, 3);
    CHECK_EQ(vt.height, 3);
    ScaleSurface(src, dst, vt);

    static const uint8_t expect[3][3][3] = {
        {{255, 0, 0}, {255, 0, 0}, {0, 255, 0}},
        {{255, 0, 0}, {255, 0, 0}, {0, 255, 0}},
        {{0, 0, 255}, {0, 0, 255}, {255, 255, 255}},
    };
    for (int y = 0; y < 3; ++y) {
        for (int x = 0; x < 3; ++x) {
            uint8_t r = 0, g = 0, b = 0, a = 0;
            CHECK(dst.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, expect[y][x][0]);
            CHECK_EQ(g, expect[y][x][1]);
            CHECK_EQ(b, expect[y][x][2]);
        }
    }
}

RTSC_TEST(view_scale_benchmark_budget) {
    // Timing guard over the seven contract shapes (1:1 / letterbox up to 1080p,
    // 2x / 1.33x / 0.8x on 1080p, 0.5x and 0.4x on 4K). The budgets are ~3x the
    // measured value so they catch an algorithmic regression -- a return to
    // per-pixel division or a float resample is 10x or worse -- without failing
    // when unrelated load steals the CPU. Measured on an idle machine: 0.12 /
    // 0.12 / 4.8 / 16.5 / 14.4 / 2.8 / 30.5 ms; running the whole ctest suite
    // concurrently with other services has been observed to inflate the 4K
    // cases by ~50%, which the earlier 1.15x headroom could not absorb.
    //
    // The budgets only mean something for an OPTIMIZED build. An unoptimized
    // (-O0) build is 5-6x slower -- measured: the 0.4x 4K case takes 44 ms in
    // Release and 256 ms in the Debug build the Linux gate configures -- so
    // running this here would report an "algorithmic regression" that is just
    // the absence of -O2. Under NDEBUG (Release/RelWithDebInfo/MinSizeRel) the
    // budgets are a real guard; otherwise the test proves nothing and is
    // skipped rather than allowed to fail for the wrong reason.
#if defined(NDEBUG)
    struct Case {
        int sw, sh, dw, dh;
        const char* label;
        double budget_ms;
        // Iterations per sample, chosen so every sample lasts roughly 10 ms or
        // more. A single 0.11 ms call is dominated by jitter: the same case that
        // reads 0.11 ms idle reached 0.89 ms (7.4x) while a parallel build ran,
        // while the 43 ms case only doubled under the same load. Amortising the
        // small shapes makes every case respond to load the same way (about 2x),
        // which is what makes one budget policy work for all of them.
        int iters;
    };
    // Every budget is about 4x the idle measurement, and every sample is at
    // least ~10 ms so that jitter cannot dominate a single sample (see `iters`).
    // That combination tolerates a machine that is twice as busy while still
    // catching the regression this test exists for.
    //
    // Idle measurements on this machine (RelWithDebInfo, NDEBUG):
    //   1:1 0.11 ms | letterbox 0.12 ms | 2x 4.8 ms | 0.8x 22.9 ms
    //   0.5x 4K 16.9 ms | 1.33x 1.8 ms | 0.4x 4K 43.0 ms
    //
    // The regression to catch is structural: replacing a fast path with a
    // per-pixel loop. Measured by doing exactly that to CopyExact's row memcpy
    // (a per-pixel copy with a division): the two 1:1 shapes go 0.12 -> 2.6-3.1
    // ms, i.e. 12-14x, well past their 1.1/1.2 ms budgets.
    //
    // The floor is real load, not imagination: with a parallel build running the
    // same binary reported 0.89 ms for a 0.12 ms shape (7.4x) before the sample
    // length was raised, and 0.4x 4K reached 92 ms against its 43 ms idle value
    // (2.1x). Budgets sit above the load-induced values with roughly 1.5x to 2x
    // headroom.
    static const Case cases[] = {
        {1280, 1024, 1280, 1024, "1:1", 1.2, 100},
        {1280, 1024, 1280, 1200, "1:1 letterbox", 1.1, 100},
        {1920, 1080, 3840, 2160, "2x", 20.0, 2},
        {1920, 1080, 1536, 864, "0.8x", 80.0, 1},
        {3840, 2160, 1920, 1080, "0.5x 4K", 60.0, 1},
        {1920, 1080, 2560, 1440, "1.33x", 12.0, 4},
        {3840, 2160, 1536, 864, "0.4x 4K", 140.0, 1},
    };
    for (const Case& c : cases) {
        Surface src(static_cast<uint16_t>(c.sw), static_cast<uint16_t>(c.sh));
        for (int y = 0; y < src.height(); ++y) {
            for (int x = 0; x < src.width(); ++x) {
                src.SetPixel(x, y, static_cast<uint8_t>(x),
                             static_cast<uint8_t>(y), 0x80, 0xFF);
            }
        }
        Surface dst(static_cast<uint16_t>(c.dw), static_cast<uint16_t>(c.dh));
        const auto vt = ComputeViewTransform(c.sw, c.sh, c.dw, c.dh,
                                             static_cast<double>(c.dw) / c.sw,
                                             false);
        // Measurement policy. A wall-clock budget on a shared machine is only
        // meaningful if it survives other processes, and the minimum is the
        // right statistic: interference can only ever ADD time, so the smallest
        // sample is the closest estimate of the true cost. Two things follow.
        //
        // 1. Sample generously. Ten short reps cost well under a millisecond for
        //    the small shapes, and give the scheduler more chances to hand us an
        //    uncontended window.
        // 2. Give a case a second chance before calling it a regression. A real
        //    algorithmic regression (per-pixel division, float resample: 10x or
        //    worse) reproduces on every sample, so re-measuring cannot hide it.
        //    A busy machine usually does not reproduce. Measured here: the 1:1
        //    letterbox case is 0.11-0.16 ms idle and reached 0.89 ms while a
        //    parallel build ran, which is indistinguishable from a 5x regression
        //    in a single sample but obvious in a second one.
        const auto measure = [&]() {
            double best = 1e9;
            for (int rep = 0; rep < 10; ++rep) {
                const auto t0 = std::chrono::steady_clock::now();
                for (int i = 0; i < c.iters; ++i) ScaleSurface(src, dst, vt);
                const double ms =
                    std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - t0)
                        .count() / c.iters;
                if (ms < best) best = ms;
            }
            return best;
        };
        double best = measure();
        if (!(best < c.budget_ms)) {
            std::printf("  [bench] %-16s retrying: %.2f ms is over the %.2f ms budget\n",
                        c.label, best, c.budget_ms);
            best = measure();
        }
        std::printf("  [bench] %-16s %4dx%-4d -> %4dx%-4d  %7.2f ms (budget %5.2f)\n",
                    c.label, c.sw, c.sh, c.dw, c.dh, best, c.budget_ms);
        CHECK(best < c.budget_ms);
    }
#else
    // Unoptimized build: measuring throughput would only measure the absence of
    // -O2. Say so explicitly so a reader does not mistake this for "passed".
    std::printf("  skipped: timing budgets require an optimized build (NDEBUG)\n");
#endif  // NDEBUG
}
int main() { return ::rtsc::test::run_all("rtsc_view_tests"); }
