// View scaling: ComputeViewTransform / ScaleSurface, the zoom input controller,
// and GraphicsPipeline::RenderTo.

#include "rtsc/client/graphics.h"
#include "rtsc/client/view.h"

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

}  // namespace

RTSC_TEST(view_nearest_neighbor_2x_maps_a_2x2_block) {
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
    CHECK(zs.fit);

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
    CHECK(!ApplyZoomInput(wheel, zs));  // already at the maximum
    CHECK_EQ(zs.zoom, 5.0);
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
    CHECK(zs.fit);
}

RTSC_TEST(graphics_defaults_to_fit) {
    GraphicsPipeline g(8, 8);
    CHECK_EQ(g.zoom(), 1.0);
    CHECK(g.fit());
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
    // source (the old nearest-neighbour path could not be relied on for this).
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

RTSC_TEST(view_scale_bilinear_interpolates_non_integer) {
    // A non-integer zoom is bilinear: the corners stay exact (they land on a
    // source pixel) and the centre is a blend of all four source pixels.
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

    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(dst.GetPixel(0, 0, r, g, b, a) && r == 255 && g == 0 && b == 0);
    CHECK(dst.GetPixel(2, 0, r, g, b, a) && r == 0 && g == 255 && b == 0);
    CHECK(dst.GetPixel(0, 2, r, g, b, a) && r == 0 && g == 0 && b == 255);
    CHECK(dst.GetPixel(2, 2, r, g, b, a) && r == 255 && g == 255 && b == 255);

    CHECK(dst.GetPixel(1, 1, r, g, b, a));
    CHECK(r > 0 && g > 0 && b > 0);              // a blend of all four
    CHECK(!(r == 255 && g == 0 && b == 0));      // not a source corner
    CHECK(!(r == 0 && g == 255 && b == 0));
    CHECK(!(r == 0 && g == 0 && b == 255));
    CHECK(!(r == 255 && g == 255 && b == 255));
}

RTSC_TEST(view_scale_benchmark_1280x1024) {
    Surface src(1280, 1024);
    for (int y = 0; y < src.height(); ++y) {
        for (int x = 0; x < src.width(); ++x) {
            src.SetPixel(x, y, static_cast<uint8_t>(x), static_cast<uint8_t>(y),
                         0x80, 0xFF);
        }
    }
    Surface dst(1280, 1024);
    const auto time_it = [&](const ViewTransform& vt, const char* label) {
        const auto t0 = std::chrono::steady_clock::now();
        const int iters = 30;
        for (int i = 0; i < iters; ++i) ScaleSurface(src, dst, vt);
        const double ms =
            std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - t0)
                .count();
        std::printf("  [bench] ScaleSurface 1280x1024 %s: %.2f ms/iter (%.0f fps)\n",
                    label, ms / iters, iters / (ms / 1000.0));
        return ms / iters;
    };
    const double one = time_it(ComputeViewTransform(1280, 1024, 1280, 1024, 1.0, false), "1:1 blit");
    const double two = time_it(ComputeViewTransform(1280, 1024, 2560, 2048, 2.0, false), "2x block");
    const double half = time_it(ComputeViewTransform(1280, 1024, 640, 512, 0.5, false), "0.5x bilinear");
    // Generous floors that still catch a regression to the old per-pixel
    // division path (which was ~10 ms for a 1:1 1280x1024 frame).
    CHECK(one < 2.0);
    CHECK(two < 16.0);
    CHECK(half < 32.0);
}

int main() { return ::rtsc::test::run_all("rtsc_view_tests"); }
