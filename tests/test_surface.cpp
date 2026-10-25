// Surface Commands framing ([MS-RDPBCGR] 2.2.9.2) and the ui::Surface pixel API.

#include "rtsc/proto/surface.h"
#include "rtsc/ui/surface.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;
using rtsc::ui::Surface;

namespace {

std::vector<uint8_t> Cmd(uint16_t type, const std::vector<uint8_t>& data) {
    ByteWriter w;
    w.u16le(type);
    w.u16le(static_cast<uint16_t>(4 + data.size()));
    w.bytes(data.data(), data.size());
    return w.take();
}

}  // namespace

RTSC_TEST(surface_single_command_parses) {
    const auto buf = Cmd(kFrameMarker, {0x00, 0x00, 0x00, 0x00});
    std::vector<SurfaceCommand> cmds;
    CHECK(ParseSurfaceCommands(buf.data(), buf.size(), cmds) == Status::Ok);
    CHECK_EQ(cmds.size(), static_cast<size_t>(1));
    CHECK_EQ(cmds[0].cmd_type, static_cast<uint16_t>(kFrameMarker));
    CHECK_EQ(cmds[0].data.size(), static_cast<size_t>(4));
}

RTSC_TEST(surface_multiple_commands_parse_in_order) {
    auto a = Cmd(kFrameMarker, {0x01});
    auto b = Cmd(kSetSurfaceBits, {0x02, 0x03, 0x04});
    std::vector<uint8_t> buf = a;
    buf.insert(buf.end(), b.begin(), b.end());

    std::vector<SurfaceCommand> cmds;
    CHECK(ParseSurfaceCommands(buf.data(), buf.size(), cmds) == Status::Ok);
    CHECK_EQ(cmds.size(), static_cast<size_t>(2));
    CHECK_EQ(cmds[0].cmd_type, static_cast<uint16_t>(kFrameMarker));
    CHECK_EQ(cmds[1].cmd_type, static_cast<uint16_t>(kSetSurfaceBits));
    CHECK_EQ(cmds[1].data.size(), static_cast<size_t>(3));
    CHECK_EQ(cmds[1].data[0], static_cast<uint8_t>(0x02));
}

RTSC_TEST(surface_empty_command_has_no_data) {
    const auto buf = Cmd(kFrameMarker, {});
    std::vector<SurfaceCommand> cmds;
    CHECK(ParseSurfaceCommands(buf.data(), buf.size(), cmds) == Status::Ok);
    CHECK_EQ(cmds.size(), static_cast<size_t>(1));
    CHECK(cmds[0].data.empty());
}

RTSC_TEST(surface_rejects_short_cmd_length) {
    // cmdLength = 3 (< the 4-byte header) must be rejected, not looped on.
    const std::vector<uint8_t> buf = {0x01, 0x00, 0x03, 0x00, 0xAA};
    std::vector<SurfaceCommand> cmds;
    CHECK(ParseSurfaceCommands(buf.data(), buf.size(), cmds) ==
          Status::InvalidLength);
}

RTSC_TEST(surface_rejects_truncated_command) {
    // Declares a 10-byte command but only 6 bytes follow.
    const std::vector<uint8_t> buf = {0x04, 0x00, 0x0A, 0x00, 0x00, 0x00};
    std::vector<SurfaceCommand> cmds;
    CHECK(ParseSurfaceCommands(buf.data(), buf.size(), cmds) ==
          Status::NeedMoreData);
}

// ---------------------------------------------------------------------------
// ui::Surface pixel API
// ---------------------------------------------------------------------------

RTSC_TEST(surface_set_pixel_round_trips) {
    Surface s(10, 10);
    s.SetPixel(3, 4, 0x11, 0x22, 0x33, 0x44);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(3, 4, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK_EQ(g, static_cast<uint8_t>(0x22));
    CHECK_EQ(b, static_cast<uint8_t>(0x33));
    CHECK_EQ(a, static_cast<uint8_t>(0x44));
}

RTSC_TEST(surface_set_pixel_clips_all_four_boundaries) {
    Surface s(8, 8);
    s.Fill(0, 0, 0, 0);
    s.SetPixel(-1, 0, 1, 2, 3, 4);  // left
    s.SetPixel(0, -1, 1, 2, 3, 4);  // top
    s.SetPixel(8, 0, 1, 2, 3, 4);   // right
    s.SetPixel(0, 8, 1, 2, 3, 4);   // bottom
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 8; ++y) {
        for (int x = 0; x < 8; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, static_cast<uint8_t>(0));
            CHECK_EQ(g, static_cast<uint8_t>(0));
            CHECK_EQ(b, static_cast<uint8_t>(0));
            CHECK_EQ(a, static_cast<uint8_t>(0));
        }
    }
    CHECK(!s.GetPixel(-1, 0, r, g, b, a));
    CHECK(!s.GetPixel(0, -1, r, g, b, a));
    CHECK(!s.GetPixel(8, 0, r, g, b, a));
    CHECK(!s.GetPixel(0, 8, r, g, b, a));
}

RTSC_TEST(surface_line_horizontal_round_trips) {
    Surface s(10, 10);
    s.Fill(0, 0, 0, 0);
    s.Line(2, 5, 7, 5, 0xAA, 0xBB, 0xCC, 0xDD);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int x = 2; x <= 7; ++x) {
        CHECK(s.GetPixel(x, 5, r, g, b, a));
        CHECK_EQ(r, static_cast<uint8_t>(0xAA));
        CHECK_EQ(g, static_cast<uint8_t>(0xBB));
        CHECK_EQ(b, static_cast<uint8_t>(0xCC));
        CHECK_EQ(a, static_cast<uint8_t>(0xDD));
    }
    CHECK(s.GetPixel(1, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(8, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(surface_line_diagonal_round_trips) {
    Surface s(10, 10);
    s.Fill(0, 0, 0, 0);
    s.Line(1, 1, 5, 5, 0x11, 0x22, 0x33, 0x44);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int i = 1; i <= 5; ++i) {
        CHECK(s.GetPixel(i, i, r, g, b, a));
        CHECK_EQ(r, static_cast<uint8_t>(0x11));
    }
    CHECK(s.GetPixel(0, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(6, 6, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(surface_line_clips_left) {
    Surface s(10, 10);
    s.Fill(0, 0, 0, 0);
    s.Line(-3, 5, 3, 5, 0x11, 0x22, 0x33, 0x44);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(0, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s.GetPixel(3, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s.GetPixel(4, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(9, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(surface_line_clips_top) {
    Surface s(10, 10);
    s.Fill(0, 0, 0, 0);
    s.Line(5, -3, 5, 3, 0x11, 0x22, 0x33, 0x44);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(5, 0, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s.GetPixel(5, 3, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s.GetPixel(5, 4, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(surface_line_clips_right) {
    Surface s(10, 10);
    s.Fill(0, 0, 0, 0);
    s.Line(7, 5, 13, 5, 0x11, 0x22, 0x33, 0x44);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(7, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s.GetPixel(9, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s.GetPixel(6, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(surface_line_clips_bottom) {
    Surface s(10, 10);
    s.Fill(0, 0, 0, 0);
    s.Line(5, 7, 5, 13, 0x11, 0x22, 0x33, 0x44);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(5, 7, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s.GetPixel(5, 9, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s.GetPixel(5, 6, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(surface_line_fully_out_of_bounds_writes_nothing) {
    Surface s(10, 10);
    s.Fill(0x7F, 0x7F, 0x7F, 0x7F);
    s.Line(-5, -5, -1, -1, 0x11, 0x22, 0x33, 0x44);
    s.Line(20, 20, 30, 30, 0x11, 0x22, 0x33, 0x44);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    for (int y = 0; y < 10; ++y) {
        for (int x = 0; x < 10; ++x) {
            CHECK(s.GetPixel(x, y, r, g, b, a));
            CHECK_EQ(r, static_cast<uint8_t>(0x7F));
            CHECK_EQ(g, static_cast<uint8_t>(0x7F));
            CHECK_EQ(b, static_cast<uint8_t>(0x7F));
            CHECK_EQ(a, static_cast<uint8_t>(0x7F));
        }
    }
}

RTSC_TEST(surface_line_zero_length_is_a_single_point) {
    Surface s(10, 10);
    s.Fill(0, 0, 0, 0);
    s.Line(4, 4, 4, 4, 0x11, 0x22, 0x33, 0x44);
    uint8_t r = 0, g = 0, b = 0, a = 0;
    CHECK(s.GetPixel(4, 4, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x11));
    CHECK(s.GetPixel(3, 4, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(5, 4, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(4, 3, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
    CHECK(s.GetPixel(4, 5, r, g, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

int main() { return ::rtsc::test::run_all("rtsc_surface_tests"); }
