// Display Control virtual channel wire format ([MS-RDPEDISP]).
//
// These tests pin the two structures the client puts on the wire: the
// server-to-client CAPS PDU parser and the client-to-server monitor layout
// encoder. The encoder's range rules are the same ones the server applies
// before it will act, so a layout this code rejects is one the server would
// have refused.

#include <cstdint>
#include <vector>

#include "rtsc/proto/display_control.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

const uint8_t kCapsPdu[] = {
    0x05, 0x00, 0x00, 0x00,  // type = DISPLAYCONTROL_PDU_TYPE_CAPS
    0x14, 0x00, 0x00, 0x00,  // length = 20
    0x04, 0x00, 0x00, 0x00,  // MaxNumMonitors = 4
    0x10, 0x27, 0x00, 0x00,  // MaxMonitorAreaFactorA = 10000
    0x10, 0x27, 0x00, 0x00,  // MaxMonitorAreaFactorB = 10000
};

uint32_t rd32(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint32_t>(b[off]) |
           (static_cast<uint32_t>(b[off + 1]) << 8) |
           (static_cast<uint32_t>(b[off + 2]) << 16) |
           (static_cast<uint32_t>(b[off + 3]) << 24);
}

DisplayControlMonitor MakeValidMonitor(uint32_t width, uint32_t height) {
    DisplayControlMonitor m;
    m.flags = kDisplayControlMonitorPrimary;
    m.left = 0;
    m.top = 0;
    m.width = width;
    m.height = height;
    m.physical_width = 0;
    m.physical_height = 0;
    m.orientation = 0;
    m.desktop_scale_factor = 100;
    m.device_scale_factor = 100;
    return m;
}

DisplayControlMonitor MakeSecondaryMonitor(uint32_t width, uint32_t height,
                                          int32_t left, int32_t top) {
    DisplayControlMonitor m = MakeValidMonitor(width, height);
    m.flags = 0;  // only the primary carries DISPLAYCONTROL_MONITOR_PRIMARY
    m.left = left;
    m.top = top;
    return m;
}

}  // namespace

RTSC_TEST(disp_caps_parses_the_fixed_fields) {
    DisplayControlCaps caps;
    CHECK(ParseDisplayControlCaps(kCapsPdu, sizeof(kCapsPdu), caps));
    CHECK_EQ(caps.max_num_monitors, static_cast<uint32_t>(4));
    CHECK_EQ(caps.max_monitor_area_factor_a, static_cast<uint32_t>(10000));
    CHECK_EQ(caps.max_monitor_area_factor_b, static_cast<uint32_t>(10000));
}

RTSC_TEST(disp_caps_rejects_wrong_type) {
    std::vector<uint8_t> pdu(kCapsPdu, kCapsPdu + sizeof(kCapsPdu));
    pdu[0] = 0x02;  // MONITOR_LAYOUT
    DisplayControlCaps caps;
    CHECK(!ParseDisplayControlCaps(pdu.data(), pdu.size(), caps));
}

RTSC_TEST(disp_caps_rejects_short_or_truncated_length) {
    DisplayControlCaps caps;
    // Declared length below the fixed body.
    std::vector<uint8_t> short_len(kCapsPdu, kCapsPdu + sizeof(kCapsPdu));
    short_len[4] = 0x10;
    CHECK(!ParseDisplayControlCaps(short_len.data(), short_len.size(), caps));
    // Declared length beyond the received bytes.
    std::vector<uint8_t> too_long(kCapsPdu, kCapsPdu + sizeof(kCapsPdu));
    too_long[4] = 0x40;
    CHECK(!ParseDisplayControlCaps(too_long.data(), too_long.size(), caps));
    // Buffer itself is below the fixed size.
    CHECK(!ParseDisplayControlCaps(kCapsPdu, sizeof(kCapsPdu) - 1, caps));
    CHECK(!ParseDisplayControlCaps(nullptr, 0, caps));
}

RTSC_TEST(disp_layout_encodes_header_and_monitor) {
    const auto pdu = EncodeDisplayControlMonitorLayout(
        {MakeValidMonitor(1280, 1024)});
    // header(8) + MonitorLayoutSize(4) + NumMonitors(4) + 40-byte monitor.
    CHECK_EQ(pdu.size(), static_cast<size_t>(56));
    CHECK_EQ(rd32(pdu, 0), static_cast<uint32_t>(2));   // MONITOR_LAYOUT
    CHECK_EQ(rd32(pdu, 4), static_cast<uint32_t>(56));  // length
    CHECK_EQ(rd32(pdu, 8), static_cast<uint32_t>(40));  // MonitorLayoutSize
    CHECK_EQ(rd32(pdu, 12), static_cast<uint32_t>(1));  // NumMonitors
    CHECK_EQ(rd32(pdu, 16), kDisplayControlMonitorPrimary);
    CHECK_EQ(rd32(pdu, 20), static_cast<uint32_t>(0));     // left
    CHECK_EQ(rd32(pdu, 24), static_cast<uint32_t>(0));     // top
    CHECK_EQ(rd32(pdu, 28), static_cast<uint32_t>(1280));  // width
    CHECK_EQ(rd32(pdu, 32), static_cast<uint32_t>(1024));  // height
    CHECK_EQ(rd32(pdu, 48), static_cast<uint32_t>(100));   // desktop scale
    CHECK_EQ(rd32(pdu, 52), static_cast<uint32_t>(100));   // device scale
}

RTSC_TEST(disp_layout_preserves_signed_offsets) {
    DisplayControlMonitor m = MakeSecondaryMonitor(800, 600, -1920, 0);
    const auto pdu = EncodeDisplayControlMonitorLayout({m});
    CHECK_EQ(pdu.size(), static_cast<size_t>(56));
    if (pdu.size() != 56) return;
    CHECK_EQ(rd32(pdu, 16), static_cast<uint32_t>(0));            // flags
    CHECK_EQ(rd32(pdu, 20), static_cast<uint32_t>(0xFFFFF880));  // left -1920
    CHECK_EQ(rd32(pdu, 24), static_cast<uint32_t>(0));            // top
    CHECK_EQ(rd32(pdu, 28), static_cast<uint32_t>(800));          // width

    // A primary monitor cannot sit off the origin ([MS-RDPEDISP] 2.2.2.2.1).
    DisplayControlMonitor primary = MakeValidMonitor(800, 600);
    primary.left = -1920;
    CHECK(EncodeDisplayControlMonitorLayout({primary}).empty());
}

RTSC_TEST(disp_layout_rejects_empty_and_invalid_dimensions) {
    CHECK(EncodeDisplayControlMonitorLayout({}).empty());
    // Odd width is forbidden by the spec.
    CHECK(EncodeDisplayControlMonitorLayout({MakeValidMonitor(1281, 1024)})
              .empty());
    // Below and above the 200..8192 window.
    CHECK(EncodeDisplayControlMonitorLayout({MakeValidMonitor(198, 1024)})
              .empty());
    CHECK(EncodeDisplayControlMonitorLayout({MakeValidMonitor(1280, 8194)})
              .empty());
}

RTSC_TEST(disp_layout_rejects_bad_orientation_and_scale) {
    DisplayControlMonitor orientation = MakeValidMonitor(800, 600);
    orientation.orientation = 45;
    CHECK(EncodeDisplayControlMonitorLayout({orientation}).empty());

    DisplayControlMonitor desktop_scale = MakeValidMonitor(800, 600);
    desktop_scale.desktop_scale_factor = 99;
    CHECK(EncodeDisplayControlMonitorLayout({desktop_scale}).empty());

    DisplayControlMonitor device_scale = MakeValidMonitor(800, 600);
    device_scale.device_scale_factor = 120;
    CHECK(EncodeDisplayControlMonitorLayout({device_scale}).empty());
}

RTSC_TEST(disp_layout_within_caps_checks_count_and_area) {
    const DisplayControlCaps caps{4, 10000, 10000};
    CHECK(DisplayControlLayoutWithinCaps({MakeValidMonitor(1920, 1080)}, caps));

    // Five monitors exceeds MaxNumMonitors = 4.
    std::vector<DisplayControlMonitor> five(5, MakeValidMonitor(200, 200));
    CHECK(!DisplayControlLayoutWithinCaps(five, caps));

    // Area above 4 * 10000 * 10000.
    const DisplayControlCaps small{1, 100, 100};
    CHECK(!DisplayControlLayoutWithinCaps({MakeValidMonitor(200, 200)}, small));
    CHECK(DisplayControlLayoutWithinCaps({MakeValidMonitor(200, 200)},
                                         DisplayControlCaps{1, 200, 200}));
}

RTSC_TEST(disp_layout_within_caps_rejects_zero_caps) {
    const DisplayControlCaps zero{0, 10000, 10000};
    CHECK(!DisplayControlLayoutWithinCaps({MakeValidMonitor(800, 600)}, zero));
}

RTSC_TEST(disp_viewport_monitor_rounds_odd_width_down) {
    DisplayControlMonitor m;
    CHECK(MakePrimaryMonitorFromViewport(1281, 720, m));
    CHECK_EQ(m.width, static_cast<uint32_t>(1280));
    CHECK_EQ(m.height, static_cast<uint32_t>(720));
    CHECK_EQ(m.flags, kDisplayControlMonitorPrimary);
    CHECK(DisplayControlMonitorValid(m));
}

RTSC_TEST(disp_viewport_monitor_rejects_out_of_range) {
    DisplayControlMonitor m;
    // Too small after the even rounding (199 -> 198).
    CHECK(!MakePrimaryMonitorFromViewport(199, 600, m));
    CHECK(!MakePrimaryMonitorFromViewport(800, 199, m));
    // An odd width is rounded down first, so 8193 -> 8192 is accepted; the
    // upper bound rejects only an even value above 8192.
    CHECK(MakePrimaryMonitorFromViewport(8193, 600, m));
    CHECK_EQ(m.width, static_cast<uint32_t>(8192));
    CHECK(!MakePrimaryMonitorFromViewport(8194, 600, m));
    CHECK(!MakePrimaryMonitorFromViewport(800, 8193, m));
    // The exact bounds are accepted.
    CHECK(MakePrimaryMonitorFromViewport(200, 200, m));
    CHECK(MakePrimaryMonitorFromViewport(8192, 8192, m));
}

RTSC_TEST(disp_layout_requires_adjacency_and_no_overlap) {
    DisplayControlMonitor a = MakeValidMonitor(800, 600);
    CHECK(DisplayControlLayoutValid({a}));  // a single monitor is trivially valid

    DisplayControlMonitor b = MakeSecondaryMonitor(800, 600, 800, 0);
    CHECK(DisplayControlLayoutValid({a, b}));
    CHECK_EQ(EncodeDisplayControlMonitorLayout({a, b}).size(),
             static_cast<size_t>(96));  // 16 + 2*40

    b.top = 600;  // touches a only at its bottom-right corner
    CHECK(DisplayControlLayoutValid({a, b}));

    b.left = 400;  // overlaps a
    b.top = 0;
    CHECK(!DisplayControlLayoutValid({a, b}));
    CHECK(EncodeDisplayControlMonitorLayout({a, b}).empty());

    b.left = 1000;  // 200 px gap: not adjacent
    b.top = 0;
    CHECK(!DisplayControlLayoutValid({a, b}));
}

RTSC_TEST(disp_layout_rejects_one_detached_monitor) {
    DisplayControlMonitor a = MakeValidMonitor(800, 600);
    DisplayControlMonitor b = MakeSecondaryMonitor(800, 600, 800, 0);
    DisplayControlMonitor c = MakeSecondaryMonitor(800, 600, 2000, 0);
    CHECK(!DisplayControlLayoutValid({a, b, c}));  // c detached from a and b
    c.left = 1600;  // now adjacent to b's right edge
    CHECK(DisplayControlLayoutValid({a, b, c}));
}

// [MS-RDPEDISP] 2.2.2.2.1: the upper-left corner of the primary monitor is
// always (0, 0), and only one monitor may be designated primary.
RTSC_TEST(disp_layout_primary_must_be_at_origin_and_unique) {
    DisplayControlMonitor primary = MakeValidMonitor(800, 600);
    CHECK(DisplayControlLayoutValid({primary}));

    primary.left = 100;  // primary off the origin
    CHECK(!DisplayControlLayoutValid({primary}));
    CHECK(!DisplayControlMonitorValid(primary));
    primary.left = 0;
    primary.top = 50;
    CHECK(!DisplayControlLayoutValid({primary}));

    DisplayControlMonitor off_origin = MakeValidMonitor(800, 600);
    off_origin.left = 100;
    DisplayControlMonitor second = MakeSecondaryMonitor(800, 600, 900, 0);
    CHECK(!DisplayControlLayoutValid({off_origin, second}));

    DisplayControlMonitor a = MakeValidMonitor(800, 600);
    DisplayControlMonitor b = MakeValidMonitor(800, 600);
    b.left = 800;  // second primary flag is inconsistent
    CHECK(!DisplayControlLayoutValid({a, b}));
}

// The caps area bound is MaxNumMonitors * FactorA * FactorB; with factors near
// 2^32 the product overflows 64 bits and must saturate instead of wrapping to
// a small bound that would reject a legal layout.
RTSC_TEST(disp_caps_area_bound_saturates) {
    DisplayControlCaps caps;
    caps.max_num_monitors = 0xFFFFFFFFu;
    caps.max_monitor_area_factor_a = 0xFFFFFFFFu;
    caps.max_monitor_area_factor_b = 0xFFFFFFFFu;
    std::vector<DisplayControlMonitor> monitors;
    for (uint32_t row = 0; row < 10; ++row) {
        for (uint32_t col = 0; col < 20; ++col) {
            monitors.push_back(MakeSecondaryMonitor(
                8192, 8192, static_cast<int32_t>(col) * 8192,
                static_cast<int32_t>(row) * 8192));
        }
    }
    CHECK(DisplayControlLayoutValid(monitors));
    CHECK(DisplayControlLayoutWithinCaps(monitors, caps));
    // A tiny bound must still reject the same layout.
    caps.max_num_monitors = 200;
    caps.max_monitor_area_factor_a = 200;
    caps.max_monitor_area_factor_b = 200;
    CHECK(!DisplayControlLayoutWithinCaps(monitors, caps));
}

int main() { return ::rtsc::test::run_all("rtsc_display_control_tests"); }
