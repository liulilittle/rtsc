// Multi-monitor: TS_MONITOR_DEF, Client Monitor Data (CS_MONITOR) and the
// Monitor Layout PDU, plus the client's multi-surface pipeline.
//
// The wire formats are [MS-RDPBCGR] 2.2.1.3.6 / 2.2.1.3.6.1 / 2.2.12.1.

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/client/graphics.h"
#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/capabilities.h"
#include "rtsc/proto/connect_machine.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/multimon.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/proto/session_setup.h"
#include "rtsc/proto/output.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc;
using namespace rtsc::proto;

namespace {

std::vector<uint8_t> Hex(const char* s) {
    std::vector<uint8_t> out;
    int hi = -1;
    for (const char* p = s; *p != '\0'; ++p) {
        int v = -1;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else continue;
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

// A two-monitor layout: a primary 4x4 at the origin and a 4x4 to its right.
std::vector<MonitorDef> MakeMonitors() {
    std::vector<MonitorDef> m(2);
    m[0] = {0, 0, 3, 3, MonitorDef::kPrimary};
    m[1] = {4, 0, 7, 3, 0};
    return m;
}

// A primary at the origin with a monitor above it (negative origin), which
// exercises the virtual desktop union offset.
std::vector<MonitorDef> MakeNegativeOriginMonitors() {
    std::vector<MonitorDef> m(2);
    m[0] = {0, 0, 3, 3, MonitorDef::kPrimary};   // below
    m[1] = {0, -4, 3, -1, 0};                    // above
    return m;
}

// Server -> client MCS Send Data Indication wrapping `payload`.
std::vector<uint8_t> ServerPdu(const std::vector<uint8_t>& payload) {
    return McsSendData::build_indication(0x03EA, 0x03EF, payload);
}

// A server slow-path data PDU carrying `type` (share data header + payload).
std::vector<uint8_t> ServerDataPdu(ShareDataPduType type,
                                   const std::vector<uint8_t>& payload) {
    ByteWriter w;
    w.u16le(static_cast<uint16_t>(ShareDataHeader::kSize + payload.size()));
    w.u16le(0x0017);  // pduType: type=7, version=1
    w.u16le(0x03EA);  // pduSource = server channel
    w.u32le(0x000103EA);  // shareID
    w.u8(0);
    w.u8(0x01);
    w.u16le(static_cast<uint16_t>(payload.size()));
    w.u8(static_cast<uint8_t>(type));
    w.u8(0);
    w.u16le(0);
    if (!payload.empty()) w.bytes(payload.data(), payload.size());
    return ServerPdu(w.take());
}

// A minimal Demand Active PDU with a bitmap capability set, enough to drive
// SessionSetupMachine from S1 to S3.
std::vector<uint8_t> BuildDemandActive() {
    BitmapCapabilitySet bmp;
    bmp.desktop_width = 1280;
    bmp.desktop_height = 1024;
    std::vector<CapabilitySet> sets{bmp.encode()};

    ByteWriter caps;
    uint16_t count = 0;
    uint16_t combined = 0;
    WriteCapabilitySets(caps, sets, count, combined);

    const std::string descriptor = "RDP";
    const size_t src_len = descriptor.size() + 1;
    const size_t total = 14 + src_len + combined + 4;

    ByteWriter w;
    w.u16le(static_cast<uint16_t>(total));
    w.u16le(0x0011);  // PDUTYPE_DEMANDACTIVEPDU | version 1
    w.u16le(0x03EA);
    w.u32le(0x000103EA);
    w.u16le(static_cast<uint16_t>(src_len));
    w.u16le(combined);
    w.bytes(reinterpret_cast<const uint8_t*>(descriptor.data()), descriptor.size());
    w.u8(0);
    w.u16le(count);
    w.u16le(0);
    w.bytes(caps.data().data(), caps.size());
    w.u32le(0x00000001);
    return w.take();
}

SessionSetupMachine::Config MakeSessionConfig() {
    SessionSetupMachine::Config c;
    c.user_channel_id = 0x03EF;
    c.io_channel_id = 0x03EB;
    c.desktop_width = 1280;
    c.desktop_height = 1024;
    c.color_depth = 24;
    c.source_descriptor = "RTSC";
    return c;
}

// Builds a TS_BITMAP_DATA rectangle with raw (uncompressed) BGRA data.
std::vector<uint8_t> RawRect(int dst_x, int dst_y, uint16_t w, uint16_t h,
                             const std::vector<uint8_t>& bgra) {
    ByteWriter d;
    d.u16le(static_cast<uint16_t>(dst_x));
    d.u16le(static_cast<uint16_t>(dst_y));
    d.u16le(static_cast<uint16_t>(dst_x + w - 1));
    d.u16le(static_cast<uint16_t>(dst_y + h - 1));
    d.u16le(w);
    d.u16le(h);
    d.u16le(32);   // bpp
    d.u16le(0);    // flags: uncompressed
    d.u16le(static_cast<uint16_t>(bgra.size()));
    d.bytes(bgra.data(), bgra.size());
    return d.take();
}

// Wraps bitmap rectangles into a fast-path bitmap update + PDU.
std::vector<uint8_t> FastPathBitmapPdu(
    const std::vector<std::vector<uint8_t>>& rects) {
    ByteWriter data;
    data.u16le(0x0001);  // UPDATETYPE_BITMAP
    data.u16le(static_cast<uint16_t>(rects.size()));
    for (const auto& r : rects) data.bytes(r.data(), r.size());
    const auto d = data.take();

    ByteWriter w;
    w.u8(0x00);  // fpOutputHeader
    w.u8(static_cast<uint8_t>(1 + 1 + 1 + 2 + d.size()));
    w.u8(0x01);  // updateCode = bitmap
    w.u16le(static_cast<uint16_t>(d.size()));
    w.bytes(d.data(), d.size());
    return w.take();
}

}  // namespace

// ---- TS_MONITOR_DEF --------------------------------------------------------

RTSC_TEST(monitor_def_roundtrips_20_bytes) {
    MonitorDef m;
    m.left = -100;
    m.top = 200;
    m.right = 1199;
    m.bottom = 1223;
    m.flags = MonitorDef::kPrimary;

    ByteWriter w;
    m.write(w);
    CHECK_EQ(w.size(), static_cast<size_t>(20));

    ByteReader r(w.data().data(), w.size());
    MonitorDef back;
    CHECK(back.read(r));
    CHECK(r.empty());
    CHECK_EQ(back.left, m.left);
    CHECK_EQ(back.top, m.top);
    CHECK_EQ(back.right, m.right);
    CHECK_EQ(back.bottom, m.bottom);
    CHECK_EQ(back.flags, m.flags);
    CHECK(back.primary());
    CHECK_EQ(back.width(), 1300);
    CHECK_EQ(back.height(), 1024);
}

RTSC_TEST(monitor_def_secondary_is_not_primary) {
    MonitorDef m;
    m.left = 1280;
    m.top = 0;
    m.right = 2559;
    m.bottom = 1023;
    m.flags = 0;
    CHECK(!m.primary());
    CHECK_EQ(m.width(), 1280);
    CHECK_EQ(m.height(), 1024);
}

RTSC_TEST(monitor_def_read_rejects_truncated) {
    const std::vector<uint8_t> bytes(19, 0);
    ByteReader r(bytes.data(), bytes.size());
    MonitorDef m;
    CHECK(!m.read(r));
}

// ---- Client Monitor Data (CS_MONITOR) --------------------------------------

RTSC_TEST(client_monitor_data_roundtrips) {
    ClientMonitorData data;
    data.monitors = MakeMonitors();
    const auto block = data.encode();

    // GCC header: type 0xC005, length = 4 + 4 (flags) + 4 (count) + 2*20.
    CHECK_EQ(block.size(), static_cast<size_t>(4 + 4 + 4 + 40));
    CHECK_EQ(block[0], static_cast<uint8_t>(0x05));
    CHECK_EQ(block[1], static_cast<uint8_t>(0xC0));

    ClientMonitorData back;
    CHECK(ClientMonitorData::parse(block.data(), block.size(), back) ==
          Status::Ok);
    CHECK_EQ(back.flags, static_cast<uint32_t>(0));
    CHECK_EQ(back.monitors.size(), static_cast<size_t>(2));
    CHECK(back.monitors[0].primary());
    CHECK(!back.monitors[1].primary());
    CHECK_EQ(back.monitors[1].left, 4);
    CHECK_EQ(back.monitors[1].bottom, 3);
}

RTSC_TEST(client_monitor_data_rejects_wrong_block_type) {
    ClientMonitorData data;
    data.monitors = MakeMonitors();
    auto block = data.encode();
    block[0] = 0x01;  // CS_CORE instead of CS_MONITOR
    block[1] = 0xC0;
    ClientMonitorData back;
    CHECK(ClientMonitorData::parse(block.data(), block.size(), back) ==
          Status::InvalidType);
}

RTSC_TEST(client_monitor_data_rejects_count_above_max) {
    ClientMonitorData data;
    data.monitors = MakeMonitors();
    auto block = data.encode();
    // Patch monitorCount (payload offset 4) to 17 > 16.
    block[8] = 17;
    block[9] = 0;
    block[10] = 0;
    block[11] = 0;
    ClientMonitorData back;
    CHECK(ClientMonitorData::parse(block.data(), block.size(), back) ==
          Status::InvalidLength);
}

RTSC_TEST(client_monitor_data_rejects_truncated_array) {
    ClientMonitorData data;
    data.monitors = MakeMonitors();
    auto block = data.encode();
    block.pop_back();  // drop the last byte of the second TS_MONITOR_DEF
    ClientMonitorData back;
    CHECK(ClientMonitorData::parse(block.data(), block.size(), back) ==
          Status::InvalidLength);
}

RTSC_TEST(client_monitor_data_empty_layout_is_legal) {
    ClientMonitorData data;
    const auto block = data.encode();
    CHECK_EQ(block.size(), static_cast<size_t>(12));
    ClientMonitorData back;
    CHECK(ClientMonitorData::parse(block.data(), block.size(), back) ==
          Status::Ok);
    CHECK_EQ(back.monitors.size(), static_cast<size_t>(0));
}

// ---- Monitor Layout PDU ----------------------------------------------------

RTSC_TEST(monitor_layout_body_roundtrips) {
    MonitorLayoutPdu pdu;
    pdu.monitors = MakeMonitors();
    const auto body = pdu.encode_body();
    CHECK_EQ(body.size(), static_cast<size_t>(4 + 40));

    MonitorLayoutPdu back;
    CHECK(MonitorLayoutPdu::parse_body(body.data(), body.size(), back) ==
          Status::Ok);
    CHECK_EQ(back.monitor_count, static_cast<uint32_t>(2));
    CHECK_EQ(back.monitors.size(), static_cast<size_t>(2));
    CHECK(back.monitors[0].primary());
    CHECK_EQ(back.monitors[1].right, 7);
}

RTSC_TEST(monitor_layout_body_rejects_truncated) {
    MonitorLayoutPdu pdu;
    pdu.monitors = MakeMonitors();
    auto body = pdu.encode_body();
    body.pop_back();
    MonitorLayoutPdu back;
    CHECK(MonitorLayoutPdu::parse_body(body.data(), body.size(), back) ==
          Status::InvalidLength);
}

RTSC_TEST(monitor_layout_body_rejects_trailing_slack) {
    MonitorLayoutPdu pdu;
    pdu.monitors = MakeMonitors();
    auto body = pdu.encode_body();
    body.push_back(0);  // monitorCount does not describe this byte
    MonitorLayoutPdu back;
    CHECK(MonitorLayoutPdu::parse_body(body.data(), body.size(), back) ==
          Status::InvalidLength);
}

RTSC_TEST(monitor_layout_body_rejects_count_above_max) {
    MonitorLayoutPdu pdu;
    pdu.monitors = MakeMonitors();
    auto body = pdu.encode_body();
    body[0] = 17;  // monitorCount = 17 > 16
    MonitorLayoutPdu back;
    CHECK(MonitorLayoutPdu::parse_body(body.data(), body.size(), back) ==
          Status::InvalidLength);
}

RTSC_TEST(monitor_layout_pdu_full_roundtrips) {
    MonitorLayoutPdu pdu;
    pdu.monitors = MakeMonitors();
    const auto wire = pdu.encode(0x03EA, 0x000103EA);

    // The share data header's pduType2 must be 0x37. It sits 8 bytes into the
    // share data header's tail (shareID 4 + pad1 1 + streamID 1 + length 2).
    const size_t type2_offset = ShareControlHeader::kSize + 8;
    CHECK_EQ(wire[type2_offset], static_cast<uint8_t>(0x37));

    MonitorLayoutPdu back;
    CHECK(MonitorLayoutPdu::parse(wire.data(), wire.size(), back) == Status::Ok);
    CHECK_EQ(back.monitors.size(), static_cast<size_t>(2));
    CHECK(back.monitors[0].primary());
    CHECK_EQ(back.monitors[1].top, 0);
}

RTSC_TEST(monitor_layout_pdu_rejects_wrong_pdu_type) {
    MonitorLayoutPdu pdu;
    pdu.monitors = MakeMonitors();
    auto wire = pdu.encode(0x03EA, 0x000103EA);
    const size_t type2_offset = ShareControlHeader::kSize + 8;
    wire[type2_offset] = static_cast<uint8_t>(ShareDataPduType::kFontMap);
    MonitorLayoutPdu back;
    CHECK(MonitorLayoutPdu::parse(wire.data(), wire.size(), back) ==
          Status::InvalidType);
}

// ---- Connect Initial carries the CS_MONITOR block --------------------------

RTSC_TEST(connect_initial_carries_client_monitor_data) {
    ConnectMachine::Config c;
    c.cookie = "Cookie: mstshash=tester";
    c.requested_protocols = kProtocolRdp;
    c.desktop_width = 1280;
    c.desktop_height = 1024;
    c.client_build = 3790;
    c.client_name = "RTSC";
    c.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
    c.encryption_methods = 0;
    c.monitors = MakeMonitors();
    ConnectMachine::Credentials creds;
    creds.user_name = "eltons";

    ConnectMachine m(c, creds);
    m.Start();
    const auto ccf =
        Hex("03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 00 00 00");
    const auto step = m.OnData(ccf.data(), ccf.size());
    CHECK(!m.failed());

    // The CS_MONITOR block is appended verbatim to the Connect Initial.
    ClientMonitorData expect;
    expect.monitors = MakeMonitors();
    const auto block = expect.encode();
    const auto it = std::search(step.output.begin(), step.output.end(),
                                block.begin(), block.end());
    CHECK(it != step.output.end());
}

RTSC_TEST(connect_initial_omits_monitor_data_without_layout) {
    ConnectMachine::Config c;
    c.cookie = "Cookie: mstshash=tester";
    c.requested_protocols = kProtocolRdp;
    c.desktop_width = 1280;
    c.desktop_height = 1024;
    c.client_build = 3790;
    c.client_name = "RTSC";
    c.channel_names = {"rdpdr"};
    c.encryption_methods = 0;
    ConnectMachine::Credentials creds;
    creds.user_name = "eltons";

    ConnectMachine m(c, creds);
    m.Start();
    const auto ccf =
        Hex("03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 00 00 00");
    const auto step = m.OnData(ccf.data(), ccf.size());
    CHECK(!m.failed());

    const std::vector<uint8_t> tag{0x05, 0xC0};
    const auto it = std::search(step.output.begin(), step.output.end(),
                                tag.begin(), tag.end());
    CHECK(it == step.output.end());
}

RTSC_TEST(connect_initial_sets_monitor_layout_capability_flag) {
    ConnectMachine::Config c;
    c.cookie = "Cookie: mstshash=tester";
    c.requested_protocols = kProtocolRdp;
    c.desktop_width = 1280;
    c.desktop_height = 1024;
    c.client_build = 3790;
    c.client_name = "RTSC";
    c.channel_names = {"rdpdr"};
    c.encryption_methods = 0;
    c.support_monitor_layout_pdu = true;
    ConnectMachine::Credentials creds;
    creds.user_name = "eltons";

    ConnectMachine m(c, creds);
    m.Start();
    const auto ccf =
        Hex("03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 00 00 00");
    const auto step = m.OnData(ccf.data(), ccf.size());
    CHECK(!m.failed());

    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(step.output.data(), step.output.size(), ci) ==
          Status::Ok);

    // Walk the GCC payload to the user data blocks: 7-byte T.124 identifier,
    // a PER length, the 8-byte CCRQ header, the 4-byte H.221 key, another PER
    // length, then the blocks.
    const auto& gcc = ci.gcc_conference_create_request;
    CHECK(gcc.size() > 21);
    size_t off = 7;
    off += (gcc[off] & 0x80) == 0 ? 1 : 2;
    off += 8 + 4;
    off += (gcc[off] & 0x80) == 0 ? 1 : 2;
    GccUserData ud;
    CHECK(GccUserData::parse(gcc.data() + off, gcc.size() - off, ud) ==
          Status::Ok);

    const auto* core = ud.find(0xC001);
    CHECK(core != nullptr);
    // TS_UD_CS_CORE earlyCapabilityFlags sits at payload offset 140.
    CHECK(core->payload.size() >= 142);
    const uint16_t flags = static_cast<uint16_t>(core->payload[140] |
                                                 (core->payload[141] << 8));
    // RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU (0x0040) plus the default 0x0001.
    CHECK((flags & 0x0040) != 0);
}

// ---- SessionSetup records the Monitor Layout PDU ---------------------------

RTSC_TEST(session_setup_records_monitor_layout_without_state_change) {
    SessionSetupMachine m(MakeSessionConfig());
    m.Start();
    const auto da = BuildDemandActive();
    m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());
    CHECK(m.state().phase == SessionPhase::kFinalizing);
    CHECK(!m.state().has_monitor_layout);

    MonitorLayoutPdu layout;
    layout.monitors = MakeMonitors();
    const auto ml =
        ServerDataPdu(ShareDataPduType::kMonitorLayout, layout.encode_body());
    const auto step = m.OnPdu(ml.data(), ml.size());
    CHECK(!step.failed);
    CHECK(m.state().has_monitor_layout);
    CHECK_EQ(m.state().monitors.size(), static_cast<size_t>(2));
    CHECK(m.state().monitors[0].primary());
    // The PDU does not change the phase (capabilities.md 12.2).
    CHECK(m.state().phase == SessionPhase::kFinalizing);
}

// ---- Multi-surface pipeline ------------------------------------------------

RTSC_TEST(multimon_pipeline_builds_virtual_desktop_and_monitor_surfaces) {
    client::GraphicsPipeline g(4, 4);
    g.set_monitor_layout(MakeMonitors());
    CHECK_EQ(g.monitor_count(), static_cast<size_t>(2));
    CHECK_EQ(g.virtual_width(), 8);
    CHECK_EQ(g.virtual_height(), 4);
    CHECK_EQ(g.origin_x(), 0);
    CHECK_EQ(g.origin_y(), 0);
    CHECK(g.monitor_surface(0) != nullptr);
    CHECK(g.monitor_surface(1) != nullptr);
    CHECK_EQ(g.monitor_surface(0)->width(), static_cast<uint16_t>(4));
    CHECK_EQ(g.monitor_surface(1)->width(), static_cast<uint16_t>(4));
    CHECK(g.monitor_surface(2) == nullptr);
}

RTSC_TEST(multimon_pipeline_translates_negative_origin) {
    client::GraphicsPipeline g(4, 4);
    g.set_monitor_layout(MakeNegativeOriginMonitors());
    CHECK_EQ(g.monitor_count(), static_cast<size_t>(2));
    // Union spans y = -4 .. 3, so the virtual desktop is 4x8 at origin (0,-4).
    CHECK_EQ(g.virtual_width(), 4);
    CHECK_EQ(g.virtual_height(), 8);
    CHECK_EQ(g.origin_x(), 0);
    CHECK_EQ(g.origin_y(), -4);
}

RTSC_TEST(multimon_pipeline_render_monitor_rectangles) {
    client::GraphicsPipeline g(4, 4);
    g.set_monitor_layout(MakeMonitors());
    // Paint the left half red and the right half green on the virtual desktop.
    g.surface().FillRect(0, 0, 4, 4, 0xFF, 0, 0, 0xFF);
    g.surface().FillRect(4, 0, 4, 4, 0, 0xFF, 0, 0xFF);

    ui::Surface left(4, 4);
    ui::Surface right(4, 4);
    g.RenderMonitorTo(0, left);
    g.RenderMonitorTo(1, right);

    auto all = [](const ui::Surface& s, uint8_t r, uint8_t gg, uint8_t b) {
        for (int y = 0; y < s.height(); ++y) {
            for (int x = 0; x < s.width(); ++x) {
                uint8_t pr = 0, pg = 0, pb = 0, pa = 0;
                if (!s.GetPixel(x, y, pr, pg, pb, pa)) return false;
                if (pr != r || pg != gg || pb != b) return false;
            }
        }
        return true;
    };
    CHECK(all(left, 0xFF, 0, 0));
    CHECK(all(right, 0, 0xFF, 0));
}

RTSC_TEST(multimon_pipeline_render_negative_origin) {
    client::GraphicsPipeline g(4, 4);
    g.set_monitor_layout(MakeNegativeOriginMonitors());
    // Virtual desktop is 4x8; rows 0..3 are the upper (secondary) monitor and
    // rows 4..7 are the primary. Paint them differently.
    g.surface().FillRect(0, 0, 4, 4, 0, 0, 0xFF, 0xFF);  // upper: blue
    g.surface().FillRect(0, 4, 4, 4, 0xFF, 0, 0, 0xFF);  // lower: red

    ui::Surface upper(4, 4);
    ui::Surface lower(4, 4);
    g.RenderMonitorTo(1, upper);  // the monitor above the primary
    g.RenderMonitorTo(0, lower);

    uint8_t r = 0, gg = 0, b = 0, a = 0;
    CHECK(upper.GetPixel(0, 0, r, gg, b, a) && b == 0xFF && r == 0);
    CHECK(lower.GetPixel(0, 0, r, gg, b, a) && r == 0xFF && b == 0);
}

RTSC_TEST(multimon_pipeline_bitmap_negative_desktop_coordinate_translates) {
    client::GraphicsPipeline g(4, 4);
    // Origin (0,-4): the virtual desktop is 4x8 and a monitor above the
    // primary lives at negative y. A bitmap at virtual-desktop (0,-2) must be
    // translated by -origin to surface (0,2).
    g.set_monitor_layout(MakeNegativeOriginMonitors());
    const auto pdu = FastPathBitmapPdu(
        {RawRect(0, -2, 1, 1, {0x00, 0x00, 0xFF, 0xFF})});
    FastPathOutputPdu parsed;
    CHECK(FastPathOutputPdu::parse(pdu.data(), pdu.size(), parsed) == Status::Ok);
    CHECK_EQ(g.ApplyFastPathOutput(parsed), 1);

    uint8_t r = 0, gg = 0, b = 0, a = 0;
    CHECK(g.surface().GetPixel(0, 2, r, gg, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xFF));
    // The untranslated position must stay black.
    CHECK(g.surface().GetPixel(0, 0, r, gg, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(multimon_pipeline_empty_layout_keeps_single_surface) {
    client::GraphicsPipeline g(4, 4);
    g.set_monitor_layout({});
    CHECK_EQ(g.monitor_count(), static_cast<size_t>(0));
    CHECK_EQ(g.virtual_width(), 4);
    CHECK_EQ(g.virtual_height(), 4);
    CHECK(g.monitor_surface(0) == nullptr);
    // A no-op blit path still works.
    g.surface().Fill(0xFF, 0, 0, 0xFF);
    ui::Surface dst(4, 4);
    g.RenderTo(dst);
    uint8_t r = 0, gg = 0, b = 0, a = 0;
    CHECK(dst.GetPixel(0, 0, r, gg, b, a) && r == 0xFF);
}

int main() { return rtsc::test::run_all("rtsc_multimon_tests"); }
