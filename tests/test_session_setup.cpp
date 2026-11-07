// Session setup state machine: Capability Exchange + Connection Finalization.
//
// Reference: docs/spec/capabilities.md section 12; [MS-RDPBCGR] 1.3.1.1 phase 8.
//
// The Demand Active PDU is the official [MS-RDPBCGR] 4.1.12 dump (359 bytes of
// decrypted TS_DEMAND_ACTIVE_PDU), wrapped here in an MCS Send Data frame.

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "rtsc/proto/mcs.h"
#include "rtsc/proto/session_setup.h"
#include "rtsc/proto/share.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> FromHex(const char* s) {
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

// [MS-RDPBCGR] 4.1.12 Demand Active PDU, decrypted plaintext (359 bytes).
const char* kDemandActiveHex =
    "67 01 11 00 ea 03 ea 03 01 00 04 00 51 01 52 44 "
    "50 00 0d 00 00 00 09 00 08 00 ea 03 dc e2 01 00 "
    "18 00 01 00 03 00 00 02 00 00 00 00 1d 04 00 00 "
    "00 00 00 00 01 01 14 00 08 00 02 00 00 00 16 00 "
    "28 00 00 00 00 00 70 f6 13 f3 01 00 00 00 01 00 "
    "00 00 18 00 00 00 9c f6 13 f3 61 a6 82 80 00 00 "
    "00 00 00 50 91 bf 0e 00 04 00 02 00 1c 00 18 00 "
    "01 00 01 00 01 00 00 05 00 04 00 00 01 00 01 00 "
    "00 00 01 00 00 00 03 00 58 00 00 00 00 00 00 00 "
    "00 00 00 00 00 00 00 00 00 00 40 42 0f 00 01 00 "
    "14 00 00 00 01 00 00 00 22 00 01 01 01 01 01 00 "
    "00 01 01 01 01 01 00 00 00 01 01 01 01 01 01 01 "
    "01 00 01 01 01 01 00 00 00 00 a1 06 00 00 40 42 "
    "0f 00 40 42 0f 00 01 00 00 00 00 00 00 00 0a 00 "
    "08 00 06 00 00 00 12 00 08 00 01 00 00 00 08 00 "
    "0a 00 01 00 19 00 19 00 0d 00 58 00 35 00 00 00 "
    "a1 06 00 00 40 42 0f 00 0c f6 13 f3 93 5a 37 f3 "
    "00 90 30 e1 34 1c 38 f3 40 f6 13 f3 04 00 00 00 "
    "4c 54 dc e2 08 50 dc e2 01 00 00 00 08 50 dc e2 "
    "00 00 00 00 38 f6 13 f3 2e 05 38 f3 08 50 dc e2 "
    "2c f6 13 f3 00 00 00 00 08 00 0a 00 01 00 19 00 "
    "17 00 08 00 00 00 00 00 18 00 0b 00 00 00 00 00 "
    "00 00 00 00 00 00 00";

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

SessionSetupMachine::Config MakeConfig() {
    SessionSetupMachine::Config c;
    c.user_channel_id = 0x03EF;
    c.io_channel_id = 0x03EB;
    c.desktop_width = 1280;
    c.desktop_height = 1024;
    c.color_depth = 24;
    c.source_descriptor = "RTSC";
    return c;
}

// A minimal TS_DEMAND_ACTIVE_PDU carrying exactly `sets`, wrapped in the MCS
// Send Data frame SessionSetupMachine::OnPdu consumes.
std::vector<uint8_t> DemandActiveWithSets(
    const std::vector<CapabilitySet>& sets) {
    ByteWriter caps;
    uint16_t count = 0;
    uint16_t combined = 0;
    WriteCapabilitySets(caps, sets, count, combined);
    const std::string src = "RTSC";
    ByteWriter w;
    // totalLength = share control (6) + shareID (4) + lenSrc/lenCombined (4)
    //             + src + numberCap/pad2 (4, inside combined) + sets + sessionId.
    w.u16le(static_cast<uint16_t>(14 + src.size() + combined + 4));
    w.u16le(0x0011);  // pduType: type 1 (Demand Active), version 1
    w.u16le(0x03EA);  // pduSource = server channel
    w.u32le(0x000103EA);  // shareID
    w.u16le(static_cast<uint16_t>(src.size()));
    w.u16le(combined);
    if (!src.empty()) {
        w.bytes(reinterpret_cast<const uint8_t*>(src.data()), src.size());
    }
    w.u16le(count);
    w.u16le(0);  // pad2Octets
    w.bytes(caps.data().data(), caps.size());
    w.u32le(0);  // sessionId
    return ServerPdu(w.take());
}

}  // namespace

RTSC_TEST(session_setup_starts_waiting_for_demand_active) {
    SessionSetupMachine m(MakeConfig());
    CHECK(m.state().phase == SessionPhase::kInit);
    m.Start();
    CHECK(m.state().phase == SessionPhase::kWaitDemandActive);
}

RTSC_TEST(session_setup_stores_server_input_flags) {
    // The Input capability set parsing is what gates client-sent features like
    // PTRFLAGS_HWHEEL: a server that advertises INPUT_FLAG_MOUSE_HWHEEL
    // (0x0100) is recorded as supporting it, one that does not stays clear.
    InputCapabilitySet in;  // the default client set includes 0x0100
    CHECK((in.input_flags & InputCapabilitySet::kInputFlagMouseHWheel) != 0);

    SessionSetupMachine supported(MakeConfig());
    supported.Start();
    const std::vector<uint8_t> with_wire = DemandActiveWithSets({in.encode()});
    auto step = supported.OnPdu(with_wire.data(), with_wire.size());
    CHECK(!step.failed);
    CHECK((supported.state().server_input_flags &
           InputCapabilitySet::kInputFlagMouseHWheel) != 0);

    InputCapabilitySet bare;
    bare.input_flags = in.input_flags & ~InputCapabilitySet::kInputFlagMouseHWheel;
    SessionSetupMachine unsupported(MakeConfig());
    unsupported.Start();
    const std::vector<uint8_t> no_wire = DemandActiveWithSets({bare.encode()});
    step = unsupported.OnPdu(no_wire.data(), no_wire.size());
    CHECK(!step.failed);
    CHECK((unsupported.state().server_input_flags &
           InputCapabilitySet::kInputFlagMouseHWheel) == 0);
}

RTSC_TEST(session_setup_demand_active_emits_finalization_batch) {
    SessionSetupMachine m(MakeConfig());
    m.Start();

    const auto da = FromHex(kDemandActiveHex);
    const auto step = m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());
    CHECK(!step.failed);

    // Confirm Active + Synchronize + Control(Cooperate) + Control(RequestControl)
    // + Font List = 5 PDUs. The Refresh Rect is NOT part of the batch: mstsc
    // sends it only after the server's Font Map completes activation.
    CHECK_EQ(step.to_send.size(), static_cast<size_t>(5));
    CHECK(m.state().phase == SessionPhase::kFinalizing);
    CHECK_EQ(m.state().share_id, static_cast<uint32_t>(0x000103EA));
    CHECK_EQ(m.state().server_channel_id, static_cast<uint16_t>(0x03EA));
    CHECK(m.state().server_capabilities.sets.size() == 13);
}

RTSC_TEST(session_setup_confirm_active_has_no_rail_caps_by_default) {
    // Desktop sessions must not claim TS_RAIL_CAPS ([MS-RDPERP] 1.3: RAIL is
    // for Remote Programs); claiming it unconditionally made the Windows
    // server run a RemoteApp session with a never-composited desktop.
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    const auto step = m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());
    CHECK(!step.failed);
    CHECK(step.to_send.size() >= 1);

    McsSendData sd;
    CHECK(McsSendData::parse(step.to_send[0].data(), step.to_send[0].size(),
                            sd) == Status::Ok);
    ConfirmActivePdu ca;
    CHECK(ConfirmActivePdu::parse(sd.user_data.data(), sd.user_data.size(),
                                  ca) == Status::Ok);
    CHECK(!ca.capabilities.has(CapabilityType::kRail));
}

RTSC_TEST(session_setup_font_map_activation_emits_refresh_rect) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());
    CHECK(m.state().phase == SessionPhase::kFinalizing);

    const std::vector<uint8_t> fontmap = {0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
                                          0x04, 0x00};
    auto wire = ServerDataPdu(ShareDataPduType::kFontMap, fontmap);
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(step.active);
    CHECK(m.state().phase == SessionPhase::kActive);

    // The activation step carries exactly one extra PDU: the Refresh Rect
    // ([MS-RDPBCGR] 2.2.11.3) requesting the full desktop, mirroring mstsc.
    CHECK_EQ(step.to_send.size(), static_cast<size_t>(1));
    McsSendData sd;
    CHECK(McsSendData::parse(step.to_send[0].data(), step.to_send[0].size(),
                            sd) == Status::Ok);
    ShareDataHeader hdr;
    CHECK(ShareDataHeader::parse(sd.user_data.data(), sd.user_data.size(),
                                 hdr) == Status::Ok);
    CHECK(hdr.pdu_type2 == ShareDataPduType::kRefreshRect);

    // Body: numberOfAreas(1) + pad3Octets(3) + one full-desktop rectangle
    // (left, top, right, bottom inclusive, [MS-RDPBCGR] 2.2.11.2.1). The
    // padding FOLLOWS the count: a server reading numberOfAreas from byte 0
    // must see 1, not the pad1 byte the old (pad1+count) layout emitted.
    const auto& body = sd.user_data;
    CHECK(body.size() >= ShareDataHeader::kSize + 12);
    const uint8_t* p = body.data() + ShareDataHeader::kSize;
    CHECK_EQ(p[0], static_cast<uint8_t>(1));  // numberOfAreas
    CHECK_EQ(p[1], static_cast<uint8_t>(0));  // pad3Octets
    CHECK_EQ(p[2], static_cast<uint8_t>(0));
    CHECK_EQ(p[3], static_cast<uint8_t>(0));
    const auto rd16 = [&p](size_t off) {
        return static_cast<uint16_t>(p[off]) |
               static_cast<uint16_t>(p[off + 1] << 8);
    };
    CHECK_EQ(rd16(4), static_cast<uint16_t>(0));   // left
    CHECK_EQ(rd16(6), static_cast<uint16_t>(0));   // top
    CHECK_EQ(rd16(8), static_cast<uint16_t>(m.state().desktop_width - 1));   // right
    CHECK_EQ(rd16(10), static_cast<uint16_t>(m.state().desktop_height - 1));  // bottom
}

RTSC_TEST(session_setup_suppress_output_allow_triggers_refresh_rect) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());
    CHECK(m.state().phase == SessionPhase::kFinalizing);

    // Server Suppress Output with allowDisplayUpdates=1 and the desktop
    // rectangle ([MS-RDPBCGR] 2.2.11.3.1: allowDisplayUpdates(1) + pad3Octets(3)
    // + desktopRect(8); no count field, no rectangle array): the client must
    // answer with a Refresh Rect for that rectangle.
    std::vector<uint8_t> body = {0x01, 0x00, 0x00, 0x00,   // allow + pad3
                                 0x00, 0x00, 0x00, 0x00,   // desktopRect left/top
                                 0xff, 0x03, 0xff, 0x03};  // desktopRect right/bottom
    const auto step = m.OnPdu(
        ServerDataPdu(ShareDataPduType::kSuppressOutput, body).data(),
        ServerDataPdu(ShareDataPduType::kSuppressOutput, body).size());
    CHECK(!step.failed);
    CHECK_EQ(step.to_send.size(), static_cast<size_t>(1));

    McsSendData sd;
    CHECK(McsSendData::parse(step.to_send[0].data(), step.to_send[0].size(),
                            sd) == Status::Ok);
    ShareDataHeader hdr;
    CHECK(ShareDataHeader::parse(sd.user_data.data(), sd.user_data.size(),
                                  hdr) == Status::Ok);
    CHECK(hdr.pdu_type2 == ShareDataPduType::kRefreshRect);
    // numberOfAreas(1)=1 then pad3Octets(3)=0.
    const uint8_t* p = sd.user_data.data() + ShareDataHeader::kSize;
    CHECK_EQ(p[0], static_cast<uint8_t>(1));
    CHECK_EQ(p[1], static_cast<uint8_t>(0));
    CHECK_EQ(p[2], static_cast<uint8_t>(0));
    CHECK_EQ(p[3], static_cast<uint8_t>(0));
    // The refreshed rectangle is the one the server named, not the full
    // desktop: (0,0)-(1023,1023).
    const auto rd16 = [&p](size_t off) {
        return static_cast<uint16_t>(p[off]) |
               static_cast<uint16_t>(p[off + 1] << 8);
    };
    CHECK_EQ(rd16(4), static_cast<uint16_t>(0));
    CHECK_EQ(rd16(6), static_cast<uint16_t>(0));
    CHECK_EQ(rd16(8), static_cast<uint16_t>(0x03ff));
    CHECK_EQ(rd16(10), static_cast<uint16_t>(0x03ff));
}

RTSC_TEST(session_setup_suppress_output_disallow_does_not_refresh) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());
    CHECK(m.state().phase == SessionPhase::kFinalizing);

    // allowDisplayUpdates=0 ([MS-RDPBCGR] 2.2.11.3.1: allow(1) + pad3(3), no
    // desktopRect, no count): output stays suppressed; no Refresh Rect.
    std::vector<uint8_t> body = {0x00, 0x00, 0x00, 0x00};
    const auto step = m.OnPdu(
        ServerDataPdu(ShareDataPduType::kSuppressOutput, body).data(),
        ServerDataPdu(ShareDataPduType::kSuppressOutput, body).size());
    CHECK(!step.failed);
    CHECK(step.to_send.empty());
}

RTSC_TEST(session_setup_suppress_output_malformed_is_ignored) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());
    CHECK(m.state().phase == SessionPhase::kFinalizing);

    // A truncated body must neither fail the session nor emit a refresh. Two
    // malformed shapes: a cut-off header, and allow=1 with the mandatory
    // desktopRect missing ([MS-RDPBCGR] 2.2.11.3.1).
    for (const std::vector<uint8_t>& body : {std::vector<uint8_t>{0x01, 0x00},
                                             std::vector<uint8_t>{0x01, 0x00,
                                                                  0x00, 0x00}}) {
        const auto step = m.OnPdu(
            ServerDataPdu(ShareDataPduType::kSuppressOutput, body).data(),
            ServerDataPdu(ShareDataPduType::kSuppressOutput, body).size());
        CHECK(!step.failed);
        CHECK(step.to_send.empty());
    }
}

RTSC_TEST(session_setup_first_pdu_is_confirm_active) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    const auto wire = ServerPdu(da);
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(step.to_send.size() >= 1);

    // Unwrap the MCS frame and check the share control header.
    McsSendData sd;
    CHECK(McsSendData::parse(step.to_send[0].data(), step.to_send[0].size(), sd) ==
          Status::Ok);
    ShareControlHeader ctrl;
    CHECK(ShareControlHeader::parse(sd.user_data.data(), sd.user_data.size(),
                                    ctrl) == Status::Ok);
    CHECK(ctrl.type == SharePduType::kConfirmActive);
    CHECK_EQ(ctrl.pdu_source, static_cast<uint16_t>(0x03EF));  // user channel
}

RTSC_TEST(session_setup_font_map_activates) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());
    CHECK(m.state().phase == SessionPhase::kFinalizing);

    // Server Synchronize, then Control, then Font Map.
    const std::vector<uint8_t> sync = {0x01, 0x00, 0xEA, 0x03};
    auto wire = ServerDataPdu(ShareDataPduType::kSynchronize, sync);
    auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(m.state().phase == SessionPhase::kFinalizing);

    const std::vector<uint8_t> control = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00};
    wire = ServerDataPdu(ShareDataPduType::kControl, control);
    step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(m.state().phase == SessionPhase::kFinalizing);

    const std::vector<uint8_t> fontmap = {0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
                                          0x04, 0x00};
    wire = ServerDataPdu(ShareDataPduType::kFontMap, fontmap);
    step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(step.active);
    CHECK(m.active());
    CHECK(m.state().phase == SessionPhase::kActive);
}

RTSC_TEST(session_setup_deactivate_all_transitions_to_deactivated) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());

    // Deactivate All: share control header with type = 6.
    ByteWriter w;
    w.u16le(9);        // totalLength
    w.u16le(0x0016);   // pduType: type=6, version=1
    w.u16le(0x03EA);   // pduSource
    w.u8(0x00);        // sourceDescriptor
    auto wire = ServerPdu(w.take());
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(m.state().phase == SessionPhase::kDeactivated);
}

RTSC_TEST(session_setup_reactivates_after_deactivate_all) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    auto wire = ServerPdu(da);
    auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(m.state().phase == SessionPhase::kFinalizing);

    const std::vector<uint8_t> fontmap = {0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
                                          0x04, 0x00};
    wire = ServerDataPdu(ShareDataPduType::kFontMap, fontmap);
    step = m.OnPdu(wire.data(), wire.size());
    CHECK(step.active);
    CHECK(m.active());

    // Deactivate All ([MS-RDPBCGR] 2.2.3.1.1): type 6, 9 bytes.
    ByteWriter w;
    w.u16le(9);
    w.u16le(0x0016);
    w.u16le(0x03EA);
    w.u8(0x00);
    wire = ServerPdu(w.take());
    step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(m.state().phase == SessionPhase::kDeactivated);
    CHECK(!m.active());

    // Deactivation-Reactivation Sequence ([MS-RDPBCGR] 1.3.1.3): a new Demand
    // Active re-runs the Capability Exchange, so the machine must emit Confirm
    // Active plus the four Connection Finalization PDUs again.
    wire = ServerPdu(da);
    step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(m.state().phase == SessionPhase::kFinalizing);
    CHECK_EQ(step.to_send.size(), static_cast<size_t>(5));

    // Font Map completes the re-activation.
    wire = ServerDataPdu(ShareDataPduType::kFontMap, fontmap);
    step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(step.active);
    CHECK(m.active());
}

RTSC_TEST(session_setup_deactivated_ignores_non_demand_pdu) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    auto wire = ServerPdu(da);
    m.OnPdu(wire.data(), wire.size());
    const std::vector<uint8_t> fontmap = {0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
                                          0x04, 0x00};
    wire = ServerDataPdu(ShareDataPduType::kFontMap, fontmap);
    m.OnPdu(wire.data(), wire.size());
    CHECK(m.active());

    ByteWriter w;
    w.u16le(9);
    w.u16le(0x0016);
    w.u16le(0x03EA);
    w.u8(0x00);
    wire = ServerPdu(w.take());
    m.OnPdu(wire.data(), wire.size());
    CHECK(m.state().phase == SessionPhase::kDeactivated);

    // While deactivated, a non-Demand-Active PDU is ignored: no failure, no
    // reactivation, and no reply.
    wire = ServerDataPdu(ShareDataPduType::kFontMap, fontmap);
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(step.to_send.empty());
    CHECK(m.state().phase == SessionPhase::kDeactivated);
    CHECK(!m.active());
}

RTSC_TEST(session_setup_reactivation_adopts_new_desktop_size) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    auto wire = ServerPdu(da);
    m.OnPdu(wire.data(), wire.size());
    const std::vector<uint8_t> fontmap = {0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
                                          0x04, 0x00};
    wire = ServerDataPdu(ShareDataPduType::kFontMap, fontmap);
    m.OnPdu(wire.data(), wire.size());
    CHECK(m.active());

    ByteWriter w;
    w.u16le(9);
    w.u16le(0x0016);
    w.u16le(0x03EA);
    w.u8(0x00);
    wire = ServerPdu(w.take());
    m.OnPdu(wire.data(), wire.size());
    CHECK(m.state().phase == SessionPhase::kDeactivated);

    // The replayed Demand Active grants a different desktop size; the machine
    // must adopt it ([MS-RDPBCGR] 2.2.1.13.1 bitmap capability).
    BitmapCapabilitySet bmp;
    bmp.desktop_width = 1600;
    bmp.desktop_height = 900;
    wire = DemandActiveWithSets({bmp.encode()});
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(m.state().phase == SessionPhase::kFinalizing);
    CHECK_EQ(m.state().desktop_width, static_cast<uint16_t>(1600));
    CHECK_EQ(m.state().desktop_height, static_cast<uint16_t>(900));
}

RTSC_TEST(session_setup_deactivated_rejects_malformed_share_control) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    auto wire = ServerPdu(da);
    m.OnPdu(wire.data(), wire.size());
    const std::vector<uint8_t> fontmap = {0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
                                          0x04, 0x00};
    wire = ServerDataPdu(ShareDataPduType::kFontMap, fontmap);
    m.OnPdu(wire.data(), wire.size());
    CHECK(m.active());

    ByteWriter w;
    w.u16le(9);
    w.u16le(0x0016);
    w.u16le(0x03EA);
    w.u8(0x00);
    wire = ServerPdu(w.take());
    m.OnPdu(wire.data(), wire.size());
    CHECK(m.state().phase == SessionPhase::kDeactivated);

    // Too short to hold a share control header: fail closed instead of
    // silently staying deactivated forever.
    const std::vector<uint8_t> tiny = {0x00, 0x00};
    wire = ServerPdu(tiny);
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(step.failed);
}

RTSC_TEST(session_setup_deactivated_ignores_repeated_deactivate_all) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    auto wire = ServerPdu(da);
    m.OnPdu(wire.data(), wire.size());
    const std::vector<uint8_t> fontmap = {0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
                                          0x04, 0x00};
    wire = ServerDataPdu(ShareDataPduType::kFontMap, fontmap);
    m.OnPdu(wire.data(), wire.size());
    CHECK(m.active());

    ByteWriter w;
    w.u16le(9);
    w.u16le(0x0016);
    w.u16le(0x03EA);
    w.u8(0x00);
    const std::vector<uint8_t> deactivate = ServerPdu(w.take());
    auto step = m.OnPdu(deactivate.data(), deactivate.size());
    CHECK(!step.failed);
    CHECK(m.state().phase == SessionPhase::kDeactivated);

    // A second Deactivate All while already deactivated must be ignored: the
    // server has not yet said whether this is a drop or a re-exchange.
    step = m.OnPdu(deactivate.data(), deactivate.size());
    CHECK(!step.failed);
    CHECK(step.to_send.empty());
    CHECK(m.state().phase == SessionPhase::kDeactivated);
    CHECK(!m.active());
}

RTSC_TEST(session_setup_set_error_info_is_recorded) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());

    // Set Error Info: errorInfo = 0x00000009 (ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES).
    const std::vector<uint8_t> payload = {0x09, 0x00, 0x00, 0x00};
    const auto wire = ServerDataPdu(ShareDataPduType::kSetErrorInfo, payload);
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(m.state().has_error_info);
    CHECK_EQ(m.state().error_info, static_cast<uint32_t>(0x00000009));
    // The state must not change.
    CHECK(m.state().phase == SessionPhase::kFinalizing);
}

RTSC_TEST(session_setup_ignores_unknown_pdu) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());

    // A graphics Update PDU (pduType2 = 0x02) before Font Map must be ignored.
    const std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x00};
    const auto wire = ServerDataPdu(ShareDataPduType::kUpdate, payload);
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(m.state().phase == SessionPhase::kFinalizing);
}

// ---- Save Session Info ([MS-RDPBCGR] 2.2.10.1.1) --------------------------

namespace {

void AppendUtf16Le(ByteWriter& w, const char* ascii) {
    for (const char* p = ascii; *p != '\0'; ++p) {
        w.u16le(static_cast<uint16_t>(static_cast<uint8_t>(*p)));
    }
    w.u16le(0);
}

// TS_LOGON_INFO_VERSION_2 body: infoType(4) + Version(2) + Size(4) +
// SessionId(4) + cbDomain(4) + cbUserName(4) + Pad(558) + strings.
std::vector<uint8_t> LogonInfoV2Body(uint32_t session_id, const char* domain,
                                     const char* user, uint32_t size_field) {
    ByteWriter w;
    w.u32le(1);  // INFOTYPE_LOGON_LONG
    w.u16le(1);  // SAVE_SESSION_PDU_VERSION_ONE
    w.u32le(size_field);
    w.u32le(session_id);
    const size_t domain_bytes = (std::strlen(domain) + 1) * 2;
    const size_t user_bytes = (std::strlen(user) + 1) * 2;
    w.u32le(static_cast<uint32_t>(domain_bytes));
    w.u32le(static_cast<uint32_t>(user_bytes));
    for (int i = 0; i < 558; ++i) w.u8(0);
    AppendUtf16Le(w, domain);
    AppendUtf16Le(w, user);
    return w.take();
}

// TS_LOGON_INFO_EXTENDED body with LOGON_EX_AUTORECONNECTCOOKIE only.
std::vector<uint8_t> LogonExtendedBody(uint32_t version, uint32_t logon_id,
                                       uint8_t seed) {
    ByteWriter w;
    w.u32le(3);  // INFOTYPE_LOGON_EXTENDED_INFO
    w.u16le(38); // Length (after the Length field)
    w.u32le(1);  // LOGON_EX_AUTORECONNECTCOOKIE
    w.u32le(28); // cbFieldData
    w.u32le(28); // ARC_SC_PRIVATE_PACKET::cbLen
    w.u32le(version);
    w.u32le(logon_id);
    for (int i = 0; i < 16; ++i) w.u8(static_cast<uint8_t>(seed + i));
    return w.take();
}

}  // namespace

RTSC_TEST(session_setup_parses_logon_info_v2) {
    SaveSessionInfo info;
    const auto body = LogonInfoV2Body(7, "NTDEV", "alice", 576);
    CHECK(ParseSaveSessionInfo(body.data(), body.size(), info) == Status::Ok);
    CHECK(info.has_logon);
    CHECK_EQ(info.session_id, static_cast<uint32_t>(7));
    CHECK(info.domain == "NTDEV");
    CHECK(info.user_name == "alice");
    CHECK(!info.has_auto_reconnect_cookie);

    // Windows Server 2019/2022 send Size = 12 (the fixed part only); both
    // values are accepted ([FreeRDP info.c] logonInfoV2Size quirk).
    SaveSessionInfo short_size;
    const auto body2 = LogonInfoV2Body(9, "D", "bob", 18);
    CHECK(ParseSaveSessionInfo(body2.data(), body2.size(), short_size) ==
          Status::Ok);
    CHECK(short_size.has_logon);
    CHECK_EQ(short_size.session_id, static_cast<uint32_t>(9));
    CHECK(short_size.user_name == "bob");
}

RTSC_TEST(session_setup_parses_auto_reconnect_cookie) {
    SaveSessionInfo info;
    const auto body = LogonExtendedBody(1, 2, 0xA0);
    CHECK(ParseSaveSessionInfo(body.data(), body.size(), info) == Status::Ok);
    CHECK(!info.has_logon);
    CHECK(info.has_auto_reconnect_cookie);
    CHECK_EQ(info.auto_reconnect_version, static_cast<uint32_t>(1));
    CHECK_EQ(info.auto_reconnect_logon_id, static_cast<uint32_t>(2));
    CHECK_EQ(info.auto_reconnect_random.size(), static_cast<size_t>(16));
    CHECK_EQ(info.auto_reconnect_random[0], static_cast<uint8_t>(0xA0));
    CHECK_EQ(info.auto_reconnect_random[15], static_cast<uint8_t>(0xAF));
}

RTSC_TEST(session_setup_rejects_truncated_logon_info) {
    SaveSessionInfo info;
    const auto body = LogonInfoV2Body(7, "NTDEV", "alice", 576);
    // Truncate inside the fixed 558-byte pad: must fail, not read past the end.
    CHECK(ParseSaveSessionInfo(body.data(), 300, info) != Status::Ok);

    // cbDomain larger than the remaining bytes: rejected.
    ByteWriter w;
    w.u32le(1);
    w.u16le(1);
    w.u32le(576);
    w.u32le(1);
    w.u32le(600);  // cbDomain: far beyond the body
    w.u32le(2);
    for (int i = 0; i < 558; ++i) w.u8(0);
    const auto bad = w.take();
    SaveSessionInfo other;
    CHECK(ParseSaveSessionInfo(bad.data(), bad.size(), other) != Status::Ok);
    CHECK(!other.has_logon);
}

RTSC_TEST(session_setup_ignores_plain_notify) {
    // INFOTYPE_LOGON_PLAINNOTIFY (2) carries 576 bytes of padding and no data.
    ByteWriter w;
    w.u32le(2);
    for (int i = 0; i < 576; ++i) w.u8(0);
    const auto body = w.take();
    SaveSessionInfo info;
    CHECK(ParseSaveSessionInfo(body.data(), body.size(), info) == Status::Ok);
    CHECK(!info.has_logon);
    CHECK(!info.has_auto_reconnect_cookie);
}

RTSC_TEST(session_setup_records_logon_info_from_pdu) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());

    const auto body = LogonInfoV2Body(3, "CONTOSO", "carol", 576);
    const auto wire = ServerDataPdu(ShareDataPduType::kSaveSessionInfo, body);
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(m.state().logon_info.has_logon);
    CHECK_EQ(m.state().logon_info.session_id, static_cast<uint32_t>(3));
    CHECK(m.state().logon_info.user_name == "carol");
    // Save Session Info does not change the phase.
    CHECK(m.state().phase == SessionPhase::kFinalizing);
}

RTSC_TEST(session_setup_records_auto_reconnect_cookie_from_pdu) {
    SessionSetupMachine m(MakeConfig());
    m.Start();
    const auto da = FromHex(kDemandActiveHex);
    m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());

    const auto body = LogonExtendedBody(1, 42, 0x10);
    const auto wire = ServerDataPdu(ShareDataPduType::kSaveSessionInfo, body);
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(m.state().logon_info.has_auto_reconnect_cookie);
    CHECK_EQ(m.state().logon_info.auto_reconnect_logon_id,
             static_cast<uint32_t>(42));
    CHECK_EQ(m.state().logon_info.auto_reconnect_random.size(),
             static_cast<size_t>(16));
    CHECK(m.state().phase == SessionPhase::kFinalizing);
}

RTSC_TEST(session_setup_encodes_logon_info_v2_round_trip) {
    const auto body = EncodeSaveSessionInfoLogon(9, "NTDEV", "alice");
    CHECK(!body.empty());
    SaveSessionInfo info;
    CHECK(ParseSaveSessionInfo(body.data(), body.size(), info) == Status::Ok);
    CHECK(info.has_logon);
    CHECK_EQ(info.session_id, static_cast<uint32_t>(9));
    CHECK(info.domain == "NTDEV");
    CHECK(info.user_name == "alice");

    // Non-ASCII UTF-8 survives the round trip.
    const auto utf8 = EncodeSaveSessionInfoLogon(1, "域", "用户");
    CHECK(!utf8.empty());
    SaveSessionInfo wide;
    CHECK(ParseSaveSessionInfo(utf8.data(), utf8.size(), wide) == Status::Ok);
    CHECK(wide.domain == "域");
    CHECK(wide.user_name == "用户");
}

RTSC_TEST(session_setup_encode_rejects_overlong_and_invalid) {
    // UserName is capped at 512 bytes (v1 fixed field), terminator included:
    // 256 ASCII characters + NUL = 514 bytes, one past the limit.
    const std::string long_user(256, 'u');
    CHECK(EncodeSaveSessionInfoLogon(1, "D", long_user).empty());
    const std::string max_user(255, 'u');  // 512 bytes including the terminator
    CHECK(!EncodeSaveSessionInfoLogon(1, "D", max_user).empty());

    // Invalid UTF-8 fails closed.
    CHECK(EncodeSaveSessionInfoLogon(1, "\xC3", "u").empty());
}

RTSC_TEST(session_setup_encodes_auto_reconnect_cookie_round_trip) {
    uint8_t random[16] = {};
    for (int i = 0; i < 16; ++i) {
        random[i] = static_cast<uint8_t>(0x30 + i);
    }
    const auto body = EncodeSaveSessionInfoCookie(1, 5, random);
    SaveSessionInfo info;
    CHECK(ParseSaveSessionInfo(body.data(), body.size(), info) == Status::Ok);
    CHECK(info.has_auto_reconnect_cookie);
    CHECK_EQ(info.auto_reconnect_version, static_cast<uint32_t>(1));
    CHECK_EQ(info.auto_reconnect_logon_id, static_cast<uint32_t>(5));
    CHECK_EQ(info.auto_reconnect_random.size(), static_cast<size_t>(16));
    CHECK_EQ(info.auto_reconnect_random[0], static_cast<uint8_t>(0x30));
    CHECK_EQ(info.auto_reconnect_random[15], static_cast<uint8_t>(0x3F));
}

int main() { return ::rtsc::test::run_all("rtsc_session_setup_tests"); }


