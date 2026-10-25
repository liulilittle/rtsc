// Session setup state machine: Capability Exchange + Connection Finalization.
//
// Reference: docs/spec/capabilities.md section 12; [MS-RDPBCGR] 1.3.1.1 phase 8.
//
// The Demand Active PDU is the official [MS-RDPBCGR] 4.1.12 dump (359 bytes of
// decrypted TS_DEMAND_ACTIVE_PDU), wrapped here in an MCS Send Data frame.

#include <cstdint>
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

}  // namespace

RTSC_TEST(session_setup_starts_waiting_for_demand_active) {
    SessionSetupMachine m(MakeConfig());
    CHECK(m.state().phase == SessionPhase::kInit);
    m.Start();
    CHECK(m.state().phase == SessionPhase::kWaitDemandActive);
}

RTSC_TEST(session_setup_demand_active_emits_finalization_batch) {
    SessionSetupMachine m(MakeConfig());
    m.Start();

    const auto da = FromHex(kDemandActiveHex);
    const auto step = m.OnPdu(ServerPdu(da).data(), ServerPdu(da).size());
    CHECK(!step.failed);

    // Confirm Active + Synchronize + Control(Cooperate) + Control(RequestControl)
    // + Font List = 5 PDUs.
    CHECK_EQ(step.to_send.size(), static_cast<size_t>(5));
    CHECK(m.state().phase == SessionPhase::kFinalizing);
    CHECK_EQ(m.state().share_id, static_cast<uint32_t>(0x000103EA));
    CHECK_EQ(m.state().server_channel_id, static_cast<uint16_t>(0x03EA));
    CHECK(m.state().server_capabilities.sets.size() == 13);
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

int main() { return ::rtsc::test::run_all("rtsc_session_setup_tests"); }
