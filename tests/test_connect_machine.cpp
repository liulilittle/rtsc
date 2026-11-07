// Connection state machine: drives X.224 negotiation -> MCS Connect Initial ->
// Erect Domain -> Attach User -> Channel Join -> Client Info.
//
// The inbound PDUs are the official annotated dumps from docs/spec/mcs-domain.md
// 搂12 and docs/spec/mcs-connect.md 搂9.1 ([MS-RDPBCGR] 4.1.2 .. 4.1.9), so a
// green run means the machine speaks the published wire format end to end.

#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/client_info.h"
#include "rtsc/proto/connect_machine.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/rdp_neg.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> hex(const char* s) {
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

ConnectMachine::Config MakeConfig() {
    ConnectMachine::Config c;
    c.cookie = "Cookie: mstshash=tester";
    c.requested_protocols = kProtocolRdp;
    c.desktop_width = 1280;
    c.desktop_height = 1024;
    c.client_build = 3790;
    c.client_name = "RTSC";
    c.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
    // No Standard RDP Security: this path is only used with PROTOCOL_RDP and the
    // RC4 key exchange is not implemented yet, so keep the bitmap at zero.
    c.encryption_methods = 0;
    return c;
}

ConnectMachine::Credentials MakeCredentials() {
    ConnectMachine::Credentials cr;
    cr.domain = "NTDEV";
    cr.user_name = "eltons";
    cr.password = "";
    return cr;
}

// [MS-RDPBCGR] 4.1.2: Connection Confirm with selectedProtocol = PROTOCOL_RDP.
const char* kCcfRdp = "03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 00 00 00";

// [MS-RDPBCGR] 4.1.4: the 337-byte Connect Response.
const char* kConnectResponseHex =
    "03 00 01 51 02 f0 80 7f 66 82 01 45 0a 01 00 02 "
    "01 00 30 1a 02 01 22 02 01 03 02 01 00 02 01 01 "
    "02 01 00 02 01 01 02 03 00 ff f8 02 01 02 04 82 "
    "01 1f 00 05 00 14 7c 00 01 2a 14 76 0a 01 01 00 "
    "01 c0 00 4d 63 44 6e 81 08 01 0c 0c 00 04 00 08 "
    "00 00 00 00 00 03 0c 10 00 eb 03 03 00 ec 03 ed "
    "03 ee 03 00 00 02 0c ec 00 02 00 00 00 02 00 00 "
    "00 20 00 00 00 b8 00 00 00 10 11 77 20 30 61 0a "
    "12 e4 34 a1 1e f2 c3 9f 31 7d a4 5f 01 89 34 96 "
    "e0 ff 11 08 69 7f 1a c3 d2 01 00 00 00 01 00 00 "
    "00 01 00 00 00 06 00 5c 00 52 53 41 31 48 00 00 "
    "00 00 02 00 00 3f 00 00 00 01 00 01 00 cb 81 fe "
    "ba 6d 61 c3 55 05 d5 5f 2e 87 f8 71 94 d6 f1 a5 "
    "cb f1 5f 0c 3d f8 70 02 96 c4 fb 9b c8 3c 2d 55 "
    "ae e8 ff 32 75 ea 68 79 e5 a2 01 fd 31 a0 b1 1f "
    "55 a6 1f c1 f6 d1 83 88 63 26 56 12 bc 00 00 00 "
    "00 00 00 00 00 08 00 48 00 e9 e1 d6 28 46 8b 4e "
    "f5 0a df fd ee 21 99 ac b4 e1 8f 5f 81 57 82 ef "
    "9d 96 52 63 27 18 29 db b3 4a fd 9a da 42 ad b5 "
    "69 21 89 0e 1d c0 4c 1a a8 aa 71 3e 0f 54 b9 9a "
    "e4 99 68 3f 6c d6 76 84 61 00 00 00 00 00 00 00 "
    "00";

// [MS-RDPBCGR] 4.1.6: Attach User Confirm assigning user channel 1007.
const char* kAttachUserConfirm = "03 00 00 0b 02 f0 80 2e 00 00 06";

// [MS-RDPBCGR] 4.1.7: Channel Join Confirms for 1007 / 1003 / 1004 / 1005 / 1006.
const char* kJoinConfirmUser = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ef 03 ef";
const char* kJoinConfirmIo = "03 00 00 0f 02 f0 80 3e 00 00 06 03 eb 03 eb";
const char* kJoinConfirmVc1 = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ec 03 ec";
const char* kJoinConfirmVc2 = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ed 03 ed";
const char* kJoinConfirmVc3 = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ee 03 ee";

ConnectStep Feed(ConnectMachine& m, const std::vector<uint8_t>& bytes) {
    return m.OnData(bytes.data(), bytes.size());
}

}  // namespace

// ---- Start ----------------------------------------------------------------

RTSC_TEST(machine_start_emits_x224_connection_request) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    const auto step = m.Start();
    CHECK(!step.output.empty());
    CHECK_EQ(step.output.size(), static_cast<size_t>(44));
    CHECK_EQ(step.output[0], static_cast<uint8_t>(0x03));  // TPKT version
    // X.224 CRQ: LI covers the whole TPDU minus itself; code 0xE0 follows.
    CHECK_EQ(step.output[4], static_cast<uint8_t>(step.output.size() - 5));
    CHECK_EQ(step.output[5], static_cast<uint8_t>(0xE0));
    CHECK(m.state().phase == ConnectPhase::kAwaitNegotiation);
    CHECK(!m.failed());
}

RTSC_TEST(machine_start_includes_cookie_and_neg_req) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    const auto step = m.Start();
    const std::string text(step.output.begin(), step.output.end());
    CHECK(text.find("Cookie: mstshash=tester") != std::string::npos);
    // RDP_NEG_REQ: type 0x01, flags 0x00, length 0x0008
    CHECK(text.find(std::string("\x01\x00\x08\x00", 4)) != std::string::npos);
}

// ---- Negotiation ----------------------------------------------------------

RTSC_TEST(machine_standard_rdp_negotiation_emits_connect_initial) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    const auto step = Feed(m, hex(kCcfRdp));
    CHECK(!m.failed());
    CHECK_EQ(m.state().negotiated_protocol, kProtocolRdp);
    CHECK(m.state().phase == ConnectPhase::kAwaitConnectResponse);
    CHECK(!step.output.empty());
    // TPKT + X.224 Data + 7F 65 (Connect Initial)
    CHECK_EQ(step.output[0], static_cast<uint8_t>(0x03));
    CHECK_EQ(step.output[4], static_cast<uint8_t>(0x02));
    CHECK_EQ(step.output[5], static_cast<uint8_t>(0xF0));
    CHECK_EQ(step.output[6], static_cast<uint8_t>(0x80));
    CHECK_EQ(step.output[7], static_cast<uint8_t>(0x7F));
    CHECK_EQ(step.output[8], static_cast<uint8_t>(0x65));
}

RTSC_TEST(machine_connect_initial_declares_tpkt_length_correctly) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    const auto step = Feed(m, hex(kCcfRdp));
    const size_t declared =
        (static_cast<size_t>(step.output[2]) << 8) | step.output[3];
    CHECK_EQ(declared, step.output.size());
}

RTSC_TEST(machine_connect_initial_roundtrips_through_parser) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    const auto step = Feed(m, hex(kCcfRdp));
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(step.output.data(), step.output.size(), ci) ==
          Status::Ok);
    CHECK(!ci.gcc_conference_create_request.empty());
}

RTSC_TEST(machine_tls_negotiation_waits_for_external_security) {
    ConnectMachine::Config cfg = MakeConfig();
    cfg.requested_protocols = kProtocolSsl | kProtocolHybrid | kProtocolHybridEx;
    ConnectMachine m(cfg, MakeCredentials());
    m.Start();

    // Connection Confirm selecting PROTOCOL_HYBRID_EX (0x08), as captured from
    // 192.168.1.7 (evidence/handshake-001.md).
    const auto ccf =
        hex("03 00 00 13 0e d0 00 00 12 34 00 02 0f 08 00 08 00 00 00");
    const auto step = Feed(m, ccf);
    CHECK(!m.failed());
    CHECK_EQ(m.state().negotiated_protocol, kProtocolHybridEx);
    CHECK(m.state().phase == ConnectPhase::kAwaitExternalSecurity);
    CHECK(step.output.empty());
}

RTSC_TEST(machine_rejects_negotiation_failure) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    // TYPE_RDP_NEG_FAILURE with failureCode 0x05 (HYBRID_REQUIRED_BY_SERVER).
    const auto ccf =
        hex("03 00 00 13 0e d0 00 00 12 34 00 03 00 08 00 05 00 00 00");
    Feed(m, ccf);
    CHECK(m.failed());
    CHECK(m.state().phase == ConnectPhase::kFailed);
}

RTSC_TEST(machine_external_security_completion_continues_sequence) {
    ConnectMachine::Config cfg = MakeConfig();
    cfg.requested_protocols = kProtocolHybridEx;
    ConnectMachine m(cfg, MakeCredentials());
    m.Start();
    Feed(m, hex("03 00 00 13 0e d0 00 00 12 34 00 02 0f 08 00 08 00 00 00"));
    CHECK(m.state().phase == ConnectPhase::kAwaitExternalSecurity);

    const auto step = m.OnExternalSecurityComplete();
    CHECK(!m.failed());
    CHECK(m.state().phase == ConnectPhase::kAwaitConnectResponse);
    CHECK_EQ(step.output[7], static_cast<uint8_t>(0x7F));
    CHECK_EQ(step.output[8], static_cast<uint8_t>(0x65));
}

RTSC_TEST(machine_rejects_data_while_awaiting_external_security) {
    ConnectMachine::Config cfg = MakeConfig();
    cfg.requested_protocols = kProtocolSsl;
    ConnectMachine m(cfg, MakeCredentials());
    m.Start();
    Feed(m, hex("03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 01 00 00 00"));
    CHECK(m.state().phase == ConnectPhase::kAwaitExternalSecurity);
    Feed(m, hex("00"));
    CHECK(m.failed());
}

// ---- Connect Response -----------------------------------------------------

RTSC_TEST(machine_connect_response_emits_erect_domain_then_attach_user) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    const auto step = Feed(m, hex(kConnectResponseHex));

    CHECK(!m.failed());
    CHECK_EQ(m.state().server_result, 0u);
    CHECK(m.state().phase == ConnectPhase::kAwaitAttachUser);
    // 12-byte Erect Domain Request followed by 8-byte Attach User Request.
    CHECK_EQ(step.output.size(), static_cast<size_t>(20));
    CHECK_EQ(step.output[7], static_cast<uint8_t>(0x04));   // erect domain
    CHECK_EQ(step.output[19], static_cast<uint8_t>(0x28));  // attach user
}

RTSC_TEST(machine_connect_response_extracts_channel_ids) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));

    CHECK_EQ(m.state().io_channel_id, static_cast<uint16_t>(1003));
    CHECK_EQ(m.state().message_channel_id, static_cast<uint16_t>(0));
    CHECK_EQ(m.state().static_virtual_channels.size(), static_cast<size_t>(3));
    CHECK_EQ(m.state().static_virtual_channels[0], static_cast<uint16_t>(1004));
    CHECK_EQ(m.state().static_virtual_channels[1], static_cast<uint16_t>(1005));
    CHECK_EQ(m.state().static_virtual_channels[2], static_cast<uint16_t>(1006));
}

RTSC_TEST(machine_connect_response_rejects_malformed_pdu) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex("03 00 00 04 02 f0 80 7f"));
    CHECK(m.failed());
}

// ---- Attach User ----------------------------------------------------------

RTSC_TEST(machine_attach_user_confirm_starts_join_sequence) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    const auto step = Feed(m, hex(kAttachUserConfirm));

    CHECK(!m.failed());
    CHECK_EQ(m.state().user_channel_id, static_cast<uint16_t>(1007));
    CHECK(m.state().phase == ConnectPhase::kAwaitChannelJoin);
    // First join is the user channel.
    CHECK_EQ(step.output.size(), static_cast<size_t>(12));
    CHECK_EQ(step.output[7], static_cast<uint8_t>(0x38));
    CHECK_EQ(step.output[10], static_cast<uint8_t>(0x03));
    CHECK_EQ(step.output[11], static_cast<uint8_t>(0xEF));
}

RTSC_TEST(machine_attach_user_confirm_rejects_failure_result) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    // result = rt-unspecified-failure (14), no initiator.
    Feed(m, hex("03 00 00 09 02 f0 80 2d c0"));
    CHECK(m.failed());
}

RTSC_TEST(machine_join_queue_orders_user_io_then_virtual_channels) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));

    const auto& q = m.state().join_queue;
    CHECK_EQ(q.size(), static_cast<size_t>(5));  // user, io, 3 VCs (no message channel)
    CHECK_EQ(q[0], static_cast<uint16_t>(1007));
    CHECK_EQ(q[1], static_cast<uint16_t>(1003));
    CHECK_EQ(q[2], static_cast<uint16_t>(1004));
    CHECK_EQ(q[3], static_cast<uint16_t>(1005));
    CHECK_EQ(q[4], static_cast<uint16_t>(1006));
}

// ---- Channel Join ---------------------------------------------------------

RTSC_TEST(machine_channel_join_advances_through_all_channels) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));

    const char* confirms[] = {kJoinConfirmUser, kJoinConfirmIo, kJoinConfirmVc1,
                              kJoinConfirmVc2, kJoinConfirmVc3};
    for (int i = 0; i < 5; ++i) {
        const auto step = Feed(m, hex(confirms[i]));
        CHECK(!m.failed());
        if (i < 4) {
            CHECK(m.state().phase == ConnectPhase::kAwaitChannelJoin);
            CHECK(!step.output.empty());
        }
    }
    // After the last confirm the machine emits Client Info.
    CHECK(!m.failed());
    CHECK(m.done());
    CHECK(m.state().phase == ConnectPhase::kAwaitClientInfoAck);
}

RTSC_TEST(machine_channel_join_rejects_mismatched_channel_id) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));
    // Confirm for 1003 while the outstanding request was for 1007.
    Feed(m, hex(kJoinConfirmIo));
    CHECK(m.failed());
}

RTSC_TEST(machine_channel_join_rejects_failure_result) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));
    // result = 14, channelId present (0x3F 0xC0).
    Feed(m, hex("03 00 00 0f 02 f0 80 3f c0 00 06 03 ef 03 ef"));
    CHECK(m.failed());
}

RTSC_TEST(machine_channel_join_rejects_missing_optional_channel_id) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));
    // channelId absent (0x3C).
    Feed(m, hex("03 00 00 0d 02 f0 80 3c 00 00 06 03 ef"));
    CHECK(m.failed());
}

// ---- Client Info ----------------------------------------------------------

RTSC_TEST(machine_emits_client_info_after_last_join) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));

    const char* confirms[] = {kJoinConfirmUser, kJoinConfirmIo, kJoinConfirmVc1,
                              kJoinConfirmVc2, kJoinConfirmVc3};
    ConnectStep last;
    for (int i = 0; i < 5; ++i) {
        last = Feed(m, hex(confirms[i]));
    }
    CHECK(!last.output.empty());
    // MCS Send Data Request: choice 25 (0x64) + initiator 1007 + channel 1003.
    CHECK_EQ(last.output[7], static_cast<uint8_t>(0x64));
    CHECK_EQ(last.output[8], static_cast<uint8_t>(0x00));
    CHECK_EQ(last.output[9], static_cast<uint8_t>(0x06));
    CHECK_EQ(last.output[10], static_cast<uint8_t>(0x03));
    CHECK_EQ(last.output[11], static_cast<uint8_t>(0xEB));
    CHECK_EQ(last.output[12], static_cast<uint8_t>(0x70));  // priority/segmentation
}

RTSC_TEST(machine_client_info_payload_decodes_back) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));
    const char* confirms[] = {kJoinConfirmUser, kJoinConfirmIo, kJoinConfirmVc1,
                              kJoinConfirmVc2, kJoinConfirmVc3};
    ConnectStep last;
    for (int i = 0; i < 5; ++i) last = Feed(m, hex(confirms[i]));

    McsSendData sd;
    CHECK(McsSendData::parse(last.output.data(), last.output.size(), sd) == Status::Ok);
    CHECK_EQ(sd.initiator, static_cast<uint16_t>(1007));
    CHECK_EQ(sd.channel_id, static_cast<uint16_t>(1003));

    ClientInfoPdu pdu;
    CHECK(ClientInfoPdu::parse(sd.user_data.data(), sd.user_data.size(), pdu) ==
          Status::Ok);
    CHECK(pdu.info.domain == "NTDEV");
    CHECK(pdu.info.user_name == "eltons");
    CHECK(pdu.info.unicode());
}

RTSC_TEST(machine_client_info_sets_expected_flags) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));
    const char* confirms[] = {kJoinConfirmUser, kJoinConfirmIo, kJoinConfirmVc1,
                              kJoinConfirmVc2, kJoinConfirmVc3};
    ConnectStep last;
    for (int i = 0; i < 5; ++i) last = Feed(m, hex(confirms[i]));

    McsSendData sd;
    McsSendData::parse(last.output.data(), last.output.size(), sd);
    ClientInfoPdu pdu;
    ClientInfoPdu::parse(sd.user_data.data(), sd.user_data.size(), pdu);
    CHECK((pdu.info.flags & info::kUnicode) != 0);
    CHECK((pdu.info.flags & info::kMouse) != 0);
    CHECK((pdu.info.flags & info::kDisableCtrlAltDel) != 0);
    CHECK((pdu.info.flags & info::kAutoLogon) == 0);
}

RTSC_TEST(machine_client_info_autologon_flag_follows_credentials) {
    ConnectMachine::Credentials cr = MakeCredentials();
    cr.password = "pw";
    cr.autologon = true;
    ConnectMachine m(MakeConfig(), cr);
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));
    const char* confirms[] = {kJoinConfirmUser, kJoinConfirmIo, kJoinConfirmVc1,
                              kJoinConfirmVc2, kJoinConfirmVc3};
    ConnectStep last;
    for (int i = 0; i < 5; ++i) last = Feed(m, hex(confirms[i]));

    McsSendData sd;
    McsSendData::parse(last.output.data(), last.output.size(), sd);
    ClientInfoPdu pdu;
    ClientInfoPdu::parse(sd.user_data.data(), sd.user_data.size(), pdu);
    CHECK((pdu.info.flags & info::kAutoLogon) != 0);
    CHECK(pdu.info.password == "pw");
}

RTSC_TEST(machine_client_info_requests_true_image_quality) {
    // mstsc requests ClearType font smoothing and DWM desktop composition via
    // the Client Info performanceFlags; without them the server renders aliased
    // text and a non-composited desktop — the "screenshot" look.
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));
    const char* confirms[] = {kJoinConfirmUser, kJoinConfirmIo, kJoinConfirmVc1,
                              kJoinConfirmVc2, kJoinConfirmVc3};
    ConnectStep last;
    for (int i = 0; i < 5; ++i) last = Feed(m, hex(confirms[i]));

    McsSendData sd;
    CHECK(McsSendData::parse(last.output.data(), last.output.size(), sd) ==
          Status::Ok);
    ClientInfoPdu pdu;
    CHECK(ClientInfoPdu::parse(sd.user_data.data(), sd.user_data.size(), pdu) ==
          Status::Ok);
    CHECK(pdu.info.has_extended_info);
    CHECK(pdu.info.extended_info.has_performance_flags);
    CHECK_EQ(pdu.info.extended_info.performance_flags,
             static_cast<uint32_t>(perf::kEnableFontSmoothing |
                                   perf::kEnableDesktopComposition));
    CHECK((pdu.info.flags & info::kEnableWindowsKey) != 0);
}

RTSC_TEST(machine_client_info_carries_auto_reconnect_cookie) {
    ConnectMachine::Config cfg = MakeConfig();
    cfg.auto_reconnect_cookie.resize(ArcCsPrivatePacket::kWireSize);
    for (size_t i = 0; i < cfg.auto_reconnect_cookie.size(); ++i) {
        cfg.auto_reconnect_cookie[i] = static_cast<uint8_t>(0x40 + i);
    }
    ConnectMachine m(cfg, MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));
    const char* confirms[] = {kJoinConfirmUser, kJoinConfirmIo, kJoinConfirmVc1,
                              kJoinConfirmVc2, kJoinConfirmVc3};
    ConnectStep last;
    for (int i = 0; i < 5; ++i) last = Feed(m, hex(confirms[i]));

    McsSendData sd;
    CHECK(McsSendData::parse(last.output.data(), last.output.size(), sd) ==
          Status::Ok);
    ClientInfoPdu pdu;
    CHECK(ClientInfoPdu::parse(sd.user_data.data(), sd.user_data.size(), pdu) ==
          Status::Ok);
    CHECK(pdu.info.extended_info.has_auto_reconnect);
    CHECK(pdu.info.extended_info.auto_reconnect_cookie.bytes ==
          cfg.auto_reconnect_cookie);

    // A wrong-sized cookie is not emitted at all (the field must be exactly
    // ARC_CS_PRIVATE_PACKET::kWireSize bytes).
    ConnectMachine::Config bad = MakeConfig();
    bad.auto_reconnect_cookie.assign(ArcCsPrivatePacket::kWireSize - 1, 0x11);
    ConnectMachine m2(bad, MakeCredentials());
    m2.Start();
    Feed(m2, hex(kCcfRdp));
    Feed(m2, hex(kConnectResponseHex));
    Feed(m2, hex(kAttachUserConfirm));
    for (int i = 0; i < 5; ++i) last = Feed(m2, hex(confirms[i]));
    CHECK(McsSendData::parse(last.output.data(), last.output.size(), sd) ==
          Status::Ok);
    ClientInfoPdu pdu2;  // parse does not clear an existing object
    CHECK(ClientInfoPdu::parse(sd.user_data.data(), sd.user_data.size(), pdu2) ==
          Status::Ok);
    CHECK(!pdu2.info.extended_info.has_auto_reconnect);
}

RTSC_TEST(machine_message_channel_joined_when_server_assigns_one) {
    // Append an SC_MCS_MSGCHANNEL (0x0C04) block assigning channel 1008 to the
    // official 337-byte Connect Response, then verify the join queue inserts it
    // between the I/O channel and the static virtual channels.
    //
    // Growing the PDU requires fixing all four enclosing length fields:
    //   TPKT length            @2   (BE16)
    //   T.125 BER length       @9   82 01 45  (0x145)
    //   userData OCTET STRING  @46  04 82 01 1F (0x11F)
    //   GCC userData PER len   @71  81 08     (0x108)
    auto rsp = hex(kConnectResponseHex);
    const size_t kBlockSize = 6;  // type(2) + length(2) + MCSChannelID(2)

    const uint16_t kMsgType = 0x0C04;
    const uint16_t kMsgChannel = 1008;
    const size_t old_size = rsp.size();
    const size_t new_size = old_size + kBlockSize;

    rsp.resize(new_size);
    rsp[new_size - 6] = static_cast<uint8_t>(kMsgType & 0xFF);
    rsp[new_size - 5] = static_cast<uint8_t>(kMsgType >> 8);
    rsp[new_size - 4] = static_cast<uint8_t>(kBlockSize & 0xFF);
    rsp[new_size - 3] = static_cast<uint8_t>(kBlockSize >> 8);
    rsp[new_size - 2] = static_cast<uint8_t>(kMsgChannel & 0xFF);
    rsp[new_size - 1] = static_cast<uint8_t>(kMsgChannel >> 8);

    const size_t tpkt_len = new_size;                 // 337 + 6 = 343
    const size_t ber_len = 0x145 + kBlockSize;        // 331
    const size_t octet_len = 0x11F + kBlockSize;      // 293
    const size_t gcc_len = 0x108 + kBlockSize;        // 270

    rsp[2] = static_cast<uint8_t>(tpkt_len >> 8);
    rsp[3] = static_cast<uint8_t>(tpkt_len & 0xFF);
    rsp[10] = static_cast<uint8_t>(ber_len >> 8);
    rsp[11] = static_cast<uint8_t>(ber_len & 0xFF);
    rsp[48] = static_cast<uint8_t>(octet_len >> 8);
    rsp[49] = static_cast<uint8_t>(octet_len & 0xFF);
    rsp[71] = static_cast<uint8_t>(0x80 | (gcc_len >> 8));
    rsp[72] = static_cast<uint8_t>(gcc_len & 0xFF);

    McsConnectResponse sanity;
    CHECK(McsConnectResponse::parse(rsp.data(), rsp.size(), sanity) == Status::Ok);

    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, rsp);
    CHECK(!m.failed());
    CHECK_EQ(m.state().message_channel_id, static_cast<uint16_t>(1008));
    Feed(m, hex(kAttachUserConfirm));
    CHECK(!m.failed());

    const auto& q = m.state().join_queue;
    CHECK_EQ(q.size(), static_cast<size_t>(6));  // user, io, msg, 3 VCs
    CHECK_EQ(q[0], static_cast<uint16_t>(1007));
    CHECK_EQ(q[1], static_cast<uint16_t>(1003));
    CHECK_EQ(q[2], static_cast<uint16_t>(1008));
    CHECK_EQ(q[3], static_cast<uint16_t>(1004));
}

RTSC_TEST(machine_client_core_declares_spec_color_depth_combo) {
    // [MS-RDPBCGR] 2.2.1.3.2: highColorDepth has no value 32 (valid: 4, 8, 15,
    // 16, 24). The mstsc-style 32bpp session combination is highColorDepth=24 +
    // RNS_UD_CS_WANT_32BPP_SESSION (0x0002) + supportedColorDepths = 24bpp |
    // 32bpp (0x0009): a real Windows server answers it with a 32bpp session
    // whose compressed bitmaps are RDP6-planar (dual-audit ruling; the planar
    // decoder now covers 32bpp, and the real-machine regression confirmed the
    // rendered session).
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    const auto step = Feed(m, hex(kCcfRdp));
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(step.output.data(), step.output.size(), ci) ==
          Status::Ok);

    // Walk the GCC payload to the user data blocks (same layout walk as
    // test_multimon: 7-byte T.124 identifier, PER length, CCRQ header, H.221
    // key, PER length, then the blocks).
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
    CHECK(core->payload.size() >= 142);
    const auto rd16 = [&core](size_t o) {
        return static_cast<uint16_t>(core->payload[o] |
                                     (core->payload[o + 1] << 8));
    };
    CHECK_EQ(rd16(136), static_cast<uint16_t>(24));      // highColorDepth
    CHECK_EQ(rd16(138), static_cast<uint16_t>(0x0009));  // 24bpp | 32bpp
    CHECK((rd16(140) & 0x0002) != 0);                    // WANT_32BPP_SESSION
    CHECK((rd16(140) & 0x0001) != 0);                    // ERRINFO PDU kept
}

// ---- mstsc /admin: Client Cluster Data ------------------------------------

namespace {

// Walks the GCC payload to the user data blocks, same layout walk used by the
// color-depth test above.
bool ParseConnectInitialUserData(const ConnectStep& step, GccUserData& ud) {
    McsConnectInitial ci;
    if (McsConnectInitial::parse(step.output.data(), step.output.size(), ci) !=
        Status::Ok) {
        return false;
    }
    const auto& gcc = ci.gcc_conference_create_request;
    if (gcc.size() <= 21) return false;
    size_t off = 7;
    off += (gcc[off] & 0x80) == 0 ? 1 : 2;
    off += 8 + 4;
    off += (gcc[off] & 0x80) == 0 ? 1 : 2;
    return GccUserData::parse(gcc.data() + off, gcc.size() - off, ud) ==
           Status::Ok;
}

}  // namespace

RTSC_TEST(machine_admin_session_emits_console_cluster_block) {
    ConnectMachine::Config cfg = MakeConfig();
    cfg.admin_session = true;
    ConnectMachine m(cfg, MakeCredentials());
    m.Start();
    const auto step = Feed(m, hex(kCcfRdp));

    GccUserData ud;
    CHECK(ParseConnectInitialUserData(step, ud));
    const auto* cluster = ud.find(0xC004);
    CHECK(cluster != nullptr);
    if (cluster != nullptr) {
        CHECK_EQ(cluster->payload.size(), static_cast<size_t>(8));
        const auto rd32 = [&cluster](size_t o) {
            return static_cast<uint32_t>(cluster->payload[o]) |
                   (static_cast<uint32_t>(cluster->payload[o + 1]) << 8) |
                   (static_cast<uint32_t>(cluster->payload[o + 2]) << 16) |
                   (static_cast<uint32_t>(cluster->payload[o + 3]) << 24);
        };
        CHECK_EQ(rd32(0), static_cast<uint32_t>(0x00000002));
        CHECK_EQ(rd32(4), static_cast<uint32_t>(0));
    }
}

RTSC_TEST(machine_normal_session_omits_cluster_block) {
    ConnectMachine m(MakeConfig(), MakeCredentials());
    m.Start();
    const auto step = Feed(m, hex(kCcfRdp));

    GccUserData ud;
    CHECK(ParseConnectInitialUserData(step, ud));
    CHECK(ud.find(0xC004) == nullptr);
}

// ---- Color depth selection ------------------------------------------------

RTSC_TEST(machine_apply_color_depth_accepts_supported_values) {
    struct Case {
        int bpp;
        uint16_t high;
        uint16_t supported;
        bool want32;
    };
    const Case cases[] = {
        {4, 0x0004, 0x0000, false},
        {8, 0x0008, 0x0000, false},
        {15, 0x000F, 0x0004, false},
        {16, 0x0010, 0x0002, false},
        {24, 0x0018, 0x0001, false},
        {32, 0x0018, 0x0009, true},
    };
    for (const Case& c : cases) {
        uint16_t high = 0xFFFF;
        uint16_t supported = 0xFFFF;
        uint16_t flags = 0x0001;  // ERRINFO must be preserved
        CHECK(ApplyClientColorDepth(c.bpp, high, supported, flags));
        CHECK_EQ(high, c.high);
        CHECK_EQ(supported, c.supported);
        CHECK_EQ((flags & 0x0002) != 0, c.want32);
        CHECK((flags & 0x0001) != 0);
    }
}

RTSC_TEST(machine_apply_color_depth_rejects_unsupported_values) {
    const int bad[] = {0, 1, 7, 10, 20, 25, 31, 33, 64, -1};
    for (int bpp : bad) {
        uint16_t high = 0x1234;
        uint16_t supported = 0x5678;
        uint16_t flags = 0x0003;
        CHECK(!ApplyClientColorDepth(bpp, high, supported, flags));
        // Fail-closed: the outputs must be untouched.
        CHECK_EQ(high, static_cast<uint16_t>(0x1234));
        CHECK_EQ(supported, static_cast<uint16_t>(0x5678));
        CHECK_EQ(flags, static_cast<uint16_t>(0x0003));
    }
}

RTSC_TEST(machine_client_core_uses_configured_16bpp) {
    ConnectMachine::Config cfg = MakeConfig();
    CHECK(ApplyClientColorDepth(16, cfg.high_color_depth,
                                cfg.supported_color_depths,
                                cfg.early_capability_flags));
    ConnectMachine m(cfg, MakeCredentials());
    m.Start();
    const auto step = Feed(m, hex(kCcfRdp));
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(step.output.data(), step.output.size(), ci) ==
          Status::Ok);
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
    CHECK(core->payload.size() >= 142);
    const auto rd16 = [&core](size_t o) {
        return static_cast<uint16_t>(core->payload[o] |
                                     (core->payload[o + 1] << 8));
    };
    CHECK_EQ(rd16(136), static_cast<uint16_t>(0x0010));  // 16bpp
    CHECK_EQ(rd16(138), static_cast<uint16_t>(0x0002));  // 16bpp support
    CHECK((rd16(140) & 0x0002) == 0);                    // no WANT_32BPP
    CHECK((rd16(140) & 0x0001) != 0);                    // ERRINFO kept
}

// ---- Guard rails ----------------------------------------------------------

RTSC_TEST(machine_standard_rdp_with_encryption_emits_plaintext_client_info) {
    // The connection machine itself never encrypts: Standard RDP Security's
    // Security Exchange and the RC4 data plane live in the security layer.
    // With encryption negotiated it must therefore still emit the plaintext
    // Client Info PDU (SEC_INFO_PKT only) instead of failing.
    ConnectMachine::Config cfg = MakeConfig();
    cfg.encryption_methods = 0x0000001B;
    ConnectMachine m(cfg, MakeCredentials());
    m.Start();
    Feed(m, hex(kCcfRdp));
    Feed(m, hex(kConnectResponseHex));
    Feed(m, hex(kAttachUserConfirm));
    const char* confirms[] = {kJoinConfirmUser, kJoinConfirmIo, kJoinConfirmVc1,
                              kJoinConfirmVc2, kJoinConfirmVc3};
    ConnectStep last;
    for (int i = 0; i < 5; ++i) last = Feed(m, hex(confirms[i]));
    CHECK(!m.failed());
    CHECK(m.done());
    CHECK(!last.output.empty());

    McsSendData sd;
    CHECK(McsSendData::parse(last.output.data(), last.output.size(), sd) ==
          Status::Ok);
    CHECK(sd.user_data.size() >= 4);
    const uint16_t flags = static_cast<uint16_t>(sd.user_data[0]) |
                           (static_cast<uint16_t>(sd.user_data[1]) << 8);
    CHECK((flags & sec::kSecInfoPkt) != 0);
    CHECK((flags & sec::kSecEncrypt) == 0);  // Client Info is sent in the clear
}

RTSC_TEST(machine_phase_names_are_stable) {
    CHECK(std::string(to_string(ConnectPhase::kAwaitNegotiation)) ==
          "await-negotiation");
    CHECK(std::string(to_string(ConnectPhase::kAwaitExternalSecurity)) ==
          "await-external-security");
    CHECK(std::string(to_string(ConnectPhase::kFailed)) == "failed");
}

int main() { return rtsc::test::run_all("rtsc_connect_machine_tests"); }
