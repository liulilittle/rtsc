// RAIL ([MS-RDPERP]) client integration tests.
//
// Covers the "rail" static virtual channel handler (reassembly + order
// dispatch), the RAIL capability set advertised in Confirm Active, the
// INFO_RAIL / channel_names advertisement in the Client Info PDU, and the
// Client-side registration that routes the server's rail PDUs to RailClient.

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "rtsc/channel/rail_client.h"
#include "rtsc/client/client.h"
#include "rtsc/credssp/ntlm.h"
#include "rtsc/credssp/ts_request.h"
#include "rtsc/crypto/hash.h"
#include "rtsc/proto/capabilities.h"
#include "rtsc/proto/client_info.h"
#include "rtsc/proto/connect_machine.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/rail.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/proto/share.h"
#include "rtsc/security/connection_driver.h"
#include "rtsc/security/security_layer.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;
using rtsc::credssp::Bytes;

namespace {

// Feeds a complete RAIL message to the handler as a chunked channel message.
void FeedRail(rtsc::channel::RailClient& c, const std::vector<uint8_t>& message) {
    const auto chunks = FragmentChannelMessage(message, 4);  // force chunking
    for (const auto& chunk : chunks) c.OnChannelData(chunk.data(), chunk.size());
}

// ---- full client harness (X.224 -> TLS -> CredSSP -> MCS -> finalization) ---

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

class ScriptedTls final : public rtsc::tls::TlsTransport {
 public:
    rtsc::tls::Error Handshake(const uint8_t* in, size_t in_size,
                               size_t& consumed,
                               std::vector<uint8_t>& out) override {
        (void)in;
        out.clear();
        consumed = in_size;
        ++rounds_;
        if (rounds_ == 1) {
            out = {0x16, 0x03, 0x01, 0x00, 0x05, 0x01};
            return rtsc::tls::Error{};
        }
        handshake_complete_ = true;
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error Send(const uint8_t* plaintext, size_t size,
                          size_t& consumed, std::vector<uint8_t>& out) override {
        out.assign(plaintext, plaintext + size);
        consumed = size;
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error Receive(const uint8_t* ciphertext, size_t size,
                             std::vector<uint8_t>& plaintext,
                             size_t max_out) override {
        (void)max_out;
        if (ciphertext != nullptr && size > 0) {
            plaintext.insert(plaintext.end(), ciphertext, ciphertext + size);
        }
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error PeerSubjectPublicKeyInfo(
        std::vector<uint8_t>& out) const override {
        out = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error PeerSubjectPublicKey(
        std::vector<uint8_t>& out) const override {
        out = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error PeerCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error LocalCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error LocalSubjectPublicKey(
        std::vector<uint8_t>& out) const override {
        out = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error negotiated(rtsc::tls::NegotiatedInfo& out) const override {
        out = rtsc::tls::NegotiatedInfo{};
        out.tls_version = 0x0304;
        return rtsc::tls::Error{};
    }
    rtsc::tls::RecordSizes record_sizes() const override {
        rtsc::tls::RecordSizes s;
        s.header = 5;
        s.max_plaintext = 16384;
        s.overhead_upper = 44;
        s.overhead_actual = 17;
        s.block_size = 16;
        return s;
    }
    rtsc::tls::Error Shutdown(std::vector<uint8_t>& out) override {
        out.clear();
        return rtsc::tls::Error{};
    }
    bool handshake_complete() const noexcept override {
        return handshake_complete_;
    }
    bool closed() const noexcept override { return false; }
    size_t buffered_input() const noexcept override { return 0; }
    const rtsc::tls::Error& last_error() const noexcept override {
        return last_error_;
    }
    const char* backend_name() const noexcept override { return "scripted"; }

 private:
    int rounds_ = 0;
    bool handshake_complete_ = false;
    rtsc::tls::Error last_error_{};
};

Bytes ServerChallengeMessage() {
    rtsc::credssp::ChallengeMessage m;
    using rtsc::credssp::AvId;
    m.flags = rtsc::credssp::ntlm_flag::kUnicode |
              rtsc::credssp::ntlm_flag::kRequestTarget |
              rtsc::credssp::ntlm_flag::kSign | rtsc::credssp::ntlm_flag::kSeal |
              rtsc::credssp::ntlm_flag::kNtlm |
              rtsc::credssp::ntlm_flag::kAlwaysSign |
              rtsc::credssp::ntlm_flag::kExtendedSessionSecurity |
              rtsc::credssp::ntlm_flag::kTargetInfo |
              rtsc::credssp::ntlm_flag::kVersion | rtsc::credssp::ntlm_flag::k128 |
              rtsc::credssp::ntlm_flag::kKeyExch | rtsc::credssp::ntlm_flag::k56 |
              rtsc::credssp::ntlm_flag::kTargetTypeServer;
    m.server_challenge = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    m.target_name = "Server";
    rtsc::credssp::AvPair domain;
    domain.id = AvId::kNbDomainName;
    domain.value = ::rtsc::crypto::Utf16Le("Domain");
    rtsc::credssp::AvPair server;
    server.id = AvId::kNbComputerName;
    server.value = ::rtsc::crypto::Utf16Le("Server");
    rtsc::credssp::AvPair ts;
    ts.id = AvId::kTimestamp;
    ts.value = Bytes(8, 0);
    m.av_pairs = {domain, server, ts};
    Bytes out;
    m.Encode(out);
    return out;
}

rtsc::security::Config MakeConfig() {
    rtsc::security::Config cfg;
    cfg.tls_config.peer_host = "127.0.0.1";
    cfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    cfg.credssp_version = 6;
    cfg.credentials.domain = "Domain";
    cfg.credentials.user = "User";
    cfg.credentials.password = "Password";
    return cfg;
}

const char* kCcfHybridEx =
    "03 00 00 13 0e d0 00 00 12 34 00 02 0f 08 00 08 00 00 00";

// [MS-RDPBCGR] 4.1.4: the 337-byte Connect Response (3 static VCs).
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

const char* kAttachUserConfirm = "03 00 00 0b 02 f0 80 2e 00 00 06";
const char* kJoinConfirmUser = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ef 03 ef";
const char* kJoinConfirmIo = "03 00 00 0f 02 f0 80 3e 00 00 06 03 eb 03 eb";
const char* kJoinConfirmVc1 = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ec 03 ec";
const char* kJoinConfirmVc2 = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ed 03 ed";
const char* kJoinConfirmVc3 = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ee 03 ee";
// The 4th static virtual channel (rail) would be assigned 1007 (0x03EF).
const char* kJoinConfirmVc4 = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ef 03 ef";

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

std::vector<uint8_t> ServerIndication(const std::vector<uint8_t>& payload) {
    return McsSendData::build_indication(0x03EA, 0x03EF, payload);
}

std::vector<uint8_t> ServerDataPdu(ShareDataPduType type,
                                   const std::vector<uint8_t>& payload) {
    ByteWriter w;
    w.u16le(static_cast<uint16_t>(18 + payload.size()));
    w.u16le(0x0017);
    w.u16le(0x03EA);
    w.u32le(0x000103EA);
    w.u8(0);
    w.u8(0x01);
    w.u16le(static_cast<uint16_t>(payload.size()));
    w.u8(static_cast<uint8_t>(type));
    w.u8(0);
    w.u16le(0);
    if (!payload.empty()) w.bytes(payload.data(), payload.size());
    return ServerIndication(w.take());
}

std::vector<uint8_t> ServerLicensePdu(const std::vector<uint8_t>& payload) {
    ByteWriter sh;
    sh.u16le(static_cast<uint16_t>(kSecLicensePkt));
    sh.u16le(0);
    std::vector<uint8_t> ud = sh.take();
    ud.insert(ud.end(), payload.begin(), payload.end());
    return ServerIndication(ud);
}

// Adds a 4th static virtual channel (id 1007) to the official Connect
// Response. The SC_NETWORK block grows from 3 to 4 channel ids: the channel
// count byte changes 3 -> 4 and the 2-byte pad becomes the new id. The block
// length (16) and every enclosing length are unchanged.
std::vector<uint8_t> ConnectResponseWithFourChannels() {
    auto rsp = Hex(kConnectResponseHex);
    const uint8_t kPattern[] = {0x03, 0x0c, 0x10, 0x00,
                                0xeb, 0x03, 0x03, 0x00};
    for (size_t i = 0; i + sizeof(kPattern) <= rsp.size(); ++i) {
        if (std::memcmp(rsp.data() + i, kPattern, sizeof(kPattern)) == 0) {
            rsp[i + 6] = 0x04;   // channel count: 3 -> 4
            rsp[i + 14] = 0xef;  // pad -> channel id 1007 low
            rsp[i + 15] = 0x03;  // channel id 1007 high
            return rsp;
        }
    }
    return rsp;
}

rtsc::security::ConnectionDriver MakeDriver(bool with_rail) {
    ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=tester";
    mcfg.requested_protocols = kProtocolSsl | kProtocolHybrid |
                               kProtocolHybridEx;
    mcfg.client_name = "RTSC";
    mcfg.channel_names = with_rail ? std::vector<std::string>{"rdpdr", "cliprdr",
                                                             "rdpsnd", "rail"}
                                   : std::vector<std::string>{"rdpdr", "cliprdr",
                                                             "rdpsnd"};
    mcfg.encryption_methods = 0;

    ConnectMachine::Credentials creds;
    creds.domain = "Domain";
    creds.user_name = "User";
    creds.password = "Password";

    rtsc::security::ConnectionDriver driver(mcfg, creds, MakeConfig());
    driver.SetTlsTransportForTest(std::make_unique<ScriptedTls>());
    return driver;
}

// Drives the driver to the active session. `four_channels` selects the Connect
// Response with a 4th static virtual channel and the matching join confirms.
bool DriveToActive(rtsc::security::ConnectionDriver& driver,
                   bool four_channels) {
    driver.Start();
    const auto ccf = Hex(kCcfHybridEx);
    auto step = driver.OnData(ccf.data(), ccf.size());
    if (step.failed) return false;

    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    step = driver.OnData(server_hello, sizeof(server_hello));
    if (step.failed) return false;

    rtsc::credssp::TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    if (!challenge.Encode(ch_der).ok()) return false;
    step = driver.OnData(ch_der.data(), ch_der.size());
    if (step.failed) return false;

    Bytes echo = driver.security()->credssp_for_test().MakeServerEchoForTest();
    rtsc::credssp::TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    if (!step4.Encode(step4_der).ok()) return false;
    step = driver.OnData(step4_der.data(), step4_der.size());
    if (step.failed) return false;

    const uint8_t euar[] = {0x00, 0x00, 0x00, 0x00};
    step = driver.OnData(euar, sizeof(euar));
    if (step.failed) return false;

    const auto cr = four_channels ? ConnectResponseWithFourChannels()
                                  : Hex(kConnectResponseHex);
    step = driver.OnData(cr.data(), cr.size());
    if (step.failed) return false;

    auto auc = Hex(kAttachUserConfirm);
    step = driver.OnData(auc.data(), auc.size());
    if (step.failed) return false;

    std::vector<std::string> confirms = {kJoinConfirmUser, kJoinConfirmIo,
                                         kJoinConfirmVc1, kJoinConfirmVc2,
                                         kJoinConfirmVc3};
    if (four_channels) confirms.push_back(kJoinConfirmVc4);
    for (const auto& c : confirms) {
        auto jc = Hex(c.c_str());
        step = driver.OnData(jc.data(), jc.size());
        if (step.failed) return false;
    }

    LicenseErrorMessage err;
    err.error_code = 0x07;  // STATUS_VALID_CLIENT
    err.state_transition = 0x02;  // ST_NO_TRANSITION
    const auto lp = LicensingPdu::Encode(LicenseMessageType::kErrorAlert,
                                         err.encode());
    auto lwire = ServerLicensePdu(lp);
    step = driver.OnData(lwire.data(), lwire.size());
    if (step.failed) return false;

    auto da = Hex(kDemandActiveHex);
    auto dawire = ServerIndication(da);
    step = driver.OnData(dawire.data(), dawire.size());
    if (step.failed) return false;

    const std::vector<uint8_t> sync = {0x01, 0x00, 0xEA, 0x03};
    auto wire = ServerDataPdu(ShareDataPduType::kSynchronize, sync);
    driver.OnData(wire.data(), wire.size());
    const std::vector<uint8_t> control = {0x04, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00};
    wire = ServerDataPdu(ShareDataPduType::kControl, control);
    driver.OnData(wire.data(), wire.size());
    const std::vector<uint8_t> fontmap = {0x00, 0x00, 0x00, 0x00,
                                          0x03, 0x00, 0x04, 0x00};
    wire = ServerDataPdu(ShareDataPduType::kFontMap, fontmap);
    step = driver.OnData(wire.data(), wire.size());
    return !step.failed && step.active;
}

}  // namespace

// ---- RailClient: reassembly + dispatch ---------------------------------------

RTSC_TEST(rail_client_reassembles_chunked_message_and_dispatches) {
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RailClient rail(
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    unsigned handshake = 0;
    unsigned syscommand = 0;
    rail.SetHandler([&](const RailPdu& pdu) {
        if (pdu.header.order_type == RailHandshake::kOrderType) ++handshake;
        if (pdu.header.order_type == RailSyscommand::kOrderType) ++syscommand;
    });

    std::vector<uint8_t> message = RailHandshake{0x1DB0}.build();
    const std::vector<uint8_t> move = RailWindowMove{5, 0, 0, 320, 240}.build();
    message.insert(message.end(), move.begin(), move.end());
    FeedRail(rail, message);

    CHECK_EQ(rail.pdu_count(), static_cast<unsigned>(2));
    CHECK_EQ(rail.handshake_count(), static_cast<unsigned>(1));
    CHECK_EQ(rail.window_move_count(), static_cast<unsigned>(1));
    CHECK_EQ(handshake, static_cast<unsigned>(1));
    CHECK_EQ(syscommand, static_cast<unsigned>(0));
    CHECK(rail.has_window_move());
    CHECK_EQ(rail.window_move().right, static_cast<int16_t>(320));
    CHECK_EQ(rail.window_move().bottom, static_cast<int16_t>(240));
}

RTSC_TEST(rail_client_tracks_server_window_state) {
    rtsc::channel::RailClient rail([](const std::vector<uint8_t>&) {});
    std::vector<uint8_t> message;
    const std::vector<uint8_t> minmax =
        RailMinMaxInfo{3, 1600, 900, -8, -30, 120, 40, 4096, 4096}.build();
    const std::vector<uint8_t> taskbar =
        RailTaskbarInfo{kRailTaskbarTabRegister, 0x42, 1}.build();
    const std::vector<uint8_t> langbar =
        RailLangbarInfo{kRailLangbarShowNormal | kRailLangbarLabels}.build();
    message.insert(message.end(), minmax.begin(), minmax.end());
    message.insert(message.end(), taskbar.begin(), taskbar.end());
    message.insert(message.end(), langbar.begin(), langbar.end());
    FeedRail(rail, message);

    CHECK_EQ(rail.minmax_info_count(), static_cast<unsigned>(1));
    CHECK(rail.has_minmax_info());
    CHECK_EQ(rail.minmax_info().max_width, static_cast<int16_t>(1600));
    CHECK(rail.has_taskbar_info());
    CHECK_EQ(rail.taskbar_info().window_id_tab, static_cast<uint32_t>(0x42));
    CHECK(rail.has_langbar_info());
    CHECK_EQ(rail.langbar_info().language_bar_status,
             static_cast<uint32_t>(kRailLangbarShowNormal | kRailLangbarLabels));
}

// ---- RailClient: client -> server orders -------------------------------------

RTSC_TEST(rail_client_sends_handshake_and_client_status_on_start) {
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RailClient rail(
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    rail.Start(0x1DB0, kRailClientAllowLocalMoveSize);

    CHECK_EQ(sent.size(), static_cast<size_t>(2));
    CHECK_EQ(sent[0][0], static_cast<uint8_t>(RailHandshake::kOrderType & 0xFF));
    CHECK_EQ(sent[1][0],
             static_cast<uint8_t>(RailClientStatus::kOrderType & 0xFF));
    CHECK_EQ(rail.send_count(), static_cast<unsigned>(2));

    RailHandshake hs;
    CHECK(RailHandshake::parse(sent[0].data(), sent[0].size(), hs) == Status::Ok);
    CHECK_EQ(hs.build_number, static_cast<uint32_t>(0x1DB0));
}

RTSC_TEST(rail_client_sends_exec_and_parses_exec_result) {
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RailClient rail(
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    RailClientExecute exec;
    exec.exe_or_file = u"C:\\Windows\\System32\\notepad.exe";
    exec.working_dir = u"C:\\Windows";
    exec.arguments = u"README.txt";
    CHECK(rail.SendExec(exec));
    CHECK(!sent.empty());
    CHECK_EQ(sent[0][0], static_cast<uint8_t>(RailClientExecute::kOrderType & 0xFF));
    RailClientExecute back;
    CHECK(RailClientExecute::parse(sent[0].data(), sent[0].size(), back) ==
          Status::Ok);
    CHECK(back.exe_or_file == exec.exe_or_file);

    // The server's ExecuteResult is parsed into the handler state.
    const std::vector<uint8_t> result =
        RailExecuteResult{0, kRailExecOk, 0, u"C:\\Windows\\System32\\notepad.exe"}
            .build();
    FeedRail(rail, result);
    CHECK(rail.has_exec_result());
    CHECK_EQ(rail.exec_result().exec_result,
             static_cast<uint16_t>(kRailExecOk));
    CHECK(rail.exec_result().exe_or_file == exec.exe_or_file);
    CHECK_EQ(rail.exec_result_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rail_client_sends_syscommand_and_sysmenu) {
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RailClient rail(
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    CHECK(rail.SendSyscommand(0x1234, kScMinimize));
    CHECK(rail.SendSysmenu(7, -12, 340));

    CHECK(sent.size() >= 2);
    RailSyscommand sc;
    CHECK(RailSyscommand::parse(sent[0].data(), sent[0].size(), sc) == Status::Ok);
    CHECK_EQ(sc.window_id, static_cast<uint32_t>(0x1234));
    CHECK_EQ(sc.command, static_cast<uint16_t>(kScMinimize));
    RailSysmenu sm;
    CHECK(RailSysmenu::parse(sent[1].data(), sent[1].size(), sm) == Status::Ok);
    CHECK_EQ(sm.left, static_cast<int16_t>(-12));
    CHECK_EQ(sm.top, static_cast<int16_t>(340));
}

RTSC_TEST(rail_client_sends_get_app_id_req_and_parses_resp) {
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RailClient rail(
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    CHECK(rail.SendGetAppIdReq(0x20052));
    CHECK(!sent.empty());
    CHECK_EQ(sent[0][0],
             static_cast<uint8_t>(RailGetAppIdReq::kOrderType & 0xFF));
    RailGetAppIdReq req;
    CHECK(RailGetAppIdReq::parse(sent[0].data(), sent[0].size(), req) ==
          Status::Ok);
    CHECK_EQ(req.window_id, static_cast<uint32_t>(0x20052));

    // A server GetAppIdResp (windowId + fixed 512-byte null-terminated UTF-16)
    // is parsed into the handler state.
    ByteWriter body;
    body.u32le(0x20052);
    const std::vector<uint8_t> app = RailUtf16ToLeBytes(u"microsoft.windows.notepad");
    body.bytes(app.data(), app.size());
    for (size_t i = app.size(); i < 512; ++i) body.u8(0);
    const std::vector<uint8_t> resp =
        BuildRailPdu(static_cast<uint16_t>(RailOrderType::kGetAppIdResp),
                     body.take());
    FeedRail(rail, resp);
    CHECK(rail.has_app_id());
    CHECK_EQ(rail.app_id_window(), static_cast<uint32_t>(0x20052));
    CHECK(rail.app_id() == u"microsoft.windows.notepad");
    CHECK_EQ(rail.get_app_id_resp_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rail_client_answers_get_app_id_req_with_resp) {
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RailClient rail(
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    rail.SetAppUserModelId(0x20052, u"microsoft.windows.notepad");

    const std::vector<uint8_t> req = RailGetAppIdReq{0x20052}.build();
    FeedRail(rail, req);
    CHECK_EQ(rail.get_app_id_req_count(), static_cast<unsigned>(1));
    CHECK_EQ(sent.size(), static_cast<size_t>(1));
    CHECK_EQ(sent[0][0],
             static_cast<uint8_t>(RailOrderType::kGetAppIdResp));
    // orderLength = 4 (header) + 4 (windowId) + 520 (ApplicationId) = 528.
    const uint16_t order_length = static_cast<uint16_t>(sent[0][2]) |
                                  (static_cast<uint16_t>(sent[0][3]) << 8);
    CHECK_EQ(order_length, static_cast<uint16_t>(528));
    CHECK_EQ(sent[0].size(), static_cast<size_t>(528));
    const uint32_t wid = static_cast<uint32_t>(sent[0][4]) |
                         (static_cast<uint32_t>(sent[0][5]) << 8) |
                         (static_cast<uint32_t>(sent[0][6]) << 16) |
                         (static_cast<uint32_t>(sent[0][7]) << 24);
    CHECK_EQ(wid, static_cast<uint32_t>(0x20052));
    const std::u16string got =
        rtsc::proto::RailLeBytesToUtf16(sent[0].data() + 8, 520);
    const size_t z = got.find(u'\0');
    const std::u16string trimmed =
        z == std::u16string::npos ? got : got.substr(0, z);
    CHECK(trimmed == u"microsoft.windows.notepad");
}

RTSC_TEST(rail_client_sends_activate_and_langbar) {
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RailClient rail(
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    CHECK(rail.SendActivate(9, true));
    CHECK(rail.SendLangbarInfo(kRailLangbarShowNormal));

    CHECK(sent.size() >= 2);
    CHECK_EQ(sent[0][0],
             static_cast<uint8_t>(RailOrderType::kActivate));
    CHECK_EQ(sent[0][8], static_cast<uint8_t>(1));  // enabled
    RailLangbarInfo lb;
    CHECK(RailLangbarInfo::parse(sent[1].data(), sent[1].size(), lb) == Status::Ok);
    CHECK_EQ(lb.language_bar_status,
             static_cast<uint32_t>(kRailLangbarShowNormal));
}

// ---- RAIL capability set -----------------------------------------------------

RTSC_TEST(rail_capability_set_round_trips) {
    RailCapabilitySet in;
    in.rail_support_level =
        RailCapabilitySet::kLevelSupported |
        RailCapabilitySet::kLevelHandshakeExSupported;
    const CapabilitySet set = in.encode();
    CHECK(set.type == CapabilityType::kRail);
    CHECK_EQ(set.wire_size(), static_cast<size_t>(8));
    CHECK_EQ(set.data.size(), static_cast<size_t>(4));

    RailCapabilitySet out;
    CHECK(RailCapabilitySet::parse(set, out) == Status::Ok);
    CHECK_EQ(out.rail_support_level,
             static_cast<uint32_t>(RailCapabilitySet::kLevelSupported |
                                   RailCapabilitySet::kLevelHandshakeExSupported));
}

RTSC_TEST(default_client_capabilities_advertise_rail) {
    const auto sets = BuildDefaultClientCapabilities(1280, 1024, 0xCA01);
    bool found = false;
    for (const auto& set : sets) {
        if (set.type == CapabilityType::kRail) {
            RailCapabilitySet rail;
            CHECK(RailCapabilitySet::parse(set, rail) == Status::Ok);
            CHECK((rail.rail_support_level &
                   RailCapabilitySet::kLevelSupported) != 0);
            found = true;
        }
    }
    CHECK(found);
}

// ---- ConnectMachine: channel_names + INFO_RAIL -------------------------------

namespace {

const char* kCcfRdp = "03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 00 00 00";

ConnectMachine::Config MakeRailConfig(bool with_rail) {
    ConnectMachine::Config c;
    c.cookie = "Cookie: mstshash=tester";
    c.requested_protocols = kProtocolRdp;
    c.client_build = 3790;
    c.client_name = "RTSC";
    c.channel_names = with_rail ? std::vector<std::string>{"rdpdr", "cliprdr",
                                                          "rdpsnd", "rail"}
                                : std::vector<std::string>{"rdpdr", "cliprdr",
                                                          "rdpsnd"};
    c.encryption_methods = 0;
    return c;
}

ConnectStep FeedMachine(ConnectMachine& m, const std::vector<uint8_t>& bytes) {
    return m.OnData(bytes.data(), bytes.size());
}

// Drives the machine to the Client Info PDU and returns it.
std::vector<uint8_t> ClientInfoBytes(ConnectMachine& m) {
    m.Start();
    FeedMachine(m, Hex(kCcfRdp));
    FeedMachine(m, Hex(kConnectResponseHex));
    FeedMachine(m, Hex(kAttachUserConfirm));
    const char* confirms[] = {kJoinConfirmUser, kJoinConfirmIo, kJoinConfirmVc1,
                              kJoinConfirmVc2, kJoinConfirmVc3};
    ConnectStep last;
    for (int i = 0; i < 5; ++i) last = FeedMachine(m, Hex(confirms[i]));
    return last.output;
}

}  // namespace

RTSC_TEST(connect_machine_advertises_rail_and_sets_info_rail) {
    ConnectMachine m(MakeRailConfig(true), ConnectMachine::Credentials{});
    const auto info = ClientInfoBytes(m);
    CHECK(!info.empty());

    McsSendData sd;
    CHECK(McsSendData::parse(info.data(), info.size(), sd) == Status::Ok);
    ClientInfoPdu pdu;
    CHECK(ClientInfoPdu::parse(sd.user_data.data(), sd.user_data.size(), pdu) ==
          Status::Ok);
    CHECK((pdu.info.flags & info::kRail) != 0);
}

RTSC_TEST(connect_machine_without_rail_leaves_info_rail_clear) {
    ConnectMachine m(MakeRailConfig(false), ConnectMachine::Credentials{});
    const auto info = ClientInfoBytes(m);
    CHECK(!info.empty());

    McsSendData sd;
    CHECK(McsSendData::parse(info.data(), info.size(), sd) == Status::Ok);
    ClientInfoPdu pdu;
    CHECK(ClientInfoPdu::parse(sd.user_data.data(), sd.user_data.size(), pdu) ==
          Status::Ok);
    CHECK((pdu.info.flags & info::kRail) == 0);
}

// ---- Client integration ------------------------------------------------------

RTSC_TEST(client_channel_id_for_name_maps_advertised_channels) {
    auto driver = MakeDriver(true);
    CHECK(DriveToActive(driver, true));

    CHECK_EQ(driver.ChannelIdForName("rdpdr"), static_cast<uint16_t>(1004));
    CHECK_EQ(driver.ChannelIdForName("cliprdr"), static_cast<uint16_t>(1005));
    CHECK_EQ(driver.ChannelIdForName("rdpsnd"), static_cast<uint16_t>(1006));
    CHECK_EQ(driver.ChannelIdForName("rail"), static_cast<uint16_t>(1007));
    CHECK_EQ(driver.ChannelIdForName("nope"), static_cast<uint16_t>(0));
}

RTSC_TEST(client_start_rail_channel_registers_and_dispatches) {
    auto driver = MakeDriver(true);
    rtsc::client::Client client(std::move(driver), 16, 16);
    CHECK(DriveToActive(client.driver(), true));
    CHECK(client.active());

    std::vector<uint16_t> sent_ids;
    std::vector<std::vector<uint8_t>> sent_msgs;
    client.SetRailSender([&](uint16_t id, const std::vector<uint8_t>& m) {
        sent_ids.push_back(id);
        sent_msgs.push_back(m);
        return true;
    });

    unsigned dispatched = 0;
    client.rail().SetHandler(
        [&](const RailPdu&) { ++dispatched; });

    const uint16_t rail_id = client.StartRailChannel(0x1DB0, 0);
    CHECK_EQ(rail_id, static_cast<uint16_t>(1007));
    // Start() emits Handshake + ClientStatus.
    CHECK_EQ(sent_msgs.size(), static_cast<size_t>(2));
    CHECK_EQ(sent_ids.size(), static_cast<size_t>(2));
    CHECK_EQ(sent_ids[0], static_cast<uint16_t>(1007));

    // A chunked rail message on the rail channel reaches the handler.
    std::vector<uint8_t> message = RailHandshake{0x1DB0}.build();
    const std::vector<uint8_t> move =
        RailWindowMove{5, 0, 0, 320, 240}.build();
    message.insert(message.end(), move.begin(), move.end());
    for (const auto& chunk : FragmentChannelMessage(message, 4)) {
        const auto pdu =
            McsSendData::build_indication(0x03EA, rail_id, chunk);
        auto step = client.driver().OnData(pdu.data(), pdu.size());
        CHECK(!step.failed);
    }
    CHECK_EQ(dispatched, static_cast<unsigned>(2));
    CHECK_EQ(client.rail().pdu_count(), static_cast<unsigned>(2));
    CHECK(client.rail().has_window_move());
}

RTSC_TEST(client_without_rail_channel_reports_zero) {
    auto driver = MakeDriver(false);
    rtsc::client::Client client(std::move(driver), 16, 16);
    CHECK(DriveToActive(client.driver(), false));
    client.SetRailSender([](uint16_t, const std::vector<uint8_t>&) {
        return true;
    });
    CHECK_EQ(client.StartRailChannel(0x1DB0, 0), static_cast<uint16_t>(0));
    CHECK_EQ(client.rail().send_count(), static_cast<unsigned>(0));
}

int main() { return ::rtsc::test::run_all("rtsc_rail_client_tests"); }
