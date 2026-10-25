// RDP server: X.224 / MCS / licensing / Demand Active encoding and the
// connection state machine, exercised end to end.
//
// The tests drive the server with a scripted peer that speaks the client half
// of [MS-RDPBCGR] using the project's own encoders/decoders. A green run means
// the server emits the published wire format and reaches the active session.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "rtsc/net/transport.h"
#include "rtsc/proto/bitmap.h"
#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/capabilities.h"
#include "rtsc/proto/client_info.h"
#include "rtsc/proto/connect_machine.h"
#include "rtsc/proto/connection_initiation.h"
#include "rtsc/proto/finalization.h"
#include "rtsc/proto/input.h"
#include "rtsc/proto/licensing.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/output.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/proto/share.h"
#include "rtsc/proto/tpkt.h"
#include "rtsc/server/server.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;
using rtsc::server::RdpServer;
using rtsc::server::ServerConfig;

namespace {

// ---- TPKT frame reader over a blocking transport ---------------------------

class FrameReader {
 public:
    explicit FrameReader(rtsc::net::Transport& t) : t_(t) {}

    bool Read(std::vector<uint8_t>& frame) {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        for (;;) {
            if (buf_.size() >= 2) {
                if (buf_[0] != 0x03 || buf_[1] != 0x00) return false;
                if (buf_.size() >= 4) {
                    const size_t len =
                        (static_cast<size_t>(buf_[2]) << 8) | buf_[3];
                    if (len < 4) return false;
                    if (buf_.size() >= len) {
                        const auto begin = buf_.begin();
                        frame.assign(begin,
                                     begin + static_cast<std::ptrdiff_t>(len));
                        buf_.erase(begin,
                                   begin + static_cast<std::ptrdiff_t>(len));
                        return true;
                    }
                }
            }
            if (std::chrono::steady_clock::now() >= deadline) return false;
            uint8_t tmp[8192];
            const int n = t_.Read(tmp, sizeof(tmp));
            if (n == rtsc::net::kReadTimeout) continue;
            if (n <= 0) return false;
            buf_.insert(buf_.end(), tmp, tmp + static_cast<size_t>(n));
        }
    }

 private:
    rtsc::net::Transport& t_;
    std::vector<uint8_t> buf_;
};

bool WriteAll(rtsc::net::Transport& t, const std::vector<uint8_t>& b) {
    return !b.empty() && t.Write(b.data(), b.size());
}

// ---- Client GCC user data blocks (mirrors connect_machine.cpp) -------------

std::vector<uint8_t> ClientCoreBody(uint16_t w, uint16_t h) {
    ByteWriter body;
    body.u32le(0x00080004);
    body.u16le(w);
    body.u16le(h);
    body.u16le(0xCA01);       // colorDepth
    body.u16le(0xAA03);       // sasSequence
    body.u32le(0x00000409);   // keyboardLayout
    body.u32le(3790);         // clientBuild
    const char name[5] = "RTSC";
    for (int i = 0; i < 16; ++i) {
        body.u16le(i < 4 ? static_cast<uint16_t>(name[i]) : 0);
    }
    body.u32le(4);            // keyboardType
    body.u32le(0);            // keyboardSubType
    body.u32le(12);           // keyboardFunctionKey
    for (int i = 0; i < 32; ++i) body.u16le(0);  // imeFileName
    body.u16le(0xCA01);       // postBeta2ColorDepth
    body.u16le(1);            // clientProductId
    body.u32le(0);            // serialNumber
    body.u16le(24);           // highColorDepth
    body.u16le(0x0007);       // supportedColorDepths
    body.u16le(0x0001);       // earlyCapabilityFlags
    for (int i = 0; i < 32; ++i) body.u16le(0);  // clientDigProductId
    body.u8(0);               // connectionType
    body.u8(0);               // pad1octet
    body.u32le(0);            // serverSelectedProtocol
    return body.take();
}

std::vector<uint8_t> ClientSecurityBody(uint32_t methods) {
    ByteWriter body;
    body.u32le(methods);
    body.u32le(0);
    return body.take();
}

std::vector<uint8_t> ClientNetworkBody() {
    ByteWriter body;
    const char* names[3] = {"rdpdr", "cliprdr", "rdpsnd"};
    body.u32le(3);
    for (const char* n : names) {
        char fixed[8] = {0};
        std::memcpy(fixed, n, std::strlen(n));
        for (char c : fixed) body.u8(static_cast<uint8_t>(c));
        body.u32le(0xC0A00000);
    }
    return body.take();
}

GccUserData ClientBlocks(uint16_t w, uint16_t h, uint32_t methods) {
    GccUserData ud;
    ud.blocks.push_back({0xC001, ClientCoreBody(w, h)});
    ud.blocks.push_back({0xC002, ClientSecurityBody(methods)});
    ud.blocks.push_back({0xC003, ClientNetworkBody()});
    return ud;
}

// ---- Scripted client -------------------------------------------------------

struct HandshakeResult {
    bool reached_active = false;
    uint16_t io_channel = 0;
    uint16_t user_channel = 0;
    uint32_t share_id = 0;
    uint16_t desktop_width = 0;
    uint16_t desktop_height = 0;
    bool license_valid_client = false;
    bool got_bitmap = false;
    uint16_t bitmap_width = 0;
    uint16_t bitmap_height = 0;
    std::vector<uint8_t> bitmap_pixels;
    std::string error;
};

HandshakeResult DriveToActive(uint16_t port, bool send_input = false) {
    HandshakeResult r;
    std::string error;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", port, error);
    if (!transport) {
        r.error = "connect: " + error;
        return r;
    }
    FrameReader reader(*transport);

    // 1. X.224 Connection Request.
    X224ConnectionRequest crq;
    crq.cookie = "Cookie: mstshash=rtsc";
    crq.include_neg_req = true;
    crq.neg_req.requested_protocols = 0;  // PROTOCOL_RDP only
    if (!WriteAll(*transport, crq.encode())) {
        r.error = "x224 write";
        return r;
    }

    std::vector<uint8_t> frame;
    if (!reader.Read(frame)) {
        r.error = "x224 confirm read";
        return r;
    }
    X224ConnectionConfirm ccf;
    if (X224ConnectionConfirm::parse(frame.data(), frame.size(), ccf) != Status::Ok) {
        r.error = "x224 confirm parse";
        return r;
    }
    if (ccf.neg_data.kind != RdpNegData::Kind::kResponse ||
        ccf.neg_data.response.selected_protocol != 0) {
        r.error = "negotiation did not select PROTOCOL_RDP";
        return r;
    }

    // 2. MCS Connect Initial.
    const auto blocks = ClientBlocks(64, 48, 0);
    const auto ci = McsConnectInitial::build(blocks);
    if (!WriteAll(*transport, ci)) {
        r.error = "connect initial write";
        return r;
    }
    if (!reader.Read(frame)) {
        r.error = "connect response read";
        return r;
    }
    McsConnectResponse rsp;
    if (McsConnectResponse::parse(frame.data(), frame.size(), rsp) != Status::Ok) {
        r.error = "connect response parse";
        return r;
    }
    const auto* net = rsp.user_data.find(0x0C03);
    if (net == nullptr || net->payload.size() < 4) {
        r.error = "server network data missing";
        return r;
    }
    r.io_channel = static_cast<uint16_t>(net->payload[0] | (net->payload[1] << 8));

    // 3. Erect Domain + Attach User.
    if (!WriteAll(*transport, McsErectDomainRequest::build())) {
        r.error = "erect domain write";
        return r;
    }
    if (!WriteAll(*transport, McsAttachUserRequest::build())) {
        r.error = "attach user write";
        return r;
    }
    if (!reader.Read(frame)) {
        r.error = "attach user confirm read";
        return r;
    }
    McsAttachUserConfirm auc;
    if (McsAttachUserConfirm::parse(frame.data(), frame.size(), auc) != Status::Ok ||
        auc.result != McsResult::kSuccessful) {
        r.error = "attach user confirm parse";
        return r;
    }
    r.user_channel = auc.initiator;

    // 4. Channel Join (user, I/O, three static VCs).
    const uint16_t join_ids[] = {r.user_channel, r.io_channel, 1004, 1005, 1006};
    for (uint16_t id : join_ids) {
        if (!WriteAll(*transport, McsChannelJoinRequest::build(r.user_channel, id))) {
            r.error = "channel join write";
            return r;
        }
        if (!reader.Read(frame)) {
            r.error = "channel join confirm read";
            return r;
        }
        McsChannelJoinConfirm cjc;
        if (McsChannelJoinConfirm::parse(frame.data(), frame.size(), cjc) != Status::Ok ||
            cjc.result != McsResult::kSuccessful) {
            r.error = "channel join confirm parse";
            return r;
        }
    }

    // 5. Client Info PDU (no encryption: Basic security header only).
    ClientInfoPdu info;
    info.security_flags = 0x0040;  // SEC_INFO_PKT
    info.info.code_page = 0x0409;
    info.info.flags = 0x00000001 | 0x00000010;
    info.info.domain = "NTDEV";
    info.info.user_name = "rtsc";
    info.info.password = "";
    const auto info_user = info.build();
    if (!WriteAll(*transport, McsSendData::build_request(r.user_channel, r.io_channel,
                                                         info_user))) {
        r.error = "client info write";
        return r;
    }

    // 6. Server License Request -> reply -> LICENSE_ERROR_MESSAGE.
    if (!reader.Read(frame)) {
        r.error = "license request read";
        return r;
    }
    McsSendData sd;
    if (McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok ||
        sd.user_data.size() < 4) {
        r.error = "license request framing";
        return r;
    }
    LicensingPdu lic;
    if (LicensingPdu::Parse(sd.user_data.data() + 4, sd.user_data.size() - 4, lic) !=
        Status::Ok) {
        r.error = "license request parse";
        return r;
    }
    if (lic.preamble.type != LicenseMessageType::kLicenseRequest) {
        r.error = "expected SERVER_LICENSE_REQUEST";
        return r;
    }

    // Reply with a New License Request. The server does not need its contents to
    // accept the client without a CAL.
    ClientNewLicenseRequest nlr;
    nlr.client_random.assign(32, 0x42);
    nlr.encrypted_premaster.assign(136, 0);
    nlr.user_name = "rtsc";
    nlr.machine_name = "RTSC";
    const auto nlr_user =
        LicensingPdu::Encode(LicenseMessageType::kNewLicenseRequest, nlr.encode());
    ByteWriter lic_header;
    lic_header.u16le(0x0080);  // SEC_LICENSE_PKT
    lic_header.u16le(0);
    std::vector<uint8_t> lic_ud = lic_header.take();
    lic_ud.insert(lic_ud.end(), nlr_user.begin(), nlr_user.end());
    if (!WriteAll(*transport, McsSendData::build_request(r.user_channel, r.io_channel,
                                                         lic_ud))) {
        r.error = "license reply write";
        return r;
    }
    if (!reader.Read(frame)) {
        r.error = "license error read";
        return r;
    }
    if (McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok ||
        sd.user_data.size() < 4) {
        r.error = "license error framing";
        return r;
    }
    LicensingPdu err;
    if (LicensingPdu::Parse(sd.user_data.data() + 4, sd.user_data.size() - 4, err) !=
        Status::Ok) {
        r.error = "license error parse";
        return r;
    }
    r.license_valid_client = err.preamble.type == LicenseMessageType::kErrorAlert &&
                             err.error_alert.is_valid_client();

    // 7. Demand Active.
    if (!reader.Read(frame)) {
        r.error = "demand active read";
        return r;
    }
    if (McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok) {
        r.error = "demand active framing";
        return r;
    }
    DemandActivePdu da;
    if (DemandActivePdu::parse(sd.user_data.data(), sd.user_data.size(), da) !=
        Status::Ok) {
        r.error = "demand active parse";
        return r;
    }
    r.share_id = da.share_id;
    r.desktop_width = 0;
    if (const auto* bmp = da.capabilities.find(CapabilityType::kBitmap)) {
        BitmapCapabilitySet b;
        if (BitmapCapabilitySet::parse(*bmp, b) == Status::Ok) {
            r.desktop_width = b.desktop_width;
            r.desktop_height = b.desktop_height;
        }
    }
    if (da.capabilities.sets.empty()) {
        r.error = "demand active carried no capabilities";
        return r;
    }

    // 8. Confirm Active + finalization batch.
    const auto caps = BuildDefaultClientCapabilities(64, 48, 32);
    const auto confirm = ConfirmActivePdu::encode(r.user_channel, da.share_id,
                                                 da.pdu_source, "RTSC", caps);
    auto send_data = [&](ShareDataPduType type, const std::vector<uint8_t>& payload) {
        const auto share = BuildSlowPathDataPdu(r.user_channel, da.share_id, 0x01, type,
                                                payload);
        return WriteAll(*transport, McsSendData::build_request(r.user_channel,
                                                              r.io_channel, share));
    };
    if (!WriteAll(*transport, McsSendData::build_request(r.user_channel, r.io_channel,
                                                         confirm))) {
        r.error = "confirm active write";
        return r;
    }
    {
        ByteWriter p;
        p.u16le(1);
        p.u16le(da.pdu_source);
        if (!send_data(ShareDataPduType::kSynchronize, p.take())) {
            r.error = "sync write";
            return r;
        }
    }
    {
        ByteWriter p;
        p.u16le(0x0004);
        p.u16le(0);
        p.u32le(0);
        if (!send_data(ShareDataPduType::kControl, p.take())) {
            r.error = "control cooperate write";
            return r;
        }
    }
    {
        ByteWriter p;
        p.u16le(0x0001);
        p.u16le(0);
        p.u32le(0);
        if (!send_data(ShareDataPduType::kControl, p.take())) {
            r.error = "control request write";
            return r;
        }
    }
    {
        ByteWriter p;
        p.u16le(0);
        p.u16le(0);
        p.u16le(0x0003);
        p.u16le(0x0032);
        if (!send_data(ShareDataPduType::kFontList, p.take())) {
            r.error = "font list write";
            return r;
        }
    }

    // 9. Server Synchronize / Control / Font Map.
    bool got_font_map = false;
    while (!got_font_map) {
        if (!reader.Read(frame)) {
            r.error = "finalization read";
            return r;
        }
        if (McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok ||
            sd.user_data.size() < 18) {
            r.error = "finalization framing";
            return r;
        }
        if (sd.user_data[14] == static_cast<uint8_t>(ShareDataPduType::kFontMap)) {
            got_font_map = true;
        }
    }

    // 10. The server pushes one test-pattern bitmap frame.
    if (!reader.Read(frame)) {
        r.error = "bitmap frame read";
        return r;
    }
    if (McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok) {
        r.error = "bitmap framing";
        return r;
    }
    SlowPathGraphicsUpdate upd;
    if (SlowPathGraphicsUpdate::parse(sd.user_data.data(), sd.user_data.size(), upd) !=
        Status::Ok) {
        r.error = "graphics update parse";
        return r;
    }
    UpdateBitmapData bm;
    if (UpdateBitmapData::parse(upd.update_data.data(), upd.update_data.size(), bm) !=
        Status::Ok || bm.rectangles.empty()) {
        r.error = "bitmap update parse";
        return r;
    }
    const BitmapData& rect = bm.rectangles.front();
    DecodedBitmap decoded;
    if (DecodeRawBitmap(rect.bitmap_data.data(), rect.bitmap_data.size(), rect.width,
                        rect.height, rect.bits_per_pixel, decoded) != Status::Ok) {
        r.error = "bitmap decode";
        return r;
    }
    r.got_bitmap = true;
    r.bitmap_width = decoded.width;
    r.bitmap_height = decoded.height;
    r.bitmap_pixels = decoded.pixels;

    // Optionally leave an input PDU on the wire so the caller can observe the
    // server's input callback.
    if (send_input) {
        WriteAll(*transport,
                 McsSendData::build_request(
                     r.user_channel, r.io_channel,
                     EncodeFastPathInputPdu(
                         {EncodeKeyboardEvent(0x1E, false, false),
                          EncodeMouseEvent(kPtrMove, 10, 20)})));
    }

    r.reached_active = true;
    return r;
}

// ---- Server harness --------------------------------------------------------

}  // namespace

RTSC_TEST(server_negotiation_failure) {
    // With require_external_security the server must answer a client that asks
    // for TLS/HYBRID with RDP_NEG_FAILURE.
    ServerConfig cfg;
    cfg.port = 3391;
    cfg.require_external_security = true;
    RdpServer server(cfg);
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    std::string cerr;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", cfg.port, cerr);
    if (transport == nullptr) {
        server.Stop();
        runner.join();
        CHECK(transport != nullptr);
        return;
    }
    X224ConnectionRequest crq;
    crq.include_neg_req = true;
    crq.neg_req.requested_protocols = kProtocolSsl | kProtocolHybrid;
    WriteAll(*transport, crq.encode());

    FrameReader reader(*transport);
    std::vector<uint8_t> frame;
    CHECK(reader.Read(frame));
    if (!frame.empty()) {
        X224ConnectionConfirm ccf;
        CHECK(X224ConnectionConfirm::parse(frame.data(), frame.size(), ccf) ==
              Status::Ok);
        CHECK(ccf.neg_data.kind == RdpNegData::Kind::kFailure);
        CHECK(ccf.neg_data.failure.failure_code ==
              NegFailureCode::kHybridRequiredByServer);
    }
    server.Stop();
    runner.join();
}

RTSC_TEST(server_full_handshake_to_active) {
    ServerConfig cfg;
    cfg.port = 3390;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    rtsc::server::DesktopSource* source = pattern.get();

    RdpServer server(cfg);
    server.SetDesktopSource(source);
    std::string error;
    CHECK(server.Start(error));

    std::thread runner([&server]() { server.Run(); });

    const HandshakeResult r = DriveToActive(cfg.port);
    if (!r.error.empty()) {
        std::printf("  handshake error: %s\n", r.error.c_str());
    }
    CHECK(r.reached_active);
    CHECK(r.error.empty());
    CHECK_EQ(r.io_channel, 1003);
    CHECK_EQ(r.user_channel, 1001);
    CHECK_EQ(r.desktop_width, 64);
    CHECK_EQ(r.desktop_height, 48);
    CHECK(r.license_valid_client);
    CHECK(r.got_bitmap);
    CHECK_EQ(r.bitmap_width, 64);
    CHECK_EQ(r.bitmap_height, 48);
    CHECK_EQ(r.bitmap_pixels.size(), static_cast<size_t>(64) * 48 * 4);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_input_event_callback) {
    ServerConfig cfg;
    cfg.port = 3392;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    rtsc::server::DesktopSource* source = pattern.get();

    std::atomic<int> key_events{0};
    std::atomic<int> mouse_events{0};

    RdpServer server(cfg);
    server.SetDesktopSource(source);
    server.SetInputCallback([&](const rtsc::server::InputEvent& ev) {
        if (ev.kind == rtsc::server::InputEvent::Kind::kKey) {
            key_events.fetch_add(1);
        } else if (ev.kind == rtsc::server::InputEvent::Kind::kMouse) {
            mouse_events.fetch_add(1);
        }
    });
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    // Drive to active and leave a keyboard + mouse event on the wire.
    const HandshakeResult r = DriveToActive(cfg.port, /*send_input=*/true);
    CHECK(r.reached_active);

    // The callback runs on the session thread; give it a bounded moment.
    for (int i = 0; i < 100 && (key_events.load() == 0 || mouse_events.load() == 0);
         ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(key_events.load() >= 1);
    CHECK(mouse_events.load() >= 1);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_interop_with_client_machine) {
    // Drive the server with the project's own client connection machine, so the
    // X.224 / MCS / Client Info exchange is checked against the code the real
    // client ships (not a second server-side copy of it).
    ServerConfig cfg;
    cfg.port = 3393;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.requested_protocols = kProtocolRdp;
    mcfg.desktop_width = 64;
    mcfg.desktop_height = 48;
    mcfg.client_name = "RTSC";
    mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
    mcfg.encryption_methods = 0;
    ConnectMachine::Credentials creds;
    creds.domain = "NTDEV";
    creds.user_name = "rtsc";
    creds.password = "";

    ConnectMachine machine(mcfg, creds);
    std::string cerr;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", cfg.port, cerr);
    CHECK(transport != nullptr);
    if (transport != nullptr) {
        FrameReader reader(*transport);
        auto step = machine.Start();
        WriteAll(*transport, step.output);
        std::vector<uint8_t> frame;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!machine.done() && !machine.failed() &&
               std::chrono::steady_clock::now() < deadline) {
            if (!reader.Read(frame)) break;
            step = machine.OnData(frame.data(), frame.size());
            if (!step.output.empty()) WriteAll(*transport, step.output);
        }
        CHECK(machine.done());
        CHECK(!machine.failed());
        CHECK_EQ(machine.state().io_channel_id, 1003);
        CHECK_EQ(machine.state().user_channel_id, 1001);
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(test_pattern_source_shape) {
    auto source = rtsc::server::MakeTestPatternSource();
    std::vector<uint8_t> rgba;
    CHECK(source->Capture(32, 24, rgba));
    CHECK_EQ(rgba.size(), static_cast<size_t>(32) * 24 * 4);
    // The border is bright white.
    CHECK_EQ(rgba[0], 255);
    CHECK_EQ(rgba[1], 255);
    CHECK_EQ(rgba[2], 255);
    CHECK_EQ(rgba[3], 255);
}

int main() { return rtsc::test::run_all("rtsc_server_tests"); }
