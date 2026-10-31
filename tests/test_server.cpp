// RDP server: X.224 / MCS / licensing / Demand Active encoding and the
// connection state machine, exercised end to end.
//
// The tests drive the server with a scripted peer that speaks the client half
// of [MS-RDPBCGR] using the project's own encoders/decoders. A green run means
// the server emits the published wire format and reaches the active session.

// The handle-count probe below needs the Win32 thread-handle accounting; the
// rest of the suite stays platform neutral.
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>

#include "rtsc/channel/cliprdr_client.h"
#include "rtsc/clipboard/clipboard.h"
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
#include "rtsc/proto/rdpdr.h"
#include "rtsc/proto/share.h"
#include "rtsc/proto/tpkt.h"
#include "rtsc/server/server.h"
#include "test_framework.h"
#include "test_main.h"

#if defined(_WIN32)
#include <windows.h>
#endif

using namespace rtsc::proto;
using rtsc::server::RdpServer;
using rtsc::server::ServerConfig;

namespace {

// ---- TPKT frame reader over a blocking transport ---------------------------

class FrameReader {
 public:
    explicit FrameReader(rtsc::net::Transport& t,
                         std::chrono::milliseconds deadline =
                             std::chrono::seconds(5))
        : t_(&t), deadline_(deadline) {}

    bool Read(std::vector<uint8_t>& frame) {
        const auto deadline =
            std::chrono::steady_clock::now() + deadline_;
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
            const int n = t_->Read(tmp, sizeof(tmp));
            if (n == rtsc::net::kReadTimeout) continue;
            if (n <= 0) return false;
            buf_.insert(buf_.end(), tmp, tmp + static_cast<size_t>(n));
        }
    }

 private:
    rtsc::net::Transport* t_;
    std::chrono::milliseconds deadline_;
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
    bool got_demand_active = false;
    uint16_t io_channel = 0;
    uint16_t user_channel = 0;
    uint32_t share_id = 0;
    uint16_t desktop_width = 0;
    uint16_t desktop_height = 0;
    bool license_valid_client = false;
    bool rect_extents_consistent = false;
    bool got_bitmap = false;
    uint16_t bitmap_width = 0;
    uint16_t bitmap_height = 0;
    std::vector<uint8_t> bitmap_pixels;
    // Size of the share PDU (MCS userData) that carried the first bitmap
    // frame; an MCS Send Data userData is capped at 16383 bytes.
    size_t share_pdu_bytes = 0;
    // Kept open after DriveToActive so a test can keep interacting with the
    // active session (input, slow-path share PDUs).
    std::unique_ptr<rtsc::net::Transport> transport;
    std::unique_ptr<FrameReader> reader;
    std::string error;
};

HandshakeResult DriveToActive(uint16_t port, bool send_input = false,
                              uint16_t client_width = 64,
                              uint16_t client_height = 48,
                              bool expect_frame = true) {
    HandshakeResult r;
    std::string error;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", port, error);
    if (!transport) {
        r.error = "connect: " + error;
        return r;
    }
    // One reader for the whole session: handing a fresh reader to the caller
    // would drop any bytes already buffered past the last extracted frame
    // (a TPKT desync mid-frame).
    auto reader = std::make_unique<FrameReader>(*transport);

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
    if (!reader->Read(frame)) {
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
    const auto blocks = ClientBlocks(client_width, client_height, 0);
    const auto ci = McsConnectInitial::build(blocks);
    if (!WriteAll(*transport, ci)) {
        r.error = "connect initial write";
        return r;
    }
    if (!reader->Read(frame)) {
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
    if (!reader->Read(frame)) {
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
        if (!reader->Read(frame)) {
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

    // 6. Licensing: the server issues no CALs, so it sends exactly one
    //    ERROR_ALERT (STATUS_VALID_CLIENT + ST_NO_TRANSITION) and completes the
    //    phase. This matches a real Windows server without a license server
    //    (observed on Win11 26100: "80 00 00 00 ff 03 10 00 07 00 00 00 02 00
    //    00 00 04 00 00 00"); mstsc rejects a full SERVER_LICENSE_REQUEST with
    //    disconnectReasonLicensingFailed (0x808).
    if (!reader->Read(frame)) {
        r.error = "license error read";
        return r;
    }
    McsSendData sd;
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
    if (!reader->Read(frame)) {
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
    r.got_demand_active = true;
    if (da.capabilities.sets.empty()) {
        r.error = "demand active carried no capabilities";
        return r;
    }

    // 8. Confirm Active + finalization batch.
    const auto caps = BuildDefaultClientCapabilities(client_width, client_height, 32);
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
        if (!reader->Read(frame)) {
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

    // 10. The server pushes one test-pattern bitmap frame. Since the server
    //     speaks first on its static virtual channels at active (the rdpdr
    //     Server Announce / cliprdr initialization), the first on-wire frame
    //     after finalization is not necessarily the bitmap; keep reading until
    //     the graphics update arrives.
    if (!expect_frame) {
        r.reached_active = true;
        r.transport = std::move(transport);
        r.reader = std::move(reader);
        return r;
    }
    for (;;) {
        if (!reader->Read(frame)) {
            r.error = "bitmap frame read";
            return r;
        }
        if (McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok) {
            continue;  // not an MCS Send Data: keep reading
        }
        SlowPathGraphicsUpdate upd;
        if (SlowPathGraphicsUpdate::parse(sd.user_data.data(),
                                          sd.user_data.size(), upd) !=
            Status::Ok) {
            continue;  // a static virtual channel PDU (rdpdr/cliprdr): skip
        }
        UpdateBitmapData bm;
        if (UpdateBitmapData::parse(upd.update_data.data(),
                                    upd.update_data.size(), bm) !=
                Status::Ok ||
            bm.rectangles.empty()) {
            r.error = "bitmap update parse";
            return r;
        }
        const BitmapData& rect = bm.rectangles.front();
        // [MS-RDPBCGR] 2.2.9.1.1.3.1.2.2: destRight/destBottom are INCLUSIVE,
        // so destRight - destLeft + 1 must equal width. mstsc drops the
        // rectangle when they disagree (the session renders black); this is the
        // regression check for that failure mode.
        r.rect_extents_consistent =
            static_cast<int>(rect.dest_right) - static_cast<int>(rect.dest_left) + 1 ==
                static_cast<int>(rect.width) &&
            static_cast<int>(rect.dest_bottom) - static_cast<int>(rect.dest_top) + 1 ==
                static_cast<int>(rect.height);
        DecodedBitmap decoded;
        if (DecodeRawBitmap(rect.bitmap_data.data(), rect.bitmap_data.size(),
                            rect.width, rect.height, rect.bits_per_pixel,
                            decoded) != Status::Ok) {
            r.error = "bitmap decode";
            return r;
        }
        r.got_bitmap = true;
        r.bitmap_width = decoded.width;
        r.bitmap_height = decoded.height;
        r.bitmap_pixels = decoded.pixels;
        r.share_pdu_bytes = sd.user_data.size();
        break;
    }

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
    // Hand the still-open transport and its reader (with any buffered bytes)
    // to the caller so a test can keep interacting with the active session.
    r.transport = std::move(transport);
    r.reader = std::move(reader);
    return r;
}

// ---- Server harness --------------------------------------------------------

}  // namespace

RTSC_TEST(server_negotiation_failure) {
    // With require_external_security the server must answer a client that asks
    // for TLS/HYBRID with RDP_NEG_FAILURE.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.require_external_security = true;
    RdpServer server(cfg);
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    std::string cerr;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", server.bound_port(), cerr);
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
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    rtsc::server::DesktopSource* source = pattern.get();

    RdpServer server(cfg);
    server.SetDesktopSource(source);
    std::string error;
    CHECK(server.Start(error));

    std::thread runner([&server]() { server.Run(); });

    const HandshakeResult r = DriveToActive(server.bound_port());
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
    CHECK(r.rect_extents_consistent);
    CHECK(r.got_bitmap);
    CHECK_EQ(r.bitmap_width, 64);
    CHECK_EQ(r.bitmap_height, 48);
    CHECK_EQ(r.bitmap_pixels.size(), static_cast<size_t>(64) * 48 * 4);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_input_event_callback) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
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
    const HandshakeResult r = DriveToActive(server.bound_port(), /*send_input=*/true);
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

RTSC_TEST(server_decodes_mousex_buttons_with_ptrxflags) {
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    rtsc::server::DesktopSource* source = pattern.get();

    std::mutex mu;
    std::vector<rtsc::server::InputEvent> events;

    RdpServer server(cfg);
    server.SetDesktopSource(source);
    server.SetInputCallback([&](const rtsc::server::InputEvent& ev) {
        std::lock_guard<std::mutex> lock(mu);
        events.push_back(ev);
    });
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    const HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    // MOUSEX carries PTRXFLAGS ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.4): X1 = 0x0001,
    // X2 = 0x0002, plus PTRXFLAGS_DOWN = 0x8000 on presses. A plain POINTER
    // left click (0x9000) is included to prove the left path is untouched.
    const std::vector<uint8_t> fp = rtsc::proto::EncodeFastPathInputPdu({
        rtsc::proto::EncodeMouseEvent(0x8001, 10, 20, true),   // X1 down
        rtsc::proto::EncodeMouseEvent(0x8002, 11, 21, true),   // X2 down
        rtsc::proto::EncodeMouseEvent(0x0001, 10, 20, true),   // X1 up
        rtsc::proto::EncodeMouseEvent(0x0002, 11, 21, true),   // X2 up
        rtsc::proto::EncodeMouseEvent(0x9000, 30, 40, false),  // left down
    });
    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel, fp)));

    struct Seen {
        bool x1_down = false, x2_down = false, left_down = false;
        int nondown_mouse = 0;  // the two X releases arrive as plain mouse ups
    } seen;
    for (int i = 0;
         i < 100 && !(seen.x1_down && seen.x2_down && seen.left_down &&
                      seen.nondown_mouse >= 2);
         ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(mu);
        for (const auto& ev : events) {
            if (ev.kind != rtsc::server::InputEvent::Kind::kMouse) continue;
            if (ev.button_down) {
                if (ev.button == 4) seen.x1_down = true;
                if (ev.button == 5) seen.x2_down = true;
                if (ev.button == 1) seen.left_down = true;
            } else {
                ++seen.nondown_mouse;
            }
        }
    }
    CHECK(seen.x1_down);   // PTRXFLAGS_BUTTON1 (0x0001) -> X1, not left
    CHECK(seen.x2_down);   // PTRXFLAGS_BUTTON2 (0x0002) -> X2, not right
    CHECK(seen.left_down);  // the plain POINTER left path is untouched
    CHECK(seen.nondown_mouse >= 2);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_decodes_wheel_rotation_in_wire_units) {
    // PTRFLAGS_WHEEL and PTRFLAGS_HWHEEL share the 9-bit two's-complement
    // WheelRotationMask (0x01FF): 0x0100 is that field's sign bit, not a
    // standalone negative flag ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.1). One notch is
    // WHEEL_DELTA = 120 wire units, so the decoded delta is the signed 9-bit
    // value itself. HWHEEL events are decoded too (they used to be dropped as
    // plain pointer events), and WHEEL wins when both flags are present.
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();

    std::mutex mu;
    std::vector<rtsc::server::InputEvent> events;

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetInputCallback([&](const rtsc::server::InputEvent& ev) {
        std::lock_guard<std::mutex> lock(mu);
        events.push_back(ev);
    });
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    const HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    const std::vector<uint8_t> fp = rtsc::proto::EncodeFastPathInputPdu({
        rtsc::proto::EncodeMouseEvent(0x0388, 1, 1),  // vertical, -120
        rtsc::proto::EncodeMouseEvent(0x0478, 1, 2),  // horizontal, +120
        rtsc::proto::EncodeMouseEvent(0x0301, 1, 3),  // vertical, -255
        rtsc::proto::EncodeMouseEvent(0x02FF, 1, 4),  // vertical, +255
        rtsc::proto::EncodeMouseEvent(0x0600, 1, 5),  // WHEEL|HWHEEL: vertical wins
    });
    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel, fp)));

    std::vector<rtsc::server::InputEvent> wheels;
    for (int i = 0; i < 100 && wheels.size() < 5; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(mu);
        wheels.clear();
        for (const auto& ev : events) {
            if (ev.kind == rtsc::server::InputEvent::Kind::kWheel) {
                wheels.push_back(ev);
            }
        }
    }
    CHECK_EQ(wheels.size(), static_cast<size_t>(5));
    if (wheels.size() == 5) {
        CHECK_EQ(wheels[0].wheel_delta, static_cast<int16_t>(-120));
        CHECK(!wheels[0].horizontal);
        CHECK_EQ(wheels[1].wheel_delta, static_cast<int16_t>(120));
        CHECK(wheels[1].horizontal);
        CHECK_EQ(wheels[2].wheel_delta, static_cast<int16_t>(-255));
        CHECK(!wheels[2].horizontal);
        CHECK_EQ(wheels[3].wheel_delta, static_cast<int16_t>(255));
        CHECK(!wheels[3].horizontal);
        CHECK_EQ(wheels[4].wheel_delta, static_cast<int16_t>(0));
        CHECK(!wheels[4].horizontal);
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_interop_with_client_machine) {
    // Drive the server with the project's own client connection machine, so the
    // X.224 / MCS / Client Info exchange is checked against the code the real
    // client ships (not a second server-side copy of it).
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
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
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", server.bound_port(), cerr);
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

namespace {

// A desktop source that captures successfully `succeeds` times, then fails.
class FailingAfterSource : public rtsc::server::DesktopSource {
 public:
    explicit FailingAfterSource(int succeeds) : succeeds_(succeeds) {}

    bool Capture(uint16_t width, uint16_t height,
                 std::vector<uint8_t>& rgba) override {
        if (calls_++ >= succeeds_) return false;
        return pattern_->Capture(width, height, rgba);
    }

 private:
    int succeeds_;
    int calls_ = 0;
    std::unique_ptr<rtsc::server::DesktopSource> pattern_ =
        rtsc::server::MakeTestPatternSource();
};

// Sends one client slow-path share data PDU (Refresh Rect / Suppress Output).
bool SendSlowPathPdu(HandshakeResult& r, ShareDataPduType type,
                     const std::vector<uint8_t>& body) {
    const auto share =
        BuildSlowPathDataPdu(r.user_channel, r.share_id, 0x01, type, body);
    return WriteAll(*r.transport,
                    McsSendData::build_request(r.user_channel, r.io_channel,
                                               share));
}

}  // namespace

RTSC_TEST(server_refresh_rect_triggers_immediate_resend) {
    // [MS-RDPBCGR] 2.2.11.2.1: a client Refresh Rect asks the server to resend
    // the named area at once  -well before the ~1 s periodic refresh would.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    // numberOfAreas(1) + pad3Octets(3) + one full-desktop rectangle.
    std::vector<uint8_t> body = {0x01, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00,
                                 0x3f, 0x00, 0x2f, 0x00};
    CHECK(SendSlowPathPdu(r, ShareDataPduType::kRefreshRect, body));

    // A short deadline: the frame must arrive immediately (the ~1 s periodic
    // refresh cannot be what satisfied this read).
    FrameReader fast(*r.transport, std::chrono::milliseconds(500));
    std::vector<uint8_t> frame;
    CHECK(fast.Read(frame));
    McsSendData sd;
    CHECK(McsSendData::parse(frame.data(), frame.size(), sd) == Status::Ok);
    SlowPathGraphicsUpdate upd;
    CHECK(SlowPathGraphicsUpdate::parse(sd.user_data.data(), sd.user_data.size(),
                                        upd) == Status::Ok);
    UpdateBitmapData bm;
    CHECK(UpdateBitmapData::parse(upd.update_data.data(), upd.update_data.size(),
                                  bm) == Status::Ok);
    CHECK(!bm.rectangles.empty());

    server.Stop();
    runner.join();
}

RTSC_TEST(server_suppress_output_gates_refresh) {
    // [MS-RDPBCGR] 2.2.11.3.1: allowDisplayUpdates=0 stops the desktop
    // refresh; allowDisplayUpdates=1 resumes it.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    // allow(1) + pad3(3): no desktopRect.
    CHECK(SendSlowPathPdu(r, ShareDataPduType::kSuppressOutput,
                          {0x00, 0x00, 0x00, 0x00}));

    // Suppressed: no frame may arrive for 2 s (the ~1 s periodic refresh
    // must be suspended).
    std::vector<uint8_t> frame;
    CHECK(!r.reader->Read(frame));

    // allow(1) + pad3(3) + desktopRect(8): output resumes.
    CHECK(SendSlowPathPdu(r, ShareDataPduType::kSuppressOutput,
                          {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x3f, 0x00, 0x2f, 0x00}));
    CHECK(r.reader->Read(frame));
    McsSendData sd;
    CHECK(McsSendData::parse(frame.data(), frame.size(), sd) == Status::Ok);
    SlowPathGraphicsUpdate upd;
    CHECK(SlowPathGraphicsUpdate::parse(sd.user_data.data(), sd.user_data.size(),
                                        upd) == Status::Ok);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_refresh_continues_during_input) {
    // The periodic desktop refresh must run on its own ~1 s cadence and must
    // NOT be reset by client input: continuous input previously zeroed the
    // idle counter and froze the desktop while the user was interacting.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    // Send a mouse move every 200 ms and count bitmap frames over ~3 s. The
    // reader's short deadline keeps the loop sending input while it waits.
    FrameReader poller(*r.transport, std::chrono::milliseconds(300));
    int frames = 0;
    int inputs = 0;
    const auto t_end = std::chrono::steady_clock::now() +
                       std::chrono::milliseconds(3000);
    auto next_input = std::chrono::steady_clock::now();
    std::vector<uint8_t> frame;
    while (std::chrono::steady_clock::now() < t_end) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= next_input) {
            WriteAll(*r.transport,
                     McsSendData::build_request(
                         r.user_channel, r.io_channel,
                         EncodeFastPathInputPdu(
                             {EncodeMouseEvent(kPtrMove,
                                               static_cast<uint16_t>(inputs % 64),
                                               20)})));
            ++inputs;
            next_input = now + std::chrono::milliseconds(200);
        }
        if (poller.Read(frame)) ++frames;
    }
    // Input must really have kept flowing, and frames must still have arrived.
    // Margin: the window is 3000 ms, the poller's read timeout is 300 ms and
    // one input is queued per iteration, so the theoretical maximum is 10
    // events (~10 iterations). Asserting the maximum (>= 10) left zero margin
    // and failed ~14% of runs (3 of 22). A bound must stay at or below half the
    // theoretical maximum, hence >= 5.
    CHECK(inputs >= 5);
    CHECK(frames >= 2);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_wide_desktop_bands_fit_mcs_limit) {
    // A single 4Bpp row wider than ~4085 px overflows both the 16383-byte MCS
    // Send Data userData cap and the u16 bitmapLength; the banding must split
    // columns as well as rows and keep every rectangle self-consistent.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 5000;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult r = DriveToActive(server.bound_port(), /*send_input=*/false,
                                      cfg.desktop_width, cfg.desktop_height);
    if (!r.error.empty()) {
        std::printf("  handshake error: %s\n", r.error.c_str());
    }
    CHECK(r.reached_active);
    CHECK(r.error.empty());

    // First chunk: the widest single-row rectangle that fits the budget.
    CHECK(r.rect_extents_consistent);
    CHECK_EQ(r.bitmap_width, 4085);
    CHECK_EQ(r.bitmap_height, 1);
    CHECK(r.share_pdu_bytes <= 16383);

    // Next bands keep arriving, chunked the same way (4085 + 915 per row).
    const uint16_t expected_widths[3] = {915, 4085, 915};
    for (int i = 0; i < 3; ++i) {
        std::vector<uint8_t> frame;
        CHECK(r.reader->Read(frame));
        McsSendData sd;
        CHECK(McsSendData::parse(frame.data(), frame.size(), sd) == Status::Ok);
        CHECK(sd.user_data.size() <= 16383);
        SlowPathGraphicsUpdate upd;
        CHECK(SlowPathGraphicsUpdate::parse(sd.user_data.data(),
                                            sd.user_data.size(),
                                            upd) == Status::Ok);
        UpdateBitmapData bm;
        CHECK(UpdateBitmapData::parse(upd.update_data.data(),
                                      upd.update_data.size(), bm) ==
              Status::Ok);
        CHECK(!bm.rectangles.empty());
        if (bm.rectangles.empty()) break;  // CHECK above keeps counting: don't UB
        const BitmapData& rect = bm.rectangles.front();
        CHECK_EQ(rect.width, expected_widths[i]);
        CHECK_EQ(static_cast<int>(rect.dest_right) -
                     static_cast<int>(rect.dest_left) + 1,
                 static_cast<int>(rect.width));
        DecodedBitmap decoded;
        CHECK(DecodeRawBitmap(rect.bitmap_data.data(), rect.bitmap_data.size(),
                              rect.width, rect.height, rect.bits_per_pixel,
                              decoded) == Status::Ok);
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_refresh_send_failure_closes_session) {
    // A periodic-refresh SendFrame() failure must be handled: the session
    // records the error and exits, which closes the transport (the client sees
    // EOF instead of an endless silent session).
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    FailingAfterSource source(1);  // first capture OK, then fail
    RdpServer server(cfg);
    server.SetDesktopSource(&source);
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    // The next periodic refresh (~1 s) fails: the server must end the session.
    // EOF arrives within a bounded window; a silent keep-alive session would
    // only produce read timeouts.
    bool saw_eof = false;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        uint8_t tmp[4096];
        const int n = r.transport->Read(tmp, sizeof(tmp));
        if (n != rtsc::net::kReadTimeout) {
            saw_eof = n <= 0;
            break;
        }
    }
    CHECK(saw_eof);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_refuses_zero_desktop_geometry) {
    // H-3: a zero width or height used to reach the frame path, where the
    // band computation divides by the row stride (65535 / chunk_row). The
    // integer division by zero killed the whole process with 0xC0000094, so
    // one client took every other session with it. A zero geometry must be
    // refused at the entry point, with a reason.
    {
        ServerConfig cfg;
        cfg.port = 0;  // ephemeral: the kernel picks a free port
        cfg.desktop_width = 0;
        cfg.desktop_height = 48;
        RdpServer server(cfg);
        std::string error;
        CHECK(!server.Start(error));
        CHECK(!error.empty());
    }
    {
        ServerConfig cfg;
        cfg.port = 0;  // ephemeral: the kernel picks a free port
        cfg.desktop_width = 64;
        cfg.desktop_height = 0;
        RdpServer server(cfg);
        std::string error;
        CHECK(!server.Start(error));
        CHECK(!error.empty());
    }
}

RTSC_TEST(server_zero_client_geometry_serves_the_configured_desktop) {
    // A client that announces a zero width/height in TS_CLIENT_CORE_DATA
    // ([MS-RDPBCGR] 2.2.1.3.2: desktopWidth / desktopHeight) must not drive
    // the server into a zero-sized framebuffer: the configured geometry is
    // served instead and the frame path runs normally.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult r = DriveToActive(server.bound_port(), /*send_input=*/false,
                                      /*client_width=*/0, /*client_height=*/0);
    if (!r.error.empty()) {
        std::printf("  handshake error: %s\n", r.error.c_str());
    }
    CHECK(r.reached_active);
    CHECK(r.error.empty());
    CHECK_EQ(r.desktop_width, 64);
    CHECK_EQ(r.desktop_height, 48);
    CHECK(r.got_bitmap);
    CHECK_EQ(r.bitmap_width, 64);
    CHECK_EQ(r.bitmap_height, 48);

    server.Stop();
    runner.join();
}

RTSC_TEST(test_pattern_source_refuses_zero_dimensions) {
    // The synthetic desktop source used to allocate an empty framebuffer for
    // a zero width and then write the border into it (a heap overflow that
    // killed the process). A zero dimension is refused explicitly.
    auto source = rtsc::server::MakeTestPatternSource();
    std::vector<uint8_t> rgba;
    CHECK(!source->Capture(0, 48, rgba));
    CHECK(!source->Capture(48, 0, rgba));
    CHECK(!source->Capture(0, 0, rgba));
}

namespace {

// A desktop source whose behaviour the test controls. It records the geometry
// it is asked for and can fail, throw, or throw after the first capture. The
// recording happens before any allocation, so a test can observe the geometry
// the server is willing to build without actually building a huge framebuffer.
class ScriptedSource : public rtsc::server::DesktopSource {
  public:
    enum class Mode { kSucceed, kFail, kThrowAfterFirst };

    void set_mode(Mode mode) { mode_.store(mode, std::memory_order_relaxed); }

    bool Capture(uint16_t width, uint16_t height,
                 std::vector<uint8_t>& rgba) override {
        int call = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            call = ++calls_;
            last_width_ = width;
            last_height_ = height;
        }
        const Mode mode = mode_.load(std::memory_order_relaxed);
        if (mode == Mode::kFail) return false;
        if (mode == Mode::kThrowAfterFirst && call > 1) throw std::bad_alloc();
        return pattern_->Capture(width, height, rgba);
    }

    int calls() const {
        std::lock_guard<std::mutex> lock(mu_);
        return calls_;
    }
    uint16_t last_width() const {
        std::lock_guard<std::mutex> lock(mu_);
        return last_width_;
    }
    uint16_t last_height() const {
        std::lock_guard<std::mutex> lock(mu_);
        return last_height_;
    }

  private:
    std::atomic<Mode> mode_{Mode::kSucceed};
    mutable std::mutex mu_;
    int calls_ = 0;
    uint16_t last_width_ = 0;
    uint16_t last_height_ = 0;
    std::unique_ptr<rtsc::server::DesktopSource> pattern_ =
        rtsc::server::MakeTestPatternSource();
};

}  // namespace

RTSC_TEST(server_clamps_oversized_client_geometry) {
    // H-1: the client announces its desktop size in TS_CLIENT_CORE_DATA
    // ([MS-RDPBCGR] 2.2.1.3.2, two uint16 fields), so it may ask for up to
    // 65535 x 65535 -- a 17,179,344,900 byte framebuffer. The server must clamp
    // the request to its own limit (server.h kMaxDesktop*) instead of
    // allocating it, and must announce the clamped size.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    ScriptedSource source;
    source.set_mode(ScriptedSource::Mode::kFail);  // record, do not allocate
    RdpServer server(cfg);
    server.SetDesktopSource(&source);
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    const HandshakeResult r = DriveToActive(server.bound_port(), /*send_input=*/false,
                                            /*client_width=*/20000,
                                            /*client_height=*/20000,
                                            /*expect_frame=*/false);
    CHECK(r.reached_active);
    CHECK(r.got_demand_active);
    // What Demand Active announces must already be inside the limit.
    CHECK(r.desktop_width <= rtsc::server::kMaxDesktopWidth);
    CHECK(r.desktop_height <= rtsc::server::kMaxDesktopHeight);
    CHECK(static_cast<size_t>(r.desktop_width) * r.desktop_height * 4 <=
          rtsc::server::kMaxFramebufferBytes);
    // The frame path must never be asked for the oversized geometry.
    for (int i = 0; i < 200 && source.calls() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(source.calls() >= 1);
    CHECK(source.last_width() <= rtsc::server::kMaxDesktopWidth);
    CHECK(source.last_height() <= rtsc::server::kMaxDesktopHeight);
    CHECK(static_cast<size_t>(source.last_width()) * source.last_height() * 4 <=
          rtsc::server::kMaxFramebufferBytes);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_tall_client_geometry_frame_stays_bounded) {
    // H-2: the band loop counted rows in a uint16_t, so a height near 65535
    // wrapped the counter back to zero and the frame never ended (measured:
    // 1.07 GB in 3 s on a single connection). A 100 px wide desktop makes the
    // band height even (40 rows), which is exactly the wrap-around case.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult r = DriveToActive(server.bound_port(), /*send_input=*/false,
                                      /*client_width=*/100,
                                      /*client_height=*/65535);
    if (!r.error.empty()) {
        std::printf("  handshake error: %s\n", r.error.c_str());
    }
    CHECK(r.reached_active);
    CHECK(r.desktop_height <= rtsc::server::kMaxDesktopHeight);

    // Whatever the server pushes for the clamped desktop must stay bounded: a
    // wrapped row counter never finishes the frame, so the bytes explode.
    constexpr size_t kByteCap = 64u * 1024u * 1024u;
    size_t bytes = 0;
    bool exceeded = false;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(2);
    uint8_t buf[16384];
    while (std::chrono::steady_clock::now() < deadline) {
        const int n = r.transport->Read(buf, sizeof(buf));
        if (n == rtsc::net::kReadTimeout) continue;
        if (n <= 0) break;
        bytes += static_cast<size_t>(n);
        if (bytes > kByteCap) {
            exceeded = true;
            break;
        }
    }
    CHECK(!exceeded);
    CHECK(bytes < kByteCap);
    CHECK(bytes > 0);  // the frame really was sent

    server.Stop();
    runner.join();
}

RTSC_TEST(server_releases_session_when_the_client_disconnects) {
    // H-4: the session object (transport, TLS/CredSSP state and the plaintext
    // password) used to live until Stop(): every connection leaked one session
    // and kept its credentials resident. session_count() reports the live
    // sessions, so it must fall back to zero when the client disconnects.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    for (int round = 0; round < 2; ++round) {
        HandshakeResult r = DriveToActive(server.bound_port());
        CHECK(r.reached_active);
        CHECK_EQ(server.session_count(), 1);

        r.transport->Close();
        bool released = false;
        for (int i = 0; i < 300 && !released; ++i) {
            if (server.session_count() == 0) {
                released = true;
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        CHECK(released);
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_session_exception_only_fails_that_session) {
    // H-1: an exception escaping the session thread (a desktop source that
    // runs out of memory) used to escape the thread function, so
    // std::terminate killed the whole process and every other session with it.
    // The failure must stay inside the session.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    ScriptedSource source;
    source.set_mode(ScriptedSource::Mode::kThrowAfterFirst);
    RdpServer server(cfg);
    server.SetDesktopSource(&source);
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    // The next capture (the ~1 s periodic refresh) throws: this session must
    // die, the process must not.
    bool saw_eof = false;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        uint8_t tmp[4096];
        const int n = r.transport->Read(tmp, sizeof(tmp));
        if (n != rtsc::net::kReadTimeout) {
            saw_eof = n <= 0;
            break;
        }
    }
    CHECK(saw_eof);

    // Another client is still served.
    source.set_mode(ScriptedSource::Mode::kSucceed);
    const HandshakeResult r2 = DriveToActive(server.bound_port());
    CHECK(r2.reached_active);
    CHECK(r2.error.empty());

    server.Stop();
    runner.join();
}

// ---- OS handle accounting ---------------------------------------------------

// Number of kernel handles this process holds. A session thread that is never
// joined keeps one thread handle alive, so a per-connection leak shows up here
// even after the thread has exited. Returns 0 where the counter is unavailable
// (the assertion below then passes trivially).
size_t ProcessHandleCount() {
#if defined(_WIN32)
    DWORD count = 0;
    if (!::GetProcessHandleCount(::GetCurrentProcess(), &count)) return 0;
    return static_cast<size_t>(count);
#else
    return 0;
#endif
}

RTSC_TEST(server_does_not_leak_a_handle_per_connection) {
    // H-4 follow-up (audit finding): every session thread was moved into
    // Impl::threads and only joined in Stop(), so its std::thread object and
    // kernel handle stayed alive for the lifetime of the server. Eight
    // connect/disconnect rounds added eight handles (measured 107 -> 115 on
    // the standalone host). The thread must be released when the session ends.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    const auto round = [&]() {
        HandshakeResult r = DriveToActive(server.bound_port());
        CHECK(r.reached_active);
        CHECK_EQ(server.session_count(), 1);
        r.transport->Close();
        bool released = false;
        for (int i = 0; i < 300 && !released; ++i) {
            if (server.session_count() == 0) {
                released = true;
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        CHECK(released);
    };

    // Two warm-up rounds establish a baseline after any one-off allocation.
    round();
    round();
    const size_t baseline = ProcessHandleCount();
    for (int i = 0; i < 8; ++i) round();
    const size_t after = ProcessHandleCount();
    std::printf("  handles: baseline=%zu after8=%zu\n", baseline, after);
    // Eight finished sessions must not retain eight thread handles.
    if (baseline != 0) CHECK(after <= baseline + 3);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_thread_launch_failure_drops_the_connection) {
    // R-A: the live counter used to be incremented before the session thread
    // was created. When thread creation failed (thread/handle exhaustion is
    // what a connection flood causes), the count stayed up forever: Stop()
    // blocked in cv.wait(live==0) and the accept loop was left running for a
    // session that never existed. The failure must roll back and keep serving.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    std::atomic<int> launches{0};
    std::atomic<bool> fail_launch{true};
    cfg.session_thread_launcher = [&launches, &fail_launch](
                                     std::function<void()> body) {
        launches.fetch_add(1);
        if (fail_launch.load()) return false;  // platform refuses the thread
        std::thread(std::move(body)).detach();
        return true;
    };
    auto pattern = rtsc::server::MakeTestPatternSource();
    auto server = std::make_unique<RdpServer>(cfg);
    server->SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server->Start(error));
    std::thread runner([&server]() { server->Run(); });

    std::string cerr;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", server->bound_port(), cerr);
    CHECK(transport != nullptr);
    for (int i = 0; i < 300 && launches.load() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(launches.load() >= 1);

    // No session may be counted, and the connection must be dropped instead of
    // being left in a zombie state.
    CHECK_EQ(server->session_count(), 0);
    CHECK_EQ(server->total_session_count(), 0);
    bool closed = false;
    if (transport != nullptr) {
        uint8_t tmp[64];
        for (int i = 0; i < 100; ++i) {
            const int n = transport->Read(tmp, sizeof(tmp));
            if (n == rtsc::net::kReadTimeout) continue;
            closed = n <= 0;
            break;
        }
    }
    CHECK(closed);

    const bool clean = server->session_count() == 0 &&
                       server->total_session_count() == 0;
    if (!clean) {
        // Pre-fix the leaked count makes Stop() block forever. Leak the server
        // and detach the accept loop so the red run still reports instead of
        // hanging.
        runner.detach();
        (void)server.release();
        return;
    }

    // The accept loop must have survived the failed launch: a later connection
    // is served normally.
    fail_launch.store(false);
    const HandshakeResult r2 = DriveToActive(server->bound_port());
    CHECK(r2.reached_active);
    CHECK(r2.error.empty());
    CHECK_EQ(server->total_session_count(), 1);

    server->Stop();
    runner.join();
    CHECK_EQ(server->session_count(), 0);
}

RTSC_TEST(server_thread_launcher_running_body_then_failing) {
    // R-A-1: a launcher may start the body *and then* report failure (a thread
    // pool that enqueues the work and only afterwards throws, or a launcher
    // that joins the body and returns false). Both the body's teardown and the
    // rollback then decrement the live count, which underflows size_t to
    // SIZE_MAX and makes Stop() block forever. The decrement must be handed off
    // exactly once, so it cannot depend on the launcher being honest.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    std::atomic<int> launches{0};
    cfg.session_thread_launcher = [&launches](std::function<void()> body) {
        launches.fetch_add(1);
        // The body runs to completion (the peer is gone), and only then does
        // the launcher report failure.
        std::thread(std::move(body)).join();
        return false;
    };
    auto pattern = rtsc::server::MakeTestPatternSource();
    auto server = std::make_unique<RdpServer>(cfg);
    server->SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server->Start(error));
    std::thread runner([&server]() { server->Run(); });

    std::string cerr;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", server->bound_port(), cerr);
    CHECK(transport != nullptr);
    for (int i = 0; i < 300 && launches.load() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(launches.load() >= 1);
    // End the session so the body finishes and the launcher can return false.
    if (transport != nullptr) transport->Close();

    // The handoff must leave the live count at zero -- never SIZE_MAX.
    bool settled = false;
    for (int i = 0; i < 300 && !settled; ++i) {
        if (server->session_count() == 0) {
            settled = true;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    const size_t live = server->session_count();
    std::printf("  live_after_launcher_failed=%zu\n", live);
    CHECK_EQ(live, 0);
    CHECK(settled);

    if (live != 0) {
        // Pre-fix the count underflows to SIZE_MAX; Stop() would block forever.
        // Leak the server so the red run reports instead of hanging.
        runner.detach();
        (void)server.release();
        return;
    }

    // Stop() must return promptly, not wait for a session that no longer
    // exists.
    std::atomic<bool> stop_done{false};
    std::thread stopper([&server, &stop_done]() {
        server->Stop();
        stop_done.store(true);
    });
    for (int i = 0; i < 100 && !stop_done.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(stop_done.load());
    if (stop_done.load()) {
        stopper.join();
    } else {
        stopper.detach();
    }
    if (stop_done.load()) {
        runner.join();
    } else {
        runner.detach();
    }

    // The server still serves a later client after the failed launch.
    if (stop_done.load()) {
        ServerConfig cfg2;
        cfg2.port = 0;  // ephemeral: the kernel picks a free port
        cfg2.desktop_width = 64;
        cfg2.desktop_height = 48;
        auto pattern2 = rtsc::server::MakeTestPatternSource();
        RdpServer server2(cfg2);
        server2.SetDesktopSource(pattern2.get());
        std::string error2;
        CHECK(server2.Start(error2));
        std::thread runner2([&server2]() { server2.Run(); });
        const HandshakeResult r2 = DriveToActive(server2.bound_port());
        CHECK(r2.reached_active);
        CHECK(r2.error.empty());
        server2.Stop();
        runner2.join();
        CHECK_EQ(server2.session_count(), 0);
    }
}

// ---- F5: acceptance invariants only provable from the outside ---------------

RTSC_TEST(server_authenticator_rejection_leaves_no_active_session) {
    // F5: on the Standard RDP Security path the authenticator is the only real
    // credential gate, and until this test nothing exercised a rejection -- the
    // whole suite was green with the gate removed, because every other test
    // uses the accept-anything default. A rejected Client Info must fail the
    // handshake (active_ must never be true), and the session must still tear
    // down so session_count() falls back to zero.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetAuthenticator(
        [](const rtsc::server::Credentials&) { return false; });
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    const HandshakeResult r = DriveToActive(server.bound_port());
    // The peer is dropped before licensing / Demand Active, so nothing of the
    // active session may have been emitted.
    CHECK(!r.reached_active);
    CHECK(!r.got_demand_active);
    CHECK(!r.error.empty());

    bool settled = false;
    for (int i = 0; i < 300 && !settled; ++i) {
        if (server.session_count() == 0) {
            settled = true;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    CHECK(settled);
    // The session was launched (its thread ran and enforced the gate), never
    // became active, and cleaned up exactly once.
    CHECK_EQ(server.total_session_count(), 1);
    CHECK_EQ(server.session_count(), 0);

    std::atomic<bool> stop_done{false};
    std::thread stopper([&server, &stop_done]() {
        server.Stop();
        stop_done.store(true);
    });
    for (int i = 0; i < 100 && !stop_done.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(stop_done.load());
    if (stop_done.load()) {
        stopper.join();
    } else {
        stopper.detach();
    }
    runner.join();
    CHECK_EQ(server.session_count(), 0);
}

RTSC_TEST(server_concurrent_stop_is_idempotent) {
    // F5: Stop() documents itself as idempotent, but idempotence was only ever
    // exercised sequentially. Two threads stopping the same server at once must
    // both return promptly and converge to zero live sessions -- no deadlock in
    // the registry wait, no double-handoff of the live-count decrement.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    const HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);
    CHECK_EQ(server.session_count(), 1);

    std::atomic<bool> stop1_done{false}, stop2_done{false};
    std::thread s1([&server, &stop1_done]() {
        server.Stop();
        stop1_done.store(true);
    });
    std::thread s2([&server, &stop2_done]() {
        server.Stop();
        stop2_done.store(true);
    });
    for (int i = 0; i < 500 && (!stop1_done.load() || !stop2_done.load()); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(stop1_done.load());
    CHECK(stop2_done.load());
    if (stop1_done.load()) {
        s1.join();
    } else {
        s1.detach();
    }
    if (stop2_done.load()) {
        s2.join();
    } else {
        s2.detach();
    }
    runner.join();

    // Exactly one session was served and counted; the pair of stops released it
    // exactly once.
    CHECK_EQ(server.session_count(), 0);
    CHECK_EQ(server.total_session_count(), 1);
}

// Test-only helper for the flood-vs-Stop case: how long the session-thread
// launcher should pause before starting a body, widening the "registered but
// body not started" window. Defaults to 40 ms; RTSC_TEST_LAUNCH_DELAY_MS
// overrides it (0 = original detach timing, used as a control run).
int launch_delay_ms() {
#if defined(_MSC_VER)
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, "RTSC_TEST_LAUNCH_DELAY_MS") != 0 ||
        buf == nullptr) {
        return 40;
    }
    const int ms = std::atoi(buf);
    std::free(buf);
    return ms;
#else
    const char* v = std::getenv("RTSC_TEST_LAUNCH_DELAY_MS");
    return v == nullptr ? 40 : std::atoi(v);
#endif
}

RTSC_TEST(server_flood_vs_stop_race_converges) {
    // F5: the worst connection shape for Stop() is a connection flood meeting
    // the listener while it closes. Between a session's registration and its
    // body actually starting there is a window; the session_thread_launcher
    // hook widens it so Stop() reliably takes its registry snapshot while
    // sessions are registered-but-not-yet-started. The invariant this guards:
    // Stop() must reap every registered session and converge (live==0) in
    // bounded time, whoever wins the race.
    //
    // Red/green contract: every flood socket is kept open (a silent peer that
    // never finishes the handshake), so each accepted session blocks in its
    // read unless Stop() explicitly stops it. The flood finishes while the
    // listener is still open (a connect to a closed loopback listener costs
    // ~2 s to fail on this host and would dominate the runtime, not the server
    // logic), then Stop() fires while the launcher still holds several bodies
    // in the registered-but-unstarted window. Stop() runs in a background
    // thread and the test waits with a bounded timeout: a Stop() that never
    // returns is a red, never a suite hang.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    constexpr int kConnect = 8;
    const int delay_ms = launch_delay_ms();
    std::atomic<int> launches{0};
    std::atomic<bool> stop_began{false};
    std::atomic<int> started_after_stop{0};
    cfg.session_thread_launcher = [&launches, &stop_began, &started_after_stop,
                                   delay_ms](std::function<void()> body) {
            if (delay_ms > 0) {
                // Widen the "registered but body not started" window: far
                // longer than Stop() needs to take its snapshot, so the
                // snapshot-vs-launch ordering is exercised every run, not by
                // scheduling luck.
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(delay_ms));
            }
            launches.fetch_add(1, std::memory_order_relaxed);
            if (stop_began.load(std::memory_order_relaxed)) {
                // Detached after Stop() had already begun: this session was
                // registered but not yet started when Stop() took its snapshot.
                // A nonzero count is a necessary -- not sufficient -- witness
                // that the amplifier actually widened the window; whether
                // Stop() reaps every registered session is the convergence
                // assertion below, not this stat.
                started_after_stop.fetch_add(1, std::memory_order_relaxed);
            }
            std::thread(std::move(body)).detach();
            return true;
        };
    auto pattern = rtsc::server::MakeTestPatternSource();
    // Heap-owned so a failing (red) run can leak the server instead of hanging
    // the suite in its destructor.
    auto server = std::make_unique<RdpServer>(cfg);
    server->SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server->Start(error));
    std::thread runner([&server]() { server->Run(); });

    std::atomic<bool> flood_done{false};
    std::vector<std::unique_ptr<rtsc::net::Transport>> keep_open;
    std::thread flood([&server, &flood_done, &keep_open]() {
        // Connect-and-hold: the server accepts each connection and registers a
        // session whose body blocks in the never-driven handshake read. The
        // listener is still open here, so every connect completes.
        for (int i = 0; i < kConnect; ++i) {
            std::string e;
            auto t =
                rtsc::net::ConnectTcp("127.0.0.1", server->bound_port(), e);
            if (t) keep_open.push_back(std::move(t));
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        flood_done.store(true);
    });

    bool flood_finished = false;
    for (int i = 0; i < 50 && !flood_done.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    flood_finished = flood_done.load();
    flood.join();

    // Wait until all kConnect sessions are registered (live count raised at
    // registration, before the launcher starts the body). The most recent
    // launcher is then still inside its sleep window: exactly the state Stop()
    // must be able to reap.
    bool all_registered = false;
    for (int i = 0; i < 100 && !all_registered; ++i) {
        if (server->session_count() >= kConnect) {
            all_registered = true;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    std::atomic<bool> stop_done{false};
    stop_began.store(true);
    std::thread stopper([&server, &stop_done]() {
        server->Stop();
        stop_done.store(true);
    });

    // Regression detector: a Stop() that hangs is a red (bounded wait trips),
    // never a suite hang.
    bool stop_cleared = false;
    for (int i = 0; i < 50 && !stop_done.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    stop_cleared = stop_done.load();
    const size_t live = server->session_count();
    std::printf(
        "  flood_vs_stop: stop_5s=%s launches=%d registered=%d live=%zu "
        "total=%zu sockets=%zu delay_ms=%d started_after_stop=%d\n",
        stop_cleared ? "yes" : "RED_TIMEOUT", launches.load(),
        all_registered ? kConnect : -1, live, server->total_session_count(),
        keep_open.size(), delay_ms, started_after_stop.load());
    CHECK(flood_finished);
    CHECK(all_registered);
    CHECK(launches.load() >= kConnect);
    if (delay_ms > 0) {
        // Necessary-not-sufficient witness for the window: at least one body
        // must have been started after Stop() had already begun, otherwise the
        // launcher pause did not actually widen anything. Sufficiency of the
        // reaping is asserted by stop_cleared / live==0 below, not here.
        CHECK(started_after_stop.load() >= 1);
    }
    CHECK(stop_cleared);

    if (!stop_cleared) {
        // Already red above. Close the client sockets so the server sides
        // observe EOF and blocked bodies can drain; only if even that is
        // ineffective do we leak the server to keep the suite alive.
        keep_open.clear();
        for (int i = 0; i < 100 && !stop_done.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (!stop_done.load()) {
            stopper.detach();
            runner.detach();
            (void)server.release();
            return;
        }
        stopper.join();
        runner.join();
        return;
    }
    stopper.join();
    runner.join();
    CHECK_EQ(server->session_count(), 0);
}

// ---- server-side CLIPRDR integration ----------------------------------------

namespace {

// A minimal in-memory clipboard double for the server cliprdr integration
// tests. The server's cliprdr handler reads the negotiated S-clipboard from it.
class ServerClipboard final : public rtsc::clipboard::Clipboard {
 public:
    std::vector<uint32_t> formats() override { return formats_; }
    bool read(uint32_t format, std::vector<uint8_t>& out) override {
        auto it = data_.find(format);
        if (it == data_.end()) return false;
        out = it->second;
        return true;
    }
    bool write(uint32_t format, const std::vector<uint8_t>& data) override {
        data_[format] = data;
        return true;
    }
    uint64_t sequence_number() const override { return 0; }

    std::vector<uint32_t> formats_;
    std::map<uint32_t, std::vector<uint8_t>> data_;
};

// Sends one complete cliprdr message to the server's cliprdr static virtual
// channel (id 1005 for the {"rdpdr","cliprdr","rdpsnd"} client).
void SendCliprdrPdu(HandshakeResult& r, CliprdrMsgType type, uint16_t flags,
                    const std::vector<uint8_t>& body) {
    const auto pdu = BuildCliprdrPdu(type, flags, body);
    for (const auto& chunk : FragmentChannelMessage(pdu)) {
        WriteAll(*r.transport,
                 McsSendData::build_request(r.user_channel, 1005, chunk));
    }
}

// Reads one frame from the active session and hands back its cliprdr PDU, when
// it is one (returns false for a non-cliprdr frame).
bool ReadCliprdrPdu(HandshakeResult& r, CliprdrPdu& out) {
    std::vector<uint8_t> frame;
    if (!r.reader->Read(frame)) return false;
    McsSendData sd;
    if (McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok) {
        return false;
    }
    if (sd.channel_id != 1005) return false;
    if (sd.user_data.size() < ChannelPduHeader::kSize + CliprdrHeader::kSize) {
        return false;
    }
    return CliprdrPdu::parse(sd.user_data.data() + ChannelPduHeader::kSize,
                             sd.user_data.size() - ChannelPduHeader::kSize,
                             out) == Status::Ok;
}

// Sends one complete rdpdr message (a full RDPDR PDU, already carrying its
// 4-byte RDPDR_HEADER) to the server's rdpdr static virtual channel (id 1004
// for the {"rdpdr","cliprdr","rdpsnd"} client).
void SendRdpdrPdu(HandshakeResult& r, const std::vector<uint8_t>& pdu) {
    for (const auto& chunk : FragmentChannelMessage(pdu)) {
        WriteAll(*r.transport,
                 McsSendData::build_request(r.user_channel, 1004, chunk));
    }
}

// Reads one frame from the active session and hands back its rdpdr PDU, when
// it is one (returns false for a non-rdpdr frame).
bool ReadRdpdrPdu(HandshakeResult& r, RdpdrPdu& out) {
    std::vector<uint8_t> frame;
    if (!r.reader->Read(frame)) return false;
    McsSendData sd;
    if (McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok) {
        return false;
    }
    if (sd.channel_id != 1004) return false;
    if (sd.user_data.size() < ChannelPduHeader::kSize + RdpdrHeader::kSize) {
        return false;
    }
    return RdpdrPdu::parse(sd.user_data.data() + ChannelPduHeader::kSize,
                           sd.user_data.size() - ChannelPduHeader::kSize,
                           out) == Status::Ok;
}

// Re-assembles a parsed RDPDR PDU into its full wire bytes (header + data).
std::vector<uint8_t> FullRdpdrPdu(const RdpdrPdu& pdu) {
    ByteWriter w;
    pdu.header.write(w);
    w.bytes(pdu.data.data(), pdu.data.size());
    return w.take();
}

}  // namespace

// S14: the server parses the Client Network Data channel name table, so the
// cliprdr static virtual channel gets id 1005 (1004 + index) and the server's
// cliprdr initialization is delivered on that channel -- not on a sibling
// static channel.
RTSC_TEST(server_cliprdr_name_table_resolves_channel_1005) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    ServerClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetClipboard(&clip);
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    // Drive to active without reading the bitmap: the next frames on the wire
    // are the server's cliprdr initialization (design §1: server speaks first).
    HandshakeResult r = DriveToActive(server.bound_port(), /*send_input=*/false,
                                      64, 48, /*expect_frame=*/false);
    CHECK(r.reached_active);

    // Clipboard Capabilities, Monitor Ready, Format List, in order, all on the
    // cliprdr channel (1005), never on 1004 (rdpdr) or 1006 (rdpsnd).
    CliprdrPdu pdu;
    CHECK(ReadCliprdrPdu(r, pdu));
    CHECK(pdu.header.msg_type == CliprdrMsgType::kClipCaps);
    CHECK(ReadCliprdrPdu(r, pdu));
    CHECK(pdu.header.msg_type == CliprdrMsgType::kMonitorReady);
    CHECK(ReadCliprdrPdu(r, pdu));
    CHECK(pdu.header.msg_type == CliprdrMsgType::kFormatList);

    server.Stop();
    runner.join();
}

// S15: the active loop routes by MCS channel id -- the cliprdr channel feeds
// the CliprdrServer handler (a served Format Data Request round-trips), the
// I/O channel keeps the input path, and an unregistered static channel is
// ignored without disturbing the session.
RTSC_TEST(server_cliprdr_active_loop_three_way_dispatch) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    ServerClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    const std::vector<uint8_t> text = {0x48, 0x00, 0x69, 0x00};
    clip.data_[kCfUnicodeText] = text;
    std::atomic<int> key_events{0};
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetClipboard(&clip);
    server.SetInputCallback([&](const rtsc::server::InputEvent& ev) {
        if (ev.kind == rtsc::server::InputEvent::Kind::kKey) {
            key_events.fetch_add(1);
        }
    });
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult r = DriveToActive(server.bound_port(), /*send_input=*/false,
                                      64, 48, /*expect_frame=*/false);
    CHECK(r.reached_active);

    // 1. Cliprdr channel: a client Format Data Request is served by the
    //    CliprdrServer handler and the answer comes back on channel 1005. The
    //    server's own initialization (caps / monitor-ready / format list) and
    //    the first desktop frame are already buffered ahead of the answer, so
    //    the loop skips them.
    {
        ByteWriter body;
        body.u32le(kCfUnicodeText);
        SendCliprdrPdu(r, CliprdrMsgType::kFormatDataRequest, 0, body.take());
        CliprdrPdu resp;
        bool found = false;
        for (int i = 0; i < 20 && !found; ++i) {
            CliprdrPdu p;
            if (ReadCliprdrPdu(r, p) &&
                p.header.msg_type == CliprdrMsgType::kFormatDataResponse) {
                resp = p;
                found = true;
            }
        }
        CHECK(found);
        CHECK_EQ(resp.header.msg_flags,
                 static_cast<uint16_t>(rtsc::proto::kClipResponseOk));
        CHECK(std::equal(text.begin(), text.end(), resp.data.begin()));
    }

    // 2. An unregistered static channel (1006 / rdpsnd, no server handler) is
    //    ignored: garbage on it must not produce a response and must not kill
    //    the session. (The rdpdr channel, 1004, is registered and routed to
    //    the RdpdrServer handler -- covered by server_rdpdr_channel_routes_
    //    to_rdpdr_handler.)
    WriteAll(*r.transport,
             McsSendData::build_request(r.user_channel, 1006,
                                        std::vector<uint8_t>{0xDE, 0xAD, 0xBE}));

    // 3. The I/O channel still runs the original input path: a fast-path input
    //    event reaches the callback, proving the session survived step 2.
    WriteAll(*r.transport,
             McsSendData::build_request(
                 r.user_channel, r.io_channel,
                 EncodeFastPathInputPdu(
                     {EncodeKeyboardEvent(0x1E, false, false)})));
    for (int i = 0; i < 100 && key_events.load() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(key_events.load() >= 1);

    server.Stop();
    runner.join();
}

// S16: the active loop routes the rdpdr static virtual channel (1004 for the
// {"rdpdr","cliprdr","rdpsnd"} client) into the RdpdrServer handler: the
// server's Server Announce is delivered on 1004, and a client announce reply
// is answered on 1004 with the Server Capability / ClientId Confirm /
// User LoggedOn batch. The client capability and device list that follow are
// consumed without producing any rdpdr traffic.
RTSC_TEST(server_rdpdr_channel_routes_to_rdpdr_handler) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult r = DriveToActive(server.bound_port(), /*send_input=*/false,
                                      64, 48, /*expect_frame=*/false);
    CHECK(r.reached_active);

    // 1. The Server Announce arrives on the rdpdr channel (1004); the cliprdr
    //    initialization and the first desktop frame are skipped.
    RdpdrPdu announce;
    bool got_announce = false;
    for (int i = 0; i < 20 && !got_announce; ++i) {
        if (ReadRdpdrPdu(r, announce)) got_announce = true;
    }
    CHECK(got_announce);
    CHECK(announce.header.packet_id == kPakidCoreServerAnnounce);
    RdpdrServerAnnounce ann;
    CHECK(RdpdrServerAnnounce::parse(FullRdpdrPdu(announce).data(),
                                     FullRdpdrPdu(announce).size(), ann) ==
          Status::Ok);
    CHECK_EQ(ann.version_major, static_cast<uint16_t>(1));
    CHECK(ann.client_id != 0);

    // 2. The client announce reply is routed into the handler, which answers
    //    back on 1004: Server Capability, then ClientId Confirm, then User
    //    LoggedOn.
    RdpdrClientAnnounceReply reply;
    reply.version_major = 1;
    reply.version_minor = 0x000C;
    reply.client_id = ann.client_id;
    SendRdpdrPdu(r, reply.encode());

    RdpdrPdu pdu;
    std::vector<uint16_t> batch;
    for (int i = 0; i < 20 && batch.size() < 3; ++i) {
        if (ReadRdpdrPdu(r, pdu)) batch.push_back(pdu.header.packet_id);
    }
    const std::vector<uint16_t> want = {
        kPakidCoreServerCapability, kPakidCoreClientidConfirm,
        kPakidCoreUserLoggedon};
    CHECK(batch == want);

    // 3. The client's capability and (empty) device list are consumed without
    //    an answer: no rdpdr frame appears inside a short window.
    {
        RdpdrGeneralCapsSet general_body;
        general_body.protocol_major_version = 1;
        general_body.protocol_minor_version = 0x000C;
        general_body.io_code1 = 0x00003FFF;
        general_body.extended_pdu = kRdpdrUserLoggedonPdu;
        RdpdrCapabilitySet general;
        general.header.capability_type = kCapGeneralType;
        general.header.version = kGeneralCapabilityVersion02;
        general.data = general_body.encode(general.header.version);
        general.header.capability_length = static_cast<uint16_t>(
            RdpdrCapabilityHeader::kSize + general.data.size());
        RdpdrCoreCapability caps;
        caps.capabilities.push_back(general);
        SendRdpdrPdu(r, caps.encode());
        RdpdrDeviceListAnnounce list;  // deviceCount = 0
        SendRdpdrPdu(r, list.encode());
    }

    std::vector<uint8_t> frame;
    FrameReader no_rdpdr(*r.transport, std::chrono::milliseconds(400));
    bool rdpdr_seen = false;
    while (no_rdpdr.Read(frame)) {
        McsSendData sd;
        if (McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok) {
            continue;
        }
        if (sd.channel_id == 1004) {
            rdpdr_seen = true;
            break;
        }
    }
    CHECK(!rdpdr_seen);

    server.Stop();
    runner.join();
}

int main() { return rtsc::test::run_all("rtsc_server_tests"); }
