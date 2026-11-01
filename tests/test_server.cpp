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
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <set>
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
#include "rtsc/server/desktop_input.h"
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
    // Input Capability Set advertised by the server's Demand Active (P-9).
    bool got_input_caps = false;
    uint16_t input_flags = 0;
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
    if (const auto* input = da.capabilities.find(CapabilityType::kInput)) {
        InputCapabilitySet i;
        if (InputCapabilitySet::parse(*input, i) == Status::Ok) {
            r.input_flags = i.input_flags;
            r.got_input_caps = true;
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

// ---- Desktop input sink test double ---------------------------------------

// Records every sink call so a test can prove which session actually reached
// the injection seam. All methods copy under one mutex: Inject runs on a
// session thread while the test reads the snapshots.
class RecordingInputSink final : public rtsc::server::DesktopInputSink {
 public:
    void SetGeometry(uint32_t session_id,
                     const rtsc::server::InjectGeometry& g) override {
        std::lock_guard<std::mutex> lock(mu_);
        geometry_ids_.push_back(session_id);
        geometry_width_ = g.width;
        geometry_height_ = g.height;
    }

    void Inject(uint32_t session_id,
                const rtsc::server::InputEvent& ev) override {
        std::lock_guard<std::mutex> lock(mu_);
        inject_ids_.push_back(session_id);
        last_event_ = ev;
    }

    void ReleaseSession(uint32_t session_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        release_ids_.push_back(session_id);
    }

    rtsc::server::InputStats Stats() const override { return {}; }

    std::vector<uint32_t> inject_ids() const {
        std::lock_guard<std::mutex> lock(mu_);
        return inject_ids_;
    }
    std::vector<uint32_t> geometry_ids() const {
        std::lock_guard<std::mutex> lock(mu_);
        return geometry_ids_;
    }
    std::vector<uint32_t> release_ids() const {
        std::lock_guard<std::mutex> lock(mu_);
        return release_ids_;
    }
    uint16_t geometry_width() const {
        std::lock_guard<std::mutex> lock(mu_);
        return geometry_width_;
    }
    uint16_t geometry_height() const {
        std::lock_guard<std::mutex> lock(mu_);
        return geometry_height_;
    }

 private:
    mutable std::mutex mu_;
    std::vector<uint32_t> inject_ids_;
    std::vector<uint32_t> geometry_ids_;
    std::vector<uint32_t> release_ids_;
    uint16_t geometry_width_ = 0;
    uint16_t geometry_height_ = 0;
    rtsc::server::InputEvent last_event_;
};

// A sink that widens the ReleaseInput hand-off window on purpose. The server
// must call ReleaseSession BEFORE it frees the lease slot. Releasing the sink
// first queues the old session's synthetic key/button ups while the lease is
// still held; freeing the lease first lets another session acquire it and
// enqueue a key-down that the worker may emit before those ups (lifting the new
// holder's key). ReleaseSession here blocks (briefly) so an Inject from another
// session that slips into that window is observed deterministically.
class ReleaseOrderingSink final : public rtsc::server::DesktopInputSink {
 public:
    void SetGeometry(uint32_t session_id,
                     const rtsc::server::InjectGeometry& g) override {
        (void)session_id;
        (void)g;
    }

    void Inject(uint32_t session_id,
                const rtsc::server::InputEvent& ev) override {
        (void)ev;
        std::lock_guard<std::mutex> lock(mu_);
        inject_ids_.push_back(session_id);
        if (armed_ && release_started_ && !release_finished_) {
            ++injects_during_release_;
        }
        cv_.notify_all();
    }

    void ReleaseSession(uint32_t session_id) override {
        std::unique_lock<std::mutex> lock(mu_);
        release_ids_.push_back(session_id);
        if (armed_ && !release_started_) {
            release_started_ = true;
            // Timeout only matters when the fix is in place (no Inject may
            // happen while the lease is still held); with the bug the Inject
            // arrives at once and wakes this up.
            cv_.wait_for(lock, std::chrono::milliseconds(500), [this]() {
                return injects_during_release_ > 0;
            });
            release_finished_ = true;
        }
        cv_.notify_all();
    }

    rtsc::server::InputStats Stats() const override { return {}; }

    void ArmReleaseProbe() {
        std::lock_guard<std::mutex> lock(mu_);
        armed_ = true;
        release_started_ = false;
        release_finished_ = false;
        injects_during_release_ = 0;
    }

    std::vector<uint32_t> inject_ids() const {
        std::lock_guard<std::mutex> lock(mu_);
        return inject_ids_;
    }

    std::vector<uint32_t> release_ids() const {
        std::lock_guard<std::mutex> lock(mu_);
        return release_ids_;
    }

    size_t injects_during_release() const {
        std::lock_guard<std::mutex> lock(mu_);
        return injects_during_release_;
    }

 private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::vector<uint32_t> inject_ids_;
    std::vector<uint32_t> release_ids_;
    bool armed_ = false;
    bool release_started_ = false;
    bool release_finished_ = false;
    size_t injects_during_release_ = 0;
};

// A sink whose ReleaseSession can be made to throw, like the real backend when
// the synthetic-up append hits std::bad_alloc. Teardown must survive that
// exception AND still free the lease slot: a leaked slot denies every later
// session forever.
class ReleaseThrowingSink final : public rtsc::server::DesktopInputSink {
 public:
    explicit ReleaseThrowingSink(bool throw_on_release)
        : throw_on_release_(throw_on_release) {}

    void SetGeometry(uint32_t session_id,
                     const rtsc::server::InjectGeometry& g) override {
        (void)session_id;
        (void)g;
    }

    void Inject(uint32_t session_id,
                const rtsc::server::InputEvent& ev) override {
        (void)ev;
        std::lock_guard<std::mutex> lock(mu_);
        inject_ids_.push_back(session_id);
    }

    void ReleaseSession(uint32_t session_id) override {
        {
            std::lock_guard<std::mutex> lock(mu_);
            release_ids_.push_back(session_id);
        }
        if (throw_on_release_) throw std::bad_alloc();
    }

    rtsc::server::InputStats Stats() const override { return {}; }

    std::vector<uint32_t> inject_ids() const {
        std::lock_guard<std::mutex> lock(mu_);
        return inject_ids_;
    }

    std::vector<uint32_t> release_ids() const {
        std::lock_guard<std::mutex> lock(mu_);
        return release_ids_;
    }

 private:
    mutable std::mutex mu_;
    std::vector<uint32_t> inject_ids_;
    std::vector<uint32_t> release_ids_;
    bool throw_on_release_;
};

size_t DistinctIds(const std::vector<uint32_t>& ids) {
    return std::set<uint32_t>(ids.begin(), ids.end()).size();
}

size_t CountId(const std::vector<uint32_t>& ids, uint32_t id) {
    size_t n = 0;
    for (const uint32_t v : ids) {
        if (v == id) ++n;
    }
    return n;
}

bool WaitUntil(const std::function<bool()>& pred, int timeout_ms = 5000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return pred();
}

bool SendTestInput(const HandshakeResult& r) {
    return WriteAll(*r.transport,
                    McsSendData::build_request(
                        r.user_channel, r.io_channel,
                        EncodeFastPathInputPdu(
                            {EncodeKeyboardEvent(0x1E, false, false)})));
}

// One lease hand-off cycle: the first session takes the single lease and
// injects, then disconnects; the survivor must be able to take the freed slot.
// Returns true when the holder reached the sink at least once. `released`
// reports that the holder's ReleaseSession ran, `handed_off` that the survivor
// then acquired the lease.
bool RunLeaseHandoffProbe(bool throw_on_release, bool* released,
                          bool* handed_off, size_t* release_failures) {
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    cfg.enable_desktop_input = true;
    cfg.max_input_sessions = 1;

    ReleaseThrowingSink sink(throw_on_release);
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetInputSink(&sink);

    std::string error;
    if (!server.Start(error)) return false;
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult first =
        DriveToActive(server.bound_port(), false, 64, 48, /*expect_frame=*/false);
    HandshakeResult second =
        DriveToActive(server.bound_port(), false, 64, 48, /*expect_frame=*/false);
    if (!first.reached_active || !second.reached_active) {
        server.Stop();
        runner.join();
        return false;
    }

    // The first session takes the lease and reaches the sink.
    bool holder_injected = false;
    for (int i = 0; i < 300 && !holder_injected; ++i) {
        SendTestInput(first);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        holder_injected = !sink.inject_ids().empty();
    }
    const std::vector<uint32_t> injected = sink.inject_ids();
    const uint32_t holder = injected.empty() ? 0 : injected.front();

    // Disconnect the holder: teardown calls ReleaseSession (which may throw).
    first.reader.reset();
    first.transport->Close();
    first.transport.reset();
    *released = holder != 0 && WaitUntil([&sink, holder]() {
        return CountId(sink.release_ids(), holder) == 1;
    });
    if (release_failures != nullptr) {
        // ReleaseSession records the id before it throws, so give the teardown
        // a moment to reach the catch that counts the failure.
        if (throw_on_release) {
            WaitUntil([&server]() {
                return server.input_release_failure_count() != 0;
            });
        }
        *release_failures = server.input_release_failure_count();
    }

    // The survivor must acquire the freed slot. A leaked slot denies it on
    // every attempt, so a distinct session id never reaches Inject.
    *handed_off = false;
    for (int i = 0; i < 200 && !*handed_off; ++i) {
        SendTestInput(second);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        *handed_off = DistinctIds(sink.inject_ids()) == 2;
    }

    server.Stop();
    runner.join();
    return holder_injected;
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

RTSC_TEST(server_advertises_fastpath_input_capability) {
    // P-9: this server implements fast-path input decoding only, so its Demand
    // Active Input Capability Set ([MS-RDPBCGR] 2.2.7.1.6) MUST advertise
    // fast-path support:
    //   INPUT_FLAG_FASTPATH_INPUT  0x0008 (RDP 5.0/5.1 servers)
    //   INPUT_FLAG_FASTPATH_INPUT2 0x0020 ("Advertised by all RDP servers,
    //                               except for RDP 4.0, 5.0, and 5.1 servers")
    // 0x0020 is what a modern client checks before it switches to fast-path;
    // without it mstsc falls back to slow-path input, which used to be dropped.
    //
    // 0x0002 is NOT a flag of the Input Capability Set: the specification's
    // flag table has no such value (0x0001 SCANCODES, 0x0004 MOUSEX, 0x0008,
    // 0x0010 UNICODE, 0x0020, 0x0040 UNUSED1, 0x0080 MOUSE_RELATIVE,
    // 0x0100 MOUSE_HWHEEL, 0x0200 QOE_TIMESTAMPS). The historical repo constant
    // kInputFlagMouse = 0x0002 must never reach the wire.
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
    CHECK(r.got_input_caps);
    CHECK((r.input_flags & 0x0001) != 0);  // INPUT_FLAG_SCANCODES (MUST)
    CHECK((r.input_flags & 0x0008) != 0);  // INPUT_FLAG_FASTPATH_INPUT
    CHECK((r.input_flags & 0x0020) != 0);  // INPUT_FLAG_FASTPATH_INPUT2
    CHECK((r.input_flags & 0x0002) == 0);  // no such flag in the specification
    CHECK((r.input_flags & 0x0100) != 0);  // MOUSE_HWHEEL (HWHEEL is decoded)
    CHECK((r.input_flags & 0x0010) != 0);  // UNICODE (Unicode events are decoded)

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
        bool x1_up = false, x2_up = false;
        bool release_lost_button = false;
        bool release_flagged_move = false;
    } seen;
    for (int i = 0;
         i < 100 && !(seen.x1_down && seen.x2_down && seen.left_down &&
                      seen.x1_up && seen.x2_up);
         ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(mu);
        for (const auto& ev : events) {
            if (ev.kind != rtsc::server::InputEvent::Kind::kMouse) continue;
            if (ev.button_down) {
                if (ev.button == 4) seen.x1_down = true;
                if (ev.button == 5) seen.x2_down = true;
                if (ev.button == 1) seen.left_down = true;
                continue;
            }
            // P-5: a release carries the SAME button bit as its press, just
            // without PTRFLAGS_DOWN ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.3/.4). The
            // previous assertion only counted "some non-down mouse event",
            // which froze the lost-button defect (button=0) as the expectation.
            if (ev.button == 0) seen.release_lost_button = true;
            if (ev.is_move) seen.release_flagged_move = true;
            if (ev.button == 4) seen.x1_up = true;
            if (ev.button == 5) seen.x2_up = true;
        }
    }
    CHECK(seen.x1_down);   // PTRXFLAGS_BUTTON1 (0x0001) -> X1, not left
    CHECK(seen.x2_down);   // PTRXFLAGS_BUTTON2 (0x0002) -> X2, not right
    CHECK(seen.left_down);  // the plain POINTER left path is untouched
    CHECK(seen.x1_up);      // X1 release keeps its button identity
    CHECK(seen.x2_up);      // X2 release keeps its button identity
    CHECK(!seen.release_lost_button);
    CHECK(!seen.release_flagged_move);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_input_qoe_timestamp_is_not_an_input_event) {
    // P-4: the QoE timestamp (eventCode 0x6) is metadata, not an input event
    // ([MS-RDPBCGR] 2.2.8.1.2.2.6). It used to consume its 4 bytes and fall
    // through to the callback with a default-constructed InputEvent
    // (kind=kKey, scancode=0), i.e. a phantom key press.
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

    auto snapshot = [&]() {
        std::lock_guard<std::mutex> lock(mu);
        return events;
    };

    // QoE first, then a real key in its own PDU: the key proves the QoE PDU
    // was already parsed, so a phantom callback cannot arrive afterwards.
    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel,
                                     EncodeFastPathInputPdu(
                                         {EncodeQoeTimestampEvent(0x11223344)}))));
    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel,
                                     EncodeFastPathInputPdu(
                                         {EncodeKeyboardEvent(0x1E, false, false)}))));
    for (int i = 0; i < 100 && snapshot().size() < 1; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    const auto got = snapshot();
    CHECK_EQ(got.size(), static_cast<size_t>(1));
    if (got.size() == 1) {
        CHECK(got[0].kind == rtsc::server::InputEvent::Kind::kKey);
        CHECK_EQ(got[0].scancode, static_cast<uint8_t>(0x1E));
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_input_relative_mouse_keeps_signed_deltas) {
    // P-3: TS_FP_RELPOINTER_EVENT (eventCode 0x5) carries SIGNED i16
    // xDelta/yDelta ([MS-RDPBCGR] 2.2.8.1.2.2.7). It must surface as a
    // kMouseRel event, never as the default kind=kKey phantom.
    //
    // It must NOT set is_move: is_move is the kMouse PTRFLAGS_MOVE contract
    // ("move the pointer to (x, y)") and a relative event has x = y = 0, so a
    // consumer honouring the contract would teleport the cursor to (0, 0).
    // A relative event's movement lives in rel_x/rel_y and is identified by
    // kind == kMouseRel.
    //
    // Its pointerFlags are IDENTICAL to TS_RELPOINTER_EVENT's
    // ([MS-RDPBCGR] 2.2.8.1.2.2.7: "The possible flags are identical to those
    // found in the pointerFlags field of the TS_RELPOINTER_EVENT structure"),
    // and that table lists PTRXFLAGS_BUTTON1 0x0001 / PTRXFLAGS_BUTTON2 0x0002
    // ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.7), so 0x0001/0x0002 are the X1/X2 buttons
    // here too: 4 and 5, with PTRFLAGS_DOWN 0x8000 selecting press vs release.
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

    auto snapshot = [&]() {
        std::lock_guard<std::mutex> lock(mu);
        return events;
    };

    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel,
                                     EncodeFastPathInputPdu({
                                         EncodeRelativeMouseEvent(0x0001, 10, -5),
                                         EncodeRelativeMouseEvent(0x0002, 0, 0),
                                         EncodeRelativeMouseEvent(0x8002, 0, 0),
                                         EncodeRelativeMouseEvent(0x8001, 0, 0),
                                     }))));
    for (int i = 0; i < 100 && snapshot().size() < 4; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    const auto got = snapshot();
    CHECK_EQ(got.size(), static_cast<size_t>(4));
    if (got.size() == 4) {
        CHECK(got[0].kind == rtsc::server::InputEvent::Kind::kMouseRel);
        CHECK_EQ(got[0].rel_x, static_cast<int16_t>(10));
        CHECK_EQ(got[0].rel_y, static_cast<int16_t>(-5));
        CHECK(!got[0].is_move);   // relative is NOT an absolute move
        CHECK_EQ(got[0].x, static_cast<uint16_t>(0));
        CHECK_EQ(got[0].y, static_cast<uint16_t>(0));
        // PTRXFLAGS_BUTTON1 (0x0001), no DOWN => X1 release.
        CHECK_EQ(got[0].button, static_cast<uint16_t>(4));
        CHECK(!got[0].button_down);

        // PTRXFLAGS_BUTTON2 (0x0002), no DOWN => X2 release.
        CHECK(got[1].kind == rtsc::server::InputEvent::Kind::kMouseRel);
        CHECK_EQ(got[1].button, static_cast<uint16_t>(5));
        CHECK(!got[1].button_down);
        CHECK(!got[1].is_move);
        CHECK_EQ(got[1].x, static_cast<uint16_t>(0));
        CHECK_EQ(got[1].y, static_cast<uint16_t>(0));

        // PTRFLAGS_DOWN | PTRXFLAGS_BUTTON2 => X2 press.
        CHECK(got[2].kind == rtsc::server::InputEvent::Kind::kMouseRel);
        CHECK_EQ(got[2].button, static_cast<uint16_t>(5));
        CHECK(got[2].button_down);
        CHECK(!got[2].is_move);
        CHECK_EQ(got[2].x, static_cast<uint16_t>(0));
        CHECK_EQ(got[2].y, static_cast<uint16_t>(0));

        // PTRFLAGS_DOWN | PTRXFLAGS_BUTTON1 => X1 press.
        CHECK(got[3].kind == rtsc::server::InputEvent::Kind::kMouseRel);
        CHECK_EQ(got[3].button, static_cast<uint16_t>(4));
        CHECK(got[3].button_down);
        CHECK(!got[3].is_move);
        CHECK_EQ(got[3].x, static_cast<uint16_t>(0));
        CHECK_EQ(got[3].y, static_cast<uint16_t>(0));
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_input_relative_qoe_pointer_sequence_keeps_order) {
    // Regression anchor for the mixed stream: the relative event is delivered,
    // the QoE timestamp is dropped, and the pointer press follows. The old
    // decoder produced three callbacks (two phantom kKey events) here.
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

    auto snapshot = [&]() {
        std::lock_guard<std::mutex> lock(mu);
        return events;
    };

    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel,
                                     EncodeFastPathInputPdu({
                                         EncodeRelativeMouseEvent(kPtrMove, -3, 7),
                                         EncodeQoeTimestampEvent(42),
                                         EncodeMouseEvent(0x9000, 30, 40, false),
                                     }))));
    for (int i = 0; i < 100 && snapshot().size() < 2; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    const auto got = snapshot();
    CHECK_EQ(got.size(), static_cast<size_t>(2));
    if (got.size() == 2) {
        CHECK(got[0].kind == rtsc::server::InputEvent::Kind::kMouseRel);
        CHECK_EQ(got[0].rel_x, static_cast<int16_t>(-3));
        CHECK_EQ(got[0].rel_y, static_cast<int16_t>(7));
        CHECK(got[1].kind == rtsc::server::InputEvent::Kind::kMouse);
        CHECK_EQ(got[1].button, static_cast<uint16_t>(1));
        CHECK(got[1].button_down);
        CHECK_EQ(got[1].x, static_cast<uint16_t>(30));
        CHECK_EQ(got[1].y, static_cast<uint16_t>(40));
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_input_pointer_move_and_release_are_distinguishable) {
    // P-5: PTRFLAGS_MOVE (0x0800) and a button release both used to decode as
    // button=0, button_down=false, so the injector could not tell "move the
    // pointer" from "release the left button".
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

    auto snapshot = [&]() {
        std::lock_guard<std::mutex> lock(mu);
        return events;
    };

    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel,
                                     EncodeFastPathInputPdu({
                                         EncodeMouseEvent(kPtrMove, 5, 6),  // move
                                         EncodeMouseEvent(0x1000, 10, 20),  // left up
                                         EncodeMouseEvent(0x9000, 30, 40),  // left down
                                     }))));
    for (int i = 0; i < 100 && snapshot().size() < 3; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    const auto got = snapshot();
    CHECK_EQ(got.size(), static_cast<size_t>(3));
    if (got.size() == 3) {
        CHECK(got[0].kind == rtsc::server::InputEvent::Kind::kMouse);
        CHECK(got[0].is_move);          // pure move
        CHECK(!got[0].button_down);
        CHECK_EQ(got[0].button, static_cast<uint16_t>(0));

        CHECK(got[1].kind == rtsc::server::InputEvent::Kind::kMouse);
        CHECK(!got[1].is_move);         // release, not a move
        CHECK(!got[1].button_down);
        CHECK_EQ(got[1].button, static_cast<uint16_t>(1));  // identity kept

        CHECK(got[2].kind == rtsc::server::InputEvent::Kind::kMouse);
        CHECK(!got[2].is_move);
        CHECK(got[2].button_down);
        CHECK_EQ(got[2].button, static_cast<uint16_t>(1));
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_input_extended_flags_are_prefixes) {
    // P-6: FASTPATH_INPUT_KBDFLAGS_EXTENDED (0x02) means "the keyCode is
    // prefixed by 0xE0"; it is a flag, never the value 0x100 added to the
    // scancode. FASTPATH_INPUT_KBDFLAGS_EXTENDED1 (0x04) is the 0xE1 prefix
    // carried by the PAUSE sequence's CTRL events
    // ([MS-RDPBCGR] 2.2.8.1.2.2.1; docs/spec/share-data.md 3.6.1).
    // Pause injection itself stays UNVERIFIED (SendInput cannot express 0xE1);
    // this test only locks the decoded fields.
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

    auto snapshot = [&]() {
        std::lock_guard<std::mutex> lock(mu);
        return events;
    };

    std::vector<std::vector<uint8_t>> seq = EncodePauseKey();
    seq.push_back(EncodeKeyboardEvent(kScancodeEnd, false, true));  // E0 0x4F
    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel,
                                     EncodeFastPathInputPdu(seq))));
    for (int i = 0; i < 100 && snapshot().size() < 5; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    const auto got = snapshot();
    CHECK_EQ(got.size(), static_cast<size_t>(5));
    if (got.size() == 5) {
        // CTRL down / NUMLOCK down / CTRL up / NUMLOCK up (the 0xE1 pair).
        CHECK(got[0].kind == rtsc::server::InputEvent::Kind::kKey);
        CHECK_EQ(got[0].scancode, static_cast<uint8_t>(0x1D));
        CHECK(!got[0].extended);
        CHECK(got[0].extended1);
        CHECK(!got[0].release);

        CHECK_EQ(got[1].scancode, static_cast<uint8_t>(0x45));
        CHECK(!got[1].extended);
        CHECK(!got[1].extended1);

        CHECK_EQ(got[2].scancode, static_cast<uint8_t>(0x1D));
        CHECK(!got[2].extended);
        CHECK(got[2].extended1);
        CHECK(got[2].release);

        CHECK_EQ(got[3].scancode, static_cast<uint8_t>(0x45));
        CHECK(got[3].release);

        // E0-prefixed End: the flag is set, the scancode stays 0x4F.
        CHECK_EQ(got[4].scancode, static_cast<uint8_t>(0x4F));
        CHECK(got[4].extended);
        CHECK(!got[4].extended1);
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_pause_sequence_is_not_injected) {
    // P-6/K1: the whole PAUSE sequence (04 1D / 00 45 / 05 1D / 01 45) is
    // unrepresentable. Dropping only the two 0xE1-prefixed CTRL halves still
    // injects the bare NUMLOCK(0x45) down/up, which toggles the local NumLock.
    // The session filter must swallow all four BEFORE the lease gate, so the
    // sink sees none of them -- and a real NumLock tap right after is still
    // injected twice, proving the filter is sequence state, not "drop 0x45".
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    cfg.enable_desktop_input = true;
    cfg.max_input_sessions = 1;

    RecordingInputSink sink;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetInputSink(&sink);

    std::mutex mu;
    size_t decoded = 0;
    server.SetInputCallback([&](const rtsc::server::InputEvent&) {
        std::lock_guard<std::mutex> lock(mu);
        ++decoded;
    });

    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    const HandshakeResult r = DriveToActive(server.bound_port(), false, 64, 48,
                                            /*expect_frame=*/false);
    CHECK(r.reached_active);

    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel,
                                     EncodeFastPathInputPdu(EncodePauseKey()))));
    // Wait until the whole PDU is decoded: the input callback still observes
    // every event (suppression happens only at the injection seam).
    CHECK(WaitUntil([&mu, &decoded]() {
        std::lock_guard<std::mutex> lock(mu);
        return decoded >= 4;
    }));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    // None of the four events reached the sink and none took the lease.
    CHECK(sink.inject_ids().empty());
    CHECK(sink.geometry_ids().empty());
    CHECK_EQ(server.input_lease_denied_count(), static_cast<size_t>(0));

    // A standalone NumLock tap is a real key: it must inject twice.
    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel,
                                     EncodeFastPathInputPdu(
                                         {EncodeKeyboardEvent(0x45, false, false),
                                          EncodeKeyboardEvent(0x45, false, true)}))));
    CHECK(WaitUntil([&sink]() { return sink.inject_ids().size() >= 2; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    CHECK_EQ(sink.inject_ids().size(), static_cast<size_t>(2));

    server.Stop();
    runner.join();
}

RTSC_TEST(server_input_unknown_event_code_is_counted) {
    // P-11: [MS-RDPBCGR] 2.2.8.1.2.2 says the server SHOULD drop the
    // connection for an unknown eventCode. This repo deliberately stays
    // lenient (SHOULD is not MUST: a lenient session lets a capture identify
    // the offending client version) but must count the event. Its size is
    // unknown, so the rest of that PDU is abandoned.
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

    auto snapshot = [&]() {
        std::lock_guard<std::mutex> lock(mu);
        return events;
    };

    const size_t before = server.unknown_input_event_count();
    // eventHeader 0xE0 -> eventCode [7:5] = 0x7, an undefined type.
    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel,
                                     EncodeFastPathInputPdu({{0xE0}}))));
    // A following valid key proves the connection was not dropped.
    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel,
                                     EncodeFastPathInputPdu(
                                         {EncodeKeyboardEvent(0x1E, false, false)}))));
    for (int i = 0; i < 100 && snapshot().size() < 1; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    CHECK_EQ(server.unknown_input_event_count(), before + 1);
    const auto got = snapshot();
    CHECK_EQ(got.size(), static_cast<size_t>(1));
    if (got.size() == 1) {
        CHECK(got[0].kind == rtsc::server::InputEvent::Kind::kKey);
        CHECK_EQ(got[0].scancode, static_cast<uint8_t>(0x1E));
    }

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
        // Malformed WHEEL|DOWN|BUTTON1 with bogus coordinates: a wheel event
        // must ignore the other pointer flags and xPos/yPos
        // ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.3).
        rtsc::proto::EncodeMouseEvent(0x9200, 123, 456),
    });
    CHECK(WriteAll(*r.transport, McsSendData::build_request(
                                     r.user_channel, r.io_channel, fp)));

    std::vector<rtsc::server::InputEvent> wheels;
    for (int i = 0; i < 100 && wheels.size() < 6; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(mu);
        wheels.clear();
        for (const auto& ev : events) {
            if (ev.kind == rtsc::server::InputEvent::Kind::kWheel) {
                wheels.push_back(ev);
            }
        }
    }
    CHECK_EQ(wheels.size(), static_cast<size_t>(6));
    if (wheels.size() == 6) {
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
        // xPos/yPos are ignored for wheel events: never carried through.
        for (const auto& w : wheels) {
            CHECK_EQ(w.x, static_cast<uint16_t>(0));
            CHECK_EQ(w.y, static_cast<uint16_t>(0));
        }
        // WHEEL|DOWN|BUTTON1 is malformed: the wheel kind must not expose a
        // button state (the injection seam would otherwise emit a click).
        CHECK_EQ(wheels[5].button, static_cast<uint16_t>(0));
        CHECK(!wheels[5].button_down);
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

// ---- Slow-path input construction (P-10) ------------------------------------
//
// TS_INPUT_PDU_DATA ([MS-RDPBCGR] 2.2.8.1.1.3.1) = numEvents(2) +
// pad2Octets(2) + numEvents x TS_INPUT_EVENT, and TS_INPUT_EVENT
// (2.2.8.1.1.3.1.1) = eventTime(4) + messageType(2) + a 6-byte event body.
// The messageType values are the specification's, NOT a 0..4 sequence:
//   0x0000 SYNC, 0x0002 UNUSED, 0x0004 SCANCODE, 0x0005 UNICODE,
//   0x8001 MOUSE, 0x8002 MOUSEX, 0x8004 MOUSEREL.
// The event bodies are written with an explicit length so a test can build a
// malformed one on purpose.

std::vector<uint8_t> SlowPathInputEvent(uint16_t message_type,
                                        const std::vector<uint8_t>& body) {
    ByteWriter w;
    w.u32le(0);             // eventTime: ignored by the server
    w.u16le(message_type);  // messageType
    for (uint8_t b : body) w.u8(b);
    return w.take();
}

// TS_KEYBOARD_EVENT: keyboardFlags(2) + keyCode(2) + pad2Octets(2).
std::vector<uint8_t> SlowPathKeyboardBody(uint16_t flags, uint16_t key_code) {
    ByteWriter w;
    w.u16le(flags);
    w.u16le(key_code);
    w.u16le(0);  // pad2Octets
    return w.take();
}

// TS_UNICODE_KEYBOARD_EVENT: keyboardFlags(2) + unicodeCode(2) + pad(2).
std::vector<uint8_t> SlowPathUnicodeBody(uint16_t flags, uint16_t code) {
    ByteWriter w;
    w.u16le(flags);
    w.u16le(code);
    w.u16le(0);  // pad2Octets
    return w.take();
}

// TS_POINTER_EVENT / TS_POINTERX_EVENT: pointerFlags(2) + xPos(2) + yPos(2).
std::vector<uint8_t> SlowPathPointerBody(uint16_t flags, uint16_t x,
                                         uint16_t y) {
    ByteWriter w;
    w.u16le(flags);
    w.u16le(x);
    w.u16le(y);
    return w.take();
}

// TS_RELPOINTER_EVENT: pointerFlags(2) + xDelta(2) + yDelta(2), where the
// deltas are SIGNED i16 ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.7).
std::vector<uint8_t> SlowPathRelativeBody(uint16_t flags, int16_t dx,
                                          int16_t dy) {
    ByteWriter w;
    w.u16le(flags);
    w.u16le(static_cast<uint16_t>(dx));
    w.u16le(static_cast<uint16_t>(dy));
    return w.take();
}

// TS_SYNC_EVENT: pad2Octets(2) + toggleFlags(4).
std::vector<uint8_t> SlowPathSyncBody(uint32_t toggle_flags) {
    ByteWriter w;
    w.u16le(0);  // pad2Octets
    w.u32le(toggle_flags);
    return w.take();
}

std::vector<uint8_t> SlowPathInputBody(
    const std::vector<std::vector<uint8_t>>& events) {
    ByteWriter w;
    w.u16le(static_cast<uint16_t>(events.size()));  // numEvents
    w.u16le(0);                                     // pad2Octets
    for (const auto& e : events) {
        for (uint8_t b : e) w.u8(b);
    }
    return w.take();
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

RTSC_TEST(server_decodes_slowpath_scancode_input) {
    // P-10: a client that does not use fast-path sends PDUTYPE2_INPUT (0x1C)
    // with TS_INPUT_PDU_DATA. Each TS_INPUT_EVENT is eventTime(4) +
    // messageType(2) + body(6) ([MS-RDPBCGR] 2.2.8.1.1.3.1.1); for
    // INPUT_EVENT_SCANCODE (0x0004) the body is keyboardFlags(2) +
    // keyCode(2) + pad2Octets(2) (2.2.8.1.1.3.1.1.1), where KBDFLAGS_EXTENDED
    // is 0x0100 and KBDFLAGS_RELEASE is 0x8000. The decoded event must be the
    // same InputEvent the fast-path path produces.
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

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    CHECK(SendSlowPathPdu(
        r, ShareDataPduType::kInput,
        SlowPathInputBody({
            SlowPathInputEvent(0x0000, SlowPathSyncBody(0x00000003)),   // NUM|CAPS
            SlowPathInputEvent(0x0004, SlowPathKeyboardBody(0x0100, 0x4F)),  // End down
            SlowPathInputEvent(0x0004, SlowPathKeyboardBody(0x8100, 0x4F)),  // End up
        })));

    std::vector<rtsc::server::InputEvent> got;
    for (int i = 0; i < 100 && got.size() < 3; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(mu);
        got = events;
    }
    CHECK_EQ(got.size(), static_cast<size_t>(3));
    if (got.size() == 3) {
        CHECK(got[0].kind == rtsc::server::InputEvent::Kind::kSync);
        CHECK_EQ(got[0].sync_flags, static_cast<uint8_t>(0x03));
        CHECK(got[1].kind == rtsc::server::InputEvent::Kind::kKey);
        CHECK_EQ(got[1].scancode, static_cast<uint8_t>(0x4F));
        CHECK(got[1].extended);
        CHECK(!got[1].release);
        CHECK(got[2].kind == rtsc::server::InputEvent::Kind::kKey);
        CHECK_EQ(got[2].scancode, static_cast<uint8_t>(0x4F));
        CHECK(got[2].extended);
        CHECK(got[2].release);
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_decodes_slowpath_mouse_wheel) {
    // P-10: INPUT_EVENT_MOUSE (0x8001) carries TS_POINTER_EVENT
    // (pointerFlags(2) + xPos(2) + yPos(2), [MS-RDPBCGR] 2.2.8.1.1.3.1.1.3).
    // The wheel fields are the SAME 9-bit two's-complement WheelRotationMask
    // (0x01FF) used by fast-path: 0x0388 = WHEEL 0x0200 | sign bit 0x0100 |
    // rotation 0x88 (136) -> 136 - 256 = -120 wire units. 0x0478 =
    // HWHEEL 0x0400 | 0x78 (120) -> +120 horizontal. The slow-path decoder
    // must reuse that arithmetic, not re-invent it.
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

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    CHECK(SendSlowPathPdu(
        r, ShareDataPduType::kInput,
        SlowPathInputBody({
            SlowPathInputEvent(0x8001, SlowPathPointerBody(0x0388, 1, 1)),
            SlowPathInputEvent(0x8001, SlowPathPointerBody(0x0478, 1, 2)),
        })));

    std::vector<rtsc::server::InputEvent> got;
    for (int i = 0; i < 100 && got.size() < 2; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(mu);
        got = events;
    }
    CHECK_EQ(got.size(), static_cast<size_t>(2));
    if (got.size() == 2) {
        CHECK(got[0].kind == rtsc::server::InputEvent::Kind::kWheel);
        CHECK_EQ(got[0].wheel_delta, static_cast<int16_t>(-120));
        CHECK(!got[0].horizontal);
        CHECK_EQ(got[0].x, static_cast<uint16_t>(0));
        CHECK_EQ(got[0].y, static_cast<uint16_t>(0));
        CHECK(got[1].kind == rtsc::server::InputEvent::Kind::kWheel);
        CHECK_EQ(got[1].wheel_delta, static_cast<int16_t>(120));
        CHECK(got[1].horizontal);
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_decodes_slowpath_mousex) {
    // P-10: INPUT_EVENT_MOUSEX (0x8002) carries TS_POINTERX_EVENT
    // ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.4): same layout as TS_POINTER_EVENT but
    // pointerFlags are PTRXFLAGS, so 0x0001/0x0002 are X1/X2 (buttons 4/5)
    // and 0x8000 is PTRXFLAGS_DOWN.
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

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    CHECK(SendSlowPathPdu(
        r, ShareDataPduType::kInput,
        SlowPathInputBody({
            SlowPathInputEvent(0x8002, SlowPathPointerBody(0x8001, 11, 21)),
            SlowPathInputEvent(0x8002, SlowPathPointerBody(0x0002, 11, 21)),
        })));

    std::vector<rtsc::server::InputEvent> got;
    for (int i = 0; i < 100 && got.size() < 2; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(mu);
        got = events;
    }
    CHECK_EQ(got.size(), static_cast<size_t>(2));
    if (got.size() == 2) {
        CHECK(got[0].kind == rtsc::server::InputEvent::Kind::kMouse);
        CHECK_EQ(got[0].button, static_cast<uint16_t>(4));  // X1
        CHECK(got[0].button_down);
        CHECK_EQ(got[0].x, static_cast<uint16_t>(11));
        CHECK_EQ(got[0].y, static_cast<uint16_t>(21));
        CHECK(got[1].kind == rtsc::server::InputEvent::Kind::kMouse);
        CHECK_EQ(got[1].button, static_cast<uint16_t>(5));  // X2
        CHECK(!got[1].button_down);
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_decodes_slowpath_mouse_relative) {
    // F-1/GAP-3: INPUT_EVENT_MOUSEREL (0x8004) carries TS_RELPOINTER_EVENT
    // ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.7): pointerFlags(2) + xDelta(2) +
    // yDelta(2), with SIGNED deltas. It must decode to the same kMouseRel
    // InputEvent the fast-path branch produces -- never just be counted as an
    // unknown event. (10, -5) -> rel_x=10, rel_y=-5, is_move=false.
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

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    const size_t unknown_before = server.unknown_input_event_count();
    CHECK(SendSlowPathPdu(
        r, ShareDataPduType::kInput,
        SlowPathInputBody({SlowPathInputEvent(
            0x8004, SlowPathRelativeBody(0x0000, 10, -5))})));

    std::vector<rtsc::server::InputEvent> got;
    for (int i = 0; i < 100 && got.size() < 1; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(mu);
        got = events;
    }
    CHECK_EQ(got.size(), static_cast<size_t>(1));
    if (got.size() == 1) {
        CHECK(got[0].kind == rtsc::server::InputEvent::Kind::kMouseRel);
        CHECK_EQ(got[0].rel_x, static_cast<int16_t>(10));
        CHECK_EQ(got[0].rel_y, static_cast<int16_t>(-5));
        CHECK(!got[0].is_move);
    }
    // A decoded relative event is not an unknown event.
    CHECK_EQ(server.unknown_input_event_count(), unknown_before);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_decodes_slowpath_unicode) {
    // P-10: INPUT_EVENT_UNICODE (0x0005) carries TS_UNICODE_KEYBOARD_EVENT
    // ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.2): keyboardFlags(2) + unicodeCode(2) +
    // pad2Octets(2). KBDFLAGS_RELEASE is 0x8000.
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

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    CHECK(SendSlowPathPdu(
        r, ShareDataPduType::kInput,
        SlowPathInputBody({
            SlowPathInputEvent(0x0005, SlowPathUnicodeBody(0x0000, 0x0041)),
            SlowPathInputEvent(0x0005, SlowPathUnicodeBody(0x8000, 0x0041)),
        })));

    std::vector<rtsc::server::InputEvent> got;
    for (int i = 0; i < 100 && got.size() < 2; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(mu);
        got = events;
    }
    CHECK_EQ(got.size(), static_cast<size_t>(2));
    if (got.size() == 2) {
        CHECK(got[0].kind == rtsc::server::InputEvent::Kind::kUnicode);
        CHECK_EQ(got[0].unicode_code, static_cast<uint16_t>(0x0041));
        CHECK(!got[0].release);
        CHECK(got[1].kind == rtsc::server::InputEvent::Kind::kUnicode);
        CHECK_EQ(got[1].unicode_code, static_cast<uint16_t>(0x0041));
        CHECK(got[1].release);
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(server_slowpath_malformed_input_is_survivable) {
    // P-10 robustness: a malformed TS_INPUT_PDU_DATA must neither crash nor read
    // past the payload, and the session must keep decoding input afterwards.
    //   1) truncated: numEvents says 2, only one 12-byte event is present;
    //   2) over-range: numEvents = 0xFFFF with a 4-byte payload;
    //   3) unknown messageType (0x0007): counted, then the PDU is abandoned
    //      because an unknown event's length is unknown.
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

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    auto send_fast_key = [&](uint8_t scancode) {
        return WriteAll(*r.transport,
                        McsSendData::build_request(
                            r.user_channel, r.io_channel,
                            EncodeFastPathInputPdu(
                                {EncodeKeyboardEvent(scancode, false, false)})));
    };
    auto saw_scancode = [&](uint8_t scancode) {
        for (int i = 0; i < 100; ++i) {
            {
                std::lock_guard<std::mutex> lock(mu);
                for (const auto& ev : events) {
                    if (ev.kind == rtsc::server::InputEvent::Kind::kKey &&
                        ev.scancode == scancode) {
                        return true;
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return false;
    };

    // 1) Truncated: count 2, one event.
    {
        ByteWriter w;
        w.u16le(2);  // numEvents
        w.u16le(0);  // pad2Octets
        const auto one =
            SlowPathInputEvent(0x0004, SlowPathKeyboardBody(0x0000, 0x1E));
        for (uint8_t b : one) w.u8(b);
        CHECK(SendSlowPathPdu(r, ShareDataPduType::kInput, w.take()));
    }
    CHECK(send_fast_key(0x2C));  // Z: the session still decodes input
    CHECK(saw_scancode(0x2C));

    // 2) Over-range event count with an empty event array.
    CHECK(SendSlowPathPdu(r, ShareDataPduType::kInput,
                          {0xFF, 0xFF, 0x00, 0x00}));
    CHECK(send_fast_key(0x2D));  // X
    CHECK(saw_scancode(0x2D));

    // 3) Unknown messageType: counted once, no callback, session alive.
    const size_t unknown_before = server.unknown_input_event_count();
    CHECK(SendSlowPathPdu(
        r, ShareDataPduType::kInput,
        SlowPathInputBody({SlowPathInputEvent(0x0007, SlowPathPointerBody(
                                                    0x0000, 0, 0))})));
    CHECK(send_fast_key(0x2E));  // C
    CHECK(saw_scancode(0x2E));
    CHECK_EQ(server.unknown_input_event_count(), unknown_before + 1);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_slowpath_event_count_mismatch_is_counted) {
    // GAP-2: when numberEvents disagrees with the payload (here: count 2 but
    // only one 12-byte event), the decoder abandons the PDU. That framing
    // error must be observable: malformed_input_pdu_count() increments (it is
    // deliberately NOT conflated with unknown_input_event_count()).
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

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    const size_t malformed_before = server.malformed_input_pdu_count();
    const size_t unknown_before = server.unknown_input_event_count();
    ByteWriter w;
    w.u16le(2);  // numEvents says two...
    w.u16le(0);  // pad2Octets
    const auto one =
        SlowPathInputEvent(0x0004, SlowPathKeyboardBody(0x0000, 0x1E));
    for (uint8_t b : one) w.u8(b);  // ...but only one event is present
    CHECK(SendSlowPathPdu(r, ShareDataPduType::kInput, w.take()));

    // A following fast-path key proves the session kept running and pins the
    // ordering: the malformed PDU was decoded before the key.
    CHECK(WriteAll(*r.transport,
                   McsSendData::build_request(
                       r.user_channel, r.io_channel,
                       EncodeFastPathInputPdu(
                           {EncodeKeyboardEvent(0x2C, false, false)}))));
    bool saw_key = false;
    for (int i = 0; i < 100 && !saw_key; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(mu);
        for (const auto& ev : events) {
            if (ev.kind == rtsc::server::InputEvent::Kind::kKey &&
                ev.scancode == static_cast<uint8_t>(0x2C)) {
                saw_key = true;
                break;
            }
        }
    }
    CHECK(saw_key);
    CHECK_EQ(server.malformed_input_pdu_count(), malformed_before + 1);
    CHECK_EQ(server.unknown_input_event_count(), unknown_before);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_undefined_share_data_type_is_not_reinterpreted) {
    // F4: a payload that parses as a TS_SHAREDATAHEADER but carries an
    // undefined pduType2 is malformed share data -- it must NOT be handed to
    // the fast-path decoder. That fallback let a 24-byte malformed packet emit
    // phantom key events (0x1E here) and, with injection enabled, potentially
    // grab the desktop input lease. The old GAP-4 whitelist deliberately fell
    // through for undefined types; the approved policy reverses that trade-off:
    // drop the payload, count it as malformed, and keep the session alive.
    //
    // The 24-byte payload doubles as a valid fast-path PDU, which is exactly
    // why the fallback produced input:
    //   [0] 0x04 [1] 0x18  fast-path header, one-byte length 24; these bytes
    //                      are also totalLength/type of the fake share header
    //   [2] 0x17 [3] 0x00  share control: DATA type, protocol version 1
    //   [4] 0x03 [5] 0x1E  fast-path scancode event for 0x1E (the phantom)
    //   [14] 0x99          undefined sharedPDUType
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

    HandshakeResult r = DriveToActive(server.bound_port());
    CHECK(r.reached_active);

    std::vector<uint8_t> payload(24, 0);
    payload[0] = 0x04;  // fast-path header (action 0, numEvents 1)
    payload[1] = 0x18;  // fast-path length = 24
    payload[2] = 0x17;  // fake share control: DATA (0x7) | version 1 << 4
    payload[3] = 0x00;
    payload[4] = 0x03;  // fast-path scancode event header (code 0)
    payload[5] = 0x1E;  // phantom scancode
    payload[14] = 0x99;  // undefined sharedPDUType

    const size_t malformed_before = server.malformed_input_pdu_count();
    CHECK(WriteAll(*r.transport,
                   McsSendData::build_request(r.user_channel, r.io_channel,
                                              payload)));
    // Poll until the session thread has counted the malformed PDU, then assert
    // that it delivered no input event. Asserting the empty vector after a
    // fixed sleep left a race: a slow session thread could make that check pass
    // before the PDU was processed, so the test did not actually pin the
    // "no phantom key" behaviour.
    bool malformed_counted = false;
    for (int i = 0; i < 200 && !malformed_counted; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        malformed_counted =
            server.malformed_input_pdu_count() > malformed_before;
    }
    CHECK(malformed_counted);
    {
        std::lock_guard<std::mutex> lock(mu);
        CHECK(events.empty());
    }
    CHECK_EQ(server.malformed_input_pdu_count(), malformed_before + 1);

    // The session survives: a following well-formed fast-path key decodes.
    CHECK(WriteAll(*r.transport,
                   McsSendData::build_request(
                       r.user_channel, r.io_channel,
                       EncodeFastPathInputPdu(
                           {EncodeKeyboardEvent(0x2C, false, false)}))));
    bool saw_key = false;
    for (int i = 0; i < 100 && !saw_key; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(mu);
        for (const auto& ev : events) {
            if (ev.kind == rtsc::server::InputEvent::Kind::kKey &&
                ev.scancode == static_cast<uint8_t>(0x2C)) {
                saw_key = true;
                break;
            }
        }
    }
    CHECK(saw_key);

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

RTSC_TEST(server_input_sink_disabled_by_config) {
    // enable_desktop_input=false is the default and must keep the sink
    // completely untouched: no geometry, no injection, no release, even when a
    // peer sends input and a sink is installed.
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    cfg.enable_desktop_input = false;
    cfg.max_input_sessions = 1;

    RecordingInputSink sink;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetInputSink(&sink);

    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult r =
        DriveToActive(server.bound_port(), false, 64, 48, /*expect_frame=*/false);
    CHECK(r.reached_active);
    CHECK(SendTestInput(r));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    CHECK(sink.inject_ids().empty());
    CHECK(sink.geometry_ids().empty());
    CHECK(sink.release_ids().empty());
    CHECK_EQ(server.input_lease_denied_count(), static_cast<size_t>(0));

    server.Stop();
    runner.join();
    // The session ended; with injection disabled ReleaseSession must still not
    // have been called.
    CHECK(sink.release_ids().empty());
}

RTSC_TEST(server_input_lease_one_session_then_handoff) {
    // Two live sessions share one physical desktop. With the default limit of 1
    // only the first session that sends input acquires the lease; the second is
    // denied (and counted) until the holder disconnects. After the holder is
    // gone the next input event from the survivor acquires the lease.
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    cfg.enable_desktop_input = true;
    cfg.max_input_sessions = 1;

    RecordingInputSink sink;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetInputSink(&sink);

    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult first =
        DriveToActive(server.bound_port(), false, 64, 48, /*expect_frame=*/false);
    CHECK(first.reached_active);
    HandshakeResult second =
        DriveToActive(server.bound_port(), false, 64, 48, /*expect_frame=*/false);
    CHECK(second.reached_active);

    // The first session sends input: it must become the sole lease holder.
    CHECK(SendTestInput(first));
    CHECK(WaitUntil([&sink]() { return !sink.inject_ids().empty(); }));
    const std::vector<uint32_t> inject_after_first = sink.inject_ids();
    CHECK_EQ(DistinctIds(inject_after_first), static_cast<size_t>(1));
    if (inject_after_first.empty()) {
        server.Stop();
        runner.join();
        return;
    }
    const uint32_t holder = inject_after_first.front();

    // Geometry is announced for the lease holder only, with the negotiated
    // framebuffer size.
    const std::vector<uint32_t> geometry_after_first = sink.geometry_ids();
    CHECK_EQ(DistinctIds(geometry_after_first), static_cast<size_t>(1));
    CHECK(!geometry_after_first.empty() &&
          geometry_after_first.front() == holder);
    CHECK_EQ(sink.geometry_width(), static_cast<uint16_t>(64));
    CHECK_EQ(sink.geometry_height(), static_cast<uint16_t>(48));

    // The second session sends input while the lease is held: nothing reaches
    // the sink under its id, and the denial counter records the attempts.
    for (int i = 0; i < 5; ++i) CHECK(SendTestInput(second));
    CHECK(WaitUntil(
        [&server]() { return server.input_lease_denied_count() >= 5; }));
    CHECK_EQ(server.input_lease_denied_count(), static_cast<size_t>(5));
    for (const uint32_t id : sink.inject_ids()) CHECK_EQ(id, holder);

    // Disconnect the holder. Its lease is released and ReleaseSession runs
    // exactly once for it (idempotent teardown).
    first.reader.reset();
    first.transport->Close();
    first.transport.reset();
    CHECK(WaitUntil([&sink, holder]() {
        return CountId(sink.release_ids(), holder) == 1;
    }));

    // The survivor's next input event acquires the lease: a different session
    // id now reaches Inject and SetGeometry.
    bool handed_off = false;
    for (int i = 0; i < 300 && !handed_off; ++i) {
        CHECK(SendTestInput(second));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        handed_off = DistinctIds(sink.inject_ids()) == 2;
    }
    CHECK(handed_off);
    const std::vector<uint32_t> geometry_after_handoff = sink.geometry_ids();
    CHECK_EQ(DistinctIds(geometry_after_handoff), static_cast<size_t>(2));
    uint32_t survivor = 0;
    for (const uint32_t id : sink.inject_ids()) {
        if (id != holder) survivor = id;
    }
    CHECK(survivor != 0);
    CHECK_EQ(CountId(geometry_after_handoff, survivor), static_cast<size_t>(1));

    // ReleaseSession stays once-per-session: the holder was not released again.
    CHECK_EQ(CountId(sink.release_ids(), holder), static_cast<size_t>(1));
    CHECK_EQ(CountId(sink.release_ids(), survivor), static_cast<size_t>(0));

    server.Stop();
    runner.join();
    CHECK_EQ(CountId(sink.release_ids(), holder), static_cast<size_t>(1));
    CHECK_EQ(CountId(sink.release_ids(), survivor), static_cast<size_t>(1));
}

RTSC_TEST(server_input_lease_zero_means_unlimited) {
    // max_input_sessions=0 is the explicit "unlimited" value: both sessions
    // acquire and inject, and nothing is denied.
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    cfg.enable_desktop_input = true;
    cfg.max_input_sessions = 0;

    RecordingInputSink sink;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetInputSink(&sink);

    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult first =
        DriveToActive(server.bound_port(), false, 64, 48, /*expect_frame=*/false);
    CHECK(first.reached_active);
    HandshakeResult second =
        DriveToActive(server.bound_port(), false, 64, 48, /*expect_frame=*/false);
    CHECK(second.reached_active);

    bool both_injected = false;
    for (int i = 0; i < 300 && !both_injected; ++i) {
        CHECK(SendTestInput(first));
        CHECK(SendTestInput(second));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        both_injected = DistinctIds(sink.inject_ids()) == 2;
    }
    CHECK(both_injected);
    CHECK_EQ(DistinctIds(sink.geometry_ids()), static_cast<size_t>(2));
    CHECK_EQ(server.input_lease_denied_count(), static_cast<size_t>(0));

    server.Stop();
    runner.join();
}

RTSC_TEST(server_release_session_precedes_lease_handoff) {
    // F3: ReleaseInput must call sink->ReleaseSession BEFORE it frees the lease
    // slot. Releasing the sink queues the old session's synthetic key/button
    // ups; if the slot is freed first, the surviving session can acquire it and
    // Inject a key-down that the worker may emit before those ups, lifting the
    // new holder's key. The ordering sink blocks in ReleaseSession and records
    // any Inject that lands in that window.
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    cfg.enable_desktop_input = true;
    cfg.max_input_sessions = 1;

    ReleaseOrderingSink sink;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetInputSink(&sink);

    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult first =
        DriveToActive(server.bound_port(), false, 64, 48, /*expect_frame=*/false);
    CHECK(first.reached_active);
    HandshakeResult second =
        DriveToActive(server.bound_port(), false, 64, 48, /*expect_frame=*/false);
    CHECK(second.reached_active);

    // The first session takes the lease and injects at least once.
    CHECK(SendTestInput(first));
    CHECK(WaitUntil([&sink]() { return !sink.inject_ids().empty(); }));
    CHECK(!sink.inject_ids().empty() && sink.inject_ids().front() != 0);

    // The second session is denied while the first still holds the lease.
    CHECK(SendTestInput(second));
    CHECK(WaitUntil(
        [&server]() { return server.input_lease_denied_count() >= 1; }));

    sink.ArmReleaseProbe();
    std::atomic<bool> keep_sending{true};
    std::thread sender([&second, &keep_sending]() {
        while (keep_sending.load(std::memory_order_relaxed)) {
            SendTestInput(second);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });

    // Disconnect the holder. Its ReleaseSession runs while the lease is still
    // held, so no Inject may reach the sink during that window.
    first.reader.reset();
    first.transport->Close();
    first.transport.reset();
    CHECK(WaitUntil([&sink]() { return !sink.release_ids().empty(); }));
    // Let a late, wrongly-ordered Inject show up before checking.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    keep_sending.store(false, std::memory_order_relaxed);
    sender.join();

    CHECK_EQ(sink.injects_during_release(), static_cast<size_t>(0));

    // The hand-off still happens: the survivor acquires the freed lease.
    bool handed_off = false;
    for (int i = 0; i < 300 && !handed_off; ++i) {
        CHECK(SendTestInput(second));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        handed_off = DistinctIds(sink.inject_ids()) == 2;
    }
    CHECK(handed_off);

    server.Stop();
    runner.join();
}

RTSC_TEST(server_release_input_frees_lease_slot_when_release_throws) {
    // F-1: ReleaseInput calls sink->ReleaseSession before it frees the lease
    // slot (F3). That call can throw (the real backend appends the synthetic
    // ups to a queue). The exception must not skip holders.erase: the flags are
    // already set, teardown is never retried, so a skipped erase leaks the slot
    // and permanently denies every later session. The first probe is the
    // control (well-behaved sink); the second must behave the same.
    bool released = false;
    bool handed_off = false;
    size_t release_failures = 0;
    CHECK(RunLeaseHandoffProbe(/*throw_on_release=*/false, &released, &handed_off,
                               &release_failures));
    CHECK(released);
    CHECK(handed_off);
    // A well-behaved sink: teardown never failed, nothing was lost.
    CHECK_EQ(release_failures, static_cast<size_t>(0));

    released = false;
    handed_off = false;
    release_failures = 0;
    CHECK(RunLeaseHandoffProbe(/*throw_on_release=*/true, &released, &handed_off,
                               &release_failures));
    CHECK(released);
    CHECK(handed_off);
    // The throw was counted (the sink may have lost the synthetic ups): the
    // failure is observable even though the lease slot was freed.
    CHECK_EQ(release_failures, static_cast<size_t>(1));
}

RTSC_TEST(server_non_injectable_input_does_not_hold_lease) {
    // F4-A3: a session that only sends kSync (which TranslateInput drops) must
    // not acquire the single lease. Otherwise one SYNC holds it for the whole
    // session and a peer that actually controls the desktop is starved forever.
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    cfg.enable_desktop_input = true;
    cfg.max_input_sessions = 1;

    RecordingInputSink sink;
    auto pattern = rtsc::server::MakeTestPatternSource();
    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetInputSink(&sink);

    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    HandshakeResult sync_sender =
        DriveToActive(server.bound_port(), false, 64, 48, /*expect_frame=*/false);
    CHECK(sync_sender.reached_active);
    HandshakeResult key_sender =
        DriveToActive(server.bound_port(), false, 64, 48, /*expect_frame=*/false);
    CHECK(key_sender.reached_active);

    auto send_sync = [&sync_sender]() {
        return WriteAll(*sync_sender.transport,
                        McsSendData::build_request(
                            sync_sender.user_channel, sync_sender.io_channel,
                            EncodeFastPathInputPdu({EncodeSyncEvent(0)})));
    };
    for (int i = 0; i < 5; ++i) CHECK(send_sync());
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // The SYNC session never reached the sink and never took the lease.
    CHECK(sink.inject_ids().empty());
    CHECK(sink.geometry_ids().empty());
    CHECK_EQ(server.input_lease_denied_count(), static_cast<size_t>(0));

    // The other session can take the lease with a real (injectable) key.
    bool injected = false;
    for (int i = 0; i < 300 && !injected; ++i) {
        CHECK(SendTestInput(key_sender));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        injected = !sink.inject_ids().empty();
    }
    CHECK(injected);
    CHECK_EQ(DistinctIds(sink.inject_ids()), static_cast<size_t>(1));
    CHECK_EQ(server.input_lease_denied_count(), static_cast<size_t>(0));

    server.Stop();
    runner.join();
}

int main() { return rtsc::test::run_all("rtsc_server_tests"); }
