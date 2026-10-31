// End-to-end client: construction and input encoding.
//
// The connection sequence itself is covered by the driver's full-flow test and
// the graphics compositing by the graphics test; this checks the glue: the
// client builds, owns a surface of the requested size, and turns window events
// into the right Fast-Path input PDUs.

#include "rtsc/client/client.h"

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "rtsc/net/transport.h"
#include "rtsc/proto/input.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/proto/share.h"
#include "test_framework.h"
#include "test_main.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

using namespace rtsc::client;
using namespace rtsc::security;
using namespace rtsc::ui;

namespace {

ConnectionDriver MakeDriver() {
    rtsc::proto::ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=tester";
    mcfg.requested_protocols = rtsc::proto::kProtocolSsl |
                               rtsc::proto::kProtocolHybrid |
                               rtsc::proto::kProtocolHybridEx;
    mcfg.client_name = "RTSC";
    mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
    mcfg.encryption_methods = 0;

    rtsc::proto::ConnectMachine::Credentials creds;
    creds.domain = "Domain";
    creds.user_name = "User";
    creds.password = "Password";

    rtsc::security::Config scfg;
    scfg.tls_config.peer_host = "127.0.0.1";
    scfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    scfg.credentials.domain = "Domain";
    scfg.credentials.user = "User";
    scfg.credentials.password = "Password";

    return ConnectionDriver(mcfg, creds, scfg);
}

// A transport whose Read() result is scripted, so Pump's handling of the three
// outcomes (data / bounded-wait timeout / disconnect) can be tested without a
// socket. `timeout_budget` makes the first N reads report kReadTimeout before
// falling back to `next`, which models a peer that is briefly silent and then
// closes. Every Write is also recorded (last_write) so the exact PDUs a Client
// method puts on the wire can be asserted.
class ScriptedTransport final : public rtsc::net::Transport {
 public:
    int next = 0;
    int reads = 0;
    int writes = 0;
    int timeout_budget = -1;  // -1 = never time out
    std::vector<uint8_t> last_write;

    int Read(uint8_t*, size_t) override {
        ++reads;
        if (timeout_budget > 0) {
            --timeout_budget;
            return rtsc::net::kReadTimeout;
        }
        return next;
    }
    bool Write(const uint8_t* data, size_t size) override {
        ++writes;
        last_write.assign(data, data + size);
        return true;
    }
    void Close() override {}
};

std::string Hex(const std::vector<uint8_t>& b) {
    static const char* k = "0123456789abcdef";
    std::string s;
    for (uint8_t c : b) {
        s.push_back(k[c >> 4]);
        s.push_back(k[c & 0xF]);
    }
    return s;
}

// The MOUSE events of a Fast-Path input PDU whose numEvents fits the 4-bit
// header field (the wheel paths produce at most 8). Each TS_FP_POINTER_EVENT is
// eventHeader(1) + pointerFlags(2) + xPos(2) + yPos(2) = 7 bytes, so event i's
// pointerFlags start at 2 + 7*i. A two-byte FastPathLength never occurs here.
struct DecodedWheelPdu {
    size_t events = 0;
    bool one_byte_length = false;
    std::vector<uint16_t> pointer_flags;
};

DecodedWheelPdu DecodeWheelPdu(const std::vector<uint8_t>& pdu) {
    DecodedWheelPdu out;
    if (pdu.size() < 2) return out;
    out.events = (pdu[0] >> 2) & 0x0F;
    out.one_byte_length = (pdu[1] & 0x80) == 0;
    for (size_t i = 0; i < out.events; ++i) {
        const size_t off = 2 + 7 * i;
        if (off + 3 > pdu.size()) break;
        out.pointer_flags.push_back(
            static_cast<uint16_t>(pdu[off + 1] | (pdu[off + 2] << 8)));
    }
    return out;
}

// Sign-extends the 9-bit WheelRotationMask field: 0x0100 is its sign bit
// ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.1), so 0x0300 is -256, not +256.
int WheelRotation(uint16_t pointer_flags) {
    const int raw = pointer_flags & 0x01FF;
    return (raw & 0x0100) != 0 ? raw - 0x0200 : raw;
}

}  // namespace

RTSC_TEST(client_constructs_with_a_surface) {
    Client c(MakeDriver(), 800, 600);
    CHECK_EQ(c.surface().width(), static_cast<uint16_t>(800));
    CHECK_EQ(c.surface().height(), static_cast<uint16_t>(600));
    CHECK(!c.active());
}

RTSC_TEST(client_encodes_keyboard_input) {
    Client c(MakeDriver(), 16, 16);
    InputEvent k;
    k.kind = InputEvent::Kind::kKey;
    k.scancode = 0x1E;
    const auto pdu = c.EncodeInput(k);
    CHECK_EQ(pdu.size(), static_cast<size_t>(4));  // header + length + 2-byte event
    CHECK_EQ(static_cast<uint8_t>(pdu[0] & 0x03), static_cast<uint8_t>(0));  // fast-path
    CHECK_EQ(static_cast<uint8_t>((pdu[0] >> 2) & 0x0F),
             static_cast<uint8_t>(1));  // one event
    CHECK_EQ(pdu[2], static_cast<uint8_t>(0x00));  // eventHeader: scancode, no flags
    CHECK_EQ(pdu[3], static_cast<uint8_t>(0x1E));  // keyCode
}

RTSC_TEST(client_encodes_mouse_move) {
    Client c(MakeDriver(), 16, 16);
    InputEvent m;
    m.kind = InputEvent::Kind::kMouseMove;
    m.x = 683;
    m.y = 367;
    const auto pdu = c.EncodeInput(m);
    // header + length + 7-byte mouse event.
    CHECK_EQ(pdu.size(), static_cast<size_t>(9));
    CHECK_EQ(pdu[2], static_cast<uint8_t>(0x20));  // eventCode 1 (MOUSE)
    CHECK_EQ(pdu[3], static_cast<uint8_t>(0x00));  // PTRFLAGS_MOVE low byte
    CHECK_EQ(pdu[4], static_cast<uint8_t>(0x08));  // PTRFLAGS_MOVE high byte
}

RTSC_TEST(client_encodes_mouse_button) {
    Client c(MakeDriver(), 16, 16);
    InputEvent b;
    b.kind = InputEvent::Kind::kMouseButton;
    b.button = 1;  // left
    b.button_down = true;
    b.x = 1;
    b.y = 2;
    const auto pdu = c.EncodeInput(b);
    CHECK_EQ(pdu.size(), static_cast<size_t>(9));
    // PTRFLAGS_DOWN (0x8000) | PTRFLAGS_BUTTON1 (0x1000) = 0x9000.
    CHECK_EQ(pdu[3], static_cast<uint8_t>(0x00));
    CHECK_EQ(pdu[4], static_cast<uint8_t>(0x90));
}

RTSC_TEST(client_encodes_mouse_wheel) {
    // The wire rotation unit is one notch = WHEEL_DELTA (120) units
    // ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.1). FreeRDP PR #6806 fixed exactly this:
    // "xfreerdp currently uses the positive wheel value in addition to the
    // negative flag, which results in a wrong wheel value on the server side
    // (136 instead of 120)." The UI layer reports notches, so one notch down is
    // -120, which fits entirely inside the 9-bit two's-complement
    // WheelRotationMask: 0x0200 | (0xFF88 & 0x01FF) = 0x0388.
    Client c(MakeDriver(), 16, 16);
    InputEvent w;
    w.kind = InputEvent::Kind::kMouseWheel;
    w.wheel_delta = -1;  // one notch down
    const auto pdu = c.EncodeInput(w);
    CHECK_EQ(pdu.size(), static_cast<size_t>(9));
    CHECK_EQ(pdu[3], static_cast<uint8_t>(0x88));
    CHECK_EQ(pdu[4], static_cast<uint8_t>(0x03));
}

RTSC_TEST(client_encodes_one_notch_up_wheel) {
    Client c(MakeDriver(), 16, 16);
    InputEvent w;
    w.kind = InputEvent::Kind::kMouseWheel;
    w.wheel_delta = 1;  // one notch up
    const auto pdu = c.EncodeInput(w);
    CHECK_EQ(pdu.size(), static_cast<size_t>(9));
    // PTRFLAGS_WHEEL (0x0200) | 120 (0x78) = 0x0278.
    CHECK_EQ(pdu[3], static_cast<uint8_t>(0x78));
    CHECK_EQ(pdu[4], static_cast<uint8_t>(0x02));
}

RTSC_TEST(client_encodes_multi_notch_wheel) {
    Client c(MakeDriver(), 16, 16);
    InputEvent w;
    w.kind = InputEvent::Kind::kMouseWheel;
    w.wheel_delta = 2;  // two notches up
    const auto pdu = c.EncodeInput(w);
    CHECK_EQ(pdu.size(), static_cast<size_t>(9));
    // PTRFLAGS_WHEEL (0x0200) | 240 (0xF0) = 0x02F0.
    CHECK_EQ(pdu[3], static_cast<uint8_t>(0xF0));
    CHECK_EQ(pdu[4], static_cast<uint8_t>(0x02));
}

// N1: one UI wheel event may exceed the 9-bit field (3 notches = 360 units,
// while the two's-complement field carries -256..+255). Clamping to 255 used to
// lose 105 units (0.875 notch) silently. The event is split into chunks of at
// most 255 units in the SAME Fast-Path PDU, largest magnitude first, all with
// the sign of the original delta, so the wire sum is exactly 360 (or -360).
RTSC_TEST(client_splits_three_notch_wheel_without_losing_rotation) {
    Client c(MakeDriver(), 16, 16);
    InputEvent up;
    up.kind = InputEvent::Kind::kMouseWheel;
    up.wheel_delta = 3;  // 3 * WHEEL_DELTA(120) = 360 wire units
    const DecodedWheelPdu up_pdu = DecodeWheelPdu(c.EncodeInput(up));
    CHECK_EQ(up_pdu.events, static_cast<size_t>(2));
    CHECK(up_pdu.one_byte_length);
    CHECK_EQ(up_pdu.pointer_flags.size(), static_cast<size_t>(2));
    if (up_pdu.pointer_flags.size() == 2) {
        // 0x0200 | 255 = 0x02FF, then 0x0200 | 105 (0x69) = 0x0269.
        CHECK_EQ(up_pdu.pointer_flags[0], static_cast<uint16_t>(0x02FF));
        CHECK_EQ(up_pdu.pointer_flags[1], static_cast<uint16_t>(0x0269));
        CHECK_EQ(WheelRotation(up_pdu.pointer_flags[0]) +
                     WheelRotation(up_pdu.pointer_flags[1]),
                 360);
    }

    InputEvent down;
    down.kind = InputEvent::Kind::kMouseWheel;
    down.wheel_delta = -3;  // -360 wire units
    const DecodedWheelPdu down_pdu = DecodeWheelPdu(c.EncodeInput(down));
    CHECK_EQ(down_pdu.events, static_cast<size_t>(2));
    CHECK_EQ(down_pdu.pointer_flags.size(), static_cast<size_t>(2));
    if (down_pdu.pointer_flags.size() == 2) {
        // 0x0200 | (-255 & 0x01FF = 0x101) = 0x0301, then
        // 0x0200 | (-105 & 0x01FF = 0x197) = 0x0397.
        CHECK_EQ(down_pdu.pointer_flags[0], static_cast<uint16_t>(0x0301));
        CHECK_EQ(down_pdu.pointer_flags[1], static_cast<uint16_t>(0x0397));
        CHECK_EQ(WheelRotation(down_pdu.pointer_flags[0]) +
                     WheelRotation(down_pdu.pointer_flags[1]),
                 -360);
    }
}

// A single UI event is expanded to at most kMaxWheelChunksPerEvent = 8 wire
// events (8 * 255 units = 17 notches); this bounds the damage a garbage or
// hostile wheel_delta can do instead of building a huge PDU. 120 notches is
// 14,400 units = 57 chunks nominally, so only the first 8 full steps are sent.
RTSC_TEST(client_caps_wheel_chunks_for_large_delta) {
    Client c(MakeDriver(), 16, 16);
    InputEvent up;
    up.kind = InputEvent::Kind::kMouseWheel;
    up.wheel_delta = 120;
    const DecodedWheelPdu up_pdu = DecodeWheelPdu(c.EncodeInput(up));
    CHECK_EQ(up_pdu.events, static_cast<size_t>(8));
    CHECK_EQ(up_pdu.pointer_flags.size(), static_cast<size_t>(8));
    for (uint16_t flags : up_pdu.pointer_flags) {
        CHECK_EQ(flags, static_cast<uint16_t>(0x02FF));  // +255 each
    }

    InputEvent down;
    down.kind = InputEvent::Kind::kMouseWheel;
    down.wheel_delta = -120;
    const DecodedWheelPdu down_pdu = DecodeWheelPdu(c.EncodeInput(down));
    CHECK_EQ(down_pdu.events, static_cast<size_t>(8));
    CHECK_EQ(down_pdu.pointer_flags.size(), static_cast<size_t>(8));
    for (uint16_t flags : down_pdu.pointer_flags) {
        CHECK_EQ(flags, static_cast<uint16_t>(0x0301));  // -255 each
    }
}

// N6: INT16_MIN notches = -32768 * 120 = -3,932,160 units. The product must be
// computed without signed overflow (notch count widened to 64 bits), and the
// chunk cap keeps the PDU at 8 events instead of 15,420.
RTSC_TEST(client_handles_int16_min_wheel_delta_without_overflow) {
    Client c(MakeDriver(), 16, 16);
    InputEvent w;
    w.kind = InputEvent::Kind::kMouseWheel;
    w.wheel_delta = (std::numeric_limits<int16_t>::min)();
    const DecodedWheelPdu pdu = DecodeWheelPdu(c.EncodeInput(w));
    CHECK_EQ(pdu.events, static_cast<size_t>(8));
    CHECK_EQ(pdu.pointer_flags.size(), static_cast<size_t>(8));
    for (uint16_t flags : pdu.pointer_flags) {
        CHECK_EQ(flags, static_cast<uint16_t>(0x0301));  // -255 each, sign kept
    }
}

// N6: -256 notches = -30,720 wire units. One field value of -256 (0x0300 in
// WheelRotationMask) is representable, but the splitter walks symmetric 255
// steps (so the extra -256 code point is intentionally unused, N2); the sum is
// still -30,720 by construction: 120 chunks x -255 would be needed, and the
// 8-chunk cap keeps the first 8 full -255 steps. Expected values come from the
// 9-bit two's-complement field, not from the implementation.
RTSC_TEST(client_chunks_negative_256_notches_within_cap) {
    Client c(MakeDriver(), 16, 16);
    InputEvent w;
    w.kind = InputEvent::Kind::kMouseWheel;
    w.wheel_delta = -256;
    const DecodedWheelPdu pdu = DecodeWheelPdu(c.EncodeInput(w));
    CHECK_EQ(pdu.events, static_cast<size_t>(8));
    CHECK_EQ(pdu.pointer_flags.size(), static_cast<size_t>(8));
    for (uint16_t flags : pdu.pointer_flags) {
        CHECK_EQ(WheelRotation(flags), -255);
    }
}

// N3: a gated PTRFLAGS_HWHEEL drop is normal capability negotiation (the server
// did not advertise INPUT_FLAG_MOUSE_HWHEEL), so the session must not be torn
// down -- but it used to be invisible. The counter is monotonic and only counts
// horizontal drops; a vertical wheel is never gated.
RTSC_TEST(client_counts_dropped_hwheel_events) {
    Client c(MakeDriver(), 16, 16);
    CHECK_EQ(c.dropped_hwheel_count(), static_cast<size_t>(0));

    InputEvent h;
    h.kind = InputEvent::Kind::kMouseWheel;
    h.horizontal = true;
    h.wheel_delta = -1;
    CHECK(c.EncodeInput(h).empty());
    CHECK_EQ(c.dropped_hwheel_count(), static_cast<size_t>(1));
    CHECK(c.EncodeInput(h).empty());
    CHECK_EQ(c.dropped_hwheel_count(), static_cast<size_t>(2));

    InputEvent v;
    v.kind = InputEvent::Kind::kMouseWheel;
    v.wheel_delta = 1;
    CHECK(!c.EncodeInput(v).empty());
    CHECK_EQ(c.dropped_hwheel_count(), static_cast<size_t>(2));
}

RTSC_TEST(client_hwheel_is_gated_on_server_support) {
    // [MS-RDPBCGR] 2.2.8.1.1.3.1.1.1: PTRFLAGS_HWHEEL MUST NOT be sent to a
    // server that did not advertise INPUT_FLAG_MOUSE_HWHEEL in its Input
    // Capability Set. Before the Demand Active PDU is processed the client has
    // no server capability, so a horizontal wheel must not produce a PDU --
    // while a vertical wheel (an ordinary MOUSE event) still does. The positive
    // direction is covered end to end in test_gui_send (the in-tree server
    // advertises 0x0100).
    Client c(MakeDriver(), 16, 16);
    InputEvent h;
    h.kind = InputEvent::Kind::kMouseWheel;
    h.horizontal = true;
    h.wheel_delta = 1;
    CHECK(c.EncodeInput(h).empty());

    InputEvent v;
    v.kind = InputEvent::Kind::kMouseWheel;
    v.wheel_delta = 1;
    CHECK(!c.EncodeInput(v).empty());
}

RTSC_TEST(client_encodes_xbuttons_as_extended_mouse_events) {
    Client c(MakeDriver(), 16, 16);
    // MOUSEX events carry PTRXFLAGS, not PTRFLAGS ([MS-RDPBCGR]
    // 2.2.8.1.1.3.1.1.4): PTRXFLAGS_BUTTON1 = 0x0001, PTRXFLAGS_BUTTON2 =
    // 0x0002. The 0x1000/0x2000 pointer-button bits are for the plain POINTER
    // event and would alias the left/right buttons on the server.
    InputEvent x1;
    x1.kind = InputEvent::Kind::kMouseButton;
    x1.button = 4;  // X1
    x1.button_down = true;
    const auto pdu = c.EncodeInput(x1);
    CHECK_EQ(pdu.size(), static_cast<size_t>(9));
    // eventCode 2 = MOUSEX (0x40 in the header byte).
    CHECK_EQ(pdu[2], static_cast<uint8_t>(0x40));
    // PTRXFLAGS_DOWN (0x8000) | PTRXFLAGS_BUTTON1 (0x0001) = 0x8001.
    CHECK_EQ(pdu[3], static_cast<uint8_t>(0x01));
    CHECK_EQ(pdu[4], static_cast<uint8_t>(0x80));

    InputEvent x2;
    x2.kind = InputEvent::Kind::kMouseButton;
    x2.button = 5;  // X2
    x2.button_down = true;
    const auto pdu2 = c.EncodeInput(x2);
    CHECK_EQ(pdu2.size(), static_cast<size_t>(9));
    CHECK_EQ(pdu2[2], static_cast<uint8_t>(0x40));
    // PTRXFLAGS_DOWN | PTRXFLAGS_BUTTON2 (0x0002) = 0x8002.
    CHECK_EQ(pdu2[3], static_cast<uint8_t>(0x02));
    CHECK_EQ(pdu2[4], static_cast<uint8_t>(0x80));

    // Release events carry the button bit alone (no PTRXFLAGS_DOWN).
    InputEvent x1_up = x1;
    x1_up.button_down = false;
    const auto pdu1u = c.EncodeInput(x1_up);
    CHECK_EQ(pdu1u.size(), static_cast<size_t>(9));
    CHECK_EQ(pdu1u[2], static_cast<uint8_t>(0x40));
    CHECK_EQ(pdu1u[3], static_cast<uint8_t>(0x01));  // X1 up: 0x0001
    CHECK_EQ(pdu1u[4], static_cast<uint8_t>(0x00));

    InputEvent x2_up = x2;
    x2_up.button_down = false;
    const auto pdu2u = c.EncodeInput(x2_up);
    CHECK_EQ(pdu2u.size(), static_cast<size_t>(9));
    CHECK_EQ(pdu2u[2], static_cast<uint8_t>(0x40));
    CHECK_EQ(pdu2u[3], static_cast<uint8_t>(0x02));  // X2 up: 0x0002
    CHECK_EQ(pdu2u[4], static_cast<uint8_t>(0x00));
}

RTSC_TEST(client_send_sas_and_pause_write_the_expected_pdus) {
    Client c(MakeDriver(), 16, 16);
    ScriptedTransport t;
    std::string error;
    // Mirrors the GUI command dispatch (tools/rtsc_gui/main.cpp): a kUiCommand
    // carrying kCmdSendCtrlAltDel / kCmdSendPause is routed to the matching
    // Client method instead of the ordinary input path.
    const auto dispatch = [&](const InputEvent& ev, std::string& err) {
        if (ev.command == kCmdSendCtrlAltDel) return c.SendCtrlAltDel(t, err);
        if (ev.command == kCmdSendPause) return c.SendPauseKey(t, err);
        return false;
    };

    InputEvent sas;
    sas.kind = InputEvent::Kind::kUiCommand;
    sas.command = kCmdSendCtrlAltDel;
    CHECK(dispatch(sas, error));
    // The six-scancode SAS (Ctrl/Alt/Delete down, Delete/Alt/Ctrl up) framed as
    // one Fast-Path input PDU ([MS-RDPBCGR] 2.2.8.1.2).
    CHECK(Hex(t.last_write) == "180e001d0038025303530138011d");

    InputEvent pause;
    pause.kind = InputEvent::Kind::kUiCommand;
    pause.command = kCmdSendPause;
    CHECK(dispatch(pause, error));
    // Pause = CTRL(EXTENDED1)+NUMLOCK sequence (04 1d / 00 45 / 05 1d / 01 45)
    // framed as one Fast-Path input PDU.
    CHECK(Hex(t.last_write) == "100a041d0045051d0145");
}

RTSC_TEST(client_ignores_close_event) {
    Client c(MakeDriver(), 16, 16);
    InputEvent e;
    e.kind = InputEvent::Kind::kClose;
    CHECK(c.EncodeInput(e).empty());
}

// A silent peer is the normal idle case, not a disconnect: Pump must keep the
// session alive (and must not set an error) so the UI loop can carry on pumping
// window messages. This is the regression guard for the "window not responding
// while the server is quiet" bug.
RTSC_TEST(client_pump_returns_true_on_read_timeout) {
    Client c(MakeDriver(), 16, 16);
    ScriptedTransport t;
    t.next = rtsc::net::kReadTimeout;
    std::string error = "sentinel";
    CHECK(c.Pump(t, error));
    CHECK(error == "sentinel");  // a bounded-wait timeout is not an error
    CHECK_EQ(t.reads, 1);
    CHECK_EQ(t.writes, 0);  // nothing to send back
}

// An orderly EOF is a real disconnect and must end the session.
RTSC_TEST(client_pump_returns_false_on_peer_close) {
    Client c(MakeDriver(), 16, 16);
    ScriptedTransport t;
    t.next = 0;  // orderly EOF
    std::string error;
    CHECK(!c.Pump(t, error));
    CHECK(!error.empty());
}

// A socket error is a real failure and must end the session with a reason.
RTSC_TEST(client_pump_returns_false_on_read_error) {
    Client c(MakeDriver(), 16, 16);
    ScriptedTransport t;
    t.next = -1;  // socket error
    std::string error;
    CHECK(!c.Pump(t, error));
    CHECK(!error.empty());
}

// Connect must ride through a bounded-wait timeout (the server has not answered
// yet) and only fail when the peer actually closes.
RTSC_TEST(client_connect_retries_past_read_timeouts) {
    Client c(MakeDriver(), 16, 16);
    ScriptedTransport t;
    t.timeout_budget = 3;  // three silent reads...
    t.next = 0;            // ...then the peer closes
    std::string error;
    CHECK(!c.Connect(t, error));
    CHECK(!error.empty());
    CHECK_EQ(t.reads, 4);  // the timeouts were retried, not fatal
}

#if defined(_WIN32)
// End-to-end proof that a connected-but-silent peer cannot stall Read(): before
// the fix the socket blocked for the 30 s SO_RCVTIMEO (freezing the UI); now it
// returns kReadTimeout within the bounded wait, and an orderly close surfaces as
// EOF (0). The 2 s bound is far below the old 30 s stall.
RTSC_TEST(client_read_is_bounded_on_a_silent_peer) {
    WSADATA wsa;
    CHECK(::WSAStartup(MAKEWORD(2, 2), &wsa) == 0);

    SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(listener != INVALID_SOCKET);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    CHECK(::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    int addr_len = sizeof(addr);
    CHECK(::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addr_len) ==
          0);
    CHECK(::listen(listener, 1) == 0);

    std::string error;
    auto transport =
        rtsc::net::ConnectTcp("127.0.0.1", ntohs(addr.sin_port), error);
    CHECK(transport != nullptr);
    if (transport == nullptr) {
        ::closesocket(listener);
        ::WSACleanup();
        return;
    }

    SOCKET server = ::accept(listener, nullptr, nullptr);
    CHECK(server != INVALID_SOCKET);

    const auto t0 = std::chrono::steady_clock::now();
    uint8_t buf[64];
    const int n = transport->Read(buf, sizeof(buf));
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0)
            .count();
    CHECK_EQ(n, rtsc::net::kReadTimeout);
    CHECK(elapsed_ms < 2000);

    ::closesocket(server);
    const auto t1 = std::chrono::steady_clock::now();
    const int m = transport->Read(buf, sizeof(buf));
    const auto eof_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t1)
            .count();
    CHECK_EQ(m, 0);
    CHECK(eof_ms < 2000);

    ::closesocket(listener);
    ::WSACleanup();
}
#endif

int main() { return ::rtsc::test::run_all("rtsc_client_tests"); }
