// End-to-end client: construction and input encoding.
//
// The connection sequence itself is covered by the driver's full-flow test and
// the graphics compositing by the graphics test; this checks the glue: the
// client builds, owns a surface of the requested size, and turns window events
// into the right Fast-Path input PDUs.

#include "rtsc/client/client.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/net/transport.h"
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
// closes.
class ScriptedTransport final : public rtsc::net::Transport {
 public:
    int next = 0;
    int reads = 0;
    int writes = 0;
    int timeout_budget = -1;  // -1 = never time out

    int Read(uint8_t*, size_t) override {
        ++reads;
        if (timeout_budget > 0) {
            --timeout_budget;
            return rtsc::net::kReadTimeout;
        }
        return next;
    }
    bool Write(const uint8_t*, size_t) override {
        ++writes;
        return true;
    }
    void Close() override {}
};

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
    Client c(MakeDriver(), 16, 16);
    InputEvent w;
    w.kind = InputEvent::Kind::kMouseWheel;
    w.wheel_delta = -1;  // scroll down
    const auto pdu = c.EncodeInput(w);
    CHECK_EQ(pdu.size(), static_cast<size_t>(9));
    // PTRFLAGS_WHEEL (0x0200) | PTRFLAGS_WHEEL_NEGATIVE (0x0100) | 1 = 0x0301.
    CHECK_EQ(pdu[3], static_cast<uint8_t>(0x01));
    CHECK_EQ(pdu[4], static_cast<uint8_t>(0x03));
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
