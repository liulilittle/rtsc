// Server-side CLIPRDR end-to-end: one in-process server session and the
// project's own client over Standard RDP Security (PROTOCOL_RDP, plaintext
// data plane on this host), driven on real loopback sockets (blueprint:
// test_server_multisession.cpp).
//
// E1 server->client clipboard round-trip, E2 client->server round-trip, E3
// handshake counts (capabilities each side exactly once, Monitor Ready exactly
// once, Format List Response pair).

#include "rtsc/channel/cliprdr_client.h"
#include "rtsc/channel/cliprdr_server.h"
#include "rtsc/client/client.h"
#include "rtsc/clipboard/clipboard.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/server/server.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;
using rtsc::server::RdpServer;
using rtsc::server::ServerConfig;

namespace {

// A shared clipboard double for both ends. The server HALF is written by the
// server session thread while the test thread reads it, so every accessor is
// mutex-protected. `seq_` is bumped on write but kept as the protocol's
// baseline (the echo-swallow compares against it; no external writes occur in
// these tests).
class FakeClipboard final : public rtsc::clipboard::Clipboard {
 public:
    std::vector<uint32_t> formats() override {
        std::lock_guard<std::mutex> lock(mu_);
        return formats_;
    }
    bool read(uint32_t format, std::vector<uint8_t>& out) override {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = data_.find(format);
        if (it == data_.end()) return false;
        out = it->second;
        return true;
    }
    bool write(uint32_t format, const std::vector<uint8_t>& data) override {
        std::lock_guard<std::mutex> lock(mu_);
        data_[format] = data;
        ++write_count_;
        ++seq_;
        return true;
    }
    uint64_t sequence_number() const override {
        std::lock_guard<std::mutex> lock(mu_);
        return seq_;
    }

    void set(uint32_t format, const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lock(mu_);
        data_[format] = data;
        formats_.push_back(format);
    }
    bool has(uint32_t format, std::vector<uint8_t>& out) const {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = data_.find(format);
        if (it == data_.end()) return false;
        out = it->second;
        return true;
    }
    unsigned writes() const {
        std::lock_guard<std::mutex> lock(mu_);
        return write_count_;
    }

 private:
    mutable std::mutex mu_;
    std::vector<uint32_t> formats_;
    std::map<uint32_t, std::vector<uint8_t>> data_;
    uint64_t seq_ = 0;
    unsigned write_count_ = 0;
};

rtsc::security::ConnectionDriver MakeDriver(uint16_t w, uint16_t h) {
    ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.requested_protocols = kProtocolRdp;
    mcfg.desktop_width = w;
    mcfg.desktop_height = h;
    mcfg.client_name = "RTSC";
    mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
    mcfg.encryption_methods = 0;  // plaintext data plane (cross-platform)

    ConnectMachine::Credentials creds;
    creds.domain = "NTDEV";
    creds.user_name = "rtsc";

    rtsc::security::Config scfg;  // unused by Standard RDP Security
    return rtsc::security::ConnectionDriver(mcfg, creds, scfg);
}

// Pumps the client until `pred` holds or the deadline elapses. Returns whether
// the predicate ever held.
template <typename Pred>
bool PumpUntil(rtsc::client::Client& client, rtsc::net::Transport& transport,
               std::chrono::milliseconds timeout, Pred pred) {
    const auto deadline =
        std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::string error;
        if (!client.Pump(transport, error)) return pred();
    }
    return pred();
}

}  // namespace

// E1: server -> client. The server clipboard holds a text format; the client
// learns it through the handshake and the data round-trips onto the client
// clipboard via the client's eager format request.
RTSC_TEST(e2e_cliprdr_server_to_client_round_trip) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    FakeClipboard server_clip;
    const std::vector<uint8_t> server_text = {0x48, 0x00, 0x69, 0x00,
                                              0xA8, 0x01};
    server_clip.set(kCfUnicodeText, server_text);

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetClipboard(&server_clip);
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    std::string cerr;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", server.bound_port(), cerr);
    CHECK(transport != nullptr);
    if (transport == nullptr) {
        server.Stop();
        runner.join();
        return;
    }
    rtsc::client::Client client(MakeDriver(64, 48), 64, 48);
    FakeClipboard client_clip;
    std::atomic<bool> send_failed{false};
    rtsc::channel::CliprdrClient client_cliprdr(
        &client_clip, [&](const std::vector<uint8_t>& message) {
            std::string perr;
            if (!client.SendChannelPdu(*transport, 1005, message, perr)) {
                send_failed.store(true);
            }
        });
    client.RegisterChannel(
        1005, [&](const uint8_t* data, size_t size) {
            client_cliprdr.OnChannelData(data, size);
        });

    CHECK(client.Connect(*transport, cerr));
    // The name table pairs cliprdr with the server-assigned channel id.
    CHECK_EQ(client.driver().ChannelIdForName("cliprdr"),
             static_cast<uint16_t>(1005));
    client_cliprdr.Start();

    // The client applied the server-clipboard text.
    std::vector<uint8_t> got;
    const bool ok = PumpUntil(
        client, *transport, std::chrono::seconds(8),
        [&]() { return client_clip.has(kCfUnicodeText, got); });
    CHECK(ok);
    CHECK(got == server_text);
    CHECK(client_clip.writes() >= 1);
    CHECK(!send_failed.load());

    transport->Close();
    server.Stop();
    runner.join();
}

// E2: client -> server. The client clipboard holds a text format; the server
// learns it and the data round-trips onto the server clipboard through the
// server's eager format request (written on the server session thread).
RTSC_TEST(e2e_cliprdr_client_to_server_round_trip) {
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    FakeClipboard server_clip;

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetClipboard(&server_clip);
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    std::string cerr;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", server.bound_port(), cerr);
    CHECK(transport != nullptr);
    if (transport == nullptr) {
        server.Stop();
        runner.join();
        return;
    }
    rtsc::client::Client client(MakeDriver(64, 48), 64, 48);
    FakeClipboard client_clip;
    const std::vector<uint8_t> client_text = {0x77, 0x00, 0x6F, 0x00,
                                              0x72, 0x00, 0x6C, 0x00,
                                              0x64, 0x00};
    client_clip.set(kCfUnicodeText, client_text);
    std::atomic<bool> send_failed{false};
    rtsc::channel::CliprdrClient client_cliprdr(
        &client_clip, [&](const std::vector<uint8_t>& message) {
            std::string perr;
            if (!client.SendChannelPdu(*transport, 1005, message, perr)) {
                send_failed.store(true);
            }
        });
    client.RegisterChannel(
        1005, [&](const uint8_t* data, size_t size) {
            client_cliprdr.OnChannelData(data, size);
        });

    CHECK(client.Connect(*transport, cerr));
    client_cliprdr.Start();

    // The server applied the client-clipboard text to its own clipboard.
    std::vector<uint8_t> got;
    const bool ok = PumpUntil(
        client, *transport, std::chrono::seconds(8),
        [&]() { return server_clip.has(kCfUnicodeText, got); });
    CHECK(ok);
    CHECK(got == client_text);
    CHECK(server_clip.writes() >= 1);
    CHECK(!send_failed.load());

    transport->Close();
    server.Stop();
    runner.join();
}

// E3: handshake counts observed on the client side (the only authoritative
// view the test owns): server capabilities received exactly once, Monitor
// Ready exactly once, one remote format list, and the Format List Response
// pair, with both ends' capability exchanges completed.
RTSC_TEST(e2e_cliprdr_handshake_counts) {
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    FakeClipboard server_clip;
    server_clip.set(kCfUnicodeText, {0x48, 0x00, 0x69, 0x00});

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetClipboard(&server_clip);
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    std::string cerr;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", server.bound_port(), cerr);
    CHECK(transport != nullptr);
    if (transport == nullptr) {
        server.Stop();
        runner.join();
        return;
    }
    rtsc::client::Client client(MakeDriver(64, 48), 64, 48);
    FakeClipboard client_clip;
    client_clip.set(kCfUnicodeText, {0x77, 0x00, 0x6F, 0x00});
    std::atomic<bool> send_failed{false};
    rtsc::channel::CliprdrClient client_cliprdr(
        &client_clip, [&](const std::vector<uint8_t>& message) {
            std::string perr;
            if (!client.SendChannelPdu(*transport, 1005, message, perr)) {
                send_failed.store(true);
            }
        });
    client.RegisterChannel(
        1005, [&](const uint8_t* data, size_t size) {
            client_cliprdr.OnChannelData(data, size);
        });

    CHECK(client.Connect(*transport, cerr));
    client_cliprdr.Start();

    // Let both directions settle: the server applies the client's text and the
    // client applies the server's text.
    const bool settled = PumpUntil(
        client, *transport, std::chrono::seconds(8),
        [&]() {
            std::vector<uint8_t> a, b;
            return client_clip.has(kCfUnicodeText, a) &&
                   server_clip.has(kCfUnicodeText, b) && client_clip.writes() >= 1 &&
                   server_clip.writes() >= 1;
        });
    CHECK(settled);
    CHECK(!send_failed.load());

    // Server caps received exactly once (the server sent its caps once).
    CHECK_EQ(client_cliprdr.server_caps_count(), static_cast<unsigned>(1));
    // Monitor Ready PDUs received exactly once: the server's "恰一次".
    CHECK_EQ(client_cliprdr.monitor_ready_received_count(),
             static_cast<unsigned>(1));
    // The server advertised exactly one format list.
    CHECK_EQ(client_cliprdr.remote_format_list_count(), static_cast<unsigned>(1));
    // Client caps sent exactly once (server received exactly one).
    CHECK_EQ(client_cliprdr.clip_caps_count(), static_cast<unsigned>(1));
    // Format List Response pair: one sent by each side.
    CHECK_EQ(client_cliprdr.format_list_response_count(), static_cast<unsigned>(1));
    CHECK_EQ(client_cliprdr.format_list_response_received_count(),
             static_cast<unsigned>(1));
    CHECK_EQ(client_cliprdr.last_format_list_response_ok(), true);
    // The channel is fully negotiated.
    CHECK(client_cliprdr.server_caps_received());
    CHECK_EQ(client_cliprdr.long_format_names(), true);

    transport->Close();
    server.Stop();
    runner.join();
}

int main() { return rtsc::test::run_all("rtsc_server_cliprdr_e2e_tests"); }