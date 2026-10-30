// Server-side RDPSND end-to-end: the RdpsndServer audio handler streams the
// deterministic sine capture source to the project's own RdpsndClient, twice —
// once as back-to-back handler objects in one process (which exposes the server
// session's diagnostic counters) and once over a real loopback session
// (RdpServer + ConnectionDriver + RdpsndClient + MockSink), the same wiring the
// cliprdr/rdpdr e2e tests use. A third test runs two concurrent loopback
// clients against one server and asserts both receive audio. Design 7.6:
//
//   E1 the handshake pair completes (formats -> quality -> training ->
//      training-confirm) and both state machines reach READY;
//   E2 the server streams Wave2 blocks of the sine source; the client confirms
//      every one, so wave_confirm == wave2 on both sides and in_flight == 0;
//   E3 the client sink receives 20 ms / 3528-byte 44100/16/2 PCM blocks;
//   E4 over the real loopback session the client sees the wire-visible half of
//      the handshake, the rdpsnd channel id from the name table is 1006
//      (kFirstStaticChannelId + index 2), audio flows, and a client disconnect
//      releases the server session (session_count -> 0);
//   E5 two concurrent clients on one server both negotiate and stream.

#include "rtsc/channel/rdpsnd_client.h"
#include "rtsc/channel/rdpsnd_server.h"
#include "rtsc/client/client.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/server/server.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "rtsc/audio/audio_source.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;
using rtsc::audio::AudioSink;
using rtsc::audio::PcmFormat;
using rtsc::channel::RdpsndClient;
using rtsc::channel::RdpsndServer;
using rtsc::server::RdpServer;
using rtsc::server::ServerConfig;

namespace {

constexpr uint16_t kRdpsndChannelId = 1006;  // kFirstStaticChannelId + index 2

// Records every audio block the client consumes.
class MockSink final : public AudioSink {
 public:
    void Submit(const std::vector<uint8_t>& pcm,
                const PcmFormat& format) override {
        submitted_.push_back(pcm);
        formats_.push_back(format);
        bytes_ += pcm.size();
    }
    void SetVolume(uint16_t, uint16_t) override {}
    bool ok() const override { return true; }

    size_t bytes() const { return bytes_; }
    size_t blocks() const { return submitted_.size(); }
    const PcmFormat& last_format() const { return formats_.back(); }

 private:
    std::vector<std::vector<uint8_t>> submitted_;
    std::vector<PcmFormat> formats_;
    size_t bytes_ = 0;
};

// The handshake-pair harness. The two handlers pass real CHANNEL_PDU chunks to
// each other through the delivery queues; nothing is mocked at the protocol
// layer.
struct Pair {
    std::vector<std::vector<uint8_t>> server_to_client;
    std::vector<std::vector<uint8_t>> client_to_server;
    std::unique_ptr<RdpsndServer> server;
    std::unique_ptr<RdpsndClient> client;
    std::unique_ptr<MockSink> sink;
    std::chrono::steady_clock::time_point t0;
};

// Constructs the handlers in a caller-owned Pair. The send lambdas capture the
// Pair's address, so the Pair must not be moved afterwards.
void InitPair(Pair& p) {
    p.sink = std::make_unique<MockSink>();
    p.server = std::make_unique<RdpsndServer>(
        rtsc::audio::CreateSineSource(),
        [&p](const std::vector<uint8_t>& chunk) {
            p.server_to_client.push_back(chunk);
        });
    p.client = std::make_unique<RdpsndClient>(
        p.sink.get(), [&p](const std::vector<uint8_t>& chunk) {
            p.client_to_server.push_back(chunk);
        });
    p.t0 = std::chrono::steady_clock::now();
}

// Delivers every queued chunk in both directions once.
void PumpPair(Pair& p) {
    auto s2c = std::move(p.server_to_client);
    auto c2s = std::move(p.client_to_server);
    for (const auto& chunk : s2c) {
        p.client->OnChannelData(chunk.data(), chunk.size());
    }
    for (const auto& chunk : c2s) {
        p.server->OnChannelData(chunk.data(), chunk.size());
    }
}

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
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::string error;
        if (!client.Pump(transport, error)) return pred();
    }
    return pred();
}

}  // namespace

// E1+E2+E3 at the handler level: the two halves of the channel complete the
// whole [MS-RDPEA] sequence on their real wire encoding, the server streams the
// sine source, and the client confirms each block.
RTSC_TEST(rdpsnd_e2e_handler_pair_streams_and_confirms) {
    Pair p;
    InitPair(p);
    p.server->Start();
    for (int i = 0; i < 8 && p.server->phase() != RdpsndServer::Phase::kReady;
         ++i) {
        PumpPair(p);
    }

    // E1: both state machines reached READY and the server-side diagnostics
    // reflect the exact handshake exchange.
    CHECK(p.server->phase() == RdpsndServer::Phase::kReady);
    CHECK(p.server->started());
    CHECK(p.server->client_alive());
    CHECK(p.server->format_valid());
    CHECK_EQ(p.server->client_version(), static_cast<uint16_t>(8));
    CHECK_EQ(p.server->server_formats_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->client_formats_count(), static_cast<unsigned>(1));
    // D-A: the server never sends a Quality Mode PDU (it is client-to-server);
    // it only relays the client's into the training handshake.
    CHECK_EQ(p.server->quality_mode_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->training_sent_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->training_confirm_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->out_of_order_count(), static_cast<unsigned>(0));
    CHECK_EQ(p.server->malformed_pdu_count(), static_cast<unsigned>(0));
    // The client's mirror: one of each incoming, one of each outgoing.
    CHECK_EQ(p.client->server_formats_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.client->client_formats_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.client->quality_mode_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.client->training_confirm_count(), static_cast<unsigned>(1));

    // E2+E3: stream ten 20 ms blocks; every one is delivered and confirmed.
    auto now = p.t0;
    for (int i = 0; i < 10; ++i) {
        now += std::chrono::milliseconds(25);
        p.server->Poll(now);
        PumpPair(p);
        PumpPair(p);
    }
    PumpPair(p);

    CHECK_EQ(p.server->wave2_count(), static_cast<unsigned>(10));
    CHECK_EQ(p.client->wave2_count(), static_cast<unsigned>(10));
    CHECK_EQ(p.client->wave_confirm_count(), static_cast<unsigned>(10));
    CHECK_EQ(p.client->wave_confirm_count(), p.client->wave2_count());
    // Every confirm reached the server: nothing stays in flight, nothing was
    // dropped.
    CHECK_EQ(p.server->wave_confirm_count(), p.server->wave2_count());
    CHECK_EQ(p.server->in_flight(), static_cast<size_t>(0));
    CHECK_EQ(p.server->dropped_blocks(), static_cast<unsigned>(0));
    CHECK_EQ(p.server->bytes_sent(), static_cast<size_t>(10 * 3528));

    CHECK_EQ(p.sink->blocks(), static_cast<size_t>(10));
    CHECK_EQ(p.sink->bytes(), static_cast<size_t>(10 * 3528));
    CHECK_EQ(p.sink->last_format().channels, static_cast<uint16_t>(2));
    CHECK_EQ(p.sink->last_format().samples_per_sec, static_cast<uint32_t>(44100));
    CHECK_EQ(p.sink->last_format().bits_per_sample, static_cast<uint16_t>(16));
}

// E4: the wire-visible half of the handshake and the audio flow over a real
// loopback session, and the channel id the name table assigns ("rdpdr"=1004,
// "cliprdr"=1005, "rdpsnd"=1006).
RTSC_TEST(rdpsnd_e2e_loopback_streams_audio) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    cfg.audio_source_factory = [] {
        return rtsc::audio::CreateSineSource();
    };
    auto pattern = rtsc::server::MakeTestPatternSource();

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
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
    std::atomic<bool> send_failed{false};
    auto sink = std::make_shared<MockSink>();
    RdpsndClient client_rdpsnd(
        sink.get(),
        [&](const std::vector<uint8_t>& message) {
            std::string perr;
            if (!client.SendChannelPdu(*transport, kRdpsndChannelId, message,
                                       perr)) {
                send_failed.store(true);
            }
        });
    client.RegisterChannel(kRdpsndChannelId, [&](const uint8_t* data,
                                                size_t size) {
        client_rdpsnd.OnChannelData(data, size);
    });

    CHECK(client.Connect(*transport, cerr));
    // The name table pairs rdpsnd with the server-assigned channel id.
    CHECK_EQ(client.driver().ChannelIdForName("rdpsnd"), kRdpsndChannelId);
    CHECK_EQ(client.driver().ChannelIdForName("rdpdr"),
             static_cast<uint16_t>(1004));
    CHECK_EQ(client.driver().ChannelIdForName("cliprdr"),
             static_cast<uint16_t>(1005));

    // E4a: the full handshake completes over the wire.
    const bool handshake = PumpUntil(
        client, *transport, std::chrono::seconds(8),
        [&]() {
            return client_rdpsnd.server_formats_count() >= 1u &&
                   client_rdpsnd.client_formats_count() >= 1u &&
                   client_rdpsnd.training_confirm_count() >= 1u;
        });
    CHECK(handshake);
    if (!handshake) {
        transport->Close();
        server.Stop();
        runner.join();
        return;
    }
    CHECK_EQ(client_rdpsnd.server_formats_count(), static_cast<unsigned>(1));
    CHECK_EQ(client_rdpsnd.client_formats_count(), static_cast<unsigned>(1));
    CHECK_EQ(client_rdpsnd.quality_mode_count(), static_cast<unsigned>(1));

    // E4b: the server streams the sine source and the client confirms each
    // Wave2.
    const bool streamed = PumpUntil(
        client, *transport, std::chrono::seconds(8),
        [&]() { return client_rdpsnd.wave2_count() > 0u; });
    CHECK(streamed);
    if (streamed) {
        CHECK_EQ(client_rdpsnd.wave_confirm_count(),
                 client_rdpsnd.wave2_count());
        CHECK(sink->bytes() > 0);
        CHECK_EQ(sink->last_format().channels, static_cast<uint16_t>(2));
        CHECK_EQ(sink->last_format().samples_per_sec,
                 static_cast<uint32_t>(44100));
        CHECK_EQ(sink->last_format().bits_per_sample, static_cast<uint16_t>(16));
        CHECK_EQ(sink->bytes() % 3528, static_cast<size_t>(0));
    }
    CHECK(!send_failed.load());

    transport->Close();
    server.Stop();
    runner.join();
    // E4c: the disconnect released the session.
    CHECK_EQ(server.session_count(), static_cast<size_t>(0));
    CHECK_EQ(server.total_session_count(), static_cast<size_t>(1));
}

// E5: two concurrent loopback clients against one server both negotiate and
// receive audio from their own per-session sine sources.
RTSC_TEST(rdpsnd_e2e_two_clients_both_receive) {
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    cfg.audio_source_factory = [] {
        return rtsc::audio::CreateSineSource();
    };
    auto pattern = rtsc::server::MakeTestPatternSource();

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    std::atomic<bool> c1_ok{false};
    std::atomic<bool> c2_ok{false};
    std::atomic<unsigned> c1_wave2{0};
    std::atomic<unsigned> c2_wave2{0};
    std::atomic<size_t> c1_bytes{0};
    std::atomic<size_t> c2_bytes{0};

    auto run_client = [&](std::atomic<bool>& ok, std::atomic<unsigned>& wave2,
                          std::atomic<size_t>& bytes) {
        std::string cerr;
        auto transport =
            rtsc::net::ConnectTcp("127.0.0.1", server.bound_port(), cerr);
        if (transport == nullptr) return;
        rtsc::client::Client client(MakeDriver(64, 48), 64, 48);
        std::atomic<bool> send_failed{false};
        auto sink = std::make_shared<MockSink>();
        RdpsndClient client_rdpsnd(
            sink.get(),
            [&](const std::vector<uint8_t>& message) {
                std::string perr;
                if (!client.SendChannelPdu(*transport, kRdpsndChannelId,
                                           message, perr)) {
                    send_failed.store(true);
                }
            });
        client.RegisterChannel(kRdpsndChannelId, [&](const uint8_t* data,
                                                    size_t size) {
            client_rdpsnd.OnChannelData(data, size);
        });

        if (!client.Connect(*transport, cerr)) {
            transport->Close();
            return;
        }
        if (client.driver().ChannelIdForName("rdpsnd") != kRdpsndChannelId) {
            transport->Close();
            return;
        }
        const bool streamed = PumpUntil(
            client, *transport, std::chrono::seconds(8),
            [&]() { return client_rdpsnd.wave2_count() > 0u; });
        if (streamed && !send_failed.load()) {
            ok.store(true);
            wave2.store(client_rdpsnd.wave2_count());
            bytes.store(sink->bytes());
        }
        transport->Close();
    };

    std::thread t1(run_client, std::ref(c1_ok), std::ref(c1_wave2),
                   std::ref(c1_bytes));
    std::thread t2(run_client, std::ref(c2_ok), std::ref(c2_wave2),
                   std::ref(c2_bytes));
    t1.join();
    t2.join();

    server.Stop();
    runner.join();

    CHECK(c1_ok.load());
    CHECK(c2_ok.load());
    CHECK(c1_wave2.load() > 0u);
    CHECK(c2_wave2.load() > 0u);
    CHECK(c1_bytes.load() > 0);
    CHECK(c2_bytes.load() > 0);
    // Two sessions ran and both were released on disconnect.
    CHECK_EQ(server.total_session_count(), static_cast<size_t>(2));
    CHECK_EQ(server.session_count(), static_cast<size_t>(0));
}

int main() { return rtsc::test::run_all("rtsc_server_rdpsnd_e2e_tests"); }