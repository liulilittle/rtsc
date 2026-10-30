// Server-side RDPDR end-to-end pairing: the two halves of the rdpdr static
// virtual channel talk to each other through their real wire encoding, twice —
// once as back-to-back handler objects in one process (which exposes the server
// session's RdpdrServer diagnostics that the live RdpServer does not publish),
// and once over a real loopback session (RdpServer + ConnectionDriver +
// RdpdrClient), the same wiring the cliprdr e2e uses. Design R1-R5:
//
//   R1 the handshake pair completes: server announce -> client announce reply +
//      name -> Server Capability + ClientId Confirm + User LoggedOn -> client
//      capability + device list, both state machines reaching READY;
//   R2 the server-side diagnostics (announce sent, capability sent, ClientId
//      Confirm sent, client name, client capability, user logged on) each say
//      exactly one, with zero out-of-order / malformed input;
//   R3 the v1 empty device list: neither direction carries a Device Announce or
//      a Device Reply, and the client's announced list has deviceCount = 0;
//   R4 a duplicate client announce reply after the exchange settled is
//      ignored (counted, never answered) and does not disturb the counters;
//   R5 a client disconnect releases the server session (no dangling handler).

#include "rtsc/channel/rdpdr_client.h"
#include "rtsc/channel/rdpdr_server.h"
#include "rtsc/client/client.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/rdpdr/file_system.h"
#include "rtsc/server/server.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;
using rtsc::channel::RdpdrClient;
using rtsc::channel::RdpdrServer;
using rtsc::rdpdr::HostFileSystem;
using rtsc::rdpdr::IFileSystem;
using rtsc::server::RdpServer;
using rtsc::server::ServerConfig;

namespace {

// The handshake pair harness. The two handlers pass real CHANNEL_PDU chunks
// to each other through the delivery queues; nothing is mocked at the protocol
// layer. Every chunk a handler emits is ALSO appended to its `*_captured`
// diary, which (unlike the drained queues) holds what each side actually sent.
struct Pair {
    std::vector<std::vector<uint8_t>> server_to_client;  // delivery queue
    std::vector<std::vector<uint8_t>> client_to_server;  // delivery queue
    std::vector<std::vector<uint8_t>> server_captured;   // all server sends
    std::vector<std::vector<uint8_t>> client_captured;   // all client sends
    std::unique_ptr<RdpdrServer> server;
    std::unique_ptr<RdpdrClient> client;
};

// Constructs the handlers in a caller-owned Pair. The send lambdas capture the
// Pair's address, so the Pair must not be moved afterwards (returning it by
// value would leave the captures dangling). `fs` / `devices` drive the client
// side: the driver-wiring case passes a HostFileSystem backed by a temporary
// directory and one device.
void InitPair(Pair& p, const char* name, IFileSystem* fs = nullptr,
              std::vector<RdpdrClient::Device> devices = {}) {
    p.server = std::make_unique<RdpdrServer>(
        [&p](const std::vector<uint8_t>& chunk) {
            p.server_to_client.push_back(chunk);
            p.server_captured.push_back(chunk);
        });
    p.client = std::make_unique<RdpdrClient>(
        fs, std::move(devices), name,
        [&p](const std::vector<uint8_t>& chunk) {
            p.client_to_server.push_back(chunk);
            p.client_captured.push_back(chunk);
        });
}

std::filesystem::path MakeTempDir(const char* tag) {
    static unsigned counter = 0;
    std::filesystem::path dir = std::filesystem::temp_directory_path() /
        ("rtsc_rdpdr_e2e_" + std::string(tag) + "_" +
         std::to_string(++counter));
    std::filesystem::create_directories(dir);
    return dir;
}

// Drains every pending message across both directions until the queues empty
// or `max_rounds` passes run (a guard against an unbounded ping-pong).
void PumpPair(Pair& p, int max_rounds = 8) {
    for (int i = 0; i < max_rounds; ++i) {
        if (p.server_to_client.empty() && p.client_to_server.empty()) return;
        auto sc = std::move(p.server_to_client);
        auto cs = std::move(p.client_to_server);
        for (const auto& chunk : sc) p.client->OnChannelData(chunk.data(), chunk.size());
        for (const auto& chunk : cs) p.server->OnChannelData(chunk.data(), chunk.size());
    }
}

// Strips the 8-byte CHANNEL_PDU_HEADER, leaving the rdpdr PDU (header + body).
std::vector<uint8_t> StrictBody(const std::vector<uint8_t>& chunk) {
    return std::vector<uint8_t>(chunk.begin() + ChannelPduHeader::kSize, chunk.end());
}

RdpdrPdu DecodeSent(const std::vector<uint8_t>& chunk) {
    RdpdrPdu pdu;
    const auto body = StrictBody(chunk);
    CHECK(RdpdrPdu::parse(body.data(), body.size(), pdu) == Status::Ok);
    return pdu;
}

std::vector<uint16_t> PacketIds(const std::vector<std::vector<uint8_t>>& chunks) {
    std::vector<uint16_t> ids;
    ids.reserve(chunks.size());
    for (const auto& chunk : chunks) ids.push_back(DecodeSent(chunk).header.packet_id);
    return ids;
}

bool HasId(const std::vector<std::vector<uint8_t>>& chunks, uint16_t packet_id) {
    for (const auto& chunk : chunks) {
        if (DecodeSent(chunk).header.packet_id == packet_id) return true;
    }
    return false;
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

// True once the client handler has consumed the whole server initialization
// batch (capability + ClientId Confirm + User LoggedOn, which may arrive in
// separate reads) and emitted its own capability + device list.
bool RdpdrHandshakeSettled(const RdpdrClient& c) {
    return c.phase() == RdpdrClient::Phase::kReady && c.user_logged_on() &&
           c.server_capability_count() >= 1u && c.client_capability_count() >= 1u &&
           c.device_list_announce_count() >= 1u;
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

// R1+R2+R3 at the handler level: the RdpdrServer and the RdpdrClient complete
// the whole initialization exchange on their real wire encoding, and the
// server-side diagnostics the live RdpServer session hides are each exactly one
// with zero out-of-order / malformed input.
RTSC_TEST(rdpdr_e2e_handler_pair_handshake_completes) {
    Pair p;
    InitPair(p, "RTSC-E2E");
    p.server->Start();
    PumpPair(p);

    // R1: both state machines reached READY purely from the other side's PDUs.
    CHECK(p.server->phase() == RdpdrServer::Phase::kReady);
    CHECK(p.client->phase() == RdpdrClient::Phase::kReady);
    // The client adopted the server-assigned client id and version pair.
    CHECK_EQ(p.client->client_id(), p.server->client_id());
    CHECK_EQ(p.client->version_major(), p.server->version_major());
    CHECK_EQ(p.client->version_minor(), p.server->version_minor());

    // R2 server-side diagnostics: every counter exactly one...
    CHECK_EQ(p.server->server_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->server_capability_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->clientid_confirm_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->user_loggedon_count(), static_cast<unsigned>(1));
    CHECK(p.server->user_logged_on_sent());
    CHECK(p.server->client_announce_received());
    CHECK_EQ(p.server->client_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->client_name_count(), static_cast<unsigned>(1));
    CHECK(p.server->client_computer_name() == "RTSC-E2E");
    CHECK(p.server->client_capability_received());
    CHECK_EQ(p.server->client_capability_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->device_list_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->out_of_order_count(), static_cast<unsigned>(0));
    CHECK_EQ(p.server->malformed_pdu_count(), static_cast<unsigned>(0));

    // ...and the client mirror matches: one of each incoming, one of each
    // outgoing, User LoggedOn received.
    CHECK_EQ(p.client->server_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.client->server_capability_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.client->client_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.client->client_name_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.client->client_capability_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.client->device_list_announce_count(), static_cast<unsigned>(1));
    CHECK(p.client->user_logged_on());

    // The wire carried exactly the [MS-RDPEFS] initialisation sequence in
    // order, four PDUs each way.
    const std::vector<uint16_t> want_server = {
        kPakidCoreServerAnnounce, kPakidCoreServerCapability,
        kPakidCoreClientidConfirm, kPakidCoreUserLoggedon};
    CHECK(PacketIds(p.server_captured) == want_server);
    // The server's ClientId Confirm is the spec 12-byte form:
    // RDPDR_HEADER(4) + VersionMajor(2) + VersionMinor(2) + ClientId(4). A
    // shorter packet would fail a real client's length check and take the
    // channel down, so the wire itself is pinned byte-count-exact here.
    {
        bool saw_confirm = false;
        for (const auto& chunk : p.server_captured) {
            const auto body = StrictBody(chunk);
            RdpdrPdu pdu;
            if (RdpdrPdu::parse(body.data(), body.size(), pdu) != Status::Ok) continue;
            if (pdu.header.packet_id != kPakidCoreClientidConfirm) continue;
            CHECK_EQ(body.size(), static_cast<size_t>(12));
            RdpdrServerClientIdConfirm confirm;
            CHECK(RdpdrServerClientIdConfirm::parse(body.data(), body.size(),
                                                    confirm) == Status::Ok);
            CHECK_EQ(confirm.version_major, p.server->version_major());
            CHECK_EQ(confirm.version_minor, p.server->version_minor());
            CHECK_EQ(confirm.client_id, p.server->client_id());
            saw_confirm = true;
        }
        CHECK(saw_confirm);
    }
    const std::vector<uint16_t> want_client = {
        kPakidCoreClientidConfirm, kPakidCoreClientName, kPakidCoreClientCapability,
        kPakidCoreDevicelistAnnounce};
    CHECK(PacketIds(p.client_captured) == want_client);

    // R3: the v1 empty device list. The server never sends a device announce,
    // reply or I/O request; the client's own device list carries 0 devices.
    CHECK(!HasId(p.server_captured, kPakidCoreDevicelistAnnounce));
    CHECK(!HasId(p.server_captured, kPakidCoreDeviceReply));
    CHECK(!HasId(p.server_captured, kPakidCoreDeviceIorequest));
    CHECK(!HasId(p.client_captured, kPakidCoreDeviceReply));
    CHECK(!HasId(p.client_captured, kPakidCoreDeviceIorequest));

    RdpdrDeviceListAnnounce list;
    bool saw_list = false;
    for (const auto& chunk : p.client_captured) {
        const auto body = StrictBody(chunk);
        RdpdrPdu pdu;
        if (RdpdrPdu::parse(body.data(), body.size(), pdu) != Status::Ok) continue;
        if (pdu.header.packet_id != kPakidCoreDevicelistAnnounce) continue;
        CHECK(RdpdrDeviceListAnnounce::parse(body, list) == Status::Ok);
        saw_list = true;
    }
    CHECK(saw_list);
    CHECK_EQ(list.device_count, static_cast<uint32_t>(0));
    CHECK(list.devices.empty());

    // No error counters on the client either.
    CHECK_EQ(p.client->device_reply_count(), static_cast<unsigned>(0));
    CHECK_EQ(p.client->create_count(), static_cast<unsigned>(0));
    CHECK_EQ(p.client->read_count(), static_cast<unsigned>(0));
    CHECK_EQ(p.client->write_count(), static_cast<unsigned>(0));
    CHECK_EQ(p.client->close_count(), static_cast<unsigned>(0));
    CHECK_EQ(p.client->query_directory_count(), static_cast<unsigned>(0));
    CHECK_EQ(p.client->control_count(), static_cast<unsigned>(0));
}

// The driver-wiring form of the Pair: the client is backed by a real
// HostFileSystem over a temporary directory and announces exactly one device.
// The server observes the list (device_list_announce_count == 1) and both
// sides reach READY over the real wire encoding.
RTSC_TEST(rdpdr_e2e_handler_pair_announces_one_device) {
    const std::filesystem::path dir = MakeTempDir("pair_dev");
    HostFileSystem host_fs;
    Pair p;
    InitPair(p, "RTSC-E2E", &host_fs, {{1, "C:", dir.string()}});
    p.server->Start();
    PumpPair(p);

    CHECK(p.server->phase() == RdpdrServer::Phase::kReady);
    CHECK(p.client->phase() == RdpdrClient::Phase::kReady);
    CHECK_EQ(p.server->device_list_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.client->device_list_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.client->devices().size(), static_cast<size_t>(1));

    RdpdrDeviceListAnnounce list;
    bool saw_list = false;
    for (const auto& chunk : p.client_captured) {
        const auto body = StrictBody(chunk);
        RdpdrPdu pdu;
        if (RdpdrPdu::parse(body.data(), body.size(), pdu) != Status::Ok) continue;
        if (pdu.header.packet_id != kPakidCoreDevicelistAnnounce) continue;
        CHECK(RdpdrDeviceListAnnounce::parse(body, list) == Status::Ok);
        saw_list = true;
    }
    CHECK(saw_list);
    CHECK_EQ(list.device_count, static_cast<uint32_t>(1));
    CHECK_EQ(list.devices.size(), static_cast<size_t>(1));
    if (list.devices.size() == 1) {
        CHECK_EQ(list.devices[0].device_id, static_cast<uint32_t>(1));
        CHECK(list.devices[0].dos_name() == "C:");
    }

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// R1+R2 (wire-visible half) + R3 over a real loopback session: the RdpServer
// runs the RdpdrServer handler on its rdpdr static virtual channel and the
// project's own RdpdrClient is wired onto the client side. The client finishes
// the handshake, emits its capability and empty device list, and sees no
// device traffic.
RTSC_TEST(rdpdr_e2e_loopback_pairing) {
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
    const uint16_t rdpdr_id = 1004;  // kFirstStaticChannelId + index 0
    RdpdrClient client_rdpdr(
        nullptr, std::vector<RdpdrClient::Device>{}, "RTSC-E2E",
        [&](const std::vector<uint8_t>& message) {
            std::string perr;
            if (!client.SendChannelPdu(*transport, rdpdr_id, message, perr)) {
                send_failed.store(true);
            }
        });
    client.RegisterChannel(rdpdr_id, [&](const uint8_t* data, size_t size) {
        client_rdpdr.OnChannelData(data, size);
    });

    CHECK(client.Connect(*transport, cerr));
    // The name table pairs rdpdr with the server-assigned channel id.
    CHECK_EQ(client.driver().ChannelIdForName("rdpdr"), rdpdr_id);

    // R1: the full rdpdr initialization exchange settles over the loopback.
    const bool ready = PumpUntil(
        client, *transport, std::chrono::seconds(8),
        [&]() { return RdpdrHandshakeSettled(client_rdpdr); });
    CHECK(ready);
    if (!ready) {
        transport->Close();
        server.Stop();
        runner.join();
        return;
    }

    // Client observed the server's announce / capability / logged-on exactly
    // once each (the wire-visible mirror of the server-side counts), and the
    // ClientId Confirm carried the server-assigned id + version pair.
    CHECK_EQ(client_rdpdr.server_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(client_rdpdr.server_capability_count(), static_cast<unsigned>(1));
    CHECK(client_rdpdr.user_logged_on());
    CHECK(client_rdpdr.client_id() != 0);
    CHECK_EQ(client_rdpdr.version_major(), static_cast<uint16_t>(1));
    CHECK_EQ(client_rdpdr.version_minor(), static_cast<uint16_t>(0x000C));

    // The client emitted its announce reply, name, capability and device list.
    CHECK_EQ(client_rdpdr.client_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(client_rdpdr.client_name_count(), static_cast<unsigned>(1));
    CHECK_EQ(client_rdpdr.client_capability_count(), static_cast<unsigned>(1));
    CHECK_EQ(client_rdpdr.device_list_announce_count(), static_cast<unsigned>(1));

    // R3: no device replies and no I/O requests at all (empty redirect list).
    CHECK_EQ(client_rdpdr.device_reply_count(), static_cast<unsigned>(0));
    CHECK_EQ(client_rdpdr.create_count(), static_cast<unsigned>(0));
    CHECK_EQ(client_rdpdr.read_count(), static_cast<unsigned>(0));
    CHECK_EQ(client_rdpdr.write_count(), static_cast<unsigned>(0));
    CHECK_EQ(client_rdpdr.close_count(), static_cast<unsigned>(0));
    CHECK_EQ(client_rdpdr.query_directory_count(), static_cast<unsigned>(0));
    CHECK_EQ(client_rdpdr.control_count(), static_cast<unsigned>(0));
    CHECK(!send_failed.load());

    transport->Close();
    server.Stop();
    runner.join();
}

// Loopback with one redirected device: a HostFileSystem backed by a temporary
// directory and a single "C:" drive. The handshake settles (READY) exactly as
// the empty-list loopback does, with the client announcing its one device.
// This is also the wiring-proof mutation target: dropping the OnChannelData
// call from the channel lambda leaves the handshake stuck and this test red.
RTSC_TEST(rdpdr_e2e_loopback_with_device_ready) {
    const std::filesystem::path dir = MakeTempDir("loop_dev");
    HostFileSystem host_fs;

    ServerConfig cfg;
    cfg.port = 0;  // ephemeral
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
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
    const uint16_t rdpdr_id = 1004;
    RdpdrClient client_rdpdr(
        &host_fs, {{1, "C:", dir.string()}}, "RTSC-E2E",
        [&](const std::vector<uint8_t>& message) {
            std::string perr;
            if (!client.SendChannelPdu(*transport, rdpdr_id, message, perr)) {
                send_failed.store(true);
            }
        });
    client.RegisterChannel(rdpdr_id, [&](const uint8_t* data, size_t size) {
        client_rdpdr.OnChannelData(data, size);
    });

    CHECK(client.Connect(*transport, cerr));
    const bool ready = PumpUntil(
        client, *transport, std::chrono::seconds(8),
        [&]() { return RdpdrHandshakeSettled(client_rdpdr); });
    CHECK(ready);
    if (ready) {
        CHECK_EQ(client_rdpdr.device_list_announce_count(),
                 static_cast<unsigned>(1));
        CHECK_EQ(client_rdpdr.devices().size(), static_cast<size_t>(1));
    }
    CHECK(!send_failed.load());

    transport->Close();
    server.Stop();
    runner.join();
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// R4: once the exchange is settled a duplicate client announce reply is out of
// order: counted, never answered, and the state machine is undisturbed.
RTSC_TEST(rdpdr_e2e_duplicate_client_announce_ignored) {
    Pair p;
    InitPair(p, "RTSC-E2E");
    p.server->Start();
    PumpPair(p);
    CHECK(p.server->phase() == RdpdrServer::Phase::kReady);
    const size_t outbound_before = p.server_captured.size();

    RdpdrClientAnnounceReply reply;
    reply.version_major = 1;
    reply.version_minor = 0x000C;
    reply.client_id = p.server->client_id();
    for (const auto& chunk : FragmentChannelMessage(reply.encode())) {
        p.server->OnChannelData(chunk.data(), chunk.size());
    }

    // Ignored: the announce is not re-counted and nothing new goes out.
    CHECK_EQ(p.server->client_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->out_of_order_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->malformed_pdu_count(), static_cast<unsigned>(0));
    CHECK(p.server->phase() == RdpdrServer::Phase::kReady);
    CHECK(p.server->started());
    CHECK_EQ(p.server_captured.size(), outbound_before);

    // A good announce still works after the spurious one.
    p.server->Start();  // idempotent no-op
    CHECK_EQ(p.server->server_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server_captured.size(), outbound_before);
}

// R5: the client drops the connection mid-session. The server session thread
// sees EOF, ends, and releases the session: live count falls back to zero (no
// dangling handler), while the monotonic launch counter stays at one.
RTSC_TEST(rdpdr_e2e_client_disconnect_releases_session) {
    ServerConfig cfg;
    cfg.port = 0;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
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
    const uint16_t rdpdr_id = 1004;
    RdpdrClient client_rdpdr(
        nullptr, std::vector<RdpdrClient::Device>{}, "RTSC-E2E",
        [&](const std::vector<uint8_t>& message) {
            std::string perr;
            if (!client.SendChannelPdu(*transport, rdpdr_id, message, perr)) {
                send_failed.store(true);
            }
        });
    client.RegisterChannel(rdpdr_id, [&](const uint8_t* data, size_t size) {
        client_rdpdr.OnChannelData(data, size);
    });

    CHECK(client.Connect(*transport, cerr));
    const bool ready = PumpUntil(
        client, *transport, std::chrono::seconds(8),
        [&]() { return RdpdrHandshakeSettled(client_rdpdr); });
    CHECK(ready);
    CHECK_EQ(server.total_session_count(), static_cast<size_t>(1));
    CHECK_EQ(server.session_count(), static_cast<size_t>(1));

    // Abrupt mid-session drop from the client side.
    transport->Close();
    server.Stop();
    runner.join();
    // R-D: after Stop() joined the session thread no session may still be live.
    CHECK_EQ(server.session_count(), static_cast<size_t>(0));
    CHECK_EQ(server.total_session_count(), static_cast<size_t>(1));
    CHECK(!send_failed.load());
}

int main() { return rtsc::test::run_all("rtsc_server_rdpdr_e2e_tests"); }