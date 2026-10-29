// RDP server multi-session concurrency.
//
// The server's documented model is "one thread per accepted session" with full
// session isolation (D1): every session owns its X.224/MCS state, its security
// state, its capability sets and its framebuffer. These tests prove that N
// concurrent clients each reach an independent active session: they all connect,
// the session counter reaches N, each session reports its own desktop geometry
// (from its own Demand Active bitmap capability set), and the frame source is
// captured once per session with that session's own dimensions.
//
// The connection uses Standard RDP Security (PROTOCOL_RDP). The cross-platform
// tests keep the data plane plaintext (encryption_methods = 0) because the RSA
// backend is Windows-only: on Linux the server fails closed to plaintext, so an
// encrypted run would not behave the same on both platforms. The per-session
// RSA / RC4 path is covered by the Windows-only test at the bottom.

#include "rtsc/client/client.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "rtsc/channel/cliprdr_client.h"
#include "rtsc/clipboard/clipboard.h"
#include "rtsc/net/transport.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/server/server.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;
using rtsc::server::RdpServer;
using rtsc::server::ServerConfig;

namespace {

// One client's outcome, written only by its own thread.
struct SessionResult {
    bool connected = false;
    bool active = false;
    bool got_frame = false;
    uint16_t desktop_width = 0;
    uint16_t desktop_height = 0;
    std::string error;
};

// The static-channel name table the test clients request (also used by
// MakeDriver below). The server assigns static channel ids 1004 + index in the
// client's name-table order (server.cpp kFirstStaticChannelId), and the client
// driver resolves the same ids from the Server Network Data. Deriving the
// cliprdr id from this table instead of a magic literal keeps the registration
// correct if the table order ever changes.
const std::vector<std::string>& ChannelNameTable() {
    static const std::vector<std::string> kNames = {"rdpdr", "cliprdr",
                                                     "rdpsnd"};
    return kNames;
}

// The cliprdr static channel id this client expects: 1004 + its index in the
// name table. Registration must happen before Connect (post-active channel
// chunks are dispatched as they are read), so the id is derived here; after
// Connect, driver().ChannelIdForName("cliprdr") is asserted to match.
uint16_t CliprdrChannelId() {
    const std::vector<std::string>& names = ChannelNameTable();
    for (size_t i = 0; i < names.size(); ++i) {
        if (names[i] == "cliprdr") {
            return static_cast<uint16_t>(1004u + i);
        }
    }
    return 0;
}

// A Standard RDP Security (PROTOCOL_RDP) driver. `encryption_methods` is 0 for
// the platform-neutral plaintext data plane, or a non-zero bitmap for the
// Windows-only encrypted path.
rtsc::security::ConnectionDriver MakeDriver(uint16_t w, uint16_t h,
                                            uint32_t encryption_methods) {
    ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.requested_protocols = kProtocolRdp;
    mcfg.desktop_width = w;
    mcfg.desktop_height = h;
    mcfg.client_name = "RTSC";
    mcfg.channel_names = ChannelNameTable();
    mcfg.encryption_methods = encryption_methods;

    ConnectMachine::Credentials creds;
    creds.domain = "NTDEV";
    creds.user_name = "rtsc";

    rtsc::security::Config scfg;  // unused by Standard RDP Security
    return rtsc::security::ConnectionDriver(mcfg, creds, scfg);
}

// Connects one client, waits for the active session, then pumps until the
// test-pattern frame lands. `ready`/`go` form a start barrier so the N clients
// connect concurrently instead of one after another.
void RunClient(uint16_t port, uint16_t w, uint16_t h,
               uint32_t encryption_methods, std::atomic<int>& ready,
               std::atomic<int>& go, SessionResult& out) {
    ready.fetch_add(1);
    while (go.load() == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    std::string error;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", port, error);
    if (!transport) {
        out.error = "connect: " + error;
        return;
    }
    rtsc::client::Client client(MakeDriver(w, h, encryption_methods), w, h);
    if (!client.Connect(*transport, error)) {
        out.error = "connect: " + error;
        transport->Close();
        return;
    }
    out.connected = true;
    out.active = client.active();
    out.desktop_width = client.desktop_width();
    out.desktop_height = client.desktop_height();

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!out.got_frame && std::chrono::steady_clock::now() < deadline) {
        if (!client.Pump(*transport, error)) break;
        uint8_t r = 0, g = 0, b = 0, a = 0;
        if (client.surface().GetPixel(0, 0, r, g, b, a) && r == 255 &&
            g == 255 && b == 255 && a == 255) {
            out.got_frame = true;
        }
    }
    if (!out.got_frame && out.error.empty()) out.error = error;
    transport->Close();
}

// A DesktopSource that produces the recognisable test pattern (a bright border)
// and records the dimensions of every capture. Capture runs on a session thread,
// so the log is mutex-protected. It proves the server calls the source once per
// session with that session's own geometry rather than sharing one framebuffer.
class RecordingSource : public rtsc::server::DesktopSource {
  public:
    bool Capture(uint16_t width, uint16_t height,
                 std::vector<uint8_t>& rgba) override {
        {
            std::lock_guard<std::mutex> lock(mu_);
            dims_.emplace_back(width, height);
        }
        rgba.assign(static_cast<size_t>(width) * height * 4, 0);
        for (uint32_t x = 0; x < width; ++x) {
            SetPixel(rgba, width, x, 0, 255, 255, 255);
            SetPixel(rgba, width, x, height - 1, 255, 255, 255);
        }
        for (uint32_t y = 0; y < height; ++y) {
            SetPixel(rgba, width, 0, y, 255, 255, 255);
            SetPixel(rgba, width, width - 1, y, 255, 255, 255);
        }
        return true;
    }

    std::vector<std::pair<uint16_t, uint16_t>> dimensions() {
        std::lock_guard<std::mutex> lock(mu_);
        return dims_;
    }

  private:
    static void SetPixel(std::vector<uint8_t>& rgba, uint16_t width, uint32_t x,
                         uint32_t y, uint8_t r, uint8_t g, uint8_t b) {
        const size_t i = (static_cast<size_t>(y) * width + x) * 4;
        rgba[i + 0] = r;
        rgba[i + 1] = g;
        rgba[i + 2] = b;
        rgba[i + 3] = 255;
    }

    std::mutex mu_;
    std::vector<std::pair<uint16_t, uint16_t>> dims_;
};

struct Spec {
    uint16_t w;
    uint16_t h;
};

// Starts the server's clients concurrently and returns their results. The
// caller keeps `server` and its desktop source alive for the whole call.
std::vector<SessionResult> RunConcurrent(uint16_t port,
                                         const std::vector<Spec>& specs,
                                         uint32_t encryption_methods) {
    std::atomic<int> ready{0};
    std::atomic<int> go{0};
    std::vector<SessionResult> results(specs.size());
    std::vector<std::thread> clients;
    clients.reserve(specs.size());
    for (size_t i = 0; i < specs.size(); ++i) {
        clients.emplace_back(RunClient, port, specs[i].w, specs[i].h,
                             encryption_methods, std::ref(ready),
                             std::ref(go), std::ref(results[i]));
    }
    while (ready.load() < static_cast<int>(specs.size())) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    go.store(1);
    for (auto& t : clients) t.join();
    return results;
}

void ReportResults(const std::vector<SessionResult>& results,
                   const std::vector<Spec>& specs) {
    for (size_t i = 0; i < results.size(); ++i) {
        if (!results[i].error.empty()) {
            std::printf("  client %zu error: %s\n", i, results[i].error.c_str());
        }
        CHECK(results[i].connected);
        CHECK(results[i].active);
        CHECK(results[i].got_frame);
        CHECK_EQ(results[i].desktop_width, specs[i].w);
        CHECK_EQ(results[i].desktop_height, specs[i].h);
    }
}

// ---- cliprdr multi-session concurrency (design: shared clipboard + mutex +
// last-writer-wins) ----------------------------------------------------------
//
// These tests drive N concurrent cliprdr sessions over real loopback sockets
// and one in-memory shared clipboard (the object RdpServer::SetClipboard
// installs; every session's CliprdrServer reads and writes it from its own
// session thread). The double serializes every accessor, which is exactly the
// Win32 backend's process-level mutex behaviour -- the shared-desktop
// concurrency contract under test.

// A thread-safe shared clipboard double. write() models a remote-applied write
// (also bumping the sequence number, which the server sessions' Poll uses for
// change detection); SimulateExternalChange() models a third-party local edit
// on the shared desktop, which the Poll must also notice. `set()` injects
// initial content without bumping the sequence (no phantom change at Start).
class SharedClipboard final : public rtsc::clipboard::Clipboard {
  public:
    std::vector<uint32_t> formats() override {
        std::lock_guard<std::mutex> lock(mu_);
        return formats_;
    }
    bool read(uint32_t format, std::vector<uint8_t>& out) override {
        std::lock_guard<std::mutex> lock(mu_);
        ++read_count_;
        const auto it = data_.find(format);
        if (it == data_.end()) return false;
        out = it->second;
        return true;
    }
    bool write(uint32_t format, const std::vector<uint8_t>& data) override {
        std::lock_guard<std::mutex> lock(mu_);
        data_[format] = data;
        AddFormatLocked(format);
        ++write_count_;
        ++seq_;
        return true;
    }
    uint64_t sequence_number() const override {
        std::lock_guard<std::mutex> lock(mu_);
        return seq_;
    }

    // Direct injection (initial content / a test's local edit). Content only:
    // the sequence number is not bumped.
    void set(uint32_t format, const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lock(mu_);
        data_[format] = data;
        AddFormatLocked(format);
    }
    // A non-protocol local edit on the shared desktop: content plus a
    // sequence-number bump the server sessions' Poll must notice.
    void SimulateExternalChange(uint32_t format,
                                const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lock(mu_);
        data_[format] = data;
        AddFormatLocked(format);
        ++seq_;
    }
    bool has(uint32_t format, std::vector<uint8_t>& out) const {
        std::lock_guard<std::mutex> lock(mu_);
        const auto it = data_.find(format);
        if (it == data_.end()) return false;
        out = it->second;
        return true;
    }
    unsigned writes() const {
        std::lock_guard<std::mutex> lock(mu_);
        return write_count_;
    }
    unsigned reads() const {
        std::lock_guard<std::mutex> lock(mu_);
        return read_count_;
    }

  private:
    void AddFormatLocked(uint32_t format) {
        if (std::find(formats_.begin(), formats_.end(), format) ==
            formats_.end()) {
            formats_.push_back(format);
        }
    }
    mutable std::mutex mu_;
    std::vector<uint32_t> formats_;
    std::map<uint32_t, std::vector<uint8_t>> data_;
    uint64_t seq_ = 0;
    unsigned write_count_ = 0;
    unsigned read_count_ = 0;
};

// One cliprdr client session. Everything the worker thread writes is read only
// after join(), so no field needs its own lock. The transport is closed from
// the test thread in the disconnect test, which the TCP transport tolerates.
struct ClipClient {
    std::unique_ptr<rtsc::net::Transport> transport;
    std::unique_ptr<rtsc::client::Client> client;
    std::unique_ptr<rtsc::channel::CliprdrClient> cliprdr;
    SharedClipboard clip;  // this client's LOCAL clipboard
    std::atomic<bool> send_failed{false};
    std::string error;
    uint16_t channel_id = 0;
    bool connected = false;
    bool active = false;
    bool handshake_done = false;
    bool stable_final = false;
    unsigned local_changes = 0;    // OnLocalClipboardChanged() calls
    unsigned remote_requests = 0;  // RequestRemoteFormat() calls
};

// Connects one client, registers its cliprdr channel handler (before Connect,
// so no post-active channel data is dropped) and drives it until the full
// handshake completes: server ClipCaps + Monitor Ready + Format List answered
// by client caps + format list + the server's Format List Response. Returns
// false (setting `out.error`) on failure.
bool InitClipClient(uint16_t port, uint16_t w, uint16_t h, ClipClient& out) {
    std::string error;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", port, error);
    if (!transport) {
        out.error = "connect: " + error;
        return false;
    }
    out.transport = std::move(transport);

    out.client = std::make_unique<rtsc::client::Client>(MakeDriver(w, h, 0), w, h);
    rtsc::client::Client* client = out.client.get();
    rtsc::net::Transport* tr = out.transport.get();
    const uint16_t cliprdr_id = CliprdrChannelId();
    out.cliprdr = std::make_unique<rtsc::channel::CliprdrClient>(
        &out.clip,
        [client, tr, cliprdr_id, &out](const std::vector<uint8_t>& message) {
            std::string perr;
            if (!client->SendChannelPdu(*tr, cliprdr_id, message, perr)) {
                out.send_failed.store(true);
            }
        });
    rtsc::channel::CliprdrClient* cliprdr = out.cliprdr.get();
    client->RegisterChannel(cliprdr_id, [cliprdr](const uint8_t* data,
                                                  size_t size) {
        cliprdr->OnChannelData(data, size);
    });
    if (!client->Connect(*tr, error)) {
        out.error = "connect: " + error;
        return false;
    }
    out.connected = true;
    out.active = client->active();
    out.channel_id = client->driver().ChannelIdForName("cliprdr");
    out.cliprdr->Start();

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(8);
    auto handshaken = [&]() {
        return cliprdr->server_caps_received() &&
               cliprdr->monitor_ready_received_count() >= 1u &&
               cliprdr->clip_caps_count() >= 1u &&
               cliprdr->format_list_response_count() >= 1u &&
               cliprdr->format_list_response_received_count() >= 1u;
    };
    while (std::chrono::steady_clock::now() < deadline) {
        if (handshaken()) {
            out.handshake_done = true;
            break;
        }
        std::string perr;
        if (!client->Pump(*tr, perr)) {
            out.error = "pump: " + perr;
            return false;
        }
    }
    if (!out.handshake_done) {
        out.error = "cliprdr handshake timeout";
        return false;
    }
    return true;
}

// Pumps `c` until `pred` holds or `timeout` elapses. The first pump failure is
// recorded in `c.error` (a pumped predicate may still have been satisfied).
template <typename Pred>
bool PumpUntil(ClipClient& c, std::chrono::milliseconds timeout, Pred pred) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::string error;
        if (!c.client->Pump(*c.transport, error)) {
            if (c.error.empty()) c.error = "pump: " + error;
            return pred();
        }
    }
    return pred();
}

// A payload unique per (session, iteration): distinct complete clipboard
// images, so the shared clipboard's final content can be matched exactly (a
// torn or interleaved write could never equal any single payload).
std::vector<uint8_t> MakePayload(unsigned session, unsigned iteration) {
    std::vector<uint8_t> out;
    out.reserve(16);
    for (int b = 0; b < 16; ++b) {
        out.push_back(static_cast<uint8_t>(0x20 + session * 7 + iteration * 3 +
                                           b * 11));
    }
    return out;
}

}  // namespace

RTSC_TEST(server_multisession_concurrent_clients_are_isolated) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    // Each client requests a distinct desktop size, so a shared desktop
    // dimension (or a shared framebuffer) would show up as the wrong size here.
    const std::vector<Spec> specs = {{64, 48}, {80, 60}, {96, 72}};
    std::vector<SessionResult> results =
        RunConcurrent(port, specs, /*encryption_methods=*/0);

    ReportResults(results, specs);
    CHECK_EQ(server.total_session_count(), specs.size());

    server.Stop();
    runner.join();
    // R-D: after all clients disconnected and Stop() joined the accept loop,
    // no session may still be counted as live (join rules out the race).
    CHECK_EQ(server.session_count(), 0);
}

RTSC_TEST(server_multisession_framebuffer_capture_is_per_session) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    RecordingSource source;

    RdpServer server(cfg);
    server.SetDesktopSource(&source);
    std::string error;
    CHECK(server.Start(error));
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    const std::vector<Spec> specs = {{64, 48}, {80, 60}, {96, 72}};
    std::vector<SessionResult> results =
        RunConcurrent(port, specs, /*encryption_methods=*/0);
    ReportResults(results, specs);

    // Every distinct geometry must have been captured. If the server shared a
    // single framebuffer (or a single desktop dimension) across sessions, the
    // log would miss one of these sizes.
    const std::vector<std::pair<uint16_t, uint16_t>> dims = source.dimensions();
    for (const Spec& s : specs) {
        bool found = false;
        for (const auto& d : dims) {
            if (d.first == s.w && d.second == s.h) found = true;
        }
        CHECK(found);
    }
    CHECK_EQ(server.total_session_count(), specs.size());

    server.Stop();
    runner.join();
    // R-D: after all clients disconnected and Stop() joined the accept loop,
    // no session may still be counted as live (join rules out the race).
    CHECK_EQ(server.session_count(), 0);
}

#if defined(_WIN32)
RTSC_TEST(server_multisession_encrypted_standard_rdp) {
    // The encrypted Standard RDP Security path generates a per-session RSA
    // keypair and derives per-session RC4 keys. The Windows-only RSA backend is
    // what makes this reachable; on Linux the server fails closed to
    // plaintext, so the encrypted assertions are not portable.
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    const std::vector<Spec> specs = {{64, 48}, {80, 60}};
    std::vector<SessionResult> results =
        RunConcurrent(port, specs, /*encryption_methods=*/0x0000001B);
    ReportResults(results, specs);
    CHECK_EQ(server.total_session_count(), specs.size());

    server.Stop();
    runner.join();
    // R-D: after all clients disconnected and Stop() joined the accept loop,
    // no session may still be counted as live (join rules out the race).
    CHECK_EQ(server.session_count(), 0);
}
#endif  // _WIN32

// S-M1: two clients connect to the same server concurrently, each completing
// the cliprdr handshake (Clipboard Capabilities, Monitor Ready, Format List)
// on its own channel. The shared clipboard must not serialise or disturb the
// two independent handshakes.
RTSC_TEST(server_multisession_cliprdr_concurrent_handshake) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral: the kernel picks a free port
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    SharedClipboard server_clip;

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetClipboard(&server_clip);
    std::string error;
    CHECK(server.Start(error));
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    static constexpr size_t kSessions = 2;
    std::atomic<int> ready{0};
    std::atomic<int> go{0};
    std::vector<ClipClient> clients(kSessions);
    std::vector<std::thread> threads;
    threads.reserve(kSessions);
    for (size_t i = 0; i < kSessions; ++i) {
        threads.emplace_back([&clients, &ready, &go, port, i]() {
            ready.fetch_add(1);
            while (go.load() == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            InitClipClient(port, 64, 48, clients[i]);
        });
    }
    while (ready.load() < static_cast<int>(kSessions)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    go.store(1);
    for (auto& t : threads) t.join();

    for (size_t i = 0; i < kSessions; ++i) {
        const ClipClient& cc = clients[i];
        CHECK(cc.connected);
        CHECK(cc.active);
        CHECK(cc.handshake_done);
        CHECK(cc.error.empty());
        CHECK(!cc.send_failed.load());
        // The channel id we registered on agrees with the server's assignment
        // (the driver-only way to read it back).
        CHECK_EQ(cc.channel_id, CliprdrChannelId());
        // Server -> client arm of the handshake, each once: ClipCaps, Monitor
        // Ready, Format List.
        CHECK_EQ(cc.cliprdr->server_caps_count(), 1u);
        CHECK_EQ(cc.cliprdr->monitor_ready_received_count(), 1u);
        CHECK_EQ(cc.cliprdr->remote_format_list_count(), 1u);
        CHECK(cc.cliprdr->server_caps_received());
        // Client -> server answer, each once: ClipCaps, Format List, and the
        // server's Format List Response back; long format names negotiated.
        CHECK_EQ(cc.cliprdr->clip_caps_count(), 1u);
        CHECK_EQ(cc.cliprdr->format_list_response_count(), 1u);
        CHECK_EQ(cc.cliprdr->format_list_response_received_count(), 1u);
        CHECK_EQ(cc.cliprdr->long_format_names(), true);
    }
    CHECK_EQ(server.total_session_count(), kSessions);

    server.Stop();
    runner.join();
    // R-D: after all clients disconnected and Stop() joined the accept loop,
    // no session may still be counted as live (join rules out the race).
    CHECK_EQ(server.session_count(), 0);
}

// S-M2: two clients write their local clipboards concurrently (each write
// walks the eager FormatDataResponse fill into the shared clipboard). The
// backend must survive the interleaving and every write must land atomically.
//
// A concurrent duel over WHICH of two divergent values wins is nondeterministic
// under last-writer-wins by definition (a "particular winner" assertion would
// be flaky), so this test pins the three deterministic contracts instead:
//   (1) atomic write-down  - the shared clipboard only ever shows one complete
//       payload, never a torn mix of the two concurrent writers;
//   (2) convergence        - once every session holds the same final payload,
//       every subsequent write re-applies it, so the content converges;
//   (3) echo-swallow       - a recessed stale per-session echo must not revive
//       a superseded payload across a session Poll cadence (~1.3 s hold).
RTSC_TEST(server_multisession_cliprdr_concurrent_writes_converge_no_stale) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    SharedClipboard server_clip;

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetClipboard(&server_clip);
    std::string error;
    CHECK(server.Start(error));
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    const std::vector<uint8_t> text_a = {0x61, 0x00, 0x6C, 0x00, 0x70, 0x00,
                                         0x68, 0x00, 0x61, 0x00, 0x2D, 0x00,
                                         0x41, 0x00};  // "alpha-A"
    const std::vector<uint8_t> text_b = {0x62, 0x00, 0x65, 0x00, 0x74, 0x00,
                                         0x61, 0x00, 0x2D, 0x00, 0x42, 0x00,
                                         0x62, 0x00, 0x65, 0x00};  // "beta-Bbe"
    const std::vector<uint8_t> text_final = {0x67, 0x00, 0x61, 0x00, 0x6D, 0x00,
                                             0x6D, 0x00, 0x61, 0x00, 0x46, 0x00};  // "gammaF"

    static constexpr size_t kSessions = 2;
    std::atomic<int> ready{0};
    std::atomic<int> go{0};
    std::atomic<int> p1done{0};
    std::atomic<int> final_go{0};
    std::vector<ClipClient> clients(kSessions);
    std::vector<std::thread> threads;
    threads.reserve(kSessions);

    threads.emplace_back([&]() {
        ready.fetch_add(1);
        while (go.load() == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (!InitClipClient(port, 64, 48, clients[0])) return;
        clients[0].clip.set(kCfUnicodeText, text_a);
        clients[0].cliprdr->OnLocalClipboardChanged();
        ++clients[0].local_changes;
        PumpUntil(clients[0], std::chrono::seconds(8),
                  [&]() { return server_clip.writes() >= 2; });
        p1done.fetch_add(1);
        while (final_go.load() == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        clients[0].clip.set(kCfUnicodeText, text_final);
        clients[0].cliprdr->OnLocalClipboardChanged();
        ++clients[0].local_changes;
        PumpUntil(clients[0], std::chrono::seconds(8), [&]() {
            std::vector<uint8_t> got;
            return server_clip.has(kCfUnicodeText, got) && got == text_final;
        });
        // Must have been stable across at least one session Poll (~1 s): no
        // recessed echo may have reintroduced a stale payload.
        clients[0].stable_final = true;
        const auto sd =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(1300);
        while (std::chrono::steady_clock::now() < sd) {
            std::vector<uint8_t> got;
            if (!server_clip.has(kCfUnicodeText, got) || got != text_final) {
                clients[0].stable_final = false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    });
    threads.emplace_back([&]() {
        ready.fetch_add(1);
        while (go.load() == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (!InitClipClient(port, 64, 48, clients[1])) return;
        clients[1].clip.set(kCfUnicodeText, text_b);
        clients[1].cliprdr->OnLocalClipboardChanged();
        ++clients[1].local_changes;
        PumpUntil(clients[1], std::chrono::seconds(8),
                  [&]() { return server_clip.writes() >= 2; });
        p1done.fetch_add(1);
        while (final_go.load() == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        clients[1].clip.set(kCfUnicodeText, text_final);
        clients[1].cliprdr->OnLocalClipboardChanged();
        ++clients[1].local_changes;
        PumpUntil(clients[1], std::chrono::seconds(8), [&]() {
            std::vector<uint8_t> got;
            return server_clip.has(kCfUnicodeText, got) && got == text_final;
        });
        clients[1].stable_final = true;
        const auto sd =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(1300);
        while (std::chrono::steady_clock::now() < sd) {
            std::vector<uint8_t> got;
            if (!server_clip.has(kCfUnicodeText, got) || got != text_final) {
                clients[1].stable_final = false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    });
    while (ready.load() < static_cast<int>(kSessions)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    go.store(1);
    while (p1done.load() < static_cast<int>(kSessions)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    // Both concurrent writers have been applied. The shared clipboard must
    // only ever show one complete payload; if the backend tore or interleaved
    // the concurrent writes this 400 ms sweep would observe a stray image.
    bool clean = true;
    const auto obs_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(400);
    while (std::chrono::steady_clock::now() < obs_deadline) {
        std::vector<uint8_t> got;
        if (server_clip.has(kCfUnicodeText, got) && got != text_a &&
            got != text_b) {
            clean = false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    CHECK(clean);

    final_go.store(1);
    for (auto& t : threads) t.join();

    std::vector<uint8_t> got;
    CHECK(server_clip.has(kCfUnicodeText, got));
    // Last writer wins: the second-generation payload (every session now holds
    // it) is the only content, and nothing recessed revived the stale A/B.
    CHECK(got == text_final);
    CHECK(server_clip.writes() >= 2);
    for (size_t i = 0; i < kSessions; ++i) {
        const ClipClient& cc = clients[i];
        CHECK(cc.handshake_done);
        CHECK(cc.error.empty());
        CHECK(!cc.send_failed.load());
        CHECK(cc.stable_final);
        CHECK_EQ(cc.channel_id, CliprdrChannelId());
        // The user-visible local-change path on this session actually ran.
        CHECK(cc.local_changes >= 2);
    }
    CHECK_EQ(server.total_session_count(), kSessions);

    server.Stop();
    runner.join();
    CHECK_EQ(server.session_count(), 0);
}

// S-M3: one session drops off the network while the other keeps working. The
// surviving session's clipboard still round-trips after the death, and the
// server tears every session down without leaving a dangling counter.
RTSC_TEST(server_multisession_cliprdr_disconnect_keeps_peer_session_alive) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    SharedClipboard server_clip;

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetClipboard(&server_clip);
    std::string error;
    CHECK(server.Start(error));
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    static constexpr size_t kSessions = 2;
    const std::vector<uint8_t> text_b = {0x62, 0x00, 0x65, 0x00, 0x74, 0x00,
                                         0x61, 0x00, 0x42, 0x00};  // "betaB"
    std::atomic<int> ready{0};
    std::atomic<int> go{0};
    std::atomic<bool> b_go{false};
    std::atomic<bool> b_done{false};
    std::atomic<bool> b_stop{false};
    std::vector<ClipClient> clients(kSessions);
    std::vector<std::thread> threads;
    threads.reserve(kSessions);

    // Session A: connect and stay connected until the test closes it.
    threads.emplace_back([&]() {
        ready.fetch_add(1);
        while (go.load() == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (!InitClipClient(port, 64, 48, clients[0])) return;
        for (;;) {
            std::string perr;
            if (!clients[0].client->Pump(*clients[0].transport, perr)) break;
        }
    });
    // Session B: connect, then on `b_go` post its local clipboard and wait for
    // the server to apply it -- proving the peer session is unaffected by A's
    // disconnect.
    threads.emplace_back([&]() {
        ready.fetch_add(1);
        while (go.load() == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (!InitClipClient(port, 64, 48, clients[1])) return;
        while (!b_go.load()) {
            std::string perr;
            if (!clients[1].client->Pump(*clients[1].transport, perr)) break;
        }
        if (!b_go.load()) return;  // died before the write could be posted
        clients[1].clip.set(kCfUnicodeText, text_b);
        clients[1].cliprdr->OnLocalClipboardChanged();
        ++clients[1].local_changes;
        PumpUntil(clients[1], std::chrono::seconds(8), [&]() {
            std::vector<uint8_t> got;
            return server_clip.has(kCfUnicodeText, got) && got == text_b;
        });
        b_done.store(true);
        while (!b_stop.load()) {
            std::string perr;
            if (!clients[1].client->Pump(*clients[1].transport, perr)) break;
        }
    });
    while (ready.load() < static_cast<int>(kSessions)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    go.store(1);

    // Wait for both sessions to reach the cliprdr handshake.
    const auto hb = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < hb &&
           !(clients[0].handshake_done && clients[1].handshake_done)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(clients[0].handshake_done);
    CHECK(clients[1].handshake_done);
    CHECK_EQ(server.session_count(), kSessions);

    // Kill session A mid-connection. Its session thread must wind down on the
    // server side.
    clients[0].transport->Close();
    const auto sd = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < sd &&
           server.session_count() > kSessions - 1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK_EQ(server.session_count(), kSessions - 1);

    // The surviving session still posts its clipboard to the shared backend.
    b_go.store(true);
    const auto bd = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < bd && !b_done.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(b_done.load());
    CHECK(clients[1].error.empty());
    CHECK(!clients[1].send_failed.load());
    CHECK_EQ(clients[1].channel_id, CliprdrChannelId());
    std::vector<uint8_t> got;
    CHECK(server_clip.has(kCfUnicodeText, got));
    CHECK(got == text_b);
    CHECK(server_clip.writes() >= 1);

    b_stop.store(true);
    clients[1].transport->Close();
    server.Stop();
    runner.join();
    for (auto& t : threads) t.join();
    CHECK_EQ(server.session_count(), 0);
}

// S-M4: N sessions each repeatedly trigger local clipboard changes and remote
// data requests for a fixed window while the test thread simulates external
// edits on the shared desktop. The shared backend must survive the churn with
// no crash, no assertion failure and no deadlock; after every session drops,
// the server's live counter returns to zero.
RTSC_TEST(server_multisession_cliprdr_stress_8_sessions) {
    ServerConfig cfg;
    cfg.port = 0;  // ephemeral
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();
    SharedClipboard server_clip;
    server_clip.set(kCfUnicodeText, MakePayload(99, 0));

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    server.SetClipboard(&server_clip);
    std::string error;
    CHECK(server.Start(error));
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    static constexpr size_t kSessions = 8;
    const auto kDuration = std::chrono::seconds(2);
    std::atomic<int> ready{0};
    std::atomic<int> go{0};
    std::atomic<int> done{0};
    std::atomic<bool> stop_stress{false};
    std::vector<ClipClient> clients(kSessions);
    std::vector<std::thread> threads;
    threads.reserve(kSessions);
    for (size_t i = 0; i < kSessions; ++i) {
        threads.emplace_back([&, i]() {
            ready.fetch_add(1);
            while (go.load() == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            if (!InitClipClient(port, 64, 48, clients[i])) {
                done.fetch_add(1);
                return;
            }
            const auto deadline =
                std::chrono::steady_clock::now() + kDuration;
            unsigned iter = 0;
            while (std::chrono::steady_clock::now() < deadline &&
                   !stop_stress.load()) {
                clients[i].clip.set(kCfUnicodeText,
                                    MakePayload(static_cast<unsigned>(i), iter));
                clients[i].cliprdr->OnLocalClipboardChanged();
                ++clients[i].local_changes;
                if (iter % 3 == 0) {
                    clients[i].cliprdr->RequestRemoteFormat(kCfUnicodeText);
                    ++clients[i].remote_requests;
                }
                PumpUntil(clients[i], std::chrono::milliseconds(40),
                          []() { return false; });
                if (!clients[i].error.empty()) break;
                ++iter;
                std::this_thread::sleep_for(std::chrono::milliseconds(15));
            }
            PumpUntil(clients[i], std::chrono::milliseconds(400),
                      []() { return false; });
            done.fetch_add(1);
        });
    }
    while (ready.load() < static_cast<int>(kSessions)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const auto stress_start = std::chrono::steady_clock::now();
    go.store(1);

    // While the sessions churn, the shared desktop is edited externally: every
    // bump of the sequence number makes every live session's Poll re-advertise
    // the clipboard, so all N handlers concurrently re-broadcast and re-apply.
    unsigned ext = 1;
    const auto deadline = std::chrono::steady_clock::now() + kDuration;
    while (std::chrono::steady_clock::now() < deadline &&
           done.load() < static_cast<int>(kSessions)) {
        server_clip.SimulateExternalChange(
            kCfUnicodeText, MakePayload(static_cast<unsigned>(kSessions), ext));
        ++ext;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    while (done.load() < static_cast<int>(kSessions)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    for (auto& t : threads) t.join();

    const auto duration_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - stress_start)
            .count();

    for (size_t i = 0; i < kSessions; ++i) {
        const ClipClient& cc = clients[i];
        CHECK(cc.connected);
        CHECK(cc.active);
        CHECK(cc.handshake_done);
        CHECK(cc.error.empty());
        CHECK(!cc.send_failed.load());
        CHECK_EQ(cc.channel_id, CliprdrChannelId());
        // The stress loop actually ran on this session (no premature death).
        CHECK(cc.local_changes >= 5);
        CHECK(cc.remote_requests >= 1);
    }
    // The eager data path both directions actually delivered: the server
    // applied at least one remote write and served reads for client requests.
    CHECK(server_clip.writes() >= 1);
    CHECK(server_clip.reads() >= 1);
    CHECK_EQ(server.total_session_count(), kSessions);

    for (size_t i = 0; i < kSessions; ++i) clients[i].transport->Close();
    server.Stop();
    runner.join();
    CHECK_EQ(server.session_count(), 0);

    unsigned total_changes = 0;
    unsigned total_requests = 0;
    for (size_t i = 0; i < kSessions; ++i) {
        total_changes += clients[i].local_changes;
        total_requests += clients[i].remote_requests;
    }
    std::printf("  stress: %zu sessions over %lld ms, ~%u local changes, %u "
                "remote requests, %u shared-clipboard writes, %u reads\n",
                kSessions, static_cast<long long>(duration_ms), total_changes,
                total_requests, server_clip.writes(), server_clip.reads());
}

int main() { return ::rtsc::test::run_all("rtsc_server_multisession_tests"); }
