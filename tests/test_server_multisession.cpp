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

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

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
    mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
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

}  // namespace

RTSC_TEST(server_multisession_concurrent_clients_are_isolated) {
    const uint16_t port = 3397;
    ServerConfig cfg;
    cfg.port = port;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
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
}

RTSC_TEST(server_multisession_framebuffer_capture_is_per_session) {
    const uint16_t port = 3398;
    ServerConfig cfg;
    cfg.port = port;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    RecordingSource source;

    RdpServer server(cfg);
    server.SetDesktopSource(&source);
    std::string error;
    CHECK(server.Start(error));
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
}

#if defined(_WIN32)
RTSC_TEST(server_multisession_encrypted_standard_rdp) {
    // The encrypted Standard RDP Security path generates a per-session RSA
    // keypair and derives per-session RC4 keys. The Windows-only RSA backend is
    // what makes this reachable; on Linux the server fails closed to
    // plaintext, so the encrypted assertions are not portable.
    const uint16_t port = 3399;
    ServerConfig cfg;
    cfg.port = port;
    cfg.desktop_width = 64;
    cfg.desktop_height = 48;
    auto pattern = rtsc::server::MakeTestPatternSource();

    RdpServer server(cfg);
    server.SetDesktopSource(pattern.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    const std::vector<Spec> specs = {{64, 48}, {80, 60}};
    std::vector<SessionResult> results =
        RunConcurrent(port, specs, /*encryption_methods=*/0x0000001B);
    ReportResults(results, specs);
    CHECK_EQ(server.total_session_count(), specs.size());

    server.Stop();
    runner.join();
}
#endif  // _WIN32

int main() { return ::rtsc::test::run_all("rtsc_server_multisession_tests"); }
