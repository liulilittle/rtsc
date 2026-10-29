// ConnectTcp hardening tests: three observable states of the TCP handshake.
//
//   connect_tcp_times_out_on_a_blackhole   a host that drops SYN -> bounded
//                                          timeout error ("timeout"), nowhere
//                                          near "forever"
//   connect_tcp_fails_fast_on_a_closed_port an RST -> "failed" error well below
//                                          the connect budget
//   connect_tcp_connects_and_round_trips    a live peer -> success plus a real
//                                          Write/Read round trip on both sides
//
// Boundary cases (getaddrinfo / invalid port) stay fast and fail closed, so the
// timeout path is provably distinct from resolver and local errors.

#include "rtsc/net/transport.h"

#include "connect_addr.h"

#include "test_main.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

// A "closed" loopback port: a socket bound (but never listening) to an
// ephemeral port and held open for the duration. The TCP stack refuses a
// connect to it (RST), and because the socket stays bound, no other process can
// steal the port between "reserve" and "connect" -- no port race.
class ClosedPort {
 public:
    ClosedPort() = default;
    ClosedPort(const ClosedPort&) = delete;
    ClosedPort& operator=(const ClosedPort&) = delete;
    ~ClosedPort() { Reset(); }

    bool Acquire() {
#if defined(_WIN32)
        static const bool wsa_ok = [] {
            WSADATA d;
            return ::WSAStartup(MAKEWORD(2, 2), &d) == 0;
        }();
        if (!wsa_ok) return false;
        const SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return false;
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
            ::closesocket(s);
            return false;
        }
        int len = sizeof(a);
        if (::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
            ::closesocket(s);
            return false;
        }
        sock_ = s;
        port_ = ntohs(a.sin_port);
        return port_ != 0;
#else
        const int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) return false;
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
            ::close(fd);
            return false;
        }
        socklen_t len = sizeof(a);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
            ::close(fd);
            return false;
        }
        fd_ = fd;
        port_ = ntohs(a.sin_port);
        return port_ != 0;
#endif
    }

    void Reset() {
#if defined(_WIN32)
        if (sock_ != INVALID_SOCKET) {
            ::closesocket(sock_);
            sock_ = INVALID_SOCKET;
        }
#else
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
#endif
        port_ = 0;
    }

    uint16_t port() const { return port_; }

 private:
#if defined(_WIN32)
    SOCKET sock_ = INVALID_SOCKET;
#else
    int fd_ = -1;
#endif
    uint16_t port_ = 0;
};

// A blackhole: a host that silently drops SYN instead of answering with SYN-ACK
// or RST. The probe (temp/opencode/bh_probe.cpp, windows) confirmed that a
// non-blocking connect to 10.255.255.1:3389 stays pending for >= 12 s in this
// environment, so the handshake can only complete via an explicit timeout. This
// stands in for a dead gateway behind a firewall (the flood-test finding).
constexpr const char* kBlackholeHost = "10.255.255.1";
constexpr uint16_t kBlackholePort = 3389;

// The worker thread that runs ConnectTcp(): a buggy endless connect must not be
// able to hang the whole test binary, so the main thread only waits a bounded
// watchdog. The result lives on the heap (owned by the caller) so a stuck
// worker that keeps going afterwards never writes into freed stack storage.
struct ConnectResult {
    std::unique_ptr<rtsc::net::Transport> transport;
    std::string error;
    std::atomic<bool> done{false};
};

// Returns true when the connect finished within the watchdog and the caller may
// join it. Returns false when the connect was still pending after the watchdog:
// a pre-fix defect. In that case the worker is detached and the caller must
// terminate the process promptly (std::_Exit) -- nothing else can stop a thread
// locked inside a blocking connect, and running on would race it against the
// CRT teardown.
bool ConnectWithWatchdog(const std::string& host, uint16_t port,
                         ConnectResult& result, int watchdog_ms) {
    std::thread worker([&]() {
        result.transport = rtsc::net::ConnectTcp(host, port, result.error);
        result.done.store(true);
    });
    using namespace std::chrono;
    const auto watchdog = steady_clock::now() + milliseconds(watchdog_ms);
    while (!result.done.load() && steady_clock::now() < watchdog) {
        std::this_thread::sleep_for(milliseconds(50));
    }
    if (!result.done.load()) {
        worker.detach();
        return false;
    }
    worker.join();
    return true;
}

// Accept() as a bounded wait: the library's Listener::Accept() blocks
// indefinitely, so a connect that actually targeted a different host (this
// test's "blackhole" address is routable and served in some networks) would
// hang the whole suite if we awaited a peer that can never arrive. The result
// lives on the heap so a watchdog-overrun worker keeps writing to live memory;
// closing the listener unblocks Accept afterwards.
std::unique_ptr<rtsc::net::Transport> AcceptBounded(rtsc::net::Listener& listener,
                                                    int timeout_ms) {
    struct AcceptBox {
        std::unique_ptr<rtsc::net::Transport> peer;
        std::atomic<bool> done{false};
    };
    auto box = std::make_unique<AcceptBox>();
    std::thread worker([&]() {
        box->peer = listener.Accept();
        box->done.store(true);
    });
    using namespace std::chrono;
    const auto deadline = steady_clock::now() + milliseconds(timeout_ms);
    while (!box->done.load() && steady_clock::now() < deadline) {
        std::this_thread::sleep_for(milliseconds(50));
    }
    if (!box->done.load()) {
        worker.detach();  // cleared once the listener is closed below
        return nullptr;   // box stays alive on the heap; no dangling writes
    }
    worker.join();
    return std::move(box->peer);
}

}  // namespace

// A listener helper: bind an ephemeral port on loopback so the tests never race
// a hardcoded port against other processes.
static std::unique_ptr<rtsc::net::Listener> BindLoopbackListener(
    std::string& error) {
    auto listener = rtsc::net::ListenTcp("127.0.0.1", 0, error);
    if (listener == nullptr || listener->local_port() == 0) {
        return nullptr;
    }
    return listener;
}

// RED state (pre-fix, Windows): the connect blocks forever; the 15 s watchdog
// trips and the test fails. GREEN state: ConnectTcp bounds the handshake.
//
// Three legitimate green outcomes: (a) the environment really drops SYN from
// 10.255.255.1 (this box -> the full budget is burned and the error is a
// distinct "timeout"); (b) the sandbox refuses/unreaches the address fast
// instead (e.g. an ARP failure in WSL), so the SYN-blackhole premise does not
// hold and only the bounded failure can be asserted; (c) the network really
// routes the address and serves a listener, so the connect succeeds -- a
// reachable host, not a defect. Case (a) is what the Windows suites exercise;
// the assertions there are the strong ones.
RTSC_TEST(connect_tcp_times_out_on_a_blackhole) {
    auto result = std::make_unique<ConnectResult>();
    const auto t0 = std::chrono::steady_clock::now();
    const bool bounded =
        ConnectWithWatchdog(kBlackholeHost, kBlackholePort, *result, 15000);
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0)
            .count();

    if (!bounded) {
        // The handshake was still pending after 15 s: the pre-fix defect. Report
        // the failure, then end the process now -- nothing else can stop the
        // still-blocked worker thread, and running on would let it race the CRT.
        CHECK(bounded);
        std::fflush(stdout);
        std::_Exit(1);
    }

    if (result->transport != nullptr) {
        // Case (c): a CI network may genuinely route 10.255.255.1 -- and even
        // serve a listener on 3389. A successful connect is then a reachable
        // host, not a timeout defect; close it and skip the timeout assertions.
        result->transport->Close();
        CHECK(result->error.empty());
        return;
    }
    if (result->error.find("timeout") != std::string::npos) {
        // Case (a): a genuine SYN blackhole. The budget was actually burned --
        // this is a timeout, not a sneaky fast failure that happens to mention
        // the word -- and the wait is bounded (never many minutes).
        CHECK(elapsed_ms >= rtsc::net::kConnectTimeoutMs - 1200);
        CHECK(elapsed_ms < 12000);
    } else {
        // Case (b): no blackhole in this environment; the connect failed fast
        // with a real error. It must still be bounded.
        CHECK(!result->error.empty());
        CHECK(elapsed_ms < 12000);
    }
}

// F1 regression guard: an earlier address that burns its whole budget slice (a
// firewall blackhole) must not prevent a later reachable address from being
// tried -- the per-address budget slicing exists exactly for that. The public
// API cannot produce a [blackhole, reachable] getaddrinfo result (numeric
// literals resolve to a single address), so the address list is injected
// through the internal ConnectAddresses() seam.
RTSC_TEST(connect_tcp_blackhole_first_then_reachable) {
    std::string error;
    auto listener = BindLoopbackListener(error);
    CHECK(listener != nullptr);
    if (listener == nullptr) return;

    sockaddr_in blackhole{};
    blackhole.sin_family = AF_INET;
    CHECK(::inet_pton(AF_INET, kBlackholeHost, &blackhole.sin_addr) == 1);
    blackhole.sin_port = htons(kBlackholePort);

    sockaddr_in reachable{};
    reachable.sin_family = AF_INET;
    reachable.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    reachable.sin_port = htons(listener->local_port());

    addrinfo ai_blackhole{};
    ai_blackhole.ai_family = AF_INET;
    ai_blackhole.ai_socktype = SOCK_STREAM;
    ai_blackhole.ai_protocol = IPPROTO_TCP;
    ai_blackhole.ai_addrlen = sizeof(blackhole);
    ai_blackhole.ai_addr = reinterpret_cast<sockaddr*>(&blackhole);

    addrinfo ai_reachable{};
    ai_reachable.ai_family = AF_INET;
    ai_reachable.ai_socktype = SOCK_STREAM;
    ai_reachable.ai_protocol = IPPROTO_TCP;
    ai_reachable.ai_addrlen = sizeof(reachable);
    ai_reachable.ai_addr = reinterpret_cast<sockaddr*>(&reachable);

    ai_blackhole.ai_next = &ai_reachable;

    const auto t0 = std::chrono::steady_clock::now();
    rtsc::net::ConnectAttempt attempt = rtsc::net::ConnectAddresses(&ai_blackhole);
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0)
            .count();

    // The reachable second address must still be attempted after the
    // blackhole's slice, and the whole attempt stays within the budget (< 10 s
    // with a 5 s slice for each of two addresses).
    CHECK(attempt.transport != nullptr);
    CHECK(elapsed_ms < rtsc::net::kConnectTimeoutMs);
    if (attempt.transport == nullptr) {
        listener->Close();
        return;
    }

    // If this network actually routes 10.255.255.1 -- and even serves a
    // listener on 3389 -- the connect above targeted that real remote host, so
    // our loopback listener has no pending peer. Wait for it with a bound
    // instead of blocking forever (which would hang the suite); report a SKIP
    // so a pass here is never mistaken for a blackhole assertion.
    auto peer = AcceptBounded(*listener, 3000);
    if (peer == nullptr) {
        std::printf("[ SKIP ] connect_tcp_blackhole_first_then_reachable: "
                    "10.255.255.1 is actually reachable here; the blackhole "
                    "premise does not hold\n");
        listener->Close();
        return;
    }

    // The connected socket is live: round-trip one byte both ways (also proves
    // the restored-blocking socket still reads and writes normally).
    const uint8_t sent = 0x5a;
    CHECK(attempt.transport->Write(&sent, 1));
    uint8_t got = 0;
    CHECK_EQ(peer->Read(&got, 1), 1);
    CHECK_EQ(static_cast<int>(got), 0x5a);

    const uint8_t reply = 0xa5;
    CHECK(peer->Write(&reply, 1));
    CHECK_EQ(attempt.transport->Read(&got, 1), 1);
    CHECK_EQ(static_cast<int>(got), 0xa5);

    attempt.transport->Close();
    peer->Close();
    listener->Close();
}

// A closed port answers with RST. The refusal must surface as a "failed" error
// long before the 10 s connect budget, never as a timeout.
RTSC_TEST(connect_tcp_fails_fast_on_a_closed_port) {
    ClosedPort closed;
    CHECK(closed.Acquire());
    if (closed.port() == 0) return;
    std::string error;

    const auto t0 = std::chrono::steady_clock::now();
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", closed.port(), error);
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0)
            .count();

    CHECK(transport == nullptr);
    CHECK(error.find("failed") != std::string::npos);
    CHECK(error.find("timeout") == std::string::npos);
    // Fast refusal, well clear of the 10 s timeout mark.
    CHECK(elapsed_ms < 8000);
}

// A live peer connects successfully and data flows both ways: the returned
// transport must behave exactly like the old blocking one (Write flushes, Read
// sees the peer), so the non-blocking connect cannot have leaked into the data
// path.
RTSC_TEST(connect_tcp_connects_and_round_trips) {
    std::string error;
    auto listener = BindLoopbackListener(error);
    CHECK(listener != nullptr);
    if (listener == nullptr) return;

    auto client = rtsc::net::ConnectTcp("127.0.0.1", listener->local_port(), error);
    CHECK(client != nullptr);
    if (client == nullptr) {
        listener->Close();
        return;
    }
    auto peer = listener->Accept();
    CHECK(peer != nullptr);
    listener->Close();

    const uint8_t ping[] = {'p', 'i', 'n', 'g'};
    const uint8_t pong[] = {'p', 'o', 'n', 'g'};

    CHECK(client->Write(ping, sizeof(ping)));
    uint8_t got[8] = {};
    const int n1 = peer->Read(got, sizeof(got));
    CHECK_EQ(n1, 4);
    CHECK(std::memcmp(got, ping, 4) == 0);

    CHECK(peer->Write(pong, sizeof(pong)));
    const int n2 = client->Read(got, sizeof(got));
    CHECK_EQ(n2, 4);
    CHECK(std::memcmp(got, pong, 4) == 0);

    client->Close();
    peer->Close();
}

// Resolver and argument boundaries stay fast and fail closed, distinct from the
// connect failure and the timeout path.
RTSC_TEST(connect_tcp_rejects_unknown_host) {
    std::string error;
    auto transport = rtsc::net::ConnectTcp("no-such-host.invalid", 3389, error);
    CHECK(transport == nullptr);
    CHECK(error.find("getaddrinfo") != std::string::npos);
}

// An empty host is not a valid connect target. Windows resolves "" to the
// local host (several addresses, each refused in turn); other platforms fail in
// getaddrinfo. Either way it must fail closed without a crash and without an
// unbounded wait.
RTSC_TEST(connect_tcp_rejects_empty_host) {
    ClosedPort closed;
    CHECK(closed.Acquire());
    if (closed.port() == 0) return;
    std::string error;

    const auto t0 = std::chrono::steady_clock::now();
    auto transport = rtsc::net::ConnectTcp("", closed.port(), error);
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0)
            .count();

    CHECK(transport == nullptr);
    CHECK(!error.empty());
    // Bounded by the connect budget (never an infinite wait), but the resolver
    // may legitimately hand back several addresses, each refused at ~1-2 s.
    CHECK(elapsed_ms < 15000);
}

RTSC_TEST(connect_tcp_rejects_port_zero) {
    std::string error;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", 0, error);
    CHECK(transport == nullptr);
    CHECK(!error.empty());
}

int main() { return ::rtsc::test::run_all("rtsc_net_tests"); }