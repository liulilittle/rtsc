// Winsock implementation of the blocking byte transport.
//
// Compiled only on Windows (see CMakeLists.txt). The interface it implements is
// platform neutral; a POSIX implementation will live in a sibling file.

#include "connect_addr.h"
#include "rtsc/net/transport.h"

#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <utility>

namespace rtsc::net {
namespace {

// Poll interval used by Accept() so Close() from another thread is noticed
// promptly instead of waiting for a peer that may never arrive.
constexpr int kAcceptPollMs = 200;

class WinsockTransport : public Transport {
 public:
    explicit WinsockTransport(SOCKET s) : sock_(s) {}
    ~WinsockTransport() override { Close(); }

    int Read(uint8_t* buf, size_t size) override {
        if (sock_ == INVALID_SOCKET || size == 0) return -1;
        // Wait for readability with a bounded timeout so a silent peer cannot
        // block the caller (and with it the UI message pump). select() separates
        // the three outcomes cleanly: 0 = timeout (kReadTimeout), SOCKET_ERROR =
        // error (-1), >0 = data or EOF is ready for recv().
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock_, &readfds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = kReadTimeoutMs * 1000;
        const int ready = ::select(0, &readfds, nullptr, nullptr, &tv);
        if (ready == 0) return kReadTimeout;
        if (ready == SOCKET_ERROR) return -1;
        const int n = ::recv(sock_, reinterpret_cast<char*>(buf),
                             static_cast<int>(size), 0);
        return n;
    }

    bool Write(const uint8_t* data, size_t size) override {
        if (sock_ == INVALID_SOCKET) return false;
        size_t sent = 0;
        while (sent < size) {
            const int n = ::send(sock_, reinterpret_cast<const char*>(data + sent),
                                 static_cast<int>(size - sent), 0);
            if (n <= 0) return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }

    void Close() override {
        if (sock_ != INVALID_SOCKET) {
            ::closesocket(sock_);
            sock_ = INVALID_SOCKET;
        }
    }

 private:
    SOCKET sock_ = INVALID_SOCKET;
};

class WinsockListener : public Listener {
 public:
    explicit WinsockListener(SOCKET s, uint16_t local_port)
        : sock_(s), local_port_(local_port) {}
    ~WinsockListener() override { Close(); }

    std::unique_ptr<Transport> Accept() override {
        for (;;) {
            if (closed_.load(std::memory_order_relaxed)) return nullptr;
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sock_, &readfds);
            timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = kAcceptPollMs * 1000;
            const int ready = ::select(0, &readfds, nullptr, nullptr, &tv);
            if (closed_.load(std::memory_order_relaxed)) return nullptr;
            if (ready == 0) continue;  // timeout: re-check the closed flag
            if (ready == SOCKET_ERROR) return nullptr;
            const SOCKET c = ::accept(sock_, nullptr, nullptr);
            if (c == INVALID_SOCKET) return nullptr;
            return std::make_unique<WinsockTransport>(c);
        }
    }

    void Close() override {
        closed_.store(true, std::memory_order_relaxed);
        if (sock_ != INVALID_SOCKET) {
            ::closesocket(sock_);
            sock_ = INVALID_SOCKET;
        }
    }

    uint16_t local_port() const override { return local_port_; }

 private:
    SOCKET sock_ = INVALID_SOCKET;
    uint16_t local_port_ = 0;
    std::atomic<bool> closed_{false};
};

// One-time WSAStartup for the process. Kept in a function-local static so the
// transport does not impose an init order on its callers.
bool EnsureWinsock() {
    static const bool ok = []() {
        WSADATA d;
        return ::WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }();
    return ok;
}

// Sets or clears the socket's non-blocking mode. Used only while the handshake
// runs; the connected socket is restored to blocking before it is handed out.
bool SetNonBlocking(SOCKET s, bool nonblocking) {
    u_long mode = nonblocking ? 1 : 0;
    return ::ioctlsocket(s, FIONBIO, &mode) == 0;
}

}  // namespace

ConnectAttempt ConnectAddresses(addrinfo* addr_head) {
    if (addr_head == nullptr) return ConnectAttempt{};

    // Number the addresses so every one gets an equal slice of the connect
    // budget. A single-address connect therefore still gets the full budget,
    // and a blackhole in a multi-address result can only consume its own slice
    // instead of starving the later addresses.
    int addr_count = 0;
    for (addrinfo* p = addr_head; p != nullptr; p = p->ai_next) ++addr_count;
    const int address_total = addr_count > 0 ? addr_count : 1;
    int slice_ms = kConnectTimeoutMs / address_total;
    if (slice_ms < 100) slice_ms = 100;  // keep degenerate lists usable

    const auto start = std::chrono::steady_clock::now();
    const auto deadline = start + std::chrono::milliseconds(kConnectTimeoutMs);

    // A bounded non-blocking handshake. A plain blocking connect() has no
    // timeout of its own, so a host that silently drops SYN (a firewall
    // blackhole) would stall the caller indefinitely. The connect() is issued
    // in non-blocking mode; Winsock signals the outcome with the write set on
    // success and the exception set on failure (some providers use both), so
    // getsockopt(SO_ERROR) disambiguates and both sets are watched.
    SOCKET s = INVALID_SOCKET;
    bool any_timed_out = false;
    for (addrinfo* p = addr_head; p != nullptr; p = p->ai_next) {
        // The whole attempt is also capped at the budget, so even an unusual
        // many-address result cannot stretch it beyond kConnectTimeoutMs.
        const auto remaining = std::chrono::duration_cast<
            std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())
                                   .count();
        if (remaining <= 0) {
            any_timed_out = true;
            break;
        }
        int wait_ms = static_cast<int>(remaining);
        if (wait_ms > slice_ms) wait_ms = slice_ms;  // this address's own slice

        s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (!SetNonBlocking(s, true)) {
            ::closesocket(s);
            s = INVALID_SOCKET;
            continue;
        }
        if (::connect(s, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) {
            break;  // connected immediately
        }
        const int connect_err = ::WSAGetLastError();
        if (connect_err == WSAEWOULDBLOCK) {
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(s, &writefds);
            fd_set exceptfds;
            FD_ZERO(&exceptfds);
            FD_SET(s, &exceptfds);
            timeval tv{};
            tv.tv_sec = wait_ms / 1000;
            tv.tv_usec = (wait_ms % 1000) * 1000;
            const int ready = ::select(0, nullptr, &writefds, &exceptfds, &tv);
            if (ready == 0) {
                // This address used up its slice. That is a timeout only for
                // this address: the next one still gets its own budget.
                any_timed_out = true;
            } else if (ready == SOCKET_ERROR) {
                // select failed on this socket: try the next address.
            } else {
                int so_err = 0;
                int so_len = sizeof(so_err);
                if (::getsockopt(s, SOL_SOCKET, SO_ERROR,
                                 reinterpret_cast<char*>(&so_err),
                                 &so_len) == 0 &&
                    so_err == 0) {
                    break;  // connected
                }
            }
        }
        // This address failed (refused / unreachable / select error) or burned
        // its slice. Close it and try the next one: a blackhole eats only its
        // own slice, never the later addresses' budget.
        ::closesocket(s);
        s = INVALID_SOCKET;
    }

    if (s == INVALID_SOCKET) return ConnectAttempt{nullptr, any_timed_out};

    // Restore blocking mode. Read()/Write() assume a blocking socket (select()
    // pre-check plus blocking recv/send); leaving the socket non-blocking would
    // make a full send buffer or a drained receive buffer report failure where
    // the peers just need to drain/fill first.
    if (!SetNonBlocking(s, false)) {
        // Practically unreachable: FIONBIO on a just-created socket does not
        // fail. Reported through the generic path (which reads "connect timeout"
        // when a slice was burned earlier) rather than its own message -- an
        // accepted micro-flaw, see W11-D2.
        ::closesocket(s);
        return ConnectAttempt{nullptr, any_timed_out};
    }
    return ConnectAttempt{std::make_unique<WinsockTransport>(s), false};
}

std::unique_ptr<Transport> ConnectTcp(const std::string& host, uint16_t port,
                                      std::string& error) {
    error.clear();
    if (!EnsureWinsock()) {
        error = "WSAStartup failed";
        return nullptr;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const std::string port_str = std::to_string(port);
    addrinfo* result = nullptr;
    if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result) != 0 ||
        result == nullptr) {
        error = "getaddrinfo failed for " + host;
        return nullptr;
    }

    ConnectAttempt attempt = ConnectAddresses(result);
    ::freeaddrinfo(result);

    if (attempt.transport != nullptr) return std::move(attempt.transport);

    if (attempt.timed_out) {
        // No handshake completed within the budget: the distinct timeout error
        // (a refused peer reports this as a plain connect failure below).
        error = "connect timeout: " + host + ":" + port_str +
                " (no handshake within " + std::to_string(kConnectTimeoutMs) +
                " ms)";
    } else {
        // Existing message, unchanged: an outright failure (e.g. RST refusal).
        error = "connect to " + host + ":" + port_str + " failed";
    }
    return nullptr;
}

std::unique_ptr<Listener> ListenTcp(const std::string& host, uint16_t port,
                                    std::string& error) {
    error.clear();
    if (!EnsureWinsock()) {
        error = "WSAStartup failed";
        return nullptr;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    const std::string port_str = std::to_string(port);
    const char* node = host.empty() ? nullptr : host.c_str();
    addrinfo* result = nullptr;
    if (::getaddrinfo(node, port_str.c_str(), &hints, &result) != 0 ||
        result == nullptr) {
        error = "getaddrinfo failed for " + (host.empty() ? std::string("*") : host);
        return nullptr;
    }

    SOCKET s = INVALID_SOCKET;
    for (addrinfo* p = result; p != nullptr; p = p->ai_next) {
        s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        int on = 1;
        ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&on), sizeof(on));
        if (::bind(s, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0 &&
            ::listen(s, SOMAXCONN) == 0) {
            break;
        }
        ::closesocket(s);
        s = INVALID_SOCKET;
    }
    ::freeaddrinfo(result);

    if (s == INVALID_SOCKET) {
        error = "listen on " + (host.empty() ? std::string("*") : host) + ":" +
                port_str + " failed";
        return nullptr;
    }

    // Read back the port the socket was actually bound to. With port 0 the
    // kernel picks one, and the caller (a test binding an ephemeral port) has
    // no other way to learn it. Fail closed rather than report a bogus 0.
    uint16_t bound_port = 0;
    sockaddr_storage local{};
    int local_len = sizeof(local);
    const int got = ::getsockname(s, reinterpret_cast<sockaddr*>(&local),
                                  &local_len);
    if (got == 0) {
        if (local.ss_family == AF_INET) {
            bound_port = ::ntohs(
                reinterpret_cast<const sockaddr_in*>(&local)->sin_port);
        } else if (local.ss_family == AF_INET6) {
            bound_port = ::ntohs(
                reinterpret_cast<const sockaddr_in6*>(&local)->sin6_port);
        }
    }
    if (bound_port == 0) {
        ::closesocket(s);
        error = "getsockname on the listening socket failed";
        return nullptr;
    }
    return std::make_unique<WinsockListener>(s, bound_port);
}

}  // namespace rtsc::net

#endif  // _WIN32
