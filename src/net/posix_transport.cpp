// POSIX implementation of the blocking byte transport.
//
// Compiled only on non-Windows platforms (see CMakeLists.txt). The interface it
// implements is platform neutral; the Windows sibling is winsock_transport.cpp.

#include "connect_addr.h"
#include "rtsc/net/transport.h"

#if !defined(_WIN32)

#include <arpa/inet.h>
#include <chrono>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <memory>
#include <string>
#include <utility>

namespace rtsc::net {
namespace {

// Poll interval used by Accept() so Close() from another thread is noticed
// promptly instead of waiting for a peer that may never arrive.
constexpr int kAcceptPollMs = 200;

class PosixTransport : public Transport {
 public:
    explicit PosixTransport(int fd) : fd_(fd) {}
    ~PosixTransport() override { Close(); }

    int Read(uint8_t* buf, size_t size) override {
        if (fd_ < 0 || size == 0) return -1;
        // Wait for readability with a bounded timeout so a silent peer cannot
        // block the caller (and with it the UI message pump). poll() separates
        // the three outcomes cleanly: 0 = timeout (kReadTimeout), -1 = error,
        // >0 = data or EOF is ready for recv().
        pollfd pfd{};
        pfd.fd = fd_;
        pfd.events = POLLIN;
        const int ready = ::poll(&pfd, 1, kReadTimeoutMs);
        if (ready == 0) return kReadTimeout;
        if (ready < 0) return -1;
        const ssize_t n = ::recv(fd_, buf, size, 0);
        return static_cast<int>(n);
    }

    bool Write(const uint8_t* data, size_t size) override {
        if (fd_ < 0) return false;
        size_t sent = 0;
        while (sent < size) {
            const ssize_t n =
                ::send(fd_, data + sent, size - sent, MSG_NOSIGNAL);
            if (n <= 0) return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }

    void Close() override {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

 private:
    int fd_ = -1;
};

class PosixListener : public Listener {
 public:
    PosixListener(int fd, uint16_t local_port)
        : fd_(fd), local_port_(local_port) {}
    ~PosixListener() override { Close(); }

    std::unique_ptr<Transport> Accept() override {
        for (;;) {
            if (closed_.load(std::memory_order_relaxed)) return nullptr;
            pollfd pfd{};
            pfd.fd = fd_;
            pfd.events = POLLIN;
            const int ready = ::poll(&pfd, 1, kAcceptPollMs);
            if (closed_.load(std::memory_order_relaxed)) return nullptr;
            if (ready == 0) continue;  // timeout: re-check the closed flag
            if (ready < 0) return nullptr;
            const int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) return nullptr;
            return std::make_unique<PosixTransport>(c);
        }
    }

    void Close() override {
        closed_.store(true, std::memory_order_relaxed);
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    uint16_t local_port() const override { return local_port_; }

 private:
    int fd_ = -1;
    uint16_t local_port_ = 0;
    std::atomic<bool> closed_{false};
};

// Sets or clears the socket's non-blocking mode. Used only while the handshake
// runs; the connected socket is restored to blocking before it is handed out.
bool SetNonBlocking(int fd, bool nonblocking) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    const int updated =
        nonblocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return ::fcntl(fd, F_SETFL, updated) == 0;
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
    // in non-blocking mode; poll() reports POLLOUT on success *and* on failure,
    // so getsockopt(SO_ERROR) disambiguates the two.
    int fd = -1;
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

        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (!SetNonBlocking(fd, true)) {
            ::close(fd);
            fd = -1;
            continue;
        }
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        const int connect_err = errno;
        if (connect_err == EINPROGRESS) {
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLOUT;
            const int ready = ::poll(&pfd, 1, wait_ms);
            if (ready == 0) {
                // This address used up its slice. That is a timeout only for
                // this address: the next one still gets its own budget.
                any_timed_out = true;
            } else if (ready > 0) {
                int so_err = 0;
                socklen_t so_len = sizeof(so_err);
                if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err,
                                 &so_len) == 0 &&
                    so_err == 0) {
                    break;  // connected
                }
            }
            // ready < 0 (poll error): try the next address below.
        }
        // This address failed (refused / unreachable / poll error) or burned
        // its slice. Close it and try the next one: a blackhole eats only its
        // own slice, never the later addresses' budget.
        ::close(fd);
        fd = -1;
    }

    if (fd < 0) return ConnectAttempt{nullptr, any_timed_out};

    // Restore blocking mode. Read()/Write() assume a blocking socket (poll()
    // pre-check plus blocking recv/send); leaving the socket non-blocking would
    // make a full send buffer or a drained receive buffer report failure where
    // the peers just need to drain/fill first.
    if (!SetNonBlocking(fd, false)) {
        // Practically unreachable: fcntl(F_SETFL) on a just-created socket does
        // not fail. Reported through the generic path (which reads "connect
        // timeout" when a slice was burned earlier) rather than its own message
        // -- an accepted micro-flaw, see W11-D2.
        ::close(fd);
        return ConnectAttempt{nullptr, any_timed_out};
    }
    return ConnectAttempt{std::make_unique<PosixTransport>(fd), false};
}

std::unique_ptr<Transport> ConnectTcp(const std::string& host, uint16_t port,
                                      std::string& error) {
    error.clear();

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

    int fd = -1;
    for (addrinfo* p = result; p != nullptr; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        int on = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (::bind(fd, p->ai_addr, p->ai_addrlen) == 0 &&
            ::listen(fd, SOMAXCONN) == 0) {
            break;
        }
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(result);

    if (fd < 0) {
        error = "listen on " + (host.empty() ? std::string("*") : host) + ":" +
                port_str + " failed";
        return nullptr;
    }

    // Read back the port the socket was actually bound to. With port 0 the
    // kernel picks one, and the caller (a test binding an ephemeral port) has
    // no other way to learn it. Fail closed rather than report a bogus 0.
    sockaddr_storage local{};
    socklen_t local_len = sizeof(local);
    uint16_t bound_port = 0;
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_len) == 0) {
        if (local.ss_family == AF_INET) {
            bound_port =
                ::ntohs(reinterpret_cast<const sockaddr_in*>(&local)->sin_port);
        } else if (local.ss_family == AF_INET6) {
            bound_port = ::ntohs(
                reinterpret_cast<const sockaddr_in6*>(&local)->sin6_port);
        }
    }
    if (bound_port == 0) {
        ::close(fd);
        error = "getsockname on the listening socket failed";
        return nullptr;
    }
    return std::make_unique<PosixListener>(fd, bound_port);
}

}  // namespace rtsc::net

#endif  // !_WIN32
