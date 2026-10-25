// Winsock implementation of the blocking byte transport.
//
// Compiled only on Windows (see CMakeLists.txt). The interface it implements is
// platform neutral; a POSIX implementation will live in a sibling file.

#include "rtsc/net/transport.h"

#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
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
    explicit WinsockListener(SOCKET s) : sock_(s) {}
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

 private:
    SOCKET sock_ = INVALID_SOCKET;
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

}  // namespace

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

    SOCKET s = INVALID_SOCKET;
    for (addrinfo* p = result; p != nullptr; p = p->ai_next) {
        s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (::connect(s, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) {
            break;
        }
        ::closesocket(s);
        s = INVALID_SOCKET;
    }
    ::freeaddrinfo(result);

    if (s == INVALID_SOCKET) {
        error = "connect to " + host + ":" + port_str + " failed";
        return nullptr;
    }

    // No SO_RCVTIMEO here: Read() bounds its own wait with select() so it can
    // tell a timeout apart from an error and an EOF. A 30 s socket timeout
    // would freeze the UI for 30 s before reporting a failure.

    return std::make_unique<WinsockTransport>(s);
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
    return std::make_unique<WinsockListener>(s);
}

}  // namespace rtsc::net

#endif  // _WIN32
