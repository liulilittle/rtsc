// POSIX implementation of the blocking byte transport.
//
// Compiled only on non-Windows platforms (see CMakeLists.txt). The interface it
// implements is platform neutral; the Windows sibling is winsock_transport.cpp.

#include "rtsc/net/transport.h"

#if !defined(_WIN32)

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <memory>
#include <string>

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
    explicit PosixListener(int fd) : fd_(fd) {}
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

 private:
    int fd_ = -1;
    std::atomic<bool> closed_{false};
};

}  // namespace

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

    int fd = -1;
    for (addrinfo* p = result; p != nullptr; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(result);

    if (fd < 0) {
        error = "connect to " + host + ":" + port_str + " failed";
        return nullptr;
    }

    // No SO_RCVTIMEO here: Read() bounds its own wait with poll() so it can
    // tell a timeout apart from an error and an EOF. A 30 s socket timeout
    // would freeze the UI for 30 s before reporting a failure.

    return std::make_unique<PosixTransport>(fd);
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
    return std::make_unique<PosixListener>(fd);
}

}  // namespace rtsc::net

#endif  // !_WIN32
