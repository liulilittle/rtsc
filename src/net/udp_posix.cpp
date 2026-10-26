// POSIX implementation of the UDP socket seam.

#include "rtsc/net/gateway_transport.h"

#if !defined(_WIN32)

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <string>

namespace rtsc::net {
namespace {

constexpr int kReceiveTimeoutMs = 100;

class PosixUdpSocket : public UdpSocket {
 public:
    explicit PosixUdpSocket(int sock) : sock_(sock) {}
    ~PosixUdpSocket() override { Close(); }

    bool Send(const uint8_t* data, size_t size) override {
        if (sock_ < 0) return false;
        size_t sent = 0;
        while (sent < size) {
            const ssize_t n = ::send(sock_, data + sent, size - sent, 0);
            if (n <= 0) return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }

    int Receive(uint8_t* buf, size_t size) override {
        if (sock_ < 0 || size == 0) return -1;
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock_, &readfds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = kReceiveTimeoutMs * 1000;
        const int ready = ::select(sock_ + 1, &readfds, nullptr, nullptr, &tv);
        if (ready == 0) return 0;
        if (ready < 0) return -1;
        const ssize_t n = ::recv(sock_, buf, size, 0);
        return n < 0 ? -1 : static_cast<int>(n);
    }

    void Close() override {
        if (sock_ >= 0) {
            ::close(sock_);
            sock_ = -1;
        }
    }

 private:
    int sock_ = -1;
};

}  // namespace

std::unique_ptr<UdpSocket> ConnectUdp(const std::string& host,
                                      uint16_t local_port, uint16_t peer_port,
                                      std::string& error) {
    error.clear();
    const std::string local_str = std::to_string(local_port);
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* local = nullptr;
    if (::getaddrinfo("0.0.0.0", local_str.c_str(), &hints, &local) != 0 ||
        local == nullptr) {
        error = "getaddrinfo failed for the local bind";
        return nullptr;
    }
    int sock = -1;
    for (addrinfo* p = local; p != nullptr; p = p->ai_next) {
        sock = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        int on = 1;
        ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (::bind(sock, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(sock);
        sock = -1;
    }
    ::freeaddrinfo(local);
    if (sock < 0) {
        error = "cannot bind the local UDP port " + local_str;
        return nullptr;
    }

    const std::string peer_str = std::to_string(peer_port);
    addrinfo* peer = nullptr;
    if (::getaddrinfo(host.c_str(), peer_str.c_str(), &hints, &peer) != 0 ||
        peer == nullptr) {
        ::close(sock);
        error = "getaddrinfo failed for " + host;
        return nullptr;
    }
    bool connected = false;
    for (addrinfo* p = peer; p != nullptr; p = p->ai_next) {
        if (::connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            connected = true;
            break;
        }
    }
    ::freeaddrinfo(peer);
    if (!connected) {
        ::close(sock);
        error = "UDP connect to " + host + ":" + peer_str + " failed";
        return nullptr;
    }
    return std::make_unique<PosixUdpSocket>(sock);
}

}  // namespace rtsc::net

#endif  // !_WIN32
