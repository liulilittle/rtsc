// Winsock implementation of the UDP socket seam.

#include "rtsc/net/gateway_transport.h"

#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>

#include <string>

namespace rtsc::net {
namespace {

constexpr int kReceiveTimeoutMs = 100;

class WinsockUdpSocket : public UdpSocket {
 public:
    explicit WinsockUdpSocket(SOCKET sock) : sock_(sock) {}
    ~WinsockUdpSocket() override { Close(); }

    bool Send(const uint8_t* data, size_t size) override {
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

    int Receive(uint8_t* buf, size_t size) override {
        if (sock_ == INVALID_SOCKET || size == 0) return -1;
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock_, &readfds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = kReceiveTimeoutMs * 1000;
        const int ready = ::select(0, &readfds, nullptr, nullptr, &tv);
        if (ready == 0) return 0;
        if (ready == SOCKET_ERROR) return -1;
        const int n = ::recv(sock_, reinterpret_cast<char*>(buf),
                             static_cast<int>(size), 0);
        return n;
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

bool EnsureWinsock() {
    static const bool ok = []() {
        WSADATA data;
        return ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    return ok;
}

}  // namespace

std::unique_ptr<UdpSocket> ConnectUdp(const std::string& host,
                                      uint16_t local_port, uint16_t peer_port,
                                      std::string& error) {
    error.clear();
    if (!EnsureWinsock()) {
        error = "WSAStartup failed";
        return nullptr;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    const std::string local_str = std::to_string(local_port);
    addrinfo* local = nullptr;
    if (::getaddrinfo("0.0.0.0", local_str.c_str(), &hints, &local) != 0 ||
        local == nullptr) {
        error = "getaddrinfo failed for the local bind";
        return nullptr;
    }

    SOCKET sock = INVALID_SOCKET;
    for (addrinfo* p = local; p != nullptr; p = p->ai_next) {
        sock = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == INVALID_SOCKET) continue;
        int on = 1;
        ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&on), sizeof(on));
        if (::bind(sock, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) break;
        ::closesocket(sock);
        sock = INVALID_SOCKET;
    }
    ::freeaddrinfo(local);
    if (sock == INVALID_SOCKET) {
        error = "cannot bind the local UDP port " + local_str;
        return nullptr;
    }

    const std::string peer_str = std::to_string(peer_port);
    addrinfo* peer = nullptr;
    if (::getaddrinfo(host.c_str(), peer_str.c_str(), &hints, &peer) != 0 ||
        peer == nullptr) {
        ::closesocket(sock);
        error = "getaddrinfo failed for " + host;
        return nullptr;
    }
    bool connected = false;
    for (addrinfo* p = peer; p != nullptr; p = p->ai_next) {
        if (::connect(sock, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) {
            connected = true;
            break;
        }
    }
    ::freeaddrinfo(peer);
    if (!connected) {
        ::closesocket(sock);
        error = "UDP connect to " + host + ":" + peer_str + " failed";
        return nullptr;
    }
    return std::make_unique<WinsockUdpSocket>(sock);
}

}  // namespace rtsc::net

#endif  // _WIN32
