#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "rtsc/proto/connection_initiation.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/proto/tpkt.h"
#include "rtsc/proto/x224.h"
#include "rtsc/util/crash_guard.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

namespace {

using namespace rtsc::proto;

constexpr const char* kVersion = "rtsc_probe 0.1.0";

void usage() {
    std::printf(
        "%s\n"
        "usage:\n"
        "  rtsc_probe --version\n"
        "  rtsc_probe --parse-hex <hex bytes>     decode a TPKT/X.224/RDP_NEG PDU\n"
        "  rtsc_probe --crq-hex [cookie]          print the CRQ we would send\n"
        "  rtsc_probe --connect <host> [port] [cookie]\n"
        "                                         send CRQ, decode server CCF\n",
        kVersion);
}

std::vector<uint8_t> parse_hex(const char* s, bool& ok) {
    std::vector<uint8_t> out;
    ok = true;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    int hi = -1;
    for (const char* p = s; *p; ++p) {
        if (*p == ' ' || *p == ',' || *p == '-' || *p == ':') continue;
        const int v = nib(*p);
        if (v < 0) {
            ok = false;
            return {};
        }
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    if (hi >= 0) ok = false;
    return out;
}

const char* protocol_name(uint32_t p) {
    switch (p) {
        case kProtocolRdp: return "PROTOCOL_RDP (standard RDP security)";
        case kProtocolSsl: return "PROTOCOL_SSL (TLS)";
        case kProtocolHybrid: return "PROTOCOL_HYBRID (CredSSP/NLA)";
        case kProtocolRdstls: return "PROTOCOL_RDSTLS";
        case kProtocolHybridEx: return "PROTOCOL_HYBRID_EX (CredSSP + EUAR)";
        case kProtocolRdsaad: return "PROTOCOL_RDSAAD";
        default: return "UNKNOWN";
    }
}

void dump(const std::vector<uint8_t>& bytes) {
    for (size_t i = 0; i < bytes.size(); ++i) {
        std::printf("%02X ", bytes[i]);
        if ((i + 1) % 16 == 0) std::printf("\n");
    }
    if (bytes.size() % 16 != 0) std::printf("\n");
}

int decode(const std::vector<uint8_t>& bytes) {
    std::printf("bytes: %zu\n", bytes.size());
    dump(bytes);

    TpktHeader tpkt;
    Status s = TpktHeader::parse(bytes.data(), bytes.size(), tpkt);
    if (s != Status::Ok) {
        std::printf("TPKT: %s\n", to_string(s));
        return 1;
    }
    std::printf("TPKT: version=3 length=%u payload=%zu\n", tpkt.length,
                tpkt.payload_size());
    s = tpkt.validate(bytes.size());
    if (s != Status::Ok) {
        std::printf("TPKT validate: %s\n", to_string(s));
        return 1;
    }

    X224Tpdu tpdu;
    s = X224Tpdu::parse(bytes.data() + TpktHeader::kSize, tpkt.payload_size(), tpdu);
    if (s != Status::Ok) {
        std::printf("X.224: %s\n", to_string(s));
        return 1;
    }
    const char* code_name = "UNKNOWN";
    switch (tpdu.code) {
        case X224Tpdu::kConnectionRequest: code_name = "CRQ"; break;
        case X224Tpdu::kConnectionConfirm: code_name = "CCF"; break;
        case X224Tpdu::kDisconnectRequest: code_name = "DR"; break;
        case X224Tpdu::kData: code_name = "DT"; break;
    }
    std::printf("X.224: LI=%u code=0x%02X(%s) dst=%u src=0x%04X class=0x%02X\n",
                tpdu.length_indicator, tpdu.code, code_name, tpdu.destination_reference,
                tpdu.source_reference, tpdu.class_options);

    const size_t neg_off = TpktHeader::kSize + X224Tpdu::kSize;
    if (bytes.size() <= neg_off) {
        std::printf("RDP_NEG: absent (implicit PROTOCOL_RDP)\n");
        return 0;
    }
    RdpNegData neg;
    s = RdpNegData::parse(bytes.data() + neg_off, bytes.size() - neg_off, neg);
    if (s != Status::Ok) {
        std::printf("RDP_NEG: %s\n", to_string(s));
        return 1;
    }
    switch (neg.kind) {
        case RdpNegData::Kind::kNone:
            std::printf("RDP_NEG: absent (implicit PROTOCOL_RDP)\n");
            break;
        case RdpNegData::Kind::kResponse:
            std::printf("RDP_NEG_RSP: flags=0x%02X selected=0x%08X %s\n",
                        neg.response.flags, neg.response.selected_protocol,
                        protocol_name(neg.response.selected_protocol));
            break;
        case RdpNegData::Kind::kFailure:
            std::printf("RDP_NEG_FAILURE: 0x%08X %s\n",
                        static_cast<uint32_t>(neg.failure.failure_code),
                        to_string(neg.failure.failure_code));
            break;
    }
    return 0;
}

std::vector<uint8_t> build_crq(const std::string& cookie) {
    X224ConnectionRequest req;
    if (!cookie.empty()) req.cookie = "Cookie: mstshash=" + cookie;
    req.include_neg_req = true;
    req.neg_req.flags = 0;
    req.neg_req.requested_protocols = kProtocolSsl | kProtocolHybrid | kProtocolHybridEx;
    return req.encode();
}

#ifdef _WIN32
int connect_and_negotiate(const std::string& host, uint16_t port,
                          const std::string& cookie) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::printf("WSAStartup failed\n");
        return 1;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    std::snprintf(port_str, sizeof(port_str), "%u", port);

    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), port_str, &hints, &result) != 0) {
        std::printf("getaddrinfo(%s) failed\n", host.c_str());
        WSACleanup();
        return 1;
    }

    SOCKET sock = INVALID_SOCKET;
    for (addrinfo* p = result; p; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == INVALID_SOCKET) continue;
        if (connect(sock, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) break;
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
    freeaddrinfo(result);

    if (sock == INVALID_SOCKET) {
        std::printf("connect %s:%u failed (error %d)\n", host.c_str(), port,
                    WSAGetLastError());
        WSACleanup();
        return 1;
    }
    std::printf("connected to %s:%u\n", host.c_str(), port);

    const auto crq = build_crq(cookie);
    std::printf("--> CRQ (%zu bytes)\n", crq.size());
    dump(crq);
    if (send(sock, reinterpret_cast<const char*>(crq.data()),
             static_cast<int>(crq.size()), 0) != static_cast<int>(crq.size())) {
        std::printf("send failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::vector<uint8_t> resp(4096);
    const int n = recv(sock, reinterpret_cast<char*>(resp.data()),
                       static_cast<int>(resp.size()), 0);
    if (n <= 0) {
        std::printf("recv failed (%d)\n", n);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    resp.resize(static_cast<size_t>(n));
    std::printf("<-- CCF (%d bytes)\n", n);
    const int rc = decode(resp);

    closesocket(sock);
    WSACleanup();
    return rc;
}
#else
int connect_and_negotiate(const std::string&, uint16_t, const std::string&) {
    std::printf("connect not implemented on this platform yet\n");
    return 1;
}
#endif

}  // namespace

int main(int argc, char** argv) {
    rtsc::util::InstallCrashGuard("rtsc_probe");
    if (argc < 2) {
        usage();
        return 1;
    }
    const std::string cmd = argv[1];
    if (cmd == "--version" || cmd == "-v") {
        std::printf("%s\n", kVersion);
        return 0;
    }
    if (cmd == "--help" || cmd == "-h") {
        usage();
        return 0;
    }
    if (cmd == "--parse-hex" && argc >= 3) {
        bool ok = false;
        const auto bytes = parse_hex(argv[2], ok);
        if (!ok || bytes.empty()) {
            std::printf("invalid hex input\n");
            return 1;
        }
        return decode(bytes);
    }
    if (cmd == "--crq-hex") {
        const std::string cookie = argc >= 3 ? argv[2] : std::string();
        const auto crq = build_crq(cookie);
        std::printf("CRQ (%zu bytes)\n", crq.size());
        dump(crq);
        return 0;
    }
    if (cmd == "--connect" && argc >= 3) {
        const std::string host = argv[2];
        const uint16_t port =
            argc >= 4 ? static_cast<uint16_t>(std::stoi(argv[3])) : 3389;
        const std::string cookie = argc >= 5 ? argv[4] : std::string();
        return connect_and_negotiate(host, port, cookie);
    }
    usage();
    return 1;
}
