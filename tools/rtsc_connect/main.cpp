// rtsc_connect: drive a real RDP connection through the protocol state machine
// and the security layer.
//
// Usage:
//   rtsc_connect <host> [port] [domain] [user] [password]
//
// Without credentials the tool still runs the X.224 negotiation and starts the
// external security handshake; it will fail at the server's NTLM challenge,
// which is expected and reported. With credentials it can reach the Client Info
// PDU. Nothing is logged that contains the password.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "rtsc/net/transport.h"
#include "rtsc/proto/connect_machine.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/security/connection_driver.h"
#include "rtsc/util/crash_guard.h"

namespace {

constexpr const char* kVersion = "rtsc_connect 0.1.0";

void usage() {
    std::printf(
        "%s\n"
        "usage: rtsc_connect <host> [port] [domain] [user] [password]\n"
        "  port defaults to 3389; credentials are optional.\n",
        kVersion);
}

bool WriteAll(rtsc::net::Transport& t, const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return true;
    return t.Write(bytes.data(), bytes.size());
}

}  // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    rtsc::util::InstallCrashGuard("rtsc_connect");

    if (argc < 2) {
        usage();
        return 2;
    }
    const std::string host = argv[1];
    const uint16_t port =
        argc >= 3 ? static_cast<uint16_t>(std::atoi(argv[2])) : 3389;
    const std::string domain = argc >= 4 ? argv[3] : "";
    const std::string user = argc >= 5 ? argv[4] : "";
    const std::string password = argc >= 6 ? argv[5] : "";

    std::printf("connecting to %s:%u\n", host.c_str(),
                static_cast<unsigned>(port));

    std::string error;
    auto transport = rtsc::net::ConnectTcp(host, port, error);
    if (!transport) {
        std::printf("connect failed: %s\n", error.c_str());
        return 1;
    }

    rtsc::proto::ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.requested_protocols = rtsc::proto::kProtocolSsl |
                               rtsc::proto::kProtocolHybrid |
                               rtsc::proto::kProtocolHybridEx;
    mcfg.client_name = "RTSC";
    mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
    mcfg.encryption_methods = 0;

    rtsc::proto::ConnectMachine::Credentials creds;
    creds.domain = domain;
    creds.user_name = user;
    creds.password = password;

    rtsc::security::Config scfg;
    scfg.tls_config.peer_host = host;
    scfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    scfg.credentials.domain = domain;
    scfg.credentials.user = user;
    scfg.credentials.password = password;

    rtsc::security::ConnectionDriver driver(mcfg, creds, scfg);

    auto step = driver.Start();
    if (!WriteAll(*transport, step.to_send)) {
        std::printf("failed to send the X.224 Connection Request\n");
        return 1;
    }
    std::printf("sent X.224 Connection Request (%zu bytes)\n",
                step.to_send.size());

    uint8_t buf[8192];
    // A bounded read timeout is not a disconnect: keep waiting until the
    // wall-clock deadline, and only fail when the peer actually closes.
    int round = 0;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (round < 64) {
        const int n = transport->Read(buf, sizeof(buf));
        if (n == rtsc::net::kReadTimeout) {
            if (std::chrono::steady_clock::now() >= deadline) {
                std::printf("timed out waiting for the peer\n");
                return 1;
            }
            continue;
        }
        if (n <= 0) {
            std::printf("peer closed or read error (n=%d)\n", n);
            return 1;
        }
        ++round;
        step = driver.OnData(buf, static_cast<size_t>(n));
        if (step.failed) {
            std::printf("FAILED: %s\n", step.error.c_str());
            return 1;
        }
        if (!step.to_send.empty() && !WriteAll(*transport, step.to_send)) {
            std::printf("write failed\n");
            return 1;
        }
        std::printf(
            "round %d: recv %d, send %zu, phase=%s, protocol=0x%08x\n", round,
            n, step.to_send.size(),
            rtsc::proto::to_string(driver.machine().state().phase),
            driver.machine().state().negotiated_protocol);
        if (step.done) {
            std::printf("DONE: Client Info PDU sent\n");
            return 0;
        }
    }

    std::printf("stopped after the round limit\n");
    return 1;
}
