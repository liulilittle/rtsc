// rtsc_connect: drive a real RDP connection through the protocol state machine
// and the security layer.
//
// Usage:
//   rtsc_connect [--rdp] <host> [port] [domain] [user] [password]
//
// Without --rdp the tool requests external security (TLS / CredSSP). With
// --rdp it requests PROTOCOL_RDP (Standard RDP Security): the MCS channel stays
// plaintext, the Security Exchange uses RSA, and the licensing/data PDUs use
// the RC4 SEC_ENCRYPT layer. In that mode the tool keeps reading until the
// session is active and at least one graphics/data PDU has arrived, which is
// the end-to-end loopback check against the in-tree server.
//
// Nothing is logged that contains the password.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

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
        "usage: rtsc_connect [--rdp] [--tls-insecure] <host> [port] [domain] "
        "[user] [password]\n"
        "  --rdp           request PROTOCOL_RDP (Standard RDP Security, RC4 data plane)\n"
        "  --tls-insecure  disable TLS certificate verification (not recommended)\n"
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

    bool standard_rdp = false;
    bool tls_insecure = false;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--rdp") == 0) {
            standard_rdp = true;
            continue;
        }
        if (std::strcmp(argv[i], "--tls-insecure") == 0) {
            tls_insecure = true;
            continue;
        }
        args.emplace_back(argv[i]);
    }
    if (args.empty()) {
        usage();
        return 2;
    }

    const std::string host = args[0];
    const uint16_t port =
        args.size() >= 2 ? static_cast<uint16_t>(std::atoi(args[1].c_str()))
                         : 3389;
    const std::string domain = args.size() >= 3 ? args[2] : "";
    const std::string user = args.size() >= 4 ? args[3] : "";
    const std::string password = args.size() >= 5 ? args[4] : "";

    std::printf("connecting to %s:%u (%s)\n", host.c_str(),
                static_cast<unsigned>(port),
                standard_rdp ? "PROTOCOL_RDP" : "external security");

    std::string error;
    auto transport = rtsc::net::ConnectTcp(host, port, error);
    if (!transport) {
        std::printf("connect failed: %s\n", error.c_str());
        return 1;
    }

    rtsc::proto::ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.client_name = "RTSC";
    mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
    if (standard_rdp) {
        mcfg.requested_protocols = rtsc::proto::kProtocolRdp;
        // Advertise 40/128/56-bit Standard RDP Security. The server picks the
        // strongest method and returns the matching RSA certificate.
        mcfg.encryption_methods = 0x0000001B;
    } else {
        mcfg.requested_protocols = rtsc::proto::kProtocolSsl |
                                   rtsc::proto::kProtocolHybrid |
                                   rtsc::proto::kProtocolHybridEx;
        mcfg.encryption_methods = 0;
    }

    rtsc::proto::ConnectMachine::Credentials creds;
    creds.domain = domain;
    creds.user_name = user;
    creds.password = password;

    rtsc::security::Config scfg;
    scfg.tls_config.peer_host = host;
    // Certificate verification is on by default; --tls-insecure is the
    // explicit escape hatch for isolated environments.
    scfg.tls_config.cert_policy = tls_insecure
                                      ? rtsc::tls::CertPolicy::kInsecure
                                      : rtsc::tls::CertPolicy::kStrict;
    scfg.credentials.domain = domain;
    scfg.credentials.user = user;
    scfg.credentials.password = password;

    rtsc::security::ConnectionDriver driver(mcfg, creds, scfg);
    size_t session_pdus = 0;
    size_t session_bytes = 0;
    driver.SetSessionPduHandler([&](const std::vector<uint8_t>& pdu) {
        ++session_pdus;
        session_bytes += pdu.size();
        std::printf("data PDU %zu: %zu bytes\n", session_pdus, pdu.size());
    });

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
    bool done_printed = false;
    bool active = false;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (round < 256) {
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

        const bool negotiated_rdp =
            driver.machine().state().negotiated_protocol ==
            rtsc::proto::kProtocolRdp;
        if (step.done && !done_printed) {
            done_printed = true;
            std::printf("DONE: Client Info PDU sent\n");
            if (!negotiated_rdp) {
                // Historical behaviour for the external-security path: the
                // tool's job ends once the post-handshake MCS sequence is up.
                return 0;
            }
        }
        if (step.active && !active) {
            active = true;
            std::printf("ACTIVE: session reached S4 (Font Map received)\n");
        }
        if (negotiated_rdp && active && session_pdus > 0) {
            std::printf("LOOPBACK OK: active, %zu data PDUs, %zu bytes\n",
                        session_pdus, session_bytes);
            return 0;
        }
    }

    std::printf("stopped after the round limit\n");
    return 1;
}
