// Server-side enhanced security: TLS accept, CredSSP server, EUAR.
//
// These tests drive the server stack against the project's own client stack in
// the same process. A green run means the in-tree RDP server can complete the
// TLS + CredSSP leg that mstsc requires before it will send MCS.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "rtsc/client/client.h"
#include "rtsc/credssp/credssp.h"
#include "rtsc/credssp/credssp_server.h"
#include "rtsc/net/tls.h"
#include "rtsc/net/transport.h"
#include "rtsc/proto/connect_machine.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/security/connection_driver.h"
#include "rtsc/security/security_layer.h"
#include "rtsc/security/server_security_layer.h"
#include "rtsc/server/server.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::credssp;
using rtsc::security::SecurityLayer;
using rtsc::security::ServerConfig;
using rtsc::security::ServerSecurityLayer;
using rtsc::security::StepResult;
using rtsc::security::Want;

namespace {

std::optional<std::string> Lookup(const std::string& domain, const std::string& user) {
    if (user == "rtsc" && domain == "NTDEV") return std::string("password");
    return std::nullopt;
}

Bytes FixedServerKey() {
    // The binding hash only needs a non-empty, deterministic key. A real
    // server uses its RSA SubjectPublicKey.
    return Bytes(64, 0x5A);
}

// Pumps the client and server security layers against each other until both
// complete or either fails. Returns true when both reached kDone.
bool RunLoopback(SecurityLayer& client, ServerSecurityLayer& server, std::string& error) {
    std::vector<uint8_t> c2s;
    std::vector<uint8_t> s2c;
    for (int round = 0; round < 128; ++round) {
        StepResult cr = client.Step(c2s.data(), c2s.size());
        c2s.clear();
        if (cr.want == Want::kWrite) {
            s2c.insert(s2c.end(), cr.to_wire.begin(), cr.to_wire.end());
        } else if (cr.want == Want::kFailed) {
            error = "client: " + cr.error;
            return false;
        }

        StepResult sr = server.Step(s2c.data(), s2c.size());
        s2c.clear();
        if (sr.want == Want::kWrite) {
            c2s.insert(c2s.end(), sr.to_wire.begin(), sr.to_wire.end());
        } else if (sr.want == Want::kFailed) {
            error = "server: " + sr.error;
            return false;
        }

        if (client.handshake_complete() && server.handshake_complete()) return true;
        if (cr.want == Want::kRead && sr.want == Want::kRead && c2s.empty() && s2c.empty()) {
            error = "deadlock: both sides waiting with no output";
            return false;
        }
    }
    error = "did not converge within 128 rounds";
    return false;
}

}  // namespace

RTSC_TEST(credssp_server_direct_exchange) {
    Credentials creds;
    creds.domain = "NTDEV";
    creds.user = "rtsc";
    creds.password = "password";

    CredsspClient client(creds, 6);
    client.SetServerPublicKey(FixedServerKey());
    CredsspServer server(Lookup, 6);
    server.SetServerPublicKey(FixedServerKey());

    Bytes m1, m2, m3, m4, m5, m6;
    CHECK(client.Start(m1).ok());
    CHECK(!m1.empty());
    CHECK(server.OnClientMessage(m1.data(), m1.size(), m2).ok());
    CHECK(!m2.empty());
    CHECK(client.OnServerResponse(m2.data(), m2.size(), m3).ok());
    CHECK(!m3.empty());
    CHECK(server.OnClientMessage(m3.data(), m3.size(), m4).ok());
    CHECK(!m4.empty());
    CHECK(client.OnServerResponse(m4.data(), m4.size(), m5).ok());
    CHECK(!m5.empty());
    CHECK(server.OnClientMessage(m5.data(), m5.size(), m6).ok());
    CHECK(server.complete());
    CHECK(client.complete());
    CHECK(server.credentials().user == "rtsc");
    CHECK(server.credentials().password == "password");
    CHECK(server.mic_verified());
}

RTSC_TEST(credssp_server_challenge_flags_and_version) {
    // Regression for the mstsc interop fix: the server's NTLM CHALLENGE must
    // advertise NTLMSSP_NEGOTIATE_TARGET_INFO because it always sends an AV
    // list, and when NTLMSSP_NEGOTIATE_VERSION is negotiated the version
    // field (offset 48..55) must be non-zero. A real client (mstsc) rejects a
    // CHALLENGE that advertises kVersion with a zero version, or an AV list
    // without kTargetInfo, and drops the connection at the pubKeyAuth step.
    CredsspServer server(Lookup, 6);
    server.SetServerPublicKey(FixedServerKey());

    // A mstsc-like NEGOTIATE: it does NOT request kTargetInfo, so the server
    // must set that flag on its own because it always sends an AV list. Using
    // the project's own CredsspClient here would hide a kTargetInfo revert,
    // because that client requests the flag itself.
    NegotiateMessage neg;
    neg.flags = 0xE20882B7;  // measured mstsc NEGOTIATE flags (no kTargetInfo)
    Bytes neg_bytes;
    CHECK(neg.Encode(neg_bytes).ok());
    TsRequest req;
    req.version = 6;
    req.nego_token = neg_bytes;
    Bytes m1;
    CHECK(req.Encode(m1).ok());

    Bytes m2;
    CHECK(server.OnClientMessage(m1.data(), m1.size(), m2).ok());

    const Bytes challenge = server.ChallengeMessageForTest();
    CHECK(challenge.size() >= 56);
    CHECK(challenge[0] == static_cast<uint8_t>('N'));
    CHECK_EQ(challenge[8], static_cast<uint8_t>(0x02));  // MESSAGE_TYPE_CHALLENGE

    const uint32_t flags = static_cast<uint32_t>(challenge[20]) |
                           (static_cast<uint32_t>(challenge[21]) << 8) |
                           (static_cast<uint32_t>(challenge[22]) << 16) |
                           (static_cast<uint32_t>(challenge[23]) << 24);
    CHECK((flags & ntlm_flag::kTargetInfo) != 0);
    CHECK((flags & ntlm_flag::kVersion) != 0);
    CHECK_EQ(challenge[48], static_cast<uint8_t>(0x0A));  // ProductMajorVersion
    CHECK_EQ(challenge[49], static_cast<uint8_t>(0x00));  // ProductMinorVersion
}

RTSC_TEST(credssp_server_rejects_unknown_account) {
    Credentials creds;
    creds.domain = "NTDEV";
    creds.user = "ghost";
    creds.password = "password";

    CredsspClient client(creds, 6);
    client.SetServerPublicKey(FixedServerKey());
    CredsspServer server(Lookup, 6);
    server.SetServerPublicKey(FixedServerKey());

    Bytes m1, m2, m3;
    CHECK(client.Start(m1).ok());
    CHECK(server.OnClientMessage(m1.data(), m1.size(), m2).ok());
    CHECK(client.OnServerResponse(m2.data(), m2.size(), m3).ok());
    // The server cannot derive the session key for an unknown account, so the
    // AUTHENTICATE is rejected and the exchange never completes.
    CHECK(!server.OnClientMessage(m3.data(), m3.size(), m2).ok());
    CHECK(!server.complete());
}

RTSC_TEST(tls_server_loopback_to_done) {
    rtsc::security::Config ccfg;
    ccfg.tls_config.role = rtsc::tls::Role::kClient;
    ccfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    ccfg.tls_config.peer_host = "127.0.0.1";
    ccfg.credssp_version = 6;
    ccfg.credentials.domain = "NTDEV";
    ccfg.credentials.user = "rtsc";
    ccfg.credentials.password = "password";

    ServerConfig scfg;
    scfg.tls_config.role = rtsc::tls::Role::kServer;
    scfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    scfg.credssp_version = 6;
    scfg.credential_lookup = Lookup;

    std::string cwhy, swhy;
    auto client = SecurityLayer::Create(ccfg, cwhy);
    auto server = ServerSecurityLayer::Create(scfg, swhy);
    if (!client || !server) {
        std::printf("  create failed: client=%s server=%s\n", cwhy.c_str(),
                    swhy.c_str());
    }
    CHECK(client != nullptr);
    CHECK(server != nullptr);
    if (!client || !server) return;

    std::string error;
    CHECK(RunLoopback(*client, *server, error));
    if (!error.empty()) std::printf("  loopback error: %s\n", error.c_str());
}

#if defined(_WIN32)
RTSC_TEST(server_enhanced_security_loopback_to_active) {
    // The full loopback: the project's own client (ConnectionDriver + graphics)
    // connects to the in-tree server over PROTOCOL_HYBRID (TLS + CredSSP) and
    // reaches the active session, receiving a test-pattern frame. This is the
    // same leg mstsc needs before it will send MCS.
    const uint16_t port = 3396;
    rtsc::server::ServerConfig scfg;
    scfg.port = port;
    scfg.desktop_width = 64;
    scfg.desktop_height = 48;
    scfg.enable_enhanced_security = true;
    scfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    scfg.credssp_version = 6;
    scfg.credential_lookup = Lookup;
    auto source = rtsc::server::MakeTestPatternSource();
    rtsc::server::RdpServer server(scfg);
    server.SetDesktopSource(source.get());
    std::string error;
    CHECK(server.Start(error));
    std::thread runner([&server]() { server.Run(); });

    rtsc::proto::ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.requested_protocols =
        rtsc::proto::kProtocolSsl | rtsc::proto::kProtocolHybrid;
    mcfg.desktop_width = 64;
    mcfg.desktop_height = 48;
    mcfg.client_name = "RTSC";
    mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
    mcfg.encryption_methods = 0;

    rtsc::proto::ConnectMachine::Credentials creds;
    creds.domain = "NTDEV";
    creds.user_name = "rtsc";
    creds.password = "password";

    rtsc::security::Config secfg;
    secfg.tls_config.peer_host = "127.0.0.1";
    secfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    secfg.credssp_version = 6;
    secfg.credentials.domain = "NTDEV";
    secfg.credentials.user = "rtsc";
    secfg.credentials.password = "password";

    rtsc::security::ConnectionDriver driver(mcfg, creds, secfg);
    rtsc::client::Client client(std::move(driver), 64, 48);

    std::string cerr;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", port, cerr);
    CHECK(transport != nullptr);
    if (transport != nullptr) {
        CHECK(client.Connect(*transport, error));
        if (!error.empty()) std::printf("  connect error: %s\n", error.c_str());
        CHECK(client.active());
        CHECK(!client.driver().standard_rdp());
        CHECK(client.driver().security_active());
        CHECK(client.driver().security() != nullptr);
        CHECK(client.driver().security()->handshake_complete());

        bool got_frame = false;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!got_frame && std::chrono::steady_clock::now() < deadline) {
            if (!client.Pump(*transport, error)) break;
            uint8_t r = 0, g = 0, b = 0, a = 0;
            if (client.surface().GetPixel(0, 0, r, g, b, a) && r == 255 &&
                g == 255 && b == 255 && a == 255) {
                got_frame = true;
            }
        }
        if (!got_frame) std::printf("  frame error: %s\n", error.c_str());
        CHECK(got_frame);
        transport->Close();
    }

    server.Stop();
    runner.join();
}
#endif  // _WIN32

int main() { return rtsc::test::run_all("rtsc_server_security_tests"); }
