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
#include "test_tls_scripted.h"
#include "test_framework.h"
#include "test_main.h"


// The coalesced-handshake deadlock regression drives a bare OpenSSL client so
// the same process can build a REAL "[client Finished][first app record]"
// segment. test_tls_openssl.cpp does not link rtsc_security, so the deadlock
// (which lives in ServerSecurityLayer::DriveCredssp) cannot be exercised there.
//
// The guard is the BACKEND option, not the platform: RTSC_TLS_OPENSSL defaults
// to OFF, so a non-Windows build (the Linux gate) has no OpenSSL headers or
// libs unless it was explicitly enabled. `!defined(_WIN32)` was wrong there and
// broke the link with undefined SSL_* references.
#if defined(RTSC_TLS_OPENSSL)
#include <openssl/ssl.h>
#endif

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

    if (rtsc::tls::EnumerateTlsBackends().empty()) {
        std::printf("  skipped: no platform TLS backend (need SChannel or RTSC_TLS_OPENSSL)\n");
        return;
    }

    std::string error;
    CHECK(RunLoopback(*client, *server, error));
    if (!error.empty()) std::printf("  loopback error: %s\n", error.c_str());
}

RTSC_TEST(server_security_layer_hybrid_without_ex_omits_euar) {
    // [MS-RDPBCGR] 2.2.10.2: the server sends the 4-byte Early User
    // Authorization Result only when PROTOCOL_HYBRID_EX was negotiated. A
    // HYBRID-only session must end after CredSSP step 5 with no extra bytes;
    // otherwise the client (mstsc) sees unsolicited data and resets with a
    // protocol error (0x1204).
    ServerConfig scfg;
    scfg.tls_config.role = rtsc::tls::Role::kServer;
    scfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    scfg.credssp_version = 6;
    scfg.credential_lookup = Lookup;
    scfg.euar_required = false;

    std::string swhy;
    auto server = ServerSecurityLayer::Create(scfg, swhy);
    CHECK(server != nullptr);
    if (!server) return;
    server->SetTlsTransportForTest(std::make_unique<ScriptedTls>());

    // Complete the server TLS accept. The scripted transport consumes the two
    // handshake tokens, so the CredSSP exchange below starts with an empty
    // plaintext buffer (exactly as after a real accept).
    auto sr = server->Step(nullptr, 0);
    CHECK(sr.want == Want::kRead);
    const uint8_t hello[] = {0x16, 0x03, 0x01, 0x00, 0x05, 0x01};
    sr = server->Step(hello, sizeof(hello));
    CHECK(sr.want == Want::kWrite);  // server hello
    const uint8_t finished[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    sr = server->Step(finished, sizeof(finished));
    CHECK(sr.want == Want::kRead);  // accept complete, awaiting CredSSP

    // Drive a real CredSSP client directly so the exchange is not masked by
    // the project's own client state machine.
    Credentials creds;
    creds.domain = "NTDEV";
    creds.user = "rtsc";
    creds.password = "password";
    CredsspClient client(creds, 6);
    client.SetServerPublicKey(
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01});

    Bytes m1, m2, m3, m4, m5;
    CHECK(client.Start(m1).ok());
    sr = server->Step(m1.data(), m1.size());
    CHECK(sr.want == Want::kWrite);
    m2 = sr.to_wire;
    CHECK(client.OnServerResponse(m2.data(), m2.size(), m3).ok());
    sr = server->Step(m3.data(), m3.size());
    CHECK(sr.want == Want::kWrite);
    m4 = sr.to_wire;
    CHECK(client.OnServerResponse(m4.data(), m4.size(), m5).ok());

    // Step 5 (authInfo) completes CredSSP. With HYBRID there is no EUAR: the
    // layer must report kDone and must not emit a 4-byte AUTHZ result.
    sr = server->Step(m5.data(), m5.size());
    CHECK(sr.want == Want::kDone);
    CHECK(server->handshake_complete());
    CHECK(!(sr.to_wire.size() == 4 && sr.to_wire[0] == 0x00 &&
            sr.to_wire[1] == 0x00 && sr.to_wire[2] == 0x00 &&
            sr.to_wire[3] == 0x00));
}

RTSC_TEST(server_enhanced_security_loopback_to_active) {
    // The full loopback: the project's own client (ConnectionDriver + graphics)
    // connects to the in-tree server over PROTOCOL_HYBRID (TLS + CredSSP) and
    // reaches the active session, receiving a test-pattern frame. This is the
    // same leg mstsc needs before it will send MCS.
    if (rtsc::tls::EnumerateTlsBackends().empty()) {
        std::printf("  skipped: no platform TLS backend (need SChannel or RTSC_TLS_OPENSSL)\n");
        return;
    }
    rtsc::server::ServerConfig scfg;
    scfg.port = 0;  // ephemeral: the kernel picks a free port
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
    const uint16_t port = server.bound_port();
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

RTSC_TEST(server_selects_hybrid_ex_when_client_requests_it) {
    // mstsc advertises PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX
    // (0x0B). The server must answer with PROTOCOL_HYBRID_EX (0x8) and send
    // the EUAR; selecting plain HYBRID (0x2) while still sending the EUAR makes
    // mstsc treat those 4 bytes as a protocol error (0x1204) and reset.
    if (rtsc::tls::EnumerateTlsBackends().empty()) {
        std::printf("  skipped: no platform TLS backend (need SChannel or RTSC_TLS_OPENSSL)\n");
        return;
    }
    rtsc::server::ServerConfig scfg;
    scfg.port = 0;  // ephemeral: the kernel picks a free port
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
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    rtsc::proto::ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.requested_protocols = rtsc::proto::kProtocolSsl |
                               rtsc::proto::kProtocolHybrid |
                               rtsc::proto::kProtocolHybridEx;
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
        CHECK(client.driver().machine().state().negotiated_protocol ==
              rtsc::proto::kProtocolHybridEx);
        CHECK(client.active());
        transport->Close();
    }

    server.Stop();
    runner.join();
}

#if defined(RTSC_TLS_OPENSSL)
// ---------------------------------------------------------------------------
// Coalesced-handshake deadlock regression (P0, D1 dependency).
//
// A real peer (mstsc / FreeRDP) sends its FINAL handshake flight AND the first
// application record (the CredSSP NEGOTIATE) in one TCP segment. D1 makes the
// OpenSSL backend report that whole buffer as consumed (consumed == in_size),
// so pending_cipher_ is empty after the handshake AND the record sits in the
// backend's read BIO. ServerSecurityLayer::DriveCredssp must still run the
// buffered_input() drain with no pending ciphertext, otherwise the NEGOTIATE is
// stranded and both ends wait forever (the client for a CHALLENGE that the
// server can never produce).
// ---------------------------------------------------------------------------

struct RawOpenSslClient {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    BIO* rbio = nullptr;
    BIO* wbio = nullptr;

    ~RawOpenSslClient() {
        if (ssl) SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
    }

    bool Start() {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) return false;
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        ssl = SSL_new(ctx);
        if (!ssl) return false;
        rbio = BIO_new(BIO_s_mem());
        wbio = BIO_new(BIO_s_mem());
        if (!rbio || !wbio) return false;
        SSL_set_bio(ssl, rbio, wbio);
        SSL_set_connect_state(ssl);
        return true;
    }

    void Feed(const uint8_t* data, size_t size) {
        if (size > 0) BIO_write(rbio, data, static_cast<int>(size));
    }

    std::vector<uint8_t> Drain() {
        std::vector<uint8_t> out;
        for (;;) {
            const size_t pending = BIO_ctrl_pending(wbio);
            if (pending == 0) break;
            const size_t old = out.size();
            out.resize(old + pending);
            const int n =
                BIO_read(wbio, out.data() + old, static_cast<int>(pending));
            if (n <= 0) { out.resize(old); break; }
            out.resize(old + static_cast<size_t>(n));
        }
        return out;
    }

    // Any application plaintext currently decryptable (empty on WANT_READ).
    std::vector<uint8_t> ReadAvailable() {
        std::vector<uint8_t> out;
        for (;;) {
            uint8_t buf[4096];
            const int n = SSL_read(ssl, buf, sizeof(buf));
            if (n <= 0) break;
            out.insert(out.end(), buf, buf + n);
        }
        return out;
    }
};

RTSC_TEST(tls_server_regression_coalesced_first_record_no_stall) {
    if (rtsc::tls::EnumerateTlsBackends().empty()) {
        std::printf("  skipped: no platform TLS backend\n");
        return;
    }

    ServerConfig scfg;
    scfg.tls_config.role = rtsc::tls::Role::kServer;
    scfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    scfg.credssp_version = 6;
    scfg.credential_lookup = Lookup;
    std::string swhy;
    auto server = ServerSecurityLayer::Create(scfg, swhy);
    CHECK(server != nullptr);
    if (!server) return;

    // A valid CredSSP NEGOTIATE TSRequest: the application record that would be
    // stranded in the TLS backend if the drain did not run.
    NegotiateMessage neg;
    neg.flags = 0xE20882B7;
    Bytes negb;
    CHECK(neg.Encode(negb).ok());
    TsRequest req;
    req.version = 6;
    req.nego_token = negb;
    Bytes payload;
    CHECK(req.Encode(payload).ok());

    RawOpenSslClient client;
    CHECK(client.Start());

    // Pump the handshake until the bare client's side is complete. Its FINAL
    // flight (Finished) is held, then coalesced with the app record below.
    std::vector<uint8_t> coalesced;
    for (int i = 0; i < 40; ++i) {
        const int rc = SSL_do_handshake(client.ssl);
        auto c_out = client.Drain();
        if (rc == 1) {
            // Finished is the last drain; append the FIRST application record.
            if (SSL_write(client.ssl, payload.data(),
                          static_cast<int>(payload.size())) !=
                static_cast<int>(payload.size())) {
                CHECK(false);
                break;
            }
            auto extra = client.Drain();
            for (const uint8_t b : extra) c_out.push_back(b);
            coalesced = std::move(c_out);
            break;
        }
        const StepResult sr = server->Step(c_out.data(), c_out.size());
        CHECK(sr.want != Want::kFailed);
        if (sr.want == Want::kFailed) break;
        if (sr.want == Want::kWrite && !sr.to_wire.empty()) {
            client.Feed(sr.to_wire.data(), sr.to_wire.size());
        }
    }
    CHECK(!coalesced.empty());
    if (coalesced.empty()) return;

    // Present [Finished][NEGOTIATE] once, then give the layer NO further input.
    // The NEGOTIATE must still surface as a CHALLENGE solely via the drain.
    StepResult sr = server->Step(coalesced.data(), coalesced.size());
    bool got_challenge = false;
    for (int i = 0; i < 6 && !got_challenge; ++i) {
        if (sr.want == Want::kFailed) break;
        if (sr.want == Want::kWrite && !sr.to_wire.empty()) {
            client.Feed(sr.to_wire.data(), sr.to_wire.size());
            const std::vector<uint8_t> der = client.ReadAvailable();
            // A CredSSP server response begins with DER SEQUENCE (0x30).
            if (!der.empty() && der[0] == 0x30) {
                got_challenge = true;
                break;
            }
        }
        sr = server->Step(nullptr, 0);
    }
    // RED before the DriveCredssp drain hoist: the record stays in the backend,
    // no kWrite ever materialises, and Step(nullptr, 0) keeps returning kRead.
    //
    // The gate asserts this marker, because a check COUNT is not proof the body
    // ran (checks are counted per CHECK, so real ones can be swapped for
    // `CHECK(true)` with the total unchanged).
    //
    // What the marker proves: this success path was reached. The drain that
    // makes it reachable is ServerSecurityLayer's CredSSP-phase loop
    // (src/security/server_security_layer.cpp:194); disabling THAT loop is what
    // turns this case red (measured), so this case is that loop's only guard.
    // What the marker does NOT prove: that `CHECK(got_challenge)` below still exists.
    // Deleting just that statement keeps the marker and the exit code at 0 --
    // CHECK reports failures without altering control flow
    // (tests/test_framework.h:47-53), so "produced output" cannot witness a
    // deleted assertion (audit X, measured). Guarding against that is code
    // review's job.
    if (got_challenge) std::printf("  drain: challenge surfaced after coalesced record\n");
    CHECK(got_challenge);
}
#endif  // defined(RTSC_TLS_OPENSSL)

int main() { return rtsc::test::run_all("rtsc_server_security_tests"); }
