// Security layer: TLS + CredSSP + EUAR state machine.
//
// Reference: docs/spec/security-integration.audit-a.md section 4.1 (方案 B).
//
// The TLS transport is scripted so the state machine can be driven end to end
// without a network peer. The CredSSP server side is simulated from the spec
// (see test_credssp_sm.cpp for the same technique): the client's own
// MakeServerEchoForTest() produces the step-4 echo, which is legitimate because
// the echo must match the client's binding hash by construction.

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/client/client.h"
#include "rtsc/crypto/hash.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/security/connection_driver.h"
#include "rtsc/security/security_layer.h"
#include "test_tls_scripted.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::credssp;

namespace {



// A server-side CHALLENGE built from the official NTLM vector (same shape as
// test_credssp_sm.cpp), so the client sees a realistic message.
Bytes ServerChallengeMessage() {
    ChallengeMessage m;
    m.flags = ntlm_flag::kUnicode | ntlm_flag::kRequestTarget | ntlm_flag::kSign |
              ntlm_flag::kSeal | ntlm_flag::kNtlm | ntlm_flag::kAlwaysSign |
              ntlm_flag::kExtendedSessionSecurity | ntlm_flag::kTargetInfo |
              ntlm_flag::kVersion | ntlm_flag::k128 | ntlm_flag::kKeyExch |
              ntlm_flag::k56 | ntlm_flag::kTargetTypeServer;
    m.server_challenge = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    m.target_name = "Server";
    AvPair domain;
    domain.id = AvId::kNbDomainName;
    domain.value = ::rtsc::crypto::Utf16Le("Domain");
    AvPair server;
    server.id = AvId::kNbComputerName;
    server.value = ::rtsc::crypto::Utf16Le("Server");
    AvPair ts;
    ts.id = AvId::kTimestamp;
    ts.value = Bytes(8, 0);
    m.av_pairs = {domain, server, ts};
    Bytes out;
    m.Encode(out);
    return out;
}

rtsc::security::Config MakeConfig() {
    rtsc::security::Config cfg;
    cfg.tls_config.peer_host = "127.0.0.1";
    cfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    cfg.credssp_version = 6;
    cfg.credentials.domain = "Domain";
    cfg.credentials.user = "User";
    cfg.credentials.password = "Password";
    return cfg;
}

std::unique_ptr<rtsc::security::SecurityLayer> MakeLayer() {
    std::string why;
    auto layer = rtsc::security::SecurityLayer::Create(MakeConfig(), why);
    if (layer) layer->SetTlsTransportForTest(std::make_unique<ScriptedTls>());
    return layer;
}

std::vector<uint8_t> Hex(const char* s) {
    std::vector<uint8_t> out;
    int hi = -1;
    for (const char* p = s; *p != '\0'; ++p) {
        int v = -1;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else continue;
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

}  // namespace

RTSC_TEST(security_layer_create) {
    std::string why;
    auto layer = rtsc::security::SecurityLayer::Create(MakeConfig(), why);
    CHECK(layer != nullptr);
    // `why` is non-empty only when no platform TLS backend exists (e.g. Linux
    // before the OpenSSL backend lands); a scripted transport is injected for
    // the rest of the tests.
    CHECK(!layer->handshake_complete());
    CHECK(!layer->failed());
}

RTSC_TEST(security_layer_tls_handshake_emits_client_hello) {
    auto layer = MakeLayer();
    CHECK(layer != nullptr);
    const auto r = layer->Step(nullptr, 0);
    CHECK(r.want == rtsc::security::Want::kWrite);
    CHECK(!r.to_wire.empty());
    CHECK(r.to_wire[0] == 0x16);  // handshake record
    CHECK(!layer->handshake_complete());
}

RTSC_TEST(security_layer_tls_complete_emits_credssp_step1) {
    auto layer = MakeLayer();
    CHECK(layer != nullptr);
    layer->Step(nullptr, 0);  // client hello

    // Second handshake round completes TLS; Step must then emit CredSSP step 1
    // without any extra pump.
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    const auto r = layer->Step(server_hello, sizeof(server_hello));
    CHECK(r.want == rtsc::security::Want::kWrite);
    CHECK(!r.to_wire.empty());

    // The emitted bytes are a CredSSP step 1: a DER SEQUENCE whose NegoData
    // carries the NTLM NEGOTIATE (signature "NTLMSSP\0" + type 1).
    CHECK(r.to_wire[0] == 0x30);  // TSRequest SEQUENCE
    bool found_ntlm = false;
    for (size_t i = 0; i + 8 <= r.to_wire.size(); ++i) {
        if (r.to_wire[i] == 'N' && r.to_wire[i + 1] == 'T' &&
            r.to_wire[i + 2] == 'L' && r.to_wire[i + 3] == 'M' &&
            r.to_wire[i + 4] == 'S' && r.to_wire[i + 5] == 'S' &&
            r.to_wire[i + 6] == 'P' && r.to_wire[i + 7] == 0x00) {
            found_ntlm = true;
            break;
        }
    }
    CHECK(found_ntlm);
}

RTSC_TEST(security_layer_full_handshake_reaches_done) {
    auto layer = MakeLayer();
    CHECK(layer != nullptr);

    // TLS round 1.
    auto r = layer->Step(nullptr, 0);
    CHECK(r.want == rtsc::security::Want::kWrite);

    // TLS round 2 -> completes and emits CredSSP step 1.
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    r = layer->Step(server_hello, sizeof(server_hello));
    CHECK(r.want == rtsc::security::Want::kWrite);
    CHECK(!layer->handshake_complete());

    // Server CHALLENGE -> client emits step 3.
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    r = layer->Step(ch_der.data(), ch_der.size());
    CHECK(r.want == rtsc::security::Want::kWrite);
    CHECK(!layer->failed());

    // Server echo (built from the client's own state so it matches) -> the
    // client emits step 5 (authInfo); the EUAR is only sent by the server
    // after it receives that message, so the client must not wait for it yet.
    Bytes echo = layer->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    CHECK(step4.Encode(step4_der).ok());
    r = layer->Step(step4_der.data(), step4_der.size());
    CHECK(!layer->failed());
    CHECK(r.want == rtsc::security::Want::kWrite);
    CHECK(!r.to_wire.empty());
    CHECK(r.to_wire[0] == 0x30);  // CredSSP step 5 (authInfo)

    // EUAR AUTHZ_SUCCESS -> done.
    const uint8_t euar[] = {0x00, 0x00, 0x00, 0x00};
    r = layer->Step(euar, sizeof(euar));
    CHECK(r.want == rtsc::security::Want::kDone);
    CHECK(layer->handshake_complete());
    CHECK(!layer->failed());
}

RTSC_TEST(security_layer_hybrid_without_euar_completes_after_step5) {
    // PROTOCOL_HYBRID (0x2): no EUAR. The layer must complete as soon as the
    // final CredSSP message (step 5, authInfo) has been produced; waiting for a
    // 4-byte EUAR that will never arrive deadlocks the connection.
    rtsc::security::Config cfg = MakeConfig();
    cfg.expect_euar = false;
    std::string why;
    auto layer = rtsc::security::SecurityLayer::Create(cfg, why);
    CHECK(layer != nullptr);
    layer->SetTlsTransportForTest(std::make_unique<ScriptedTls>());

    auto r = layer->Step(nullptr, 0);
    CHECK(r.want == rtsc::security::Want::kWrite);
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    r = layer->Step(server_hello, sizeof(server_hello));
    CHECK(r.want == rtsc::security::Want::kWrite);

    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    r = layer->Step(ch_der.data(), ch_der.size());
    CHECK(r.want == rtsc::security::Want::kWrite);

    Bytes echo = layer->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    CHECK(step4.Encode(step4_der).ok());
    r = layer->Step(step4_der.data(), step4_der.size());
    CHECK(r.want == rtsc::security::Want::kWrite);
    CHECK(!r.to_wire.empty());
    CHECK(r.to_wire[0] == 0x30);  // CredSSP step 5 (authInfo)

    // No EUAR is coming: pumping with no input must report completion.
    r = layer->Step(nullptr, 0);
    CHECK(r.want == rtsc::security::Want::kDone);
    CHECK(layer->handshake_complete());
    CHECK(!layer->failed());
}

RTSC_TEST(security_layer_euar_denied_fails) {
    auto layer = MakeLayer();
    CHECK(layer != nullptr);
    layer->Step(nullptr, 0);
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    layer->Step(server_hello, sizeof(server_hello));

    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    layer->Step(ch_der.data(), ch_der.size());

    Bytes echo = layer->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    CHECK(step4.Encode(step4_der).ok());
    layer->Step(step4_der.data(), step4_der.size());

    // AUTHZ_ACCESS_DENIED must latch a failure.
    const uint8_t euar[] = {0x05, 0x00, 0x00, 0x00};
    const auto r = layer->Step(euar, sizeof(euar));
    CHECK(r.want == rtsc::security::Want::kFailed);
    CHECK(layer->failed());
    CHECK(!layer->handshake_complete());
}

RTSC_TEST(security_layer_receivepdu_peels_tpkt_frames) {
    auto layer = MakeLayer();
    CHECK(layer != nullptr);
    // Drive to done quickly.
    layer->Step(nullptr, 0);
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    layer->Step(server_hello, sizeof(server_hello));
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    layer->Step(ch_der.data(), ch_der.size());
    Bytes echo = layer->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    CHECK(step4.Encode(step4_der).ok());
    layer->Step(step4_der.data(), step4_der.size());
    const uint8_t euar[] = {0x00, 0x00, 0x00, 0x00};
    layer->Step(euar, sizeof(euar));
    CHECK(layer->handshake_complete());

    // Two concatenated TPKT frames, fed in one ciphertext chunk.
    const std::vector<uint8_t> pdu1 = {0x03, 0x00, 0x00, 0x08, 0xAA, 0xBB,
                                       0xCC, 0xDD};
    const std::vector<uint8_t> pdu2 = {0x03, 0x00, 0x00, 0x06, 0x11, 0x22};
    std::vector<uint8_t> wire = pdu1;
    wire.insert(wire.end(), pdu2.begin(), pdu2.end());

    const auto frames = layer->ReceivePdu(wire.data(), wire.size());
    CHECK(frames.size() == 2);
    CHECK(frames[0] == pdu1);
    CHECK(frames[1] == pdu2);
}

RTSC_TEST(security_layer_receivepdu_waits_for_full_frame) {
    auto layer = MakeLayer();
    CHECK(layer != nullptr);
    layer->Step(nullptr, 0);
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    layer->Step(server_hello, sizeof(server_hello));
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    layer->Step(ch_der.data(), ch_der.size());
    Bytes echo = layer->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    CHECK(step4.Encode(step4_der).ok());
    layer->Step(step4_der.data(), step4_der.size());
    const uint8_t euar[] = {0x00, 0x00, 0x00, 0x00};
    layer->Step(euar, sizeof(euar));

    // Half a TPKT frame: nothing may be returned until the frame is complete.
    const std::vector<uint8_t> partial = {0x03, 0x00, 0x00, 0x08, 0xAA};
    auto frames = layer->ReceivePdu(partial.data(), partial.size());
    CHECK(frames.empty());

    // The rest arrives; now the frame is emitted.
    const std::vector<uint8_t> rest = {0xBB, 0xCC, 0xDD};
    frames = layer->ReceivePdu(rest.data(), rest.size());
    CHECK(frames.size() == 1);
    CHECK(frames[0].size() == 8);
    CHECK(frames[0][4] == 0xAA);
}

RTSC_TEST(security_layer_credssp_drain_lifts_coalesced_record) {
    // DriveCredssp's drain (SecurityLayer::DriveCredssp) is the client
    // mirror of the server-side CredSSP drain. A peer that coalesces its final
    // handshake flight with the CHALLENGE leaves that message staged in the
    // backend; only this drain can lift it out. Disabling the loop left every
    // suite green (measured on Linux, whole ctest tree), so this case is its
    // only guard.
    std::string why;
    auto layer = rtsc::security::SecurityLayer::Create(MakeConfig(), why);
    CHECK(layer != nullptr);
    if (!layer) return;
    auto scripted = std::make_unique<ScriptedTls>();
    ScriptedTls* tls_raw = scripted.get();
    layer->SetTlsTransportForTest(std::move(scripted));

    auto r = layer->Step(nullptr, 0);
    CHECK(r.want == rtsc::security::Want::kWrite);
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    r = layer->Step(server_hello, sizeof(server_hello));
    CHECK(r.want == rtsc::security::Want::kWrite);  // CredSSP step 1

    // The CHALLENGE is staged behind the handshake; the caller passes nothing,
    // so the drain is the only way it can reach the state machine.
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    tls_raw->stage_for_test(ch_der);

    r = layer->Step(nullptr, 0);
    CHECK(r.want == rtsc::security::Want::kWrite);  // CredSSP step 3
    CHECK(!layer->failed());
}

RTSC_TEST(security_layer_euar_drain_lifts_coalesced_record) {
    // DriveEuar's drain (SecurityLayer::DriveEuar) supplies the tail
    // of the EUAR when the peer coalesced it with the last CredSSP message.
    // Only the first byte arrives as ciphertext here; the remaining three are
    // staged in the backend. With the loop disabled the layer stalls at kRead
    // instead of reaching kDone (measured), so this case is its guard.
    std::string why;
    auto layer = rtsc::security::SecurityLayer::Create(MakeConfig(), why);
    CHECK(layer != nullptr);
    if (!layer) return;
    auto scripted = std::make_unique<ScriptedTls>();
    ScriptedTls* tls_raw = scripted.get();
    layer->SetTlsTransportForTest(std::move(scripted));

    layer->Step(nullptr, 0);
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    layer->Step(server_hello, sizeof(server_hello));
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    layer->Step(ch_der.data(), ch_der.size());
    Bytes echo = layer->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    CHECK(step4.Encode(step4_der).ok());
    layer->Step(step4_der.data(), step4_der.size());

    const uint8_t first_euar_byte = 0x00;
    tls_raw->stage_for_test({0x00, 0x00, 0x00});
    const auto r = layer->Step(&first_euar_byte, 1);
    CHECK(r.want == rtsc::security::Want::kDone);
    CHECK(layer->handshake_complete());
}

RTSC_TEST(security_layer_receivepdu_drain_lifts_coalesced_record) {
    // ReceivePdu's drain (SecurityLayer::ReceivePdu) is the client
    // data-plane twin of the loop guarded in test_server_security.cpp. A real
    // server coalesces its last handshake flight with the first frame, leaving
    // it staged; with the loop disabled ReceivePdu returns no frames and every
    // suite stayed green (measured). This case is its only guard.
    std::string why;
    auto layer = rtsc::security::SecurityLayer::Create(MakeConfig(), why);
    CHECK(layer != nullptr);
    if (!layer) return;
    auto scripted = std::make_unique<ScriptedTls>();
    ScriptedTls* tls_raw = scripted.get();
    layer->SetTlsTransportForTest(std::move(scripted));

    layer->Step(nullptr, 0);
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    layer->Step(server_hello, sizeof(server_hello));
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    layer->Step(ch_der.data(), ch_der.size());
    Bytes echo = layer->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    CHECK(step4.Encode(step4_der).ok());
    layer->Step(step4_der.data(), step4_der.size());
    const uint8_t euar[] = {0x00, 0x00, 0x00, 0x00};
    layer->Step(euar, sizeof(euar));
    CHECK(layer->handshake_complete());

    const std::vector<uint8_t> pdu = {0x03, 0x00, 0x00, 0x08,
                                      0xAA, 0xBB, 0xCC, 0xDD};
    tls_raw->stage_for_test(pdu);

    const auto frames = layer->ReceivePdu(nullptr, 0);
    CHECK(frames.size() == 1);
    if (frames.size() != 1) return;
    CHECK(frames[0] == pdu);
}
// ---- ConnectionDriver -----------------------------------------------------

namespace {

rtsc::security::ConnectionDriver MakeDriver() {
    rtsc::proto::ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=tester";
    mcfg.requested_protocols = rtsc::proto::kProtocolSsl |
                               rtsc::proto::kProtocolHybrid |
                               rtsc::proto::kProtocolHybridEx;
    mcfg.client_name = "RTSC";
    mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
    mcfg.encryption_methods = 0;

    rtsc::proto::ConnectMachine::Credentials creds;
    creds.domain = "Domain";
    creds.user_name = "User";
    creds.password = "Password";

    rtsc::security::ConnectionDriver driver(mcfg, creds, MakeConfig());
    driver.SetTlsTransportForTest(std::make_unique<ScriptedTls>());
    return driver;
}

// Connection Confirm selecting PROTOCOL_HYBRID_EX (0x08), captured from
// 192.168.1.7 (evidence/handshake-001.md).
const char* kCcfHybridEx = "03 00 00 13 0e d0 00 00 12 34 00 02 0f 08 00 08 00 00 00";

// Connection Confirm selecting PROTOCOL_HYBRID (0x02): no EUAR follows.
const char* kCcfHybrid = "03 00 00 13 0e d0 00 00 12 34 00 02 0f 08 00 02 00 00 00";

}  // namespace

RTSC_TEST(connection_driver_start_emits_x224_crq) {
    auto driver = MakeDriver();
    const auto step = driver.Start();
    CHECK(!step.failed);
    CHECK(step.to_send.size() >= 4);
    CHECK(step.to_send[0] == 0x03);  // TPKT
    CHECK(step.to_send[1] == 0x00);
    CHECK(!driver.security_active());
}

RTSC_TEST(connection_driver_ccf_starts_tls) {
    auto driver = MakeDriver();
    driver.Start();
    const auto ccf = Hex(kCcfHybridEx);
    const auto step = driver.OnData(ccf.data(), ccf.size());
    CHECK(!step.failed);
    CHECK(driver.security_active());
    // The security layer's first output is the TLS ClientHello record.
    CHECK(!step.to_send.empty());
    CHECK(step.to_send[0] == 0x16);
}

RTSC_TEST(connection_driver_full_handshake_to_mcs_connect_initial) {
    auto driver = MakeDriver();
    driver.Start();

    const auto ccf = Hex(kCcfHybridEx);
    auto step = driver.OnData(ccf.data(), ccf.size());
    CHECK(step.to_send[0] == 0x16);  // ClientHello

    // TLS server hello completes the handshake; the layer then emits CredSSP
    // step 1.
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    step = driver.OnData(server_hello, sizeof(server_hello));
    CHECK(!step.failed);
    CHECK(!step.to_send.empty());
    CHECK(step.to_send[0] == 0x30);  // TSRequest SEQUENCE (CredSSP step 1)

    // Server CHALLENGE -> step 3.
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    step = driver.OnData(ch_der.data(), ch_der.size());
    CHECK(!step.failed);
    CHECK(step.to_send[0] == 0x30);

    // Server echo (matches the client's binding hash) -> the client emits
    // step 5 (authInfo); the EUAR follows on the wire after the server has
    // received it.
    Bytes echo = driver.security()->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    CHECK(step4.Encode(step4_der).ok());
    step = driver.OnData(step4_der.data(), step4_der.size());
    CHECK(!step.failed);
    CHECK(!step.to_send.empty());
    CHECK(step.to_send[0] == 0x30);  // CredSSP step 5 (authInfo)

    // EUAR AUTHZ_SUCCESS -> the driver emits the MCS Connect Initial through
    // the security layer.
    const uint8_t euar[] = {0x00, 0x00, 0x00, 0x00};
    step = driver.OnData(euar, sizeof(euar));
    CHECK(!step.failed);
    CHECK(!step.to_send.empty());
    CHECK(driver.machine().state().phase ==
          rtsc::proto::ConnectPhase::kAwaitConnectResponse);
}

RTSC_TEST(connection_driver_hybrid_without_ex_skips_euar) {
    // A server that selects PROTOCOL_HYBRID (0x2) does not send an EUAR
    // ([MS-RDPBCGR] 2.2.10.2). The driver must therefore emit the MCS Connect
    // Initial as soon as CredSSP step 5 is on the wire instead of waiting for a
    // 4-byte result that will never arrive.
    auto driver = MakeDriver();
    driver.Start();
    const auto ccf = Hex(kCcfHybrid);
    driver.OnData(ccf.data(), ccf.size());

    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    driver.OnData(server_hello, sizeof(server_hello));

    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    driver.OnData(ch_der.data(), ch_der.size());

    Bytes echo = driver.security()->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    CHECK(step4.Encode(step4_der).ok());
    const auto step = driver.OnData(step4_der.data(), step4_der.size());
    CHECK(!step.failed);
    CHECK(driver.machine().state().negotiated_protocol ==
          rtsc::proto::kProtocolHybrid);
    CHECK(driver.machine().state().phase ==
          rtsc::proto::ConnectPhase::kAwaitConnectResponse);
    // The emitted bytes carry both the CredSSP step 5 SEQUENCE and the MCS
    // Connect Initial TPKT.
    bool has_tpkt = false;
    for (size_t i = 0; i + 1 < step.to_send.size(); ++i) {
        if (step.to_send[i] == 0x03 && step.to_send[i + 1] == 0x00) {
            has_tpkt = true;
            break;
        }
    }
    CHECK(has_tpkt);
}

RTSC_TEST(connection_driver_euar_denied_fails) {
    auto driver = MakeDriver();
    driver.Start();
    const auto ccf = Hex(kCcfHybridEx);
    driver.OnData(ccf.data(), ccf.size());
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    driver.OnData(server_hello, sizeof(server_hello));

    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    driver.OnData(ch_der.data(), ch_der.size());

    Bytes echo = driver.security()->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    CHECK(step4.Encode(step4_der).ok());
    driver.OnData(step4_der.data(), step4_der.size());

    const uint8_t euar[] = {0x05, 0x00, 0x00, 0x00};  // AUTHZ_ACCESS_DENIED
    const auto step = driver.OnData(euar, sizeof(euar));
    CHECK(step.failed);
    CHECK(!step.error.empty());
}

// ---- ConnectionDriver: full flow through licensing and session setup -------

namespace {

// [MS-RDPBCGR] 4.1.4: the 337-byte Connect Response.
const char* kConnectResponseHex =
    "03 00 01 51 02 f0 80 7f 66 82 01 45 0a 01 00 02 "
    "01 00 30 1a 02 01 22 02 01 03 02 01 00 02 01 01 "
    "02 01 00 02 01 01 02 03 00 ff f8 02 01 02 04 82 "
    "01 1f 00 05 00 14 7c 00 01 2a 14 76 0a 01 01 00 "
    "01 c0 00 4d 63 44 6e 81 08 01 0c 0c 00 04 00 08 "
    "00 00 00 00 00 03 0c 10 00 eb 03 03 00 ec 03 ed "
    "03 ee 03 00 00 02 0c ec 00 02 00 00 00 02 00 00 "
    "00 20 00 00 00 b8 00 00 00 10 11 77 20 30 61 0a "
    "12 e4 34 a1 1e f2 c3 9f 31 7d a4 5f 01 89 34 96 "
    "e0 ff 11 08 69 7f 1a c3 d2 01 00 00 00 01 00 00 "
    "00 01 00 00 00 06 00 5c 00 52 53 41 31 48 00 00 "
    "00 00 02 00 00 3f 00 00 00 01 00 01 00 cb 81 fe "
    "ba 6d 61 c3 55 05 d5 5f 2e 87 f8 71 94 d6 f1 a5 "
    "cb f1 5f 0c 3d f8 70 02 96 c4 fb 9b c8 3c 2d 55 "
    "ae e8 ff 32 75 ea 68 79 e5 a2 01 fd 31 a0 b1 1f "
    "55 a6 1f c1 f6 d1 83 88 63 26 56 12 bc 00 00 00 "
    "00 00 00 00 00 08 00 48 00 e9 e1 d6 28 46 8b 4e "
    "f5 0a df fd ee 21 99 ac b4 e1 8f 5f 81 57 82 ef "
    "9d 96 52 63 27 18 29 db b3 4a fd 9a da 42 ad b5 "
    "69 21 89 0e 1d c0 4c 1a a8 aa 71 3e 0f 54 b9 9a "
    "e4 99 68 3f 6c d6 76 84 61 00 00 00 00 00 00 00 "
    "00";

const char* kAttachUserConfirm = "03 00 00 0b 02 f0 80 2e 00 00 06";
const char* kJoinConfirmUser = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ef 03 ef";
const char* kJoinConfirmIo = "03 00 00 0f 02 f0 80 3e 00 00 06 03 eb 03 eb";
const char* kJoinConfirmVc1 = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ec 03 ec";
const char* kJoinConfirmVc2 = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ed 03 ed";
const char* kJoinConfirmVc3 = "03 00 00 0f 02 f0 80 3e 00 00 06 03 ee 03 ee";

// [MS-RDPBCGR] 4.1.12 Demand Active PDU (decrypted plaintext, 359 bytes).
const char* kDemandActiveHex =
    "67 01 11 00 ea 03 ea 03 01 00 04 00 51 01 52 44 "
    "50 00 0d 00 00 00 09 00 08 00 ea 03 dc e2 01 00 "
    "18 00 01 00 03 00 00 02 00 00 00 00 1d 04 00 00 "
    "00 00 00 00 01 01 14 00 08 00 02 00 00 00 16 00 "
    "28 00 00 00 00 00 70 f6 13 f3 01 00 00 00 01 00 "
    "00 00 18 00 00 00 9c f6 13 f3 61 a6 82 80 00 00 "
    "00 00 00 50 91 bf 0e 00 04 00 02 00 1c 00 18 00 "
    "01 00 01 00 01 00 00 05 00 04 00 00 01 00 01 00 "
    "00 00 01 00 00 00 03 00 58 00 00 00 00 00 00 00 "
    "00 00 00 00 00 00 00 00 00 00 40 42 0f 00 01 00 "
    "14 00 00 00 01 00 00 00 22 00 01 01 01 01 01 00 "
    "00 01 01 01 01 01 00 00 00 01 01 01 01 01 01 01 "
    "01 00 01 01 01 01 00 00 00 00 a1 06 00 00 40 42 "
    "0f 00 40 42 0f 00 01 00 00 00 00 00 00 00 0a 00 "
    "08 00 06 00 00 00 12 00 08 00 01 00 00 00 08 00 "
    "0a 00 01 00 19 00 19 00 0d 00 58 00 35 00 00 00 "
    "a1 06 00 00 40 42 0f 00 0c f6 13 f3 93 5a 37 f3 "
    "00 90 30 e1 34 1c 38 f3 40 f6 13 f3 04 00 00 00 "
    "4c 54 dc e2 08 50 dc e2 01 00 00 00 08 50 dc e2 "
    "00 00 00 00 38 f6 13 f3 2e 05 38 f3 08 50 dc e2 "
    "2c f6 13 f3 00 00 00 00 08 00 0a 00 01 00 19 00 "
    "17 00 08 00 00 00 00 00 18 00 0b 00 00 00 00 00 "
    "00 00 00 00 00 00 00";

// Server -> client MCS Send Data Indication wrapping `payload`.
std::vector<uint8_t> ServerIndication(const std::vector<uint8_t>& payload) {
    return rtsc::proto::McsSendData::build_indication(0x03EA, 0x03EF, payload);
}

// A server slow-path data PDU (share data header + payload).
std::vector<uint8_t> ServerDataPdu(rtsc::proto::ShareDataPduType type,
                                   const std::vector<uint8_t>& payload) {
    rtsc::proto::ByteWriter w;
    w.u16le(static_cast<uint16_t>(18 + payload.size()));
    w.u16le(0x0017);
    w.u16le(0x03EA);
    w.u32le(0x000103EA);
    w.u8(0);
    w.u8(0x01);
    w.u16le(static_cast<uint16_t>(payload.size()));
    w.u8(static_cast<uint8_t>(type));
    w.u8(0);
    w.u16le(0);
    if (!payload.empty()) w.bytes(payload.data(), payload.size());
    return ServerIndication(w.take());
}

// A licensing PDU (SEC_LICENSE_PKT header + licensing payload).
std::vector<uint8_t> ServerLicensePdu(const std::vector<uint8_t>& payload) {
    rtsc::proto::ByteWriter sh;
    sh.u16le(static_cast<uint16_t>(rtsc::proto::kSecLicensePkt));
    sh.u16le(0);
    std::vector<uint8_t> ud = sh.take();
    ud.insert(ud.end(), payload.begin(), payload.end());
    return ServerIndication(ud);
}

}  // namespace

RTSC_TEST(connection_driver_full_flow_to_active_session) {
    auto driver = MakeDriver();
    driver.Start();

    // X.224 negotiation.
    const auto ccf = Hex(kCcfHybridEx);
    auto step = driver.OnData(ccf.data(), ccf.size());
    CHECK(step.to_send[0] == 0x16);  // TLS ClientHello

    // TLS + CredSSP + EUAR.
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    step = driver.OnData(server_hello, sizeof(server_hello));
    CHECK(step.to_send[0] == 0x30);  // CredSSP step 1

    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    CHECK(challenge.Encode(ch_der).ok());
    step = driver.OnData(ch_der.data(), ch_der.size());
    CHECK(step.to_send[0] == 0x30);  // CredSSP step 3

    Bytes echo = driver.security()->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    CHECK(step4.Encode(step4_der).ok());
    step = driver.OnData(step4_der.data(), step4_der.size());
    CHECK(!step.to_send.empty());  // CredSSP step 5 (authInfo)

    const uint8_t euar[] = {0x00, 0x00, 0x00, 0x00};
    step = driver.OnData(euar, sizeof(euar));
    CHECK(!step.to_send.empty());  // MCS Connect Initial
    CHECK(driver.machine().state().phase ==
          rtsc::proto::ConnectPhase::kAwaitConnectResponse);

    // MCS: Connect Response -> Attach User -> Channel Joins -> Client Info.
    auto cr = Hex(kConnectResponseHex);
    driver.OnData(cr.data(), cr.size());
    CHECK(driver.machine().state().phase ==
          rtsc::proto::ConnectPhase::kAwaitAttachUser);

    auto auc = Hex(kAttachUserConfirm);
    driver.OnData(auc.data(), auc.size());
    CHECK(driver.machine().state().phase ==
          rtsc::proto::ConnectPhase::kAwaitChannelJoin);

    const char* confirms[] = {kJoinConfirmUser, kJoinConfirmIo, kJoinConfirmVc1,
                              kJoinConfirmVc2, kJoinConfirmVc3};
    for (int i = 0; i < 5; ++i) {
        auto jc = Hex(confirms[i]);
        step = driver.OnData(jc.data(), jc.size());
    }
    CHECK(step.done);  // Client Info sent
    CHECK(driver.machine().done());

    // Licensing: LICENSE_ERROR_MESSAGE with STATUS_VALID_CLIENT.
    rtsc::proto::LicenseErrorMessage err;
    err.error_code = 0x07;  // STATUS_VALID_CLIENT
    err.state_transition = 0x02;  // ST_NO_TRANSITION
    const auto lp = rtsc::proto::LicensingPdu::Encode(
        rtsc::proto::LicenseMessageType::kErrorAlert, err.encode());
    auto lwire = ServerLicensePdu(lp);
    step = driver.OnData(lwire.data(), lwire.size());
    CHECK(!step.failed);

    // Demand Active -> Confirm Active + finalization batch.
    auto da = Hex(kDemandActiveHex);
    auto dawire = ServerIndication(da);
    step = driver.OnData(dawire.data(), dawire.size());
    CHECK(!step.failed);
    CHECK(step.to_send.size() >= 1);

    // Server Synchronize / Control / Font Map -> active.
    const std::vector<uint8_t> sync = {0x01, 0x00, 0xEA, 0x03};
    auto wire = ServerDataPdu(rtsc::proto::ShareDataPduType::kSynchronize, sync);
    driver.OnData(wire.data(), wire.size());

    const std::vector<uint8_t> control = {0x04, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00};
    wire = ServerDataPdu(rtsc::proto::ShareDataPduType::kControl, control);
    driver.OnData(wire.data(), wire.size());

    const std::vector<uint8_t> fontmap = {0x00, 0x00, 0x00, 0x00, 0x03,
                                          0x00, 0x04, 0x00};
    wire = ServerDataPdu(rtsc::proto::ShareDataPduType::kFontMap, fontmap);
    step = driver.OnData(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(step.active);
}

// ---- ConnectionDriver: post-active static virtual channel routing ----------

namespace {

// Drives the driver through X.224 -> TLS -> CredSSP -> EUAR -> MCS -> licensing
// -> capability exchange -> finalization, ending in the active session. Returns
// false if any step fails. Extracted from the full-flow test above so the
// post-active routing tests share one harness.
bool DriveToActive(rtsc::security::ConnectionDriver& driver) {
    driver.Start();
    const auto ccf = Hex(kCcfHybridEx);
    auto step = driver.OnData(ccf.data(), ccf.size());
    if (step.failed) return false;

    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    step = driver.OnData(server_hello, sizeof(server_hello));
    if (step.failed) return false;

    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    if (!challenge.Encode(ch_der).ok()) return false;
    step = driver.OnData(ch_der.data(), ch_der.size());
    if (step.failed) return false;

    Bytes echo = driver.security()->credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    if (!step4.Encode(step4_der).ok()) return false;
    step = driver.OnData(step4_der.data(), step4_der.size());
    if (step.failed) return false;

    const uint8_t euar[] = {0x00, 0x00, 0x00, 0x00};
    step = driver.OnData(euar, sizeof(euar));
    if (step.failed) return false;

    auto cr = Hex(kConnectResponseHex);
    step = driver.OnData(cr.data(), cr.size());
    if (step.failed) return false;

    auto auc = Hex(kAttachUserConfirm);
    step = driver.OnData(auc.data(), auc.size());
    if (step.failed) return false;

    const char* confirms[] = {kJoinConfirmUser, kJoinConfirmIo, kJoinConfirmVc1,
                              kJoinConfirmVc2, kJoinConfirmVc3};
    for (int i = 0; i < 5; ++i) {
        auto jc = Hex(confirms[i]);
        step = driver.OnData(jc.data(), jc.size());
        if (step.failed) return false;
    }

    rtsc::proto::LicenseErrorMessage err;
    err.error_code = 0x07;  // STATUS_VALID_CLIENT
    err.state_transition = 0x02;  // ST_NO_TRANSITION
    const auto lp = rtsc::proto::LicensingPdu::Encode(
        rtsc::proto::LicenseMessageType::kErrorAlert, err.encode());
    auto lwire = ServerLicensePdu(lp);
    step = driver.OnData(lwire.data(), lwire.size());
    if (step.failed) return false;

    auto da = Hex(kDemandActiveHex);
    auto dawire = ServerIndication(da);
    step = driver.OnData(dawire.data(), dawire.size());
    if (step.failed) return false;

    const std::vector<uint8_t> sync = {0x01, 0x00, 0xEA, 0x03};
    auto wire = ServerDataPdu(rtsc::proto::ShareDataPduType::kSynchronize, sync);
    driver.OnData(wire.data(), wire.size());
    const std::vector<uint8_t> control = {0x04, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00};
    wire = ServerDataPdu(rtsc::proto::ShareDataPduType::kControl, control);
    driver.OnData(wire.data(), wire.size());
    const std::vector<uint8_t> fontmap = {0x00, 0x00, 0x00, 0x00, 0x03,
                                          0x00, 0x04, 0x00};
    wire = ServerDataPdu(rtsc::proto::ShareDataPduType::kFontMap, fontmap);
    step = driver.OnData(wire.data(), wire.size());
    return !step.failed && step.active;
}

}  // namespace

RTSC_TEST(connection_driver_routes_static_virtual_channel) {
    auto driver = MakeDriver();
    CHECK(DriveToActive(driver));
    CHECK(driver.session_active());

    int vc_calls = 0;
    size_t vc_size = 0;
    std::vector<uint8_t> vc_bytes;
    driver.SetChannelHandler(1004, [&](const uint8_t* data, size_t size) {
        ++vc_calls;
        vc_size = size;
        vc_bytes.assign(data, data + size);
    });

    int graphics_calls = 0;
    driver.SetSessionPduHandler(
        [&](const std::vector<uint8_t>&) { ++graphics_calls; });

    // A static virtual channel PDU on 1004 (rdpdr Server Announce Request),
    // captured from the real peer. The channel payload starts with the
    // channelPduHeader: length(4 LE) + flags(4 LE).
    const std::vector<uint8_t> vc_payload = {
        0x0C, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x72, 0x44, 0x6E, 0x49, 0x01, 0x00, 0x0D, 0x00,
        0x03, 0x00, 0x00, 0x00};
    const auto vc =
        rtsc::proto::McsSendData::build_indication(0x03EA, 1004, vc_payload);
    auto step = driver.OnData(vc.data(), vc.size());
    CHECK(!step.failed);
    CHECK_EQ(vc_calls, 1);
    CHECK_EQ(graphics_calls, 0);

    // The handler must receive sd.user_data, not the full MCS Send Data PDU:
    // its length equals the channel payload, and its first 8 bytes are the
    // channelPduHeader (length(4 LE) + flags(4 LE)) rather than the MCS header.
    CHECK_EQ(vc_size, vc_payload.size());
    CHECK_EQ(vc_bytes.size(), vc_payload.size());
    CHECK_BYTES(std::vector<uint8_t>(vc_bytes.begin(), vc_bytes.begin() + 8),
                0x0C, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00);
    const uint32_t cp_length = static_cast<uint32_t>(vc_bytes[0]) |
                               (static_cast<uint32_t>(vc_bytes[1]) << 8) |
                               (static_cast<uint32_t>(vc_bytes[2]) << 16) |
                               (static_cast<uint32_t>(vc_bytes[3]) << 24);
    const uint32_t cp_flags = static_cast<uint32_t>(vc_bytes[4]) |
                              (static_cast<uint32_t>(vc_bytes[5]) << 8) |
                              (static_cast<uint32_t>(vc_bytes[6]) << 16) |
                              (static_cast<uint32_t>(vc_bytes[7]) << 24);
    CHECK_EQ(cp_length, 0x0000000Cu);
    CHECK_EQ(cp_flags, 0x00000003u);
    // MCS Send Data Indication starts with DomainMCspduOctet(26) == 0x68; the
    // channel data must not begin with that octet.
    CHECK(vc_bytes[0] != 0x68);
}

RTSC_TEST(connection_driver_routes_io_channel_to_graphics) {
    auto driver = MakeDriver();
    CHECK(DriveToActive(driver));
    CHECK(driver.session_active());

    int graphics_calls = 0;
    driver.SetSessionPduHandler(
        [&](const std::vector<uint8_t>&) { ++graphics_calls; });
    // A handler on 1004 must not steal the I/O channel.
    int vc_calls = 0;
    driver.SetChannelHandler(1004, [&](const uint8_t*, size_t) { ++vc_calls; });

    // The I/O channel id comes from Server Network Data (1003 in this capture).
    const std::vector<uint8_t> payload = {0x01, 0x02, 0x03};
    const auto io =
        rtsc::proto::McsSendData::build_indication(0x03EA, 1003, payload);
    auto step = driver.OnData(io.data(), io.size());
    CHECK(!step.failed);
    CHECK_EQ(graphics_calls, 1);
    CHECK_EQ(vc_calls, 0);
}

RTSC_TEST(connection_driver_records_save_session_info_after_active) {
    auto driver = MakeDriver();
    CHECK(DriveToActive(driver));
    CHECK(driver.session_active());

    int graphics_calls = 0;
    driver.SetSessionPduHandler(
        [&](const std::vector<uint8_t>&) { ++graphics_calls; });

    // TS_SAVE_SESSION_INFO_PDU_DATA / INFOTYPE_LOGON_LONG
    // ([MS-RDPBCGR] 2.2.10.1.1.2): session id 7, domain NTDEV, user alice.
    rtsc::proto::ByteWriter w;
    w.u32le(1);   // infoType = INFOTYPE_LOGON_LONG
    w.u16le(1);   // Version
    w.u32le(576); // Size

    w.u32le(7);   // SessionId
    w.u32le(12);  // cbDomain (including the null terminator)
    w.u32le(12);  // cbUserName
    for (int i = 0; i < 558; ++i) w.u8(0);  // Pad
    for (const char* p = "NTDEV"; *p != '\0'; ++p) {
        w.u16le(static_cast<uint16_t>(*p));
    }
    w.u16le(0);
    for (const char* p = "alice"; *p != '\0'; ++p) {
        w.u16le(static_cast<uint16_t>(*p));
    }
    w.u16le(0);
    const auto body = w.take();

    // Save Session Info arrives on the I/O channel (1003 in this capture), not
    // on the static virtual-channel id ServerIndication() uses.
    rtsc::proto::ByteWriter sw;
    sw.u16le(static_cast<uint16_t>(18 + body.size()));
    sw.u16le(0x0017);
    sw.u16le(0x03EA);
    sw.u32le(0x000103EA);
    sw.u8(0);
    sw.u8(0x01);
    sw.u16le(static_cast<uint16_t>(body.size()));
    sw.u8(static_cast<uint8_t>(rtsc::proto::ShareDataPduType::kSaveSessionInfo));
    sw.u8(0);
    sw.u16le(0);
    sw.bytes(body.data(), body.size());
    const auto wire =
        rtsc::proto::McsSendData::build_indication(0x03EA, 1003, sw.take());
    const auto step = driver.OnData(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(driver.logon_info().has_logon);
    CHECK_EQ(driver.logon_info().session_id, static_cast<uint32_t>(7));
    CHECK(driver.logon_info().domain == "NTDEV");
    CHECK(driver.logon_info().user_name == "alice");
    // A logon notification is not graphics data.
    CHECK_EQ(graphics_calls, 0);
}

RTSC_TEST(connection_driver_reconnects_after_reset) {
    auto driver = MakeDriver();
    CHECK(DriveToActive(driver));
    CHECK(driver.session_active());

    // A reconnect carries the 28-byte ARC_CS_PRIVATE_PACKET from the previous
    // session (here an arbitrary value; the server does not validate it yet).
    driver.ResetForReconnect(std::vector<uint8_t>(28, 0x5A));
    CHECK(!driver.session_active());
    CHECK(driver.phase_name() == "connect");
    // The cookie must reach the machine that builds the Client Info PDU.
    CHECK(driver.machine().config().auto_reconnect_cookie ==
          std::vector<uint8_t>(28, 0x5A));

    // A second full handshake on the same driver must reach active again.
    driver.SetTlsTransportForTest(std::make_unique<ScriptedTls>());
    CHECK(DriveToActive(driver));
    CHECK(driver.session_active());
}

RTSC_TEST(connection_driver_routes_deactivate_all_to_session_setup) {
    auto driver = MakeDriver();
    CHECK(DriveToActive(driver));
    CHECK(driver.session_active());

    int graphics_calls = 0;
    driver.SetSessionPduHandler(
        [&](const std::vector<uint8_t>&) { ++graphics_calls; });

    // Deactivate All on the I/O channel (1003): share control type 6, 9 bytes.
    rtsc::proto::ByteWriter w;
    w.u16le(9);
    w.u16le(0x0016);
    w.u16le(0x03EA);
    w.u8(0x00);
    const auto pdu = rtsc::proto::McsSendData::build_indication(
        0x03EA, 1003, w.take());
    auto step = driver.OnData(pdu.data(), pdu.size());
    CHECK(!step.failed);
    // The session machine must see it (active becomes false); the graphics
    // handler must not.
    CHECK(!driver.session_active());
    CHECK_EQ(graphics_calls, 0);
}

RTSC_TEST(client_pump_reports_peer_close_after_deactivate_all) {
    // A Deactivate All can also mean "the connection will be dropped". After
    // the session leaves active, the transport closing must surface as a
    // disconnect, not be mistaken for a silent timeout.
    class ClosedTransport final : public rtsc::net::Transport {
     public:
        int Read(uint8_t*, size_t) override { return 0; }
        bool Write(const uint8_t*, size_t) override { return false; }
        void Close() override {}
    } transport;

    auto driver = MakeDriver();
    rtsc::client::Client client(std::move(driver), 16, 16);
    CHECK(DriveToActive(client.driver()));
    CHECK(client.active());

    rtsc::proto::ByteWriter w;
    w.u16le(9);
    w.u16le(0x0016);
    w.u16le(0x03EA);
    w.u8(0x00);
    const auto pdu = rtsc::proto::McsSendData::build_indication(
        0x03EA, 1003, w.take());
    const auto step = client.driver().OnData(pdu.data(), pdu.size());
    CHECK(!step.failed);
    CHECK(!client.active());

    std::string error;
    CHECK(!client.Pump(transport, error));
    CHECK(error == "peer closed or read error");
}

RTSC_TEST(connection_driver_ignores_unregistered_channel) {
    auto driver = MakeDriver();
    CHECK(DriveToActive(driver));
    CHECK(driver.session_active());

    int graphics_calls = 0;
    driver.SetSessionPduHandler(
        [&](const std::vector<uint8_t>&) { ++graphics_calls; });
    int vc_calls = 0;
    driver.SetChannelHandler(1004, [&](const uint8_t*, size_t) { ++vc_calls; });

    // 1007 is the user channel in this capture and has no registered handler.
    const std::vector<uint8_t> payload = {0x0A, 0x0B};
    const auto pdu =
        rtsc::proto::McsSendData::build_indication(0x03EA, 1007, payload);
    auto step = driver.OnData(pdu.data(), pdu.size());
    CHECK(!step.failed);
    CHECK_EQ(graphics_calls, 0);
    CHECK_EQ(vc_calls, 0);
    CHECK_EQ(driver.unrouted_channel_count(), static_cast<size_t>(1));
}

RTSC_TEST(client_register_channel_forwards_to_driver) {
    auto driver = MakeDriver();
    rtsc::client::Client client(std::move(driver), 16, 16);
    CHECK(DriveToActive(client.driver()));
    CHECK(client.active());

    int vc_calls = 0;
    client.RegisterChannel(1004, [&](const uint8_t*, size_t) { ++vc_calls; });

    const std::vector<uint8_t> vc_payload = {0x0C, 0x00};
    const auto vc =
        rtsc::proto::McsSendData::build_indication(0x03EA, 1004, vc_payload);
    auto step = client.driver().OnData(vc.data(), vc.size());
    CHECK(!step.failed);
    CHECK_EQ(vc_calls, 1);
}

// ---- ConnectionDriver: post-active application send path -------------------

RTSC_TEST(connection_driver_sends_application_and_channel_pdus_over_tls) {
    auto driver = MakeDriver();
    CHECK(DriveToActive(driver));
    CHECK(driver.session_active());
    CHECK(driver.security_active());

    // The input Fast-Path PDU is application data on the TLS stream: it is
    // passed to the security layer unchanged (no MCS wrapper).
    const std::vector<uint8_t> input = {0x40, 0x00, 0x01, 0x1E};
    const auto input_wire = driver.SendApplicationPdu(input);
    CHECK(!input_wire.empty());
    CHECK(input_wire == input);

    // A static virtual channel message is framed in an MCS Send Data Request
    // on that channel id, then carried by the same TLS stream. The scripted
    // TLS transport is the identity, so the MCS frame is directly parseable.
    const std::vector<uint8_t> channel_message = {
        0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xAA, 0xBB, 0xCC, 0xDD};
    const auto channel_wire = driver.SendChannelPdu(1005, channel_message);
    CHECK(!channel_wire.empty());
    rtsc::proto::McsSendData sd;
    CHECK(rtsc::proto::McsSendData::parse(channel_wire.data(),
                                          channel_wire.size(), sd) ==
          rtsc::proto::Status::Ok);
    CHECK_EQ(sd.channel_id, static_cast<uint16_t>(1005));
    CHECK(sd.user_data == channel_message);
}

// TLS 1.3 observability (plan.md:56). The negotiated version is decided by the
// backend during Handshake, but before this test there was no way for a caller
// (rtsc_connect, the GUI log) to observe it, so the TLS 1.3 ticket branch could
// never be proven from a real-server run. The accessor must report exactly what
// the backend negotiated, and must be safe to call before the handshake (0).
RTSC_TEST(security_layer_exposes_negotiated_tls_version) {
    auto layer = MakeLayer();
    CHECK(layer != nullptr);
    // Before the TLS handshake the version is unknown.
    rtsc::tls::NegotiatedInfo before;
    CHECK(!layer->negotiated_tls(before));
    CHECK_EQ(before.tls_version, static_cast<uint16_t>(0));

    layer->Step(nullptr, 0);  // client hello
    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    layer->Step(server_hello, sizeof(server_hello));  // TLS done, CredSSP step 1

    rtsc::tls::NegotiatedInfo after;
    CHECK(layer->negotiated_tls(after));
    // The scripted transport reports 0x0304 (TLS 1.3); the accessor must pass
    // the backend value through unchanged, never a compiled-in constant.
    CHECK_EQ(after.tls_version, static_cast<uint16_t>(0x0304));
}
int main() { return ::rtsc::test::run_all("rtsc_security_tests"); }
