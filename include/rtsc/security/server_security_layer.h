// Server-side security layer: drives TLS accept + CredSSP server + EUAR as a
// single reentrant state machine.
//
// Reference: docs/spec/security-integration.audit-a.md section 4.1 (方案 B),
// [MS-RDPBCGR] 5.3.2 (TLS), 5.4 (CredSSP / NLA), [MS-CSSP] 3.1.5.
//
// This is the mirror of SecurityLayer (the client half). The layer owns the
// TLS transport and the CredSSP server; it does NOT own the socket. The caller
// feeds ciphertext in and takes ciphertext out, exactly like TlsTransport and
// CredsspServer individually.
//
// Framing rules change per phase, which is why the phase and the buffer live in
// one object:
//   * TLS handshake  -> record layer, handled inside TlsTransport::Handshake
//   * CredSSP        -> DER self-delimited SEQUENCE (TSRequest)
//   * EUAR           -> exactly 4 bytes, emitted by the server
//   * MCS data plane -> TPKT length field (after handshake)
//
// The server is reactive: it waits for the client's ClientHello before it can
// do anything, so DriveTls() returns kRead while no ciphertext is buffered.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "rtsc/credssp/credssp_server.h"
#include "rtsc/net/tls.h"
// Want / StepResult are shared with the client security layer (the two halves
// speak the same reentrant state machine); including the header is what keeps
// a single definition in the rtsc::security namespace.
#include "rtsc/security/security_layer.h"

namespace rtsc::security {

// Configuration for the server security layer.
struct ServerConfig {
    // TLS configuration. The caller MUST set role = tls::Role::kServer; the
    // layer rejects a client-role transport so a mis-wired caller cannot
    // silently skip the accept.
    tls::Config tls_config;

    // CredSSP version (5 or 6 recommended).
    uint32_t credssp_version = 6;

    // When true (default) the layer runs the full CredSSP exchange and emits
    // the EUAR. When false the layer completes right after TLS (PROTOCOL_SSL:
    // transport security only, no network-level authentication).
    bool credssp_required = true;

    // Whether to emit the 4-byte Early User Authorization Result PDU after
    // CredSSP. [MS-RDPBCGR] 2.2.10.2: the EUAR MUST only be sent when the
    // client advertised PROTOCOL_HYBRID_EX and the server selected it. A
    // HYBRID-only session (0x2) resumes directly with the MCS Connect Initial.
    bool euar_required = true;

    // Account lookup used to derive the NTLM session key. Null means every
    // CredSSP connection is rejected (the TLS leg still completes).
    credssp::CredentialLookup credential_lookup;

    // Server's SubjectPublicKey (BIT STRING content) for pubKeyAuth. When
    // empty the layer takes it from the TLS transport after the handshake.
    std::vector<uint8_t> server_public_key;
};

class ServerSecurityLayer {
 public:
    static std::unique_ptr<ServerSecurityLayer> Create(const ServerConfig& config,
                                                       std::string& why);

    ~ServerSecurityLayer();

    // ---- handshake driver ---------------------------------------------------
    // Feed ciphertext received from the peer. Returns what the caller should do.
    // `in` may be nullptr with size 0 to pump the state machine.
    StepResult Step(const uint8_t* in, size_t in_size);

    // ---- post-handshake data plane ------------------------------------------
    // Encrypt an MCS PDU (with TPKT header) for sending. Returns ciphertext.
    std::vector<uint8_t> SendPdu(const std::vector<uint8_t>& pdu);

    // Decrypt ciphertext and return complete MCS PDUs. May return multiple.
    // Returns empty if more ciphertext is needed.
    std::vector<std::vector<uint8_t>> ReceivePdu(const uint8_t* in, size_t in_size);

    // ---- state --------------------------------------------------------------
    bool handshake_complete() const noexcept { return phase_ == Phase::kDone; }
    bool failed() const noexcept { return phase_ == Phase::kFailed; }
    const std::string& error() const noexcept { return error_; }

    // ---- test hooks ---------------------------------------------------------
    // Replace the platform TLS transport with a scripted one. Must be called
    // before the first Step(); Create() installs the platform transport.
    void SetTlsTransportForTest(std::unique_ptr<tls::TlsTransport> tls) {
        tls_ = std::move(tls);
    }
    credssp::CredsspServer& credssp_for_test() { return *credssp_; }

 private:
    ServerSecurityLayer();

    enum class Phase : uint8_t {
        kTlsHandshake,  // TLS accept in progress
        kCredsspAwait,  // exchanging TSRequests with the client
        kDone,          // handshake complete
        kFailed,
    };

    StepResult DriveTls();
    StepResult DriveCredssp();
    StepResult EncryptAndWrite(const credssp::Bytes& plaintext);
    StepResult Fail(const std::string& reason);

    Phase phase_ = Phase::kTlsHandshake;
    std::string error_;

    std::unique_ptr<tls::TlsTransport> tls_;
    std::unique_ptr<credssp::CredsspServer> credssp_;
    ServerConfig config_;

    std::vector<uint8_t> plain_buf_;      // TLS plaintext (partial DER / TPKT)
    std::vector<uint8_t> pending_cipher_; // ciphertext not yet consumed
};

}  // namespace rtsc::security
