// Security layer: drives TLS + CredSSP + EUAR as a single reentrant state machine.
//
// Reference: docs/spec/security-integration.audit-a.md section 4.1 (方案 B).
//
// The layer owns the TLS transport and the CredSSP client. It does NOT own the
// socket: the caller feeds ciphertext in and takes ciphertext out, exactly like
// TlsTransport and CredsspClient individually. Once the handshake completes
// (TLS + CredSSP + EUAR), the layer switches to pass-through mode: SendPdu
// encrypts an MCS PDU and returns ciphertext; ReceivePdu decrypts ciphertext
// and returns a complete MCS PDU (with TPKT header).

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "rtsc/credssp/credssp.h"
#include "rtsc/net/tls.h"

namespace rtsc::security {

// Result of one Step() call. The caller inspects `want` to decide what to do
// next: read more ciphertext, write ciphertext to the socket, or process a PDU.
enum class Want : uint8_t {
    kRead,    // need more ciphertext from the peer
    kWrite,   // `to_wire` holds bytes to send
    kPdu,     // `pdu` holds a complete inbound MCS PDU (with TPKT header)
    kDone,    // handshake complete, ready for SendPdu/ReceivePdu
    kFailed,  // `error` populated
};

struct StepResult {
    Want want = Want::kRead;
    std::vector<uint8_t> to_wire;  // bytes to send (when want == kWrite)
    std::vector<uint8_t> pdu;      // complete inbound PDU (when want == kPdu)
    std::string error;             // (when want == kFailed)
};

// Configuration for the security layer.
struct Config {
    // TLS configuration (peer host, cert policy, version bounds, etc.)
    tls::Config tls_config;

    // CredSSP version (5 or 6 recommended).
    uint32_t credssp_version = 6;

    // Client credentials for CredSSP.
    credssp::Credentials credentials;

    // Server's SubjectPublicKey (BIT STRING content) for pubKeyAuth.
    // If empty, the layer fetches it from the TLS transport after handshake.
    std::vector<uint8_t> server_public_key;
};

class SecurityLayer {
 public:
    // Create a security layer. Returns nullptr on failure (why populated).
    static std::unique_ptr<SecurityLayer> Create(const Config& config,
                                                std::string& why);

    ~SecurityLayer();

    // ---- handshake driver ---------------------------------------------------
    // Feed ciphertext received from the peer. Returns what the caller should do.
    // `in` may be nullptr with size 0 to pump the state machine (e.g. after a
    // write completes).
    StepResult Step(const uint8_t* in, size_t in_size);

    // ---- post-handshake data plane ------------------------------------------
    // Encrypt an MCS PDU (with TPKT header) for sending. Returns ciphertext.
    std::vector<uint8_t> SendPdu(const std::vector<uint8_t>& pdu);

    // Decrypt ciphertext and return complete MCS PDUs. May return multiple.
    // Returns empty if more ciphertext is needed.
    std::vector<std::vector<uint8_t>> ReceivePdu(const uint8_t* in,
                                                  size_t in_size);

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
    // Direct access to the CredSSP client so a scripted peer can drive it
    // (e.g. via MakeServerEchoForTest).
    credssp::CredsspClient& credssp_for_test() { return *credssp_; }

 private:
    SecurityLayer();

    enum class Phase : uint8_t {
        kTlsHandshake,     // TLS handshake in progress
        kCredsspStart,     // need to emit CredSSP step 1
        kCredsspAwait,     // awaiting CredSSP server response
        kEuar,             // need to read 4-byte EUAR
        kDone,             // handshake complete
        kFailed,
    };

    // Drive the TLS handshake with the buffered ciphertext.
    StepResult DriveTls();
    // Emit CredSSP step 1 (TLS-encrypted) once the TLS handshake is done.
    StepResult DriveCredsspStart();
    // Process a CredSSP server response; may complete the handshake.
    StepResult DriveCredssp();
    // Read and check the 4-byte EUAR that follows the CredSSP handshake.
    StepResult DriveEuar();
    // TLS-encrypt `plaintext` and wrap it in a write StepResult.
    StepResult EncryptAndWrite(const credssp::Bytes& plaintext);
    // Latch a failure and return it.
    StepResult Fail(const std::string& reason);

    Phase phase_ = Phase::kTlsHandshake;
    std::string error_;

    std::unique_ptr<tls::TlsTransport> tls_;
    std::unique_ptr<credssp::CredsspClient> credssp_;
    Config config_;

    // Buffered plaintext from TLS (may contain partial DER / EUAR / TPKT).
    std::vector<uint8_t> plain_buf_;
    // Ciphertext received but not yet consumed (e.g. leftover after the TLS
    // handshake completed inside the same TCP segment as the final flight).
    std::vector<uint8_t> pending_cipher_;

    // EUAR accumulation buffer (exactly 4 bytes are needed).
    std::vector<uint8_t> euar_buf_;
};

}  // namespace rtsc::security
