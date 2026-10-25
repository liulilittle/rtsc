// CredSSP client state machine (client side of [MS-CSSP] 3.1.5).
//
// Reference: docs/spec/security-layer.md sections 5.3 (five steps),
// 5.4 (pubKeyAuth), 5.5 (TSCredentials), 5.6 (measured wire choices).
//
// The class owns no transport: it produces the bytes to send and consumes the
// bytes received, so it can be driven by the TLS layer, by a test, or later by
// a different platform without changes.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "rtsc/credssp/ntlm.h"
#include "rtsc/credssp/ts_request.h"

namespace rtsc::credssp {

struct Credentials {
    std::string domain;
    std::string user;
    std::string password;
};

// Version 5 and 6 replace the raw encrypted public key with a SHA-256 binding
// hash; 2/3/4 use the raw key. The two paths are not interchangeable.
constexpr uint32_t kMinVersion = 2;
constexpr uint32_t kMaxVersion = 6;
constexpr uint32_t kFirstHashVersion = 5;

// SHA256("CredSSP Client-To-Server Binding Hash\0" || nonce || SubjectPublicKey)
Bytes ClientToServerBindingHash(const Bytes& subject_public_key, const Bytes& nonce);
// SHA256("CredSSP Server-To-Client Binding Hash\0" || nonce || SubjectPublicKey)
Bytes ServerToClientBindingHash(const Bytes& subject_public_key, const Bytes& nonce);

class CredsspClient {
public:
    CredsspClient(Credentials credentials, uint32_t version);

    // Step 1: emit TSRequest{version, negoTokens(NTLM NEGOTIATE)}.
    Error Start(Bytes& out);

    // Feed the server's TSRequest and get the next message to send.
    // Step 2 (CHALLENGE) -> produces step 3.
    // Step 4 (pubKeyAuth echo) -> produces step 5 and completes.
    // A response carrying errorCode always fails with that code.
    Error OnServerResponse(const uint8_t* data, size_t size, Bytes& out);

    bool complete() const noexcept { return step_ == Step::kDone; }
    uint32_t version() const noexcept { return version_; }

    // Supplies the server's SubjectPublicKey for pubKeyAuth. Production callers
    // feed this from TlsTransport::PeerSubjectPublicKey() after the TLS
    // handshake; BuildStep3 refuses to run without it, because an empty key
    // reduces pubKeyAuth to SHA256(magic || nonce || "") and silently drops the
    // only man-in-the-middle protection CredSSP provides.
    void SetServerPublicKey(Bytes spk) { server_public_key_ = std::move(spk); }

    // Supplies the server's leaf certificate DER. When set, the client derives
    // the NTLM channel binding (RFC 5929 tls-server-end-point) and sends it in
    // MsvAvChannelBindings instead of Z(16). Servers with Extended Protection
    // for Authentication (Windows 11 22H2 RDP) reject a client that omits it.
    // Not yet verified against a server that enforces CBT.
    void SetServerCertificateDer(Bytes der) { server_cert_der_ = std::move(der); }

    // ClientSuppliedTargetName ([MS-NLMP] 3.1.1.2): the SPN of the target
    // server, echoed in the MsvAvTargetName AV pair ([MS-NLMP] 2.2.2.1). For
    // RDP this is "TERMSRV/<host>". [MS-NLMP] 3.1.1.5 sends the pair in both
    // branches: with the value when set, and as an empty value when the caller
    // never supplied one (NULL). Calling this with "" is a distinct, explicitly
    // empty value, not the same as never calling it.
    void SetClientTargetName(std::string spn) {
        client_target_name_ = std::move(spn);
        has_target_name_ = true;
    }

    // ---- test hooks -------------------------------------------------------
    // The production path generates the nonce with a CSPRNG. Tests inject a
    // fixed one so the binding hash is reproducible; the hook is explicit so a
    // missing call in production is a visible omission, not a silent default.
    void SetNonceForTest(const Bytes& nonce) { nonce_ = nonce; }
    void SetServerPublicKeyForTest(const Bytes& spk) { server_public_key_ = spk; }
    // Produces a step-4 response the client will accept (server side of the
    // exchange), so the happy path can be tested without a real server.
    Bytes MakeServerEchoForTest() const;
    // Decrypts a pubKeyAuth/authInfo field the client produced, for assertions.
    Bytes DecryptPubKeyAuthForTest(const Bytes& field) const;
    Bytes DecryptAuthInfoForTest(const Bytes& field) const;
    // The three messages and the session key, so a test can recompute the MIC
    // from scratch instead of trusting the client's own arithmetic.
    Bytes ExportedSessionKeyForTest() const { return exported_session_key_; }
    Bytes NegotiateMessageForTest() const { return negotiate_message_; }
    Bytes ChallengeMessageForTest() const { return challenge_message_; }

private:
    enum class Step : uint8_t {
        kNotStarted,
        kAwaitChallenge,
        kAwaitServerEcho,
        kDone,
        kFailed,
    };

    Error BuildStep3(const TsRequest& challenge, Bytes& out);
    Error BuildStep5(const TsRequest& echo, Bytes& out);
    Error Fail(Status status, std::string message, int32_t native_code = 0);

    // Seals `plaintext` with the current send sequence number and advances it.
    Error SealSend(const Bytes& plaintext, Bytes& field);
    // Opens a sealed field received from the server with the receive sequence.
    Error OpenReceive(const Bytes& field, Bytes& plaintext);

    Credentials credentials_;
    uint32_t version_ = kMaxVersion;
    Step step_ = Step::kNotStarted;
    Error last_error_{};

    Bytes nonce_;
    Bytes server_public_key_;
    Bytes server_cert_der_;
    std::string client_target_name_;
    // True once SetClientTargetName was called, even with an empty string.
    // Distinguishes "no SPN supplied" (NULL) from "explicitly empty"; both
    // emit MsvAvTargetName, per [MS-NLMP] 3.1.1.5.
    bool has_target_name_ = false;

    // NTLM state carried between steps.
    Bytes negotiate_message_;
    Bytes challenge_message_;
    Bytes authenticate_message_;
    std::array<uint8_t, 8> server_challenge_{};
    Bytes target_info_;
    Bytes session_base_key_;
    Bytes exported_session_key_;
    Bytes signing_key_;
    Bytes sealing_key_;
    bool use_56_bit_key_ = false;

    // SEAL keeps one RC4 stream per direction for the whole session: the
    // checksum is encrypted on the stream the previous message advanced. A
    // fresh instance per message would produce signatures the peer rejects.
    crypto::Rc4 send_rc4_;
    crypto::Rc4 recv_rc4_;
    bool rc4_ready_ = false;

    uint32_t send_seq_ = 0;
    uint32_t recv_seq_ = 0;
};

}  // namespace rtsc::credssp
