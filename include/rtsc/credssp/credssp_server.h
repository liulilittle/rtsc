// CredSSP server state machine (server side of [MS-CSSP] 3.1.5).
//
// Reference: docs/spec/security-layer.md sections 5.3 (five steps), 5.4
// (pubKeyAuth), 5.5 (TSCredentials), 6.x (NTLM), 7.x (SEAL/MIC).
//
// This is the mirror image of CredsspClient. The class owns no transport: it
// consumes the client's TSRequest bytes and produces the server's TSRequest
// bytes, so it can be driven by TLS (production) or by a test directly.
//
// CredSSP is a three-message exchange on the server side:
//   client step 1 (NTLM NEGOTIATE)     -> server step 2 (NTLM CHALLENGE)
//   client step 3 (NTLM AUTHENTICATE
//                + pubKeyAuth)         -> server step 4 (pubKeyAuth echo)
//   client step 5 (authInfo)           -> the server emits the 4-byte EUAR
//
// The NTLM session key cannot be derived from the AUTHENTICATE alone: the
// server must know the account password to compute NTOWFv2 and hence
// SessionBaseKey. That is why the caller supplies a credential lookup. An
// account the lookup does not know is rejected before any key is derived, and
// the lookup is the single authority for who may connect.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "rtsc/credssp/credssp.h"
#include "rtsc/credssp/ntlm.h"
#include "rtsc/credssp/ts_request.h"

namespace rtsc::credssp {

// Returns the account password for (domain, user), or nullopt when the
// account is unknown. A present-but-empty password is a real (rejected)
// credential, distinct from an unknown account.
using CredentialLookup = std::function<std::optional<std::string>(
    const std::string& domain, const std::string& user)>;

class CredsspServer {
public:
    CredsspServer(CredentialLookup lookup, uint32_t version);

    // Process one client TSRequest. On success `out` holds the server's reply
    // (empty when the exchange is complete and the caller should send EUAR).
    Error OnClientMessage(const uint8_t* data, size_t size, Bytes& out);

    bool complete() const noexcept { return state_ == State::kDone; }
    bool failed() const noexcept { return state_ == State::kFailed; }
    const Error& last_error() const noexcept { return last_error_; }
    uint32_t version() const noexcept { return version_; }

    // The client's credentials, decoded from authInfo after completion.
    const PasswordCredentials& credentials() const noexcept { return credentials_; }

    // The server's SubjectPublicKey (BIT STRING content). The security layer
    // supplies it from the TLS transport after the handshake; tests may set it
    // directly so the binding hash is reproducible.
    void SetServerPublicKey(Bytes spk) { server_public_key_ = std::move(spk); }
    const Bytes& server_public_key() const noexcept { return server_public_key_; }

    // ---- test hooks -------------------------------------------------------
    void SetServerChallengeForTest(const std::array<uint8_t, 8>& c) {
        server_challenge_ = c;
    }
    Bytes ExportedSessionKeyForTest() const { return exported_session_key_; }
    Bytes ChallengeMessageForTest() const { return challenge_message_; }
    Bytes NegotiateMessageForTest() const { return negotiate_message_; }
    bool mic_verified() const noexcept { return mic_verified_; }

private:
    enum class State : uint8_t {
        kAwaitNegotiate,
        kAwaitAuthenticate,
        kAwaitAuthInfo,
        kDone,
        kFailed,
    };

    Error BuildChallenge(const TsRequest& req, Bytes& out);
    Error BuildPubKeyEcho(const TsRequest& req, Bytes& out);
    Error ProcessAuthInfo(const TsRequest& req);
    Error Fail(Status status, std::string message);

    // Opens a sealed field from the client (client-to-server direction).
    Error OpenReceive(const Bytes& field, Bytes& out);
    // Seals a field for the client (server-to-client direction).
    Error SealSend(const Bytes& plaintext, Bytes& out);

    CredentialLookup lookup_;
    uint32_t version_ = kMaxVersion;
    State state_ = State::kAwaitNegotiate;
    Error last_error_{};

    Bytes server_public_key_;
    std::array<uint8_t, 8> server_challenge_{};
    Bytes negotiate_message_;
    Bytes challenge_message_;
    Bytes target_info_;
    PasswordCredentials credentials_;
    bool mic_verified_ = false;

    Bytes exported_session_key_;
    Bytes signing_key_c2s_;
    Bytes sealing_key_c2s_;
    Bytes signing_key_s2c_;
    Bytes sealing_key_s2c_;
    bool use_56_bit_key_ = false;

    crypto::Rc4 send_rc4_;
    crypto::Rc4 recv_rc4_;
    bool rc4_ready_ = false;
    uint32_t send_seq_ = 0;
    uint32_t recv_seq_ = 0;
};

}  // namespace rtsc::credssp
