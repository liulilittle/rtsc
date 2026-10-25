// CredSSP client state machine.
//
// Reference: docs/spec/security-layer.md sections 5.3-5.6.

#include "rtsc/credssp/credssp.h"

#include <algorithm>

#include "rtsc/crypto/random.h"
#include <cstring>
#include <utility>

namespace rtsc::credssp {
namespace {

constexpr char kClientMagic[] = "CredSSP Client-To-Server Binding Hash";
constexpr char kServerMagic[] = "CredSSP Server-To-Client Binding Hash";
constexpr size_t kNonceSize = 32;
constexpr size_t kSignatureSize = 16;
constexpr size_t kExportedKeySize = 16;  // security-layer.md:830

Bytes HashWithMagic(const char* magic, const Bytes& nonce, const Bytes& key) {
    // The magic's NUL terminator is part of the hash input; dropping it yields
    // a plausible but wrong value.
    const size_t magic_len = std::strlen(magic) + 1;
    Bytes input(magic, magic + magic_len);
    input.insert(input.end(), nonce.begin(), nonce.end());
    input.insert(input.end(), key.begin(), key.end());
    const auto digest = crypto::Sha256(input.data(), input.size());
    return Bytes(digest.begin(), digest.end());
}

}  // namespace

Bytes ClientToServerBindingHash(const Bytes& subject_public_key, const Bytes& nonce) {
    return HashWithMagic(kClientMagic, nonce, subject_public_key);
}

Bytes ServerToClientBindingHash(const Bytes& subject_public_key, const Bytes& nonce) {
    return HashWithMagic(kServerMagic, nonce, subject_public_key);
}

CredsspClient::CredsspClient(Credentials credentials, uint32_t version)
    : credentials_(std::move(credentials)), version_(version) {
    if (version_ < kMinVersion) version_ = kMinVersion;
    if (version_ > kMaxVersion) version_ = kMaxVersion;
    // S1: fresh CSPRNG material per connection. The nonce seeds ClientChallenge
    // (c:176) and ExportedSessionKey (c:191), so a constant here made the NTLM
    // exchange predictable while still "working" against a cooperative peer.
    // On RNG failure the buffer is left empty on purpose: BuildStep3 (c:229)
    // then fails closed instead of falling back to zeros.
    if (!crypto::RandomBytes(nonce_, kNonceSize)) nonce_.clear();
}

Error CredsspClient::Fail(Status status, std::string message, int32_t native_code) {
    last_error_ = Error{};
    last_error_.status = status;
    last_error_.message = std::move(message);
    last_error_.native_code = native_code;
    step_ = Step::kFailed;
    return last_error_;
}

Error CredsspClient::Start(Bytes& out) {
    out.clear();
    if (step_ != Step::kNotStarted) {
        return Fail(Status::kMalformed, "Start called twice");
    }

    NegotiateMessage negotiate;
    negotiate.flags = ntlm_flag::kCredsspClient;
    Bytes negotiate_bytes;
    Error e = negotiate.Encode(negotiate_bytes);
    if (!e.ok()) return Fail(e.status, "cannot encode NEGOTIATE");
    negotiate_message_ = negotiate_bytes;

    TsRequest req;
    req.version = version_;
    req.nego_token = negotiate_bytes;
    e = req.Encode(out);
    if (!e.ok()) return Fail(e.status, "cannot encode TSRequest");

    step_ = Step::kAwaitChallenge;
    return Ok();
}

Error CredsspClient::OnServerResponse(const uint8_t* data, size_t size, Bytes& out) {
    out.clear();
    if (step_ == Step::kFailed) return last_error_;
    if (step_ == Step::kDone) {
        return Fail(Status::kMalformed, "response after completion");
    }
    if (step_ == Step::kNotStarted) {
        return Fail(Status::kMalformed, "response before Start");
    }

    TsRequest req;
    Error e = req.Decode(data, size);
    if (!e.ok()) return Fail(e.status, "cannot decode TSRequest");

    // The errorCode check comes first: a peer that declared failure must not
    // have its token processed.
    if (req.has_error_code) {
        Error err;
        err.status = Status::kMalformed;
        err.message = "server reported an error";
        err.native_code = static_cast<int32_t>(req.error_code);
        last_error_ = err;
        step_ = Step::kFailed;
        return last_error_;
    }

    // S5 + S6, both scoped to the challenge step (final verdict, §8.2/§8.3).
    //
    // Step 2 is the ONLY version negotiation point (security-layer.md:673); the
    // step-4 version carries no negotiation semantics (security-layer.md:674).
    // Keeping both the range check and the write-back inside this branch means
    // step 4 neither rejects on version nor rewrites version_, so step 5 always
    // uses the same version step 3 used. Doing either one outside the branch
    // would (a) let a step-4 version downgrade an already negotiated version and
    // (b) add a rejection point that did not exist before.
    //
    // Reject only the lower bound: a peer may advertise a newer version
    // (security-layer.md:236 measured 1..8 all answered 6) and per [MS-CSSP] is
    // then treated as the highest we understand, which min() below does.
    // Placement after the errorCode branch keeps native_code intact (D6).
    if (step_ == Step::kAwaitChallenge) {
        if (req.version < kMinVersion) {
            return Fail(Status::kUnsupported, "unsupported TSRequest version");
        }
        version_ = std::min(version_, req.version);   // downgrade only, never upgrade
        return BuildStep3(req, out);
    }
    if (step_ == Step::kAwaitServerEcho) {
        return BuildStep5(req, out);
    }
    return Fail(Status::kMalformed, "unexpected state");
}

Error CredsspClient::BuildStep3(const TsRequest& challenge, Bytes& out) {
    // S18: pubKeyAuth is only worth as much as the key it binds. With an empty
    // key the binding hash degenerates to SHA256(magic || nonce || "") (measured:
    // probe P5), which a peer either rejects or -- worse -- accepts while the
    // client silently loses its only MITM protection. Fail closed here.
    // The key must arrive from TlsTransport::PeerSubjectPublicKey()
    // (include/rtsc/net/tls.h:170; implemented src/net/tls_schannel.cpp:371).
    if (server_public_key_.empty()) {
        return Fail(Status::kUnsupported, "server public key not set");
    }
    // S1 follow-up (D5): c:176 and c:191 slice nonce_[0..8) and nonce_[8..24)
    // BEFORE the only size check, which sits at c:229 inside the version>=5
    // branch. A short nonce is therefore an out-of-range slice, not an error.
    // Measured on the unpatched library: nonce=0/4 exit 0xC0000409.
    if (nonce_.size() != kNonceSize) {
        return Fail(Status::kUnsupported, "nonce must be 32 bytes");
    }
    if (challenge.nego_token.empty()) {
        return Fail(Status::kMalformed, "challenge without token");
    }
    challenge_message_ = challenge.nego_token;

    ChallengeMessage msg;
    Error e = msg.Decode(challenge.nego_token.data(), challenge.nego_token.size());
    if (!e.ok()) return Fail(e.status, "cannot decode CHALLENGE");
    server_challenge_ = msg.server_challenge;

    // The AV list as received, minus the trailing EOL: the client appends its
    // own pairs (target name, channel bindings) and re-terminates.
    target_info_.clear();
    for (const auto& p : msg.av_pairs) {
        const uint8_t hdr[4] = {
            static_cast<uint8_t>(static_cast<uint16_t>(p.id) & 0xFF),
            static_cast<uint8_t>(static_cast<uint16_t>(p.id) >> 8),
            static_cast<uint8_t>(p.value.size() & 0xFF),
            static_cast<uint8_t>(p.value.size() >> 8)};
        target_info_.insert(target_info_.end(), hdr, hdr + 4);
        target_info_.insert(target_info_.end(), p.value.begin(), p.value.end());
    }

    // §7.3: the client should supply MsvAvTargetName and MsvAvChannelBindings,
    // and must set the MIC bit in MsvAvFlags when a timestamp is present.
    bool have_timestamp = false;
    Bytes ts_value;
    if (msg.FindAvPair(AvId::kTimestamp, ts_value).ok()) have_timestamp = true;

    Bytes flags_value(4, 0);
    Bytes existing_flags;
    if (msg.FindAvPair(AvId::kFlags, existing_flags).ok() && existing_flags.size() == 4) {
        flags_value = existing_flags;
    }
    if (have_timestamp) {
        flags_value[0] = static_cast<uint8_t>(flags_value[0] | 0x02);
        const uint8_t hdr[4] = {0x06, 0x00, 0x04, 0x00};
        target_info_.insert(target_info_.end(), hdr, hdr + 4);
        target_info_.insert(target_info_.end(), flags_value.begin(), flags_value.end());
    }
    // MsvAvChannelBindings = Z(16): the TLS channel binding is carried by
    // pubKeyAuth instead, so a second binding layer would be redundant.
    {
        const uint8_t hdr[4] = {0x0A, 0x00, 0x10, 0x00};
        target_info_.insert(target_info_.end(), hdr, hdr + 4);
        target_info_.insert(target_info_.end(), 16, 0);
    }
    target_info_.push_back(0);
    target_info_.push_back(0);
    target_info_.push_back(0);
    target_info_.push_back(0);

    NtlmV2Inputs in;
    in.user = credentials_.user;
    in.domain = credentials_.domain;
    in.password = credentials_.password;
    in.server_challenge.assign(server_challenge_.begin(), server_challenge_.end());
    // ClientChallenge: 8 bytes. A fixed value would weaken the exchange, so the
    // nonce prefix is used here; it is already random per connection.
    in.client_challenge.assign(nonce_.begin(), nonce_.begin() + 8);
    in.timestamp = have_timestamp ? ts_value : Bytes(8, 0);
    in.target_info = target_info_;
    in.suppress_lm_response = have_timestamp;

    NtlmV2Output v2;
    e = ComputeNtlmV2(in, v2);
    if (!e.ok()) return Fail(e.status, "NTLMv2 computation failed");
    session_base_key_ = v2.session_base_key;

    // Key exchange: a fresh random exported key, encrypted under the session
    // base key when KEY_EXCH is negotiated.
    use_56_bit_key_ = (msg.flags & ntlm_flag::k56) != 0 &&
                      (msg.flags & ntlm_flag::k128) == 0;
    if ((msg.flags & ntlm_flag::kKeyExch) != 0) {
        // N-B1: ExportedSessionKey MUST be an independent 16-byte random value
        // (security-layer.md:829-830). Deriving it from nonce_ would publish it:
        // the whole nonce travels in cleartext as TSRequest.clientNonce (c:244,
        // ts:263-267), so anyone who can read step 3 could derive the sealing key
        // and decrypt the password sent at step 5. Never derive one from the other.
        if (!crypto::RandomBytes(exported_session_key_, kExportedKeySize)) {
            return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");
        }
    } else {
        exported_session_key_ = session_base_key_;
    }

    signing_key_ = DeriveSigningKey(exported_session_key_, false);
    sealing_key_ = DeriveSealingKey(exported_session_key_, use_56_bit_key_, false);

    AuthenticateMessage auth;
    auth.flags = msg.flags & ntlm_flag::kCredsspClient;
    auth.domain = credentials_.domain;
    auth.user = credentials_.user;
    auth.workstation = "";
    auth.lm_response = v2.lm_response;
    auth.nt_response = v2.nt_response;
    if ((msg.flags & ntlm_flag::kKeyExch) != 0) {
        auth.encrypted_random_session_key =
            Rc4Crypt(session_base_key_, exported_session_key_);
    }
    Bytes auth_bytes;
    e = auth.Encode(auth_bytes);
    if (!e.ok()) return Fail(e.status, "cannot encode AUTHENTICATE");

    if (have_timestamp) {
        const auto mic = ComputeMic(exported_session_key_, negotiate_message_,
                                    challenge_message_, auth_bytes);
        std::memcpy(auth_bytes.data() + 72, mic.data(), 16);
        auth.mic = mic;
        auth.mic_is_set = true;
        e = auth.Encode(auth_bytes);
        if (!e.ok()) return Fail(e.status, "cannot re-encode AUTHENTICATE with MIC");
    }
    authenticate_message_ = auth_bytes;

    // pubKeyAuth: the binding hash (v5+) or the raw key (v2/3/4), sealed with
    // send sequence 0.
    Bytes plain;
    if (version_ >= kFirstHashVersion) {
        if (nonce_.size() != kNonceSize) {
            return Fail(Status::kUnsupported, "nonce must be 32 bytes");
        }
        plain = ClientToServerBindingHash(server_public_key_, nonce_);
    } else {
        plain = server_public_key_;
    }
    Bytes sealed;
    e = SealSend(plain, sealed);
    if (!e.ok()) return e;

    TsRequest req;
    req.version = version_;
    req.nego_token = auth_bytes;
    req.pub_key_auth = sealed;
    if (version_ >= kFirstHashVersion) req.client_nonce = nonce_;
    e = req.Encode(out);
    if (!e.ok()) return Fail(e.status, "cannot encode step 3");

    step_ = Step::kAwaitServerEcho;
    return Ok();
}

Error CredsspClient::BuildStep5(const TsRequest& echo, Bytes& out) {
    if (echo.pub_key_auth.empty()) {
        return Fail(Status::kMalformed, "step 4 without pubKeyAuth");
    }

    Bytes plain;
    Error e = OpenReceive(echo.pub_key_auth, plain);
    if (!e.ok()) return e;

    // The echo proves the peer holds the same session key. Verifying it is what
    // makes the exchange resistant to a man in the middle; skipping it would
    // still "work" against a cooperative server and silently lose the
    // protection.
    Bytes expected;
    if (version_ >= kFirstHashVersion) {
        expected = ServerToClientBindingHash(server_public_key_, nonce_);
    } else {
        expected = server_public_key_;
    }
    if (version_ < kFirstHashVersion) {
        // Versions 2/3/4: the server adds 1 to the first byte (little-endian
        // increment) so the message cannot be replayed back to the client.
        if (plain.size() != expected.size()) {
            return Fail(Status::kMalformed, "echo length mismatch");
        }
        size_t i = 0;
        while (i < plain.size() && plain[i] == 0x00) ++i;
        if (i >= plain.size()) return Fail(Status::kMalformed, "echo underflow");
        plain[i] = static_cast<uint8_t>(plain[i] - 1);
        for (size_t k = 0; k < i; ++k) plain[k] = 0xFF;
    }
    if (plain != expected) {
        return Fail(Status::kMalformed, "server echo mismatch");
    }

    PasswordCredentials creds;
    creds.domain = credentials_.domain;
    creds.user = credentials_.user;
    creds.password = credentials_.password;
    Bytes creds_der;
    e = creds.Encode(creds_der);
    if (!e.ok()) return Fail(e.status, "cannot encode TSCredentials");

    Bytes sealed;
    e = SealSend(creds_der, sealed);
    if (!e.ok()) return e;

    TsRequest req;
    req.version = version_;
    req.auth_info = sealed;
    e = req.Encode(out);
    if (!e.ok()) return Fail(e.status, "cannot encode step 5");

    step_ = Step::kDone;
    return Ok();
}

Error CredsspClient::SealSend(const Bytes& plaintext, Bytes& field) {
    if (!rc4_ready_) {
        send_rc4_.Init(sealing_key_.data(), sealing_key_.size());
        recv_rc4_.Init(DeriveSealingKey(exported_session_key_, use_56_bit_key_, true).data(),
                       sealing_key_.size());
        rc4_ready_ = true;
    }
    // Continue the same stream across messages, exactly as SEAL requires.
    SealedMessage sealed;
    sealed.ciphertext = send_rc4_.Apply(plaintext);

    Bytes mac_input(4, 0);
    mac_input[0] = static_cast<uint8_t>(send_seq_ & 0xFF);
    mac_input[1] = static_cast<uint8_t>((send_seq_ >> 8) & 0xFF);
    mac_input[2] = static_cast<uint8_t>((send_seq_ >> 16) & 0xFF);
    mac_input[3] = static_cast<uint8_t>((send_seq_ >> 24) & 0xFF);
    mac_input.insert(mac_input.end(), plaintext.begin(), plaintext.end());
    const auto hmac = crypto::HmacMd5(signing_key_.data(), signing_key_.size(),
                                      mac_input.data(), mac_input.size());
    const Bytes mac8(hmac.begin(), hmac.begin() + 8);
    const Bytes checksum = send_rc4_.Apply(mac8);

    sealed.signature[0] = 0x01;
    sealed.signature[1] = 0x00;
    sealed.signature[2] = 0x00;
    sealed.signature[3] = 0x00;
    std::memcpy(sealed.signature.data() + 4, checksum.data(), 8);
    sealed.signature[12] = static_cast<uint8_t>(send_seq_ & 0xFF);
    sealed.signature[13] = static_cast<uint8_t>((send_seq_ >> 8) & 0xFF);
    sealed.signature[14] = static_cast<uint8_t>((send_seq_ >> 16) & 0xFF);
    sealed.signature[15] = static_cast<uint8_t>((send_seq_ >> 24) & 0xFF);

    ++send_seq_;
    field.assign(sealed.signature.begin(), sealed.signature.end());
    field.insert(field.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
    return Ok();
}

Error CredsspClient::OpenReceive(const Bytes& field, Bytes& plaintext) {
    if (field.size() < kSignatureSize) {
        return Fail(Status::kMalformed, "sealed field too short");
    }
    if (!rc4_ready_) {
        send_rc4_.Init(sealing_key_.data(), sealing_key_.size());
        recv_rc4_.Init(DeriveSealingKey(exported_session_key_, use_56_bit_key_, true).data(),
                       sealing_key_.size());
        rc4_ready_ = true;
    }
    const Bytes ciphertext(field.begin() + static_cast<ptrdiff_t>(kSignatureSize),
                           field.end());
    plaintext = recv_rc4_.Apply(ciphertext);

    // S11: SEAL appends HMAC_MD5(SigningKey, seq || message)[0..7] encrypted on
    // the *same* RC4 stream, right after the ciphertext (SealSend c:318-343 and
    // Seal in ntlm.cpp:401-422). Decrypting without verifying therefore lets an
    // attacker flip ciphertext bits and have the peer accept them. Order must be
    // symmetric with SealSend: decrypt the message, then decrypt the checksum.
    const Bytes checksum = recv_rc4_.Apply(
        Bytes(field.begin() + 4, field.begin() + 12));
    if (field[0] != 0x01 || field[1] != 0x00 || field[2] != 0x00 || field[3] != 0x00) {
        return Fail(Status::kMalformed, "sealed field unsupported version");
    }
    const uint32_t seq = static_cast<uint32_t>(field[12]) |
                         (static_cast<uint32_t>(field[13]) << 8) |
                         (static_cast<uint32_t>(field[14]) << 16) |
                         (static_cast<uint32_t>(field[15]) << 24);
    if (seq != recv_seq_) {
        return Fail(Status::kMalformed, "sealed field out of sequence");
    }
    Bytes mac_input(4, 0);
    mac_input[0] = static_cast<uint8_t>(recv_seq_ & 0xFF);
    mac_input[1] = static_cast<uint8_t>((recv_seq_ >> 8) & 0xFF);
    mac_input[2] = static_cast<uint8_t>((recv_seq_ >> 16) & 0xFF);
    mac_input[3] = static_cast<uint8_t>((recv_seq_ >> 24) & 0xFF);
    mac_input.insert(mac_input.end(), plaintext.begin(), plaintext.end());
    // The receive direction is signed with the SERVER-to-client signing key.
    // signing_key_ (c:196) is client-to-server, so reusing it here would reject
    // every well-formed step-4 echo; verified by mutation (see audit notes).
    const Bytes recv_signing_key = DeriveSigningKey(exported_session_key_, true);
    const auto hmac = crypto::HmacMd5(recv_signing_key.data(), recv_signing_key.size(),
                                      mac_input.data(), mac_input.size());
    const Bytes expected_mac(hmac.begin(), hmac.begin() + 8);
    if (checksum != expected_mac) {
        plaintext.clear();
        return Fail(Status::kMalformed, "sealed field MAC mismatch");
    }
    ++recv_seq_;
    return Ok();
}

Bytes CredsspClient::MakeServerEchoForTest() const {
    // Produces what a correct server would send at step 4, using the
    // server-to-client keys.
    Bytes plain;
    if (version_ >= kFirstHashVersion) {
        plain = ServerToClientBindingHash(server_public_key_, nonce_);
    } else {
        plain = server_public_key_;
        // little-endian increment of the first byte, with carry
        size_t i = 0;
        while (i < plain.size()) {
            if (plain[i] == 0xFF) {
                plain[i] = 0x00;
                ++i;
                continue;
            }
            plain[i] = static_cast<uint8_t>(plain[i] + 1);
            break;
        }
    }
    const Bytes sign = DeriveSigningKey(exported_session_key_, true);
    const Bytes seal = DeriveSealingKey(exported_session_key_, use_56_bit_key_, true);
    SealedMessage s;
    Seal(seal, sign, recv_seq_, plain, s);
    Bytes out(s.signature.begin(), s.signature.end());
    out.insert(out.end(), s.ciphertext.begin(), s.ciphertext.end());
    return out;
}

Bytes CredsspClient::DecryptPubKeyAuthForTest(const Bytes& field) const {
    if (field.size() < kSignatureSize) return Bytes{};
    const Bytes ciphertext(field.begin() + static_cast<ptrdiff_t>(kSignatureSize),
                           field.end());
    // Independent instance: step 3's pubKeyAuth is the first message sent, so a
    // fresh stream reproduces it exactly.
    crypto::Rc4 rc4(sealing_key_);
    return rc4.Apply(ciphertext);
}

Bytes CredsspClient::DecryptAuthInfoForTest(const Bytes& field) const {
    if (field.size() < kSignatureSize) return Bytes{};
    const Bytes ciphertext(field.begin() + static_cast<ptrdiff_t>(kSignatureSize),
                           field.end());
    // authInfo is the second message, so the stream must first be advanced by
    // the step-3 plaintext plus its checksum.
    crypto::Rc4 rc4(sealing_key_);
    const Bytes first = ClientToServerBindingHash(server_public_key_, nonce_);
    rc4.Skip(first.size() + 8);
    return rc4.Apply(ciphertext);
}

}  // namespace rtsc::credssp
