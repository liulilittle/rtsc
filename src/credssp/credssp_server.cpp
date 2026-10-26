// CredSSP server state machine implementation.
//
// Reference: docs/spec/security-layer.md sections 5.3-5.6, 6.x, 7.x.

#include "rtsc/credssp/credssp_server.h"

#include "rtsc/credssp/credssp.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <utility>

#include "rtsc/crypto/hash.h"
#include "rtsc/crypto/random.h"

namespace rtsc::credssp {
namespace {

// AV pair ids reused from the NTLM layer (see ntlm.h AvId).
constexpr uint16_t kAvNbComputerName = 0x0001;
constexpr uint16_t kAvNbDomainName = 0x0002;
constexpr uint16_t kAvTimestamp = 0x0007;

void AppendAvPair(Bytes& out, uint16_t id, const Bytes& value) {
    out.push_back(static_cast<uint8_t>(id & 0xFF));
    out.push_back(static_cast<uint8_t>(id >> 8));
    out.push_back(static_cast<uint8_t>(value.size() & 0xFF));
    out.push_back(static_cast<uint8_t>(value.size() >> 8));
    out.insert(out.end(), value.begin(), value.end());
}

// FILETIME (100 ns since 1601-01-01) for MsvAvTimestamp. std::chrono keeps this
// translation unit free of any platform header.
std::array<uint8_t, 8> NowFileTime() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    const uint64_t filetime =
        static_cast<uint64_t>(ns) / 100u + 116444736000000000ull;
    std::array<uint8_t, 8> out{};
    for (size_t i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>((filetime >> (8 * i)) & 0xFF);
    }
    return out;
}

}  // namespace

CredsspServer::CredsspServer(CredentialLookup lookup, uint32_t version)
    : lookup_(std::move(lookup)) {
    if (version < kMinVersion) version = kMinVersion;
    if (version > kMaxVersion) version = kMaxVersion;
    version_ = version;
}

Error CredsspServer::Fail(Status status, std::string message) {
    last_error_ = Error{};
    last_error_.status = status;
    last_error_.message = std::move(message);
    state_ = State::kFailed;
    return last_error_;
}

Error CredsspServer::OnClientMessage(const uint8_t* data, size_t size, Bytes& out) {
    out.clear();
    if (state_ == State::kFailed) return last_error_;
    if (state_ == State::kDone) {
        return Fail(Status::kMalformed, "message after completion");
    }

    TsRequest req;
    Error e = req.Decode(data, size);
    if (!e.ok()) return Fail(e.status, "cannot decode TSRequest");

    switch (state_) {
        case State::kAwaitNegotiate: {
            e = BuildChallenge(req, out);
            if (e.ok()) state_ = State::kAwaitAuthenticate;
            return e;
        }
        case State::kAwaitAuthenticate: {
            e = BuildPubKeyEcho(req, out);
            if (e.ok()) state_ = State::kAwaitAuthInfo;
            return e;
        }
        case State::kAwaitAuthInfo:
            return ProcessAuthInfo(req);
        default:
            return Fail(Status::kMalformed, "unexpected state");
    }
}

Error CredsspServer::BuildChallenge(const TsRequest& req, Bytes& out) {
    if (req.nego_token.empty()) return Fail(Status::kMalformed, "NEGOTIATE missing");
    if (server_public_key_.empty()) {
        return Fail(Status::kUnsupported, "server public key not set");
    }
    if (req.version < kMinVersion) return Fail(Status::kUnsupported, "unsupported version");
    version_ = std::min(version_, req.version);

    NegotiateMessage neg;
    Error e = neg.Decode(req.nego_token.data(), req.nego_token.size());
    if (!e.ok()) return Fail(e.status, "cannot decode NEGOTIATE");
    negotiate_message_ = req.nego_token;

    if (!crypto::RandomBytes(server_challenge_.data(), server_challenge_.size())) {
        return Fail(Status::kInternal, "CSPRNG unavailable for server challenge");
    }

    const std::string nb_computer = "RTSC-SERVER";
    const std::string nb_domain = "RTSC";
    target_info_.clear();
    AppendAvPair(target_info_, kAvNbComputerName, crypto::Utf16Le(nb_computer));
    AppendAvPair(target_info_, kAvNbDomainName, crypto::Utf16Le(nb_domain));
    const std::array<uint8_t, 8> ts = NowFileTime();
    AppendAvPair(target_info_, kAvTimestamp, Bytes(ts.begin(), ts.end()));

    ChallengeMessage msg;
    // Negotiate the subset of the client's flags this server supports. k56 is
    // deliberately left out so the 56-bit sealing-key path is not selected.
    msg.flags = neg.flags & (ntlm_flag::kUnicode | ntlm_flag::kNtlm |
                            ntlm_flag::kAlwaysSign | ntlm_flag::kExtendedSessionSecurity |
                            ntlm_flag::kTargetInfo | ntlm_flag::kVersion |
                            ntlm_flag::k128 | ntlm_flag::kKeyExch);
    msg.flags |= ntlm_flag::kKeyExch | ntlm_flag::k128;
    msg.server_challenge = server_challenge_;
    msg.target_name = nb_domain;
    msg.av_pairs.clear();
    // Re-encode the AV list the ChallengeMessage encoder expects.
    {
        size_t off = 0;
        while (off + 4 <= target_info_.size()) {
            const uint16_t id = static_cast<uint16_t>(target_info_[off]) |
                                (static_cast<uint16_t>(target_info_[off + 1]) << 8);
            const uint16_t len = static_cast<uint16_t>(target_info_[off + 2]) |
                                 (static_cast<uint16_t>(target_info_[off + 3]) << 8);
            off += 4;
            if (off + len > target_info_.size()) return Fail(Status::kInternal, "av overflow");
            AvPair p;
            p.id = static_cast<AvId>(id);
            p.value.assign(target_info_.begin() + static_cast<ptrdiff_t>(off),
                           target_info_.begin() + static_cast<ptrdiff_t>(off + len));
            msg.av_pairs.push_back(std::move(p));
            off += len;
        }
    }

    Bytes msg_bytes;
    e = msg.Encode(msg_bytes);
    if (!e.ok()) return Fail(e.status, "cannot encode CHALLENGE");
    challenge_message_ = msg_bytes;

    TsRequest reply;
    reply.version = version_;
    reply.nego_token = std::move(msg_bytes);
    return reply.Encode(out);
}

Error CredsspServer::BuildPubKeyEcho(const TsRequest& req, Bytes& out) {
    if (req.nego_token.empty()) return Fail(Status::kMalformed, "AUTHENTICATE missing");
    if (req.pub_key_auth.empty()) return Fail(Status::kMalformed, "pubKeyAuth missing");

    AuthenticateMessage auth;
    Error e = auth.Decode(req.nego_token.data(), req.nego_token.size());
    if (!e.ok()) return Fail(e.status, "cannot decode AUTHENTICATE");
    if (auth.nt_response.size() < 16) {
        return Fail(Status::kMalformed, "NT response too short");
    }

    const std::optional<std::string> password = lookup_(auth.domain, auth.user);
    if (!password.has_value()) {
        return Fail(Status::kUnsupported, "unknown account");
    }

    const Bytes nt_proof(auth.nt_response.begin(),
                         auth.nt_response.begin() + static_cast<ptrdiff_t>(16));
    const Bytes response_key = Ntowfv2(*password, auth.user, auth.domain);
    const auto sbk = crypto::HmacMd5(response_key.data(), response_key.size(),
                                     nt_proof.data(), nt_proof.size());
    const Bytes session_base_key(sbk.begin(), sbk.end());

    use_56_bit_key_ = (auth.flags & ntlm_flag::k56) != 0 &&
                      (auth.flags & ntlm_flag::k128) == 0;
    if ((auth.flags & ntlm_flag::kKeyExch) != 0) {
        exported_session_key_ =
            Rc4Crypt(session_base_key, auth.encrypted_random_session_key);
    } else {
        exported_session_key_ = session_base_key;
    }

    signing_key_c2s_ = DeriveSigningKey(exported_session_key_, false);
    sealing_key_c2s_ = DeriveSealingKey(exported_session_key_, use_56_bit_key_, false);
    signing_key_s2c_ = DeriveSigningKey(exported_session_key_, true);
    sealing_key_s2c_ = DeriveSealingKey(exported_session_key_, use_56_bit_key_, true);
    send_rc4_.Init(sealing_key_s2c_.data(), sealing_key_s2c_.size());
    recv_rc4_.Init(sealing_key_c2s_.data(), sealing_key_c2s_.size());
    rc4_ready_ = true;
    send_seq_ = 0;
    recv_seq_ = 0;

    if (auth.mic_is_set) {
        const auto expected =
            ComputeMic(exported_session_key_, negotiate_message_, challenge_message_,
                       req.nego_token);
        if (expected != auth.mic) {
            return Fail(Status::kMalformed, "MIC mismatch");
        }
        mic_verified_ = true;
    }

    Bytes plain;
    e = OpenReceive(req.pub_key_auth, plain);
    if (!e.ok()) return Fail(e.status, "pubKeyAuth open failed");

    Bytes expected;
    if (version_ >= kFirstHashVersion) {
        expected = ClientToServerBindingHash(server_public_key_, req.client_nonce);
    } else {
        expected = server_public_key_;
    }
    if (plain != expected) return Fail(Status::kMalformed, "pubKeyAuth mismatch");

    Bytes echo_plain;
    if (version_ >= kFirstHashVersion) {
        echo_plain = ServerToClientBindingHash(server_public_key_, req.client_nonce);
    } else {
        echo_plain = server_public_key_;
        // Versions 2/3/4: little-endian increment so the message cannot be
        // replayed back to the client (see CredsspClient::BuildStep5).
        size_t i = 0;
        while (i < echo_plain.size()) {
            if (echo_plain[i] == 0xFF) {
                echo_plain[i] = 0x00;
                ++i;
                continue;
            }
            echo_plain[i] = static_cast<uint8_t>(echo_plain[i] + 1);
            break;
        }
    }

    Bytes sealed;
    e = SealSend(echo_plain, sealed);
    if (!e.ok()) return Fail(e.status, "cannot seal pubKeyAuth echo");

    TsRequest reply;
    reply.version = version_;
    reply.pub_key_auth = std::move(sealed);
    return reply.Encode(out);
}

Error CredsspServer::ProcessAuthInfo(const TsRequest& req) {
    if (req.auth_info.empty()) return Fail(Status::kMalformed, "authInfo missing");
    Bytes plain;
    Error e = OpenReceive(req.auth_info, plain);
    if (!e.ok()) return Fail(e.status, "authInfo open failed");
    e = credentials_.Decode(plain.data(), plain.size());
    if (!e.ok()) return Fail(e.status, "cannot decode TSCredentials");
    state_ = State::kDone;
    return Ok();
}

Error CredsspServer::OpenReceive(const Bytes& field, Bytes& out) {
    if (field.size() < 16) return Fail(Status::kMalformed, "sealed field too short");
    if (!rc4_ready_) return Fail(Status::kInternal, "session keys not ready");

    const Bytes ciphertext(field.begin() + 16, field.end());
    out = recv_rc4_.Apply(ciphertext);
    // Decrypt the checksum from the same RC4 stream, after the message.
    const Bytes checksum =
        recv_rc4_.Apply(Bytes(field.begin() + 4, field.begin() + 12));

    if (field[0] != 0x01 || field[1] != 0x00 || field[2] != 0x00 || field[3] != 0x00) {
        return Fail(Status::kMalformed, "sealed field unsupported version");
    }
    const uint32_t seq = static_cast<uint32_t>(field[12]) |
                         (static_cast<uint32_t>(field[13]) << 8) |
                         (static_cast<uint32_t>(field[14]) << 16) |
                         (static_cast<uint32_t>(field[15]) << 24);
    if (seq != recv_seq_) return Fail(Status::kMalformed, "sealed field out of sequence");

    Bytes mac_input(4, 0);
    mac_input[0] = static_cast<uint8_t>(recv_seq_ & 0xFF);
    mac_input[1] = static_cast<uint8_t>((recv_seq_ >> 8) & 0xFF);
    mac_input[2] = static_cast<uint8_t>((recv_seq_ >> 16) & 0xFF);
    mac_input[3] = static_cast<uint8_t>((recv_seq_ >> 24) & 0xFF);
    mac_input.insert(mac_input.end(), out.begin(), out.end());
    const auto hmac =
        crypto::HmacMd5(signing_key_c2s_.data(), signing_key_c2s_.size(),
                        mac_input.data(), mac_input.size());
    const Bytes expected_mac(hmac.begin(), hmac.begin() + 8);
    if (checksum != expected_mac) {
        return Fail(Status::kMalformed, "sealed field MAC mismatch");
    }
    ++recv_seq_;
    return Ok();
}

Error CredsspServer::SealSend(const Bytes& plaintext, Bytes& out) {
    if (!rc4_ready_) return Fail(Status::kInternal, "session keys not ready");

    const Bytes ciphertext = send_rc4_.Apply(plaintext);
    Bytes mac_input(4, 0);
    mac_input[0] = static_cast<uint8_t>(send_seq_ & 0xFF);
    mac_input[1] = static_cast<uint8_t>((send_seq_ >> 8) & 0xFF);
    mac_input[2] = static_cast<uint8_t>((send_seq_ >> 16) & 0xFF);
    mac_input[3] = static_cast<uint8_t>((send_seq_ >> 24) & 0xFF);
    mac_input.insert(mac_input.end(), plaintext.begin(), plaintext.end());
    const auto hmac =
        crypto::HmacMd5(signing_key_s2c_.data(), signing_key_s2c_.size(),
                        mac_input.data(), mac_input.size());
    const Bytes mac8(hmac.begin(), hmac.begin() + 8);
    const Bytes checksum = send_rc4_.Apply(mac8);

    out.assign(16, 0);
    out[0] = 0x01;
    std::memcpy(out.data() + 4, checksum.data(), 8);
    out[12] = static_cast<uint8_t>(send_seq_ & 0xFF);
    out[13] = static_cast<uint8_t>((send_seq_ >> 8) & 0xFF);
    out[14] = static_cast<uint8_t>((send_seq_ >> 16) & 0xFF);
    out[15] = static_cast<uint8_t>((send_seq_ >> 24) & 0xFF);
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    ++send_seq_;
    return Ok();
}

}  // namespace rtsc::credssp
