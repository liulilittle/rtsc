// NTLM message layer and NTLMv2 / SEAL primitives.
//
// Reference: docs/spec/security-layer.md sections 6.1-6.7 and 7.1-7.5.

#include "rtsc/credssp/ntlm.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace rtsc::credssp {
namespace {

constexpr char kSignature[8] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'};
constexpr size_t kNegotiateHeaderSize = 40;
constexpr size_t kChallengeHeaderSize = 56;
constexpr size_t kAuthenticateHeaderSize = 88;
constexpr uint32_t kMessageTypeNegotiate = 1;
constexpr uint32_t kMessageTypeChallenge = 2;
constexpr uint32_t kMessageTypeAuthenticate = 3;

uint16_t LoadLe16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}
uint32_t LoadLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
void StoreLe16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>(v >> 8);
}
void StoreLe32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

Error CheckSignature(const uint8_t* data, size_t size, uint32_t expected_type) {
    if (size < 12) return Fail(Status::kTruncated, "ntlm message too short");
    if (std::memcmp(data, kSignature, 8) != 0) {
        return Fail(Status::kMalformed, "bad NTLMSSP signature");
    }
    if (LoadLe32(data + 8) != expected_type) {
        return Fail(Status::kMalformed, "unexpected MessageType");
    }
    return Ok();
}

// A security buffer: length, allocated length, offset from message start.
struct SecBuf {
    uint16_t len = 0;
    uint16_t max_len = 0;
    uint32_t offset = 0;
};

Error ReadSecBuf(const uint8_t* data, size_t size, size_t field_offset,
                 size_t header_size, SecBuf& out) {
    if (field_offset + 8 > size) return Fail(Status::kTruncated, "security buffer");
    out.len = LoadLe16(data + field_offset);
    out.max_len = LoadLe16(data + field_offset + 2);
    out.offset = LoadLe32(data + field_offset + 4);
    // The payload must live after the fixed header: an offset inside the
    // header is either corruption or an attempt to make the parser read
    // header bytes as credential data.
    if (out.len != 0 && out.offset < header_size) {
        return Fail(Status::kMalformed, "payload offset inside header");
    }
    if (out.offset > size || out.len > size - out.offset) {
        return Fail(Status::kTruncated, "payload outside message");
    }
    return Ok();
}

void WriteSecBuf(uint8_t* p, size_t len, uint32_t offset) {
    StoreLe16(p, static_cast<uint16_t>(len));
    StoreLe16(p + 2, static_cast<uint16_t>(len));
    StoreLe32(p + 4, offset);
}

std::string Utf16LeToString(const uint8_t* data, size_t size) {
    std::string out;
    out.reserve(size / 2);
    for (size_t i = 0; i + 1 < size; i += 2) {
        const uint32_t unit = static_cast<uint32_t>(data[i]) |
                              (static_cast<uint32_t>(data[i + 1]) << 8);
        if (unit < 0x80) {
            out.push_back(static_cast<char>(unit));
        } else if (unit < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (unit >> 6)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (unit >> 12)));
            out.push_back(static_cast<char>(0x80 | ((unit >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3F)));
        }
    }
    return out;
}

Bytes EncodeAvPairs(const std::vector<AvPair>& pairs) {
    Bytes out;
    for (const auto& p : pairs) {
        if (p.id == AvId::kEol) continue;  // the terminator is appended below
        const uint8_t hdr[4] = {static_cast<uint8_t>(static_cast<uint16_t>(p.id) & 0xFF),
                                static_cast<uint8_t>(static_cast<uint16_t>(p.id) >> 8),
                                static_cast<uint8_t>(p.value.size() & 0xFF),
                                static_cast<uint8_t>(p.value.size() >> 8)};
        out.insert(out.end(), hdr, hdr + 4);
        out.insert(out.end(), p.value.begin(), p.value.end());
    }
    // The list must always end with MsvAvEOL; without it there is no defined
    // end and a parser can run off the buffer.
    out.push_back(0);
    out.push_back(0);
    out.push_back(0);
    out.push_back(0);
    return out;
}

Error DecodeAvPairs(const uint8_t* data, size_t size, std::vector<AvPair>& out) {
    out.clear();
    size_t off = 0;
    for (;;) {
        if (off + 4 > size) return Fail(Status::kTruncated, "av pair header");
        const uint16_t id = LoadLe16(data + off);
        const uint16_t len = LoadLe16(data + off + 2);
        off += 4;
        if (off + len > size) return Fail(Status::kTruncated, "av pair value");
        if (id == 0) {
            if (len != 0) return Fail(Status::kMalformed, "MsvAvEOL with value");
            return Ok();
        }
        AvPair p;
        p.id = static_cast<AvId>(id);
        p.value.assign(data + off, data + off + len);
        out.push_back(std::move(p));
        off += len;
    }
}

}  // namespace

// ---- NegotiateMessage -----------------------------------------------------

Error NegotiateMessage::Encode(Bytes& out) const {
    out.assign(kNegotiateHeaderSize, 0);
    std::memcpy(out.data(), kSignature, 8);
    StoreLe32(out.data() + 8, kMessageTypeNegotiate);
    StoreLe32(out.data() + 12, flags);
    // DomainName / WorkstationName are empty; their offsets point at the end of
    // the header, which is where an empty payload starts.
    WriteSecBuf(out.data() + 16, 0, static_cast<uint32_t>(kNegotiateHeaderSize));
    WriteSecBuf(out.data() + 24, 0, static_cast<uint32_t>(kNegotiateHeaderSize));
    // Version: 10.0, build 0x4563, revision NTLMSSP_REVISION_W2K3 (0x0F).
    out[32] = 0x0a;
    out[33] = 0x00;
    StoreLe16(out.data() + 34, 0x4563);
    out[39] = 0x0F;
    return Ok();
}

Error NegotiateMessage::Decode(const uint8_t* data, size_t size) {
    Error e = CheckSignature(data, size, kMessageTypeNegotiate);
    if (!e.ok()) return e;
    if (size < 32) return Fail(Status::kTruncated, "negotiate header");
    flags = LoadLe32(data + 12);
    return Ok();
}

// ---- ChallengeMessage -----------------------------------------------------

Error ChallengeMessage::Encode(Bytes& out) const {
    const Bytes target = crypto::Utf16Le(target_name);
    const Bytes avs = EncodeAvPairs(av_pairs);
    out.assign(kChallengeHeaderSize, 0);
    std::memcpy(out.data(), kSignature, 8);
    StoreLe32(out.data() + 8, kMessageTypeChallenge);
    StoreLe32(out.data() + 20, flags);
    std::memcpy(out.data() + 24, server_challenge.data(), 8);
    // Reserved at 32..39 stays zero.
    size_t off = kChallengeHeaderSize;
    WriteSecBuf(out.data() + 12, target.size(), static_cast<uint32_t>(off));
    out.insert(out.end(), target.begin(), target.end());
    off += target.size();
    WriteSecBuf(out.data() + 40, avs.size(), static_cast<uint32_t>(off));
    out.insert(out.end(), avs.begin(), avs.end());
    // The version field is only meaningful when NTLMSSP_NEGOTIATE_VERSION is set.
    // A real client rejects a CHALLENGE that advertises the flag but carries a
    // zero version, so the field is written whenever the flag is present.
    if ((flags & ntlm_flag::kVersion) != 0) {
        out[48] = version_major;
        out[49] = version_minor;
        StoreLe16(out.data() + 50, version_build);
        out[55] = version_revision;
    }
    return Ok();
}

Error ChallengeMessage::Decode(const uint8_t* data, size_t size) {
    Error e = CheckSignature(data, size, kMessageTypeChallenge);
    if (!e.ok()) return e;
    if (size < kChallengeHeaderSize) return Fail(Status::kTruncated, "challenge header");
    flags = LoadLe32(data + 20);
    std::memcpy(server_challenge.data(), data + 24, 8);

    SecBuf target;
    e = ReadSecBuf(data, size, 12, kChallengeHeaderSize, target);
    if (!e.ok()) return e;
    if ((target.len % 2) != 0) return Fail(Status::kMalformed, "odd UTF-16 length");
    target_name = Utf16LeToString(data + target.offset, target.len);

    SecBuf av;
    e = ReadSecBuf(data, size, 40, kChallengeHeaderSize, av);
    if (!e.ok()) return e;
    av_pairs.clear();
    if (av.len != 0) {
        e = DecodeAvPairs(data + av.offset, av.len, av_pairs);
        if (!e.ok()) return e;
    }
    return Ok();
}

Error ChallengeMessage::FindAvPair(AvId id, Bytes& value) const {
    for (const auto& p : av_pairs) {
        if (p.id == id) {
            value = p.value;
            return Ok();
        }
    }
    return Fail(Status::kUnsupported, "av pair not present");
}

// ---- AuthenticateMessage --------------------------------------------------

Error AuthenticateMessage::Encode(Bytes& out) const {
    const Bytes domain_u = crypto::Utf16Le(domain);
    const Bytes user_u = crypto::Utf16Le(user);
    const Bytes ws_u = crypto::Utf16Le(workstation);

    out.assign(kAuthenticateHeaderSize, 0);
    std::memcpy(out.data(), kSignature, 8);
    StoreLe32(out.data() + 8, kMessageTypeAuthenticate);

    size_t off = kAuthenticateHeaderSize;
    auto emit = [&](const Bytes& v, size_t field) {
        WriteSecBuf(out.data() + field, v.size(), static_cast<uint32_t>(off));
        out.insert(out.end(), v.begin(), v.end());
        off += v.size();
    };
    emit(lm_response, 12);
    emit(nt_response, 20);
    emit(domain_u, 28);
    emit(user_u, 36);
    emit(ws_u, 44);
    emit(encrypted_random_session_key, 52);

    StoreLe32(out.data() + 60, flags);
    // Version at 64..71 stays zero.
    if (mic_is_set) std::memcpy(out.data() + 72, mic.data(), 16);
    return Ok();
}

Error AuthenticateMessage::Decode(const uint8_t* data, size_t size) {
    Error e = CheckSignature(data, size, kMessageTypeAuthenticate);
    if (!e.ok()) return e;
    if (size < kAuthenticateHeaderSize) {
        return Fail(Status::kTruncated, "authenticate header");
    }
    SecBuf lm, nt, dom, usr, ws, key;
    const size_t fields[] = {12, 20, 28, 36, 44, 52};
    SecBuf* targets[] = {&lm, &nt, &dom, &usr, &ws, &key};
    for (size_t i = 0; i < 6; ++i) {
        e = ReadSecBuf(data, size, fields[i], kAuthenticateHeaderSize, *targets[i]);
        if (!e.ok()) return e;
    }
    if ((dom.len % 2) != 0 || (usr.len % 2) != 0 || (ws.len % 2) != 0) {
        return Fail(Status::kMalformed, "odd UTF-16 length");
    }
    lm_response.assign(data + lm.offset, data + lm.offset + lm.len);
    nt_response.assign(data + nt.offset, data + nt.offset + nt.len);
    domain = Utf16LeToString(data + dom.offset, dom.len);
    user = Utf16LeToString(data + usr.offset, usr.len);
    workstation = Utf16LeToString(data + ws.offset, ws.len);
    encrypted_random_session_key.assign(data + key.offset, data + key.offset + key.len);
    flags = LoadLe32(data + 60);
    std::memcpy(mic.data(), data + 72, 16);
    mic_is_set = true;
    return Ok();
}

// ---- NTLMv2 ---------------------------------------------------------------

Bytes Ntowfv2(const std::string& password, const std::string& user,
              const std::string& domain) {
    const Bytes password_utf16 = crypto::Utf16Le(password);
    const std::array<uint8_t, 16> nt_hash =
        crypto::Md4(password_utf16.data(), password_utf16.size());
    std::string upper = user;
    for (char& c : upper) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    const Bytes identity = crypto::Utf16Le(upper + domain);
    const auto digest = crypto::HmacMd5(nt_hash.data(), nt_hash.size(),
                                       identity.data(), identity.size());
    return Bytes(digest.begin(), digest.end());
}

Error ComputeNtlmV2(const NtlmV2Inputs& in, NtlmV2Output& out) {
    out = NtlmV2Output{};
    if (in.server_challenge.size() != 8) {
        return Fail(Status::kMalformed, "server challenge must be 8 bytes");
    }
    if (in.client_challenge.size() != 8) {
        return Fail(Status::kMalformed, "client challenge must be 8 bytes");
    }
    if (in.timestamp.size() != 8) {
        return Fail(Status::kMalformed, "timestamp must be 8 bytes");
    }
    // The anonymous special case in [MS-NLMP] 3.3.2 produces a response that
    // CredSSP never wants; sending it would look like a malformed attempt.
    if (in.user.empty() || in.password.empty()) {
        return Fail(Status::kUnsupported, "empty credentials are not supported");
    }

    const Bytes response_key = Ntowfv2(in.password, in.user, in.domain);

    // temp = RespType(1) || HiRespType(1) || Z(6) || Time(8) ||
    //        ClientChallenge(8) || Z(4) || ServerName || Z(4)
    Bytes temp;
    temp.push_back(1);
    temp.push_back(1);
    temp.insert(temp.end(), 6, 0);
    temp.insert(temp.end(), in.timestamp.begin(), in.timestamp.end());
    temp.insert(temp.end(), in.client_challenge.begin(), in.client_challenge.end());
    temp.insert(temp.end(), 4, 0);
    temp.insert(temp.end(), in.target_info.begin(), in.target_info.end());
    temp.insert(temp.end(), 4, 0);

    Bytes proof_input = in.server_challenge;
    proof_input.insert(proof_input.end(), temp.begin(), temp.end());
    const auto proof = crypto::HmacMd5(response_key.data(), response_key.size(),
                                       proof_input.data(), proof_input.size());
    out.nt_proof_str.assign(proof.begin(), proof.end());
    out.nt_response = out.nt_proof_str;
    out.nt_response.insert(out.nt_response.end(), temp.begin(), temp.end());

    if (in.suppress_lm_response) {
        out.lm_response.assign(24, 0);
    } else {
        Bytes lm_input = in.server_challenge;
        lm_input.insert(lm_input.end(), in.client_challenge.begin(),
                        in.client_challenge.end());
        const auto lm = crypto::HmacMd5(response_key.data(), response_key.size(),
                                        lm_input.data(), lm_input.size());
        out.lm_response.assign(lm.begin(), lm.end());
        out.lm_response.insert(out.lm_response.end(), in.client_challenge.begin(),
                               in.client_challenge.end());
    }

    const auto sbk = crypto::HmacMd5(response_key.data(), response_key.size(),
                                     out.nt_proof_str.data(),
                                     out.nt_proof_str.size());
    out.session_base_key.assign(sbk.begin(), sbk.end());
    return Ok();
}

// ---- Session security -----------------------------------------------------

namespace {
constexpr char kSignMagicClient[] =
    "session key to client-to-server signing key magic constant";
constexpr char kSignMagicServer[] =
    "session key to server-to-client signing key magic constant";
constexpr char kSealMagicClient[] =
    "session key to client-to-server sealing key magic constant";
constexpr char kSealMagicServer[] =
    "session key to server-to-client sealing key magic constant";

Bytes Md5Of(const Bytes& a, const char* cstr) {
    // The magic constants are null terminated; the NUL is part of the hash
    // input, so the length is strlen + 1.
    Bytes input = a;
    const size_t n = std::strlen(cstr);
    input.insert(input.end(), cstr, cstr + n + 1);
    const auto d = crypto::Md5(input.data(), input.size());
    return Bytes(d.begin(), d.end());
}
}  // namespace

Bytes DeriveSigningKey(const Bytes& exported_session_key, bool server_to_client) {
    return Md5Of(exported_session_key,
                 server_to_client ? kSignMagicServer : kSignMagicClient);
}

Bytes DeriveSealingKey(const Bytes& exported_session_key, bool use_56_bit,
                       bool server_to_client) {
    Bytes src = exported_session_key;
    if (use_56_bit && src.size() > 7) src.resize(7);
    return Md5Of(src, server_to_client ? kSealMagicServer : kSealMagicClient);
}

Bytes Rc4Crypt(const Bytes& key, const Bytes& data) {
    crypto::Rc4 rc4(key);
    return rc4.Apply(data);
}

Error Seal(const Bytes& sealing_key, const Bytes& signing_key, uint32_t seq_num,
           const Bytes& message, SealedMessage& out) {
    out = SealedMessage{};
    // One RC4 instance for both steps: the checksum is encrypted on the stream
    // that the message just advanced. A fresh instance gives a different value
    // and the peer rejects the signature.
    crypto::Rc4 rc4(sealing_key);
    out.ciphertext = rc4.Apply(message);

    Bytes mac_input(4, 0);
    StoreLe32(mac_input.data(), seq_num);
    mac_input.insert(mac_input.end(), message.begin(), message.end());
    const auto hmac = crypto::HmacMd5(signing_key.data(), signing_key.size(),
                                      mac_input.data(), mac_input.size());
    const Bytes mac8(hmac.begin(), hmac.begin() + 8);
    const Bytes checksum = rc4.Apply(mac8);

    StoreLe32(out.signature.data(), 1);  // Version
    std::memcpy(out.signature.data() + 4, checksum.data(), 8);
    StoreLe32(out.signature.data() + 12, seq_num);
    return Ok();
}

std::array<uint8_t, 16> ComputeMic(const Bytes& exported_session_key,
                                   const Bytes& negotiate,
                                   const Bytes& challenge,
                                   const Bytes& authenticate) {
    // The MIC field inside AUTHENTICATE_MESSAGE must be zero during the
    // computation, otherwise recomputing after filling it in would disagree.
    Bytes auth = authenticate;
    if (auth.size() >= kAuthenticateHeaderSize) {
        std::fill(auth.begin() + 72, auth.begin() + 88, static_cast<uint8_t>(0));
    }
    Bytes input = negotiate;
    input.insert(input.end(), challenge.begin(), challenge.end());
    input.insert(input.end(), auth.begin(), auth.end());
    return crypto::HmacMd5(exported_session_key.data(), exported_session_key.size(),
                           input.data(), input.size());
}

}  // namespace rtsc::credssp
