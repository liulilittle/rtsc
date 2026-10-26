// NTLM message layer (NEGOTIATE / CHALLENGE / AUTHENTICATE) plus the NTLMv2
// response computation and the SEAL/MIC primitives CredSSP needs.
//
// Reference: docs/spec/security-layer.md sections 6.1-6.7 and 7.1-7.5,
// citing [MS-NLMP] 2.2.1.x / 2.2.2.x / 3.3.2 / 3.4.3 / 3.4.4.2 / 3.4.5.x.
//
// Platform neutral: only the crypto primitives and the byte layout are used,
// so this compiles unchanged on Linux/Android/macOS.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/crypto/hash.h"
#include "rtsc/credssp/ts_request.h"

namespace rtsc::credssp {

// ---- NEGOTIATE flags ([MS-NLMP] 2.2.2.5) ---------------------------------
namespace ntlm_flag {
constexpr uint32_t kUnicode = 0x00000001u;
constexpr uint32_t kOem = 0x00000002u;
constexpr uint32_t kRequestTarget = 0x00000004u;
constexpr uint32_t kSign = 0x00000010u;
constexpr uint32_t kSeal = 0x00000020u;
constexpr uint32_t kDatagram = 0x00000040u;
constexpr uint32_t kLmKey = 0x00000080u;
constexpr uint32_t kNtlm = 0x00000200u;
constexpr uint32_t kAnonymous = 0x00000800u;
constexpr uint32_t kOemDomainSupplied = 0x00001000u;
constexpr uint32_t kOemWorkstationSupplied = 0x00002000u;
constexpr uint32_t kAlwaysSign = 0x00008000u;
constexpr uint32_t kTargetTypeDomain = 0x00010000u;
constexpr uint32_t kTargetTypeServer = 0x00020000u;
constexpr uint32_t kExtendedSessionSecurity = 0x00080000u;
constexpr uint32_t kIdentify = 0x00100000u;
constexpr uint32_t kRequestNonNtSessionKey = 0x00400000u;
constexpr uint32_t kTargetInfo = 0x00800000u;
constexpr uint32_t kVersion = 0x02000000u;
constexpr uint32_t k128 = 0x20000000u;
constexpr uint32_t kKeyExch = 0x40000000u;
constexpr uint32_t k56 = 0x80000000u;

// The set the client requests for CredSSP: everything needed for a modern
// NTLMv2 exchange with MIC and session security, and nothing that changes the
// credential semantics.
constexpr uint32_t kCredsspClient = kUnicode | kRequestTarget | kSign | kSeal |
                                    kNtlm | kAlwaysSign | kExtendedSessionSecurity |
                                    kTargetInfo | kVersion | k128 | kKeyExch | k56;
}  // namespace ntlm_flag

// ---- AV_PAIR ([MS-NLMP] 2.2.2.1) -----------------------------------------
enum class AvId : uint16_t {
    kEol = 0x0000,
    kNbComputerName = 0x0001,
    kNbDomainName = 0x0002,
    kDnsComputerName = 0x0003,
    kDnsDomainName = 0x0004,
    kDnsTreeName = 0x0005,
    kFlags = 0x0006,
    kTimestamp = 0x0007,
    kSingleHost = 0x0008,
    kTargetName = 0x0009,
    kChannelBindings = 0x000A,
};

struct AvPair {
    AvId id = AvId::kEol;
    Bytes value;
};

// ---- Messages -------------------------------------------------------------
struct NegotiateMessage {
    uint32_t flags = ntlm_flag::kCredsspClient;
    Error Encode(Bytes& out) const;
    Error Decode(const uint8_t* data, size_t size);
};

struct ChallengeMessage {
    uint32_t flags = 0;
    std::array<uint8_t, 8> server_challenge{};
    std::string target_name;
    std::vector<AvPair> av_pairs;
    // NTLM version (written only when flags carries NTLMSSP_NEGOTIATE_VERSION).
    // A zero version while the flag is set is what a real client rejects.
    uint8_t version_major = 0x0A;
    uint8_t version_minor = 0x00;
    uint16_t version_build = 0x4563;
    uint8_t version_revision = 0x0F;

    Error Encode(Bytes& out) const;
    Error Decode(const uint8_t* data, size_t size);
    // Looks up one AV pair. Returns kUnsupported when absent, which callers
    // must treat as "not provided" rather than "empty value".
    Error FindAvPair(AvId id, Bytes& value) const;
};

struct AuthenticateMessage {
    uint32_t flags = 0;
    std::string domain;
    std::string user;
    std::string workstation;
    Bytes lm_response;
    Bytes nt_response;
    Bytes encrypted_random_session_key;
    std::array<uint8_t, 16> mic{};
    bool mic_is_set = false;

    Error Encode(Bytes& out) const;
    Error Decode(const uint8_t* data, size_t size);
};

// ---- NTLMv2 response ([MS-NLMP] 3.3.2) -----------------------------------
struct NtlmV2Inputs {
    std::string user;
    std::string domain;
    std::string password;
    Bytes server_challenge;  // exactly 8 bytes
    Bytes client_challenge;  // exactly 8 bytes
    Bytes timestamp;         // exactly 8 bytes, little endian FILETIME
    Bytes target_info;       // AV_PAIR sequence, without the trailing EOL
    // When the CHALLENGE carries MsvAvTimestamp the client SHOULD send Z(24)
    // instead of an LMv2 response.
    bool suppress_lm_response = false;
};

struct NtlmV2Output {
    Bytes nt_proof_str;      // 16 bytes
    Bytes nt_response;       // NTProofStr || NTLMv2_CLIENT_CHALLENGE
    Bytes lm_response;       // 24 bytes
    Bytes session_base_key;  // 16 bytes
};

// NTOWFv2(Passwd, User, UserDom) = HMAC_MD5(MD4(UNICODE(Passwd)),
//                                          UNICODE(Uppercase(User) || UserDom))
Bytes Ntowfv2(const std::string& password, const std::string& user,
              const std::string& domain);

Error ComputeNtlmV2(const NtlmV2Inputs& in, NtlmV2Output& out);

// ---- Session security ([MS-NLMP] 3.4.5) ----------------------------------
// `use_56_bit` selects the 56-bit sealing key derivation (exported[0..6]).
Bytes DeriveSigningKey(const Bytes& exported_session_key, bool server_to_client);
Bytes DeriveSealingKey(const Bytes& exported_session_key, bool use_56_bit,
                       bool server_to_client = false);

struct SealedMessage {
    Bytes ciphertext;
    std::array<uint8_t, 16> signature{};  // Version(4) | Checksum(8) | SeqNum(4)
};

// SEAL: RC4(SealingKey, Message), then RC4(HMAC_MD5(SigningKey, SeqNum ||
// Message)[0..7]) on the SAME RC4 stream. Getting a fresh RC4 instance for the
// checksum is the single most common implementation mistake.
Error Seal(const Bytes& sealing_key, const Bytes& signing_key, uint32_t seq_num,
           const Bytes& message, SealedMessage& out);

// MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE)
// with the AUTHENTICATE MIC field zeroed.
std::array<uint8_t, 16> ComputeMic(const Bytes& exported_session_key,
                                   const Bytes& negotiate,
                                   const Bytes& challenge,
                                   const Bytes& authenticate);

// Bare RC4 (no MAC), used for EncryptedRandomSessionKey.
Bytes Rc4Crypt(const Bytes& key, const Bytes& data);

}  // namespace rtsc::credssp
