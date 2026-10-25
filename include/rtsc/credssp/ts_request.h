// CredSSP message layer: TSRequest and TSCredentials.
//
// Reference: docs/spec/security-layer.md sections 5.1, 5.2, 5.5, 5.7.
//
// These structures are DER, but the server emits one non-canonical form in
// practice (errorCode as a raw 4-byte unsigned value without the leading 0x00
// that DER requires for a negative INTEGER). The decoder therefore accepts
// both spellings while the encoder always emits canonical DER.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rtsc::credssp {

using Bytes = std::vector<uint8_t>;

enum class Status : uint8_t {
    kOk = 0,
    kTruncated,       // input ended inside a TLV
    kMalformed,       // tag/length/structure violation
    kUnsupported,     // valid structure, value this implementation rejects
    kInternal,        // local environment failure (CSPRNG unavailable, etc.)
};

struct Error {
    Status status = Status::kOk;
    std::string message;
    // Peer-reported code when the failure came from the server (for example a
    // CredSSP errorCode such as STATUS_LOGON_FAILURE). Callers must be able to
    // surface it verbatim instead of guessing from the text.
    int32_t native_code = 0;
    bool ok() const noexcept { return status == Status::kOk; }
};

inline Error Ok() { return Error{}; }
inline Error Fail(Status s, std::string msg) {
    Error e;
    e.status = s;
    e.message = std::move(msg);
    return e;
}

// TSRequest ::= SEQUENCE {
//     version    [0] INTEGER,
//     negoTokens [1] NegoData  OPTIONAL,
//     authInfo   [2] OCTET STRING OPTIONAL,
//     pubKeyAuth [3] OCTET STRING OPTIONAL,
//     errorCode  [4] INTEGER OPTIONAL,
//     clientNonce [5] OCTET STRING OPTIONAL
// }
struct TsRequest {
    uint32_t version = 6;
    Bytes nego_token;  // contents of the innermost OCTET STRING
    Bytes auth_info;
    Bytes pub_key_auth;
    uint32_t error_code = 0;
    bool has_error_code = false;
    Bytes client_nonce;

    Error Encode(Bytes& out) const;
    Error Decode(const uint8_t* data, size_t size);
};

// TSCredentials ::= SEQUENCE { credType [0] INTEGER, credentials [1] OCTET STRING }
// TSPasswordCreds ::= SEQUENCE { domainName [0], userName [1], password [2] }
// All three strings are UTF-16LE.
struct PasswordCredentials {
    std::string domain;
    std::string user;
    std::string password;

    static constexpr uint32_t kCredTypePassword = 1;

    Error Encode(Bytes& out) const;
    Error Decode(const uint8_t* data, size_t size);
};

// DER helpers shared by the message encoders.
// Writes a context-specific constructed tag [n] wrapping the given content.
void WriteContextual(Bytes& out, uint8_t tag_number, const Bytes& content);
// Writes an OCTET STRING with definite length (short or long form).
void WriteOctetString(Bytes& out, const uint8_t* data, size_t size);
// Writes a non-negative INTEGER using the shortest content octets.
void WriteInteger(Bytes& out, uint32_t value);
// Writes a DER length field.
void WriteLength(Bytes& out, size_t length);

}  // namespace rtsc::credssp
