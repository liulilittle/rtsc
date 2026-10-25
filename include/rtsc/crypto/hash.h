#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rtsc::crypto {

using Bytes = std::vector<uint8_t>;

// ---- MD4 ([RFC 1320]) -----------------------------------------------------
// Needed only for the NTLM password hash (NTOWFv1/NTOWFv2). Windows still
// uses MD4 here, so a "modern" replacement would break authentication.
std::array<uint8_t, 16> Md4(const uint8_t* data, size_t size);
inline std::array<uint8_t, 16> Md4(const Bytes& data) {
    return Md4(data.data(), data.size());
}

// ---- MD5 ([RFC 1321]) -----------------------------------------------------
std::array<uint8_t, 16> Md5(const uint8_t* data, size_t size);
inline std::array<uint8_t, 16> Md5(const Bytes& data) {
    return Md5(data.data(), data.size());
}

// ---- SHA-1 ([RFC 3174]) ---------------------------------------------------
std::array<uint8_t, 20> Sha1(const uint8_t* data, size_t size);
inline std::array<uint8_t, 20> Sha1(const Bytes& data) {
    return Sha1(data.data(), data.size());
}

// ---- SHA-256 ([FIPS 180-4]) -----------------------------------------------
// Required by CredSSP version 5 and 6, where the public key binding value is
// SHA256(magic || nonce || SubjectPublicKey). Not used by RDP security itself,
// so it is deliberately not shared with the SHA-1 code path.
std::array<uint8_t, 32> Sha256(const uint8_t* data, size_t size);
inline std::array<uint8_t, 32> Sha256(const Bytes& data) {
    return Sha256(data.data(), data.size());
}

// ---- HMAC-MD5 ([RFC 2104]) ------------------------------------------------
std::array<uint8_t, 16> HmacMd5(const uint8_t* key, size_t key_size,
                                const uint8_t* data, size_t data_size);
inline std::array<uint8_t, 16> HmacMd5(const Bytes& key, const Bytes& data) {
    return HmacMd5(key.data(), key.size(), data.data(), data.size());
}

// ---- RC4 ([MS-RDPBCGR] 5.1.3 / [MS-NLMP] 3.4.4.2) -------------------------
// A stateful stream cipher: the keystream continues across calls, which is
// required both by the licensing MAC/encrypt pair and by NTLM SEAL.
class Rc4 {
public:
    Rc4() = default;
    Rc4(const uint8_t* key, size_t key_size);
    explicit Rc4(const Bytes& key);

    // Re-keys and resets the keystream to its start.
    void Init(const uint8_t* key, size_t key_size);

    // XORs `size` bytes in place and advances the keystream.
    void Apply(uint8_t* data, size_t size);
    Bytes Apply(const Bytes& data);

    // Discards `size` keystream bytes without producing output.
    void Skip(size_t size);

private:
    uint8_t s_[256] = {};
    uint8_t i_ = 0;
    uint8_t j_ = 0;
};

// ---- Helpers --------------------------------------------------------------

// UTF-16LE encoding of an ASCII/UTF-8 string without a terminator, as used by
// NTLM for the password, user name, and domain.
Bytes Utf16Le(const std::string& text);

// Concatenates byte ranges.
Bytes Concat(const Bytes& a, const Bytes& b);
Bytes Concat(const Bytes& a, const Bytes& b, const Bytes& c);
Bytes Concat(const Bytes& a, const Bytes& b, const Bytes& c, const Bytes& d);

}  // namespace rtsc::crypto
