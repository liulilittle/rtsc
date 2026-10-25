// Server-side RSA keypair for standard RDP security.
//
// Reference: [MS-RDPBCGR] 2.2.1.4.3.1 (server certificate), 5.3.4 (encrypting
// the client random), 5.4.4 (decrypting it), [MS-RDPELE] 2.2.2.1 (licensing
// Server License Request certificate).
//
// The client encrypts its 32-byte client random with the server's public key
// using raw RSA (c = r^e mod n, little-endian r). The server decrypts with the
// private key and recovers the little-endian random. Standard RDP security
// does NOT validate the server certificate signature (that is a Terminal
// Services licensing concept), so the signature blob emitted here is a
// correctly sized placeholder.
//
// The handle type is kept opaque so this header stays free of windows.h, which
// lets the Linux build compile the server sources unchanged (the Windows
// implementation is the only platform that can actually serve a connection).

#pragma once

#include <cstdint>
#include <vector>

namespace rtsc::crypto {

class RsaServerKeyPair {
 public:
    RsaServerKeyPair() = default;
    ~RsaServerKeyPair();

    RsaServerKeyPair(RsaServerKeyPair&& other) noexcept;
    RsaServerKeyPair& operator=(RsaServerKeyPair&& other) noexcept;
    RsaServerKeyPair(const RsaServerKeyPair&) = delete;
    RsaServerKeyPair& operator=(const RsaServerKeyPair&) = delete;

    // Generates a fresh keypair. `bits` is the modulus size (512 is the value
    // the reference Windows server uses; 1024/2048 are also accepted by the
    // client). Returns false when the platform provider is unavailable.
    bool Generate(uint32_t bits);

    uint32_t bits() const noexcept { return bits_; }

    // Big-endian modulus and public exponent (e.g. {0x01, 0x00, 0x01}).
    const std::vector<uint8_t>& modulus() const noexcept { return modulus_; }
    const std::vector<uint8_t>& exponent() const noexcept { return exponent_; }

    // The PROPRIETARYSERVERCERTIFICATE blob for the Server Security Data and
    // the licensing Server License Request. Empty when no key is loaded.
    std::vector<uint8_t> BuildCertificate() const;

    // The RSA_PUBLIC_KEY wire blob (little-endian modulus + 8 zero bytes),
    // matching rtsc::proto::RsaPublicKey::encode().
    std::vector<uint8_t> WirePublicKey() const;

    // Decrypts the RSA-encrypted client random. `in` is the (bitlen/8)+8 byte
    // buffer from the Client Security Exchange PDU; the trailing 8 bytes are
    // ignored. On success `out` holds the 32-byte client random.
    bool DecryptClientRandom(const std::vector<uint8_t>& in,
                             std::vector<uint8_t>& out);

 private:
    void Close() noexcept;

    void* alg_ = nullptr;  // BCRYPT_ALG_HANDLE
    void* key_ = nullptr;  // BCRYPT_KEY_HANDLE
    uint32_t bits_ = 0;
    std::vector<uint8_t> modulus_;   // big-endian
    std::vector<uint8_t> exponent_;  // big-endian
};

}  // namespace rtsc::crypto
