// Standard RDP Security session keys ([MS-RDPBCGR] 5.3.5).
//
// Reference: docs/spec/security-layer.md section 5.3; [MS-RDPBCGR] 5.3.5.1
// (Non-FIPS). The algorithm was cross-checked against FreeRDP's
// libfreerdp/core/security.c (security_establish_keys / security_A / security_X).
//
// Two details differ from the licensing L3 derivation and are easy to conflate:
//   * the pre-master secret is First192Bits(ClientRandom) || First192Bits(ServerRandom);
//   * the session key blob uses the SAME SaltedHash ordering (ClientRandom then
//     ServerRandom) with the identifiers 'X' / 'YY' / 'ZZ', whereas licensing
//     uses the swapped ordering with 'A' / 'BB' / 'CCC'.
//
// The MAC key ("sign key"), the client-to-server encryption key and the
// server-to-client decryption key are produced here. Encryption itself is RC4
// (crypto::Rc4); this module only derives the keys and the MAC signature.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/crypto/hash.h"

namespace rtsc::crypto {

// encryptionMethod from TS_UD_SC_SEC1 ([MS-RDPBCGR] 2.2.1.4.3).
enum class RdpEncryptionMethod : uint32_t {
    kNone = 0x00000000,
    k40Bit = 0x00000001,
    k56Bit = 0x00000002,
    k128Bit = 0x00000008,
    kFips = 0x00000010,
};

struct RdpSessionKeys {
    // MAC key ("sign key"): 8 bytes for 40/56-bit, 16 bytes for 128-bit.
    std::vector<uint8_t> mac_key;
    // Client-to-server key (client encrypts with it, server decrypts).
    std::vector<uint8_t> encrypt_key;
    // Server-to-client key (server encrypts with it, client decrypts).
    std::vector<uint8_t> decrypt_key;
    // RC4 key length actually used: 8 (40/56-bit) or 16 (128-bit).
    size_t rc4_key_len = 16;
    // The negotiated encryption method, needed by the periodic key update.
    uint32_t method = 0;
};

// Derives the session keys. `client_random` and `server_random` must be 32 bytes
// each. Returns keys with empty fields when the method is unsupported.
RdpSessionKeys DeriveRdpSessionKeys(const std::vector<uint8_t>& client_random,
                                    const std::vector<uint8_t>& server_random,
                                    uint32_t encryption_method);

// MAC signature ([MS-RDPBCGR] 5.3.5.1, security_mac_signature):
//   First64Bits(MD5(MACKey + pad2 + SHA1(MACKey + pad1 + LE32(len) + data)))
// with pad1 = 40 x 0x36 and pad2 = 48 x 0x5C.
std::array<uint8_t, 8> RdpMacSignature(const std::vector<uint8_t>& mac_key,
                                       const std::vector<uint8_t>& data);

// Stateful Standard RDP Security encryptor/decryptor ([MS-RDPBCGR] 5.3.6).
//
// One instance per connection. It owns the two RC4 streams (one per direction)
// and the per-direction packet counters used for the mandatory key update every
// 4096 packets. Encrypt/Decrypt operate on the data that follows the security
// header; the caller writes/reads the 8-byte MAC in the header.
class RdpSecurityContext {
 public:
    RdpSecurityContext() = default;

    // `keys` must come from DeriveRdpSessionKeys. Both directions are set up:
    // the client sends with encrypt_key and receives with decrypt_key.
    void Init(const RdpSessionKeys& keys);

    // Encrypts `data` in place (RC4) and returns the 8-byte MAC, which is
    // computed over the *plaintext* and goes into the security header.
    std::array<uint8_t, 8> Encrypt(std::vector<uint8_t>& data);

    // Decrypts `data` in place after verifying `mac`. Returns false when the
    // MAC does not match (the caller must drop the connection).
    bool Decrypt(std::vector<uint8_t>& data, const std::array<uint8_t, 8>& mac);

    uint32_t send_count() const noexcept { return send_count_; }
    uint32_t recv_count() const noexcept { return recv_count_; }

 private:
    void UpdateSendKey();
    void UpdateRecvKey();

    RdpSessionKeys keys_;
    Rc4 send_rc4_;
    Rc4 recv_rc4_;
    std::vector<uint8_t> send_update_key_;
    std::vector<uint8_t> recv_update_key_;
    uint32_t send_count_ = 0;
    uint32_t recv_count_ = 0;
    bool initialized_ = false;
};

}  // namespace rtsc::crypto
