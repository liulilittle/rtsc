// RSA primitive for the RDP "encrypt client random" operation.
//
// Reference: [MS-RDPBCGR] 5.3.4.1 (Encrypting Client Random).
//
// This is deliberately NOT PKCS#1: RDP performs raw RSA, c = r^e mod n, and
// interprets the input as an unsigned little-endian integer. The ciphertext is
// copied into a zeroed buffer of (bitlen / 8) + 8 bytes, so the last 8 bytes are
// always zero. Getting any of these three details wrong produces a value the
// server cannot decrypt, and the failure surfaces only as a dropped connection.
//
// The primitive is implemented per platform (Windows = BCrypt). The interface
// stays free of platform types so licensing / Standard RDP Security compile
// unchanged everywhere.

#pragma once

#include <cstdint>
#include <vector>

namespace rtsc::crypto {

// An RSA public key. `modulus` and `exponent` are big-endian; the modulus may
// carry leading zero bytes, which are ignored when sizing the key.
struct RsaPublicKey {
    std::vector<uint8_t> modulus;   // big-endian
    std::vector<uint8_t> exponent;  // big-endian, e.g. {0x01, 0x00, 0x01}
};

// Encrypts `input` with the server's public key as described in
// [MS-RDPBCGR] 5.3.4.1:
//   * `input` is interpreted as an unsigned little-endian integer r;
//   * c = r^e mod n;
//   * `out` is (bitlen / 8) + 8 bytes: c (big-endian, modulus size) followed by
//     8 zero bytes.
// Returns false when the key is unusable or the input does not fit.
bool RdpRsaEncryptClientRandom(const RsaPublicKey& key,
                               const std::vector<uint8_t>& input,
                               std::vector<uint8_t>& out);

}  // namespace rtsc::crypto
