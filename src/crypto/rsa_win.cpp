// Windows implementation of the RDP raw-RSA primitive (BCrypt).

#include "rtsc/crypto/rsa.h"

#if defined(_WIN32)

#include <windows.h>

#include <bcrypt.h>

#include <cstring>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace rtsc::crypto {
namespace {

// Builds a BCRYPT_RSAPUBLIC_BLOB from big-endian key components. Leading zero
// bytes are stripped from both the modulus and the exponent.
std::vector<uint8_t> BuildPublicKeyBlob(const RsaPublicKey& key) {
    size_t m_start = 0;
    while (m_start < key.modulus.size() && key.modulus[m_start] == 0) ++m_start;
    const size_t m_len = key.modulus.size() - m_start;

    size_t e_start = 0;
    while (e_start < key.exponent.size() && key.exponent[e_start] == 0) ++e_start;
    const size_t e_len = key.exponent.size() - e_start;

    if (m_len == 0 || e_len == 0) return {};

    BCRYPT_RSAKEY_BLOB hdr{};
    hdr.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    hdr.BitLength = static_cast<ULONG>(m_len * 8);
    hdr.cbPublicExp = static_cast<ULONG>(e_len);
    hdr.cbModulus = static_cast<ULONG>(m_len);
    hdr.cbPrime1 = 0;
    hdr.cbPrime2 = 0;

    std::vector<uint8_t> blob(sizeof(hdr));
    std::memcpy(blob.data(), &hdr, sizeof(hdr));
    blob.insert(blob.end(), key.exponent.begin() + static_cast<ptrdiff_t>(e_start),
                key.exponent.end());
    blob.insert(blob.end(), key.modulus.begin() + static_cast<ptrdiff_t>(m_start),
                key.modulus.end());
    return blob;
}

}  // namespace

bool RdpRsaEncryptClientRandom(const RsaPublicKey& key,
                               const std::vector<uint8_t>& input,
                               std::vector<uint8_t>& out) {
    out.clear();

    std::vector<uint8_t> blob = BuildPublicKeyBlob(key);
    if (blob.empty()) return false;

    BCRYPT_RSAKEY_BLOB hdr{};
    std::memcpy(&hdr, blob.data(), sizeof(hdr));
    const size_t modulus_size = hdr.cbModulus;
    if (modulus_size == 0 || input.size() > modulus_size) return false;

    // The input is a little-endian integer; BCrypt takes big-endian, left-padded
    // to the modulus size.
    std::vector<uint8_t> be(modulus_size, 0);
    for (size_t i = 0; i < input.size(); ++i) {
        be[modulus_size - 1 - i] = input[i];
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS st =
        BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(st)) return false;

    BCRYPT_KEY_HANDLE key_handle = nullptr;
    st = BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPUBLIC_BLOB, &key_handle,
                             blob.data(), static_cast<ULONG>(blob.size()), 0);
    if (!NT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    ULONG written = 0;
    std::vector<uint8_t> cipher(modulus_size);
    st = BCryptEncrypt(key_handle, be.data(), static_cast<ULONG>(be.size()),
                       nullptr, nullptr, 0, cipher.data(),
                       static_cast<ULONG>(cipher.size()), &written,
                       BCRYPT_PAD_NONE);
    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!NT_SUCCESS(st) || written != modulus_size) return false;

    // (bitlen / 8) + 8: the ciphertext followed by 8 zero bytes.
    out = cipher;
    out.resize(modulus_size + 8, 0);
    return true;
}

}  // namespace rtsc::crypto

#endif  // _WIN32
