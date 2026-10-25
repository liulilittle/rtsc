// RDP raw-RSA primitive ([MS-RDPBCGR] 5.3.4.1).
//
// The key pair is generated in-process with BCrypt so the round trip is checked
// against an independent RSA implementation rather than a hand-copied constant.

#include "rtsc/crypto/rsa.h"

#include <cstring>
#include <vector>

#if defined(_WIN32)
#include <windows.h>

#include <bcrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#endif

#include "test_framework.h"
#include "test_main.h"

namespace {

#if defined(_WIN32)

struct TestKeyPair {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    std::vector<uint8_t> modulus_be;
    std::vector<uint8_t> exponent_be;
};

bool GenerateKeyPair(TestKeyPair& kp) {
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&kp.alg, BCRYPT_RSA_ALGORITHM,
                                                nullptr, 0))) {
        return false;
    }
    if (!NT_SUCCESS(BCryptGenerateKeyPair(kp.alg, &kp.key, 2048, 0))) return false;
    if (!NT_SUCCESS(BCryptFinalizeKeyPair(kp.key, 0))) return false;

    ULONG len = 0;
    if (!NT_SUCCESS(BCryptExportKey(kp.key, nullptr, BCRYPT_RSAPUBLIC_BLOB,
                                    nullptr, 0, &len, 0))) {
        return false;
    }
    std::vector<uint8_t> blob(len);
    if (!NT_SUCCESS(BCryptExportKey(kp.key, nullptr, BCRYPT_RSAPUBLIC_BLOB,
                                    blob.data(), len, &len, 0))) {
        return false;
    }

    BCRYPT_RSAKEY_BLOB hdr{};
    std::memcpy(&hdr, blob.data(), sizeof(hdr));
    const uint8_t* p = blob.data() + sizeof(hdr);
    kp.exponent_be.assign(p, p + hdr.cbPublicExp);
    kp.modulus_be.assign(p + hdr.cbPublicExp, p + hdr.cbPublicExp + hdr.cbModulus);
    return true;
}

// Raw RSA decrypt (c^d mod n). `cipher` must be the modulus size.
bool RawDecrypt(TestKeyPair& kp, std::vector<uint8_t>& cipher,
                std::vector<uint8_t>& out) {
    ULONG written = 0;
    out.assign(cipher.size(), 0);
    const NTSTATUS st =
        BCryptDecrypt(kp.key, cipher.data(), static_cast<ULONG>(cipher.size()),
                      nullptr, nullptr, 0, out.data(),
                      static_cast<ULONG>(out.size()), &written, BCRYPT_PAD_NONE);
    if (!NT_SUCCESS(st)) return false;
    out.resize(written);
    return true;
}

#endif  // _WIN32

}  // namespace

RTSC_TEST(rdp_rsa_encrypt_client_random_round_trip) {
#if defined(_WIN32)
    TestKeyPair kp;
    CHECK(GenerateKeyPair(kp));

    rtsc::crypto::RsaPublicKey pub;
    pub.modulus = kp.modulus_be;
    pub.exponent = kp.exponent_be;

    std::vector<uint8_t> client_random(32);
    for (size_t i = 0; i < client_random.size(); ++i) {
        client_random[i] = static_cast<uint8_t>(i * 7 + 1);
    }

    std::vector<uint8_t> enc;
    CHECK(rtsc::crypto::RdpRsaEncryptClientRandom(pub, client_random, enc));

    // (bitlen / 8) + 8 = 256 + 8 = 264.
    CHECK_EQ(enc.size(), static_cast<size_t>(264));
    for (size_t i = 256; i < 264; ++i) CHECK_EQ(enc[i], static_cast<uint8_t>(0));

    // Decrypt the ciphertext (the first 256 bytes) with the private key.
    std::vector<uint8_t> cipher(enc.begin(), enc.begin() + 256);
    std::vector<uint8_t> plain;
    CHECK(RawDecrypt(kp, cipher, plain));
    CHECK_EQ(plain.size(), static_cast<size_t>(256));

    // plain is big-endian; the client random occupies the low 32 bytes reversed.
    for (size_t i = 0; i < 32; ++i) {
        CHECK_EQ(plain[256 - 1 - i], client_random[i]);
    }
    for (size_t i = 0; i < 256 - 32; ++i) {
        CHECK_EQ(plain[i], static_cast<uint8_t>(0));
    }

    BCryptDestroyKey(kp.key);
    BCryptCloseAlgorithmProvider(kp.alg, 0);
#else
    CHECK(true);  // RSA is Windows-only for now
#endif
}

RTSC_TEST(rdp_rsa_rejects_empty_key) {
    rtsc::crypto::RsaPublicKey pub;
    std::vector<uint8_t> in = {1, 2, 3};
    std::vector<uint8_t> out;
    CHECK(!rtsc::crypto::RdpRsaEncryptClientRandom(pub, in, out));
    CHECK(out.empty());
}

int main() { return ::rtsc::test::run_all("rtsc_rsa_tests"); }
