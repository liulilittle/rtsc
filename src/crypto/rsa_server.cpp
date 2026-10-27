// Server-side RSA keypair implementation (BCrypt / Windows).

#include "rtsc/crypto/rsa_server.h"

#if defined(_WIN32)

#include <windows.h>

#include <bcrypt.h>

#include <cstring>
#include <utility>

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif

namespace rtsc::crypto {
namespace {

void PushU16le(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x));
    v.push_back(static_cast<uint8_t>(x >> 8));
}

void PushU32le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x));
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x >> 16));
    v.push_back(static_cast<uint8_t>(x >> 24));
}

std::vector<uint8_t> StripLeadingZeros(std::vector<uint8_t> v) {
    size_t i = 0;
    while (i < v.size() && v[i] == 0) ++i;
    if (i != 0) v.erase(v.begin(), v.begin() + static_cast<ptrdiff_t>(i));
    return v;
}

}  // namespace

RsaServerKeyPair::~RsaServerKeyPair() { Close(); }

RsaServerKeyPair::RsaServerKeyPair(RsaServerKeyPair&& other) noexcept
    : alg_(other.alg_),
      key_(other.key_),
      bits_(other.bits_),
      modulus_(std::move(other.modulus_)),
      exponent_(std::move(other.exponent_)) {
    other.alg_ = nullptr;
    other.key_ = nullptr;
    other.bits_ = 0;
}

RsaServerKeyPair& RsaServerKeyPair::operator=(RsaServerKeyPair&& other) noexcept {
    if (this != &other) {
        Close();
        alg_ = other.alg_;
        key_ = other.key_;
        bits_ = other.bits_;
        modulus_ = std::move(other.modulus_);
        exponent_ = std::move(other.exponent_);
        other.alg_ = nullptr;
        other.key_ = nullptr;
        other.bits_ = 0;
    }
    return *this;
}

void RsaServerKeyPair::Close() noexcept {
    if (key_ != nullptr) {
        BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(key_));
        key_ = nullptr;
    }
    if (alg_ != nullptr) {
        BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(alg_), 0);
        alg_ = nullptr;
    }
    bits_ = 0;
    modulus_.clear();
    exponent_.clear();
}

bool RsaServerKeyPair::Generate(uint32_t bits) {
    Close();
    if (bits < 512 || bits % 8 != 0) return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(st)) return false;

    BCRYPT_KEY_HANDLE key = nullptr;
    st = BCryptGenerateKeyPair(alg, &key, static_cast<ULONG>(bits), 0);
    if (NT_SUCCESS(st)) st = BCryptFinalizeKeyPair(key, 0);
    if (!NT_SUCCESS(st)) {
        if (key != nullptr) BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    ULONG written = 0;
    st = BCryptExportKey(key, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &written, 0);
    if (!NT_SUCCESS(st) || written < sizeof(BCRYPT_RSAKEY_BLOB)) {
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }
    std::vector<uint8_t> blob(written);
    st = BCryptExportKey(key, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(),
                         static_cast<ULONG>(blob.size()), &written, 0);
    if (!NT_SUCCESS(st) || written != blob.size()) {
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    BCRYPT_RSAKEY_BLOB hdr{};
    std::memcpy(&hdr, blob.data(), sizeof(hdr));
    if (hdr.Magic != BCRYPT_RSAPUBLIC_MAGIC || hdr.cbModulus == 0 ||
        hdr.cbPublicExp == 0 ||
        sizeof(hdr) + hdr.cbPublicExp + hdr.cbModulus != blob.size()) {
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    std::vector<uint8_t> exponent(blob.begin() + sizeof(hdr),
                                  blob.begin() + sizeof(hdr) + hdr.cbPublicExp);
    std::vector<uint8_t> modulus(blob.begin() + sizeof(hdr) + hdr.cbPublicExp,
                                 blob.begin() + sizeof(hdr) + hdr.cbPublicExp +
                                     hdr.cbModulus);

    exponent_ = StripLeadingZeros(std::move(exponent));
    modulus_ = StripLeadingZeros(std::move(modulus));
    bits_ = static_cast<uint32_t>(hdr.BitLength);
    alg_ = alg;
    key_ = key;
    return true;
}

std::vector<uint8_t> RsaServerKeyPair::WirePublicKey() const {
    std::vector<uint8_t> out;
    if (modulus_.empty()) return out;

    const uint32_t modulus_bytes = bits_ / 8;
    const uint32_t keylen = modulus_bytes + 8;
    const uint32_t datalen = modulus_bytes - 1;
    uint32_t pub_exp = 0;
    for (uint8_t b : exponent_) pub_exp = (pub_exp << 8) | b;

    PushU32le(out, 0x31415352);  // "RSA1"
    PushU32le(out, keylen);
    PushU32le(out, bits_);
    PushU32le(out, datalen);
    PushU32le(out, pub_exp);
    // The wire modulus is little-endian.
    out.insert(out.end(), modulus_.rbegin(), modulus_.rend());
    for (int i = 0; i < 8; ++i) out.push_back(0);
    return out;
}

std::vector<uint8_t> RsaServerKeyPair::BuildCertificate() const {
    std::vector<uint8_t> out;
    const std::vector<uint8_t> public_key = WirePublicKey();
    if (public_key.empty()) return out;

    const uint32_t modulus_bytes = bits_ / 8;
    PushU32le(out, 1);  // dwVersion = CERT_CHAIN_VERSION_1
    PushU32le(out, 1);  // dwSigAlgId = SIGNATURE_ALG_RSA
    PushU32le(out, 1);  // dwKeyAlgId = KEY_EXCHANGE_ALG_RSA
    PushU16le(out, 6);  // wPublicKeyBlobType = BB_RSA_KEY_BLOB
    PushU16le(out, static_cast<uint16_t>(public_key.size()));
    out.insert(out.end(), public_key.begin(), public_key.end());
    PushU16le(out, 8);  // wSignatureBlobType = BB_RSA_SIGNATURE_BLOB
    PushU16le(out, static_cast<uint16_t>(modulus_bytes + 8));
    out.insert(out.end(), modulus_bytes + 8, 0);  // placeholder signature
    return out;
}

bool RsaServerKeyPair::DecryptClientRandom(const std::vector<uint8_t>& in,
                                           std::vector<uint8_t>& out) {
    out.clear();
    if (key_ == nullptr || bits_ == 0) return false;
    const size_t modulus_size = bits_ / 8;
    if (in.size() < modulus_size) return false;

    std::vector<uint8_t> cipher(in.begin(),
                                in.begin() + static_cast<ptrdiff_t>(modulus_size));
    std::vector<uint8_t> plain(modulus_size, 0);
    ULONG written = 0;
    const NTSTATUS st = BCryptDecrypt(
        static_cast<BCRYPT_KEY_HANDLE>(key_), cipher.data(),
        static_cast<ULONG>(cipher.size()), nullptr, nullptr, 0, plain.data(),
        static_cast<ULONG>(plain.size()), &written, BCRYPT_PAD_NONE);
    if (!NT_SUCCESS(st) || written != modulus_size) return false;

    // plain is big-endian; RDP interprets the client random as little-endian.
    out.assign(32, 0);
    for (size_t i = 0; i < 32; ++i) {
        out[i] = plain[modulus_size - 1 - i];
    }
    return true;
}

bool RsaServerKeyPair::DecryptRaw(const std::vector<uint8_t>& in,
                                  std::vector<uint8_t>& out) {
    out.clear();
    if (key_ == nullptr || bits_ == 0) return false;
    const size_t modulus_size = bits_ / 8;
    if (in.size() < modulus_size) return false;

    std::vector<uint8_t> cipher(in.begin(),
                                in.begin() + static_cast<ptrdiff_t>(modulus_size));
    std::vector<uint8_t> plain(modulus_size, 0);
    ULONG written = 0;
    const NTSTATUS st = BCryptDecrypt(
        static_cast<BCRYPT_KEY_HANDLE>(key_), cipher.data(),
        static_cast<ULONG>(cipher.size()), nullptr, nullptr, 0, plain.data(),
        static_cast<ULONG>(plain.size()), &written, BCRYPT_PAD_NONE);
    if (!NT_SUCCESS(st) || written != modulus_size) return false;

    // plain is big-endian; RDP interprets the plaintext as little-endian.
    out.assign(modulus_size, 0);
    for (size_t i = 0; i < modulus_size; ++i) {
        out[i] = plain[modulus_size - 1 - i];
    }
    return true;
}

}  // namespace rtsc::crypto

#endif  // _WIN32
