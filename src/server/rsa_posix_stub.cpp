// POSIX stub for the server-side RSA keypair.
//
// The real backend is BCrypt (rsa_server.cpp, Windows only). On a platform with
// no backend this stub fails closed: Generate() returns false, so the server
// falls back to "no encryption" instead of serving with a broken key. The
// declarations live in rtsc/crypto/rsa_server.h, which stays free of any
// platform header.

#include "rtsc/crypto/rsa_server.h"

#if !defined(_WIN32)

namespace rtsc::crypto {

RsaServerKeyPair::~RsaServerKeyPair() = default;

RsaServerKeyPair::RsaServerKeyPair(RsaServerKeyPair&& other) noexcept = default;
RsaServerKeyPair& RsaServerKeyPair::operator=(RsaServerKeyPair&& other) noexcept =
    default;

bool RsaServerKeyPair::Generate(uint32_t /*bits*/) { return false; }

std::vector<uint8_t> RsaServerKeyPair::BuildCertificate() const { return {}; }

std::vector<uint8_t> RsaServerKeyPair::WirePublicKey() const { return {}; }

bool RsaServerKeyPair::DecryptClientRandom(const std::vector<uint8_t>& /*in*/,
                                           std::vector<uint8_t>& out) {
    out.clear();
    return false;
}

bool RsaServerKeyPair::DecryptRaw(const std::vector<uint8_t>& /*in*/,
                                  std::vector<uint8_t>& out) {
    out.clear();
    return false;
}

}  // namespace rtsc::crypto

#endif  // !_WIN32
