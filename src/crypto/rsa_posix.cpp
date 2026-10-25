// POSIX stub for the RDP raw-RSA primitive.
//
// The real backend is BCrypt (rsa_win.cpp). A Linux backend will use
// OpenSSL/BoringSSL; until then this stub fails closed so the library still
// links and callers cannot accidentally treat an empty key as success.

#include "rtsc/crypto/rsa.h"

#if !defined(_WIN32)

namespace rtsc::crypto {

bool RdpRsaEncryptClientRandom(const RsaPublicKey& /*key*/,
                               const std::vector<uint8_t>& /*input*/,
                               std::vector<uint8_t>& out) {
    out.clear();
    return false;
}

}  // namespace rtsc::crypto

#endif  // !_WIN32
