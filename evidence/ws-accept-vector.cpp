// Independent derivation of the RFC 6455 Sec-WebSocket-Accept test vector.
// RFC 6455 section 1.3: the example key "dGhlIHNhbXBsZSBub25jZQ==" must yield
// the accept value "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=". Producing it here, with the
// repo's own SHA-1 and base64, gives a reference the executor's implementation
// can be checked against without trusting either side.
#include <cstdio>
#include <string>
#include <vector>

#include "rtsc/crypto/hash.h"
#include "rtsc/proto/gateway.h"

namespace {

std::string Base64(const std::vector<uint8_t>& in) {
    static const char* kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    while (i + 2 < in.size()) {
        const uint32_t v = (uint32_t(in[i]) << 16) | (uint32_t(in[i + 1]) << 8) |
                           uint32_t(in[i + 2]);
        out.push_back(kAlphabet[(v >> 18) & 0x3F]);
        out.push_back(kAlphabet[(v >> 12) & 0x3F]);
        out.push_back(kAlphabet[(v >> 6) & 0x3F]);
        out.push_back(kAlphabet[v & 0x3F]);
        i += 3;
    }
    if (i + 1 == in.size()) {
        const uint32_t v = uint32_t(in[i]) << 16;
        out.push_back(kAlphabet[(v >> 18) & 0x3F]);
        out.push_back(kAlphabet[(v >> 12) & 0x3F]);
        out += "==";
    } else if (i + 2 == in.size()) {
        const uint32_t v = (uint32_t(in[i]) << 16) | (uint32_t(in[i + 1]) << 8);
        out.push_back(kAlphabet[(v >> 18) & 0x3F]);
        out.push_back(kAlphabet[(v >> 12) & 0x3F]);
        out.push_back(kAlphabet[(v >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

}  // namespace

int main() {
    const char* kGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const std::string key = "dGhlIHNhbXBsZSBub25jZQ==";
    const std::string material = key + kGuid;

    const auto digest = rtsc::crypto::Sha1(
        reinterpret_cast<const uint8_t*>(material.data()), material.size());
    const std::string accept =
        Base64(std::vector<uint8_t>(digest.begin(), digest.end()));

    std::printf("key      = %s\n", key.c_str());
    std::printf("material = %s\n", material.c_str());
    std::printf("sha1     = ");
    for (uint8_t b : digest) std::printf("%02x", b);
    std::printf("\n");
    std::printf("accept   = %s\n", accept.c_str());

    const int ok = accept == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" ? 0 : 1;
    std::printf("[%s] RFC 6455 1.3 vector\n", ok == 0 ? "PASS" : "FAIL");
    return ok;
}
