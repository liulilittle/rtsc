// Standard RDP Security session keys ([MS-RDPBCGR] 5.3.5.1).
//
// The expected values below were produced by an independent Python
// implementation (hashlib MD5/SHA-1) of the same derivation, so this is a
// differential test of the derivation logic, not a self-comparison.

#include "rtsc/crypto/rdp_security.h"

#include <cstdint>
#include <string>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

namespace {

std::string Hex(const std::vector<uint8_t>& b) {
    static const char* k = "0123456789abcdef";
    std::string s;
    for (uint8_t c : b) {
        s.push_back(k[c >> 4]);
        s.push_back(k[c & 0xF]);
    }
    return s;
}

std::vector<uint8_t> ClientRandom() {
    std::vector<uint8_t> v(32);
    for (size_t i = 0; i < 32; ++i) v[i] = static_cast<uint8_t>(i);
    return v;
}

std::vector<uint8_t> ServerRandom() { return std::vector<uint8_t>(32, 0xA0); }

}  // namespace

RTSC_TEST(rdp_session_keys_match_independent_derivation) {
    const auto cr = ClientRandom();
    const auto sr = ServerRandom();
    const auto keys = rtsc::crypto::DeriveRdpSessionKeys(
        cr, sr, static_cast<uint32_t>(rtsc::crypto::RdpEncryptionMethod::k128Bit));

    CHECK(Hex(keys.mac_key) == "137109ce48b0e903d545cc1d1124aace");
    CHECK(Hex(keys.decrypt_key) == "2e5ac519724428ecc5ba7e3bdb8ac778");
    CHECK(Hex(keys.encrypt_key) == "3679373c966c7aa55f9d0a3a72fd56c2");
    CHECK(keys.rc4_key_len == 16);
}

RTSC_TEST(rdp_session_keys_40bit_reduction) {
    const auto keys = rtsc::crypto::DeriveRdpSessionKeys(
        ClientRandom(), ServerRandom(),
        static_cast<uint32_t>(rtsc::crypto::RdpEncryptionMethod::k40Bit));

    // MACKey40 = 0xD1269E + Last40Bits(First64Bits(MACKey128)).
    CHECK(Hex(keys.mac_key) == "d1269ece48b0e903");
    CHECK(keys.rc4_key_len == 8);
    CHECK(keys.mac_key.size() == 8);
    CHECK(keys.encrypt_key.size() == 8);
    CHECK(keys.decrypt_key.size() == 8);
}

RTSC_TEST(rdp_session_keys_56bit_reduction) {
    const auto keys = rtsc::crypto::DeriveRdpSessionKeys(
        ClientRandom(), ServerRandom(),
        static_cast<uint32_t>(rtsc::crypto::RdpEncryptionMethod::k56Bit));
    CHECK(keys.rc4_key_len == 8);
    // MACKey56 = 0xD1 + Last56Bits(First64Bits(MACKey128)).
    CHECK(keys.mac_key[0] == 0xD1);
    CHECK(Hex(keys.mac_key) == "d17109ce48b0e903");
}

RTSC_TEST(rdp_session_keys_reject_none_and_fips) {
    const auto none = rtsc::crypto::DeriveRdpSessionKeys(
        ClientRandom(), ServerRandom(),
        static_cast<uint32_t>(rtsc::crypto::RdpEncryptionMethod::kNone));
    CHECK(none.mac_key.empty());

    const auto fips = rtsc::crypto::DeriveRdpSessionKeys(
        ClientRandom(), ServerRandom(),
        static_cast<uint32_t>(rtsc::crypto::RdpEncryptionMethod::kFips));
    CHECK(fips.mac_key.empty());
}

RTSC_TEST(rdp_session_keys_are_deterministic_and_distinct) {
    const auto a = rtsc::crypto::DeriveRdpSessionKeys(
        ClientRandom(), ServerRandom(),
        static_cast<uint32_t>(rtsc::crypto::RdpEncryptionMethod::k128Bit));
    const auto b = rtsc::crypto::DeriveRdpSessionKeys(
        ClientRandom(), ServerRandom(),
        static_cast<uint32_t>(rtsc::crypto::RdpEncryptionMethod::k128Bit));
    CHECK(a.mac_key == b.mac_key);
    CHECK(a.encrypt_key == b.encrypt_key);

    // The encrypt and decrypt keys must differ (they are different key data).
    CHECK(a.encrypt_key != a.decrypt_key);

    auto sr2 = ServerRandom();
    sr2[0] ^= 0xFF;
    const auto c = rtsc::crypto::DeriveRdpSessionKeys(
        ClientRandom(), sr2,
        static_cast<uint32_t>(rtsc::crypto::RdpEncryptionMethod::k128Bit));
    CHECK(c.mac_key != a.mac_key);
}

RTSC_TEST(rdp_mac_signature_matches_independent_derivation) {
    const auto keys = rtsc::crypto::DeriveRdpSessionKeys(
        ClientRandom(), ServerRandom(),
        static_cast<uint32_t>(rtsc::crypto::RdpEncryptionMethod::k128Bit));
    const std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
    const auto sig = rtsc::crypto::RdpMacSignature(keys.mac_key, data);
    const std::vector<uint8_t> sig_vec(sig.begin(), sig.end());
    CHECK(Hex(sig_vec) == "03fad5902c7e4718");
}

// ---- RdpSecurityContext ---------------------------------------------------

namespace {

// A client context and the matching server context (directions swapped).
void MakePair(rtsc::crypto::RdpSecurityContext& client,
              rtsc::crypto::RdpSecurityContext& server) {
    const auto ck = rtsc::crypto::DeriveRdpSessionKeys(
        ClientRandom(), ServerRandom(),
        static_cast<uint32_t>(rtsc::crypto::RdpEncryptionMethod::k128Bit));
    auto sk = ck;
    std::swap(sk.encrypt_key, sk.decrypt_key);
    client.Init(ck);
    server.Init(sk);
}

}  // namespace

RTSC_TEST(rdp_security_context_rc4_round_trip) {
    rtsc::crypto::RdpSecurityContext client;
    rtsc::crypto::RdpSecurityContext server;
    MakePair(client, server);

    std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    const std::vector<uint8_t> original = data;
    const auto mac = client.Encrypt(data);
    CHECK(data != original);  // RC4 changed the bytes

    CHECK(server.Decrypt(data, mac));
    CHECK(data == original);
}

RTSC_TEST(rdp_security_context_mac_mismatch_fails) {
    rtsc::crypto::RdpSecurityContext client;
    rtsc::crypto::RdpSecurityContext server;
    MakePair(client, server);

    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    auto mac = client.Encrypt(data);
    mac[0] ^= 0xFF;  // tamper with the MAC
    CHECK(!server.Decrypt(data, mac));
}

RTSC_TEST(rdp_security_context_key_update_keeps_both_sides_in_sync) {
    rtsc::crypto::RdpSecurityContext client;
    rtsc::crypto::RdpSecurityContext server;
    MakePair(client, server);

    // Cross the 4096-packet key-update boundary twice.
    int failures = 0;
    for (int i = 0; i < 9000; ++i) {
        std::vector<uint8_t> data = {static_cast<uint8_t>(i),
                                     static_cast<uint8_t>(i >> 8)};
        const std::vector<uint8_t> original = data;
        const auto mac = client.Encrypt(data);
        if (!server.Decrypt(data, mac) || data != original) {
            ++failures;
            if (failures > 3) break;
        }
    }
    CHECK_EQ(failures, 0);
    CHECK(client.send_count() < 4096);
    CHECK(server.recv_count() < 4096);
}

int main() { return ::rtsc::test::run_all("rtsc_rdp_security_tests"); }
