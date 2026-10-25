// Standard RDP Security session keys ([MS-RDPBCGR] 5.3.5.1).

#include "rtsc/crypto/rdp_security.h"

#include <cstring>

#include "rtsc/crypto/hash.h"

namespace rtsc::crypto {
namespace {

std::vector<uint8_t> ToVec(const std::array<uint8_t, 16>& a) {
    return std::vector<uint8_t>(a.begin(), a.end());
}

std::vector<uint8_t> ToVec(const std::array<uint8_t, 20>& a) {
    return std::vector<uint8_t>(a.begin(), a.end());
}

// SaltedHash(S, I) = MD5(S + SHA1(I + S + ClientRandom + ServerRandom)).
std::array<uint8_t, 16> SaltedHash(const std::vector<uint8_t>& salt,
                                   const std::vector<uint8_t>& ident,
                                   const std::vector<uint8_t>& client_random,
                                   const std::vector<uint8_t>& server_random) {
    const auto inner = Sha1(Concat(ident, salt, client_random, server_random));
    return Md5(Concat(salt, ToVec(inner)));
}

// FinalHash(K) = MD5(K + ClientRandom + ServerRandom).
std::array<uint8_t, 16> FinalHash(const std::vector<uint8_t>& k,
                                  const std::vector<uint8_t>& client_random,
                                  const std::vector<uint8_t>& server_random) {
    return Md5(Concat(k, client_random, server_random));
}

// Overwrites the leading bytes of a 128-bit key with the reduction salt
// ([MS-RDPBCGR] 5.3.5.1 Table 1).
void ReduceKey(std::vector<uint8_t>& key, uint32_t method) {
    if (method == static_cast<uint32_t>(RdpEncryptionMethod::k40Bit)) {
        key[0] = 0xD1;
        key[1] = 0x26;
        key[2] = 0x9E;
    } else if (method == static_cast<uint32_t>(RdpEncryptionMethod::k56Bit)) {
        key[0] = 0xD1;
    }
}

}  // namespace

RdpSessionKeys DeriveRdpSessionKeys(const std::vector<uint8_t>& client_random,
                                    const std::vector<uint8_t>& server_random,
                                    uint32_t encryption_method) {
    RdpSessionKeys keys;
    if (client_random.size() < 32 || server_random.size() < 32) return keys;
    if (encryption_method == static_cast<uint32_t>(RdpEncryptionMethod::kNone) ||
        encryption_method == static_cast<uint32_t>(RdpEncryptionMethod::kFips)) {
        return keys;  // FIPS uses 3DES and a different derivation, out of scope
    }

    // PreMasterSecret = First192Bits(CR) + First192Bits(SR) = 48 bytes.
    std::vector<uint8_t> pre_master;
    pre_master.insert(pre_master.end(), client_random.begin(),
                      client_random.begin() + 24);
    pre_master.insert(pre_master.end(), server_random.begin(),
                      server_random.begin() + 24);

    // MasterSecret = SaltedHash(pre, 'A') + SaltedHash(pre, 'BB') + SaltedHash(pre, 'CCC').
    const std::vector<uint8_t> id_a = {'A'};
    const std::vector<uint8_t> id_bb = {'B', 'B'};
    const std::vector<uint8_t> id_ccc = {'C', 'C', 'C'};
    std::vector<uint8_t> master_secret;
    for (const auto* id : {&id_a, &id_bb, &id_ccc}) {
        const auto h = SaltedHash(pre_master, *id, client_random, server_random);
        master_secret.insert(master_secret.end(), h.begin(), h.end());
    }

    // SessionKeyBlob = SaltedHash(master, 'X') + SaltedHash(master, 'YY') + SaltedHash(master, 'ZZ').
    // Standard RDP Security keeps the ClientRandom || ServerRandom order here
    // (unlike licensing, which swaps them).
    const std::vector<uint8_t> id_x = {'X'};
    const std::vector<uint8_t> id_yy = {'Y', 'Y'};
    const std::vector<uint8_t> id_zz = {'Z', 'Z', 'Z'};
    std::vector<uint8_t> blob;
    for (const auto* id : {&id_x, &id_yy, &id_zz}) {
        const auto h = SaltedHash(master_secret, *id, client_random, server_random);
        blob.insert(blob.end(), h.begin(), h.end());
    }

    // MACKey128 = First128Bits(blob).
    keys.mac_key.assign(blob.begin(), blob.begin() + 16);
    // Client: decrypt = FinalHash(Second128Bits), encrypt = FinalHash(Third128Bits).
    const std::vector<uint8_t> second(blob.begin() + 16, blob.begin() + 32);
    const std::vector<uint8_t> third(blob.begin() + 32, blob.begin() + 48);
    keys.decrypt_key = ToVec(FinalHash(second, client_random, server_random));
    keys.encrypt_key = ToVec(FinalHash(third, client_random, server_random));

    if (encryption_method == static_cast<uint32_t>(RdpEncryptionMethod::k40Bit) ||
        encryption_method == static_cast<uint32_t>(RdpEncryptionMethod::k56Bit)) {
        ReduceKey(keys.mac_key, encryption_method);
        ReduceKey(keys.encrypt_key, encryption_method);
        ReduceKey(keys.decrypt_key, encryption_method);
        keys.rc4_key_len = 8;
    } else {
        keys.rc4_key_len = 16;
    }

    keys.mac_key.resize(keys.rc4_key_len);
    keys.encrypt_key.resize(keys.rc4_key_len);
    keys.decrypt_key.resize(keys.rc4_key_len);
    keys.method = encryption_method;
    return keys;
}

std::array<uint8_t, 8> RdpMacSignature(const std::vector<uint8_t>& mac_key,
                                       const std::vector<uint8_t>& data) {
    const std::vector<uint8_t> pad1(40, 0x36);
    const std::vector<uint8_t> pad2(48, 0x5c);
    const uint32_t n = static_cast<uint32_t>(data.size());
    const std::vector<uint8_t> len_field = {
        static_cast<uint8_t>(n), static_cast<uint8_t>(n >> 8),
        static_cast<uint8_t>(n >> 16), static_cast<uint8_t>(n >> 24)};

    const auto inner = Sha1(Concat(mac_key, pad1, len_field, data));
    const auto outer = Md5(Concat(mac_key, pad2, ToVec(inner)));

    std::array<uint8_t, 8> out{};
    std::memcpy(out.data(), outer.data(), 8);
    return out;
}

namespace {

// security_key_update ([MS-RDPBCGR] 5.3.6.1):
//   key = RC4(key, MD5(update_key + pad2 + SHA1(update_key + pad1 + key)))
// followed by the 40/56-bit salt reduction.
void UpdateKey(std::vector<uint8_t>& key, const std::vector<uint8_t>& update_key,
               uint32_t method) {
    const std::vector<uint8_t> pad1(40, 0x36);
    const std::vector<uint8_t> pad2(48, 0x5c);
    const auto sha1h = Sha1(Concat(update_key, pad1, key));
    const auto md5h = Md5(Concat(update_key, pad2, ToVec(sha1h)));
    key.assign(md5h.begin(), md5h.begin() + static_cast<ptrdiff_t>(key.size()));
    Rc4 rc4(key.data(), key.size());
    rc4.Apply(key.data(), key.size());
    ReduceKey(key, method);
}

}  // namespace

void RdpSecurityContext::Init(const RdpSessionKeys& keys) {
    keys_ = keys;
    send_update_key_ = keys.encrypt_key;
    recv_update_key_ = keys.decrypt_key;
    send_rc4_.Init(keys.encrypt_key.data(), keys.encrypt_key.size());
    recv_rc4_.Init(keys.decrypt_key.data(), keys.decrypt_key.size());
    send_count_ = 0;
    recv_count_ = 0;
    initialized_ = true;
}

std::array<uint8_t, 8> RdpSecurityContext::Encrypt(std::vector<uint8_t>& data) {
    const auto mac = RdpMacSignature(keys_.mac_key, data);
    if (!data.empty()) send_rc4_.Apply(data.data(), data.size());
    ++send_count_;
    if (send_count_ >= 4096) UpdateSendKey();
    return mac;
}

bool RdpSecurityContext::Decrypt(std::vector<uint8_t>& data,
                                 const std::array<uint8_t, 8>& mac) {
    if (!data.empty()) recv_rc4_.Apply(data.data(), data.size());
    ++recv_count_;
    if (RdpMacSignature(keys_.mac_key, data) != mac) return false;
    if (recv_count_ >= 4096) UpdateRecvKey();
    return true;
}

void RdpSecurityContext::UpdateSendKey() {
    UpdateKey(keys_.encrypt_key, send_update_key_, keys_.method);
    send_rc4_.Init(keys_.encrypt_key.data(), keys_.encrypt_key.size());
    send_count_ = 0;
}

void RdpSecurityContext::UpdateRecvKey() {
    UpdateKey(keys_.decrypt_key, recv_update_key_, keys_.method);
    recv_rc4_.Init(keys_.decrypt_key.data(), keys_.decrypt_key.size());
    recv_count_ = 0;
}

}  // namespace rtsc::crypto
