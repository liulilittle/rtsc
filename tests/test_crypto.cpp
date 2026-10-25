#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/crypto/hash.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::crypto;

namespace {

Bytes FromHex(const char* hex) {
    Bytes out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    int hi = -1;
    for (const char* p = hex; *p; ++p) {
        if (*p == ' ') continue;
        const int v = nib(*p);
        if (v < 0) return {};
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

Bytes Str(const char* s) {
    return Bytes(s, s + std::char_traits<char>::length(s));
}

std::string ToHex(const uint8_t* p, size_t n) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < n; ++i) {
        out.push_back(kHex[p[i] >> 4]);
        out.push_back(kHex[p[i] & 0xF]);
    }
    return out;
}

template <size_t N>
std::string ToHex(const std::array<uint8_t, N>& a) {
    return ToHex(a.data(), a.size());
}

std::string ToHex(const Bytes& v) { return ToHex(v.data(), v.size()); }

void CheckHash(const std::string& got, const char* want_hex) {
    CHECK(got == std::string(want_hex));
}

}  // namespace

// ---- MD4 ([RFC 1320] appendix A.5) ----------------------------------------

RTSC_TEST(md4_rfc1320_vectors) {
    const auto empty = Md4(nullptr, 0);
    CheckHash(ToHex(empty), "31d6cfe0d16ae931b73c59d7e0c089c0");
    const auto abc = Md4(Str("abc"));
    CheckHash(ToHex(abc), "a448017aaf21d8525fc10ae87aa6729d");
    const auto md = Md4(Str("message digest"));
    CheckHash(ToHex(md), "d9130a8164549fe818874806e1c7014b");
    const auto alpha = Md4(Str("abcdefghijklmnopqrstuvwxyz"));
    CheckHash(ToHex(alpha), "d79e1c308aa5bbcdeea8ed63df412da9");
}

RTSC_TEST(md4_ntlm_password_hash) {
    // MD4(UTF-16LE("Password")) -- the NTLM password hash for "Password".
    const auto nt = Md4(Utf16Le("Password"));
    CheckHash(ToHex(nt), "a4f49c406510bdcab6824ee7c30fd852");
}

RTSC_TEST(md4_handles_block_boundaries) {
    // 55 / 56 / 64 byte inputs exercise the padding edge cases.
    for (size_t n : {size_t{55}, size_t{56}, size_t{64}, size_t{119}}) {
        Bytes v(n, 0x61);
        const auto a = Md4(v);
        const auto b = Md4(v.data(), v.size());
        CHECK(a == b);
    }
}

// ---- MD5 ([RFC 1321] appendix A.5) ----------------------------------------

RTSC_TEST(md5_rfc1321_vectors) {
    CheckHash(ToHex(Md5(nullptr, 0)), "d41d8cd98f00b204e9800998ecf8427e");
    CheckHash(ToHex(Md5(Str("a"))), "0cc175b9c0f1b6a831c399e269772661");
    CheckHash(ToHex(Md5(Str("abc"))), "900150983cd24fb0d6963f7d28e17f72");
    CheckHash(ToHex(Md5(Str("message digest"))), "f96b697d7cb7938d525a2f31aaf161d0");
    CheckHash(ToHex(Md5(Str("abcdefghijklmnopqrstuvwxyz"))),
              "c3fcd3d76192e4007dfb496cca67e13b");
}

// ---- SHA-1 ([RFC 3174] test vectors) --------------------------------------

RTSC_TEST(sha1_rfc3174_vectors) {
    CheckHash(ToHex(Sha1(nullptr, 0)), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    CheckHash(ToHex(Sha1(Str("abc"))), "a9993e364706816aba3e25717850c26c9cd0d89d");
    CheckHash(ToHex(Sha1(Str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
              "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

// ---- HMAC-MD5 ([RFC 2202] test cases) -------------------------------------

RTSC_TEST(hmac_md5_rfc2202_vectors) {
    const Bytes key1(16, 0x0b);
    const auto t1 = HmacMd5(key1, Str("Hi There"));
    CheckHash(ToHex(t1), "9294727a3638bb1c13f48ef8158bfc9d");

    const auto t2 = HmacMd5(Str("Jefe"), Str("what do ya want for nothing?"));
    CheckHash(ToHex(t2), "750c783e6ab0b503eaa86e310a5db738");

    const Bytes key3(16, 0xaa);
    const Bytes data3(50, 0xdd);
    const auto t3 = HmacMd5(key3, data3);
    CheckHash(ToHex(t3), "56be34521d144c88dbb8c733f0e8b3f6");
}

RTSC_TEST(hmac_md5_long_key_is_hashed) {
    // Keys longer than the 64-byte block are replaced by MD5(key).
    Bytes key(80, 0xaa);
    const auto got = HmacMd5(key, Str("Test Using Larger Than Block-Size Key - Hash Key First"));
    CheckHash(ToHex(got), "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
}

// ---- RC4 ([MS-NLMP] 3.4.4.2 / classic vectors) ----------------------------

RTSC_TEST(rc4_classic_vectors) {
    const auto c1 = Rc4(Str("Key")).Apply(Str("Plaintext"));
    CheckHash(ToHex(c1.data(), c1.size()), "bbf316e8d940af0ad3");

    const auto c2 = Rc4(Str("Wiki")).Apply(Str("pedia"));
    CheckHash(ToHex(c2.data(), c2.size()), "1021bf0420");

    const auto c3 = Rc4(Str("Secret")).Apply(Str("Attack at dawn"));
    CheckHash(ToHex(c3.data(), c3.size()), "45a01f645fc35b383552544b9bf5");
}

RTSC_TEST(rc4_roundtrips) {
    Bytes msg(300);
    for (size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<uint8_t>(i);
    const Bytes key = FromHex("0102030405060708090a0b0c0d0e0f10");
    Rc4 enc(key);
    const Bytes cipher = enc.Apply(msg);
    CHECK(cipher.size() == msg.size());  // stream cipher: no padding
    Rc4 dec(key);
    CHECK(dec.Apply(cipher) == msg);
}

RTSC_TEST(rc4_state_continues_across_calls) {
    // This is the property the licensing MAC/encrypt pair and NTLM SEAL rely on:
    // encrypting in two calls must equal encrypting in one.
    const Bytes key = FromHex("00112233445566778899aabbccddeeff");
    Bytes msg(64);
    for (size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<uint8_t>(i * 3);

    Rc4 one(key);
    const Bytes a = one.Apply(msg);

    Rc4 two(key);
    Bytes b = two.Apply(Bytes(msg.begin(), msg.begin() + 20));
    const Bytes tail = two.Apply(Bytes(msg.begin() + 20, msg.end()));
    b.insert(b.end(), tail.begin(), tail.end());

    CHECK(a == b);
}

RTSC_TEST(rc4_skip_matches_apply) {
    const Bytes key = FromHex("0102030405");
    Rc4 a(key);
    Bytes discard = a.Apply(Bytes(37, 0));
    const Bytes want = a.Apply(Str("tail"));

    Rc4 b(key);
    b.Skip(37);
    CHECK(b.Apply(Str("tail")) == want);
    (void)discard;
}

RTSC_TEST(rc4_reinit_resets_keystream) {
    Rc4 c(Str("key1"));
    const Bytes first = c.Apply(Str("abcdef"));
    c.Init(Str("key1").data(), 4);
    CHECK(c.Apply(Str("abcdef")) == first);
}

// ---- UTF-16LE -------------------------------------------------------------

RTSC_TEST(utf16le_encoding) {
    const Bytes u = Utf16Le("Ab");
    CHECK_BYTES(u, 0x41, 0x00, 0x62, 0x00);
    CHECK_EQ(Utf16Le("").size(), static_cast<size_t>(0));
}

RTSC_TEST(concat_helpers) {
    const Bytes x1 = FromHex("01 02");
    const Bytes x2 = FromHex("03");
    const Bytes x3 = FromHex("04 05");
    CHECK_BYTES(Concat(x1, x2), 0x01, 0x02, 0x03);
    CHECK_BYTES(Concat(x1, x2, x3), 0x01, 0x02, 0x03, 0x04, 0x05);
    CHECK_BYTES(Concat(x1, x2, x3, x1), 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02);
}

// ---- NTLMv2 ([MS-NLMP] 4.2.1 / 4.2.2 / 4.2.4) -----------------------------

RTSC_TEST(ntlmv2_official_vector) {
    // [MS-NLMP] 4.2.1: User="User", Domain="Domain", Password="Password".
    const auto nt_hash_arr = Md4(Utf16Le("Password"));
    const Bytes nt_hash(nt_hash_arr.begin(), nt_hash_arr.end());
    CheckHash(ToHex(nt_hash), "a4f49c406510bdcab6824ee7c30fd852");

    // NTOWFv2 = HMAC_MD5(NT hash, UTF16(Upper(User) + UserDom)).
    const auto ntowfv2_arr = HmacMd5(nt_hash, Utf16Le("USERDomain"));
    const Bytes ntowfv2(ntowfv2_arr.begin(), ntowfv2_arr.end());
    CheckHash(ToHex(ntowfv2), "0c868a403bfd7a93a3001ef22ef02e3f");

    // ServerChallenge from 4.2.1.
    const Bytes server_challenge = FromHex("01 23 45 67 89 ab cd ef");
    const Bytes client_challenge(8, 0xaa);

    // temp = 01 01 00*6 | Time(8) | ClientChallenge(8) | 00*4 | ServerName | 00*4
    // [MS-NLMP] 4.2.1 fixes Time = 0 and ServerName to two AV_PAIRs:
    //   MsvAvNbDomainName (0x0002) = "Domain"
    //   MsvAvNbComputerName (0x0001) = "Server"
    //   MsvAvEOL (0x0000)
    auto AvPair = [](uint16_t id, const std::string& value) {
        Bytes out;
        const Bytes utf16 = Utf16Le(value);
        out.push_back(static_cast<uint8_t>(id));
        out.push_back(static_cast<uint8_t>(id >> 8));
        out.push_back(static_cast<uint8_t>(utf16.size()));
        out.push_back(static_cast<uint8_t>(utf16.size() >> 8));
        out.insert(out.end(), utf16.begin(), utf16.end());
        return out;
    };
    Bytes server_name = AvPair(0x0002, "Domain");
    const Bytes computer = AvPair(0x0001, "Server");
    server_name.insert(server_name.end(), computer.begin(), computer.end());
    server_name.push_back(0x00);
    server_name.push_back(0x00);
    server_name.push_back(0x00);
    server_name.push_back(0x00);

    Bytes temp;
    temp.push_back(0x01);
    temp.push_back(0x01);
    temp.insert(temp.end(), 6, 0x00);
    temp.insert(temp.end(), 8, 0x00);  // Time = 0
    temp.insert(temp.end(), client_challenge.begin(), client_challenge.end());
    temp.insert(temp.end(), 4, 0x00);
    temp.insert(temp.end(), server_name.begin(), server_name.end());
    temp.insert(temp.end(), 4, 0x00);

    const Bytes proof_input = Concat(server_challenge, temp);
    const auto nt_proof_arr = HmacMd5(ntowfv2, proof_input);
    const Bytes nt_proof(nt_proof_arr.begin(), nt_proof_arr.end());
    CheckHash(ToHex(nt_proof), "68cd0ab851e51c96aabc927bebef6a1c");

    const Bytes nt_response = Concat(nt_proof, temp);
    CheckHash(ToHex(nt_response.data(), nt_response.size()),
              "68cd0ab851e51c96aabc927bebef6a1c01010000000000000000000000000000"
              "aaaaaaaaaaaaaaaa00000000"
              "02000c0044006f006d00610069006e00"
              "01000c00530065007200760065007200"
              "00000000"
              "00000000");

    // SessionBaseKey = HMAC_MD5(NTOWFv2, NTProofStr).
    const auto session_base_key = HmacMd5(ntowfv2, nt_proof);
    CheckHash(ToHex(session_base_key), "8de40ccadbc14a82f15cb0ad0de95ca3");

    // LMv2 = HMAC_MD5(NTOWFv2, ServerChallenge || ClientChallenge) || ClientChallenge.
    const auto lm_proof_arr = HmacMd5(ntowfv2, Concat(server_challenge, client_challenge));
    const Bytes lm_proof(lm_proof_arr.begin(), lm_proof_arr.end());
    const Bytes lm_response = Concat(lm_proof, client_challenge);
    CheckHash(ToHex(lm_response.data(), lm_response.size()),
              "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa");
}

RTSC_TEST(ntlm_encrypted_session_key_vector) {
    // [MS-NLMP] 4.2.2: RC4K(SessionBaseKey, 16 x 0x55).
    const Bytes session_base_key = FromHex("8de40ccadbc14a82f15cb0ad0de95ca3");
    const Bytes exported(16, 0x55);
    const auto enc = Rc4(session_base_key).Apply(exported);
    CheckHash(ToHex(enc.data(), enc.size()), "c5dad2544fc9799094ce1ce90bc9d03e");
}

// ---- Licensing L3 key derivation ([MS-RDPELE] 5.1.2) ----------------------

namespace {

// SaltedHash(S, I) = MD5(S || SHA1(I || S || ClientRandom || ServerRandom)).
std::array<uint8_t, 16> SaltedHash(const Bytes& salt, const Bytes& ident,
                                   const Bytes& client_random,
                                   const Bytes& server_random) {
    const auto inner = Sha1(Concat(ident, salt, client_random, server_random));
    return Md5(Concat(salt, Bytes(inner.begin(), inner.end())));
}

// SaltedHash2(S, I) = MD5(S || SHA1(I || S || ServerRandom || ClientRandom)).
std::array<uint8_t, 16> SaltedHash2(const Bytes& salt, const Bytes& ident,
                                    const Bytes& client_random,
                                    const Bytes& server_random) {
    const auto inner = Sha1(Concat(ident, salt, server_random, client_random));
    return Md5(Concat(salt, Bytes(inner.begin(), inner.end())));
}

Bytes AsBytes(const std::array<uint8_t, 16>& a) { return Bytes(a.begin(), a.end()); }

}  // namespace

RTSC_TEST(licensing_key_derivation_shape) {
    const Bytes premaster(48, 0x42);
    const Bytes client_random(32, 0x11);
    const Bytes server_random(32, 0x22);

    const auto a = SaltedHash(premaster, Str("A"), client_random, server_random);
    const auto bb = SaltedHash(premaster, Str("BB"), client_random, server_random);
    const auto ccc = SaltedHash(premaster, Str("CCC"), client_random, server_random);

    const Bytes master_secret = Concat(AsBytes(a), AsBytes(bb), AsBytes(ccc));
    CHECK_EQ(master_secret.size(), static_cast<size_t>(48));

    const auto ma = SaltedHash2(master_secret, Str("A"), client_random, server_random);
    const auto mbb = SaltedHash2(master_secret, Str("BB"), client_random, server_random);
    const auto mccc = SaltedHash2(master_secret, Str("CCC"), client_random, server_random);

    const Bytes session_key_blob = Concat(AsBytes(ma), AsBytes(mbb), AsBytes(mccc));
    CHECK_EQ(session_key_blob.size(), static_cast<size_t>(48));

    // MAC-salt-key = first 128 bits.
    const Bytes mac_salt_key(session_key_blob.begin(), session_key_blob.begin() + 16);
    CHECK(mac_salt_key.size() == 16);

    // LicensingEncryptionKey = MD5(second 128 bits || ClientRandom || ServerRandom).
    const Bytes second(session_key_blob.begin() + 16, session_key_blob.begin() + 32);
    const auto lic_key = Md5(Concat(second, client_random, server_random));
    CHECK(lic_key.size() == 16);
}

RTSC_TEST(licensing_key_derivation_is_deterministic) {
    const Bytes premaster(48, 0x01);
    const Bytes cr(32, 0x02);
    const Bytes sr(32, 0x03);
    const auto x = SaltedHash(premaster, Str("A"), cr, sr);
    const auto y = SaltedHash(premaster, Str("A"), cr, sr);
    CHECK(x == y);
    // SaltedHash and SaltedHash2 differ only in random order, so they must not
    // produce the same digest for asymmetric inputs.
    const auto z = SaltedHash2(premaster, Str("A"), cr, sr);
    CHECK(x != z);
}

RTSC_TEST(licensing_key_derivation_uses_literal_identifiers) {
    // 'A' / 'BB' / 'CCC' are literal strings, not repeated characters. Using
    // 'AAA' instead must produce a different key.
    const Bytes premaster(48, 0x07);
    const Bytes cr(32, 0x08);
    const Bytes sr(32, 0x09);
    const auto good = SaltedHash(premaster, Str("A"), cr, sr);
    const auto bad = SaltedHash(premaster, Str("AAA"), cr, sr);
    CHECK(good != bad);
}

// ---- Licensing L3 MAC ([MS-RDPELE] 5.1.5) ---------------------------------

namespace {

std::array<uint8_t, 16> LicensingMac(const Bytes& mac_salt_key,
                                     const Bytes& data) {
    const Bytes pad1(40, 0x36);
    const Bytes pad2(48, 0x5c);
    Bytes len_field;
    const uint32_t n = static_cast<uint32_t>(data.size());
    len_field.push_back(static_cast<uint8_t>(n));
    len_field.push_back(static_cast<uint8_t>(n >> 8));
    len_field.push_back(static_cast<uint8_t>(n >> 16));
    len_field.push_back(static_cast<uint8_t>(n >> 24));

    const auto inner = Sha1(Concat(mac_salt_key, pad1, len_field, data));
    return Md5(Concat(mac_salt_key, pad2, Bytes(inner.begin(), inner.end())));
}

}  // namespace

RTSC_TEST(licensing_mac_is_16_bytes_and_deterministic) {
    const Bytes key = FromHex("000102030405060708090a0b0c0d0e0f");
    const Bytes data = FromHex("deadbeef");
    const auto a = LicensingMac(key, data);
    const auto b = LicensingMac(key, data);
    CHECK(a.size() == 16);  // full MD5, not 8-byte truncation
    CHECK(a == b);
    CHECK(LicensingMac(key, FromHex("deadbeee")) != a);
}

RTSC_TEST(licensing_mac_pads_are_not_swapped) {
    // pad1 = 40 x 0x36, pad2 = 48 x 0x5C. Swapping them must change the MAC.
    const Bytes key = FromHex("0f0e0d0c0b0a09080706050403020100");
    const Bytes data = FromHex("00112233");
    const auto correct = LicensingMac(key, data);

    const Bytes pad1(48, 0x36);
    const Bytes pad2(40, 0x5c);
    Bytes len_field = FromHex("04 00 00 00");
    const auto inner = Sha1(Concat(key, pad1, len_field, data));
    const auto swapped = Md5(Concat(key, pad2, Bytes(inner.begin(), inner.end())));
    CHECK(correct != swapped);
}

// ---------------------------------------------------------------------------
// SHA-256 ([FIPS 180-4]) — needed by CredSSP v5/v6 public key binding
// ---------------------------------------------------------------------------

RTSC_TEST(sha256_matches_fips_vectors) {
    struct Vector {
        const char* msg;
        const char* digest;
    };
    // FIPS 180-4 / RFC 6234 appendix vectors.
    const Vector vectors[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
    };
    for (const auto& v : vectors) {
        const Bytes msg = Str(v.msg);
        const auto got = Sha256(msg.data(), msg.size());
        CHECK(ToHex(got) == v.digest);
    }
}

RTSC_TEST(sha256_handles_length_around_the_block_boundary) {
    // 55 / 56 / 64 bytes: the padding must add a whole extra block at 56 and
    // exactly fill at 64. Getting this wrong is invisible for short inputs.
    struct Vector {
        size_t n;
        const char* digest;
    };
    const Vector vectors[] = {
        {55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"},
        {56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"},
        {64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"},
    };
    for (const auto& v : vectors) {
        const Bytes msg(v.n, 'a');
        const auto got = Sha256(msg.data(), msg.size());
        CHECK(ToHex(got) == v.digest);
    }
}

RTSC_TEST(sha256_is_not_sha1_or_md5) {
    // A copy-paste of the SHA-1 round constants would still produce 32 bytes;
    // only a value comparison catches it.
    const Bytes msg = Str("abc");
    const auto sha256 = Sha256(msg.data(), msg.size());
    const auto sha1 = Sha1(msg.data(), msg.size());
    const auto md5 = Md5(msg.data(), msg.size());
    CHECK(sha256.size() == 32);
    CHECK(ToHex(sha256) != ToHex(sha1).substr(0, 32));
    CHECK(ToHex(sha256).substr(0, 32) != ToHex(md5));
}

RTSC_TEST(sha256_credssp_magic_is_38_bytes_with_nul) {
    // CredSSP v5/v6 binding hash: the magic MUST include the trailing NUL.
    // A 37-byte magic produces a plausible but wrong hash, so the length is
    // asserted directly rather than inferred from a digest.
    //
    // Note: Str() uses char_traits::length, which stops at the NUL, so the
    // 38-byte buffer must be built explicitly. Using Str() here would silently
    // yield 37 bytes and make this test pass for the wrong reason.
    const char magic[] = "CredSSP Client-To-Server Binding Hash";
    const Bytes without_nul = Str(magic);
    CHECK(without_nul.size() == 37);

    Bytes with_nul = without_nul;
    with_nul.push_back(0x00);
    CHECK(with_nul.size() == 38);
    CHECK(with_nul.back() == static_cast<uint8_t>(0x00));

    const auto h = Sha256(with_nul.data(), with_nul.size());
    CHECK(ToHex(h) ==
          "c56cd3d364eb253d743b63bdcb8b7e00047844aaa62eba489174e73598b848d8");

    // Without the NUL the digest must differ: this is the exact mistake the
    // spec calls out, so the difference has to be observable.
    const auto h2 = Sha256(without_nul.data(), without_nul.size());
    CHECK(h != h2);
}

int main() { return rtsc::test::run_all("rtsc_crypto_tests"); }
