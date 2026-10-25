#include "rtsc/crypto/hash.h"

#include <cstring>

namespace rtsc::crypto {

namespace {

inline uint32_t Rotl32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }
inline uint32_t Rotr32(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

inline uint32_t LoadLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline void StoreLe32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

inline uint32_t LoadBe32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline void StoreBe32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

// Appends the MD-style padding (0x80, zeros, 64-bit little-endian bit length).
Bytes MdPad(const uint8_t* data, size_t size) {
    Bytes m(data, data + size);
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0);
    const uint64_t bits = static_cast<uint64_t>(size) * 8;
    for (int i = 0; i < 8; ++i) {
        m.push_back(static_cast<uint8_t>(bits >> (8 * i)));
    }
    return m;
}

// Appends the SHA-1 padding (0x80, zeros, 64-bit big-endian bit length).
Bytes ShaPad(const uint8_t* data, size_t size) {
    Bytes m(data, data + size);
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0);
    const uint64_t bits = static_cast<uint64_t>(size) * 8;
    for (int i = 7; i >= 0; --i) {
        m.push_back(static_cast<uint8_t>(bits >> (8 * i)));
    }
    return m;
}

}  // namespace

// ---- MD4 ------------------------------------------------------------------

namespace {

void Md4Block(uint32_t (&h)[4], const uint8_t* p) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = LoadLe32(p + i * 4);

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];

    auto f = [](uint32_t u, uint32_t v, uint32_t w) { return (u & v) | (~u & w); };
    auto g = [](uint32_t u, uint32_t v, uint32_t w) { return (u & v) | (u & w) | (v & w); };
    auto hh = [](uint32_t u, uint32_t v, uint32_t w) { return u ^ v ^ w; };

#define RT1(aa, bb, cc, dd, k, s) aa = Rotl32(aa + f(bb, cc, dd) + x[k], s)
    RT1(a, b, c, d, 0, 3); RT1(d, a, b, c, 1, 7); RT1(c, d, a, b, 2, 11); RT1(b, c, d, a, 3, 19);
    RT1(a, b, c, d, 4, 3); RT1(d, a, b, c, 5, 7); RT1(c, d, a, b, 6, 11); RT1(b, c, d, a, 7, 19);
    RT1(a, b, c, d, 8, 3); RT1(d, a, b, c, 9, 7); RT1(c, d, a, b, 10, 11); RT1(b, c, d, a, 11, 19);
    RT1(a, b, c, d, 12, 3); RT1(d, a, b, c, 13, 7); RT1(c, d, a, b, 14, 11); RT1(b, c, d, a, 15, 19);
#undef RT1

#define RT2(aa, bb, cc, dd, k, s) aa = Rotl32(aa + g(bb, cc, dd) + x[k] + 0x5A827999u, s)
    RT2(a, b, c, d, 0, 3); RT2(d, a, b, c, 4, 5); RT2(c, d, a, b, 8, 9); RT2(b, c, d, a, 12, 13);
    RT2(a, b, c, d, 1, 3); RT2(d, a, b, c, 5, 5); RT2(c, d, a, b, 9, 9); RT2(b, c, d, a, 13, 13);
    RT2(a, b, c, d, 2, 3); RT2(d, a, b, c, 6, 5); RT2(c, d, a, b, 10, 9); RT2(b, c, d, a, 14, 13);
    RT2(a, b, c, d, 3, 3); RT2(d, a, b, c, 7, 5); RT2(c, d, a, b, 11, 9); RT2(b, c, d, a, 15, 13);
#undef RT2

#define RT3(aa, bb, cc, dd, k, s) aa = Rotl32(aa + hh(bb, cc, dd) + x[k] + 0x6ED9EBA1u, s)
    RT3(a, b, c, d, 0, 3); RT3(d, a, b, c, 8, 9); RT3(c, d, a, b, 4, 11); RT3(b, c, d, a, 12, 15);
    RT3(a, b, c, d, 2, 3); RT3(d, a, b, c, 10, 9); RT3(c, d, a, b, 6, 11); RT3(b, c, d, a, 14, 15);
    RT3(a, b, c, d, 1, 3); RT3(d, a, b, c, 9, 9); RT3(c, d, a, b, 5, 11); RT3(b, c, d, a, 13, 15);
    RT3(a, b, c, d, 3, 3); RT3(d, a, b, c, 11, 9); RT3(c, d, a, b, 7, 11); RT3(b, c, d, a, 15, 15);
#undef RT3

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
}

}  // namespace

std::array<uint8_t, 16> Md4(const uint8_t* data, size_t size) {
    uint32_t h[4] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u};
    const Bytes m = MdPad(data, size);
    for (size_t off = 0; off < m.size(); off += 64) Md4Block(h, m.data() + off);
    std::array<uint8_t, 16> out{};
    for (int i = 0; i < 4; ++i) StoreLe32(out.data() + i * 4, h[i]);
    return out;
}

// ---- MD5 ------------------------------------------------------------------

namespace {

constexpr uint32_t kMd5K[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au,
    0xa8304613u, 0xfd469501u, 0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u, 0xf61e2562u, 0xc040b340u,
    0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u,
    0x676f02d9u, 0x8d2a4c8au, 0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u, 0x289b7ec6u, 0xeaa127fau,
    0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u,
    0xffeff47du, 0x85845dd1u, 0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u};

constexpr int kMd5S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                           5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                           4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                           6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

void Md5Block(uint32_t (&h)[4], const uint8_t* p) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = LoadLe32(p + i * 4);

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    for (int i = 0; i < 64; ++i) {
        uint32_t f = 0;
        int g = 0;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        const uint32_t tmp = d;
        d = c;
        c = b;
        b = b + Rotl32(a + f + kMd5K[i] + x[g], kMd5S[i]);
        a = tmp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
}

}  // namespace

std::array<uint8_t, 16> Md5(const uint8_t* data, size_t size) {
    uint32_t h[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    const Bytes m = MdPad(data, size);
    for (size_t off = 0; off < m.size(); off += 64) Md5Block(h, m.data() + off);
    std::array<uint8_t, 16> out{};
    for (int i = 0; i < 4; ++i) StoreLe32(out.data() + i * 4, h[i]);
    return out;
}

// ---- SHA-1 ----------------------------------------------------------------

namespace {

void Sha1Block(uint32_t (&h)[5], const uint8_t* p) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = LoadBe32(p + i * 4);
    for (int i = 16; i < 80; ++i) {
        w[i] = Rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f = 0, k = 0;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        const uint32_t tmp = Rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = Rotl32(b, 30);
        b = a;
        a = tmp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

}  // namespace

std::array<uint8_t, 20> Sha1(const uint8_t* data, size_t size) {
    uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u,
                     0xC3D2E1F0u};
    const Bytes m = ShaPad(data, size);
    for (size_t off = 0; off < m.size(); off += 64) Sha1Block(h, m.data() + off);
    std::array<uint8_t, 20> out{};
    for (int i = 0; i < 5; ++i) StoreBe32(out.data() + i * 4, h[i]);
    return out;
}

// ---- SHA-256 --------------------------------------------------------------

namespace {

void Sha256Block(uint32_t (&h)[8], const uint8_t* p) {
    // FIPS 180-4 section 4.2.2 round constants: the first 32 bits of the
    // fractional parts of the cube roots of the first 64 primes.
    static const uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
        0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
        0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
        0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
        0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
        0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
        0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
        0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
        0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
        0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = LoadBe32(p + i * 4);
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = Rotr32(w[i - 15], 7) ^ Rotr32(w[i - 15], 18) ^
                            (w[i - 15] >> 3);
        const uint32_t s1 = Rotr32(w[i - 2], 17) ^ Rotr32(w[i - 2], 19) ^
                            (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t s1 = Rotr32(e, 6) ^ Rotr32(e, 11) ^ Rotr32(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = hh + s1 + ch + k[i] + w[i];
        const uint32_t s0 = Rotr32(a, 2) ^ Rotr32(a, 13) ^ Rotr32(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = s0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

}  // namespace

std::array<uint8_t, 32> Sha256(const uint8_t* data, size_t size) {
    // FIPS 180-4 section 5.3.3 initial hash value.
    uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                     0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    // Padding is identical to SHA-1 (0x80, zero fill to 56 mod 64, 64-bit
    // big-endian length), so the shared helper is used on purpose.
    const Bytes m = ShaPad(data, size);
    for (size_t off = 0; off < m.size(); off += 64) Sha256Block(h, m.data() + off);
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) StoreBe32(out.data() + i * 4, h[i]);
    return out;
}

// ---- HMAC-MD5 -------------------------------------------------------------

std::array<uint8_t, 16> HmacMd5(const uint8_t* key, size_t key_size,
                                const uint8_t* data, size_t data_size) {
    constexpr size_t kBlock = 64;
    uint8_t k[kBlock] = {};
    if (key_size > kBlock) {
        const auto hashed = Md5(key, key_size);
        std::memcpy(k, hashed.data(), hashed.size());
    } else if (key_size != 0) {
        std::memcpy(k, key, key_size);
    }

    Bytes inner;
    inner.reserve(kBlock + data_size);
    for (size_t i = 0; i < kBlock; ++i) inner.push_back(k[i] ^ 0x36);
    if (data_size != 0) inner.insert(inner.end(), data, data + data_size);
    const auto inner_hash = Md5(inner.data(), inner.size());

    Bytes outer;
    outer.reserve(kBlock + inner_hash.size());
    for (size_t i = 0; i < kBlock; ++i) outer.push_back(k[i] ^ 0x5c);
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return Md5(outer.data(), outer.size());
}

// ---- RC4 ------------------------------------------------------------------

Rc4::Rc4(const uint8_t* key, size_t key_size) { Init(key, key_size); }

Rc4::Rc4(const Bytes& key) { Init(key.data(), key.size()); }

void Rc4::Init(const uint8_t* key, size_t key_size) {
    for (int i = 0; i < 256; ++i) s_[i] = static_cast<uint8_t>(i);
    i_ = 0;
    j_ = 0;
    if (key == nullptr || key_size == 0) return;

    uint8_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j = static_cast<uint8_t>(j + s_[i] + key[i % key_size]);
        const uint8_t t = s_[i];
        s_[i] = s_[j];
        s_[j] = t;
    }
}

void Rc4::Apply(uint8_t* data, size_t size) {
    if (data == nullptr) return;
    for (size_t n = 0; n < size; ++n) {
        i_ = static_cast<uint8_t>(i_ + 1);
        j_ = static_cast<uint8_t>(j_ + s_[i_]);
        const uint8_t t = s_[i_];
        s_[i_] = s_[j_];
        s_[j_] = t;
        data[n] ^= s_[static_cast<uint8_t>(s_[i_] + s_[j_])];
    }
}

Bytes Rc4::Apply(const Bytes& data) {
    Bytes out = data;
    Apply(out.data(), out.size());
    return out;
}

void Rc4::Skip(size_t size) {
    for (size_t n = 0; n < size; ++n) {
        i_ = static_cast<uint8_t>(i_ + 1);
        j_ = static_cast<uint8_t>(j_ + s_[i_]);
        const uint8_t t = s_[i_];
        s_[i_] = s_[j_];
        s_[j_] = t;
    }
}

// ---- Helpers --------------------------------------------------------------

Bytes Utf16Le(const std::string& text) {
    Bytes out;
    out.reserve(text.size() * 2);
    for (unsigned char ch : text) {
        out.push_back(ch);
        out.push_back(0);
    }
    return out;
}

Bytes Concat(const Bytes& a, const Bytes& b) {
    Bytes out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

Bytes Concat(const Bytes& a, const Bytes& b, const Bytes& c) {
    return Concat(Concat(a, b), c);
}

Bytes Concat(const Bytes& a, const Bytes& b, const Bytes& c, const Bytes& d) {
    return Concat(Concat(a, b), Concat(c, d));
}

}  // namespace rtsc::crypto
