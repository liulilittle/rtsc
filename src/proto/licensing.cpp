#include "rtsc/proto/licensing.h"

#include <cstring>

#include "rtsc/crypto/hash.h"

namespace rtsc::proto {

namespace {

// Reads a u32-length-prefixed byte field. `length` counts bytes as declared by
// the sender; a length that overruns the buffer is InvalidLength.
Status ReadU32Sized(ByteReader& r, std::vector<uint8_t>& out) {
    uint32_t n = 0;
    if (!r.u32le(n)) return Status::NeedMoreData;
    if (n > r.remaining()) return Status::InvalidLength;
    out.resize(n);
    if (n != 0 && !r.bytes(out.data(), n)) return Status::InvalidLength;
    return Status::Ok;
}

void WriteU32Sized(ByteWriter& w, const std::vector<uint8_t>& v) {
    w.u32le(static_cast<uint32_t>(v.size()));
    if (!v.empty()) w.bytes(v.data(), v.size());
}

// Appends an ANSI string with a NUL terminator (no terminator added if the
// caller already included one).
std::vector<uint8_t> AnsiZ(const std::string& s) {
    std::vector<uint8_t> out(s.begin(), s.end());
    if (out.empty() || out.back() != 0) out.push_back(0);
    return out;
}

// Decodes UTF-16LE to UTF-8, stopping at the first NUL code unit. Non-ASCII
// code points are encoded as 3-byte UTF-8; surrogate pairs are not handled
// because RDP's own fields here are ASCII in practice.
std::string Utf16LeToUtf8(const std::vector<uint8_t>& v) {
    std::string out;
    for (size_t i = 0; i + 1 < v.size(); i += 2) {
        const uint16_t cu = static_cast<uint16_t>(v[i]) |
                            static_cast<uint16_t>(v[i + 1] << 8);
        if (cu == 0) break;
        if (cu < 0x80) {
            out.push_back(static_cast<char>(cu));
        } else if (cu < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cu >> 6)));
            out.push_back(static_cast<char>(0x80 | (cu & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (cu >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cu >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cu & 0x3F)));
        }
    }
    return out;
}

}  // namespace

const char* to_string(LicenseMessageType type) {
    switch (type) {
        case LicenseMessageType::kLicenseRequest: return "license-request";
        case LicenseMessageType::kPlatformChallenge: return "platform-challenge";
        case LicenseMessageType::kNewLicense: return "new-license";
        case LicenseMessageType::kUpgradeLicense: return "upgrade-license";
        case LicenseMessageType::kLicenseInfo: return "license-info";
        case LicenseMessageType::kNewLicenseRequest: return "new-license-request";
        case LicenseMessageType::kPlatformChallengeResponse:
            return "platform-challenge-response";
        case LicenseMessageType::kErrorAlert: return "error-alert";
    }
    return "unknown";
}

// ---- LicensePreamble ------------------------------------------------------

Status LicensePreamble::parse(const uint8_t* data, size_t size,
                              LicensePreamble& out) {
    if (data == nullptr) return Status::NeedMoreData;
    if (size < kSize) return Status::NeedMoreData;
    out.type = static_cast<LicenseMessageType>(data[0]);
    out.flags = data[1];
    out.message_size = static_cast<uint16_t>(static_cast<uint16_t>(data[2]) |
                                             static_cast<uint16_t>(data[3] << 8));
    // The preamble alone is 4 bytes; anything smaller cannot be a real message.
    if (out.message_size < kSize) return Status::InvalidLength;
    return Status::Ok;
}

void LicensePreamble::write(ByteWriter& w) const {
    w.u8(static_cast<uint8_t>(type));
    w.u8(flags);
    w.u16le(message_size);
}

// ---- LicenseBlob ----------------------------------------------------------

Status LicenseBlob::parse(ByteReader& r, LicenseBlob& out) {
    uint16_t type = 0;
    uint16_t len = 0;
    if (!r.u16le(type)) return Status::NeedMoreData;
    if (!r.u16le(len)) return Status::NeedMoreData;
    out.type = static_cast<LicenseBlobType>(type);
    out.data.clear();
    // wBlobLen == 0 means blobData is absent, not empty-but-present.
    if (len == 0) return Status::Ok;
    if (len > r.remaining()) return Status::InvalidLength;
    out.data.resize(len);
    if (!r.bytes(out.data.data(), len)) return Status::InvalidLength;
    return Status::Ok;
}

void LicenseBlob::write(ByteWriter& w) const {
    w.u16le(static_cast<uint16_t>(type));
    w.u16le(static_cast<uint16_t>(data.size()));
    if (!data.empty()) w.bytes(data.data(), data.size());
}

// ---- ProductInfo ----------------------------------------------------------

Status ProductInfo::parse(ByteReader& r, ProductInfo& out) {
    if (!r.u32le(out.version)) return Status::NeedMoreData;
    Status s = ReadU32Sized(r, out.company_name);
    if (s != Status::Ok) return s;
    s = ReadU32Sized(r, out.product_id);
    if (s != Status::Ok) return s;
    // Both strings MUST be non-empty per 2.2.2.1.1.
    if (out.company_name.empty() || out.product_id.empty()) {
        return Status::InvalidField;
    }
    return Status::Ok;
}

void ProductInfo::write(ByteWriter& w) const {
    w.u32le(version);
    WriteU32Sized(w, company_name);
    WriteU32Sized(w, product_id);
}

std::string ProductInfo::company_name_utf8() const {
    return Utf16LeToUtf8(company_name);
}

std::string ProductInfo::product_id_utf8() const {
    return Utf16LeToUtf8(product_id);
}

// ---- ScopeList ------------------------------------------------------------

Status ScopeList::parse(ByteReader& r, ScopeList& out) {
    uint32_t count = 0;
    if (!r.u32le(count)) return Status::NeedMoreData;
    // Each SCOPE is at least 4 bytes, so the count is bounded by the remaining
    // input. This rejects absurd counts before allocating.
    if (count > r.remaining() / LicenseBlob::kHeaderSize) {
        return Status::InvalidLength;
    }
    out.scopes.clear();
    out.scopes.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        LicenseBlob blob;
        const Status s = LicenseBlob::parse(r, blob);
        if (s != Status::Ok) return s;
        if (blob.type != LicenseBlobType::kScope) return Status::InvalidType;
        out.scopes.push_back(std::move(blob.data));
    }
    return Status::Ok;
}

void ScopeList::write(ByteWriter& w) const {
    w.u32le(static_cast<uint32_t>(scopes.size()));
    for (const auto& scope : scopes) {
        LicenseBlob blob;
        blob.type = LicenseBlobType::kScope;
        blob.data = scope;
        blob.write(w);
    }
}

// ---- ServerLicenseRequest -------------------------------------------------

Status ServerLicenseRequest::parse(const uint8_t* data, size_t size,
                                   ServerLicenseRequest& out) {
    ByteReader r(data, size);
    out.server_random.clear();
    out.key_exchange_algs.clear();
    out.server_certificate = LicenseBlob{};

    out.server_random.resize(32);
    if (!r.bytes(out.server_random.data(), out.server_random.size())) {
        return Status::NeedMoreData;
    }
    Status s = ProductInfo::parse(r, out.product_info);
    if (s != Status::Ok) return s;

    LicenseBlob key_list;
    s = LicenseBlob::parse(r, key_list);
    if (s != Status::Ok) return s;
    if (key_list.type != LicenseBlobType::kKeyExchgAlg) return Status::InvalidType;
    if (key_list.data.size() % 4 != 0) return Status::InvalidLength;
    for (size_t i = 0; i < key_list.data.size(); i += 4) {
        const uint32_t alg = static_cast<uint32_t>(key_list.data[i]) |
                             (static_cast<uint32_t>(key_list.data[i + 1]) << 8) |
                             (static_cast<uint32_t>(key_list.data[i + 2]) << 16) |
                             (static_cast<uint32_t>(key_list.data[i + 3]) << 24);
        out.key_exchange_algs.push_back(alg);
    }

    s = LicenseBlob::parse(r, out.server_certificate);
    if (s != Status::Ok) return s;
    // wBlobLen == 0 is legal (server may rely on the MCS Connect Response
    // certificate), but a non-empty blob MUST be typed as a certificate.
    if (!out.server_certificate.data.empty() &&
        out.server_certificate.type != LicenseBlobType::kCertificate) {
        return Status::InvalidType;
    }

    s = ScopeList::parse(r, out.scope_list);
    if (s != Status::Ok) return s;
    return Status::Ok;
}

// ---- ClientNewLicenseRequest ----------------------------------------------

std::vector<uint8_t> ClientNewLicenseRequest::encode() const {
    ByteWriter w;
    w.u32le(preferred_key_exchange_alg);
    w.u32le(platform_id);
    w.bytes(client_random.data(), client_random.size());

    LicenseBlob premaster;
    premaster.type = LicenseBlobType::kRandom;
    premaster.data = encrypted_premaster;
    premaster.write(w);

    LicenseBlob user;
    user.type = LicenseBlobType::kClientUserName;
    user.data = AnsiZ(user_name);
    user.write(w);

    LicenseBlob machine;
    machine.type = LicenseBlobType::kClientMachineName;
    machine.data = AnsiZ(machine_name);
    machine.write(w);
    return w.take();
}

Status ClientNewLicenseRequest::parse(const uint8_t* data, size_t size,
                                      ClientNewLicenseRequest& out) {
    ByteReader r(data, size);
    if (!r.u32le(out.preferred_key_exchange_alg)) return Status::NeedMoreData;
    if (!r.u32le(out.platform_id)) return Status::NeedMoreData;
    out.client_random.resize(32);
    if (!r.bytes(out.client_random.data(), out.client_random.size())) {
        return Status::NeedMoreData;
    }

    LicenseBlob premaster;
    Status s = LicenseBlob::parse(r, premaster);
    if (s != Status::Ok) return s;
    if (premaster.type != LicenseBlobType::kRandom) return Status::InvalidType;
    out.encrypted_premaster = std::move(premaster.data);

    LicenseBlob user;
    s = LicenseBlob::parse(r, user);
    if (s != Status::Ok) return s;
    if (user.type != LicenseBlobType::kClientUserName) return Status::InvalidType;
    out.user_name.assign(user.data.begin(), user.data.end());

    LicenseBlob machine;
    s = LicenseBlob::parse(r, machine);
    if (s != Status::Ok) return s;
    if (machine.type != LicenseBlobType::kClientMachineName) {
        return Status::InvalidType;
    }
    out.machine_name.assign(machine.data.begin(), machine.data.end());
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

// ---- ServerPlatformChallenge ----------------------------------------------

Status ServerPlatformChallenge::parse(const uint8_t* data, size_t size,
                                      ServerPlatformChallenge& out) {
    ByteReader r(data, size);
    if (!r.u32le(out.connect_flags)) return Status::NeedMoreData;
    Status s = LicenseBlob::parse(r, out.encrypted_challenge);
    if (s != Status::Ok) return s;
    // The blob type is explicitly unused for this field, so it is not checked.
    out.mac.resize(16);
    if (!r.bytes(out.mac.data(), out.mac.size())) return Status::NeedMoreData;
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

// ---- PlatformChallengeResponseData ----------------------------------------

std::vector<uint8_t> PlatformChallengeResponseData::encode() const {
    ByteWriter w;
    w.u16le(version);
    w.u16le(client_type);
    w.u16le(license_detail_level);
    w.u16le(static_cast<uint16_t>(challenge.size()));
    if (!challenge.empty()) w.bytes(challenge.data(), challenge.size());
    return w.take();
}

Status PlatformChallengeResponseData::parse(const uint8_t* data, size_t size,
                                            PlatformChallengeResponseData& out) {
    ByteReader r(data, size);
    if (!r.u16le(out.version)) return Status::NeedMoreData;
    if (!r.u16le(out.client_type)) return Status::NeedMoreData;
    if (!r.u16le(out.license_detail_level)) return Status::NeedMoreData;
    uint16_t cb = 0;
    if (!r.u16le(cb)) return Status::NeedMoreData;
    if (cb > r.remaining()) return Status::InvalidLength;
    out.challenge.resize(cb);
    if (cb != 0 && !r.bytes(out.challenge.data(), cb)) return Status::InvalidLength;
    return Status::Ok;
}

// ---- ClientHardwareId -----------------------------------------------------

std::vector<uint8_t> ClientHardwareId::encode() const {
    ByteWriter w;
    w.u32le(platform_id);
    for (uint32_t v : data) w.u32le(v);
    return w.take();
}

Status ClientHardwareId::parse(const uint8_t* data, size_t size,
                               ClientHardwareId& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ByteReader r(data, size);
    if (!r.u32le(out.platform_id)) return Status::NeedMoreData;
    for (uint32_t& v : out.data) {
        if (!r.u32le(v)) return Status::NeedMoreData;
    }
    return Status::Ok;
}

// ---- ClientPlatformChallengeResponse --------------------------------------

std::vector<uint8_t> ClientPlatformChallengeResponse::encode() const {
    ByteWriter w;
    LicenseBlob challenge;
    challenge.type = LicenseBlobType::kEncryptedData;
    challenge.data = encrypted_challenge_response;
    challenge.write(w);

    LicenseBlob hwid;
    hwid.type = LicenseBlobType::kEncryptedData;
    hwid.data = encrypted_hwid;
    hwid.write(w);

    if (!mac.empty()) w.bytes(mac.data(), mac.size());
    return w.take();
}

// ---- ServerNewLicense -----------------------------------------------------

Status ServerNewLicense::parse(const uint8_t* data, size_t size,
                               ServerNewLicense& out) {
    ByteReader r(data, size);
    Status s = LicenseBlob::parse(r, out.encrypted_license_info);
    if (s != Status::Ok) return s;
    // wBlobType is a SHOULD, and Server 2003 leaves it undefined: never check.
    out.mac.resize(16);
    if (!r.bytes(out.mac.data(), out.mac.size())) return Status::NeedMoreData;
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

// ---- NewLicenseInfo -------------------------------------------------------

Status NewLicenseInfo::parse(const uint8_t* data, size_t size,
                             NewLicenseInfo& out) {
    ByteReader r(data, size);
    if (!r.u32le(out.version)) return Status::NeedMoreData;
    Status s = ReadU32Sized(r, out.scope);
    if (s != Status::Ok) return s;
    s = ReadU32Sized(r, out.company_name);
    if (s != Status::Ok) return s;
    s = ReadU32Sized(r, out.product_id);
    if (s != Status::Ok) return s;
    s = ReadU32Sized(r, out.license_info);
    if (s != Status::Ok) return s;
    return Status::Ok;
}

std::vector<uint8_t> NewLicenseInfo::encode() const {
    ByteWriter w;
    w.u32le(version);
    WriteU32Sized(w, scope);
    WriteU32Sized(w, company_name);
    WriteU32Sized(w, product_id);
    WriteU32Sized(w, license_info);
    return w.take();
}

// ---- LicenseErrorMessage --------------------------------------------------

Status LicenseErrorMessage::parse(const uint8_t* data, size_t size,
                                  LicenseErrorMessage& out) {
    ByteReader r(data, size);
    if (!r.u32le(out.error_code)) return Status::NeedMoreData;
    if (!r.u32le(out.state_transition)) return Status::NeedMoreData;
    LicenseBlob blob;
    const Status s = LicenseBlob::parse(r, blob);
    if (s != Status::Ok) return s;
    if (blob.type != LicenseBlobType::kError) return Status::InvalidType;
    out.error_info = std::move(blob.data);
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

std::vector<uint8_t> LicenseErrorMessage::encode() const {
    ByteWriter w;
    w.u32le(error_code);
    w.u32le(state_transition);
    LicenseBlob blob;
    blob.type = LicenseBlobType::kError;
    blob.data = error_info;
    blob.write(w);
    return w.take();
}

// ---- RsaPublicKey ---------------------------------------------------------

Status RsaPublicKey::parse(const uint8_t* data, size_t size, RsaPublicKey& out) {
    ByteReader r(data, size);
    uint32_t magic = 0;
    if (!r.u32le(magic)) return Status::NeedMoreData;
    if (magic != kMagic) return Status::InvalidField;
    if (!r.u32le(out.key_length)) return Status::NeedMoreData;
    if (!r.u32le(out.bit_length)) return Status::NeedMoreData;
    if (!r.u32le(out.data_length)) return Status::NeedMoreData;
    if (!r.u32le(out.public_exponent)) return Status::NeedMoreData;

    // Size invariants from 2.2.1.4.3.1.1.1. A bit length that is not a whole
    // number of bytes, or a key length that does not match, means the blob is
    // corrupt and the modulus would be misparsed.
    if (out.bit_length == 0 || out.bit_length % 8 != 0) {
        return Status::InvalidField;
    }
    const uint32_t modulus_bytes = out.bit_length / 8;
    if (out.key_length != modulus_bytes + 8) return Status::InvalidField;
    if (out.data_length != modulus_bytes - 1) return Status::InvalidField;
    if (out.key_length > r.remaining()) return Status::InvalidLength;

    // modulus carries 8 trailing zero padding bytes counted by key_length.
    out.modulus.resize(modulus_bytes);
    if (!r.bytes(out.modulus.data(), modulus_bytes)) return Status::InvalidLength;
    uint8_t pad[8] = {};
    if (!r.bytes(pad, sizeof(pad))) return Status::InvalidLength;
    for (uint8_t b : pad) {
        if (b != 0) return Status::InvalidField;
    }
    return Status::Ok;
}

std::vector<uint8_t> RsaPublicKey::encode() const {
    ByteWriter w;
    w.u32le(kMagic);
    w.u32le(key_length);
    w.u32le(bit_length);
    w.u32le(data_length);
    w.u32le(public_exponent);
    if (!modulus.empty()) w.bytes(modulus.data(), modulus.size());
    for (int i = 0; i < 8; ++i) w.u8(0);
    return w.take();
}

Status ExtractRsaPublicKey(const std::vector<uint8_t>& certificate_blob,
                           RsaPublicKey& out) {
    ByteReader r(certificate_blob.data(), certificate_blob.size());
    uint32_t version = 0;
    if (!r.u32le(version)) return Status::NeedMoreData;

    constexpr uint32_t kCertChainVersionMask = 0x7FFFFFFF;
    constexpr uint32_t kCertChainVersion1 = 0x00000001;
    if ((version & kCertChainVersionMask) != kCertChainVersion1) {
        // CERT_CHAIN_VERSION_2 (X.509) or unknown: the caller must fall back to
        // the MCS Connect Response certificate instead.
        return Status::InvalidType;
    }

    uint32_t sig_alg = 0;
    uint32_t key_alg = 0;
    if (!r.u32le(sig_alg)) return Status::NeedMoreData;
    if (!r.u32le(key_alg)) return Status::NeedMoreData;
    if (sig_alg != 0x00000001 || key_alg != 0x00000001) {
        return Status::InvalidField;
    }

    uint16_t blob_type = 0;
    uint16_t blob_len = 0;
    if (!r.u16le(blob_type)) return Status::NeedMoreData;
    if (!r.u16le(blob_len)) return Status::NeedMoreData;
    if (blob_type != static_cast<uint16_t>(LicenseBlobType::kRsaKey)) {
        return Status::InvalidType;
    }
    if (blob_len > r.remaining()) return Status::InvalidLength;
    return RsaPublicKey::parse(r.cursor(), blob_len, out);
}

// ---- Licensing L3 crypto --------------------------------------------------

namespace {

std::vector<uint8_t> ToVec(const std::array<uint8_t, 16>& a) {
    return std::vector<uint8_t>(a.begin(), a.end());
}

std::vector<uint8_t> ToVec(const std::array<uint8_t, 20>& a) {
    return std::vector<uint8_t>(a.begin(), a.end());
}

// SaltedHash(S, I) = MD5(S || SHA1(I || S || ClientRandom || ServerRandom)).
std::array<uint8_t, 16> SaltedHash(const std::vector<uint8_t>& salt,
                                   const std::vector<uint8_t>& ident,
                                   const std::vector<uint8_t>& client_random,
                                   const std::vector<uint8_t>& server_random) {
    using crypto::Concat;
    const auto inner = crypto::Sha1(Concat(ident, salt, client_random, server_random));
    return crypto::Md5(Concat(salt, ToVec(inner)));
}

// SaltedHash2(S, I) = MD5(S || SHA1(I || S || ServerRandom || ClientRandom)).
// The two randoms are swapped relative to SaltedHash.
std::array<uint8_t, 16> SaltedHash2(const std::vector<uint8_t>& salt,
                                    const std::vector<uint8_t>& ident,
                                    const std::vector<uint8_t>& client_random,
                                    const std::vector<uint8_t>& server_random) {
    using crypto::Concat;
    const auto inner = crypto::Sha1(Concat(ident, salt, server_random, client_random));
    return crypto::Md5(Concat(salt, ToVec(inner)));
}

}  // namespace

LicensingKeys DeriveLicensingKeys(const std::vector<uint8_t>& premaster_secret,
                                  const std::vector<uint8_t>& client_random,
                                  const std::vector<uint8_t>& server_random) {
    using crypto::Concat;
    // 'A', 'BB', 'CCC' are literal strings, not repeated characters.
    const std::vector<uint8_t> id_a = {'A'};
    const std::vector<uint8_t> id_bb = {'B', 'B'};
    const std::vector<uint8_t> id_ccc = {'C', 'C', 'C'};

    const std::vector<uint8_t> master_secret =
        Concat(ToVec(SaltedHash(premaster_secret, id_a, client_random, server_random)),
               ToVec(SaltedHash(premaster_secret, id_bb, client_random, server_random)),
               ToVec(SaltedHash(premaster_secret, id_ccc, client_random, server_random)));

    const std::vector<uint8_t> session_key_blob =
        Concat(ToVec(SaltedHash2(master_secret, id_a, client_random, server_random)),
               ToVec(SaltedHash2(master_secret, id_bb, client_random, server_random)),
               ToVec(SaltedHash2(master_secret, id_ccc, client_random, server_random)));

    LicensingKeys keys;
    std::memcpy(keys.mac_salt_key.data(), session_key_blob.data(), 16);
    const std::vector<uint8_t> second(session_key_blob.begin() + 16,
                                      session_key_blob.begin() + 32);
    keys.encryption_key = crypto::Md5(Concat(second, client_random, server_random));
    return keys;
}

std::array<uint8_t, 16> LicensingMac(const std::array<uint8_t, 16>& mac_salt_key,
                                     const std::vector<uint8_t>& data) {
    using crypto::Concat;
    const std::vector<uint8_t> key = ToVec(mac_salt_key);
    const std::vector<uint8_t> pad1(40, 0x36);
    const std::vector<uint8_t> pad2(48, 0x5c);

    const uint32_t n = static_cast<uint32_t>(data.size());
    const std::vector<uint8_t> len_field = {
        static_cast<uint8_t>(n), static_cast<uint8_t>(n >> 8),
        static_cast<uint8_t>(n >> 16), static_cast<uint8_t>(n >> 24)};

    const auto inner = crypto::Sha1(Concat(key, pad1, len_field, data));
    return crypto::Md5(Concat(key, pad2, ToVec(inner)));
}

// ---- LicensingPdu ---------------------------------------------------------

namespace {

bool IsKnownLicenseType(LicenseMessageType t) {
    switch (t) {
        case LicenseMessageType::kLicenseRequest:
        case LicenseMessageType::kPlatformChallenge:
        case LicenseMessageType::kNewLicense:
        case LicenseMessageType::kUpgradeLicense:
        case LicenseMessageType::kLicenseInfo:
        case LicenseMessageType::kNewLicenseRequest:
        case LicenseMessageType::kPlatformChallengeResponse:
        case LicenseMessageType::kErrorAlert:
            return true;
    }
    return false;
}

}  // namespace

Status LicensingPdu::Parse(const uint8_t* data, size_t size, LicensingPdu& out) {
    Status s = LicensePreamble::parse(data, size, out.preamble);
    if (s != Status::Ok) return s;
    if (!IsKnownLicenseType(out.preamble.type)) return Status::InvalidType;

    // wMsgSize covers the preamble plus the message body and nothing else.
    if (out.preamble.message_size != size) return Status::InvalidLength;

    const uint8_t* body = data + LicensePreamble::kSize;
    const size_t body_size = size - LicensePreamble::kSize;

    switch (out.preamble.type) {
        case LicenseMessageType::kLicenseRequest:
            return ServerLicenseRequest::parse(body, body_size, out.license_request);
        case LicenseMessageType::kPlatformChallenge:
            return ServerPlatformChallenge::parse(body, body_size,
                                                  out.platform_challenge);
        case LicenseMessageType::kNewLicense:
        case LicenseMessageType::kUpgradeLicense:
            return ServerNewLicense::parse(body, body_size, out.new_license);
        case LicenseMessageType::kErrorAlert:
            return LicenseErrorMessage::parse(body, body_size, out.error_alert);
        default:
            // Client-to-server messages are not expected inbound; the caller
            // decides what to do, but the framing itself is well formed.
            return Status::Ok;
    }
}

std::vector<uint8_t> LicensingPdu::Encode(LicenseMessageType type,
                                          const std::vector<uint8_t>& body,
                                          bool extended_error) {
    LicensePreamble pre;
    pre.type = type;
    pre.flags = static_cast<uint8_t>(LicensePreamble::kVersion3 |
                                     (extended_error
                                          ? LicensePreamble::kExtendedErrorSupported
                                          : 0));
    pre.message_size =
        static_cast<uint16_t>(LicensePreamble::kSize + body.size());
    ByteWriter w;
    pre.write(w);
    if (!body.empty()) w.bytes(body.data(), body.size());
    return w.take();
}

}  // namespace rtsc::proto
