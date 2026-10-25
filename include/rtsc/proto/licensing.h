#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// Licensing phase structures ([MS-RDPELE] 2.2, [MS-RDPBCGR] 2.2.1.12.1).
//
// The licensing exchange happens over the I/O channel after the Client Info PDU
// and before the Demand Active PDU. Every licensing PDU carries a security
// header with SEC_LICENSE_PKT (0x0080); this file models the licensing payload
// only, not the enclosing share/security headers.

// bMsgType values ([MS-RDPELE] 2.2.2). Note the gaps: this is NOT a contiguous
// range, so matching must use an explicit whitelist.
enum class LicenseMessageType : uint8_t {
    kLicenseRequest = 0x01,             // server -> client
    kPlatformChallenge = 0x02,          // server -> client
    kNewLicense = 0x03,                 // server -> client
    kUpgradeLicense = 0x04,             // server -> client
    kLicenseInfo = 0x12,                // client -> server
    kNewLicenseRequest = 0x13,          // client -> server
    kPlatformChallengeResponse = 0x15,  // client -> server
    kErrorAlert = 0xFF,                 // both directions
};

const char* to_string(LicenseMessageType type);

// LICENSE_BINARY_BLOB wBlobType values ([MS-RDPBCGR] 2.2.1.12.1.2).
enum class LicenseBlobType : uint16_t {
    kData = 0x0001,             // BB_DATA_BLOB
    kRandom = 0x0002,           // BB_RANDOM_BLOB
    kCertificate = 0x0003,      // BB_CERTIFICATE_BLOB
    kError = 0x0004,            // BB_ERROR_BLOB
    kRsaKey = 0x0006,           // BB_RSA_KEY_BLOB
    kRsaSignature = 0x0008,     // BB_RSA_SIGNATURE_BLOB
    kEncryptedData = 0x0009,    // BB_ENCRYPTED_DATA_BLOB
    kKeyExchgAlg = 0x000D,      // BB_KEY_EXCHG_ALG_BLOB
    kScope = 0x000E,            // BB_SCOPE_BLOB
    kClientUserName = 0x000F,   // BB_CLIENT_USER_NAME_BLOB
    kClientMachineName = 0x0010 // BB_CLIENT_MACHINE_NAME_BLOB
};

// License error codes ([MS-RDPBCGR] 2.2.1.12.1.3).
enum class LicenseErrorCode : uint32_t {
    kInvalidServerCertificate = 0x01,
    kNoLicense = 0x02,
    kInvalidMac = 0x03,
    kInvalidScope = 0x04,
    kNoLicenseServer = 0x06,
    kStatusValidClient = 0x07,  // success: client needs no license
    kInvalidClient = 0x08,
    kInvalidProductId = 0x0B,
    kInvalidMessageLen = 0x0C,
};

// License state transition codes ([MS-RDPBCGR] 2.2.1.12.1.3).
enum class LicenseStateTransition : uint32_t {
    kTotalAbort = 0x01,
    kNoTransition = 0x02,  // success, pairs with kStatusValidClient
    kResetPhaseToStart = 0x03,
    kResendLastMessage = 0x04,
};

// LICENSE_PREAMBLE ([MS-RDPBCGR] 2.2.1.12.1.1), 4 bytes.
//
// The same byte is called `flags` by [MS-RDPBCGR] and `bVersion` by [MS-RDPELE];
// both refer to offset 1. Windows sends 0x03 | 0x80 = 0x83.
struct LicensePreamble {
    static constexpr size_t kSize = 4;
    static constexpr uint8_t kVersionMask = 0x0F;
    static constexpr uint8_t kExtendedErrorSupported = 0x80;
    static constexpr uint8_t kVersion2 = 0x02;  // RDP 4.0
    static constexpr uint8_t kVersion3 = 0x03;  // RDP 5.0+

    LicenseMessageType type = LicenseMessageType::kErrorAlert;
    uint8_t flags = kVersion3 | kExtendedErrorSupported;
    uint16_t message_size = kSize;  // includes the 4-byte preamble

    uint8_t version() const { return static_cast<uint8_t>(flags & kVersionMask); }
    bool extended_error_supported() const {
        return (flags & kExtendedErrorSupported) != 0;
    }

    static Status parse(const uint8_t* data, size_t size, LicensePreamble& out);
    void write(ByteWriter& w) const;
};

// LICENSE_BINARY_BLOB ([MS-RDPBCGR] 2.2.1.12.1.2).
//
// Hard rule: when wBlobLen == 0 the blobData field is absent from the wire, so
// the encoded size is exactly 4 bytes.
struct LicenseBlob {
    static constexpr size_t kHeaderSize = 4;

    LicenseBlobType type = LicenseBlobType::kData;
    std::vector<uint8_t> data;

    static Status parse(ByteReader& r, LicenseBlob& out);
    void write(ByteWriter& w) const;
    size_t encoded_size() const { return kHeaderSize + data.size(); }
};

// PRODUCT_INFO ([MS-RDPELE] 2.2.2.1.1).
struct ProductInfo {
    uint32_t version = 0;               // hi16 = OS major, lo16 = OS minor
    std::vector<uint8_t> company_name;  // UTF-16LE, NUL terminated
    std::vector<uint8_t> product_id;    // UTF-16LE, NUL terminated, e.g. "A02"

    static Status parse(ByteReader& r, ProductInfo& out);
    void write(ByteWriter& w) const;

    std::string company_name_utf8() const;
    std::string product_id_utf8() const;
};

// SCOPE_LIST ([MS-RDPELE] 2.2.2.1.2): u32 count + SCOPE[].
// Each SCOPE is a LICENSE_BINARY_BLOB (type 0x000E) holding an ANSI string.
struct ScopeList {
    std::vector<std::vector<uint8_t>> scopes;  // raw ANSI bytes, NUL terminated

    static Status parse(ByteReader& r, ScopeList& out);
    void write(ByteWriter& w) const;
};

// SERVER_LICENSE_REQUEST (bMsgType 0x01, [MS-RDPELE] 2.2.2.1).
struct ServerLicenseRequest {
    std::vector<uint8_t> server_random;  // 32 bytes
    ProductInfo product_info;
    std::vector<uint32_t> key_exchange_algs;
    LicenseBlob server_certificate;  // may have an empty payload
    ScopeList scope_list;

    static Status parse(const uint8_t* data, size_t size,
                        ServerLicenseRequest& out);
};

// CLIENT_NEW_LICENSE_REQUEST (bMsgType 0x13, [MS-RDPELE] 2.2.2.2).
struct ClientNewLicenseRequest {
    static constexpr uint32_t kKeyExchangeAlgRsa = 1;
    static constexpr uint32_t kClientOsIdWinntPost52 = 0x04000000;
    static constexpr uint32_t kClientImageIdMicrosoft = 0x00010000;

    uint32_t preferred_key_exchange_alg = kKeyExchangeAlgRsa;
    uint32_t platform_id = kClientOsIdWinntPost52 | kClientImageIdMicrosoft;
    std::vector<uint8_t> client_random;         // 32 bytes
    std::vector<uint8_t> encrypted_premaster;   // RSA output, (bitlen/8)+8
    std::string user_name;                      // ANSI, NUL added on write
    std::string machine_name;                   // ANSI, NUL added on write

    std::vector<uint8_t> encode() const;
    static Status parse(const uint8_t* data, size_t size,
                        ClientNewLicenseRequest& out);
};

// SERVER_PLATFORM_CHALLENGE (bMsgType 0x02, [MS-RDPELE] 2.2.2.4).
struct ServerPlatformChallenge {
    uint32_t connect_flags = 0;              // reserved, MUST be ignored
    LicenseBlob encrypted_challenge;         // wBlobType unused
    std::vector<uint8_t> mac;                // 16 bytes over the plaintext

    static Status parse(const uint8_t* data, size_t size,
                        ServerPlatformChallenge& out);
};

// PLATFORM_CHALLENGE_RESPONSE_DATA ([MS-RDPELE] 2.2.2.5.1).
struct PlatformChallengeResponseData {
    static constexpr uint16_t kWin32ClientType = 0x0100;
    static constexpr uint16_t kDetailDetail = 0x0003;

    uint16_t version = 0x0100;
    uint16_t client_type = kWin32ClientType;
    uint16_t license_detail_level = kDetailDetail;
    std::vector<uint8_t> challenge;  // decrypted challenge, NUL included

    std::vector<uint8_t> encode() const;
    static Status parse(const uint8_t* data, size_t size,
                        PlatformChallengeResponseData& out);
};

// CLIENT_HARDWARE_ID ([MS-RDPELE] 2.2.2.3.1), fixed 20 bytes.
struct ClientHardwareId {
    static constexpr size_t kSize = 20;
    uint32_t platform_id = 0;
    uint32_t data[4] = {0, 0, 0, 0};

    std::vector<uint8_t> encode() const;
    static Status parse(const uint8_t* data, size_t size, ClientHardwareId& out);
};

// CLIENT_PLATFORM_CHALLENGE_RESPONSE (bMsgType 0x15, [MS-RDPELE] 2.2.2.5).
struct ClientPlatformChallengeResponse {
    std::vector<uint8_t> encrypted_challenge_response;
    std::vector<uint8_t> encrypted_hwid;  // 20 bytes (RC4 keeps the length)
    std::vector<uint8_t> mac;             // 16 bytes

    std::vector<uint8_t> encode() const;
};

// SERVER_NEW_LICENSE / SERVER_UPGRADE_LICENSE (0x03 / 0x04, [MS-RDPELE]
// 2.2.2.6 / 2.2.2.7). Both share one structure.
struct ServerNewLicense {
    LicenseBlob encrypted_license_info;
    std::vector<uint8_t> mac;  // 16 bytes over the plaintext NEW_LICENSE_INFO

    static Status parse(const uint8_t* data, size_t size, ServerNewLicense& out);
};

// NEW_LICENSE_INFO ([MS-RDPELE] 2.2.2.6.1).
//
// Encoding trap: pbScope is ANSI while pbCompanyName / pbProductId are UTF-16LE.
struct NewLicenseInfo {
    uint32_t version = 0;
    std::vector<uint8_t> scope;         // ANSI, NUL terminated
    std::vector<uint8_t> company_name;  // UTF-16LE, NUL terminated
    std::vector<uint8_t> product_id;    // UTF-16LE, NUL terminated
    std::vector<uint8_t> license_info;  // opaque CAL bytes

    static Status parse(const uint8_t* data, size_t size, NewLicenseInfo& out);
    std::vector<uint8_t> encode() const;
};

// LICENSE_ERROR_MESSAGE (bMsgType 0xFF, [MS-RDPBCGR] 2.2.1.12.1.3).
struct LicenseErrorMessage {
    uint32_t error_code = 0;
    uint32_t state_transition = 0;
    std::vector<uint8_t> error_info;  // may be empty

    static Status parse(const uint8_t* data, size_t size,
                        LicenseErrorMessage& out);
    std::vector<uint8_t> encode() const;

    // The "valid client" PDU: STATUS_VALID_CLIENT + ST_NO_TRANSITION.
    bool is_valid_client() const {
        return error_code == static_cast<uint32_t>(LicenseErrorCode::kStatusValidClient) &&
               state_transition ==
                   static_cast<uint32_t>(LicenseStateTransition::kNoTransition);
    }
};

// RSA_PUBLIC_KEY ([MS-RDPBCGR] 2.2.1.4.3.1.1.1).
//
// This is the RDP wire format, NOT a CryptoAPI PUBLICKEYSTRUC: there is no
// bType/bVersion/reserved/aiKeyAlg, and `modulus` carries 8 trailing zero bytes
// that are counted by keylen.
struct RsaPublicKey {
    static constexpr uint32_t kMagic = 0x31415352;  // "RSA1"

    uint32_t key_length = 0;  // modulus byte count, (bitlen/8)+8
    uint32_t bit_length = 0;
    uint32_t data_length = 0;  // (bitlen/8)-1
    uint32_t public_exponent = 0;
    std::vector<uint8_t> modulus;  // little-endian, bitlen/8 bytes (padding stripped)

    static Status parse(const uint8_t* data, size_t size, RsaPublicKey& out);
    std::vector<uint8_t> encode() const;
};

// Extracts the RSA public key from a SERVER_CERTIFICATE blob
// ([MS-RDPBCGR] 2.2.1.4.3.1). Only CERT_CHAIN_VERSION_1
// (PROPRIETARYSERVERCERTIFICATE) is supported; X.509 chains are rejected
// because extracting the key from DER is the TLS layer's job.
Status ExtractRsaPublicKey(const std::vector<uint8_t>& certificate_blob,
                           RsaPublicKey& out);

// A licensing PDU: the 4-byte preamble plus its message body, as carried in the
// payload of an MCS Send Data PDU with SEC_LICENSE_PKT set.
//
// Parse() dispatches on bMsgType and fills whichever member matches; Encode()
// writes the preamble (computing wMsgSize) followed by the body.
struct LicensingPdu {
    LicensePreamble preamble;
    ServerLicenseRequest license_request;
    ServerPlatformChallenge platform_challenge;
    ServerNewLicense new_license;
    LicenseErrorMessage error_alert;

    // Parses a complete licensing payload. Rejects a wMsgSize that disagrees
    // with the actual length, and a bMsgType outside the eight defined values.
    static Status Parse(const uint8_t* data, size_t size, LicensingPdu& out);

    // Encodes `body` with the preamble type/size filled in.
    static std::vector<uint8_t> Encode(LicenseMessageType type,
                                       const std::vector<uint8_t>& body,
                                       bool extended_error = true);
};

// ---- Licensing L3 crypto ([MS-RDPELE] 5.1.2 - 5.1.5) ----------------------

struct LicensingKeys {
    std::array<uint8_t, 16> mac_salt_key{};        // First128Bits(SessionKeyBlob)
    std::array<uint8_t, 16> encryption_key{};      // MD5(Second128Bits + CR + SR)
};

// Derives the licensing keys from the 48-byte premaster secret and the two
// 32-byte randoms. The two SaltedHash rounds use opposite random orderings,
// which is the most commonly mis-implemented part of this derivation.
LicensingKeys DeriveLicensingKeys(const std::vector<uint8_t>& premaster_secret,
                                  const std::vector<uint8_t>& client_random,
                                  const std::vector<uint8_t>& server_random);

// MACData = MD5(mac_salt_key || pad2 || SHA1(mac_salt_key || pad1 ||
//               LE32(len) || data)) with pad1 = 40 x 0x36, pad2 = 48 x 0x5C.
// Returns the full 16 bytes (not the 8-byte truncation used by Standard RDP
// Security).
std::array<uint8_t, 16> LicensingMac(const std::array<uint8_t, 16>& mac_salt_key,
                                     const std::vector<uint8_t>& data);

}  // namespace rtsc::proto
