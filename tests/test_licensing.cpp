#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/licensing.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> FromHex(const std::string& hex) {
    std::vector<uint8_t> out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    int hi = -1;
    for (char c : hex) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        const int v = nib(c);
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

// "Microsoft Corporation\0" in UTF-16LE (44 bytes).
std::vector<uint8_t> MicrosoftCorp() {
    std::vector<uint8_t> out;
    for (char c : std::string("Microsoft Corporation")) {
        out.push_back(static_cast<uint8_t>(c));
        out.push_back(0);
    }
    out.push_back(0);
    out.push_back(0);
    return out;
}

// "A02\0" in UTF-16LE (8 bytes).
std::vector<uint8_t> A02() {
    return {0x41, 0x00, 0x30, 0x00, 0x32, 0x00, 0x00, 0x00};
}

}  // namespace

// ---- LICENSE_PREAMBLE -----------------------------------------------------

RTSC_TEST(preamble_parses_official_bytes) {
    // [MS-RDPELE] 4.1: "01 03 98 08" -- LICENSE_REQUEST, v3, 2200 bytes.
    const auto bytes = FromHex("01 03 98 08");
    LicensePreamble p;
    CHECK(LicensePreamble::parse(bytes.data(), bytes.size(), p) == Status::Ok);
    CHECK(p.type == LicenseMessageType::kLicenseRequest);
    CHECK_EQ(p.message_size, static_cast<uint16_t>(2200));
    CHECK_EQ(p.version(), static_cast<uint8_t>(3));
    CHECK(!p.extended_error_supported());
}

RTSC_TEST(preamble_flags_high_bit_is_extended_error) {
    const auto bytes = FromHex("13 83 55 01");
    LicensePreamble p;
    CHECK(LicensePreamble::parse(bytes.data(), bytes.size(), p) == Status::Ok);
    CHECK(p.type == LicenseMessageType::kNewLicenseRequest);
    CHECK_EQ(p.message_size, static_cast<uint16_t>(341));
    CHECK_EQ(p.version(), static_cast<uint8_t>(3));
    CHECK(p.extended_error_supported());
}

RTSC_TEST(preamble_rejects_truncated_and_short_size) {
    LicensePreamble p;
    const auto short_input = FromHex("01 03 98");
    CHECK(LicensePreamble::parse(short_input.data(), short_input.size(), p) ==
          Status::NeedMoreData);
    // message_size < 4 cannot contain the preamble itself.
    const auto bad = FromHex("01 03 03 00");
    CHECK(LicensePreamble::parse(bad.data(), bad.size(), p) == Status::InvalidLength);
}

RTSC_TEST(preamble_roundtrips) {
    LicensePreamble p;
    p.type = LicenseMessageType::kPlatformChallengeResponse;
    p.flags = 0x83;
    p.message_size = 66;
    ByteWriter w;
    p.write(w);
    CHECK_BYTES(w.data(), 0x15, 0x83, 0x42, 0x00);
}

RTSC_TEST(message_type_names_cover_all_eight) {
    CHECK(std::string(to_string(LicenseMessageType::kLicenseRequest)) ==
          "license-request");
    CHECK(std::string(to_string(LicenseMessageType::kErrorAlert)) == "error-alert");
    CHECK(std::string(to_string(LicenseMessageType::kPlatformChallengeResponse)) ==
          "platform-challenge-response");
    CHECK(std::string(to_string(static_cast<LicenseMessageType>(0x05))) == "unknown");
}

// ---- LICENSE_BINARY_BLOB --------------------------------------------------

RTSC_TEST(blob_zero_length_has_no_payload) {
    // Hard rule: wBlobLen == 0 means blobData is absent, so the blob is 4 bytes.
    const auto bytes = FromHex("09 00 00 00");
    ByteReader r(bytes.data(), bytes.size());
    LicenseBlob blob;
    CHECK(LicenseBlob::parse(r, blob) == Status::Ok);
    CHECK(blob.type == LicenseBlobType::kEncryptedData);
    CHECK(blob.data.empty());
    CHECK_EQ(blob.encoded_size(), static_cast<size_t>(4));
    CHECK(r.empty());

    ByteWriter w;
    blob.write(w);
    CHECK_BYTES(w.data(), 0x09, 0x00, 0x00, 0x00);
}

RTSC_TEST(blob_rejects_length_overrun) {
    const auto bytes = FromHex("09 00 10 00 01 02");
    ByteReader r(bytes.data(), bytes.size());
    LicenseBlob blob;
    CHECK(LicenseBlob::parse(r, blob) == Status::InvalidLength);
}

RTSC_TEST(blob_roundtrips_payload) {
    LicenseBlob blob;
    blob.type = LicenseBlobType::kRandom;
    blob.data = FromHex("de ad be ef");
    ByteWriter w;
    blob.write(w);
    CHECK_BYTES(w.data(), 0x02, 0x00, 0x04, 0x00, 0xde, 0xad, 0xbe, 0xef);

    ByteReader r(w.data().data(), w.data().size());
    LicenseBlob back;
    CHECK(LicenseBlob::parse(r, back) == Status::Ok);
    CHECK(back.type == LicenseBlobType::kRandom);
    CHECK(back.data == blob.data);
}

// ---- PRODUCT_INFO ---------------------------------------------------------

RTSC_TEST(product_info_matches_official_dump) {
    // From 11.1: dwVersion 0x00060000, "Microsoft Corporation", "A02".
    ByteWriter w;
    w.u32le(0x00060000);
    const auto company = MicrosoftCorp();
    w.u32le(static_cast<uint32_t>(company.size()));
    w.bytes(company.data(), company.size());
    const auto pid = A02();
    w.u32le(static_cast<uint32_t>(pid.size()));
    w.bytes(pid.data(), pid.size());

    ByteReader r(w.data().data(), w.data().size());
    ProductInfo pi;
    CHECK(ProductInfo::parse(r, pi) == Status::Ok);
    CHECK_EQ(pi.version, static_cast<uint32_t>(0x00060000));
    CHECK_EQ(pi.company_name.size(), static_cast<size_t>(44));
    CHECK_EQ(pi.product_id.size(), static_cast<size_t>(8));
    CHECK(pi.company_name_utf8() == "Microsoft Corporation");
    CHECK(pi.product_id_utf8() == "A02");
    CHECK(r.empty());

    ByteWriter re;
    pi.write(re);
    CHECK(re.data() == w.data());
}

RTSC_TEST(product_info_rejects_empty_strings) {
    ByteWriter w;
    w.u32le(0);
    w.u32le(0);  // cbCompanyName = 0, which the spec forbids
    w.u32le(0);
    ByteReader r(w.data().data(), w.data().size());
    ProductInfo pi;
    CHECK(ProductInfo::parse(r, pi) == Status::InvalidField);
}

// ---- SCOPE_LIST -----------------------------------------------------------

RTSC_TEST(scope_list_matches_official_dump) {
    // 11.1 tail: ScopeCount=1, blob type 0x000E, len 14, "microsoft.com\0" (ANSI).
    const auto bytes = FromHex(
        "01 00 00 00 0e 00 0e 00 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 00");
    ByteReader r(bytes.data(), bytes.size());
    ScopeList list;
    CHECK(ScopeList::parse(r, list) == Status::Ok);
    CHECK_EQ(list.scopes.size(), static_cast<size_t>(1));
    CHECK_EQ(list.scopes[0].size(), static_cast<size_t>(14));
    CHECK(std::string(list.scopes[0].begin(), list.scopes[0].end()) ==
          std::string("microsoft.com\0", 14));
    CHECK(r.empty());

    ByteWriter w;
    list.write(w);
    CHECK(w.data() == bytes);
}

RTSC_TEST(scope_list_rejects_wrong_blob_type) {
    // Type 0x0001 instead of 0x000E.
    const auto bytes = FromHex("01 00 00 00 01 00 01 00 00");
    ByteReader r(bytes.data(), bytes.size());
    ScopeList list;
    CHECK(ScopeList::parse(r, list) == Status::InvalidType);
}

RTSC_TEST(scope_list_rejects_absurd_count) {
    const auto bytes = FromHex("ff ff ff ff 0e 00 00 00");
    ByteReader r(bytes.data(), bytes.size());
    ScopeList list;
    CHECK(ScopeList::parse(r, list) == Status::InvalidLength);
}

// ---- SERVER_LICENSE_REQUEST -----------------------------------------------

namespace {

// Rebuilds the header portion of the official 11.1 dump (through the
// certificate blob header) and appends a synthetic certificate payload.
std::vector<uint8_t> BuildLicenseRequest(uint16_t cert_len,
                                         const std::vector<uint8_t>& cert) {
    ByteWriter w;
    for (int i = 0; i < 32; ++i) w.u8(static_cast<uint8_t>(0xA0 + i));  // ServerRandom
    w.u32le(0x00060000);
    const auto company = MicrosoftCorp();
    w.u32le(static_cast<uint32_t>(company.size()));
    w.bytes(company.data(), company.size());
    const auto pid = A02();
    w.u32le(static_cast<uint32_t>(pid.size()));
    w.bytes(pid.data(), pid.size());
    w.u16le(0x000D);  // BB_KEY_EXCHG_ALG_BLOB
    w.u16le(4);
    w.u32le(1);  // KEY_EXCHANGE_ALG_RSA
    w.u16le(0x0003);  // BB_CERTIFICATE_BLOB
    w.u16le(cert_len);
    if (!cert.empty()) w.bytes(cert.data(), cert.size());
    w.u32le(1);      // ScopeCount
    w.u16le(0x000E);
    w.u16le(14);
    const std::string scope = "microsoft.com";
    for (char c : scope) w.u8(static_cast<uint8_t>(c));
    w.u8(0);
    return w.take();
}

}  // namespace

RTSC_TEST(server_license_request_parses_official_layout) {
    const std::vector<uint8_t> cert = {0x02, 0x00, 0x00, 0x80};
    const auto bytes = BuildLicenseRequest(static_cast<uint16_t>(cert.size()), cert);

    ServerLicenseRequest req;
    CHECK(ServerLicenseRequest::parse(bytes.data(), bytes.size(), req) == Status::Ok);
    CHECK_EQ(req.server_random.size(), static_cast<size_t>(32));
    CHECK_EQ(req.server_random[0], static_cast<uint8_t>(0xA0));
    CHECK_EQ(req.product_info.version, static_cast<uint32_t>(0x00060000));
    CHECK(req.product_info.company_name_utf8() == "Microsoft Corporation");
    CHECK(req.product_info.product_id_utf8() == "A02");
    CHECK_EQ(req.key_exchange_algs.size(), static_cast<size_t>(1));
    CHECK_EQ(req.key_exchange_algs[0], static_cast<uint32_t>(1));
    CHECK(req.server_certificate.type == LicenseBlobType::kCertificate);
    CHECK(req.server_certificate.data == cert);
    CHECK_EQ(req.scope_list.scopes.size(), static_cast<size_t>(1));
}

RTSC_TEST(server_license_request_allows_empty_certificate) {
    // wBlobLen == 0: the server relies on the MCS Connect Response certificate.
    const auto bytes = BuildLicenseRequest(0, {});
    ServerLicenseRequest req;
    CHECK(ServerLicenseRequest::parse(bytes.data(), bytes.size(), req) == Status::Ok);
    CHECK(req.server_certificate.data.empty());
}

RTSC_TEST(server_license_request_rejects_wrong_cert_type) {
    // Replace the certificate blob type with BB_DATA_BLOB while keeping a payload.
    auto bytes = BuildLicenseRequest(2, {0xAA, 0xBB});
    // The certificate blob type sits right after the key exchange list.
    const size_t off = 32 + 4 + 4 + 44 + 4 + 8 + 4 + 4;
    CHECK_EQ(bytes[off], static_cast<uint8_t>(0x03));
    bytes[off] = 0x01;
    ServerLicenseRequest req;
    CHECK(ServerLicenseRequest::parse(bytes.data(), bytes.size(), req) ==
          Status::InvalidType);
}

RTSC_TEST(server_license_request_rejects_short_random) {
    const auto bytes = FromHex("00 01 02 03");
    ServerLicenseRequest req;
    CHECK(ServerLicenseRequest::parse(bytes.data(), bytes.size(), req) ==
          Status::NeedMoreData);
}

// ---- CLIENT_NEW_LICENSE_REQUEST -------------------------------------------

RTSC_TEST(client_new_license_request_matches_official_dump) {
    // Reconstruct 11.2 field by field, then compare the exact wire bytes for the
    // header, the three blob headers, and the two ANSI strings.
    ClientNewLicenseRequest req;
    req.preferred_key_exchange_alg = 1;
    req.platform_id = 0x04010000;
    req.client_random.assign(32, 0x5A);
    req.encrypted_premaster.assign(264, 0x77);
    req.user_name = "Administrator";
    req.machine_name = "RODENT";
    const auto bytes = req.encode();

    // 4 + 4 + 32 + (4+264) + (4+14) + (4+7) = 337 body bytes;
    // the official 341-byte PDU adds the 4-byte preamble.
    CHECK_EQ(bytes.size(), static_cast<size_t>(337));
    CHECK_EQ(bytes[0], static_cast<uint8_t>(0x01));  // PreferredKeyExchangeAlg LE
    // Body layout (no preamble): alg@0, PlatformId@4, ClientRandom@8.
    CHECK_EQ(bytes[4], static_cast<uint8_t>(0x00));  // PlatformId = 0x04010000
    CHECK_EQ(bytes[5], static_cast<uint8_t>(0x00));
    CHECK_EQ(bytes[6], static_cast<uint8_t>(0x01));
    CHECK_EQ(bytes[7], static_cast<uint8_t>(0x04));
    CHECK_EQ(bytes[40], static_cast<uint8_t>(0x02));  // BB_RANDOM_BLOB
    CHECK_EQ(bytes[42], static_cast<uint8_t>(0x08));  // wBlobLen = 0x0108
    CHECK_EQ(bytes[43], static_cast<uint8_t>(0x01));

    ClientNewLicenseRequest back;
    CHECK(ClientNewLicenseRequest::parse(bytes.data(), bytes.size(), back) ==
          Status::Ok);
    CHECK_EQ(back.platform_id, static_cast<uint32_t>(0x04010000));
    CHECK_EQ(back.encrypted_premaster.size(), static_cast<size_t>(264));
    CHECK(back.user_name == std::string("Administrator\0", 14));
    CHECK(back.machine_name == std::string("RODENT\0", 7));
}

RTSC_TEST(client_new_license_request_rejects_wrong_blob_types) {
    ClientNewLicenseRequest req;
    req.client_random.assign(32, 0);
    req.encrypted_premaster.assign(8, 0);
    req.user_name = "u";
    req.machine_name = "m";
    auto bytes = req.encode();

    // Premaster blob type lives at offset 4+4+32 = 40.
    bytes[40] = 0x09;
    ClientNewLicenseRequest back;
    CHECK(ClientNewLicenseRequest::parse(bytes.data(), bytes.size(), back) ==
          Status::InvalidType);
}

// ---- SERVER_PLATFORM_CHALLENGE --------------------------------------------

RTSC_TEST(platform_challenge_matches_official_dump) {
    // 11.3, complete 38-byte message.
    // The 38-byte message minus the 4-byte preamble is a 34-byte body.
    const auto bytes = FromHex(
        "ff ff ff ff 50 f7 0a 00 46 37 85 54 8e c5 91 34 97 5d "
        "78 94 ad 3b 81 da 88 18 56 0f 3a d1 f1 03 ef 35");
    CHECK_EQ(bytes.size(), static_cast<size_t>(34));

    ServerPlatformChallenge ch;
    CHECK(ServerPlatformChallenge::parse(bytes.data(), bytes.size(), ch) == Status::Ok);
    // ConnectFlags is uninitialized on the wire and MUST NOT be validated.
    CHECK_EQ(ch.connect_flags, static_cast<uint32_t>(0xFFFFFFFF));
    CHECK_EQ(ch.encrypted_challenge.data.size(), static_cast<size_t>(10));
    // The blob type is 0x50F7 -- garbage. Parsing must not reject it.
    CHECK_EQ(static_cast<uint16_t>(ch.encrypted_challenge.type),
             static_cast<uint16_t>(0xF750));
    CHECK_EQ(ch.mac.size(), static_cast<size_t>(16));
    CHECK_BYTES(ch.mac, 0x78, 0x94, 0xad, 0x3b, 0x81, 0xda, 0x88, 0x18, 0x56,
                0x0f, 0x3a, 0xd1, 0xf1, 0x03, 0xef, 0x35);
}

RTSC_TEST(platform_challenge_rejects_missing_mac) {
    const auto bytes = FromHex(
        "ff ff ff ff 50 f7 0a 00 46 37 85 54 8e c5 91 34 97 5d");
    ServerPlatformChallenge ch;
    CHECK(ServerPlatformChallenge::parse(bytes.data(), bytes.size(), ch) ==
          Status::NeedMoreData);
}

RTSC_TEST(platform_challenge_rejects_trailing_garbage) {
    auto bytes = FromHex(
        "ff ff ff ff 50 f7 0a 00 46 37 85 54 8e c5 91 34 97 5d "
        "78 94 ad 3b 81 da 88 18 56 0f 3a d1 f1 03 ef 35");
    bytes.push_back(0x00);
    ServerPlatformChallenge ch;
    CHECK(ServerPlatformChallenge::parse(bytes.data(), bytes.size(), ch) ==
          Status::InvalidLength);
}

// ---- PLATFORM_CHALLENGE_RESPONSE_DATA -------------------------------------

RTSC_TEST(pcr_data_matches_official_decrypted_bytes) {
    // 11.4 decrypted PCR_DATA (18 bytes).
    const auto bytes = FromHex(
        "00 01 00 01 03 00 0a 00 54 00 45 00 53 00 54 00 00 00");
    PlatformChallengeResponseData d;
    CHECK(PlatformChallengeResponseData::parse(bytes.data(), bytes.size(), d) ==
          Status::Ok);
    CHECK_EQ(d.version, static_cast<uint16_t>(0x0100));
    CHECK_EQ(d.client_type, static_cast<uint16_t>(0x0100));
    CHECK_EQ(d.license_detail_level, static_cast<uint16_t>(0x0003));
    CHECK_EQ(d.challenge.size(), static_cast<size_t>(10));
    CHECK_BYTES(d.challenge, 0x54, 0x00, 0x45, 0x00, 0x53, 0x00, 0x54, 0x00, 0x00,
                0x00);
    CHECK(d.encode() == bytes);
}

RTSC_TEST(pcr_data_rejects_challenge_overrun) {
    const auto bytes = FromHex("00 01 00 01 03 00 0a 00 54 00");
    PlatformChallengeResponseData d;
    CHECK(PlatformChallengeResponseData::parse(bytes.data(), bytes.size(), d) ==
          Status::InvalidLength);
}

// ---- CLIENT_HARDWARE_ID ---------------------------------------------------

RTSC_TEST(hardware_id_is_20_bytes) {
    ClientHardwareId id;
    id.platform_id = 0x04010000;
    id.data[0] = 0x3E8759F1;
    id.data[1] = 0xAF98D8C9;
    id.data[2] = 0xF3F80224;
    id.data[3] = 0x26F03A29;
    const auto bytes = id.encode();
    CHECK_EQ(bytes.size(), static_cast<size_t>(20));

    ClientHardwareId back;
    CHECK(ClientHardwareId::parse(bytes.data(), bytes.size(), back) == Status::Ok);
    CHECK_EQ(back.platform_id, static_cast<uint32_t>(0x04010000));
    CHECK_EQ(back.data[0], static_cast<uint32_t>(0x3E8759F1));
    CHECK_EQ(back.data[3], static_cast<uint32_t>(0x26F03A29));
}

RTSC_TEST(hardware_id_rejects_short_input) {
    std::vector<uint8_t> bytes(19, 0);
    ClientHardwareId id;
    CHECK(ClientHardwareId::parse(bytes.data(), bytes.size(), id) ==
          Status::NeedMoreData);
}

// ---- CLIENT_PLATFORM_CHALLENGE_RESPONSE -----------------------------------

RTSC_TEST(client_platform_challenge_response_encodes_with_encrypted_blob_type) {
    ClientPlatformChallengeResponse resp;
    resp.encrypted_challenge_response =
        FromHex("fa b4 e8 24 cf 56 b2 4e 80 02 bd b6 61 fc df e9 6c 44");
    resp.encrypted_hwid =
        FromHex("f8 b5 e8 25 3d 0f 3f 70 1d da 60 19 16 fe 73 1a 45 7e 02 71");
    resp.mac = FromHex("38 23 62 5d 10 8b 93 c3 f1 e4 67 1f 4a b6 00 0a");

    const auto body = resp.encode();
    // 4 + (4+18) + (4+20) + 16 = 66 including the preamble.
    CHECK_EQ(body.size(), static_cast<size_t>(62));
    const auto full =
        LicensingPdu::Encode(LicenseMessageType::kPlatformChallengeResponse, body);
    CHECK_EQ(full.size(), static_cast<size_t>(66));
    CHECK_EQ(full[0], static_cast<uint8_t>(0x15));
    CHECK_EQ(full[1], static_cast<uint8_t>(0x83));
    CHECK_EQ(full[2], static_cast<uint8_t>(0x42));
    CHECK_EQ(full[3], static_cast<uint8_t>(0x00));
    // We write the SHOULD value BB_ENCRYPTED_DATA_BLOB (0x0009).
    CHECK_EQ(full[4], static_cast<uint8_t>(0x09));
    CHECK_EQ(full[5], static_cast<uint8_t>(0x00));
    CHECK_EQ(full[6], static_cast<uint8_t>(0x12));  // wBlobLen = 18
    CHECK_EQ(full[26], static_cast<uint8_t>(0x09));  // second blob type
    CHECK_EQ(full[28], static_cast<uint8_t>(0x14));  // wBlobLen = 20
}

RTSC_TEST(client_platform_challenge_response_official_dump_uses_blob_type_1) {
    // [MS-RDPELE] 4.5: the official client writes 0x0001 for BOTH blobs even
    // though the spec says SHOULD 0x0009. A receiver that validates this field
    // would reject a real Windows client, so parsing must not check it.
    const auto official = FromHex(
        "15 83 42 00 01 00 12 00 fa b4 e8 24 cf 56 b2 4e 80 02 bd b6 61 fc df e9 "
        "6c 44 01 00 14 00 f8 b5 e8 25 3d 0f 3f 70 1d da 60 19 16 fe 73 1a 45 7e "
        "02 71 38 23 62 5d 10 8b 93 c3 f1 e4 67 1f 4a b6 00 0a");
    CHECK_EQ(official.size(), static_cast<size_t>(66));
    // Spot-check the two blob-type words that differ from what we emit.
    CHECK_EQ(official[4], static_cast<uint8_t>(0x01));
    CHECK_EQ(official[26], static_cast<uint8_t>(0x01));
    // The 18-byte challenge response decrypts to a 10-byte challenge, and the
    // 20-byte HWID blob is exactly CLIENT_HARDWARE_ID's size.
    CHECK_EQ(official[6], static_cast<uint8_t>(0x12));
    CHECK_EQ(official[28], static_cast<uint8_t>(0x14));
}

// ---- SERVER_NEW_LICENSE / NEW_LICENSE_INFO --------------------------------

RTSC_TEST(new_license_matches_official_header) {
    // 11.5 header: type 0x03, flags 0x03, size 0x0807, blob 0x0009 / 0x07EF,
    // then 2031 ciphertext bytes and a 16-byte MAC.
    ByteWriter w;
    w.u16le(0x0009);
    w.u16le(0x07EF);
    std::vector<uint8_t> cipher(2031, 0x5C);
    w.bytes(cipher.data(), cipher.size());
    for (int i = 0; i < 16; ++i) w.u8(static_cast<uint8_t>(i));

    ServerNewLicense lic;
    CHECK(ServerNewLicense::parse(w.data().data(), w.data().size(), lic) ==
          Status::Ok);
    CHECK(lic.encrypted_license_info.type == LicenseBlobType::kEncryptedData);
    CHECK_EQ(lic.encrypted_license_info.data.size(), static_cast<size_t>(2031));
    CHECK_EQ(lic.mac.size(), static_cast<size_t>(16));
    // 4 + 4 + 2031 + 16 = 2055 = 0x0807 (the wMsgSize from the dump).
    CHECK_EQ(4 + 4 + lic.encrypted_license_info.data.size() + lic.mac.size(),
             static_cast<size_t>(0x0807));
}

RTSC_TEST(new_license_info_mixed_ansi_and_utf16) {
    // 11.5 decrypted NEW_LICENSE_INFO prefix: ANSI scope + UTF-16LE company.
    ByteWriter w;
    w.u32le(0x00060000);
    const std::string scope = "microsoft.com";
    w.u32le(14);
    for (char c : scope) w.u8(static_cast<uint8_t>(c));
    w.u8(0);
    const auto company = MicrosoftCorp();
    w.u32le(static_cast<uint32_t>(company.size()));
    w.bytes(company.data(), company.size());
    const auto pid = A02();
    w.u32le(static_cast<uint32_t>(pid.size()));
    w.bytes(pid.data(), pid.size());
    w.u32le(3);
    w.bytes(reinterpret_cast<const uint8_t*>("\x30\x82\x01"), 3);

    NewLicenseInfo info;
    CHECK(NewLicenseInfo::parse(w.data().data(), w.data().size(), info) == Status::Ok);
    CHECK_EQ(info.version, static_cast<uint32_t>(0x00060000));
    // pbScope is ANSI: 14 bytes, not 28.
    CHECK_EQ(info.scope.size(), static_cast<size_t>(14));
    CHECK(std::string(info.scope.begin(), info.scope.end()) ==
          std::string("microsoft.com\0", 14));
    // pbCompanyName is UTF-16LE: 44 bytes, not 22.
    CHECK_EQ(info.company_name.size(), static_cast<size_t>(44));
    CHECK_EQ(info.product_id.size(), static_cast<size_t>(8));
    CHECK_EQ(info.license_info.size(), static_cast<size_t>(3));
    CHECK(info.encode() == w.data());
}

// ---- LICENSE_ERROR_MESSAGE ------------------------------------------------

RTSC_TEST(error_alert_valid_client_is_16_bytes) {
    LicenseErrorMessage m;
    m.error_code = static_cast<uint32_t>(LicenseErrorCode::kStatusValidClient);
    m.state_transition =
        static_cast<uint32_t>(LicenseStateTransition::kNoTransition);
    const auto bytes = m.encode();
    // Body: 4 + 4 + 4 (empty BB_ERROR_BLOB header) = 12 bytes. The full
    // 16-byte PDU adds the 4-byte preamble.
    CHECK_EQ(bytes.size(), static_cast<size_t>(12));
    CHECK_BYTES(bytes, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00,
                0x00, 0x00);

    const auto full = LicensingPdu::Encode(LicenseMessageType::kErrorAlert, bytes);
    CHECK_EQ(full.size(), static_cast<size_t>(16));
    CHECK(m.is_valid_client());

    LicenseErrorMessage back;
    CHECK(LicenseErrorMessage::parse(bytes.data(), bytes.size(), back) == Status::Ok);
    CHECK(back.is_valid_client());
    CHECK(back.error_info.empty());
}

RTSC_TEST(error_alert_valid_client_is_not_an_error) {
    // This is the trap the spec calls out: STATUS_VALID_CLIENT is a SUCCESS
    // signal. Treating it as a failure aborts a connection that would have
    // proceeded to Demand Active.
    LicenseErrorMessage m;
    m.error_code = 7;
    m.state_transition = 2;
    CHECK(m.is_valid_client());
    m.state_transition = 1;  // ST_TOTAL_ABORT
    CHECK(!m.is_valid_client());
}

RTSC_TEST(error_alert_rejects_wrong_blob_type) {
    const auto bytes = FromHex("03 00 00 00 01 00 00 00 09 00 00 00");
    LicenseErrorMessage m;
    CHECK(LicenseErrorMessage::parse(bytes.data(), bytes.size(), m) ==
          Status::InvalidType);
}

RTSC_TEST(error_alert_carries_error_info) {
    LicenseErrorMessage m;
    m.error_code = static_cast<uint32_t>(LicenseErrorCode::kInvalidMac);
    m.state_transition = static_cast<uint32_t>(LicenseStateTransition::kTotalAbort);
    m.error_info = FromHex("01 02 03");
    const auto bytes = m.encode();
    CHECK_EQ(bytes.size(), static_cast<size_t>(15));

    LicenseErrorMessage back;
    CHECK(LicenseErrorMessage::parse(bytes.data(), bytes.size(), back) == Status::Ok);
    CHECK_EQ(back.error_code, static_cast<uint32_t>(0x03));
    CHECK_EQ(back.state_transition, static_cast<uint32_t>(0x01));
    CHECK_BYTES(back.error_info, 0x01, 0x02, 0x03);
}

// ---- RSA_PUBLIC_KEY -------------------------------------------------------

namespace {

// 512-bit key exactly as printed in [MS-RDPBCGR] 5.3.3.1.2.
std::vector<uint8_t> OfficialRsa512() {
    return FromHex(
        "52 53 41 31"          // magic "RSA1"
        "48 00 00 00"          // keylen = 72
        "00 02 00 00"          // bitlen = 512
        "3f 00 00 00"          // datalen = 63
        "01 00 01 00"          // pubExp = 65537
        // 64-byte little-endian modulus
        "af da 0d a7 4a 8b 3c 5b 5d 8b 9c 6d 7f 8c 1e 3f"
        "6e 2c 5d 3a 4b 7c 9d 1e 2f 3a 4b 5c 6d 7e 8f 90"
        "a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d 7e 8f 90"
        "a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d 7e 8f 90"
        // 8 zero padding bytes counted by keylen
        "00 00 00 00 00 00 00 00");
}

}  // namespace

RTSC_TEST(rsa_public_key_parses_official_layout) {
    const auto bytes = OfficialRsa512();
    CHECK_EQ(bytes.size(), static_cast<size_t>(92));

    RsaPublicKey key;
    CHECK(RsaPublicKey::parse(bytes.data(), bytes.size(), key) == Status::Ok);
    CHECK_EQ(key.key_length, static_cast<uint32_t>(72));
    CHECK_EQ(key.bit_length, static_cast<uint32_t>(512));
    CHECK_EQ(key.data_length, static_cast<uint32_t>(63));
    CHECK_EQ(key.public_exponent, static_cast<uint32_t>(65537));
    // The modulus keeps only bitlen/8 bytes; the 8-byte padding is stripped.
    CHECK_EQ(key.modulus.size(), static_cast<size_t>(64));
    CHECK_EQ(key.modulus[0], static_cast<uint8_t>(0xAF));
    CHECK(key.encode() == bytes);
}

RTSC_TEST(rsa_public_key_accepts_2048_bit) {
    // 2048-bit: keylen = 264, datalen = 255, total 284 bytes.
    std::vector<uint8_t> bytes;
    auto push32 = [&bytes](uint32_t v) {
        for (int i = 0; i < 4; ++i) bytes.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    push32(0x31415352);
    push32(264);
    push32(2048);
    push32(255);
    push32(65537);
    bytes.insert(bytes.end(), 256, 0x11);
    bytes.insert(bytes.end(), 8, 0x00);
    CHECK_EQ(bytes.size(), static_cast<size_t>(284));

    RsaPublicKey key;
    CHECK(RsaPublicKey::parse(bytes.data(), bytes.size(), key) == Status::Ok);
    CHECK_EQ(key.modulus.size(), static_cast<size_t>(256));
}

RTSC_TEST(rsa_public_key_rejects_bad_magic) {
    auto bytes = OfficialRsa512();
    bytes[0] = 0x00;
    RsaPublicKey key;
    CHECK(RsaPublicKey::parse(bytes.data(), bytes.size(), key) ==
          Status::InvalidField);
}

RTSC_TEST(rsa_public_key_rejects_inconsistent_lengths) {
    // keylen must equal bitlen/8 + 8.
    auto bytes = OfficialRsa512();
    bytes[4] = 0x40;  // keylen = 64 instead of 72
    RsaPublicKey key;
    CHECK(RsaPublicKey::parse(bytes.data(), bytes.size(), key) ==
          Status::InvalidField);

    // datalen must equal bitlen/8 - 1.
    auto bytes2 = OfficialRsa512();
    bytes2[12] = 0x40;  // datalen = 64 instead of 63
    CHECK(RsaPublicKey::parse(bytes2.data(), bytes2.size(), key) ==
          Status::InvalidField);
}

RTSC_TEST(rsa_public_key_rejects_nonzero_padding) {
    auto bytes = OfficialRsa512();
    bytes.back() = 0x01;
    RsaPublicKey key;
    CHECK(RsaPublicKey::parse(bytes.data(), bytes.size(), key) ==
          Status::InvalidField);
}

RTSC_TEST(rsa_public_key_rejects_non_byte_aligned_bits) {
    auto bytes = OfficialRsa512();
    bytes[8] = 0x01;  // bitlen = 257
    RsaPublicKey key;
    CHECK(RsaPublicKey::parse(bytes.data(), bytes.size(), key) ==
          Status::InvalidField);
}

RTSC_TEST(extract_rsa_from_proprietary_certificate) {
    // PROPRIETARYSERVERCERTIFICATE header + RSA blob + a dummy signature blob.
    ByteWriter w;
    w.u32le(0x00000001);  // dwVersion = CERT_CHAIN_VERSION_1
    w.u32le(0x00000001);  // dwSigAlgId = SIGNATURE_ALG_RSA
    w.u32le(0x00000001);  // dwKeyAlgId = KEY_EXCHANGE_ALG_RSA
    const auto rsa = OfficialRsa512();
    w.u16le(0x0006);  // BB_RSA_KEY_BLOB
    w.u16le(static_cast<uint16_t>(rsa.size()));
    w.bytes(rsa.data(), rsa.size());
    w.u16le(0x0008);  // BB_RSA_SIGNATURE_BLOB
    w.u16le(4);
    w.bytes(reinterpret_cast<const uint8_t*>("\x01\x02\x03\x04"), 4);

    RsaPublicKey key;
    CHECK(ExtractRsaPublicKey(w.data(), key) == Status::Ok);
    CHECK_EQ(key.bit_length, static_cast<uint32_t>(512));
}

RTSC_TEST(extract_rsa_rejects_x509_chain) {
    // certChainVersion = 2 (X.509): the caller must fall back elsewhere.
    ByteWriter w;
    w.u32le(0x80000002);
    RsaPublicKey key;
    CHECK(ExtractRsaPublicKey(w.data(), key) == Status::InvalidType);
}

RTSC_TEST(extract_rsa_rejects_bad_algorithm_ids) {
    ByteWriter w;
    w.u32le(0x00000001);
    w.u32le(0x00000002);  // wrong signature algorithm
    w.u32le(0x00000001);
    RsaPublicKey key;
    CHECK(ExtractRsaPublicKey(w.data(), key) == Status::InvalidField);
}

// ---- Licensing L3 key derivation and MAC ----------------------------------

RTSC_TEST(licensing_keys_are_16_bytes_each) {
    const std::vector<uint8_t> premaster(48, 0x31);
    const std::vector<uint8_t> cr(32, 0x32);
    const std::vector<uint8_t> sr(32, 0x33);
    const auto keys = DeriveLicensingKeys(premaster, cr, sr);
    // std::array::size() is constexpr, so CHECK_EQ would trip C4127.
    CHECK(keys.mac_salt_key.size() == 16);
    CHECK(keys.encryption_key.size() == 16);
    // The two halves of SessionKeyBlob feed different outputs, so the MAC salt
    // and the encryption key must not coincide.
    CHECK(keys.mac_salt_key != keys.encryption_key);
}

RTSC_TEST(licensing_keys_are_deterministic_and_input_sensitive) {
    const std::vector<uint8_t> premaster(48, 0x01);
    const std::vector<uint8_t> cr(32, 0x02);
    const std::vector<uint8_t> sr(32, 0x03);
    const auto a = DeriveLicensingKeys(premaster, cr, sr);
    const auto b = DeriveLicensingKeys(premaster, cr, sr);
    CHECK(a.mac_salt_key == b.mac_salt_key);
    CHECK(a.encryption_key == b.encryption_key);

    // Swapping the randoms must change everything: SaltedHash and SaltedHash2
    // use opposite orderings, so a swap is not a no-op.
    const auto swapped = DeriveLicensingKeys(premaster, sr, cr);
    CHECK(swapped.mac_salt_key != a.mac_salt_key);
    CHECK(swapped.encryption_key != a.encryption_key);
}

RTSC_TEST(licensing_mac_is_full_md5) {
    std::array<uint8_t, 16> salt{};
    for (int i = 0; i < 16; ++i) salt[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    const std::vector<uint8_t> data = {0x10, 0x20, 0x30};
    const auto mac = LicensingMac(salt, data);
    CHECK(mac.size() == 16);  // constexpr size(): avoid CHECK_EQ/C4127
    // Deterministic and sensitive to the payload.
    CHECK(mac == LicensingMac(salt, data));
    CHECK(mac != LicensingMac(salt, std::vector<uint8_t>{0x10, 0x20, 0x31}));
}

RTSC_TEST(licensing_mac_depends_on_length_field) {
    // The MAC input includes a little-endian length; a different length with the
    // same prefix must change the digest.
    std::array<uint8_t, 16> salt{};
    const std::vector<uint8_t> a = {0x01};
    const std::vector<uint8_t> b = {0x01, 0x00};
    CHECK(LicensingMac(salt, a) != LicensingMac(salt, b));
}

int main() { return rtsc::test::run_all("rtsc_licensing_tests"); }
