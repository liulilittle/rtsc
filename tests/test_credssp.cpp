// Behaviour specification for the CredSSP message layer.
//
// Reference: docs/spec/security-layer.md
//   §5.1  TSRequest ASN.1 structure
//   §5.2  NegoData wrapping
//   §5.5  TSCredentials / TSPasswordCreds
//   §5.7  DER constraints (including the server's non-canonical errorCode)
//
// The wire forms asserted here come from the spec's measured captures, not
// from this implementation's output: a test that only round-trips its own
// encoder cannot tell a wrong encoding from a consistent one.

#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/credssp/ts_request.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::credssp;

namespace {

using Bytes = std::vector<uint8_t>;

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

}  // namespace

// ---------------------------------------------------------------------------
// §5.1: version-only TSRequest
// ---------------------------------------------------------------------------

RTSC_TEST(tsrequest_version_only_matches_measured_shape) {
    // The smallest legal TSRequest: SEQUENCE { [0] INTEGER version }.
    // 30 03 a0 01 06 would be wrong: the INTEGER itself needs its own tag,
    // so the inner [0] holds 02 01 06.
    TsRequest r;
    r.version = 6;
    Bytes out;
    CHECK(r.Encode(out).ok());
    CHECK(out == FromHex("30 05 a0 03 02 01 06"));
}

RTSC_TEST(tsrequest_version_uses_shortest_integer_encoding) {
    // DER requires the minimal number of content octets. v2 must be 02 01 02,
    // not 02 02 00 02.
    TsRequest r;
    r.version = 2;
    Bytes out;
    CHECK(r.Encode(out).ok());
    CHECK(out == FromHex("30 05 a0 03 02 01 02"));

    r.version = 256;
    out.clear();
    CHECK(r.Encode(out).ok());
    CHECK(out == FromHex("30 06 a0 04 02 02 01 00"));
}

RTSC_TEST(tsrequest_roundtrips_version) {
    for (uint32_t v : {2u, 3u, 4u, 5u, 6u}) {
        TsRequest r;
        r.version = v;
        Bytes out;
        CHECK(r.Encode(out).ok());
        TsRequest back;
        CHECK(back.Decode(out.data(), out.size()).ok());
        CHECK(back.version == v);
    }
}

// ---------------------------------------------------------------------------
// §5.2: NegoData wrapping (two nested SEQUENCEs, then [0] OCTET STRING)
// ---------------------------------------------------------------------------

RTSC_TEST(tsrequest_negotoken_wrapping_is_double_sequence) {
    // Wire shape from the spec's 91-byte capture:
    //   a1 <len> 30 <len> 30 <len> a0 <len> 04 <len> <token>
    // Three nested layers. Dropping one produces a structure the server
    // rejects with SEC_E_INVALID_TOKEN, so the nesting is asserted exactly.
    TsRequest r;
    r.version = 6;
    r.nego_token = FromHex("4e544c4d53535000");
    Bytes out;
    CHECK(r.Encode(out).ok());

    const Bytes want = FromHex(
        "30 17"
        "  a0 03 02 01 06"
        "  a1 10"
        "    30 0e"
        "      30 0c"
        "        a0 0a"
        "          04 08 4e544c4d53535000");
    CHECK(out == want);
}

RTSC_TEST(tsrequest_negotoken_roundtrips) {
    TsRequest r;
    r.version = 6;
    r.nego_token = FromHex("00112233445566778899aabbccddeeff");
    Bytes out;
    CHECK(r.Encode(out).ok());
    TsRequest back;
    CHECK(back.Decode(out.data(), out.size()).ok());
    CHECK(back.version == 6);
    CHECK(back.nego_token == r.nego_token);
}

// ---------------------------------------------------------------------------
// §5.1: authInfo and pubKeyAuth are OCTET STRINGs inside [2] / [3]
// ---------------------------------------------------------------------------

RTSC_TEST(tsrequest_authinfo_and_pubkeyauth_tags) {
    TsRequest r;
    r.version = 6;
    r.pub_key_auth = FromHex("aa");
    Bytes out;
    CHECK(r.Encode(out).ok());
    // [3] = 0xA3 wrapping an OCTET STRING.
    CHECK(out == FromHex("30 0a a0 03 02 01 06 a3 03 04 01 aa"));

    r = TsRequest{};
    r.version = 6;
    r.auth_info = FromHex("cc");
    out.clear();
    CHECK(r.Encode(out).ok());
    // [2] = 0xA2.
    CHECK(out == FromHex("30 0a a0 03 02 01 06 a2 03 04 01 cc"));

    // Both at once, in ascending tag order (DER requires it).
    r.pub_key_auth = FromHex("dd");
    out.clear();
    CHECK(r.Encode(out).ok());
    CHECK(out == FromHex("30 0f a0 03 02 01 06 a2 03 04 01 cc a3 03 04 01 dd"));
}

// ---------------------------------------------------------------------------
// §5.1: clientNonce is version >= 5 only, and must be 32 bytes
// ---------------------------------------------------------------------------

RTSC_TEST(tsrequest_client_nonce_is_32_bytes_and_tag_5) {
    TsRequest r;
    r.version = 6;
    Bytes nonce(32, 0x11);
    r.client_nonce = nonce;
    Bytes out;
    CHECK(r.Encode(out).ok());
    // [5] = 0xA5 wrapping OCTET STRING of 32 bytes (0x20).
    CHECK(out == FromHex("30 29 a0 03 02 01 06 a5 22 04 20"
                         "11111111111111111111111111111111"
                         "11111111111111111111111111111111"));
}

RTSC_TEST(tsrequest_rejects_wrong_nonce_length) {
    // 32 bytes is the spec value. A 16-byte nonce is a common mistake and
    // must be refused at encode time rather than sent and rejected remotely.
    TsRequest r;
    r.version = 6;
    r.client_nonce = Bytes(16, 0x22);
    Bytes out;
    const auto e = r.Encode(out);
    CHECK(!e.ok());
}

RTSC_TEST(tsrequest_rejects_nonce_below_version_5) {
    TsRequest r;
    r.version = 4;
    r.client_nonce = Bytes(32, 0x33);
    Bytes out;
    CHECK(!r.Encode(out).ok());
}

// ---------------------------------------------------------------------------
// §5.7: errorCode must be parsed in the server's non-canonical form
// ---------------------------------------------------------------------------

RTSC_TEST(tsrequest_parses_noncanonical_error_code) {
    // Measured capture: a4 06 02 04 c0 00 00 6d. A negative NTSTATUS written
    // as a raw 4-byte unsigned value, without the leading 0x00 DER requires.
    // A strict DER reader rejects it; this one must accept it.
    const Bytes wire = FromHex("30 0d a0 03 02 01 06 a4 06 02 04 c0 00 00 6d");
    TsRequest r;
    const auto e = r.Decode(wire.data(), wire.size());
    CHECK(e.ok());
    CHECK(r.version == 6);
    CHECK(r.has_error_code);
    CHECK(r.error_code == 0xC000006Du);
}

RTSC_TEST(tsrequest_parses_canonical_error_code_too) {
    // The same value with the leading 0x00 must also parse: real peers differ.
    const Bytes wire = FromHex("30 0e a0 03 02 01 06 a4 07 02 05 00 c0 00 00 6d");
    TsRequest r;
    CHECK(r.Decode(wire.data(), wire.size()).ok());
    CHECK(r.has_error_code);
    CHECK(r.error_code == 0xC000006Du);
}

// ---------------------------------------------------------------------------
// §5.7: long-form lengths
// ---------------------------------------------------------------------------

RTSC_TEST(tsrequest_uses_long_form_length_above_127) {
    TsRequest r;
    r.version = 6;
    r.nego_token = Bytes(200, 0xAB);
    Bytes out;
    CHECK(r.Encode(out).ok());
    // Outer SEQUENCE length > 127 -> 30 81 xx. The token itself is 200 bytes
    // -> 04 81 c8.
    CHECK(out.size() > 127);
    CHECK(out[0] == 0x30);
    CHECK(out[1] == 0x81);
}

RTSC_TEST(tsrequest_decodes_long_form_length) {
    TsRequest r;
    r.version = 6;
    r.nego_token = Bytes(300, 0xCD);
    Bytes out;
    CHECK(r.Encode(out).ok());
    TsRequest back;
    CHECK(back.Decode(out.data(), out.size()).ok());
    CHECK(back.nego_token == r.nego_token);
}

// ---------------------------------------------------------------------------
// Malformed input must be rejected, not silently accepted
// ---------------------------------------------------------------------------

RTSC_TEST(tsrequest_rejects_truncated_input) {
    const Bytes wire = FromHex("30 05 a0 03 02 01 06");
    TsRequest r;
    CHECK(!r.Decode(wire.data(), wire.size() - 2).ok());
}

RTSC_TEST(tsrequest_rejects_out_of_order_tags) {
    // DER requires ascending context tags. [2] before [0] is invalid.
    //
    // Both fields are individually well-formed, so the ONLY defect is the
    // order. An earlier version used a malformed [1] payload, which made the
    // decoder fail for an unrelated reason and left this rule untested.
    const Bytes wire = FromHex("30 0a a2 03 04 01 cc a0 03 02 01 06");
    TsRequest r;
    CHECK(!r.Decode(wire.data(), wire.size()).ok());
}

RTSC_TEST(tsrequest_accepts_ascending_tags) {
    // The counterpart to the ordering check: a well-formed request with [0]
    // then [2] must decode, otherwise "reject out of order" would be
    // indistinguishable from "reject everything".
    TsRequest r;
    r.version = 6;
    r.auth_info = FromHex("cc");
    Bytes out;
    CHECK(r.Encode(out).ok());
    TsRequest back;
    CHECK(back.Decode(out.data(), out.size()).ok());
    CHECK(back.version == 6);
    CHECK(back.auth_info == FromHex("cc"));
}

RTSC_TEST(tsrequest_rejects_missing_version) {
    // version is not OPTIONAL; a TSRequest without [0] is invalid.
    const Bytes wire = FromHex("30 03 a1 01 00");
    TsRequest r;
    CHECK(!r.Decode(wire.data(), wire.size()).ok());
}

RTSC_TEST(tsrequest_rejects_trailing_garbage) {
    const Bytes wire = FromHex("30 05 a0 03 02 01 06 ff ff");
    TsRequest r;
    CHECK(!r.Decode(wire.data(), wire.size()).ok());
}

RTSC_TEST(tsrequest_rejects_unknown_context_tag) {
    const Bytes wire = FromHex("30 06 a0 03 02 01 06 a9 00");
    TsRequest r;
    CHECK(!r.Decode(wire.data(), wire.size()).ok());
}

// ---------------------------------------------------------------------------
// §5.5: TSCredentials / TSPasswordCreds
// ---------------------------------------------------------------------------

RTSC_TEST(tscredentials_password_creds_use_utf16le) {
    // domainName / userName / password are UTF-16LE inside OCTET STRINGs.
    // ASCII would produce half the bytes and still parse, so the length and
    // the interleaved zeros are asserted directly.
    PasswordCredentials creds;
    creds.domain = "DOM";
    creds.user = "bob";
    creds.password = "pw";
    Bytes out;
    CHECK(creds.Encode(out).ok());

    // TSCredentials ::= SEQUENCE { [0] INTEGER 1, [1] OCTET STRING { TSPasswordCreds } }
    const Bytes want = FromHex(
        "30 27"
        "  a0 03 02 01 01"
        "  a1 20"
        "    04 1e"
        "      30 1c"
        "        a0 08 04 06 44 00 4f 00 4d 00"
        "        a1 08 04 06 62 00 6f 00 62 00"
        "        a2 06 04 04 70 00 77 00");
    CHECK(out == want);
}

RTSC_TEST(tscredentials_roundtrips) {
    PasswordCredentials creds;
    creds.domain = "WORKGROUP";
    creds.user = "Administrator";
    creds.password = "P@ssw0rd!";
    Bytes out;
    CHECK(creds.Encode(out).ok());
    PasswordCredentials back;
    CHECK(back.Decode(out.data(), out.size()).ok());
    CHECK(back.domain == creds.domain);
    CHECK(back.user == creds.user);
    CHECK(back.password == creds.password);
}

RTSC_TEST(tscredentials_rejects_wrong_cred_type) {
    // credType 2 is smart card, whose payload is a different structure.
    const Bytes wire = FromHex("30 08 a0 03 02 01 02 a1 01 04 00");
    PasswordCredentials creds;
    CHECK(!creds.Decode(wire.data(), wire.size()).ok());
}

RTSC_TEST(tscredentials_rejects_odd_length_utf16) {
    // A UTF-16LE string must have an even number of bytes. Odd length means
    // either truncation or a byte-order mistake.
    const Bytes wire = FromHex(
        "30 17 a0 03 02 01 01 a1 10 04 0e"
        "  30 0c a0 03 04 01 44 a1 03 04 01 62 a2 02 04 00");
    PasswordCredentials creds;
    CHECK(!creds.Decode(wire.data(), wire.size()).ok());
}

int main() { return rtsc::test::run_all("rtsc_credssp_tests"); }
