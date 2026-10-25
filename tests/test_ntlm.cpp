// Behaviour specification for the NTLM message layer.
//
// Reference: docs/spec/security-layer.md sections 6.1-6.7 and 7.1-7.5,
// which in turn cite [MS-NLMP] 2.2.1.1 / 2.2.1.2 / 2.2.1.3 / 3.3.2 / 4.2.
//
// Expected values come from the official [MS-NLMP] test vectors (N21/N22/N23)
// and from the measured 40-byte NEGOTIATE / 238-byte CHALLENGE captures, never
// from this implementation's own output.

#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/credssp/ntlm.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::credssp;

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

std::string Hex(const Bytes& b) {
    static const char* k = "0123456789abcdef";
    std::string s;
    for (uint8_t c : b) {
        s.push_back(k[c >> 4]);
        s.push_back(k[c & 0xF]);
    }
    return s;
}

template <size_t N>
std::string Hex(const std::array<uint8_t, N>& b) {
    return Hex(Bytes(b.begin(), b.end()));
}

}  // namespace

// ---------------------------------------------------------------------------
// §6.1 NEGOTIATE_MESSAGE
// ---------------------------------------------------------------------------

RTSC_TEST(negotiate_message_is_40_bytes_with_version) {
    // Measured capture: 40 bytes, flags 0xE2888235, Version 0a 00 63 45 00 00
    // 00 0f. Writing a 32-byte header (omitting Version) still parses on most
    // peers but breaks the offset layout, so the length is asserted.
    NegotiateMessage m;
    m.flags = 0xE2888235u;
    Bytes out;
    CHECK(m.Encode(out).ok());
    CHECK(out.size() == 40);

    CHECK(out[0] == 'N');
    CHECK(out[1] == 'T');
    CHECK(out[2] == 'L');
    CHECK(out[3] == 'M');
    CHECK(out[4] == 'S');
    CHECK(out[5] == 'S');
    CHECK(out[6] == 'P');
    CHECK(out[7] == 0x00);
    // MessageType = 1, little endian.
    CHECK(out[8] == 0x01);
    CHECK(out[9] == 0x00);
    CHECK(out[10] == 0x00);
    CHECK(out[11] == 0x00);
    // NegotiateFlags, little endian.
    CHECK(out[12] == 0x35);
    CHECK(out[13] == 0x82);
    CHECK(out[14] == 0x88);
    CHECK(out[15] == 0xE2);
    // DomainName / WorkstationName are empty in the measured message.
    CHECK(out[16] == 0x00);
    CHECK(out[17] == 0x00);
    CHECK(out[24] == 0x00);
    CHECK(out[25] == 0x00);
    // Version: 10.0 build 0x4563, revision 0x0F.
    CHECK(out[32] == 0x0a);
    CHECK(out[33] == 0x00);
    CHECK(out[34] == 0x63);
    CHECK(out[35] == 0x45);
    CHECK(out[39] == 0x0F);
}

RTSC_TEST(negotiate_message_roundtrips_flags) {
    NegotiateMessage m;
    m.flags = 0xE2888235u;
    Bytes out;
    CHECK(m.Encode(out).ok());
    NegotiateMessage back;
    CHECK(back.Decode(out.data(), out.size()).ok());
    CHECK(back.flags == 0xE2888235u);
}

RTSC_TEST(negotiate_message_rejects_wrong_signature) {
    NegotiateMessage m;
    m.flags = 0xE2888235u;
    Bytes out;
    CHECK(m.Encode(out).ok());
    out[0] = 'X';
    NegotiateMessage back;
    CHECK(!back.Decode(out.data(), out.size()).ok());
}

RTSC_TEST(negotiate_message_rejects_wrong_message_type) {
    NegotiateMessage m;
    m.flags = 0xE2888235u;
    Bytes out;
    CHECK(m.Encode(out).ok());
    out[8] = 0x02;  // claims to be a CHALLENGE
    NegotiateMessage back;
    CHECK(!back.Decode(out.data(), out.size()).ok());
}

// ---------------------------------------------------------------------------
// §6.2 CHALLENGE_MESSAGE
// ---------------------------------------------------------------------------

RTSC_TEST(challenge_message_header_is_56_bytes) {
    // The payload offsets are absolute from the message start, so a 48-byte
    // header (omitting Version) shifts everything by 8 and the AV list is
    // parsed from the wrong place.
    ChallengeMessage m;
    m.flags = 0xE28A8235u;
    for (int i = 0; i < 8; ++i) m.server_challenge[static_cast<size_t>(i)] = 0x11;
    m.target_name = "SRV";
    Bytes out;
    CHECK(m.Encode(out).ok());
    // 56 header + 6 target name + 4 MsvAvEOL (the terminator is always emitted).
    CHECK(out.size() == 56 + 6 + 4);
    // TargetNameLen at 12..13
    CHECK(out[12] == 0x06);
    CHECK(out[13] == 0x00);
    // TargetNameBufferOffset at 16..19 must be 56.
    CHECK(out[16] == 56);
    CHECK(out[17] == 0x00);
    CHECK(out[18] == 0x00);
    CHECK(out[19] == 0x00);
}

RTSC_TEST(challenge_message_parses_av_pairs) {
    // TargetInfo is an AV_PAIR sequence terminated by MsvAvEOL, with no
    // alignment padding.
    ChallengeMessage m;
    m.flags = 0xE28A8235u;
    AvPair ts;
    ts.id = AvId::kTimestamp;
    ts.value = FromHex("0011223344556677");
    AvPair flags;
    flags.id = AvId::kFlags;
    flags.value = FromHex("02000000");
    m.av_pairs = {ts, flags};

    Bytes out;
    CHECK(m.Encode(out).ok());
    ChallengeMessage back;
    CHECK(back.Decode(out.data(), out.size()).ok());
    CHECK(back.av_pairs.size() == 2);
    CHECK(back.av_pairs[0].id == AvId::kTimestamp);
    CHECK(Hex(back.av_pairs[0].value) == "0011223344556677");
    CHECK(back.av_pairs[1].id == AvId::kFlags);
    CHECK(Hex(back.av_pairs[1].value) == "02000000");
}

RTSC_TEST(challenge_message_av_pairs_end_with_eol) {
    ChallengeMessage m;
    m.flags = 0xE28A8235u;
    AvPair ts;
    ts.id = AvId::kTimestamp;
    ts.value = FromHex("0011223344556677");
    m.av_pairs = {ts};
    Bytes out;
    CHECK(m.Encode(out).ok());
    // Find TargetInfo via its offset field, then check the last 4 bytes are
    // 00 00 00 00 (AvId=0, AvLen=0).
    const size_t ti_len = static_cast<size_t>(out[40]) |
                          (static_cast<size_t>(out[41]) << 8);
    const size_t ti_off = static_cast<size_t>(out[44]) |
                          (static_cast<size_t>(out[45]) << 8);
    CHECK(ti_off + ti_len == out.size());
    CHECK(out[out.size() - 4] == 0x00);
    CHECK(out[out.size() - 3] == 0x00);
    CHECK(out[out.size() - 2] == 0x00);
    CHECK(out[out.size() - 1] == 0x00);
}

RTSC_TEST(challenge_message_rejects_unterminated_av_list) {
    // Without MsvAvEOL the AV list has no defined end; accepting it would let
    // the parser run off the end of the buffer.
    ChallengeMessage m;
    m.flags = 0xE28A8235u;
    AvPair ts;
    ts.id = AvId::kTimestamp;
    ts.value = FromHex("0011223344556677");
    m.av_pairs = {ts};
    Bytes out;
    CHECK(m.Encode(out).ok());
    // Overwrite the EOL with a second timestamp entry.
    const size_t n = out.size();
    out[n - 4] = 0x07;
    out[n - 3] = 0x00;
    out[n - 2] = 0x08;
    out[n - 1] = 0x00;
    // Now the list claims 8 bytes of value but only 4 remain.
    ChallengeMessage back;
    CHECK(!back.Decode(out.data(), out.size()).ok());
}

// ---------------------------------------------------------------------------
// §6.5 NTLMv2 response: official vectors (N21/N22)
// ---------------------------------------------------------------------------

RTSC_TEST(ntowfv2_matches_official_vector) {
    // [MS-NLMP] 4.2.2 / N22: NTOWFv2("Password", "User", "Domain")
    const Bytes got = Ntowfv2("Password", "User", "Domain");
    CHECK(Hex(got) == "0c868a403bfd7a93a3001ef22ef02e3f");
}

RTSC_TEST(ntlmv2_response_matches_official_vector) {
    // [MS-NLMP] 4.2.4. The example context carries TWO AV pairs before EOL:
    //   AV Pair 1 - NetBIOS Server name : "Server"
    //   AV Pair 2 - NetBIOS Domain name : "Domain"
    // With an empty AV list the LMv2 response still matches (it does not use
    // the AV list) but SessionBaseKey and NTProofStr do not, which is exactly
    // how the missing pairs were found.
    NtlmV2Inputs in;
    in.user = "User";
    in.domain = "Domain";
    in.password = "Password";
    in.server_challenge = FromHex("0123456789abcdef");
    in.client_challenge = FromHex("aaaaaaaaaaaaaaaa");
    in.timestamp = FromHex("0000000000000000");
    // The published AUTHENTICATE_MESSAGE places NbDomainName (0x0002) before
    // NbComputerName (0x0001); reversing them changes the hash.
    in.target_info = FromHex("02000c0044006f006d00610069006e00"
                             "01000c00530065007200760065007200"
                             "00000000");

    NtlmV2Output out;
    const auto e = ComputeNtlmV2(in, out);
    CHECK(e.ok());
    CHECK(Hex(out.nt_proof_str) == "68cd0ab851e51c96aabc927bebef6a1c");
    CHECK(Hex(out.session_base_key) == "8de40ccadbc14a82f15cb0ad0de95ca3");
    CHECK(Hex(out.lm_response) ==
          "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa");
    // NtChallengeResponse = NTProofStr || temp, where temp is 28-byte header +
    // AvPairs + 4 zero bytes.
    CHECK(Hex(out.nt_response).substr(0, 32) == "68cd0ab851e51c96aabc927bebef6a1c");
    CHECK(out.nt_response.size() == 16 + 28 + 36 + 4);
}

RTSC_TEST(ntlmv2_vector_needs_the_av_pairs) {
    // Same inputs, empty AV list: the LMv2 response is unchanged but the
    // session base key is not. This is what makes the AV pair requirement
    // checkable rather than an unexplained constant in the test above.
    NtlmV2Inputs in;
    in.user = "User";
    in.domain = "Domain";
    in.password = "Password";
    in.server_challenge = FromHex("0123456789abcdef");
    in.client_challenge = FromHex("aaaaaaaaaaaaaaaa");
    in.timestamp = FromHex("0000000000000000");
    in.target_info = Bytes{};

    NtlmV2Output out;
    CHECK(ComputeNtlmV2(in, out).ok());
    CHECK(Hex(out.lm_response) ==
          "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa");
    CHECK(Hex(out.session_base_key) != "8de40ccadbc14a82f15cb0ad0de95ca3");
}

RTSC_TEST(ntlmv2_encrypted_session_key_matches_official_vector) {
    // N22: RC4(SessionBaseKey, 16 x 0x55)
    const Bytes key = FromHex("8de40ccadbc14a82f15cb0ad0de95ca3");
    const Bytes exported(16, 0x55);
    const Bytes got = Rc4Crypt(key, exported);
    CHECK(Hex(got) == "c5dad2544fc9799094ce1ce90bc9d03e");
}

// ---------------------------------------------------------------------------
// §5.4.3 / §6.6.2: SEAL — the RC4 stream must continue across the message and
// the checksum, which is the single most common implementation mistake
// ---------------------------------------------------------------------------

RTSC_TEST(seal_matches_official_vector_4_2_4_4) {
    // [MS-NLMP] 4.2.4.4 (NTLMv2 context). ExportedSessionKey is 0x55 * 16:
    // that is the key whose RC4 encryption under SessionBaseKey produces the
    // published Encrypted Session Key c5 da d2 54 ....
    //
    // NOTE: 4.2.4.4 and 4.2.3.4 use DIFFERENT session keys. Pairing 4.2.3.4's
    // ciphertext (a0 23 72 f6 ...) with 4.2.4.4's checksum (7fb38ec5...) is
    // impossible to satisfy; docs/spec/security-layer.md 6.6.2 mixes them.
    const Bytes exported(16, 0x55);
    const Bytes sign_key = DeriveSigningKey(exported, false);
    const Bytes seal_key = DeriveSealingKey(exported, false);

    const Bytes plaintext = FromHex("50006c00610069006e007400650078007400");
    SealedMessage sealed;
    const auto e = Seal(seal_key, sign_key, 0, plaintext, sealed);
    CHECK(e.ok());
    CHECK(Hex(sealed.ciphertext) == "54e50165bf1936dc996020c1811b0f06fb5f");
    CHECK(Hex(sealed.signature).substr(8, 16) == "7fb38ec5c55d4976");
    CHECK(sealed.signature.size() == 16);
    // Signature layout: Version(4) | Checksum(8) | SeqNum(4), all LE.
    CHECK(Hex(sealed.signature).substr(0, 8) == "01000000");
    CHECK(Hex(sealed.signature).substr(24, 8) == "00000000");
}

RTSC_TEST(seal_matches_official_vector_4_2_3_4) {
    // [MS-NLMP] 4.2.3.4 (NTLMv1 with client challenge). The document states
    // "Cut key exchange key to 56 bits: eb 93 42 9a 8b d9 52", so the sealing
    // key is MD5(exported[0..6] || magic). Only this derivation reproduces the
    // published ciphertext a0 23 72 f6 53 02.
    const Bytes exported = FromHex("eb93429a8bd952f8b89c55b87f475edc");
    // Signing key depends only on direction, not on key strength.
    const Bytes sign_key = DeriveSigningKey(exported, false);
    CHECK(Hex(sign_key) == "60e799be5c72fc92922ae8ebe961fb8d");

    const Bytes seal_key = DeriveSealingKey(exported, true);
    CHECK(Hex(seal_key) == "04dd7f014d8504d265a25cc86a3a7c06");

    const Bytes plaintext = FromHex("50006c00610069006e007400650078007400");
    SealedMessage sealed;
    const auto e = Seal(seal_key, sign_key, 0, plaintext, sealed);
    CHECK(e.ok());
    CHECK(Hex(sealed.ciphertext) == "a02372f6530273f3aa1eb90190ce5200c99d");
}

RTSC_TEST(seal_sealing_key_derivation_depends_on_key_strength) {
    // 56-bit and 128-bit sessions derive different sealing keys from the same
    // exported key. Using the wrong truncation yields a ciphertext that does
    // not match either published vector, so the two must be distinguishable.
    const Bytes exported = FromHex("eb93429a8bd952f8b89c55b87f475edc");
    const Bytes k128 = DeriveSealingKey(exported, false);
    const Bytes k56 = DeriveSealingKey(exported, true);
    CHECK(Hex(k128) != Hex(k56));
    CHECK(Hex(k128) == "85e2ec2f379361bae332a928ad1da7d0");
    CHECK(Hex(k56) == "04dd7f014d8504d265a25cc86a3a7c06");
}

RTSC_TEST(seal_checksum_requires_continued_rc4_state) {
    // The checksum is RC4(HMAC_MD5(...)) computed on the SAME stream that just
    // encrypted the message. Using a fresh RC4 instance yields a different
    // value; this asserts the difference is observable, so the test above
    // cannot pass by accident with an independent instance.
    const Bytes exported(16, 0x55);
    const Bytes sign_key = DeriveSigningKey(exported, false);
    const Bytes seal_key = DeriveSealingKey(exported, false);
    const Bytes plaintext = FromHex("50006c00610069006e007400650078007400");

    SealedMessage sealed;
    CHECK(Seal(seal_key, sign_key, 0, plaintext, sealed).ok());

    // Independent instance: encrypt, then compute the checksum separately.
    const Bytes ciphertext = Rc4Crypt(seal_key, plaintext);
    Bytes mac_input(4, 0);
    mac_input.insert(mac_input.end(), plaintext.begin(), plaintext.end());
    const auto hmac_arr = ::rtsc::crypto::HmacMd5(
        sign_key.data(), sign_key.size(), mac_input.data(), mac_input.size());
    const Bytes hmac(hmac_arr.begin(), hmac_arr.end());
    const Bytes mac8(hmac.begin(), hmac.begin() + 8);
    const Bytes wrong = Rc4Crypt(seal_key, mac8);
    CHECK(Hex(sealed.signature).substr(8, 16) != Hex(wrong));
    CHECK(ciphertext == sealed.ciphertext);
}

RTSC_TEST(seal_sequence_number_is_incremented_by_caller) {
    // §5.4.4: SeqNum starts at 0 and increments per message. Sealing the same
    // plaintext with seq 0 and seq 1 must give different checksums.
    const Bytes exported(16, 0x55);
    const Bytes sign_key = DeriveSigningKey(exported, false);
    const Bytes seal_key = DeriveSealingKey(exported, false);
    const Bytes plaintext = FromHex("00112233");

    SealedMessage a, b;
    CHECK(Seal(seal_key, sign_key, 0, plaintext, a).ok());
    CHECK(Seal(seal_key, sign_key, 1, plaintext, b).ok());
    CHECK(Hex(a.signature).substr(8, 16) != Hex(b.signature).substr(8, 16));
    CHECK(Hex(a.signature).substr(24, 8) == "00000000");
    CHECK(Hex(b.signature).substr(24, 8) == "01000000");
}

// ---------------------------------------------------------------------------
// §6.5 / §7.3: AV_PAIR handling that CredSSP requires
// ---------------------------------------------------------------------------

RTSC_TEST(av_pair_timestamp_is_used_as_time) {
    // When the CHALLENGE carries MsvAvTimestamp the client must use the
    // server's time, not the local clock, so the two sides agree.
    ChallengeMessage m;
    m.flags = 0xE28A8235u;
    AvPair ts;
    ts.id = AvId::kTimestamp;
    ts.value = FromHex("0011223344556677");
    m.av_pairs = {ts};

    Bytes ts_value;
    CHECK(m.FindAvPair(AvId::kTimestamp, ts_value).ok());
    CHECK(Hex(ts_value) == "0011223344556677");

    Bytes missing;
    CHECK(!m.FindAvPair(AvId::kSingleHost, missing).ok());
}

RTSC_TEST(ntlmv2_uses_supplied_timestamp) {
    // Same inputs as the official vector but with a non-zero timestamp: the
    // response must change, proving the timestamp is actually consumed rather
    // than defaulted to zero.
    NtlmV2Inputs base;
    base.user = "User";
    base.domain = "Domain";
    base.password = "Password";
    base.server_challenge = FromHex("0123456789abcdef");
    base.client_challenge = FromHex("aaaaaaaaaaaaaaaa");
    base.timestamp = FromHex("0000000000000000");

    NtlmV2Output a;
    CHECK(ComputeNtlmV2(base, a).ok());

    base.timestamp = FromHex("0102030405060708");
    NtlmV2Output b;
    CHECK(ComputeNtlmV2(base, b).ok());

    CHECK(Hex(a.nt_response) != Hex(b.nt_response));
    // The timestamp appears verbatim inside the NTLMv2_CLIENT_CHALLENGE.
    CHECK(Hex(b.nt_response).find("0102030405060708") != std::string::npos);
}

RTSC_TEST(ntlmv2_lm_response_is_zeroed_when_timestamp_present) {
    // §6.5: if MsvAvTimestamp is present the client SHOULD send Z(24).
    NtlmV2Inputs in;
    in.user = "User";
    in.domain = "Domain";
    in.password = "Password";
    in.server_challenge = FromHex("0123456789abcdef");
    in.client_challenge = FromHex("aaaaaaaaaaaaaaaa");
    in.timestamp = FromHex("0011223344556677");
    in.suppress_lm_response = true;

    NtlmV2Output out;
    CHECK(ComputeNtlmV2(in, out).ok());
    CHECK(out.lm_response.size() == 24);
    CHECK(Hex(out.lm_response) == std::string(48, '0'));
}

RTSC_TEST(ntlmv2_requires_server_challenge) {
    NtlmV2Inputs in;
    in.user = "u";
    in.password = "p";
    NtlmV2Output out;
    CHECK(!ComputeNtlmV2(in, out).ok());
}

RTSC_TEST(ntlmv2_anonymous_is_rejected_not_silently_wrong) {
    // §6.5 has an anonymous special case, but CredSSP never uses it. Silently
    // producing a response for empty credentials would send garbage to the
    // server, so it is refused explicitly.
    NtlmV2Inputs in;
    in.server_challenge = FromHex("0123456789abcdef");
    in.client_challenge = FromHex("aaaaaaaaaaaaaaaa");
    NtlmV2Output out;
    CHECK(!ComputeNtlmV2(in, out).ok());
}

// ---------------------------------------------------------------------------
// §6.3 AUTHENTICATE_MESSAGE
// ---------------------------------------------------------------------------

RTSC_TEST(authenticate_message_header_is_88_bytes) {
    // 88 = 64 (classic) + 8 (Version) + 16 (MIC). Writing 64 is the classic
    // mistake: every payload offset ends up 24 bytes short.
    AuthenticateMessage m;
    m.flags = 0xE28A8235u;
    m.domain = "DOM";
    m.user = "bob";
    m.workstation = "";
    m.lm_response = Bytes(24, 0x00);
    m.nt_response = FromHex("00112233");
    Bytes out;
    CHECK(m.Encode(out).ok());
    // Smallest payload: domain(6) + user(6) + nt(4) + lm(24) = 40 bytes.
    CHECK(out.size() == 88 + 40);

    // MessageType = 3.
    CHECK(out[8] == 0x03);
    CHECK(out[9] == 0x00);
    // NtChallengeResponseBufferOffset must be >= 88.
    const size_t nt_off = static_cast<size_t>(out[24]) |
                          (static_cast<size_t>(out[25]) << 8) |
                          (static_cast<size_t>(out[26]) << 16) |
                          (static_cast<size_t>(out[27]) << 24);
    CHECK(nt_off >= 88);
    // MIC region is 16 zero bytes when unset.
    for (int i = 72; i < 88; ++i) CHECK(out[static_cast<size_t>(i)] == 0x00);
}

RTSC_TEST(authenticate_message_roundtrips) {
    AuthenticateMessage m;
    m.flags = 0xE28A8235u;
    m.domain = "DOM";
    m.user = "bob";
    m.workstation = "WS";
    m.lm_response = Bytes(24, 0x11);
    m.nt_response = FromHex("0011223344556677");
    m.encrypted_random_session_key = Bytes(16, 0x22);
    Bytes out;
    CHECK(m.Encode(out).ok());

    AuthenticateMessage back;
    CHECK(back.Decode(out.data(), out.size()).ok());
    CHECK(back.domain == "DOM");
    CHECK(back.user == "bob");
    CHECK(back.workstation == "WS");
    CHECK(Hex(back.nt_response) == "0011223344556677");
    CHECK(Hex(back.encrypted_random_session_key) == std::string(32, '2'));
}

RTSC_TEST(authenticate_message_rejects_offset_inside_header) {
    // A payload offset pointing into the 88-byte header is either a corrupt
    // message or a deliberate attempt to make the parser read header bytes as
    // credential data.
    AuthenticateMessage m;
    m.flags = 0xE28A8235u;
    m.user = "bob";
    m.nt_response = FromHex("00112233");
    Bytes out;
    CHECK(m.Encode(out).ok());
    out[24] = 40;  // NtChallengeResponseBufferOffset inside the header
    out[25] = 0x00;
    out[26] = 0x00;
    out[27] = 0x00;
    AuthenticateMessage back;
    CHECK(!back.Decode(out.data(), out.size()).ok());
}

// ---------------------------------------------------------------------------
// MIC (§6.5)
// ---------------------------------------------------------------------------

RTSC_TEST(mic_covers_all_three_messages_with_zeroed_field) {
    // MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE)
    // where the AUTHENTICATE MIC field is zeroed during the computation.
    const Bytes exported(16, 0x33);
    const Bytes negotiate = FromHex("0102030405");
    const Bytes challenge = FromHex("060708090a");
    Bytes authenticate(88, 0x00);
    authenticate[0] = 'N';

    const auto mic_arr = ComputeMic(exported, negotiate, challenge, authenticate);
    const Bytes mic(mic_arr.begin(), mic_arr.end());
    CHECK(mic.size() == 16);

    // Changing any of the three inputs must change the MIC.
    // Byte 87 lies inside the MIC field, which is zeroed before hashing, so
    // changing it must NOT change the result. Mutating it would have made this
    // assertion pass for the wrong reason.
    Bytes in_mic_field = authenticate;
    in_mic_field[87] = 0x01;
    CHECK(Hex(ComputeMic(exported, negotiate, challenge, in_mic_field)) == Hex(mic));

    Bytes alt = authenticate;
    alt[1] = 0xEE;  // outside the MIC field
    CHECK(Hex(ComputeMic(exported, negotiate, challenge, alt)) != Hex(mic));
    CHECK(Hex(ComputeMic(exported, negotiate, challenge, authenticate)) == Hex(mic));
}

RTSC_TEST(mic_ignores_existing_mic_bytes) {
    // The MIC field is zeroed before hashing, so a message that already has a
    // MIC filled in must produce the same value. Otherwise recomputation after
    // filling the field would disagree with the first computation.
    const Bytes exported(16, 0x33);
    const Bytes negotiate = FromHex("0102030405");
    const Bytes challenge = FromHex("060708090a");
    Bytes authenticate(88, 0x00);

    const auto mic_a_arr = ComputeMic(exported, negotiate, challenge, authenticate);
    const Bytes mic_a(mic_a_arr.begin(), mic_a_arr.end());
    Bytes filled = authenticate;
    for (int i = 0; i < 16; ++i) filled[72 + static_cast<size_t>(i)] = mic_a[static_cast<size_t>(i)];
    const auto mic_b_arr = ComputeMic(exported, negotiate, challenge, filled);
    const Bytes mic_b(mic_b_arr.begin(), mic_b_arr.end());
    CHECK(Hex(mic_a) == Hex(mic_b));
}

int main() { return rtsc::test::run_all("rtsc_ntlm_tests"); }
