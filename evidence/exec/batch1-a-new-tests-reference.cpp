// Behaviour specification for the CredSSP handshake state machine.
//
// Reference: docs/spec/security-layer.md sections 5.3 (five steps),
// 5.4 (pubKeyAuth), 5.5 (TSCredentials), 5.6 (measured wire choices).
//
// The client is driven step by step; the server side is simulated from the
// spec, which is legitimate here because the state machine's job is to emit the
// right bytes in the right order, and every emitted byte is compared against
// independently derived expectations (DER from ts_request, NTLM vectors from
// [MS-NLMP], SHA-256 binding hash from FIPS 180-4).

#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/credssp/credssp.h"
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

// Deterministic nonce so the binding hash is reproducible in tests. The
// production path uses a CSPRNG; this hook exists only for tests.
Bytes FixedNonce() {
    Bytes n(32, 0);
    for (size_t i = 0; i < n.size(); ++i) n[i] = static_cast<uint8_t>(i);
    return n;
}

Credentials TestCreds() {
    Credentials c;
    c.domain = "Domain";
    c.user = "User";
    c.password = "Password";
    return c;
}

// A server-side CHALLENGE built from the official NTLM vector, so the client
// sees a realistic message.
Bytes ServerChallengeMessage() {
    ChallengeMessage m;
    m.flags = ntlm_flag::kUnicode | ntlm_flag::kRequestTarget | ntlm_flag::kSign |
              ntlm_flag::kSeal | ntlm_flag::kNtlm | ntlm_flag::kAlwaysSign |
              ntlm_flag::kExtendedSessionSecurity | ntlm_flag::kTargetInfo |
              ntlm_flag::kVersion | ntlm_flag::k128 | ntlm_flag::kKeyExch |
              ntlm_flag::k56 | ntlm_flag::kTargetTypeServer;
    m.server_challenge = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    m.target_name = "Server";
    AvPair domain;
    domain.id = AvId::kNbDomainName;
    domain.value = ::rtsc::crypto::Utf16Le("Domain");
    AvPair server;
    server.id = AvId::kNbComputerName;
    server.value = ::rtsc::crypto::Utf16Le("Server");
    AvPair ts;
    ts.id = AvId::kTimestamp;
    ts.value = FromHex("0000000000000000");
    m.av_pairs = {domain, server, ts};
    Bytes out;
    m.Encode(out);
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// §5.3 step 1: version + negoTokens(NTLM NEGOTIATE), nothing else
// ---------------------------------------------------------------------------

RTSC_TEST(step1_emits_version_and_negotiate_token_only) {
    CredsspClient client(TestCreds(), 6);
    client.SetNonceForTest(FixedNonce());

    Bytes out;
    CHECK(client.Start(out).ok());

    TsRequest req;
    CHECK(req.Decode(out.data(), out.size()).ok());
    CHECK(req.version == 6);
    CHECK(!req.nego_token.empty());
    // The token is a bare NTLM NEGOTIATE: signature + type 1.
    CHECK(req.nego_token.size() == 40);
    CHECK(Hex(Bytes(req.nego_token.begin(), req.nego_token.begin() + 8)) ==
          "4e544c4d53535000");
    CHECK(req.nego_token[8] == 0x01);
    // authInfo / pubKeyAuth must be absent at this step.
    CHECK(req.auth_info.empty());
    CHECK(req.pub_key_auth.empty());
    // clientNonce is only sent together with pubKeyAuth (step 3).
    CHECK(req.client_nonce.empty());
}

RTSC_TEST(step1_rejects_server_version_above_our_max) {
    // A peer claiming a newer version must be treated as the highest we
    // understand, not rejected; but a version below 2 is invalid.
    CredsspClient client(TestCreds(), 6);
    TsRequest bad;
    bad.version = 1;
    bad.nego_token = FromHex("0011");
    Bytes wire;
    CHECK(bad.Encode(wire).ok());
    Bytes out;
    const auto e = client.OnServerResponse(wire.data(), wire.size(), out);
    CHECK(!e.ok());
}

// ---------------------------------------------------------------------------
// §5.3 step 3: negoTokens(AUTHENTICATE) + pubKeyAuth + clientNonce together
// ---------------------------------------------------------------------------

RTSC_TEST(step3_carries_authenticate_pubkeyauth_and_nonce) {
    CredsspClient client(TestCreds(), 6);
    client.SetNonceForTest(FixedNonce());
    client.SetServerPublicKeyForTest(FromHex("3006020101020101"));

    Bytes out;
    CHECK(client.Start(out).ok());

    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(challenge.Encode(wire).ok());

    Bytes step3;
    CHECK(client.OnServerResponse(wire.data(), wire.size(), step3).ok());

    TsRequest req;
    CHECK(req.Decode(step3.data(), step3.size()).ok());
    CHECK(req.version == 6);
    CHECK(!req.nego_token.empty());
    // The AUTHENTICATE message is sent bare: wrapping it in SPNEGO
    // negTokenResp makes the server answer SEC_E_INVALID_TOKEN (measured).
    CHECK(Hex(Bytes(req.nego_token.begin(), req.nego_token.begin() + 8)) ==
          "4e544c4d53535000");
    CHECK(req.nego_token[8] == 0x03);
    // pubKeyAuth is signature(16) || ciphertext(32) for version >= 5.
    CHECK(req.pub_key_auth.size() == 48);
    // clientNonce must equal the nonce used for the binding hash.
    CHECK(req.client_nonce == FixedNonce());
    CHECK(req.auth_info.empty());
}

RTSC_TEST(step3_authenticate_carries_a_nonzero_mic) {
    // Without a timestamp the MIC is optional; with one it is required, and a
    // zero MIC is indistinguishable from "not computed". This asserts the
    // client actually fills the field.
    CredsspClient client(TestCreds(), 6);
    client.SetNonceForTest(FixedNonce());
    client.SetServerPublicKeyForTest(FromHex("3006020101020101"));

    Bytes out;
    CHECK(client.Start(out).ok());
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(challenge.Encode(wire).ok());
    Bytes step3;
    CHECK(client.OnServerResponse(wire.data(), wire.size(), step3).ok());

    TsRequest req;
    CHECK(req.Decode(step3.data(), step3.size()).ok());
    CHECK(req.nego_token.size() > 88);
    Bytes mic(req.nego_token.begin() + 72, req.nego_token.begin() + 88);
    CHECK(Hex(mic) != Hex(Bytes(16, 0)));

    // Recomputing the MIC from the three messages must reproduce it, which
    // proves it covers all three and not just the last one.
    const Bytes exported = client.ExportedSessionKeyForTest();
    const auto mic_arr = ComputeMic(exported, client.NegotiateMessageForTest(),
                                    client.ChallengeMessageForTest(), req.nego_token);
    CHECK(Hex(Bytes(mic_arr.begin(), mic_arr.end())) == Hex(mic));
}

RTSC_TEST(step3_pubkeyauth_hash_matches_independent_computation) {
    // The binding hash is SHA256(magic || nonce || SubjectPublicKey) with the
    // magic's NUL included. Recomputing it here from the spec text gives an
    // expectation independent of the client implementation.
    const Bytes spk = FromHex("3006020101020101");
    const Bytes nonce = FixedNonce();

    CredsspClient client(TestCreds(), 6);
    client.SetNonceForTest(nonce);
    client.SetServerPublicKeyForTest(spk);

    Bytes out;
    CHECK(client.Start(out).ok());
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(challenge.Encode(wire).ok());
    Bytes step3;
    CHECK(client.OnServerResponse(wire.data(), wire.size(), step3).ok());

    TsRequest req;
    CHECK(req.Decode(step3.data(), step3.size()).ok());
    CHECK(req.pub_key_auth.size() == 48);

    // The plaintext of pubKeyAuth must be the binding hash, and the client must
    // expose the session keys so the check does not need to re-derive RC4.
    const Bytes expected_hash = ClientToServerBindingHash(spk, nonce);
    CHECK(expected_hash.size() == 32);

    const Bytes plain = client.DecryptPubKeyAuthForTest(req.pub_key_auth);
    CHECK(Hex(plain) == Hex(expected_hash));
}

RTSC_TEST(binding_hash_matches_independent_value) {
    // Expected values computed outside this codebase with SHA256(magic ||
    // 0x00 || nonce || SubjectPublicKey). Comparing the implementation against
    // itself (as an earlier version of this test did) cannot detect a wrong
    // magic, a missing NUL, or a swapped order.
    const Bytes spk = FromHex("3006020101020101");
    Bytes nonce(32, 0);
    for (size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<uint8_t>(i);

    CHECK(Hex(ClientToServerBindingHash(spk, nonce)) ==
          "38e6b5801b2a07e738371fa8056aa7f5f4e6cb72c5b663add8eac3efb7ada78e");
    CHECK(Hex(ServerToClientBindingHash(spk, nonce)) ==
          "d791087c0e91a056ef1ce7d5ba4610680d8c9a59ee4a1426ac7ce80d03ea607a");
}

RTSC_TEST(binding_hash_includes_magic_nul_and_nonce) {
    const Bytes spk = FromHex("3006020101020101");
    const Bytes nonce(32, 0xAA);
    const Bytes h1 = ClientToServerBindingHash(spk, nonce);

    // Changing the nonce changes the hash.
    Bytes nonce2 = nonce;
    nonce2[0] ^= 0xFF;
    CHECK(Hex(ClientToServerBindingHash(spk, nonce2)) != Hex(h1));

    // Changing the public key changes the hash.
    Bytes spk2 = spk;
    spk2[0] ^= 0xFF;
    CHECK(Hex(ClientToServerBindingHash(spk2, nonce)) != Hex(h1));

    // The two directions use different magics, so they must differ.
    CHECK(Hex(ServerToClientBindingHash(spk, nonce)) != Hex(h1));
}

// ---------------------------------------------------------------------------
// §5.3 step 5: authInfo only, carrying TSCredentials
// ---------------------------------------------------------------------------

RTSC_TEST(step5_sends_authinfo_only) {
    CredsspClient client(TestCreds(), 6);
    client.SetNonceForTest(FixedNonce());
    client.SetServerPublicKeyForTest(FromHex("3006020101020101"));

    Bytes out;
    CHECK(client.Start(out).ok());
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(challenge.Encode(wire).ok());
    Bytes step3;
    CHECK(client.OnServerResponse(wire.data(), wire.size(), step3).ok());

    // Step 4: the server echoes an encrypted server-to-client binding hash.
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = client.MakeServerEchoForTest();
    Bytes step4_wire;
    CHECK(step4.Encode(step4_wire).ok());

    Bytes step5;
    CHECK(client.OnServerResponse(step4_wire.data(), step4_wire.size(), step5).ok());

    TsRequest req;
    CHECK(req.Decode(step5.data(), step5.size()).ok());
    CHECK(req.version == 6);
    CHECK(req.nego_token.empty());
    CHECK(req.pub_key_auth.empty());
    CHECK(!req.auth_info.empty());
    CHECK(client.complete());
}

RTSC_TEST(step5_rejects_wrong_server_echo) {
    // A mismatched step 4 echo means the peer cannot prove it holds the same
    // session key: a man-in-the-middle signature. The client must abort and
    // must not send credentials.
    CredsspClient client(TestCreds(), 6);
    client.SetNonceForTest(FixedNonce());
    client.SetServerPublicKeyForTest(FromHex("3006020101020101"));

    Bytes out;
    CHECK(client.Start(out).ok());
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(challenge.Encode(wire).ok());
    Bytes step3;
    CHECK(client.OnServerResponse(wire.data(), wire.size(), step3).ok());

    TsRequest step4;
    step4.version = 6;
    Bytes echo = client.MakeServerEchoForTest();
    echo[20] ^= 0xFF;  // corrupt the ciphertext
    step4.pub_key_auth = echo;
    Bytes step4_wire;
    CHECK(step4.Encode(step4_wire).ok());

    Bytes step5;
    const auto e = client.OnServerResponse(step4_wire.data(), step4_wire.size(), step5);
    CHECK(!e.ok());
    CHECK(step5.empty());
    CHECK(!client.complete());
}

// ---------------------------------------------------------------------------
// §5.3 failure branch: errorCode must abort with that code
// ---------------------------------------------------------------------------

RTSC_TEST(error_code_aborts_with_server_status) {
    CredsspClient client(TestCreds(), 6);
    client.SetNonceForTest(FixedNonce());

    Bytes out;
    CHECK(client.Start(out).ok());

    TsRequest err;
    err.version = 6;
    err.has_error_code = true;
    err.error_code = 0xC000006Du;  // STATUS_LOGON_FAILURE
    Bytes wire;
    CHECK(err.Encode(wire).ok());

    Bytes next;
    const auto e = client.OnServerResponse(wire.data(), wire.size(), next);
    CHECK(!e.ok());
    CHECK(e.native_code == static_cast<int32_t>(0xC000006Du));
    CHECK(next.empty());
}

RTSC_TEST(error_code_is_checked_before_any_token_processing) {
    // A response carrying both a token and an errorCode must fail: continuing
    // would process a token from a peer that already declared failure.
    CredsspClient client(TestCreds(), 6);
    client.SetNonceForTest(FixedNonce());
    Bytes out;
    CHECK(client.Start(out).ok());

    TsRequest err;
    err.version = 6;
    err.has_error_code = true;
    err.error_code = 0xC000006Du;
    err.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(err.Encode(wire).ok());

    Bytes next;
    CHECK(!client.OnServerResponse(wire.data(), wire.size(), next).ok());
}

// ---------------------------------------------------------------------------
// Step ordering must be enforced, not inferred from the payload
// ---------------------------------------------------------------------------

RTSC_TEST(unexpected_step_is_rejected) {
    CredsspClient client(TestCreds(), 6);
    client.SetNonceForTest(FixedNonce());

    // A response before Start() is a protocol violation.
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(challenge.Encode(wire).ok());
    Bytes out;
    CHECK(!client.OnServerResponse(wire.data(), wire.size(), out).ok());
}

RTSC_TEST(step4_response_without_pubkeyauth_is_rejected) {
    CredsspClient client(TestCreds(), 6);
    client.SetNonceForTest(FixedNonce());
    client.SetServerPublicKeyForTest(FromHex("3006020101020101"));

    Bytes out;
    CHECK(client.Start(out).ok());
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(challenge.Encode(wire).ok());
    Bytes step3;
    CHECK(client.OnServerResponse(wire.data(), wire.size(), step3).ok());

    // Step 4 must carry pubKeyAuth; an empty one is not "nothing to do".
    TsRequest step4;
    step4.version = 6;
    Bytes step4_wire;
    CHECK(step4.Encode(step4_wire).ok());
    Bytes step5;
    CHECK(!client.OnServerResponse(step4_wire.data(), step4_wire.size(), step5).ok());
}

// ---------------------------------------------------------------------------
// §5.5: the authInfo plaintext is TSCredentials with the real credentials
// ---------------------------------------------------------------------------

RTSC_TEST(authinfo_plaintext_is_tscredentials_with_credentials) {
    CredsspClient client(TestCreds(), 6);
    client.SetNonceForTest(FixedNonce());
    client.SetServerPublicKeyForTest(FromHex("3006020101020101"));

    Bytes out;
    CHECK(client.Start(out).ok());
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(challenge.Encode(wire).ok());
    Bytes step3;
    CHECK(client.OnServerResponse(wire.data(), wire.size(), step3).ok());

    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = client.MakeServerEchoForTest();
    Bytes step4_wire;
    CHECK(step4.Encode(step4_wire).ok());
    Bytes step5;
    CHECK(client.OnServerResponse(step4_wire.data(), step4_wire.size(), step5).ok());

    TsRequest req;
    CHECK(req.Decode(step5.data(), step5.size()).ok());
    const Bytes plain = client.DecryptAuthInfoForTest(req.auth_info);
    PasswordCredentials creds;
    CHECK(creds.Decode(plain.data(), plain.size()).ok());
    CHECK(creds.domain == "Domain");
    CHECK(creds.user == "User");
    CHECK(creds.password == "Password");
}

// ---------------------------------------------------------------------------
// Version 2/3/4 path: pubKeyAuth is the raw SubjectPublicKey, not a hash
// ---------------------------------------------------------------------------

RTSC_TEST(version_4_pubkeyauth_is_encrypted_public_key_not_hash) {
    CredsspClient client(TestCreds(), 4);
    client.SetNonceForTest(FixedNonce());
    const Bytes spk = FromHex("3006020101020101");
    client.SetServerPublicKeyForTest(spk);

    Bytes out;
    CHECK(client.Start(out).ok());
    TsRequest challenge;
    challenge.version = 4;
    challenge.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(challenge.Encode(wire).ok());
    Bytes step3;
    CHECK(client.OnServerResponse(wire.data(), wire.size(), step3).ok());

    TsRequest req;
    CHECK(req.Decode(step3.data(), step3.size()).ok());
    // No nonce for version < 5.
    CHECK(req.client_nonce.empty());
    // pubKeyAuth = signature(16) || encrypted SubjectPublicKey (7 bytes here).
    CHECK(req.pub_key_auth.size() == 16 + spk.size());

    const Bytes plain = client.DecryptPubKeyAuthForTest(req.pub_key_auth);
    CHECK(Hex(plain) == Hex(spk));
}


// ---------------------------------------------------------------------------
// Batch 1 (S1 S5 S6 S11 S18): production injection + peer-version handling
// ---------------------------------------------------------------------------

RTSC_TEST(two_constructions_have_different_nonces) {
    // S1: the nonce seeds ClientChallenge (credssp.cpp:176) and ExportedSessionKey
    // (:191). Two independent clients that see the same CHALLENGE must derive
    // different session keys, otherwise any passive observer can predict them.
    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(challenge.Encode(wire).ok());

    Bytes prev;
    for (int i = 0; i < 4; ++i) {
        CredsspClient c(TestCreds(), 6);
        c.SetServerPublicKeyForTest(FromHex("3006020101020101"));
        Bytes out;
        CHECK(c.Start(out).ok());
        Bytes step3;
        CHECK(c.OnServerResponse(wire.data(), wire.size(), step3).ok());
        const Bytes k = c.ExportedSessionKeyForTest();
        CHECK(k.size() == 16);
        // All-zero is the pre-fix signature; a constant fill would reproduce it.
        CHECK(Hex(k) != Hex(Bytes(16, 0)));
        // Pairwise distinct across four constructions: a "seeded once" RNG or a
        // fill with a fixed pattern fails here even if two samples happened to
        // differ.
        if (i > 0) CHECK(Hex(k) != Hex(prev));
        prev = k;
    }
}

RTSC_TEST(version_below_min_is_rejected_with_valid_challenge) {
    // S5: the old "version 1 is rejected" coverage passed for the wrong reason --
    // it sent nego_token = "0011", so the CHALLENGE parser failed first. This
    // test uses a legal CHALLENGE, so only the version check can reject it.
    CredsspClient c(TestCreds(), 6);
    c.SetNonceForTest(FixedNonce());
    c.SetServerPublicKeyForTest(FromHex("3006020101020101"));
    Bytes out;
    CHECK(c.Start(out).ok());

    TsRequest bad;
    bad.version = 1;
    bad.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(bad.Encode(wire).ok());

    Bytes step3;
    const Error e = c.OnServerResponse(wire.data(), wire.size(), step3);
    CHECK(!e.ok());
    CHECK(e.status == Status::kUnsupported);
    CHECK(step3.empty());
    CHECK(!c.complete());

    // Control: a fresh client accepts the identical CHALLENGE at version 6, so
    // the rejection above is caused by the version and not by the fixture. A
    // second call on `c` is not a valid control: Fail() latches kFailed (c:54).
    CredsspClient c2(TestCreds(), 6);
    c2.SetNonceForTest(FixedNonce());
    c2.SetServerPublicKeyForTest(FromHex("3006020101020101"));
    Bytes out2;
    CHECK(c2.Start(out2).ok());
    TsRequest good;
    good.version = 6;
    good.nego_token = ServerChallengeMessage();
    Bytes good_wire;
    CHECK(good.Encode(good_wire).ok());
    Bytes ok3;
    CHECK(c2.OnServerResponse(good_wire.data(), good_wire.size(), ok3).ok());
}

RTSC_TEST(server_version_is_echoed_back) {
    // S6: steps 3 and 5 must use the negotiated version, not the constructor
    // argument. A server that answers 3 means the raw-key pubKeyAuth path and no
    // clientNonce; answering 6 while the client advertised 4 must NOT upgrade it.
    const Bytes spk = FromHex("3006020101020101");

    {   // server downgrades: 6 -> 3
        CredsspClient c(TestCreds(), 6);
        c.SetNonceForTest(FixedNonce());
        c.SetServerPublicKeyForTest(spk);
        Bytes out;
        CHECK(c.Start(out).ok());
        TsRequest ch;
        ch.version = 3;
        ch.nego_token = ServerChallengeMessage();
        Bytes wire;
        CHECK(ch.Encode(wire).ok());
        Bytes step3;
        CHECK(c.OnServerResponse(wire.data(), wire.size(), step3).ok());
        TsRequest req;
        CHECK(req.Decode(step3.data(), step3.size()).ok());
        CHECK(req.version == 3);
        CHECK(req.client_nonce.empty());
        CHECK(req.pub_key_auth.size() == 16 + spk.size());
        CHECK(c.version() == 3);
    }

    {   // server higher than the client: 4 stays 4, never upgraded to 6
        CredsspClient c(TestCreds(), 4);
        c.SetNonceForTest(FixedNonce());
        c.SetServerPublicKeyForTest(spk);
        Bytes out;
        CHECK(c.Start(out).ok());
        TsRequest ch;
        ch.version = 6;
        ch.nego_token = ServerChallengeMessage();
        Bytes wire;
        CHECK(ch.Encode(wire).ok());
        Bytes step3;
        CHECK(c.OnServerResponse(wire.data(), wire.size(), step3).ok());
        TsRequest req;
        CHECK(req.Decode(step3.data(), step3.size()).ok());
        CHECK(req.version == 4);
        CHECK(req.client_nonce.empty());
        CHECK(req.pub_key_auth.size() == 16 + spk.size());
        CHECK(c.version() == 4);
    }
}

RTSC_TEST(tampered_signature_checksum_is_rejected) {
    // S11: tampering a ciphertext byte is caught downstream by the echo compare,
    // so it cannot tell "MAC checked" from "echo compared". Tampering only the
    // checksum byte leaves the plaintext (and therefore the echo) intact: without
    // a MAC check this is completely invisible.
    CredsspClient c(TestCreds(), 6);
    c.SetNonceForTest(FixedNonce());
    c.SetServerPublicKeyForTest(FromHex("3006020101020101"));
    Bytes out;
    CHECK(c.Start(out).ok());
    TsRequest ch;
    ch.version = 6;
    ch.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(ch.Encode(wire).ok());
    Bytes step3;
    CHECK(c.OnServerResponse(wire.data(), wire.size(), step3).ok());

    TsRequest step4;
    step4.version = 6;
    Bytes echo = c.MakeServerEchoForTest();
    echo[4] ^= 0xFF;  // first checksum byte; ciphertext untouched
    step4.pub_key_auth = echo;
    Bytes w4;
    CHECK(step4.Encode(w4).ok());
    Bytes step5;
    const Error e = c.OnServerResponse(w4.data(), w4.size(), step5);
    CHECK(!e.ok());
    CHECK(e.status == Status::kMalformed);
    CHECK(step5.empty());
    CHECK(!c.complete());

    // Control: an untampered echo is still accepted, so the check rejects
    // tampering rather than the whole step-4 path.
    CredsspClient d(TestCreds(), 6);
    d.SetNonceForTest(FixedNonce());
    d.SetServerPublicKeyForTest(FromHex("3006020101020101"));
    Bytes out2;
    CHECK(d.Start(out2).ok());
    Bytes step3b;
    CHECK(d.OnServerResponse(wire.data(), wire.size(), step3b).ok());
    TsRequest step4b;
    step4b.version = 6;
    step4b.pub_key_auth = d.MakeServerEchoForTest();
    Bytes w4b;
    CHECK(step4b.Encode(w4b).ok());
    Bytes step5b;
    CHECK(d.OnServerResponse(w4b.data(), w4b.size(), step5b).ok());
    CHECK(d.complete());
}

RTSC_TEST(start_without_public_key_fails) {
    // S18: nothing in production ever wrote server_public_key_ (only the ForTest
    // hook did), so pubKeyAuth was SHA256(magic || nonce || "") and the handshake
    // "succeeded" into a state with no MITM protection. It must fail instead.
    CredsspClient c(TestCreds(), 6);
    c.SetNonceForTest(FixedNonce());

    Bytes out;
    const Error se = c.Start(out);
    if (!se.ok()) {
        CHECK(se.status == Status::kUnsupported);
        CHECK(out.empty());
        return;
    }

    TsRequest ch;
    ch.version = 6;
    ch.nego_token = ServerChallengeMessage();
    Bytes wire;
    CHECK(ch.Encode(wire).ok());
    Bytes step3;
    const Error e = c.OnServerResponse(wire.data(), wire.size(), step3);
    CHECK(!e.ok());
    CHECK(e.status == Status::kUnsupported);
    CHECK(step3.empty());
    CHECK(!c.complete());
}


RTSC_TEST(error_code_wins_over_bad_version) {
    // Ordering question: a peer can answer with an out-of-range version AND an
    // errorCode. The server's own status is the actionable information; masking
    // it with "unsupported version" (native_code 0) loses the diagnosis. The
    // errorCode branch therefore runs first, and the version range check second.
    CredsspClient c(TestCreds(), 6);
    c.SetNonceForTest(FixedNonce());
    c.SetServerPublicKeyForTest(FromHex("3006020101020101"));
    Bytes out;
    CHECK(c.Start(out).ok());

    TsRequest err;
    err.version = 1;                 // out of range on purpose
    err.has_error_code = true;
    err.error_code = 0xC000006Du;    // STATUS_LOGON_FAILURE
    Bytes wire;
    CHECK(err.Encode(wire).ok());

    Bytes next;
    const Error e = c.OnServerResponse(wire.data(), wire.size(), next);
    CHECK(!e.ok());
    CHECK(e.native_code == static_cast<int32_t>(0xC000006Du));
    CHECK(next.empty());

    // Control: the same out-of-range version WITHOUT an errorCode is still
    // rejected by the version check, so the range check has not been dropped.
    CredsspClient d(TestCreds(), 6);
    d.SetNonceForTest(FixedNonce());
    d.SetServerPublicKeyForTest(FromHex("3006020101020101"));
    Bytes out2;
    CHECK(d.Start(out2).ok());
    TsRequest bad;
    bad.version = 1;
    bad.nego_token = ServerChallengeMessage();
    Bytes wire2;
    CHECK(bad.Encode(wire2).ok());
    Bytes step3;
    const Error e2 = d.OnServerResponse(wire2.data(), wire2.size(), step3);
    CHECK(!e2.ok());
    CHECK(e2.status == Status::kUnsupported);
}

int main() { return rtsc::test::run_all("rtsc_credssp_sm_tests"); }
