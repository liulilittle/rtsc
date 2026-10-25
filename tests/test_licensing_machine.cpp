// Licensing state machine ([MS-RDPELE] 1.3).
//
// The server side is simulated from the spec. The server certificate carries a
// real 2048-bit RSA public key generated in-process, so the encrypted premaster
// secret is checked by decrypting it with the matching private key.

#include "rtsc/proto/licensing_machine.h"

#include <array>
#include <cstring>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>

#include <bcrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#endif

#include "rtsc/crypto/hash.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/share.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

#if defined(_WIN32)
struct TestKeyPair {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    std::vector<uint8_t> modulus_be;
    std::vector<uint8_t> exponent_be;
};

bool GenerateKeyPair(TestKeyPair& kp) {
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&kp.alg, BCRYPT_RSA_ALGORITHM,
                                                nullptr, 0))) {
        return false;
    }
    if (!NT_SUCCESS(BCryptGenerateKeyPair(kp.alg, &kp.key, 2048, 0))) return false;
    if (!NT_SUCCESS(BCryptFinalizeKeyPair(kp.key, 0))) return false;

    ULONG len = 0;
    if (!NT_SUCCESS(BCryptExportKey(kp.key, nullptr, BCRYPT_RSAPUBLIC_BLOB,
                                    nullptr, 0, &len, 0))) {
        return false;
    }
    std::vector<uint8_t> blob(len);
    if (!NT_SUCCESS(BCryptExportKey(kp.key, nullptr, BCRYPT_RSAPUBLIC_BLOB,
                                    blob.data(), len, &len, 0))) {
        return false;
    }
    BCRYPT_RSAKEY_BLOB hdr{};
    std::memcpy(&hdr, blob.data(), sizeof(hdr));
    const uint8_t* p = blob.data() + sizeof(hdr);
    kp.exponent_be.assign(p, p + hdr.cbPublicExp);
    kp.modulus_be.assign(p + hdr.cbPublicExp, p + hdr.cbPublicExp + hdr.cbModulus);
    return true;
}

bool RawDecrypt(TestKeyPair& kp, std::vector<uint8_t>& cipher,
                std::vector<uint8_t>& out) {
    ULONG written = 0;
    out.assign(cipher.size(), 0);
    const NTSTATUS st =
        BCryptDecrypt(kp.key, cipher.data(), static_cast<ULONG>(cipher.size()),
                      nullptr, nullptr, 0, out.data(),
                      static_cast<ULONG>(out.size()), &written, BCRYPT_PAD_NONE);
    if (!NT_SUCCESS(st)) return false;
    out.resize(written);
    return true;
}
#endif  // _WIN32

#if defined(_WIN32)
std::vector<uint8_t> Utf16Z(const std::string& s) {
    auto b = rtsc::crypto::Utf16Le(s);
    b.push_back(0);
    b.push_back(0);
    return b;
}
#endif  // _WIN32

// Wraps a licensing payload in a 4-byte SEC_LICENSE_PKT security header and an
// MCS Send Data Indication.
std::vector<uint8_t> ServerLicensePdu(const std::vector<uint8_t>& payload) {
    ByteWriter sh;
    sh.u16le(static_cast<uint16_t>(kSecLicensePkt));
    sh.u16le(0);
    std::vector<uint8_t> user_data = sh.take();
    user_data.insert(user_data.end(), payload.begin(), payload.end());
    return McsSendData::build_indication(0x03EA, 0x03EF, user_data);
}

#if defined(_WIN32)
// Builds a SERVER_LICENSE_REQUEST carrying `cert` as the server certificate.
std::vector<uint8_t> BuildLicenseRequest(const std::vector<uint8_t>& cert) {
    ByteWriter w;
    for (int i = 0; i < 32; ++i) w.u8(static_cast<uint8_t>(0xA0 + i));
    w.u32le(0x00060000);
    const auto company = Utf16Z("Microsoft Corporation");
    w.u32le(static_cast<uint32_t>(company.size()));
    w.bytes(company.data(), company.size());
    const auto pid = Utf16Z("A02");
    w.u32le(static_cast<uint32_t>(pid.size()));
    w.bytes(pid.data(), pid.size());
    w.u16le(0x000D);  // BB_KEY_EXCHG_ALG_BLOB
    w.u16le(4);
    w.u32le(1);  // KEY_EXCHANGE_ALG_RSA
    w.u16le(0x0003);  // BB_CERTIFICATE_BLOB
    w.u16le(static_cast<uint16_t>(cert.size()));
    w.bytes(cert.data(), cert.size());
    w.u32le(1);      // ScopeCount
    w.u16le(0x000E);  // BB_SCOPE_BLOB
    w.u16le(14);
    for (char c : std::string("microsoft.com")) w.u8(static_cast<uint8_t>(c));
    w.u8(0);
    return w.take();
}

// Builds a proprietary server certificate wrapping an RSA_PUBLIC_KEY blob.
std::vector<uint8_t> BuildProprietaryCert(const std::vector<uint8_t>& rsa_blob) {
    ByteWriter w;
    w.u32le(1);  // dwVersion = CERT_CHAIN_VERSION_1
    w.u32le(1);  // dwSigAlgId = SIGNATURE_ALG_RSA
    w.u32le(1);  // dwKeyAlgId = KEY_EXCHANGE_ALG_RSA
    w.u16le(0x0006);  // BB_RSA_KEY_BLOB
    w.u16le(static_cast<uint16_t>(rsa_blob.size()));
    w.bytes(rsa_blob.data(), rsa_blob.size());
    return w.take();
}

// Builds an RSA_PUBLIC_KEY blob (RSA1 magic, little-endian modulus) from a
// big-endian modulus.
std::vector<uint8_t> BuildRsaPublicKeyBlob(const std::vector<uint8_t>& modulus_be,
                                           uint32_t exponent) {
    RsaPublicKey k;
    k.key_length = static_cast<uint32_t>(modulus_be.size()) + 8;
    k.bit_length = static_cast<uint32_t>(modulus_be.size()) * 8;
    k.data_length = static_cast<uint32_t>(modulus_be.size()) - 1;
    k.public_exponent = exponent;
    k.modulus.assign(modulus_be.rbegin(), modulus_be.rend());  // to little-endian
    return k.encode();
}
#endif  // _WIN32

LicensingMachine::Config MakeConfig() {
    LicensingMachine::Config c;
    c.user_channel_id = 0x03EF;
    c.io_channel_id = 0x03EB;
    c.user_name = "User";
    c.machine_name = "RTSC-PC";
    c.platform_id = 0x04010000;
    return c;
}

}  // namespace

RTSC_TEST(licensing_machine_starts_awaiting_request) {
    LicensingMachine m(MakeConfig());
    CHECK(m.state().phase == LicensePhase::kInit);
    m.Start();
    CHECK(m.state().phase == LicensePhase::kAwaitLicenseRequest);
}

RTSC_TEST(licensing_machine_error_valid_client_completes) {
    LicensingMachine m(MakeConfig());
    m.Start();

    LicenseErrorMessage err;
    err.error_code = static_cast<uint32_t>(LicenseErrorCode::kStatusValidClient);
    err.state_transition =
        static_cast<uint32_t>(LicenseStateTransition::kNoTransition);
    const auto payload = LicensingPdu::Encode(LicenseMessageType::kErrorAlert,
                                              err.encode());
    const auto wire = ServerLicensePdu(payload);
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK(step.done);
    CHECK(m.done());
}

RTSC_TEST(licensing_machine_error_other_code_fails) {
    LicensingMachine m(MakeConfig());
    m.Start();

    LicenseErrorMessage err;
    err.error_code = static_cast<uint32_t>(LicenseErrorCode::kNoLicense);
    err.state_transition = static_cast<uint32_t>(LicenseStateTransition::kTotalAbort);
    const auto payload = LicensingPdu::Encode(LicenseMessageType::kErrorAlert,
                                              err.encode());
    const auto wire = ServerLicensePdu(payload);
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(step.failed);
    CHECK(m.state().phase == LicensePhase::kFailed);
    CHECK_EQ(m.state().error_code, static_cast<uint32_t>(LicenseErrorCode::kNoLicense));
}

RTSC_TEST(licensing_machine_license_request_emits_new_license_request) {
#if defined(_WIN32)
    TestKeyPair kp;
    CHECK(GenerateKeyPair(kp));

    const auto rsa_blob = BuildRsaPublicKeyBlob(kp.modulus_be, 65537);
    const auto cert = BuildProprietaryCert(rsa_blob);
    const auto body = BuildLicenseRequest(cert);
    const auto payload = LicensingPdu::Encode(LicenseMessageType::kLicenseRequest, body);
    const auto wire = ServerLicensePdu(payload);

    LicensingMachine m(MakeConfig());
    m.Start();
    const auto step = m.OnPdu(wire.data(), wire.size());
    CHECK(!step.failed);
    CHECK_EQ(step.to_send.size(), static_cast<size_t>(1));
    CHECK(m.state().phase == LicensePhase::kAwaitPlatformChallenge);

    // Unwrap the reply.
    McsSendData sd;
    CHECK(McsSendData::parse(step.to_send[0].data(), step.to_send[0].size(), sd) ==
          Status::Ok);
    CHECK(sd.user_data.size() > 4);
    LicensingPdu reply;
    CHECK(LicensingPdu::Parse(sd.user_data.data() + 4, sd.user_data.size() - 4,
                              reply) == Status::Ok);
    CHECK(reply.preamble.type == LicenseMessageType::kNewLicenseRequest);

    // Decrypt the encrypted premaster secret with the private key.
    ClientNewLicenseRequest req;
    CHECK(ClientNewLicenseRequest::parse(sd.user_data.data() + 4 + 4,
                                         sd.user_data.size() - 4 - 4,
                                         req) == Status::Ok);
    CHECK_EQ(req.preferred_key_exchange_alg, static_cast<uint32_t>(1));
    CHECK_EQ(req.client_random.size(), static_cast<size_t>(32));
    CHECK_EQ(req.encrypted_premaster.size(), static_cast<size_t>(264));
    // The last 8 bytes of the encrypted blob are zero padding.
    for (size_t i = 256; i < 264; ++i) {
        CHECK_EQ(req.encrypted_premaster[i], static_cast<uint8_t>(0));
    }

    // Decrypt and check the premaster matches what the machine generated.
    std::vector<uint8_t> cipher(req.encrypted_premaster.begin(),
                                req.encrypted_premaster.begin() + 256);
    std::vector<uint8_t> plain;
    CHECK(RawDecrypt(kp, cipher, plain));
    CHECK_EQ(plain.size(), static_cast<size_t>(256));
    const auto& pm = m.premaster_for_test();
    CHECK_EQ(pm.size(), static_cast<size_t>(48));
    for (size_t i = 0; i < 48; ++i) {
        CHECK_EQ(plain[256 - 1 - i], pm[i]);
    }

    BCryptDestroyKey(kp.key);
    BCryptCloseAlgorithmProvider(kp.alg, 0);
#else
    CHECK(true);
#endif
}

int main() { return ::rtsc::test::run_all("rtsc_licensing_machine_tests"); }
