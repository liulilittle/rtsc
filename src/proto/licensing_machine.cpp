// Licensing state machine implementation.
//
// Reference: docs/spec/licensing.md sections 4 and 6.

#include "rtsc/proto/licensing_machine.h"

#include <cstring>
#include <utility>

#include "rtsc/crypto/hash.h"
#include "rtsc/crypto/random.h"
#include "rtsc/crypto/rsa.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/share.h"

namespace rtsc::proto {

namespace {

constexpr size_t kRandomSize = 32;
constexpr size_t kPremasterSize = 48;

// Converts the RDP wire RSA public key (little-endian modulus, u32 exponent)
// into the crypto layer's big-endian form.
crypto::RsaPublicKey ToCryptoKey(const RsaPublicKey& k) {
    crypto::RsaPublicKey out;
    out.modulus.assign(k.modulus.rbegin(), k.modulus.rend());

    const uint8_t e[4] = {
        static_cast<uint8_t>((k.public_exponent >> 24) & 0xFF),
        static_cast<uint8_t>((k.public_exponent >> 16) & 0xFF),
        static_cast<uint8_t>((k.public_exponent >> 8) & 0xFF),
        static_cast<uint8_t>(k.public_exponent & 0xFF),
    };
    size_t start = 0;
    while (start < 4 && e[start] == 0) ++start;
    out.exponent.assign(e + start, e + 4);
    return out;
}

std::vector<uint8_t> ToBytes(const std::array<uint8_t, 16>& a) {
    return std::vector<uint8_t>(a.begin(), a.end());
}

}  // namespace

const char* to_string(LicensePhase phase) {
    switch (phase) {
        case LicensePhase::kInit: return "init";
        case LicensePhase::kAwaitLicenseRequest: return "await-license-request";
        case LicensePhase::kAwaitPlatformChallenge: return "await-platform-challenge";
        case LicensePhase::kAwaitNewLicense: return "await-new-license";
        case LicensePhase::kDone: return "done";
        case LicensePhase::kFailed: return "failed";
    }
    return "unknown";
}

LicensingMachine::LicensingMachine(const Config& config) : config_(config) {}

void LicensingMachine::Start() {
    state_.phase = LicensePhase::kAwaitLicenseRequest;
}

LicenseStep LicensingMachine::Fail(const std::string& reason) {
    state_.phase = LicensePhase::kFailed;
    state_.error = reason;
    LicenseStep s;
    s.failed = true;
    s.error = reason;
    return s;
}

std::vector<uint8_t> LicensingMachine::FrameLicensePdu(
    const std::vector<uint8_t>& payload) const {
    // A 4-byte Basic security header with SEC_LICENSE_PKT, then the payload.
    ByteWriter sh;
    sh.u16le(static_cast<uint16_t>(kSecLicensePkt));
    sh.u16le(0);
    std::vector<uint8_t> user_data = sh.take();
    user_data.insert(user_data.end(), payload.begin(), payload.end());
    return McsSendData::build_request(config_.user_channel_id,
                                      config_.io_channel_id, user_data);
}

LicenseStep LicensingMachine::OnPdu(const uint8_t* data, size_t size) {
    LicenseStep out;
    if (state_.phase == LicensePhase::kFailed) {
        out.failed = true;
        out.error = state_.error;
        return out;
    }
    if (state_.phase == LicensePhase::kDone) {
        out.done = true;
        return out;
    }

    McsSendData sd;
    if (McsSendData::parse(data, size, sd) != Status::Ok) {
        return Fail("malformed MCS Send Data PDU");
    }
    if (sd.user_data.size() < 4) return Fail("licensing PDU is too short");

    const uint16_t flags = static_cast<uint16_t>(sd.user_data[0]) |
                           (static_cast<uint16_t>(sd.user_data[1]) << 8);
    if ((flags & static_cast<uint16_t>(kSecLicensePkt)) == 0) {
        return Fail("PDU does not carry SEC_LICENSE_PKT");
    }

    LicensingPdu pdu;
    if (LicensingPdu::Parse(sd.user_data.data() + 4, sd.user_data.size() - 4,
                            pdu) != Status::Ok) {
        return Fail("malformed licensing PDU");
    }

    // A LICENSE_ERROR_MESSAGE may arrive at any point.
    if (pdu.preamble.type == LicenseMessageType::kErrorAlert) {
        return HandleError(pdu);
    }

    switch (state_.phase) {
        case LicensePhase::kAwaitLicenseRequest:
            if (pdu.preamble.type != LicenseMessageType::kLicenseRequest) {
                return Fail("expected SERVER_LICENSE_REQUEST");
            }
            return HandleLicenseRequest(pdu);
        case LicensePhase::kAwaitPlatformChallenge:
            if (pdu.preamble.type != LicenseMessageType::kPlatformChallenge) {
                return Fail("expected SERVER_PLATFORM_CHALLENGE");
            }
            return HandlePlatformChallenge(pdu);
        case LicensePhase::kAwaitNewLicense:
            if (pdu.preamble.type != LicenseMessageType::kNewLicense &&
                pdu.preamble.type != LicenseMessageType::kUpgradeLicense) {
                return Fail("expected SERVER_NEW_LICENSE");
            }
            return HandleNewLicense(pdu);
        default:
            return Fail("unexpected licensing PDU for the current phase");
    }
}

LicenseStep LicensingMachine::HandleLicenseRequest(const LicensingPdu& pdu) {
    LicenseStep out;
    const ServerLicenseRequest& req = pdu.license_request;

    // Prefer the certificate carried by the license request itself; fall back
    // to the one from TS_UD_SC_SEC1 (the in-tree server puts the key only
    // there).
    std::vector<uint8_t> certificate = req.server_certificate.data;
    if (certificate.empty()) certificate = config_.server_certificate;

    crypto::RsaPublicKey key;
    const bool have_key = !certificate.empty();
    if (have_key) {
        RsaPublicKey rsa;
        if (ExtractRsaPublicKey(certificate, rsa) != Status::Ok) {
            return Fail("cannot extract the server RSA public key from the "
                        "license request certificate");
        }
        key = ToCryptoKey(rsa);
    } else if (!config_.allow_missing_server_key) {
        return Fail("cannot extract the server RSA public key from the license "
                    "request certificate");
    }

    if (premaster_.size() != kPremasterSize) {
        if (!crypto::RandomBytes(premaster_, kPremasterSize)) {
            return Fail("CSPRNG unavailable for the premaster secret");
        }
    }
    if (client_random_.size() != kRandomSize) {
        if (!crypto::RandomBytes(client_random_, kRandomSize)) {
            return Fail("CSPRNG unavailable for the client random");
        }
    }
    server_random_ = req.server_random;
    if (server_random_.size() != kRandomSize) {
        return Fail("SERVER_LICENSE_REQUEST server random is not 32 bytes");
    }

    std::vector<uint8_t> encrypted;
    if (have_key &&
        !crypto::RdpRsaEncryptClientRandom(key, premaster_, encrypted)) {
        return Fail("RSA encryption of the premaster secret failed");
    }

    keys_ = DeriveLicensingKeys(premaster_, client_random_, server_random_);
    keys_ready_ = true;

    ClientNewLicenseRequest reply;
    reply.preferred_key_exchange_alg = ClientNewLicenseRequest::kKeyExchangeAlgRsa;
    reply.platform_id = config_.platform_id;
    reply.client_random = client_random_;
    reply.encrypted_premaster = encrypted;
    reply.user_name = config_.user_name;
    reply.machine_name = config_.machine_name;

    out.to_send.push_back(FrameLicensePdu(LicensingPdu::Encode(
        LicenseMessageType::kNewLicenseRequest, reply.encode())));
    state_.phase = LicensePhase::kAwaitPlatformChallenge;
    return out;
}

LicenseStep LicensingMachine::HandlePlatformChallenge(const LicensingPdu& pdu) {
    LicenseStep out;
    if (!keys_ready_) return Fail("platform challenge before the keys are ready");

    const ServerPlatformChallenge& ch = pdu.platform_challenge;

    // Decrypt the challenge with the licensing encryption key.
    crypto::Rc4 rc4_dec(keys_.encryption_key.data(), keys_.encryption_key.size());
    const std::vector<uint8_t> challenge = rc4_dec.Apply(ch.encrypted_challenge.data);

    if (ToBytes(LicensingMac(keys_.mac_salt_key, challenge)) != ch.mac) {
        return Fail("platform challenge MAC mismatch");
    }

    PlatformChallengeResponseData resp;
    resp.version = 0x0100;
    resp.client_type = PlatformChallengeResponseData::kWin32ClientType;
    resp.license_detail_level = PlatformChallengeResponseData::kDetailDetail;
    resp.challenge = challenge;
    const std::vector<uint8_t> resp_plain = resp.encode();

    crypto::Rc4 rc4_enc1(keys_.encryption_key.data(), keys_.encryption_key.size());
    const std::vector<uint8_t> resp_enc = rc4_enc1.Apply(resp_plain);

    ClientHardwareId hwid;
    hwid.platform_id = config_.platform_id;
    for (size_t i = 0; i < 4; ++i) hwid.data[i] = config_.hardware_id[i];
    const std::vector<uint8_t> hwid_plain = hwid.encode();

    crypto::Rc4 rc4_enc2(keys_.encryption_key.data(), keys_.encryption_key.size());
    const std::vector<uint8_t> hwid_enc = rc4_enc2.Apply(hwid_plain);

    // The MAC covers the plaintext response data and the plaintext HWID.
    std::vector<uint8_t> mac_input = resp_plain;
    mac_input.insert(mac_input.end(), hwid_plain.begin(), hwid_plain.end());

    ClientPlatformChallengeResponse reply;
    reply.encrypted_challenge_response = resp_enc;
    reply.encrypted_hwid = hwid_enc;
    reply.mac = ToBytes(LicensingMac(keys_.mac_salt_key, mac_input));

    out.to_send.push_back(FrameLicensePdu(LicensingPdu::Encode(
        LicenseMessageType::kPlatformChallengeResponse, reply.encode())));
    state_.phase = LicensePhase::kAwaitNewLicense;
    return out;
}

LicenseStep LicensingMachine::HandleNewLicense(const LicensingPdu& /*pdu*/) {
    // The CAL is opaque; storing it for a future CLIENT_LICENSE_INFO is out of
    // scope (licensing.md section 10). The phase is over.
    state_.phase = LicensePhase::kDone;
    LicenseStep out;
    out.done = true;
    return out;
}

LicenseStep LicensingMachine::HandleError(const LicensingPdu& pdu) {
    state_.error_code = pdu.error_alert.error_code;
    if (pdu.error_alert.is_valid_client()) {
        // STATUS_VALID_CLIENT + ST_NO_TRANSITION: no license is needed.
        state_.phase = LicensePhase::kDone;
        LicenseStep out;
        out.done = true;
        return out;
    }
    return Fail("licensing error 0x" +
                std::to_string(static_cast<unsigned>(pdu.error_alert.error_code)));
}

}  // namespace rtsc::proto
