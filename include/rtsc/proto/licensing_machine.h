// Client-side licensing state machine ([MS-RDPELE] 1.3 / [MS-RDPBCGR] 1.3.1.1
// phase 5).
//
// Reference: docs/spec/licensing.md sections 4 and 6.
//
// This machine runs after the Client Info PDU, before the capability exchange.
// It consumes licensing PDUs (each an MCS Send Data PDU carrying a 4-byte
// SEC_LICENSE_PKT security header followed by a LICENSE_PREAMBLE + message) and
// produces the client's replies.
//
// L3 crypto is always present, independently of TLS (licensing.md section 6.1):
// the client random and a 48-byte premaster secret are RSA-encrypted with the
// server's public key, and every Encrypted* field is RC4-encrypted under a key
// derived from the premaster secret.
//
// Two outcomes end the phase: SERVER_NEW_LICENSE / SERVER_UPGRADE_LICENSE, or a
// LICENSE_ERROR_MESSAGE carrying STATUS_VALID_CLIENT (no license needed).

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/licensing.h"

namespace rtsc::proto {

enum class LicensePhase : uint8_t {
    kInit,                     // nothing sent
    kAwaitLicenseRequest,      // waiting for SERVER_LICENSE_REQUEST
    kAwaitPlatformChallenge,   // sent CLIENT_NEW_LICENSE_REQUEST
    kAwaitNewLicense,          // sent CLIENT_PLATFORM_CHALLENGE_RESPONSE
    kDone,                     // licensed (or no license needed)
    kFailed,
};

const char* to_string(LicensePhase phase);

struct LicenseState {
    LicensePhase phase = LicensePhase::kInit;
    uint32_t error_code = 0;  // from a failing LICENSE_ERROR_MESSAGE
    std::string error;
};

struct LicenseStep {
    std::vector<std::vector<uint8_t>> to_send;  // MCS-framed licensing PDUs
    bool done = false;
    bool failed = false;
    std::string error;
};

class LicensingMachine {
 public:
    struct Config {
        uint16_t user_channel_id = 0;
        uint16_t io_channel_id = 0;
        std::string user_name;
        std::string machine_name;
        uint32_t platform_id = 0x04010000;  // WinNT POST_5.2 | Microsoft
        // Any stable 16 bytes works: the server only uses the HWID as an index
        // (licensing.md section 7).
        std::array<uint32_t, 4> hardware_id{};
    };

    explicit LicensingMachine(const Config& config);

    // Enters kAwaitLicenseRequest.
    void Start();

    // Consumes a complete inbound licensing PDU (TPKT-framed MCS Send Data).
    LicenseStep OnPdu(const uint8_t* data, size_t size);

    const LicenseState& state() const { return state_; }
    bool done() const { return state_.phase == LicensePhase::kDone; }

    // ---- test hooks ---------------------------------------------------------
    // The premaster secret and randoms are normally drawn from the CSPRNG.
    void SetPremasterForTest(const std::vector<uint8_t>& p) { premaster_ = p; }
    void SetClientRandomForTest(const std::vector<uint8_t>& r) { client_random_ = r; }
    const std::vector<uint8_t>& premaster_for_test() const { return premaster_; }
    const std::vector<uint8_t>& client_random_for_test() const { return client_random_; }
    const LicensingKeys& keys_for_test() const { return keys_; }

 private:
    LicenseStep Fail(const std::string& reason);
    std::vector<uint8_t> FrameLicensePdu(const std::vector<uint8_t>& payload) const;

    LicenseStep HandleLicenseRequest(const LicensingPdu& pdu);
    LicenseStep HandlePlatformChallenge(const LicensingPdu& pdu);
    LicenseStep HandleNewLicense(const LicensingPdu& pdu);
    LicenseStep HandleError(const LicensingPdu& pdu);

    Config config_;
    LicenseState state_;

    std::vector<uint8_t> client_random_;  // 32 bytes
    std::vector<uint8_t> server_random_;  // 32 bytes
    std::vector<uint8_t> premaster_;      // 48 bytes
    LicensingKeys keys_{};
    bool keys_ready_ = false;
};

}  // namespace rtsc::proto
