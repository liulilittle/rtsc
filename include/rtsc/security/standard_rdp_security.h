// Standard RDP Security data plane (PROTOCOL_RDP, no TLS / CredSSP).
//
// Reference: [MS-RDPBCGR] 2.2.1.4.3 (TS_UD_SC_SEC1), 2.2.1.10 (Security
// Exchange), 5.3.4 (Encrypting the Client Random), 5.3.5 (session keys),
// 5.3.6 (RC4 + MAC), 5.3.7 (key update).
//
// Two layers are easy to conflate and must stay separate:
//   * the MCS/T.125 channel is plaintext (there is no TLS underneath), and
//   * the RDP security header on each post-exchange userData selects RC4
//     encryption (SEC_ENCRYPT) when the negotiated encryption level/method are
//     non-zero.
//
// This class owns the client half of that second layer:
//   * Configure() parses the server's TS_UD_SC_SEC1 and latches the server
//     random + certificate;
//   * BuildSecurityExchange() generates the client random, RSA-encrypts it and
//     returns the MCS-framed Security Exchange PDU (SEC_EXCHANGE_PKT);
//   * SendPdu()/ReceivePdu() apply the RC4 + 8-byte MAC layer to MCS PDUs and
//     return the plaintext PDU the upper layers expect.
//
// Client Info is deliberately NOT encrypted here: under Standard RDP Security
// it is sent with only SEC_INFO_PKT in the clear (the server's security layer
// is armed by the Security Exchange that precedes it).

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "rtsc/crypto/rdp_security.h"
#include "rtsc/crypto/rsa.h"

namespace rtsc::security {

class StandardRdpSecurity {
 public:
    // TS_UD_SC_SEC1 fields ([MS-RDPBCGR] 2.2.1.4.3).
    struct ServerSecurityData {
        uint32_t encryption_method = 0;
        uint32_t encryption_level = 0;
        std::vector<uint8_t> server_random;       // 32 bytes when present
        std::vector<uint8_t> server_certificate;  // PROPRIETARYSERVERCERTIFICATE
    };

    StandardRdpSecurity() = default;

    StandardRdpSecurity(StandardRdpSecurity&&) = default;
    StandardRdpSecurity& operator=(StandardRdpSecurity&&) = default;
    StandardRdpSecurity(const StandardRdpSecurity&) = delete;
    StandardRdpSecurity& operator=(const StandardRdpSecurity&) = delete;

    // Parses the TS_UD_SC_SEC1 payload (the GCC block body, without its 4-byte
    // TS_UD_HEADER). Returns false and fills `why` on a malformed block.
    static bool ParseServerSecurityData(const uint8_t* data, size_t size,
                                        ServerSecurityData& out,
                                        std::string& why);

    // Latches the server parameters. When encryptionLevel and encryptionMethod
    // are both zero the session stays plaintext (Configure succeeds with
    // encryption_enabled() == false). Otherwise the server random and the RSA
    // certificate are mandatory and the public key is extracted eagerly, so a
    // bad certificate fails before the MCS handshake reaches Client Info.
    bool Configure(const ServerSecurityData& data, std::string& why);

    bool configured() const noexcept { return configured_; }
    bool encryption_enabled() const noexcept { return encryption_enabled_; }
    bool exchange_complete() const noexcept { return exchange_complete_; }
    bool failed() const noexcept { return failed_; }
    const std::string& error() const noexcept { return error_; }

    // The certificate the server sent in TS_UD_SC_SEC1. The licensing machine
    // uses it when the Server License Request carries an empty certificate
    // (the in-tree server does exactly that).
    const std::vector<uint8_t>& server_certificate() const noexcept {
        return server_certificate_;
    }

    // Builds the complete MCS Send Data Request carrying the Security Exchange
    // PDU. Returns an empty vector when encryption is disabled or on failure
    // (`why` populated). On success the session keys are derived and the RC4
    // streams are armed, so SendPdu() may be used immediately afterwards.
    std::vector<uint8_t> BuildSecurityExchange(uint16_t initiator,
                                               uint16_t channel_id,
                                               std::string& why);

    // Post-exchange data plane. `pdu` is a complete TPKT-framed MCS Send Data
    // PDU. With encryption enabled the userData is wrapped in a 12-byte
    // TS_SECURITY_HEADER1 (SEC_ENCRYPT + MAC) and RC4-encrypted; with
    // encryption disabled the PDU is returned unchanged.
    std::vector<uint8_t> SendPdu(const std::vector<uint8_t>& pdu);

    // Feeds plaintext bytes from the peer (still TPKT/fast-path framed) and
    // returns complete MCS PDUs with any SEC_ENCRYPT layer removed. Multiple
    // PDUs may be returned. On a MAC failure failed() becomes true and no
    // further PDUs are returned.
    std::vector<std::vector<uint8_t>> ReceivePdu(const uint8_t* in,
                                                 size_t in_size);

    // Inserts bytes that were already buffered by the caller (the connect-phase
    // plaintext framer) ahead of the next ReceivePdu input.
    void PrependInput(const std::vector<uint8_t>& bytes);

 private:
    bool DecryptUserData(std::vector<uint8_t>& pdu);
    bool Fail(const std::string& reason);

    bool configured_ = false;
    bool encryption_enabled_ = false;
    bool exchange_complete_ = false;
    bool failed_ = false;
    std::string error_;

    uint32_t encryption_method_ = 0;
    uint32_t encryption_level_ = 0;
    std::vector<uint8_t> server_random_;
    std::vector<uint8_t> server_certificate_;
    crypto::RsaPublicKey server_key_;
    std::vector<uint8_t> client_random_;
    std::unique_ptr<crypto::RdpSecurityContext> context_;

    std::vector<uint8_t> input_buf_;
};

}  // namespace rtsc::security
