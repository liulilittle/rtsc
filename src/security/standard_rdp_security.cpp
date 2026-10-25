// Standard RDP Security data plane implementation.

#include "rtsc/security/standard_rdp_security.h"

#include <array>
#include <cstring>
#include <utility>

#include "rtsc/crypto/random.h"
#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/client_info.h"
#include "rtsc/proto/licensing.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/share.h"

namespace rtsc::security {
namespace {

using proto::Status;

constexpr size_t kServerRandomSize = 32;
constexpr size_t kClientRandomSize = 32;
constexpr size_t kSecurityHeaderSize = 12;  // flags(2)+flagsHi(2)+MAC(8)

// Reads a complete TPKT frame length from `buf` at `start`, or 0 if incomplete.
size_t TpktFrameLength(const std::vector<uint8_t>& buf, size_t start) {
    if (start + 4 > buf.size()) return 0;
    if (buf[start] != 0x03 || buf[start + 1] != 0x00) return 0;
    const size_t len = (static_cast<size_t>(buf[start + 2]) << 8) |
                       static_cast<size_t>(buf[start + 3]);
    if (len < 4) return 0;
    if (start + len > buf.size()) return 0;
    return len;
}

uint16_t ReadU16Le(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint16_t>(b[off]) |
           static_cast<uint16_t>(static_cast<uint16_t>(b[off + 1]) << 8);
}

// Converts the RDP wire RSA public key (little-endian modulus, u32 exponent)
// into the crypto layer's big-endian form.
crypto::RsaPublicKey ToCryptoKey(const proto::RsaPublicKey& k) {
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

}  // namespace

bool StandardRdpSecurity::ParseServerSecurityData(const uint8_t* data,
                                                  size_t size,
                                                  ServerSecurityData& out,
                                                  std::string& why) {
    proto::ByteReader r(data, size);
    if (!r.u32le(out.encryption_method) || !r.u32le(out.encryption_level)) {
        why = "TS_UD_SC_SEC1 is shorter than the 8-byte fixed header";
        return false;
    }

    // The random/certificate fields are absent only when both values are zero
    // ([MS-RDPBCGR] 2.2.1.4.3).
    if (out.encryption_method == 0 && out.encryption_level == 0) return true;

    uint32_t random_len = 0;
    uint32_t cert_len = 0;
    if (!r.u32le(random_len) || !r.u32le(cert_len)) {
        why = "TS_UD_SC_SEC1 is missing the serverRandom/serverCertificate lengths";
        return false;
    }
    if (random_len > r.remaining()) {
        why = "TS_UD_SC_SEC1 serverRandom overruns the block";
        return false;
    }
    out.server_random.assign(r.cursor(), r.cursor() + random_len);
    if (!r.skip(random_len)) {
        why = "TS_UD_SC_SEC1 serverRandom overruns the block";
        return false;
    }
    if (cert_len > r.remaining()) {
        why = "TS_UD_SC_SEC1 serverCertificate overruns the block";
        return false;
    }
    out.server_certificate.assign(r.cursor(), r.cursor() + cert_len);
    return true;
}

bool StandardRdpSecurity::Configure(const ServerSecurityData& data,
                                    std::string& why) {
    if (configured_) {
        why = "Standard RDP Security is already configured";
        return false;
    }
    encryption_method_ = data.encryption_method;
    encryption_level_ = data.encryption_level;
    server_random_ = data.server_random;
    server_certificate_ = data.server_certificate;

    // No encryption: the MCS channel is plaintext for the whole session. This
    // is the encryption_methods == 0 fallback some servers use.
    if (encryption_method_ == 0 && encryption_level_ == 0) {
        configured_ = true;
        return true;
    }

    if (encryption_method_ == 0 || encryption_level_ == 0) {
        why = "TS_UD_SC_SEC1 has an inconsistent method/level pair";
        return false;
    }
    if (encryption_method_ ==
        static_cast<uint32_t>(crypto::RdpEncryptionMethod::kFips)) {
        why = "FIPS encryption is not supported";
        return false;
    }
    if (encryption_method_ !=
            static_cast<uint32_t>(crypto::RdpEncryptionMethod::k40Bit) &&
        encryption_method_ !=
            static_cast<uint32_t>(crypto::RdpEncryptionMethod::k56Bit) &&
        encryption_method_ !=
            static_cast<uint32_t>(crypto::RdpEncryptionMethod::k128Bit)) {
        why = "unknown RDP encryption method";
        return false;
    }
    if (server_random_.size() != kServerRandomSize) {
        why = "TS_UD_SC_SEC1 serverRandom is not 32 bytes";
        return false;
    }
    if (server_certificate_.empty()) {
        why = "TS_UD_SC_SEC1 has encryption enabled but no certificate";
        return false;
    }

    proto::RsaPublicKey wire_key;
    if (proto::ExtractRsaPublicKey(server_certificate_, wire_key) != Status::Ok) {
        why = "cannot extract the RSA public key from the server certificate";
        return false;
    }
    server_key_ = ToCryptoKey(wire_key);
    if (server_key_.modulus.empty() || server_key_.exponent.empty()) {
        why = "the server certificate carries an empty RSA public key";
        return false;
    }

    configured_ = true;
    encryption_enabled_ = true;
    return true;
}

std::vector<uint8_t> StandardRdpSecurity::BuildSecurityExchange(
    uint16_t initiator, uint16_t channel_id, std::string& why) {
    if (!configured_) {
        why = "Standard RDP Security is not configured";
        return {};
    }
    if (!encryption_enabled_) {
        why = "encryption is not enabled";
        return {};
    }
    if (exchange_complete_) {
        why = "the Security Exchange PDU has already been sent";
        return {};
    }
    if (!crypto::RandomBytes(client_random_, kClientRandomSize)) {
        why = "CSPRNG unavailable for the client random";
        return {};
    }

    std::vector<uint8_t> encrypted;
    if (!crypto::RdpRsaEncryptClientRandom(server_key_, client_random_,
                                           encrypted)) {
        why = "RSA encryption of the client random failed";
        return {};
    }

    proto::SecurityExchangePdu exchange;
    exchange.encrypted_client_random = std::move(encrypted);
    const auto frame =
        proto::McsSendData::build_request(initiator, channel_id,
                                          exchange.build());
    if (frame.empty()) {
        why = "cannot frame the Security Exchange PDU";
        return {};
    }

    const crypto::RdpSessionKeys keys = crypto::DeriveRdpSessionKeys(
        client_random_, server_random_, encryption_method_);
    if (keys.encrypt_key.empty() || keys.decrypt_key.empty() ||
        keys.mac_key.empty()) {
        why = "cannot derive the Standard RDP Security session keys";
        return {};
    }
    context_ = std::make_unique<crypto::RdpSecurityContext>();
    context_->Init(keys);
    exchange_complete_ = true;
    return frame;
}

std::vector<uint8_t> StandardRdpSecurity::SendPdu(
    const std::vector<uint8_t>& pdu) {
    if (!encryption_enabled_) return pdu;
    if (!exchange_complete_ || context_ == nullptr) {
        Fail("post-exchange PDU sent before the Security Exchange");
        return {};
    }

    proto::McsSendData sd;
    if (proto::McsSendData::parse(pdu.data(), pdu.size(), sd) != Status::Ok) {
        Fail("cannot parse the outbound MCS Send Data PDU");
        return {};
    }

    std::vector<uint8_t> data = sd.user_data;
    const std::array<uint8_t, 8> mac = context_->Encrypt(data);

    proto::ByteWriter w;
    w.u16le(static_cast<uint16_t>(proto::sec::kSecEncrypt));
    w.u16le(0);
    w.bytes(mac.data(), mac.size());
    if (!data.empty()) w.bytes(data.data(), data.size());

    return proto::McsSendData::build_request(sd.initiator, sd.channel_id,
                                             w.take(), sd.priority);
}

void StandardRdpSecurity::PrependInput(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return;
    input_buf_.insert(input_buf_.begin(), bytes.begin(), bytes.end());
}

std::vector<std::vector<uint8_t>> StandardRdpSecurity::ReceivePdu(
    const uint8_t* in, size_t in_size) {
    std::vector<std::vector<uint8_t>> frames;
    if (failed_) return frames;
    if (in != nullptr && in_size > 0) {
        input_buf_.insert(input_buf_.end(), in, in + in_size);
    }

    size_t start = 0;
    for (;;) {
        size_t len = TpktFrameLength(input_buf_, start);
        if (len == 0 && start < input_buf_.size()) {
            proto::FastPathPdu fp;
            if (proto::FastPathPdu::parse(input_buf_.data() + start,
                                          input_buf_.size() - start, false,
                                          fp) == Status::Ok) {
                len = fp.length.value;
            }
        }
        if (len == 0) break;

        std::vector<uint8_t> frame(
            input_buf_.begin() + static_cast<ptrdiff_t>(start),
            input_buf_.begin() + static_cast<ptrdiff_t>(start + len));
        start += len;

        if (encryption_enabled_) {
            if (!DecryptUserData(frame)) return frames;
        }
        frames.push_back(std::move(frame));
    }
    if (start > 0) {
        input_buf_.erase(input_buf_.begin(),
                         input_buf_.begin() + static_cast<ptrdiff_t>(start));
    }
    return frames;
}

bool StandardRdpSecurity::DecryptUserData(std::vector<uint8_t>& pdu) {
    proto::McsSendData sd;
    if (proto::McsSendData::parse(pdu.data(), pdu.size(), sd) != Status::Ok) {
        // Not an MCS Send Data PDU. In an encrypted session this is unexpected,
        // but the upper layer will ignore it; do not fail the whole connection
        // on a control PDU we do not understand.
        return true;
    }
    if (sd.user_data.size() < 2) return Fail("MCS userData is too short");

    const uint16_t flags = ReadU16Le(sd.user_data, 0);
    if ((flags & static_cast<uint16_t>(proto::sec::kSecEncrypt)) == 0) {
        // A plaintext PDU in an otherwise encrypted session (e.g. a control
        // message the server chose not to encrypt). Pass it through.
        return true;
    }
    if (sd.user_data.size() < kSecurityHeaderSize) {
        return Fail("SEC_ENCRYPT PDU is shorter than TS_SECURITY_HEADER1");
    }
    if (context_ == nullptr) {
        return Fail("SEC_ENCRYPT PDU received before the session keys are ready");
    }

    std::array<uint8_t, 8> mac{};
    std::memcpy(mac.data(), sd.user_data.data() + 4, mac.size());
    std::vector<uint8_t> plain(sd.user_data.begin() + kSecurityHeaderSize,
                               sd.user_data.end());
    if (!context_->Decrypt(plain, mac)) {
        return Fail("Standard RDP Security MAC verification failed");
    }

    pdu = proto::McsSendData::build_indication(sd.initiator, sd.channel_id,
                                               plain, sd.priority);
    if (pdu.empty()) return Fail("cannot rebuild the decrypted MCS PDU");
    return true;
}

bool StandardRdpSecurity::Fail(const std::string& reason) {
    if (!failed_) {
        failed_ = true;
        error_ = reason;
    }
    return false;
}

}  // namespace rtsc::security
