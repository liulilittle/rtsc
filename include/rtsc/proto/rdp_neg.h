#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// [MS-RDPBCGR] 2.2.1.1.1 / 2.2.1.2.1 / 2.2.1.2.2
enum class NegType : uint8_t {
    kRequest = 0x01,   // TYPE_RDP_NEG_REQ
    kResponse = 0x02,  // TYPE_RDP_NEG_RSP
    kFailure = 0x03,   // TYPE_RDP_NEG_FAILURE
};

// requestedProtocols / selectedProtocol bit flags.
enum ProtocolFlag : uint32_t {
    kProtocolRdp = 0x00000000,
    kProtocolSsl = 0x00000001,
    kProtocolHybrid = 0x00000002,
    kProtocolRdstls = 0x00000004,
    kProtocolHybridEx = 0x00000008,
    kProtocolRdsaad = 0x00000010,
};

// RDP_NEG_REQ flags.
enum NegReqFlag : uint8_t {
    kRestrictedAdminModeRequired = 0x01,
    kRedirectedAuthenticationModeRequired = 0x02,
    kCorrelationInfoPresent = 0x08,
};

// RDP_NEG_RSP flags.
enum NegRspFlag : uint8_t {
    kExtendedClientDataSupported = 0x01,
    kDynvcGfxProtocolSupported = 0x02,
    kNegRspFlagReserved = 0x04,
    kRestrictedAdminModeSupported = 0x08,
    kRedirectedAuthenticationModeSupported = 0x10,
};

// RDP_NEG_FAILURE failureCode.
enum class NegFailureCode : uint32_t {
    kSslRequiredByServer = 0x01,
    kSslNotAllowedByServer = 0x02,
    kSslCertNotOnServer = 0x03,
    kInconsistentFlags = 0x04,
    kHybridRequiredByServer = 0x05,
    kSslWithUserAuthRequiredByServer = 0x06,
    kEntraAuthRequiredByServer = 0x07,
};

const char* to_string(NegFailureCode code);

struct RdpNegReq {
    static constexpr size_t kSize = 8;
    uint8_t flags = 0;
    uint32_t requested_protocols = kProtocolSsl | kProtocolHybrid | kProtocolHybridEx;

    std::vector<uint8_t> encode() const;
};

struct RdpNegRsp {
    static constexpr size_t kSize = 8;
    uint8_t flags = 0;
    uint32_t selected_protocol = kProtocolRdp;
};

struct RdpNegFailure {
    static constexpr size_t kSize = 8;
    NegFailureCode failure_code = NegFailureCode::kSslRequiredByServer;
};

// Unified result of parsing the optional rdpNegData field.
struct RdpNegData {
    enum class Kind { kNone, kResponse, kFailure };

    Kind kind = Kind::kNone;
    RdpNegRsp response;
    RdpNegFailure failure;

    // Parses the rdpNegData tail of an X.224 CRQ/CCF PDU.
    // Empty input yields Kind::kNone. Any structure other than
    // TYPE_RDP_NEG_RSP / TYPE_RDP_NEG_FAILURE is InvalidType.
    static Status parse(const uint8_t* data, size_t size, RdpNegData& out);
};

}  // namespace rtsc::proto
