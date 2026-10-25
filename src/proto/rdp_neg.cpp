#include "rtsc/proto/rdp_neg.h"

namespace rtsc::proto {

const char* to_string(NegFailureCode code) {
    switch (code) {
        case NegFailureCode::kSslRequiredByServer: return "SSL_REQUIRED_BY_SERVER";
        case NegFailureCode::kSslNotAllowedByServer: return "SSL_NOT_ALLOWED_BY_SERVER";
        case NegFailureCode::kSslCertNotOnServer: return "SSL_CERT_NOT_ON_SERVER";
        case NegFailureCode::kInconsistentFlags: return "INCONSISTENT_FLAGS";
        case NegFailureCode::kHybridRequiredByServer: return "HYBRID_REQUIRED_BY_SERVER";
        case NegFailureCode::kSslWithUserAuthRequiredByServer:
            return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER";
        case NegFailureCode::kEntraAuthRequiredByServer: return "ENTRA_AUTH_REQUIRED_BY_SERVER";
    }
    return "UNKNOWN";
}

std::vector<uint8_t> RdpNegReq::encode() const {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(NegType::kRequest));
    w.u8(flags);
    w.u16le(static_cast<uint16_t>(kSize));
    w.u32le(requested_protocols);
    return w.take();
}

Status RdpNegData::parse(const uint8_t* data, size_t size, RdpNegData& out) {
    out = RdpNegData{};
    if (size == 0) return Status::Ok;
    if (size < 4) return Status::InvalidLength;

    const uint8_t type = data[0];
    ByteReader r(data, size);
    uint8_t raw_type = 0;
    uint8_t flags = 0;
    uint16_t length = 0;
    r.u8(raw_type);
    r.u8(flags);
    r.u16le(length);

    if (length != 8) return Status::InvalidLength;
    if (size < length) return Status::InvalidLength;

    uint32_t value = 0;
    if (!r.u32le(value)) return Status::InvalidLength;

    switch (static_cast<NegType>(type)) {
        case NegType::kResponse:
            out.kind = Kind::kResponse;
            out.response.flags = flags;
            out.response.selected_protocol = value;
            return Status::Ok;
        case NegType::kFailure:
            out.kind = Kind::kFailure;
            out.failure.failure_code = static_cast<NegFailureCode>(value);
            return Status::Ok;
        case NegType::kRequest:
        default:
            return Status::InvalidType;
    }
}

}  // namespace rtsc::proto
