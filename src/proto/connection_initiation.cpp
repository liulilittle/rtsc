#include "rtsc/proto/connection_initiation.h"

namespace rtsc::proto {

std::vector<uint8_t> CorrelationInfo::encode() const {
    ByteWriter w;
    w.u8(static_cast<uint8_t>(version));
    w.u32le(id >> 32);
    w.u32le(static_cast<uint32_t>(id & 0xFFFFFFFFu));
    // Pad to the fixed 36-byte size mandated by [MS-RDPBCGR] 2.2.1.1.2.
    while (w.size() < kSize) w.u8(0);
    return w.take();
}

std::vector<uint8_t> X224ConnectionRequest::encode() const {
    ByteWriter body;
    if (!routing_token.empty()) {
        body.bytes(reinterpret_cast<const uint8_t*>(routing_token.data()),
                   routing_token.size());
        body.u8(0x0D);
        body.u8(0x0A);
    } else if (!cookie.empty()) {
        body.bytes(reinterpret_cast<const uint8_t*>(cookie.data()), cookie.size());
        body.u8(0x0D);
        body.u8(0x0A);
    }
    if (include_neg_req) {
        const auto neg = neg_req.encode();
        body.bytes(neg.data(), neg.size());
    }
    if (include_correlation_info) {
        const auto corr = correlation_info.encode();
        body.bytes(corr.data(), corr.size());
    }

    X224Tpdu tpdu = X224Tpdu::make_connection_request();
    tpdu.length_indicator = static_cast<uint8_t>(6 + body.size());
    const auto tpdu_bytes = tpdu.encode();

    const size_t total = TpktHeader::kSize + tpdu_bytes.size() + body.size();
    TpktHeader tpkt;
    tpkt.length = static_cast<uint16_t>(total);

    ByteWriter w;
    const auto tpkt_bytes = tpkt.encode();
    w.bytes(tpkt_bytes.data(), tpkt_bytes.size());
    w.bytes(tpdu_bytes.data(), tpdu_bytes.size());
    const auto body_bytes = body.data();
    w.bytes(body_bytes.data(), body_bytes.size());
    return w.take();
}

Status X224ConnectionConfirm::parse(const uint8_t* data, size_t size,
                                    X224ConnectionConfirm& out) {
    TpktHeader tpkt;
    Status s = TpktHeader::parse(data, size, tpkt);
    if (s != Status::Ok) return s;
    s = tpkt.validate(size);
    if (s != Status::Ok) return s;

    const size_t payload = tpkt.length - TpktHeader::kSize;
    if (payload < X224Tpdu::kSize) return Status::InvalidLength;

    s = X224Tpdu::parse(data + TpktHeader::kSize, payload, out.x224);
    if (s != Status::Ok) return s;
    if (out.x224.code != X224Tpdu::kConnectionConfirm) return Status::InvalidType;

    const size_t neg_size = payload - X224Tpdu::kSize;
    return RdpNegData::parse(data + TpktHeader::kSize + X224Tpdu::kSize, neg_size,
                             out.neg_data);
}

Status read_framed_pdu(const uint8_t* data, size_t size, FramedPdu& out,
                       size_t& consumed) {
    TpktHeader tpkt;
    Status s = TpktHeader::parse(data, size, tpkt);
    if (s != Status::Ok) return s;
    s = tpkt.validate(size);
    if (s != Status::Ok) return s;

    out.payload.assign(data + TpktHeader::kSize, data + tpkt.length);
    consumed = tpkt.length;
    return Status::Ok;
}

}  // namespace rtsc::proto
