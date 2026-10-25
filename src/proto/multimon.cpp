// Multi-monitor support: TS_MONITOR_DEF, Client Monitor Data and the Monitor
// Layout PDU. See multimon.h and [MS-RDPBCGR] 2.2.1.3.6 / 2.2.12.1.

#include "rtsc/proto/multimon.h"

#include "rtsc/proto/finalization.h"

namespace rtsc::proto {

void MonitorDef::write(ByteWriter& w) const {
    w.u32le(static_cast<uint32_t>(left));
    w.u32le(static_cast<uint32_t>(top));
    w.u32le(static_cast<uint32_t>(right));
    w.u32le(static_cast<uint32_t>(bottom));
    w.u32le(flags);
}

bool MonitorDef::read(ByteReader& r) {
    uint32_t l = 0, t = 0, rr = 0, b = 0;
    if (!r.u32le(l) || !r.u32le(t) || !r.u32le(rr) || !r.u32le(b)) return false;
    if (!r.u32le(flags)) return false;
    left = static_cast<int32_t>(l);
    top = static_cast<int32_t>(t);
    right = static_cast<int32_t>(rr);
    bottom = static_cast<int32_t>(b);
    return true;
}

std::vector<uint8_t> ClientMonitorData::encode() const {
    ByteWriter body;
    body.u32le(flags);
    body.u32le(static_cast<uint32_t>(monitors.size()));
    for (const auto& m : monitors) m.write(body);
    ByteWriter out;
    GccUserData::write_block(out, kBlock, body.data());
    return out.take();
}

Status ClientMonitorData::parse(const uint8_t* data, size_t size,
                                ClientMonitorData& out) {
    out = ClientMonitorData{};
    if (data == nullptr || size < GccUserDataHeader::kSize) {
        return Status::NeedMoreData;
    }
    ByteReader hr(data, size);
    uint16_t type = 0, len = 0;
    if (!hr.u16le(type) || !hr.u16le(len)) return Status::NeedMoreData;
    if (type != kBlock) return Status::InvalidType;
    if (len < GccUserDataHeader::kSize || static_cast<size_t>(len) > size) {
        return Status::InvalidLength;
    }
    const uint8_t* p = data + GccUserDataHeader::kSize;
    const size_t payload = static_cast<size_t>(len) - GccUserDataHeader::kSize;
    ByteReader r(p, payload);
    if (!r.u32le(out.flags)) return Status::InvalidLength;
    uint32_t count = 0;
    if (!r.u32le(count)) return Status::InvalidLength;
    if (count > MonitorDef::kMaxMonitors) return Status::InvalidLength;
    out.monitors.clear();
    out.monitors.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        MonitorDef m;
        if (!m.read(r)) return Status::InvalidLength;
        out.monitors.push_back(m);
    }
    return Status::Ok;
}

std::vector<uint8_t> MonitorLayoutPdu::encode_body() const {
    ByteWriter w;
    w.u32le(static_cast<uint32_t>(monitors.size()));
    for (const auto& m : monitors) m.write(w);
    return w.take();
}

Status MonitorLayoutPdu::parse_body(const uint8_t* data, size_t size,
                                    MonitorLayoutPdu& out) {
    out = MonitorLayoutPdu{};
    ByteReader r(data, size);
    uint32_t count = 0;
    if (!r.u32le(count)) return Status::NeedMoreData;
    if (count > MonitorDef::kMaxMonitors) return Status::InvalidLength;
    out.monitor_count = count;
    out.monitors.clear();
    out.monitors.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        MonitorDef m;
        if (!m.read(r)) return Status::InvalidLength;
        out.monitors.push_back(m);
    }
    // A trailing byte is a malformed layout: monitorCount must describe the
    // whole body, so the array cannot be silently truncated.
    if (r.remaining() != 0) return Status::InvalidLength;
    return Status::Ok;
}

std::vector<uint8_t> MonitorLayoutPdu::encode(uint16_t pdu_source,
                                             uint32_t share_id,
                                             uint8_t stream_id) const {
    return BuildSlowPathDataPdu(pdu_source, share_id, stream_id, kPduType2,
                                encode_body());
}

Status MonitorLayoutPdu::parse(const uint8_t* data, size_t size,
                               MonitorLayoutPdu& out) {
    out = MonitorLayoutPdu{};
    ShareDataHeader hdr;
    const Status s = ShareDataHeader::parse(data, size, hdr);
    if (s != Status::Ok) return s;
    if (hdr.pdu_type2 != kPduType2) return Status::InvalidType;
    if (size < ShareDataHeader::kSize) return Status::NeedMoreData;
    return parse_body(data + ShareDataHeader::kSize,
                      size - ShareDataHeader::kSize, out);
}

}  // namespace rtsc::proto
