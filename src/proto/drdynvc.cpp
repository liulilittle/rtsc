// Dynamic virtual channel (drdynvc) structure layer ([MS-RDPEDYC] 2.2).

#include "rtsc/proto/drdynvc.h"

namespace rtsc::proto {

const char* to_string(DynvcCmd cmd) {
    switch (cmd) {
        case DynvcCmd::kCreate: return "create";
        case DynvcCmd::kDataFirst: return "data-first";
        case DynvcCmd::kData: return "data";
        case DynvcCmd::kClose: return "close";
        case DynvcCmd::kCapability: return "capability";
        case DynvcCmd::kDataFirstCompressed: return "data-first-compressed";
        case DynvcCmd::kDataCompressed: return "data-compressed";
        case DynvcCmd::kSoftSyncRequest: return "soft-sync-request";
        case DynvcCmd::kSoftSyncResponse: return "soft-sync-response";
    }
    return "unknown";
}

Status DynvcHeader::parse(const uint8_t* data, size_t size, DynvcHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    const uint8_t h = data[0];
    out.cb_id = static_cast<uint8_t>(h & 0x03);
    out.sp = static_cast<uint8_t>((h >> 2) & 0x03);
    out.cmd = static_cast<DynvcCmd>((h >> 4) & 0x0F);
    return Status::Ok;
}

void DynvcHeader::write(ByteWriter& w) const {
    w.u8(static_cast<uint8_t>((static_cast<uint8_t>(cmd) << 4) |
                              ((sp & 0x03) << 2) | (cb_id & 0x03)));
}

Status ParseDynvcChannelId(const DynvcHeader& header, const uint8_t* data,
                           size_t size, uint32_t& out) {
    if (!header.valid()) return Status::InvalidField;
    const size_t n = header.channel_id_size();
    if (data == nullptr || size < n) return Status::NeedMoreData;
    uint32_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        v |= static_cast<uint32_t>(data[i]) << (8 * i);
    }
    out = v;
    return Status::Ok;
}

Status DynvcPdu::parse(const uint8_t* data, size_t size, DynvcPdu& out) {
    out.data.clear();
    Status s = DynvcHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    if (!out.header.valid()) return Status::InvalidField;

    s = ParseDynvcChannelId(out.header, data + DynvcHeader::kSize,
                            size - DynvcHeader::kSize, out.channel_id);
    if (s != Status::Ok) return s;

    const size_t off = DynvcHeader::kSize + out.header.channel_id_size();
    out.data.assign(data + off, data + size);
    return Status::Ok;
}

std::vector<uint8_t> BuildDynvcPdu(DynvcCmd cmd, uint8_t sp, uint32_t channel_id,
                                   const std::vector<uint8_t>& data) {
    DynvcHeader h;
    h.cmd = cmd;
    h.sp = sp;
    h.cb_id = (channel_id <= 0xFF) ? 0 : (channel_id <= 0xFFFF ? 1 : 2);

    ByteWriter w;
    h.write(w);
    const size_t n = h.channel_id_size();
    for (size_t i = 0; i < n; ++i) {
        w.u8(static_cast<uint8_t>((channel_id >> (8 * i)) & 0xFF));
    }
    if (!data.empty()) w.bytes(data.data(), data.size());
    return w.take();
}

}  // namespace rtsc::proto
