// Clipboard virtual channel (cliprdr) structure layer ([MS-RDPECLIP] 2.2).

#include "rtsc/proto/cliprdr.h"

namespace rtsc::proto {

const char* to_string(CliprdrMsgType type) {
    switch (type) {
        case CliprdrMsgType::kMonitorReady: return "monitor-ready";
        case CliprdrMsgType::kFormatList: return "format-list";
        case CliprdrMsgType::kFormatListResponse: return "format-list-response";
        case CliprdrMsgType::kFormatDataRequest: return "format-data-request";
        case CliprdrMsgType::kFormatDataResponse: return "format-data-response";
        case CliprdrMsgType::kTempDirectory: return "temp-directory";
        case CliprdrMsgType::kClipCaps: return "clip-caps";
        case CliprdrMsgType::kFileContentsRequest: return "file-contents-request";
        case CliprdrMsgType::kFileContentsResponse: return "file-contents-response";
        case CliprdrMsgType::kLockClipData: return "lock-clip-data";
        case CliprdrMsgType::kUnlockClipData: return "unlock-clip-data";
    }
    return "unknown";
}

Status CliprdrHeader::parse(const uint8_t* data, size_t size,
                            CliprdrHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ByteReader r(data, size);
    uint16_t mt = 0;
    r.u16le(mt);
    out.msg_type = static_cast<CliprdrMsgType>(mt);
    r.u16le(out.msg_flags);
    r.u32le(out.data_len);
    return Status::Ok;
}

void CliprdrHeader::write(ByteWriter& w) const {
    w.u16le(static_cast<uint16_t>(msg_type));
    w.u16le(msg_flags);
    w.u32le(data_len);
}

Status CliprdrPdu::parse(const uint8_t* data, size_t size, CliprdrPdu& out) {
    out.data.clear();
    Status s = CliprdrHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    if (size < CliprdrHeader::kSize + out.header.data_len) {
        return Status::NeedMoreData;
    }
    out.data.assign(data + CliprdrHeader::kSize,
                    data + CliprdrHeader::kSize + out.header.data_len);
    return Status::Ok;
}

std::vector<uint8_t> BuildCliprdrPdu(CliprdrMsgType type, uint16_t flags,
                                     const std::vector<uint8_t>& data) {
    CliprdrHeader h;
    h.msg_type = type;
    h.msg_flags = flags;
    h.data_len = static_cast<uint32_t>(data.size());

    ByteWriter w;
    h.write(w);
    if (!data.empty()) w.bytes(data.data(), data.size());
    return w.take();
}

Status CliprdrFormatList::parse(const std::vector<uint8_t>& data,
                                CliprdrFormatList& out) {
    out.formats.clear();
    if (data.size() % 4 != 0) return Status::InvalidLength;
    ByteReader r(data.data(), data.size());
    while (!r.empty()) {
        uint32_t f = 0;
        if (!r.u32le(f)) return Status::NeedMoreData;
        out.formats.push_back(f);
    }
    return Status::Ok;
}

std::vector<uint8_t> CliprdrFormatList::encode() const {
    ByteWriter w;
    for (uint32_t f : formats) w.u32le(f);
    return w.take();
}

Status CliprdrFormatDataRequest::parse(const std::vector<uint8_t>& data,
                                       CliprdrFormatDataRequest& out) {
    if (data.size() < 4) return Status::NeedMoreData;
    ByteReader r(data.data(), data.size());
    r.u32le(out.format_id);
    return Status::Ok;
}

std::vector<uint8_t> CliprdrFormatDataRequest::encode() const {
    ByteWriter w;
    w.u32le(format_id);
    return w.take();
}

}  // namespace rtsc::proto
