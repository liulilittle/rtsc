// Clipboard virtual channel (cliprdr) structure layer ([MS-RDPECLIP] 2.2).

#include "rtsc/proto/cliprdr.h"

#include <limits>
#include <utility>

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

Status CliprdrFileContentsRequest::parse(
    const std::vector<uint8_t>& body, CliprdrFileContentsRequest& out) {
    // [MS-RDPECLIP] 2.2.5.3: the fixed header is 24 bytes followed by an
    // optional clipDataId(4): a request is 24 or 28 bytes, no presence field.
    if (body.size() != 24 && body.size() != 28) {
        return Status::InvalidLength;
    }
    ByteReader r(body.data(), body.size());
    if (!r.u32le(out.stream_id)) return Status::NeedMoreData;
    uint32_t lindex = 0;
    if (!r.u32le(lindex)) return Status::NeedMoreData;
    out.lindex = static_cast<int32_t>(lindex);
    if (!r.u32le(out.dw_flags)) return Status::NeedMoreData;
    if (!r.u32le(out.n_position_low)) return Status::NeedMoreData;
    if (!r.u32le(out.n_position_high)) return Status::NeedMoreData;
    if (!r.u32le(out.cb_requested)) return Status::NeedMoreData;
    out.has_clip_data_id = false;
    out.clip_data_id = 0;
    if (body.size() == 28) {
        if (!r.u32le(out.clip_data_id)) return Status::NeedMoreData;
        out.has_clip_data_id = true;
    }
    return Status::Ok;
}

std::vector<uint8_t> CliprdrFileContentsRequest::encode() const {
    ByteWriter w;
    w.u32le(stream_id);
    w.u32le(static_cast<uint32_t>(lindex));
    w.u32le(dw_flags);
    w.u32le(n_position_low);
    w.u32le(n_position_high);
    w.u32le(cb_requested);
    if (has_clip_data_id) w.u32le(clip_data_id);
    return w.take();
}

Status CliprdrFileContentsResponse::parse(
    const std::vector<uint8_t>& body, bool ok, CliprdrFileContentsResponse& out) {
    out.data.clear();
    if (body.size() < 4) return Status::InvalidLength;
    ByteReader r(body.data(), body.size());
    if (!r.u32le(out.stream_id)) return Status::NeedMoreData;
    if (ok && !r.empty()) {
        out.data.assign(r.cursor(), r.cursor() + r.remaining());
    }
    return Status::Ok;
}

std::vector<uint8_t> CliprdrFileContentsResponse::encode(bool ok) const {
    ByteWriter w;
    w.u32le(stream_id);
    if (ok && !data.empty()) w.bytes(data.data(), data.size());
    return w.take();
}

Status CliprdrFileDescriptor::parse(ByteReader& reader,
                                    CliprdrFileDescriptor& out) {
    if (!reader.u32le(out.dw_flags)) return Status::NeedMoreData;
    if (!reader.skip(32)) return Status::NeedMoreData;
    if (!reader.u32le(out.file_attributes)) return Status::NeedMoreData;
    if (!reader.skip(16)) return Status::NeedMoreData;
    uint32_t ft_lo = 0;
    uint32_t ft_hi = 0;
    if (!reader.u32le(ft_lo) || !reader.u32le(ft_hi)) return Status::NeedMoreData;
    out.last_write_time =
        (static_cast<uint64_t>(ft_hi) << 32) | static_cast<uint64_t>(ft_lo);
    uint32_t size_hi = 0;
    uint32_t size_lo = 0;
    if (!reader.u32le(size_hi) || !reader.u32le(size_lo)) return Status::NeedMoreData;
    // The size fields are only meaningful when FD_FILESIZE is set
    // ([MS-RDPECLIP] 2.2.5.2.3.1); otherwise they must not be misread.
    out.file_size = (out.dw_flags & kFileDescriptorSize) != 0
                        ? (static_cast<uint64_t>(size_hi) << 32) |
                              static_cast<uint64_t>(size_lo)
                        : 0;
    // cFileName: up to 260 UTF-16 code units including the null terminator;
    // the rest of the 520-byte block is zero padding.
    out.file_name.clear();
    for (size_t i = 0; i < 260; ++i) {
        uint16_t ch = 0;
        if (!reader.u16le(ch)) return Status::NeedMoreData;
        if (ch == 0) {
            if (!reader.skip(520 - (i + 1) * 2)) return Status::NeedMoreData;
            return Status::Ok;
        }
        out.file_name.push_back(static_cast<char16_t>(ch));
    }
    return Status::InvalidField;  // no null within the name block
}

bool CliprdrFileDescriptor::write(ByteWriter& w) const {
    // The name plus its null terminator must fit the 520-byte block (<=260
    // units incl. the null).
    if (file_name.size() > 259) return false;
    if (file_name.find(u'\0') != std::u16string::npos) return false;
    w.u32le(dw_flags);
    for (size_t i = 0; i < 32; ++i) w.u8(0);
    w.u32le(file_attributes);
    for (size_t i = 0; i < 16; ++i) w.u8(0);
    w.u32le(static_cast<uint32_t>(last_write_time & 0xFFFFFFFFu));
    w.u32le(static_cast<uint32_t>(last_write_time >> 32));
    w.u32le(static_cast<uint32_t>(file_size >> 32));
    w.u32le(static_cast<uint32_t>(file_size & 0xFFFFFFFFu));
    for (const char16_t c : file_name) {
        w.u16le(static_cast<uint16_t>(c));
    }
    w.u16le(0);
    const size_t pad = 260 - (file_name.size() + 1);
    for (size_t i = 0; i < pad; ++i) w.u16le(0);
    return true;
}

Status CliprdrFileList::parse(const std::vector<uint8_t>& data,
                              CliprdrFileList& out) {
    out.files.clear();
    if (data.size() < 4) return Status::InvalidLength;
    ByteReader r(data.data(), data.size());
    uint32_t count = 0;
    if (!r.u32le(count)) return Status::NeedMoreData;
    // cItems x kSize overflow guard: the product is computed in 64 bits and
    // must fit the remaining payload.
    if (static_cast<uint64_t>(count) * CliprdrFileDescriptor::kSize !=
        r.remaining()) {
        return Status::InvalidLength;
    }
    out.files.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        CliprdrFileDescriptor descriptor;
        if (CliprdrFileDescriptor::parse(r, descriptor) != Status::Ok) {
            return Status::InvalidLength;
        }
        out.files.push_back(std::move(descriptor));
    }
    return Status::Ok;
}

std::vector<uint8_t> CliprdrFileList::encode() const {
    if (files.size() > 0xFFFFFFFFu) return {};
    if (files.size() >
        (std::numeric_limits<size_t>::max() - 4) / CliprdrFileDescriptor::kSize) {
        return {};
    }
    ByteWriter w;
    w.u32le(static_cast<uint32_t>(files.size()));
    for (const CliprdrFileDescriptor& descriptor : files) {
        if (!descriptor.write(w)) return {};
    }
    return w.take();
}

}  // namespace rtsc::proto
