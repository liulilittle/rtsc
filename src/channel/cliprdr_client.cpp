// Clipboard virtual channel (cliprdr) client handler ([MS-RDPECLIP]).

#include "rtsc/channel/cliprdr_client.h"

#include <utility>

namespace rtsc::channel {

namespace {

constexpr uint16_t kCbCapstypeGeneral = 0x0001;
constexpr uint16_t kGeneralCapsLength = 0x000C;
constexpr uint32_t kCbCapsVersion2 = 0x00000002;
constexpr size_t kShortFormatNameSize = 36;   // formatId(4) + formatName(32)
constexpr size_t kShortFormatNameField = 32;

// Converts a UTF-16 code unit sequence to UTF-8. Clipboard format names are
// ASCII in practice; the encode handles the BMP without surrogate pairs.
std::string Utf16ToUtf8(const std::u16string& in) {
    std::string out;
    for (const char16_t c : in) {
        const uint32_t cp = static_cast<uint32_t>(c);
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

uint16_t ReadU16Le(const uint8_t* p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                 (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t ReadU32Le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

}  // namespace

CliprdrClient::CliprdrClient(clipboard::Clipboard* clipboard, SendFn send)
    : clipboard_(clipboard), send_(std::move(send)) {}

CliprdrClient::~CliprdrClient() = default;

void CliprdrClient::OnChannelData(const uint8_t* data, size_t size) {
    if (data == nullptr || size < rtsc::proto::ChannelPduHeader::kSize) return;

    rtsc::proto::ChannelPduHeader header;
    if (rtsc::proto::ChannelPduHeader::parse(data, size, header) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    bool complete = false;
    std::vector<uint8_t> message;
    const rtsc::proto::Status st = reassembler_.Feed(
        header, data + rtsc::proto::ChannelPduHeader::kSize,
        size - rtsc::proto::ChannelPduHeader::kSize, complete, message);
    if (st != rtsc::proto::Status::Ok) {
        reassembler_.Reset();
        return;
    }
    if (!complete) return;
    OnMessage(message);
}

void CliprdrClient::OnMessage(const std::vector<uint8_t>& message) {
    size_t offset = 0;
    while (offset + rtsc::proto::CliprdrHeader::kSize <= message.size()) {
        rtsc::proto::CliprdrPdu pdu;
        if (rtsc::proto::CliprdrPdu::parse(message.data() + offset,
                                           message.size() - offset, pdu) !=
            rtsc::proto::Status::Ok) {
            return;
        }
        OnPdu(pdu);
        offset += rtsc::proto::CliprdrHeader::kSize +
                  static_cast<size_t>(pdu.header.data_len);
    }
}

void CliprdrClient::OnPdu(const rtsc::proto::CliprdrPdu& pdu) {
    switch (pdu.header.msg_type) {
        case rtsc::proto::CliprdrMsgType::kClipCaps:
            OnServerClipCaps(pdu.data);
            break;
        case rtsc::proto::CliprdrMsgType::kFormatList:
            OnFormatList(pdu);
            break;
        case rtsc::proto::CliprdrMsgType::kFormatDataRequest:
            OnFormatDataRequest(pdu.data);
            break;
        case rtsc::proto::CliprdrMsgType::kFormatDataResponse:
            OnFormatDataResponse(pdu);
            break;
        case rtsc::proto::CliprdrMsgType::kTempDirectory:
            OnTempDirectory(pdu.data);
            break;
        case rtsc::proto::CliprdrMsgType::kLockClipData:
            OnLockClipData(pdu.data, true);
            break;
        case rtsc::proto::CliprdrMsgType::kUnlockClipData:
            OnLockClipData(pdu.data, false);
            break;
        default:
            break;
    }
}

void CliprdrClient::OnServerClipCaps(const std::vector<uint8_t>& body) {
    if (body.size() < 4) return;
    rtsc::proto::ByteReader r(body.data(), body.size());
    uint16_t count = 0;
    uint16_t pad = 0;
    if (!r.u16le(count) || !r.u16le(pad)) return;
    for (uint16_t i = 0; i < count; ++i) {
        uint16_t type = 0;
        uint16_t length = 0;
        if (!r.u16le(type) || !r.u16le(length)) return;
        if (length < 4 || r.remaining() < static_cast<size_t>(length) - 4) return;
        if (type == kCbCapstypeGeneral && length >= kGeneralCapsLength) {
            r.skip(4);  // version (informational only)
            uint32_t flags = 0;
            if (!r.u32le(flags)) return;
            server_flags_ = flags;
            r.skip(static_cast<size_t>(length) - kGeneralCapsLength);
        } else {
            r.skip(static_cast<size_t>(length) - 4);
        }
    }
    long_format_names_ =
        (kClientGeneralFlags & kClipCapsUseLongFormatNames) != 0 &&
        (server_flags_ & kClipCapsUseLongFormatNames) != 0;
    ++server_caps_count_;
}

void CliprdrClient::OnFormatList(const rtsc::proto::CliprdrPdu& pdu) {
    remote_formats_.clear();
    const std::vector<uint8_t>& data = pdu.data;
    if (long_format_names_) {
        size_t offset = 0;
        while (offset + 4 <= data.size()) {
            const uint32_t format = ReadU32Le(data.data() + offset);
            offset += 4;
            bool terminated = false;
            while (offset + 2 <= data.size()) {
                const uint16_t ch = ReadU16Le(data.data() + offset);
                offset += 2;
                if (ch == 0) {
                    terminated = true;
                    break;
                }
            }
            if (!terminated) break;  // malformed: no null terminator
            remote_formats_.push_back(format);
        }
    } else {
        size_t offset = 0;
        while (offset + kShortFormatNameSize <= data.size()) {
            remote_formats_.push_back(ReadU32Le(data.data() + offset));
            offset += kShortFormatNameSize;
        }
    }
    ++remote_format_list_count_;
    SendFormatListResponse(true);
    // Eager sync: request the data for the preferred format so a local paste
    // sees the remote clipboard immediately.
    const uint32_t preferred = PickPreferredFormat();
    if (preferred != 0) RequestRemoteFormat(preferred);
}

void CliprdrClient::OnFormatDataRequest(const std::vector<uint8_t>& body) {
    rtsc::proto::CliprdrFormatDataRequest request;
    if (rtsc::proto::CliprdrFormatDataRequest::parse(body, request) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    ++format_data_request_count_;
    std::vector<uint8_t> data;
    const bool ok =
        clipboard_ != nullptr && clipboard_->read(request.format_id, data);
    SendFormatDataResponse(ok ? data : std::vector<uint8_t>{}, ok);
}

void CliprdrClient::OnFormatDataResponse(
    const rtsc::proto::CliprdrPdu& pdu) {
    ++format_data_response_count_;
    const bool ok =
        (pdu.header.msg_flags & rtsc::proto::kClipResponseOk) != 0;
    if (!ok || clipboard_ == nullptr || pdu.data.empty()) return;
    // The response carries the data for the format that was requested. Applying
    // it fires WM_CLIPBOARDUPDATE, which OnLocalClipboardChanged swallows.
    remote_sync_pending_ = true;
    clipboard_->write(pending_format_, pdu.data);
}

void CliprdrClient::OnTempDirectory(const std::vector<uint8_t>& body) {
    std::u16string wide;
    size_t offset = 0;
    while (offset + 2 <= body.size()) {
        const uint16_t ch = ReadU16Le(body.data() + offset);
        offset += 2;
        if (ch == 0) break;
        wide.push_back(static_cast<char16_t>(ch));
    }
    temp_directory_ = Utf16ToUtf8(wide);
    ++temp_directory_count_;
}

void CliprdrClient::OnLockClipData(const std::vector<uint8_t>& body,
                                   bool lock) {
    if (body.size() < 4) return;
    locked_clipdata_id_ = ReadU32Le(body.data());
    if (lock) {
        ++lock_clipdata_count_;
    } else {
        ++unlock_clipdata_count_;
    }
}

void CliprdrClient::SendPdu(rtsc::proto::CliprdrMsgType type, uint16_t flags,
                            const std::vector<uint8_t>& body) {
    if (!send_) return;
    const std::vector<uint8_t> pdu =
        rtsc::proto::BuildCliprdrPdu(type, flags, body);
    const std::vector<std::vector<uint8_t>> chunks = rtsc::proto::
        FragmentChannelMessage(pdu, rtsc::proto::kDefaultChannelChunkSize);
    for (const auto& chunk : chunks) send_(chunk);
}

void CliprdrClient::SendClipCaps() {
    rtsc::proto::ByteWriter w;
    w.u16le(1);   // cCapabilitiesSets
    w.u16le(0);   // pad1
    w.u16le(kCbCapstypeGeneral);
    w.u16le(kGeneralCapsLength);
    w.u32le(kCbCapsVersion2);
    w.u32le(kClientGeneralFlags);
    SendPdu(rtsc::proto::CliprdrMsgType::kClipCaps, 0, w.take());
    caps_sent_ = true;
    ++clip_caps_count_;
}

void CliprdrClient::SendFormatList() {
    const std::vector<uint32_t> formats =
        clipboard_ != nullptr ? clipboard_->formats()
                              : std::vector<uint32_t>{};
    rtsc::proto::ByteWriter w;
    for (const uint32_t format : formats) {
        w.u32le(format);
        if (long_format_names_) {
            // A nameless format is a single null UTF-16 code unit.
            w.u16le(0);
        } else {
            for (size_t i = 0; i < kShortFormatNameField; ++i) w.u8(0);
        }
    }
    SendPdu(rtsc::proto::CliprdrMsgType::kFormatList, 0, w.take());
    ++local_format_list_count_;
}

void CliprdrClient::SendFormatListResponse(bool ok) {
    SendPdu(rtsc::proto::CliprdrMsgType::kFormatListResponse,
            ok ? rtsc::proto::kClipResponseOk : rtsc::proto::kClipResponseFail,
            {});
    ++format_list_response_count_;
}

void CliprdrClient::SendFormatDataResponse(const std::vector<uint8_t>& data,
                                           bool ok) {
    SendPdu(rtsc::proto::CliprdrMsgType::kFormatDataResponse,
            ok ? rtsc::proto::kClipResponseOk : rtsc::proto::kClipResponseFail,
            data);
    ++format_data_response_sent_count_;
}

uint32_t CliprdrClient::PickPreferredFormat() const {
    for (const uint32_t f : remote_formats_) {
        if (f == rtsc::clipboard::kCfUnicodetext) return f;
    }
    for (const uint32_t f : remote_formats_) {
        if (f == rtsc::clipboard::kCfDib) return f;
    }
    for (const uint32_t f : remote_formats_) {
        if (f == rtsc::clipboard::kCfDibV5) return f;
    }
    for (const uint32_t f : remote_formats_) {
        if (f == rtsc::clipboard::kCfText) return f;
    }
    if (!remote_formats_.empty()) return remote_formats_.front();
    return 0;
}

void CliprdrClient::Start() {
    if (started_) return;
    started_ = true;
    SendPdu(rtsc::proto::CliprdrMsgType::kMonitorReady, 0, {});
    ++monitor_ready_count_;
    SendClipCaps();
    SendFormatList();
}

void CliprdrClient::OnLocalClipboardChanged() {
    if (remote_sync_pending_) {
        remote_sync_pending_ = false;
        return;
    }
    if (!started_) return;
    SendFormatList();
}

void CliprdrClient::RequestRemoteFormat(uint32_t format) {
    pending_format_ = format;
    rtsc::proto::ByteWriter w;
    w.u32le(format);
    SendPdu(rtsc::proto::CliprdrMsgType::kFormatDataRequest, 0, w.take());
}

}  // namespace rtsc::channel
