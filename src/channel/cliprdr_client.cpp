// Clipboard virtual channel (cliprdr) client handler ([MS-RDPECLIP]).

#include "rtsc/channel/cliprdr_client.h"

#include <algorithm>
#include <cstdlib>
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

// Writes `in` (UTF-8) as a null-terminated UTF-16LE string into `out`, which
// must already be zero-filled. The encoding plus its terminator must fit the
// whole buffer, since the field has a fixed size ([MS-RDPECLIP] 2.2.2.3).
// Returns false, leaving `out` untouched, when the string does not fit.
bool EncodeUtf16Le(const std::string& in, std::vector<uint8_t>& out) {
    std::vector<uint8_t> encoded;
    encoded.reserve(in.size() * 2);
    size_t i = 0;
    while (i < in.size()) {
        const unsigned char lead = static_cast<unsigned char>(in[i]);
        uint32_t cp = 0;
        size_t length = 0;
        if (lead < 0x80) {
            cp = lead;
            length = 1;
        } else if ((lead & 0xE0) == 0xC0) {
            cp = lead & 0x1F;
            length = 2;
        } else if ((lead & 0xF0) == 0xE0) {
            cp = lead & 0x0F;
            length = 3;
        } else if ((lead & 0xF8) == 0xF0) {
            cp = lead & 0x07;
            length = 4;
        } else {
            return false;  // malformed lead byte
        }
        if (i + length > in.size()) return false;
        for (size_t k = 1; k < length; ++k) {
            const unsigned char cont = static_cast<unsigned char>(in[i + k]);
            if ((cont & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cont & 0x3F);
        }
        i += length;
        if (cp <= 0xFFFF) {
            if (cp >= 0xD800 && cp <= 0xDFFF) return false;  // lone surrogate
            encoded.push_back(static_cast<uint8_t>(cp & 0xFF));
            encoded.push_back(static_cast<uint8_t>((cp >> 8) & 0xFF));
        } else if (cp <= 0x10FFFF) {
            const uint32_t v = cp - 0x10000;
            const uint16_t high = static_cast<uint16_t>(0xD800 + (v >> 10));
            const uint16_t low = static_cast<uint16_t>(0xDC00 + (v & 0x3FF));
            encoded.push_back(static_cast<uint8_t>(high & 0xFF));
            encoded.push_back(static_cast<uint8_t>((high >> 8) & 0xFF));
            encoded.push_back(static_cast<uint8_t>(low & 0xFF));
            encoded.push_back(static_cast<uint8_t>((low >> 8) & 0xFF));
        } else {
            return false;
        }
    }
    if (encoded.size() + 2 > out.size()) return false;
    std::copy(encoded.begin(), encoded.end(), out.begin());
    return true;
}

// Reads an environment variable. The MSVC CRT marks getenv as unsafe and the
// project builds with /WX, so the duplicate-and-free helper is used there;
// everywhere else std::getenv is the portable form.
std::string ReadEnvironment(const char* name) {
#if defined(_MSC_VER)
    char* value = nullptr;
    size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) {
        return std::string();
    }
    std::string out(value);
    std::free(value);
    return out;
#else
    const char* value = std::getenv(name);
    return value != nullptr ? std::string(value) : std::string();
#endif
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

void CliprdrClient::SetTemporaryDirectory(std::string path) {
    local_temp_directory_ = std::move(path);
}

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
        case rtsc::proto::CliprdrMsgType::kMonitorReady:
            OnMonitorReady();
            break;
        case rtsc::proto::CliprdrMsgType::kClipCaps:
            OnServerClipCaps(pdu.data);
            break;
        case rtsc::proto::CliprdrMsgType::kFormatList:
            OnFormatList(pdu);
            break;
        case rtsc::proto::CliprdrMsgType::kFormatListResponse:
            OnFormatListResponse(pdu);
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
    // [MS-RDPECLIP] 2.2.2.1.1.1: the long format name variant is used only when
    // both endpoints advertise CB_USE_LONG_FORMAT_NAMES. This client always
    // advertises it, so the server flag decides the negotiated variant.
    long_format_names_ =
        (kClientGeneralFlags & kClipCapsUseLongFormatNames) != 0 &&
        (server_flags_ & kClipCapsUseLongFormatNames) != 0;
    server_caps_received_ = true;
    ++server_caps_count_;
}

void CliprdrClient::OnMonitorReady() {
    ++monitor_ready_received_count_;
    monitor_ready_received_ = true;
    // Without Start() the channel has not been joined yet; the sequence is then
    // sent when Start() runs.
    if (!started_) return;
    RunInitializationSequence();
}

void CliprdrClient::RunInitializationSequence() {
    if (init_sequence_done_) return;
    init_sequence_done_ = true;
    // [MS-RDPECLIP] 1.3.2.1 steps 3-5, in this order: Clipboard Capabilities,
    // Temporary Directory, Format List.
    SendClipCaps();
    SendTemporaryDirectory();
    SendFormatList();
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

void CliprdrClient::OnFormatListResponse(const rtsc::proto::CliprdrPdu& pdu) {
    // [MS-RDPECLIP] 2.2.3.2: the response carries the peer's verdict in
    // msgFlags as CB_RESPONSE_OK (0x0001) or CB_RESPONSE_FAIL (0x0002).
    ++format_list_response_received_count_;
    last_format_list_response_ok_ =
        (pdu.header.msg_flags & rtsc::proto::kClipResponseOk) != 0;
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
    if (!ok || clipboard_ == nullptr) return;
    // The response carries the data for the format that was requested. Applying
    // it fires WM_CLIPBOARDUPDATE, which OnLocalClipboardChanged swallows.
    remote_sync_pending_ = true;
    last_applied_format_ = pending_format_;
    last_applied_data_ = pdu.data;
    clipboard_->write(pending_format_, pdu.data);
    last_applied_formats_ =
        clipboard_ != nullptr ? clipboard_->formats()
                              : std::vector<uint32_t>{};
    has_last_applied_ = true;
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

std::string CliprdrClient::ResolveLocalTempDirectory() const {
    if (!local_temp_directory_.empty()) return local_temp_directory_;
    // The application injects the platform directory with
    // SetTemporaryDirectory(); the fallback reads the environment, which is
    // where every supported platform publishes its temp directory. The handler
    // stays platform neutral, so no <windows.h> is pulled into this file.
    for (const char* name : {"TEMP", "TMP", "TMPDIR"}) {
        std::string value = ReadEnvironment(name);
        if (!value.empty()) return value;
    }
#if !defined(_WIN32)
    return std::string("/tmp");  // always present and absolute on POSIX
#else
    // Nothing absolute to advertise: the PDU is optional ([MS-RDPECLIP]
    // 2.2.2.3) and only useful when the server can reach the directory.
    return std::string();
#endif
}

void CliprdrClient::SendTemporaryDirectory() {
    // [MS-RDPECLIP] 2.2.2.3: a client-to-server PDU announcing where the server
    // may deposit files copied to the client. It is sent after the Monitor
    // Ready PDU, and its wszTempDir field is a fixed 520-byte block holding a
    // null-terminated absolute path padded with null characters.
    const std::string dir = ResolveLocalTempDirectory();
    if (dir.empty()) return;  // optional PDU: nothing useful to announce
    std::vector<uint8_t> body(kTempDirectoryFieldSize, 0);
    if (!EncodeUtf16Le(dir, body)) return;  // does not fit the fixed field
    local_temp_directory_ = dir;
    SendPdu(rtsc::proto::CliprdrMsgType::kTempDirectory, 0, body);
    ++temp_directory_sent_count_;
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
    // [MS-RDPECLIP] 2.2.2.2: the Monitor Ready PDU is a server-to-client PDU,
    // so the client never sends one. The client's own PDUs are the answer to
    // the server's Monitor Ready PDU ([MS-RDPECLIP] 1.3.2.1 steps 3-5).
    if (monitor_ready_received_) RunInitializationSequence();
}

void CliprdrClient::OnLocalClipboardChanged() {
    if (remote_sync_pending_) {
        remote_sync_pending_ = false;
        return;
    }
    // A single SetClipboardData can fire more than one WM_CLIPBOARDUPDATE. If
    // the local clipboard still holds the fingerprint of the write we applied,
    // the event was caused by our own write and must not be echoed to the
    // server. The guard stays armed until a genuinely different clipboard is
    // observed; a failed read keeps it armed rather than risking an echo.
    if (has_last_applied_ && clipboard_ != nullptr) {
        std::vector<uint8_t> current;
        if (!clipboard_->read(last_applied_format_, current)) {
            return;
        }
        const bool same_data = current == last_applied_data_;
        const bool same_formats =
            clipboard_->formats() == last_applied_formats_;
        if (same_data && same_formats) {
            return;
        }
        has_last_applied_ = false;
    }
    // A Format List may only be sent once the capability exchange completed
    // ([MS-RDPECLIP] 1.3.2.1: the server's Monitor Ready PDU starts it).
    if (!init_sequence_done_) return;
    SendFormatList();
}

void CliprdrClient::RequestRemoteFormat(uint32_t format) {
    pending_format_ = format;
    rtsc::proto::ByteWriter w;
    w.u32le(format);
    SendPdu(rtsc::proto::CliprdrMsgType::kFormatDataRequest, 0, w.take());
}

}  // namespace rtsc::channel
