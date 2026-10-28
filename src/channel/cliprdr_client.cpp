// Clipboard virtual channel (cliprdr) client handler ([MS-RDPECLIP]).

#include "rtsc/channel/cliprdr_client.h"

#include <algorithm>
#include <chrono>
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
        case rtsc::proto::CliprdrMsgType::kFileContentsRequest:
            OnFileContentsRequest(pdu);
            break;
        case rtsc::proto::CliprdrMsgType::kFileContentsResponse:
            OnFileContentsResponse(pdu);
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
        (client_general_flags_ & kClipCapsUseLongFormatNames) != 0 &&
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
    // The previous format list may not carry the file format any more; the
    // descriptors held from a stale list are dropped with it (fix ② records
    // the long name and leaves no dangling format id).
    const uint32_t previous_format_id = remote_file_list_format_id_;
    remote_file_list_format_id_ = 0;
    const std::vector<uint8_t>& data = pdu.data;
    if (long_format_names_) {
        size_t offset = 0;
        while (offset + 4 <= data.size()) {
            const uint32_t format = ReadU32Le(data.data() + offset);
            offset += 4;
            std::u16string name;
            bool terminated = false;
            while (offset + 2 <= data.size()) {
                const uint16_t ch = ReadU16Le(data.data() + offset);
                offset += 2;
                if (ch == 0) {
                    terminated = true;
                    break;
                }
                name.push_back(static_cast<char16_t>(ch));
            }
            if (!terminated) break;  // malformed: no null terminator
            remote_formats_.push_back(format);
            // [MS-RDPECLIP] 1.3.2.1: the file list is exchanged through a
            // registered format whose name identifies it.
            if (name == rtsc::proto::kFileGroupDescriptorName) {
                remote_file_list_format_id_ = format;
            } else if (remote_file_list_format_id_ == 0 &&
                       format == rtsc::proto::kDeFactoFileListFormatId) {
                remote_file_list_format_id_ = format;
            }
        }
    } else {
        size_t offset = 0;
        while (offset + kShortFormatNameSize <= data.size()) {
            const uint32_t format = ReadU32Le(data.data() + offset);
            // Short format names carry no names; the de facto fallback id is
            // the only recognisable marker.
            if (format == rtsc::proto::kDeFactoFileListFormatId) {
                remote_file_list_format_id_ = format;
            }
            remote_formats_.push_back(format);
            offset += kShortFormatNameSize;
        }
    }
    if (remote_file_list_format_id_ == 0) {
        // D4: the in-flight file-list request is now moot -- its reply must
        // not be written to the clipboard when it finally arrives.
        if (pending_format_ != 0 && pending_format_ == previous_format_id) {
            pending_format_ = 0;
        }
        remote_file_list_.clear();
        have_remote_file_list_ = false;
    }
    ++remote_format_list_count_;
    SendFormatListResponse(true);
    // Eager sync: request the data for the preferred format so a local paste
    // sees the remote clipboard immediately. File formats are skipped.
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
    // Direction-B serve: when the peer asks for the file-list format we
    // advertise, answer with a CLIPRDR_FILELIST built from the provider
    // instead of the (failing) local clipboard read. A build failure answers
    // FAIL -- an empty file list is still a valid 4-byte cItems=0 payload,
    // so the two cases stay distinct.
    if (request.format_id == rtsc::proto::kDeFactoFileListFormatId &&
        provider_ != nullptr) {
        rtsc::proto::CliprdrFileList list;
        const uint32_t count = provider_->file_count();
        list.files.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            rtsc::clipboard::FileInfo info;
            if (!provider_->file_info(i, info)) {
                SendFormatDataResponse({}, false);
                return;
            }
            rtsc::proto::CliprdrFileDescriptor descriptor;
            descriptor.dw_flags = rtsc::proto::kFileDescriptorSize |
                                  rtsc::proto::kFileDescriptorAttributes;
            descriptor.file_attributes = info.attributes;
            if (info.is_directory) {
                descriptor.file_attributes |= rtsc::proto::kFileAttributeDirectory;
            }
            descriptor.file_size = info.size;
            descriptor.file_name = std::move(info.name);
            list.files.push_back(std::move(descriptor));
        }
        // A failed encode (e.g. an over-long file name) is distinct from a
        // legal empty list (4-byte cItems=0) and must answer FAIL.
        const std::vector<uint8_t> payload = list.encode();
        if (payload.empty()) {
            SendFormatDataResponse({}, false);
            return;
        }
        SendFormatDataResponse(payload, true);
        return;
    }
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
    if (!ok || clipboard_ == nullptr) {
        pending_format_ = 0;
        return;
    }
    // D4: a response with no outstanding request must not be written to the
    // clipboard (it is either a stray duplicate or a stale file-list reply
    // whose format id was invalidated by a newer format list).
    if (pending_format_ == 0) return;
    // Fix ①: a response for the file-list format is a FILELIST, never a
    // clipboard write. It is parsed and buffered; RequestRemoteFile() then
    // serves it through the file-contents path.
    if (pending_format_ == remote_file_list_format_id_) {
        rtsc::proto::CliprdrFileList list;
        if (rtsc::proto::CliprdrFileList::parse(pdu.data, list) ==
            rtsc::proto::Status::Ok) {
            remote_file_list_ = std::move(list.files);
            have_remote_file_list_ = true;
            ++remote_file_list_received_;
        }
        pending_format_ = 0;
        return;
    }
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
    pending_format_ = 0;
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
    w.u32le(client_general_flags_);
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
    // Fix ④: without a provider the file-list format must not be advertised;
    // the provider itself is the only source the peer can read from, and the
    // format id is never emitted when it merely sits in the local clipboard.
    for (const uint32_t format : formats) {
        if (format == rtsc::proto::kDeFactoFileListFormatId) continue;
        w.u32le(format);
        if (long_format_names_) {
            // A nameless format is a single null UTF-16 code unit.
            w.u16le(0);
        } else {
            for (size_t i = 0; i < kShortFormatNameField; ++i) w.u8(0);
        }
    }
    if (provider_ != nullptr) {
        w.u32le(rtsc::proto::kDeFactoFileListFormatId);
        if (long_format_names_) {
            for (const char16_t c : rtsc::proto::kFileGroupDescriptorName) {
                w.u16le(static_cast<uint16_t>(c));
            }
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
    // Fix ③: the file-list format is never eager-synced as text data; a
    // clipboard holding only files triggers no automatic format request.
    const auto is_file_format = [&](uint32_t f) {
        return f == remote_file_list_format_id_ ||
               f == rtsc::proto::kDeFactoFileListFormatId;
    };
    for (const uint32_t f : remote_formats_) {
        if (f == rtsc::clipboard::kCfUnicodetext && !is_file_format(f)) return f;
    }
    for (const uint32_t f : remote_formats_) {
        if (f == rtsc::clipboard::kCfDib && !is_file_format(f)) return f;
    }
    for (const uint32_t f : remote_formats_) {
        if (f == rtsc::clipboard::kCfDibV5 && !is_file_format(f)) return f;
    }
    for (const uint32_t f : remote_formats_) {
        if (f == rtsc::clipboard::kCfText && !is_file_format(f)) return f;
    }
    for (const uint32_t f : remote_formats_) {
        if (!is_file_format(f)) return f;
    }
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

void CliprdrClient::EnableFileClip() {
    file_clip_enabled_ = true;
    client_general_flags_ |= kClipCapsStreamFileClip;
}

void CliprdrClient::EnableHugeFileSupport() {
    huge_enabled_ = true;
    client_general_flags_ |= kClipCapsHugeFileSupport;
}

void CliprdrClient::SetFileListProvider(
    rtsc::clipboard::FileListProvider* provider) {
    provider_ = provider;
}

void CliprdrClient::SetTransferTimeoutMs(uint32_t ms) {
    transfer_timeout_ms_ = ms;
}

void CliprdrClient::SetFileTransferWindow(uint32_t bytes) {
    transfer_window_ = bytes != 0 ? bytes : kDefaultFileTransferWindow;
}

void CliprdrClient::RequestRemoteFileList() {
    // [MS-RDPECLIP] 1.3.2.1 / 3.1.5.4.1: the FILELIST rides a Format Data
    // Request for the peer's file-list format. Only send it when the peer
    // negotiated stream file clip, the format is known and the single
    // format-data slot is free (serialisation).
    if ((server_flags_ & kClipCapsStreamFileClip) == 0) return;
    if (remote_file_list_format_id_ == 0) return;
    if (pending_format_ != 0) return;
    pending_format_ = remote_file_list_format_id_;
    rtsc::proto::ByteWriter w;
    w.u32le(remote_file_list_format_id_);
    SendPdu(rtsc::proto::CliprdrMsgType::kFormatDataRequest, 0, w.take());
}

bool CliprdrClient::RequestRemoteFile(uint32_t lindex,
                                      FileContentsDone done) {
    if ((server_flags_ & kClipCapsStreamFileClip) == 0) return false;
    if (pending_.size() >= kMaxInflightFileOps) return false;
    if (lindex >= remote_file_list_.size()) return false;
    if (remote_file_list_[lindex].is_directory()) return false;
    const uint32_t stream_id = AllocateStreamId();
    PendingFileContents entry;
    entry.lindex = lindex;
    entry.done = std::move(done);
    if (transfer_timeout_ms_ != 0) {
        entry.deadline = std::chrono::steady_clock::now() +
                         std::chrono::milliseconds(transfer_timeout_ms_);
    }
    pending_[stream_id] = std::move(entry);
    // Start with a SIZE probe ([MS-RDPECLIP] 3.1.5.4.2).
    SendFileContentsRequest(stream_id, lindex, rtsc::proto::kFileContentsSize, 0,
                            8, false, 0);
    return true;
}

void CliprdrClient::Poll(std::chrono::steady_clock::time_point now) {
    if (transfer_timeout_ms_ == 0 || pending_.empty()) return;
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (now < it->second.deadline) {
            ++it;
            continue;
        }
        ++transfer_timeout_count_;
        FileContentsDone done = std::move(it->second.done);
        const uint32_t lindex = it->second.lindex;
        const std::u16string name = FilenameFor(lindex);
        const uint64_t file_size = it->second.file_size;
        pending_.erase(it++);
        if (done) done(lindex, name, file_size, {}, false);
    }
}

void CliprdrClient::CancelRemoteFileContents() {
    for (auto& kv : pending_) {
        if (kv.second.done) {
            kv.second.done(kv.second.lindex, FilenameFor(kv.second.lindex),
                           kv.second.file_size, std::vector<uint8_t>{}, false);
        }
    }
    pending_.clear();
}

void CliprdrClient::OnFileContentsRequest(const rtsc::proto::CliprdrPdu& pdu) {
    ++file_contents_request_received_;
    // F2: an incoming request carries no msgFlags; one that does is ignored
    // (loose handling, never served).
    if (pdu.header.msg_flags != 0) {
        ++file_contents_request_rejected_;
        return;
    }
    rtsc::proto::CliprdrFileContentsRequest req;
    // F1: a malformed body is dropped and counted.
    if (rtsc::proto::CliprdrFileContentsRequest::parse(pdu.data, req) !=
        rtsc::proto::Status::Ok) {
        ++file_contents_request_rejected_;
        return;
    }
    const auto respond_fail = [&]() {
        ++file_contents_request_rejected_;
        SendFileContentsResponse(req.stream_id, false, {});
    };
    // G1: our Format List was rejected by the peer, so nothing can be served
    // with it ([MS-RDPECLIP] 3.1.5.2.4 / 3.1.5.4.7).
    if (format_list_response_received_count_ > 0 &&
        !last_format_list_response_ok_) {
        respond_fail();
        return;
    }
    // F5: dwFlags must contain exactly one of SIZE / RANGE.
    const uint32_t valid =
        rtsc::proto::kFileContentsSize | rtsc::proto::kFileContentsRange;
    if ((req.dw_flags & ~valid) != 0 || (req.dw_flags & valid) == 0 ||
        (req.dw_flags & valid) == valid) {
        respond_fail();
        return;
    }
    const uint64_t position =
        (static_cast<uint64_t>(req.n_position_high)) << 32 | req.n_position_low;
    // F12: a zero-length request is never meaningful.
    if (req.cb_requested == 0) {
        respond_fail();
        return;
    }
    const bool is_size =
        (req.dw_flags & rtsc::proto::kFileContentsSize) != 0;
    if (is_size) {
        // F6: a SIZE probe asks for exactly 8 bytes at position 0.
        if (req.cb_requested != 8 || position != 0) {
            respond_fail();
            return;
        }
        // G2 / F8: locked clip data needs CB_CAN_LOCK_CLIPDATA negotiated and
        // the current lock id. This client never advertises the capability.
        if (req.has_clip_data_id &&
            ((client_general_flags_ & kClipCapsCanLockClipData) == 0 ||
             req.clip_data_id != locked_clipdata_id_)) {
            respond_fail();
            return;
        }
        ServeFileSizeRequest(req);
        return;
    }
    // RANGE.
    // F13: without huge-file support the peer cannot address beyond 2^32 via a
    // range position.
    if (!huge_enabled_ && position >= (1ULL << 32)) {
        respond_fail();
        return;
    }
    // G2 / F8: same lock gate as SIZE.
    if (req.has_clip_data_id &&
        ((client_general_flags_ & kClipCapsCanLockClipData) == 0 ||
         req.clip_data_id != locked_clipdata_id_)) {
        respond_fail();
        return;
    }
    // F14: a single range is capped.
    if (req.cb_requested > kMaxServeRange) {
        respond_fail();
        return;
    }
    ServeFileRangeRequest(req);
}

void CliprdrClient::ServeFileSizeRequest(
    const rtsc::proto::CliprdrFileContentsRequest& req) {
    const auto respond_fail = [&]() {
        ++file_contents_request_rejected_;
        SendFileContentsResponse(req.stream_id, false, {});
    };
    // G3 / direction-B store gate.
    if (provider_ == nullptr) {
        respond_fail();
        return;
    }
    // F7: lindex bounds.
    if (req.lindex < 0 ||
        static_cast<uint32_t>(req.lindex) >= provider_->file_count()) {
        respond_fail();
        return;
    }
    rtsc::clipboard::FileInfo info;
    if (!provider_->file_info(static_cast<uint32_t>(req.lindex), info)) {
        respond_fail();
        return;
    }
    // F13: the size answer is always the full 64-bit size (F15: 0 is legal
    // for an empty file).
    std::vector<uint8_t> size_bytes(8, 0);
    const uint64_t size = info.size;
    for (size_t i = 0; i < 8; ++i) {
        size_bytes[i] = static_cast<uint8_t>((size >> (8 * i)) & 0xFF);
    }
    SendFileContentsResponse(req.stream_id, true, size_bytes);
}

void CliprdrClient::ServeFileRangeRequest(
    const rtsc::proto::CliprdrFileContentsRequest& req) {
    const auto respond_fail = [&]() {
        ++file_contents_request_rejected_;
        SendFileContentsResponse(req.stream_id, false, {});
    };
    if (provider_ == nullptr) {
        respond_fail();
        return;
    }
    if (req.lindex < 0 ||
        static_cast<uint32_t>(req.lindex) >= provider_->file_count()) {
        respond_fail();
        return;
    }
    rtsc::clipboard::FileInfo info;
    if (!provider_->file_info(static_cast<uint32_t>(req.lindex), info)) {
        respond_fail();
        return;
    }
    const uint64_t position =
        (static_cast<uint64_t>(req.n_position_high)) << 32 | req.n_position_low;
    // F11: EOF semantics.
    if (position > info.size) {
        respond_fail();
        return;
    }
    const uint64_t count = std::min<uint64_t>(
        req.cb_requested, info.size - position);
    if (count == 0) {
        // offset == size: OK with an empty range ([MS-RDPECLIP] 3.1.5.4.2).
        SendFileContentsResponse(req.stream_id, true, {});
        return;
    }
    std::vector<uint8_t> ranged;
    if (!provider_->read_range(static_cast<uint32_t>(req.lindex), position,
                               static_cast<uint32_t>(count), ranged)) {
        respond_fail();
        return;
    }
    if (ranged.size() > count) ranged.resize(static_cast<size_t>(count));
    SendFileContentsResponse(req.stream_id, true, ranged);
}

void CliprdrClient::OnFileContentsResponse(const rtsc::proto::CliprdrPdu& pdu) {
    ++file_contents_response_received_;
    // F4: both OK and FAIL is ambiguous -> failure. F3: neither flag is treated
    // as a failure too (fail-close).
    const bool ok_flag =
        (pdu.header.msg_flags & rtsc::proto::kClipResponseOk) != 0;
    const bool fail_flag =
        (pdu.header.msg_flags & rtsc::proto::kClipResponseFail) != 0;
    const bool ok = ok_flag && !fail_flag;

    rtsc::proto::CliprdrFileContentsResponse resp;
    if (rtsc::proto::CliprdrFileContentsResponse::parse(pdu.data, ok, resp) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    auto it = pending_.find(resp.stream_id);
    if (it == pending_.end()) return;  // late / unmatched response: ignore.
    const auto finish = [&](std::map<uint32_t, PendingFileContents>::iterator e,
                            bool transfer_ok, std::vector<uint8_t> data) {
        FileContentsDone done = std::move(e->second.done);
        const uint32_t lindex = e->second.lindex;
        const std::u16string name = FilenameFor(lindex);
        const uint64_t file_size = e->second.file_size;
        pending_.erase(e);
        if (done) done(lindex, name, file_size, data, transfer_ok);
    };
    if (!ok) {
        finish(it, false, {});
        return;
    }
    if (it->second.size_pending) {
        // The SIZE answer is exactly the 8 bytes we asked for (F6/Take: a
        // response larger than cbRequested is an error).
        if (resp.data.size() != 8) {
            finish(it, false, {});
            return;
        }
        it->second.file_size =
            ReadU32Le(resp.data.data()) |
            (static_cast<uint64_t>(ReadU32Le(resp.data.data() + 4)) << 32);
        // D3: without huge-file support (0x20) a file whose size we cannot
        // address is failed now, before any RANGE request reaches >= 2^32.
        if (!huge_enabled_ && it->second.file_size >= (1ULL << 32)) {
            finish(it, false, {});
            return;
        }
        it->second.size_pending = false;
        it->second.offset = 0;
        it->second.data.clear();
        SendFileRangeRequest(resp.stream_id);
        return;
    }
    // RANGE answer.
    if (resp.data.size() > it->second.cb_requested) {
        finish(it, false, {});
        return;
    }
    it->second.offset += resp.data.size();
    it->second.data.insert(it->second.data.end(), resp.data.begin(),
                           resp.data.end());
    if (it->second.offset == it->second.file_size) {
        finish(it, true, std::move(it->second.data));
        return;
    }
    if (resp.data.empty()) {
        // 0 bytes before EOF: the peer stalled the stream.
        finish(it, false, {});
        return;
    }
    SendFileRangeRequest(resp.stream_id);
}

void CliprdrClient::SendFileContentsRequest(uint32_t stream_id,
                                            uint32_t lindex,
                                            uint32_t dw_flags,
                                            uint64_t position,
                                            uint32_t cb_requested,
                                            bool has_clip_data_id,
                                            uint32_t clip_data_id) {
    rtsc::proto::CliprdrFileContentsRequest req;
    req.stream_id = stream_id;
    req.lindex = static_cast<int32_t>(lindex);
    req.dw_flags = dw_flags;
    req.n_position_low = static_cast<uint32_t>(position & 0xFFFFFFFFu);
    req.n_position_high = static_cast<uint32_t>(position >> 32);
    req.cb_requested = cb_requested;
    req.has_clip_data_id = has_clip_data_id;
    req.clip_data_id = clip_data_id;
    SendPdu(rtsc::proto::CliprdrMsgType::kFileContentsRequest, 0, req.encode());
    ++file_contents_request_sent_;
}

void CliprdrClient::SendFileContentsResponse(uint32_t stream_id, bool ok,
                                             const std::vector<uint8_t>& data) {
    rtsc::proto::CliprdrFileContentsResponse resp;
    resp.stream_id = stream_id;
    resp.data = data;
    SendPdu(rtsc::proto::CliprdrMsgType::kFileContentsResponse,
            ok ? rtsc::proto::kClipResponseOk : rtsc::proto::kClipResponseFail,
            resp.encode(ok));
    ++file_contents_response_sent_;
}

void CliprdrClient::SendFileRangeRequest(uint32_t stream_id) {
    auto it = pending_.find(stream_id);
    if (it == pending_.end()) return;
    PendingFileContents& entry = it->second;
    // D3 defensive: without huge support never issue a RANGE at/above 2^32.
    if (!huge_enabled_ && entry.offset >= (1ULL << 32)) {
        FileContentsDone done = std::move(entry.done);
        const uint32_t lindex = entry.lindex;
        const std::u16string name = FilenameFor(lindex);
        const uint64_t file_size = entry.file_size;
        pending_.erase(it);
        if (done) done(lindex, name, file_size, {}, false);
        return;
    }
    const uint64_t remaining = entry.file_size - entry.offset;
    const uint64_t count = std::min<uint64_t>(remaining, transfer_window_);
    if (count == 0) {
        // offset == size: the tail of the transfer (also the empty-file case).
        const auto finish_tail = [&]() {
            FileContentsDone done = std::move(entry.done);
            const uint32_t lindex = entry.lindex;
            const std::u16string name = FilenameFor(lindex);
            const uint64_t file_size = entry.file_size;
            const std::vector<uint8_t> data = std::move(entry.data);
            pending_.erase(it);
            if (done) done(lindex, name, file_size, data, true);
        };
        finish_tail();
        return;
    }
    entry.cb_requested = static_cast<uint32_t>(count);
    SendFileContentsRequest(stream_id, entry.lindex,
                            rtsc::proto::kFileContentsRange, entry.offset,
                            entry.cb_requested, false, 0);
}

uint32_t CliprdrClient::AllocateStreamId() {
    for (;;) {
        ++next_stream_id_;
        if (next_stream_id_ == 0) continue;  // 0 is reserved
        if (pending_.find(next_stream_id_) == pending_.end()) {
            return next_stream_id_;
        }
    }
}

std::u16string CliprdrClient::FilenameFor(uint32_t lindex) const {
    if (lindex < remote_file_list_.size()) {
        return remote_file_list_[lindex].file_name;
    }
    return std::u16string();
}

}  // namespace rtsc::channel
