// Clipboard virtual channel (cliprdr) server handler ([MS-RDPECLIP]).

#include "rtsc/channel/cliprdr_server.h"

#include <algorithm>
#include <chrono>
#include <cstring>
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

const char* CliprdrServer::to_string(State s) {
    switch (s) {
        case State::kIdle: return "idle";
        case State::kInitSent: return "init-sent";
        case State::kCapsReceived: return "caps-received";
        case State::kSynced: return "synced";
        case State::kActive: return "active";
    }
    return "unknown";
}

CliprdrServer::CliprdrServer(clipboard::Clipboard* clipboard, SendFn send)
    : clipboard_(clipboard), send_(std::move(send)) {}

CliprdrServer::~CliprdrServer() = default;

CliprdrServer::State CliprdrServer::state() const {
    if (!started_) return State::kIdle;
    if (!client_caps_received_ && !first_format_list_received_) {
        return State::kInitSent;
    }
    if (!first_format_list_received_) {
        return State::kCapsReceived;
    }
    if (!client_caps_received_) {
        return State::kSynced;
    }
    // Both the capability exchange and the first format list happened: the
    // session is fully negotiated.
    return State::kActive;
}

void CliprdrServer::Start() {
    if (started_) return;
    started_ = true;
    // [MS-RDPECLIP] 1.3.2.1 with the server speaking first (design §1 "服务器
    // 先发"): Clipboard Capabilities, then Monitor Ready, then a Format List.
    // The Format List is sent even when the local clipboard is empty; the
    // ordering (and the Monitor Ready) is what orders the client's answer and
    // avoids the server/client initialization deadlock.
    SendClipCaps();
    SendPdu(rtsc::proto::CliprdrMsgType::kMonitorReady, 0, {});
    ++monitor_ready_count_;
    // Seed the sequence-based change detection so the poll does not mistake
    // the initial state for a change.
    if (clipboard_ != nullptr) {
        last_observed_seq_ = clipboard_->sequence_number();
        has_observed_seq_ = true;
    }
    SendFormatList();
}

void CliprdrServer::OnChannelData(const uint8_t* data, size_t size) {
    if (data == nullptr || size < rtsc::proto::ChannelPduHeader::kSize) {
        ++malformed_pdu_count_;
        return;
    }
    rtsc::proto::ChannelPduHeader header;
    if (rtsc::proto::ChannelPduHeader::parse(data, size, header) !=
        rtsc::proto::Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    bool complete = false;
    std::vector<uint8_t> message;
    const rtsc::proto::Status st = reassembler_.Feed(
        header, data + rtsc::proto::ChannelPduHeader::kSize,
        size - rtsc::proto::ChannelPduHeader::kSize, complete, message);
    if (st != rtsc::proto::Status::Ok) {
        ++malformed_pdu_count_;
        reassembler_.Reset();
        return;
    }
    if (!complete) return;
    OnMessage(message);
}

void CliprdrServer::OnMessage(const std::vector<uint8_t>& message) {
    size_t offset = 0;
    while (offset + rtsc::proto::CliprdrHeader::kSize <= message.size()) {
        rtsc::proto::CliprdrPdu pdu;
        if (rtsc::proto::CliprdrPdu::parse(message.data() + offset,
                                           message.size() - offset, pdu) !=
            rtsc::proto::Status::Ok) {
            ++malformed_pdu_count_;
            return;
        }
        OnPdu(pdu);
        offset += rtsc::proto::CliprdrHeader::kSize +
                  static_cast<size_t>(pdu.header.data_len);
    }
}

void CliprdrServer::OnPdu(const rtsc::proto::CliprdrPdu& pdu) {
    switch (pdu.header.msg_type) {
        case rtsc::proto::CliprdrMsgType::kClipCaps:
            OnClientClipCaps(pdu.data);
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
            // v1 runs no in-flight file operations; the response is only
            // counted (receiving one must not move the sent counter).
            ++file_contents_response_received_;
            break;
        default:
            // Monitor Ready, unknown msgType: SHOULD ignore ([MS-RDPECLIP]).
            break;
    }
}

void CliprdrServer::OnClientClipCaps(const std::vector<uint8_t>& body) {
    if (body.size() < 4) {
        ++malformed_pdu_count_;
        return;
    }
    rtsc::proto::ByteReader r(body.data(), body.size());
    uint16_t count = 0;
    uint16_t pad = 0;
    if (!r.u16le(count) || !r.u16le(pad)) {
        ++malformed_pdu_count_;
        return;
    }
    for (uint16_t i = 0; i < count; ++i) {
        uint16_t type = 0;
        uint16_t length = 0;
        if (!r.u16le(type) || !r.u16le(length)) {
            ++malformed_pdu_count_;
            return;
        }
        if (length < 4 || r.remaining() < static_cast<size_t>(length) - 4) {
            ++malformed_pdu_count_;
            return;
        }
        if (type == kCbCapstypeGeneral && length >= kGeneralCapsLength) {
            r.skip(4);  // version (informational only)
            uint32_t flags = 0;
            if (!r.u32le(flags)) {
                ++malformed_pdu_count_;
                return;
            }
            client_general_flags_ = flags;
            r.skip(static_cast<size_t>(length) - kGeneralCapsLength);
        } else {
            r.skip(static_cast<size_t>(length) - 4);
        }
    }
    // The long format name variant is used only when both endpoints
    // advertise CB_USE_LONG_FORMAT_NAMES. This server always advertises it,
    // so the client flag decides the negotiated variant.
    long_format_names_ =
        (server_general_flags_ & kClipCapsUseLongFormatNames) != 0 &&
        (client_general_flags_ & kClipCapsUseLongFormatNames) != 0;
    client_caps_received_ = true;
    ++client_caps_count_;
}

void CliprdrServer::OnFormatList(const rtsc::proto::CliprdrPdu& pdu) {
    remote_formats_.clear();
    const std::vector<uint8_t>& data = pdu.data;
    size_t offset = 0;
    bool well_formed = true;
    if (long_format_names_) {
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
            if (!terminated) {
                well_formed = false;  // malformed: no null terminator
                break;
            }
            remote_formats_.push_back(format);
        }
        // A trailing partial entry (bytes left past the last whole format) is
        // also malformed.
        if (offset != data.size()) well_formed = false;
    } else {
        while (offset + kShortFormatNameSize <= data.size()) {
            const uint32_t format = ReadU32Le(data.data() + offset);
            remote_formats_.push_back(format);
            offset += kShortFormatNameSize;
        }
        // Short format entries are fixed-size; a ragged tail is malformed.
        if (offset != data.size()) well_formed = false;
    }
    if (!well_formed) {
        ++malformed_pdu_count_;
        remote_formats_.clear();
        return;
    }
    first_format_list_received_ = true;
    ++remote_format_list_count_;
    SendFormatListResponse(true);
    // Eager sync: request the data for the preferred remote format so a local
    // paste sees the client's clipboard immediately. File formats are skipped.
    const uint32_t preferred = PickPreferredFormat();
    if (preferred != 0) RequestClientFormat(preferred);
}

void CliprdrServer::OnFormatListResponse(const rtsc::proto::CliprdrPdu& pdu) {
    ++format_list_response_received_count_;
    last_format_list_response_ok_ =
        (pdu.header.msg_flags & rtsc::proto::kClipResponseOk) != 0;
}

void CliprdrServer::OnFormatDataRequest(const std::vector<uint8_t>& body) {
    rtsc::proto::CliprdrFormatDataRequest request;
    if (rtsc::proto::CliprdrFormatDataRequest::parse(body, request) !=
        rtsc::proto::Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    ++format_data_request_count_;
    const auto respond_fail = [&]() {
        SendFormatDataResponse({}, false);
    };
    // G1: our Format List was rejected by the client, so nothing can be
    // served with it ([MS-RDPECLIP] 3.1.5.2.4).
    if (format_list_response_received_count_ > 0 &&
        !last_format_list_response_ok_) {
        respond_fail();
        return;
    }
    // The file-list format is served from the injected provider, never from
    // the local clipboard (which holds it as an opaque drop mark).
    if (request.format_id == rtsc::proto::kDeFactoFileListFormatId &&
        provider_ != nullptr) {
        rtsc::proto::CliprdrFileList list;
        const uint32_t count = provider_->file_count();
        list.files.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            rtsc::clipboard::FileInfo info;
            if (!provider_->file_info(i, info)) {
                respond_fail();
                return;
            }
            rtsc::proto::CliprdrFileDescriptor descriptor;
            descriptor.dw_flags = rtsc::proto::kFileDescriptorSize |
                                  rtsc::proto::kFileDescriptorAttributes;
            descriptor.file_attributes = info.attributes;
            if (info.is_directory) {
                descriptor.file_attributes |=
                    rtsc::proto::kFileAttributeDirectory;
            }
            descriptor.file_size = info.size;
            descriptor.file_name = std::move(info.name);
            list.files.push_back(std::move(descriptor));
        }
        const std::vector<uint8_t> payload = list.encode();
        if (payload.empty()) {
            respond_fail();
            return;
        }
        SendFormatDataResponse(payload, true);
        return;
    }
    if (request.format_id == rtsc::proto::kDeFactoFileListFormatId) {
        respond_fail();  // file clip off or no provider (v1)
        return;
    }
    std::vector<uint8_t> data;
    const bool ok =
        clipboard_ != nullptr && clipboard_->read(request.format_id, data);
    SendFormatDataResponse(ok ? data : std::vector<uint8_t>{}, ok);
}

void CliprdrServer::OnFormatDataResponse(
    const rtsc::proto::CliprdrPdu& pdu) {
    ++format_data_response_received_count_;
    const bool ok =
        (pdu.header.msg_flags & rtsc::proto::kClipResponseOk) != 0;
    if (!ok || clipboard_ == nullptr) {
        pending_format_ = 0;
        return;
    }
    // A response with no outstanding request is stray: not written.
    if (pending_format_ == 0) return;
    // A file-list answer is a CLIPRDR_FILELIST, never clipboard data; v1 has
    // no local file store, so it is dropped (it rides a request we never
    // issue for this format).
    if (pending_format_ == rtsc::proto::kDeFactoFileListFormatId) {
        pending_format_ = 0;
        return;
    }
    // Apply the remote data. The write bumps the clipboard sequence number;
    // the post-application sequence is remembered so the resulting local
    // "change" is swallowed ("应用后 seq").
    clipboard_->write(pending_format_, pdu.data);
    last_applied_seq_ = clipboard_->sequence_number();
    has_last_applied_seq_ = true;
    pending_format_ = 0;
    ++format_data_applied_count_;
}

void CliprdrServer::OnTempDirectory(const std::vector<uint8_t>& body) {
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

void CliprdrServer::OnLockClipData(const std::vector<uint8_t>& body,
                                   bool lock) {
    if (body.size() < 4) {
        ++malformed_pdu_count_;
        return;
    }
    locked_clipdata_id_ = ReadU32Le(body.data());
    if (lock) {
        ++lock_clipdata_count_;
    } else {
        ++unlock_clipdata_count_;
    }
}

void CliprdrServer::SendPdu(rtsc::proto::CliprdrMsgType type, uint16_t flags,
                            const std::vector<uint8_t>& body) {
    if (!send_) return;
    const std::vector<uint8_t> pdu =
        rtsc::proto::BuildCliprdrPdu(type, flags, body);
    const std::vector<std::vector<uint8_t>> chunks = rtsc::proto::
        FragmentChannelMessage(pdu, rtsc::proto::kDefaultChannelChunkSize);
    for (const auto& chunk : chunks) send_(chunk);
}

void CliprdrServer::SendClipCaps() {
    rtsc::proto::ByteWriter w;
    w.u16le(1);   // cCapabilitiesSets
    w.u16le(0);   // pad1
    w.u16le(kCbCapstypeGeneral);
    w.u16le(kGeneralCapsLength);
    w.u32le(kCbCapsVersion2);
    w.u32le(server_general_flags_);
    SendPdu(rtsc::proto::CliprdrMsgType::kClipCaps, 0, w.take());
    ++clip_caps_count_;
}

void CliprdrServer::SendFormatList() {
    const std::vector<uint32_t> formats =
        clipboard_ != nullptr ? clipboard_->formats()
                              : std::vector<uint32_t>{};
    // Outbound encoding follows the server's own advertised capability: it
    // always advertises CB_USE_LONG_FORMAT_NAMES, so before the client caps
    // arrive (Start) the long variant is used; afterwards the negotiated
    // value. The client parses with the same negotiated value, so the two
    // sides agree. (A pre-capability long variant is harmless for the common
    // empty table -- a long-named null name and a short-named null name both
    // cost one entry and an empty list is all zero bytes.)
    const bool use_long = long_format_names_ || !client_caps_received_;
    rtsc::proto::ByteWriter w;
    for (const uint32_t format : formats) {
        if (format == rtsc::proto::kDeFactoFileListFormatId) continue;
        w.u32le(format);
        if (use_long) {
            // A nameless format is a single null UTF-16 code unit.
            w.u16le(0);
        } else {
            for (size_t i = 0; i < kShortFormatNameField; ++i) w.u8(0);
        }
    }
    if (provider_ != nullptr) {
        w.u32le(rtsc::proto::kDeFactoFileListFormatId);
        if (use_long) {
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

void CliprdrServer::SendFormatListResponse(bool ok) {
    SendPdu(rtsc::proto::CliprdrMsgType::kFormatListResponse,
            ok ? rtsc::proto::kClipResponseOk : rtsc::proto::kClipResponseFail,
            {});
    ++format_list_response_count_;
}

void CliprdrServer::SendFormatDataResponse(const std::vector<uint8_t>& data,
                                           bool ok) {
    SendPdu(rtsc::proto::CliprdrMsgType::kFormatDataResponse,
            ok ? rtsc::proto::kClipResponseOk : rtsc::proto::kClipResponseFail,
            data);
    ++format_data_response_sent_count_;
}

void CliprdrServer::SendFileContentsResponse(uint32_t stream_id, bool ok,
                                             const std::vector<uint8_t>& data) {
    rtsc::proto::CliprdrFileContentsResponse resp;
    resp.stream_id = stream_id;
    resp.data = data;
    SendPdu(rtsc::proto::CliprdrMsgType::kFileContentsResponse,
            ok ? rtsc::proto::kClipResponseOk : rtsc::proto::kClipResponseFail,
            resp.encode(ok));
    ++file_contents_response_sent_;
}

uint32_t CliprdrServer::PickPreferredFormat() const {
    // The file-list format is never eager-synced as text data.
    const auto is_file_format = [&](uint32_t f) {
        return f == rtsc::proto::kDeFactoFileListFormatId;
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

void CliprdrServer::OnLocalClipboardChanged() {
    // A change caused by our own remote-applied write (the post-application
    // sequence number matches) is swallowed. The guard stays armed until a
    // genuinely different clipboard is observed.
    if (has_last_applied_seq_ && clipboard_ != nullptr) {
        const uint64_t seq = clipboard_->sequence_number();
        if (seq == last_applied_seq_) return;
        has_last_applied_seq_ = false;
    }
    // The server speaks first (Start), so a Format List may only be pushed
    // after it has spoken ([MS-RDPECLIP] 1.3.2.1).
    if (!started_) return;
    SendFormatList();
}

bool CliprdrServer::RequestClientFormat(uint32_t format) {
    if (!started_ || pending_format_ != 0) return false;
    if (format == rtsc::proto::kDeFactoFileListFormatId) return false;
    if (format == 0) return false;
    pending_format_ = format;
    rtsc::proto::ByteWriter w;
    w.u32le(format);
    SendPdu(rtsc::proto::CliprdrMsgType::kFormatDataRequest, 0, w.take());
    ++format_data_request_sent_count_;
    return true;
}

void CliprdrServer::Poll(std::chrono::steady_clock::time_point now) {
    (void)now;  // no timed housekeeping in v1
    if (clipboard_ == nullptr) return;
    const uint64_t seq = clipboard_->sequence_number();
    if (has_observed_seq_ && seq == last_observed_seq_) return;
    last_observed_seq_ = seq;
    has_observed_seq_ = true;
    OnLocalClipboardChanged();
}

void CliprdrServer::EnableFileClip() {
    file_clip_enabled_ = true;
    server_general_flags_ |= kClipCapsStreamFileClip;
}

void CliprdrServer::EnableHugeFileSupport() {
    huge_enabled_ = true;
    server_general_flags_ |= kClipCapsHugeFileSupport;
}

void CliprdrServer::SetFileListProvider(
    rtsc::clipboard::FileListProvider* provider) {
    provider_ = provider;
}

void CliprdrServer::OnFileContentsRequest(
    const rtsc::proto::CliprdrPdu& pdu) {
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
    // G1: our Format List was rejected by the client, so nothing can be
    // served with it ([MS-RDPECLIP] 3.1.5.2.4 / 3.1.5.4.7).
    if (format_list_response_received_count_ > 0 &&
        !last_format_list_response_ok_) {
        respond_fail();
        return;
    }
    // G3 / direction-B store gate: file clip is off by default (v1) and a
    // request cannot be served without a provider either; both fail.
    if (!file_clip_enabled_ || provider_ == nullptr) {
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
        ServeFileSizeRequest(req);
        return;
    }
    // RANGE.
    // F13: without huge-file support the peer cannot address beyond 2^32.
    if (!huge_enabled_ && position >= (1ULL << 32)) {
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

void CliprdrServer::ServeFileSizeRequest(
    const rtsc::proto::CliprdrFileContentsRequest& req) {
    const auto respond_fail = [&]() {
        ++file_contents_request_rejected_;
        SendFileContentsResponse(req.stream_id, false, {});
    };
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
    std::vector<uint8_t> size_bytes(8, 0);
    const uint64_t size = info.size;
    for (size_t i = 0; i < 8; ++i) {
        size_bytes[i] = static_cast<uint8_t>((size >> (8 * i)) & 0xFF);
    }
    SendFileContentsResponse(req.stream_id, true, size_bytes);
}

void CliprdrServer::ServeFileRangeRequest(
    const rtsc::proto::CliprdrFileContentsRequest& req) {
    const auto respond_fail = [&]() {
        ++file_contents_request_rejected_;
        SendFileContentsResponse(req.stream_id, false, {});
    };
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

}  // namespace rtsc::channel