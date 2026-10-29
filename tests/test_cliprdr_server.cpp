// Server-side CLIPRDR channel handler unit tests ([MS-RDPECLIP]).
//
// Covers the CliprdrServer state machine and failure paths (design S1-S13):
// Start's cap/monitor-ready/format-list order, long/short format-name
// negotiation, format-data serve and request (with self-echo swallowing),
// reassembly, malformed-PDU ignoring, temp-directory recording, the v1
// FILECONTENTS fail path and the gated file serve.

#include "rtsc/channel/cliprdr_server.h"
#include "rtsc/clipboard/clipboard.h"
#include "rtsc/clipboard/file_list.h"
#include "rtsc/proto/cliprdr.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

// A test double for the local clipboard: serves the configured formats/data,
// records writes and tracks a monotonic sequence number (the serialization of
// the Win32 GetClipboardSequenceNumber the real backend exposes).
class FakeClipboard final : public rtsc::clipboard::Clipboard {
 public:
    std::vector<uint32_t> formats() override { return formats_; }
    bool read(uint32_t format, std::vector<uint8_t>& out) override {
        if (read_fails_) {
            out.clear();
            return false;
        }
        auto it = data_.find(format);
        if (it == data_.end()) return false;
        out = it->second;
        return true;
    }
    bool write(uint32_t format, const std::vector<uint8_t>& data) override {
        data_[format] = data;
        ++write_count_;
        ++seq_;
        return true;
    }
    uint64_t sequence_number() const override { return seq_; }

    // Simulates an external clipboard change (a local copy).
    void bump() { ++seq_; }

    bool read_fails_ = false;
    std::vector<uint32_t> formats_;
    std::map<uint32_t, std::vector<uint8_t>> data_;
    uint64_t seq_ = 0;
    unsigned write_count_ = 0;
};

// Decodes one sent channel chunk (CHANNEL_PDU_HEADER + cliprdr PDU).
CliprdrPdu DecodeChunk(const std::vector<uint8_t>& chunk) {
    CliprdrPdu pdu;
    CHECK_EQ(chunk.size() >= ChannelPduHeader::kSize, true);
    const uint8_t* p = chunk.data() + ChannelPduHeader::kSize;
    const size_t n = chunk.size() - ChannelPduHeader::kSize;
    CHECK(CliprdrPdu::parse(p, n, pdu) == Status::Ok);
    return pdu;
}

// Wraps a cliprdr PDU in a channel message and feeds it to the server.
void FeedPdu(rtsc::channel::CliprdrServer& server, CliprdrMsgType type,
             uint16_t flags, const std::vector<uint8_t>& body) {
    const auto pdu = BuildCliprdrPdu(type, flags, body);
    for (const auto& chunk : FragmentChannelMessage(pdu)) {
        server.OnChannelData(chunk.data(), chunk.size());
    }
}

// Builds the payload of a client CB_CLIP_CAPS PDU with the given general flags
// (the client's own SendClipCaps byte layout).
std::vector<uint8_t> ClientCapsBody(uint32_t flags) {
    ByteWriter w;
    w.u16le(1);    // cCapabilitiesSets
    w.u16le(0);    // pad1
    w.u16le(1);    // capabilitySetType = CB_CAPSTYPE_GENERAL
    w.u16le(12);   // lengthCapability
    w.u32le(2);    // CB_CAPS_VERSION_2
    w.u32le(flags);
    return w.take();
}

void FeedClientCaps(rtsc::channel::CliprdrServer& server, uint32_t flags) {
    FeedPdu(server, CliprdrMsgType::kClipCaps, 0, ClientCapsBody(flags));
}

// The message types of the PDUs the server sent, in order.
std::vector<CliprdrMsgType> SentTypes(
    const std::vector<std::vector<uint8_t>>& sent) {
    std::vector<CliprdrMsgType> types;
    types.reserve(sent.size());
    for (const auto& chunk : sent) {
        types.push_back(DecodeChunk(chunk).header.msg_type);
    }
    return types;
}

bool HasSentType(const std::vector<std::vector<uint8_t>>& sent,
                 CliprdrMsgType type) {
    for (const auto& chunk : sent) {
        if (DecodeChunk(chunk).header.msg_type == type) return true;
    }
    return false;
}

uint32_t ReadU32Le(const std::vector<uint8_t>& d) {
    return static_cast<uint32_t>(d[0]) | (static_cast<uint32_t>(d[1]) << 8) |
           (static_cast<uint32_t>(d[2]) << 16) |
           (static_cast<uint32_t>(d[3]) << 24);
}

uint64_t ReadU64Le(const std::vector<uint8_t>& d) {
    return ReadU32Le(d) |
           (static_cast<uint64_t>(
                ReadU32Le(std::vector<uint8_t>(d.begin() + 4, d.end())))
            << 32);
}

// A provider serving `bytes` from the first FileInfo.
class FakeProvider final : public rtsc::clipboard::FileListProvider {
 public:
    uint32_t file_count() const override {
        return static_cast<uint32_t>(files.size());
    }
    bool file_info(uint32_t index, rtsc::clipboard::FileInfo& out) const override {
        if (index >= files.size()) return false;
        out = files[index];
        return true;
    }
    bool read_range(uint32_t index, uint64_t offset, uint32_t count,
                    std::vector<uint8_t>& out) override {
        if (index >= files.size()) return false;
        if (fail_reads_) {
            out.clear();
            return false;
        }
        const auto& b = blocks[index];
        if (offset >= b.size()) {
            out.clear();
            return true;
        }
        const size_t n =
            std::min<size_t>(count, b.size() - static_cast<size_t>(offset));
        out.assign(b.begin() + static_cast<ptrdiff_t>(offset),
                   b.begin() + static_cast<ptrdiff_t>(offset + n));
        return true;
    }

    bool fail_reads_ = false;
    std::vector<rtsc::clipboard::FileInfo> files;
    std::vector<std::vector<uint8_t>> blocks;
};

// A server whose SendFn records every emitted chunk. `sent` must outlive it.
std::unique_ptr<rtsc::channel::CliprdrServer> MakeServer(
    FakeClipboard* clip, std::vector<std::vector<uint8_t>>& sent) {
    return std::make_unique<rtsc::channel::CliprdrServer>(
        clip, [&sent](const std::vector<uint8_t>& m) { sent.push_back(m); });
}

std::vector<uint8_t> FcrBody(uint32_t stream_id, int32_t lindex,
                             uint32_t dw_flags, uint64_t position,
                             uint32_t cb_requested) {
    CliprdrFileContentsRequest req;
    req.stream_id = stream_id;
    req.lindex = lindex;
    req.dw_flags = dw_flags;
    req.n_position_low = static_cast<uint32_t>(position & 0xFFFFFFFFu);
    req.n_position_high = static_cast<uint32_t>(position >> 32);
    req.cb_requested = cb_requested;
    return req.encode();
}

}  // namespace

// S1: Start sends Clipboard Capabilities, then Monitor Ready, then a Format
// List, exactly once. The Formats List uses long format names (the server
// advertises CB_USE_LONG_FORMAT_NAMES, so its own outbound list is the long
// variant even before the client caps arrive).
RTSC_TEST(cliprdr_server_start_sends_init_sequence_once) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText, kCfDib};
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    CHECK(server->state() == rtsc::channel::CliprdrServer::State::kIdle);

    server->Start();
    CHECK(server->started());
    CHECK(server->state() == rtsc::channel::CliprdrServer::State::kInitSent);
    const std::vector<CliprdrMsgType> want = {CliprdrMsgType::kClipCaps,
                                              CliprdrMsgType::kMonitorReady,
                                              CliprdrMsgType::kFormatList};
    CHECK(SentTypes(sent) == want);
    CHECK_EQ(sent.size(), static_cast<size_t>(3));

    // Capabilities payload: cCapabilitiesSets=1, pad1=0, type=1, length=12,
    // version=2, flags=LONG (0x02).
    const CliprdrPdu caps = DecodeChunk(sent[0]);
    CHECK_EQ(caps.header.data_len, static_cast<uint32_t>(16));
    CHECK_BYTES(caps.data, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0C, 0x00, 0x02,
                0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00);
    CHECK_EQ(server->clip_caps_count(), static_cast<unsigned>(1));

    // Monitor Ready is server-to-client only, with no payload.
    const CliprdrPdu mr = DecodeChunk(sent[1]);
    CHECK(mr.header.msg_type == CliprdrMsgType::kMonitorReady);
    CHECK_EQ(mr.header.data_len, static_cast<uint32_t>(0));
    CHECK_EQ(server->monitor_ready_count(), static_cast<unsigned>(1));

    // Format List: long variant, two formats of 6 bytes each.
    const CliprdrPdu list = DecodeChunk(sent[2]);
    CHECK_EQ(list.data.size(), static_cast<size_t>(2 * 6));
    CHECK_EQ(ReadU32Le(list.data), static_cast<uint32_t>(kCfUnicodeText));
    CHECK_EQ(server->local_format_list_count(), static_cast<unsigned>(1));

    // A second Start is a no-op.
    const size_t after_first = sent.size();
    server->Start();
    CHECK_EQ(sent.size(), after_first);
    CHECK_EQ(server->clip_caps_count(), static_cast<unsigned>(1));
    CHECK_EQ(server->monitor_ready_count(), static_cast<unsigned>(1));
}

// S2: the long format name variant is negotiated only when the client also
// advertises CB_USE_LONG_FORMAT_NAMES (the server always advertises it).
RTSC_TEST(cliprdr_server_long_format_names_follow_client_caps) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->Start();
    CHECK_EQ(server->client_caps_received(), false);
    CHECK_EQ(server->long_format_names(), false);

    // A client without the flag keeps the short variant.
    FeedClientCaps(*server, 0);
    CHECK(server->client_caps_received());
    CHECK_EQ(server->long_format_names(), false);
    CHECK(server->state() == rtsc::channel::CliprdrServer::State::kCapsReceived);

    // A second caps PDU with the flag negotiates long names.
    FeedClientCaps(*server, rtsc::channel::kClipCapsUseLongFormatNames);
    CHECK_EQ(server->long_format_names(), true);
    CHECK_EQ(server->client_flags(),
             static_cast<uint32_t>(rtsc::channel::kClipCapsUseLongFormatNames));
    CHECK_EQ(server->client_caps_count(), static_cast<unsigned>(2));
}

// S3: a short format name Format List is parsed and answered OK. The first
// Format List from the client brings the state machine to kSynced; long names
// are not negotiated yet (no client caps), so the short variant applies.
RTSC_TEST(cliprdr_server_short_format_list_parses_and_responds_ok) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->Start();
    const size_t after_start = sent.size();

    ByteWriter body;
    body.u32le(kCfText);
    for (int i = 0; i < 32; ++i) body.u8(0);
    body.u32le(kCfUnicodeText);
    for (int i = 0; i < 32; ++i) body.u8(0);
    FeedPdu(*server, CliprdrMsgType::kFormatList, 0, body.take());

    CHECK_EQ(server->remote_formats().size(), static_cast<size_t>(2));
    CHECK_EQ(server->remote_formats()[0], static_cast<uint32_t>(kCfText));
    CHECK_EQ(server->remote_formats()[1],
             static_cast<uint32_t>(kCfUnicodeText));
    CHECK_EQ(server->remote_format_list_count(), static_cast<unsigned>(1));
    CHECK(server->state() == rtsc::channel::CliprdrServer::State::kSynced);
    // FL response OK plus an eager format-data request for the preferred
    // format (CF_UNICODETEXT), mirroring the client.
    CHECK_EQ(sent.size(), after_start + 2);
    const CliprdrPdu resp = DecodeChunk(sent[after_start]);
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatListResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    CHECK_EQ(server->format_list_response_count(), static_cast<unsigned>(1));
    const CliprdrPdu eager = DecodeChunk(sent[after_start + 1]);
    CHECK(eager.header.msg_type == CliprdrMsgType::kFormatDataRequest);
}

// S4: a long format name Format List (with names) is parsed and answered OK.
// The client caps (with the long flag) arrived first, so the list is the long
// variant and the capability exchange is complete (kActive).
RTSC_TEST(cliprdr_server_long_format_list_parses_names_and_responds_ok) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->Start();
    FeedClientCaps(*server, rtsc::channel::kClipCapsUseLongFormatNames);
    const size_t after_negotiate = sent.size();

    ByteWriter body;
    // formatId = 0xC004, name = "Native" (UTF-16LE, null-terminated).
    body.u32le(0xC004);
    for (char16_t c : std::u16string(u"Native")) {
        body.u16le(static_cast<uint16_t>(c));
    }
    body.u16le(0);
    // formatId = 5, no name (a single null wchar).
    body.u32le(static_cast<uint32_t>(rtsc::clipboard::kCfDif));
    body.u16le(0);
    FeedPdu(*server, CliprdrMsgType::kFormatList, 0, body.take());

    CHECK_EQ(server->remote_formats().size(), static_cast<size_t>(2));
    CHECK_EQ(server->remote_formats()[0], static_cast<uint32_t>(0xC004));
    CHECK_EQ(server->remote_formats()[1],
             static_cast<uint32_t>(rtsc::clipboard::kCfDif));
    CHECK_EQ(sent.size(), after_negotiate + 2);  // FLR + eager data request
    const CliprdrPdu resp = DecodeChunk(sent[after_negotiate]);
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatListResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    // Both the client caps and the first format list are in: fully negotiated.
    CHECK(server->state() == rtsc::channel::CliprdrServer::State::kActive);
}

// S5: a Format Data Request for a present format is served OK with the data;
// a missing format answers FAIL.
RTSC_TEST(cliprdr_server_format_data_request_serves_local) {
    FakeClipboard clip;
    const std::vector<uint8_t> text = {0x48, 0x00, 0x69, 0x00, 0x00, 0x00};
    clip.data_[kCfUnicodeText] = text;
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);

    ByteWriter body;
    body.u32le(kCfUnicodeText);
    FeedPdu(*server, CliprdrMsgType::kFormatDataRequest, 0, body.take());

    CHECK_EQ(server->format_data_request_count(), static_cast<unsigned>(1));
    CHECK_EQ(sent.size(), static_cast<size_t>(1));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatDataResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    CHECK(resp.data == text);
    CHECK_EQ(server->format_data_response_sent(), static_cast<unsigned>(1));
}

RTSC_TEST(cliprdr_server_format_data_request_fails_when_absent) {
    FakeClipboard clip;  // empty clipboard
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);

    ByteWriter body;
    body.u32le(kCfUnicodeText);
    FeedPdu(*server, CliprdrMsgType::kFormatDataRequest, 0, body.take());

    CHECK_EQ(sent.size(), static_cast<size_t>(1));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatDataResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

// S6: RequestClientFormat sends the request; the client's answer is written to
// the local clipboard and the echo of that write is swallowed (post-application
// sequence number), while a genuinely different clipboard is reported.
RTSC_TEST(cliprdr_server_request_client_format_applies_and_swallows_echo) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->Start();
    const size_t after_start = sent.size();

    CHECK(server->RequestClientFormat(kCfUnicodeText));
    CHECK_EQ(server->pending_format_for_test(),
             static_cast<uint32_t>(kCfUnicodeText));
    CHECK_EQ(sent.size(), after_start + 1);
    const CliprdrPdu fdr = DecodeChunk(sent.back());
    CHECK(fdr.header.msg_type == CliprdrMsgType::kFormatDataRequest);
    CHECK_EQ(server->format_data_request_sent(), static_cast<unsigned>(1));

    const std::vector<uint8_t> text = {0x41, 0x00, 0x00, 0x00};
    FeedPdu(*server, CliprdrMsgType::kFormatDataResponse, kClipResponseOk, text);
    CHECK(clip.data_[kCfUnicodeText] == text);
    CHECK_EQ(clip.write_count_, static_cast<unsigned>(1));
    CHECK_EQ(server->format_data_applied_count(), static_cast<unsigned>(1));
    CHECK_EQ(server->pending_format_for_test(), static_cast<uint32_t>(0));

    // The change event fired by our own write must not be echoed back.
    server->OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), after_start + 1);

    // A genuinely different local clipboard is reported as a new Format List.
    clip.bump();
    server->OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), after_start + 2);
    CHECK(DecodeChunk(sent.back()).header.msg_type ==
          CliprdrMsgType::kFormatList);
}

// S6: a second RequestClientFormat is refused while one is in flight.
RTSC_TEST(cliprdr_server_request_client_format_serializes) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->Start();
    const size_t after_start = sent.size();
    CHECK(server->RequestClientFormat(kCfUnicodeText));
    CHECK(!server->RequestClientFormat(kCfDib));
    CHECK_EQ(sent.size(), after_start + 1);
}

// S7: the 1 s poll reports an external clipboard change as a Format List and
// swallows the echo of the server's own applied write.
RTSC_TEST(cliprdr_server_poll_reports_local_change) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->Start();
    const size_t after_start = sent.size();

    clip.bump();  // the user copied something locally
    server->Poll(std::chrono::steady_clock::now());
    CHECK_EQ(sent.size(), after_start + 1);
    CHECK(DecodeChunk(sent.back()).header.msg_type ==
          CliprdrMsgType::kFormatList);

    // No change: nothing sent.
    server->Poll(std::chrono::steady_clock::now());
    CHECK_EQ(sent.size(), after_start + 1);
}

RTSC_TEST(cliprdr_server_poll_swallows_self_echo_and_reports_next) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->Start();

    CHECK(server->RequestClientFormat(kCfUnicodeText));
    const std::vector<uint8_t> text = {0x42, 0x00};
    FeedPdu(*server, CliprdrMsgType::kFormatDataResponse, kClipResponseOk, text);

    // Our own write bumped the sequence number; the poll must swallow it.
    const size_t after_apply = sent.size();
    server->Poll(std::chrono::steady_clock::now());
    CHECK_EQ(sent.size(), after_apply);

    // The next real change is reported.
    clip.bump();
    server->Poll(std::chrono::steady_clock::now());
    CHECK_EQ(sent.size(), after_apply + 1);
}

// S7: a local change before Start must not be reported (no Format List before
// the server spoke).
RTSC_TEST(cliprdr_server_local_change_before_start_is_not_sent) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), static_cast<size_t>(0));
}

// S8: a message split across chunks is reassembled and answered.
RTSC_TEST(cliprdr_server_fragmented_message_reassembled) {
    FakeClipboard clip;
    clip.data_[kCfUnicodeText] = {0x41, 0x00};
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);

    ByteWriter body;
    body.u32le(kCfUnicodeText);
    const std::vector<uint8_t> pdu =
        BuildCliprdrPdu(CliprdrMsgType::kFormatDataRequest, 0, body.take());
    const size_t half = pdu.size() / 2;
    {
        ByteWriter w;
        w.u32le(static_cast<uint32_t>(pdu.size()));
        w.u32le(static_cast<uint32_t>(rtsc::proto::kChannelFirst));
        w.bytes(pdu.data(), half);
        const auto chunk = w.take();
        server->OnChannelData(chunk.data(), chunk.size());
    }
    CHECK_EQ(sent.size(), static_cast<size_t>(0));  // incomplete
    {
        ByteWriter w;
        w.u32le(static_cast<uint32_t>(pdu.size()));
        w.u32le(static_cast<uint32_t>(rtsc::proto::kChannelLast));
        w.bytes(pdu.data() + half, pdu.size() - half);
        const auto chunk = w.take();
        server->OnChannelData(chunk.data(), chunk.size());
    }
    CHECK_EQ(sent.size(), static_cast<size_t>(1));
    const CliprdrPdu resp = DecodeChunk(sent[0]);
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatDataResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
}

// S8: channel data may arrive before Start() (pre-active); once the pieces
// arrive the message is still processed normally (design risk R5).
RTSC_TEST(cliprdr_server_preactive_fragment_buffered_until_complete) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    CHECK_EQ(server->started(), false);

    const std::vector<uint8_t> pdu =
        BuildCliprdrPdu(CliprdrMsgType::kTempDirectory, 0, [&] {
            ByteWriter w;
            for (char16_t c : std::u16string(u"C:\\temp\\clip1")) {
                w.u16le(static_cast<uint16_t>(c));
            }
            w.u16le(0);
            return w.take();
        }());
    const size_t half = pdu.size() / 2;
    {
        ByteWriter w;
        w.u32le(static_cast<uint32_t>(pdu.size()));
        w.u32le(static_cast<uint32_t>(rtsc::proto::kChannelFirst));
        w.bytes(pdu.data(), half);
        const auto chunk = w.take();
        server->OnChannelData(chunk.data(), chunk.size());
    }
    {
        ByteWriter w;
        w.u32le(static_cast<uint32_t>(pdu.size()));
        w.u32le(static_cast<uint32_t>(rtsc::proto::kChannelLast));
        w.bytes(pdu.data() + half, pdu.size() - half);
        const auto chunk = w.take();
        server->OnChannelData(chunk.data(), chunk.size());
    }
    CHECK(server->temp_directory() == std::string("C:\\temp\\clip1"));
    CHECK_EQ(server->temp_directory_count(), static_cast<unsigned>(1));
}

// S9: a malformed PDU is ignored and counted, never answered.
RTSC_TEST(cliprdr_server_malformed_pdu_ignored) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->Start();
    const size_t after_start = sent.size();

    // A Format Data Request with a truncated body.
    const std::vector<uint8_t> bad =
        BuildCliprdrPdu(CliprdrMsgType::kFormatDataRequest, 0,
                        std::vector<uint8_t>{0x01, 0x00});
    server->OnChannelData(bad.data(), bad.size());
    CHECK_EQ(server->format_data_request_count(), static_cast<unsigned>(0));
    CHECK_EQ(sent.size(), after_start);

    // A Format List that is not a multiple of 4 bytes.
    FeedPdu(*server, CliprdrMsgType::kFormatList, 0, std::vector<uint8_t>{1, 2, 3});
    CHECK_EQ(server->remote_format_list_count(), static_cast<unsigned>(0));
    CHECK_EQ(sent.size(), after_start);

    // A completely bogus channel header is dropped too.
    const std::vector<uint8_t> junk = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02};
    server->OnChannelData(junk.data(), junk.size());
    CHECK_EQ(sent.size(), after_start);
}

// S10: the client's Temporary Directory PDU is recorded (where the server may
// deposit files copied to the client).
RTSC_TEST(cliprdr_server_temp_directory_recorded) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);

    ByteWriter body;
    for (char16_t c : std::u16string(u"C:\\temp\\client")) {
        body.u16le(static_cast<uint16_t>(c));
    }
    body.u16le(0);
    FeedPdu(*server, CliprdrMsgType::kTempDirectory, 0, body.take());

    CHECK(server->temp_directory() == std::string("C:\\temp\\client"));
    CHECK_EQ(server->temp_directory_count(), static_cast<unsigned>(1));
}

// S11: v1 default (file clip not enabled, no provider): every
// CB_FILECONTENTS_REQUEST answers FAIL (design §8).
RTSC_TEST(cliprdr_server_file_contents_fails_in_v1) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->Start();
    const size_t after_start = sent.size();

    FeedPdu(*server, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(3, 0, kFileContentsSize, 0, 8));
    CHECK_EQ(server->file_contents_request_received(), static_cast<unsigned>(1));
    CHECK_EQ(server->file_contents_request_rejected(), static_cast<unsigned>(1));
    CHECK_EQ(sent.size(), after_start + 1);
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK(resp.header.msg_type == CliprdrMsgType::kFileContentsResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

// S11: an enabled file clip without a provider still fails every request
// (direction-B store gate).
RTSC_TEST(cliprdr_server_file_contents_fails_without_provider) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->EnableFileClip();
    server->Start();

    FeedPdu(*server, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(3, 0, kFileContentsRange, 0, 64));
    CHECK_EQ(server->file_contents_request_rejected(), static_cast<unsigned>(1));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK(resp.header.msg_type == CliprdrMsgType::kFileContentsResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

// S12: with EnableFileClip and a provider the server serves a SIZE probe (the
// 64-bit file size) and a RANGE request.
RTSC_TEST(cliprdr_server_enable_file_clip_serves) {
    FakeClipboard clip;
    FakeProvider provider;
    rtsc::clipboard::FileInfo fi;
    fi.size = 0x100000123ULL;
    fi.name = u"big.bin";
    provider.files = {fi};
    provider.blocks = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}};
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->EnableFileClip();
    CHECK_EQ(server->file_clip_enabled(), true);
    // EnableFileClip ORs CB_STREAM_FILECLIP_ENABLED into the advertised caps.
    CHECK(server->server_flags() &
          static_cast<uint32_t>(rtsc::channel::kClipCapsStreamFileClip));
    CHECK(server->server_flags() &
          static_cast<uint32_t>(rtsc::channel::kClipCapsUseLongFormatNames));
    server->SetFileListProvider(&provider);
    server->Start();
    const std::vector<uint8_t> caps_data = DecodeChunk(sent[0]).data;
    // flags field sits at offset 12 of the caps PDU body.
    CHECK_EQ(ReadU32Le(std::vector<uint8_t>(caps_data.begin() + 12,
                                            caps_data.begin() + 16)),
             static_cast<uint32_t>(rtsc::channel::kClipCapsUseLongFormatNames |
                                   rtsc::channel::kClipCapsStreamFileClip));

    // SIZE probe: OK with the full 64-bit size.
    FeedPdu(*server, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(3, 0, kFileContentsSize, 0, 8));
    CHECK_EQ(server->file_contents_request_received(), static_cast<unsigned>(1));
    CHECK_EQ(server->file_contents_response_sent(), static_cast<unsigned>(1));
    const CliprdrPdu size_resp = DecodeChunk(sent.back());
    CHECK(size_resp.header.msg_type ==
          CliprdrMsgType::kFileContentsResponse);
    CHECK_EQ(size_resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    CHECK_EQ(size_resp.data.size(), static_cast<size_t>(12));  // streamID + size
    CHECK_EQ(ReadU64Le(std::vector<uint8_t>(size_resp.data.begin() + 4,
                                            size_resp.data.end())),
             static_cast<uint64_t>(0x100000123ULL));

    // RANGE request: OK with the requested bytes.
    FeedPdu(*server, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(4, 0, kFileContentsRange, 1, 3));
    const CliprdrPdu range_resp = DecodeChunk(sent.back());
    CHECK(range_resp.header.msg_type ==
          CliprdrMsgType::kFileContentsResponse);
    CHECK_EQ(range_resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    CHECK_EQ(range_resp.data.size(), static_cast<size_t>(7));  // streamID + 3
    CHECK(range_resp.data[4] == static_cast<uint8_t>(0xBB));
}

// S13: Start sends a Format List even when the local clipboard is empty (an
// empty format table is still a valid, sent Format List).
RTSC_TEST(cliprdr_server_start_sends_empty_format_list) {
    FakeClipboard clip;  // empty formats
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);

    server->Start();
    CHECK_EQ(sent.size(), static_cast<size_t>(3));
    const CliprdrPdu list = DecodeChunk(sent[2]);
    CHECK(list.header.msg_type == CliprdrMsgType::kFormatList);
    CHECK_EQ(list.header.data_len, static_cast<uint32_t>(0));
    CHECK(list.data.empty());
    CHECK_EQ(server->local_format_list_count(), static_cast<unsigned>(1));
}

// S1: an empty remote Format List is answered OK (not a protocol error).
RTSC_TEST(cliprdr_server_empty_client_format_list_responds_ok) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto server = MakeServer(&clip, sent);
    server->Start();
    const size_t after_start = sent.size();

    FeedPdu(*server, CliprdrMsgType::kFormatList, 0, {});
    CHECK_EQ(sent.size(), after_start + 1);
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatListResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
}

int main() { return rtsc::test::run_all("rtsc_cliprdr_server_tests"); }