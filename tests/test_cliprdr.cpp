// Clipboard virtual channel (cliprdr) structure layer ([MS-RDPECLIP] 2.2).

#include "rtsc/channel/cliprdr_client.h"
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

RTSC_TEST(cliprdr_header_parses) {
    // msgType = CB_FORMAT_LIST (2), flags = 0, dataLen = 8.
    const std::vector<uint8_t> h = {0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
                                    0x00};
    CliprdrHeader out;
    CHECK(CliprdrHeader::parse(h.data(), h.size(), out) == Status::Ok);
    CHECK(out.msg_type == CliprdrMsgType::kFormatList);
    CHECK_EQ(out.msg_flags, static_cast<uint16_t>(0));
    CHECK_EQ(out.data_len, static_cast<uint32_t>(8));
    CHECK(CliprdrHeader::parse(h.data(), 7, out) == Status::NeedMoreData);
}

RTSC_TEST(cliprdr_monitor_ready_pdu_round_trip) {
    const auto pdu = BuildCliprdrPdu(CliprdrMsgType::kMonitorReady, 0, {});
    CHECK_EQ(pdu.size(), static_cast<size_t>(8));
    CliprdrPdu out;
    CHECK(CliprdrPdu::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK(out.header.msg_type == CliprdrMsgType::kMonitorReady);
    CHECK(out.data.empty());
}

RTSC_TEST(cliprdr_format_list_round_trip) {
    CliprdrFormatList list;
    list.formats = {kCfUnicodeText, kCfDib, kCfHdrop};
    const auto payload = list.encode();
    CHECK_EQ(payload.size(), static_cast<size_t>(12));

    const auto pdu = BuildCliprdrPdu(CliprdrMsgType::kFormatList, 0, payload);
    CliprdrPdu out;
    CHECK(CliprdrPdu::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.header.data_len, static_cast<uint32_t>(12));

    CliprdrFormatList parsed;
    CHECK(CliprdrFormatList::parse(out.data, parsed) == Status::Ok);
    CHECK_EQ(parsed.formats.size(), static_cast<size_t>(3));
    CHECK_EQ(parsed.formats[0], static_cast<uint32_t>(kCfUnicodeText));
    CHECK_EQ(parsed.formats[2], static_cast<uint32_t>(kCfHdrop));
}

RTSC_TEST(cliprdr_format_list_rejects_ragged_length) {
    const std::vector<uint8_t> bad = {1, 0, 0, 0, 2, 0};  // 6 bytes, not a multiple of 4
    CliprdrFormatList list;
    CHECK(CliprdrFormatList::parse(bad, list) == Status::InvalidLength);
}

RTSC_TEST(cliprdr_format_data_request_round_trip) {
    CliprdrFormatDataRequest req;
    req.format_id = kCfUnicodeText;
    const auto payload = req.encode();

    const auto pdu =
        BuildCliprdrPdu(CliprdrMsgType::kFormatDataRequest, 0, payload);
    CliprdrPdu out;
    CHECK(CliprdrPdu::parse(pdu.data(), pdu.size(), out) == Status::Ok);

    CliprdrFormatDataRequest parsed;
    CHECK(CliprdrFormatDataRequest::parse(out.data, parsed) == Status::Ok);
    CHECK_EQ(parsed.format_id, static_cast<uint32_t>(kCfUnicodeText));
}

RTSC_TEST(cliprdr_format_data_response_carries_payload) {
    // A Unicode text response: "Hi\0" in UTF-16LE.
    const std::vector<uint8_t> text = {0x48, 0x00, 0x69, 0x00, 0x00, 0x00};
    const auto pdu = BuildCliprdrPdu(CliprdrMsgType::kFormatDataResponse,
                                     kClipResponseOk, text);
    CliprdrPdu out;
    CHECK(CliprdrPdu::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK(out.header.msg_type == CliprdrMsgType::kFormatDataResponse);
    CHECK_EQ(out.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    CHECK(out.data == text);
}

RTSC_TEST(cliprdr_pdu_rejects_truncated_payload) {
    // dataLen = 10 but only 4 bytes of payload follow.
    const std::vector<uint8_t> pdu = {0x02, 0x00, 0x00, 0x00, 0x0A, 0x00,
                                      0x00, 0x00, 0x01, 0x02, 0x03, 0x04};
    CliprdrPdu out;
    CHECK(CliprdrPdu::parse(pdu.data(), pdu.size(), out) == Status::NeedMoreData);
}

// ---- client channel handler ([MS-RDPECLIP] 1.3) ---------------------------

namespace {

// A test double for the local clipboard: it records writes and serves the
// formats/data the test configures.
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
        return true;
    }

    bool read_fails_ = false;
    std::vector<uint32_t> formats_;
    std::map<uint32_t, std::vector<uint8_t>> data_;
    unsigned write_count_ = 0;
};

// Decodes one sent channel chunk (CHANNEL_PDU_HEADER + cliprdr PDU) into the
// cliprdr PDU.
CliprdrPdu DecodeChunk(const std::vector<uint8_t>& chunk) {
    CliprdrPdu pdu;
    CHECK_EQ(chunk.size() >= ChannelPduHeader::kSize, true);
    const uint8_t* p = chunk.data() + ChannelPduHeader::kSize;
    const size_t n = chunk.size() - ChannelPduHeader::kSize;
    CHECK(CliprdrPdu::parse(p, n, pdu) == Status::Ok);
    return pdu;
}

// Wraps a cliprdr PDU in a channel message and feeds it to the client.
void FeedPdu(rtsc::channel::CliprdrClient& client, CliprdrMsgType type,
             uint16_t flags, const std::vector<uint8_t>& body) {
    const auto pdu = BuildCliprdrPdu(type, flags, body);
    for (const auto& chunk : FragmentChannelMessage(pdu)) {
        client.OnChannelData(chunk.data(), chunk.size());
    }
}

// Builds the payload of a server CB_CLIP_CAPS PDU with the given general flags.
std::vector<uint8_t> ServerCapsBody(uint32_t flags) {
    ByteWriter w;
    w.u16le(1);  // cCapabilitiesSets
    w.u16le(0);  // pad1
    w.u16le(1);  // capabilitySetType = CB_CAPSTYPE_GENERAL
    w.u16le(12);  // lengthCapability
    w.u32le(2);  // CB_CAPS_VERSION_2
    w.u32le(flags);
    return w.take();
}

void FeedServerCaps(rtsc::channel::CliprdrClient& client, uint32_t flags) {
    FeedPdu(client, CliprdrMsgType::kClipCaps, 0, ServerCapsBody(flags));
}

// Feeds the server Monitor Ready PDU ([MS-RDPECLIP] 2.2.2.2): it is sent by
// the server, and receiving it is what drives the client's initialization
// sequence ([MS-RDPECLIP] 1.3.2.1 step 3).
void FeedMonitorReady(rtsc::channel::CliprdrClient& client) {
    FeedPdu(client, CliprdrMsgType::kMonitorReady, 0, {});
}

// The message types of the PDUs the client sent, in order.
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

}  // namespace

// Regression for S6: the old code made Start() send a CB_MONITOR_READY PDU
// first. That violates [MS-RDPECLIP] 1.3.2.1 step 2 and 2.2.2.2, which define
// the Monitor Ready PDU as a server-to-client PDU.
RTSC_TEST(cliprdr_client_start_does_not_send_monitor_ready) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText, kCfDib};
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    FeedServerCaps(client, rtsc::channel::kClipCapsUseLongFormatNames);
    client.Start();

    // [MS-RDPECLIP] 2.2.2.2: "The Monitor Ready PDU is sent from the server to
    // the client". The client must never send one.
    CHECK_EQ(HasSentType(sent, CliprdrMsgType::kMonitorReady), false);
    CHECK_EQ(client.monitor_ready_count(), static_cast<unsigned>(0));
    // Nothing is sent before the server Monitor Ready PDU arrives: capabilities
    // and the format list answer it ([MS-RDPECLIP] 1.3.2.1 step 3).
    CHECK_EQ(sent.size(), static_cast<size_t>(0));
}

// [MS-RDPECLIP] 1.3.2.1 steps 3-5: on the server Monitor Ready PDU the client
// sends Clipboard Capabilities, then the Temporary Directory, then a Format
// List.
RTSC_TEST(cliprdr_client_monitor_ready_triggers_initialization_sequence) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText, kCfDib};
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.SetTemporaryDirectory("C:\\temp\\clipdata");

    FeedServerCaps(client, rtsc::channel::kClipCapsUseLongFormatNames);
    client.Start();
    CHECK_EQ(sent.size(), static_cast<size_t>(0));
    FeedMonitorReady(client);

    CHECK_EQ(client.monitor_ready_received_count(), static_cast<unsigned>(1));
    // The exact message-type sequence, independent of the payloads.
    const std::vector<CliprdrMsgType> want = {CliprdrMsgType::kClipCaps,
                                              CliprdrMsgType::kTempDirectory,
                                              CliprdrMsgType::kFormatList};
    CHECK(SentTypes(sent) == want);
    CHECK_EQ(sent.size(), static_cast<size_t>(3));

    const CliprdrPdu caps = DecodeChunk(sent[0]);
    CHECK_EQ(caps.header.data_len, static_cast<uint32_t>(16));
    // cCapabilitiesSets=1, pad1=0, type=1, length=12, version=2, flags=LONG.
    CHECK_BYTES(caps.data, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0C, 0x00, 0x02,
                0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00);
    CHECK_EQ(client.clip_caps_count(), static_cast<unsigned>(1));

    // [MS-RDPECLIP] 2.2.2.3: wszTempDir is a fixed 520-byte block holding a
    // null-terminated path; the unused space is filled with null characters.
    const CliprdrPdu temp = DecodeChunk(sent[1]);
    CHECK_EQ(temp.header.data_len, static_cast<uint32_t>(520));
    CHECK_EQ(temp.data.size(), static_cast<size_t>(520));
    const std::string path = "C:\\temp\\clipdata";
    const auto want_path = std::vector<uint8_t>([&] {
        std::vector<uint8_t> v;
        for (const char c : path) {
            v.push_back(static_cast<uint8_t>(c));
            v.push_back(0x00);
        }
        return v;
    }());
    CHECK(temp.data.size() >= want_path.size());
    CHECK(std::equal(want_path.begin(), want_path.end(), temp.data.begin()));
    CHECK_EQ(temp.data[want_path.size()], static_cast<uint8_t>(0));
    bool padding_is_null = true;
    for (size_t i = want_path.size() + 2; i < temp.data.size(); ++i) {
        if (temp.data[i] != 0) padding_is_null = false;
    }
    CHECK(padding_is_null);
    CHECK(client.local_temp_directory() == path);
    CHECK_EQ(client.temp_directory_sent_count(), static_cast<unsigned>(1));

    const CliprdrPdu list = DecodeChunk(sent[2]);
    // Two long format names (the server advertised CB_USE_LONG_FORMAT_NAMES):
    // formatId(4) + a single null wchar(2) each.
    CHECK_EQ(list.data.size(), static_cast<size_t>(2 * 6));
    CHECK_EQ(ReadU32Le(list.data), static_cast<uint32_t>(kCfUnicodeText));
}

// The initialization sequence runs once even if the server repeats the Monitor
// Ready PDU.
RTSC_TEST(cliprdr_client_initialization_sequence_runs_once) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.SetTemporaryDirectory("C:\\temp\\clipdata");

    FeedServerCaps(client, rtsc::channel::kClipCapsUseLongFormatNames);
    client.Start();
    FeedMonitorReady(client);
    const size_t after_first = sent.size();
    FeedMonitorReady(client);
    CHECK_EQ(sent.size(), after_first);
    CHECK_EQ(client.monitor_ready_received_count(), static_cast<unsigned>(2));
    CHECK_EQ(client.clip_caps_count(), static_cast<unsigned>(1));
}

// A Monitor Ready PDU that arrives before Start() (the channel is joined) is
// still answered, but only once Start() arms the client.
RTSC_TEST(cliprdr_client_monitor_ready_before_start_is_answered_on_start) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.SetTemporaryDirectory("C:\\temp\\clipdata");

    FeedServerCaps(client, rtsc::channel::kClipCapsUseLongFormatNames);
    FeedMonitorReady(client);
    CHECK_EQ(client.monitor_ready_received_count(), static_cast<unsigned>(1));

    client.Start();
    const std::vector<CliprdrMsgType> want = {CliprdrMsgType::kClipCaps,
                                              CliprdrMsgType::kTempDirectory,
                                              CliprdrMsgType::kFormatList};
    CHECK(SentTypes(sent) == want);
}

// [MS-RDPECLIP] 2.2.3.2: the Format List Response carries the server's verdict
// in msgFlags (CB_RESPONSE_OK 0x0001 / CB_RESPONSE_FAIL 0x0002). It must be
// observable and must not be confused with the response this client sends.
RTSC_TEST(cliprdr_client_format_list_response_is_observable) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    CHECK_EQ(client.format_list_response_received_count(),
             static_cast<unsigned>(0));

    FeedPdu(client, CliprdrMsgType::kFormatListResponse, kClipResponseOk, {});
    CHECK_EQ(client.format_list_response_received_count(),
             static_cast<unsigned>(1));
    CHECK_EQ(client.last_format_list_response_ok(), true);
    // The send-side counter (the responses this client sends to the server)
    // must not move because of an inbound response.
    CHECK_EQ(client.format_list_response_count(), static_cast<unsigned>(0));

    FeedPdu(client, CliprdrMsgType::kFormatListResponse, kClipResponseFail, {});
    CHECK_EQ(client.format_list_response_received_count(),
             static_cast<unsigned>(2));
    CHECK_EQ(client.last_format_list_response_ok(), false);
    CHECK_EQ(client.format_list_response_count(), static_cast<unsigned>(0));
}

// [MS-RDPECLIP] 2.2.2.1.1.1: CB_USE_LONG_FORMAT_NAMES must be set by both
// endpoints for the long format name variant to be used. Until the server
// capabilities arrive the client must not assume long names.
RTSC_TEST(cliprdr_client_long_format_names_defaults_to_short) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    CHECK_EQ(client.server_caps_received(), false);
    CHECK_EQ(client.long_format_names(), false);
}

RTSC_TEST(cliprdr_client_long_format_names_follow_server_capabilities) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    // The server does not advertise long format names: the negotiated variant
    // is the short one even though this client advertises the capability.
    FeedServerCaps(client, 0);
    CHECK_EQ(client.server_caps_received(), true);
    CHECK_EQ(client.long_format_names(), false);

    // A General Capability Set without the flag keeps it off.
    FeedServerCaps(client, rtsc::channel::kClipCapsCanLockClipData);
    CHECK_EQ(client.long_format_names(), false);
}

RTSC_TEST(cliprdr_client_long_format_names_negotiated_when_both_agree) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    FeedServerCaps(client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    CHECK_EQ(client.server_caps_received(), true);
    CHECK_EQ(client.long_format_names(), true);
    CHECK_EQ(client.server_flags(),
             static_cast<uint32_t>(rtsc::channel::kClipCapsUseLongFormatNames |
                                   rtsc::channel::kClipCapsStreamFileClip));
}

RTSC_TEST(cliprdr_client_short_format_list_responds_ok) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    FeedServerCaps(client, 0);
    CHECK_EQ(client.long_format_names(), false);

    ByteWriter body;
    body.u32le(kCfText);
    for (int i = 0; i < 32; ++i) body.u8(0);
    body.u32le(kCfUnicodeText);
    for (int i = 0; i < 32; ++i) body.u8(0);
    FeedPdu(client, CliprdrMsgType::kFormatList, 0, body.take());

    CHECK_EQ(client.remote_formats().size(), static_cast<size_t>(2));
    CHECK_EQ(client.remote_formats()[0], static_cast<uint32_t>(kCfText));
    CHECK_EQ(client.remote_formats()[1], static_cast<uint32_t>(kCfUnicodeText));
    // Eager sync: the response is followed by a data request for the preferred
    // format (CF_UNICODETEXT).
    CHECK_EQ(sent.size(), static_cast<size_t>(2));
    const CliprdrPdu resp = DecodeChunk(sent[0]);
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatListResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    const CliprdrPdu req = DecodeChunk(sent[1]);
    CHECK(req.header.msg_type == CliprdrMsgType::kFormatDataRequest);
    CHECK_EQ(req.data.size(), static_cast<size_t>(4));
    CHECK_EQ(ReadU32Le(req.data), static_cast<uint32_t>(kCfUnicodeText));
}

RTSC_TEST(cliprdr_client_long_format_list_parses_names) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    FeedServerCaps(client, rtsc::channel::kClipCapsUseLongFormatNames);

    ByteWriter body;
    // formatId = 0xC004, name = "Native" (UTF-16LE, null-terminated).
    body.u32le(0xC004);
    for (char16_t c : std::u16string(u"Native")) {
        body.u16le(static_cast<uint16_t>(c));
    }
    body.u16le(0);
    // formatId = 3 (Metafile), no name (a single null wchar).
    body.u32le(kCfBitmap);
    body.u16le(0);
    FeedPdu(client, CliprdrMsgType::kFormatList, 0, body.take());

    CHECK_EQ(client.remote_formats().size(), static_cast<size_t>(2));
    CHECK_EQ(client.remote_formats()[0], static_cast<uint32_t>(0xC004));
    CHECK_EQ(client.remote_formats()[1], static_cast<uint32_t>(kCfBitmap));
    CHECK_EQ(sent.size(), static_cast<size_t>(2));  // response + data request
    const CliprdrPdu resp = DecodeChunk(sent[0]);
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatListResponse);
}

RTSC_TEST(cliprdr_client_format_data_request_reads_local) {
    FakeClipboard clip;
    const std::vector<uint8_t> text = {0x48, 0x00, 0x69, 0x00, 0x00, 0x00};
    clip.data_[kCfUnicodeText] = text;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    ByteWriter body;
    body.u32le(kCfUnicodeText);
    FeedPdu(client, CliprdrMsgType::kFormatDataRequest, 0, body.take());

    CHECK_EQ(sent.size(), static_cast<size_t>(1));
    const CliprdrPdu resp = DecodeChunk(sent[0]);
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatDataResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    CHECK(resp.data == text);
}

RTSC_TEST(cliprdr_client_format_data_request_reports_fail_when_absent) {
    FakeClipboard clip;  // empty clipboard
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    ByteWriter body;
    body.u32le(kCfUnicodeText);
    FeedPdu(client, CliprdrMsgType::kFormatDataRequest, 0, body.take());

    CHECK_EQ(sent.size(), static_cast<size_t>(1));
    const CliprdrPdu resp = DecodeChunk(sent[0]);
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatDataResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

RTSC_TEST(cliprdr_client_format_data_response_writes_local) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    const std::vector<uint8_t> text = {0x48, 0x00, 0x69, 0x00, 0x00, 0x00};
    client.RequestRemoteFormat(kCfUnicodeText);
    FeedPdu(client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk, text);

    CHECK(clip.data_[kCfUnicodeText] == text);
    CHECK_EQ(clip.write_count_, static_cast<unsigned>(1));
}

RTSC_TEST(cliprdr_client_local_change_sends_format_list) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.SetTemporaryDirectory("C:\\temp\\clipdata");
    FeedServerCaps(client, rtsc::channel::kClipCapsUseLongFormatNames);
    client.Start();
    // The initialization sequence must complete before a local change is
    // reported ([MS-RDPECLIP] 1.3.2.1: the capability exchange comes first).
    FeedMonitorReady(client);
    const size_t after_start = sent.size();
    client.OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), after_start + 1);
    const CliprdrPdu list = DecodeChunk(sent.back());
    CHECK(list.header.msg_type == CliprdrMsgType::kFormatList);
}

RTSC_TEST(cliprdr_client_local_change_before_init_is_not_sent) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.Start();
    // No server Monitor Ready yet: a Format List may not be sent before the
    // capability exchange completes ([MS-RDPECLIP] 1.3.2.1).
    client.OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), static_cast<size_t>(0));
}

RTSC_TEST(cliprdr_client_remote_write_swallows_local_change) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.RequestRemoteFormat(kCfUnicodeText);
    const size_t after_request = sent.size();
    const std::vector<uint8_t> text = {0x41, 0x00, 0x00, 0x00};
    FeedPdu(client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk, text);
    CHECK_EQ(sent.size(), after_request);
    // The WM_CLIPBOARDUPDATE fired by applying the remote data must not be
    // echoed back to the server.
    client.OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), after_request);
}

RTSC_TEST(cliprdr_client_remote_write_swallows_repeated_local_change) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.SetTemporaryDirectory("C:\\temp\\clipdata");
    FeedServerCaps(client, 0);
    client.Start();
    FeedMonitorReady(client);
    const std::vector<uint8_t> text = {0x41, 0x00, 0x00, 0x00};
    client.RequestRemoteFormat(kCfUnicodeText);
    FeedPdu(client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk, text);
    const size_t after_write = sent.size();
    // A single write can fire several WM_CLIPBOARDUPDATE events; every one
    // caused by our own write must be swallowed.
    client.OnLocalClipboardChanged();
    client.OnLocalClipboardChanged();
    client.OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), after_write);
    // A genuinely different local clipboard is then reported.
    clip.data_[kCfUnicodeText] = {0x42, 0x00, 0x00, 0x00};
    client.OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), after_write + 1);
    const CliprdrPdu list = DecodeChunk(sent.back());
    CHECK(list.header.msg_type == CliprdrMsgType::kFormatList);
}

RTSC_TEST(cliprdr_client_remote_write_reports_when_format_set_changes) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.SetTemporaryDirectory("C:\\temp\\clipdata");
    FeedServerCaps(client, 0);
    client.Start();
    FeedMonitorReady(client);
    const std::vector<uint8_t> text = {0x41, 0x00, 0x00, 0x00};
    client.RequestRemoteFormat(kCfUnicodeText);
    FeedPdu(client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk, text);
    const size_t after_write = sent.size();
    client.OnLocalClipboardChanged();  // our own write: swallowed
    CHECK_EQ(sent.size(), after_write);
    // A genuinely different clipboard (a new format appears) is reported even
    // when the previously written data is unchanged.
    clip.formats_ = {kCfDib};
    client.OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), after_write + 1);
    const CliprdrPdu list = DecodeChunk(sent.back());
    CHECK(list.header.msg_type == CliprdrMsgType::kFormatList);
}

RTSC_TEST(cliprdr_client_remote_write_keeps_guard_on_read_failure) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.SetTemporaryDirectory("C:\\temp\\clipdata");
    FeedServerCaps(client, 0);
    client.Start();
    FeedMonitorReady(client);
    const std::vector<uint8_t> text = {0x41, 0x00, 0x00, 0x00};
    client.RequestRemoteFormat(kCfUnicodeText);
    FeedPdu(client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk, text);
    const size_t after_write = sent.size();
    // If the clipboard cannot be read the guard must stay armed (no echo).
    clip.read_fails_ = true;
    client.OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), after_write);
}

RTSC_TEST(cliprdr_client_zero_length_write_does_not_loop) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.SetTemporaryDirectory("C:\\temp\\clipdata");
    FeedServerCaps(client, 0);
    client.Start();
    FeedMonitorReady(client);
    // A remote zero-length write must still arm the guard.
    client.RequestRemoteFormat(kCfUnicodeText);
    FeedPdu(client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk, {});
    const size_t after_write = sent.size();
    // The WM_CLIPBOARDUPDATE from our own (empty) write is swallowed.
    client.OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), after_write);
    // A genuinely different non-empty clipboard is then reported.
    clip.data_[kCfUnicodeText] = {0x42, 0x00};
    client.OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), after_write + 1);
    const CliprdrPdu list = DecodeChunk(sent.back());
    CHECK(list.header.msg_type == CliprdrMsgType::kFormatList);
}

RTSC_TEST(cliprdr_client_temp_directory_recorded) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    ByteWriter body;
    for (char16_t c : std::u16string(u"C:\\temp\\clipdata")) {
        body.u16le(static_cast<uint16_t>(c));
    }
    body.u16le(0);
    FeedPdu(client, CliprdrMsgType::kTempDirectory, 0, body.take());

    CHECK(client.temp_directory() == std::string("C:\\temp\\clipdata"));
    CHECK_EQ(client.temp_directory_count(), static_cast<unsigned>(1));
}

RTSC_TEST(cliprdr_client_lock_unlock_tracked) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    ByteWriter body;
    body.u32le(0x1234);
    FeedPdu(client, CliprdrMsgType::kLockClipData, 0, body.take());
    CHECK_EQ(client.locked_clipdata_id(), static_cast<uint32_t>(0x1234));
    CHECK_EQ(client.lock_clipdata_count(), static_cast<unsigned>(1));
    ByteWriter unlock;
    unlock.u32le(0x1234);
    FeedPdu(client, CliprdrMsgType::kUnlockClipData, 0, unlock.take());
    CHECK_EQ(client.unlock_clipdata_count(), static_cast<unsigned>(1));
}

RTSC_TEST(cliprdr_client_truncated_pdu_is_buffered) {
    FakeClipboard clip;
    clip.data_[kCfUnicodeText] = {0x41, 0x00};
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

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
        client.OnChannelData(chunk.data(), chunk.size());
    }
    CHECK_EQ(sent.size(), static_cast<size_t>(0));  // incomplete
    {
        ByteWriter w;
        w.u32le(static_cast<uint32_t>(pdu.size()));
        w.u32le(static_cast<uint32_t>(rtsc::proto::kChannelLast));
        w.bytes(pdu.data() + half, pdu.size() - half);
        const auto chunk = w.take();
        client.OnChannelData(chunk.data(), chunk.size());
    }
    CHECK_EQ(sent.size(), static_cast<size_t>(1));
    const CliprdrPdu resp = DecodeChunk(sent[0]);
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatDataResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
}

RTSC_TEST(cliprdr_client_short_format_list_sent_when_not_negotiated) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.SetTemporaryDirectory("C:\\temp\\clipdata");
    FeedServerCaps(client, 0);
    client.Start();
    FeedMonitorReady(client);
    const CliprdrPdu list = DecodeChunk(sent.back());
    CHECK(list.header.msg_type == CliprdrMsgType::kFormatList);
    // Short format name: formatId(4) + formatName(32).
    CHECK_EQ(list.data.size(), static_cast<size_t>(36));
}

// ---- file contents structures ([MS-RDPECLIP] 2.2.4) ------------------------

namespace {

void WriteU64Le(ByteWriter& w, uint64_t v) {
    w.u32le(static_cast<uint32_t>(v & 0xFFFFFFFFu));
    w.u32le(static_cast<uint32_t>(v >> 32));
}

uint64_t ReadU64Le(const std::vector<uint8_t>& d) {
    return ReadU32Le(d) |
           (static_cast<uint64_t>(ReadU32Le(
                std::vector<uint8_t>(d.begin() + 4, d.end()))) << 32);
}

// Builds a provider that serves `bytes` from the first FileInfo.
class FakeProvider final : public rtsc::clipboard::FileListProvider {
 public:
    uint32_t file_count() const override {
        return static_cast<uint32_t>(files.size());
    }
    bool file_info(uint32_t index, rtsc::clipboard::FileInfo& out) const override {
        if (index >= files.size()) return false;
        if (fail_info_) {
            out = rtsc::clipboard::FileInfo{};
            return false;
        }
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
        const size_t n = std::min<size_t>(count, b.size() - static_cast<size_t>(offset));
        out.assign(b.begin() + static_cast<ptrdiff_t>(offset),
                   b.begin() + static_cast<ptrdiff_t>(offset + n));
        return true;
    }

    bool fail_reads_ = false;
    bool fail_info_ = false;
    std::vector<rtsc::clipboard::FileInfo> files;
    std::vector<std::vector<uint8_t>> blocks;
};

// A CliprdrClient factory. The client holds a copy of the lambda, so `sent`
// must outlive the client.
std::unique_ptr<rtsc::channel::CliprdrClient> MakeClient(
    FakeClipboard* clip, std::vector<std::vector<uint8_t>>& sent) {
    return std::make_unique<rtsc::channel::CliprdrClient>(
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

std::vector<uint8_t> FcrBodyLocked(uint32_t stream_id, int32_t lindex,
                                   uint32_t dw_flags, uint64_t position,
                                   uint32_t cb_requested, uint32_t clip_data_id) {
    CliprdrFileContentsRequest req;
    req.stream_id = stream_id;
    req.lindex = lindex;
    req.dw_flags = dw_flags;
    req.n_position_low = static_cast<uint32_t>(position & 0xFFFFFFFFu);
    req.n_position_high = static_cast<uint32_t>(position >> 32);
    req.cb_requested = cb_requested;
    req.has_clip_data_id = true;
    req.clip_data_id = clip_data_id;
    return req.encode();
}

std::vector<uint8_t> FcRespBody(uint32_t stream_id,
                                const std::vector<uint8_t>& data) {
    CliprdrFileContentsResponse resp;
    resp.stream_id = stream_id;
    resp.data = data;
    return resp.encode(true);
}

// Arms a client for file-clip serving: provider set, stream file clip enabled,
// and a (successful) server capability exchange so the serve gates are open.
std::unique_ptr<rtsc::channel::CliprdrClient> MakeServeClient(
    FakeClipboard* clip, FakeProvider* provider,
    std::vector<std::vector<uint8_t>>& sent) {
    auto client = MakeClient(clip, sent);
    client->EnableFileClip();
    client->SetFileListProvider(provider);
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    return client;
}

}  // namespace

// kFileContentsSize / kFileContentsRange ([MS-RDPECLIP] 2.2.4.1).
RTSC_TEST(cliprdr_file_contents_flags_values) {
    uint32_t size_flag = 0x00000001u;
    uint32_t range_flag = 0x00000002u;
    CHECK_EQ(static_cast<uint32_t>(kFileContentsSize), size_flag);
    CHECK_EQ(static_cast<uint32_t>(kFileContentsRange), range_flag);
}

RTSC_TEST(cliprdr_file_contents_request_parses_minimal) {
    ByteWriter w;
    w.u32le(0x01020304);  // streamID
    w.u32le(3);           // lindex
    w.u32le(kFileContentsSize);
    w.u32le(0);  // nPositionLow
    w.u32le(0);  // nPositionHigh
    w.u32le(8);  // cbRequested
    CliprdrFileContentsRequest out;
    CHECK(CliprdrFileContentsRequest::parse(w.take(), out) == Status::Ok);
    CHECK_EQ(out.stream_id, static_cast<uint32_t>(0x01020304));
    CHECK_EQ(out.lindex, 3);
    CHECK_EQ(out.dw_flags, static_cast<uint32_t>(kFileContentsSize));
    CHECK_EQ(out.cb_requested, static_cast<uint32_t>(8));
    CHECK_EQ(out.has_clip_data_id, false);
    CHECK_EQ(out.clip_data_id, static_cast<uint32_t>(0));
}

RTSC_TEST(cliprdr_file_contents_request_parses_clip_data_id) {
    // Canonical 28-byte request: the fixed header followed by clipDataId.
    // There is NO presence field on the wire ([MS-RDPECLIP] 2.2.5.3).
    ByteWriter w;
    w.u32le(5);
    w.u32le(1);
    w.u32le(kFileContentsRange);
    w.u32le(0x100);
    w.u32le(0);
    w.u32le(64 * 1024);
    w.u32le(0x11223344);  // clipDataId
    CliprdrFileContentsRequest out;
    CHECK(CliprdrFileContentsRequest::parse(w.take(), out) == Status::Ok);
    CHECK_EQ(out.stream_id, static_cast<uint32_t>(5));
    CHECK_EQ(out.has_clip_data_id, true);
    CHECK_EQ(out.clip_data_id, static_cast<uint32_t>(0x11223344));
}

// F1/r4: only 24 (no clipDataId) and 28 (id present) are legal; every other
// length in 20..40 is InvalidLength.
RTSC_TEST(cliprdr_file_contents_request_rejects_invalid_lengths) {
    std::vector<uint8_t> body;
    {
        ByteWriter w;
        w.u32le(1);
        w.u32le(0);
        w.u32le(1);
        w.u32le(0);
        w.u32le(0);
        w.u32le(8);
        body = w.take();
    }
    CliprdrFileContentsRequest out;
    CHECK(CliprdrFileContentsRequest::parse(body, out) == Status::Ok);
    for (size_t n = 20; n <= 40; ++n) {
        if (n == 24 || n == 28) continue;  // the two legal sizes
        std::vector<uint8_t> bad = body;
        bad.resize(n);
        CHECK(CliprdrFileContentsRequest::parse(bad, out) == Status::InvalidLength);
    }
}

// r2: a bare 24-byte RANGE request round-trips.
RTSC_TEST(cliprdr_file_contents_request_range_24b_round_trip) {
    CliprdrFileContentsRequest req;
    req.stream_id = 2;
    req.lindex = 0;
    req.dw_flags = kFileContentsRange;
    req.n_position_low = 0x1000;
    req.n_position_high = 0;
    req.cb_requested = 1024;
    const auto blob = req.encode();
    CHECK_EQ(blob.size(), static_cast<size_t>(24));
    CliprdrFileContentsRequest out;
    CHECK(CliprdrFileContentsRequest::parse(blob, out) == Status::Ok);
    CHECK_EQ(out.dw_flags, static_cast<uint32_t>(kFileContentsRange));
    CHECK_EQ(out.has_clip_data_id, false);
    CHECK_EQ(out.cb_requested, static_cast<uint32_t>(1024));
}

RTSC_TEST(cliprdr_file_contents_request_encode_round_trip) {
    CliprdrFileContentsRequest req;
    req.stream_id = 7;
    req.lindex = 2;
    req.dw_flags = kFileContentsSize;
    req.n_position_low = 0x1000;
    req.n_position_high = 0x2000;
    req.cb_requested = 8;
    req.has_clip_data_id = true;
    req.clip_data_id = 0x55;
    const auto blob = req.encode();
    CHECK_EQ(blob.size(), static_cast<size_t>(28));
    CliprdrFileContentsRequest out;
    CHECK(CliprdrFileContentsRequest::parse(blob, out) == Status::Ok);
    CHECK_EQ(out.stream_id, static_cast<uint32_t>(7));
    CHECK_EQ(out.n_position_low, static_cast<uint32_t>(0x1000));
    CHECK_EQ(out.n_position_high, static_cast<uint32_t>(0x2000));
    CHECK_EQ(out.clip_data_id, static_cast<uint32_t>(0x55));
}

RTSC_TEST(cliprdr_file_contents_response_encode_ok) {
    CliprdrFileContentsResponse resp;
    resp.stream_id = 9;
    resp.data = {1, 2, 3, 4};
    const auto blob = resp.encode(true);
    // streamID(4) + data; the PDU header carries the flags.
    CHECK_EQ(blob.size(), static_cast<size_t>(8));
    CHECK_EQ(ReadU32Le(blob), static_cast<uint32_t>(9));
}

RTSC_TEST(cliprdr_file_contents_response_parse) {
    ByteWriter w;
    w.u32le(9);
    w.u8(0xAA);
    w.u8(0xBB);
    CliprdrFileContentsResponse out;
    CHECK(CliprdrFileContentsResponse::parse(w.take(), true, out) == Status::Ok);
    CHECK_EQ(out.stream_id, static_cast<uint32_t>(9));
    CHECK_EQ(out.data.size(), static_cast<size_t>(2));
    CHECK_EQ(out.data[0], static_cast<uint8_t>(0xAA));
    CHECK_EQ(out.data[1], static_cast<uint8_t>(0xBB));
}

// A FAIL response carries no useful payload ([MS-RDPECLIP] 2.2.4.2).
RTSC_TEST(cliprdr_file_contents_response_parse_drops_payload_on_fail) {
    ByteWriter w;
    w.u32le(9);
    w.u32le(0xAA);
    CliprdrFileContentsResponse out;
    CHECK(CliprdrFileContentsResponse::parse(w.take(), false, out) == Status::Ok);
    CHECK_EQ(out.stream_id, static_cast<uint32_t>(9));
    CHECK(out.data.empty());
}

RTSC_TEST(cliprdr_file_descriptor_parse) {
    std::vector<uint8_t> raw(CliprdrFileDescriptor::kSize, 0);
    {
        ByteWriter w;
        w.u32le(kFileDescriptorSize | kFileDescriptorAttributes);
        for (size_t i = 0; i < 32; ++i) w.u8(0);
        w.u32le(0x10);  // dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY
        for (size_t i = 0; i < 16; ++i) w.u8(0);
        WriteU64Le(w, 0x1F2A0B3C);
        w.u32le(0x00000001);  // nFileSizeHigh
        w.u32le(0x23456789);  // nFileSizeLow
        for (char16_t c : std::u16string(u"docs\\report.txt")) {
            w.u16le(static_cast<uint16_t>(c));
        }
        w.u16le(0);
        const auto head = w.take();
        CHECK(head.size() <= raw.size());
        std::copy(head.begin(), head.end(), raw.begin());
    }
    ByteReader r(raw.data(), raw.size());
    CliprdrFileDescriptor out;
    CHECK(CliprdrFileDescriptor::parse(r, out) == Status::Ok);
    CHECK_EQ(out.dw_flags,
             static_cast<uint32_t>(kFileDescriptorSize |
                                   kFileDescriptorAttributes));
    CHECK_EQ(out.file_attributes, static_cast<uint32_t>(0x10));
    CHECK(out.is_directory());
    CHECK_EQ(out.last_write_time, static_cast<uint64_t>(0x1F2A0B3C));
    CHECK_EQ(out.file_size, static_cast<uint64_t>(0x0000000123456789ULL));
    CHECK(out.file_name == std::u16string(u"docs\\report.txt"));
}

// r13: without FD_FILESIZE the size fields are not meaningful and must not be
// misread.
RTSC_TEST(cliprdr_file_descriptor_only_reads_size_with_flag) {
    std::vector<uint8_t> raw(CliprdrFileDescriptor::kSize, 0);
    {
        ByteWriter w;
        w.u32le(kFileDescriptorAttributes);  // no FD_FILESIZE
        for (size_t i = 0; i < 32; ++i) w.u8(0);
        w.u32le(0);
        for (size_t i = 0; i < 16; ++i) w.u8(0);
        WriteU64Le(w, 0);
        w.u32le(0x00000002);
        w.u32le(0x34567890);
        for (char16_t c : std::u16string(u"n.txt")) {
            w.u16le(static_cast<uint16_t>(c));
        }
        w.u16le(0);
        const auto head = w.take();
        std::copy(head.begin(), head.end(), raw.begin());
    }
    ByteReader r(raw.data(), raw.size());
    CliprdrFileDescriptor out;
    CHECK(CliprdrFileDescriptor::parse(r, out) == Status::Ok);
    CHECK_EQ(out.file_size, static_cast<uint64_t>(0));
    // The same byte layout with FD_FILESIZE set is read as the real size.
    ByteWriter w2;
    w2.u32le(kFileDescriptorSize | kFileDescriptorAttributes);
    for (size_t i = 0; i < 32; ++i) w2.u8(0);
    w2.u32le(0);
    for (size_t i = 0; i < 16; ++i) w2.u8(0);
    WriteU64Le(w2, 0);
    w2.u32le(0x00000002);
    w2.u32le(0x34567890);
    for (char16_t c : std::u16string(u"n.txt")) {
        w2.u16le(static_cast<uint16_t>(c));
    }
    w2.u16le(0);
    std::vector<uint8_t> raw2(CliprdrFileDescriptor::kSize, 0);
    const auto head2 = w2.take();
    std::copy(head2.begin(), head2.end(), raw2.begin());
    ByteReader r2(raw2.data(), raw2.size());
    CliprdrFileDescriptor out2;
    CHECK(CliprdrFileDescriptor::parse(r2, out2) == Status::Ok);
    CHECK_EQ(out2.file_size, static_cast<uint64_t>(0x0000000234567890ULL));
}

// r12: a truncated descriptor cannot be parsed.
RTSC_TEST(cliprdr_file_descriptor_rejects_truncated) {
    std::vector<uint8_t> raw(CliprdrFileDescriptor::kSize, 0);
    raw.resize(100);  // header plus a handful of name bytes
    ByteReader r(raw.data(), raw.size());
    CliprdrFileDescriptor out;
    CHECK(CliprdrFileDescriptor::parse(r, out) == Status::NeedMoreData);
}

// cFileName is 520 bytes (260 UTF-16 code units including the null): no null
// terminator within the field is a malformed descriptor.
RTSC_TEST(cliprdr_file_descriptor_rejects_unterminated_name) {
    ByteWriter w;
    w.u32le(0);
    for (size_t i = 0; i < 32; ++i) w.u8(0);
    w.u32le(0);
    for (size_t i = 0; i < 16; ++i) w.u8(0);
    WriteU64Le(w, 0);
    w.u32le(0);
    w.u32le(0);
    for (size_t i = 0; i < 260; ++i) w.u16le(static_cast<uint16_t>(0x41));
    const auto raw = w.take();
    CHECK_EQ(raw.size(), static_cast<size_t>(CliprdrFileDescriptor::kSize));
    ByteReader r(raw.data(), raw.size());
    CliprdrFileDescriptor out;
    CHECK(CliprdrFileDescriptor::parse(r, out) == Status::InvalidField);
}

RTSC_TEST(cliprdr_file_descriptor_encode_round_trip) {
    CliprdrFileDescriptor d;
    d.dw_flags = kFileDescriptorSize | kFileDescriptorAttributes;
    d.file_attributes = 0x20;
    d.last_write_time = 12345;
    d.file_size = 0x123456789ABCULL;
    d.file_name = u"照片.png";
    ByteWriter w;
    CHECK_EQ(d.write(w), true);
    CHECK_EQ(w.size(), CliprdrFileDescriptor::kSize);
    ByteReader r(w.data().data(), w.size());
    CliprdrFileDescriptor out;
    CHECK(CliprdrFileDescriptor::parse(r, out) == Status::Ok);
    CHECK_EQ(out.file_size, static_cast<uint64_t>(0x123456789ABCULL));
    CHECK(out.file_name == std::u16string(u"照片.png"));
}

RTSC_TEST(cliprdr_file_descriptor_write_rejects_long_name) {
    CliprdrFileDescriptor d;
    d.file_name.assign(260, u'A');  // 261 units with the null > 260 limit
    ByteWriter w;
    CHECK_EQ(d.write(w), false);
    CHECK_EQ(w.size(), static_cast<size_t>(0));
}

RTSC_TEST(cliprdr_file_list_round_trip) {
    CliprdrFileList list;
    CliprdrFileDescriptor a;
    a.dw_flags = kFileDescriptorSize | kFileDescriptorAttributes;
    a.last_write_time = 1;
    a.file_size = 100;
    a.file_name = u"a.txt";
    CliprdrFileDescriptor b;
    b.dw_flags = kFileDescriptorSize | kFileDescriptorAttributes;
    b.last_write_time = 2;
    b.file_size = 0;
    b.file_name = u"b.bin";
    list.files = {a, b};
    const auto payload = list.encode();
    CHECK_EQ(payload.size(), static_cast<size_t>(4 + 2 * CliprdrFileDescriptor::kSize));
    CliprdrFileList out;
    CHECK(CliprdrFileList::parse(payload, out) == Status::Ok);
    CHECK_EQ(out.files.size(), static_cast<size_t>(2));
    CHECK(out.files[0].file_name == std::u16string(u"a.txt"));
    CHECK_EQ(out.files[0].file_size, static_cast<uint64_t>(100));
    CHECK_EQ(out.files[1].file_size, static_cast<uint64_t>(0));
}

// cItems x 592 must not overflow: a huge count over a tiny payload is
// rejected without a multiplication overflow.
RTSC_TEST(cliprdr_file_list_rejects_citems_overflow) {
    ByteWriter w;
    w.u32le(0xFFFFFFFF);
    CliprdrFileList out;
    CHECK(CliprdrFileList::parse(w.take(), out) == Status::InvalidLength);
}

RTSC_TEST(cliprdr_file_list_rejects_ragged_tail) {
    std::vector<uint8_t> body;
    {
        CliprdrFileList list;
        CliprdrFileDescriptor d;
        d.file_name = u"x";
        list.files = {d};
        body = list.encode();
    }
    body.push_back(0);
    CliprdrFileList out;
    CHECK(CliprdrFileList::parse(body, out) == Status::InvalidLength);
}

RTSC_TEST(cliprdr_file_list_empty_is_valid) {
    ByteWriter w;
    w.u32le(0);
    CliprdrFileList out;
    CHECK(CliprdrFileList::parse(w.take(), out) == Status::Ok);
    CHECK(out.files.empty());
}

RTSC_TEST(cliprdr_file_group_descriptor_constants) {
    CHECK(std::u16string(kFileGroupDescriptorName) ==
          std::u16string(u"FileGroupDescriptorW"));
    uint32_t de_facto_id = 0x046C0000u;
    CHECK_EQ(static_cast<uint32_t>(kDeFactoFileListFormatId), de_facto_id);
}

// ---- serve side: answering CB_FILECONTENTS_REQUEST -------------------------

// S-cap: stream file clip is off by default and toggled by EnableFileClip().
RTSC_TEST(cliprdr_client_file_clip_capability_default_off) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    CHECK_EQ(client->client_flags(),
             static_cast<uint32_t>(rtsc::channel::kClipCapsUseLongFormatNames));
    CHECK_EQ(client->file_clip_enabled(), false);
    CHECK_EQ(client->huge_file_support(), false);
}

// S-cap: EnableFileClip() ORs CB_STREAM_FILECLIP_ENABLED (0x04) into the
// advertised general flags; the HugeFile bit stays independent and off.
RTSC_TEST(cliprdr_client_enable_file_clip_sets_capability) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->SetTemporaryDirectory("C:\\temp\\clipdata");
    client->EnableFileClip();
    CHECK_EQ(client->file_clip_enabled(), true);
    CHECK_EQ(client->client_flags(),
             static_cast<uint32_t>(rtsc::channel::kClipCapsUseLongFormatNames |
                                   rtsc::channel::kClipCapsStreamFileClip));
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                                rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    const CliprdrPdu caps = DecodeChunk(sent[0]);
    // General flags field: length(4)+version(4)+flags(4) at offset 8.
    CHECK_EQ(ReadU32Le(std::vector<uint8_t>(caps.data.begin() + 12,
                                            caps.data.begin() + 16)),
             static_cast<uint32_t>(rtsc::channel::kClipCapsUseLongFormatNames |
                                   rtsc::channel::kClipCapsStreamFileClip));
}

RTSC_TEST(cliprdr_client_huge_file_support_is_independent) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    CHECK_EQ(client->huge_file_support(), false);
    client->EnableHugeFileSupport();
    CHECK_EQ(client->huge_file_support(), true);
    CHECK_EQ(client->client_flags(),
             static_cast<uint32_t>(rtsc::channel::kClipCapsUseLongFormatNames |
                                   rtsc::channel::kClipCapsStreamFileClip |
                                   rtsc::channel::kClipCapsHugeFileSupport));
}

// S1: a SIZE probe answers OK with the 64-bit file size regardless of huge
// support ([MS-RDPECLIP] 2.2.4.1, F13/F15).
RTSC_TEST(cliprdr_serve_size_returns_u64) {
    FakeClipboard clip;
    FakeProvider provider;
    rtsc::clipboard::FileInfo fi;
    fi.size = 0x100000123ULL;
    fi.name = u"big.bin";
    provider.files = {fi};
    provider.blocks = {{}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(3, 0, kFileContentsSize, 0, 8));

    CHECK_EQ(client->file_contents_request_received(), static_cast<unsigned>(1));
    CHECK_EQ(client->file_contents_response_sent(), static_cast<unsigned>(1));
    CHECK_EQ(sent.size(), static_cast<size_t>(1));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK(resp.header.msg_type == CliprdrMsgType::kFileContentsResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    CHECK_EQ(resp.data.size(), static_cast<size_t>(12));  // streamID(4) + size(8)
    const std::vector<uint8_t> size_bytes(resp.data.begin() + 4, resp.data.end());
    CHECK_EQ(ReadU64Le(size_bytes), static_cast<uint64_t>(0x100000123ULL));
}

// Serve F15: an empty file answers SIZE OK with an 8-byte zero size.
RTSC_TEST(cliprdr_serve_size_empty_file_is_valid) {
    FakeClipboard clip;
    FakeProvider provider;
    rtsc::clipboard::FileInfo fi;
    fi.size = 0;
    fi.name = u"empty";
    provider.files = {fi};
    provider.blocks = {{}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(4, 0, kFileContentsSize, 0, 8));

    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    const std::vector<uint8_t> size_bytes(resp.data.begin() + 4, resp.data.end());
    CHECK_EQ(ReadU64Le(size_bytes), static_cast<uint64_t>(0));
}

// S2: a RANGE probe answers OK with the requested bytes.
RTSC_TEST(cliprdr_serve_range_returns_bytes) {
    FakeClipboard clip;
    FakeProvider provider;
    rtsc::clipboard::FileInfo fi;
    fi.size = 4;
    fi.name = u"x";
    provider.files = {fi};
    provider.blocks = {{0x11, 0x22, 0x33, 0x44}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(5, 0, kFileContentsRange, 0, 4));

    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    CHECK_EQ(resp.data.size(), static_cast<size_t>(8));  // streamID + 4 bytes
    const std::vector<uint8_t> bytes(resp.data.begin() + 4, resp.data.end());
    CHECK(bytes == std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}));
}

// S3/F1: a malformed request body is dropped (no response) and counted.
RTSC_TEST(cliprdr_serve_drops_malformed_request) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 1, u"x", false}};
    provider.blocks = {{}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    std::vector<uint8_t> body = FcrBody(6, 0, kFileContentsSize, 0, 8);
    body.resize(23);
    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0, body);
    CHECK_EQ(client->file_contents_request_received(), static_cast<unsigned>(1));
    CHECK_EQ(client->file_contents_request_rejected(), static_cast<unsigned>(1));
    CHECK_EQ(sent.size(), static_cast<size_t>(0));
    for (size_t n : {25u, 26u, 27u}) {
        body = FcrBody(6, 0, kFileContentsSize, 0, 8);
        body.resize(n);
        FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0, body);
    }
    CHECK_EQ(client->file_contents_request_rejected(), static_cast<unsigned>(4));
    CHECK_EQ(sent.size(), static_cast<size_t>(0));
}

// S4/F2: an inbound request carrying msgFlags is ignored (loose), never served.
RTSC_TEST(cliprdr_serve_ignores_request_with_flags) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 1, u"x", false}};
    provider.blocks = {{0x11}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, kClipResponseOk,
            FcrBody(7, 0, kFileContentsRange, 0, 1));
    CHECK_EQ(sent.size(), static_cast<size_t>(0));
    CHECK_EQ(client->file_contents_request_rejected(), static_cast<unsigned>(1));
}

// S5/F5: dwFlags with bits outside SIZE|RANGE is refused.
RTSC_TEST(cliprdr_serve_fails_bad_flags) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 1, u"x", false}};
    provider.blocks = {{0x11}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(8, 0, 0x80000000u, 0, 8));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK(resp.header.msg_type == CliprdrMsgType::kFileContentsResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
    CHECK_EQ(client->file_contents_request_rejected(), static_cast<unsigned>(1));
    CHECK_EQ(client->file_contents_response_sent(), static_cast<unsigned>(1));
}

// S6/F6: a SIZE probe must ask for exactly 8 bytes at position 0.
RTSC_TEST(cliprdr_serve_fails_size_with_bad_cb_or_position) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 8, u"x", false}};
    provider.blocks = {{0}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(9, 0, kFileContentsSize, 0, 4));
    CHECK_EQ(DecodeChunk(sent.back()).header.msg_flags,
             static_cast<uint16_t>(kClipResponseFail));
    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(10, 0, kFileContentsSize, 1, 8));
    CHECK_EQ(DecodeChunk(sent.back()).header.msg_flags,
             static_cast<uint16_t>(kClipResponseFail));
}

// S7/F7: an out-of-range lindex is refused.
RTSC_TEST(cliprdr_serve_fails_out_of_range_lindex) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 1, u"x", false}};
    provider.blocks = {{0x11}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(11, 5, kFileContentsSize, 0, 8));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

// S8/F8: a request carrying clipDataId is only served when we advertised
// CB_CAN_LOCK_CLIPDATA and the id matches the locked id. This client never
// advertises CAN_LOCK, so the request is always refused.
RTSC_TEST(cliprdr_serve_fails_clip_data_id_without_can_lock) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 1, u"x", false}};
    provider.blocks = {{0x11}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    ByteWriter lock_body;
    lock_body.u32le(0x22);
    FeedPdu(*client, CliprdrMsgType::kLockClipData, 0, lock_body.take());
    CHECK_EQ(client->locked_clipdata_id(), static_cast<uint32_t>(0x22));

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBodyLocked(12, 0, kFileContentsRange, 0, 1, 0x22));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

// S9/F9: once our Format List was rejected, every file contents request fails.
RTSC_TEST(cliprdr_serve_format_list_rejected_fails_all) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 1, u"x", false}};
    provider.blocks = {{0x11}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFormatListResponse, kClipResponseFail, {});
    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(13, 0, kFileContentsSize, 0, 8));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
    // A later, perfectly valid request still fails.
    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(14, 0, kFileContentsSize, 0, 8));
    CHECK_EQ(DecodeChunk(sent.back()).header.msg_flags,
             static_cast<uint16_t>(kClipResponseFail));
}

// S10/F10: a read failure answers FAIL.
RTSC_TEST(cliprdr_serve_fails_read_error) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 4, u"x", false}};
    provider.blocks = {{0x11, 0x22, 0x33, 0x44}};
    provider.fail_reads_ = true;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(15, 0, kFileContentsRange, 0, 4));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

// S11/F11: EOF semantics of a range request.
RTSC_TEST(cliprdr_serve_range_eof_semantics) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 4, u"x", false}};
    provider.blocks = {{0x11, 0x22, 0x33, 0x44}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    // offset == size: OK with an empty range.
    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(16, 0, kFileContentsRange, 4, 4));
    {
        const CliprdrPdu resp = DecodeChunk(sent.back());
        CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
        CHECK_EQ(resp.data.size(), static_cast<size_t>(4));  // streamID only
    }
    // offset > size: FAIL.
    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(17, 0, kFileContentsRange, 5, 4));
    CHECK_EQ(DecodeChunk(sent.back()).header.msg_flags,
             static_cast<uint16_t>(kClipResponseFail));
    // offset + count > size: OK, truncated at EOF.
    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(18, 0, kFileContentsRange, 3, 100));
    {
        const CliprdrPdu resp = DecodeChunk(sent.back());
        CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
        CHECK_EQ(resp.data.size(), static_cast<size_t>(5));  // streamID + 1 byte
        CHECK_EQ(resp.data[4], static_cast<uint8_t>(0x44));
    }
}

// S12/F12: a zero-length range is refused.
RTSC_TEST(cliprdr_serve_fails_zero_cb) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 4, u"x", false}};
    provider.blocks = {{0x11}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(19, 0, kFileContentsRange, 0, 0));
    CHECK_EQ(DecodeChunk(sent.back()).header.msg_flags,
             static_cast<uint16_t>(kClipResponseFail));
}

// S13/F14: a range larger than the serve cap is refused.
RTSC_TEST(cliprdr_serve_fails_oversized_request) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 0x200000, u"big", false}};
    provider.blocks = {{}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(20, 0, kFileContentsRange, 0, 1024 * 1024 + 1));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

// S/F13: without huge-file support a range position >= 2^32 is refused,
// while a SIZE probe still returns the full 64-bit size.
RTSC_TEST(cliprdr_serve_rejects_huge_position_without_huge_support) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 0x100000000ULL, u"huge", false}};
    provider.blocks = {{}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(21, 0, kFileContentsRange, 0x100000000ULL, 4));
    CHECK_EQ(DecodeChunk(sent.back()).header.msg_flags,
             static_cast<uint16_t>(kClipResponseFail));
    // SIZE is unaffected by the huge gate.
    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(22, 0, kFileContentsSize, 0, 8));
    {
        const CliprdrPdu resp = DecodeChunk(sent.back());
        CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
        CHECK_EQ(resp.data.size(), static_cast<size_t>(12));
    }
}

// Direction B store gate: without a provider every request fails.
RTSC_TEST(cliprdr_serve_fails_without_provider) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(23, 0, kFileContentsSize, 0, 8));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(24, 0, kFileContentsRange, 0, 4));
    CHECK_EQ(DecodeChunk(sent.back()).header.msg_flags,
             static_cast<uint16_t>(kClipResponseFail));
}

// ---- take side: requesting a remote file -----------------------------------

namespace {

// A server Format List that carries only the file-clip format, so the eager
// sync skips it (PickPreferredFormat must jump file formats).
void FeedFileOnlyFormatList(rtsc::channel::CliprdrClient& client,
                            uint32_t file_format_id) {
    ByteWriter w;
    w.u32le(file_format_id);
    for (char16_t c : std::u16string(u"FileGroupDescriptorW")) {
        w.u16le(static_cast<uint16_t>(c));
    }
    w.u16le(0);
    FeedPdu(client, CliprdrMsgType::kFormatList, 0, w.take());
}

// A server Format List carrying a text format plus the file-clip format.
void FeedTextAndFileFormatList(rtsc::channel::CliprdrClient& client,
                               uint32_t file_format_id) {
    ByteWriter w;
    w.u32le(kCfUnicodeText);
    w.u16le(0);
    w.u32le(file_format_id);
    for (char16_t c : std::u16string(u"FileGroupDescriptorW")) {
        w.u16le(static_cast<uint16_t>(c));
    }
    w.u16le(0);
    FeedPdu(client, CliprdrMsgType::kFormatList, 0, w.take());
}

}  // namespace

// T1: RequestRemoteFileList sends nothing until the server advertises
// CB_STREAM_FILECLIP_ENABLED.
RTSC_TEST(cliprdr_take_request_file_list_requires_server_file_clip) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    client->SetTemporaryDirectory("C:\\temp\\clipdata");
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    CHECK_EQ(client->remote_file_list_format_id(), static_cast<uint32_t>(0x0F00));
    const size_t before = sent.size();
    client->RequestRemoteFileList();
    CHECK_EQ(sent.size(), before);
}

// T2: with 0x04 negotiated and the FGDW format recognised, the request sends a
// Format Data Request for the file-list format id. The eager sync must not
// request the file format on its own.
RTSC_TEST(cliprdr_take_request_file_list_sends_format_data_request) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    client->SetTemporaryDirectory("C:\\temp\\clipdata");
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    // Only the Format List Response was sent: no eager data request for the
    // file format.
    CHECK_EQ(sent.size(), static_cast<size_t>(4));
    CHECK(DecodeChunk(sent.back()).header.msg_type ==
          CliprdrMsgType::kFormatListResponse);

    client->RequestRemoteFileList();
    const CliprdrPdu req = DecodeChunk(sent.back());
    CHECK(req.header.msg_type == CliprdrMsgType::kFormatDataRequest);
    CHECK_EQ(ReadU32Le(req.data), static_cast<uint32_t>(0x0F00));
}

// T3: a Format Data Response for the file-list format parses the FILELIST and
// never touches the local clipboard.
RTSC_TEST(cliprdr_take_file_list_response_parses_without_clipboard_write) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    client->SetTemporaryDirectory("C:\\temp\\clipdata");
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();

    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.dw_flags = 0x6;
    f.file_size = 10;
    f.file_name = u"a.txt";
    CliprdrFileDescriptor d;
    d.dw_flags = 0x6;
    d.file_attributes = 0x10;
    d.file_name = u"dir";
    list.files = {f, d};
    const auto payload = list.encode();

    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            payload);

    CHECK_EQ(client->remote_file_list_received(), static_cast<unsigned>(1));
    CHECK_EQ(client->remote_file_list().size(), static_cast<size_t>(2));
    CHECK(client->remote_file_list()[0].file_name == std::u16string(u"a.txt"));
    CHECK_EQ(client->remote_file_list()[1].is_directory(), true);
    CHECK_EQ(client->have_remote_file_list(), true);
    CHECK_EQ(clip.write_count_, static_cast<unsigned>(0));
    CHECK_EQ(clip.data_.count(0x0F00), static_cast<size_t>(0));
}

// T4: RequestRemoteFile requires the negotiated file clip bit.
RTSC_TEST(cliprdr_take_request_remote_file_requires_negotiation) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    client->SetTemporaryDirectory("C:\\temp\\clipdata");
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames);
    client->Start();
    FeedMonitorReady(*client);
    const size_t before = sent.size();

    bool called = false;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool) { called = true; }),
             false);
    CHECK_EQ(called, false);
    CHECK_EQ(sent.size(), before);
}

// T5: only one file transfer is in flight (kMaxInflightFileOps = 1).
RTSC_TEST(cliprdr_take_request_remote_file_single_inflight) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());

    const auto first_done = [](uint32_t, std::u16string, uint64_t,
                               const std::vector<uint8_t>&, bool) {};
    CHECK_EQ(client->RequestRemoteFile(0, first_done), true);
    CHECK_EQ(client->RequestRemoteFile(0, first_done), false);
}

// T6: a directory descriptor is not downloadable (RequestRemoteFile fails).
RTSC_TEST(cliprdr_take_request_remote_file_directory_fails) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor d;
    d.file_attributes = 0x10;
    d.file_name = u"dir";
    list.files = {d};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());

    bool called = false;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool) { called = true; }),
             false);
    CHECK_EQ(called, false);
    CHECK_EQ(client->file_contents_request_sent(), static_cast<unsigned>(0));
}

// T7: a download starts with a SIZE probe (cbRequested = 8, position 0).
RTSC_TEST(cliprdr_take_requests_size_first) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());

    const size_t before = sent.size();
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool) {}),
             true);
    CHECK_EQ(sent.size(), before + 1);
    const CliprdrPdu req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest parsed;
    CHECK(CliprdrFileContentsRequest::parse(req.data, parsed) == Status::Ok);
    CHECK_EQ(parsed.dw_flags, static_cast<uint32_t>(kFileContentsSize));
    CHECK_EQ(parsed.cb_requested, static_cast<uint32_t>(8));
    CHECK_EQ(parsed.n_position_low, static_cast<uint32_t>(0));
    CHECK_EQ(parsed.n_position_high, static_cast<uint32_t>(0));
    CHECK_EQ(parsed.lindex, 0);
    CHECK_EQ(parsed.stream_id != 0, true);
}

// T8: after the SIZE answer a RANGE request for the remaining window follows.
RTSC_TEST(cliprdr_take_size_response_starts_range_request) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    client->SetTemporaryDirectory("C:\\temp\\clipdata");
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool) {}),
             true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);

    ByteWriter rb;
    rb.u32le(size_parsed.stream_id);
    WriteU64Le(rb, 10);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            rb.take());

    const CliprdrPdu range_req = DecodeChunk(sent.back());
    CHECK(range_req.header.msg_type == CliprdrMsgType::kFileContentsRequest);
    CliprdrFileContentsRequest range_parsed;
    CHECK(CliprdrFileContentsRequest::parse(range_req.data, range_parsed) ==
          Status::Ok);
    CHECK_EQ(range_parsed.dw_flags, static_cast<uint32_t>(kFileContentsRange));
    CHECK_EQ(range_parsed.stream_id, size_parsed.stream_id);
    CHECK_EQ(range_parsed.cb_requested, static_cast<uint32_t>(10));
    CHECK_EQ(range_parsed.n_position_low, static_cast<uint32_t>(0));
}

// T9: a full transfer completes and invokes the callback with the data.
RTSC_TEST(cliprdr_take_transfers_file) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 3;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());

    bool called = false;
    std::u16string got_name;
    uint64_t got_size = 0;
    std::vector<uint8_t> got_data;
    bool got_ok = false;
    const auto done = [&](uint32_t, std::u16string name, uint64_t size,
                          const std::vector<uint8_t>& data, bool ok) {
        called = true;
        got_name = std::move(name);
        got_size = size;
        got_data = data;
        got_ok = ok;
    };
    CHECK_EQ(client->RequestRemoteFile(0, done), true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    const uint32_t stream_id = size_parsed.stream_id;

    ByteWriter rb;
    rb.u32le(stream_id);
    WriteU64Le(rb, 3);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            rb.take());
    CHECK_EQ(called, false);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            FcRespBody(stream_id, {0x41, 0x42, 0x43}));
    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, true);
    CHECK_EQ(got_size, static_cast<uint64_t>(3));
    CHECK(got_name == std::u16string(u"a.txt"));
    CHECK(got_data == std::vector<uint8_t>({0x41, 0x42, 0x43}));
    // The slot is freed: a second download can start.
    CHECK_EQ(client->RequestRemoteFile(0, done), true);
}

// T/oversized: a Size response longer than cbRequested fails the transfer.
RTSC_TEST(cliprdr_take_fails_oversized_size_response) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 3;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    bool called = false;
    bool got_ok = true;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool ok) {
                     called = true;
                     got_ok = ok;
                 }),
             true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    ByteWriter rb;
    rb.u32le(size_parsed.stream_id);
    WriteU64Le(rb, 3);
    rb.u8(0);  // one byte too many
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            rb.take());
    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, false);
}

// T/empty: a zero-byte range response before EOF is abnormal.
RTSC_TEST(cliprdr_take_fails_empty_response_mid_file) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    bool called = false;
    bool got_ok = true;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool ok) {
                     called = true;
                     got_ok = ok;
                 }),
             true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    ByteWriter rb;
    rb.u32le(size_parsed.stream_id);
    WriteU64Le(rb, 10);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            rb.take());
    CHECK_EQ(called, false);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            FcRespBody(size_parsed.stream_id, {}));
    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, false);
}

// T/RESP-FAIL: a FAIL reply ends the transfer with ok=false.
RTSC_TEST(cliprdr_take_fails_on_response_fail) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    bool called = false;
    bool got_ok = true;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool ok) {
                     called = true;
                     got_ok = ok;
                 }),
             true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseFail,
            FcRespBody(size_parsed.stream_id, {}));
    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, false);
}

// T/F4: a response carrying both OK and FAIL is treated as a failure.
RTSC_TEST(cliprdr_take_fails_on_ambiguous_response) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    bool called = false;
    bool got_ok = true;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool ok) {
                     called = true;
                     got_ok = ok;
                 }),
             true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse,
            static_cast<uint16_t>(kClipResponseOk | kClipResponseFail),
            FcRespBody(size_parsed.stream_id, {}));
    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, false);
}

// T/F3: a response with neither flag is treated as a failure.
RTSC_TEST(cliprdr_take_fails_on_unflagged_response) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    bool called = false;
    bool got_ok = true;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool ok) {
                     called = true;
                     got_ok = ok;
                 }),
             true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, 0,
            FcRespBody(size_parsed.stream_id, {}));
    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, false);
}

// T/late: a response whose stream id has no matching in-flight transfer is
// ignored.
RTSC_TEST(cliprdr_take_ignores_unmatched_response) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    bool called = false;
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            FcRespBody(999, {0x41}));
    CHECK_EQ(called, false);
    CHECK_EQ(client->in_flight_file_ops(), static_cast<size_t>(0));
}

// T/timeout: a stalled transfer is ended by Poll and counted.
RTSC_TEST(cliprdr_take_timeout_finishes) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    client->SetTransferTimeoutMs(50);
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    bool called = false;
    bool got_ok = true;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool ok) {
                     called = true;
                     got_ok = ok;
                 }),
             true);

    // A deadline far in the future changes nothing.
    client->Poll(std::chrono::steady_clock::now());
    CHECK_EQ(called, false);
    CHECK_EQ(client->transfer_timeout_count(), static_cast<unsigned>(0));
    // Beyond the deadline the transfer is finished as a timeout.
    client->Poll(std::chrono::steady_clock::now() + std::chrono::milliseconds(200));
    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, false);
    CHECK_EQ(client->transfer_timeout_count(), static_cast<unsigned>(1));
}

// T/cancel: CancelRemoteFileContents ends the in-flight transfer.
RTSC_TEST(cliprdr_take_cancel_aborts) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    bool called = false;
    bool got_ok = true;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool ok) {
                     called = true;
                     got_ok = ok;
                 }),
             true);
    CHECK_EQ(client->in_flight_file_ops(), static_cast<size_t>(1));
    client->CancelRemoteFileContents();
    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, false);
    CHECK_EQ(client->in_flight_file_ops(), static_cast<size_t>(0));
}

// T/window: the range loop walks the file in configurable windows.
RTSC_TEST(cliprdr_take_window_loop_accumulates) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    client->SetFileTransferWindow(4);
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    std::vector<uint8_t> accumulated;
    bool called = false;
    bool got_ok = false;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>& data, bool ok) {
                     called = true;
                     got_ok = ok;
                     accumulated = data;
                 }),
             true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    const uint32_t stream = size_parsed.stream_id;

    ByteWriter rb;
    rb.u32le(stream);
    WriteU64Le(rb, 10);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            rb.take());
    // 4 + 4 + 2 byte windows.
    for (std::vector<uint8_t> chunk : {std::vector<uint8_t>({1, 2, 3, 4}),
                                       std::vector<uint8_t>({5, 6, 7, 8}),
                                       std::vector<uint8_t>({9, 10})}) {
        FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
                FcRespBody(stream, chunk));
    }
    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, true);
    CHECK(accumulated ==
          std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8, 9, 10}));
}

// T/serialize: RequestRemoteFileList waits for the single-slot format-data
// request to complete (a format request is in flight).
RTSC_TEST(cliprdr_take_request_file_list_serializes_with_format_slot) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    // A list with a text format: the eager sync grabs the format-data slot.
    FeedTextAndFileFormatList(*client, 0x0F00);
    const size_t before = sent.size();
    client->RequestRemoteFileList();
    // pending_format_ is owned by the eager text request: nothing is sent yet.
    CHECK_EQ(sent.size(), before);
}

// r5/r6: dwFlags carrying both SIZE and RANGE, or neither, is refused.
RTSC_TEST(cliprdr_serve_fails_ambiguous_or_empty_flags) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 1, u"x", false}};
    provider.blocks = {{0x11}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(1, 0, kFileContentsSize | kFileContentsRange, 0, 1));
    CHECK_EQ(DecodeChunk(sent.back()).header.msg_flags,
             static_cast<uint16_t>(kClipResponseFail));
    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(2, 0, 0, 0, 1));
    CHECK_EQ(DecodeChunk(sent.back()).header.msg_flags,
             static_cast<uint16_t>(kClipResponseFail));
}

// s3/F7: a negative lindex is out of range.
RTSC_TEST(cliprdr_serve_fails_negative_lindex) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 1, u"x", false}};
    provider.blocks = {{0x11}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0,
            FcrBody(3, -1, kFileContentsRange, 0, 1));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

// D1 lock gate: a canonical 28-byte request carries clipDataId, and without
// CB_CAN_LOCK_CLIPDATA advertised the serve path must FAIL (the lock gate must
// not be bypassable by a 28-byte body that was previously parsed without an id).
RTSC_TEST(cliprdr_serve_fails_canonical_28b_clipdata_request) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 1, u"x", false}};
    provider.blocks = {{0x11}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    ByteWriter w;
    w.u32le(30);
    w.u32le(0);
    w.u32le(kFileContentsRange);
    w.u32le(0);
    w.u32le(0);
    w.u32le(1);
    w.u32le(0x77);  // clipDataId
    const auto body = w.take();
    CHECK_EQ(body.size(), static_cast<size_t>(28));
    FeedPdu(*client, CliprdrMsgType::kFileContentsRequest, 0, body);

    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
    CHECK_EQ(resp.data.size(), static_cast<size_t>(4));  // streamID only
    CHECK_EQ(client->file_contents_request_rejected(), static_cast<unsigned>(1));
}

// D2 direction-B serve: a Format Data Request for the file-list format id we
// advertise is answered with a CLIPRDR_FILELIST built from the provider; the
// local clipboard (which would fail the read) is not touched.
RTSC_TEST(cliprdr_serve_file_list_format_data_response) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {
        {0, 100, u"a.txt", false},
        {0, 0, u"docs", true},
    };
    provider.blocks = {{}, {}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    rtsc::proto::CliprdrFormatDataRequest req;
    req.format_id = kDeFactoFileListFormatId;
    FeedPdu(*client, CliprdrMsgType::kFormatDataRequest, 0, req.encode());

    CHECK_EQ(sent.size(), static_cast<size_t>(1));
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK(resp.header.msg_type == CliprdrMsgType::kFormatDataResponse);
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseOk));
    CliprdrFileList list;
    CHECK(CliprdrFileList::parse(resp.data, list) == Status::Ok);
    CHECK_EQ(list.files.size(), static_cast<size_t>(2));
    CHECK(list.files[0].file_name == std::u16string(u"a.txt"));
    CHECK_EQ(list.files[0].file_size, static_cast<uint64_t>(100));
    CHECK_EQ(list.files[0].dw_flags & kFileDescriptorSize, static_cast<uint32_t>(kFileDescriptorSize));
    CHECK_EQ(list.files[1].is_directory(), true);
    CHECK_EQ(list.files[1].dw_flags & kFileDescriptorAttributes,
             static_cast<uint32_t>(kFileDescriptorAttributes));
}

// D2: a build failure (provider cannot enumerate) answers FAIL, distinct from
// an empty list which is still a valid response.
RTSC_TEST(cliprdr_serve_file_list_build_failure_responds_fail) {
    FakeClipboard clip;
    FakeProvider provider;
    provider.files = {{0, 1, u"x", false}};
    provider.blocks = {{0x11}};
    provider.fail_info_ = true;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    rtsc::proto::CliprdrFormatDataRequest req;
    req.format_id = kDeFactoFileListFormatId;
    FeedPdu(*client, CliprdrMsgType::kFormatDataRequest, 0, req.encode());
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

// D2: without a provider the file-list request falls back to the clipboard
// read, which cannot serve it (FAIL).
RTSC_TEST(cliprdr_serve_file_list_without_provider_responds_fail) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);

    rtsc::proto::CliprdrFormatDataRequest req;
    req.format_id = kDeFactoFileListFormatId;
    FeedPdu(*client, CliprdrMsgType::kFormatDataRequest, 0, req.encode());
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

// D2-R: a provider entry whose name cannot be encoded fails the whole list
// answer with FAIL (distinct from a legal empty list).
RTSC_TEST(cliprdr_serve_file_list_encode_failure_responds_fail) {
    FakeClipboard clip;
    FakeProvider provider;
    rtsc::clipboard::FileInfo fi;
    fi.name.assign(260, u'N');  // 260 units: no room for the null terminator
    provider.files = {fi};
    provider.blocks = {{}};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeServeClient(&clip, &provider, sent);

    rtsc::proto::CliprdrFormatDataRequest req;
    req.format_id = kDeFactoFileListFormatId;
    FeedPdu(*client, CliprdrMsgType::kFormatDataRequest, 0, req.encode());
    const CliprdrPdu resp = DecodeChunk(sent.back());
    CHECK_EQ(resp.header.msg_flags, static_cast<uint16_t>(kClipResponseFail));
}

// T8: an empty remote file finishes normally right after the SIZE probe.
RTSC_TEST(cliprdr_take_empty_file_finishes_immediately) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 0;
    f.file_name = u"empty";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());

    bool called = false;
    bool got_ok = false;
    std::vector<uint8_t> got_data;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>& data, bool ok) {
                     called = true;
                     got_ok = ok;
                     got_data = data;
                 }),
             true);
    const size_t before = sent.size();
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    ByteWriter rb;
    rb.u32le(size_parsed.stream_id);
    WriteU64Le(rb, 0);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            rb.take());

    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, true);
    CHECK(got_data.empty());
    // No RANGE request was issued for an already-complete file.
    CHECK_EQ(sent.size(), before);
}

// T9: a RANGE response larger than cbRequested fails the transfer.
RTSC_TEST(cliprdr_take_fails_oversized_range_response) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    bool called = false;
    bool got_ok = true;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool ok) {
                     called = true;
                     got_ok = ok;
                 }),
             true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    const uint32_t stream = size_parsed.stream_id;
    ByteWriter rb;
    rb.u32le(stream);
    WriteU64Le(rb, 10);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            rb.take());
    CHECK_EQ(called, false);
    // The range window asked for 10 bytes; 11 is oversized.
    std::vector<uint8_t> eleven(11, 0x41);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            FcRespBody(stream, eleven));
    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, false);
}

// T10: a response arriving after the transfer timed out is ignored.
RTSC_TEST(cliprdr_take_late_response_after_timeout_ignored) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    client->SetTransferTimeoutMs(50);
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    unsigned calls = 0;
    bool got_ok = true;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool ok) {
                     ++calls;
                     got_ok = ok;
                 }),
             true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    const uint32_t stream = size_parsed.stream_id;

    client->Poll(std::chrono::steady_clock::now() + std::chrono::milliseconds(200));
    CHECK_EQ(calls, static_cast<unsigned>(1));
    CHECK_EQ(got_ok, false);
    // The stale reply (matching the old stream id) is dropped: the callback is
    // still invoked exactly once.
    ByteWriter rb;
    rb.u32le(stream);
    WriteU64Le(rb, 10);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            rb.take());
    CHECK_EQ(calls, static_cast<unsigned>(1));
    CHECK_EQ(client->file_contents_response_received(), static_cast<unsigned>(1));
}

// T17: the take path is gated before the initialization / capability exchange.
RTSC_TEST(cliprdr_take_guarded_before_init) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    // No server capabilities, no Start(): server_flags_ is still 0.

    client->RequestRemoteFileList();
    CHECK_EQ(sent.size(), static_cast<size_t>(0));
    bool called = false;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool) { called = true; }),
             false);
    CHECK_EQ(called, false);
}

// cancel: the next transfer must not reuse the cancelled stream id.
RTSC_TEST(cliprdr_take_cancel_then_new_stream_id) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());

    const auto noop = [](uint32_t, std::u16string, uint64_t,
                         const std::vector<uint8_t>&, bool) {};
    CHECK_EQ(client->RequestRemoteFile(0, noop), true);
    const CliprdrPdu first_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest first_parsed;
    CHECK(CliprdrFileContentsRequest::parse(first_req.data, first_parsed) ==
          Status::Ok);
    const uint32_t first_stream = first_parsed.stream_id;
    client->CancelRemoteFileContents();
    CHECK_EQ(client->RequestRemoteFile(0, noop), true);
    const CliprdrPdu second_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest second_parsed;
    CHECK(CliprdrFileContentsRequest::parse(second_req.data, second_parsed) ==
          Status::Ok);
    CHECK_EQ(second_parsed.stream_id == first_stream, false);
}

// D3 take: a file whose reported size is >= 2^32 fails immediately when this
// client does not advertise huge-file support; with 0x20 enabled it proceeds.
RTSC_TEST(cliprdr_take_rejects_huge_file_without_huge_support) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 0x100000000ULL;
    f.file_name = u"huge.bin";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    bool called = false;
    bool got_ok = true;
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool ok) {
                     called = true;
                     got_ok = ok;
                 }),
             true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    const size_t before = sent.size();
    ByteWriter rb;
    rb.u32le(size_parsed.stream_id);
    WriteU64Le(rb, 0x100000000ULL);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            rb.take());
    CHECK_EQ(called, true);
    CHECK_EQ(got_ok, false);
    // No RANGE at/above 2^32 was issued.
    CHECK_EQ(sent.size(), before);
}

RTSC_TEST(cliprdr_take_huge_file_proceeds_with_huge_support) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    client->EnableHugeFileSupport();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip |
                               rtsc::channel::kClipCapsHugeFileSupport);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 0x100000100ULL;
    f.file_name = u"huge.bin";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    CHECK_EQ(client->RequestRemoteFile(
                 0, [&](uint32_t, std::u16string, uint64_t,
                        const std::vector<uint8_t>&, bool) {}),
             true);
    const CliprdrPdu size_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest size_parsed;
    CHECK(CliprdrFileContentsRequest::parse(size_req.data, size_parsed) ==
          Status::Ok);
    ByteWriter rb;
    rb.u32le(size_parsed.stream_id);
    WriteU64Le(rb, 0x100000100ULL);
    FeedPdu(*client, CliprdrMsgType::kFileContentsResponse, kClipResponseOk,
            rb.take());
    // A RANGE at 0 is issued with the huge position encoded in the high word.
    const CliprdrPdu range_req = DecodeChunk(sent.back());
    CliprdrFileContentsRequest range_parsed;
    CHECK(CliprdrFileContentsRequest::parse(range_req.data, range_parsed) ==
          Status::Ok);
    CHECK_EQ(range_parsed.dw_flags, static_cast<uint32_t>(kFileContentsRange));
    CHECK_EQ(range_parsed.cb_requested, static_cast<uint32_t>(64 * 1024));
}

// D4: a stray Format Data Response with no outstanding request must never be
// written to the clipboard.
RTSC_TEST(cliprdr_client_stale_response_does_not_overwrite_clipboard) {
    FakeClipboard clip;
    const std::vector<uint8_t> text1 = {0x48, 0x00, 0x69, 0x00, 0x00, 0x00};
    const std::vector<uint8_t> text2 = {0x41, 0x00, 0x00, 0x00};
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->RequestRemoteFormat(kCfUnicodeText);
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk, text1);
    CHECK_EQ(clip.write_count_, static_cast<unsigned>(1));
    // A duplicate / stale reply: the request slot was already released.
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk, text2);
    CHECK_EQ(clip.write_count_, static_cast<unsigned>(1));
    CHECK_EQ(clip.formats().size(), static_cast<size_t>(0));
}

// D4: when a newer format list drops the file format, the in-flight file-list
// request is cancelled; its late reply must not populate the remote list nor
// reach the clipboard.
RTSC_TEST(cliprdr_take_stale_file_list_response_dropped) {
    FakeClipboard clip;
    std::vector<std::vector<uint8_t>> sent;
    auto client = MakeClient(&clip, sent);
    client->EnableFileClip();
    FeedServerCaps(*client, rtsc::channel::kClipCapsUseLongFormatNames |
                               rtsc::channel::kClipCapsStreamFileClip);
    client->Start();
    FeedMonitorReady(*client);
    FeedFileOnlyFormatList(*client, 0x0F00);
    client->RequestRemoteFileList();
    CHECK_EQ(client->remote_file_list_format_id(), static_cast<uint32_t>(0x0F00));

    // A newer empty format list drops the file format entirely.
    FeedPdu(*client, CliprdrMsgType::kFormatList, 0, {});
    CHECK_EQ(client->remote_file_list_format_id(), static_cast<uint32_t>(0));
    CHECK_EQ(client->pending_format_for_test(), static_cast<uint32_t>(0));

    // The stale FILELIST reply arrives: it must be dropped.
    CliprdrFileList list;
    CliprdrFileDescriptor f;
    f.file_size = 10;
    f.file_name = u"a.txt";
    list.files = {f};
    FeedPdu(*client, CliprdrMsgType::kFormatDataResponse, kClipResponseOk,
            list.encode());
    CHECK_EQ(clip.write_count_, static_cast<unsigned>(0));
    CHECK_EQ(client->remote_file_list_received(), static_cast<unsigned>(0));
    CHECK_EQ(client->have_remote_file_list(), false);
    CHECK_EQ(client->remote_file_list().size(), static_cast<size_t>(0));
}

int main() { return ::rtsc::test::run_all("rtsc_cliprdr_tests"); }
