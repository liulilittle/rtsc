// Clipboard virtual channel (cliprdr) structure layer ([MS-RDPECLIP] 2.2).

#include "rtsc/channel/cliprdr_client.h"
#include "rtsc/clipboard/clipboard.h"
#include "rtsc/proto/cliprdr.h"

#include <cstdint>
#include <map>
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

uint32_t ReadU32Le(const std::vector<uint8_t>& d) {
    return static_cast<uint32_t>(d[0]) | (static_cast<uint32_t>(d[1]) << 8) |
           (static_cast<uint32_t>(d[2]) << 16) |
           (static_cast<uint32_t>(d[3]) << 24);
}

}  // namespace

RTSC_TEST(cliprdr_client_start_sends_ready_caps_and_format_list) {
    FakeClipboard clip;
    clip.formats_ = {kCfUnicodeText, kCfDib};
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::CliprdrClient client(
        &clip, [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    FeedServerCaps(client, rtsc::channel::kClipCapsUseLongFormatNames);
    client.Start();

    CHECK_EQ(sent.size(), static_cast<size_t>(3));
    const CliprdrPdu ready = DecodeChunk(sent[0]);
    CHECK(ready.header.msg_type == CliprdrMsgType::kMonitorReady);
    CHECK_EQ(ready.header.data_len, static_cast<uint32_t>(0));

    const CliprdrPdu caps = DecodeChunk(sent[1]);
    CHECK(caps.header.msg_type == CliprdrMsgType::kClipCaps);
    CHECK_EQ(caps.header.data_len, static_cast<uint32_t>(16));
    // cCapabilitiesSets=1, pad1=0, type=1, length=12, version=2, flags=LONG.
    CHECK_BYTES(caps.data, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0C, 0x00, 0x02,
                0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00);

    const CliprdrPdu list = DecodeChunk(sent[2]);
    CHECK(list.header.msg_type == CliprdrMsgType::kFormatList);
    // Two long format names: formatId(4) + a single null wchar(2) each.
    CHECK_EQ(list.data.size(), static_cast<size_t>(2 * 6));
    CHECK_EQ(ReadU32Le(list.data), static_cast<uint32_t>(kCfUnicodeText));
    CHECK_EQ(client.long_format_names(), true);
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
    FeedServerCaps(client, rtsc::channel::kClipCapsUseLongFormatNames);
    client.Start();
    const size_t after_start = sent.size();
    client.OnLocalClipboardChanged();
    CHECK_EQ(sent.size(), after_start + 1);
    const CliprdrPdu list = DecodeChunk(sent.back());
    CHECK(list.header.msg_type == CliprdrMsgType::kFormatList);
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
    FeedServerCaps(client, 0);
    client.Start();
    const CliprdrPdu list = DecodeChunk(sent.back());
    CHECK(list.header.msg_type == CliprdrMsgType::kFormatList);
    // Short format name: formatId(4) + formatName(32).
    CHECK_EQ(list.data.size(), static_cast<size_t>(36));
}

int main() { return ::rtsc::test::run_all("rtsc_cliprdr_tests"); }
