// Static virtual channel PDU framing ([MS-RDPBCGR] 2.2.6.1).

#include "rtsc/proto/channel.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> Chunk(uint32_t total, uint32_t flags,
                           const std::vector<uint8_t>& data) {
    ByteWriter w;
    w.u32le(total);
    w.u32le(flags);
    w.bytes(data.data(), data.size());
    return w.take();
}

}  // namespace

RTSC_TEST(channel_pdu_header_parses) {
    const std::vector<uint8_t> h = {0x10, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00,
                                    0x00};
    ChannelPduHeader out;
    CHECK(ChannelPduHeader::parse(h.data(), h.size(), out) == Status::Ok);
    CHECK_EQ(out.length, static_cast<uint32_t>(0x10));
    CHECK_EQ(out.flags, static_cast<uint32_t>(kChannelFirst | kChannelShowProtocol));
    CHECK(ChannelPduHeader::parse(h.data(), 4, out) == Status::NeedMoreData);
}

RTSC_TEST(channel_single_chunk_reassembles) {
    const std::vector<uint8_t> payload = {1, 2, 3, 4, 5};
    const auto chunk = Chunk(5, kChannelFirst | kChannelLast | kChannelShowProtocol,
                             payload);
    ChannelPduHeader h;
    CHECK(ChannelPduHeader::parse(chunk.data(), chunk.size(), h) == Status::Ok);

    ChannelReassembler r;
    bool complete = false;
    std::vector<uint8_t> msg;
    CHECK(r.Feed(h, chunk.data() + ChannelPduHeader::kSize,
                 chunk.size() - ChannelPduHeader::kSize, complete, msg) == Status::Ok);
    CHECK(complete);
    CHECK(msg == payload);
    CHECK_EQ(r.buffered(), static_cast<size_t>(0));
}

RTSC_TEST(channel_multi_chunk_reassembles_in_order) {
    const std::vector<uint8_t> p1 = {1, 2, 3};
    const std::vector<uint8_t> p2 = {4, 5, 6};
    const std::vector<uint8_t> p3 = {7};

    ChannelReassembler r;
    bool complete = false;
    std::vector<uint8_t> msg;

    auto c1 = Chunk(7, kChannelFirst | kChannelShowProtocol, p1);
    auto c2 = Chunk(7, kChannelShowProtocol, p2);
    auto c3 = Chunk(7, kChannelLast | kChannelShowProtocol, p3);

    ChannelPduHeader h;
    CHECK(ChannelPduHeader::parse(c1.data(), c1.size(), h) == Status::Ok);
    CHECK(r.Feed(h, c1.data() + 8, c1.size() - 8, complete, msg) == Status::Ok);
    CHECK(!complete);

    CHECK(ChannelPduHeader::parse(c2.data(), c2.size(), h) == Status::Ok);
    CHECK(r.Feed(h, c2.data() + 8, c2.size() - 8, complete, msg) == Status::Ok);
    CHECK(!complete);
    CHECK_EQ(r.buffered(), static_cast<size_t>(6));

    CHECK(ChannelPduHeader::parse(c3.data(), c3.size(), h) == Status::Ok);
    CHECK(r.Feed(h, c3.data() + 8, c3.size() - 8, complete, msg) == Status::Ok);
    CHECK(complete);
    CHECK(msg == std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7}));
}

RTSC_TEST(channel_middle_chunk_without_first_is_rejected) {
    ChannelReassembler r;
    bool complete = false;
    std::vector<uint8_t> msg;
    ChannelPduHeader h;
    h.length = 7;
    h.flags = kChannelShowProtocol;  // neither FIRST nor LAST
    CHECK(r.Feed(h, nullptr, 0, complete, msg) == Status::InvalidField);
}

RTSC_TEST(channel_length_mismatch_is_rejected) {
    ChannelReassembler r;
    bool complete = false;
    std::vector<uint8_t> msg;
    ChannelPduHeader h;
    h.length = 99;  // lies about the total
    h.flags = kChannelFirst | kChannelLast | kChannelShowProtocol;
    const uint8_t data[] = {1, 2, 3};
    CHECK(r.Feed(h, data, sizeof(data), complete, msg) == Status::InvalidLength);
    CHECK(!complete);
    // The reassembler must be usable again after the failure.
    CHECK_EQ(r.buffered(), static_cast<size_t>(0));
}

RTSC_TEST(channel_fragment_then_reassemble_round_trip) {
    std::vector<uint8_t> message(4000);
    for (size_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    const auto chunks = FragmentChannelMessage(message, 1600);
    CHECK_EQ(chunks.size(), static_cast<size_t>(3));  // 1600 + 1600 + 800

    ChannelReassembler r;
    bool complete = false;
    std::vector<uint8_t> msg;
    for (size_t i = 0; i < chunks.size(); ++i) {
        ChannelPduHeader h;
        CHECK(ChannelPduHeader::parse(chunks[i].data(), chunks[i].size(), h) ==
              Status::Ok);
        CHECK_EQ(h.length, static_cast<uint32_t>(4000));
        if (i == 0) CHECK((h.flags & kChannelFirst) != 0);
        else CHECK((h.flags & kChannelFirst) == 0);
        if (i + 1 == chunks.size()) CHECK((h.flags & kChannelLast) != 0);
        else CHECK((h.flags & kChannelLast) == 0);
        CHECK(r.Feed(h, chunks[i].data() + 8, chunks[i].size() - 8, complete, msg) ==
              Status::Ok);
    }
    CHECK(complete);
    CHECK(msg == message);
}

RTSC_TEST(channel_fragment_single_chunk_sets_both_flags) {
    const std::vector<uint8_t> message = {9, 8, 7};
    const auto chunks = FragmentChannelMessage(message, 1600);
    CHECK_EQ(chunks.size(), static_cast<size_t>(1));
    ChannelPduHeader h;
    CHECK(ChannelPduHeader::parse(chunks[0].data(), chunks[0].size(), h) == Status::Ok);
    CHECK((h.flags & kChannelFirst) != 0);
    CHECK((h.flags & kChannelLast) != 0);
    CHECK(chunks[0].size() == ChannelPduHeader::kSize + 3);
}

// F1: a FIRST chunk whose declared total exceeds the reassembly cap is
// rejected up front, before any payload is buffered. No LAST flag: without the
// cap the length-mismatch check can never fire (the sequence simply stays
// open), so this pins the FIRST-length guard specifically.
RTSC_TEST(channel_first_declaring_over_limit_is_rejected) {
    const std::vector<uint8_t> payload(16, 0x11);
    const auto chunk =
        Chunk(static_cast<uint32_t>(kMaxChannelMessageBytes + 1),
              kChannelFirst | kChannelShowProtocol, payload);
    ChannelPduHeader h;
    CHECK(ChannelPduHeader::parse(chunk.data(), chunk.size(), h) == Status::Ok);
    CHECK_EQ(h.length, static_cast<uint32_t>(kMaxChannelMessageBytes + 1));

    ChannelReassembler r;
    bool complete = false;
    std::vector<uint8_t> msg;
    CHECK(r.Feed(h, chunk.data() + ChannelPduHeader::kSize,
                 chunk.size() - ChannelPduHeader::kSize, complete, msg) ==
          Status::InvalidLength);
    CHECK(!complete);
    // The failed message must not leave data behind.
    CHECK_EQ(r.buffered(), static_cast<size_t>(0));
}

// F1: chunk payloads that accumulate past the cap are rejected even when every
// individual chunk declares a legal total. Reaching exactly the cap is fine;
// the first chunk pushing beyond it fails and resets.
RTSC_TEST(channel_accumulated_past_limit_is_rejected) {
    const size_t cap = kMaxChannelMessageBytes;
    ChannelReassembler r;
    bool complete = false;
    std::vector<uint8_t> msg;
    ChannelPduHeader h;

    // FIRST carries cap - 2000; two MIDDLE chunks take it to exactly cap; a
    // third MIDDLE chunk would push it past the cap.
    std::vector<uint8_t> head(cap - 2000, 0xAB);
    auto c1 = Chunk(static_cast<uint32_t>(cap),
                    kChannelFirst | kChannelShowProtocol, head);
    CHECK(ChannelPduHeader::parse(c1.data(), c1.size(), h) == Status::Ok);
    CHECK(r.Feed(h, c1.data() + ChannelPduHeader::kSize,
                 c1.size() - ChannelPduHeader::kSize, complete, msg) == Status::Ok);
    CHECK_EQ(r.buffered(), cap - 2000);

    std::vector<uint8_t> mid(1000, 0xCD);
    auto c2 = Chunk(static_cast<uint32_t>(cap), kChannelShowProtocol, mid);
    CHECK(ChannelPduHeader::parse(c2.data(), c2.size(), h) == Status::Ok);
    CHECK(r.Feed(h, c2.data() + ChannelPduHeader::kSize,
                 c2.size() - ChannelPduHeader::kSize, complete, msg) == Status::Ok);
    CHECK_EQ(r.buffered(), cap - 1000);

    auto c3 = Chunk(static_cast<uint32_t>(cap), kChannelShowProtocol, mid);
    CHECK(ChannelPduHeader::parse(c3.data(), c3.size(), h) == Status::Ok);
    CHECK(r.Feed(h, c3.data() + ChannelPduHeader::kSize,
                 c3.size() - ChannelPduHeader::kSize, complete, msg) == Status::Ok);
    CHECK_EQ(r.buffered(), cap);

    auto c4 = Chunk(static_cast<uint32_t>(cap), kChannelShowProtocol, mid);
    CHECK(ChannelPduHeader::parse(c4.data(), c4.size(), h) == Status::Ok);
    CHECK(r.Feed(h, c4.data() + ChannelPduHeader::kSize,
                 c4.size() - ChannelPduHeader::kSize, complete, msg) ==
          Status::InvalidLength);
    CHECK(!complete);
    CHECK_EQ(r.buffered(), static_cast<size_t>(0));
}

// F1: a complete message of exactly kMaxChannelMessageBytes passes the cap
// checks and reassembles (boundary pass).
RTSC_TEST(channel_exact_limit_message_completes) {
    const size_t cap = kMaxChannelMessageBytes;
    std::vector<uint8_t> payload(cap, 0x5A);

    ChannelReassembler r;
    bool complete = false;
    std::vector<uint8_t> msg;

    ChannelPduHeader h;
    const auto chunk = Chunk(static_cast<uint32_t>(cap),
                             kChannelFirst | kChannelLast | kChannelShowProtocol,
                             payload);
    CHECK(ChannelPduHeader::parse(chunk.data(), chunk.size(), h) == Status::Ok);
    CHECK_EQ(h.length, static_cast<uint32_t>(cap));
    CHECK(r.Feed(h, chunk.data() + ChannelPduHeader::kSize,
                 chunk.size() - ChannelPduHeader::kSize, complete, msg) == Status::Ok);
    CHECK(complete);
    CHECK(msg == payload);
    CHECK_EQ(r.buffered(), static_cast<size_t>(0));
}

int main() { return ::rtsc::test::run_all("rtsc_channel_tests"); }
