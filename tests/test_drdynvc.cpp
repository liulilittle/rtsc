// Dynamic virtual channel (drdynvc) structure layer ([MS-RDPEDYC] 2.2).

#include "rtsc/proto/drdynvc.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

RTSC_TEST(dynvc_header_parses_bitfields) {
    // cbId=0 (1 byte), Sp=0, Cmd=Capability (5) -> 0x50.
    const std::vector<uint8_t> b = {0x50};
    DynvcHeader h;
    CHECK(DynvcHeader::parse(b.data(), b.size(), h) == Status::Ok);
    CHECK(h.cmd == DynvcCmd::kCapability);
    CHECK_EQ(h.sp, static_cast<uint8_t>(0));
    CHECK_EQ(h.cb_id, static_cast<uint8_t>(0));
    CHECK_EQ(h.channel_id_size(), static_cast<size_t>(1));
    CHECK(DynvcHeader::parse(b.data(), 0, h) == Status::NeedMoreData);
}

RTSC_TEST(dynvc_header_bit_order_matches_spec) {
    // Cmd=Create (1) << 4 | Sp=2 << 2 | cbId=1 -> 0x19.
    const std::vector<uint8_t> b = {0x19};
    DynvcHeader h;
    CHECK(DynvcHeader::parse(b.data(), b.size(), h) == Status::Ok);
    CHECK(h.cmd == DynvcCmd::kCreate);
    CHECK_EQ(h.sp, static_cast<uint8_t>(2));
    CHECK_EQ(h.cb_id, static_cast<uint8_t>(1));
    CHECK_EQ(h.channel_id_size(), static_cast<size_t>(2));
}

RTSC_TEST(dynvc_channel_id_widths) {
    // 1-byte channel id.
    {
        const std::vector<uint8_t> b = {0x30, 0x07};  // Cmd=Data(3), cbId=0
        DynvcPdu p;
        CHECK(DynvcPdu::parse(b.data(), b.size(), p) == Status::Ok);
        CHECK_EQ(p.channel_id, static_cast<uint32_t>(7));
        CHECK(p.data.empty());
    }
    // 2-byte channel id.
    {
        const std::vector<uint8_t> b = {0x31, 0x34, 0x12, 0xAA};
        DynvcPdu p;
        CHECK(DynvcPdu::parse(b.data(), b.size(), p) == Status::Ok);
        CHECK_EQ(p.channel_id, static_cast<uint32_t>(0x1234));
        CHECK_EQ(p.data.size(), static_cast<size_t>(1));
        CHECK_EQ(p.data[0], static_cast<uint8_t>(0xAA));
    }
    // 4-byte channel id.
    {
        const std::vector<uint8_t> b = {0x32, 0x78, 0x56, 0x34, 0x12};
        DynvcPdu p;
        CHECK(DynvcPdu::parse(b.data(), b.size(), p) == Status::Ok);
        CHECK_EQ(p.channel_id, static_cast<uint32_t>(0x12345678));
        CHECK(p.data.empty());
    }
}

RTSC_TEST(dynvc_rejects_invalid_cbid) {
    // cbId = 3 is invalid.
    const std::vector<uint8_t> b = {0x33, 0x01, 0x02};
    DynvcPdu p;
    CHECK(DynvcPdu::parse(b.data(), b.size(), p) == Status::InvalidField);
}

RTSC_TEST(dynvc_rejects_truncated_channel_id) {
    // cbId = 1 (2-byte id) but only 1 byte follows.
    const std::vector<uint8_t> b = {0x31, 0x00};
    DynvcPdu p;
    CHECK(DynvcPdu::parse(b.data(), b.size(), p) == Status::NeedMoreData);
}

RTSC_TEST(dynvc_build_picks_smallest_id_width) {
    // 7 -> 1 byte.
    auto p = BuildDynvcPdu(DynvcCmd::kData, 0, 7, {0xAA});
    CHECK_EQ(p.size(), static_cast<size_t>(3));
    CHECK_EQ(p[0], static_cast<uint8_t>(0x30));  // Cmd=3, cbId=0
    CHECK_EQ(p[1], static_cast<uint8_t>(7));

    // 0x1234 -> 2 bytes.
    p = BuildDynvcPdu(DynvcCmd::kCreate, 0, 0x1234, {});
    CHECK_EQ(p[0], static_cast<uint8_t>(0x11));  // Cmd=1, cbId=1
    CHECK_EQ(p[1], static_cast<uint8_t>(0x34));
    CHECK_EQ(p[2], static_cast<uint8_t>(0x12));

    // 0x12345678 -> 4 bytes.
    p = BuildDynvcPdu(DynvcCmd::kClose, 0, 0x12345678, {});
    CHECK_EQ(p[0], static_cast<uint8_t>(0x42));  // Cmd=4, cbId=2
    CHECK_EQ(p.size(), static_cast<size_t>(5));
}

RTSC_TEST(dynvc_round_trip) {
    const std::vector<uint8_t> payload = {1, 2, 3, 4, 5};
    const auto pdu = BuildDynvcPdu(DynvcCmd::kDataFirst, 0, 0x1234, payload);
    DynvcPdu p;
    CHECK(DynvcPdu::parse(pdu.data(), pdu.size(), p) == Status::Ok);
    CHECK(p.header.cmd == DynvcCmd::kDataFirst);
    CHECK_EQ(p.channel_id, static_cast<uint32_t>(0x1234));
    CHECK(p.data == payload);
}

// ---- per-channel message reassembly ([MS-RDPEDYC] 2.2.2.1/2.2.2.2) -------
//
// Frames are built from the wire format directly: DYNVC_DATA_FIRST carries the
// total Length of the logical message as a 4-byte little-endian field, a
// continuation DYNVC_DATA carries only the next fragment.

namespace {

std::vector<uint8_t> MakeDvcPdu(DynvcCmd cmd, uint32_t channel_id,
                                const std::vector<uint8_t>& body) {
    DynvcHeader h;
    h.cmd = cmd;
    h.sp = 0;
    h.cb_id = channel_id <= 0xFF
                  ? static_cast<uint8_t>(0)
                  : (channel_id <= 0xFFFF ? static_cast<uint8_t>(1)
                                          : static_cast<uint8_t>(2));
    ByteWriter w;
    h.write(w);
    for (size_t i = 0; i < h.channel_id_size(); ++i) {
        w.u8(static_cast<uint8_t>((channel_id >> (8 * i)) & 0xFF));
    }
    if (!body.empty()) w.bytes(body.data(), body.size());
    return w.take();
}

std::vector<uint8_t> DataFirstFrame(uint32_t channel_id, uint32_t total_length,
                                    const std::vector<uint8_t>& data) {
    std::vector<uint8_t> body = {
        static_cast<uint8_t>(total_length & 0xFF),
        static_cast<uint8_t>((total_length >> 8) & 0xFF),
        static_cast<uint8_t>((total_length >> 16) & 0xFF),
        static_cast<uint8_t>((total_length >> 24) & 0xFF)};
    body.insert(body.end(), data.begin(), data.end());
    return MakeDvcPdu(DynvcCmd::kDataFirst, channel_id, body);
}

std::vector<uint8_t> DataFrame(uint32_t channel_id,
                               const std::vector<uint8_t>& data) {
    return MakeDvcPdu(DynvcCmd::kData, channel_id, data);
}

struct Deliveries {
    std::vector<uint32_t> ids;
    std::vector<std::vector<uint8_t>> messages;
};

void FeedFrame(DynvcReassembler& r, const std::vector<uint8_t>& frame,
               Deliveries& out) {
    DynvcPdu pdu;
    CHECK(DynvcPdu::parse(frame.data(), frame.size(), pdu) == Status::Ok);
    std::vector<uint8_t> message;
    if (r.Feed(pdu, message)) {
        out.ids.push_back(pdu.channel_id);
        out.messages.push_back(message);
    }
}

}  // namespace

RTSC_TEST(dynvc_data_after_complete_message_is_a_new_message) {
    // A DYNVC_DATA that does not follow a DYNVC_DATA_FIRST is a whole
    // single-PDU message ([MS-RDPEDYC] 3.1.5.2.2), so it is delivered on its
    // own and must not inherit the bytes of the previous message.
    DynvcReassembler r;
    Deliveries d;
    FeedFrame(r, DataFirstFrame(7, 2, {0xAA, 0xAA}), d);
    FeedFrame(r, DataFrame(7, {0xBB, 0xBB}), d);

    CHECK_EQ(d.messages.size(), static_cast<size_t>(2));
    if (!d.messages.empty()) {
        CHECK_EQ(d.ids[0], static_cast<uint32_t>(7));
        CHECK_BYTES(d.messages[0], 0xAA, 0xAA);
    }
    if (d.messages.size() >= 2) {
        CHECK_EQ(d.ids[1], static_cast<uint32_t>(7));
        CHECK_BYTES(d.messages[1], 0xBB, 0xBB);
    }
    CHECK_EQ(r.pending_channels(), static_cast<size_t>(0));
}

RTSC_TEST(dynvc_single_data_pdu_is_a_whole_message) {
    // Messages of at most 1,590 bytes are sent as a single DYNVC_DATA PDU and
    // must be delivered immediately, including a full-size 1,500-byte payload.
    DynvcReassembler r;
    Deliveries d;
    FeedFrame(r, DataFrame(11, {0x11, 0x22}), d);
    std::vector<uint8_t> big(1500);
    for (size_t i = 0; i < big.size(); ++i) {
        big[i] = static_cast<uint8_t>(i);
    }
    FeedFrame(r, DataFrame(11, big), d);
    FeedFrame(r, DataFrame(11, {0x33}), d);

    CHECK_EQ(d.messages.size(), static_cast<size_t>(3));
    if (d.messages.size() >= 1) CHECK_BYTES(d.messages[0], 0x11, 0x22);
    if (d.messages.size() >= 2) CHECK(d.messages[1] == big);
    if (d.messages.size() >= 3) CHECK_BYTES(d.messages[2], 0x33);
    CHECK_EQ(r.pending_channels(), static_cast<size_t>(0));
}

RTSC_TEST(dynvc_rejects_oversized_message_length) {
    // An absurd Length must not be buffered or tracked.
    DynvcReassembler r;
    Deliveries d;
    FeedFrame(r, DataFirstFrame(12, 0xFFFFFFFFu, {0xAA}), d);
    CHECK_EQ(d.messages.size(), static_cast<size_t>(0));
    CHECK_EQ(r.pending_channels(), static_cast<size_t>(0));

    // The channel is not poisoned by the rejected sequence: a standalone DATA
    // is still a whole message.
    FeedFrame(r, DataFrame(12, {0x55}), d);
    CHECK_EQ(d.messages.size(), static_cast<size_t>(1));
    if (!d.messages.empty()) CHECK_BYTES(d.messages[0], 0x55);
    CHECK_EQ(r.pending_channels(), static_cast<size_t>(0));
}

RTSC_TEST(dynvc_caps_pending_channels) {
    // One half-assembled message per channel cannot grow without bound.
    DynvcReassembler r;
    Deliveries d;
    for (uint32_t id = 100; id < 100 + 65; ++id) {
        FeedFrame(r, DataFirstFrame(id, 4, {0x01}), d);
    }
    CHECK_EQ(d.messages.size(), static_cast<size_t>(0));
    CHECK_EQ(r.pending_channels(), DynvcReassembler::kMaxPendingChannels);
}

RTSC_TEST(dynvc_reassembly_is_isolated_per_channel) {
    // Interleaved fragments of two channels keep independent state.
    DynvcReassembler r;
    Deliveries d;
    FeedFrame(r, DataFirstFrame(2, 2, {0xA1}), d);
    FeedFrame(r, DataFirstFrame(3, 2, {0xB1}), d);
    FeedFrame(r, DataFrame(2, {0xA2}), d);
    FeedFrame(r, DataFrame(3, {0xB2}), d);

    CHECK_EQ(d.messages.size(), static_cast<size_t>(2));
    if (!d.messages.empty()) {
        CHECK_EQ(d.ids[0], static_cast<uint32_t>(2));
        CHECK_BYTES(d.messages[0], 0xA1, 0xA2);
    }
    if (d.messages.size() >= 2) {
        CHECK_EQ(d.ids[1], static_cast<uint32_t>(3));
        CHECK_BYTES(d.messages[1], 0xB1, 0xB2);
    }
    CHECK_EQ(r.pending_channels(), static_cast<size_t>(0));
}

RTSC_TEST(dynvc_reassembly_respects_total_length) {
    // Exactly reaching the declared Length delivers; overshooting or falling
    // short of it does not.
    DynvcReassembler r;
    Deliveries d;
    FeedFrame(r, DataFirstFrame(4, 3, {0x10, 0x11}), d);
    FeedFrame(r, DataFrame(4, {0x12}), d);
    // A DATA_FIRST that already holds the whole message delivers at once.
    FeedFrame(r, DataFirstFrame(5, 3, {0x10, 0x11, 0x12}), d);
    CHECK_EQ(d.messages.size(), static_cast<size_t>(2));
    if (d.messages.size() >= 1) CHECK_BYTES(d.messages[0], 0x10, 0x11, 0x12);
    if (d.messages.size() >= 2) CHECK_BYTES(d.messages[1], 0x10, 0x11, 0x12);

    // Overshoot: accumulated bytes exceed the declared Length, so the whole
    // sequence is dropped.
    FeedFrame(r, DataFirstFrame(6, 3, {0x20, 0x21}), d);
    FeedFrame(r, DataFrame(6, {0x22, 0x23}), d);
    CHECK_EQ(d.messages.size(), static_cast<size_t>(2));
    // The dropped sequence leaves no open state: the next DATA is a new
    // single-PDU message, not a continuation.
    FeedFrame(r, DataFrame(6, {0x24}), d);
    CHECK_EQ(d.messages.size(), static_cast<size_t>(3));
    if (d.messages.size() >= 3) CHECK_BYTES(d.messages[2], 0x24);

    // Truncated: fewer bytes than the declared Length, still waiting.
    FeedFrame(r, DataFirstFrame(8, 5, {0x30, 0x31}), d);
    FeedFrame(r, DataFrame(8, {0x32}), d);
    CHECK_EQ(d.messages.size(), static_cast<size_t>(3));
    CHECK_EQ(r.pending_channels(), static_cast<size_t>(1));
}

RTSC_TEST(dynvc_reassembly_resets_after_delivery) {
    // Two complete messages on one channel stay independent, and a new
    // DATA_FIRST discards a half-assembled sequence.
    DynvcReassembler r;
    Deliveries d;
    FeedFrame(r, DataFirstFrame(9, 2, {0x41, 0x42}), d);
    FeedFrame(r, DataFirstFrame(9, 2, {0x51, 0x52}), d);
    FeedFrame(r, DataFirstFrame(9, 4, {0x61}), d);
    FeedFrame(r, DataFirstFrame(9, 2, {0x71, 0x72}), d);

    CHECK_EQ(d.messages.size(), static_cast<size_t>(3));
    if (d.messages.size() >= 1) CHECK_BYTES(d.messages[0], 0x41, 0x42);
    if (d.messages.size() >= 2) CHECK_BYTES(d.messages[1], 0x51, 0x52);
    if (d.messages.size() >= 3) CHECK_BYTES(d.messages[2], 0x71, 0x72);
    CHECK_EQ(r.pending_channels(), static_cast<size_t>(0));
}

RTSC_TEST(dynvc_encode_single_pdu_for_small_messages) {
    // [MS-RDPEDYC] 3.1.5.2: a message of at most 1,590 bytes is sent as a
    // single DYNVC_DATA PDU (no Length field).
    for (const size_t size : {size_t{0}, size_t{2}, size_t{1500}, size_t{1590}}) {
        const std::vector<uint8_t> payload(size, 0x3C);
        const auto pdus = BuildDynvcDataPdus(7, payload);
        CHECK_EQ(pdus.size(), static_cast<size_t>(1));
        if (pdus.empty()) continue;
        DynvcPdu p;
        CHECK(DynvcPdu::parse(pdus[0].data(), pdus[0].size(), p) == Status::Ok);
        CHECK(p.header.cmd == DynvcCmd::kData);
        CHECK_EQ(p.length, static_cast<uint32_t>(0));
        CHECK(p.data == payload);
    }
}

RTSC_TEST(dynvc_encode_fragmented_message_declares_total_length) {
    // [MS-RDPEDYC] 2.2.3.1: only messages larger than 1,590 bytes are
    // fragmented, and DATA_FIRST.Length is the whole message size.
    const std::vector<uint8_t> payload(3000, 0x7E);
    const auto pdus = BuildDynvcDataPdus(0x1234, payload);
    CHECK_EQ(pdus.size(), static_cast<size_t>(2));
    if (pdus.empty()) return;

    DynvcPdu first;
    CHECK(DynvcPdu::parse(pdus[0].data(), pdus[0].size(), first) == Status::Ok);
    CHECK(first.header.cmd == DynvcCmd::kDataFirst);
    CHECK_EQ(first.channel_id, static_cast<uint32_t>(0x1234));
    CHECK_EQ(first.length, static_cast<uint32_t>(3000));

    if (pdus.size() < 2) return;
    DynvcPdu second;
    CHECK(DynvcPdu::parse(pdus[1].data(), pdus[1].size(), second) == Status::Ok);
    CHECK(second.header.cmd == DynvcCmd::kData);
    CHECK_EQ(second.length, static_cast<uint32_t>(0));

    // The receiver side must rebuild exactly the original message.
    DynvcReassembler r;
    Deliveries d;
    FeedFrame(r, pdus[0], d);
    FeedFrame(r, pdus[1], d);
    CHECK_EQ(d.messages.size(), static_cast<size_t>(1));
    if (!d.messages.empty()) CHECK(d.messages[0] == payload);
}

int main() { return ::rtsc::test::run_all("rtsc_drdynvc_tests"); }
