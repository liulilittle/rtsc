#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/framing.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

void Append(TpktStream& s, std::initializer_list<uint8_t> v) {
    const std::vector<uint8_t> b(v);
    s.Append(b.data(), b.size());
}

}  // namespace

RTSC_TEST(framer_returns_complete_pdu) {
    TpktStream s;
    const auto pdu = WrapTpkt(reinterpret_cast<const uint8_t*>("\xAA\xBB"), 2);
    CHECK_EQ(pdu.size(), static_cast<size_t>(6));
    s.Append(pdu.data(), pdu.size());

    std::vector<uint8_t> payload;
    CHECK(s.Next(payload) == Status::Ok);
    CHECK_BYTES(payload, 0xAA, 0xBB);
    CHECK_EQ(s.buffered(), static_cast<size_t>(0));
}

RTSC_TEST(framer_waits_for_full_header) {
    TpktStream s;
    Append(s, {0x03, 0x00});
    std::vector<uint8_t> payload;
    CHECK(s.Next(payload) == Status::NeedMoreData);
    CHECK_EQ(s.buffered(), static_cast<size_t>(2));

    Append(s, {0x00, 0x06});
    CHECK(s.Next(payload) == Status::NeedMoreData);
    CHECK_EQ(s.buffered(), static_cast<size_t>(4));

    Append(s, {0x11, 0x22});
    CHECK(s.Next(payload) == Status::Ok);
    CHECK_BYTES(payload, 0x11, 0x22);
}

RTSC_TEST(framer_waits_for_full_payload) {
    TpktStream s;
    const auto pdu = WrapTpkt(reinterpret_cast<const uint8_t*>("\x01\x02\x03\x04"), 4);
    s.Append(pdu.data(), 5);
    std::vector<uint8_t> payload;
    CHECK(s.Next(payload) == Status::NeedMoreData);
    CHECK_EQ(s.buffered(), static_cast<size_t>(5));

    s.Append(pdu.data() + 5, pdu.size() - 5);
    CHECK(s.Next(payload) == Status::Ok);
    CHECK_BYTES(payload, 0x01, 0x02, 0x03, 0x04);
}

RTSC_TEST(framer_splits_two_coalesced_pdus) {
    TpktStream s;
    const auto a = WrapTpkt(reinterpret_cast<const uint8_t*>("\xAA"), 1);
    const auto pdu_b = WrapTpkt(reinterpret_cast<const uint8_t*>("\xBB\xCC"), 2);
    s.Append(a.data(), a.size());
    s.Append(pdu_b.data(), pdu_b.size());

    std::vector<uint8_t> payload;
    CHECK(s.Next(payload) == Status::Ok);
    CHECK_BYTES(payload, 0xAA);
    CHECK(s.Next(payload) == Status::Ok);
    CHECK_BYTES(payload, 0xBB, 0xCC);
    CHECK(s.Next(payload) == Status::NeedMoreData);
    CHECK_EQ(s.buffered(), static_cast<size_t>(0));
}

RTSC_TEST(framer_handles_zero_length_payload) {
    TpktStream s;
    const auto pdu = WrapTpkt(nullptr, 0);
    CHECK_BYTES(pdu, 0x03, 0x00, 0x00, 0x04);
    s.Append(pdu.data(), pdu.size());
    std::vector<uint8_t> payload;
    CHECK(s.Next(payload) == Status::Ok);
    CHECK_EQ(payload.size(), static_cast<size_t>(0));
}

RTSC_TEST(framer_resyncs_after_garbage) {
    TpktStream s;
    Append(s, {0xDE, 0xAD, 0xBE, 0xEF, 0x00});
    const auto pdu = WrapTpkt(reinterpret_cast<const uint8_t*>("\x77"), 1);
    s.Append(pdu.data(), pdu.size());

    std::vector<uint8_t> payload;
    CHECK(s.Next(payload) == Status::Ok);
    CHECK_BYTES(payload, 0x77);
    CHECK_EQ(s.dropped_bytes(), static_cast<size_t>(5));
}

RTSC_TEST(framer_rejects_short_length) {
    TpktStream s;
    // version 3, reserved 0, length 2 (below the 4-byte minimum).
    Append(s, {0x03, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x05, 0x99});
    std::vector<uint8_t> payload;
    CHECK(s.Next(payload) == Status::InvalidLength);
    CHECK_EQ(s.dropped_bytes(), static_cast<size_t>(1));
    // The following valid PDU is still recoverable.
    CHECK(s.Next(payload) == Status::Ok);
    CHECK_BYTES(payload, 0x99);
}

RTSC_TEST(framer_clear_resets_state) {
    TpktStream s;
    Append(s, {0xDE, 0xAD});
    std::vector<uint8_t> payload;
    CHECK(s.Next(payload) == Status::NeedMoreData);
    CHECK_EQ(s.buffered(), static_cast<size_t>(2));
    s.Clear();
    CHECK_EQ(s.buffered(), static_cast<size_t>(0));
    CHECK_EQ(s.dropped_bytes(), static_cast<size_t>(0));
}

RTSC_TEST(framer_survives_many_pdus_without_quadratic_growth) {
    TpktStream s;
    const auto pdu = WrapTpkt(reinterpret_cast<const uint8_t*>("\x42\x43"), 2);
    std::vector<uint8_t> payload;
    size_t total = 0;
    int bad = 0;
    for (int i = 0; i < 5000; ++i) {
        s.Append(pdu.data(), pdu.size());
        if (s.Next(payload) != Status::Ok || payload.size() != 2) ++bad;
        total += payload.size();
    }
    CHECK_EQ(bad, 0);
    CHECK_EQ(total, static_cast<size_t>(10000));
    CHECK_EQ(s.buffered(), static_cast<size_t>(0));
    CHECK_EQ(s.dropped_bytes(), static_cast<size_t>(0));
}

RTSC_TEST(wrap_tpkt_rejects_oversized_payload) {
    std::vector<uint8_t> big(TpktHeader::kMaxPayload + 1, 0);
    CHECK(WrapTpkt(big.data(), big.size()).empty());
    std::vector<uint8_t> exact(TpktHeader::kMaxPayload, 0);
    const auto ok = WrapTpkt(exact.data(), exact.size());
    // kMaxPayload is the largest payload whose TPKT length still fits in 16 bits.
    CHECK_EQ(ok.size(), static_cast<size_t>(0xFFFC));
    CHECK_EQ(ok[2], static_cast<uint8_t>(0xFF));
    CHECK_EQ(ok[3], static_cast<uint8_t>(0xFC));
}

RTSC_TEST(wrap_tpkt_roundtrips_through_framer) {
    std::vector<uint8_t> body(300);
    for (size_t i = 0; i < body.size(); ++i) {
        body[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    const auto pdu = WrapTpkt(body.data(), body.size());
    CHECK_EQ(pdu.size(), static_cast<size_t>(304));
    CHECK_EQ(pdu[2], static_cast<uint8_t>(0x01));
    CHECK_EQ(pdu[3], static_cast<uint8_t>(0x30));

    TpktStream s;
    s.Append(pdu.data(), pdu.size());
    std::vector<uint8_t> payload;
    CHECK(s.Next(payload) == Status::Ok);
    CHECK(payload == body);
}

int main() { return rtsc::test::run_all("rtsc_framing_tests"); }
