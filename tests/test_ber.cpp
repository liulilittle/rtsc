#include <cstdio>
#include <vector>

#include "rtsc/proto/ber.h"
#include "rtsc/proto/byte_order.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> pattern(size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>((i * 7 + 3) & 0xFF);
    return v;
}

// BerWriter::begin_constructed emits a single tag byte, so the second byte of
// the two-byte MCS application tag (0x7F 0x65) is written with raw_byte().

}  // namespace

RTSC_TEST(octet_string_encodes_empty_value_as_short_form) {
    BerWriter w;
    w.octet_string(nullptr, 0);
    CHECK_BYTES(w.data(), 0x04, 0x00);

    BerReader r(w.data().data(), w.size());
    std::vector<uint8_t> out{0xAA};
    CHECK(r.read_octet_string(out) == Status::Ok);
    CHECK(out.empty());
    CHECK_EQ(r.remaining(), static_cast<size_t>(0));
}

RTSC_TEST(octet_string_encodes_short_value_without_long_form) {
    const uint8_t payload[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    BerWriter w;
    w.octet_string(payload, 5);
    CHECK_BYTES(w.data(), 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05);

    BerReader r(w.data().data(), w.size());
    std::vector<uint8_t> out;
    CHECK(r.read_octet_string(out) == Status::Ok);
    CHECK_BYTES(out, 0x01, 0x02, 0x03, 0x04, 0x05);
}

RTSC_TEST(octet_string_switches_to_long_form_length_at_128_bytes) {
    const auto p127 = pattern(127);
    BerWriter w_a;
    w_a.octet_string(p127);
    CHECK_EQ(w_a.size(), static_cast<size_t>(129));
    CHECK_EQ(static_cast<int>(w_a.data()[1]), 0x7F);

    const auto p128 = pattern(128);
    BerWriter w_b;
    w_b.octet_string(p128);
    CHECK_EQ(w_b.size(), static_cast<size_t>(131));
    CHECK_EQ(static_cast<int>(w_b.data()[1]), 0x81);
    CHECK_EQ(static_cast<int>(w_b.data()[2]), 0x80);

    BerReader r(w_b.data().data(), w_b.size());
    std::vector<uint8_t> out;
    CHECK(r.read_octet_string(out) == Status::Ok);
    CHECK(out == p128);
}

RTSC_TEST(octet_string_encodes_256_byte_length_in_two_length_bytes) {
    const auto p = pattern(256);
    BerWriter w;
    w.octet_string(p);
    CHECK_EQ(static_cast<int>(w.data()[1]), 0x82);
    CHECK_EQ(static_cast<int>(w.data()[2]), 0x01);
    CHECK_EQ(static_cast<int>(w.data()[3]), 0x00);
    CHECK_EQ(w.size(), static_cast<size_t>(260));

    BerReader r(w.data().data(), w.size());
    std::vector<uint8_t> out;
    CHECK(r.read_octet_string(out) == Status::Ok);
    CHECK(out == p);
}

RTSC_TEST(integer_encodes_small_positive_values_in_one_byte) {
    BerWriter w_a;
    w_a.integer(0);
    CHECK_BYTES(w_a.data(), 0x02, 0x01, 0x00);

    BerWriter w_b;
    w_b.integer(1);
    CHECK_BYTES(w_b.data(), 0x02, 0x01, 0x01);

    BerWriter w_c;
    w_c.integer(127);
    CHECK_BYTES(w_c.data(), 0x02, 0x01, 0x7F);
}

RTSC_TEST(integer_adds_leading_zero_when_high_bit_is_set) {
    BerWriter w_a;
    w_a.integer(128);
    CHECK_BYTES(w_a.data(), 0x02, 0x02, 0x00, 0x80);

    BerWriter w_b;
    w_b.integer(255);
    CHECK_BYTES(w_b.data(), 0x02, 0x02, 0x00, 0xFF);

    BerWriter w_c;
    w_c.integer(256);
    CHECK_BYTES(w_c.data(), 0x02, 0x02, 0x01, 0x00);
}

RTSC_TEST(integer_encodes_negative_values_in_twos_complement) {
    BerWriter w_a;
    w_a.integer(-1);
    CHECK_BYTES(w_a.data(), 0x02, 0x01, 0xFF);

    BerWriter w_b;
    w_b.integer(-128);
    CHECK_BYTES(w_b.data(), 0x02, 0x01, 0x80);

    BerWriter w_c;
    w_c.integer(-129);
    CHECK_BYTES(w_c.data(), 0x02, 0x02, 0xFF, 0x7F);
}

RTSC_TEST(integer_roundtrips_signed_boundary_values) {
    const int64_t values[] = {0,
                              1,
                              -1,
                              127,
                              128,
                              255,
                              256,
                              -128,
                              -129,
                              32767,
                              65535,
                              2147483647,
                              -2147483648LL,
                              static_cast<int64_t>(1) << 40};
    for (const int64_t v : values) {
        BerWriter w;
        w.integer(v);
        BerReader r(w.data().data(), w.size());
        int64_t got = 0;
        CHECK(r.read_integer(got) == Status::Ok);
        CHECK_EQ(got, v);
        CHECK_EQ(r.remaining(), static_cast<size_t>(0));
    }
}

RTSC_TEST(boolean_encodes_true_as_ff_and_decodes_any_nonzero) {
    BerWriter w_a;
    w_a.boolean(true);
    CHECK_BYTES(w_a.data(), 0x01, 0x01, 0xFF);

    BerWriter w_b;
    w_b.boolean(false);
    CHECK_BYTES(w_b.data(), 0x01, 0x01, 0x00);

    BerReader ra(w_a.data().data(), w_a.size());
    bool v = false;
    CHECK(ra.read_boolean(v) == Status::Ok);
    CHECK(v);

    BerReader rb(w_b.data().data(), w_b.size());
    v = true;
    CHECK(rb.read_boolean(v) == Status::Ok);
    CHECK(!v);

    const uint8_t one[3] = {0x01, 0x01, 0x01};
    BerReader rc(one, 3);
    v = false;
    CHECK(rc.read_boolean(v) == Status::Ok);
    CHECK(v);
}

RTSC_TEST(enumerated_encodes_tag_0a_and_reads_back_as_integer) {
    BerWriter w;
    w.enumerated(2);
    CHECK_BYTES(w.data(), 0x0A, 0x01, 0x02);

    BerReader r(w.data().data(), w.size());
    int64_t v = 0;
    CHECK(r.read_integer(v) == Status::Ok);
    CHECK_EQ(v, static_cast<int64_t>(2));
}

RTSC_TEST(empty_sequence_encodes_as_30_00) {
    BerWriter w;
    const size_t mark = w.begin_sequence();
    w.end_constructed(mark, kBerSequence);
    CHECK_BYTES(w.data(), 0x30, 0x00);

    BerReader r(w.data().data(), w.size());
    BerReader sub(nullptr, 0);
    CHECK(r.read_constructed(kBerSequence, sub) == Status::Ok);
    CHECK(sub.empty());
    CHECK_EQ(r.remaining(), static_cast<size_t>(0));
}

RTSC_TEST(nested_sequences_encode_inner_then_outer_lengths) {
    BerWriter w;
    const size_t outer = w.begin_sequence();
    const size_t inner = w.begin_sequence();
    w.end_constructed(inner, kBerSequence);
    w.end_constructed(outer, kBerSequence);
    CHECK_BYTES(w.data(), 0x30, 0x02, 0x30, 0x00);

    BerReader r(w.data().data(), w.size());
    BerReader sub(nullptr, 0);
    CHECK(r.read_constructed(kBerSequence, sub) == Status::Ok);
    BerReader inner_reader(nullptr, 0);
    CHECK(sub.read_constructed(kBerSequence, inner_reader) == Status::Ok);
    CHECK(inner_reader.empty());
    CHECK_EQ(sub.remaining(), static_cast<size_t>(0));
}

RTSC_TEST(constructed_element_encodes_200_byte_content_in_long_form) {
    const auto a = pattern(127);
    const auto b = pattern(69);
    BerWriter w;
    const size_t mark = w.begin_sequence();
    w.octet_string(a);
    w.octet_string(b);
    w.end_constructed(mark, kBerSequence);
    CHECK_EQ(static_cast<int>(w.data()[0]), 0x30);
    CHECK_EQ(static_cast<int>(w.data()[1]), 0x81);
    CHECK_EQ(static_cast<int>(w.data()[2]), 0xC8);
    CHECK_EQ(w.size(), static_cast<size_t>(3 + 200));
}

RTSC_TEST(end_constructed_keeps_content_aligned_when_length_grows) {
    const auto payload = pattern(127);
    BerWriter w;
    const size_t outer = w.begin_sequence();
    const size_t inner = w.begin_sequence();
    w.octet_string(payload);
    w.end_constructed(inner, kBerSequence);
    w.end_constructed(outer, kBerSequence);

    CHECK_EQ(static_cast<int>(w.data()[0]), 0x30);
    CHECK_EQ(static_cast<int>(w.data()[1]), 0x81);
    CHECK_EQ(static_cast<int>(w.data()[2]), 132);
    CHECK_EQ(static_cast<int>(w.data()[3]), 0x30);

    BerReader r(w.data().data(), w.size());
    BerReader sub(nullptr, 0);
    CHECK(r.read_constructed(kBerSequence, sub) == Status::Ok);
    CHECK_EQ(r.remaining(), static_cast<size_t>(0));
    BerReader leaf(nullptr, 0);
    CHECK(sub.read_constructed(kBerSequence, leaf) == Status::Ok);
    CHECK_EQ(sub.remaining(), static_cast<size_t>(0));
    std::vector<uint8_t> got;
    CHECK(leaf.read_octet_string(got) == Status::Ok);
    CHECK(got == payload);
    CHECK(leaf.empty());
}

RTSC_TEST(read_header_needs_more_data_for_empty_input) {
    const uint8_t dummy[1] = {0};
    BerReader r(dummy, 0);
    uint8_t tag = 0;
    const uint8_t* value = nullptr;
    size_t n = 0;
    CHECK(r.read_header(tag, value, n) == Status::NeedMoreData);
    CHECK_EQ(r.offset(), static_cast<size_t>(0));
}

RTSC_TEST(read_header_needs_more_data_with_only_tag_byte) {
    const uint8_t buf[1] = {0x04};
    BerReader r(buf, 1);
    uint8_t tag = 0;
    const uint8_t* value = nullptr;
    size_t n = 0;
    CHECK(r.read_header(tag, value, n) == Status::NeedMoreData);
}

RTSC_TEST(read_header_rejects_indefinite_length) {
    const uint8_t buf[3] = {0x04, 0x80, 0x00};
    BerReader r(buf, 3);
    uint8_t tag = 0;
    const uint8_t* value = nullptr;
    size_t n = 0;
    CHECK(r.read_header(tag, value, n) == Status::InvalidLength);
}

RTSC_TEST(read_header_rejects_length_byte_count_above_four) {
    const uint8_t buf[8] = {0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    BerReader r(buf, 8);
    uint8_t tag = 0;
    const uint8_t* value = nullptr;
    size_t n = 0;
    CHECK(r.read_header(tag, value, n) == Status::InvalidLength);
}

RTSC_TEST(read_header_rejects_non_minimal_long_form_length) {
    const uint8_t buf[8] = {0x04, 0x81, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00};
    BerReader r(buf, 8);
    uint8_t tag = 0;
    const uint8_t* value = nullptr;
    size_t n = 0;
    CHECK(r.read_header(tag, value, n) == Status::InvalidLength);
}

RTSC_TEST(read_header_rejects_long_form_with_leading_zero) {
    const uint8_t buf[8] = {0x04, 0x82, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04};
    BerReader r(buf, 8);
    uint8_t tag = 0;
    const uint8_t* value = nullptr;
    size_t n = 0;
    CHECK(r.read_header(tag, value, n) == Status::InvalidLength);
}

RTSC_TEST(read_header_needs_more_data_when_value_truncated) {
    const uint8_t buf[4] = {0x04, 0x05, 0x01, 0x02};
    BerReader r(buf, 4);
    uint8_t tag = 0;
    const uint8_t* value = nullptr;
    size_t n = 0;
    CHECK(r.read_header(tag, value, n) == Status::NeedMoreData);
}

RTSC_TEST(read_boolean_rejects_non_boolean_tag) {
    const uint8_t buf[3] = {0x02, 0x01, 0x00};
    BerReader r(buf, 3);
    bool v = false;
    CHECK(r.read_boolean(v) == Status::InvalidType);
}

RTSC_TEST(read_boolean_rejects_value_length_other_than_one) {
    const uint8_t buf[4] = {0x01, 0x02, 0x00, 0x00};
    BerReader r(buf, 4);
    bool v = false;
    CHECK(r.read_boolean(v) == Status::InvalidLength);
}

RTSC_TEST(read_integer_rejects_empty_value) {
    const uint8_t buf[2] = {0x02, 0x00};
    BerReader r(buf, 2);
    int64_t v = 0;
    CHECK(r.read_integer(v) == Status::InvalidLength);
}

RTSC_TEST(read_integer_rejects_value_longer_than_eight_bytes) {
    const uint8_t buf[11] = {0x02, 0x09, 0x01, 0x02, 0x03, 0x04,
                             0x05, 0x06, 0x07, 0x08, 0x09};
    BerReader r(buf, 11);
    int64_t v = 0;
    CHECK(r.read_integer(v) == Status::InvalidLength);
}

RTSC_TEST(read_octet_string_rejects_integer_tag) {
    const uint8_t buf[3] = {0x02, 0x01, 0x00};
    BerReader r(buf, 3);
    std::vector<uint8_t> out;
    CHECK(r.read_octet_string(out) == Status::InvalidType);
}

RTSC_TEST(read_constructed_rejects_unexpected_tag) {
    const uint8_t buf[5] = {0x31, 0x03, 0x02, 0x01, 0x05};
    BerReader r(buf, 5);
    BerReader sub(nullptr, 0);
    CHECK(r.read_constructed(kBerSequence, sub) == Status::InvalidType);
}

RTSC_TEST(read_constructed_returns_value_subreader_and_advances_parent) {
    const uint8_t buf[5] = {0x30, 0x03, 0x02, 0x01, 0x05};
    BerReader r(buf, 5);
    BerReader sub(nullptr, 0);
    CHECK(r.read_constructed(kBerSequence, sub) == Status::Ok);
    CHECK_EQ(sub.remaining(), static_cast<size_t>(3));
    int64_t v = 0;
    CHECK(sub.read_integer(v) == Status::Ok);
    CHECK_EQ(v, static_cast<int64_t>(5));
    CHECK(sub.empty());
    CHECK_EQ(r.remaining(), static_cast<size_t>(0));
    CHECK_EQ(r.offset(), static_cast<size_t>(5));
}

RTSC_TEST(peek_tag_does_not_consume_and_reports_empty_input) {
    const uint8_t buf[2] = {0x04, 0x00};
    BerReader r(buf, 2);
    uint8_t tag = 0;
    CHECK(r.peek_tag(tag));
    CHECK_EQ(tag, static_cast<uint8_t>(0x04));
    CHECK_EQ(r.offset(), static_cast<size_t>(0));
    CHECK(r.peek_tag(tag));
    CHECK_EQ(r.offset(), static_cast<size_t>(0));

    BerReader empty(buf, 0);
    CHECK(!empty.peek_tag(tag));
    CHECK_EQ(empty.offset(), static_cast<size_t>(0));
}

RTSC_TEST(read_header_exposes_value_span_of_three_bytes) {
    const uint8_t buf[5] = {0x04, 0x03, 0xAA, 0xBB, 0xCC};
    BerReader r(buf, 5);
    uint8_t tag = 0;
    const uint8_t* value = nullptr;
    size_t n = 0;
    CHECK(r.read_header(tag, value, n) == Status::Ok);
    CHECK_EQ(tag, static_cast<uint8_t>(0x04));
    CHECK_EQ(n, static_cast<size_t>(3));
    CHECK(value == buf + 2);
    CHECK_BYTES(std::vector<uint8_t>(value, value + n), 0xAA, 0xBB, 0xCC);
    CHECK_EQ(r.remaining(), static_cast<size_t>(0));
}

RTSC_TEST(connect_initial_application_tag_roundtrips_short_and_long_lengths) {
    const auto small = pattern(8);
    BerWriter short_w;
    const size_t short_mark = short_w.begin_constructed(0x7F);
    short_w.raw_byte(0x65);
    short_w.octet_string(small);
    short_w.end_constructed(short_mark, 0x7F);
    const auto short_bytes = short_w.take();
    CHECK_EQ(static_cast<int>(short_bytes[0]), 0x7F);
    CHECK_EQ(static_cast<int>(short_bytes[1]), 11);
    CHECK_EQ(static_cast<int>(short_bytes[2]), 0x65);

    BerReader ra(short_bytes.data(), short_bytes.size());
    uint8_t tag = 0;
    const uint8_t* value = nullptr;
    size_t n = 0;
    CHECK(ra.read_header(tag, value, n) == Status::Ok);
    CHECK_EQ(tag, static_cast<uint8_t>(0x7F));
    CHECK_EQ(n, static_cast<size_t>(11));
    CHECK_EQ(static_cast<int>(value[0]), 0x65);
    CHECK_EQ(ra.remaining(), static_cast<size_t>(0));

    const auto large = pattern(200);
    BerWriter long_w;
    const size_t long_mark = long_w.begin_constructed(0x7F);
    long_w.raw_byte(0x65);
    long_w.octet_string(large);
    long_w.end_constructed(long_mark, 0x7F);
    const auto long_bytes = long_w.take();
    CHECK_EQ(static_cast<int>(long_bytes[0]), 0x7F);
    CHECK_EQ(static_cast<int>(long_bytes[1]), 0x81);
    CHECK_EQ(static_cast<int>(long_bytes[2]), 204);

    BerReader rb(long_bytes.data(), long_bytes.size());
    CHECK(rb.read_header(tag, value, n) == Status::Ok);
    CHECK_EQ(tag, static_cast<uint8_t>(0x7F));
    CHECK_EQ(n, static_cast<size_t>(204));
    CHECK_EQ(static_cast<int>(value[0]), 0x65);
    CHECK_EQ(rb.remaining(), static_cast<size_t>(0));

    std::vector<uint8_t> payload;
    BerReader value_reader(value + 1, n - 1);
    CHECK(value_reader.read_octet_string(payload) == Status::Ok);
    CHECK(payload == large);
}

RTSC_TEST(user_data_octet_string_encodes_432_byte_length_in_long_form) {
    const auto payload = pattern(432);
    BerWriter w;
    w.octet_string(payload);
    CHECK_EQ(static_cast<int>(w.data()[0]), 0x04);
    CHECK_EQ(static_cast<int>(w.data()[1]), 0x82);
    CHECK_EQ(static_cast<int>(w.data()[2]), 0x01);
    CHECK_EQ(static_cast<int>(w.data()[3]), 0xB0);
    CHECK_EQ(w.size(), static_cast<size_t>(436));

    BerReader r(w.data().data(), w.size());
    std::vector<uint8_t> got;
    CHECK(r.read_octet_string(got) == Status::Ok);
    CHECK_EQ(got.size(), static_cast<size_t>(432));
    CHECK(got == payload);
}

int main() { return rtsc::test::run_all("rtsc_ber_tests"); }
