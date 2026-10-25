#include <cstdio>

#include "rtsc/proto/connection_initiation.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/proto/tpkt.h"
#include "rtsc/proto/x224.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> hex(const char* s) {
    std::vector<uint8_t> out;
    while (*s) {
        while (*s == ' ') ++s;
        if (!*s) break;
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(s[0]);
        int lo = nib(s[1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        s += 2;
    }
    return out;
}

}  // namespace

RTSC_TEST(tpkt_parse_rejects_short_buffer) {
    const uint8_t buf[3] = {0x03, 0x00, 0x00};
    TpktHeader h;
    CHECK(TpktHeader::parse(buf, 3, h) == Status::NeedMoreData);
}

RTSC_TEST(tpkt_parse_rejects_bad_version) {
    const uint8_t buf[4] = {0x04, 0x00, 0x00, 0x13};
    TpktHeader h;
    CHECK(TpktHeader::parse(buf, 4, h) == Status::InvalidVersion);
}

RTSC_TEST(tpkt_parse_rejects_nonzero_reserved) {
    const uint8_t buf[4] = {0x03, 0x01, 0x00, 0x13};
    TpktHeader h;
    CHECK(TpktHeader::parse(buf, 4, h) == Status::InvalidReserved);
}

RTSC_TEST(tpkt_parse_reads_big_endian_length) {
    const uint8_t buf[4] = {0x03, 0x00, 0x01, 0x2C};
    TpktHeader h;
    CHECK(TpktHeader::parse(buf, 4, h) == Status::Ok);
    CHECK_EQ(h.length, 0x012C);
    CHECK_EQ(h.payload_size(), 0x012C - 4);
}

RTSC_TEST(tpkt_validate_rejects_length_below_header) {
    TpktHeader h;
    h.length = 3;
    CHECK(h.validate(3) == Status::InvalidLength);
}

RTSC_TEST(tpkt_validate_needs_more_data_when_truncated) {
    TpktHeader h;
    h.length = 19;
    CHECK(h.validate(10) == Status::NeedMoreData);
    CHECK(h.validate(19) == Status::Ok);
    CHECK(h.validate(64) == Status::Ok);
}

RTSC_TEST(tpkt_encode_roundtrip) {
    TpktHeader h;
    h.length = 19;
    CHECK_BYTES(h.encode(), 0x03, 0x00, 0x00, 0x13);
}

RTSC_TEST(x224_parse_connection_confirm_from_spec_dump) {
    const auto bytes = hex("0e d0 00 00 12 34 00");
    X224Tpdu t;
    CHECK(X224Tpdu::parse(bytes.data(), bytes.size(), t) == Status::Ok);
    CHECK_EQ(t.length_indicator, 0x0E);
    CHECK_EQ(t.code, X224Tpdu::kConnectionConfirm);
    CHECK_EQ(t.destination_reference, 0);
    CHECK_EQ(t.source_reference, 0x1234);
    CHECK_EQ(t.class_options, 0);
}

RTSC_TEST(x224_parse_rejects_short_buffer) {
    const auto bytes = hex("0e d0 00 00 12");
    X224Tpdu t;
    CHECK(X224Tpdu::parse(bytes.data(), bytes.size(), t) == Status::NeedMoreData);
}

RTSC_TEST(x224_validate_rejects_data_tpdu) {
    X224Tpdu t;
    t.code = X224Tpdu::kData;
    CHECK(t.validate() == Status::InvalidType);
}

RTSC_TEST(x224_validate_rejects_parameters_li) {
    X224Tpdu t = X224Tpdu::make_connection_request();
    t.length_indicator = 8;
    CHECK(t.validate() == Status::InvalidLength);
}

RTSC_TEST(x224_validate_rejects_nonzero_class) {
    X224Tpdu t = X224Tpdu::make_connection_request();
    t.class_options = 0x02;
    CHECK(t.validate() == Status::InvalidField);
}

RTSC_TEST(x224_connection_request_encoding) {
    const auto crq = X224Tpdu::make_connection_request();
    CHECK_BYTES(crq.encode(), 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00);
}

RTSC_TEST(x224_connection_confirm_encoding_uses_spec_source_ref) {
    const auto ccf = X224Tpdu::make_connection_confirm();
    CHECK_BYTES(ccf.encode(), 0x06, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00);
}

RTSC_TEST(x224_data_prefix_parse_and_encode) {
    const auto bytes = hex("02 f0 80");
    CHECK(X224DataPrefix::parse(bytes.data(), bytes.size()) == Status::Ok);
    ByteWriter w;
    X224DataPrefix::encode(w);
    CHECK_BYTES(w.data(), 0x02, 0xF0, 0x80);
}

RTSC_TEST(x224_data_prefix_rejects_bad_eot) {
    const auto bytes = hex("02 f0 00");
    CHECK(X224DataPrefix::parse(bytes.data(), bytes.size()) == Status::InvalidField);
}

RTSC_TEST(neg_req_encode_matches_spec_layout) {
    RdpNegReq req;
    req.flags = 0;
    req.requested_protocols = kProtocolSsl | kProtocolHybrid;
    CHECK_BYTES(req.encode(), 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00);
}

RTSC_TEST(neg_parse_response_from_spec_dump) {
    const auto bytes = hex("02 00 08 00 00 00 00 00");
    RdpNegData d;
    CHECK(RdpNegData::parse(bytes.data(), bytes.size(), d) == Status::Ok);
    CHECK(d.kind == RdpNegData::Kind::kResponse);
    CHECK_EQ(d.response.flags, 0);
    CHECK_EQ(d.response.selected_protocol, static_cast<uint32_t>(kProtocolRdp));
}

RTSC_TEST(neg_parse_response_hybrid) {
    const auto bytes = hex("02 03 08 00 02 00 00 00");
    RdpNegData d;
    CHECK(RdpNegData::parse(bytes.data(), bytes.size(), d) == Status::Ok);
    CHECK(d.kind == RdpNegData::Kind::kResponse);
    CHECK_EQ(d.response.flags, 0x03);
    CHECK_EQ(d.response.selected_protocol, static_cast<uint32_t>(kProtocolHybrid));
}

RTSC_TEST(neg_parse_failure) {
    const auto bytes = hex("03 00 08 00 05 00 00 00");
    RdpNegData d;
    CHECK(RdpNegData::parse(bytes.data(), bytes.size(), d) == Status::Ok);
    CHECK(d.kind == RdpNegData::Kind::kFailure);
    CHECK(d.failure.failure_code == NegFailureCode::kHybridRequiredByServer);
}

RTSC_TEST(neg_parse_empty_is_none) {
    RdpNegData d;
    CHECK(RdpNegData::parse(nullptr, 0, d) == Status::Ok);
    CHECK(d.kind == RdpNegData::Kind::kNone);
}

RTSC_TEST(neg_parse_rejects_short) {
    const auto bytes = hex("02 00 08");
    RdpNegData d;
    CHECK(RdpNegData::parse(bytes.data(), bytes.size(), d) == Status::InvalidLength);
}

RTSC_TEST(neg_parse_rejects_wrong_declared_length) {
    const auto bytes = hex("02 00 07 00 00 00 00 00");
    RdpNegData d;
    CHECK(RdpNegData::parse(bytes.data(), bytes.size(), d) == Status::InvalidLength);
}

RTSC_TEST(neg_parse_rejects_request_type_in_response_slot) {
    const auto bytes = hex("01 00 08 00 00 00 00 00");
    RdpNegData d;
    CHECK(RdpNegData::parse(bytes.data(), bytes.size(), d) == Status::InvalidType);
}

RTSC_TEST(ccf_parse_official_annotated_dump) {
    const auto bytes = hex("03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 00 00 00");
    X224ConnectionConfirm ccf;
    CHECK(X224ConnectionConfirm::parse(bytes.data(), bytes.size(), ccf) == Status::Ok);
    CHECK_EQ(ccf.x224.code, X224Tpdu::kConnectionConfirm);
    CHECK_EQ(ccf.x224.source_reference, 0x1234);
    CHECK(ccf.neg_data.kind == RdpNegData::Kind::kResponse);
    CHECK_EQ(ccf.neg_data.response.selected_protocol, static_cast<uint32_t>(kProtocolRdp));
}

RTSC_TEST(ccf_parse_without_neg_data_implies_standard_rdp) {
    const auto bytes = hex("03 00 00 0B 0e d0 00 00 12 34 00");
    X224ConnectionConfirm ccf;
    CHECK(X224ConnectionConfirm::parse(bytes.data(), bytes.size(), ccf) == Status::Ok);
    CHECK(ccf.neg_data.kind == RdpNegData::Kind::kNone);
}

RTSC_TEST(ccf_parse_rejects_truncated) {
    const auto bytes = hex("03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00");
    X224ConnectionConfirm ccf;
    CHECK(X224ConnectionConfirm::parse(bytes.data(), bytes.size(), ccf) ==
          Status::NeedMoreData);
}

RTSC_TEST(ccf_parse_rejects_inconsistent_tpkt_length) {
    // TPKT claims 12 bytes but X.224 LI claims 14 => payload too small.
    const auto bytes = hex("03 00 00 0C 0e d0 00 00 12 34 00 00");
    X224ConnectionConfirm ccf;
    CHECK(X224ConnectionConfirm::parse(bytes.data(), bytes.size(), ccf) ==
          Status::InvalidLength);
}

RTSC_TEST(ccf_parse_rejects_crq_code) {
    const auto bytes = hex("03 00 00 13 0e e0 00 00 00 00 00 02 00 08 00 00 00 00 00");
    X224ConnectionConfirm ccf;
    CHECK(X224ConnectionConfirm::parse(bytes.data(), bytes.size(), ccf) ==
          Status::InvalidType);
}

RTSC_TEST(crq_encode_minimal_matches_spec_layout) {
    X224ConnectionRequest req;
    req.include_neg_req = true;
    req.neg_req.requested_protocols = kProtocolRdp;
    req.neg_req.flags = 0;
    const auto bytes = req.encode();
    CHECK_BYTES(bytes,
                0x03, 0x00, 0x00, 0x13,              // TPKT, total 19
                0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,  // X.224 CRQ
                0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00);  // RDP_NEG_REQ
}

RTSC_TEST(crq_encode_with_cookie_grows_length_fields) {
    X224ConnectionRequest req;
    req.cookie = "Cookie: mstshash=tester";
    req.neg_req.requested_protocols = kProtocolSsl | kProtocolHybrid;
    const auto bytes = req.encode();

    const size_t expected = 4 + 7 + (req.cookie.size() + 2) + 8;
    CHECK_EQ(bytes.size(), expected);
    CHECK_EQ(bytes[2], static_cast<uint8_t>(expected >> 8));
    CHECK_EQ(bytes[3], static_cast<uint8_t>(expected & 0xFF));
    CHECK_EQ(bytes[4], static_cast<uint8_t>(6 + req.cookie.size() + 2 + 8));
    CHECK(bytes[11] == 'C');
    const size_t cookie_end = 11 + req.cookie.size();
    CHECK_EQ(bytes[cookie_end], 0x0D);
    CHECK_EQ(bytes[cookie_end + 1], 0x0A);
    // The negotiation request follows the cookie terminator.
    CHECK_EQ(bytes[cookie_end + 2], 0x01);
}

RTSC_TEST(crq_encode_without_neg_req) {
    X224ConnectionRequest req;
    req.include_neg_req = false;
    const auto bytes = req.encode();
    CHECK_EQ(bytes.size(), static_cast<size_t>(11));
    CHECK_EQ(bytes[3], static_cast<uint8_t>(11));
    CHECK_EQ(bytes[4], static_cast<uint8_t>(6));
}

RTSC_TEST(crq_routing_token_excludes_cookie) {
    X224ConnectionRequest req;
    req.cookie = "Cookie: mstshash=tester";
    req.routing_token = "token";
    req.include_neg_req = false;
    const auto bytes = req.encode();
    CHECK_EQ(bytes.size(), static_cast<size_t>(4 + 7 + 7));
    CHECK(bytes[11] == 't');
}

RTSC_TEST(correlation_info_is_36_bytes) {
    CorrelationInfo ci;
    ci.id = 0x1122334455667788ull;
    CHECK_EQ(ci.encode().size(), CorrelationInfo::kSize);
}

RTSC_TEST(crq_with_correlation_info_sets_flag_and_size) {
    X224ConnectionRequest req;
    req.include_neg_req = true;
    req.neg_req.flags = kCorrelationInfoPresent;
    req.include_correlation_info = true;
    const auto bytes = req.encode();
    CHECK_EQ(bytes.size(), static_cast<size_t>(4 + 7 + 8 + 36));
    CHECK_EQ(bytes[12], static_cast<uint8_t>(kCorrelationInfoPresent));
}

RTSC_TEST(read_framed_pdu_consumes_exact_length) {
    const auto bytes = hex("03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 00 00 00");
    FramedPdu pdu;
    size_t consumed = 0;
    CHECK(read_framed_pdu(bytes.data(), bytes.size(), pdu, consumed) == Status::Ok);
    CHECK_EQ(consumed, bytes.size());
    CHECK_EQ(pdu.payload.size(), bytes.size() - 4);
}

RTSC_TEST(read_framed_pdu_handles_back_to_back_pdus) {
    std::vector<uint8_t> buf = hex("03 00 00 0B 0e d0 00 00 12 34 00");
    const auto second = hex("03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 00 00 00");
    buf.insert(buf.end(), second.begin(), second.end());

    FramedPdu pdu;
    size_t consumed = 0;
    CHECK(read_framed_pdu(buf.data(), buf.size(), pdu, consumed) == Status::Ok);
    CHECK_EQ(consumed, static_cast<size_t>(11));
    CHECK(read_framed_pdu(buf.data() + consumed, buf.size() - consumed, pdu, consumed) ==
          Status::Ok);
    CHECK_EQ(consumed, second.size());
}

RTSC_TEST(read_framed_pdu_needs_more_data_on_partial) {
    const auto bytes = hex("03 00 00 13 0e d0 00 00");
    FramedPdu pdu;
    size_t consumed = 0;
    CHECK(read_framed_pdu(bytes.data(), bytes.size(), pdu, consumed) ==
          Status::NeedMoreData);
}

int main() { return rtsc::test::run_all("rtsc_tests"); }
