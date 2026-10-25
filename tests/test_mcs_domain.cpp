// MCS domain / channel establishment layer.
//
// Every byte vector below is copied verbatim from docs/spec/mcs-domain.md 搂12
// (the annotated dumps of [MS-RDPBCGR] 4.1.5 .. 4.1.12), so a failure here means
// the encoder/decoder diverges from the published wire format.

#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/mcs.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> hex(const char* s) {
    std::vector<uint8_t> out;
    int hi = -1;
    for (const char* p = s; *p != '\0'; ++p) {
        int v = -1;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else continue;
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

// First differing offset, or `size` when identical.
size_t first_difference(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    const size_t n = a.size() < b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return i;
    }
    return (a.size() == b.size()) ? a.size() : n;
}

}  // namespace

// ---- Erect Domain Request -------------------------------------------------

RTSC_TEST(erect_domain_request_matches_spec_vector) {
    const auto want = hex("03 00 00 0c 02 f0 80 04 01 00 01 00");
    const auto got = McsErectDomainRequest::build();
    CHECK_EQ(first_difference(got, want), want.size());
    CHECK_EQ(got.size(), static_cast<size_t>(12));
}

RTSC_TEST(erect_domain_request_roundtrips_zero_fields) {
    const auto bytes = McsErectDomainRequest::build();
    McsErectDomainRequest out;
    CHECK(McsErectDomainRequest::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK_EQ(out.sub_height, 0u);
    CHECK_EQ(out.sub_interval, 0u);
}

RTSC_TEST(erect_domain_request_roundtrips_nonzero_fields) {
    const auto bytes = McsErectDomainRequest::build(7, 1000);
    McsErectDomainRequest out;
    CHECK(McsErectDomainRequest::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK_EQ(out.sub_height, 7u);
    CHECK_EQ(out.sub_interval, 1000u);
}

RTSC_TEST(erect_domain_request_rejects_wrong_choice) {
    // Attach User Request octet (0x28) is not choice 1.
    const auto bytes = hex("03 00 00 08 02 f0 80 28");
    McsErectDomainRequest out;
    CHECK(McsErectDomainRequest::parse(bytes.data(), bytes.size(), out) ==
          Status::InvalidType);
}

RTSC_TEST(erect_domain_request_rejects_tpkt_length_mismatch) {
    auto bytes = hex("03 00 00 0c 02 f0 80 04 01 00 01 00");
    bytes[3] = 0x0D;  // claim 13 bytes, supply 12
    McsErectDomainRequest out;
    CHECK(McsErectDomainRequest::parse(bytes.data(), bytes.size(), out) ==
          Status::InvalidLength);
}

RTSC_TEST(erect_domain_request_rejects_non_x224_data_prefix) {
    auto bytes = hex("03 00 00 0c 02 f0 80 04 01 00 01 00");
    bytes[4] = 0xF0;  // X.224 code must be 0xF0 (Data TPDU)
    McsErectDomainRequest out;
    CHECK(McsErectDomainRequest::parse(bytes.data(), bytes.size(), out) ==
          Status::InvalidType);
}

// ---- Attach User Request --------------------------------------------------

RTSC_TEST(attach_user_request_matches_spec_vector) {
    const auto want = hex("03 00 00 08 02 f0 80 28");
    const auto got = McsAttachUserRequest::build();
    CHECK_EQ(first_difference(got, want), want.size());
    CHECK_EQ(got.size(), static_cast<size_t>(8));
}

RTSC_TEST(attach_user_request_parses_own_output) {
    const auto bytes = McsAttachUserRequest::build();
    CHECK(McsAttachUserRequest::parse(bytes.data(), bytes.size()) == Status::Ok);
}

RTSC_TEST(attach_user_request_rejects_extra_body_octets) {
    // 9-byte TPKT whose body has one octet too many.
    const auto bytes = hex("03 00 00 09 02 f0 80 28 00");
    CHECK(McsAttachUserRequest::parse(bytes.data(), bytes.size()) ==
          Status::InvalidLength);
}

// ---- Attach User Confirm --------------------------------------------------

RTSC_TEST(attach_user_confirm_matches_spec_vector) {
    // [MS-RDPBCGR] 4.1.6: 2e 00 00 06 -> choice 11, present, result 0, id 1007.
    const auto bytes = hex("03 00 00 0b 02 f0 80 2e 00 00 06");
    McsAttachUserConfirm out;
    CHECK(McsAttachUserConfirm::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK(out.result == McsResult::kSuccessful);
    CHECK(out.has_initiator);
    CHECK_EQ(out.initiator, static_cast<uint16_t>(1007));
}

RTSC_TEST(attach_user_confirm_decodes_unspecified_failure_without_initiator) {
    // result = 14 (1110), no initiator: 0x2D (choice 11, present=0, result bit3=1),
    // second octet 110 00000 = 0xC0.
    const auto bytes = hex("03 00 00 09 02 f0 80 2d c0");
    McsAttachUserConfirm out;
    CHECK(McsAttachUserConfirm::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK(out.result == McsResult::kUnspecifiedFailure);
    CHECK(!out.has_initiator);
}

RTSC_TEST(attach_user_confirm_maps_every_result_value) {
    // Exercise all 16 enum values through the same bit layout the decoder reads.
    for (uint8_t v = 0; v <= 15; ++v) {
        const uint8_t b0 = static_cast<uint8_t>(0x2C | ((v >> 3) & 0x01));
        const uint8_t b1 = static_cast<uint8_t>((v & 0x07) << 5);
        const std::vector<uint8_t> bytes = {0x03, 0x00, 0x00, 0x09, 0x02,
                                            0xF0, 0x80, b0,   b1};
        McsAttachUserConfirm out;
        CHECK(McsAttachUserConfirm::parse(bytes.data(), bytes.size(), out) ==
              Status::Ok);
        CHECK_EQ(static_cast<uint8_t>(out.result), v);
    }
}

RTSC_TEST(attach_user_confirm_rejects_nonzero_padding) {
    const auto bytes = hex("03 00 00 0b 02 f0 80 2e 01 00 06");
    McsAttachUserConfirm out;
    CHECK(McsAttachUserConfirm::parse(bytes.data(), bytes.size(), out) ==
          Status::InvalidField);
}

// ---- Channel Join Request -------------------------------------------------

RTSC_TEST(channel_join_request_matches_user_channel_vector) {
    const auto want = hex("03 00 00 0c 02 f0 80 38 00 06 03 ef");
    const auto got = McsChannelJoinRequest::build(1007, 1007);
    CHECK_EQ(first_difference(got, want), want.size());
}

RTSC_TEST(channel_join_request_matches_io_channel_vector) {
    const auto want = hex("03 00 00 0c 02 f0 80 38 00 06 03 eb");
    const auto got = McsChannelJoinRequest::build(1007, 1003);
    CHECK_EQ(first_difference(got, want), want.size());
}

RTSC_TEST(channel_join_request_matches_all_static_virtual_channels) {
    struct Case {
        uint16_t channel;
        const char* bytes;
    };
    const Case cases[] = {
        {1004, "03 00 00 0c 02 f0 80 38 00 06 03 ec"},
        {1005, "03 00 00 0c 02 f0 80 38 00 06 03 ed"},
        {1006, "03 00 00 0c 02 f0 80 38 00 06 03 ee"},
    };
    for (const auto& c : cases) {
        const auto want = hex(c.bytes);
        const auto got = McsChannelJoinRequest::build(1007, c.channel);
        CHECK_EQ(first_difference(got, want), want.size());
    }
}

RTSC_TEST(channel_join_request_roundtrips) {
    const auto bytes = McsChannelJoinRequest::build(1007, 1003);
    McsChannelJoinRequest out;
    CHECK(McsChannelJoinRequest::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK_EQ(out.initiator, static_cast<uint16_t>(1007));
    CHECK_EQ(out.channel_id, static_cast<uint16_t>(1003));
}

RTSC_TEST(channel_join_request_accepts_zero_channel_id) {
    // T.125 搂11.21: channelId may be zero to request a new assigned channel.
    const auto bytes = McsChannelJoinRequest::build(1007, 0);
    McsChannelJoinRequest out;
    CHECK(McsChannelJoinRequest::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK_EQ(out.channel_id, static_cast<uint16_t>(0));
}

RTSC_TEST(channel_join_request_rejects_user_id_below_1001) {
    CHECK(McsChannelJoinRequest::build(1000, 1003).empty());
    CHECK(McsChannelJoinRequest::build(0, 1003).empty());
}

// ---- Channel Join Confirm -------------------------------------------------

RTSC_TEST(channel_join_confirm_matches_user_channel_vector) {
    const auto bytes = hex("03 00 00 0f 02 f0 80 3e 00 00 06 03 ef 03 ef");
    McsChannelJoinConfirm out;
    CHECK(McsChannelJoinConfirm::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK(out.result == McsResult::kSuccessful);
    CHECK(out.has_channel_id);
    CHECK_EQ(out.initiator, static_cast<uint16_t>(1007));
    CHECK_EQ(out.requested, static_cast<uint16_t>(1007));
    CHECK_EQ(out.channel_id, static_cast<uint16_t>(1007));
}

RTSC_TEST(channel_join_confirm_matches_all_channel_vectors) {
    struct Case {
        const char* bytes;
        uint16_t channel;
    };
    const Case cases[] = {
        {"03 00 00 0f 02 f0 80 3e 00 00 06 03 eb 03 eb", 1003},
        {"03 00 00 0f 02 f0 80 3e 00 00 06 03 ec 03 ec", 1004},
        {"03 00 00 0f 02 f0 80 3e 00 00 06 03 ed 03 ed", 1005},
        {"03 00 00 0f 02 f0 80 3e 00 00 06 03 ee 03 ee", 1006},
    };
    for (const auto& c : cases) {
        const auto bytes = hex(c.bytes);
        McsChannelJoinConfirm out;
        CHECK(McsChannelJoinConfirm::parse(bytes.data(), bytes.size(), out) ==
              Status::Ok);
        CHECK_EQ(out.channel_id, c.channel);
    }
}

RTSC_TEST(channel_join_confirm_accepts_absent_optional_channel_id) {
    // Derived layout when channelId is absent: 0x3C 0x00 then initiator+requested.
    const auto bytes = hex("03 00 00 0d 02 f0 80 3c 00 00 06 03 ef");
    McsChannelJoinConfirm out;
    CHECK(McsChannelJoinConfirm::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK(!out.has_channel_id);
    CHECK_EQ(out.requested, static_cast<uint16_t>(1007));
}

RTSC_TEST(channel_join_confirm_reports_unspecified_failure) {
    const auto bytes = hex("03 00 00 0f 02 f0 80 3f c0 00 06 03 ef 03 ef");
    McsChannelJoinConfirm out;
    CHECK(McsChannelJoinConfirm::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK(out.result == McsResult::kUnspecifiedFailure);
}

// ---- Send Data ------------------------------------------------------------

RTSC_TEST(send_data_request_matches_spec_vector) {
    // 0x50 = 80 bytes of userData in the [MS-RDPBCGR] 4.1.8 dump.
    std::vector<uint8_t> payload(80, 0xAA);
    const auto got = McsSendData::build_request(1007, 1003, payload);
    const auto want = hex("03 00 00 5e 02 f0 80 64 00 06 03 eb 70 50");
    CHECK_EQ(got.size(), static_cast<size_t>(4 + 3 + 7 + 80));
    CHECK_EQ(first_difference(got, want), want.size());
}

RTSC_TEST(send_data_request_header_is_fixed_0x70_flags) {
    std::vector<uint8_t> payload(4, 0x00);
    const auto got = McsSendData::build_request(1007, 1003, payload);
    // offsets: 0..3 TPKT, 4..6 X.224, 7 choice, 8..9 initiator, 10..11 channelId
    CHECK_EQ(got[7], static_cast<uint8_t>(0x64));
    CHECK_EQ(got[12], static_cast<uint8_t>(0x70));
}

RTSC_TEST(send_data_indication_matches_spec_vector_prefix) {
    // [MS-RDPBCGR] 4.1.12: 68 00 01 03 eb 70 81 73 -> initiator 1002.
    std::vector<uint8_t> payload(371, 0x00);
    const auto got = McsSendData::build_indication(1002, 1003, payload);
    CHECK_EQ(got[7], static_cast<uint8_t>(0x68));
    CHECK_EQ(got[8], static_cast<uint8_t>(0x00));
    CHECK_EQ(got[9], static_cast<uint8_t>(0x01));
    CHECK_EQ(got[10], static_cast<uint8_t>(0x03));
    CHECK_EQ(got[11], static_cast<uint8_t>(0xEB));
    CHECK_EQ(got[12], static_cast<uint8_t>(0x70));
    CHECK_EQ(got[13], static_cast<uint8_t>(0x81));
    CHECK_EQ(got[14], static_cast<uint8_t>(0x73));
}

RTSC_TEST(send_data_roundtrips_user_data) {
    std::vector<uint8_t> payload;
    for (int i = 0; i < 300; ++i) payload.push_back(static_cast<uint8_t>(i));
    const auto bytes = McsSendData::build_request(1007, 1003, payload);
    McsSendData out;
    CHECK(McsSendData::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK_EQ(out.initiator, static_cast<uint16_t>(1007));
    CHECK_EQ(out.channel_id, static_cast<uint16_t>(1003));
    CHECK(out.priority == McsDataPriority::kHigh);
    CHECK(out.segmentation == McsSegmentation::kBeginEnd);
    CHECK(out.user_data == payload);
}

RTSC_TEST(send_data_uses_two_octet_length_at_128_bytes) {
    std::vector<uint8_t> payload(412, 0x00);
    const auto bytes = McsSendData::build_request(1007, 1003, payload);
    // 412 = 0x19C -> 81 9C (matches the [MS-RDPBCGR] 4.1.9 dump).
    CHECK_EQ(bytes[13], static_cast<uint8_t>(0x81));
    CHECK_EQ(bytes[14], static_cast<uint8_t>(0x9C));
}

RTSC_TEST(send_data_rejects_payload_above_16383_bytes) {
    std::vector<uint8_t> payload(mcs::kMaxSendDataUserData + 1, 0x00);
    CHECK(McsSendData::build_request(1007, 1003, payload).empty());
}

RTSC_TEST(send_data_accepts_exactly_16383_bytes) {
    std::vector<uint8_t> payload(mcs::kMaxSendDataUserData, 0x00);
    const auto bytes = McsSendData::build_request(1007, 1003, payload);
    CHECK(!bytes.empty());
    CHECK_EQ(bytes[13], static_cast<uint8_t>(0xBF));
    CHECK_EQ(bytes[14], static_cast<uint8_t>(0xFF));
    McsSendData out;
    CHECK(McsSendData::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK_EQ(out.user_data.size(), mcs::kMaxSendDataUserData);
}

RTSC_TEST(send_data_decodes_each_data_priority) {
    for (uint8_t p = 0; p <= 3; ++p) {
        std::vector<uint8_t> payload(1, 0x00);
        const auto bytes = McsSendData::build_request(
            1007, 1003, payload, static_cast<McsDataPriority>(p));
        McsSendData out;
        CHECK(McsSendData::parse(bytes.data(), bytes.size(), out) == Status::Ok);
        CHECK_EQ(static_cast<uint8_t>(out.priority), p);
    }
}

RTSC_TEST(send_data_rejects_unknown_choice) {
    auto bytes = McsSendData::build_request(1007, 1003, {0x00});
    bytes[7] = static_cast<uint8_t>(mcs::kSendDataRequest << 2) | 0x01;
    McsSendData out;
    CHECK(McsSendData::parse(bytes.data(), bytes.size(), out) == Status::InvalidField);
}

RTSC_TEST(send_data_needs_more_data_when_payload_truncated) {
    auto bytes = McsSendData::build_request(1007, 1003, std::vector<uint8_t>(10, 0x00));
    bytes.resize(bytes.size() - 3);
    bytes[2] = 0x00;
    bytes[3] = static_cast<uint8_t>(bytes.size());
    McsSendData out;
    CHECK(McsSendData::parse(bytes.data(), bytes.size(), out) == Status::NeedMoreData);
}

// ---- Disconnect Provider Ultimatum ----------------------------------------

RTSC_TEST(disconnect_provider_ultimatum_matches_spec_vector) {
    const auto want = hex("03 00 00 09 02 f0 80 21 80");
    const auto got = McsDisconnectProviderUltimatum::build(
        McsDisconnectReason::kUserRequested);
    CHECK_EQ(first_difference(got, want), want.size());
    CHECK_EQ(got.size(), static_cast<size_t>(9));
}

RTSC_TEST(disconnect_provider_ultimatum_roundtrips_every_reason) {
    for (uint8_t v = 0; v <= 4; ++v) {
        const auto bytes =
            McsDisconnectProviderUltimatum::build(static_cast<McsDisconnectReason>(v));
        CHECK_EQ(bytes.size(), static_cast<size_t>(9));
        McsDisconnectProviderUltimatum out;
        CHECK(McsDisconnectProviderUltimatum::parse(bytes.data(), bytes.size(), out) ==
              Status::Ok);
        CHECK_EQ(static_cast<uint8_t>(out.reason), v);
    }
}

RTSC_TEST(disconnect_provider_ultimatum_rejects_unknown_reason) {
    CHECK(McsDisconnectProviderUltimatum::build(
              static_cast<McsDisconnectReason>(5))
              .empty());
    // reason bits 101 = 5 -> 0x21 | 0x02 = 0x23, second octet 0x80.
    const auto bytes = hex("03 00 00 09 02 f0 80 22 80");
    McsDisconnectProviderUltimatum out;
    CHECK(McsDisconnectProviderUltimatum::parse(bytes.data(), bytes.size(), out) ==
          Status::InvalidField);
}

// ---- Enum names -----------------------------------------------------------

RTSC_TEST(result_enum_names_cover_all_sixteen_values) {
    CHECK(std::string(to_string(McsResult::kSuccessful)) == "rt-successful");
    CHECK(std::string(to_string(McsResult::kUnspecifiedFailure)) ==
          "rt-unspecified-failure");
    CHECK(std::string(to_string(McsResult::kUserRejected)) == "rt-user-rejected");
    CHECK(std::string(to_string(static_cast<McsResult>(99))) == "rt-unknown");
}

RTSC_TEST(disconnect_reason_names_cover_all_five_values) {
    CHECK(std::string(to_string(McsDisconnectReason::kProviderInitiated)) ==
          "rn-provider-initiated");
    CHECK(std::string(to_string(McsDisconnectReason::kUserRequested)) ==
          "rn-user-requested");
    CHECK(std::string(to_string(static_cast<McsDisconnectReason>(9))) == "rn-unknown");
}

RTSC_TEST(server_channel_id_is_fixed_1002) {
    // volatile reads keep these out of constant folding; CHECK_EQ expands to
    // `if (!(a == b))` which MSVC flags as C4127 for constant operands.
    volatile uint16_t server_channel = mcs::kServerChannelId;
    volatile uint16_t min_dynamic = mcs::kMinDynamicChannelId;
    volatile uint16_t max_dynamic = mcs::kMaxDynamicChannelId;
    CHECK_EQ(server_channel, static_cast<uint16_t>(1002));
    CHECK_EQ(min_dynamic, static_cast<uint16_t>(1001));
    CHECK_EQ(max_dynamic, static_cast<uint16_t>(65535));
}

int main() { return rtsc::test::run_all("rtsc_mcs_domain_tests"); }
