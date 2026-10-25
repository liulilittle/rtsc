// Client Info PDU (TS_INFO_PACKET / TS_EXTENDED_INFO_PACKET) and the Security
// Exchange PDU payload.
//
// The 400-byte plaintext in the first test is the decrypted TS_INFO_PACKET from
// docs/spec/mcs-domain.md 搂12.6.2 ([MS-RDPBCGR] 4.1.9), copied byte for byte.

#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/client_info.h"
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

// [MS-RDPBCGR] 4.1.9 decrypted TS_INFO_PACKET, 400 bytes.
const char* kInfoPacketHex =
    "09 04 09 04 b3 43 00 00 0a 00 0c 00 00 00 00 00"
    "00 00 4e 00 54 00 44 00 45 00 56 00 00 00 65 00"
    "6c 00 74 00 6f 00 6e 00 73 00 00 00 00 00 00 00"
    "00 00 02 00 1e 00 31 00 35 00 37 00 2e 00 35 00"
    "39 00 2e 00 32 00 34 00 32 00 2e 00 31 00 35 00"
    "36 00 00 00 84 00 43 00 3a 00 5c 00 64 00 65 00"
    "70 00 6f 00 74 00 73 00 5c 00 77 00 32 00 6b 00"
    "33 00 5f 00 31 00 5c 00 74 00 65 00 72 00 6d 00"
    "73 00 72 00 76 00 5c 00 6e 00 65 00 77 00 63 00"
    "6c 00 69 00 65 00 6e 00 74 00 5c 00 6c 00 69 00"
    "62 00 5c 00 77 00 69 00 6e 00 33 00 32 00 5c 00"
    "6f 00 62 00 6a 00 5c 00 69 00 33 00 38 00 36 00"
    "5c 00 6d 00 73 00 74 00 73 00 63 00 61 00 78 00"
    "2e 00 64 00 6c 00 6c 00 00 00 e0 01 00 00 50 00"
    "61 00 63 00 69 00 66 00 69 00 63 00 20 00 53 00"
    "74 00 61 00 6e 00 64 00 61 00 72 00 64 00 20 00"
    "54 00 69 00 6d 00 65 00 00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    "0a 00 00 00 05 00 02 00 00 00 00 00 00 00 00 00"
    "00 00 50 00 61 00 63 00 69 00 66 00 69 00 63 00"
    "20 00 44 00 61 00 79 00 6c 00 69 00 67 00 68 00"
    "74 00 20 00 54 00 69 00 6d 00 65 00 00 00 00 00"
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    "00 00 00 00 04 00 00 00 01 00 02 00 00 00 00 00"
    "00 00 c4 ff ff ff 00 00 00 00 01 00 00 00 00 00";

}  // namespace

// ---- TS_INFO_PACKET -------------------------------------------------------

RTSC_TEST(info_packet_parses_official_400_byte_vector) {
    const auto bytes = hex(kInfoPacketHex);
    CHECK_EQ(bytes.size(), static_cast<size_t>(400));
    TsInfoPacket info;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(info.read(r) == Status::Ok);
    CHECK(r.empty());
}

RTSC_TEST(info_packet_decodes_header_fields) {
    const auto bytes = hex(kInfoPacketHex);
    TsInfoPacket info;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(info.read(r) == Status::Ok);
    CHECK_EQ(info.code_page, 0x04090409u);
    CHECK_EQ(info.flags, 0x000043B3u);
    CHECK(info.unicode());
}

RTSC_TEST(info_packet_decodes_strings) {
    const auto bytes = hex(kInfoPacketHex);
    TsInfoPacket info;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(info.read(r) == Status::Ok);
    CHECK(info.domain == "NTDEV");
    CHECK(info.user_name == "eltons");
    CHECK(info.password.empty());
    CHECK(info.alternate_shell.empty());
    CHECK(info.working_dir.empty());
}

RTSC_TEST(info_packet_decodes_extended_info) {
    const auto bytes = hex(kInfoPacketHex);
    TsInfoPacket info;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(info.read(r) == Status::Ok);
    CHECK(info.has_extended_info);
    CHECK_EQ(info.extended_info.client_address_family,
             TsExtendedInfoPacket::kAfInet);
    CHECK(info.extended_info.client_address == "157.59.242.156");
    CHECK(info.extended_info.client_dir ==
          "C:\\depots\\w2k3_1\\termsrv\\newclient\\lib\\win32\\obj\\i386\\mstscax.dll");
}

RTSC_TEST(info_packet_decodes_time_zone) {
    const auto bytes = hex(kInfoPacketHex);
    TsInfoPacket info;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(info.read(r) == Status::Ok);
    const auto& tz = info.extended_info.time_zone;
    CHECK(info.extended_info.has_time_zone);
    CHECK_EQ(tz.bias, 480);
    CHECK(tz.standard_name == "Pacific Standard Time");
    CHECK_EQ(tz.standard_date.month, static_cast<uint16_t>(10));
    CHECK_EQ(tz.standard_date.day_of_week, static_cast<uint16_t>(0));
    CHECK_EQ(tz.standard_date.day, static_cast<uint16_t>(5));
    CHECK_EQ(tz.standard_date.hour, static_cast<uint16_t>(2));
    CHECK_EQ(tz.standard_bias, 0);
    CHECK(tz.daylight_name == "Pacific Daylight Time");
    CHECK_EQ(tz.daylight_date.month, static_cast<uint16_t>(4));
    CHECK_EQ(tz.daylight_date.day, static_cast<uint16_t>(1));
    CHECK_EQ(tz.daylight_bias, -60);
}

RTSC_TEST(info_packet_decodes_trailing_extended_flags) {
    const auto bytes = hex(kInfoPacketHex);
    TsInfoPacket info;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(info.read(r) == Status::Ok);
    CHECK(info.extended_info.has_session_id);
    CHECK_EQ(info.extended_info.session_id, 0u);
    CHECK(info.extended_info.has_performance_flags);
    CHECK_EQ(info.extended_info.performance_flags, 0x00000001u);
    // cbAutoReconnectCookie is present with value 0: the field exists, the
    // 28-byte cookie does not follow.
    CHECK(info.extended_info.has_auto_reconnect);
    CHECK(info.extended_info.auto_reconnect_cookie.bytes.empty());
    CHECK(!info.extended_info.has_reserved);
    CHECK(!info.extended_info.has_dynamic_dst);
}

RTSC_TEST(info_packet_reencodes_official_vector_byte_for_byte) {
    const auto want = hex(kInfoPacketHex);
    TsInfoPacket info;
    ByteReader r(want.data(), want.size());
    CHECK(info.read(r) == Status::Ok);

    ByteWriter w;
    info.write(w);
    const auto got = w.take();
    CHECK_EQ(got.size(), want.size());
    CHECK(got == want);
}

RTSC_TEST(info_packet_roundtrips_without_extended_info) {
    TsInfoPacket info;
    info.code_page = 0x0409;
    info.flags = info::kMouse | info::kUnicode;
    info.domain = "D";
    info.user_name = "user";
    info.password = "pw";

    ByteWriter w;
    info.write(w);
    const auto bytes = w.take();

    TsInfoPacket out;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(out.read(r) == Status::Ok);
    CHECK(r.empty());
    CHECK(!out.has_extended_info);
    CHECK(out.domain == "D");
    CHECK(out.user_name == "user");
    CHECK(out.password == "pw");
}

RTSC_TEST(info_packet_ansi_mode_uses_single_byte_terminator) {
    TsInfoPacket info;
    info.code_page = 1252;
    info.flags = info::kMouse;  // no INFO_UNICODE
    info.domain = "AB";

    ByteWriter w;
    info.write(w);
    const auto bytes = w.take();
    // 18 header + ("AB" + 1 NUL) + 4 empty fields * 1 NUL = 25
    CHECK_EQ(bytes.size(), static_cast<size_t>(25));
    CHECK_EQ(bytes[18], static_cast<uint8_t>('A'));
    CHECK_EQ(bytes[19], static_cast<uint8_t>('B'));
    CHECK_EQ(bytes[20], static_cast<uint8_t>(0));

    TsInfoPacket out;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(out.read(r) == Status::Ok);
    CHECK(out.domain == "AB");
    CHECK(!out.unicode());
}

RTSC_TEST(info_packet_empty_strings_still_occupy_a_terminator) {
    TsInfoPacket info;
    info.flags = info::kUnicode;
    ByteWriter w;
    info.write(w);
    const auto bytes = w.take();
    // 18 header + 5 * 2-byte terminators, no extended info
    CHECK_EQ(bytes.size(), static_cast<size_t>(28));
}

RTSC_TEST(info_packet_compression_type_shifts_into_mask) {
    // volatile keeps the operands out of constant folding: CHECK_EQ expands to
    // `if (!(a == b))`, which MSVC flags as C4127 for constant operands.
    volatile uint32_t f = info::kCompression | info::CompressionType(1);
    volatile uint32_t masked1 = info::CompressionType(1) & info::kCompressionTypeMask;
    volatile uint32_t masked3 = info::CompressionType(3) & info::kCompressionTypeMask;
    CHECK_EQ(f & info::kCompressionTypeMask, 0x00000200u);
    CHECK_EQ(masked1, 0x00000200u);
    CHECK_EQ(masked3, 0x00000600u);
}

RTSC_TEST(info_packet_read_needs_more_data_for_short_header) {
    const std::vector<uint8_t> bytes(10, 0);
    TsInfoPacket info;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(info.read(r) == Status::NeedMoreData);
}

RTSC_TEST(info_packet_read_needs_more_data_when_string_truncated) {
    // Header claims cbDomain = 10 but supplies nothing after the header.
    const std::vector<uint8_t> bytes = {0x09, 0x04, 0x09, 0x04, 0x10, 0x00, 0x00, 0x00,
                                        0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00};
    TsInfoPacket info;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(info.read(r) == Status::NeedMoreData);
}

// ---- TS_EXTENDED_INFO_PACKET chained presence -----------------------------

RTSC_TEST(extended_info_omits_everything_after_absent_time_zone) {
    TsExtendedInfoPacket ext;
    ext.client_address = "1.2.3.4";
    ext.client_dir = "C:\\x";
    ext.has_time_zone = false;
    ext.has_session_id = true;
    ext.session_id = 7;

    ByteWriter w;
    ext.write(w, true);
    const auto bytes = w.take();

    TsExtendedInfoPacket out;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(out.read(r, true) == Status::Ok);
    CHECK(!out.has_time_zone);
    CHECK(!out.has_session_id);  // chain: time zone absent => nothing after it
    CHECK(out.client_address == "1.2.3.4");
}

RTSC_TEST(extended_info_roundtrips_full_chain) {
    TsExtendedInfoPacket ext;
    ext.client_address = "10.0.0.1";
    ext.client_dir = "C:\\app";
    ext.has_time_zone = true;
    ext.time_zone.bias = -300;
    ext.time_zone.standard_name = "Eastern Standard Time";
    ext.time_zone.standard_date.month = 11;
    ext.time_zone.standard_date.day = 1;
    ext.time_zone.standard_date.hour = 2;
    ext.time_zone.daylight_bias = 0;
    ext.has_session_id = true;
    ext.session_id = 3;
    ext.has_performance_flags = true;
    ext.performance_flags = 0x02;
    ext.has_auto_reconnect = true;
    ext.auto_reconnect_cookie.bytes.assign(ArcCsPrivatePacket::kWireSize, 0x5A);
    ext.has_reserved = true;
    ext.reserved1 = 0;
    ext.reserved2 = 0;
    ext.has_dynamic_dst = true;
    ext.dynamic_dst_time_zone_key_name = "Eastern Standard Time";
    ext.dynamic_daylight_time_disabled = 1;

    ByteWriter w;
    ext.write(w, true);
    const auto bytes = w.take();

    TsExtendedInfoPacket out;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(out.read(r, true) == Status::Ok);
    CHECK(r.empty());
    CHECK_EQ(out.time_zone.bias, -300);
    CHECK(out.time_zone.standard_name == "Eastern Standard Time");
    CHECK_EQ(out.time_zone.standard_date.month, static_cast<uint16_t>(11));
    CHECK_EQ(out.session_id, 3u);
    CHECK_EQ(out.performance_flags, 0x02u);
    CHECK(out.has_auto_reconnect);
    CHECK(out.auto_reconnect_cookie.bytes.size() == ArcCsPrivatePacket::kWireSize);
    CHECK_EQ(out.auto_reconnect_cookie.bytes[0], static_cast<uint8_t>(0x5A));
    CHECK(out.has_reserved);
    CHECK(out.has_dynamic_dst);
    CHECK(out.dynamic_dst_time_zone_key_name == "Eastern Standard Time");
    CHECK_EQ(out.dynamic_daylight_time_disabled, static_cast<uint16_t>(1));
}

RTSC_TEST(extended_info_rejects_unknown_address_family) {
    const std::vector<uint8_t> bytes = {0x05, 0x00, 0x02, 0x00, 0x41, 0x00};
    TsExtendedInfoPacket out;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(out.read(r, true) == Status::InvalidField);
}

RTSC_TEST(extended_info_rejects_auto_reconnect_cookie_of_wrong_size) {
    TsExtendedInfoPacket ext;
    ext.client_address = "1.1.1.1";
    ext.client_dir = "C:\\";
    ext.has_time_zone = true;
    ext.has_session_id = true;
    ext.has_performance_flags = true;
    ext.has_auto_reconnect = true;
    ext.auto_reconnect_cookie.bytes.assign(ArcCsPrivatePacket::kWireSize, 0);

    ByteWriter w;
    ext.write(w, true);
    auto bytes = w.take();
    // Patch cbAutoReconnectCookie (28) to an illegal value.
    for (size_t i = 0; i + 1 < bytes.size(); ++i) {
        if (bytes[i] == 0x1C && bytes[i + 1] == 0x00) {
            bytes[i] = 0x10;
            break;
        }
    }
    TsExtendedInfoPacket out;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(out.read(r, true) == Status::InvalidLength);
}

// ---- TS_TIME_ZONE_INFORMATION / TS_SYSTEMTIME -----------------------------

RTSC_TEST(time_zone_wire_size_is_172_bytes) {
    TsTimeZoneInformation tz;
    ByteWriter w;
    tz.write(w);
    CHECK_EQ(w.size(), TsTimeZoneInformation::kWireSize);
}

RTSC_TEST(system_time_is_zero_detects_absent_dst) {
    TsSystemTime st;
    CHECK(st.is_zero());
    st.month = 10;
    CHECK(!st.is_zero());
}

RTSC_TEST(system_time_roundtrips) {
    TsSystemTime st;
    st.year = 0;
    st.month = 3;
    st.day_of_week = 6;
    st.day = 2;
    st.hour = 2;
    st.minute = 30;
    st.second = 15;
    st.milliseconds = 250;

    ByteWriter w;
    st.write(w);
    const auto bytes = w.take();
    CHECK_EQ(bytes.size(), static_cast<size_t>(16));

    TsSystemTime out;
    ByteReader r(bytes.data(), bytes.size());
    CHECK(out.read(r) == Status::Ok);
    CHECK_EQ(out.month, static_cast<uint16_t>(3));
    CHECK_EQ(out.day_of_week, static_cast<uint16_t>(6));
    CHECK_EQ(out.minute, static_cast<uint16_t>(30));
    CHECK_EQ(out.milliseconds, static_cast<uint16_t>(250));
}

// ---- CLIENT_INFO_PDU ------------------------------------------------------

RTSC_TEST(client_info_pdu_wraps_security_header_and_info_packet) {
    ClientInfoPdu pdu;
    pdu.info.flags = info::kMouse | info::kUnicode;
    pdu.info.domain = "NTDEV";
    pdu.info.user_name = "eltons";

    const auto bytes = pdu.build();
    // 4 security header + 18 fixed + (10+2) + (12+2) + 3 * 2 terminators
    CHECK_EQ(bytes.size(), static_cast<size_t>(4 + 18 + 12 + 14 + 6));
    CHECK_EQ(bytes[0], static_cast<uint8_t>(0x40));  // SEC_INFO_PKT
    CHECK_EQ(bytes[1], static_cast<uint8_t>(0x00));
}

RTSC_TEST(client_info_pdu_roundtrips) {
    ClientInfoPdu pdu;
    pdu.info.code_page = 0x0409;
    pdu.info.flags = info::kMouse | info::kUnicode | info::kDisableCtrlAltDel;
    pdu.info.domain = "DOM";
    pdu.info.user_name = "bob";
    pdu.info.password = "secret";

    const auto bytes = pdu.build();
    ClientInfoPdu out;
    CHECK(ClientInfoPdu::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK_EQ(out.security_flags, sec::kSecInfoPkt);
    CHECK(out.info.domain == "DOM");
    CHECK(out.info.user_name == "bob");
    CHECK(out.info.password == "secret");
    CHECK_EQ(out.info.flags, pdu.info.flags);
}

RTSC_TEST(client_info_pdu_rejects_missing_info_flag) {
    std::vector<uint8_t> bytes = {0x08, 0x00, 0x00, 0x00};
    ClientInfoPdu out;
    CHECK(ClientInfoPdu::parse(bytes.data(), bytes.size(), out) == Status::InvalidField);
}

RTSC_TEST(client_info_pdu_needs_more_data_for_short_security_header) {
    const std::vector<uint8_t> bytes = {0x40, 0x00};
    ClientInfoPdu out;
    CHECK(ClientInfoPdu::parse(bytes.data(), bytes.size(), out) == Status::NeedMoreData);
}

// ---- SECURITY_EXCHANGE_PDU ------------------------------------------------

RTSC_TEST(security_exchange_buffer_size_matches_spec_formula) {
    // "For example, if the public key of the server is 512 bits long, then the
    // zeroed-out buffer is 72 bytes."
    CHECK_EQ(SecurityExchangePdu::BufferSizeForKeyBits(512), static_cast<size_t>(72));
    CHECK_EQ(SecurityExchangePdu::BufferSizeForKeyBits(2048), static_cast<size_t>(264));
    CHECK_EQ(SecurityExchangePdu::BufferSizeForKeyBits(1024), static_cast<size_t>(136));
}

RTSC_TEST(security_exchange_pdu_matches_spec_layout) {
    SecurityExchangePdu pdu;
    pdu.encrypted_client_random.assign(72, 0x00);  // 512-bit key => 64 + 8 padding

    const auto bytes = pdu.build();
    // flags(2) + flagsHi(2) + length(4) + 72
    CHECK_EQ(bytes.size(), static_cast<size_t>(80));
    CHECK_EQ(bytes[0], static_cast<uint8_t>(0x01));  // SEC_EXCHANGE_PKT
    CHECK_EQ(bytes[1], static_cast<uint8_t>(0x02));  // SEC_LICENSE_ENCRYPT_SC
    CHECK_EQ(bytes[2], static_cast<uint8_t>(0x00));  // flagsHi
    CHECK_EQ(bytes[3], static_cast<uint8_t>(0x00));
    CHECK_EQ(bytes[4], static_cast<uint8_t>(0x48));  // length = 72
    CHECK_EQ(bytes[5], static_cast<uint8_t>(0x00));
    CHECK_EQ(bytes[6], static_cast<uint8_t>(0x00));
    CHECK_EQ(bytes[7], static_cast<uint8_t>(0x00));
}

RTSC_TEST(security_exchange_pdu_roundtrips) {
    SecurityExchangePdu pdu;
    pdu.encrypted_client_random.resize(72);
    for (size_t i = 0; i < 72; ++i) {
        pdu.encrypted_client_random[i] = static_cast<uint8_t>(i);
    }
    const auto bytes = pdu.build();

    SecurityExchangePdu out;
    CHECK(SecurityExchangePdu::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK_EQ(out.flags, pdu.flags);
    CHECK(out.encrypted_client_random == pdu.encrypted_client_random);
}

RTSC_TEST(security_exchange_pdu_rejects_missing_exchange_flag) {
    SecurityExchangePdu pdu;
    pdu.encrypted_client_random.assign(8, 0);
    auto bytes = pdu.build();
    bytes[0] = 0x40;  // SEC_INFO_PKT instead of SEC_EXCHANGE_PKT
    SecurityExchangePdu out;
    CHECK(SecurityExchangePdu::parse(bytes.data(), bytes.size(), out) ==
          Status::InvalidField);
}

RTSC_TEST(security_exchange_pdu_needs_more_data_when_buffer_truncated) {
    SecurityExchangePdu pdu;
    pdu.encrypted_client_random.assign(72, 0);
    auto bytes = pdu.build();
    bytes.resize(bytes.size() - 10);
    SecurityExchangePdu out;
    CHECK(SecurityExchangePdu::parse(bytes.data(), bytes.size(), out) ==
          Status::NeedMoreData);
}

RTSC_TEST(security_exchange_pdu_rejects_trailing_bytes) {
    SecurityExchangePdu pdu;
    pdu.encrypted_client_random.assign(72, 0);
    auto bytes = pdu.build();
    bytes.push_back(0xFF);
    SecurityExchangePdu out;
    CHECK(SecurityExchangePdu::parse(bytes.data(), bytes.size(), out) ==
          Status::InvalidLength);
}

int main() { return rtsc::test::run_all("rtsc_client_info_tests"); }
