#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/share.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> FromHex(const std::string& hex) {
    std::vector<uint8_t> out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    int hi = -1;
    for (char c : hex) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        const int v = nib(c);
        if (v < 0) return {};
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

}  // namespace

// ---- ShareControlHeader ---------------------------------------------------

RTSC_TEST(share_control_header_parses_official_synchronize) {
    // 4.1.14 Client Synchronize: totalLength 0x0016, pduType 0x0017
    // (TS_PROTOCOL_VERSION | PDUTYPE_DATAPDU), pduSource 0x03eb.
    const auto bytes = FromHex("16 00 17 00 eb 03");
    ShareControlHeader h;
    CHECK(ShareControlHeader::parse(bytes.data(), bytes.size(), h) == Status::Ok);
    CHECK_EQ(h.total_length, static_cast<uint16_t>(0x0016));
    CHECK(h.type == SharePduType::kData);
    CHECK_EQ(h.pdu_version, static_cast<uint16_t>(1));
    CHECK_EQ(h.pdu_source, static_cast<uint16_t>(0x03EB));

    ByteWriter w;
    h.write(w);
    CHECK(w.data() == bytes);
}

RTSC_TEST(share_control_header_splits_pdu_type_bits) {
    // pduType = 0x0017 -> type 0x7, version 0x1.
    const auto bytes = FromHex("0a 00 17 00 00 00");
    ShareControlHeader h;
    CHECK(ShareControlHeader::parse(bytes.data(), bytes.size(), h) == Status::Ok);
    CHECK_EQ(static_cast<uint16_t>(h.type), static_cast<uint16_t>(0x7));
    CHECK_EQ(h.pdu_version, static_cast<uint16_t>(0x1));
}

RTSC_TEST(share_control_header_accepts_all_five_types) {
    struct Case {
        uint16_t type;
        SharePduType want;
    };
    const Case cases[] = {{0x1, SharePduType::kDemandActive},
                          {0x3, SharePduType::kConfirmActive},
                          {0x6, SharePduType::kDeactivateAll},
                          {0x7, SharePduType::kData},
                          {0xA, SharePduType::kServerRedirection}};
    for (const auto& c : cases) {
        const uint16_t pdu_type = static_cast<uint16_t>(0x10 | c.type);
        const auto bytes = FromHex("06 00 00 00 00 00");
        auto mutable_bytes = bytes;
        mutable_bytes[2] = static_cast<uint8_t>(pdu_type);
        mutable_bytes[3] = static_cast<uint8_t>(pdu_type >> 8);
        ShareControlHeader h;
        CHECK(ShareControlHeader::parse(mutable_bytes.data(), mutable_bytes.size(),
                                        h) == Status::Ok);
        CHECK(h.type == c.want);
    }
}

RTSC_TEST(share_control_header_rejects_undefined_type) {
    // type 0x0 / 0x2 / 0x4 / 0x5 / 0x8 / 0x9 / 0xB..0xF are undefined.
    for (uint16_t raw : {uint16_t{0x0}, uint16_t{0x2}, uint16_t{0x4},
                         uint16_t{0x5}, uint16_t{0x8}, uint16_t{0x9},
                         uint16_t{0xB}, uint16_t{0xF}}) {
        auto bytes = FromHex("06 00 00 00 00 00");
        const uint16_t pdu_type = static_cast<uint16_t>(0x10 | raw);
        bytes[2] = static_cast<uint8_t>(pdu_type);
        bytes[3] = static_cast<uint8_t>(pdu_type >> 8);
        ShareControlHeader h;
        CHECK(ShareControlHeader::parse(bytes.data(), bytes.size(), h) ==
              Status::InvalidType);
    }
}

RTSC_TEST(share_control_header_rejects_short_input) {
    const auto bytes = FromHex("16 00 17 00 eb");
    ShareControlHeader h;
    CHECK(ShareControlHeader::parse(bytes.data(), bytes.size(), h) ==
          Status::NeedMoreData);
}

// ---- ShareDataHeader ------------------------------------------------------

RTSC_TEST(share_data_header_parses_official_font_list) {
    // 4.1.18 Client Font List header (18 bytes):
    //   16 00 17 00 eb 03   share control header
    //   ea 03 01 00         shareID = 0x000103ea (little-endian)
    //   00                  pad1
    //   01                  streamID = LOW
    //   db 39               uncompressedLength (uninitialized on the wire)
    //   27                  pduType2 = FONTLIST
    //   00                  compressedType
    //   00 00               compressedLength
    const auto bytes =
        FromHex("16 00 17 00 eb 03 ea 03 01 00 00 01 db 39 27 00 00 00");
    CHECK_EQ(bytes.size(), static_cast<size_t>(18));

    ShareDataHeader h;
    CHECK(ShareDataHeader::parse(bytes.data(), bytes.size(), h) == Status::Ok);
    CHECK_EQ(h.control.total_length, static_cast<uint16_t>(0x0016));
    CHECK(h.control.type == SharePduType::kData);
    CHECK_EQ(h.share_id, static_cast<uint32_t>(0x000103EA));
    CHECK_EQ(h.stream_id, static_cast<uint8_t>(0x01));  // STREAM_LOW
    // uncompressedLength is declared, not validated: this value is a bug in the
    // reference implementation and must not cause a rejection.
    CHECK_EQ(h.uncompressed_length, static_cast<uint16_t>(0x39DB));
    CHECK(h.pdu_type2 == ShareDataPduType::kFontList);
    CHECK_EQ(h.compressed_type, static_cast<uint8_t>(0));
}

RTSC_TEST(share_data_header_roundtrips) {
    ShareDataHeader h;
    h.control.total_length = 26;
    h.control.type = SharePduType::kData;
    h.control.pdu_version = 1;
    h.control.pdu_source = 0x03EB;
    h.share_id = 0x000103EA;
    h.pad1 = 0;
    h.stream_id = 0x02;
    h.uncompressed_length = 0;
    h.pdu_type2 = ShareDataPduType::kFontMap;
    h.compressed_type = 0;
    h.compressed_length = 0;

    ByteWriter w;
    h.write(w);
    CHECK_EQ(w.data().size(), static_cast<size_t>(18));
    CHECK_EQ(w.data()[14], static_cast<uint8_t>(0x28));  // FONTMAP

    ShareDataHeader back;
    CHECK(ShareDataHeader::parse(w.data().data(), w.data().size(), back) ==
          Status::Ok);
    CHECK_EQ(back.share_id, static_cast<uint32_t>(0x000103EA));
    CHECK(back.pdu_type2 == ShareDataPduType::kFontMap);
    CHECK_EQ(back.stream_id, static_cast<uint8_t>(0x02));
}

RTSC_TEST(share_data_header_rejects_non_data_pdu) {
    // type = PDUTYPE_DEMANDACTIVEPDU cannot be parsed as a data header.
    const auto bytes =
        FromHex("16 00 11 00 eb 03 00 00 03 01 00 00 00 00 27 00 00 00");
    ShareDataHeader h;
    CHECK(ShareDataHeader::parse(bytes.data(), bytes.size(), h) ==
          Status::InvalidType);
}

RTSC_TEST(share_data_header_rejects_wrong_protocol_version) {
    // pduType = 0x0027 -> type 0x7 but version 0x2, which is not allowed.
    auto bytes = FromHex("16 00 27 00 eb 03 ea 03 01 00 00 00 00 00 27 00 00 00");
    ShareDataHeader h;
    CHECK(ShareDataHeader::parse(bytes.data(), bytes.size(), h) ==
          Status::InvalidVersion);
}

RTSC_TEST(share_data_header_accepts_uninitialized_pad1) {
    // Official dumps carry pad1 = 0x00 / 0x14 / 0xb5 / 0x12 / 0x45.
    for (uint8_t pad : {uint8_t{0x00}, uint8_t{0x14}, uint8_t{0xB5},
                        uint8_t{0x12}, uint8_t{0x45}}) {
        auto bytes =
            FromHex("16 00 17 00 eb 03 ea 03 01 00 00 01 00 00 27 00 00 00");
        bytes[10] = pad;
        ShareDataHeader h;
        CHECK(ShareDataHeader::parse(bytes.data(), bytes.size(), h) == Status::Ok);
        CHECK_EQ(h.pad1, pad);
    }
}

RTSC_TEST(share_data_pdu_type_names_are_sparse) {
    CHECK(std::string(to_string(ShareDataPduType::kUpdate)) == "update");
    CHECK(std::string(to_string(ShareDataPduType::kSynchronize)) == "synchronize");
    CHECK(std::string(to_string(ShareDataPduType::kMonitorLayout)) == "monitor-layout");
    CHECK(std::string(to_string(static_cast<ShareDataPduType>(0x03))) == "unknown");
    CHECK(std::string(to_string(ShareDataPduType::kPersistentKeyList)) ==
          "persistent-key-list");
}

// ---- Security header selection --------------------------------------------

RTSC_TEST(security_header_selection_follows_method_and_level) {
    // No encryption at all -> no header.
    CHECK(SelectSecurityHeader(0, 0) == SecurityHeaderKind::kNone);
    // LOW level -> basic.
    CHECK(SelectSecurityHeader(1, 0) == SecurityHeaderKind::kBasic);
    // 40/56/128-bit -> non-FIPS (12 bytes).
    CHECK(SelectSecurityHeader(2, 0x1) == SecurityHeaderKind::kNonFips);
    CHECK(SelectSecurityHeader(2, 0x2) == SecurityHeaderKind::kNonFips);
    CHECK(SelectSecurityHeader(2, 0x8) == SecurityHeaderKind::kNonFips);
    CHECK(SelectSecurityHeader(3, 0x2) == SecurityHeaderKind::kNonFips);
    // FIPS -> 16 bytes, regardless of level.
    CHECK(SelectSecurityHeader(4, 0x10) == SecurityHeaderKind::kFips);
    CHECK(SelectSecurityHeader(0, 0x10) == SecurityHeaderKind::kFips);
}

RTSC_TEST(security_header_forced_basic_for_client_info_and_license) {
    // Even with no encryption, Client Info and licensing PDUs carry a basic
    // security header ([MS-RDPBCGR] 5.3.8).
    CHECK(SelectSecurityHeader(0, 0, true) == SecurityHeaderKind::kBasic);
    CHECK(SelectSecurityHeader(0, 0, false) == SecurityHeaderKind::kNone);
}

RTSC_TEST(security_header_kind_sizes) {
    // volatile keeps these from being constant-folded, which would trip C4127.
    const volatile size_t none = static_cast<size_t>(SecurityHeaderKind::kNone);
    const volatile size_t basic = static_cast<size_t>(SecurityHeaderKind::kBasic);
    const volatile size_t non_fips = static_cast<size_t>(SecurityHeaderKind::kNonFips);
    const volatile size_t fips = static_cast<size_t>(SecurityHeaderKind::kFips);
    CHECK(none == 0);
    CHECK(basic == 4);
    CHECK(non_fips == 12);
    CHECK(fips == 16);
}

// ---- Security header parsing ----------------------------------------------

RTSC_TEST(security_header_basic_parses_ignored_flags_hi) {
    // 4.1.14: flags = 0x0028 (SEC_IGNORE_SEQNO | SEC_ENCRYPT), flagsHi = 0xf881.
    const auto bytes = FromHex("28 00 81 f8");
    SecurityHeader h;
    CHECK(SecurityHeader::parse(bytes.data(), bytes.size(),
                                SecurityHeaderKind::kBasic, h) == Status::Ok);
    CHECK_EQ(h.flags, static_cast<uint16_t>(0x0028));
    CHECK((h.flags & kSecEncrypt) != 0);
    CHECK((h.flags & kSecIgnoreSeqno) != 0);
    CHECK((h.flags & kSecFlagsHiValid) == 0);  // so flagsHi is meaningless
    CHECK_EQ(h.flags_hi, static_cast<uint16_t>(0xF881));
    CHECK_EQ(h.size(), static_cast<size_t>(4));
    CHECK(!h.has_mac());
}

RTSC_TEST(security_header_flags_hi_is_always_two_bytes) {
    // The field is structurally present even when SEC_FLAGSHI_VALID is clear:
    // a 4-byte header is still 4 bytes, not 2.
    const auto bytes = FromHex("08 00 02 03");
    SecurityHeader h;
    CHECK(SecurityHeader::parse(bytes.data(), bytes.size(),
                                SecurityHeaderKind::kBasic, h) == Status::Ok);
    CHECK_EQ(h.flags_hi, static_cast<uint16_t>(0x0302));
    CHECK_EQ(h.size(), static_cast<size_t>(4));
}

RTSC_TEST(security_header_non_fips_carries_eight_byte_mac) {
    const auto bytes = FromHex("08 00 00 00 aa bb cc dd ee ff 11 22");
    SecurityHeader h;
    CHECK(SecurityHeader::parse(bytes.data(), bytes.size(),
                                SecurityHeaderKind::kNonFips, h) == Status::Ok);
    CHECK(h.has_mac());
    CHECK_EQ(h.signature.size(), static_cast<size_t>(8));
    CHECK_BYTES(h.signature, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22);
    CHECK_EQ(h.size(), static_cast<size_t>(12));

    ByteWriter w;
    h.write(w);
    CHECK(w.data() == bytes);
}

RTSC_TEST(security_header_fips_layout) {
    // flags, flagsHi, length=0x0010, version=1, padlen=3, then 8 MAC bytes.
    const auto bytes =
        FromHex("08 00 00 00 10 00 01 03 aa bb cc dd ee ff 11 22");
    SecurityHeader h;
    CHECK(SecurityHeader::parse(bytes.data(), bytes.size(),
                                SecurityHeaderKind::kFips, h) == Status::Ok);
    CHECK_EQ(h.fips_length, static_cast<uint16_t>(0x0010));
    CHECK_EQ(h.fips_version, static_cast<uint8_t>(1));
    CHECK_EQ(h.padlen, static_cast<uint8_t>(3));
    CHECK_EQ(h.signature.size(), static_cast<size_t>(8));
    CHECK_EQ(h.size(), static_cast<size_t>(16));

    ByteWriter w;
    h.write(w);
    CHECK(w.data() == bytes);
}

RTSC_TEST(security_header_fips_rejects_wrong_length_field) {
    // length must be 0x0010; 0x0008 means the sender is malformed.
    const auto bytes = FromHex("08 00 00 00 08 00 01 00 aa bb cc dd ee ff 11 22");
    SecurityHeader h;
    CHECK(SecurityHeader::parse(bytes.data(), bytes.size(),
                                SecurityHeaderKind::kFips, h) ==
          Status::InvalidField);
}

RTSC_TEST(security_header_none_consumes_nothing) {
    SecurityHeader h;
    CHECK(SecurityHeader::parse(nullptr, 0, SecurityHeaderKind::kNone, h) ==
          Status::Ok);
    CHECK_EQ(h.size(), static_cast<size_t>(0));
    CHECK_EQ(h.flags, static_cast<uint16_t>(0));
}

RTSC_TEST(security_header_rejects_truncated) {
    const auto bytes = FromHex("08 00 00");
    SecurityHeader h;
    CHECK(SecurityHeader::parse(bytes.data(), bytes.size(),
                                SecurityHeaderKind::kBasic, h) ==
          Status::NeedMoreData);
    const auto short_mac = FromHex("08 00 00 00 aa bb cc");
    CHECK(SecurityHeader::parse(short_mac.data(), short_mac.size(),
                                SecurityHeaderKind::kNonFips, h) ==
          Status::NeedMoreData);
}

// ---- Fast-path classification and length ----------------------------------

RTSC_TEST(fastpath_classification_uses_low_two_bits) {
    FastPathAction a;
    // 0xc4 is a real fast-path input header: low 2 bits = 0 -> fast-path.
    CHECK(ClassifyFastPath(0xC4, a));
    CHECK(a == FastPathAction::kFastPath);
    // High-two-bit reading would give 3 (slow-path), which contradicts the
    // official annotation.
    CHECK(ClassifyFastPath(0x03, a));
    CHECK(a == FastPathAction::kX224);
    // Undefined action values.
    CHECK(!ClassifyFastPath(0x01, a));
    CHECK(!ClassifyFastPath(0x02, a));
    CHECK(!ClassifyFastPath(0x05, a));
    CHECK(!ClassifyFastPath(0x06, a));
}

RTSC_TEST(fastpath_length_single_byte) {
    const auto bytes = FromHex("11");
    FastPathLength len;
    CHECK(FastPathLength::parse(bytes.data(), bytes.size(), len) == Status::Ok);
    CHECK_EQ(len.value, static_cast<size_t>(17));
    CHECK(!len.two_byte);
}

RTSC_TEST(fastpath_length_two_byte_is_big_endian) {
    // 300 bytes -> length1 = 0x81, length2 = 0x2C.
    const auto bytes = FromHex("81 2c");
    FastPathLength len;
    CHECK(FastPathLength::parse(bytes.data(), bytes.size(), len) == Status::Ok);
    CHECK_EQ(len.value, static_cast<size_t>(300));
    CHECK(len.two_byte);

    ByteWriter w;
    len.write(w);
    CHECK_BYTES(w.data(), 0x81, 0x2C);
}

RTSC_TEST(fastpath_length_rejects_impossible_values) {
    FastPathLength len;
    // 0x80 0x00 encodes 0, below the 2-byte minimum.
    const auto zero = FromHex("80 00");
    CHECK(FastPathLength::parse(zero.data(), zero.size(), len) ==
          Status::InvalidLength);
    // 0x01 encodes 1, also below the minimum.
    const auto one = FromHex("01");
    CHECK(FastPathLength::parse(one.data(), one.size(), len) ==
          Status::InvalidLength);
    // Truncated two-byte form.
    const auto truncated = FromHex("81");
    CHECK(FastPathLength::parse(truncated.data(), truncated.size(), len) ==
          Status::NeedMoreData);
}

RTSC_TEST(fastpath_length_roundtrips_boundaries) {
    struct Case {
        size_t value;
        bool two;
    };
    const Case cases[] = {{2, false}, {0x7F, false}, {0x80, true},
                          {0x1234, true}, {32767, true}};
    for (const auto& c : cases) {
        FastPathLength len;
        len.value = c.value;
        len.two_byte = c.two;
        ByteWriter w;
        len.write(w);
        FastPathLength back;
        CHECK(FastPathLength::parse(w.data().data(), w.data().size(), back) ==
              Status::Ok);
        CHECK_EQ(back.value, c.value);
    }
}

// ---- Fast-path header and PDU ---------------------------------------------

RTSC_TEST(fastpath_input_header_bit_layout) {
    // 0xc4 = 1100 0100 -> action 0, numEvents 1, flags 3.
    const auto bytes = FromHex("c4");
    FastPathHeader h;
    CHECK(FastPathHeader::parse(bytes.data(), bytes.size(), true, h) == Status::Ok);
    CHECK(h.action == FastPathAction::kFastPath);
    CHECK_EQ(h.count_or_reserved, static_cast<uint8_t>(1));
    CHECK_EQ(h.flags, static_cast<uint8_t>(3));

    ByteWriter w;
    h.write(w, true);
    CHECK_BYTES(w.data(), 0xC4);
}

RTSC_TEST(fastpath_input_header_num_events_zero_means_extended) {
    // numEvents 0 in the 4-bit field signals an extended count byte later.
    const auto bytes = FromHex("00");
    FastPathHeader h;
    CHECK(FastPathHeader::parse(bytes.data(), bytes.size(), true, h) == Status::Ok);
    CHECK_EQ(h.count_or_reserved, static_cast<uint8_t>(0));
}

RTSC_TEST(fastpath_output_header_rejects_slow_path_byte) {
    const auto bytes = FromHex("03");
    FastPathHeader h;
    CHECK(FastPathHeader::parse(bytes.data(), bytes.size(), false, h) ==
          Status::InvalidType);
}

RTSC_TEST(fastpath_pdu_parses_official_input_sample) {
    // 4.7: c4 | 11 | 8-byte MAC | 7-byte ciphertext = 17 bytes.
    const auto bytes =
        FromHex("c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de 28");
    CHECK_EQ(bytes.size(), static_cast<size_t>(17));

    FastPathPdu pdu;
    CHECK(FastPathPdu::parse(bytes.data(), bytes.size(), true, pdu) == Status::Ok);
    CHECK_EQ(pdu.header.count_or_reserved, static_cast<uint8_t>(1));
    CHECK_EQ(pdu.header.flags, static_cast<uint8_t>(3));
    CHECK_EQ(pdu.length.value, static_cast<size_t>(17));
    CHECK(!pdu.length.two_byte);
    // Body = MAC (8) + ciphertext (7).
    CHECK_EQ(pdu.body.size(), static_cast<size_t>(15));
    CHECK_BYTES(pdu.body, 0x30, 0x35, 0x6B, 0x5B, 0xB5, 0x34, 0xC8, 0x47, 0x26,
                0x18, 0x5E, 0x76, 0x0E, 0xDE, 0x28);
}

RTSC_TEST(fastpath_pdu_rejects_truncated_body) {
    const auto bytes = FromHex("c4 11 30 35 6b");
    FastPathPdu pdu;
    CHECK(FastPathPdu::parse(bytes.data(), bytes.size(), true, pdu) ==
          Status::NeedMoreData);
}

RTSC_TEST(fastpath_pdu_ignores_trailing_bytes) {
    // Chaining: a complete PDU followed by the next one's first byte.
    const auto bytes = FromHex("c4 05 01 02 03 99");
    FastPathPdu pdu;
    CHECK(FastPathPdu::parse(bytes.data(), bytes.size(), true, pdu) == Status::Ok);
    CHECK_EQ(pdu.length.value, static_cast<size_t>(5));
    CHECK_EQ(pdu.body.size(), static_cast<size_t>(3));
}

// ---- Fast-path event sizes ------------------------------------------------

RTSC_TEST(fastpath_input_event_sizes_are_fixed) {
    CHECK(FastPathInputEventSize(FastPathInputEventCode::kScancode) == 2);
    CHECK(FastPathInputEventSize(FastPathInputEventCode::kMouse) == 7);
    CHECK(FastPathInputEventSize(FastPathInputEventCode::kMouseX) == 7);
    CHECK(FastPathInputEventSize(FastPathInputEventCode::kSync) == 1);
    CHECK(FastPathInputEventSize(FastPathInputEventCode::kUnicode) == 3);
    CHECK(FastPathInputEventSize(FastPathInputEventCode::kMouseRel) == 7);
    CHECK(FastPathInputEventSize(FastPathInputEventCode::kQoeTimestamp) == 5);
    // 0x7 is undefined.
    CHECK(FastPathInputEventSize(static_cast<FastPathInputEventCode>(0x7)) == 0);
}

RTSC_TEST(fastpath_official_mouse_event_decodes) {
    // 4.7 decrypted: 20 | 00 08 | ab 02 | 6f 01 = 7 bytes.
    const auto bytes = FromHex("20 00 08 ab 02 6f 01");
    CHECK_EQ(bytes.size(), static_cast<size_t>(7));

    // eventHeader 0x20 -> eventFlags 0, eventCode 1 (MOUSE).
    const uint8_t header = bytes[0];
    CHECK_EQ(static_cast<uint8_t>((header >> 5) & 0x07), static_cast<uint8_t>(1));
    CHECK_EQ(static_cast<uint8_t>(header & 0x1F), static_cast<uint8_t>(0));
    CHECK(FastPathInputEventSize(FastPathInputEventCode::kMouse) == bytes.size());

    ByteReader r(bytes.data(), bytes.size());
    uint8_t ev = 0;
    uint16_t flags = 0, x = 0, y = 0;
    CHECK(r.u8(ev));
    CHECK(r.u16le(flags));
    CHECK(r.u16le(x));
    CHECK(r.u16le(y));
    CHECK_EQ(flags, static_cast<uint16_t>(0x0800));  // PTRFLAGS_MOVE
    CHECK_EQ(x, static_cast<uint16_t>(683));
    CHECK_EQ(y, static_cast<uint16_t>(367));
}

RTSC_TEST(set_error_info_text_is_readable) {
    CHECK(rtsc::proto::SetErrorInfoText(0x00000000) == std::string("no error"));
    CHECK(rtsc::proto::SetErrorInfoText(0x00000003) ==
          std::string("disconnected after the idle session limit"));
    CHECK(rtsc::proto::SetErrorInfoText(0x00000005) ==
          std::string("disconnected because another user connected to the session"));
    CHECK(rtsc::proto::SetErrorInfoText(0x0000000C) ==
          std::string("the user logged off"));
    CHECK(rtsc::proto::SetErrorInfoText(0x0000001A) ==
          std::string("the remote server is rebooting"));
    CHECK(rtsc::proto::SetErrorInfoText(0xDEADBEEF) ==
          std::string("unknown error"));
}

int main() { return rtsc::test::run_all("rtsc_share_tests"); }
