#include <cstdio>
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
    while (*s) {
        while (*s == ' ' || *s == '\n' || *s == '\r' || *s == '\t') ++s;
        if (!*s) break;
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int hi = nib(s[0]);
        const int lo = nib(s[1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        s += 2;
    }
    return out;
}

// [MS-RDPBCGR] 4.1.3 annotated dump, 416 bytes (docs/spec/mcs-connect.md 搂9.1).
const char* kConnectInitialHex =
    "03 00 01 a0 02 f0 80 7f 65 82 01 94 04 01 01 04 "
    "01 01 01 01 ff 30 19 02 01 22 02 01 02 02 01 00 "
    "02 01 01 02 01 00 02 01 01 02 02 ff ff 02 01 02 "
    "30 19 02 01 01 02 01 01 02 01 01 02 01 01 02 01 "
    "00 02 01 01 02 02 04 20 02 01 02 30 1c 02 02 ff "
    "ff 02 02 fc 17 02 02 ff ff 02 01 01 02 01 00 02 "
    "01 01 02 02 ff ff 02 01 02 04 82 01 33 00 05 00 "
    "14 7c 00 01 81 2a 00 08 00 10 00 01 c0 00 44 75 "
    "63 61 81 1c 01 c0 d8 00 04 00 08 00 00 05 00 04 "
    "01 ca 03 aa 09 04 00 00 ce 0e 00 00 45 00 4c 00 "
    "54 00 4f 00 4e 00 53 00 2d 00 44 00 45 00 56 00 "
    "32 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00 "
    "00 00 00 00 0c 00 00 00 00 00 00 00 00 00 00 00 "
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
    "00 00 00 00 00 00 00 00 01 ca 01 00 00 00 00 00 "
    "18 00 07 00 01 00 36 00 39 00 37 00 31 00 32 00 "
    "2d 00 37 00 38 00 33 00 2d 00 30 00 33 00 35 00 "
    "37 00 39 00 37 00 34 00 2d 00 34 00 32 00 37 00 "
    "31 00 34 00 00 00 00 00 00 00 00 00 00 00 00 00 "
    "00 00 00 00 00 00 00 00 00 00 00 00 04 c0 0c 00 "
    "0d 00 00 00 00 00 00 00 02 c0 0c 00 1b 00 00 00 "
    "00 00 00 00 03 c0 2c 00 03 00 00 00 72 64 70 64 "
    "72 00 00 00 00 00 80 80 63 6c 69 70 72 64 72 00 "
    "00 00 a0 c0 72 64 70 73 6e 64 00 00 00 00 00 c0";

// [MS-RDPBCGR] 4.1.4 annotated dump, 337 bytes (docs/spec/mcs-connect.md 搂9.1).
const char* kConnectResponseHex =
    "03 00 01 51 02 f0 80 7f 66 82 01 45 0a 01 00 02 "
    "01 00 30 1a 02 01 22 02 01 03 02 01 00 02 01 01 "
    "02 01 00 02 01 01 02 03 00 ff f8 02 01 02 04 82 "
    "01 1f 00 05 00 14 7c 00 01 2a 14 76 0a 01 01 00 "
    "01 c0 00 4d 63 44 6e 81 08 01 0c 0c 00 04 00 08 "
    "00 00 00 00 00 03 0c 10 00 eb 03 03 00 ec 03 ed "
    "03 ee 03 00 00 02 0c ec 00 02 00 00 00 02 00 00 "
    "00 20 00 00 00 b8 00 00 00 10 11 77 20 30 61 0a "
    "12 e4 34 a1 1e f2 c3 9f 31 7d a4 5f 01 89 34 96 "
    "e0 ff 11 08 69 7f 1a c3 d2 01 00 00 00 01 00 00 "
    "00 01 00 00 00 06 00 5c 00 52 53 41 31 48 00 00 "
    "00 00 02 00 00 3f 00 00 00 01 00 01 00 cb 81 fe "
    "ba 6d 61 c3 55 05 d5 5f 2e 87 f8 71 94 d6 f1 a5 "
    "cb f1 5f 0c 3d f8 70 02 96 c4 fb 9b c8 3c 2d 55 "
    "ae e8 ff 32 75 ea 68 79 e5 a2 01 fd 31 a0 b1 1f "
    "55 a6 1f c1 f6 d1 83 88 63 26 56 12 bc 00 00 00 "
    "00 00 00 00 00 08 00 48 00 e9 e1 d6 28 46 8b 4e "
    "f5 0a df fd ee 21 99 ac b4 e1 8f 5f 81 57 82 ef "
    "9d 96 52 63 27 18 29 db b3 4a fd 9a da 42 ad b5 "
    "69 21 89 0e 1d c0 4c 1a a8 aa 71 3e 0f 54 b9 9a "
    "e4 99 68 3f 6c d6 76 84 61 00 00 00 00 00 00 00 "
    "00";

std::vector<uint8_t> initial_vector() { return hex(kConnectInitialHex); }
std::vector<uint8_t> response_vector() { return hex(kConnectResponseHex); }

std::vector<uint8_t> prefix(const std::vector<uint8_t>& v, size_t off, size_t n) {
    return std::vector<uint8_t>(v.begin() + static_cast<std::ptrdiff_t>(off),
                                v.begin() + static_cast<std::ptrdiff_t>(off + n));
}

size_t first_difference(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    const size_t n = a.size() < b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return i;
    }
    return n;
}

}  // namespace

// ---------------------------------------------------------------------------
// A. PER aligned length determinant (T.124 搂9.6 / X.691)
// ---------------------------------------------------------------------------

RTSC_TEST(per_length_encodes_zero_in_one_byte) {
    ByteWriter w;
    CHECK(mcs::encode_per_length(w, 0) == Status::Ok);
    CHECK_BYTES(w.data(), 0x00);
}

RTSC_TEST(per_length_encodes_127_in_one_byte) {
    ByteWriter w;
    CHECK(mcs::encode_per_length(w, 127) == Status::Ok);
    CHECK_BYTES(w.data(), 0x7F);
}

RTSC_TEST(per_length_encodes_128_in_two_bytes) {
    ByteWriter w;
    CHECK(mcs::encode_per_length(w, 128) == Status::Ok);
    CHECK_BYTES(w.data(), 0x80, 0x80);

    ByteReader r(w.data().data(), w.size());
    size_t len = 0;
    CHECK(mcs::decode_per_length(r, len) == Status::Ok);
    CHECK_EQ(len, static_cast<size_t>(128));
    CHECK(r.empty());
}

RTSC_TEST(per_length_encodes_298_as_81_2a) {
    ByteWriter w;
    CHECK(mcs::encode_per_length(w, 298) == Status::Ok);
    CHECK_BYTES(w.data(), 0x81, 0x2A);

    ByteReader r(w.data().data(), w.size());
    size_t len = 0;
    CHECK(mcs::decode_per_length(r, len) == Status::Ok);
    CHECK_EQ(len, static_cast<size_t>(298));
}

RTSC_TEST(per_length_encodes_284_as_81_1c) {
    ByteWriter w;
    CHECK(mcs::encode_per_length(w, 284) == Status::Ok);
    CHECK_BYTES(w.data(), 0x81, 0x1C);
}

RTSC_TEST(per_length_encodes_264_as_81_08) {
    ByteWriter w;
    CHECK(mcs::encode_per_length(w, 264) == Status::Ok);
    CHECK_BYTES(w.data(), 0x81, 0x08);
}

RTSC_TEST(per_length_encodes_16383_as_bf_ff) {
    ByteWriter w;
    CHECK(mcs::encode_per_length(w, 16383) == Status::Ok);
    CHECK_BYTES(w.data(), 0xBF, 0xFF);

    ByteReader r(w.data().data(), w.size());
    size_t len = 0;
    CHECK(mcs::decode_per_length(r, len) == Status::Ok);
    CHECK_EQ(len, static_cast<size_t>(16383));
}

RTSC_TEST(per_length_rejects_16384) {
    ByteWriter w;
    CHECK(mcs::encode_per_length(w, 16384) == Status::InvalidLength);
    CHECK_EQ(w.size(), static_cast<size_t>(0));

    const uint8_t fragment_form[2] = {0xC0, 0x00};
    ByteReader r(fragment_form, 2);
    size_t len = 0;
    CHECK(mcs::decode_per_length(r, len) == Status::InvalidLength);
}

RTSC_TEST(per_length_rejects_every_fragmentation_first_byte) {
    // X.691 搂10.9.3.8: 11xxxxxx starts the fragmentation form, which RDP never
    // uses. Every 0xC0..0xFF first byte must be rejected, not decoded.
    for (int first = 0xC0; first <= 0xFF; ++first) {
        const uint8_t buf[2] = {static_cast<uint8_t>(first), 0xFF};
        ByteReader r(buf, 2);
        size_t len = 0;
        CHECK(mcs::decode_per_length(r, len) == Status::InvalidLength);
    }
    ByteWriter w;
    CHECK(mcs::encode_per_length(w, 0x4000) == Status::InvalidLength);
    CHECK_EQ(w.size(), static_cast<size_t>(0));
}

RTSC_TEST(per_length_needs_more_data_when_two_byte_form_truncated) {
    const uint8_t one_byte[1] = {0x81};
    ByteReader r(one_byte, 1);
    size_t len = 0;
    CHECK(mcs::decode_per_length(r, len) == Status::NeedMoreData);

    ByteReader empty(nullptr, 0);
    CHECK(mcs::decode_per_length(empty, len) == Status::NeedMoreData);
}

// ---------------------------------------------------------------------------
// B. Official 416-byte Connect Initial vector
// ---------------------------------------------------------------------------

RTSC_TEST(connect_initial_parses_official_416_byte_vector) {
    const auto bytes = initial_vector();
    CHECK_EQ(bytes.size(), static_cast<size_t>(416));
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
}

RTSC_TEST(connect_initial_gcc_user_data_is_307_bytes) {
    const auto bytes = initial_vector();
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    CHECK_EQ(ci.gcc_conference_create_request.size(), static_cast<size_t>(307));
}

RTSC_TEST(connect_initial_gcc_starts_with_t124_identifier) {
    const auto bytes = initial_vector();
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    CHECK_BYTES(prefix(ci.gcc_conference_create_request, 0, 7),
                0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01);
}

RTSC_TEST(connect_initial_gcc_connect_pdu_length_is_81_2a) {
    const auto bytes = initial_vector();
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    CHECK_BYTES(prefix(ci.gcc_conference_create_request, 7, 2), 0x81, 0x2A);
}

RTSC_TEST(connect_initial_gcc_conference_create_header) {
    const auto bytes = initial_vector();
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    CHECK_BYTES(prefix(ci.gcc_conference_create_request, 9, 8),
                0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00);
}

RTSC_TEST(connect_initial_gcc_h221_key_is_duca) {
    const auto bytes = initial_vector();
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    CHECK_BYTES(prefix(ci.gcc_conference_create_request, 17, 4),
                0x44, 0x75, 0x63, 0x61);
}

RTSC_TEST(connect_initial_gcc_user_data_length_is_81_1c) {
    const auto bytes = initial_vector();
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    CHECK_BYTES(prefix(ci.gcc_conference_create_request, 21, 2), 0x81, 0x1C);
}

RTSC_TEST(connect_initial_gcc_blocks_have_expected_types_and_lengths) {
    const auto bytes = initial_vector();
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    CHECK_EQ(ci.gcc_conference_create_request.size(), static_cast<size_t>(307));

    GccUserData ud;
    CHECK(GccUserData::parse(ci.gcc_conference_create_request.data() + 23, 284, ud) ==
          Status::Ok);
    CHECK_EQ(ud.blocks.size(), static_cast<size_t>(4));
    if (ud.blocks.size() == 4) {
        CHECK_EQ(ud.blocks[0].type, static_cast<uint16_t>(0xC001));
        CHECK_EQ(ud.blocks[0].payload.size() + 4, static_cast<size_t>(216));
        CHECK_EQ(ud.blocks[1].type, static_cast<uint16_t>(0xC004));
        CHECK_EQ(ud.blocks[1].payload.size() + 4, static_cast<size_t>(12));
        CHECK_EQ(ud.blocks[2].type, static_cast<uint16_t>(0xC002));
        CHECK_EQ(ud.blocks[2].payload.size() + 4, static_cast<size_t>(12));
        CHECK_EQ(ud.blocks[3].type, static_cast<uint16_t>(0xC003));
        CHECK_EQ(ud.blocks[3].payload.size() + 4, static_cast<size_t>(44));
    }
}

RTSC_TEST(connect_initial_cs_core_block_reports_216_byte_length) {
    const auto bytes = initial_vector();
    // Block header at absolute offset 132 is `01 C0 D8 00`: type 0xC001 and a
    // 216-byte length that includes the 4-byte header, so the payload starts
    // with ServerSelectedProtocol-era CS_CORE version 0x00080004 (`04 00`).
    CHECK_BYTES(prefix(bytes, 132, 4), 0x01, 0xC0, 0xD8, 0x00);
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    GccUserData ud;
    CHECK(GccUserData::parse(ci.gcc_conference_create_request.data() + 23, 284, ud) ==
          Status::Ok);
    const GccUserData::Block* core = ud.find(0xC001);
    CHECK(core != nullptr);
    if (core != nullptr) {
        CHECK_EQ(core->payload.size() + 4, static_cast<size_t>(216));
        CHECK_BYTES(prefix(core->payload, 0, 4), 0x04, 0x00, 0x08, 0x00);
    }
}

// ---------------------------------------------------------------------------
// C. Official 337-byte Connect Response vector
// ---------------------------------------------------------------------------

RTSC_TEST(connect_response_parses_official_337_byte_vector) {
    const auto bytes = response_vector();
    CHECK_EQ(bytes.size(), static_cast<size_t>(337));
    McsConnectResponse cr;
    CHECK(McsConnectResponse::parse(bytes.data(), bytes.size(), cr) == Status::Ok);
}

RTSC_TEST(connect_response_result_is_zero) {
    const auto bytes = response_vector();
    McsConnectResponse cr;
    CHECK(McsConnectResponse::parse(bytes.data(), bytes.size(), cr) == Status::Ok);
    CHECK_EQ(cr.result, static_cast<uint32_t>(0));
}

RTSC_TEST(connect_response_channels_come_from_sc_net) {
    const auto bytes = response_vector();
    McsConnectResponse cr;
    CHECK(McsConnectResponse::parse(bytes.data(), bytes.size(), cr) == Status::Ok);
    CHECK_EQ(cr.channels.size(), static_cast<size_t>(3));
    if (cr.channels.size() == 3) {
        CHECK_EQ(cr.channels[0].id, static_cast<uint16_t>(0x03EC));
        CHECK_EQ(cr.channels[1].id, static_cast<uint16_t>(0x03ED));
        CHECK_EQ(cr.channels[2].id, static_cast<uint16_t>(0x03EE));
    }
}

RTSC_TEST(connect_response_contains_three_server_blocks) {
    const auto bytes = response_vector();
    McsConnectResponse cr;
    CHECK(McsConnectResponse::parse(bytes.data(), bytes.size(), cr) == Status::Ok);
    CHECK_EQ(cr.user_data.blocks.size(), static_cast<size_t>(3));
    CHECK(cr.user_data.find(0x0C01) != nullptr);
    CHECK(cr.user_data.find(0x0C03) != nullptr);
    CHECK(cr.user_data.find(0x0C02) != nullptr);
}

RTSC_TEST(connect_response_sc_core_version_is_00080004) {
    const auto bytes = response_vector();
    McsConnectResponse cr;
    CHECK(McsConnectResponse::parse(bytes.data(), bytes.size(), cr) == Status::Ok);
    const GccUserData::Block* core = cr.user_data.find(0x0C01);
    CHECK(core != nullptr);
    if (core != nullptr) {
        CHECK_BYTES(prefix(core->payload, 0, 4), 0x04, 0x00, 0x08, 0x00);
    }
}

// ---------------------------------------------------------------------------
// D. build() and the length identities
// ---------------------------------------------------------------------------

RTSC_TEST(build_reproduces_official_416_byte_length) {
    const auto bytes = initial_vector();
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    GccUserData ud;
    CHECK(GccUserData::parse(ci.gcc_conference_create_request.data() + 23, 284, ud) ==
          Status::Ok);
    const auto built = McsConnectInitial::build(ud);
    CHECK_EQ(built.size(), static_cast<size_t>(416));
}

RTSC_TEST(build_matches_official_416_byte_vector_byte_for_byte) {
    const auto bytes = initial_vector();
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    GccUserData ud;
    CHECK(GccUserData::parse(ci.gcc_conference_create_request.data() + 23, 284, ud) ==
          Status::Ok);

    const auto built = McsConnectInitial::build(ud);
    CHECK_EQ(built.size(), bytes.size());
    const size_t diff = first_difference(built, bytes);
    if (diff != bytes.size()) {
        std::printf("  [info] build differs from official vector at offset %zu\n", diff);
    }
    CHECK(diff == bytes.size());
}

RTSC_TEST(build_with_single_short_block_uses_one_byte_length_fields) {
    GccUserData ud;
    GccUserData::Block blk;
    blk.type = static_cast<uint16_t>(GccUserDataBlock::kCsCore);
    blk.payload.assign(96, 0xAB);
    ud.blocks.push_back(blk);

    // S = 100 (< 0x80) => connectPDU length = 13 + 100 = 113 (1 byte);
    // gcc OCTET STRING content = 7 + 1 + 8 + 4 + 1 + 100 = 121 (1 byte);
    // BER body = 9 + 27 + 27 + 30 + (2 + 121) = 216 => 81 D8;
    // frame = 4 (TPKT) + 3 (X.224) + 2 (7F 65) + 2 (BER len) + 216 = 227.
    const auto bytes = McsConnectInitial::build(ud);
    CHECK_EQ(bytes.size(), static_cast<size_t>(227));
    CHECK_BYTES(prefix(bytes, 0, 4), 0x03, 0x00, 0x00, 0xE3);
    CHECK_BYTES(prefix(bytes, 7, 4), 0x7F, 0x65, 0x81, 0xD8);
    CHECK_BYTES(prefix(bytes, 104, 2), 0x04, 0x79);
    CHECK_EQ(bytes[113], static_cast<uint8_t>(113));  // connectPDU length
    CHECK_EQ(bytes[126], static_cast<uint8_t>(100));  // userData length
    CHECK_BYTES(prefix(bytes, 127, 4), 0x01, 0xC0, 0x64, 0x00);

    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    CHECK_EQ(ci.gcc_conference_create_request.size(), static_cast<size_t>(121));
}

RTSC_TEST(build_with_empty_user_data_parses_back_to_21_byte_gcc) {
    GccUserData ud;
    const auto bytes = McsConnectInitial::build(ud);
    // S = 0 => connectPDU length = 13, gcc content = 7 + 1 + 8 + 4 + 1 + 0 = 21,
    // BER body = 9 + 84 + (2 + 21) = 116 => one-byte length 0x74,
    // frame = 4 + 3 + 2 + 1 + 116 = 126.
    CHECK_EQ(bytes.size(), static_cast<size_t>(126));
    CHECK_BYTES(prefix(bytes, 0, 4), 0x03, 0x00, 0x00, 0x7E);

    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::Ok);
    CHECK_EQ(ci.gcc_conference_create_request.size(), static_cast<size_t>(21));
    CHECK_EQ(ci.gcc_conference_create_request[7], static_cast<uint8_t>(13));
    CHECK_EQ(ci.gcc_conference_create_request[20], static_cast<uint8_t>(0));
    CHECK_BYTES(prefix(ci.gcc_conference_create_request, 16, 4),
                0x44, 0x75, 0x63, 0x61);

    GccUserData back;
    CHECK(GccUserData::parse(ci.gcc_conference_create_request.data() + 21, 0, back) ==
          Status::Ok);
    CHECK(back.blocks.empty());
}

RTSC_TEST(connect_response_ignores_declared_connect_pdu_length) {
    // [MS-RDPBCGR] 4.1.4: the connectPDU length declared by the server is
    // ignored; the OCTET STRING size is authoritative. Corrupt that byte
    // (absolute offset 57, dump value 0x2A = 42 vs. actual 279) and the PDU
    // must still parse identically.
    auto bytes = response_vector();
    CHECK_EQ(bytes[57], static_cast<uint8_t>(0x2A));
    bytes[57] = 0x7F;
    McsConnectResponse cr;
    CHECK(McsConnectResponse::parse(bytes.data(), bytes.size(), cr) == Status::Ok);
    CHECK_EQ(cr.user_data.blocks.size(), static_cast<size_t>(3));
    CHECK_EQ(cr.channels.size(), static_cast<size_t>(3));

    // A two-byte-form lie must be tolerated the same way. Insert one byte so
    // the connectPDU determinant becomes `81 2A`, then repair the three
    // enclosing definite lengths (TPKT, BER body, userData OCTET STRING).
    auto bytes2 = response_vector();
    std::vector<uint8_t> widened;
    widened.insert(widened.end(), bytes2.begin(), bytes2.begin() + 57);
    widened.push_back(0x81);
    widened.push_back(0x2A);
    widened.insert(widened.end(), bytes2.begin() + 58, bytes2.end());
    CHECK_EQ(widened.size(), static_cast<size_t>(338));
    widened[2] = static_cast<uint8_t>((widened.size() >> 8) & 0xFF);
    widened[3] = static_cast<uint8_t>(widened.size() & 0xFF);
    widened[10] = static_cast<uint8_t>(((widened.size() - 12) >> 8) & 0xFF);
    widened[11] = static_cast<uint8_t>((widened.size() - 12) & 0xFF);
    widened[48] = static_cast<uint8_t>(((widened.size() - 50) >> 8) & 0xFF);
    widened[49] = static_cast<uint8_t>((widened.size() - 50) & 0xFF);
    McsConnectResponse cr2;
    CHECK(McsConnectResponse::parse(widened.data(), widened.size(), cr2) == Status::Ok);
    CHECK_EQ(cr2.user_data.blocks.size(), static_cast<size_t>(3));
    CHECK_EQ(cr2.channels.size(), static_cast<size_t>(3));
}

// ---------------------------------------------------------------------------
// E. Malformed input
// ---------------------------------------------------------------------------

RTSC_TEST(connect_initial_parse_rejects_bad_tpkt_version) {
    auto bytes = initial_vector();
    bytes[0] = 0x04;
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) ==
          Status::InvalidVersion);
}

RTSC_TEST(connect_initial_parse_rejects_tpkt_length_mismatch) {
    auto bytes = initial_vector();
    bytes[2] = 0x01;
    bytes[3] = 0x9F;  // 415 != 416
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) ==
          Status::InvalidLength);
}

RTSC_TEST(connect_initial_parse_rejects_connect_response_tag) {
    const auto bytes = response_vector();
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::InvalidType);
}

RTSC_TEST(connect_initial_parse_rejects_trailing_bytes_after_mcs_pdu) {
    auto bytes = initial_vector();
    bytes.push_back(0x00);
    bytes[2] = static_cast<uint8_t>((bytes.size() >> 8) & 0xFF);
    bytes[3] = static_cast<uint8_t>(bytes.size() & 0xFF);
    McsConnectInitial ci;
    CHECK(McsConnectInitial::parse(bytes.data(), bytes.size(), ci) == Status::InvalidLength);
}

RTSC_TEST(gcc_parse_rejects_block_length_below_header) {
    const uint8_t buf[4] = {0x01, 0xC0, 0x02, 0x00};
    GccUserData ud;
    CHECK(GccUserData::parse(buf, 4, ud) == Status::InvalidLength);
    CHECK(ud.blocks.empty());
}

RTSC_TEST(gcc_parse_needs_more_data_when_block_length_exceeds_remaining) {
    const uint8_t buf[8] = {0x01, 0xC0, 0x10, 0x00, 0xAA, 0xBB, 0xCC, 0xDD};
    GccUserData ud;
    CHECK(GccUserData::parse(buf, 8, ud) == Status::NeedMoreData);
    CHECK(ud.blocks.empty());
}

int main() { return rtsc::test::run_all("rtsc_mcs_tests"); }
