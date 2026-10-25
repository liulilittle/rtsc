#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/finalization.h"
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

ShareDataHeader MakeHeader(ShareDataPduType type, uint16_t source) {
    ShareDataHeader h;
    h.control.total_length = ShareDataHeader::kSize + 8;
    h.control.type = SharePduType::kData;
    h.control.pdu_version = 1;
    h.control.pdu_source = source;
    h.share_id = 0x000103EA;
    h.stream_id = 0x01;  // STREAM_LOW
    h.pdu_type2 = type;
    return h;
}

}  // namespace

// ---- Official Synchronize dump -------------------------------------------

RTSC_TEST(synchronize_matches_official_dump) {
    // 4.1.14 decrypted plaintext, 22 bytes.
    const auto expected = FromHex(
        "16 00 17 00 ef 03 ea 03 01 00 00 01 08 00 1f 00 00 00 01 00 ea 03");
    CHECK_EQ(expected.size(), static_cast<size_t>(22));

    SynchronizePdu pdu;
    CHECK(SynchronizePdu::parse(expected.data(), expected.size(), pdu) == Status::Ok);
    CHECK_EQ(pdu.message_type, static_cast<uint16_t>(1));
    // The client sets targetUser to the Server Channel ID (1002 = 0x03EA).
    CHECK_EQ(pdu.target_user, static_cast<uint16_t>(0x03EA));

    // Re-encode from the header fields and compare byte for byte.
    ShareDataHeader h;
    h.control.total_length = 22;
    h.control.type = SharePduType::kData;
    h.control.pdu_version = 1;
    h.control.pdu_source = 0x03EF;  // user channel ID
    h.share_id = 0x000103EA;
    h.pad1 = 0;
    h.stream_id = 0x01;
    h.uncompressed_length = 8;  // 4 payload bytes + the 4 header bytes it covers
    h.pdu_type2 = ShareDataPduType::kSynchronize;
    h.compressed_type = 0;
    h.compressed_length = 0;

    ByteWriter w;
    SynchronizePdu out;
    out.message_type = 1;
    out.target_user = 0x03EA;
    out.write(w, h);
    CHECK(w.data() == expected);
}

RTSC_TEST(synchronize_rejects_wrong_message_type) {
    auto bytes = FromHex(
        "16 00 17 00 ef 03 ea 03 01 00 00 01 08 00 1f 00 00 00 02 00 ea 03");
    SynchronizePdu pdu;
    CHECK(SynchronizePdu::parse(bytes.data(), bytes.size(), pdu) ==
          Status::InvalidField);
}

RTSC_TEST(synchronize_rejects_wrong_pdu_type2) {
    auto bytes = FromHex(
        "16 00 17 00 ef 03 ea 03 01 00 00 01 08 00 14 00 00 00 01 00 ea 03");
    SynchronizePdu pdu;
    CHECK(SynchronizePdu::parse(bytes.data(), bytes.size(), pdu) ==
          Status::InvalidType);
}

// ---- Control PDU ----------------------------------------------------------

RTSC_TEST(control_client_cooperate_is_26_bytes) {
    ShareDataHeader h = MakeHeader(ShareDataPduType::kControl, 0x03EF);
    h.control.total_length = 26;
    ByteWriter w;
    ControlPdu pdu;
    pdu.action = ControlAction::kCooperate;
    pdu.grant_id = 0;
    pdu.control_id = 0;
    pdu.write(w, h);
    CHECK_EQ(w.data().size(), static_cast<size_t>(26));
    CHECK_EQ(w.data()[14], static_cast<uint8_t>(0x14));  // PDUTYPE2_CONTROL
    CHECK_EQ(w.data()[18], static_cast<uint8_t>(0x04));  // action = cooperate

    ControlPdu back;
    CHECK(ControlPdu::parse(w.data().data(), w.data().size(), back) == Status::Ok);
    CHECK(back.action == ControlAction::kCooperate);
    CHECK_EQ(back.grant_id, static_cast<uint16_t>(0));
    CHECK_EQ(back.control_id, static_cast<uint32_t>(0));
}

RTSC_TEST(control_parses_server_granted_control) {
    // 4.1.21: action=2, grantId=0x03EF (1007), controlId=0x03EA (1002).
    // Both must be accepted even though the client sends zeros.
    ByteWriter w;
    ShareDataHeader h = MakeHeader(ShareDataPduType::kControl, 0x03EA);
    h.control.total_length = 26;
    ControlPdu pdu;
    pdu.action = ControlAction::kGrantedControl;
    pdu.grant_id = 0x03EF;
    pdu.control_id = 0x03EA;
    pdu.write(w, h);

    ControlPdu back;
    CHECK(ControlPdu::parse(w.data().data(), w.data().size(), back) == Status::Ok);
    CHECK(back.action == ControlAction::kGrantedControl);
    CHECK_EQ(back.grant_id, static_cast<uint16_t>(0x03EF));
    CHECK_EQ(back.control_id, static_cast<uint32_t>(0x03EA));
}

RTSC_TEST(control_rejects_invalid_action) {
    ByteWriter w;
    ShareDataHeader h = MakeHeader(ShareDataPduType::kControl, 1);
    h.control.total_length = 26;
    h.write(w);
    w.u16le(0x0005);  // outside 1..4
    w.u16le(0);
    w.u32le(0);
    ControlPdu pdu;
    CHECK(ControlPdu::parse(w.data().data(), w.data().size(), pdu) ==
          Status::InvalidField);
}

RTSC_TEST(control_action_names) {
    CHECK(std::string(to_string(ControlAction::kRequestControl)) == "request-control");
    CHECK(std::string(to_string(ControlAction::kGrantedControl)) == "granted-control");
    CHECK(std::string(to_string(ControlAction::kDetach)) == "detach");
    CHECK(std::string(to_string(ControlAction::kCooperate)) == "cooperate");
}

// ---- Font List / Font Map -------------------------------------------------

RTSC_TEST(font_list_is_26_bytes_with_expected_defaults) {
    ByteWriter w;
    ShareDataHeader h = MakeHeader(ShareDataPduType::kFontList, 0x03EF);
    h.control.total_length = 26;
    FontListPdu pdu;
    pdu.write(w, h);
    CHECK_EQ(w.data().size(), static_cast<size_t>(26));
    CHECK_EQ(w.data()[14], static_cast<uint8_t>(0x27));  // PDUTYPE2_FONTLIST
    // numberFonts=0, totalNumFonts=0, listFlags=0x0003, entrySize=0x0032
    CHECK_EQ(w.data()[18], static_cast<uint8_t>(0x00));
    CHECK_EQ(w.data()[20], static_cast<uint8_t>(0x00));
    CHECK_EQ(w.data()[22], static_cast<uint8_t>(0x03));
    CHECK_EQ(w.data()[23], static_cast<uint8_t>(0x00));
    CHECK_EQ(w.data()[24], static_cast<uint8_t>(0x32));
    CHECK_EQ(w.data()[25], static_cast<uint8_t>(0x00));

    FontListPdu back;
    CHECK(FontListPdu::parse(w.data().data(), w.data().size(), back) == Status::Ok);
    CHECK_EQ(back.list_flags, static_cast<uint16_t>(0x0003));
    CHECK_EQ(back.entry_size, static_cast<uint16_t>(0x0032));
}

RTSC_TEST(font_map_is_26_bytes_and_entry_size_differs) {
    ByteWriter w;
    ShareDataHeader h = MakeHeader(ShareDataPduType::kFontMap, 0x03EA);
    h.control.total_length = 26;
    FontMapPdu pdu;
    pdu.write(w, h);
    CHECK_EQ(w.data().size(), static_cast<size_t>(26));
    CHECK_EQ(w.data()[14], static_cast<uint8_t>(0x28));  // PDUTYPE2_FONTMAP
    CHECK_EQ(w.data()[22], static_cast<uint8_t>(0x03));  // mapFlags
    // entrySize is 4, NOT 50 like Font List.
    CHECK_EQ(w.data()[24], static_cast<uint8_t>(0x04));
    CHECK_EQ(w.data()[25], static_cast<uint8_t>(0x00));

    FontMapPdu back;
    CHECK(FontMapPdu::parse(w.data().data(), w.data().size(), back) == Status::Ok);
    CHECK_EQ(back.map_flags, static_cast<uint16_t>(0x0003));
    CHECK_EQ(back.entry_size, static_cast<uint16_t>(0x0004));
}

RTSC_TEST(font_list_and_font_map_do_not_share_entry_size) {
    FontListPdu list;
    FontMapPdu map;
    CHECK(list.entry_size != map.entry_size);
    CHECK_EQ(list.entry_size, static_cast<uint16_t>(50));
    CHECK_EQ(map.entry_size, static_cast<uint16_t>(4));
}

// ---- Deactivate All -------------------------------------------------------

RTSC_TEST(deactivate_all_parses_minimal_pdu) {
    // 6 (share control) + 4 (shareID) + 2 (lengthSourceDescriptor) + 1 (0x00)
    // = 13 bytes; pduType = 0x0016 (version 1 | type 6).
    const auto bytes =
        FromHex("0d 00 16 00 ea 03 ea 03 01 00 01 00 00");
    CHECK_EQ(bytes.size(), static_cast<size_t>(13));

    DeactivateAllPdu pdu;
    CHECK(DeactivateAllPdu::parse(bytes.data(), bytes.size(), pdu) == Status::Ok);
    CHECK_EQ(pdu.share_id, static_cast<uint32_t>(0x000103EA));
    CHECK_EQ(pdu.source_descriptor.size(), static_cast<size_t>(1));
    CHECK_EQ(pdu.source_descriptor[0], static_cast<uint8_t>(0));
}

RTSC_TEST(deactivate_all_rejects_wrong_type) {
    auto bytes = FromHex("0d 00 16 00 ea 03 ea 03 01 00 01 00 00");
    bytes[2] = 0x11;  // Demand Active
    DeactivateAllPdu pdu;
    CHECK(DeactivateAllPdu::parse(bytes.data(), bytes.size(), pdu) ==
          Status::InvalidType);
}

RTSC_TEST(deactivate_all_rejects_length_mismatch) {
    auto bytes = FromHex("0d 00 16 00 ea 03 ea 03 01 00 01 00 00");
    bytes[0] = 0x0E;  // claims 14 bytes
    DeactivateAllPdu pdu;
    CHECK(DeactivateAllPdu::parse(bytes.data(), bytes.size(), pdu) ==
          Status::InvalidLength);
}

// ---- Persistent Key List --------------------------------------------------

namespace {

// Builds a Persistent Key List PDU with `counts[i]` keys per cache.
std::vector<uint8_t> BuildPersistentKeyList(const uint16_t (&counts)[5],
                                            const uint16_t (&totals)[5],
                                            uint8_t bit_mask) {
    size_t keys = 0;
    for (uint16_t c : counts) keys += c;
    const size_t total = 18 + 24 + keys * 8;

    ByteWriter w;
    ShareDataHeader h;
    h.control.total_length = static_cast<uint16_t>(total);
    h.control.type = SharePduType::kData;
    h.control.pdu_version = 1;
    h.control.pdu_source = 0x03EF;
    h.share_id = 0x000103EA;
    h.stream_id = 0x01;
    h.pdu_type2 = ShareDataPduType::kPersistentKeyList;
    h.write(w);

    for (uint16_t c : counts) w.u16le(c);
    for (uint16_t t : totals) w.u16le(t);
    w.u8(bit_mask);
    w.u8(0);      // Pad2
    w.u16le(0);   // Pad3
    for (size_t i = 0; i < keys; ++i) {
        w.u32le(static_cast<uint32_t>(0x1000 + i));  // Key1 (low)
        w.u32le(static_cast<uint32_t>(0x2000 + i));  // Key2 (high)
    }
    return w.take();
}

}  // namespace

RTSC_TEST(persistent_key_list_matches_official_shape) {
    // 4.1.17: totalLength 242, numEntriesCache2 = 25, totalEntriesCache2 = 25,
    // bBitMask = 0x03. 18 + 24 + 25*8 = 242.
    uint16_t counts[5] = {0, 0, 25, 0, 0};
    uint16_t totals[5] = {0, 0, 25, 0, 0};
    const auto bytes = BuildPersistentKeyList(counts, totals, 0x03);
    CHECK_EQ(bytes.size(), static_cast<size_t>(242));

    PersistentKeyListPdu pdu;
    CHECK(PersistentKeyListPdu::parse(bytes.data(), bytes.size(), pdu) == Status::Ok);
    CHECK_EQ(pdu.num_entries[2], static_cast<uint16_t>(25));
    CHECK_EQ(pdu.total_entries[2], static_cast<uint16_t>(25));
    CHECK_EQ(pdu.bit_mask, static_cast<uint8_t>(0x03));
    CHECK_EQ(pdu.key1.size(), static_cast<size_t>(25));
    CHECK_EQ(pdu.key2.size(), static_cast<size_t>(25));
    CHECK_EQ(pdu.key1[0], static_cast<uint32_t>(0x1000));
    CHECK_EQ(pdu.key2[0], static_cast<uint32_t>(0x2000));
}

RTSC_TEST(persistent_key_list_rejects_truncated_entries) {
    uint16_t counts[5] = {0, 0, 25, 0, 0};
    uint16_t totals[5] = {0, 0, 25, 0, 0};
    auto bytes = BuildPersistentKeyList(counts, totals, 0x03);
    // Drop the last entry: the declared count now over-describes the data.
    bytes.resize(bytes.size() - 8);
    bytes[0] = static_cast<uint8_t>((bytes.size()) & 0xFF);
    bytes[1] = static_cast<uint8_t>((bytes.size() >> 8) & 0xFF);
    PersistentKeyListPdu pdu;
    CHECK(PersistentKeyListPdu::parse(bytes.data(), bytes.size(), pdu) ==
          Status::InvalidLength);
}

RTSC_TEST(persistent_key_list_rejects_excessive_total) {
    uint16_t counts[5] = {0, 0, 1, 0, 0};
    // The constraint is on the SUM of the five totals, not on each one:
    // 5 x 0xFFFF = 327675 > 262144.
    uint16_t totals[5] = {0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF};
    const auto bytes = BuildPersistentKeyList(counts, totals, 0x03);
    PersistentKeyListPdu pdu;
    CHECK(PersistentKeyListPdu::parse(bytes.data(), bytes.size(), pdu) ==
          Status::InvalidField);
}

RTSC_TEST(persistent_key_list_rejects_wrong_pdu_type) {
    uint16_t counts[5] = {0, 0, 0, 0, 0};
    uint16_t totals[5] = {0, 0, 0, 0, 0};
    auto bytes = BuildPersistentKeyList(counts, totals, 0x01);
    bytes[14] = 0x27;  // Font List
    PersistentKeyListPdu pdu;
    CHECK(PersistentKeyListPdu::parse(bytes.data(), bytes.size(), pdu) ==
          Status::InvalidType);
}

// ---- Framing helper -------------------------------------------------------

RTSC_TEST(build_slow_path_data_pdu_frames_correctly) {
    const std::vector<uint8_t> payload = {0x01, 0x00, 0xEA, 0x03};
    const auto pdu = BuildSlowPathDataPdu(0x03EF, 0x000103EA, 0x01,
                                          ShareDataPduType::kSynchronize, payload);
    CHECK_EQ(pdu.size(), static_cast<size_t>(22));

    ShareDataHeader h;
    CHECK(ShareDataHeader::parse(pdu.data(), pdu.size(), h) == Status::Ok);
    CHECK_EQ(h.control.total_length, static_cast<uint16_t>(22));
    CHECK(h.control.type == SharePduType::kData);
    CHECK_EQ(h.control.pdu_source, static_cast<uint16_t>(0x03EF));
    CHECK_EQ(h.share_id, static_cast<uint32_t>(0x000103EA));
    CHECK_EQ(h.stream_id, static_cast<uint8_t>(0x01));
    CHECK(h.pdu_type2 == ShareDataPduType::kSynchronize);
    CHECK_EQ(h.uncompressed_length, static_cast<uint16_t>(4));

    // Payload follows the header unchanged.
    CHECK(pdu[18] == 0x01);
    CHECK(pdu[19] == 0x00);
    CHECK(pdu[20] == 0xEA);
    CHECK(pdu[21] == 0x03);
}

RTSC_TEST(build_slow_path_data_pdu_roundtrips_as_synchronize) {
    const auto bytes = BuildSlowPathDataPdu(0x03EF, 0x000103EA, 0x01,
                                            ShareDataPduType::kSynchronize,
                                            {0x01, 0x00, 0xEA, 0x03});
    SynchronizePdu pdu;
    CHECK(SynchronizePdu::parse(bytes.data(), bytes.size(), pdu) == Status::Ok);
    CHECK_EQ(pdu.message_type, static_cast<uint16_t>(1));
    CHECK_EQ(pdu.target_user, static_cast<uint16_t>(0x03EA));
}

int main() { return rtsc::test::run_all("rtsc_finalization_tests"); }
