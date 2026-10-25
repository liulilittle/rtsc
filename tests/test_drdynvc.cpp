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

int main() { return ::rtsc::test::run_all("rtsc_drdynvc_tests"); }
