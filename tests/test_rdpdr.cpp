// Device redirection virtual channel (rdpdr) structure layer ([MS-RDPEFS] 2.2).

#include "rtsc/proto/rdpdr.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> FromHex(const char* h) {
    std::vector<uint8_t> out;
    int hi = -1;
    for (const char* p = h; *p; ++p) {
        int v = -1;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else continue;
        if (hi < 0) hi = v;
        else { out.push_back(static_cast<uint8_t>((hi << 4) | v)); hi = -1; }
    }
    return out;
}

}  // namespace

RTSC_TEST(rdpdr_header_parses) {
    const auto b = FromHex("72 44 6e 49");
    RdpdrHeader h;
    CHECK(RdpdrHeader::parse(b.data(), b.size(), h) == Status::Ok);
    CHECK_EQ(h.component, static_cast<uint16_t>(kRdpdrCtypCore));
    CHECK_EQ(h.packet_id, static_cast<uint16_t>(kPakidCoreServerAnnounce));
    CHECK(RdpdrHeader::parse(b.data(), 3, h) == Status::NeedMoreData);
}

RTSC_TEST(rdpdr_server_announce_matches_official_dump) {
    // [MS-RDPEFS] 2.2.2.2: 12 bytes, server to client.
    const auto b = FromHex("72 44 6e 49 01 00 0c 00 01 00 00 00");
    CHECK_EQ(b.size(), static_cast<size_t>(12));

    RdpdrServerAnnounce a;
    CHECK(RdpdrServerAnnounce::parse(b.data(), b.size(), a) == Status::Ok);
    CHECK_EQ(a.version_major, static_cast<uint16_t>(0x0001));
    CHECK_EQ(a.version_minor, static_cast<uint16_t>(0x000C));
    CHECK_EQ(a.client_id, static_cast<uint32_t>(0x00000001));
}

RTSC_TEST(rdpdr_server_announce_rejects_wrong_packet_id) {
    auto b = FromHex("72 44 6e 49 01 00 0c 00 01 00 00 00");
    b[2] = 0x00;  // break PAKID_CORE_SERVER_ANNOUNCE
    RdpdrServerAnnounce a;
    CHECK(RdpdrServerAnnounce::parse(b.data(), b.size(), a) == Status::InvalidType);
    CHECK(RdpdrServerAnnounce::parse(b.data(), 11, a) == Status::NeedMoreData);
}

RTSC_TEST(rdpdr_pdu_exposes_trailing_bytes) {
    // Client Name Request: header + PacketLength + Unicode computer name + code page.
    const auto b = FromHex("72 44 4e 43 20 00 00 00 00 00 00 00");
    RdpdrPdu p;
    CHECK(RdpdrPdu::parse(b.data(), b.size(), p) == Status::Ok);
    CHECK_EQ(p.header.component, static_cast<uint16_t>(kRdpdrCtypCore));
    CHECK_EQ(p.header.packet_id, static_cast<uint16_t>(kPakidCoreClientName));
    CHECK_EQ(p.data.size(), static_cast<size_t>(8));
    CHECK_EQ(p.data[0], static_cast<uint8_t>(0x20));
}

RTSC_TEST(rdpdr_print_component_is_recognised) {
    const auto b = FromHex("52 50 43 50");
    RdpdrHeader h;
    CHECK(RdpdrHeader::parse(b.data(), b.size(), h) == Status::Ok);
    CHECK_EQ(h.component, static_cast<uint16_t>(kRdpdrCtypPrn));
    CHECK_EQ(h.packet_id, static_cast<uint16_t>(0x5043));  // PAKID_PRN_CACHE_DATA
}

int main() { return ::rtsc::test::run_all("rtsc_rdpdr_tests"); }
