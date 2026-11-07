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

uint32_t U32At(const std::vector<uint8_t>& data, size_t offset) {
    return static_cast<uint32_t>(data[offset]) |
           (static_cast<uint32_t>(data[offset + 1]) << 8) |
           (static_cast<uint32_t>(data[offset + 2]) << 16) |
           (static_cast<uint32_t>(data[offset + 3]) << 24);
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

RTSC_TEST(rdpdr_server_clientid_confirm_is_12_bytes) {
    // [MS-RDPEFS] 2.2.2.6 DR_CORE_SERVER_CLIENTID_CONFIRM is Header(4) +
    // VersionMajor(2) + VersionMinor(2) + ClientId(4). Real clients enforce
    // this length and parse both version fields, so the historical 8-byte
    // (client id only) form is refused.
    const auto b = FromHex("72 44 43 43 01 00 0c 00 01 00 00 00");
    CHECK_EQ(b.size(), static_cast<size_t>(12));

    RdpdrServerClientIdConfirm c;
    CHECK(RdpdrServerClientIdConfirm::parse(b.data(), b.size(), c) == Status::Ok);
    CHECK_EQ(c.version_major, static_cast<uint16_t>(0x0001));
    CHECK_EQ(c.version_minor, static_cast<uint16_t>(0x000C));
    CHECK_EQ(c.client_id, static_cast<uint32_t>(0x00000001));

    // The encoder reproduces the same wire form byte for byte.
    RdpdrServerClientIdConfirm out;
    out.version_major = 1;
    out.version_minor = 0x000C;
    out.client_id = 1;
    CHECK(out.encode() == b);

    // The old 8-byte confirm (version fields omitted) is rejected, as is an
    // 11-byte truncated packet.
    RdpdrServerClientIdConfirm old_form;
    const auto eight = FromHex("72 44 43 43 01 00 00 00");
    CHECK(RdpdrServerClientIdConfirm::parse(eight.data(), eight.size(), old_form) ==
          Status::NeedMoreData);
    CHECK(RdpdrServerClientIdConfirm::parse(b.data(), 11, old_form) ==
          Status::NeedMoreData);
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

RTSC_TEST(rdpdr_devicelist_remove_round_trip) {
    RdpdrDeviceListRemove remove;
    remove.device_count = 2;
    remove.device_ids = {7, 9};
    const std::vector<uint8_t> encoded = remove.encode();
    CHECK_EQ(encoded.size(), static_cast<size_t>(16));
    CHECK_EQ(encoded[0], static_cast<uint8_t>('r'));
    CHECK_EQ(encoded[1], static_cast<uint8_t>('D'));
    CHECK_EQ(encoded[2], static_cast<uint8_t>(0x4D));
    CHECK_EQ(encoded[3], static_cast<uint8_t>(0x44));
    RdpdrDeviceListRemove parsed;
    CHECK(RdpdrDeviceListRemove::parse(encoded, parsed) == Status::Ok);
    CHECK_EQ(parsed.device_count, static_cast<uint32_t>(2));
    CHECK_EQ(parsed.device_ids.size(), static_cast<size_t>(2));
    CHECK_EQ(parsed.device_ids[0], static_cast<uint32_t>(7));
    CHECK_EQ(parsed.device_ids[1], static_cast<uint32_t>(9));
}

RTSC_TEST(rdpdr_devicelist_remove_rejects_truncated_ids) {
    RdpdrDeviceListRemove remove;
    remove.device_count = 2;
    remove.device_ids = {7, 9};
    std::vector<uint8_t> encoded = remove.encode();
    encoded.resize(encoded.size() - 2);  // second id cut short
    RdpdrDeviceListRemove parsed;
    CHECK(RdpdrDeviceListRemove::parse(encoded, parsed) ==
          Status::NeedMoreData);
}

RTSC_TEST(rdpdr_query_volume_req_parses) {
    RdpdrDeviceIoRequest req;
    req.device_id = 7;
    req.file_id = 3;
    req.completion_id = 9;
    req.major_function = kIrpMjQueryVolumeInformation;
    const std::vector<uint8_t> head = req.encode();
    ByteWriter w;
    w.bytes(head.data(), head.size());
    w.u32le(0x03);  // FileFsSizeInformation
    w.u32le(0);     // Length
    for (int i = 0; i < 24; ++i) w.u8(0);  // Padding
    const std::vector<uint8_t> body = w.take();
    CHECK_EQ(body.size(), RdpdrQueryVolumeReq::kFixedSize);

    RdpdrQueryVolumeReq parsed;
    CHECK(RdpdrQueryVolumeReq::parse(body, parsed) == Status::Ok);
    CHECK_EQ(parsed.request.device_id, static_cast<uint32_t>(7));
    CHECK_EQ(parsed.request.file_id, static_cast<uint32_t>(3));
    CHECK_EQ(parsed.fs_information_class, static_cast<uint32_t>(0x03));
    CHECK_EQ(parsed.length, static_cast<uint32_t>(0));

    std::vector<uint8_t> truncated = body;
    truncated.pop_back();
    CHECK(RdpdrQueryVolumeReq::parse(truncated, parsed) ==
          Status::NeedMoreData);
}

RTSC_TEST(rdpdr_set_information_req_parses) {
    RdpdrDeviceIoRequest req;
    req.device_id = 7;
    req.file_id = 3;
    req.completion_id = 9;
    req.major_function = kIrpMjSetInformation;
    const std::vector<uint8_t> head = req.encode();
    ByteWriter w;
    w.bytes(head.data(), head.size());
    w.u32le(0x0D);  // FileDispositionInformation
    w.u32le(1);     // Length
    for (int i = 0; i < 24; ++i) w.u8(0);  // Padding
    w.u8(1);                               // DeleteFile
    const std::vector<uint8_t> body = w.take();
    CHECK_EQ(body.size(), RdpdrSetInformationReq::kFixedSize + 1);

    RdpdrSetInformationReq parsed;
    CHECK(RdpdrSetInformationReq::parse(body, parsed) == Status::Ok);
    CHECK_EQ(parsed.request.major_function,
             static_cast<uint32_t>(kIrpMjSetInformation));
    CHECK_EQ(parsed.fs_information_class, static_cast<uint32_t>(0x0D));
    CHECK_EQ(parsed.length, static_cast<uint32_t>(1));
    CHECK_EQ(parsed.buffer.size(), static_cast<size_t>(1));
    CHECK_EQ(parsed.buffer[0], static_cast<uint8_t>(1));

    std::vector<uint8_t> truncated = body;
    truncated.pop_back();
    CHECK(RdpdrSetInformationReq::parse(truncated, parsed) ==
          Status::NeedMoreData);
}

RTSC_TEST(rdpdr_notify_change_directory_req_parses) {
    RdpdrDeviceIoRequest req;
    req.device_id = 7;
    req.file_id = 3;
    req.completion_id = 9;
    req.major_function = kIrpMjDirectoryControl;
    req.minor_function = kIrpMnNotifyChangeDirectory;
    const std::vector<uint8_t> head = req.encode();
    ByteWriter w;
    w.bytes(head.data(), head.size());
    w.u8(1);        // WatchTree
    w.u32le(0x00000001);  // CompletionFilter
    for (int i = 0; i < 27; ++i) w.u8(0);  // Padding
    const std::vector<uint8_t> body = w.take();
    CHECK_EQ(body.size(), RdpdrNotifyChangeDirectoryReq::kFixedSize);

    RdpdrNotifyChangeDirectoryReq parsed;
    CHECK(RdpdrNotifyChangeDirectoryReq::parse(body, parsed) == Status::Ok);
    CHECK_EQ(parsed.request.minor_function,
             static_cast<uint32_t>(kIrpMnNotifyChangeDirectory));
    CHECK_EQ(parsed.watch_tree, static_cast<uint8_t>(1));
    CHECK_EQ(parsed.completion_filter, static_cast<uint32_t>(0x00000001));

    std::vector<uint8_t> truncated = body;
    truncated.pop_back();
    CHECK(RdpdrNotifyChangeDirectoryReq::parse(truncated, parsed) ==
          Status::NeedMoreData);
}

RTSC_TEST(rdpdr_query_information_req_parses) {
    RdpdrDeviceIoRequest req;
    req.device_id = 7;
    req.file_id = 3;
    req.completion_id = 9;
    req.major_function = kIrpMjQueryInformation;
    const std::vector<uint8_t> head = req.encode();
    ByteWriter w;
    w.bytes(head.data(), head.size());
    w.u32le(0x04);  // FileBasicInformation
    w.u32le(0);     // Length
    for (int i = 0; i < 24; ++i) w.u8(0);  // Padding
    const std::vector<uint8_t> body = w.take();
    CHECK_EQ(body.size(), RdpdrQueryInformationReq::kFixedSize);

    RdpdrQueryInformationReq parsed;
    CHECK(RdpdrQueryInformationReq::parse(body, parsed) == Status::Ok);
    CHECK_EQ(parsed.request.major_function,
             static_cast<uint32_t>(kIrpMjQueryInformation));
    CHECK_EQ(parsed.fs_information_class, static_cast<uint32_t>(0x04));
    CHECK_EQ(parsed.length, static_cast<uint32_t>(0));

    std::vector<uint8_t> truncated = body;
    truncated.pop_back();
    CHECK(RdpdrQueryInformationReq::parse(truncated, parsed) ==
          Status::NeedMoreData);
}

RTSC_TEST(rdpdr_lock_req_parses) {
    RdpdrDeviceIoRequest req;
    req.device_id = 7;
    req.file_id = 3;
    req.completion_id = 9;
    req.major_function = kIrpMjLockControl;
    const std::vector<uint8_t> head = req.encode();
    ByteWriter w;
    w.bytes(head.data(), head.size());
    w.u32le(kRdpLowioOpExclusiveLock);
    w.u32le(0);  // Flags
    w.u32le(2);  // NumLocks
    for (int i = 0; i < 20; ++i) w.u8(0);  // Padding2
    w.u32le(10);
    w.u32le(0);  // Length
    w.u32le(100);
    w.u32le(0);  // Offset
    w.u32le(20);
    w.u32le(0);
    w.u32le(200);
    w.u32le(0);
    const std::vector<uint8_t> body = w.take();
    CHECK_EQ(body.size(), RdpdrLockReq::kFixedSize + 32);

    RdpdrLockReq parsed;
    CHECK(RdpdrLockReq::parse(body, parsed) == Status::Ok);
    CHECK_EQ(parsed.operation,
             static_cast<uint32_t>(kRdpLowioOpExclusiveLock));
    CHECK_EQ(parsed.num_locks, static_cast<uint32_t>(2));
    CHECK_EQ(parsed.locks.size(), static_cast<size_t>(2));
    CHECK_EQ(parsed.locks[0].length, static_cast<uint64_t>(10));
    CHECK_EQ(parsed.locks[0].offset, static_cast<uint64_t>(100));
    CHECK_EQ(parsed.locks[1].length, static_cast<uint64_t>(20));
    CHECK_EQ(parsed.locks[1].offset, static_cast<uint64_t>(200));

    std::vector<uint8_t> truncated = body;
    truncated.pop_back();
    CHECK(RdpdrLockReq::parse(truncated, parsed) == Status::NeedMoreData);
}

RTSC_TEST(rdpdr_set_volume_req_parses) {
    RdpdrDeviceIoRequest req;
    req.device_id = 7;
    req.file_id = 3;
    req.completion_id = 9;
    req.major_function = kIrpMjSetVolumeInformation;
    const std::vector<uint8_t> head = req.encode();
    ByteWriter w;
    w.bytes(head.data(), head.size());
    w.u32le(0x02);  // FileFsLabelInformation
    w.u32le(6);     // Length
    for (int i = 0; i < 24; ++i) w.u8(0);  // Padding
    w.u32le(2);  // VolumeLabelLength
    w.u8('A');
    w.u8(0);
    const std::vector<uint8_t> body = w.take();
    CHECK_EQ(body.size(), RdpdrSetVolumeReq::kFixedSize + 6);

    RdpdrSetVolumeReq parsed;
    CHECK(RdpdrSetVolumeReq::parse(body, parsed) == Status::Ok);
    CHECK_EQ(parsed.request.major_function,
             static_cast<uint32_t>(kIrpMjSetVolumeInformation));
    CHECK_EQ(parsed.fs_information_class, static_cast<uint32_t>(0x02));
    CHECK_EQ(parsed.length, static_cast<uint32_t>(6));
    CHECK_EQ(parsed.buffer.size(), static_cast<size_t>(6));

    std::vector<uint8_t> truncated = body;
    truncated.pop_back();
    CHECK(RdpdrSetVolumeReq::parse(truncated, parsed) ==
          Status::NeedMoreData);
}

RTSC_TEST(rdpdr_printer_announce_encodes) {
    const std::u16string driver = u"MS Publisher Imagesetter";
    const std::u16string printer_name = u"Office Printer";
    const std::vector<uint8_t> data = EncodePrinterAnnounce(
        0x10, driver, printer_name);
    const size_t expected = 24 + (driver.size() + 1) * 2 +
                            (printer_name.size() + 1) * 2;
    CHECK_EQ(data.size(), expected);
    if (data.size() < 24) return;
    CHECK_EQ(U32At(data, 0), static_cast<uint32_t>(0x10));
    CHECK_EQ(U32At(data, 4), static_cast<uint32_t>(0));
    CHECK_EQ(U32At(data, 8), static_cast<uint32_t>(0));
    CHECK_EQ(U32At(data, 12),
             static_cast<uint32_t>((driver.size() + 1) * 2));
    CHECK_EQ(U32At(data, 16),
             static_cast<uint32_t>((printer_name.size() + 1) * 2));
    CHECK_EQ(U32At(data, 20), static_cast<uint32_t>(0));
    CHECK_EQ(data[24], static_cast<uint8_t>('M'));
    CHECK_EQ(data[25], static_cast<uint8_t>(0));

    // A PnP name adds its own length and bytes before the driver name.
    const std::u16string pnp = u"PNP";
    const std::vector<uint8_t> with_pnp =
        EncodePrinterAnnounce(0, driver, printer_name, pnp);
    CHECK_EQ(with_pnp.size(),
             expected + (pnp.size() + 1) * 2);
    CHECK_EQ(U32At(with_pnp, 8),
             static_cast<uint32_t>((pnp.size() + 1) * 2));
}

int main() { return ::rtsc::test::run_all("rtsc_rdpdr_tests"); }
