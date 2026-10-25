// rdpdr virtual channel handler tests ([MS-RDPEFS] 3.1).
//
// These exercise the client-side state machine (announce -> client name ->
// client id confirm -> capabilities/device list) and the drive redirection
// file I/O dispatch against a recording IFileSystem. The HostFileSystem bridge
// is exercised separately against a real temporary directory.

#include "rtsc/channel/rdpdr_client.h"
#include "rtsc/rdpdr/file_system.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "rtsc/proto/channel.h"
#include "rtsc/proto/rdpdr.h"
#include "test_framework.h"

namespace proto = rtsc::proto;
using rtsc::channel::RdpdrClient;
using rtsc::rdpdr::HostFileSystem;
using rtsc::rdpdr::IFileSystem;

namespace {

constexpr uint32_t kDeviceId = 7;
constexpr uint32_t kRequiredIoCode1 = 0x00003FFF;

uint32_t U32At(const std::vector<uint8_t>& v, size_t off) {
    return static_cast<uint32_t>(v[off]) |
           (static_cast<uint32_t>(v[off + 1]) << 8) |
           (static_cast<uint32_t>(v[off + 2]) << 16) |
           (static_cast<uint32_t>(v[off + 3]) << 24);
}

// ---- channel plumbing ------------------------------------------------------

void FeedMessage(RdpdrClient& c, const std::vector<uint8_t>& pdu) {
    for (const auto& chunk : proto::FragmentChannelMessage(pdu)) {
        c.OnChannelData(chunk.data(), chunk.size());
    }
}

void FeedBody(RdpdrClient& c, uint16_t packet_id,
              const std::vector<uint8_t>& body) {
    FeedMessage(c, proto::BuildRdpdrPdu(packet_id, body));
}

std::vector<uint8_t> Sub(const std::vector<uint8_t>& m) {
    return std::vector<uint8_t>(m.begin() + proto::ChannelPduHeader::kSize,
                                m.end());
}

const std::vector<uint8_t>* FindSent(
    const std::vector<std::vector<uint8_t>>& sent, uint16_t packet_id) {
    for (const auto& m : sent) {
        if (m.size() < proto::ChannelPduHeader::kSize + proto::RdpdrHeader::kSize) {
            continue;
        }
        proto::RdpdrPdu pdu;
        if (proto::RdpdrPdu::parse(m.data() + proto::ChannelPduHeader::kSize,
                                   m.size() - proto::ChannelPduHeader::kSize,
                                   pdu) == proto::Status::Ok &&
            pdu.header.packet_id == packet_id) {
            return &m;
        }
    }
    return nullptr;
}

// ---- request body builders -------------------------------------------------

std::vector<uint8_t> IoRequestBody(uint32_t device_id, uint32_t file_id,
                                  uint32_t completion_id, uint32_t major,
                                  uint32_t minor) {
    proto::RdpdrDeviceIoRequest r;
    r.device_id = device_id;
    r.file_id = file_id;
    r.completion_id = completion_id;
    r.major_function = major;
    r.minor_function = minor;
    return r.encode();
}

std::vector<uint8_t> CreateBody(uint32_t device_id, uint32_t completion_id,
                                uint32_t disposition, const std::string& path) {
    proto::ByteWriter w;
    const std::vector<uint8_t> req =
        IoRequestBody(device_id, 0, completion_id, proto::kIrpMjCreate, 0);
    w.bytes(req.data(), req.size());
    w.u32le(0x00100000);      // DesiredAccess
    w.u32le(0); w.u32le(0);   // AllocationSize (u64)
    w.u32le(0x80);            // FileAttributes
    w.u32le(0);               // SharedAccess
    w.u32le(disposition);
    w.u32le(0);               // CreateOptions
    const std::vector<uint8_t> path_bytes = proto::RdpdrEncodeUtf16(path);
    w.u32le(static_cast<uint32_t>(path_bytes.size()));
    w.bytes(path_bytes.data(), path_bytes.size());
    return w.take();
}

std::vector<uint8_t> ReadBody(uint32_t device_id, uint32_t file_id,
                              uint32_t completion_id, uint32_t length,
                              uint64_t offset) {
    proto::ByteWriter w;
    const std::vector<uint8_t> req =
        IoRequestBody(device_id, file_id, completion_id, proto::kIrpMjRead, 0);
    w.bytes(req.data(), req.size());
    w.u32le(length);
    w.u32le(static_cast<uint32_t>(offset & 0xFFFFFFFFu));
    w.u32le(static_cast<uint32_t>(offset >> 32));
    return w.take();
}

std::vector<uint8_t> WriteBody(uint32_t device_id, uint32_t file_id,
                               uint32_t completion_id, uint64_t offset,
                               const std::vector<uint8_t>& data) {
    proto::ByteWriter w;
    const std::vector<uint8_t> req =
        IoRequestBody(device_id, file_id, completion_id, proto::kIrpMjWrite, 0);
    w.bytes(req.data(), req.size());
    w.u32le(static_cast<uint32_t>(data.size()));
    w.u32le(static_cast<uint32_t>(offset & 0xFFFFFFFFu));
    w.u32le(static_cast<uint32_t>(offset >> 32));
    for (int i = 0; i < 20; ++i) w.u8(0);  // Padding
    w.bytes(data.data(), data.size());
    return w.take();
}

std::vector<uint8_t> QueryDirBody(uint32_t device_id, uint32_t file_id,
                                  uint32_t completion_id, uint32_t info_class,
                                  bool initial, const std::string& path) {
    proto::ByteWriter w;
    const std::vector<uint8_t> req = IoRequestBody(
        device_id, file_id, completion_id, proto::kIrpMjDirectoryControl,
        proto::kIrpMnQueryDirectory);
    w.bytes(req.data(), req.size());
    w.u32le(info_class);
    w.u8(initial ? 1 : 0);
    const std::vector<uint8_t> path_bytes = proto::RdpdrEncodeUtf16(path);
    w.u32le(static_cast<uint32_t>(path_bytes.size()));
    for (int i = 0; i < 23; ++i) w.u8(0);  // Padding
    w.bytes(path_bytes.data(), path_bytes.size());
    return w.take();
}

std::vector<uint8_t> ControlBody(uint32_t device_id, uint32_t file_id,
                                 uint32_t completion_id, uint32_t ioctl,
                                 const std::vector<uint8_t>& input) {
    proto::ByteWriter w;
    const std::vector<uint8_t> req = IoRequestBody(
        device_id, file_id, completion_id, proto::kIrpMjDeviceControl, 0);
    w.bytes(req.data(), req.size());
    w.u32le(0);  // OutputBufferLength
    w.u32le(static_cast<uint32_t>(input.size()));
    w.u32le(ioctl);
    for (int i = 0; i < 20; ++i) w.u8(0);  // Padding
    w.bytes(input.data(), input.size());
    return w.take();
}

// ---- recording fake --------------------------------------------------------

class MockFs final : public IFileSystem {
 public:
    bool Open(const std::string& local_path, bool for_write, bool create,
              uint32_t& file_id) override {
        ++open_calls;
        last_open_path = local_path;
        last_for_write = for_write;
        last_create = create;
        if (fail_open_once) {
            fail_open_once = false;
            return false;
        }
        file_id = next_id_++;
        return true;
    }

    bool Read(uint32_t file_id, uint64_t offset, uint32_t length,
              std::vector<uint8_t>& out) override {
        ++read_calls;
        last_read_id = file_id;
        last_read_offset = offset;
        last_read_length = length;
        out = read_data;
        return read_result;
    }

    bool Write(uint32_t file_id, uint64_t offset,
               const std::vector<uint8_t>& data, uint32_t& written) override {
        ++write_calls;
        last_write_id = file_id;
        last_write_offset = offset;
        last_write_data = data;
        written = static_cast<uint32_t>(data.size());
        return write_result;
    }

    bool Close(uint32_t file_id) override {
        ++close_calls;
        last_close_id = file_id;
        return close_result;
    }

    bool QueryDirectory(uint32_t file_id, bool initial,
                        uint32_t fs_information_class,
                        std::vector<uint8_t>& out) override {
        ++query_calls;
        last_query_id = file_id;
        last_query_initial = initial;
        last_query_class = fs_information_class;
        out = query_data;
        return query_result;
    }

    bool Stat(const std::string& local_path, bool& is_directory) override {
        ++stat_calls;
        last_stat_path = local_path;
        is_directory = false;
        return stat_result;
    }

    unsigned open_calls = 0;
    unsigned read_calls = 0;
    unsigned write_calls = 0;
    unsigned close_calls = 0;
    unsigned query_calls = 0;
    unsigned stat_calls = 0;
    bool fail_open_once = false;
    bool read_result = true;
    bool write_result = true;
    bool close_result = true;
    bool query_result = true;
    bool stat_result = true;
    std::string last_open_path;
    std::string last_stat_path;
    bool last_for_write = false;
    bool last_create = false;
    uint32_t last_read_id = 0;
    uint64_t last_read_offset = 0;
    uint32_t last_read_length = 0;
    uint32_t last_write_id = 0;
    uint64_t last_write_offset = 0;
    uint32_t last_close_id = 0;
    uint32_t last_query_id = 0;
    bool last_query_initial = false;
    uint32_t last_query_class = 0;
    std::vector<uint8_t> read_data;
    std::vector<uint8_t> last_write_data;
    std::vector<uint8_t> query_data;

 private:
    uint32_t next_id_ = 1;
};

// ---- filesystem temp helpers ----------------------------------------------

std::filesystem::path MakeTempDir(const char* tag) {
    static unsigned counter = 0;
    std::filesystem::path dir = std::filesystem::temp_directory_path() /
        ("rtsc_rdpdr_" + std::string(tag) + "_" + std::to_string(++counter));
    std::filesystem::create_directories(dir);
    return dir;
}

std::vector<uint8_t> ReadWholeFile(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    in.seekg(0, std::ios::end);
    const size_t n = static_cast<size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> out(n);
    if (n > 0) {
        in.read(reinterpret_cast<char*>(out.data()),
                static_cast<std::streamsize>(n));
    }
    return out;
}

// ---- state machine ---------------------------------------------------------

RTSC_TEST(rdpdr_client_starts_awaiting_server_announce) {
    MockFs fs;
    RdpdrClient client(&fs, {}, "HOST", [](const std::vector<uint8_t>&) {});
    CHECK(client.phase() == RdpdrClient::Phase::kAwaitServerAnnounce);
    CHECK_EQ(client.client_id(), static_cast<uint32_t>(0));
    CHECK_EQ(client.server_announce_count(), static_cast<unsigned>(0));
    CHECK_EQ(client.client_announce_count(), static_cast<unsigned>(0));
    CHECK(!client.user_logged_on());
}

RTSC_TEST(rdpdr_client_announce_replies_and_advances_phase) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST1",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 0x1234;
    FeedMessage(client, announce.encode());

    CHECK(client.phase() == RdpdrClient::Phase::kAwaitClientIdConfirm);
    CHECK_EQ(client.server_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.client_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.client_name_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.client_id(), static_cast<uint32_t>(0x1234));
    CHECK_EQ(client.version_major(), static_cast<uint16_t>(1));
    CHECK_EQ(client.version_minor(), static_cast<uint16_t>(0x000C));

    const std::vector<uint8_t>* reply =
        FindSent(sent, proto::kPakidCoreClientidConfirm);
    CHECK(reply != nullptr);
    if (reply != nullptr) {
        proto::RdpdrClientAnnounceReply parsed;
        CHECK(proto::RdpdrClientAnnounceReply::parse(reply->data() + 8,
                                                      reply->size() - 8,
                                                      parsed) == proto::Status::Ok);
        CHECK_EQ(parsed.version_major, static_cast<uint16_t>(1));
        CHECK_EQ(parsed.version_minor, static_cast<uint16_t>(0x000C));
        CHECK_EQ(parsed.client_id, static_cast<uint32_t>(0x1234));
    }

    const std::vector<uint8_t>* name =
        FindSent(sent, proto::kPakidCoreClientName);
    CHECK(name != nullptr);
    if (name != nullptr) {
        proto::RdpdrClientNameRequest parsed;
        CHECK(proto::RdpdrClientNameRequest::parse(Sub(*name), parsed) ==
              proto::Status::Ok);
        CHECK_EQ(parsed.unicode_flag, static_cast<uint32_t>(1));
        CHECK_EQ(parsed.code_page, static_cast<uint32_t>(0));
        CHECK(proto::RdpdrDecodeUtf16(parsed.computer_name.data(),
                                      parsed.computer_name.size()) == "HOST1");
    }
}

RTSC_TEST(rdpdr_client_confirm_sends_capabilities_and_devices) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST1",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 0x1234;
    FeedMessage(client, announce.encode());

    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 0x55;
    FeedMessage(client, confirm.encode());

    CHECK(client.phase() == RdpdrClient::Phase::kReady);
    CHECK_EQ(client.client_capability_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.device_list_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.client_id(), static_cast<uint32_t>(0x55));

    const std::vector<uint8_t>* caps =
        FindSent(sent, proto::kPakidCoreClientCapability);
    CHECK(caps != nullptr);
    if (caps != nullptr) {
        proto::RdpdrCoreCapability parsed;
        CHECK(proto::RdpdrCoreCapability::parse(Sub(*caps), parsed) ==
              proto::Status::Ok);
        CHECK_EQ(parsed.num_capabilities, static_cast<uint16_t>(2));
        bool saw_general = false;
        bool saw_drive = false;
        for (const auto& set : parsed.capabilities) {
            if (set.header.capability_type == proto::kCapGeneralType) {
                saw_general = true;
                proto::RdpdrGeneralCapsSet general;
                CHECK(proto::RdpdrGeneralCapsSet::parse(set.data,
                                                         set.header.version,
                                                         general) ==
                      proto::Status::Ok);
                CHECK_EQ(general.io_code1, kRequiredIoCode1);
                CHECK_EQ(general.protocol_major_version, static_cast<uint16_t>(1));
                CHECK_EQ(general.protocol_minor_version,
                         static_cast<uint16_t>(0x000C));
            } else if (set.header.capability_type == proto::kCapDriveType) {
                saw_drive = true;
            }
        }
        CHECK(saw_general);
        CHECK(saw_drive);
    }

    const std::vector<uint8_t>* list =
        FindSent(sent, proto::kPakidCoreDevicelistAnnounce);
    CHECK(list != nullptr);
    if (list != nullptr) {
        proto::RdpdrDeviceListAnnounce parsed;
        CHECK(proto::RdpdrDeviceListAnnounce::parse(Sub(*list), parsed) ==
              proto::Status::Ok);
        CHECK_EQ(parsed.device_count, static_cast<uint32_t>(1));
        CHECK_EQ(parsed.devices.size(), static_cast<size_t>(1));
        CHECK_EQ(parsed.devices[0].device_id, kDeviceId);
        CHECK_EQ(parsed.devices[0].device_type,
                 static_cast<uint32_t>(proto::kRdpdrDtypFilesystem));
        CHECK(parsed.devices[0].dos_name() == "C:");
    }
}

RTSC_TEST(rdpdr_client_server_capability_and_user_logged_on) {
    MockFs fs;
    RdpdrClient client(&fs, {}, "HOST", [](const std::vector<uint8_t>&) {});

    proto::ByteWriter caps;
    caps.u16le(1);
    caps.u16le(0);
    proto::RdpdrGeneralCapsSet general;
    general.protocol_major_version = 1;
    general.protocol_minor_version = 0x000C;
    general.io_code1 = kRequiredIoCode1;
    proto::RdpdrCapabilitySet general_set;
    general_set.header.capability_type = proto::kCapGeneralType;
    general_set.header.version = proto::kGeneralCapabilityVersion02;
    general_set.data = general.encode(general_set.header.version);
    general_set.header.capability_length = static_cast<uint16_t>(
        proto::RdpdrCapabilityHeader::kSize + general_set.data.size());
    caps.bytes(general_set.encode().data(), general_set.encode().size());
    FeedBody(client, proto::kPakidCoreServerCapability, caps.take());
    CHECK_EQ(client.server_capability_count(), static_cast<unsigned>(1));

    FeedBody(client, proto::kPakidCoreUserLoggedon, {});
    CHECK(client.user_logged_on());
}

RTSC_TEST(rdpdr_client_device_reply_recorded) {
    MockFs fs;
    RdpdrClient client(&fs, {}, "HOST", [](const std::vector<uint8_t>&) {});

    proto::RdpdrDeviceReply reply;
    reply.device_id = kDeviceId;
    reply.result_code = 0;
    FeedMessage(client, reply.encode());
    CHECK_EQ(client.device_reply_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_client_reassembles_chunked_announce) {
    MockFs fs;
    RdpdrClient client(&fs, {}, "HOST", [](const std::vector<uint8_t>&) {});

    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 0x42;
    const std::vector<uint8_t> pdu = announce.encode();
    const auto chunks = proto::FragmentChannelMessage(pdu, 3);
    CHECK(chunks.size() > 1);
    for (const auto& chunk : chunks) {
        client.OnChannelData(chunk.data(), chunk.size());
    }
    CHECK_EQ(client.server_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.client_id(), static_cast<uint32_t>(0x42));
}

RTSC_TEST(rdpdr_client_ignores_short_and_garbage) {
    MockFs fs;
    RdpdrClient client(&fs, {}, "HOST", [](const std::vector<uint8_t>&) {});
    client.OnChannelData(nullptr, 0);
    const uint8_t tiny[3] = {1, 2, 3};
    client.OnChannelData(tiny, sizeof(tiny));
    CHECK_EQ(client.server_announce_count(), static_cast<unsigned>(0));
}

// ---- file I/O dispatch -----------------------------------------------------

RTSC_TEST(rdpdr_client_create_maps_remote_path_and_opens) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 9, 0x00000003 /* kFileOpenIf */,
                        "\\tsclient\\C\\dir\\file.txt"));

    CHECK_EQ(fs.open_calls, static_cast<unsigned>(1));
    // kFileOpenIf needs write access (the client may create the file).
    CHECK_EQ(fs.last_for_write, true);
    CHECK_EQ(fs.last_create, false);
    CHECK(fs.last_open_path == "C:\\dir\\file.txt");
    CHECK(client.last_remote_path() == "\\tsclient\\C\\dir\\file.txt");
    CHECK(client.last_local_path() == "C:\\dir\\file.txt");
    CHECK_EQ(client.create_count(), static_cast<unsigned>(1));

    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(1));  // file id
        CHECK_EQ((*rsp)[28], static_cast<uint8_t>(proto::kFileOpened));
    }
}

RTSC_TEST(rdpdr_client_create_openif_falls_back_to_create) {
    MockFs fs;
    fs.fail_open_once = true;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 9, 0x00000003 /* kFileOpenIf */,
                        "\\tsclient\\C\\new.txt"));

    CHECK_EQ(fs.open_calls, static_cast<unsigned>(2));
    CHECK_EQ(fs.last_for_write, true);
    CHECK_EQ(fs.last_create, true);
    CHECK_EQ(client.create_count(), static_cast<unsigned>(1));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
    }
}

RTSC_TEST(rdpdr_client_create_unknown_device_is_access_denied) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(999, 9, 0x00000001, "\\tsclient\\C\\x.txt"));

    CHECK_EQ(fs.open_calls, static_cast<unsigned>(0));
    CHECK_EQ(client.create_count(), static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusAccessDenied));
    }
}

RTSC_TEST(rdpdr_client_read_write_close_round_trip) {
    MockFs fs;
    fs.read_data = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ReadBody(kDeviceId, 0x100, 11, 4, 64));
    CHECK_EQ(fs.read_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_read_id, static_cast<uint32_t>(0x100));
    CHECK_EQ(fs.last_read_offset, static_cast<uint64_t>(64));
    CHECK_EQ(fs.last_read_length, static_cast<uint32_t>(4));
    CHECK_EQ(client.read_count(), static_cast<unsigned>(1));
    {
        const std::vector<uint8_t>* rsp =
            FindSent(sent, proto::kPakidCoreDeviceIocompletion);
        CHECK(rsp != nullptr);
        if (rsp != nullptr) {
            CHECK_EQ(U32At(*rsp, 20),
                     static_cast<uint32_t>(proto::kStatusSuccess));
            CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(4));
            CHECK(std::vector<uint8_t>(rsp->begin() + 28, rsp->end()) ==
                  fs.read_data);
        }
    }

    const std::vector<uint8_t> payload = {1, 2, 3};
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             WriteBody(kDeviceId, 0x100, 12, 8, payload));
    CHECK_EQ(fs.write_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_write_id, static_cast<uint32_t>(0x100));
    CHECK_EQ(fs.last_write_offset, static_cast<uint64_t>(8));
    CHECK(fs.last_write_data == payload);
    CHECK_EQ(client.write_count(), static_cast<unsigned>(1));

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(kDeviceId, 0x100, 13, proto::kIrpMjClose, 0));
    CHECK_EQ(fs.close_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_close_id, static_cast<uint32_t>(0x100));
    CHECK_EQ(client.close_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_client_query_directory_returns_entry) {
    MockFs fs;
    fs.query_data = {0xAA, 0xBB};
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             QueryDirBody(kDeviceId, 0x100, 14, 0x0C, true, "*.txt"));

    CHECK_EQ(fs.query_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_query_id, static_cast<uint32_t>(0x100));
    CHECK_EQ(fs.last_query_initial, true);
    CHECK_EQ(fs.last_query_class, static_cast<uint32_t>(0x0C));
    CHECK_EQ(client.query_directory_count(), static_cast<unsigned>(1));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusSuccess));
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(2));
        CHECK(std::vector<uint8_t>(rsp->begin() + 28, rsp->end()) ==
              fs.query_data);
    }
}

RTSC_TEST(rdpdr_client_control_is_unsuccessful) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ControlBody(kDeviceId, 0x100, 15, 0x1234, {9, 9}));

    CHECK_EQ(client.control_count(), static_cast<unsigned>(1));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusUnsuccessful));
    }
}

// ---- HostFileSystem bridge -------------------------------------------------

RTSC_TEST(rdpdr_filesystem_open_read_write_close) {
    const std::filesystem::path dir = MakeTempDir("basic");
    const std::filesystem::path file = dir / "hello.txt";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("hello world", 11);
    }

    HostFileSystem fs;
    uint32_t id = 0;
    CHECK(fs.Open(file.string(), false, false, id));
    CHECK(id != 0);

    std::vector<uint8_t> data;
    CHECK(fs.Read(id, 0, 5, data));
    CHECK(data == std::vector<uint8_t>({'h', 'e', 'l', 'l', 'o'}));
    CHECK(fs.Read(id, 6, 5, data));
    CHECK(data == std::vector<uint8_t>({'w', 'o', 'r', 'l', 'd'}));

    CHECK(fs.Close(id));
    CHECK(!fs.Read(id, 0, 5, data));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_filesystem_write_and_append) {
    const std::filesystem::path dir = MakeTempDir("write");
    const std::filesystem::path file = dir / "out.bin";

    HostFileSystem fs;
    uint32_t id = 0;
    CHECK(fs.Open(file.string(), true, true, id));

    const std::vector<uint8_t> a = {1, 2, 3, 4};
    uint32_t written = 0;
    CHECK(fs.Write(id, 0, a, written));
    CHECK_EQ(written, static_cast<uint32_t>(4));

    const std::vector<uint8_t> b = {5, 6};
    CHECK(fs.Write(id, 0xFFFFFFFFFFFFFFFFULL, b, written));
    CHECK_EQ(written, static_cast<uint32_t>(2));
    CHECK(fs.Close(id));

    CHECK(ReadWholeFile(file) ==
          std::vector<uint8_t>({1, 2, 3, 4, 5, 6}));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_filesystem_query_directory_names) {
    const std::filesystem::path dir = MakeTempDir("qdir");
    {
        std::ofstream out(dir / "a.txt", std::ios::binary);
        out.put('a');
    }
    {
        std::ofstream out(dir / "b.txt", std::ios::binary);
        out.put('b');
    }

    HostFileSystem fs;
    uint32_t id = 0;
    CHECK(fs.Open(dir.string(), false, false, id));

    std::vector<uint8_t> out;
    CHECK(fs.QueryDirectory(id, true, 0x0C, out));
    CHECK_EQ(U32At(out, 8), static_cast<uint32_t>(2 * 5));  // "a.txt"
    CHECK(fs.QueryDirectory(id, false, 0x0C, out));
    CHECK_EQ(U32At(out, 8), static_cast<uint32_t>(2 * 5));  // "b.txt"
    CHECK(!fs.QueryDirectory(id, false, 0x0C, out));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_filesystem_query_directory_full_info) {
    const std::filesystem::path dir = MakeTempDir("qfull");
    {
        std::ofstream out(dir / "c.txt", std::ios::binary);
        out.put('c');
    }

    HostFileSystem fs;
    uint32_t id = 0;
    CHECK(fs.Open(dir.string(), false, false, id));

    std::vector<uint8_t> out;
    CHECK(fs.QueryDirectory(id, true, 0x01, out));
    CHECK_EQ(U32At(out, 56), static_cast<uint32_t>(0x20));  // FileAttributes
    CHECK_EQ(U32At(out, 60), static_cast<uint32_t>(2 * 5));  // FileNameLength
    CHECK_EQ(out.size(), static_cast<size_t>(64 + 2 * 5));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_filesystem_stat) {
    const std::filesystem::path dir = MakeTempDir("stat");
    const std::filesystem::path file = dir / "s.txt";
    {
        std::ofstream out(file, std::ios::binary);
        out.put('x');
    }

    HostFileSystem fs;
    bool is_directory = false;
    CHECK(fs.Stat(file.string(), is_directory));
    CHECK(!is_directory);
    CHECK(fs.Stat(dir.string(), is_directory));
    CHECK(is_directory);
    CHECK(!fs.Stat((dir / "missing").string(), is_directory));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

}  // namespace
