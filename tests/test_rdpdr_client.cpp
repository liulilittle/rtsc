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
                                uint32_t disposition, const std::string& path,
                                uint32_t desired_access = 0xC0000000u) {
    proto::ByteWriter w;
    const std::vector<uint8_t> req =
        IoRequestBody(device_id, 0, completion_id, proto::kIrpMjCreate, 0);
    w.bytes(req.data(), req.size());
    w.u32le(desired_access);  // GENERIC_READ | GENERIC_WRITE by default
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
              bool truncate, uint32_t& file_id) override {
        ++open_calls;
        last_open_path = local_path;
        last_for_write = for_write;
        last_create = create;
        last_truncate = truncate;
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
    bool last_truncate = false;
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

// Regression guard for DR_CORE_SERVER_CLIENTID_CONFIRM ([MS-RDPEFS] 2.2.2.6): a
// server that sends the historical 8-byte form (version fields omitted) is
// rejected by the length check and the state machine must not advance; the
// spec 12-byte form still completes the handshake.
RTSC_TEST(rdpdr_client_rejects_old_8_byte_clientid_confirm) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    CHECK(client.phase() == RdpdrClient::Phase::kAwaitClientIdConfirm);

    // Header(4) + ClientId(4): the off-spec 8-byte confirm.
    const std::vector<uint8_t> old_form = {
        0x72, 0x44, 0x43, 0x43,  // RDPDR_HEADER: component "rD", PAKID 0x4343
        0x07, 0x00, 0x00, 0x00};  // client id only, no version pair
    FeedMessage(client, old_form);
    CHECK(client.phase() == RdpdrClient::Phase::kAwaitClientIdConfirm);
    CHECK_EQ(client.client_capability_count(), static_cast<unsigned>(0));
    CHECK_EQ(client.device_list_announce_count(), static_cast<unsigned>(0));

    // The spec form still works afterwards.
    proto::RdpdrServerClientIdConfirm good;
    good.version_major = 1;
    good.version_minor = 0x000C;
    good.client_id = 1;
    FeedMessage(client, good.encode());
    CHECK(client.phase() == RdpdrClient::Phase::kReady);
    CHECK_EQ(client.client_capability_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.device_list_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.client_id(), static_cast<uint32_t>(1));
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
    // kFileOpenIf needs write access and creates the file when it is missing
    // ([MS-SMB2] 2.2.13), but must not truncate an existing one.
    CHECK_EQ(fs.last_for_write, true);
    CHECK_EQ(fs.last_create, true);
    CHECK_EQ(fs.last_truncate, false);
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
             CreateBody(kDeviceId, 10, 0x00000001 /* FILE_OPEN */,
                        "\\tsclient\\C\\data.bin"));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ReadBody(kDeviceId, file_id, 11, 4, 64));
    CHECK_EQ(fs.read_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_read_id, file_id);
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
             WriteBody(kDeviceId, file_id, 12, 8, payload));
    CHECK_EQ(fs.write_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_write_id, file_id);
    CHECK_EQ(fs.last_write_offset, static_cast<uint64_t>(8));
    CHECK(fs.last_write_data == payload);
    CHECK_EQ(client.write_count(), static_cast<unsigned>(1));

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(kDeviceId, file_id, 13, proto::kIrpMjClose, 0));
    CHECK_EQ(fs.close_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_close_id, file_id);
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

    // F5: a directory query is only served against a live handle, so open one
    // first (the old test used the never-opened handle 0x100).
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 13, 0x00000001 /* FILE_OPEN */,
                        "\\tsclient\\C\\dir"));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    uint32_t file_id = 0;
    CHECK(crsp != nullptr);
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             QueryDirBody(kDeviceId, file_id, 14, 0x0C, true, "*.txt"));

    CHECK_EQ(fs.query_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_query_id, file_id);
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

// ---- path containment (S3-7) ----------------------------------------------

void MakeReady(RdpdrClient& client) {
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
}

RTSC_TEST(rdpdr_path_rejects_parent_traversal_forms) {
    const std::string root = "C:\\share";
    const char* forms[] = {
        "..\\..\\Windows\\evil.dll",
        "..\\evil.dll",
        "sub\\..\\..\\evil.dll",
        "../x",
        "/../../x",
        "sub/../../x",
        "....\\evil.dll",
        "...\\evil.dll",
        ".. \\evil.dll",
        "..\\..\\windows\\EVIL.DLL",
        "sub\\..\\CON",
    };
    for (const char* form : forms) {
        std::string out;
        const bool ok = rtsc::channel::ResolvePathUnderRoot(root, form, out);
        if (ok) {
            std::printf("  accepted traversal form: %s -> %s\n", form,
                        out.c_str());
        }
        CHECK(!ok);
    }
}

RTSC_TEST(rdpdr_path_rejects_absolute_drive_unc_and_device_forms) {
    const std::string root = "C:\\share";
    const char* forms[] = {
        "C:\\Windows\\evil.dll",
        "c:/windows/evil.dll",
        "D:evil.dll",
        "\\\\server\\share\\evil.dll",
        "\\\\.\\PhysicalDrive0",
        "\\\\?\\C:\\Windows\\evil.dll",
        "CON",
        "con.txt",
        "NUL",
        "aux.log",
        "COM1",
        "lpt9",
        "CONIN$",
        "evil.dll:stream",
        "evil.txt ",
        "evil.txt.",
        "a<b",
        "a|b",
        "a*b",
        "a?b",
    };
    for (const char* form : forms) {
        std::string out;
        const bool ok = rtsc::channel::ResolvePathUnderRoot(root, form, out);
        if (ok) {
            std::printf("  accepted absolute/device form: %s -> %s\n", form,
                        out.c_str());
        }
        CHECK(!ok);
    }
}

RTSC_TEST(rdpdr_path_accepts_legal_paths_under_root) {
    const std::string root = "C:\\share";
    std::string out;

    CHECK(rtsc::channel::ResolvePathUnderRoot(root, "\\dir\\file.txt", out));
    CHECK(out == "C:\\share\\dir\\file.txt");

    CHECK(rtsc::channel::ResolvePathUnderRoot(root, "/dir/sub/file.txt", out));
    CHECK(out == "C:\\share\\dir\\sub\\file.txt");

    CHECK(rtsc::channel::ResolvePathUnderRoot(root, "PROGRA~1\\app.dll", out));
    CHECK(out == "C:\\share\\PROGRA~1\\app.dll");

    CHECK(rtsc::channel::ResolvePathUnderRoot(root, "Dir\\.\\File.TXT", out));
    CHECK(out == "C:\\share\\Dir\\File.TXT");

    CHECK(rtsc::channel::ResolvePathUnderRoot("C:\\", "Windows\\x.dll", out));
    CHECK(out == "C:\\Windows\\x.dll");
}

RTSC_TEST(rdpdr_client_create_rejects_traversal_path) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\share"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 9, 0x00000002,
                        "\\tsclient\\C\\..\\..\\Windows\\evil.dll"));

    CHECK_EQ(fs.open_calls, static_cast<unsigned>(0));
    CHECK(client.last_local_path().empty());
    CHECK(client.last_remote_path() ==
          "\\tsclient\\C\\..\\..\\Windows\\evil.dll");
    CHECK_EQ(client.create_count(), static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusAccessDenied));
    }
}

RTSC_TEST(rdpdr_client_traversal_create_does_not_escape_root) {
    const std::filesystem::path dir = MakeTempDir("s3_7");
    const std::string escape_name = "rtsc_s3_7_escape.txt";
    const std::filesystem::path outside = dir.parent_path() / escape_name;
    std::error_code ec;
    std::filesystem::remove(outside, ec);

    HostFileSystem fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 9, 0x00000005,
                        "\\tsclient\\C\\..\\" + escape_name));

    CHECK(!std::filesystem::exists(outside));
    CHECK(client.last_local_path().empty());
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusAccessDenied));
    }

    std::filesystem::remove(outside, ec);
    std::filesystem::remove_all(dir, ec);
}

// ---- read size limiting (S3-8) --------------------------------------------

RTSC_TEST(rdpdr_client_read_rejects_oversized_length) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    // F5: the length gate is on the read path after the file_id check, so the
    // probe needs a live handle (0x100 was never opened).
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 10, 0x00000001 /* FILE_OPEN */,
                        "\\tsclient\\C\\big.bin"));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    uint32_t file_id = 0;
    CHECK(crsp != nullptr);
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ReadBody(kDeviceId, file_id, 11, 0xFFFFFFFFu, 0));

    CHECK_EQ(fs.read_calls, static_cast<unsigned>(0));
    CHECK_EQ(client.read_count(), static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusInvalidParameter));
    }
}

RTSC_TEST(rdpdr_filesystem_read_rejects_oversized_length) {
    const std::filesystem::path dir = MakeTempDir("readcap");
    const std::filesystem::path file = dir / "big.txt";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("hello", 5);
    }

    HostFileSystem fs;
    uint32_t id = 0;
    CHECK(fs.Open(file.string(), false, false, false, id));

    const uint32_t probes[] = {64u * 1024u * 1024u, 0xFFFFFFFFu};
    for (const uint32_t length : probes) {
        std::vector<uint8_t> data(1, 0xAA);
        bool threw = false;
        bool ok = false;
        try {
            ok = fs.Read(id, 0, length, data);
        } catch (...) {
            threw = true;
        }
        if (ok) std::printf("  accepted read length %u\n", length);
        CHECK(!threw);
        CHECK(!ok);
        CHECK(data.empty());
    }

    std::vector<uint8_t> data;
    CHECK(fs.Read(id, 0, 5, data));
    CHECK(data == std::vector<uint8_t>({'h', 'e', 'l', 'l', 'o'}));

    fs.Close(id);
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// ---- overwrite truncation (S3-9) ------------------------------------------

RTSC_TEST(rdpdr_filesystem_overwrite_truncates_existing) {
    const std::filesystem::path dir = MakeTempDir("s3_9fs");
    const std::filesystem::path file = dir / "old.bin";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("OLDDATA", 7);
    }

    HostFileSystem fs;
    uint32_t id = 0;
    CHECK(fs.Open(file.string(), true, false, true, id));
    const std::vector<uint8_t> fresh = {'N', 'E', 'W'};
    uint32_t written = 0;
    CHECK(fs.Write(id, 0, fresh, written));
    CHECK_EQ(written, static_cast<uint32_t>(3));
    CHECK(fs.Close(id));

    const std::vector<uint8_t> got = ReadWholeFile(file);
    if (got != fresh) {
        std::printf("  overwrite left %zu bytes: %.*s\n", got.size(),
                    static_cast<int>(got.size()),
                    reinterpret_cast<const char*>(got.data()));
    }
    CHECK(got == fresh);

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_client_overwrite_dispositions_truncate_existing_file) {
    const uint32_t dispositions[] = {0x00000000u, 0x00000004u, 0x00000005u};
    for (const uint32_t disposition : dispositions) {
        const std::filesystem::path dir = MakeTempDir("s3_9");
        const std::filesystem::path file = dir / "data.bin";
        {
            std::ofstream out(file, std::ios::binary);
            out.write("OLDDATA", 7);
        }

        HostFileSystem fs;
        std::vector<std::vector<uint8_t>> sent;
        RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                          [&](const std::vector<uint8_t>& m) {
                              sent.push_back(m);
                          });
        MakeReady(client);

        FeedBody(client, proto::kPakidCoreDeviceIorequest,
                 CreateBody(kDeviceId, 21, disposition,
                            "\\tsclient\\C\\data.bin"));
        const std::vector<uint8_t>* rsp =
            FindSent(sent, proto::kPakidCoreDeviceIocompletion);
        uint32_t file_id = 0;
        CHECK(rsp != nullptr);
        if (rsp != nullptr) {
            CHECK_EQ(U32At(*rsp, 20),
                     static_cast<uint32_t>(proto::kStatusSuccess));
            file_id = U32At(*rsp, 24);
        }
        CHECK(file_id != 0);

        if (file_id != 0) {
            const std::vector<uint8_t> fresh = {'N', 'E', 'W'};
            FeedBody(client, proto::kPakidCoreDeviceIorequest,
                     WriteBody(kDeviceId, file_id, 22, 0, fresh));
            FeedBody(client, proto::kPakidCoreDeviceIorequest,
                     IoRequestBody(kDeviceId, file_id, 23, proto::kIrpMjClose,
                                   0));
            const std::vector<uint8_t> got = ReadWholeFile(file);
            if (got != fresh) {
                std::printf("  disposition 0x%02X left %zu bytes: %.*s\n",
                            disposition, got.size(),
                            static_cast<int>(got.size()),
                            reinterpret_cast<const char*>(got.data()));
            }
            CHECK(got == fresh);
        }

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
}

RTSC_TEST(rdpdr_client_openif_does_not_truncate_existing_file) {
    const std::filesystem::path dir = MakeTempDir("s3_9open");
    const std::filesystem::path file = dir / "data.bin";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("OLDDATA", 7);
    }

    HostFileSystem fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 21, 0x00000003, "\\tsclient\\C\\data.bin"));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    uint32_t file_id = 0;
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusSuccess));
        file_id = U32At(*rsp, 24);
    }
    CHECK(file_id != 0);
    if (file_id != 0) {
        const std::vector<uint8_t> tail = {'N', 'E', 'W'};
        FeedBody(client, proto::kPakidCoreDeviceIorequest,
                 WriteBody(kDeviceId, file_id, 22, 7, tail));
        FeedBody(client, proto::kPakidCoreDeviceIorequest,
                 IoRequestBody(kDeviceId, file_id, 23, proto::kIrpMjClose, 0));
    }
    CHECK(ReadWholeFile(file) ==
          std::vector<uint8_t>({'O', 'L', 'D', 'D', 'A', 'T', 'A', 'N', 'E',
                                'W'}));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// ---- DesiredAccess semantics (S3-7') --------------------------------------

RTSC_TEST(rdpdr_client_create_read_access_opens_read_only) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 9, 0x00000001, "\\tsclient\\C\\ro.txt",
                        0x80000000u /* GENERIC_READ */));

    CHECK_EQ(fs.open_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_for_write, false);
    CHECK_EQ(client.create_count(), static_cast<unsigned>(1));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusSuccess));
    }
}

RTSC_TEST(rdpdr_client_create_write_access_opens_for_write) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 9, 0x00000001, "\\tsclient\\C\\rw.txt",
                        0x40000000u /* GENERIC_WRITE */));

    CHECK_EQ(fs.open_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_for_write, true);
    CHECK_EQ(client.create_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_client_create_openif_read_access_is_not_over_authorised) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 9, 0x00000003, "\\tsclient\\C\\ro2.txt",
                        0x00120089u /* FILE_READ_DATA|READ_ATTRIBUTES */));

    CHECK_EQ(fs.open_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_for_write, false);
    CHECK_EQ(client.create_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_client_write_to_read_only_handle_is_denied) {
    const std::filesystem::path dir = MakeTempDir("s3_7p_ro");
    const std::filesystem::path file = dir / "data.bin";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("OLDDATA", 7);
    }

    HostFileSystem fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 21, 0x00000001, "\\tsclient\\C\\data.bin",
                        0x80000000u /* GENERIC_READ */));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    uint32_t file_id = 0;
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusSuccess));
        file_id = U32At(*rsp, 24);
    }
    CHECK(file_id != 0);
    if (file_id != 0) {
        sent.clear();
        const std::vector<uint8_t> fresh = {'N', 'E', 'W'};
        FeedBody(client, proto::kPakidCoreDeviceIorequest,
                 WriteBody(kDeviceId, file_id, 22, 0, fresh));
        const std::vector<uint8_t>* wrsp =
            FindSent(sent, proto::kPakidCoreDeviceIocompletion);
        CHECK(wrsp != nullptr);
        if (wrsp != nullptr) {
            if (U32At(*wrsp, 20) ==
                static_cast<uint32_t>(proto::kStatusSuccess)) {
                std::printf("  read-only handle accepted a write\n");
            }
            CHECK(U32At(*wrsp, 20) !=
                  static_cast<uint32_t>(proto::kStatusSuccess));
        }
        FeedBody(client, proto::kPakidCoreDeviceIorequest,
                 IoRequestBody(kDeviceId, file_id, 23, proto::kIrpMjClose, 0));
    }
    CHECK(ReadWholeFile(file) ==
          std::vector<uint8_t>({'O', 'L', 'D', 'D', 'A', 'T', 'A'}));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_client_create_write_on_read_only_file_fails) {
    const std::filesystem::path dir = MakeTempDir("s3_7p_attr");
    const std::filesystem::path file = dir / "locked.bin";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("OLDDATA", 7);
    }
    std::error_code ec;
    std::filesystem::permissions(file, std::filesystem::perms::owner_read,
                                 std::filesystem::perm_options::replace, ec);

    HostFileSystem fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 21, 0x00000001, "\\tsclient\\C\\locked.bin",
                        0x40000000u /* GENERIC_WRITE */));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        if (U32At(*rsp, 20) == static_cast<uint32_t>(proto::kStatusSuccess)) {
            std::printf("  write open of a read-only file succeeded\n");
        }
        CHECK(U32At(*rsp, 20) != static_cast<uint32_t>(proto::kStatusSuccess));
    }
    CHECK_EQ(client.create_count(), static_cast<unsigned>(0));

    std::filesystem::permissions(file, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_client_create_existing_file_fails_without_truncating) {
    const std::filesystem::path dir = MakeTempDir("s3_create_exists");
    const std::filesystem::path file = dir / "exists.txt";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("OLDDATA", 7);
    }

    HostFileSystem fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 21, 0x00000002 /* FILE_CREATE */,
                        "\\tsclient\\C\\exists.txt"));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        if (U32At(*rsp, 20) == static_cast<uint32_t>(proto::kStatusSuccess)) {
            std::printf("  FILE_CREATE on an existing file succeeded\n");
        }
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000035));
    }
    CHECK_EQ(client.create_count(), static_cast<unsigned>(0));
    CHECK(ReadWholeFile(file) ==
          std::vector<uint8_t>({'O', 'L', 'D', 'D', 'A', 'T', 'A'}));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_path_accepts_drive_root) {
    std::string out;
    CHECK(rtsc::channel::ResolvePathUnderRoot("C:\\share", "", out));
    CHECK(out == "C:\\share");
    CHECK(rtsc::channel::ResolvePathUnderRoot("C:\\share", "\\", out));
    CHECK(out == "C:\\share");
    CHECK(rtsc::channel::ResolvePathUnderRoot("C:\\share\\", "", out));
    CHECK(out == "C:\\share");
}

RTSC_TEST(rdpdr_client_create_maximum_allowed_is_write) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 9, 0x00000003, "\\tsclient\\C\\max.txt",
                        0x02000000u /* MAXIMUM_ALLOWED */));
    CHECK_EQ(fs.last_for_write, true);

    const std::filesystem::path dir = MakeTempDir("s3_7p_max");
    const std::filesystem::path file = dir / "m.bin";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("OLDDATA", 7);
    }

    HostFileSystem hfs;
    std::vector<std::vector<uint8_t>> hsent;
    RdpdrClient hclient(&hfs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           hsent.push_back(m);
                       });
    MakeReady(hclient);
    FeedBody(hclient, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 21, 0x00000003, "\\tsclient\\C\\m.bin",
                        0x02000000u));
    const std::vector<uint8_t>* rsp =
        FindSent(hsent, proto::kPakidCoreDeviceIocompletion);
    uint32_t file_id = 0;
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusSuccess));
        file_id = U32At(*rsp, 24);
    }
    CHECK(file_id != 0);
    if (file_id != 0) {
        const std::vector<uint8_t> fresh = {'N', 'E', 'W'};
        FeedBody(hclient, proto::kPakidCoreDeviceIorequest,
                 WriteBody(kDeviceId, file_id, 22, 0, fresh));
        FeedBody(hclient, proto::kPakidCoreDeviceIorequest,
                 IoRequestBody(kDeviceId, file_id, 23, proto::kIrpMjClose, 0));
    }
    CHECK(ReadWholeFile(file) ==
          std::vector<uint8_t>({'N', 'E', 'W', 'D', 'A', 'T', 'A'}));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_client_create_delete_only_is_not_data_write) {
    const std::filesystem::path dir = MakeTempDir("s3_7p_del");
    const std::filesystem::path file = dir / "d.bin";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("OLDDATA", 7);
    }
    std::error_code ec;
    std::filesystem::permissions(file, std::filesystem::perms::owner_read,
                                 std::filesystem::perm_options::replace, ec);

    HostFileSystem fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 21, 0x00000001, "\\tsclient\\C\\d.bin",
                        0x00010000u /* DELETE */));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    uint32_t file_id = 0;
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        if (U32At(*rsp, 20) != static_cast<uint32_t>(proto::kStatusSuccess)) {
            std::printf("  DELETE-only open of a read-only file was denied\n");
        }
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusSuccess));
        file_id = U32At(*rsp, 24);
    }
    CHECK(file_id != 0);
    if (file_id != 0) {
        sent.clear();
        const std::vector<uint8_t> fresh = {'N', 'E', 'W'};
        FeedBody(client, proto::kPakidCoreDeviceIorequest,
                 WriteBody(kDeviceId, file_id, 22, 0, fresh));
        const std::vector<uint8_t>* wrsp =
            FindSent(sent, proto::kPakidCoreDeviceIocompletion);
        CHECK(wrsp != nullptr);
        if (wrsp != nullptr) {
            CHECK(U32At(*wrsp, 20) !=
                  static_cast<uint32_t>(proto::kStatusSuccess));
        }
        FeedBody(client, proto::kPakidCoreDeviceIorequest,
                 IoRequestBody(kDeviceId, file_id, 23, proto::kIrpMjClose, 0));
    }
    CHECK(ReadWholeFile(file) ==
          std::vector<uint8_t>({'O', 'L', 'D', 'D', 'A', 'T', 'A'}));

    std::filesystem::permissions(file, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_client_open_and_overwrite_missing_file_fail) {
    const std::filesystem::path dir = MakeTempDir("s3_missing");
    const uint32_t dispositions[] = {0x00000001u /* FILE_OPEN */,
                                    0x00000004u /* FILE_OVERWRITE */};
    for (const uint32_t disposition : dispositions) {
        HostFileSystem fs;
        std::vector<std::vector<uint8_t>> sent;
        RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                          [&](const std::vector<uint8_t>& m) {
                              sent.push_back(m);
                          });
        MakeReady(client);

        FeedBody(client, proto::kPakidCoreDeviceIorequest,
                 CreateBody(kDeviceId, 21, disposition,
                            "\\tsclient\\C\\missing.txt"));
        const std::vector<uint8_t>* rsp =
            FindSent(sent, proto::kPakidCoreDeviceIocompletion);
        CHECK(rsp != nullptr);
        if (rsp != nullptr) {
            if (U32At(*rsp, 20) ==
                static_cast<uint32_t>(proto::kStatusSuccess)) {
                std::printf("  disposition 0x%02X created a missing file\n",
                            disposition);
            }
            CHECK(U32At(*rsp, 20) !=
                  static_cast<uint32_t>(proto::kStatusSuccess));
        }
        CHECK(!std::filesystem::exists(dir / "missing.txt"));
    }
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// ---- truncate independent of access mode (R2) -----------------------------

RTSC_TEST(rdpdr_filesystem_truncate_applies_without_write_access) {
    const std::filesystem::path dir = MakeTempDir("r2_fs");
    const std::filesystem::path file = dir / "keep.bin";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("OLDDATA", 7);
    }

    HostFileSystem fs;
    uint32_t id = 0;
    CHECK(fs.Open(file.string(), false, true, true, id));
    std::vector<uint8_t> data;
    CHECK(fs.Read(id, 0, 64, data));
    if (!data.empty()) {
        std::printf("  read-only overwrite left %zu bytes\n", data.size());
    }
    CHECK(data.empty());

    uint32_t written = 0;
    CHECK(!fs.Write(id, 0, {'X'}, written));
    fs.Close(id);

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_client_read_only_overwrite_truncates_file) {
    const std::filesystem::path dir = MakeTempDir("r2_ch");
    const std::filesystem::path file = dir / "data.bin";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("OLDDATA", 7);
    }

    HostFileSystem fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 31, 0x00000004 /* FILE_OVERWRITE */,
                        "\\tsclient\\C\\data.bin", 0x80000000u /* READ */));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusSuccess));
    }
    CHECK(ReadWholeFile(file).empty());

    const std::filesystem::path kept = dir / "kept.bin";
    {
        std::ofstream out(kept, std::ios::binary);
        out.write("OLDDATA", 7);
    }
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 32, 0x00000001 /* FILE_OPEN */,
                        "\\tsclient\\C\\kept.bin", 0x80000000u /* READ */));
    CHECK(ReadWholeFile(kept).size() == static_cast<size_t>(7));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// ---- status codes for missing paths / unknown handles (R1, R4) ------------

RTSC_TEST(rdpdr_client_open_missing_file_reports_name_not_found) {
    const std::filesystem::path dir = MakeTempDir("r1_missing");
    HostFileSystem fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 41, 0x00000001 /* FILE_OPEN */,
                        "\\tsclient\\C\\nope.txt"));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        if (U32At(*rsp, 20) != 0xC0000034u) {
            std::printf("  OPEN missing file returned 0x%08X\n",
                        U32At(*rsp, 20));
        }
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000034));
    }
    CHECK_EQ(client.create_count(), static_cast<unsigned>(0));
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_client_write_open_denied_stays_access_denied) {
    const std::filesystem::path dir = MakeTempDir("r1_denied");
    const std::filesystem::path file = dir / "locked.bin";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("OLDDATA", 7);
    }
    std::error_code ec;
    std::filesystem::permissions(file, std::filesystem::perms::owner_read,
                                 std::filesystem::perm_options::replace, ec);

    HostFileSystem fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 42, 0x00000001, "\\tsclient\\C\\locked.bin",
                        0x40000000u /* GENERIC_WRITE */));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000022));
    }

    std::filesystem::permissions(file, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_client_unknown_handle_is_invalid_handle) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(kDeviceId, 9999, 51, proto::kIrpMjClose, 0));
    CHECK_EQ(fs.close_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
        CHECK_EQ(U32At(*rsp, 16), static_cast<uint32_t>(51));
    }

    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             WriteBody(kDeviceId, 8888, 52, 0, {1, 2, 3}));
    CHECK_EQ(fs.write_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* wrsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(wrsp != nullptr);
    if (wrsp != nullptr) {
        CHECK_EQ(U32At(*wrsp, 20), static_cast<uint32_t>(0xC0000008));
    }
}

// ---- batch safety fixes (F3, F5, F6) --------------------------------------

// F3: an I/O request received before the handshake reached kReady must be
// answered with STATUS_UNSUCCESSFUL and never touch the file system.
RTSC_TEST(rdpdr_client_io_request_before_ready_is_unsuccessful) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    CHECK(client.phase() != RdpdrClient::Phase::kReady);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 9, 0x00000001 /* FILE_OPEN */,
                        "\\tsclient\\C\\x.txt"));
    CHECK_EQ(fs.open_calls, static_cast<unsigned>(0));
    CHECK_EQ(client.create_count(), static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusUnsuccessful));
    }
}

// F5: reading or querying a file id that was never handed out answers
// STATUS_INVALID_HANDLE instead of running an unvalidated operation.
RTSC_TEST(rdpdr_client_read_unknown_handle_is_invalid_handle) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ReadBody(kDeviceId, 0x100, 11, 4, 0));
    CHECK_EQ(fs.read_calls, static_cast<unsigned>(0));
    CHECK_EQ(client.read_count(), static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
    }
}

RTSC_TEST(rdpdr_client_query_directory_unknown_handle_is_invalid_handle) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             QueryDirBody(kDeviceId, 0x100, 14, 0x0C, true, "*.txt"));
    CHECK_EQ(fs.query_calls, static_cast<unsigned>(0));
    CHECK_EQ(client.query_directory_count(), static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
    }
}

// F6: a write larger than the symmetric 1 MiB read cap is rejected with
// STATUS_INVALID_PARAMETER and never reaches the file system.
RTSC_TEST(rdpdr_client_write_rejects_oversized_payload) {
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                      [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 20, 0x00000001 /* FILE_OPEN */,
                        "\\tsclient\\C\\big.bin"));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    uint32_t file_id = 0;
    CHECK(crsp != nullptr);
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    const std::vector<uint8_t> big(rtsc::rdpdr::kMaxReadLength + 1, 0xAA);
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             WriteBody(kDeviceId, file_id, 21, 0, big));
    CHECK_EQ(fs.write_calls, static_cast<unsigned>(0));
    CHECK_EQ(client.write_count(), static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusInvalidParameter));
    }
}

// F2: enumerate a directory that contains a dangling symlink: the failing
// stat calls are skipped, the loop completes, and the surviving entry is still
// returned.
RTSC_TEST(rdpdr_filesystem_query_directory_dangling_symlink_skipped) {
    const std::filesystem::path dir = MakeTempDir("f2_dangling");
    {
        std::ofstream out(dir / "a.txt", std::ios::binary);
        out.put('a');
    }
    std::error_code ec;
    const std::filesystem::path link = dir / "dangling";
    std::filesystem::create_symlink(dir / "missing_target.bin", link, ec);
    if (ec) {
        std::printf("  SKIP: cannot create symlink (%d: %s)\n", ec.value(),
                    ec.message().c_str());
        CHECK(true);
    } else {
        HostFileSystem fs;
        uint32_t id = 0;
        CHECK(fs.Open(dir.string(), false, false, false, id));

        unsigned entries = 0;
        bool threw = false;
        std::vector<uint8_t> out_data;
        try {
            while (fs.QueryDirectory(id, entries == 0, 0x0C, out_data)) {
                ++entries;
            }
        } catch (...) {
            threw = true;
        }
        if (threw) std::printf("  dangling symlink enumeration threw\n");
        CHECK(!threw);
        if (!threw) {
            if (entries != 1u) {
                std::printf("  entries=%u (want 1: 'a.txt' only)\n", entries);
            }
            CHECK_EQ(entries, static_cast<unsigned>(1));
        }
        fs.Close(id);
    }
    std::filesystem::remove_all(dir, ec);
}

// ---- reparse point escape (R3) --------------------------------------------

RTSC_TEST(rdpdr_path_rejects_symlink_escape) {
    const std::filesystem::path dir = MakeTempDir("r3_root");
    const std::filesystem::path outside = MakeTempDir("r3_outside");
    {
        std::ofstream out(outside / "secret.txt", std::ios::binary);
        out.write("SECRET", 6);
    }

    std::error_code ec;
    const std::filesystem::path link = dir / "link";
    std::filesystem::create_directory_symlink(outside, link, ec);
    if (ec) {
        std::printf("  SKIP: cannot create symlink (%d: %s)\n", ec.value(),
                    ec.message().c_str());
        CHECK(true);
    } else {
        std::string out;
        const bool ok = rtsc::channel::ResolvePathUnderRoot(
            dir.string(), "link\\secret.txt", out);
        if (ok) std::printf("  symlink escape accepted -> %s\n", out.c_str());
        CHECK(!ok);
    }

    std::filesystem::remove_all(dir, ec);
    std::filesystem::remove_all(outside, ec);
}

RTSC_TEST(rdpdr_client_symlink_escape_create_is_denied) {
    const std::filesystem::path dir = MakeTempDir("r3_ch");
    const std::filesystem::path outside = MakeTempDir("r3_ch_out");
    std::error_code ec;
    const std::filesystem::path link = dir / "link";
    std::filesystem::create_directory_symlink(outside, link, ec);
    if (ec) {
        std::printf("  SKIP: cannot create symlink (%d: %s)\n", ec.value(),
                    ec.message().c_str());
        CHECK(true);
    } else {
        HostFileSystem fs;
        std::vector<std::vector<uint8_t>> sent;
        RdpdrClient client(&fs, {{kDeviceId, "C:", dir.string()}}, "HOST",
                          [&](const std::vector<uint8_t>& m) {
                              sent.push_back(m);
                          });
        MakeReady(client);

        FeedBody(client, proto::kPakidCoreDeviceIorequest,
                 CreateBody(kDeviceId, 61, 0x00000005,
                            "\\tsclient\\C\\link\\escaped.txt"));
        const std::vector<uint8_t>* rsp =
            FindSent(sent, proto::kPakidCoreDeviceIocompletion);
        CHECK(rsp != nullptr);
        if (rsp != nullptr) {
            CHECK(U32At(*rsp, 20) !=
                  static_cast<uint32_t>(proto::kStatusSuccess));
        }
        if (std::filesystem::exists(outside / "escaped.txt")) {
            std::printf("  file was created outside the shared root\n");
        }
        CHECK(!std::filesystem::exists(outside / "escaped.txt"));
        CHECK_EQ(client.create_count(), static_cast<unsigned>(0));
    }

    std::filesystem::remove_all(dir, ec);
    std::filesystem::remove_all(outside, ec);
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
    CHECK(fs.Open(file.string(), false, false, false, id));
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
    CHECK(fs.Open(file.string(), true, true, true, id));

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
    CHECK(fs.Open(dir.string(), false, false, false, id));

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
    CHECK(fs.Open(dir.string(), false, false, false, id));

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
