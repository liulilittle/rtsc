// rdpdr virtual channel handler tests ([MS-RDPEFS] 3.1).
//
// These exercise the client-side state machine (announce -> client name ->
// client id confirm -> capabilities/device list) and the drive redirection
// file I/O dispatch against a recording IFileSystem. The HostFileSystem bridge
// is exercised separately against a real temporary directory.

#include "rtsc/channel/rdpdr_client.h"
#include "rtsc/rdpdr/file_system.h"
#include "rtsc/rdpdr/path_guard.h"
#include "rtsc/rdpdr/printer_win32.h"
#include "rtsc/rdpdr/serial_win32.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
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

std::vector<uint8_t> NotifyChangeBody(uint32_t device_id, uint32_t file_id,
                                      uint32_t completion_id,
                                      uint32_t minor_function =
                                          proto::kIrpMnNotifyChangeDirectory) {
    proto::ByteWriter w;
    const std::vector<uint8_t> req = IoRequestBody(
        device_id, file_id, completion_id, proto::kIrpMjDirectoryControl,
        minor_function);
    w.bytes(req.data(), req.size());
    w.u8(1);              // WatchTree
    w.u32le(0x00000001);  // CompletionFilter (FILE_NAME)
    for (int i = 0; i < 27; ++i) w.u8(0);  // Padding
    return w.take();
}

std::vector<uint8_t> LockBody(
    uint32_t device_id, uint32_t file_id, uint32_t completion_id,
    uint32_t operation,
    const std::vector<std::pair<uint64_t, uint64_t>>& ranges) {
    proto::ByteWriter w;
    const std::vector<uint8_t> req = IoRequestBody(
        device_id, file_id, completion_id, proto::kIrpMjLockControl, 0);
    w.bytes(req.data(), req.size());
    w.u32le(operation);
    w.u32le(0);  // Flags
    w.u32le(static_cast<uint32_t>(ranges.size()));
    for (int i = 0; i < 20; ++i) w.u8(0);  // Padding2
    // RDP_LOCK_INFO is Length then Offset.
    for (const auto& range : ranges) {
        w.u32le(static_cast<uint32_t>(range.first & 0xFFFFFFFFu));
        w.u32le(static_cast<uint32_t>(range.first >> 32));
        w.u32le(static_cast<uint32_t>(range.second & 0xFFFFFFFFu));
        w.u32le(static_cast<uint32_t>(range.second >> 32));
    }
    return w.take();
}

std::vector<uint8_t> SetVolumeBody(uint32_t device_id, uint32_t file_id,
                                   uint32_t completion_id, uint32_t info_class,
                                   const std::u16string& label) {
    std::vector<uint8_t> buffer;
    const uint32_t label_bytes = static_cast<uint32_t>(label.size() * 2);
    buffer.push_back(static_cast<uint8_t>(label_bytes & 0xFF));
    buffer.push_back(static_cast<uint8_t>((label_bytes >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((label_bytes >> 16) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((label_bytes >> 24) & 0xFF));
    for (const char16_t c : label) {
        buffer.push_back(static_cast<uint8_t>(c & 0xFF));
        buffer.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
    }
    proto::ByteWriter w;
    const std::vector<uint8_t> req = IoRequestBody(
        device_id, file_id, completion_id, proto::kIrpMjSetVolumeInformation, 0);
    w.bytes(req.data(), req.size());
    w.u32le(info_class);
    w.u32le(static_cast<uint32_t>(buffer.size()));
    for (int i = 0; i < 24; ++i) w.u8(0);  // Padding
    w.bytes(buffer.data(), buffer.size());
    return w.take();
}

uint32_t CreateFileForTest(RdpdrClient& client,
                           std::vector<std::vector<uint8_t>>& sent,
                           const std::string& remote_path) {
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 10, 0x00000001 /* FILE_OPEN */,
                        remote_path));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    sent.clear();
    return file_id;
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

    bool QueryVolume(uint32_t file_id, uint32_t fs_information_class,
                     std::vector<uint8_t>& out) override {
        ++query_volume_calls;
        last_query_volume_id = file_id;
        last_query_volume_class = fs_information_class;
        out = query_volume_data;
        return query_volume_result;
    }

    bool Rename(const std::string& local_path, const std::string& new_path,
                bool replace) override {
        ++rename_calls;
        last_rename_from = local_path;
        last_rename_to = new_path;
        last_rename_replace = replace;
        return rename_result;
    }

    bool Delete(const std::string& local_path) override {
        ++delete_calls;
        last_delete_path = local_path;
        return delete_result;
    }

    bool QueryInformation(uint32_t file_id, uint32_t fs_information_class,
                          std::vector<uint8_t>& out) override {
        ++query_information_calls;
        last_query_information_id = file_id;
        last_query_information_class = fs_information_class;
        out = query_information_data;
        return query_information_result;
    }

    bool SetVolumeName(uint32_t file_id, const std::string& label) override {
        ++set_volume_label_calls;
        last_volume_label_id = file_id;
        last_volume_label = label;
        return set_volume_label_result;
    }

    unsigned open_calls = 0;
    unsigned read_calls = 0;
    unsigned write_calls = 0;
    unsigned close_calls = 0;
    unsigned query_calls = 0;
    unsigned query_volume_calls = 0;
    unsigned query_information_calls = 0;
    unsigned set_volume_label_calls = 0;
    unsigned rename_calls = 0;
    unsigned delete_calls = 0;
    unsigned stat_calls = 0;
    bool fail_open_once = false;
    bool read_result = true;
    bool write_result = true;
    bool close_result = true;
    bool query_result = true;
    bool query_volume_result = true;
    bool query_information_result = true;
    bool set_volume_label_result = true;
    bool rename_result = true;
    bool delete_result = true;
    bool stat_result = true;
    std::string last_open_path;
    std::string last_stat_path;
    std::string last_rename_from;
    std::string last_rename_to;
    std::string last_delete_path;
    bool last_rename_replace = false;
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
    uint32_t last_query_volume_id = 0;
    uint32_t last_query_volume_class = 0;
    uint32_t last_query_information_id = 0;
    uint32_t last_query_information_class = 0;
    uint32_t last_volume_label_id = 0;
    std::string last_volume_label;
    std::vector<uint8_t> query_volume_data;
    std::vector<uint8_t> query_information_data;
    bool last_query_initial = false;
    uint32_t last_query_class = 0;
    std::vector<uint8_t> read_data;
    std::vector<uint8_t> last_write_data;
    std::vector<uint8_t> query_data;

 private:
    uint32_t next_id_ = 1;
};

class FakeSerial final : public rtsc::rdpdr::ISerialBackend {
 public:
    uint32_t Open(const std::string& port) override {
        ++open_calls;
        last_open_port = port;
        if (fail_open) return 0;
        return next_handle_++;
    }
    bool Read(uint32_t handle, uint32_t length,
              std::vector<uint8_t>& out) override {
        ++read_calls;
        last_read_handle = handle;
        last_read_length = length;
        out = read_data;
        return read_result;
    }
    bool Write(uint32_t handle, const std::vector<uint8_t>& data,
               uint32_t& written) override {
        ++write_calls;
        last_write_handle = handle;
        last_write_data = data;
        written = static_cast<uint32_t>(data.size());
        return write_result;
    }
    bool Close(uint32_t handle) override {
        ++close_calls;
        last_close_handle = handle;
        return true;
    }
    bool Control(uint32_t handle, uint32_t ioctl,
                 const std::vector<uint8_t>& input,
                 std::vector<uint8_t>& output) override {
        ++control_calls;
        last_control_handle = handle;
        last_ioctl = ioctl;
        last_control_input = input;
        output = control_output;
        return control_result;
    }

    unsigned open_calls = 0;
    unsigned read_calls = 0;
    unsigned write_calls = 0;
    unsigned close_calls = 0;
    unsigned control_calls = 0;
    bool fail_open = false;
    bool read_result = true;
    bool write_result = true;
    bool control_result = true;
    std::string last_open_port;
    uint32_t last_read_handle = 0;
    uint32_t last_read_length = 0;
    uint32_t last_write_handle = 0;
    uint32_t last_close_handle = 0;
    uint32_t last_control_handle = 0;
    uint32_t last_ioctl = 0;
    std::vector<uint8_t> read_data;
    std::vector<uint8_t> last_write_data;
    std::vector<uint8_t> last_control_input;
    std::vector<uint8_t> control_output;

 private:
    uint32_t next_handle_ = 0x100;
};

class FakePrinter final : public rtsc::rdpdr::IPrinterBackend {
 public:
    uint32_t OpenJob(const std::string& printer_name) override {
        ++open_calls;
        last_printer_name = printer_name;
        if (fail_open) return 0;
        return next_job_++;
    }
    bool Write(uint32_t job, const std::vector<uint8_t>& data,
               uint32_t& written) override {
        ++write_calls;
        last_job = job;
        last_data = data;
        written = (write_written == 0xFFFFFFFFu)
                      ? static_cast<uint32_t>(data.size())
                      : write_written;
        return write_result;
    }
    bool CloseJob(uint32_t job) override {
        ++close_calls;
        last_close_job = job;
        return true;
    }

    unsigned open_calls = 0;
    unsigned write_calls = 0;
    unsigned close_calls = 0;
    bool fail_open = false;
    bool write_result = true;
    uint32_t write_written = 0xFFFFFFFFu;  // bytes accepted; sentinel = all
    std::string last_printer_name;
    uint32_t last_job = 0;
    uint32_t last_close_job = 0;
    std::vector<uint8_t> last_data;

 private:
    uint32_t next_job_ = 0x200;
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

// These tests model a *Windows* drive redirector: the redirected drive root and
// the server-supplied relative paths are Windows-form ("C:\\", "\\dir\\file.txt").
// On POSIX that root is not a real directory, so the drive-dispatch cases are
// skipped there; the portable path guard has its own POSIX cases below.
#if defined(_WIN32)
#define RTSC_RDPDR_DRIVE_TESTS 1
#else
#define RTSC_RDPDR_DRIVE_TESTS 0
#endif

// ---- state machine ---------------------------------------------------------

RTSC_TEST(rdpdr_client_starts_awaiting_server_announce) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    RdpdrClient client(&fs, {}, "HOST", [](const std::vector<uint8_t>&) {});
    CHECK(client.phase() == RdpdrClient::Phase::kAwaitServerAnnounce);
    CHECK_EQ(client.client_id(), static_cast<uint32_t>(0));
    CHECK_EQ(client.server_announce_count(), static_cast<unsigned>(0));
    CHECK_EQ(client.client_announce_count(), static_cast<unsigned>(0));
    CHECK(!client.user_logged_on());
}

RTSC_TEST(rdpdr_client_announce_replies_and_advances_phase) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    RdpdrClient client(&fs, {}, "HOST", [](const std::vector<uint8_t>&) {});

    proto::RdpdrDeviceReply reply;
    reply.device_id = kDeviceId;
    reply.result_code = 0;
    FeedMessage(client, reply.encode());
    CHECK_EQ(client.device_reply_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_client_reassembles_chunked_announce) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    RdpdrClient client(&fs, {}, "HOST", [](const std::vector<uint8_t>&) {});
    client.OnChannelData(nullptr, 0);
    const uint8_t tiny[3] = {1, 2, 3};
    client.OnChannelData(tiny, sizeof(tiny));
    CHECK_EQ(client.server_announce_count(), static_cast<unsigned>(0));
}

// ---- file I/O dispatch -----------------------------------------------------

RTSC_TEST(rdpdr_client_create_maps_remote_path_and_opens) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
            // Guard the slice: an error completion is shorter than 28 bytes and
            // rsp->begin() + 28 past the end is UB (it threw length_error on
            // the POSIX build where the remote Windows path is rejected).
            if (rsp->size() >= 28) {
                CHECK(std::vector<uint8_t>(rsp->begin() + 28, rsp->end()) ==
                      fs.read_data);
            } else {
                CHECK(false);
            }
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
        // Guard the slice: an error completion is shorter than 28 bytes.
        if (rsp->size() >= 28) {
            CHECK(std::vector<uint8_t>(rsp->begin() + 28, rsp->end()) ==
                  fs.query_data);
        } else {
            CHECK(false);
        }
    }
}

RTSC_TEST(rdpdr_client_control_is_unsuccessful) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    std::string out;
    CHECK(rtsc::channel::ResolvePathUnderRoot("C:\\share", "", out));
    CHECK(out == "C:\\share");
    CHECK(rtsc::channel::ResolvePathUnderRoot("C:\\share", "\\", out));
    CHECK(out == "C:\\share");
    CHECK(rtsc::channel::ResolvePathUnderRoot("C:\\share\\", "", out));
    CHECK(out == "C:\\share");
}

RTSC_TEST(rdpdr_client_create_maximum_allowed_is_write) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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

// ---- W11 route-A hardening (S6 / S2 / S4) --------------------------------

// S6: a file id handed out by device A must not be serviced when an IRP names
// device B. Every operation that dereferences the handle table re-checks that
// the handle's owning device matches the request.
RTSC_TEST(rdpdr_client_io_checks_device_id_on_existing_handle) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    fs.read_data = {0xAA, 0xBB};
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 90, 0x00000001 /* FILE_OPEN */,
                        "\\tsclient\\C\\x.bin"));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    uint32_t file_id = 0;
    CHECK(crsp != nullptr);
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    const uint32_t other = kDeviceId + 100;

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ReadBody(other, file_id, 91, 4, 0));
    CHECK_EQ(fs.read_calls, static_cast<unsigned>(0));
    {
        const std::vector<uint8_t>* rsp =
            FindSent(sent, proto::kPakidCoreDeviceIocompletion);
        CHECK(rsp != nullptr);
        if (rsp != nullptr) {
            CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
        }
    }
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             WriteBody(other, file_id, 92, 0, {1, 2, 3}));
    CHECK_EQ(fs.write_calls, static_cast<unsigned>(0));
    {
        const std::vector<uint8_t>* rsp =
            FindSent(sent, proto::kPakidCoreDeviceIocompletion);
        CHECK(rsp != nullptr);
        if (rsp != nullptr) {
            CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
        }
    }
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             QueryDirBody(other, file_id, 93, 0x0C, true, "*.txt"));
    CHECK_EQ(fs.query_calls, static_cast<unsigned>(0));
    {
        const std::vector<uint8_t>* rsp =
            FindSent(sent, proto::kPakidCoreDeviceIocompletion);
        CHECK(rsp != nullptr);
        if (rsp != nullptr) {
            CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
        }
    }
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(other, file_id, 94, proto::kIrpMjClose, 0));
    CHECK_EQ(fs.close_calls, static_cast<unsigned>(0));
    {
        const std::vector<uint8_t>* rsp =
            FindSent(sent, proto::kPakidCoreDeviceIocompletion);
        CHECK(rsp != nullptr);
        if (rsp != nullptr) {
            CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
        }
    }
    sent.clear();

    // The handle still works on its own device after all the rejects.
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ReadBody(kDeviceId, file_id, 95, 4, 0));
    CHECK_EQ(fs.read_calls, static_cast<unsigned>(1));
    CHECK_EQ(client.read_count(), static_cast<unsigned>(1));
}

// S2: the open handle table is capped at 256; the 257th create is refused with
// STATUS_TOO_MANY_OPENED_FILES and already-open handles stay usable.
RTSC_TEST(rdpdr_client_open_handle_limit_rejects_extra) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    constexpr uint32_t kTooManyOpenedFiles = 0xC0000041;
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    MakeReady(client);

    uint32_t first_file_id = 0;
    for (unsigned i = 0; i < 257; ++i) {
        sent.clear();
        FeedBody(client, proto::kPakidCoreDeviceIorequest,
                 CreateBody(kDeviceId, 100 + i, 0x00000001 /* FILE_OPEN */,
                            "\\tsclient\\C\\h.bin"));
        const std::vector<uint8_t>* rsp =
            FindSent(sent, proto::kPakidCoreDeviceIocompletion);
        CHECK(rsp != nullptr);
        if (rsp == nullptr) continue;
        if (i < 256) {
            CHECK_EQ(U32At(*rsp, 20),
                     static_cast<uint32_t>(proto::kStatusSuccess));
            if (i == 0) first_file_id = U32At(*rsp, 24);
        } else {
            if (U32At(*rsp, 20) != kTooManyOpenedFiles) {
                std::printf("  257th create returned 0x%08X\n", U32At(*rsp, 20));
            }
            CHECK_EQ(U32At(*rsp, 20), kTooManyOpenedFiles);
        }
    }
    CHECK_EQ(client.create_count(), static_cast<unsigned>(256));
    CHECK_EQ(fs.open_calls, static_cast<unsigned>(256));
    CHECK(first_file_id != 0);

    // One of the handles opened before the cap is still serviceable.
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ReadBody(kDeviceId, first_file_id, 400, 4, 0));
    CHECK_EQ(fs.read_calls, static_cast<unsigned>(1));
    CHECK_EQ(client.read_count(), static_cast<unsigned>(1));
}

// S4: a device whose local_root does not exist (or is not a directory) is
// rejected up front and recorded, so ResolvePathUnderRoot can never fabricate a
// lexical path underneath it.
RTSC_TEST(rdpdr_client_create_rejects_missing_local_root) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    const std::filesystem::path missing =
        std::filesystem::temp_directory_path() / "rtsc_missing_root_w11";
    std::error_code ec;
    std::filesystem::remove_all(missing, ec);
    RdpdrClient client(&fs,
                       {{kDeviceId, "C:", missing.string()}}, "HOST",
                       [&](const std::vector<uint8_t>& m) { sent.push_back(m); });

    CHECK(client.device_root_invalid_count() >= static_cast<unsigned>(1));
    MakeReady(client);

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
                 static_cast<uint32_t>(proto::kStatusAccessDenied));
    }
}

// The path guard itself is portable: with a POSIX root the redirected relative
// path (which is always Windows-form, [MS-RDPEFS] 2.2.2.9) must stay inside the
// root and the traversal/UNC/drive forms must still be rejected. This keeps the
// security-relevant coverage on the POSIX build, where the drive-dispatch cases
// above are skipped.
RTSC_TEST(rdpdr_path_guard_is_portable) {
    if (RTSC_RDPDR_DRIVE_TESTS) return;  // Windows has the full drive suite
    std::string out;
    CHECK(rtsc::rdpdr::ResolvePathUnderRoot("/tmp/root", "\\dir\\file.txt", out));
    CHECK(out == "/tmp/root/dir/file.txt");
    CHECK(rtsc::rdpdr::ResolvePathUnderRoot("/tmp/root", "dir/file.txt", out));
    CHECK(out == "/tmp/root/dir/file.txt");
    CHECK(!rtsc::rdpdr::ResolvePathUnderRoot("/tmp/root", "..\\..\\etc\\passwd", out));
    CHECK(!rtsc::rdpdr::ResolvePathUnderRoot("/tmp/root", "dir\\..\\..\\escape", out));
    CHECK(!rtsc::rdpdr::ResolvePathUnderRoot("/tmp/root", "\\\\server\\share", out));
    CHECK(!rtsc::rdpdr::ResolvePathUnderRoot("/tmp/root", "C:\\Windows", out));
}

// After a reconnect the server restarts the rdpdr handshake from its Server
// Announce. Reset() must drop the old session's negotiated state and close the
// file handles it still owns, while the configuration (devices) survives.
RTSC_TEST(rdpdr_client_reset_returns_to_await_announce) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
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
    CHECK(client.phase() == RdpdrClient::Phase::kReady);

    // Open one file so Reset() has a handle to close.
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 9, 0x00000003 /* kFileOpenIf */,
                        "\\tsclient\\C\\dir\\file.txt"));
    CHECK_EQ(fs.open_calls, static_cast<unsigned>(1));

    client.Reset();
    CHECK(client.phase() == RdpdrClient::Phase::kAwaitServerAnnounce);
    CHECK_EQ(client.client_id(), static_cast<uint32_t>(0));
    CHECK_EQ(fs.close_calls, static_cast<unsigned>(1));

    // The new session re-runs the same handshake.
    FeedMessage(client, announce.encode());
    CHECK(client.phase() == RdpdrClient::Phase::kAwaitClientIdConfirm);
    CHECK_EQ(client.server_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.devices().size(), static_cast<size_t>(1));
}

RTSC_TEST(rdpdr_client_remove_device_sends_and_stops_serving) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    CHECK(client.RemoveDevice(kDeviceId));
    CHECK_EQ(client.devices().size(), static_cast<size_t>(0));
    CHECK_EQ(client.device_remove_count(), static_cast<unsigned>(1));
    const std::vector<uint8_t>* remove =
        FindSent(sent, proto::kPakidCoreDevicelistRemove);
    CHECK(remove != nullptr);
    if (remove != nullptr) {
        CHECK_EQ(U32At(*remove, proto::ChannelPduHeader::kSize + 4),
                 static_cast<uint32_t>(1));  // DeviceCount
        CHECK_EQ(U32At(*remove, proto::ChannelPduHeader::kSize + 8),
                 static_cast<uint32_t>(kDeviceId));
    }

    // The removed device is no longer served: the create fails before the
    // filesystem is touched.
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(kDeviceId, 12, 0x00000001 /* FILE_OPEN */,
                        "\\tsclient\\C\\data.bin"));
    CHECK_EQ(fs.open_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusAccessDenied));
    }
}

RTSC_TEST(rdpdr_client_remove_unknown_device_is_rejected) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    CHECK(!client.RemoveDevice(kDeviceId + 1));
    CHECK_EQ(client.devices().size(), static_cast<size_t>(1));
    CHECK_EQ(client.device_remove_count(), static_cast<unsigned>(0));
    CHECK(sent.empty());
}

std::vector<uint8_t> QueryVolumeBody(uint32_t device_id, uint32_t file_id,
                                     uint32_t completion_id,
                                     uint32_t info_class) {
    proto::ByteWriter w;
    const std::vector<uint8_t> req = IoRequestBody(
        device_id, file_id, completion_id,
        proto::kIrpMjQueryVolumeInformation, 0);
    w.bytes(req.data(), req.size());
    w.u32le(info_class);
    w.u32le(0);  // Length
    for (int i = 0; i < 24; ++i) w.u8(0);  // Padding
    return w.take();
}

std::vector<uint8_t> QueryInformationBody(uint32_t device_id, uint32_t file_id,
                                          uint32_t completion_id,
                                          uint32_t info_class) {
    proto::ByteWriter w;
    const std::vector<uint8_t> req = IoRequestBody(
        device_id, file_id, completion_id, proto::kIrpMjQueryInformation, 0);
    w.bytes(req.data(), req.size());
    w.u32le(info_class);
    w.u32le(0);  // Length
    for (int i = 0; i < 24; ++i) w.u8(0);  // Padding
    return w.take();
}

std::vector<uint8_t> SetInformationBody(uint32_t device_id, uint32_t file_id,
                                        uint32_t completion_id,
                                        uint32_t info_class,
                                        const std::vector<uint8_t>& buffer) {
    proto::ByteWriter w;
    const std::vector<uint8_t> req = IoRequestBody(
        device_id, file_id, completion_id, proto::kIrpMjSetInformation, 0);
    w.bytes(req.data(), req.size());
    w.u32le(info_class);
    w.u32le(static_cast<uint32_t>(buffer.size()));
    for (int i = 0; i < 24; ++i) w.u8(0);  // Padding
    w.bytes(buffer.data(), buffer.size());
    return w.take();
}

// FileRenameInformation: ReplaceIfExists(1) + Reserved(7) + RootDirectory(8)
// + FileNameLength(4) + FileName (UTF-16LE, no terminator).
std::vector<uint8_t> RenameBuffer(bool replace, const std::string& path) {
    proto::ByteWriter w;
    w.u8(replace ? 1 : 0);
    for (int i = 0; i < 7; ++i) w.u8(0);
    w.u32le(0);
    w.u32le(0);  // RootDirectory
    std::vector<uint8_t> name;
    for (const char c : path) {
        name.push_back(static_cast<uint8_t>(c));
        name.push_back(0);
    }
    w.u32le(static_cast<uint32_t>(name.size()));
    w.bytes(name.data(), name.size());
    return w.take();
}

RTSC_TEST(rdpdr_client_query_volume_returns_the_structure) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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

    fs.query_volume_data = {1, 2, 3, 4, 5, 6, 7, 8,
                            9, 10, 11, 12, 13, 14, 15, 16,
                            17, 18, 19, 20, 21, 22, 23, 24};
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             QueryVolumeBody(kDeviceId, file_id, 11, 0x03));
    CHECK_EQ(fs.query_volume_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_query_volume_id, file_id);
    CHECK_EQ(fs.last_query_volume_class, static_cast<uint32_t>(0x03));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(24));
        CHECK_EQ((*rsp)[28], static_cast<uint8_t>(1));
        CHECK_EQ((*rsp)[51], static_cast<uint8_t>(24));
    }
    CHECK_EQ(client.query_volume_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_client_query_volume_unsupported_class_fails_closed) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    fs.query_volume_result = false;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             QueryVolumeBody(kDeviceId, file_id, 12, 0x05));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusNotSupported));
        // A failed completion carries only DeviceIoReply (12 bytes); there is
        // no Length/Buffer.
        CHECK_EQ(rsp->size(), proto::ChannelPduHeader::kSize +
                                  proto::RdpdrHeader::kSize + 12);
    }
    CHECK_EQ(client.query_volume_count(), static_cast<unsigned>(0));
}

RTSC_TEST(rdpdr_client_query_volume_unknown_handle_is_invalid) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             QueryVolumeBody(kDeviceId, 99, 13, 0x03));
    CHECK_EQ(fs.query_volume_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
    }
}

RTSC_TEST(rdpdr_client_query_information_returns_the_structure) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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

    fs.query_information_data.clear();
    for (int i = 1; i <= 36; ++i) {
        fs.query_information_data.push_back(static_cast<uint8_t>(i));
    }
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             QueryInformationBody(kDeviceId, file_id, 11, 0x04));
    CHECK_EQ(fs.query_information_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_query_information_id, file_id);
    CHECK_EQ(fs.last_query_information_class, static_cast<uint32_t>(0x04));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(36));
        CHECK_EQ((*rsp)[28], static_cast<uint8_t>(1));
        CHECK_EQ((*rsp)[63], static_cast<uint8_t>(36));
    }
    CHECK_EQ(client.query_information_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_client_query_information_unsupported_class_fails_closed) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    fs.query_information_result = false;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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
             QueryInformationBody(kDeviceId, file_id, 11, 0x09));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusNotSupported));
        CHECK_EQ(rsp->size(), proto::ChannelPduHeader::kSize +
                                  proto::RdpdrHeader::kSize + 12);
    }
    CHECK_EQ(client.query_information_count(), static_cast<unsigned>(0));
}

RTSC_TEST(rdpdr_client_query_information_unknown_handle_is_invalid) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             QueryInformationBody(kDeviceId, 99, 13, 0x04));
    CHECK_EQ(fs.query_information_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
    }
}

RTSC_TEST(rdpdr_client_set_information_delete_is_applied_on_close) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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
             SetInformationBody(kDeviceId, file_id, 11, 0x0D, {1}));
    CHECK_EQ(fs.delete_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(0));  // Length
        CHECK_EQ(rsp->size(), proto::ChannelPduHeader::kSize +
                                  proto::RdpdrHeader::kSize + 16);
    }
    CHECK_EQ(client.set_information_count(), static_cast<unsigned>(1));
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(kDeviceId, file_id, 12, proto::kIrpMjClose, 0));
    CHECK_EQ(fs.close_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.delete_calls, static_cast<unsigned>(1));
    CHECK(fs.last_delete_path == "C:\\data.bin");
}

RTSC_TEST(rdpdr_client_set_information_delete_can_be_cancelled) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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
             SetInformationBody(kDeviceId, file_id, 11, 0x0D, {1}));
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             SetInformationBody(kDeviceId, file_id, 12, 0x0D, {0}));
    CHECK_EQ(client.set_information_count(), static_cast<unsigned>(2));
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(kDeviceId, file_id, 13, proto::kIrpMjClose, 0));
    CHECK_EQ(fs.close_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.delete_calls, static_cast<unsigned>(0));
}

RTSC_TEST(rdpdr_client_set_information_rename_is_applied_on_close) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    fs.stat_result = false;  // the target name does not exist
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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
                        "\\tsclient\\C\\old.bin"));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             SetInformationBody(
                 kDeviceId, file_id, 11, 0x0A,
                 RenameBuffer(false, "\\tsclient\\C\\new.bin")));
    CHECK_EQ(fs.rename_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
    }
    CHECK_EQ(client.set_information_count(), static_cast<unsigned>(1));
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(kDeviceId, file_id, 12, proto::kIrpMjClose, 0));
    CHECK_EQ(fs.close_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.rename_calls, static_cast<unsigned>(1));
    CHECK(fs.last_rename_from == "C:\\old.bin");
    CHECK(fs.last_rename_to == "C:\\new.bin");
    CHECK(!fs.last_rename_replace);
}

RTSC_TEST(rdpdr_client_set_information_rename_collision_is_rejected) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    fs.stat_result = true;  // the target name exists
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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
                        "\\tsclient\\C\\old.bin"));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             SetInformationBody(
                 kDeviceId, file_id, 11, 0x0A,
                 RenameBuffer(false, "\\tsclient\\C\\new.bin")));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000035));
    }
    CHECK_EQ(client.set_information_count(), static_cast<unsigned>(0));
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(kDeviceId, file_id, 12, proto::kIrpMjClose, 0));
    CHECK_EQ(fs.rename_calls, static_cast<unsigned>(0));
}

RTSC_TEST(rdpdr_client_set_information_rename_to_same_name_is_noop) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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
                        "\\tsclient\\C\\old.bin"));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             SetInformationBody(
                 kDeviceId, file_id, 11, 0x0A,
                 RenameBuffer(false, "\\tsclient\\C\\old.bin")));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
    }
    CHECK_EQ(client.set_information_count(), static_cast<unsigned>(1));
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(kDeviceId, file_id, 12, proto::kIrpMjClose, 0));
    CHECK_EQ(fs.rename_calls, static_cast<unsigned>(0));
}

RTSC_TEST(rdpdr_client_set_information_unsupported_class_fails_closed) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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
             SetInformationBody(kDeviceId, file_id, 11, 0x0E, {0, 0, 0, 0}));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusNotSupported));
    }
    CHECK_EQ(client.set_information_count(), static_cast<unsigned>(0));
}

RTSC_TEST(rdpdr_client_set_information_rename_with_root_is_unsupported) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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
                        "\\tsclient\\C\\old.bin"));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    std::vector<uint8_t> buffer =
        RenameBuffer(false, "\\tsclient\\C\\new.bin");
    buffer[8] = 1;  // RootDirectory != 0
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             SetInformationBody(kDeviceId, file_id, 11, 0x0A, buffer));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusNotSupported));
    }
    CHECK_EQ(client.set_information_count(), static_cast<unsigned>(0));
}

RTSC_TEST(rdpdr_client_set_information_unknown_handle_is_invalid) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             SetInformationBody(kDeviceId, 99, 11, 0x0D, {1}));
    CHECK_EQ(fs.delete_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
    }
}

RTSC_TEST(rdpdr_client_notify_change_directory_fails_closed) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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
                        "\\tsclient\\C\\dir"));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             NotifyChangeBody(kDeviceId, file_id, 11));
    CHECK_EQ(fs.query_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusNotSupported));
        // A failed completion carries only the DeviceIoReply (12 bytes).
        CHECK_EQ(rsp->size(), proto::ChannelPduHeader::kSize +
                                  proto::RdpdrHeader::kSize + 12);
    }
    CHECK_EQ(client.notify_change_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_client_notify_change_directory_unknown_handle_is_invalid) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             NotifyChangeBody(kDeviceId, 99, 11));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
    }
    CHECK_EQ(client.notify_change_count(), static_cast<unsigned>(0));
}

RTSC_TEST(rdpdr_client_directory_control_unknown_minor_is_invalid) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
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
                        "\\tsclient\\C\\dir"));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             NotifyChangeBody(kDeviceId, file_id, 11, 0x7 /* unknown minor */));
    CHECK_EQ(fs.query_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000010));
    }
}

RTSC_TEST(rdpdr_client_lock_control_succeeds) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    const uint32_t file_id =
        CreateFileForTest(client, sent, "\\tsclient\\C\\data.bin");
    CHECK(file_id != 0);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             LockBody(kDeviceId, file_id, 11,
                      proto::kRdpLowioOpExclusiveLock, {{10, 0}}));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
        // DeviceIoReply (12) + 5 bytes of padding.
        CHECK_EQ(rsp->size(), proto::ChannelPduHeader::kSize +
                                  proto::RdpdrHeader::kSize + 17);
    }
    CHECK_EQ(client.lock_control_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_client_lock_control_conflict_is_not_granted) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    const uint32_t file_id =
        CreateFileForTest(client, sent, "\\tsclient\\C\\data.bin");
    CHECK(file_id != 0);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             LockBody(kDeviceId, file_id, 11,
                      proto::kRdpLowioOpExclusiveLock, {{10, 0}}));
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             LockBody(kDeviceId, file_id, 12,
                      proto::kRdpLowioOpSharedLock, {{10, 5}}));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusLockNotGranted));
    }
    CHECK_EQ(client.lock_control_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_client_lock_control_unlock_not_locked) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    const uint32_t file_id =
        CreateFileForTest(client, sent, "\\tsclient\\C\\data.bin");
    CHECK(file_id != 0);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             LockBody(kDeviceId, file_id, 11, proto::kRdpLowioOpUnlock,
                      {{10, 0}}));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusRangeNotLocked));
    }
    CHECK_EQ(client.lock_control_count(), static_cast<unsigned>(0));
}

RTSC_TEST(rdpdr_client_lock_control_unknown_operation_is_invalid) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    const uint32_t file_id =
        CreateFileForTest(client, sent, "\\tsclient\\C\\data.bin");
    CHECK(file_id != 0);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             LockBody(kDeviceId, file_id, 11, 0x1, {{10, 0}}));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusInvalidParameter));
    }
}

RTSC_TEST(rdpdr_client_lock_control_unknown_handle_is_invalid) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             LockBody(kDeviceId, 99, 11, proto::kRdpLowioOpExclusiveLock,
                      {{10, 0}}));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
    }
}

RTSC_TEST(rdpdr_client_close_releases_locks) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    const uint32_t first =
        CreateFileForTest(client, sent, "\\tsclient\\C\\data.bin");
    CHECK(first != 0);
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             LockBody(kDeviceId, first, 11,
                      proto::kRdpLowioOpExclusiveLock, {{10, 0}}));
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(kDeviceId, first, 12, proto::kIrpMjClose, 0));
    sent.clear();

    const uint32_t second =
        CreateFileForTest(client, sent, "\\tsclient\\C\\data.bin");
    CHECK(second != 0);
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             LockBody(kDeviceId, second, 13,
                      proto::kRdpLowioOpExclusiveLock, {{10, 0}}));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
    }
}

RTSC_TEST(rdpdr_lock_table_shared_and_exclusive_conflicts) {
    rtsc::rdpdr::LockTable table;
    CHECK(table.Lock(1, {0, 10}, false) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    CHECK(table.Lock(2, {5, 10}, false) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    CHECK(table.Lock(3, {5, 10}, true) ==
          rtsc::rdpdr::LockTable::Result::kConflict);
    CHECK(table.Lock(3, {20, 10}, true) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    // A zero-length region is valid and never conflicts.
    CHECK(table.Lock(4, {0, 0}, true) ==
          rtsc::rdpdr::LockTable::Result::kOk);
}

RTSC_TEST(rdpdr_lock_table_unlock_requires_exact_match) {
    rtsc::rdpdr::LockTable table;
    CHECK(table.Lock(1, {0, 10}, true) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    CHECK(table.Unlock(1, {0, 5}) ==
          rtsc::rdpdr::LockTable::Result::kNotLocked);
    CHECK(table.Unlock(2, {0, 10}) ==
          rtsc::rdpdr::LockTable::Result::kNotLocked);
    CHECK(table.Unlock(1, {0, 10}) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    CHECK_EQ(table.size(), static_cast<size_t>(0));
}

RTSC_TEST(rdpdr_lock_table_lock_many_is_atomic) {
    rtsc::rdpdr::LockTable table;
    CHECK(table.LockMany(1, {{0, 10}, {20, 10}}, true) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    const size_t before = table.size();
    CHECK(table.LockMany(2, {{5, 10}, {100, 10}}, true) ==
          rtsc::rdpdr::LockTable::Result::kConflict);
    CHECK_EQ(table.size(), before);
    // The non-conflicting second range of the failed request was not added.
    CHECK(table.Lock(2, {100, 10}, true) ==
          rtsc::rdpdr::LockTable::Result::kOk);
}

RTSC_TEST(rdpdr_lock_table_unlock_many_is_atomic) {
    rtsc::rdpdr::LockTable table;
    CHECK(table.Lock(1, {0, 10}, true) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    CHECK(table.Lock(1, {20, 10}, true) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    CHECK(table.UnlockMany(1, {{0, 10}, {30, 10}}) ==
          rtsc::rdpdr::LockTable::Result::kNotLocked);
    CHECK_EQ(table.size(), static_cast<size_t>(2));
    CHECK(table.UnlockMany(1, {{0, 10}, {20, 10}}) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    CHECK_EQ(table.size(), static_cast<size_t>(0));
}

RTSC_TEST(rdpdr_lock_table_release_file_drops_only_its_locks) {
    rtsc::rdpdr::LockTable table;
    CHECK(table.Lock(1, {0, 10}, true) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    CHECK(table.Lock(2, {20, 10}, true) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    table.ReleaseFile(1);
    CHECK_EQ(table.size(), static_cast<size_t>(1));
    // The released range is free again, the other handle still holds its own.
    CHECK(table.Lock(3, {0, 10}, true) ==
          rtsc::rdpdr::LockTable::Result::kOk);
    CHECK(table.Lock(3, {20, 10}, true) ==
          rtsc::rdpdr::LockTable::Result::kConflict);
}

RTSC_TEST(rdpdr_client_set_volume_information_sets_label) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    const uint32_t file_id =
        CreateFileForTest(client, sent, "\\tsclient\\C\\data.bin");
    CHECK(file_id != 0);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             SetVolumeBody(kDeviceId, file_id, 11, 0x02, u"NEWLABEL"));
    CHECK_EQ(fs.set_volume_label_calls, static_cast<unsigned>(1));
    CHECK_EQ(fs.last_volume_label_id, file_id);
    CHECK(fs.last_volume_label == "NEWLABEL");
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
        // Length MUST match the request: 4 + 8 chars * 2.
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(20));
        CHECK_EQ(rsp->size(), proto::ChannelPduHeader::kSize +
                                  proto::RdpdrHeader::kSize + 16);
    }
    CHECK_EQ(client.set_volume_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_client_set_volume_information_unsupported_class) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    const uint32_t file_id =
        CreateFileForTest(client, sent, "\\tsclient\\C\\data.bin");
    CHECK(file_id != 0);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             SetVolumeBody(kDeviceId, file_id, 11, 0x01, u"NEWLABEL"));
    CHECK_EQ(fs.set_volume_label_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusNotSupported));
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(20));
    }
    CHECK_EQ(client.set_volume_count(), static_cast<unsigned>(0));
}

RTSC_TEST(rdpdr_client_set_volume_information_label_length_mismatch) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    const uint32_t file_id =
        CreateFileForTest(client, sent, "\\tsclient\\C\\data.bin");
    CHECK(file_id != 0);

    std::vector<uint8_t> body =
        SetVolumeBody(kDeviceId, file_id, 11, 0x02, u"");
    // The buffer starts after DeviceIoRequest(20) + class(4) + length(4) +
    // padding(24); claim a label longer than the buffer.
    body[52] = 100;
    FeedBody(client, proto::kPakidCoreDeviceIorequest, body);
    CHECK_EQ(fs.set_volume_label_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusInvalidParameter));
    }
}

RTSC_TEST(rdpdr_client_set_volume_information_unknown_handle) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             SetVolumeBody(kDeviceId, 99, 11, 0x02, u"NEWLABEL"));
    CHECK_EQ(fs.set_volume_label_calls, static_cast<unsigned>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(0xC0000008));
    }
}

RTSC_TEST(rdpdr_client_set_volume_information_access_denied) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    fs.set_volume_label_result = false;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{kDeviceId, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    const uint32_t file_id =
        CreateFileForTest(client, sent, "\\tsclient\\C\\data.bin");
    CHECK(file_id != 0);

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             SetVolumeBody(kDeviceId, file_id, 11, 0x02, u"NEWLABEL"));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusAccessDenied));
    }
    CHECK_EQ(client.set_volume_count(), static_cast<unsigned>(0));
}

RTSC_TEST(rdpdr_serial_device_is_announced_with_port_capability) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    FakeSerial serial;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs,
        {{kDeviceId, "C:", "C:\\"},
         {2, "COM1", "", RdpdrClient::DeviceType::kSerial}},
        "HOST", [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.EnableSerial(&serial);
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());

    const std::vector<uint8_t>* caps =
        FindSent(sent, proto::kPakidCoreClientCapability);
    CHECK(caps != nullptr);
    // ChannelPduHeader(8) + RdpdrHeader(4) + NumCapabilities(2) + padding(2).
    bool port_found = false;
    if (caps != nullptr) {
        size_t offset = 16;
        while (offset + 8 <= caps->size()) {
            const uint16_t type =
                static_cast<uint16_t>((*caps)[offset]) |
                (static_cast<uint16_t>((*caps)[offset + 1]) << 8);
            const uint16_t len =
                static_cast<uint16_t>((*caps)[offset + 2]) |
                (static_cast<uint16_t>((*caps)[offset + 3]) << 8);
            if (type == 0x0003) {  // CAP_PORT_TYPE
                port_found = true;
                CHECK_EQ(U32At(*caps, offset + 4), 1u);
            }
            if (len < 8) break;
            offset += len;
        }
    }
    CHECK(port_found);

    const std::vector<uint8_t>* list =
        FindSent(sent, proto::kPakidCoreDevicelistAnnounce);
    CHECK(list != nullptr);
    if (list != nullptr) {
        // DeviceCount @12; each DEVICE_ANNOUNCE is 20 bytes.
        CHECK_EQ(U32At(*list, 12), 2u);
        CHECK_EQ(U32At(*list, 36), static_cast<uint32_t>(0x00000001));
        CHECK_EQ((*list)[44], static_cast<uint8_t>('C'));
        CHECK_EQ((*list)[45], static_cast<uint8_t>('O'));
    }
}

RTSC_TEST(rdpdr_serial_create_read_write_close) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    FakeSerial serial;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs, {{2, "COM1", "", RdpdrClient::DeviceType::kSerial}}, "HOST",
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.EnableSerial(&serial);
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 10, 0x00000001 /* FILE_OPEN */, ""));
    CHECK_EQ(serial.open_calls, static_cast<unsigned>(1));
    CHECK(serial.last_open_port == "COM1");
    CHECK_EQ(client.open_serial_count(), static_cast<size_t>(1));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    serial.read_data = {0x41, 0x42};
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ReadBody(2, file_id, 11, 16, 0));
    CHECK_EQ(serial.read_calls, static_cast<unsigned>(1));
    CHECK_EQ(serial.last_read_length, static_cast<uint32_t>(16));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(2));
        CHECK_EQ((*rsp)[28], static_cast<uint8_t>(0x41));
    }
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             WriteBody(2, file_id, 12, 0, {1, 2, 3}));
    CHECK_EQ(serial.write_calls, static_cast<unsigned>(1));
    CHECK(serial.last_write_data == std::vector<uint8_t>({1, 2, 3}));
    rsp = FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(3));
    }
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(2, file_id, 13, proto::kIrpMjClose, 0));
    CHECK_EQ(serial.close_calls, static_cast<unsigned>(1));
    CHECK_EQ(client.open_serial_count(), static_cast<size_t>(0));
    CHECK_EQ(client.serial_io_count(), static_cast<unsigned>(2));
}

RTSC_TEST(rdpdr_serial_create_without_backend_fails_closed) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs, {{2, "COM1", "", RdpdrClient::DeviceType::kSerial}}, "HOST",
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 10, 0x00000001, ""));
    CHECK_EQ(client.open_serial_count(), static_cast<size_t>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusAccessDenied));
    }
}

RTSC_TEST(rdpdr_serial_control_routes_to_backend) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    FakeSerial serial;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs, {{2, "COM1", "", RdpdrClient::DeviceType::kSerial}}, "HOST",
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.EnableSerial(&serial);
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 10, 0x00000001, ""));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    serial.control_output = {0xAA};
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ControlBody(2, file_id, 11, 0x001B0008, {0x01}));
    CHECK_EQ(serial.control_calls, static_cast<unsigned>(1));
    CHECK_EQ(serial.last_ioctl, static_cast<uint32_t>(0x001B0008));
    CHECK(serial.last_control_input == std::vector<uint8_t>({0x01}));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(1));
        CHECK_EQ((*rsp)[28], static_cast<uint8_t>(0xAA));
    }
}

RTSC_TEST(rdpdr_serial_remove_device_closes_handles) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    FakeSerial serial;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs, {{2, "COM1", "", RdpdrClient::DeviceType::kSerial}}, "HOST",
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.EnableSerial(&serial);
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 10, 0x00000001, ""));
    CHECK_EQ(client.open_serial_count(), static_cast<size_t>(1));

    CHECK(client.RemoveDevice(2));
    CHECK_EQ(serial.close_calls, static_cast<unsigned>(1));
    CHECK_EQ(client.open_serial_count(), static_cast<size_t>(0));
}

RTSC_TEST(rdpdr_win32_serial_open_missing_port_fails) {
    rtsc::rdpdr::Win32SerialBackend backend;
    CHECK_EQ(backend.Open("COM_DOES_NOT_EXIST_9999"),
             static_cast<uint32_t>(0));
}

RTSC_TEST(rdpdr_win32_serial_unknown_handle_operations_fail) {
    rtsc::rdpdr::Win32SerialBackend backend;
    std::vector<uint8_t> data;
    CHECK(!backend.Read(0xDEAD, 4, data));
    uint32_t written = 0;
    CHECK(!backend.Write(0xDEAD, {1, 2}, written));
    CHECK(!backend.Close(0xDEAD));
    std::vector<uint8_t> output;
    CHECK(!backend.Control(0xDEAD, 0x1B, {}, output));
}

RTSC_TEST(rdpdr_printer_device_is_announced) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    FakePrinter printer;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs,
        {{kDeviceId, "C:", "C:\\"},
         {2, "PRN1", "", RdpdrClient::DeviceType::kPrinter, "Office Printer",
          "MS Publisher Imagesetter"}},
        "HOST", [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.EnablePrinter(&printer);
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());

    const std::vector<uint8_t>* caps =
        FindSent(sent, proto::kPakidCoreClientCapability);
    CHECK(caps != nullptr);
    bool printer_cap_found = false;
    if (caps != nullptr) {
        size_t offset = 16;
        while (offset + 8 <= caps->size()) {
            const uint16_t type =
                static_cast<uint16_t>((*caps)[offset]) |
                (static_cast<uint16_t>((*caps)[offset + 1]) << 8);
            const uint16_t len =
                static_cast<uint16_t>((*caps)[offset + 2]) |
                (static_cast<uint16_t>((*caps)[offset + 3]) << 8);
            if (type == 0x0002) {  // CAP_PRINTER_TYPE
                printer_cap_found = true;
                CHECK_EQ(U32At(*caps, offset + 4), 1u);
            }
            if (len < 8) break;
            offset += len;
        }
    }
    CHECK(printer_cap_found);

    const std::vector<uint8_t>* list =
        FindSent(sent, proto::kPakidCoreDevicelistAnnounce);
    CHECK(list != nullptr);
    if (list != nullptr) {
        CHECK_EQ(U32At(*list, 12), 2u);
        // Second DEVICE_ANNOUNCE starts at 36: type, id, dos name, data len.
        CHECK_EQ(U32At(*list, 36), static_cast<uint32_t>(0x00000004));
        CHECK_EQ((*list)[44], static_cast<uint8_t>('P'));
        CHECK_EQ((*list)[45], static_cast<uint8_t>('R'));
        const uint32_t data_len = U32At(*list, 52);
        CHECK(data_len > 24);
        // RDPDR_PRINTER_ANNOUNCE starts at 56: Flags, CodePage, PnPNameLen,
        // DriverNameLen, PrintNameLen, CachedFieldsLen.
        CHECK_EQ(U32At(*list, 56), 0u);
        CHECK_EQ(U32At(*list, 60), 0u);
        CHECK_EQ(U32At(*list, 64), 0u);
        CHECK(U32At(*list, 68) > 0u);
        CHECK(U32At(*list, 72) > 0u);
        CHECK_EQ(U32At(*list, 76), 0u);
    }
}

RTSC_TEST(rdpdr_printer_create_write_close) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    FakePrinter printer;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs,
        {{2, "PRN1", "", RdpdrClient::DeviceType::kPrinter, "Office Printer",
          "MS Publisher Imagesetter"}},
        "HOST", [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.EnablePrinter(&printer);
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 10, 0x00000001, ""));
    CHECK_EQ(printer.open_calls, static_cast<unsigned>(1));
    CHECK(printer.last_printer_name == "Office Printer");
    CHECK_EQ(client.open_printer_count(), static_cast<size_t>(1));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             WriteBody(2, file_id, 11, 0, {0x25, 0x50, 0x44, 0x46}));
    CHECK_EQ(printer.write_calls, static_cast<unsigned>(1));
    CHECK(printer.last_data == std::vector<uint8_t>({0x25, 0x50, 0x44, 0x46}));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(4));
    }
    CHECK_EQ(client.printer_io_count(), static_cast<unsigned>(1));
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(2, file_id, 12, proto::kIrpMjClose, 0));
    CHECK_EQ(printer.close_calls, static_cast<unsigned>(1));
    CHECK_EQ(client.open_printer_count(), static_cast<size_t>(0));
}

RTSC_TEST(rdpdr_printer_write_reports_bytes_written) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    FakePrinter printer;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs,
        {{2, "PRN1", "", RdpdrClient::DeviceType::kPrinter, "Office Printer",
          "MS Publisher Imagesetter"}},
        "HOST", [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.EnablePrinter(&printer);
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 10, 0x00000001, ""));
    uint32_t file_id = 0;
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    // The spooler accepts only 2 of the 4 bytes (short write).
    printer.write_written = 2;
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             WriteBody(2, file_id, 11, 0, {0x25, 0x50, 0x44, 0x46}));
    CHECK_EQ(printer.write_calls, static_cast<unsigned>(1));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20), static_cast<uint32_t>(proto::kStatusSuccess));
        // [MS-RDPEPC] 3.2.5.1.10: DR_WRITE_RSP.Length MUST be the bytes
        // written successfully, not the requested size.
        CHECK_EQ(U32At(*rsp, 24), static_cast<uint32_t>(2));
    }
    CHECK_EQ(client.printer_io_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpdr_printer_create_without_backend_fails_closed) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs,
        {{2, "PRN1", "", RdpdrClient::DeviceType::kPrinter, "Office Printer",
          "MS Publisher Imagesetter"}},
        "HOST", [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 10, 0x00000001, ""));
    CHECK_EQ(client.open_printer_count(), static_cast<size_t>(0));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusAccessDenied));
    }
}

RTSC_TEST(rdpdr_printer_control_fails_closed) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    FakePrinter printer;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs,
        {{2, "PRN1", "", RdpdrClient::DeviceType::kPrinter, "Office Printer",
          "MS Publisher Imagesetter"}},
        "HOST", [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.EnablePrinter(&printer);
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 10, 0x00000001, ""));
    const std::vector<uint8_t>* crsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(crsp != nullptr);
    uint32_t file_id = 0;
    if (crsp != nullptr) file_id = U32At(*crsp, 24);
    CHECK(file_id != 0);
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ControlBody(2, file_id, 11, 0x00000001, {}));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(rsp != nullptr);
    if (rsp != nullptr) {
        CHECK_EQ(U32At(*rsp, 20),
                 static_cast<uint32_t>(proto::kStatusNotSupported));
    }
}

RTSC_TEST(rdpdr_win32_printer_backend_rejects_unknown_jobs) {
    rtsc::rdpdr::Win32PrinterBackend backend;
    CHECK_EQ(backend.OpenJob(""), static_cast<uint32_t>(0));
    uint32_t written = 0xFFFFFFFFu;
    CHECK(!backend.Write(0xDEAD, {1, 2, 3}, written));
    CHECK_EQ(written, static_cast<uint32_t>(0));
    CHECK(!backend.CloseJob(0xDEAD));
    // Enumeration must not crash even when the spooler has no queues.
    const std::vector<rtsc::rdpdr::LocalPrinter> printers =
        rtsc::rdpdr::EnumeratePrinters();
    for (const auto& printer : printers) {
        CHECK(!printer.name.empty());
    }
}

RTSC_TEST(rdpdr_host_file_system_reuses_closed_file_ids) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    HostFileSystem fs;
    const std::filesystem::path dir = MakeTempDir("idreuse");
    const std::string a = (dir / "a.txt").string();
    const std::string b = (dir / "b.txt").string();
    uint32_t id1 = 0;
    uint32_t id2 = 0;
    uint32_t id3 = 0;
    CHECK(fs.Open(a, true, true, false, id1));
    CHECK(fs.Open(b, true, true, false, id2));
    CHECK(id1 != 0);
    CHECK(id2 != 0);
    CHECK(id1 != id2);
    CHECK(fs.Close(id1));
    CHECK(fs.Open(a, true, false, false, id3));
    // [MS-RDPEFS] 2.2.1.5.1: the id is reused after a close response.
    CHECK_EQ(id3, id1);
    CHECK(fs.Close(id2));
    CHECK(fs.Close(id3));
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

RTSC_TEST(rdpdr_serial_reuses_closed_file_ids) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    FakeSerial serial;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs, {{2, "COM1", "", RdpdrClient::DeviceType::kSerial}}, "HOST",
        [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.EnableSerial(&serial);
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 10, 0x00000001, ""));
    const std::vector<uint8_t>* first_rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(first_rsp != nullptr);
    const uint32_t first = first_rsp != nullptr ? U32At(*first_rsp, 24) : 0;
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 11, 0x00000001, ""));
    const std::vector<uint8_t>* second_rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(second_rsp != nullptr);
    const uint32_t second = second_rsp != nullptr ? U32At(*second_rsp, 24) : 0;
    CHECK(first != 0);
    CHECK(second != 0);
    CHECK(first != second);
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(2, first, 12, proto::kIrpMjClose, 0));
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 13, 0x00000001, ""));
    const std::vector<uint8_t>* third_rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(third_rsp != nullptr);
    if (third_rsp != nullptr) CHECK_EQ(U32At(*third_rsp, 24), first);
}

RTSC_TEST(rdpdr_printer_reuses_closed_file_ids) {
    if (!RTSC_RDPDR_DRIVE_TESTS) return;  // Windows path semantics
    MockFs fs;
    FakePrinter printer;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(
        &fs,
        {{2, "PRN1", "", RdpdrClient::DeviceType::kPrinter, "Office Printer",
          "MS Publisher Imagesetter"}},
        "HOST", [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    client.EnablePrinter(&printer);
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(client, announce.encode());
    proto::RdpdrServerClientIdConfirm confirm;
    confirm.client_id = 1;
    FeedMessage(client, confirm.encode());
    sent.clear();

    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 10, 0x00000001, ""));
    const std::vector<uint8_t>* first_rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(first_rsp != nullptr);
    const uint32_t first = first_rsp != nullptr ? U32At(*first_rsp, 24) : 0;
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 11, 0x00000001, ""));
    const std::vector<uint8_t>* second_rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(second_rsp != nullptr);
    const uint32_t second = second_rsp != nullptr ? U32At(*second_rsp, 24) : 0;
    CHECK(first != 0);
    CHECK(second != 0);
    CHECK(first != second);
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             IoRequestBody(2, first, 12, proto::kIrpMjClose, 0));
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             CreateBody(2, 13, 0x00000001, ""));
    const std::vector<uint8_t>* third_rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    CHECK(third_rsp != nullptr);
    if (third_rsp != nullptr) CHECK_EQ(U32At(*third_rsp, 24), first);
}

RTSC_TEST(rdpdr_volume_info_encodes_volume_information) {
    rtsc::rdpdr::VolumeInfo info;
    info.serial = 0x12345678;
    info.label = u"DATA";
    info.supports_objects = false;
    std::vector<uint8_t> out;
    CHECK(rtsc::rdpdr::EncodeVolumeInfo(0x01, info, out));
    // 8 (time) + 4 (serial) + 4 (label length) + 1 (supports objects)
    // + 4 chars * 2 + 2 (NUL). No Reserved byte ([MS-RDPEFS] 2.2.3.3.6).
    CHECK_EQ(out.size(), static_cast<size_t>(27));
    if (out.size() < 27) return;
    CHECK_EQ(U32At(out, 0), 0u);
    CHECK_EQ(U32At(out, 8), 0x12345678u);
    CHECK_EQ(U32At(out, 12), 10u);  // includes the trailing NUL
    CHECK_EQ(out[16], static_cast<uint8_t>(0));
    CHECK_EQ(out[17], static_cast<uint8_t>('D'));
    CHECK_EQ(out[18], static_cast<uint8_t>(0));
    CHECK_EQ(out[19], static_cast<uint8_t>('A'));
    CHECK_EQ(out[25], static_cast<uint8_t>(0));
    CHECK_EQ(out[26], static_cast<uint8_t>(0));
}

RTSC_TEST(rdpdr_volume_info_encodes_device_information) {
    rtsc::rdpdr::VolumeInfo info;
    info.device_type = 0x00000007;
    info.characteristics = 0x00000021;
    std::vector<uint8_t> out;
    CHECK(rtsc::rdpdr::EncodeVolumeInfo(0x04, info, out));
    CHECK_EQ(out.size(), static_cast<size_t>(8));
    if (out.size() < 8) return;
    CHECK_EQ(U32At(out, 0), 0x00000007u);
    CHECK_EQ(U32At(out, 4), 0x00000021u);
}

RTSC_TEST(rdpdr_volume_info_encodes_attribute_information) {
    rtsc::rdpdr::VolumeInfo info;
    info.file_system_attributes = 0x00000003;
    info.max_component_length = 255;
    info.file_system_name = u"NTFS";
    std::vector<uint8_t> out;
    CHECK(rtsc::rdpdr::EncodeVolumeInfo(0x05, info, out));
    // 4 + 4 + 4 + 4 chars * 2; the name is not NUL-terminated.
    CHECK_EQ(out.size(), static_cast<size_t>(20));
    if (out.size() < 20) return;
    CHECK_EQ(U32At(out, 0), 0x00000003u);
    CHECK_EQ(U32At(out, 4), 255u);
    CHECK_EQ(U32At(out, 8), 8u);
    CHECK_EQ(out[12], static_cast<uint8_t>('N'));
    CHECK_EQ(out[19], static_cast<uint8_t>(0));
}

RTSC_TEST(rdpdr_volume_info_rejects_unknown_class) {
    rtsc::rdpdr::VolumeInfo info;
    std::vector<uint8_t> out = {1, 2, 3};
    CHECK(!rtsc::rdpdr::EncodeVolumeInfo(0x03, info, out));
    CHECK(out.empty());
}

RTSC_TEST(rdpdr_file_information_encodes_basic_information) {
    rtsc::rdpdr::FileInfo info;
    info.creation_time = 0x0102030405060708ULL;
    info.last_access_time = 0x1112131415161718ULL;
    info.last_write_time = 0x2122232425262728ULL;
    info.change_time = 0x3132333435363738ULL;
    info.attributes = 0x20;
    std::vector<uint8_t> out;
    CHECK(rtsc::rdpdr::EncodeFileInformation(0x04, info, out));
    // 4 * 8 + 4 attributes; the Reserved field MUST NOT be present.
    CHECK_EQ(out.size(), static_cast<size_t>(36));
    if (out.size() < 36) return;
    CHECK_EQ(U32At(out, 0), 0x05060708u);
    CHECK_EQ(U32At(out, 4), 0x01020304u);
    CHECK_EQ(U32At(out, 8), 0x15161718u);
    CHECK_EQ(U32At(out, 16), 0x25262728u);
    CHECK_EQ(U32At(out, 24), 0x35363738u);
    CHECK_EQ(U32At(out, 32), 0x00000020u);
}

RTSC_TEST(rdpdr_file_information_encodes_standard_information) {
    rtsc::rdpdr::FileInfo info;
    info.allocation_size = 4096;
    info.end_of_file = 1000;
    info.number_of_links = 2;
    info.delete_pending = false;
    info.is_directory = true;
    std::vector<uint8_t> out;
    CHECK(rtsc::rdpdr::EncodeFileInformation(0x05, info, out));
    // 8 + 8 + 4 + 1 + 1; the Reserved field MUST NOT be present.
    CHECK_EQ(out.size(), static_cast<size_t>(22));
    if (out.size() < 22) return;
    CHECK_EQ(U32At(out, 0), 4096u);
    CHECK_EQ(U32At(out, 8), 1000u);
    CHECK_EQ(U32At(out, 16), 2u);
    CHECK_EQ(out[20], static_cast<uint8_t>(0));  // DeletePending
    CHECK_EQ(out[21], static_cast<uint8_t>(1));  // Directory
}

RTSC_TEST(rdpdr_file_information_encodes_attribute_tag_information) {
    rtsc::rdpdr::FileInfo info;
    info.attributes = 0x400;  // FILE_ATTRIBUTE_REPARSE_POINT
    info.reparse_tag = 0xA000000C;
    std::vector<uint8_t> out;
    CHECK(rtsc::rdpdr::EncodeFileInformation(0x23, info, out));
    CHECK_EQ(out.size(), static_cast<size_t>(8));
    if (out.size() < 8) return;
    CHECK_EQ(U32At(out, 0), 0x400u);
    CHECK_EQ(U32At(out, 4), 0xA000000Cu);
}

RTSC_TEST(rdpdr_file_information_rejects_unknown_class) {
    rtsc::rdpdr::FileInfo info;
    std::vector<uint8_t> out = {9, 9};
    CHECK(!rtsc::rdpdr::EncodeFileInformation(0x09, info, out));
    CHECK(out.empty());
}

}  // namespace
