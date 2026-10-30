// Device redirection virtual channel (rdpdr) client handler ([MS-RDPEFS] 3.1).

#include "rtsc/channel/rdpdr_client.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>

namespace rtsc::channel {

namespace {

// SMB2 create dispositions ([MS-SMB2] 2.2.13), used by DR_CREATE_REQ.
constexpr uint32_t kFileSupersede = 0x00000000;
constexpr uint32_t kFileOpen = 0x00000001;
constexpr uint32_t kFileCreate = 0x00000002;
constexpr uint32_t kFileOpenIf = 0x00000003;
constexpr uint32_t kFileOverwrite = 0x00000004;
constexpr uint32_t kFileOverwriteIf = 0x00000005;

// GENERAL_CAPS_SET.ioCode1: every RDPDR_IRP_MJ_* bit that the client must set.
constexpr uint32_t kRequiredIoCode1 = 0x00003FFF;

// DesiredAccess masks ([MS-SMB2] 2.2.13.1.1 / [MS-FSCC] 2.1.5) that grant
// data write access to a redirected file. MAXIMUM_ALLOWED stands for "every
// access the caller could have", so it must open the handle writable. DELETE
// and the metadata write bits (FILE_WRITE_EA / FILE_WRITE_ATTRIBUTES) are
// deliberately excluded: they do not grant data writes, and the client has no
// delete or set-information IRP to exercise them.
constexpr uint32_t kGenericAll = 0x10000000;
constexpr uint32_t kMaximumAllowed = 0x02000000;
constexpr uint32_t kGenericWrite = 0x40000000;
constexpr uint32_t kFileWriteData = 0x00000002;
constexpr uint32_t kFileAppendData = 0x00000004;
constexpr uint32_t kDataWriteMask = kGenericWrite | kGenericAll |
                                    kMaximumAllowed | kFileWriteData |
                                    kFileAppendData;

// [MS-SMB2] 2.2.13: FILE_CREATE must fail when the file already exists.
constexpr uint32_t kStatusObjectNameCollision = 0xC0000035;
// [MS-SMB2] 3.3.5.9: a missing leaf is OBJECT_NAME_NOT_FOUND, a missing
// intermediate directory is OBJECT_PATH_NOT_FOUND.
constexpr uint32_t kStatusObjectNameNotFound = 0xC0000034;
constexpr uint32_t kStatusObjectPathNotFound = 0xC000003A;
// [MS-RDPEFS] 2.2.1.5: operations on an unknown FileId.
constexpr uint32_t kStatusInvalidHandle = 0xC0000008;

// Maps a failed open onto the NTSTATUS the server expects: existence problems
// become NOT_FOUND, everything else (share/permission denial) stays
// ACCESS_DENIED.
uint32_t OpenFailureStatus(rdpdr::IFileSystem& fs, const std::string& local) {
    bool is_directory = false;
    if (fs.Stat(local, is_directory)) return rtsc::proto::kStatusAccessDenied;
    const std::string parent =
        std::filesystem::path(local).parent_path().string();
    if (!parent.empty() && parent != local &&
        !fs.Stat(parent, is_directory)) {
        return kStatusObjectPathNotFound;
    }
    return kStatusObjectNameNotFound;
}

// True when the server asked for write access in DR_CREATE_REQ.DesiredAccess.
bool RequestsWrite(uint32_t desired_access) {
    return (desired_access & kDataWriteMask) != 0;
}

size_t FindNoCase(const std::string& haystack, const std::string& needle) {
    if (needle.empty() || needle.size() > haystack.size()) {
        return std::string::npos;
    }
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            const unsigned char a =
                static_cast<unsigned char>(haystack[i + j]);
            const unsigned char b = static_cast<unsigned char>(needle[j]);
            if (std::tolower(a) != std::tolower(b)) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }
    return std::string::npos;
}

rtsc::proto::RdpdrInformation InformationFor(uint32_t disposition) {
    switch (disposition) {
        case kFileOpenIf: return rtsc::proto::kFileOpened;
        case kFileOverwriteIf: return rtsc::proto::kFileOverwritten;
        default: return rtsc::proto::kFileSuperseded;
    }
}

bool IsSeparator(char c) { return c == '\\' || c == '/'; }

// Windows reserves the CON/PRN/AUX/NUL/COM1-9/LPT1-9 device names, with or
// without an extension ("CON.txt" still names the console device).
bool IsReservedDeviceName(const std::string& component) {
    std::string base = component.substr(0, component.find('.'));
    while (!base.empty() && (base.back() == '.' || base.back() == ' ')) {
        base.pop_back();
    }
    for (char& c : base) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    if (base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
        base == "CONIN$" || base == "CONOUT$") {
        return true;
    }
    if (base.size() == 4 && base[0] == 'C' && base[1] == 'O' && base[2] == 'M' &&
        base[3] >= '1' && base[3] <= '9') {
        return true;
    }
    if (base.size() == 4 && base[0] == 'L' && base[1] == 'P' && base[2] == 'T' &&
        base[3] >= '1' && base[3] <= '9') {
        return true;
    }
    return false;
}

// A single path component that must not reach the host file system: parent
// traversal, a name Windows would rewrite (trailing dot or space), a
// character Windows forbids in a file name, or a reserved device name.
bool IsForbiddenComponent(const std::string& component) {
    if (component == ".") return false;
    if (component == "..") return true;
    const char last = component.back();
    if (last == '.' || last == ' ') return true;
    for (const char c : component) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7F) return true;
        if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' ||
            c == '>' || c == '|') {
            return true;
        }
    }
    return IsReservedDeviceName(component);
}

// Case-insensitive check that `candidate` is `root` or lies below it.
bool IsUnderRoot(const std::string& root, const std::string& candidate) {
    if (root.empty()) return false;
    std::string prefix = root;
    if (!IsSeparator(prefix.back())) prefix.push_back('\\');
    if (candidate.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (IsSeparator(prefix[i]) && IsSeparator(candidate[i])) continue;
        const unsigned char a = static_cast<unsigned char>(prefix[i]);
        const unsigned char b = static_cast<unsigned char>(candidate[i]);
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

}  // namespace

bool ResolvePathUnderRoot(const std::string& root,
                          const std::string& remote_relative,
                          std::string& out) {
    if (root.empty()) return false;

    // UNC ("\\server\share") and Win32 device ("\\.\", "\\?\") prefixes leave
    // the drive entirely; the redirector path is always rooted below the
    // drive, so more than one leading separator is rejected.
    size_t start = 0;
    while (start < remote_relative.size() &&
           IsSeparator(remote_relative[start])) {
        ++start;
    }
    if (start >= 2) return false;

    std::vector<std::string> parts;
    std::string current;
    for (size_t i = start; i <= remote_relative.size(); ++i) {
        const char c = i < remote_relative.size() ? remote_relative[i] : '\\';
        if (!IsSeparator(c)) {
            current.push_back(c);
            continue;
        }
        if (!current.empty()) {
            if (IsForbiddenComponent(current)) return false;
            if (current != ".") parts.push_back(current);
            current.clear();
        }
    }

    std::filesystem::path base(root);
    if (base.has_root_name() && !base.has_root_directory()) base += "\\";
    base = base.lexically_normal();
    if (parts.empty()) {
        // The redirected drive root itself (IRP_MJ_CREATE / QUERY_DIRECTORY on
        // "\\tsclient\C") must be accepted and normalized regardless of a
        // trailing separator or a trailing separator on the configured root.
        std::string root_text = base.string();
        while (root_text.size() > 3 && IsSeparator(root_text.back())) {
            root_text.pop_back();
        }
        out = root_text;
        return true;
    }
    std::filesystem::path resolved = base;
    for (const auto& part : parts) resolved /= part;
    std::string result = resolved.string();
    if (!IsUnderRoot(base.string(), result)) return false;

    // Lexical normalization cannot see reparse points (junctions/symlinks), so
    // resolve the real path and re-check containment. A missing suffix is
    // canonicalized through its deepest existing ancestor.
    std::error_code ec;
    const std::filesystem::path canonical =
        std::filesystem::weakly_canonical(resolved, ec);
    if (!ec) {
        const std::string canonical_text = canonical.string();
        if (!IsUnderRoot(std::filesystem::weakly_canonical(base, ec).string(),
                         canonical_text)) {
            return false;
        }
        result = canonical_text;
    } else {
        // The drive root itself must still resolve; if even that fails the
        // host cannot answer for the path.
        ec.clear();
        const std::filesystem::path canonical_base =
            std::filesystem::canonical(base, ec);
        if (!ec && !IsUnderRoot(canonical_base.string(), result)) return false;
    }
    out = result;
    return true;
}

RdpdrClient::RdpdrClient(rdpdr::IFileSystem* fs, std::vector<Device> devices,
                         std::string client_name, SendFn send)
    : fs_(fs),
      send_(std::move(send)),
      devices_(std::move(devices)),
      client_name_(std::move(client_name)) {}

RdpdrClient::~RdpdrClient() = default;

void RdpdrClient::OnChannelData(const uint8_t* data, size_t size) {
    if (data == nullptr || size < rtsc::proto::ChannelPduHeader::kSize) return;

    rtsc::proto::ChannelPduHeader header;
    if (rtsc::proto::ChannelPduHeader::parse(data, size, header) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    bool complete = false;
    std::vector<uint8_t> message;
    const rtsc::proto::Status st = reassembler_.Feed(
        header, data + rtsc::proto::ChannelPduHeader::kSize,
        size - rtsc::proto::ChannelPduHeader::kSize, complete, message);
    if (st != rtsc::proto::Status::Ok) {
        reassembler_.Reset();
        return;
    }
    if (!complete) return;
    OnMessage(message);
}

void RdpdrClient::OnMessage(const std::vector<uint8_t>& message) {
    rtsc::proto::RdpdrPdu pdu;
    if (rtsc::proto::RdpdrPdu::parse(message.data(), message.size(), pdu) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    switch (pdu.header.packet_id) {
        case rtsc::proto::kPakidCoreServerAnnounce:
            OnServerAnnounce(message);
            break;
        case rtsc::proto::kPakidCoreServerCapability:
            OnServerCapability(message);
            break;
        case rtsc::proto::kPakidCoreClientidConfirm:
            OnClientIdConfirm(message);
            break;
        case rtsc::proto::kPakidCoreDeviceReply:
            OnDeviceReply(message);
            break;
        case rtsc::proto::kPakidCoreDeviceIorequest:
            OnDeviceIoRequest(pdu.data);
            break;
        case rtsc::proto::kPakidCoreUserLoggedon:
            user_logged_on_ = true;
            break;
        default:
            break;
    }
}

void RdpdrClient::OnServerAnnounce(const std::vector<uint8_t>& message) {
    rtsc::proto::RdpdrServerAnnounce announce;
    if (rtsc::proto::RdpdrServerAnnounce::parse(message.data(), message.size(),
                                                announce) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    ++server_announce_count_;
    client_id_ = announce.client_id;
    version_major_ = announce.version_major;
    version_minor_ = announce.version_minor;

    rtsc::proto::RdpdrClientAnnounceReply reply;
    reply.version_major = 1;
    reply.version_minor = announce.version_minor;
    reply.client_id = announce.client_id;
    SendRaw(reply.encode());
    ++client_announce_count_;

    rtsc::proto::RdpdrClientNameRequest name;
    name.unicode_flag = 1;
    name.code_page = 0;
    name.computer_name = rtsc::proto::RdpdrEncodeUtf16(client_name_);
    name.computer_name_len = static_cast<uint32_t>(name.computer_name.size());
    SendRaw(name.encode());
    ++client_name_count_;

    phase_ = Phase::kAwaitClientIdConfirm;
}

void RdpdrClient::OnServerCapability(const std::vector<uint8_t>& message) {
    rtsc::proto::RdpdrCoreCapability caps;
    if (rtsc::proto::RdpdrCoreCapability::parse(message, caps) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    ++server_capability_count_;
}

void RdpdrClient::OnClientIdConfirm(const std::vector<uint8_t>& message) {
    rtsc::proto::RdpdrServerClientIdConfirm confirm;
    if (rtsc::proto::RdpdrServerClientIdConfirm::parse(message.data(),
                                                       message.size(),
                                                       confirm) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    client_id_ = confirm.client_id;
    SendRaw(BuildClientCapabilities());
    ++client_capability_count_;
    SendRaw(BuildDeviceListAnnounce());
    ++device_list_announce_count_;
    phase_ = Phase::kReady;
}

void RdpdrClient::OnDeviceReply(const std::vector<uint8_t>& message) {
    rtsc::proto::RdpdrDeviceReply reply;
    if (rtsc::proto::RdpdrDeviceReply::parse(message, reply) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    device_replies_[reply.device_id] = reply.result_code;
    ++device_reply_count_;
}

void RdpdrClient::OnDeviceIoRequest(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrDeviceIoRequest request;
    if (rtsc::proto::RdpdrDeviceIoRequest::parse(body, request) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    if (phase_ != Phase::kReady) {
        SendIoCompletion(request, rtsc::proto::kStatusUnsuccessful);
        return;
    }
    switch (request.major_function) {
        case rtsc::proto::kIrpMjCreate: OnCreate(body); break;
        case rtsc::proto::kIrpMjRead: OnRead(body); break;
        case rtsc::proto::kIrpMjWrite: OnWrite(body); break;
        case rtsc::proto::kIrpMjClose: OnClose(body); break;
        case rtsc::proto::kIrpMjDirectoryControl: OnQueryDirectory(body); break;
        case rtsc::proto::kIrpMjDeviceControl: OnControl(body); break;
        default:
            SendIoCompletion(request, rtsc::proto::kStatusUnsuccessful);
            break;
    }
}

void RdpdrClient::OnCreate(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrCreateReq req;
    if (rtsc::proto::RdpdrCreateReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    const std::string remote = req.path_string();
    last_remote_path_ = remote;
    const std::string local = MapRemotePath(remote, req.request.device_id);
    last_local_path_ = local;
    if (local.empty() || fs_ == nullptr) {
        SendIoCompletion(req.request, rtsc::proto::kStatusAccessDenied);
        return;
    }

    const uint32_t disposition = req.create_disposition;
    const bool for_write = RequestsWrite(req.desired_access);
    if (disposition == kFileCreate) {
        // Local TOCTOU window: a file created between Stat and Open is opened
        // rather than reported as a collision. Accepted for a local redirect.
        bool is_directory = false;
        if (fs_->Stat(local, is_directory)) {
            SendIoCompletion(req.request, kStatusObjectNameCollision);
            return;
        }
    }
    // [MS-SMB2] 2.2.13: SUPERSEDE/OVERWRITE/OVERWRITE_IF replace the existing
    // content, so the handle must be opened with truncation.
    const bool truncate = disposition == kFileSupersede ||
                          disposition == kFileOverwrite ||
                          disposition == kFileOverwriteIf ||
                          disposition == kFileCreate;
    bool create = disposition == kFileCreate || disposition == kFileSupersede ||
                  disposition == kFileOpenIf || disposition == kFileOverwriteIf;
    uint32_t file_id = 0;
    if (!fs_->Open(local, for_write, create, truncate, file_id) &&
        (disposition == kFileOpenIf || disposition == kFileOverwriteIf)) {
        create = true;
        fs_->Open(local, for_write, true, truncate, file_id);
    }
    if (file_id == 0) {
        SendIoCompletion(req.request, OpenFailureStatus(*fs_, local));
        return;
    }

    open_files_[file_id] = req.request.device_id;
    file_writable_[file_id] = for_write;
    rtsc::proto::RdpdrCreateRsp response;
    response.completion.device_id = req.request.device_id;
    response.completion.completion_id = req.request.completion_id;
    response.completion.io_status = rtsc::proto::kStatusSuccess;
    response.file_id = file_id;
    response.information = InformationFor(disposition);
    SendRaw(response.encode());
    ++create_count_;
}

void RdpdrClient::OnRead(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrReadReq req;
    if (rtsc::proto::RdpdrReadReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    if (open_files_.find(req.request.file_id) == open_files_.end()) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    if (req.length > rdpdr::kMaxReadLength) {
        SendIoCompletion(req.request, rtsc::proto::kStatusInvalidParameter);
        return;
    }
    std::vector<uint8_t> data;
    if (fs_ == nullptr ||
        !fs_->Read(req.request.file_id, req.offset, req.length, data)) {
        SendIoCompletion(req.request, rtsc::proto::kStatusUnsuccessful);
        return;
    }
    rtsc::proto::RdpdrReadRsp response;
    response.completion.device_id = req.request.device_id;
    response.completion.completion_id = req.request.completion_id;
    response.completion.io_status = rtsc::proto::kStatusSuccess;
    response.length = static_cast<uint32_t>(data.size());
    response.data = std::move(data);
    SendRaw(response.encode());
    ++read_count_;
}

void RdpdrClient::OnWrite(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrWriteReq req;
    if (rtsc::proto::RdpdrWriteReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    if (req.data.size() > rdpdr::kMaxReadLength) {
        SendIoCompletion(req.request, rtsc::proto::kStatusInvalidParameter);
        return;
    }
    const auto access = file_writable_.find(req.request.file_id);
    if (access == file_writable_.end()) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    if (!access->second) {
        SendIoCompletion(req.request, rtsc::proto::kStatusAccessDenied);
        return;
    }
    uint32_t written = 0;
    if (fs_ == nullptr ||
        !fs_->Write(req.request.file_id, req.offset, req.data, written)) {
        SendIoCompletion(req.request, rtsc::proto::kStatusUnsuccessful);
        return;
    }
    rtsc::proto::RdpdrWriteRsp response;
    response.completion.device_id = req.request.device_id;
    response.completion.completion_id = req.request.completion_id;
    response.completion.io_status = rtsc::proto::kStatusSuccess;
    response.length = written;
    SendRaw(response.encode());
    ++write_count_;
}

void RdpdrClient::OnClose(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrCloseReq req;
    if (rtsc::proto::RdpdrCloseReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    if (open_files_.erase(req.request.file_id) == 0) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    if (fs_ != nullptr) fs_->Close(req.request.file_id);
    file_writable_.erase(req.request.file_id);
    SendIoCompletion(req.request, rtsc::proto::kStatusSuccess);
    ++close_count_;
}

void RdpdrClient::OnQueryDirectory(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrQueryDirectoryReq req;
    if (rtsc::proto::RdpdrQueryDirectoryReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    if (open_files_.find(req.request.file_id) == open_files_.end()) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    std::vector<uint8_t> data;
    if (fs_ == nullptr ||
        !fs_->QueryDirectory(req.request.file_id, req.initial_query != 0,
                             req.fs_information_class, data)) {
        SendIoCompletion(req.request, rtsc::proto::kStatusNoMoreFiles);
        return;
    }
    rtsc::proto::RdpdrReadRsp response;
    response.completion.device_id = req.request.device_id;
    response.completion.completion_id = req.request.completion_id;
    response.completion.io_status = rtsc::proto::kStatusSuccess;
    response.length = static_cast<uint32_t>(data.size());
    response.data = std::move(data);
    SendRaw(response.encode());
    ++query_directory_count_;
}

void RdpdrClient::OnControl(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrControlReq req;
    if (rtsc::proto::RdpdrControlReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    SendIoCompletion(req.request, rtsc::proto::kStatusUnsuccessful);
    ++control_count_;
}

const RdpdrClient::Device* RdpdrClient::FindDevice(uint32_t device_id) const {
    for (const auto& device : devices_) {
        if (device.device_id == device_id) return &device;
    }
    return nullptr;
}

std::string RdpdrClient::MapRemotePath(const std::string& remote,
                                       uint32_t device_id) const {
    const Device* device = FindDevice(device_id);
    if (device == nullptr) return {};

    std::string letter = device->dos_name;
    if (!letter.empty() && letter.back() == ':') letter.pop_back();
    if (letter.empty()) return {};

    const std::string marker = "\\tsclient\\" + letter;
    size_t pos = FindNoCase(remote, marker);
    std::string rest;
    if (pos != std::string::npos) {
        rest = remote.substr(pos + marker.size());
    } else if (letter.size() == 1 &&
               FindNoCase(remote, letter + ":") == 0) {
        rest = remote.substr(letter.size() + 1);
    } else {
        return {};
    }

    const std::string root = device->local_root;
    if (root.empty()) return {};
    std::string out;
    if (!ResolvePathUnderRoot(root, rest, out)) return {};
    return out;
}

void RdpdrClient::SendRaw(const std::vector<uint8_t>& pdu) {
    if (!send_) return;
    for (const auto& chunk : rtsc::proto::FragmentChannelMessage(pdu)) {
        send_(chunk);
    }
}

void RdpdrClient::SendIoCompletion(
    const rtsc::proto::RdpdrDeviceIoRequest& request, uint32_t status) {
    rtsc::proto::RdpdrDeviceIoCompletion completion;
    completion.device_id = request.device_id;
    completion.completion_id = request.completion_id;
    completion.io_status = status;
    SendRaw(rtsc::proto::BuildRdpdrPdu(
        rtsc::proto::kPakidCoreDeviceIocompletion, completion.encode()));
}

std::vector<uint8_t> RdpdrClient::BuildClientCapabilities() const {
    rtsc::proto::RdpdrCoreCapability caps;
    caps.num_capabilities = 2;

    rtsc::proto::RdpdrGeneralCapsSet general_body;
    general_body.os_type = 0;
    general_body.os_version = 0;
    general_body.protocol_major_version = 1;
    general_body.protocol_minor_version = 0x000C;
    general_body.io_code1 = kRequiredIoCode1;
    general_body.extended_pdu = rtsc::proto::kRdpdrDeviceRemovePdus |
                                rtsc::proto::kRdpdrClientDisplayNamePdu |
                                rtsc::proto::kRdpdrUserLoggedonPdu;

    rtsc::proto::RdpdrCapabilitySet general;
    general.header.capability_type = rtsc::proto::kCapGeneralType;
    general.header.version = rtsc::proto::kGeneralCapabilityVersion02;
    general.data = general_body.encode(general.header.version);
    general.header.capability_length =
        static_cast<uint16_t>(rtsc::proto::RdpdrCapabilityHeader::kSize +
                              general.data.size());

    rtsc::proto::RdpdrCapabilitySet drive;
    drive.header.capability_type = rtsc::proto::kCapDriveType;
    drive.header.version = rtsc::proto::kDriveCapabilityVersion02;
    drive.header.capability_length =
        static_cast<uint16_t>(rtsc::proto::RdpdrCapabilityHeader::kSize);

    caps.capabilities.push_back(general);
    caps.capabilities.push_back(drive);
    return caps.encode();
}

std::vector<uint8_t> RdpdrClient::BuildDeviceListAnnounce() const {
    rtsc::proto::RdpdrDeviceListAnnounce list;
    list.device_count = static_cast<uint32_t>(devices_.size());
    for (const auto& device : devices_) {
        rtsc::proto::RdpdrDeviceAnnounce announce;
        announce.device_type = rtsc::proto::kRdpdrDtypFilesystem;
        announce.device_id = device.device_id;
        const size_t name_len =
            std::min(device.dos_name.size(),
                     static_cast<size_t>(
                         rtsc::proto::RdpdrDeviceAnnounce::kDosNameSize));
        std::memcpy(announce.preferred_dos_name.data(), device.dos_name.data(),
                    name_len);
        announce.device_data_length = 0;
        list.devices.push_back(announce);
    }
    return list.encode();
}

}  // namespace rtsc::channel
