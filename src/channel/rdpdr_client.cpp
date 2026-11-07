// Device redirection virtual channel (rdpdr) client handler ([MS-RDPEFS] 3.1).

#include "rtsc/channel/rdpdr_client.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>

#include "rtsc/smartcard/backend.h"

namespace rtsc::channel {

using rtsc::rdpdr::ResolvePathUnderRoot;

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
// deliberately excluded: they do not grant data writes, and a delete or rename
// is applied when the handle closes, so it needs no writable stream.
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
// [MS-FSCC] 2.4 set-information classes used by DR_DRIVE_SET_INFORMATION_REQ.
constexpr uint32_t kFileRenameInformation = 0x0000000A;
constexpr uint32_t kFileDispositionInformation = 0x0000000D;
// FileRenameInformation buffer: ReplaceIfExists(1) + Reserved(7) +
// RootDirectory(8) + FileNameLength(4) + FileName.
constexpr size_t kRenameFixedSize = 20;
// [MS-SMB2] 3.3.5.9: a missing leaf is OBJECT_NAME_NOT_FOUND, a missing
// intermediate directory is OBJECT_PATH_NOT_FOUND.
constexpr uint32_t kStatusObjectNameNotFound = 0xC0000034;
constexpr uint32_t kStatusObjectPathNotFound = 0xC000003A;
// [MS-RDPEFS] 2.2.1.5: operations on an unknown FileId.
constexpr uint32_t kStatusInvalidHandle = 0xC0000008;
// [MS-ERREF] STATUS_TOO_MANY_OPENED_FILES: the per-session open handle cap.
constexpr uint32_t kStatusTooManyOpenedFiles = 0xC0000041;
// Upper bound on concurrently open redirected handles per session.
constexpr size_t kMaxOpenFiles = 256;

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

// Decodes UTF-8 into UTF-16 code units (used for printer announce strings).
std::u16string Utf16FromUtf8(const std::string& text) {
    std::u16string out;
    size_t i = 0;
    while (i < text.size()) {
        uint32_t cp = static_cast<uint8_t>(text[i]);
        if (cp < 0x80) {
            ++i;
        } else if ((cp & 0xE0) == 0xC0 && i + 1 < text.size()) {
            cp = ((cp & 0x1F) << 6) |
                 (static_cast<uint8_t>(text[i + 1]) & 0x3F);
            i += 2;
        } else if ((cp & 0xF0) == 0xE0 && i + 2 < text.size()) {
            cp = ((cp & 0x0F) << 12) |
                 ((static_cast<uint8_t>(text[i + 1]) & 0x3F) << 6) |
                 (static_cast<uint8_t>(text[i + 2]) & 0x3F);
            i += 3;
        } else {
            cp = 0xFFFD;
            ++i;
        }
        if (cp <= 0xFFFF) {
            out.push_back(static_cast<char16_t>(cp));
        } else {
            cp -= 0x10000;
            out.push_back(static_cast<char16_t>(0xD800 + (cp >> 10)));
            out.push_back(static_cast<char16_t>(0xDC00 + (cp & 0x3FF)));
        }
    }
    return out;
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

}  // namespace

RdpdrClient::RdpdrClient(rdpdr::IFileSystem* fs, std::vector<Device> devices,
                         std::string client_name, SendFn send)
    : fs_(fs),
      send_(std::move(send)),
      devices_(std::move(devices)),
      client_name_(std::move(client_name)) {
    // S4: a device whose configured local_root does not exist or is not a
    // directory must never be served. Recording it up front keeps
    // ResolvePathUnderRoot from fabricating a lexical path underneath a root
    // the host does not know: the device is disabled (empty root) and counted.
    for (auto& device : devices_) {
        std::error_code ec;
        if (device.local_root.empty() ||
            !std::filesystem::is_directory(device.local_root, ec)) {
            ++device_root_invalid_count_;
            device.local_root.clear();
        }
    }
}

RdpdrClient::~RdpdrClient() { SetAsyncSmartCard(false); }

void RdpdrClient::SetAsyncSmartCard(bool enable) {
    if (enable == scard_async_) return;
    if (enable) {
        scard_async_ = true;
        {
            std::lock_guard<std::mutex> lock(scard_mutex_);
            scard_stop_ = false;
        }
        scard_worker_ = std::thread([this] { SmartCardWorkerLoop(); });
        return;
    }
    // The worker may be blocked inside a backend call (GetStatusChange waits
    // for the whole request timeout), so this join can block. Queued calls are
    // still executed and their completions are drained below.
    scard_async_ = false;
    {
        std::lock_guard<std::mutex> lock(scard_mutex_);
        scard_stop_ = true;
    }
    scard_cv_.notify_all();
    if (scard_worker_.joinable()) scard_worker_.join();
    PollSmartCard();
}

bool RdpdrClient::PollSmartCard() {
    std::deque<ScardCompletion> done;
    {
        std::lock_guard<std::mutex> lock(scard_mutex_);
        done.swap(scard_done_);
    }
    bool sent = false;
    for (const auto& completion : done) {
        // A completion produced for the old session must not be written to
        // the new transport (D18: reject stale messages).
        if (completion.generation != scard_generation_) continue;
        CompleteSmartCard(completion);
        sent = true;
    }
    return sent;
}

void RdpdrClient::SmartCardWorkerLoop() {
    for (;;) {
        ScardJob job;
        {
            std::unique_lock<std::mutex> lock(scard_mutex_);
            scard_cv_.wait(
                lock, [this] { return scard_stop_ || !scard_queue_.empty(); });
            if (scard_stop_ && scard_queue_.empty()) return;
            job = std::move(scard_queue_.front());
            scard_queue_.pop_front();
        }
        ScardCompletion completion = BuildSmartCardCompletion(job.request);
        completion.generation = job.generation;
        {
            std::lock_guard<std::mutex> lock(scard_mutex_);
            scard_done_.push_back(std::move(completion));
        }
    }
}

void RdpdrClient::EnableSmartCard(::rtsc::smartcard::ISmartCardBackend* backend) {
    if (backend == nullptr) {
        scard_ = nullptr;
        scard_device_id_ = 0;
        return;
    }
    scard_ = backend;
    // [MS-RDPEFS] 2.2.1.3: DeviceId is chosen by the client and must be unique
    // within the announce. Reuse the drive numbering space and pick one past
    // the highest id already in use.
    uint32_t next = 1;
    for (const auto& device : devices_) {
        next = std::max(next, device.device_id + 1);
    }
    scard_device_id_ = next;
}

void RdpdrClient::EnableSerial(rdpdr::ISerialBackend* backend) {
    serial_ = backend;
}

void RdpdrClient::EnablePrinter(rdpdr::IPrinterBackend* backend) {
    printer_ = backend;
}

bool RdpdrClient::RemoveDevice(uint32_t device_id) {
    if (phase_ != Phase::kReady) return false;
    if (scard_ != nullptr && device_id == scard_device_id_) {
        // Stop the worker before dropping the backend pointer: the worker
        // reads scard_ on its own thread.
        SetAsyncSmartCard(false);
        scard_ = nullptr;
        scard_device_id_ = 0;
    } else {
        const auto it = std::find_if(
            devices_.begin(), devices_.end(),
            [device_id](const Device& d) { return d.device_id == device_id; });
        if (it == devices_.end()) return false;
        devices_.erase(it);
    }
    // Close every open file that belongs to the removed device: the server
    // will not send DR_CLOSE_REQ for handles it can no longer see.
    for (auto it = open_files_.begin(); it != open_files_.end();) {
        if (it->second == device_id) {
            if (IsPrinterHandle(it->first)) {
                if (printer_ != nullptr) {
                    printer_->CloseJob(printer_handles_[it->first]);
                }
                printer_handles_.erase(it->first);
                free_printer_file_ids_.push_back(it->first);
            } else if (IsSerialHandle(it->first)) {
                if (serial_ != nullptr) {
                    serial_->Close(serial_handles_[it->first]);
                }
                serial_handles_.erase(it->first);
                free_serial_file_ids_.push_back(it->first);
            } else {
                if (fs_ != nullptr) fs_->Close(it->first);
                file_writable_.erase(it->first);
                lock_table_.ReleaseFile(it->first);
                ApplyPendingFileOperation(it->first);
            }
            it = open_files_.erase(it);
        } else {
            ++it;
        }
    }
    device_replies_.erase(device_id);
    rtsc::proto::RdpdrDeviceListRemove remove;
    remove.device_count = 1;
    remove.device_ids.push_back(device_id);
    SendRaw(remove.encode());
    ++device_remove_count_;
    return true;
}

void RdpdrClient::Reset() {
    // The reassembler is reset first: any in-flight packet must be dropped
    // before the state machine resets.
    reassembler_.Reset();
    // Smart card calls belong to the transport that was just replaced: drop
    // the queued requests and answers, and tag later completions of in-flight
    // calls with the old generation so PollSmartCard() discards them (D18).
    ++scard_generation_;
    {
        std::lock_guard<std::mutex> lock(scard_mutex_);
        scard_queue_.clear();
        scard_done_.clear();
    }
    // The phase is reset to kAwaitServerAnnounce, which drops every pending
    // channel id and file handle. The client name and capability exchange
    // states are cleared; the server's capabilities and device list remain.
    phase_ = Phase::kAwaitServerAnnounce;
    client_id_ = 0;
    version_major_ = 0;
    version_minor_ = 0;
    user_logged_on_ = false;
    device_replies_.clear();
    // Close every file the previous session had open: the handles belong to
    // this client, not to the transport, so dropping the map without closing
    // would leak them.
    if (fs_ != nullptr) {
        for (const auto& entry : open_files_) {
            if (!IsSerialHandle(entry.first)) fs_->Close(entry.first);
        }
    }
    if (serial_ != nullptr) {
        for (const auto& entry : serial_handles_) {
            serial_->Close(entry.second);
        }
    }
    if (printer_ != nullptr) {
        for (const auto& entry : printer_handles_) {
            printer_->CloseJob(entry.second);
        }
    }
    serial_handles_.clear();
    printer_handles_.clear();
    free_serial_file_ids_.clear();
    free_printer_file_ids_.clear();
    open_files_.clear();
    file_writable_.clear();
    // Pending renames/deletes from the replaced session are dropped, not
    // applied: a transport reset is not a successful close.
    file_paths_.clear();
    pending_delete_.clear();
    pending_rename_.clear();
    lock_table_.Clear();
    client_name_.clear();
    server_announce_count_ = 0;
    server_capability_count_ = 0;
    client_announce_count_ = 0;
    client_name_count_ = 0;
    client_capability_count_ = 0;
    device_list_announce_count_ = 0;
    query_information_count_ = 0;
    set_information_count_ = 0;
    set_volume_count_ = 0;
    notify_change_count_ = 0;
    lock_control_count_ = 0;
    serial_io_count_ = 0;
    printer_io_count_ = 0;
    smartcard_count_ = 0;
    smartcard_reject_count_ = 0;
    last_scard_ioctl_name_.clear();
    last_remote_path_.clear();
    last_local_path_.clear();
    device_root_invalid_count_ = 0;
    // The configuration (file system, device list, smart card backend) is kept,
    // so these fields stay as-is:
    //   fs_
    //   devices_
    //   scard_
    //   scard_device_id_
}

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
        case rtsc::proto::kIrpMjDirectoryControl:
            switch (request.minor_function) {
                case rtsc::proto::kIrpMnQueryDirectory:
                    OnQueryDirectory(body);
                    break;
                case rtsc::proto::kIrpMnNotifyChangeDirectory:
                    OnNotifyChangeDirectory(body);
                    break;
                default:
                    SendIoCompletion(
                        request, rtsc::proto::kStatusInvalidDeviceRequest);
                    break;
            }
            break;
        case rtsc::proto::kIrpMjDeviceControl: OnControl(body); break;
    case rtsc::proto::kIrpMjQueryVolumeInformation: OnQueryVolume(body); break;
        case rtsc::proto::kIrpMjQueryInformation: OnQueryInformation(body); break;
        case rtsc::proto::kIrpMjSetInformation: OnSetInformation(body); break;
        case rtsc::proto::kIrpMjSetVolumeInformation:
            OnSetVolumeInformation(body);
            break;
        case rtsc::proto::kIrpMjLockControl: OnLockControl(body); break;
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
    if (IsPrinterDevice(req.request.device_id)) {
        const Device* device = FindDevice(req.request.device_id);
        if (printer_ == nullptr || device == nullptr ||
            open_files_.size() >= kMaxOpenFiles) {
            SendIoCompletion(req.request, rtsc::proto::kStatusAccessDenied);
            return;
        }
        const uint32_t job = printer_->OpenJob(device->printer_name);
        if (job == 0) {
            SendIoCompletion(req.request, rtsc::proto::kStatusAccessDenied);
            return;
        }
        uint32_t file_id = 0;
        if (!free_printer_file_ids_.empty()) {
            file_id = free_printer_file_ids_.back();
            free_printer_file_ids_.pop_back();
        } else {
            file_id = next_printer_file_id_++;
        }
        open_files_[file_id] = req.request.device_id;
        printer_handles_[file_id] = job;
        rtsc::proto::RdpdrCreateRsp response;
        response.completion.device_id = req.request.device_id;
        response.completion.completion_id = req.request.completion_id;
        response.completion.io_status = rtsc::proto::kStatusSuccess;
        response.file_id = file_id;
        response.information = InformationFor(req.create_disposition);
        SendRaw(response.encode());
        ++create_count_;
        return;
    }
    if (IsSerialDevice(req.request.device_id)) {
        const Device* device = FindDevice(req.request.device_id);
        if (serial_ == nullptr || device == nullptr ||
            open_files_.size() >= kMaxOpenFiles) {
            SendIoCompletion(req.request, rtsc::proto::kStatusAccessDenied);
            return;
        }
        const uint32_t handle = serial_->Open(device->dos_name);
        if (handle == 0) {
            SendIoCompletion(req.request, rtsc::proto::kStatusAccessDenied);
            return;
        }
        uint32_t file_id = 0;
        if (!free_serial_file_ids_.empty()) {
            file_id = free_serial_file_ids_.back();
            free_serial_file_ids_.pop_back();
        } else {
            file_id = next_serial_file_id_++;
        }
        open_files_[file_id] = req.request.device_id;
        serial_handles_[file_id] = handle;
        rtsc::proto::RdpdrCreateRsp response;
        response.completion.device_id = req.request.device_id;
        response.completion.completion_id = req.request.completion_id;
        response.completion.io_status = rtsc::proto::kStatusSuccess;
        response.file_id = file_id;
        response.information = InformationFor(req.create_disposition);
        SendRaw(response.encode());
        ++create_count_;
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
    if (open_files_.size() >= kMaxOpenFiles) {
        SendIoCompletion(req.request, kStatusTooManyOpenedFiles);
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
    file_paths_[file_id] = local;
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
    const auto open_entry = open_files_.find(req.request.file_id);
    if (open_entry == open_files_.end() ||
        open_entry->second != req.request.device_id) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    if (req.length > rdpdr::kMaxReadLength) {
        SendIoCompletion(req.request, rtsc::proto::kStatusInvalidParameter);
        return;
    }
    if (IsSerialHandle(req.request.file_id)) {
        std::vector<uint8_t> data;
        if (serial_ == nullptr ||
            !serial_->Read(serial_handles_[req.request.file_id], req.length,
                           data)) {
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
        ++serial_io_count_;
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
    const auto open_entry = open_files_.find(req.request.file_id);
    if (open_entry == open_files_.end() ||
        open_entry->second != req.request.device_id) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    if (IsPrinterHandle(req.request.file_id)) {
        uint32_t written = 0;
        if (printer_ == nullptr ||
            !printer_->Write(printer_handles_[req.request.file_id], req.data,
                             written)) {
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
        ++printer_io_count_;
        return;
    }
    if (IsSerialHandle(req.request.file_id)) {
        uint32_t written = 0;
        if (serial_ == nullptr ||
            !serial_->Write(serial_handles_[req.request.file_id], req.data,
                            written)) {
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
        ++serial_io_count_;
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
    const auto open_entry = open_files_.find(req.request.file_id);
    if (open_entry == open_files_.end() ||
        open_entry->second != req.request.device_id) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    if (IsPrinterHandle(req.request.file_id)) {
        if (printer_ != nullptr) {
            printer_->CloseJob(printer_handles_[req.request.file_id]);
        }
        printer_handles_.erase(req.request.file_id);
        free_printer_file_ids_.push_back(req.request.file_id);
        open_files_.erase(req.request.file_id);
        SendIoCompletion(req.request, rtsc::proto::kStatusSuccess);
        ++close_count_;
        return;
    }
    if (IsSerialHandle(req.request.file_id)) {
        if (serial_ != nullptr) {
            serial_->Close(serial_handles_[req.request.file_id]);
        }
        serial_handles_.erase(req.request.file_id);
        free_serial_file_ids_.push_back(req.request.file_id);
        open_files_.erase(req.request.file_id);
        SendIoCompletion(req.request, rtsc::proto::kStatusSuccess);
        ++close_count_;
        return;
    }
    open_files_.erase(req.request.file_id);
    if (fs_ != nullptr) fs_->Close(req.request.file_id);
    file_writable_.erase(req.request.file_id);
    lock_table_.ReleaseFile(req.request.file_id);
    ApplyPendingFileOperation(req.request.file_id);
    SendIoCompletion(req.request, rtsc::proto::kStatusSuccess);
    ++close_count_;
}

void RdpdrClient::OnQueryDirectory(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrQueryDirectoryReq req;
    if (rtsc::proto::RdpdrQueryDirectoryReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    const auto open_entry = open_files_.find(req.request.file_id);
    if (open_entry == open_files_.end() ||
        open_entry->second != req.request.device_id) {
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

void RdpdrClient::OnNotifyChangeDirectory(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrNotifyChangeDirectoryReq req;
    if (rtsc::proto::RdpdrNotifyChangeDirectoryReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    const auto open_entry = open_files_.find(req.request.file_id);
    if (open_entry == open_files_.end() ||
        open_entry->second != req.request.device_id) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    // Directory change notification is not implemented. Fail closed with a
    // completion so the server does not wait for one, instead of silently
    // dropping the request (which used to be misparsed as a query).
    SendIoCompletion(req.request, rtsc::proto::kStatusNotSupported);
    ++notify_change_count_;
}

void RdpdrClient::OnQueryVolume(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrQueryVolumeReq req;
    if (rtsc::proto::RdpdrQueryVolumeReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    const auto open_entry = open_files_.find(req.request.file_id);
    if (open_entry == open_files_.end() ||
        open_entry->second != req.request.device_id) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    std::vector<uint8_t> out;
    if (fs_ == nullptr ||
        !fs_->QueryVolume(req.request.file_id, req.fs_information_class,
                          out)) {
        SendIoCompletion(req.request, rtsc::proto::kStatusNotSupported);
        return;
    }
    // DR_DRIVE_QUERY_VOLUME_INFORMATION_RSP ([MS-RDPEFS] 2.2.3.4.6) is a
    // DeviceIoReply followed by Length + Buffer, the same layout as a device
    // control completion.
    SendControlCompletion(req.request, rtsc::proto::kStatusSuccess, out);
    ++query_volume_count_;
}

void RdpdrClient::OnQueryInformation(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrQueryInformationReq req;
    if (rtsc::proto::RdpdrQueryInformationReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    const auto open_entry = open_files_.find(req.request.file_id);
    if (open_entry == open_files_.end() ||
        open_entry->second != req.request.device_id) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    std::vector<uint8_t> out;
    if (fs_ == nullptr ||
        !fs_->QueryInformation(req.request.file_id,
                               req.fs_information_class, out)) {
        SendIoCompletion(req.request, rtsc::proto::kStatusNotSupported);
        return;
    }
    // DR_DRIVE_QUERY_INFORMATION_RSP ([MS-RDPEFS] 2.2.3.4.8) is a
    // DeviceIoReply followed by Length + Buffer.
    SendControlCompletion(req.request, rtsc::proto::kStatusSuccess, out);
    ++query_information_count_;
}

void RdpdrClient::OnSetVolumeInformation(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrSetVolumeReq req;
    if (rtsc::proto::RdpdrSetVolumeReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    const auto open_entry = open_files_.find(req.request.file_id);
    if (open_entry == open_files_.end() ||
        open_entry->second != req.request.device_id) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    constexpr uint32_t kFileFsLabelInformation = 0x00000002;
    if (req.fs_information_class != kFileFsLabelInformation) {
        SendSetVolumeCompletion(req.request, rtsc::proto::kStatusNotSupported,
                                req.length);
        return;
    }
    // [MS-FSCC] 2.5.5 FileFsLabelInformation: VolumeLabelLength(4) followed
    // by the UTF-16 label, which may be NUL-terminated or space padded.
    if (req.buffer.size() < 4) {
        SendSetVolumeCompletion(req.request,
                                rtsc::proto::kStatusInvalidParameter,
                                req.length);
        return;
    }
    const uint32_t label_length =
        static_cast<uint32_t>(req.buffer[0]) |
        (static_cast<uint32_t>(req.buffer[1]) << 8) |
        (static_cast<uint32_t>(req.buffer[2]) << 16) |
        (static_cast<uint32_t>(req.buffer[3]) << 24);
    if (label_length > req.buffer.size() - 4) {
        SendSetVolumeCompletion(req.request,
                                rtsc::proto::kStatusInvalidParameter,
                                req.length);
        return;
    }
    std::string label =
        rtsc::proto::RdpdrDecodeUtf16(req.buffer.data() + 4, label_length);
    while (!label.empty() && label.back() == ' ') label.pop_back();
    if (fs_ == nullptr || !fs_->SetVolumeName(req.request.file_id, label)) {
        SendSetVolumeCompletion(req.request, rtsc::proto::kStatusAccessDenied,
                                req.length);
        return;
    }
    SendSetVolumeCompletion(req.request, rtsc::proto::kStatusSuccess,
                            req.length);
    ++set_volume_count_;
}

void RdpdrClient::OnSetInformation(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrSetInformationReq req;
    if (rtsc::proto::RdpdrSetInformationReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    const auto open_entry = open_files_.find(req.request.file_id);
    if (open_entry == open_files_.end() ||
        open_entry->second != req.request.device_id) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    const auto path_entry = file_paths_.find(req.request.file_id);
    if (path_entry == file_paths_.end()) {
        SendIoCompletion(req.request, rtsc::proto::kStatusUnsuccessful);
        return;
    }

    if (req.fs_information_class == kFileDispositionInformation) {
        // [MS-FSCC] 2.4.4: one BOOLEAN DeleteFile.
        if (req.buffer.empty()) {
            SendIoCompletion(req.request, rtsc::proto::kStatusInvalidParameter);
            return;
        }
        if (req.buffer[0] != 0) {
            pending_delete_.insert(req.request.file_id);
            pending_rename_.erase(req.request.file_id);
        } else {
            pending_delete_.erase(req.request.file_id);
        }
        SendControlCompletion(req.request, rtsc::proto::kStatusSuccess, {});
        ++set_information_count_;
        return;
    }

    if (req.fs_information_class == kFileRenameInformation) {
        if (req.buffer.size() < kRenameFixedSize) {
            SendIoCompletion(req.request, rtsc::proto::kStatusInvalidParameter);
            return;
        }
        const bool replace = req.buffer[0] != 0;
        uint64_t root_directory = 0;
        for (int i = 0; i < 8; ++i) {
            root_directory |= static_cast<uint64_t>(req.buffer[8 + i])
                              << (8 * i);
        }
        if (root_directory != 0) {
            // A name relative to an open directory handle is not supported:
            // the server must send a share-root-relative name.
            SendIoCompletion(req.request, rtsc::proto::kStatusNotSupported);
            return;
        }
        uint32_t name_length = 0;
        for (int i = 0; i < 4; ++i) {
            name_length |= static_cast<uint32_t>(req.buffer[16 + i]) << (8 * i);
        }
        if (name_length == 0 || (name_length & 1) != 0 ||
            name_length > req.buffer.size() - kRenameFixedSize) {
            SendIoCompletion(req.request, rtsc::proto::kStatusInvalidParameter);
            return;
        }
        const std::string remote = rtsc::proto::RdpdrDecodeUtf16(
            req.buffer.data() + kRenameFixedSize, name_length);
        const std::string local =
            MapRemotePath(remote, req.request.device_id);
        if (local.empty()) {
            SendIoCompletion(req.request, rtsc::proto::kStatusAccessDenied);
            return;
        }
        if (local == path_entry->second) {
            // Renaming to the same name is a no-op success.
            pending_rename_.erase(req.request.file_id);
            SendControlCompletion(req.request, rtsc::proto::kStatusSuccess, {});
            ++set_information_count_;
            return;
        }
        if (!replace) {
            bool is_directory = false;
            if (fs_ != nullptr && fs_->Stat(local, is_directory)) {
                SendIoCompletion(req.request, kStatusObjectNameCollision);
                return;
            }
        }
        PendingRename rename;
        rename.path = local;
        rename.replace = replace;
        pending_rename_[req.request.file_id] = rename;
        pending_delete_.erase(req.request.file_id);
        SendControlCompletion(req.request, rtsc::proto::kStatusSuccess, {});
        ++set_information_count_;
        return;
    }

    SendIoCompletion(req.request, rtsc::proto::kStatusNotSupported);
}

void RdpdrClient::OnLockControl(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrLockReq req;
    if (rtsc::proto::RdpdrLockReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    const auto open_entry = open_files_.find(req.request.file_id);
    if (open_entry == open_files_.end() ||
        open_entry->second != req.request.device_id) {
        SendIoCompletion(req.request, kStatusInvalidHandle);
        return;
    }
    const bool is_lock = req.operation == rtsc::proto::kRdpLowioOpSharedLock ||
                         req.operation == rtsc::proto::kRdpLowioOpExclusiveLock;
    const bool is_unlock = req.operation == rtsc::proto::kRdpLowioOpUnlock ||
                           req.operation ==
                               rtsc::proto::kRdpLowioOpUnlockMultiple;
    if ((!is_lock && !is_unlock) || req.locks.empty()) {
        SendIoCompletion(req.request, rtsc::proto::kStatusInvalidParameter);
        return;
    }
    std::vector<rdpdr::LockTable::Range> ranges;
    ranges.reserve(req.locks.size());
    for (const auto& lock : req.locks) {
        rdpdr::LockTable::Range range;
        range.offset = lock.offset;
        range.length = lock.length;
        ranges.push_back(range);
    }
    if (is_lock) {
        const bool exclusive =
            req.operation == rtsc::proto::kRdpLowioOpExclusiveLock;
        if (lock_table_.LockMany(req.request.file_id, ranges, exclusive) !=
            rdpdr::LockTable::Result::kOk) {
            SendLockCompletion(req.request, rtsc::proto::kStatusLockNotGranted);
            return;
        }
        SendLockCompletion(req.request, rtsc::proto::kStatusSuccess);
        ++lock_control_count_;
        return;
    }
    if (lock_table_.UnlockMany(req.request.file_id, ranges) !=
        rdpdr::LockTable::Result::kOk) {
        SendLockCompletion(req.request, rtsc::proto::kStatusRangeNotLocked);
        return;
    }
    SendLockCompletion(req.request, rtsc::proto::kStatusSuccess);
    ++lock_control_count_;
}

void RdpdrClient::ApplyPendingFileOperation(uint32_t file_id) {
    const auto path_entry = file_paths_.find(file_id);
    if (path_entry == file_paths_.end()) {
        pending_delete_.erase(file_id);
        pending_rename_.erase(file_id);
        return;
    }
    if (fs_ != nullptr) {
        if (pending_delete_.erase(file_id) > 0) {
            fs_->Delete(path_entry->second);
        } else {
            const auto rename_entry = pending_rename_.find(file_id);
            if (rename_entry != pending_rename_.end()) {
                fs_->Rename(path_entry->second, rename_entry->second.path,
                            rename_entry->second.replace);
                pending_rename_.erase(rename_entry);
            }
        }
    } else {
        pending_delete_.erase(file_id);
        pending_rename_.erase(file_id);
    }
    file_paths_.erase(path_entry);
}

void RdpdrClient::OnControl(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrControlReq req;
    if (rtsc::proto::RdpdrControlReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    if (scard_ != nullptr && req.request.device_id == scard_device_id_) {
        OnSmartCardControl(req);
        return;
    }
    if (IsPrinterHandle(req.request.file_id)) {
        // Printer IOCTLs are not implemented yet.
        SendIoCompletion(req.request, rtsc::proto::kStatusNotSupported);
        ++control_count_;
        return;
    }
    if (IsSerialHandle(req.request.file_id)) {
        std::vector<uint8_t> output;
        if (serial_ == nullptr ||
            !serial_->Control(serial_handles_[req.request.file_id],
                              req.io_control_code, req.input_buffer, output)) {
            SendIoCompletion(req.request, rtsc::proto::kStatusNotSupported);
            ++control_count_;
            return;
        }
        SendControlCompletion(req.request, rtsc::proto::kStatusSuccess, output);
        ++control_count_;
        ++serial_io_count_;
        return;
    }
    SendIoCompletion(req.request, rtsc::proto::kStatusUnsuccessful);
    ++control_count_;
}

// [MS-RDPESC] 3.1.4: the server drives every smart card operation through
// IRP_MJ_DEVICE_CONTROL on the SCARD device. The InputBuffer is an NDR-encoded
// SCARD_IOCTL_* call; the OutputBuffer is the matching *_Return structure.
//
// A malformed payload never reaches the backend: the handler answers
// STATUS_UNSUCCESSFUL with an empty OutputBuffer, matching FreeRDP
// smartcard_main.c (decode failure -> irp->IoStatus = STATUS_UNSUCCESSFUL and
// no output). A status the backend returns is carried in ReturnCode with
// IoStatus STATUS_SUCCESS, as [MS-RDPESC] 2.2.3 requires.
void RdpdrClient::OnSmartCardControl(const proto::RdpdrControlReq& req) {
    last_scard_ioctl_name_ = proto::ScardIoctlName(req.io_control_code);
    if (scard_async_) {
        {
            std::lock_guard<std::mutex> lock(scard_mutex_);
            scard_queue_.push_back({req, scard_generation_});
        }
        scard_cv_.notify_one();
        return;
    }
    ScardCompletion completion = BuildSmartCardCompletion(req);
    completion.generation = scard_generation_;
    CompleteSmartCard(completion);
}

void RdpdrClient::CompleteSmartCard(const ScardCompletion& completion) {
    if (completion.rejected) {
        ++smartcard_reject_count_;
    } else {
        ++smartcard_count_;
    }
    SendScardCompletion(completion);
}

RdpdrClient::ScardCompletion RdpdrClient::BuildSmartCardCompletion(
    const proto::RdpdrControlReq& req) {
    const uint32_t code = req.io_control_code;

    proto::ScardCall call;
    if (proto::ParseScardCall(code, req.input_buffer.data(),
                              req.input_buffer.size(), call) !=
        proto::Status::Ok) {
        return {req.request, proto::kStatusUnsuccessful, {}, true};
    }

    const auto scard = static_cast<proto::ScardIoctl>(call.code);
    proto::ScardReturn ret;
    uint32_t output_limit = req.output_buffer_length;

    switch (scard) {
        case proto::ScardIoctl::kEstablishContext: {
            ret.return_code = scard_->EstablishContext(call.scope,
                                                       ret.context.bytes);
            break;
        }
        case proto::ScardIoctl::kReleaseContext: {
            ret.return_code = scard_->ReleaseContext(call.context.bytes);
            break;
        }
        case proto::ScardIoctl::kIsValidContext: {
            ret.return_code = scard_->IsValidContext(call.context.bytes);
            break;
        }
        case proto::ScardIoctl::kListReaderGroupsA: {
            std::vector<uint8_t> groups;
            ret.return_code =
                scard_->ListReaderGroups(call.context.bytes, groups);
            if (ret.return_code == 0) ret.multi_string = std::move(groups);
            break;
        }
        case proto::ScardIoctl::kListReaderGroupsW: {
            std::vector<uint8_t> groups;
            ret.return_code =
                scard_->ListReaderGroupsW(call.context.bytes, groups);
            if (ret.return_code == 0) ret.multi_string = std::move(groups);
            break;
        }
        case proto::ScardIoctl::kListReadersA: {
            std::vector<uint8_t> readers;
            ret.return_code = scard_->ListReaders(call.context.bytes,
                                                  call.groups_msz, readers);
            if (ret.return_code == 0) ret.multi_string = std::move(readers);
            break;
        }
        case proto::ScardIoctl::kListReadersW: {
            std::vector<uint8_t> readers;
            ret.return_code = scard_->ListReadersW(call.context.bytes,
                                                   call.groups_msz, readers);
            if (ret.return_code == 0) ret.multi_string = std::move(readers);
            break;
        }
        case proto::ScardIoctl::kGetStatusChangeW: {
            std::vector<smartcard::ScardReaderStateW> states;
            states.reserve(call.reader_states_w.size());
            for (const auto& st : call.reader_states_w) {
                smartcard::ScardReaderStateW out;
                out.reader = st.reader;
                out.current_state = st.current_state;
                states.push_back(std::move(out));
            }
            ret.return_code = scard_->GetStatusChangeW(
                call.context.bytes, call.timeout, states);
            if (ret.return_code == 0 ||
                ret.return_code == smartcard::kScardETimeout) {
                ret.reader_states.clear();
                for (const auto& st : states) {
                    proto::ScardReaderStateReturn out;
                    out.current_state = st.current_state;
                    out.event_state = st.event_state;
                    out.atr = st.atr;
                    ret.reader_states.push_back(std::move(out));
                }
            }
            break;
        }
        case proto::ScardIoctl::kLocateCardsW: {
            std::vector<smartcard::ScardReaderStateW> states;
            states.reserve(call.reader_states_w.size());
            for (const auto& st : call.reader_states_w) {
                smartcard::ScardReaderStateW out;
                out.reader = st.reader;
                out.current_state = st.current_state;
                states.push_back(std::move(out));
            }
            ret.return_code =
                scard_->LocateCardsW(call.context.bytes, call.cards_msz, states);
            ret.reader_states.clear();
            for (const auto& st : states) {
                proto::ScardReaderStateReturn out;
                out.current_state = st.current_state;
                out.event_state = st.event_state;
                out.atr = st.atr;
                ret.reader_states.push_back(std::move(out));
            }
            break;
        }
        case proto::ScardIoctl::kLocateCardsA: {
            std::vector<smartcard::ScardReaderState> states;
            states.reserve(call.reader_states.size());
            for (const auto& st : call.reader_states) {
                smartcard::ScardReaderState out;
                out.reader = st.reader;
                out.current_state = st.current_state;
                states.push_back(std::move(out));
            }
            ret.return_code =
                scard_->LocateCards(call.context.bytes, call.cards_msz, states);
            // Like FreeRDP smartcard_LocateCardsA_Call, the reader states are
            // copied back even on failure; the encoder drops them when the
            // ReturnCode is nonzero.
            ret.reader_states.clear();
            for (const auto& st : states) {
                proto::ScardReaderStateReturn out;
                out.current_state = st.current_state;
                out.event_state = st.event_state;
                out.atr = st.atr;
                ret.reader_states.push_back(std::move(out));
            }
            break;
        }
        case proto::ScardIoctl::kLocateCardsByAtrW: {
            std::vector<smartcard::ScardReaderStateW> states;
            states.reserve(call.reader_states_w.size());
            for (const auto& st : call.reader_states_w) {
                smartcard::ScardReaderStateW out;
                out.reader = st.reader;
                out.current_state = st.current_state;
                states.push_back(std::move(out));
            }
            std::vector<smartcard::ScardAtrMask> masks;
            masks.reserve(call.atr_masks.size());
            for (const auto& m : call.atr_masks) {
                smartcard::ScardAtrMask out;
                out.atr = m.atr;
                out.mask = m.mask;
                masks.push_back(std::move(out));
            }
            ret.return_code = scard_->LocateCardsByAtrW(
                call.context.bytes, masks, states);
            ret.reader_states.clear();
            for (const auto& st : states) {
                proto::ScardReaderStateReturn out;
                out.current_state = st.current_state;
                out.event_state = st.event_state;
                out.atr = st.atr;
                ret.reader_states.push_back(std::move(out));
            }
            break;
        }
        case proto::ScardIoctl::kLocateCardsByAtrA: {
            std::vector<smartcard::ScardReaderState> states;
            states.reserve(call.reader_states.size());
            for (const auto& st : call.reader_states) {
                smartcard::ScardReaderState out;
                out.reader = st.reader;
                out.current_state = st.current_state;
                states.push_back(std::move(out));
            }
            std::vector<smartcard::ScardAtrMask> masks;
            masks.reserve(call.atr_masks.size());
            for (const auto& m : call.atr_masks) {
                smartcard::ScardAtrMask out;
                out.atr = m.atr;
                out.mask = m.mask;
                masks.push_back(std::move(out));
            }
            ret.return_code = scard_->LocateCardsByAtr(
                call.context.bytes, masks, states);
            // Like LocateCardsA, the states are copied back even on failure;
            // the encoder drops them when the ReturnCode is nonzero.
            ret.reader_states.clear();
            for (const auto& st : states) {
                proto::ScardReaderStateReturn out;
                out.current_state = st.current_state;
                out.event_state = st.event_state;
                out.atr = st.atr;
                ret.reader_states.push_back(std::move(out));
            }
            break;
        }
        case proto::ScardIoctl::kGetStatusChangeA: {
            std::vector<smartcard::ScardReaderState> states;
            states.reserve(call.reader_states.size());
            for (const auto& st : call.reader_states) {
                smartcard::ScardReaderState out;
                out.reader = st.reader;
                out.current_state = st.current_state;
                states.push_back(std::move(out));
            }
            ret.return_code = scard_->GetStatusChange(
                call.context.bytes, call.timeout, states);
            // Like FreeRDP smartcard_GetStatusChangeA_Call, a timeout still
            // returns the readers it watched (with their unchanged state).
            if (ret.return_code == 0 ||
                ret.return_code == smartcard::kScardETimeout) {
                ret.reader_states.clear();
                for (const auto& st : states) {
                    proto::ScardReaderStateReturn out;
                    out.current_state = st.current_state;
                    out.event_state = st.event_state;
                    out.atr = st.atr;
                    ret.reader_states.push_back(std::move(out));
                }
            }
            break;
        }
        case proto::ScardIoctl::kConnectA: {
            std::vector<uint8_t> handle;
            uint32_t active = 0;
            ret.return_code = scard_->Connect(
                call.context.bytes, call.reader, call.share_mode,
                call.preferred_protocols, handle, active);
            if (ret.return_code == 0) {
                ret.handle.context = call.context;
                ret.handle.bytes = std::move(handle);
                ret.active_protocol = active;
            }
            break;
        }
        case proto::ScardIoctl::kConnectW: {
            std::vector<uint8_t> handle;
            uint32_t active = 0;
            ret.return_code = scard_->ConnectW(
                call.context.bytes, call.reader_name, call.share_mode,
                call.preferred_protocols, handle, active);
            if (ret.return_code == 0) {
                ret.handle.context = call.context;
                ret.handle.bytes = std::move(handle);
                ret.active_protocol = active;
            }
            break;
        }
        case proto::ScardIoctl::kDisconnect: {
            ret.return_code = scard_->Disconnect(
                call.handle.context.bytes, call.handle.bytes, call.disposition);
            break;
        }
        case proto::ScardIoctl::kBeginTransaction: {
            ret.return_code = scard_->BeginTransaction(
                call.handle.context.bytes, call.handle.bytes);
            break;
        }
        case proto::ScardIoctl::kEndTransaction: {
            ret.return_code = scard_->EndTransaction(
                call.handle.context.bytes, call.handle.bytes, call.disposition);
            break;
        }
        case proto::ScardIoctl::kStatusA: {
            std::vector<uint8_t> names;
            uint32_t state = 0;
            uint32_t protocol = 0;
            std::vector<uint8_t> atr;
            ret.return_code = scard_->Status(call.handle.context.bytes,
                                             call.handle.bytes, names, state,
                                             protocol, atr);
            if (ret.return_code == 0) {
                ret.reader_names = std::move(names);
                ret.state = state;
                ret.protocol = protocol;
                ret.atr = std::move(atr);
            }
            break;
        }
        case proto::ScardIoctl::kStatusW: {
            std::vector<uint8_t> names;
            uint32_t state = 0;
            uint32_t protocol = 0;
            std::vector<uint8_t> atr;
            ret.return_code = scard_->StatusW(call.handle.context.bytes,
                                              call.handle.bytes, names, state,
                                              protocol, atr);
            if (ret.return_code == 0) {
                ret.reader_names = std::move(names);
                ret.state = state;
                ret.protocol = protocol;
                ret.atr = std::move(atr);
            }
            break;
        }
        case proto::ScardIoctl::kTransmit: {
            smartcard::ScardPci send_pci;
            send_pci.protocol = call.send_pci.protocol;
            send_pci.extra = call.send_pci.extra;
            smartcard::ScardPci recv_pci;
            std::vector<uint8_t> recv;
            ret.return_code = scard_->Transmit(
                call.handle.context.bytes, call.handle.bytes, send_pci,
                call.send_buffer, call.recv_pci.has_value(), call.recv_length,
                recv_pci, recv);
            if (ret.return_code == 0) {
                if (call.recv_pci.has_value()) {
                    proto::ScardIoRequest out_pci;
                    out_pci.protocol = recv_pci.protocol;
                    out_pci.extra = recv_pci.extra;
                    ret.recv_pci = std::move(out_pci);
                }
                if (!call.recv_buffer_is_null) ret.recv_buffer = std::move(recv);
            }
            break;
        }
        case proto::ScardIoctl::kControl: {
            std::vector<uint8_t> out;
            ret.return_code = scard_->Control(
                call.handle.context.bytes, call.handle.bytes, call.control_code,
                call.in_buffer, call.out_buffer_size, out);
            if (ret.return_code == 0 && !call.out_buffer_is_null) {
                ret.out_buffer = std::move(out);
            }
            break;
        }
        case proto::ScardIoctl::kGetAttrib: {
            std::vector<uint8_t> attr;
            uint32_t attr_length = 0;
            ret.return_code = scard_->GetAttrib(
                call.handle.context.bytes, call.handle.bytes, call.attr_id,
                call.attr_is_null != 0, call.attr_capacity, attr, attr_length);
            if (ret.return_code == 0) {
                if (call.attr_is_null != 0 || call.attr_capacity == 0) {
                    // Length probe: cbAttrLen carries the length, pbAttr NULL.
                    ret.attr_length = attr_length;
                } else if (call.attr_capacity != 0xFFFFFFFFu &&
                           attr.size() > call.attr_capacity) {
                    // [MS-RDPESC] 2.2.2.21: the data does not fit.
                    ret.return_code = smartcard::kScardEInsufficientBuffer;
                } else {
                    ret.attr = std::move(attr);
                }
            }
            break;
        }
        case proto::ScardIoctl::kSetAttrib: {
            ret.return_code = scard_->SetAttrib(
                call.handle.context.bytes, call.handle.bytes, call.attr_id,
                call.set_attr_value);
            break;
        }
        case proto::ScardIoctl::kReadCacheA: {
            std::vector<uint8_t> data;
            uint32_t data_length = 0;
            ret.return_code = scard_->ReadCache(
                call.context.bytes, call.card_id, call.freshness,
                call.lookup_name, call.cache_is_null != 0,
                call.cache_capacity, data, data_length);
            if (ret.return_code == 0) {
                ret.cache_length = data_length;
                if (call.cache_is_null == 0 && !data.empty()) {
                    ret.cache = std::move(data);
                }
            }
            break;
        }
        case proto::ScardIoctl::kReadCacheW: {
            std::vector<uint8_t> data;
            uint32_t data_length = 0;
            ret.return_code = scard_->ReadCacheW(
                call.context.bytes, call.card_id, call.freshness,
                call.lookup_name_w, call.cache_is_null != 0,
                call.cache_capacity, data, data_length);
            if (ret.return_code == 0) {
                ret.cache_length = data_length;
                if (call.cache_is_null == 0 && !data.empty()) {
                    ret.cache = std::move(data);
                }
            }
            break;
        }
        case proto::ScardIoctl::kWriteCacheA: {
            ret.return_code = scard_->WriteCache(
                call.context.bytes, call.card_id, call.freshness,
                call.lookup_name, call.write_cache_data);
            break;
        }
        case proto::ScardIoctl::kWriteCacheW: {
            ret.return_code = scard_->WriteCacheW(
                call.context.bytes, call.card_id, call.freshness,
                call.lookup_name_w, call.write_cache_data);
            break;
        }
        case proto::ScardIoctl::kGetReaderIcon: {
            std::vector<uint8_t> icon;
            uint32_t icon_length = 0;
            ret.return_code = scard_->GetReaderIcon(
                call.context.bytes, call.reader_name, icon, icon_length);
            if (ret.return_code == 0) {
                ret.icon_length = icon_length;
                if (!icon.empty()) ret.icon = std::move(icon);
            }
            break;
        }
        case proto::ScardIoctl::kGetDeviceTypeId: {
            uint32_t device_id = 0;
            ret.return_code = scard_->GetDeviceTypeId(
                call.context.bytes, call.reader_name, device_id);
            if (ret.return_code == 0) ret.device_type_id = device_id;
            break;
        }
        case proto::ScardIoctl::kGetTransmitCount: {
            uint32_t count = 0;
            ret.return_code = scard_->GetTransmitCount(
                call.handle.context.bytes, call.handle.bytes, count);
            if (ret.return_code == 0) ret.transmit_count = count;
            break;
        }
        case proto::ScardIoctl::kAccessStartedEvent: {
            ret.return_code = scard_->AccessStartedEvent();
            break;
        }
        case proto::ScardIoctl::kCancel: {
            ret.return_code = scard_->Cancel(call.context.bytes);
            break;
        }
        case proto::ScardIoctl::kState: {
            uint32_t state = 0;
            uint32_t protocol = 0;
            std::vector<uint8_t> atr;
            ret.return_code = scard_->State(
                call.handle.context.bytes, call.handle.bytes, state, protocol,
                atr);
            if (ret.return_code == 0) {
                ret.state = state;
                ret.protocol = protocol;
                ret.state_atr_length = static_cast<uint32_t>(atr.size());
                if (call.atr_is_null != 0 || call.atr_capacity == 0) {
                    // Length probe: cbAtrLen carries the length, rgAtr NULL.
                } else if (call.atr_capacity != 0xFFFFFFFFu &&
                           atr.size() > call.atr_capacity) {
                    ret.return_code = smartcard::kScardEInsufficientBuffer;
                } else {
                    ret.state_atr = std::move(atr);
                }
            }
            break;
        }
        case proto::ScardIoctl::kReconnect: {
            uint32_t active = 0;
            ret.return_code = scard_->Reconnect(
                call.handle.context.bytes, call.handle.bytes, call.share_mode,
                call.preferred_protocols, call.initialization, active);
            if (ret.return_code == 0) ret.active_protocol = active;
            break;
        }
        default:
            // IsSupportedScardIoctl is the parser's gate, so this is
            // unreachable; fail closed instead of guessing a return shape.
            return {req.request, proto::kStatusUnsuccessful, {}, true};
    }

    const std::vector<uint8_t> encoded = proto::EncodeScardReturn(scard, ret);
    if (encoded.empty()) {
        // A range violation inside the return: the backend handed us fields
        // the wire format cannot carry. Fail closed.
        return {req.request, proto::kStatusUnsuccessful, {}, true};
    }
    // FreeRDP smartcard_call.c compares the encoded size against the server's
    // OutputBufferLength with no zero exemption: a probe (length 0) also gets
    // STATUS_BUFFER_TOO_SMALL so the server retries with a real buffer.
    if (encoded.size() > output_limit) {
        return {req.request, proto::kStatusBufferTooSmall, {}, false};
    }
    return {req.request, proto::kStatusSuccess, encoded, false};
}

void RdpdrClient::SendControlCompletion(
    const proto::RdpdrDeviceIoRequest& request, uint32_t status,
    const std::vector<uint8_t>& output) {
    // DR_CONTROL_RSP ([MS-RDPEFS] 2.2.1.5.5): the DeviceIoReply (12 bytes:
    // DeviceId + CompletionId + IoStatus) followed by OutputBufferLength and
    // the OutputBuffer bytes.
    rtsc::proto::ByteWriter w;
    w.u32le(request.device_id);
    w.u32le(request.completion_id);
    w.u32le(status);
    w.u32le(static_cast<uint32_t>(output.size()));
    w.bytes(output.data(), output.size());
    SendRaw(rtsc::proto::BuildRdpdrPdu(
        rtsc::proto::kPakidCoreDeviceIocompletion, w.take()));
}

// [MS-RDPESC] 3.2.5.2 / FreeRDP smartcard_call.c: when the encoded return does
// not fit the server's OutputBufferLength, the IOCTL is completed with
// STATUS_BUFFER_TOO_SMALL and an empty OutputBuffer so the server retries with
// a larger one. Smart card errors themselves stay IoStatus = STATUS_SUCCESS.
void RdpdrClient::SendLockCompletion(
    const proto::RdpdrDeviceIoRequest& request, uint32_t status) {
    // DR_DRIVE_LOCK_RSP ([MS-RDPEFS] 2.2.3.4.12): the DeviceIoReply followed
    // by 5 bytes of padding.
    rtsc::proto::ByteWriter w;
    w.u32le(request.device_id);
    w.u32le(request.completion_id);
    w.u32le(status);
    for (int i = 0; i < 5; ++i) w.u8(0);
    SendRaw(rtsc::proto::BuildRdpdrPdu(
        rtsc::proto::kPakidCoreDeviceIocompletion, w.take()));
}

void RdpdrClient::SendSetVolumeCompletion(
    const proto::RdpdrDeviceIoRequest& request, uint32_t status,
    uint32_t length) {
    // DR_DRIVE_SET_VOLUME_INFORMATION_RSP ([MS-RDPEFS] 2.2.3.4.7): the
    // DeviceIoReply followed by Length, which MUST match the request Length.
    rtsc::proto::ByteWriter w;
    w.u32le(request.device_id);
    w.u32le(request.completion_id);
    w.u32le(status);
    w.u32le(length);
    SendRaw(rtsc::proto::BuildRdpdrPdu(
        rtsc::proto::kPakidCoreDeviceIocompletion, w.take()));
}

void RdpdrClient::SendScardCompletion(const ScardCompletion& completion) {
    SendControlCompletion(completion.request, completion.status,
                          completion.output);
}

const RdpdrClient::Device* RdpdrClient::FindDevice(uint32_t device_id) const {
    for (const auto& device : devices_) {
        if (device.device_id == device_id) return &device;
    }
    return nullptr;
}
bool RdpdrClient::IsSerialDevice(uint32_t device_id) const {
    const Device* device = FindDevice(device_id);
    return device != nullptr && device->type == DeviceType::kSerial;
}

bool RdpdrClient::IsSerialHandle(uint32_t file_id) const {
    return serial_handles_.find(file_id) != serial_handles_.end();
}

bool RdpdrClient::IsPrinterDevice(uint32_t device_id) const {
    const Device* device = FindDevice(device_id);
    return device != nullptr && device->type == DeviceType::kPrinter;
}

bool RdpdrClient::IsPrinterHandle(uint32_t file_id) const {
    return printer_handles_.find(file_id) != printer_handles_.end();
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
    // General + drive, plus smart card when redirection is enabled
    // ([MS-RDPEFS] 2.2.2.7.5 SMARTCARD_CAPS_SET: an empty body, so the header
    // alone at CapabilityLength 8).
    bool has_serial = false;
    bool has_printer = false;
    for (const auto& device : devices_) {
        if (device.type == DeviceType::kSerial) has_serial = true;
        if (device.type == DeviceType::kPrinter) has_printer = true;
    }
    caps.num_capabilities = 2 + (has_serial ? 1u : 0u) +
                            (has_printer ? 1u : 0u) +
                            (scard_ != nullptr ? 1u : 0u);

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
    if (has_serial) {
        // PORT_CAPS_SET ([MS-RDPEFS] 2.2.2.7.3): an empty body, so the header
        // alone at CapabilityLength 8.
        rtsc::proto::RdpdrCapabilitySet port;
        port.header.capability_type = rtsc::proto::kCapPortType;
        port.header.version = rtsc::proto::kPortCapabilityVersion01;
        port.header.capability_length =
            static_cast<uint16_t>(rtsc::proto::RdpdrCapabilityHeader::kSize);
        caps.capabilities.push_back(port);
    }
    if (has_printer) {
        // PRINTER_CAPS_SET ([MS-RDPEFS] 2.2.2.7.2): an empty body, so the
        // header alone at CapabilityLength 8.
        rtsc::proto::RdpdrCapabilitySet printer_caps;
        printer_caps.header.capability_type = rtsc::proto::kCapPrinterType;
        printer_caps.header.version = rtsc::proto::kPrinterCapabilityVersion01;
        printer_caps.header.capability_length =
            static_cast<uint16_t>(rtsc::proto::RdpdrCapabilityHeader::kSize);
        caps.capabilities.push_back(printer_caps);
    }
    if (scard_ != nullptr) {
        rtsc::proto::RdpdrCapabilitySet smartcard;
        smartcard.header.capability_type = rtsc::proto::kCapSmartcardType;
        smartcard.header.version =
            rtsc::proto::kSmartcardCapabilityVersion01;
        smartcard.header.capability_length =
            static_cast<uint16_t>(rtsc::proto::RdpdrCapabilityHeader::kSize);
        caps.capabilities.push_back(smartcard);
    }
    return caps.encode();
}

std::vector<uint8_t> RdpdrClient::BuildDeviceListAnnounce() const {
    rtsc::proto::RdpdrDeviceListAnnounce list;
    list.device_count = static_cast<uint32_t>(devices_.size()) +
                        (scard_ != nullptr ? 1u : 0u);
    for (const auto& device : devices_) {
        rtsc::proto::RdpdrDeviceAnnounce announce;
        announce.device_type = device.type == DeviceType::kSerial
                                   ? rtsc::proto::kRdpdrDtypSerial
                                   : rtsc::proto::kRdpdrDtypFilesystem;
        if (device.type == DeviceType::kPrinter) {
            announce.device_type = rtsc::proto::kRdpdrDtypPrint;
            announce.device_data = rtsc::proto::EncodePrinterAnnounce(
                0, Utf16FromUtf8(device.printer_driver),
                Utf16FromUtf8(device.printer_name));
            announce.device_data_length =
                static_cast<uint32_t>(announce.device_data.size());
        }
        announce.device_id = device.device_id;
        const size_t name_len =
            std::min(device.dos_name.size(),
                     static_cast<size_t>(
                         rtsc::proto::RdpdrDeviceAnnounce::kDosNameSize));
        std::memcpy(announce.preferred_dos_name.data(), device.dos_name.data(),
                    name_len);
        if (device.type != DeviceType::kPrinter) {
            announce.device_data_length = 0;
        }
        list.devices.push_back(announce);
    }
    if (scard_ != nullptr) {
        // [MS-RDPEFS] 2.2.1.3: a smart card device announcement carries the
        // PreferredDosName "SCARD" and a zero-length DeviceData field.
        rtsc::proto::RdpdrDeviceAnnounce announce;
        announce.device_type = rtsc::proto::kRdpdrDtypSmartcard;
        announce.device_id = scard_device_id_;
        static constexpr char kScardDosName[] = "SCARD";
        std::memcpy(announce.preferred_dos_name.data(), kScardDosName,
                    sizeof(kScardDosName) - 1);
        announce.device_data_length = 0;
        list.devices.push_back(announce);
    }
    return list.encode();
}

}  // namespace rtsc::channel
