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

RdpdrClient::~RdpdrClient() = default;

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
    open_files_.erase(req.request.file_id);
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
    const uint32_t code = req.io_control_code;
    last_scard_ioctl_name_ = proto::ScardIoctlName(code);

    proto::ScardCall call;
    if (proto::ParseScardCall(code, req.input_buffer.data(),
                              req.input_buffer.size(), call) !=
        proto::Status::Ok) {
        ++smartcard_reject_count_;
        SendControlCompletion(req.request, proto::kStatusUnsuccessful, {});
        return;
    }

    ++smartcard_count_;
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
        case proto::ScardIoctl::kListReaderGroupsA: {
            std::vector<uint8_t> groups;
            ret.return_code =
                scard_->ListReaderGroups(call.context.bytes, groups);
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
        default:
            // IsSupportedScardIoctl is the parser's gate, so this is
            // unreachable; fail closed instead of guessing a return shape.
            ++smartcard_reject_count_;
            SendControlCompletion(req.request, proto::kStatusUnsuccessful, {});
            return;
    }

    SendScardCompletion(req.request, ret, scard, output_limit);
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
void RdpdrClient::SendScardCompletion(
    const proto::RdpdrDeviceIoRequest& request, const proto::ScardReturn& ret,
    proto::ScardIoctl code, uint32_t output_limit) {
    const std::vector<uint8_t> encoded = proto::EncodeScardReturn(code, ret);
    if (encoded.empty()) {
        // A range violation inside the return: the backend handed us fields
        // the wire format cannot carry. Fail closed.
        ++smartcard_reject_count_;
        SendControlCompletion(request, proto::kStatusUnsuccessful, {});
        return;
    }
    // FreeRDP smartcard_call.c compares the encoded size against the server's
    // OutputBufferLength with no zero exemption: a probe (length 0) also gets
    // STATUS_BUFFER_TOO_SMALL so the server retries with a real buffer.
    if (encoded.size() > output_limit) {
        SendControlCompletion(request, proto::kStatusBufferTooSmall, {});
        return;
    }
    SendControlCompletion(request, proto::kStatusSuccess, encoded);
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
    // General + drive, plus smart card when redirection is enabled
    // ([MS-RDPEFS] 2.2.2.7.5 SMARTCARD_CAPS_SET: an empty body, so the header
    // alone at CapabilityLength 8).
    caps.num_capabilities = scard_ != nullptr ? 3 : 2;

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
