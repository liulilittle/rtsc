// Device redirection virtual channel (rdpdr) client handler ([MS-RDPEFS] 3.1).

#include "rtsc/channel/rdpdr_client.h"

#include <algorithm>
#include <cctype>
#include <cstring>

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
    const bool for_write = disposition != kFileOpen;
    bool create = disposition == kFileCreate;
    uint32_t file_id = 0;
    if (!fs_->Open(local, for_write, create, file_id) &&
        (disposition == kFileOpenIf || disposition == kFileOverwriteIf)) {
        create = true;
        fs_->Open(local, true, true, file_id);
    }
    if (file_id == 0) {
        SendIoCompletion(req.request, rtsc::proto::kStatusAccessDenied);
        return;
    }

    open_files_[file_id] = req.request.device_id;
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
    if (fs_ != nullptr) fs_->Close(req.request.file_id);
    open_files_.erase(req.request.file_id);
    SendIoCompletion(req.request, rtsc::proto::kStatusSuccess);
    ++close_count_;
}

void RdpdrClient::OnQueryDirectory(const std::vector<uint8_t>& body) {
    rtsc::proto::RdpdrQueryDirectoryReq req;
    if (rtsc::proto::RdpdrQueryDirectoryReq::parse(body, req) !=
        rtsc::proto::Status::Ok) {
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

    std::string root = device->local_root;
    if (root.empty()) return {};
    if (root.back() != '\\' && root.back() != '/') root.push_back('\\');
    if (rest.empty()) return root;
    if (rest.front() == '\\' || rest.front() == '/') rest.erase(rest.begin());
    for (char& c : rest) {
        if (c == '/') c = '\\';
    }
    return root + rest;
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
