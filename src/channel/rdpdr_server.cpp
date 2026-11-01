// Device redirection virtual channel (rdpdr) server handler ([MS-RDPEFS] 3.2.5).

#include "rtsc/channel/rdpdr_server.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <utility>

namespace rtsc::channel {

namespace {

using rtsc::proto::Status;

// Handed out to every session so two sessions on one server do not share a
// rdpdr client id ([MS-RDPEFS] 2.2.2.2 carries a server-chosen 32-bit id). The
// value never leaves this process; the sequence is atomic because sessions may
// be constructed from different threads (Run and ServeOne).
uint32_t NextClientId() {
    static std::atomic<uint32_t> sequence{0xA5A50001u};
    return sequence.fetch_add(1, std::memory_order_relaxed);
}

}  // namespace

const char* RdpdrServer::to_string(Phase p) {
    switch (p) {
        case Phase::kIdle: return "idle";
        case Phase::kAwaitClientAnnounce: return "await-client-announce";
        case Phase::kReady: return "ready";
    }
    return "unknown";
}

RdpdrServer::RdpdrServer(SendFn send)
    : send_(std::move(send)), client_id_(NextClientId()) {}

RdpdrServer::~RdpdrServer() {
    // The session is going away: every IRP the client never completed is
    // failed with STATUS_UNSUCCESSFUL so no caller is left waiting forever.
    // The table is moved to a local vector first, so a callback that re-enters
    // the channel (a retry) cannot invalidate the container while it is being
    // walked.
    std::vector<PendingIrp> pending = std::move(outstanding_);
    outstanding_.clear();
    for (auto& entry : pending) {
        if (entry.callback) {
            // The callback belongs to the embedder: one that throws must not
            // turn this destructor into std::terminate. The remaining pending
            // IRPs are still failed.
            try {
                entry.callback(rtsc::proto::kStatusUnsuccessful, {});
            } catch (...) {
            }
        }
    }
}

void RdpdrServer::Start() {
    if (started_) return;
    started_ = true;
    // [MS-RDPEFS] 3.2.5.1: the server speaks first with
    // DR_CORE_SERVER_ANNOUNCE_REQ. The body layout (versionMajor,
    // versionMinor, ClientId) is the 8 bytes following the 4-byte
    // RDPDR_HEADER, which RdpdrServerAnnounce::encode() emits.
    rtsc::proto::RdpdrServerAnnounce announce;
    announce.version_major = version_major_;
    announce.version_minor = version_minor_;
    announce.client_id = client_id_;
    SendRaw(announce.encode());
    ++server_announce_count_;
    phase_ = Phase::kAwaitClientAnnounce;
}

void RdpdrServer::OnChannelData(const uint8_t* data, size_t size) {
    if (data == nullptr || size < rtsc::proto::ChannelPduHeader::kSize) {
        ++malformed_pdu_count_;
        return;
    }
    rtsc::proto::ChannelPduHeader header;
    if (rtsc::proto::ChannelPduHeader::parse(data, size, header) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    bool complete = false;
    std::vector<uint8_t> message;
    const Status st = reassembler_.Feed(
        header, data + rtsc::proto::ChannelPduHeader::kSize,
        size - rtsc::proto::ChannelPduHeader::kSize, complete, message);
    if (st != Status::Ok) {
        ++malformed_pdu_count_;
        reassembler_.Reset();
        return;
    }
    if (!complete) return;
    OnMessage(message);
}

void RdpdrServer::OnMessage(const std::vector<uint8_t>& message) {
    rtsc::proto::RdpdrPdu pdu;
    if (rtsc::proto::RdpdrPdu::parse(message.data(), message.size(), pdu) !=
        Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    switch (pdu.header.packet_id) {
        case rtsc::proto::kPakidCoreClientidConfirm:
            // The client's announce reply reuses the clientid-confirm packet
            // id ([MS-RDPEFS] 2.2.2.3).
            OnClientAnnounce(message);
            break;
        case rtsc::proto::kPakidCoreClientName:
            OnClientName(message);
            break;
        case rtsc::proto::kPakidCoreClientCapability:
            OnClientCapability(message);
            break;
        case rtsc::proto::kPakidCoreDevicelistAnnounce:
            OnDeviceListAnnounce(message);
            break;
        case rtsc::proto::kPakidCoreDeviceIorequest:
            // RdpdrDeviceIoRequest::parse is header-unaware (it reads the
            // DR_DEVICE_IOREQUEST fields straight from the given span), so the
            // RDPDR_HEADER must be stripped first -- exactly like the client
            // does (rdpdr_client.cpp OnMessage passes pdu.data).
            OnDeviceIoRequest(pdu.data);
            break;
        case rtsc::proto::kPakidCoreDeviceIocompletion:
            // The client's answer to an IRP the server issued (route A). The
            // completion is matched against the outstanding table and dispatched
            // to the registered callback.
            OnDeviceIoCompletion(pdu.data);
            break;
        default:
            // A client-originated message the server does not expect (e.g. a
            // server-only PDU); SHOULD ignore ([MS-RDPEFS] 3.2.5).
            break;
    }
}

void RdpdrServer::OnClientAnnounce(const std::vector<uint8_t>& message) {
    if (!started_ || phase_ != Phase::kAwaitClientAnnounce) {
        ++out_of_order_count_;
        return;
    }
    rtsc::proto::RdpdrClientAnnounceReply reply;
    if (rtsc::proto::RdpdrClientAnnounceReply::parse(
            message.data(), message.size(), reply) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    client_announce_received_ = true;
    ++client_announce_count_;

    // The whole server initialization batch goes out here: Server Capability,
    // then ClientId Confirm, then the optional User LoggedOn ([MS-RDPEFS]
    // 3.2.5.1). The confirmation is NOT deferred until the client capability
    // arrives: this stack's client only sends its capability in answer to the
    // confirmation (rdpdr_client.cpp OnClientIdConfirm), so waiting would
    // deadlock the channel. Gating it on the announce reply is also what the
    // FreeRDP rdpdr server does.
    SendRaw(BuildServerCapabilities());
    ++server_capability_count_;

    rtsc::proto::RdpdrServerClientIdConfirm confirm;
    // [MS-RDPEFS] 2.2.2.6 carries VersionMajor + VersionMinor before ClientId;
    // real clients enforce the 12-byte length and parse both version fields.
    // Fill them from the server's own version pair, which the announce already
    // advertised (the in-tree client echoes announce.version_minor).
    confirm.version_major = version_major_;
    confirm.version_minor = version_minor_;
    confirm.client_id = client_id_;
    SendRaw(confirm.encode());
    ++clientid_confirm_count_;

    SendRaw(rtsc::proto::BuildRdpdrPdu(rtsc::proto::kPakidCoreUserLoggedon, {}));
    ++user_loggedon_count_;
    user_logged_on_sent_ = true;

    phase_ = Phase::kReady;
}

void RdpdrServer::OnClientName(const std::vector<uint8_t>& message) {
    if (!started_) {
        ++out_of_order_count_;
        return;
    }
    rtsc::proto::RdpdrClientNameRequest name;
    if (rtsc::proto::RdpdrClientNameRequest::parse(message, name) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    client_computer_name_ = rtsc::proto::RdpdrDecodeUtf16(
        name.computer_name.data(), name.computer_name.size());
    ++client_name_count_;
}

void RdpdrServer::OnClientCapability(const std::vector<uint8_t>& message) {
    if (!started_) {
        ++out_of_order_count_;
        return;
    }
    // The capability bodies are not acted on in v1 (no devices, no I/O); the
    // message is validated so a truncated one is counted as malformed instead
    // of being mistaken for a clean capability exchange.
    rtsc::proto::RdpdrCoreCapability caps;
    if (rtsc::proto::RdpdrCoreCapability::parse(message, caps) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    client_capability_received_ = true;
    ++client_capability_count_;
}

void RdpdrServer::OnDeviceListAnnounce(const std::vector<uint8_t>& message) {
    if (!started_) {
        ++out_of_order_count_;
        return;
    }
    // The client's redirected devices are received ([MS-RDPEFS] 2.2.2.9). v1
    // issues no I/O against them, but each announced device is answered with a
    // DR_CORE_DEVICE_ANNOUNCE_RSP (2.2.2.1, result_code 0 = SUCCESS) so a real
    // mstsc server's device-ready expectation is satisfied. RdpdrDeviceReply's
    // encoder emits the RDPDR_HEADER itself, so the reply is sent as-is.
    rtsc::proto::RdpdrDeviceListAnnounce list;
    if (rtsc::proto::RdpdrDeviceListAnnounce::parse(message, list) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    ++device_list_announce_count_;
    for (const auto& device : list.devices) {
        rtsc::proto::RdpdrDeviceReply reply;
        reply.device_id = device.device_id;
        reply.result_code = 0;  // [MS-RDPEFS] 2.2.2.1 resultCode SUCCESS
        SendRaw(reply.encode());
        ++device_reply_count_;
    }
}

void RdpdrServer::OnDeviceIoRequest(const std::vector<uint8_t>& body) {
    if (!started_) {
        ++out_of_order_count_;
        return;
    }
    // The server announces no devices in v1, so a Device Io Request is bogus.
    // It is ignored and counted; no completion is fabricated.
    rtsc::proto::RdpdrDeviceIoRequest request;
    if (rtsc::proto::RdpdrDeviceIoRequest::parse(body, request) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    ++device_io_request_count_;
}

void RdpdrServer::OnDeviceIoCompletion(const std::vector<uint8_t>& body) {
    if (!started_) {
        ++out_of_order_count_;
        return;
    }
    rtsc::proto::RdpdrDeviceIoCompletion completion;
    rtsc::proto::ByteReader r(body.data(), body.size());
    if (body.size() < 12 ||
        !r.u32le(completion.device_id) || !r.u32le(completion.completion_id) ||
        !r.u32le(completion.io_status)) {
        ++malformed_pdu_count_;
        return;
    }

    auto it = std::find_if(outstanding_.begin(), outstanding_.end(),
                           [&](const PendingIrp& pending) {
                               return pending.completion_id ==
                                          completion.completion_id &&
                                      pending.device_id ==
                                          completion.device_id;
                           });
    if (it == outstanding_.end()) {
        // An unknown or replayed completion id. The spec wants the channel torn
        // down; we deliberately choose to record and drop it, so a single stray
        // frame cannot take a live session down.
        ++unknown_completion_count_;
        return;
    }
    PendingIrp pending = std::move(*it);
    outstanding_.erase(it);

    std::vector<uint8_t> data;
    if (completion.io_status == rtsc::proto::kStatusSuccess) {
        switch (pending.major_function) {
            case rtsc::proto::kIrpMjCreate: {
                uint32_t file_id = 0;
                uint8_t information = 0;
                if (r.remaining() >= 5 && r.u32le(file_id) && r.u8(information)) {
                    data.resize(4);
                    data[0] = static_cast<uint8_t>(file_id & 0xFF);
                    data[1] = static_cast<uint8_t>((file_id >> 8) & 0xFF);
                    data[2] = static_cast<uint8_t>((file_id >> 16) & 0xFF);
                    data[3] = static_cast<uint8_t>((file_id >> 24) & 0xFF);
                }
                (void)information;
                break;
            }
            case rtsc::proto::kIrpMjRead:
            case rtsc::proto::kIrpMjDirectoryControl: {
                uint32_t length = 0;
                if (r.u32le(length) && r.remaining() >= length) {
                    data.assign(r.cursor(), r.cursor() + length);
                }
                break;
            }
            case rtsc::proto::kIrpMjWrite:
            case rtsc::proto::kIrpMjClose:
            default:
                // Write / Close carry no payload that the callback consumes.
                break;
        }
    }
    pending.deadline = {};
    ++device_io_completion_count_;
    if (pending.callback) {
        pending.callback(completion.io_status, data);
    }
}

void RdpdrServer::Poll(const std::chrono::steady_clock::time_point& now) {
    // Two passes: collect and erase the expired IRPs first, then fire their
    // callbacks. Firing inside the removal scan would let a callback that
    // re-enters SubmitIrp (a natural retry pattern) mutate the table while it
    // is being iterated -- reallocating the vector and invalidating the scan.
    std::vector<PendingIrp> expired;
    for (auto it = outstanding_.begin(); it != outstanding_.end();) {
        if (now < it->deadline) {
            ++it;
            continue;
        }
        ++device_io_timeout_count_;
        expired.push_back(std::move(*it));
        it = outstanding_.erase(it);
    }
    for (auto& entry : expired) {
        if (entry.callback) {
            entry.callback(0xC00000B5 /* STATUS_IO_TIMEOUT */, {});
        }
    }
}

uint32_t RdpdrServer::SubmitIrp(uint32_t device_id, uint32_t file_id,
                                uint32_t major_function, uint32_t minor_function,
                                const std::vector<uint8_t>& tail,
                                IrpCallback cb) {
    if (phase_ != Phase::kReady) return 0;
    if (outstanding_.size() >= kMaxOutstanding) return 0;

    uint32_t completion_id = next_completion_id_++;
    if (completion_id == 0) {
        // 0 is reserved for "rejected"; wrap past it.
        completion_id = next_completion_id_++;
    }

    rtsc::proto::RdpdrDeviceIoRequest request;
    request.device_id = device_id;
    request.file_id = file_id;
    request.completion_id = completion_id;
    request.major_function = major_function;
    request.minor_function = minor_function;
    const std::vector<uint8_t> prefix = request.encode();

    rtsc::proto::ByteWriter w;
    w.bytes(prefix.data(), prefix.size());
    w.bytes(tail.data(), tail.size());
    SendRaw(rtsc::proto::BuildRdpdrPdu(rtsc::proto::kPakidCoreDeviceIorequest,
                                       w.take()));

    PendingIrp pending;
    pending.device_id = device_id;
    pending.file_id = file_id;
    pending.completion_id = completion_id;
    pending.major_function = major_function;
    pending.deadline = std::chrono::steady_clock::now() + kIrpTimeout;
    pending.callback = std::move(cb);
    outstanding_.push_back(std::move(pending));
    return completion_id;
}

uint32_t RdpdrServer::CreateFile(uint32_t device_id, const std::string& path,
                                 uint32_t desired_access, uint32_t disposition,
                                 IrpCallback cb) {
    // DR_CREATE_REQ: DeviceIoRequest(20) + DesiredAccess(4) + AllocationSize(8)
    // + FileAttributes(4) + SharedAccess(4) + CreateDisposition(4) +
    // CreateOptions(4) + PathLength(4) + Path (UTF-16LE, NUL-terminated).
    const std::vector<uint8_t> path_bytes =
        rtsc::proto::RdpdrEncodeUtf16(path);
    rtsc::proto::ByteWriter w;
    w.u32le(desired_access);
    w.u32le(0);  // AllocationSize (low)
    w.u32le(0);  // AllocationSize (high)
    w.u32le(0x80);  // FileAttributes: FILE_ATTRIBUTE_NORMAL
    w.u32le(0);  // SharedAccess
    w.u32le(disposition);
    w.u32le(0);  // CreateOptions
    w.u32le(static_cast<uint32_t>(path_bytes.size()));
    w.bytes(path_bytes.data(), path_bytes.size());
    return SubmitIrp(device_id, 0, rtsc::proto::kIrpMjCreate, 0, w.take(),
                     std::move(cb));
}

uint32_t RdpdrServer::ReadFile(uint32_t device_id, uint32_t file_id,
                               uint64_t offset, uint32_t length,
                               IrpCallback cb) {
    // DR_READ_REQ ([MS-RDPEFS] 2.2.1.4.3): DeviceIoRequest(20) + Length(4) +
    // Offset(8) + Padding(20). A real peer enforces the 52-byte body; omitting
    // the padding desynchronises the redirector's field reads.
    rtsc::proto::ByteWriter w;
    w.u32le(length);
    w.u32le(static_cast<uint32_t>(offset & 0xFFFFFFFFu));
    w.u32le(static_cast<uint32_t>(offset >> 32));
    for (int i = 0; i < 20; ++i) w.u8(0);
    return SubmitIrp(device_id, file_id, rtsc::proto::kIrpMjRead, 0, w.take(),
                     std::move(cb));
}

uint32_t RdpdrServer::WriteFile(uint32_t device_id, uint32_t file_id,
                                uint64_t offset, const std::vector<uint8_t>& data,
                                IrpCallback cb) {
    // DR_WRITE_REQ: DeviceIoRequest(20) + Length(4) + Offset(8) + Padding(20)
    // + Data.
    rtsc::proto::ByteWriter w;
    w.u32le(static_cast<uint32_t>(data.size()));
    w.u32le(static_cast<uint32_t>(offset & 0xFFFFFFFFu));
    w.u32le(static_cast<uint32_t>(offset >> 32));
    for (int i = 0; i < 20; ++i) w.u8(0);
    w.bytes(data.data(), data.size());
    return SubmitIrp(device_id, file_id, rtsc::proto::kIrpMjWrite, 0, w.take(),
                     std::move(cb));
}

uint32_t RdpdrServer::CloseFile(uint32_t device_id, uint32_t file_id,
                                IrpCallback cb) {
    // DR_CLOSE_REQ is the bare 20-byte DeviceIoRequest.
    return SubmitIrp(device_id, file_id, rtsc::proto::kIrpMjClose, 0, {},
                     std::move(cb));
}

uint32_t RdpdrServer::QueryDirectory(uint32_t device_id, uint32_t file_id,
                                     uint32_t info_class, bool initial,
                                     IrpCallback cb) {
    // DR_DRIVE_QUERY_DIRECTORY_REQ: DeviceIoRequest(20) + FsInformationClass(4)
    // + InitialQuery(1) + PathLength(4) + Padding(23) + Path (UTF-16LE).
    const std::vector<uint8_t> pattern = rtsc::proto::RdpdrEncodeUtf16("*");
    rtsc::proto::ByteWriter w;
    w.u32le(info_class);
    w.u8(initial ? 1 : 0);
    w.u32le(static_cast<uint32_t>(pattern.size()));
    for (int i = 0; i < 23; ++i) w.u8(0);
    w.bytes(pattern.data(), pattern.size());
    return SubmitIrp(device_id, file_id, rtsc::proto::kIrpMjDirectoryControl,
                     rtsc::proto::kIrpMnQueryDirectory, w.take(),
                     std::move(cb));
}

std::vector<uint8_t> RdpdrServer::BuildServerCapabilities() const {
    // [MS-RDPEFS] 2.2.2.7: one GENERAL_CAPS_SET (version 2). ioCode1 advertises
    // no IRP support because v1 provides no devices; extendedPDU advertises the
    // User LoggedOn PDU that OnClientAnnounce sends.
    rtsc::proto::RdpdrGeneralCapsSet general_body;
    general_body.os_type = 0;
    general_body.os_version = 0;
    general_body.protocol_major_version = version_major_;
    general_body.protocol_minor_version = version_minor_;
    general_body.io_code1 = 0;
    general_body.io_code2 = 0;
    general_body.extended_pdu = rtsc::proto::kRdpdrUserLoggedonPdu;
    general_body.extra_flags1 = 0;
    general_body.extra_flags2 = 0;
    general_body.special_type_device_cap = 0;

    rtsc::proto::RdpdrCapabilitySet general;
    general.header.capability_type = rtsc::proto::kCapGeneralType;
    general.header.version = rtsc::proto::kGeneralCapabilityVersion02;
    general.data = general_body.encode(general.header.version);
    general.header.capability_length = static_cast<uint16_t>(
        rtsc::proto::RdpdrCapabilityHeader::kSize + general.data.size());

    // RdpdrCoreCapability::encode() hardcodes the *client* capability packet
    // id, so the same body layout (numCapabilities + padding + capability sets)
    // is wrapped here with the server packet id. The proto layer stays
    // untouched.
    rtsc::proto::ByteWriter w;
    w.u16le(1);  // numCapabilities
    w.u16le(0);  // padding
    const std::vector<uint8_t> encoded = general.encode();
    w.bytes(encoded.data(), encoded.size());
    return rtsc::proto::BuildRdpdrPdu(rtsc::proto::kPakidCoreServerCapability,
                                      w.take());
}

void RdpdrServer::SendRaw(const std::vector<uint8_t>& pdu) {
    if (!send_) return;
    for (const auto& chunk : rtsc::proto::FragmentChannelMessage(pdu)) {
        send_(chunk);
    }
}

}  // namespace rtsc::channel