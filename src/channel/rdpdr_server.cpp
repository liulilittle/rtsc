// Device redirection virtual channel (rdpdr) server handler ([MS-RDPEFS] 3.2.5).

#include "rtsc/channel/rdpdr_server.h"

#include <atomic>
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

RdpdrServer::~RdpdrServer() = default;

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
    // The client's redirected devices are received ([MS-RDPEFS] 2.2.2.9) but
    // v1 does not consume them: the server issues no I/O. Parsing still
    // validates the announced list.
    rtsc::proto::RdpdrDeviceListAnnounce list;
    if (rtsc::proto::RdpdrDeviceListAnnounce::parse(message, list) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    ++device_list_announce_count_;
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