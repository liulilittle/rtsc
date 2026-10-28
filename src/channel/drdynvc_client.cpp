// Dynamic virtual channel (drdynvc) client transport ([MS-RDPEDYC] 2.2).

#include "rtsc/channel/drdynvc_client.h"

#include <algorithm>
#include <utility>

namespace rtsc::channel {

namespace {

constexpr uint16_t kDrdynvcVersion = 0x0001;

uint16_t ReadU16Le(const uint8_t* p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                 (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t ReadU32Le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

}  // namespace

DrdynvcClient::DrdynvcClient(IDrdynvcListener* listener, SendFn send)
    : listener_(listener), send_(std::move(send)) {}

DrdynvcClient::~DrdynvcClient() = default;

void DrdynvcClient::Start() {
    // DYNVC_CAPS_REQ VERSION1 ([MS-RDPEDYC] 2.2.1.1.1): header, Pad, Version.
    // VERSION1 has no PriorityCharge fields; VERSION2/3 append them.
    rtsc::proto::ByteWriter w;
    w.u8(static_cast<uint8_t>(
        (static_cast<uint8_t>(rtsc::proto::DynvcCmd::kCapability) << 4) | 0));
    w.u8(0);  // Pad, MUST be 0x00
    w.u16le(kDrdynvcVersion);
    SendPdu(w.take());
    ++caps_request_count_;
}

void DrdynvcClient::OnChannelData(const uint8_t* data, size_t size) {
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

    rtsc::proto::DynvcHeader h;
    if (rtsc::proto::DynvcHeader::parse(message.data(), message.size(), h) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    if (h.cmd == rtsc::proto::DynvcCmd::kCapability) {
        // header + Pad + Version ([MS-RDPEDYC] 2.2.1.1.1/2.2.1.2). VERSION2/3
        // append optional PriorityCharge0..3; VERSION1 stops at Version.
        if (message.size() < 4) return;
        version_ = ReadU16Le(message.data() + 2);
        caps_done_ = true;
        if (listener_ != nullptr) listener_->OnCapsResponse(version_);
        return;
    }

    rtsc::proto::DynvcPdu pdu;
    if (rtsc::proto::DynvcPdu::parse(message.data(), message.size(), pdu) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    switch (pdu.header.cmd) {
        case rtsc::proto::DynvcCmd::kCreate:
            OnCreateResponse(pdu);
            break;
        case rtsc::proto::DynvcCmd::kDataFirst:
        case rtsc::proto::DynvcCmd::kData:
            OnData(pdu);
            break;
        case rtsc::proto::DynvcCmd::kClose:
            OnClose(pdu);
            break;
        default:
            break;
    }
}

void DrdynvcClient::OnCaps(const rtsc::proto::DynvcPdu& pdu) {
    (void)pdu;
}

void DrdynvcClient::OnCreateResponse(const rtsc::proto::DynvcPdu& pdu) {
    ++create_response_count_;
    if (pdu.data.size() < 4) return;
    const uint32_t status = ReadU32Le(pdu.data.data());
    if (status != 0) return;
    const uint32_t id = pdu.channel_id;
    pending_.erase(id);
    open_channels_.insert(id);
    if (listener_ != nullptr) listener_->OnChannelCreated(id);
}

void DrdynvcClient::OnData(const rtsc::proto::DynvcPdu& pdu) {
    if (listener_ == nullptr) return;
    // Data for a channel that was never requested is dropped before it can
    // allocate reassembly state (unknown-channel guard).
    if (open_channels_.count(pdu.channel_id) == 0 &&
        pending_.count(pdu.channel_id) == 0) {
        return;
    }
    std::vector<uint8_t> message;
    if (!dvc_reassembler_.Feed(pdu, message)) return;
    listener_->OnChannelData(pdu.channel_id, message);
}

void DrdynvcClient::OnClose(const rtsc::proto::DynvcPdu& pdu) {
    ++close_count_;
    const uint32_t id = pdu.channel_id;
    pending_.erase(id);
    open_channels_.erase(id);
    dvc_reassembler_.Reset(id);
    if (listener_ != nullptr) listener_->OnChannelClosed(id);
}

uint32_t DrdynvcClient::CreateChannel(const ChannelDef& def) {
    const uint32_t id = next_channel_id_++;
    pending_[id] = def.name;
    rtsc::proto::ByteWriter w;
    for (const char c : def.name) w.u8(static_cast<uint8_t>(c));
    w.u8(0);
    const std::vector<uint8_t> pdu =
        rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kCreate, 0, id,
                                   w.take());
    SendPdu(pdu);
    ++create_request_count_;
    return id;
}

void DrdynvcClient::SendChannelData(uint32_t channel_id,
                                    const std::vector<uint8_t>& data) {
    // <= 1590 bytes travels as one DYNVC_DATA PDU; a larger message is
    // fragmented into DYNVC_DATA_FIRST (Length = whole message) + DYNVC_DATA
    // ([MS-RDPEDYC] 3.1.5.2).
    for (const auto& pdu : rtsc::proto::BuildDynvcDataPdus(channel_id, data)) {
        SendPdu(pdu);
    }
}

void DrdynvcClient::CloseChannel(uint32_t channel_id) {
    SendPdu(rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kClose, 0,
                                       channel_id, {}));
}

void DrdynvcClient::SendPdu(const std::vector<uint8_t>& dvc_pdu) {
    if (!send_) return;
    const std::vector<std::vector<uint8_t>> chunks =
        rtsc::proto::FragmentChannelMessage(
            dvc_pdu, rtsc::proto::kDefaultChannelChunkSize);
    for (const auto& chunk : chunks) send_(chunk);
}

}  // namespace rtsc::channel
