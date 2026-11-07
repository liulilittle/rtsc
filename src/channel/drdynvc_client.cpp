// Dynamic virtual channel (drdynvc) client transport ([MS-RDPEDYC] 2.2).

#include "rtsc/channel/drdynvc_client.h"

#include <algorithm>
#include <utility>

namespace rtsc::channel {

namespace {

// Version announced in DYNVC_CAPS_REQ (the client-initiated request format).
constexpr uint16_t kDrdynvcVersion = 0x0001;
// Highest version this implementation supports. Version 3 adds compressed DVC
// data ([MS-RDPEDYC] 2.2.1, 3.2.3.1), which BulkDecompressor now provides.
constexpr uint16_t kDrdynvcVersionMax = 0x0003;

uint16_t ReadU16Le(const uint8_t* p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                 (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t ReadU32Le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

// Parses one DVC PDU out of a bundled static channel message and advances
// `offset` past it. A server that opens several dynamic channels quickly can
// coalesce the control PDUs into a single MCS Send Data ([MS-RDPEDYC] 2.2); a
// data-carrying PDU (DataFirst / Data / compressed variants) has no length
// field and therefore always terminates the bundle. Returns false when the
// remainder is not a complete, well-formed PDU.
bool ConsumeBundlePdu(const std::vector<uint8_t>& message, size_t& offset,
                      const std::map<uint32_t, std::string>& pending_ids,
                      bool& create_request, rtsc::proto::DynvcPdu& out) {
    create_request = false;
    const uint8_t* data = message.data();
    const size_t size = message.size();
    const size_t remaining = size - offset;
    if (remaining < rtsc::proto::DynvcHeader::kSize) return false;
    rtsc::proto::DynvcHeader h;
    if (rtsc::proto::DynvcHeader::parse(data + offset, remaining, h) !=
        rtsc::proto::Status::Ok) {
        return false;
    }
    if (!h.valid()) return false;
    out.header = h;
    out.channel_id = 0;
    out.length = 0;

    if (h.cmd == rtsc::proto::DynvcCmd::kCapability) {
        // DYNVC_CAPS ([MS-RDPEDYC] 2.2.1): header + Pad + Version; VERSION1 is
        // exactly 4 bytes. VERSION2/3 append PriorityCharge0..3 (2 bytes each),
        // so those PDUs are 12 bytes. Size the PDU by the declared version
        // (web-verified: learn.microsoft.com 2.2.1.1.2 / 2.2.1.2), otherwise
        // the priority charges are mistaken for the next PDU in a bundle.
        if (remaining < 4) return false;
        const uint16_t version = ReadU16Le(data + offset + 2);
        const size_t cap_size = version >= 2 ? 12u : 4u;
        if (remaining < cap_size) return false;
        out.data.assign(data + offset, data + offset + cap_size);
        offset += cap_size;
        return true;
    }

    const size_t id_size = h.channel_id_size();
    if (remaining < rtsc::proto::DynvcHeader::kSize + id_size) return false;
    if (rtsc::proto::ParseDynvcChannelId(
            h, data + offset + rtsc::proto::DynvcHeader::kSize, id_size,
            out.channel_id) != rtsc::proto::Status::Ok) {
        return false;
    }
    size_t pdu_off = offset + rtsc::proto::DynvcHeader::kSize + id_size;

    if (h.cmd == rtsc::proto::DynvcCmd::kDataFirst) {
        // DYNVC_DATA_FIRST ([MS-RDPEDYC] 2.2.3.1): a 4-byte Length precedes the
        // first data fragment.
        if (remaining - (pdu_off - offset) < 4) return false;
        out.length = ReadU32Le(data + pdu_off);
        pdu_off += 4;
    } else if (h.cmd == rtsc::proto::DynvcCmd::kDataFirstCompressed) {
        // DYNVC_DATA_FIRST_COMPRESSED ([MS-RDPEDYC] 2.2.3.3): header Len bits
        // select a 1-, 2- or 4-byte Length (Len=3 is invalid).
        if (h.len_bits == 3) return false;
        const size_t len_size = h.length_size();
        if (remaining - (pdu_off - offset) < len_size) return false;
        uint32_t v = 0;
        for (size_t i = 0; i < len_size; ++i) {
            v |= static_cast<uint32_t>(data[pdu_off + i]) << (8 * i);
        }
        out.length = v;
        pdu_off += len_size;
    }
    out.data.assign(data + pdu_off, data + size);

    if (h.cmd == rtsc::proto::DynvcCmd::kCreate) {
        if (pending_ids.count(out.channel_id) != 0) {
            // DYNVC_CREATE_RSP ([MS-RDPEDYC] 2.2.2.2): Command + ChannelId +
            // CreationStatus(4). The response carries no channel name, so the
            // PDU boundary inside a bundle is fixed - a NUL-scan over a
            // status-only response would swallow the next PDU (the second byte
            // of a failed status is 0x00).
            if (remaining - (pdu_off - offset) < 4) return false;
            out.data.assign(data + pdu_off, data + pdu_off + 4);
            offset = pdu_off + 4;
            return true;
        }
        // DYNVC_CREATE_REQ ([MS-RDPEDYC] 2.2.2.1): the server opens a channel
        // and names the client listener. The name is a null-terminated ANSI
        // string, so the PDU ends at the NUL.
        size_t name_end = pdu_off;
        while (name_end < size && data[name_end] != 0) ++name_end;
        if (name_end >= size) return false;
        out.data.assign(data + pdu_off, data + name_end);
        offset = name_end + 1;
        create_request = true;
        return true;
    }

    // Data and every other command consumes the rest of the message.
    offset = size;
    return true;
}

}  // namespace

DrdynvcClient::DrdynvcClient(IDrdynvcListener* listener, SendFn send)
    : send_(std::move(send)) {
    AddListener(listener);
}

DrdynvcClient::~DrdynvcClient() = default;

void DrdynvcClient::Reset() {
    reassembler_.Reset();
    dvc_reassembler_.ResetAll();
    caps_done_ = false;
    version_ = 0;
    next_channel_id_ = 1;
    pending_.clear();
    open_channels_.clear();
    closing_.clear();
    decompressors_.clear();
    // The counters are diagnostics for one session; a reconnect starts a new
    // one, so they restart with it.
    caps_request_count_ = 0;
    caps_response_count_ = 0;
    negotiated_version_ = 0;
    create_request_count_ = 0;
    create_response_count_ = 0;
    server_create_count_ = 0;
    close_count_ = 0;
    compressed_data_count_ = 0;
    compressed_failure_count_ = 0;
    refused_data_count_ = 0;
}

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

    // A single static channel message may bundle several DVC PDUs
    // ([MS-RDPEDYC] 2.2); consume them all before returning.
    size_t offset = 0;
    while (offset < message.size()) {
        rtsc::proto::DynvcPdu pdu;
        bool create_request = false;
        if (!ConsumeBundlePdu(message, offset, pending_, create_request, pdu)) {
            break;
        }
        if (pdu.header.cmd == rtsc::proto::DynvcCmd::kCapability) {
            if (pdu.data.size() < 4) break;
            version_ = ReadU16Le(pdu.data.data() + 2);
            // [MS-RDPEDYC] 2.2.1 / 3.2.3.1.4: the client MUST answer with a
            // DYNVC_CAPS_RSP carrying the highest version it supports, capped
            // by what the server announced.
            negotiated_version_ =
                version_ < kDrdynvcVersionMax ? version_ : kDrdynvcVersionMax;
            rtsc::proto::ByteWriter caps;
            caps.u8(static_cast<uint8_t>(
                (static_cast<uint8_t>(rtsc::proto::DynvcCmd::kCapability) << 4) |
                0));
            caps.u8(0);  // Pad, MUST be 0x00
            caps.u16le(negotiated_version_);
            SendPdu(caps.take());
            ++caps_response_count_;
            caps_done_ = true;
            for (IDrdynvcListener* listener : listeners_) {
                listener->OnCapsResponse(version_);
            }
            continue;
        }
        switch (pdu.header.cmd) {
            case rtsc::proto::DynvcCmd::kCreate:
                if (create_request) {
                    OnCreateRequest(pdu);
                } else {
                    OnCreateResponse(pdu);
                }
                break;
            case rtsc::proto::DynvcCmd::kDataFirst:
            case rtsc::proto::DynvcCmd::kData:
                OnData(pdu);
                break;
            case rtsc::proto::DynvcCmd::kDataFirstCompressed:
            case rtsc::proto::DynvcCmd::kDataCompressed:
                OnCompressedData(pdu);
                break;
            case rtsc::proto::DynvcCmd::kClose:
                OnClose(pdu);
                break;
            default:
                // Unknown command: stop consuming the bundle.
                break;
        }
    }
}

void DrdynvcClient::OnCaps(const rtsc::proto::DynvcPdu& pdu) {
    (void)pdu;
}

void DrdynvcClient::OnCreateResponse(const rtsc::proto::DynvcPdu& pdu) {
    ++create_response_count_;
    const uint32_t id = pdu.channel_id;
    if (pdu.data.size() < 4) return;
    const uint32_t status = ReadU32Le(pdu.data.data());
    if (status != 0) {
        // The server rejected the channel: it will never open, so the request
        // must not stay pending forever.
        pending_.erase(id);
        return;
    }
    pending_.erase(id);
    open_channels_.insert(id);
    for (IDrdynvcListener* listener : listeners_) {
        listener->OnChannelCreated(id);
    }
}

void DrdynvcClient::OnCreateRequest(const rtsc::proto::DynvcPdu& pdu) {
    ++server_create_count_;
    const std::string name(pdu.data.begin(), pdu.data.end());
    bool accepted = false;
    for (IDrdynvcListener* listener : listeners_) {
        if (listener->OnChannelCreateRequest(name)) {
            accepted = true;
            break;
        }
    }
    rtsc::proto::ByteWriter w;
    w.u32le(accepted ? rtsc::proto::kDynvcCreationStatusOk
                     : rtsc::proto::kDynvcCreationStatusNoListener);
    SendPdu(rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kCreate, 0,
                                       pdu.channel_id, w.take()));
    // A rejected id must never enter the active set: the server may reuse it
    // for another channel without a DYNVC_CLOSE ([MS-RDPEDYC] 2.2.2.2).
    if (accepted) {
        open_channels_.insert(pdu.channel_id);
    }
}

void DrdynvcClient::OnData(const rtsc::proto::DynvcPdu& pdu) {
    if (listeners_.empty()) return;
    // Data for a channel that was never requested is dropped before it can
    // allocate reassembly state (unknown-channel guard).
    if (open_channels_.count(pdu.channel_id) == 0 &&
        pending_.count(pdu.channel_id) == 0) {
        return;
    }
    std::vector<uint8_t> message;
    if (!dvc_reassembler_.Feed(pdu, message)) return;
    for (IDrdynvcListener* listener : listeners_) {
        listener->OnChannelData(pdu.channel_id, message);
    }
}

void DrdynvcClient::OnCompressedData(const rtsc::proto::DynvcPdu& pdu) {
    // Data for a channel that was never requested is dropped before it can
    // allocate decompression state (unknown-channel guard, same as OnData).
    if (open_channels_.count(pdu.channel_id) == 0 &&
        pending_.count(pdu.channel_id) == 0) {
        return;
    }
    if (listeners_.empty()) return;

    // Compressed DVC data exists only in version 3 ([MS-RDPEDYC] 2.2.1 /
    // 2.2.3.3): on a version 1 or 2 transport such a PDU is a protocol
    // violation, so it is rejected instead of decoded.
    if (negotiated_version_ < 3) {
        ++compressed_failure_count_;
        return;
    }

    // Each channel has its own RDP 8.0 Lite decompression context: compressed
    // blocks may reference bytes produced by earlier blocks on this channel.
    std::vector<uint8_t> decompressed;
    rtsc::proto::BulkDecompressor& decompressor = decompressors_[pdu.channel_id];
    if (decompressor.Decompress(pdu.data, &decompressed) == 0) {
        // A rejected block leaves the context in an unknown state: drop the
        // context and any half-assembled message for this channel so a later
        // valid sequence cannot be decoded against corrupt history.
        decompressors_.erase(pdu.channel_id);
        dvc_reassembler_.Reset(pdu.channel_id);
        ++compressed_failure_count_;
        return;
    }
    ++compressed_data_count_;

    // Feed the decompressed block through the normal reassembly path: a
    // DYNVC_DATA_FIRST_COMPRESSED block starts a message whose total
    // uncompressed length is in the Length field; DYNVC_DATA_COMPRESSED is
    // either the whole message or a continuation block.
    rtsc::proto::DynvcPdu inflated;
    inflated.header.cmd =
        pdu.header.cmd == rtsc::proto::DynvcCmd::kDataFirstCompressed
            ? rtsc::proto::DynvcCmd::kDataFirst
            : rtsc::proto::DynvcCmd::kData;
    inflated.channel_id = pdu.channel_id;
    inflated.length = pdu.length;
    inflated.data = std::move(decompressed);

    std::vector<uint8_t> message;
    if (!dvc_reassembler_.Feed(inflated, message)) return;
    for (IDrdynvcListener* listener : listeners_) {
        listener->OnChannelData(pdu.channel_id, message);
    }
}
void DrdynvcClient::OnClose(const rtsc::proto::DynvcPdu& pdu) {
    ++close_count_;
    const uint32_t id = pdu.channel_id;
    const bool was_pending = pending_.erase(id) != 0;
    const bool was_open = open_channels_.erase(id) != 0;
    // [MS-RDPEDYC] 2.2.4: one CLOSE PDU serves as both the close request and
    // the close response. A CLOSE that answers our own CloseChannel is that
    // response, so the listeners were already told when we sent it.
    const bool local_close = closing_.erase(id) != 0;
    dvc_reassembler_.Reset(id);
    decompressors_.erase(id);
    if (!local_close && !was_open && !was_pending) {
        return;  // unknown channel: no-op
    }
    for (IDrdynvcListener* listener : listeners_) {
        listener->OnChannelClosed(id);
    }
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

bool DrdynvcClient::SendChannelData(uint32_t channel_id,
                                    const std::vector<uint8_t>& data) {
    // DYNVC_DATA is only meaningful on a channel the server has opened (a
    // CREATE_RSP is still pending) or is about to open. Writing to an unknown
    // or closed id is a protocol error: the data would be dropped, and the id
    // may already have been handed to another channel.
    if (open_channels_.count(channel_id) == 0 &&
        pending_.count(channel_id) == 0) {
        ++refused_data_count_;
        return false;
    }
    // <= 1590 bytes travels as one DYNVC_DATA PDU; a larger message is
    // fragmented into DYNVC_DATA_FIRST (Length = whole message) + DYNVC_DATA
    // ([MS-RDPEDYC] 3.1.5.2).
    for (const auto& pdu : rtsc::proto::BuildDynvcDataPdus(channel_id, data)) {
        SendPdu(pdu);
    }
    return true;
}

void DrdynvcClient::CloseChannel(uint32_t channel_id) {
    SendPdu(rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kClose, 0,
                                       channel_id, {}));
    // Sending DYNVC_CLOSE closes the channel locally: no further inbound data
    // is delivered. The listeners are notified when the server answers with its
    // own CLOSE (OnClose), so a caller may close the channel from inside one of
    // its own callbacks without re-entering them.
    if (open_channels_.erase(channel_id) != 0) {
        dvc_reassembler_.Reset(channel_id);
        closing_.insert(channel_id);
    }
}

void DrdynvcClient::SendPdu(const std::vector<uint8_t>& dvc_pdu) {
    if (!send_) return;
    const std::vector<std::vector<uint8_t>> chunks =
        rtsc::proto::FragmentChannelMessage(
            dvc_pdu, rtsc::proto::kDefaultChannelChunkSize);
    for (const auto& chunk : chunks) send_(chunk);
}

}  // namespace rtsc::channel
