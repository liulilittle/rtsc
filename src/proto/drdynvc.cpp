// Dynamic virtual channel (drdynvc) structure layer ([MS-RDPEDYC] 2.2).

#include "rtsc/proto/drdynvc.h"

#include <algorithm>

namespace rtsc::proto {

const char* to_string(DynvcCmd cmd) {
    switch (cmd) {
        case DynvcCmd::kCreate: return "create";
        case DynvcCmd::kDataFirst: return "data-first";
        case DynvcCmd::kData: return "data";
        case DynvcCmd::kClose: return "close";
        case DynvcCmd::kCapability: return "capability";
        case DynvcCmd::kDataFirstCompressed: return "data-first-compressed";
        case DynvcCmd::kDataCompressed: return "data-compressed";
        case DynvcCmd::kSoftSyncRequest: return "soft-sync-request";
        case DynvcCmd::kSoftSyncResponse: return "soft-sync-response";
    }
    return "unknown";
}

Status DynvcHeader::parse(const uint8_t* data, size_t size, DynvcHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    const uint8_t h = data[0];
    out.cb_id = static_cast<uint8_t>(h & 0x03);
    out.sp = static_cast<uint8_t>((h >> 2) & 0x03);
    out.len_bits = out.sp;
    out.cmd = static_cast<DynvcCmd>((h >> 4) & 0x0F);
    return Status::Ok;
}

void DynvcHeader::write(ByteWriter& w) const {
    w.u8(static_cast<uint8_t>((static_cast<uint8_t>(cmd) << 4) |
                              ((sp & 0x03) << 2) | (cb_id & 0x03)));
}

Status ParseDynvcChannelId(const DynvcHeader& header, const uint8_t* data,
                           size_t size, uint32_t& out) {
    if (!header.valid()) return Status::InvalidField;
    const size_t n = header.channel_id_size();
    if (data == nullptr || size < n) return Status::NeedMoreData;
    uint32_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        v |= static_cast<uint32_t>(data[i]) << (8 * i);
    }
    out = v;
    return Status::Ok;
}

Status DynvcPdu::parse(const uint8_t* data, size_t size, DynvcPdu& out) {
    out.data.clear();
    out.length = 0;
    Status s = DynvcHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    if (!out.header.valid()) return Status::InvalidField;

    s = ParseDynvcChannelId(out.header, data + DynvcHeader::kSize,
                            size - DynvcHeader::kSize, out.channel_id);
    if (s != Status::Ok) return s;

    size_t off = DynvcHeader::kSize + out.header.channel_id_size();
    if (out.header.cmd == DynvcCmd::kDataFirst) {
        // DYNVC_DATA_FIRST ([MS-RDPEDYC] 2.2.3.1): Length (4 bytes) follows the
        // ChannelId and precedes the first data fragment.
        ByteReader r(data + off, size - off);
        if (!r.u32le(out.length)) return Status::NeedMoreData;
        off += 4;
    } else if (out.header.cmd == DynvcCmd::kDataFirstCompressed) {
        // DYNVC_DATA_FIRST_COMPRESSED ([MS-RDPEDYC] 2.2.3.3): the header Len
        // bits select a 1-, 2- or 4-byte Length; Len=3 is invalid.
        if (out.header.len_bits == 3) return Status::InvalidField;
        const size_t n = out.header.length_size();
        if (size - off < n) return Status::NeedMoreData;
        for (size_t i = 0; i < n; ++i) {
            out.length |= static_cast<uint32_t>(data[off + i]) << (8 * i);
        }
        off += n;
    }
    out.data.assign(data + off, data + size);
    return Status::Ok;
}

std::vector<uint8_t> BuildDynvcDataFirstPdu(uint8_t sp, uint32_t channel_id,
                                            uint32_t total_length,
                                            const std::vector<uint8_t>& data) {
    DynvcHeader h;
    h.cmd = DynvcCmd::kDataFirst;
    h.sp = sp;
    h.cb_id = (channel_id <= 0xFF) ? 0 : (channel_id <= 0xFFFF ? 1 : 2);

    ByteWriter w;
    h.write(w);
    const size_t n = h.channel_id_size();
    for (size_t i = 0; i < n; ++i) {
        w.u8(static_cast<uint8_t>((channel_id >> (8 * i)) & 0xFF));
    }
    w.u32le(total_length);
    if (!data.empty()) w.bytes(data.data(), data.size());
    return w.take();
}

std::vector<uint8_t> BuildDynvcPdu(DynvcCmd cmd, uint8_t sp, uint32_t channel_id,
                                   const std::vector<uint8_t>& data) {
    if (cmd == DynvcCmd::kDataFirst) {
        return BuildDynvcDataFirstPdu(sp, channel_id,
                                      static_cast<uint32_t>(data.size()), data);
    }
    DynvcHeader h;
    h.cmd = cmd;
    h.sp = sp;
    h.cb_id = (channel_id <= 0xFF) ? 0 : (channel_id <= 0xFFFF ? 1 : 2);

    ByteWriter w;
    h.write(w);
    const size_t n = h.channel_id_size();
    for (size_t i = 0; i < n; ++i) {
        w.u8(static_cast<uint8_t>((channel_id >> (8 * i)) & 0xFF));
    }
    if (!data.empty()) w.bytes(data.data(), data.size());
    return w.take();
}

std::vector<uint8_t> BuildDynvcDataFirstCompressedPdu(
    uint8_t len_bits, uint32_t channel_id, uint32_t total_length,
    const std::vector<uint8_t>& data) {
    DynvcHeader h;
    h.cmd = DynvcCmd::kDataFirstCompressed;
    h.len_bits = (len_bits <= 2) ? len_bits : 2;
    h.sp = h.len_bits;  // Len and Sp share the same wire bits.
    h.cb_id = (channel_id <= 0xFF) ? 0 : (channel_id <= 0xFFFF ? 1 : 2);

    ByteWriter w;
    h.write(w);
    const size_t n = h.channel_id_size();
    for (size_t i = 0; i < n; ++i) {
        w.u8(static_cast<uint8_t>((channel_id >> (8 * i)) & 0xFF));
    }
    const size_t len_size = h.length_size();
    for (size_t i = 0; i < len_size; ++i) {
        w.u8(static_cast<uint8_t>((total_length >> (8 * i)) & 0xFF));
    }
    if (!data.empty()) w.bytes(data.data(), data.size());
    return w.take();
}

std::vector<std::vector<uint8_t>> BuildDynvcDataPdus(
    uint32_t channel_id, const std::vector<uint8_t>& data,
    size_t max_fragment) {
    std::vector<std::vector<uint8_t>> pdus;
    if (max_fragment == 0) max_fragment = 1500;

    if (data.size() <= kMaxSingleDataPduPayload) {
        // Single-PDU message: Cmd = Data, no Length field ([MS-RDPEDYC]
        // 2.2.3.2; the empty message is a zero-length DYNVC_DATA).
        pdus.push_back(BuildDynvcPdu(DynvcCmd::kData, 0, channel_id, data));
        return pdus;
    }

    const uint32_t total = static_cast<uint32_t>(data.size());
    size_t offset = 0;
    bool first = true;
    while (offset < data.size()) {
        const size_t n = std::min(max_fragment, data.size() - offset);
        const std::vector<uint8_t> chunk(data.begin() + offset,
                                         data.begin() + offset + n);
        if (first) {
            pdus.push_back(BuildDynvcDataFirstPdu(0, channel_id, total, chunk));
            first = false;
        } else {
            pdus.push_back(BuildDynvcPdu(DynvcCmd::kData, 0, channel_id, chunk));
        }
        offset += n;
    }
    return pdus;
}

bool DynvcReassembler::Feed(const DynvcPdu& pdu, std::vector<uint8_t>& message) {
    switch (pdu.header.cmd) {
        case DynvcCmd::kDataFirst: {
            // A new message begins on this channel; any half-assembled
            // sequence is discarded. Length is authoritative: a fragment that
            // already exceeds it is a protocol error and is not delivered.
            Reset(pdu.channel_id);
            if (pdu.length > kMaxMessageLength) return false;
            if (pdu.data.size() > pdu.length) return false;
            if (pdu.data.size() == pdu.length) {
                message = pdu.data;
                return true;
            }
            if (state_.find(pdu.channel_id) == state_.end() &&
                state_.size() >= kMaxPendingChannels) {
                return false;
            }
            State& state = state_[pdu.channel_id];
            state.expected_length = pdu.length;
            state.data = pdu.data;
            buffered_bytes_ += state.data.size();
            return false;
        }
        case DynvcCmd::kData: {
            const auto it = state_.find(pdu.channel_id);
            if (it == state_.end()) {
                // Not preceded by DYNVC_DATA_FIRST: the PDU carries a whole
                // message of at most 1,590 bytes ([MS-RDPEDYC] 2.2.3.2 /
                // 3.1.5.2.2) and is delivered as-is.
                message = pdu.data;
                return true;
            }
            State& state = it->second;
            if (state.data.size() + pdu.data.size() > state.expected_length) {
                buffered_bytes_ -= state.data.size();
                state_.erase(it);
                return false;
            }
            state.data.insert(state.data.end(), pdu.data.begin(),
                              pdu.data.end());
            buffered_bytes_ += pdu.data.size();
            if (state.data.size() == state.expected_length) {
                buffered_bytes_ -= state.data.size();
                message = std::move(state.data);
                state_.erase(it);
                return true;
            }
            if (buffered_bytes_ > kMaxBufferedBytes) {
                buffered_bytes_ -= state.data.size();
                state_.erase(it);
            }
            return false;
        }
        default:
            return false;
    }
}

void DynvcReassembler::Reset(uint32_t channel_id) {
    const auto it = state_.find(channel_id);
    if (it == state_.end()) return;
    buffered_bytes_ -= it->second.data.size();
    state_.erase(it);
}

void DynvcReassembler::ResetAll() {
    state_.clear();
    buffered_bytes_ = 0;
}

}  // namespace rtsc::proto
