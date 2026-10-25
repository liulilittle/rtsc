#include "rtsc/proto/finalization.h"

namespace rtsc::proto {

const char* to_string(ControlAction action) {
    switch (action) {
        case ControlAction::kRequestControl: return "request-control";
        case ControlAction::kGrantedControl: return "granted-control";
        case ControlAction::kDetach: return "detach";
        case ControlAction::kCooperate: return "cooperate";
    }
    return "unknown";
}

// ---- SynchronizePdu -------------------------------------------------------

Status SynchronizePdu::parse(const uint8_t* data, size_t size,
                             SynchronizePdu& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ShareDataHeader header;
    Status s = ShareDataHeader::parse(data, size, header);
    if (s != Status::Ok) return s;
    if (header.pdu_type2 != ShareDataPduType::kSynchronize) {
        return Status::InvalidType;
    }
    // The payload starts right after the 18-byte share data header.
    ByteReader r(data + ShareDataHeader::kSize, size - ShareDataHeader::kSize);
    if (!r.u16le(out.message_type)) return Status::NeedMoreData;
    if (!r.u16le(out.target_user)) return Status::NeedMoreData;
    if (out.message_type != kSyncMsgType) return Status::InvalidField;
    return Status::Ok;
}

void SynchronizePdu::write(ByteWriter& w, const ShareDataHeader& header) const {
    ShareDataHeader h = header;
    h.pdu_type2 = ShareDataPduType::kSynchronize;
    h.control.total_length = kSize;
    h.write(w);
    w.u16le(message_type);
    w.u16le(target_user);
}

// ---- ControlPdu -----------------------------------------------------------

Status ControlPdu::parse(const uint8_t* data, size_t size, ControlPdu& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ShareDataHeader header;
    Status s = ShareDataHeader::parse(data, size, header);
    if (s != Status::Ok) return s;
    if (header.pdu_type2 != ShareDataPduType::kControl) return Status::InvalidType;

    ByteReader r(data + ShareDataHeader::kSize, size - ShareDataHeader::kSize);
    uint16_t action = 0;
    if (!r.u16le(action)) return Status::NeedMoreData;
    switch (action) {
        case 0x0001: out.action = ControlAction::kRequestControl; break;
        case 0x0002: out.action = ControlAction::kGrantedControl; break;
        case 0x0003: out.action = ControlAction::kDetach; break;
        case 0x0004: out.action = ControlAction::kCooperate; break;
        default:
            // Values outside 1..4 map to ERRINFO_INVALIDCONTROLPDUACTION.
            return Status::InvalidField;
    }
    if (!r.u16le(out.grant_id)) return Status::NeedMoreData;
    if (!r.u32le(out.control_id)) return Status::NeedMoreData;
    // grant_id / control_id MUST be ignored: the server sends non-zero values in
    // Granted Control, so validating them would reject a real server.
    return Status::Ok;
}

void ControlPdu::write(ByteWriter& w, const ShareDataHeader& header) const {
    ShareDataHeader h = header;
    h.pdu_type2 = ShareDataPduType::kControl;
    h.control.total_length = kSize;
    h.write(w);
    w.u16le(static_cast<uint16_t>(action));
    w.u16le(grant_id);
    w.u32le(control_id);
}

// ---- FontListPdu ----------------------------------------------------------

Status FontListPdu::parse(const uint8_t* data, size_t size, FontListPdu& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ShareDataHeader header;
    Status s = ShareDataHeader::parse(data, size, header);
    if (s != Status::Ok) return s;
    if (header.pdu_type2 != ShareDataPduType::kFontList) return Status::InvalidType;

    ByteReader r(data + ShareDataHeader::kSize, size - ShareDataHeader::kSize);
    if (!r.u16le(out.number_fonts)) return Status::NeedMoreData;
    if (!r.u16le(out.total_num_fonts)) return Status::NeedMoreData;
    if (!r.u16le(out.list_flags)) return Status::NeedMoreData;
    if (!r.u16le(out.entry_size)) return Status::NeedMoreData;
    return Status::Ok;
}

void FontListPdu::write(ByteWriter& w, const ShareDataHeader& header) const {
    ShareDataHeader h = header;
    h.pdu_type2 = ShareDataPduType::kFontList;
    h.control.total_length = kSize;
    h.write(w);
    w.u16le(number_fonts);
    w.u16le(total_num_fonts);
    w.u16le(list_flags);
    w.u16le(entry_size);
}

// ---- FontMapPdu -----------------------------------------------------------

Status FontMapPdu::parse(const uint8_t* data, size_t size, FontMapPdu& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ShareDataHeader header;
    Status s = ShareDataHeader::parse(data, size, header);
    if (s != Status::Ok) return s;
    if (header.pdu_type2 != ShareDataPduType::kFontMap) return Status::InvalidType;

    ByteReader r(data + ShareDataHeader::kSize, size - ShareDataHeader::kSize);
    if (!r.u16le(out.number_entries)) return Status::NeedMoreData;
    if (!r.u16le(out.total_num_entries)) return Status::NeedMoreData;
    if (!r.u16le(out.map_flags)) return Status::NeedMoreData;
    if (!r.u16le(out.entry_size)) return Status::NeedMoreData;
    return Status::Ok;
}

void FontMapPdu::write(ByteWriter& w, const ShareDataHeader& header) const {
    ShareDataHeader h = header;
    h.pdu_type2 = ShareDataPduType::kFontMap;
    h.control.total_length = kSize;
    h.write(w);
    w.u16le(number_entries);
    w.u16le(total_num_entries);
    w.u16le(map_flags);
    w.u16le(entry_size);
}

// ---- DeactivateAllPdu -----------------------------------------------------

Status DeactivateAllPdu::parse(const uint8_t* data, size_t size,
                               DeactivateAllPdu& out) {
    // shareControlHeader (6) + shareID (4) + lengthSourceDescriptor (2) = 12
    if (data == nullptr || size < 12) return Status::NeedMoreData;
    ShareControlHeader control;
    Status s = ShareControlHeader::parse(data, size, control);
    if (s != Status::Ok) return s;
    if (control.type != SharePduType::kDeactivateAll) return Status::InvalidType;
    if (control.pdu_version != ShareControlHeader::kProtocolVersion) {
        return Status::InvalidVersion;
    }

    ByteReader r(data, size);
    if (!r.skip(ShareControlHeader::kSize)) return Status::NeedMoreData;
    if (!r.u32le(out.share_id)) return Status::NeedMoreData;
    uint16_t src_len = 0;
    if (!r.u16le(src_len)) return Status::NeedMoreData;
    if (src_len > r.remaining()) return Status::InvalidLength;
    out.source_descriptor.resize(src_len);
    if (src_len != 0 && !r.bytes(out.source_descriptor.data(), src_len)) {
        return Status::InvalidLength;
    }
    if (control.total_length != size) return Status::InvalidLength;
    return Status::Ok;
}

// ---- PersistentKeyListPdu -------------------------------------------------

Status PersistentKeyListPdu::parse(const uint8_t* data, size_t size,
                                   PersistentKeyListPdu& out) {
    if (data == nullptr || size < kFixedSize) return Status::NeedMoreData;
    ShareDataHeader header;
    Status s = ShareDataHeader::parse(data, size, header);
    if (s != Status::Ok) return s;
    if (header.pdu_type2 != ShareDataPduType::kPersistentKeyList) {
        return Status::InvalidType;
    }

    ByteReader r(data + ShareDataHeader::kSize, size - ShareDataHeader::kSize);
    size_t total_keys = 0;
    for (uint16_t& n : out.num_entries) {
        if (!r.u16le(n)) return Status::NeedMoreData;
        total_keys += n;
    }
    uint64_t declared_total = 0;
    for (uint16_t& n : out.total_entries) {
        if (!r.u16le(n)) return Status::NeedMoreData;
        declared_total += n;
    }
    if (!r.u8(out.bit_mask)) return Status::NeedMoreData;
    uint8_t pad2 = 0;
    if (!r.u8(pad2)) return Status::NeedMoreData;
    uint16_t pad3 = 0;
    if (!r.u16le(pad3)) return Status::NeedMoreData;

    // The declared grand total is capped at 262144 keys by the specification.
    if (declared_total > kMaxTotalKeys) return Status::InvalidField;
    // The entry count is the only reliable bound for the trailing array: without
    // it a corrupted count would over-read.
    const size_t needed = total_keys * kEntrySize;
    if (r.remaining() < needed) return Status::InvalidLength;

    out.key1.clear();
    out.key2.clear();
    out.key1.reserve(total_keys);
    out.key2.reserve(total_keys);
    for (size_t i = 0; i < total_keys; ++i) {
        uint32_t k1 = 0, k2 = 0;
        if (!r.u32le(k1)) return Status::NeedMoreData;
        if (!r.u32le(k2)) return Status::NeedMoreData;
        out.key1.push_back(k1);
        out.key2.push_back(k2);
    }
    // totalLength must equal header + fixed fields + entries.
    if (header.control.total_length != size) return Status::InvalidLength;
    return Status::Ok;
}

// ---- Framing helper -------------------------------------------------------

std::vector<uint8_t> BuildSlowPathDataPdu(uint16_t pdu_source, uint32_t share_id,
                                          uint8_t stream_id,
                                          ShareDataPduType pdu_type2,
                                          const std::vector<uint8_t>& payload) {
    ShareDataHeader header;
    header.control.total_length =
        static_cast<uint16_t>(ShareDataHeader::kSize + payload.size());
    header.control.type = SharePduType::kData;
    header.control.pdu_version = ShareControlHeader::kProtocolVersion;
    header.control.pdu_source = pdu_source;
    header.share_id = share_id;
    header.pad1 = 0;
    header.stream_id = stream_id;
    // uncompressedLength is a declaration only; the reference implementation even
    // leaves it uninitialized, so it carries the payload size here.
    header.uncompressed_length = static_cast<uint16_t>(payload.size());
    header.pdu_type2 = pdu_type2;
    header.compressed_type = 0;
    header.compressed_length = 0;

    ByteWriter w;
    header.write(w);
    if (!payload.empty()) w.bytes(payload.data(), payload.size());
    return w.take();
}

}  // namespace rtsc::proto
