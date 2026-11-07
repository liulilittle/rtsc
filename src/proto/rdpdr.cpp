// Device redirection virtual channel (rdpdr) structure layer ([MS-RDPEFS] 2.2).

#include "rtsc/proto/rdpdr.h"

namespace rtsc::proto {

namespace {

// Reads the RDPDR_HEADER and asserts the component and packet id. Returns
// false when the span is too short or the id does not match.
bool ReadCoreHeader(const uint8_t* data, size_t size, uint16_t expected_id,
                    RdpdrHeader& out) {
    if (data == nullptr || size < RdpdrHeader::kSize) return false;
    ByteReader r(data, size);
    r.u16le(out.component);
    r.u16le(out.packet_id);
    return out.component == kRdpdrCtypCore && out.packet_id == expected_id;
}

uint64_t ReadU64Le(ByteReader& r) {
    const uint8_t* p = r.cursor();
    const uint32_t lo = static_cast<uint32_t>(p[0]) |
                        (static_cast<uint32_t>(p[1]) << 8) |
                        (static_cast<uint32_t>(p[2]) << 16) |
                        (static_cast<uint32_t>(p[3]) << 24);
    const uint32_t hi = static_cast<uint32_t>(p[4]) |
                        (static_cast<uint32_t>(p[5]) << 8) |
                        (static_cast<uint32_t>(p[6]) << 16) |
                        (static_cast<uint32_t>(p[7]) << 24);
    r.skip(8);
    return static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
}

uint16_t ReadU16Le(const uint8_t* p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                 (static_cast<uint16_t>(p[1]) << 8));
}

}  // namespace

const char* to_string(RdpdrPacketId id) {
    switch (id) {
        case kPakidCoreServerAnnounce: return "server-announce";
        case kPakidCoreClientidConfirm: return "clientid-confirm";
        case kPakidCoreClientName: return "client-name";
        case kPakidCoreDevicelistAnnounce: return "devicelist-announce";
        case kPakidCoreDeviceReply: return "device-reply";
        case kPakidCoreDeviceIorequest: return "device-io-request";
        case kPakidCoreDeviceIocompletion: return "device-io-completion";
        case kPakidCoreServerCapability: return "server-capability";
        case kPakidCoreClientCapability: return "client-capability";
        case kPakidCoreDevicelistRemove: return "devicelist-remove";
        case kPakidCoreUserLoggedon: return "user-logged-on";
    }
    return "unknown";
}

Status RdpdrHeader::parse(const uint8_t* data, size_t size, RdpdrHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ByteReader r(data, size);
    r.u16le(out.component);
    r.u16le(out.packet_id);
    return Status::Ok;
}

void RdpdrHeader::write(ByteWriter& w) const {
    w.u16le(component);
    w.u16le(packet_id);
}

Status RdpdrServerAnnounce::parse(const uint8_t* data, size_t size,
                                  RdpdrServerAnnounce& out) {
    if (data == nullptr || size < 12) return Status::NeedMoreData;
    RdpdrHeader header;
    if (!ReadCoreHeader(data, size, kPakidCoreServerAnnounce, header)) {
        return Status::InvalidType;
    }
    ByteReader r(data + RdpdrHeader::kSize, size - RdpdrHeader::kSize);
    r.u16le(out.version_major);
    r.u16le(out.version_minor);
    r.u32le(out.client_id);
    return Status::Ok;
}

std::vector<uint8_t> RdpdrServerAnnounce::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreServerAnnounce;
    ByteWriter w;
    header.write(w);
    w.u16le(version_major);
    w.u16le(version_minor);
    w.u32le(client_id);
    return w.take();
}

Status RdpdrClientAnnounceReply::parse(const uint8_t* data, size_t size,
                                       RdpdrClientAnnounceReply& out) {
    if (data == nullptr || size < 12) return Status::NeedMoreData;
    RdpdrHeader header;
    if (!ReadCoreHeader(data, size, kPakidCoreClientidConfirm, header)) {
        return Status::InvalidType;
    }
    ByteReader r(data + RdpdrHeader::kSize, size - RdpdrHeader::kSize);
    r.u16le(out.version_major);
    r.u16le(out.version_minor);
    r.u32le(out.client_id);
    return Status::Ok;
}

std::vector<uint8_t> RdpdrClientAnnounceReply::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreClientidConfirm;
    ByteWriter w;
    header.write(w);
    w.u16le(version_major);
    w.u16le(version_minor);
    w.u32le(client_id);
    return w.take();
}

Status RdpdrServerClientIdConfirm::parse(const uint8_t* data, size_t size,
                                         RdpdrServerClientIdConfirm& out) {
    if (data == nullptr || size < 12) return Status::NeedMoreData;
    RdpdrHeader header;
    if (!ReadCoreHeader(data, size, kPakidCoreClientidConfirm, header)) {
        return Status::InvalidType;
    }
    ByteReader r(data + RdpdrHeader::kSize, size - RdpdrHeader::kSize);
    r.u16le(out.version_major);
    r.u16le(out.version_minor);
    r.u32le(out.client_id);
    return Status::Ok;
}

std::vector<uint8_t> RdpdrServerClientIdConfirm::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreClientidConfirm;
    ByteWriter w;
    header.write(w);
    w.u16le(version_major);
    w.u16le(version_minor);
    w.u32le(client_id);
    return w.take();
}

Status RdpdrClientNameRequest::parse(const std::vector<uint8_t>& data,
                                     RdpdrClientNameRequest& out) {
    out.computer_name.clear();
    if (data.size() < 16) return Status::NeedMoreData;
    RdpdrHeader header;
    if (!ReadCoreHeader(data.data(), data.size(), kPakidCoreClientName,
                        header)) {
        return Status::InvalidType;
    }
    ByteReader r(data.data() + RdpdrHeader::kSize,
                 data.size() - RdpdrHeader::kSize);
    r.u32le(out.unicode_flag);
    r.u32le(out.code_page);
    r.u32le(out.computer_name_len);
    if (out.computer_name_len > r.remaining()) return Status::NeedMoreData;
    out.computer_name.assign(r.cursor(), r.cursor() + out.computer_name_len);
    return Status::Ok;
}

std::vector<uint8_t> RdpdrClientNameRequest::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreClientName;
    ByteWriter w;
    header.write(w);
    w.u32le(unicode_flag);
    w.u32le(code_page);
    w.u32le(computer_name_len);
    w.bytes(computer_name.data(), computer_name.size());
    return w.take();
}

Status RdpdrCapabilityHeader::parse(const uint8_t* data, size_t size,
                                    RdpdrCapabilityHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ByteReader r(data, size);
    r.u16le(out.capability_type);
    r.u16le(out.capability_length);
    r.u32le(out.version);
    return Status::Ok;
}

void RdpdrCapabilityHeader::write(ByteWriter& w) const {
    w.u16le(capability_type);
    w.u16le(capability_length);
    w.u32le(version);
}

Status RdpdrCapabilitySet::parse(const uint8_t* data, size_t size,
                                 RdpdrCapabilitySet& out) {
    out.data.clear();
    if (data == nullptr || size < RdpdrCapabilityHeader::kSize) {
        return Status::NeedMoreData;
    }
    if (RdpdrCapabilityHeader::parse(data, size, out.header) != Status::Ok) {
        return Status::NeedMoreData;
    }
    if (out.header.capability_length < RdpdrCapabilityHeader::kSize ||
        static_cast<size_t>(out.header.capability_length) > size) {
        return Status::InvalidLength;
    }
    out.data.assign(data + RdpdrCapabilityHeader::kSize,
                    data + out.header.capability_length);
    return Status::Ok;
}

std::vector<uint8_t> RdpdrCapabilitySet::encode() const {
    ByteWriter w;
    header.write(w);
    w.bytes(data.data(), data.size());
    return w.take();
}

Status RdpdrGeneralCapsSet::parse(const std::vector<uint8_t>& data,
                                  uint32_t version,
                                  RdpdrGeneralCapsSet& out) {
    const size_t expected = version >= kGeneralCapabilityVersion02
                                ? kVersion02Size
                                : kVersion01Size;
    if (data.size() < expected) return Status::NeedMoreData;
    ByteReader r(data.data(), data.size());
    r.u32le(out.os_type);
    r.u32le(out.os_version);
    r.u16le(out.protocol_major_version);
    r.u16le(out.protocol_minor_version);
    r.u32le(out.io_code1);
    r.u32le(out.io_code2);
    r.u32le(out.extended_pdu);
    r.u32le(out.extra_flags1);
    r.u32le(out.extra_flags2);
    if (version >= kGeneralCapabilityVersion02) {
        r.u32le(out.special_type_device_cap);
    }
    return Status::Ok;
}

std::vector<uint8_t> RdpdrGeneralCapsSet::encode(uint32_t version) const {
    ByteWriter w;
    w.u32le(os_type);
    w.u32le(os_version);
    w.u16le(protocol_major_version);
    w.u16le(protocol_minor_version);
    w.u32le(io_code1);
    w.u32le(io_code2);
    w.u32le(extended_pdu);
    w.u32le(extra_flags1);
    w.u32le(extra_flags2);
    if (version >= kGeneralCapabilityVersion02) {
        w.u32le(special_type_device_cap);
    }
    return w.take();
}

Status RdpdrDriveCapsSet::parse(const std::vector<uint8_t>& data,
                                RdpdrDriveCapsSet& out) {
    (void)data;
    (void)out;
    return Status::Ok;
}

std::vector<uint8_t> RdpdrDriveCapsSet::encode() const { return {}; }

Status RdpdrCoreCapability::parse(const std::vector<uint8_t>& data,
                                  RdpdrCoreCapability& out) {
    out.capabilities.clear();
    if (data.size() < kFixedSize) return Status::NeedMoreData;
    RdpdrHeader header;
    ByteReader hr(data.data(), data.size());
    hr.u16le(header.component);
    hr.u16le(header.packet_id);
    if (header.component != kRdpdrCtypCore ||
        (header.packet_id != kPakidCoreServerCapability &&
         header.packet_id != kPakidCoreClientCapability)) {
        return Status::InvalidType;
    }
    ByteReader r(data.data() + RdpdrHeader::kSize,
                 data.size() - RdpdrHeader::kSize);
    r.u16le(out.num_capabilities);
    r.u16le(out.padding);
    size_t offset = RdpdrHeader::kSize + 4;
    for (uint16_t i = 0; i < out.num_capabilities; ++i) {
        if (offset >= data.size()) return Status::NeedMoreData;
        RdpdrCapabilitySet set;
        if (RdpdrCapabilitySet::parse(data.data() + offset, data.size() - offset,
                                      set) != Status::Ok) {
            return Status::NeedMoreData;
        }
        offset += set.header.capability_length;
        out.capabilities.push_back(std::move(set));
    }
    return Status::Ok;
}

std::vector<uint8_t> RdpdrCoreCapability::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreClientCapability;
    ByteWriter w;
    header.write(w);
    w.u16le(static_cast<uint16_t>(capabilities.size()));
    w.u16le(padding);
    for (const auto& set : capabilities) {
        const std::vector<uint8_t> encoded = set.encode();
        w.bytes(encoded.data(), encoded.size());
    }
    return w.take();
}

Status RdpdrDeviceAnnounce::parse(const uint8_t* data, size_t size,
                                  RdpdrDeviceAnnounce& out) {
    out.device_data.clear();
    out.preferred_dos_name.fill(0);
    if (data == nullptr || size < kFixedSize) return Status::NeedMoreData;
    ByteReader r(data, size);
    r.u32le(out.device_type);
    r.u32le(out.device_id);
    for (size_t i = 0; i < kDosNameSize; ++i) {
        uint8_t b = 0;
        if (!r.u8(b)) return Status::NeedMoreData;
        out.preferred_dos_name[i] = b;
    }
    r.u32le(out.device_data_length);
    if (out.device_data_length > r.remaining()) return Status::NeedMoreData;
    out.device_data.assign(r.cursor(), r.cursor() + out.device_data_length);
    return Status::Ok;
}

std::vector<uint8_t> EncodePrinterAnnounce(
    uint32_t flags, const std::u16string& driver_name,
    const std::u16string& printer_name, const std::u16string& pnp_name,
    const std::vector<uint8_t>& cached_data) {
    const auto utf16z = [](const std::u16string& text, bool with_nul) {
        std::vector<uint8_t> out;
        out.reserve((text.size() + 1) * 2);
        for (const char16_t c : text) {
            out.push_back(static_cast<uint8_t>(c & 0xFF));
            out.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
        }
        if (with_nul) {
            out.push_back(0);
            out.push_back(0);
        }
        return out;
    };
    const std::vector<uint8_t> pnp = utf16z(pnp_name, !pnp_name.empty());
    const std::vector<uint8_t> driver = utf16z(driver_name, true);
    const std::vector<uint8_t> printer = utf16z(printer_name, true);
    ByteWriter w;
    w.u32le(flags);
    w.u32le(0);  // CodePage MUST be 0
    w.u32le(static_cast<uint32_t>(pnp.size()));
    w.u32le(static_cast<uint32_t>(driver.size()));
    w.u32le(static_cast<uint32_t>(printer.size()));
    w.u32le(static_cast<uint32_t>(cached_data.size()));
    w.bytes(pnp.data(), pnp.size());
    w.bytes(driver.data(), driver.size());
    w.bytes(printer.data(), printer.size());
    w.bytes(cached_data.data(), cached_data.size());
    return w.take();
}

std::vector<uint8_t> RdpdrDeviceAnnounce::encode() const {
    ByteWriter w;
    w.u32le(device_type);
    w.u32le(device_id);
    for (uint8_t b : preferred_dos_name) w.u8(b);
    w.u32le(device_data_length);
    w.bytes(device_data.data(), device_data.size());
    return w.take();
}

std::string RdpdrDeviceAnnounce::dos_name() const {
    size_t len = 0;
    while (len < kDosNameSize && preferred_dos_name[len] != 0) ++len;
    return std::string(reinterpret_cast<const char*>(preferred_dos_name.data()),
                       len);
}

Status RdpdrDeviceListAnnounce::parse(const std::vector<uint8_t>& data,
                                      RdpdrDeviceListAnnounce& out) {
    out.devices.clear();
    if (data.size() < 8) return Status::NeedMoreData;
    RdpdrHeader header;
    if (!ReadCoreHeader(data.data(), data.size(),
                        kPakidCoreDevicelistAnnounce, header)) {
        return Status::InvalidType;
    }
    ByteReader r(data.data() + RdpdrHeader::kSize,
                 data.size() - RdpdrHeader::kSize);
    r.u32le(out.device_count);
    size_t offset = RdpdrHeader::kSize + 4;
    for (uint32_t i = 0; i < out.device_count; ++i) {
        if (offset >= data.size()) return Status::NeedMoreData;
        RdpdrDeviceAnnounce device;
        if (RdpdrDeviceAnnounce::parse(data.data() + offset,
                                       data.size() - offset, device) !=
            Status::Ok) {
            return Status::NeedMoreData;
        }
        offset += RdpdrDeviceAnnounce::kFixedSize + device.device_data_length;
        out.devices.push_back(std::move(device));
    }
    return Status::Ok;
}

std::vector<uint8_t> RdpdrDeviceListAnnounce::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreDevicelistAnnounce;
    ByteWriter w;
    header.write(w);
    w.u32le(static_cast<uint32_t>(devices.size()));
    for (const auto& device : devices) {
        const std::vector<uint8_t> encoded = device.encode();
        w.bytes(encoded.data(), encoded.size());
    }
    return w.take();
}

Status RdpdrDeviceListRemove::parse(const std::vector<uint8_t>& data,
                                    RdpdrDeviceListRemove& out) {
    out.device_ids.clear();
    if (data.size() < RdpdrHeader::kSize + 4) return Status::NeedMoreData;
    RdpdrHeader header;
    if (!ReadCoreHeader(data.data(), data.size(),
                        kPakidCoreDevicelistRemove, header)) {
        return Status::InvalidType;
    }
    ByteReader r(data.data() + RdpdrHeader::kSize,
                 data.size() - RdpdrHeader::kSize);
    r.u32le(out.device_count);
    // Each id is 4 bytes; a count that cannot fit the remaining body is a
    // truncated message, not a reason to read past the buffer.
    const size_t remaining = data.size() - RdpdrHeader::kSize - 4;
    if (static_cast<uint64_t>(out.device_count) * 4 > remaining) {
        return Status::NeedMoreData;
    }
    out.device_ids.reserve(out.device_count);
    for (uint32_t i = 0; i < out.device_count; ++i) {
        uint32_t id = 0;
        r.u32le(id);
        out.device_ids.push_back(id);
    }
    return Status::Ok;
}

std::vector<uint8_t> RdpdrDeviceListRemove::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreDevicelistRemove;
    ByteWriter w;
    header.write(w);
    w.u32le(static_cast<uint32_t>(device_ids.size()));
    for (const uint32_t id : device_ids) w.u32le(id);
    return w.take();
}

Status RdpdrDeviceReply::parse(const std::vector<uint8_t>& data,
                               RdpdrDeviceReply& out) {
    if (data.size() < 12) return Status::NeedMoreData;
    RdpdrHeader header;
    if (!ReadCoreHeader(data.data(), data.size(), kPakidCoreDeviceReply,
                        header)) {
        return Status::InvalidType;
    }
    ByteReader r(data.data() + RdpdrHeader::kSize,
                 data.size() - RdpdrHeader::kSize);
    r.u32le(out.device_id);
    r.u32le(out.result_code);
    return Status::Ok;
}

std::vector<uint8_t> RdpdrDeviceReply::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreDeviceReply;
    ByteWriter w;
    header.write(w);
    w.u32le(device_id);
    w.u32le(result_code);
    return w.take();
}

Status RdpdrDeviceIoRequest::parse(const std::vector<uint8_t>& data,
                                   RdpdrDeviceIoRequest& out) {
    if (data.size() < kFixedSize) return Status::NeedMoreData;
    ByteReader r(data.data(), data.size());
    r.u32le(out.device_id);
    r.u32le(out.file_id);
    r.u32le(out.completion_id);
    r.u32le(out.major_function);
    r.u32le(out.minor_function);
    return Status::Ok;
}

std::vector<uint8_t> RdpdrDeviceIoRequest::encode() const {
    ByteWriter w;
    w.u32le(device_id);
    w.u32le(file_id);
    w.u32le(completion_id);
    w.u32le(major_function);
    w.u32le(minor_function);
    return w.take();
}

Status RdpdrDeviceIoCompletion::parse(const std::vector<uint8_t>& data,
                                      RdpdrDeviceIoCompletion& out) {
    if (data.size() < 12) return Status::NeedMoreData;
    ByteReader r(data.data(), data.size());
    r.u32le(out.device_id);
    r.u32le(out.completion_id);
    r.u32le(out.io_status);
    return Status::Ok;
}

std::vector<uint8_t> RdpdrDeviceIoCompletion::encode() const {
    ByteWriter w;
    w.u32le(device_id);
    w.u32le(completion_id);
    w.u32le(io_status);
    return w.take();
}

Status RdpdrCreateReq::parse(const std::vector<uint8_t>& data,
                             RdpdrCreateReq& out) {
    out.path.clear();
    if (data.size() < RdpdrDeviceIoRequest::kFixedSize + 32) {
        return Status::NeedMoreData;
    }
    if (RdpdrDeviceIoRequest::parse(data, out.request) != Status::Ok) {
        return Status::NeedMoreData;
    }
    ByteReader r(data.data() + RdpdrDeviceIoRequest::kFixedSize,
                 data.size() - RdpdrDeviceIoRequest::kFixedSize);
    r.u32le(out.desired_access);
    out.allocation_size = ReadU64Le(r);
    r.u32le(out.file_attributes);
    r.u32le(out.shared_access);
    r.u32le(out.create_disposition);
    r.u32le(out.create_options);
    r.u32le(out.path_length);
    if (out.path_length > r.remaining()) return Status::NeedMoreData;
    out.path.assign(r.cursor(), r.cursor() + out.path_length);
    return Status::Ok;
}

std::string RdpdrCreateReq::path_string() const {
    return RdpdrDecodeUtf16(path.data(), path.size());
}

std::vector<uint8_t> RdpdrCreateRsp::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreDeviceIocompletion;
    ByteWriter w;
    header.write(w);
    const std::vector<uint8_t> completion_bytes = completion.encode();
    w.bytes(completion_bytes.data(), completion_bytes.size());
    w.u32le(file_id);
    w.u8(information);
    return w.take();
}

Status RdpdrReadReq::parse(const std::vector<uint8_t>& data,
                           RdpdrReadReq& out) {
    if (data.size() < RdpdrDeviceIoRequest::kFixedSize + 12) {
        return Status::NeedMoreData;
    }
    if (RdpdrDeviceIoRequest::parse(data, out.request) != Status::Ok) {
        return Status::NeedMoreData;
    }
    ByteReader r(data.data() + RdpdrDeviceIoRequest::kFixedSize,
                 data.size() - RdpdrDeviceIoRequest::kFixedSize);
    r.u32le(out.length);
    out.offset = ReadU64Le(r);
    return Status::Ok;
}

std::vector<uint8_t> RdpdrReadRsp::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreDeviceIocompletion;
    ByteWriter w;
    header.write(w);
    const std::vector<uint8_t> completion_bytes = completion.encode();
    w.bytes(completion_bytes.data(), completion_bytes.size());
    w.u32le(length);
    w.bytes(data.data(), data.size());
    return w.take();
}

Status RdpdrWriteReq::parse(const std::vector<uint8_t>& data,
                            RdpdrWriteReq& out) {
    out.data.clear();
    if (data.size() < RdpdrDeviceIoRequest::kFixedSize + 12) {
        return Status::NeedMoreData;
    }
    if (RdpdrDeviceIoRequest::parse(data, out.request) != Status::Ok) {
        return Status::NeedMoreData;
    }
    ByteReader r(data.data() + RdpdrDeviceIoRequest::kFixedSize,
                 data.size() - RdpdrDeviceIoRequest::kFixedSize);
    r.u32le(out.length);
    out.offset = ReadU64Le(r);
    if (r.remaining() < 20) return Status::NeedMoreData;  // Padding (20 bytes)
    r.skip(20);
    if (out.length > r.remaining()) return Status::NeedMoreData;
    out.data.assign(r.cursor(), r.cursor() + out.length);
    return Status::Ok;
}

std::vector<uint8_t> RdpdrWriteRsp::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreDeviceIocompletion;
    ByteWriter w;
    header.write(w);
    const std::vector<uint8_t> completion_bytes = completion.encode();
    w.bytes(completion_bytes.data(), completion_bytes.size());
    w.u32le(length);
    return w.take();
}

Status RdpdrCloseReq::parse(const std::vector<uint8_t>& data,
                            RdpdrCloseReq& out) {
    if (RdpdrDeviceIoRequest::parse(data, out.request) != Status::Ok) {
        return Status::NeedMoreData;
    }
    return Status::Ok;
}

Status RdpdrQueryVolumeReq::parse(const std::vector<uint8_t>& data,
                                  RdpdrQueryVolumeReq& out) {
    out.buffer.clear();
    if (data.size() < kFixedSize) return Status::NeedMoreData;
    if (RdpdrDeviceIoRequest::parse(data, out.request) != Status::Ok) {
        return Status::NeedMoreData;
    }
    ByteReader r(data.data() + RdpdrDeviceIoRequest::kFixedSize,
                 data.size() - RdpdrDeviceIoRequest::kFixedSize);
    if (!r.u32le(out.fs_information_class)) return Status::NeedMoreData;
    if (!r.u32le(out.length)) return Status::NeedMoreData;
    // 24 bytes of padding follow; the buffer starts after them.
    const size_t available = data.size() - kFixedSize;
    if (out.length > available) return Status::NeedMoreData;
    out.buffer.assign(data.begin() + static_cast<ptrdiff_t>(kFixedSize),
                      data.begin() +
                          static_cast<ptrdiff_t>(kFixedSize + out.length));
    return Status::Ok;
}

std::vector<uint8_t> RdpdrCloseRsp::encode() const {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = kPakidCoreDeviceIocompletion;
    ByteWriter w;
    header.write(w);
    const std::vector<uint8_t> completion_bytes = completion.encode();
    w.bytes(completion_bytes.data(), completion_bytes.size());
    return w.take();
}

Status RdpdrQueryDirectoryReq::parse(const std::vector<uint8_t>& data,
                                     RdpdrQueryDirectoryReq& out) {
    out.path.clear();
    if (data.size() < RdpdrDeviceIoRequest::kFixedSize + 12) {
        return Status::NeedMoreData;
    }
    if (RdpdrDeviceIoRequest::parse(data, out.request) != Status::Ok) {
        return Status::NeedMoreData;
    }
    // FsInformationClass(4) + InitialQuery(1) + PathLength(4) + Padding(23).
    ByteReader r(data.data() + RdpdrDeviceIoRequest::kFixedSize,
                 data.size() - RdpdrDeviceIoRequest::kFixedSize);
    r.u32le(out.fs_information_class);
    r.u8(out.initial_query);
    r.u32le(out.path_length);
    if (r.remaining() < 23) return Status::NeedMoreData;  // Padding (23 bytes)
    r.skip(23);
    if (out.path_length > r.remaining()) return Status::NeedMoreData;
    out.path.assign(r.cursor(), r.cursor() + out.path_length);
    return Status::Ok;
}

std::string RdpdrQueryDirectoryReq::path_string() const {
    return RdpdrDecodeUtf16(path.data(), path.size());
}

Status RdpdrNotifyChangeDirectoryReq::parse(
    const std::vector<uint8_t>& data, RdpdrNotifyChangeDirectoryReq& out) {
    if (data.size() < kFixedSize) return Status::NeedMoreData;
    if (RdpdrDeviceIoRequest::parse(data, out.request) != Status::Ok) {
        return Status::NeedMoreData;
    }
    ByteReader r(data.data() + RdpdrDeviceIoRequest::kFixedSize,
                 data.size() - RdpdrDeviceIoRequest::kFixedSize);
    if (!r.u8(out.watch_tree)) return Status::NeedMoreData;
    if (!r.u32le(out.completion_filter)) return Status::NeedMoreData;
    // Padding (27 bytes): unused and ignored.
    return Status::Ok;
}

Status RdpdrLockReq::parse(const std::vector<uint8_t>& data,
                           RdpdrLockReq& out) {
    out.locks.clear();
    if (data.size() < kFixedSize) return Status::NeedMoreData;
    if (RdpdrDeviceIoRequest::parse(data, out.request) != Status::Ok) {
        return Status::NeedMoreData;
    }
    ByteReader r(data.data() + RdpdrDeviceIoRequest::kFixedSize,
                 data.size() - RdpdrDeviceIoRequest::kFixedSize);
    if (!r.u32le(out.operation)) return Status::NeedMoreData;
    if (!r.u32le(out.flags)) return Status::NeedMoreData;
    if (!r.u32le(out.num_locks)) return Status::NeedMoreData;
    if (r.remaining() < 20) return Status::NeedMoreData;
    r.skip(20);  // Padding2
    if (out.num_locks > r.remaining() / 16) return Status::NeedMoreData;
    out.locks.reserve(out.num_locks);
    for (uint32_t i = 0; i < out.num_locks; ++i) {
        uint32_t length_lo = 0;
        uint32_t length_hi = 0;
        uint32_t offset_lo = 0;
        uint32_t offset_hi = 0;
        if (!r.u32le(length_lo) || !r.u32le(length_hi)) {
            return Status::NeedMoreData;
        }
        if (!r.u32le(offset_lo) || !r.u32le(offset_hi)) {
            return Status::NeedMoreData;
        }
        RdpdrLockInfo lock;
        lock.length = (static_cast<uint64_t>(length_hi) << 32) | length_lo;
        lock.offset = (static_cast<uint64_t>(offset_hi) << 32) | offset_lo;
        out.locks.push_back(lock);
    }
    return Status::Ok;
}

Status RdpdrControlReq::parse(const std::vector<uint8_t>& data,
                              RdpdrControlReq& out) {
    out.input_buffer.clear();
    if (data.size() < RdpdrDeviceIoRequest::kFixedSize + 12) {
        return Status::NeedMoreData;
    }
    if (RdpdrDeviceIoRequest::parse(data, out.request) != Status::Ok) {
        return Status::NeedMoreData;
    }
    ByteReader r(data.data() + RdpdrDeviceIoRequest::kFixedSize,
                 data.size() - RdpdrDeviceIoRequest::kFixedSize);
    r.u32le(out.output_buffer_length);
    r.u32le(out.input_buffer_length);
    r.u32le(out.io_control_code);
    if (r.remaining() < 20) return Status::NeedMoreData;  // Padding (20 bytes)
    r.skip(20);
    if (out.input_buffer_length > r.remaining()) return Status::NeedMoreData;
    out.input_buffer.assign(r.cursor(), r.cursor() + out.input_buffer_length);
    return Status::Ok;
}

Status RdpdrPdu::parse(const uint8_t* data, size_t size, RdpdrPdu& out) {
    out.data.clear();
    Status s = RdpdrHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    out.data.assign(data + RdpdrHeader::kSize, data + size);
    return Status::Ok;
}

std::vector<uint8_t> BuildRdpdrPdu(uint16_t packet_id,
                                   const std::vector<uint8_t>& body) {
    RdpdrHeader header;
    header.component = kRdpdrCtypCore;
    header.packet_id = packet_id;
    ByteWriter w;
    header.write(w);
    w.bytes(body.data(), body.size());
    return w.take();
}

std::string RdpdrDecodeUtf16(const uint8_t* data, size_t size) {
    std::string out;
    const size_t units = size / 2;
    for (size_t i = 0; i < units; ++i) {
        const uint32_t cp = ReadU16Le(data + i * 2);
        if (cp == 0) break;
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

std::vector<uint8_t> RdpdrEncodeUtf16(const std::string& text) {
    std::vector<uint8_t> out;
    for (const char c : text) {
        const uint32_t cp = static_cast<uint8_t>(c);
        out.push_back(static_cast<uint8_t>(cp & 0xFF));
        out.push_back(static_cast<uint8_t>((cp >> 8) & 0xFF));
    }
    out.push_back(0);
    out.push_back(0);
    return out;
}

}  // namespace rtsc::proto
