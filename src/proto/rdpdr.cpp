// Device redirection virtual channel (rdpdr) structure layer ([MS-RDPEFS] 2.2).

#include "rtsc/proto/rdpdr.h"

namespace rtsc::proto {

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

Status RdpdrServerAnnounce::parse(const uint8_t* data, size_t size,
                                  RdpdrServerAnnounce& out) {
    if (data == nullptr || size < 12) return Status::NeedMoreData;
    ByteReader r(data, size);
    uint16_t component = 0;
    uint16_t packet_id = 0;
    r.u16le(component);
    r.u16le(packet_id);
    if (component != kRdpdrCtypCore ||
        packet_id != kPakidCoreServerAnnounce) {
        return Status::InvalidType;
    }
    r.u16le(out.version_major);
    r.u16le(out.version_minor);
    r.u32le(out.client_id);
    return Status::Ok;
}

Status RdpdrPdu::parse(const uint8_t* data, size_t size, RdpdrPdu& out) {
    out.data.clear();
    Status s = RdpdrHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    out.data.assign(data + RdpdrHeader::kSize, data + size);
    return Status::Ok;
}

}  // namespace rtsc::proto
