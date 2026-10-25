// Device redirection virtual channel (rdpdr) structure layer ([MS-RDPEFS] 2.2).
//
// Reference: [MS-RDPEFS] 2.2.1.1 (header) and 2.2.2.2 (server announce).
//
// The RDPDR_HEADER is 4 bytes (Component + PacketId); the packet length is
// implicit from the enclosing virtual channel PDU, so there is no PacketLength
// field here (verified against the 2.2.2.2 official 12-byte dump).

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// RDPDR_HEADER.Component ([MS-RDPEFS] 2.2.1.1).
enum RdpdrComponent : uint16_t {
    kRdpdrCtypCore = 0x4472,
    kRdpdrCtypPrn = 0x5052,
};

// RDPDR_HEADER.PacketId ([MS-RDPEFS] 2.2.1.1).
enum RdpdrPacketId : uint16_t {
    kPakidCoreServerAnnounce = 0x496E,
    kPakidCoreClientidConfirm = 0x4343,
    kPakidCoreClientName = 0x434E,
    kPakidCoreDevicelistAnnounce = 0x4441,
    kPakidCoreDeviceReply = 0x6472,
    kPakidCoreDeviceIorequest = 0x4952,
    kPakidCoreDeviceIocompletion = 0x4943,
    kPakidCoreServerCapability = 0x5350,
    kPakidCoreClientCapability = 0x4350,
    kPakidCoreDevicelistRemove = 0x444D,
    kPakidCoreUserLoggedon = 0x554C,
};

const char* to_string(RdpdrPacketId id);

// RDPDR_HEADER ([MS-RDPEFS] 2.2.1.1), 4 bytes.
struct RdpdrHeader {
    static constexpr size_t kSize = 4;

    uint16_t component = 0;
    uint16_t packet_id = 0;

    static Status parse(const uint8_t* data, size_t size, RdpdrHeader& out);
};

// DR_CORE_SERVER_ANNOUNCE_REQ ([MS-RDPEFS] 2.2.2.2), 12 bytes total.
struct RdpdrServerAnnounce {
    uint16_t version_major = 0;
    uint16_t version_minor = 0;
    uint32_t client_id = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpdrServerAnnounce& out);
};

// A parsed rdpdr PDU: header + the bytes that follow (packet-specific).
struct RdpdrPdu {
    RdpdrHeader header;
    std::vector<uint8_t> data;

    static Status parse(const uint8_t* data, size_t size, RdpdrPdu& out);
};

}  // namespace rtsc::proto
