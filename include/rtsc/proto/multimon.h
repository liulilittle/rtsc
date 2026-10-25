// Multi-monitor support: the client monitor layout and the server Monitor
// Layout PDU ([MS-RDPBCGR] 2.2.1.3.6 / 2.2.1.3.6.1 / 2.2.12.1).
//
// The client advertises its local monitor layout in the GCC Connect Initial
// (Client Monitor Data, TS_UD_CS_MONITOR 0xC005) so the server can build a
// multi-monitor session. The server then reports the session layout with the
// optional Monitor Layout PDU (2.2.12.1, PDUTYPE2_MONITOR_LAYOUT_PDU 0x37),
// which the client uses to create one surface per monitor.
//
// Coordinates are in the virtual desktop space: each TS_MONITOR_DEF is the
// monitor rectangle relative to the primary monitor's top-left corner, so a
// monitor above or left of the primary has a negative left/top. The union of
// all monitors (the virtual desktop) is what the client paints and presents.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/share.h"

namespace rtsc::proto {

// TS_MONITOR_DEF ([MS-RDPBCGR] 2.2.1.3.6.1), 20 bytes.
struct MonitorDef {
    static constexpr size_t kWireSize = 20;
    // TS_MONITOR_PRIMARY: the primary monitor, whose top-left corner is the
    // virtual desktop origin (0,0).
    static constexpr uint32_t kPrimary = 0x00000001;
    // [MS-RDPBCGR] 2.2.1.3.6: the maximum number of monitors in a layout.
    static constexpr uint32_t kMaxMonitors = 16;

    int32_t left = 0;
    int32_t top = 0;
    int32_t right = 0;   // inclusive
    int32_t bottom = 0;  // inclusive
    uint32_t flags = 0;

    bool primary() const { return (flags & kPrimary) != 0; }
    int width() const { return right - left + 1; }
    int height() const { return bottom - top + 1; }

    // Appends the 20-byte little-endian definition to `w`.
    void write(ByteWriter& w) const;
    // Reads one definition from `r`. Returns false when fewer than 20 bytes
    // remain (a truncated array is a protocol error, not a partial read).
    bool read(ByteReader& r);
};

// Client Monitor Data (TS_UD_CS_MONITOR, GCC block 0xC005,
// [MS-RDPBCGR] 2.2.1.3.6). An Extended Client Data Block: it MUST NOT be sent
// unless the server advertised EXTENDED_CLIENT_DATA_SUPPORTED, which this
// client always requests via the CS_CORE earlyCapabilityFlags.
struct ClientMonitorData {
    static constexpr uint16_t kBlock = 0xC005;

    uint32_t flags = 0;  // reserved, MUST be 0
    std::vector<MonitorDef> monitors;

    // Builds the complete GCC user data block (header + flags + count + array).
    std::vector<uint8_t> encode() const;

    // Parses a GCC user data block (header + payload).
    static Status parse(const uint8_t* data, size_t size, ClientMonitorData& out);
};

// Monitor Layout PDU ([MS-RDPBCGR] 2.2.12.1,
// PDUTYPE2_MONITOR_LAYOUT_PDU 0x37), server -> client.
struct MonitorLayoutPdu {
    // The share data header's pduType2 value; kept here so the type table and
    // this module cannot drift.
    static constexpr ShareDataPduType kPduType2 = ShareDataPduType::kMonitorLayout;

    uint32_t monitor_count = 0;
    std::vector<MonitorDef> monitors;

    // monitorCount + monitorDefArray, the body that follows the 18-byte share
    // data header.
    std::vector<uint8_t> encode_body() const;
    static Status parse_body(const uint8_t* data, size_t size,
                             MonitorLayoutPdu& out);

    // The complete slow-path data PDU: share data header + body.
    std::vector<uint8_t> encode(uint16_t pdu_source, uint32_t share_id,
                                uint8_t stream_id = 0x01) const;
    static Status parse(const uint8_t* data, size_t size, MonitorLayoutPdu& out);
};

}  // namespace rtsc::proto
