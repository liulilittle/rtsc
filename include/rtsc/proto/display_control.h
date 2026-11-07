// Remote Desktop Protocol: Display Control Virtual Channel Extension
// ([MS-RDPEDISP]).
//
// The server sends DISPLAYCONTROL_CAPS_PDU once the dynamic channel is open;
// the client sends DISPLAYCONTROL_MONITOR_LAYOUT_PDU to request a new display
// configuration. All fields are little-endian.
//
// This file is the wire layer only: it does not open the drdynvc channel or
// apply a layout. Keeping the encoding here makes the 40-byte monitor struct
// and its range rules testable without a live server.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace rtsc::proto {

// DISPLAYCONTROL_HEADER.Type ([MS-RDPEDISP] 2.2.1.1).
enum class DisplayControlType : uint32_t {
    kMonitorLayout = 0x00000002,
    kCaps = 0x00000005,
};

// DISPLAYCONTROL_MONITOR_PRIMARY ([MS-RDPEDISP] 2.2.2.2.1).
constexpr uint32_t kDisplayControlMonitorPrimary = 0x00000001;

// Size of one DISPLAYCONTROL_MONITOR_LAYOUT on the wire.
constexpr uint32_t kDisplayControlMonitorLayoutSize = 40;

// DISPLAYCONTROL_CAPS_PDU ([MS-RDPEDISP] 2.2.2.1).
struct DisplayControlCaps {
    uint32_t max_num_monitors = 0;
    uint32_t max_monitor_area_factor_a = 0;
    uint32_t max_monitor_area_factor_b = 0;
};

// Parses a complete DISPLAYCONTROL_CAPS_PDU (header included). Returns false
// when the type is not kCaps, the declared length is smaller than the fixed
// 20-byte body, or the buffer is shorter than the declared length.
bool ParseDisplayControlCaps(const uint8_t* data, size_t size,
                             DisplayControlCaps& out);

// DISPLAYCONTROL_MONITOR_LAYOUT ([MS-RDPEDISP] 2.2.2.2.1).
struct DisplayControlMonitor {
    uint32_t flags = 0;  // kDisplayControlMonitorPrimary for the primary
    int32_t left = 0;
    int32_t top = 0;
    uint32_t width = 0;   // 200..8192, even
    uint32_t height = 0;  // 200..8192
    uint32_t physical_width = 0;   // mm; 10..10000 or ignored by server
    uint32_t physical_height = 0;  // mm; 10..10000 or ignored by server
    uint32_t orientation = 0;      // 0 / 90 / 180 / 270
    uint32_t desktop_scale_factor = 100;  // 100..500
    uint32_t device_scale_factor = 100;   // 100 / 140 / 180
};

// True when one monitor's pixel dimensions and orientation are in the range
// [MS-RDPEDISP] 2.2.2.2.1 allows, and a monitor flagged primary sits at the
// coordinate origin. This is the validation the server applies before it will
// act on a layout.
bool DisplayControlMonitorValid(const DisplayControlMonitor& monitor);

// Builds the single primary monitor a local window resize asks the server to
// adopt. `width` must be odd or even; an odd width is rounded down so the
// result always satisfies the "MUST NOT be odd" rule. Returns false when the
// size is outside 200..8192 or the even-rounded width would fall below 200.
bool MakePrimaryMonitorFromViewport(uint32_t width, uint32_t height,
                                    DisplayControlMonitor& out);

// Encodes a complete DISPLAYCONTROL_MONITOR_LAYOUT_PDU (header included).
// Returns an empty vector when `monitors` is empty, has a value the spec
// forbids, or the total length overflows. The caller is responsible for the
// per-server cap (MaxNumMonitors / maximum area).
std::vector<uint8_t> EncodeDisplayControlMonitorLayout(
    const std::vector<DisplayControlMonitor>& monitors);

// True when every monitor is individually valid and the total layout area does
// not exceed max_monitors * factor_a * factor_b, the bound the server stated in
// DISPLAYCONTROL_CAPS_PDU. The bound saturates at 2^64-1 instead of wrapping.
bool DisplayControlLayoutWithinCaps(
    const std::vector<DisplayControlMonitor>& monitors,
    const DisplayControlCaps& caps);

// True when the layout satisfies [MS-RDPEDISP] 3.2.5.1: every monitor is
// individually valid, at most one monitor is primary, no two monitors overlap,
// and (for two or more monitors) each monitor is adjacent to at least one
// other monitor, touching at an edge or a corner. A single monitor is
// trivially valid.
bool DisplayControlLayoutValid(
    const std::vector<DisplayControlMonitor>& monitors);

}  // namespace rtsc::proto
