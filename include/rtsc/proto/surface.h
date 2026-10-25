// Surface Commands ([MS-RDPBCGR] 2.2.9.2), carried by the fast-path SURFCMDS
// update (code 4).
//
// A surface command is a 4-byte header (cmdType + cmdLength, where cmdLength
// includes the header) followed by cmdData. One update may carry several
// commands back to back. This module covers the framing; the Set Surface Bits
// payload (which wraps an Extended Bitmap Data structure) is left opaque for a
// later codec layer.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// TS_SURFCMD.cmdType ([MS-RDPBCGR] 2.2.9.2.1).
enum SurfaceCommandType : uint16_t {
    kSetSurfaceBits = 0x0001,
    kSetSurfaceBitsEx = 0x0002,
    kStreamSurfaceBits = 0x0003,
    kFrameMarker = 0x0004,
};

// One TS_SURFCMD. `data` is cmdData (cmdLength - 4 bytes).
struct SurfaceCommand {
    uint16_t cmd_type = 0;
    std::vector<uint8_t> data;
};

// Parses a sequence of TS_SURFCMD structures. Returns InvalidLength when a
// cmdLength is smaller than the 4-byte header (which would loop forever).
Status ParseSurfaceCommands(const uint8_t* data, size_t size,
                            std::vector<SurfaceCommand>& out);

}  // namespace rtsc::proto
