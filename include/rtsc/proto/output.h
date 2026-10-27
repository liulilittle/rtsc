// Server fast-path output updates ([MS-RDPBCGR] 2.2.9.1.2).
//
// Reference: docs/spec/share-data.md sections 3.8 and 3.9.
//
// A fast-path output PDU is a 1-byte fpOutputHeader, a length, and a sequence
// of TS_FP_UPDATE structures. Each update is a 1-byte updateHeader, an optional
// compressionFlags byte, a 2-byte size, and the update data. This module parses
// the framing and the bitmap / palette / synchronize / pointer payloads; the
// codec payloads (RLE, NSCodec, ...) are left as opaque bytes for a later layer.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/share.h"

namespace rtsc::proto {

// updateCode is defined in share.h (FastPathUpdateCode).
const char* to_string(FastPathUpdateCode code);

// One TS_FP_UPDATE.
struct FastPathUpdate {
    FastPathUpdateCode code = FastPathUpdateCode::kSynchronize;
    FastPathFragmentation fragmentation = FastPathFragmentation::kSingle;
    uint8_t compression = 0;  // 2 = compressionFlags present
    bool has_compression_flags = false;
    uint8_t compression_flags = 0;
    std::vector<uint8_t> data;  // updateData, `size` bytes

    // True when compressionFlags says the data is really compressed.
    bool is_compressed() const {
        return has_compression_flags && (compression_flags & 0x20) != 0;
    }
};

// A parsed TS_FP_UPDATE_PDU.
struct FastPathOutputPdu {
    uint8_t flags = 0;  // 0x1 = secure checksum, 0x2 = encrypted (Standard RDP)
    std::vector<FastPathUpdate> updates;

    static Status parse(const uint8_t* data, size_t size, FastPathOutputPdu& out);
};

// ---- typed update payloads -------------------------------------------------

// TS_BITMAP_DATA ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.3), 20-byte header + data.
struct BitmapData {
    // [MS-RDPBCGR] 2.2.9.1.1.3.1.2.2 TS_BITMAP_DATA: destLeft/destTop/destRight/
    // destBottom/width/height/bitsPerPixel/flags/bitmapLength = 9 * 2 = 18 bytes.
    // The optional 8-byte bitmapComprHdr and the bitmapDataStream follow, and
    // bitmapLength counts both of them.
    static constexpr size_t kHeaderSize = 18;

    // destLeft/destTop are signed 16-bit virtual-desktop coordinates: in a
    // multi-monitor session a monitor above or left of the primary has a
    // negative origin, and the destination can be negative too.
    int16_t dest_left = 0;
    int16_t dest_top = 0;
    uint16_t dest_right = 0;
    uint16_t dest_bottom = 0;
    uint16_t width = 0;
    uint16_t height = 0;
    uint16_t bits_per_pixel = 0;
    uint16_t flags = 0;
    uint16_t bitmap_length = 0;
    std::vector<uint8_t> bitmap_data;
};

// TS_UPDATE_BITMAP_DATA ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.1): the payload of a
// bitmap update (used by both slow-path and fast-path updates).
struct UpdateBitmapData {
    uint16_t number_rectangles = 0;
    std::vector<BitmapData> rectangles;

    static Status parse(const uint8_t* data, size_t size, UpdateBitmapData& out);
};

// TS_UPDATE_PALETTE_DATA ([MS-RDPBCGR] 2.2.9.1.1.3.1.1.1).
struct UpdatePaletteData {
    uint32_t number_colors = 0;  // 32-bit field ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.3)
    std::vector<uint8_t> entries;  // 3 * number_colors RGB bytes

    static Status parse(const uint8_t* data, size_t size, UpdatePaletteData& out);
};

// A fast-path pointer position update (TS_POINTERPOSATTRIBUTE).
struct PointerPosition {
    uint16_t x = 0;
    uint16_t y = 0;
};

// ---- slow-path graphics update --------------------------------------------

// TS_GRAPHICS_UPDATE.updateType ([MS-RDPBCGR] 2.2.9.1.1.3.1).
enum GraphicsUpdateType : uint16_t {
    kUpdateOrders = 0x0000,
    kUpdateBitmap = 0x0001,
    kUpdatePalette = 0x0002,
    kUpdateSynchronize = 0x0003,
};

// A slow-path graphics update (TS_GRAPHICS_UPDATE): the share data header
// followed by updateType and a single update. `data` starts at the share data
// header (no TPKT / X.224 / MCS / security header).
struct SlowPathGraphicsUpdate {
    uint16_t update_type = 0;
    std::vector<uint8_t> update_data;  // type-specific data

    static Status parse(const uint8_t* data, size_t size,
                        SlowPathGraphicsUpdate& out);
};

}  // namespace rtsc::proto
