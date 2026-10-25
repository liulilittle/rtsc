#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/share.h"

namespace rtsc::proto {

// Capability exchange: Demand Active / Confirm Active and the capability sets
// ([MS-RDPBCGR] 2.2.1.13, 2.2.7).

// capabilitySetType ([MS-RDPBCGR] 2.2.1.13.1.1.1). The table has 28 assigned
// values; 0x0006 and 0x000B are holes inside the 0x0001..0x001E range.
enum class CapabilityType : uint16_t {
    kGeneral = 0x0001,
    kBitmap = 0x0002,
    kOrder = 0x0003,
    kBitmapCacheRev1 = 0x0004,
    kControl = 0x0005,
    kActivation = 0x0007,
    kPointer = 0x0008,
    kShare = 0x0009,
    kColorCache = 0x000A,
    kSound = 0x000C,
    kInput = 0x000D,
    kFont = 0x000E,
    kBrush = 0x000F,
    kGlyphCache = 0x0010,
    kOffscreenCache = 0x0011,
    kBitmapCacheHostSupport = 0x0012,
    kBitmapCacheRev2 = 0x0013,
    kVirtualChannel = 0x0014,
    kDrawNineGridCache = 0x0015,
    kDrawGdiPlus = 0x0016,
    kRail = 0x0017,
    kWindow = 0x0018,
    kCompDesk = 0x0019,
    kMultifragmentUpdate = 0x001A,
    kLargePointer = 0x001B,
    kSurfaceCommands = 0x001C,
    kBitmapCodecs = 0x001D,
    kFrameAcknowledge = 0x001E,
};

const char* to_string(CapabilityType type);

// Returns false for 0x0000, 0x0006, 0x000B, and anything above 0x001E.
bool IsAssignedCapabilityType(uint16_t raw);

// Expected total length (including the 4-byte header) of a fixed-size
// capability set, or 0 when the type is variable-length (0x001D) or unknown.
//
// These lengths are derived from the field tables in 2.2.7, not from a MUST in
// the specification: [MS-RDPBCGR] never fixes lengthCapability itself. The
// value is used only to validate and to pad, never to reject outright, because
// real servers deviate (the Font set is commonly sent as 4 bytes).
uint16_t ExpectedCapabilityLength(uint16_t raw);

// One capability set as it appears on the wire: a 4-byte header plus an opaque
// payload. Individual set layouts are decoded by the typed helpers below.
struct CapabilitySet {
    static constexpr size_t kHeaderSize = 4;

    CapabilityType type = CapabilityType::kGeneral;
    // Bytes after the 4-byte header (i.e. lengthCapability - 4).
    std::vector<uint8_t> data;

    size_t wire_size() const { return kHeaderSize + data.size(); }
};

// A parsed list of capability sets plus the framing that contained them.
//
// Parsing is defensive because the three length fields (totalLength,
// lengthCombinedCapabilities, and the sum of lengthCapability) are independent
// on the wire and can disagree. Every set is bounds-checked against the
// combined-capabilities window, not just against the received byte count.
struct CapabilitySetList {
    // numberCapabilities from the header.
    uint16_t declared_count = 0;
    // lengthCombinedCapabilities from the header.
    uint16_t combined_length = 0;
    std::vector<CapabilitySet> sets;
    // True when the sum of lengthCapability did not reach the end of the
    // combined window (trailing slack) or the declared count disagreed with the
    // number of sets actually walked.
    bool count_mismatch = false;
    bool trailing_slack = false;

    const CapabilitySet* find(CapabilityType type) const;
    bool has(CapabilityType type) const { return find(type) != nullptr; }
};

// Parses `count` capability sets out of [data, data+size).
//
// `combined_length` is lengthCombinedCapabilities, which covers numberCapabilities
// (2) + pad2Octets (2) + capabilitySets. `size` must therefore be at least
// combined_length - 4.
//
// Rejects with InvalidLength when:
//   - combined_length < 4 (the window would underflow)
//   - size < combined_length - 4 (truncated capability data)
//   - a set's lengthCapability < 4 (the walk could not advance)
//   - a set would extend past the combined window
Status ParseCapabilitySets(const uint8_t* data, size_t size, uint16_t count,
                           uint16_t combined_length, CapabilitySetList& out);

// Serialises a capability list. `combined_length` and the returned set count are
// computed from the sets themselves.
void WriteCapabilitySets(ByteWriter& w, const std::vector<CapabilitySet>& sets,
                         uint16_t& out_count, uint16_t& out_combined);

// ---- Demand Active / Confirm Active ---------------------------------------

// TS_DEMAND_ACTIVE_PDU ([MS-RDPBCGR] 2.2.1.13.1.1).
struct DemandActivePdu {
    uint16_t total_length = 0;
    uint16_t pdu_source = 0;
    uint32_t share_id = 0;
    std::vector<uint8_t> source_descriptor;
    CapabilitySetList capabilities;
    uint32_t session_id = 0;  // ignored by the client

    // Parses the PDU starting at the share control header (no security header,
    // no MCS framing).
    static Status parse(const uint8_t* data, size_t size, DemandActivePdu& out);
};

// TS_CONFIRM_ACTIVE_PDU ([MS-RDPBCGR] 2.2.1.13.2.1).
struct ConfirmActivePdu {
    uint16_t total_length = 0;
    uint16_t pdu_source = 0;   // MUST be the user channel ID
    uint32_t share_id = 0;     // should echo the Demand Active shareID
    uint16_t originator_id = 0;  // MUST be the server channel ID (0x03EA)
    std::vector<uint8_t> source_descriptor;
    CapabilitySetList capabilities;

    static Status parse(const uint8_t* data, size_t size, ConfirmActivePdu& out);

    // Builds a Confirm Active PDU. `share_id` and `originator_id` must come from
    // the Demand Active PDU and the Server Channel ID store respectively; the
    // server may reject a wrong value with ERRINFO_CONFIRMACTIVEWRONGSHAREID.
    static std::vector<uint8_t> encode(uint16_t pdu_source, uint32_t share_id,
                                       uint16_t originator_id,
                                       const std::string& source_descriptor,
                                       const std::vector<CapabilitySet>& sets);
};

// ---- Typed capability sets ------------------------------------------------

// TS_GENERAL_CAPABILITYSET ([MS-RDPBCGR] 2.2.7.1.1), 24 bytes total.
struct GeneralCapabilitySet {
    static constexpr uint16_t kProtocolVersion = 0x0200;
    static constexpr uint16_t kEncSaltedChecksum = 0x0010;
    static constexpr uint16_t kFastpathOutputSupported = 0x0400;
    static constexpr uint16_t kLongCredentialsSupported = 0x0004;

    uint16_t os_major_type = 0;
    uint16_t os_minor_type = 0;
    uint16_t protocol_version = kProtocolVersion;
    uint16_t compression_types = 0;
    uint16_t extra_flags = 0;
    uint16_t update_capability_flag = 0;
    uint16_t remote_unshare_flag = 0;
    uint16_t compression_level = 0;
    uint8_t refresh_rect_support = 0;
    uint8_t suppress_output_support = 0;

    static Status parse(const CapabilitySet& set, GeneralCapabilitySet& out);
    CapabilitySet encode() const;
};

// TS_BITMAP_CAPABILITYSET ([MS-RDPBCGR] 2.2.7.1.2), 28 bytes total.
struct BitmapCapabilitySet {
    uint16_t preferred_bits_per_pixel = 24;
    uint16_t desktop_width = 0;
    uint16_t desktop_height = 0;
    uint16_t desktop_resize_flag = 0;
    // MUST be TRUE: compressed bitmap support is required for the connection to
    // proceed ([MS-RDPBCGR] 2.2.7.1.2).
    uint16_t bitmap_compression_flag = 1;
    uint8_t high_color_flags = 0;
    uint8_t drawing_flags = 0;
    // MUST be TRUE for the same reason as bitmap_compression_flag.
    uint16_t multiple_rectangle_support = 1;

    static Status parse(const CapabilitySet& set, BitmapCapabilitySet& out);
    CapabilitySet encode() const;
};

// TS_ORDER_CAPABILITYSET ([MS-RDPBCGR] 2.2.7.1.3), 88 bytes total.
struct OrderCapabilitySet {
    static constexpr size_t kOrderSupportSize = 32;
    static constexpr uint16_t kNegotiateOrderSupport = 0x0002;
    static constexpr uint16_t kZeroBoundsDeltaSupport = 0x0008;
    // [MS-RDPBCGR] 2.2.7.1.3: the receiver can only handle solid and pattern
    // brushes (not cached brushes).
    //
    // This constant is used only by tests as a regression guard: the production
    // encoder deliberately never sets it (see the note in capabilities.cpp).
    static constexpr uint16_t kSolidPatternBrushOnly = 0x0040;

    uint16_t order_flags = kNegotiateOrderSupport | kZeroBoundsDeltaSupport;
    std::vector<uint8_t> order_support = std::vector<uint8_t>(kOrderSupportSize, 0);
    uint16_t text_flags = 0;
    uint16_t order_support_ex_flags = 0;
    uint16_t text_ansi_code_page = 0;

    static Status parse(const CapabilitySet& set, OrderCapabilitySet& out);
    CapabilitySet encode() const;
};

// TS_INPUT_CAPABILITYSET ([MS-RDPBCGR] 2.2.7.1.6), 88 bytes total.
struct InputCapabilitySet {
    static constexpr uint16_t kInputFlagScancodes = 0x0001;
    static constexpr uint16_t kInputFlagMouse = 0x0002;
    static constexpr uint16_t kInputFlagMouseX = 0x0004;
    static constexpr uint16_t kInputFlagUnicode = 0x0010;
    static constexpr uint16_t kInputFlagQoeTimestamps = 0x0200;

    // At a minimum INPUT_FLAG_SCANCODES MUST be set.
    uint16_t input_flags = kInputFlagScancodes | kInputFlagMouse |
                           kInputFlagMouseX | kInputFlagUnicode;
    uint32_t keyboard_layout = 0x00000409;
    uint32_t keyboard_type = 4;  // IBM enhanced 101/102
    uint32_t keyboard_sub_type = 0;
    uint32_t keyboard_function_key = 12;
    std::vector<uint8_t> ime_file_name;  // 64 bytes, UTF-16LE, NUL padded

    static Status parse(const CapabilitySet& set, InputCapabilitySet& out);
    CapabilitySet encode() const;
};

// TS_POINTER_CAPABILITYSET ([MS-RDPBCGR] 2.2.7.1.5), 10 bytes total.
//
// Both cache sizes being zero makes the server report ERRINFO_NOCURSORCACHE, so
// a working client declares at least one non-zero size.
struct PointerCapabilitySet {
    uint16_t color_pointer_flag = 1;
    uint16_t color_pointer_cache_size = 0;
    uint16_t pointer_cache_size = 0;

    static Status parse(const CapabilitySet& set, PointerCapabilitySet& out);
    CapabilitySet encode() const;
};

// TS_SHARE_CAPABILITYSET ([MS-RDPBCGR] 2.2.7.2.4), 8 bytes total.
struct ShareCapabilitySet {
    uint16_t node_id = 0;  // the client SHOULD send 0

    static Status parse(const CapabilitySet& set, ShareCapabilitySet& out);
    CapabilitySet encode() const;
};

// TS_VIRTUALCHANNEL_CAPABILITYSET ([MS-RDPBCGR] 2.2.7.1.10), 8 or 12 bytes.
// VCChunkSize is optional, so both lengths are legal on the wire.
struct VirtualChannelCapabilitySet {
    static constexpr uint32_t kNoComp = 0x00000000;
    static constexpr uint32_t kComprSc = 0x00000001;
    static constexpr uint32_t kComprCs8k = 0x00000002;

    uint32_t flags = kNoComp;
    bool has_chunk_size = false;
    uint32_t chunk_size = 0;

    static Status parse(const CapabilitySet& set, VirtualChannelCapabilitySet& out);
    CapabilitySet encode() const;
};

// TS_FONT_CAPABILITYSET ([MS-RDPBCGR] 2.2.7.2.5), nominally 8 bytes.
//
// The reference server sends 4 bytes (fontSupportFlags/pad2octets absent), which
// the specification itself annotates as a server bug. Both forms must parse.
struct FontCapabilitySet {
    static constexpr uint16_t kFontSupportFontList = 0x0001;

    bool has_support_flags = false;
    uint16_t font_support_flags = 0;

    static Status parse(const CapabilitySet& set, FontCapabilitySet& out);
    CapabilitySet encode() const;
};

// TS_CACHE_DEFINITION ([MS-RDPBCGR] 2.2.7.1.8.1).
struct CacheDefinition {
    uint16_t cache_entries = 0;
    uint16_t maximum_cell_size = 0;
};

// TS_GLYPHCACHE_CAPABILITYSET ([MS-RDPBCGR] 2.2.7.1.8), 52 bytes total.
struct GlyphCacheCapabilitySet {
    static constexpr size_t kGlyphCaches = 10;

    std::vector<CacheDefinition> glyph_cache;  // 10 entries
    CacheDefinition frag_cache;
    uint16_t glyph_support_level = 0;
    uint16_t pad2octets = 0;

    static Status parse(const CapabilitySet& set, GlyphCacheCapabilitySet& out);
    CapabilitySet encode() const;
};

// TS_BITMAPCACHE_CAPABILITYSET_REV2 ([MS-RDPBCGR] 2.2.7.1.4.2), fixed 40 bytes
// (36-byte payload):
//   CacheFlags(2) | Pad2(1) | NumCellCaches(1) |
//   BitmapCache0..4CellInfo (5 x 4) | Pad3(12).
// All five cell-info slots are always present; slots beyond NumCellCaches are
// zero and each is "valid" only when NumCellCaches covers it.
struct BitmapCacheRev2CapabilitySet {
    static constexpr uint16_t kPersistentKeysExpected = 0x0002;
    // NumCellCaches maximum ([MS-RDPBCGR] 2.2.7.1.4.2): 5.
    static constexpr size_t kCellInfoSlots = 5;

    uint16_t cache_flags = 0;
    uint8_t num_cell_caches = 0;
    // Bitmap cache cell info, one per cache; the high bit marks a persistent
    // cache whose cell size is encoded differently.
    std::vector<uint32_t> cell_info;

    static Status parse(const CapabilitySet& set, BitmapCacheRev2CapabilitySet& out);
    CapabilitySet encode() const;
};

// Builds the default client capability set used by this project: the sets that
// a working client must send, with conservative values.
//
// Deliberately excluded: capabilities that only the server sends, and codec sets
// whose payloads belong to other specifications.
std::vector<CapabilitySet> BuildDefaultClientCapabilities(uint16_t desktop_width,
                                                          uint16_t desktop_height,
                                                          uint16_t color_depth);

}  // namespace rtsc::proto
