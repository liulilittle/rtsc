#include "rtsc/proto/capabilities.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace rtsc::proto {

const char* to_string(CapabilityType type) {
    switch (type) {
        case CapabilityType::kGeneral: return "general";
        case CapabilityType::kBitmap: return "bitmap";
        case CapabilityType::kOrder: return "order";
        case CapabilityType::kBitmapCacheRev1: return "bitmap-cache-rev1";
        case CapabilityType::kControl: return "control";
        case CapabilityType::kActivation: return "activation";
        case CapabilityType::kPointer: return "pointer";
        case CapabilityType::kShare: return "share";
        case CapabilityType::kColorCache: return "color-cache";
        case CapabilityType::kSound: return "sound";
        case CapabilityType::kInput: return "input";
        case CapabilityType::kFont: return "font";
        case CapabilityType::kBrush: return "brush";
        case CapabilityType::kGlyphCache: return "glyph-cache";
        case CapabilityType::kOffscreenCache: return "offscreen-cache";
        case CapabilityType::kBitmapCacheHostSupport: return "bitmap-cache-host-support";
        case CapabilityType::kBitmapCacheRev2: return "bitmap-cache-rev2";
        case CapabilityType::kVirtualChannel: return "virtual-channel";
        case CapabilityType::kDrawNineGridCache: return "draw-ninegrid-cache";
        case CapabilityType::kDrawGdiPlus: return "draw-gdiplus";
        case CapabilityType::kRail: return "rail";
        case CapabilityType::kWindow: return "window";
        case CapabilityType::kCompDesk: return "compdesk";
        case CapabilityType::kMultifragmentUpdate: return "multifragment-update";
        case CapabilityType::kLargePointer: return "large-pointer";
        case CapabilityType::kSurfaceCommands: return "surface-commands";
        case CapabilityType::kBitmapCodecs: return "bitmap-codecs";
        case CapabilityType::kFrameAcknowledge: return "frame-acknowledge";
    }
    return "unknown";
}

bool IsAssignedCapabilityType(uint16_t raw) {
    switch (static_cast<CapabilityType>(raw)) {
        case CapabilityType::kGeneral:
        case CapabilityType::kBitmap:
        case CapabilityType::kOrder:
        case CapabilityType::kBitmapCacheRev1:
        case CapabilityType::kControl:
        case CapabilityType::kActivation:
        case CapabilityType::kPointer:
        case CapabilityType::kShare:
        case CapabilityType::kColorCache:
        case CapabilityType::kSound:
        case CapabilityType::kInput:
        case CapabilityType::kFont:
        case CapabilityType::kBrush:
        case CapabilityType::kGlyphCache:
        case CapabilityType::kOffscreenCache:
        case CapabilityType::kBitmapCacheHostSupport:
        case CapabilityType::kBitmapCacheRev2:
        case CapabilityType::kVirtualChannel:
        case CapabilityType::kDrawNineGridCache:
        case CapabilityType::kDrawGdiPlus:
        case CapabilityType::kRail:
        case CapabilityType::kWindow:
        case CapabilityType::kCompDesk:
        case CapabilityType::kMultifragmentUpdate:
        case CapabilityType::kLargePointer:
        case CapabilityType::kSurfaceCommands:
        case CapabilityType::kBitmapCodecs:
        case CapabilityType::kFrameAcknowledge:
            return true;
    }
    return false;
}

uint16_t ExpectedCapabilityLength(uint16_t raw) {
    switch (static_cast<CapabilityType>(raw)) {
        case CapabilityType::kGeneral: return 24;
        case CapabilityType::kBitmap: return 28;
        case CapabilityType::kOrder: return 88;
        case CapabilityType::kBitmapCacheRev1: return 40;
        case CapabilityType::kControl: return 12;
        case CapabilityType::kActivation: return 12;
        case CapabilityType::kPointer: return 10;
        case CapabilityType::kShare: return 8;
        case CapabilityType::kColorCache: return 8;
        case CapabilityType::kSound: return 8;
        case CapabilityType::kInput: return 88;
        case CapabilityType::kFont: return 8;
        case CapabilityType::kBrush: return 8;
        case CapabilityType::kGlyphCache: return 52;
        case CapabilityType::kOffscreenCache: return 12;
        case CapabilityType::kBitmapCacheHostSupport: return 8;
        case CapabilityType::kBitmapCacheRev2: return 40;  // fixed layout
        case CapabilityType::kVirtualChannel: return 8;   // 8 or 12
        case CapabilityType::kDrawNineGridCache: return 16;
        case CapabilityType::kDrawGdiPlus: return 16;
        case CapabilityType::kRail: return 0;  // variable
        case CapabilityType::kWindow: return 12;
        case CapabilityType::kCompDesk: return 8;
        case CapabilityType::kMultifragmentUpdate: return 8;
        case CapabilityType::kLargePointer: return 8;
        case CapabilityType::kSurfaceCommands: return 12;
        case CapabilityType::kBitmapCodecs: return 0;  // variable
        case CapabilityType::kFrameAcknowledge: return 8;
    }
    return 0;
}

// ---- CapabilitySetList ----------------------------------------------------

const CapabilitySet* CapabilitySetList::find(CapabilityType type) const {
    for (const auto& set : sets) {
        if (set.type == type) return &set;
    }
    return nullptr;
}

Status ParseCapabilitySets(const uint8_t* data, size_t size, uint16_t count,
                           uint16_t combined_length, CapabilitySetList& out) {
    out = CapabilitySetList{};
    out.declared_count = count;
    out.combined_length = combined_length;

    // lengthCombinedCapabilities covers numberCapabilities(2) + pad2Octets(2) +
    // capabilitySets, so it can never be smaller than 4. Without this check the
    // subtraction below would underflow.
    if (combined_length < 4) return Status::InvalidLength;
    const size_t window = static_cast<size_t>(combined_length) - 4;
    if (size < window) return Status::InvalidLength;

    size_t p = 0;
    for (uint16_t i = 0; i < count; ++i) {
        // The set header itself must fit inside the combined window.
        if (p + CapabilitySet::kHeaderSize > window) {
            out.count_mismatch = true;
            return Status::InvalidLength;
        }
        const uint16_t raw_type = static_cast<uint16_t>(
            static_cast<uint16_t>(data[p]) | static_cast<uint16_t>(data[p + 1] << 8));
        const uint16_t len = static_cast<uint16_t>(
            static_cast<uint16_t>(data[p + 2]) |
            static_cast<uint16_t>(data[p + 3] << 8));

        // len < 4 cannot contain its own header, so the walk would never advance.
        if (len < CapabilitySet::kHeaderSize) return Status::InvalidLength;
        // The whole set must fit inside the combined window (and thus in `size`).
        if (p + len > window) return Status::InvalidLength;

        CapabilitySet set;
        set.type = static_cast<CapabilityType>(raw_type);
        set.data.assign(data + p + CapabilitySet::kHeaderSize, data + p + len);
        out.sets.push_back(std::move(set));
        p += len;
    }

    // Trailing slack means the declared count under-described the data. The
    // caller decides whether that is fatal; it is recorded rather than rejected
    // so a diagnostic can be produced.
    if (p != window) out.trailing_slack = true;
    return Status::Ok;
}

void WriteCapabilitySets(ByteWriter& w, const std::vector<CapabilitySet>& sets,
                         uint16_t& out_count, uint16_t& out_combined) {
    size_t total = 0;
    for (const auto& set : sets) total += set.wire_size();
    out_count = static_cast<uint16_t>(sets.size());
    // numberCapabilities(2) + pad2Octets(2) + sets.
    out_combined = static_cast<uint16_t>(4 + total);
    for (const auto& set : sets) {
        w.u16le(static_cast<uint16_t>(set.type));
        w.u16le(static_cast<uint16_t>(set.wire_size()));
        if (!set.data.empty()) w.bytes(set.data.data(), set.data.size());
    }
}

// ---- Demand Active --------------------------------------------------------

Status DemandActivePdu::parse(const uint8_t* data, size_t size,
                              DemandActivePdu& out) {
    out = DemandActivePdu{};
    if (data == nullptr || size < 14) return Status::NeedMoreData;

    ByteReader r(data, size);
    if (!r.u16le(out.total_length)) return Status::NeedMoreData;
    uint16_t pdu_type = 0;
    if (!r.u16le(pdu_type)) return Status::NeedMoreData;
    const uint16_t type = static_cast<uint16_t>(pdu_type & 0x000F);
    const uint16_t version = static_cast<uint16_t>((pdu_type >> 4) & 0x0FFF);
    if (type != static_cast<uint16_t>(SharePduType::kDemandActive)) {
        return Status::InvalidType;
    }
    if (version != ShareControlHeader::kProtocolVersion) {
        return Status::InvalidVersion;
    }
    if (!r.u16le(out.pdu_source)) return Status::NeedMoreData;
    if (!r.u32le(out.share_id)) return Status::NeedMoreData;

    uint16_t src_len = 0;
    uint16_t combined = 0;
    if (!r.u16le(src_len)) return Status::NeedMoreData;
    if (!r.u16le(combined)) return Status::NeedMoreData;
    if (src_len > r.remaining()) return Status::InvalidLength;
    out.source_descriptor.resize(src_len);
    if (src_len != 0 && !r.bytes(out.source_descriptor.data(), src_len)) {
        return Status::InvalidLength;
    }

    uint16_t count = 0;
    if (!r.u16le(count)) return Status::NeedMoreData;
    uint16_t pad2 = 0;
    if (!r.u16le(pad2)) return Status::NeedMoreData;  // MUST be ignored

    Status s = ParseCapabilitySets(r.cursor(), r.remaining(), count, combined,
                                   out.capabilities);
    if (s != Status::Ok) return s;
    if (!r.skip(static_cast<size_t>(combined) - 4)) return Status::InvalidLength;

    // sessionId trails the capability sets; the client ignores it.
    if (r.remaining() >= 4) {
        if (!r.u32le(out.session_id)) return Status::InvalidLength;
    }

    // totalLength must agree with what was actually consumed.
    if (out.total_length != size) return Status::InvalidLength;
    return Status::Ok;
}

// ---- Confirm Active -------------------------------------------------------

Status ConfirmActivePdu::parse(const uint8_t* data, size_t size,
                               ConfirmActivePdu& out) {
    out = ConfirmActivePdu{};
    if (data == nullptr || size < 16) return Status::NeedMoreData;

    ByteReader r(data, size);
    if (!r.u16le(out.total_length)) return Status::NeedMoreData;
    uint16_t pdu_type = 0;
    if (!r.u16le(pdu_type)) return Status::NeedMoreData;
    const uint16_t type = static_cast<uint16_t>(pdu_type & 0x000F);
    const uint16_t version = static_cast<uint16_t>((pdu_type >> 4) & 0x0FFF);
    if (type != static_cast<uint16_t>(SharePduType::kConfirmActive)) {
        return Status::InvalidType;
    }
    if (version != ShareControlHeader::kProtocolVersion) {
        return Status::InvalidVersion;
    }
    if (!r.u16le(out.pdu_source)) return Status::NeedMoreData;
    if (!r.u32le(out.share_id)) return Status::NeedMoreData;
    if (!r.u16le(out.originator_id)) return Status::NeedMoreData;

    uint16_t src_len = 0;
    uint16_t combined = 0;
    if (!r.u16le(src_len)) return Status::NeedMoreData;
    if (!r.u16le(combined)) return Status::NeedMoreData;
    if (src_len > r.remaining()) return Status::InvalidLength;
    out.source_descriptor.resize(src_len);
    if (src_len != 0 && !r.bytes(out.source_descriptor.data(), src_len)) {
        return Status::InvalidLength;
    }

    uint16_t count = 0;
    if (!r.u16le(count)) return Status::NeedMoreData;
    uint16_t pad2 = 0;
    if (!r.u16le(pad2)) return Status::NeedMoreData;

    Status s = ParseCapabilitySets(r.cursor(), r.remaining(), count, combined,
                                   out.capabilities);
    if (s != Status::Ok) return s;
    if (out.total_length != size) return Status::InvalidLength;
    return Status::Ok;
}

std::vector<uint8_t> ConfirmActivePdu::encode(
    uint16_t pdu_source, uint32_t share_id, uint16_t originator_id,
    const std::string& source_descriptor, const std::vector<CapabilitySet>& sets) {
    ByteWriter caps;
    uint16_t count = 0;
    uint16_t combined = 0;
    WriteCapabilitySets(caps, sets, count, combined);

    const size_t src_len = source_descriptor.size();
    // totalLength = 6 (share control) + 4 (shareID) + 2 (originator) + 2 + 2
    //             + src_len + combined
    const size_t total = 6 + 4 + 2 + 2 + 2 + src_len + combined;

    ByteWriter w;
    w.u16le(static_cast<uint16_t>(total));
    w.u16le(static_cast<uint16_t>(
        static_cast<uint16_t>(SharePduType::kConfirmActive) |
        (static_cast<uint16_t>(ShareControlHeader::kProtocolVersion) << 4)));
    w.u16le(pdu_source);
    w.u32le(share_id);
    w.u16le(originator_id);
    w.u16le(static_cast<uint16_t>(src_len));
    w.u16le(combined);
    if (src_len != 0) {
        w.bytes(reinterpret_cast<const uint8_t*>(source_descriptor.data()), src_len);
    }
    w.u16le(count);
    w.u16le(0);  // pad2Octets
    w.bytes(caps.data().data(), caps.size());
    return w.take();
}

// ---- Typed capability sets ------------------------------------------------

namespace {

// Reads a u16 at `off` from the set payload, or returns 0 when the set is
// shorter than the declared layout. Truncated sets are legal on the wire (the
// Font set is commonly 4 bytes), so missing trailing fields read as zero.
uint16_t FieldU16(const CapabilitySet& set, size_t off) {
    if (off + 2 > set.data.size()) return 0;
    return static_cast<uint16_t>(
        static_cast<uint16_t>(set.data[off]) |
        static_cast<uint16_t>(set.data[off + 1] << 8));
}

uint32_t FieldU32(const CapabilitySet& set, size_t off) {
    if (off + 4 > set.data.size()) return 0;
    return static_cast<uint32_t>(set.data[off]) |
           (static_cast<uint32_t>(set.data[off + 1]) << 8) |
           (static_cast<uint32_t>(set.data[off + 2]) << 16) |
           (static_cast<uint32_t>(set.data[off + 3]) << 24);
}

CapabilitySet MakeSet(CapabilityType type, ByteWriter& body) {
    CapabilitySet set;
    set.type = type;
    set.data = body.take();
    return set;
}

// Rejects a set whose declared type does not match the decoder.
Status Expect(const CapabilitySet& set, CapabilityType want) {
    return set.type == want ? Status::Ok : Status::InvalidType;
}

}  // namespace

// ---- General --------------------------------------------------------------

Status GeneralCapabilitySet::parse(const CapabilitySet& set,
                                   GeneralCapabilitySet& out) {
    out = GeneralCapabilitySet{};
    if (const Status s = Expect(set, CapabilityType::kGeneral); s != Status::Ok) {
        return s;
    }
    if (set.data.size() < 20) return Status::InvalidLength;
    out.os_major_type = FieldU16(set, 0);
    out.os_minor_type = FieldU16(set, 2);
    out.protocol_version = FieldU16(set, 4);
    out.compression_types = FieldU16(set, 8);
    out.extra_flags = FieldU16(set, 10);
    out.update_capability_flag = FieldU16(set, 12);
    out.remote_unshare_flag = FieldU16(set, 14);
    out.compression_level = FieldU16(set, 16);
    // refreshRectSupport / suppressOutputSupport are 1-byte fields at 18/19 and
    // are server-only; absent in a 20-byte client set is fine.
    if (set.data.size() >= 19) out.refresh_rect_support = set.data[18];
    if (set.data.size() >= 20) out.suppress_output_support = set.data[19];
    return Status::Ok;
}

CapabilitySet GeneralCapabilitySet::encode() const {
    ByteWriter b;
    b.u16le(os_major_type);
    b.u16le(os_minor_type);
    b.u16le(protocol_version);
    b.u16le(0);  // pad2octetsA
    b.u16le(compression_types);
    b.u16le(extra_flags);
    b.u16le(update_capability_flag);
    b.u16le(remote_unshare_flag);
    b.u16le(compression_level);
    b.u8(refresh_rect_support);
    b.u8(suppress_output_support);
    return MakeSet(CapabilityType::kGeneral, b);
}

// ---- Bitmap ---------------------------------------------------------------

Status BitmapCapabilitySet::parse(const CapabilitySet& set,
                                  BitmapCapabilitySet& out) {
    out = BitmapCapabilitySet{};
    if (const Status s = Expect(set, CapabilityType::kBitmap); s != Status::Ok) {
        return s;
    }
    if (set.data.size() < 24) return Status::InvalidLength;
    out.preferred_bits_per_pixel = FieldU16(set, 0);
    // receive1/4/8BitsPerPixel at 2/4/6 are ignored.
    out.desktop_width = FieldU16(set, 8);
    out.desktop_height = FieldU16(set, 10);
    out.desktop_resize_flag = FieldU16(set, 14);
    out.bitmap_compression_flag = FieldU16(set, 16);
    out.high_color_flags = set.data[18];
    out.drawing_flags = set.data[19];
    out.multiple_rectangle_support = FieldU16(set, 20);
    return Status::Ok;
}

CapabilitySet BitmapCapabilitySet::encode() const {
    ByteWriter b;
    b.u16le(preferred_bits_per_pixel);
    b.u16le(1);  // receive1BitPerPixel (ignored)
    b.u16le(1);  // receive4BitsPerPixel (ignored)
    b.u16le(1);  // receive8BitsPerPixel (ignored)
    b.u16le(desktop_width);
    b.u16le(desktop_height);
    b.u16le(0);  // pad2octets
    b.u16le(desktop_resize_flag);
    b.u16le(bitmap_compression_flag);
    b.u8(high_color_flags);
    b.u8(drawing_flags);
    b.u16le(multiple_rectangle_support);
    b.u16le(0);  // pad2octetsB
    return MakeSet(CapabilityType::kBitmap, b);
}

// ---- Order ----------------------------------------------------------------

Status OrderCapabilitySet::parse(const CapabilitySet& set,
                                 OrderCapabilitySet& out) {
    out = OrderCapabilitySet{};
    if (const Status s = Expect(set, CapabilityType::kOrder); s != Status::Ok) {
        return s;
    }
    if (set.data.size() < 84) return Status::InvalidLength;
    out.order_flags = FieldU16(set, 30);
    out.order_support.assign(set.data.begin() + 32, set.data.begin() + 64);
    out.text_flags = FieldU16(set, 64);
    out.order_support_ex_flags = FieldU16(set, 66);
    out.text_ansi_code_page = FieldU16(set, 80);
    return Status::Ok;
}

CapabilitySet OrderCapabilitySet::encode() const {
    ByteWriter b;
    for (int i = 0; i < 16; ++i) b.u8(0);  // terminalDescriptor (ignored)
    b.u32le(0);                            // pad4octetsA
    b.u16le(1);                            // desktopSaveXGranularity
    b.u16le(20);                           // desktopSaveYGranularity
    b.u16le(0);                            // pad2octetsA
    b.u16le(1);                            // maximumOrderLevel
    b.u16le(0);                            // numberFonts
    b.u16le(order_flags);
    for (size_t i = 0; i < kOrderSupportSize; ++i) {
        b.u8(i < order_support.size() ? order_support[i] : 0);
    }
    b.u16le(text_flags);
    b.u16le(order_support_ex_flags);
    b.u32le(0);        // pad4octetsB
    b.u32le(230400);   // desktopSaveSize
    b.u16le(0);        // pad2octetsC
    b.u16le(0);        // pad2octetsD
    b.u16le(text_ansi_code_page);
    b.u16le(0);        // pad2octetsE
    return MakeSet(CapabilityType::kOrder, b);
}

// ---- Input ----------------------------------------------------------------

Status InputCapabilitySet::parse(const CapabilitySet& set,
                                 InputCapabilitySet& out) {
    out = InputCapabilitySet{};
    if (const Status s = Expect(set, CapabilityType::kInput); s != Status::Ok) {
        return s;
    }
    if (set.data.size() < 20) return Status::InvalidLength;
    out.input_flags = FieldU16(set, 0);
    out.keyboard_layout = FieldU32(set, 4);
    out.keyboard_type = FieldU32(set, 8);
    out.keyboard_sub_type = FieldU32(set, 12);
    out.keyboard_function_key = FieldU32(set, 16);
    const size_t ime_len = std::min<size_t>(64, set.data.size() - 20);
    out.ime_file_name.assign(set.data.begin() + 20, set.data.begin() + 20 + ime_len);
    return Status::Ok;
}

CapabilitySet InputCapabilitySet::encode() const {
    ByteWriter b;
    b.u16le(input_flags);
    b.u16le(0);  // pad2octetsA
    b.u32le(keyboard_layout);
    b.u32le(keyboard_type);
    b.u32le(keyboard_sub_type);
    b.u32le(keyboard_function_key);
    // imeFileName: 64 bytes, UTF-16LE, NUL padded.
    for (size_t i = 0; i < 64; ++i) {
        b.u8(i < ime_file_name.size() ? ime_file_name[i] : 0);
    }
    return MakeSet(CapabilityType::kInput, b);
}

// ---- Pointer --------------------------------------------------------------

Status PointerCapabilitySet::parse(const CapabilitySet& set,
                                   PointerCapabilitySet& out) {
    out = PointerCapabilitySet{};
    if (const Status s = Expect(set, CapabilityType::kPointer); s != Status::Ok) {
        return s;
    }
    if (set.data.size() < 6) return Status::InvalidLength;
    out.color_pointer_flag = FieldU16(set, 0);
    out.color_pointer_cache_size = FieldU16(set, 2);
    out.pointer_cache_size = FieldU16(set, 4);
    return Status::Ok;
}

CapabilitySet PointerCapabilitySet::encode() const {
    ByteWriter b;
    b.u16le(color_pointer_flag);
    b.u16le(color_pointer_cache_size);
    b.u16le(pointer_cache_size);
    return MakeSet(CapabilityType::kPointer, b);
}

// ---- Share ----------------------------------------------------------------

Status ShareCapabilitySet::parse(const CapabilitySet& set,
                                 ShareCapabilitySet& out) {
    out = ShareCapabilitySet{};
    if (const Status s = Expect(set, CapabilityType::kShare); s != Status::Ok) {
        return s;
    }
    if (set.data.size() < 2) return Status::InvalidLength;
    out.node_id = FieldU16(set, 0);
    return Status::Ok;
}

CapabilitySet ShareCapabilitySet::encode() const {
    ByteWriter b;
    b.u16le(node_id);
    b.u16le(0);  // pad2octets
    return MakeSet(CapabilityType::kShare, b);
}

// ---- Virtual channel ------------------------------------------------------

Status VirtualChannelCapabilitySet::parse(const CapabilitySet& set,
                                          VirtualChannelCapabilitySet& out) {
    out = VirtualChannelCapabilitySet{};
    if (const Status s = Expect(set, CapabilityType::kVirtualChannel);
        s != Status::Ok) {
        return s;
    }
    if (set.data.size() < 4) return Status::InvalidLength;
    out.flags = FieldU32(set, 0);
    // VCChunkSize is optional: 8-byte sets omit it, 12-byte sets include it.
    if (set.data.size() >= 8) {
        out.has_chunk_size = true;
        out.chunk_size = FieldU32(set, 4);
    }
    return Status::Ok;
}

CapabilitySet VirtualChannelCapabilitySet::encode() const {
    ByteWriter b;
    b.u32le(flags);
    if (has_chunk_size) b.u32le(chunk_size);
    return MakeSet(CapabilityType::kVirtualChannel, b);
}

// ---- Font -----------------------------------------------------------------

Status FontCapabilitySet::parse(const CapabilitySet& set,
                                FontCapabilitySet& out) {
    out = FontCapabilitySet{};
    if (const Status s = Expect(set, CapabilityType::kFont); s != Status::Ok) {
        return s;
    }
    // The reference server sends 4 bytes total, i.e. no payload at all.
    if (set.data.size() >= 2) {
        out.has_support_flags = true;
        out.font_support_flags = FieldU16(set, 0);
    }
    return Status::Ok;
}

CapabilitySet FontCapabilitySet::encode() const {
    ByteWriter b;
    if (has_support_flags) {
        b.u16le(font_support_flags);
        b.u16le(0);  // pad2octets
    }
    return MakeSet(CapabilityType::kFont, b);
}

// ---- Glyph cache ----------------------------------------------------------

Status GlyphCacheCapabilitySet::parse(const CapabilitySet& set,
                                      GlyphCacheCapabilitySet& out) {
    out = GlyphCacheCapabilitySet{};
    if (const Status s = Expect(set, CapabilityType::kGlyphCache); s != Status::Ok) {
        return s;
    }
    if (set.data.size() < 48) return Status::InvalidLength;
    out.glyph_cache.clear();
    out.glyph_cache.reserve(kGlyphCaches);
    for (size_t i = 0; i < kGlyphCaches; ++i) {
        CacheDefinition def;
        def.cache_entries = FieldU16(set, i * 4);
        def.maximum_cell_size = FieldU16(set, i * 4 + 2);
        out.glyph_cache.push_back(def);
    }
    out.frag_cache.cache_entries = FieldU16(set, 40);
    out.frag_cache.maximum_cell_size = FieldU16(set, 42);
    out.glyph_support_level = FieldU16(set, 44);
    out.pad2octets = FieldU16(set, 46);
    return Status::Ok;
}

CapabilitySet GlyphCacheCapabilitySet::encode() const {
    ByteWriter b;
    for (size_t i = 0; i < kGlyphCaches; ++i) {
        const CacheDefinition def =
            i < glyph_cache.size() ? glyph_cache[i] : CacheDefinition{};
        b.u16le(def.cache_entries);
        b.u16le(def.maximum_cell_size);
    }
    b.u16le(frag_cache.cache_entries);
    b.u16le(frag_cache.maximum_cell_size);
    b.u16le(glyph_support_level);
    b.u16le(pad2octets);
    return MakeSet(CapabilityType::kGlyphCache, b);
}

// ---- Bitmap cache Rev2 ----------------------------------------------------

Status BitmapCacheRev2CapabilitySet::parse(const CapabilitySet& set,
                                           BitmapCacheRev2CapabilitySet& out) {
    out = BitmapCacheRev2CapabilitySet{};
    if (const Status s = Expect(set, CapabilityType::kBitmapCacheRev2);
        s != Status::Ok) {
        return s;
    }
    // [MS-RDPBCGR] 2.2.7.1.4.2: CacheFlags(2) | Pad2(1) | NumCellCaches(1) |
    // BitmapCache0..4CellInfo (5 x 4) | Pad3 (12). The four header bytes must be
    // present. The fixed cell-info slots that a truncated payload does not reach
    // read as zero (FieldU32), so a short set is tolerated, not rejected.
    if (set.data.size() < 4) return Status::InvalidLength;
    out.cache_flags = FieldU16(set, 0);
    out.num_cell_caches = set.data[3];
    // NumCellCaches is bounded by 5 in the specification; a larger value is a
    // lie and cannot be represented by the five fixed slots.
    if (out.num_cell_caches > kCellInfoSlots) return Status::InvalidLength;
    out.cell_info.clear();
    out.cell_info.reserve(out.num_cell_caches);
    for (size_t i = 0; i < out.num_cell_caches; ++i) {
        out.cell_info.push_back(FieldU32(set, 4 + i * 4));
    }
    return Status::Ok;
}

CapabilitySet BitmapCacheRev2CapabilitySet::encode() const {
    // Fixed 40-byte set: all five cell-info slots are always written, so a
    // receiver can walk the structure without deriving the length from
    // NumCellCaches. Slots beyond the populated ones are zero.
    const size_t count = std::min(cell_info.size(), kCellInfoSlots);
    ByteWriter b;
    b.u16le(cache_flags);
    b.u8(0);  // Pad2, ignored
    b.u8(static_cast<uint8_t>(count));
    for (size_t i = 0; i < kCellInfoSlots; ++i) {
        b.u32le(i < cell_info.size() ? cell_info[i] : 0);
    }
    for (size_t i = 0; i < 12; ++i) b.u8(0);  // Pad3, ignored
    return MakeSet(CapabilityType::kBitmapCacheRev2, b);
}

// ---- Default client set ---------------------------------------------------

std::vector<CapabilitySet> BuildDefaultClientCapabilities(uint16_t desktop_width,
                                                          uint16_t desktop_height,
                                                          uint16_t color_depth) {
    std::vector<CapabilitySet> sets;

    GeneralCapabilitySet general;
    general.os_major_type = 0x0001;  // Windows
    general.os_minor_type = 0x0003;  // Windows NT
    // Fast-path output and salted checksums are only enabled once the transport
    // can actually handle them, so start with neither.
    general.extra_flags = 0x0001;  // FASTPATH_OUTPUT_SUPPORTED (probe)
    sets.push_back(general.encode());

    BitmapCapabilitySet bitmap;
    bitmap.preferred_bits_per_pixel = color_depth;
    bitmap.desktop_width = desktop_width;
    bitmap.desktop_height = desktop_height;
    bitmap.bitmap_compression_flag = 1;      // MUST
    bitmap.multiple_rectangle_support = 1;   // MUST
    sets.push_back(bitmap.encode());

    OrderCapabilitySet order;
    // orderSupport is indexed by negotiation index, NOT by orderType
    // ([MS-RDPBCGR] 2.2.7.1.3; see docs/spec/capabilities.md 9.4). Only the
    // orders this client actually implements are claimed: 0x00 DstBlt,
    // 0x01 PatBlt + OpaqueRect (one shared index), 0x02 ScrBlt. The rest are
    // left 0 — claiming an unimplemented order (MemBlt/Mem3Blt/SaveBitmap)
    // would make the server send orders the engine cannot decode, and the
    // unused indices (0x05/0x06/0x0A/0x0C-0x0E/0x1C-0x1F) MUST stay 0.
    const size_t indices[] = {0x00, 0x01, 0x02};
    for (size_t idx : indices) {
        if (idx < order.order_support.size()) order.order_support[idx] = 1;
    }
    // Do NOT set SOLIDPATTERNBRUSHONLY (0x0040): hatched brushes are implemented,
    // and a cached brush that is not BMF_1BPP yields kUnsupported without
    // aborting the order stream (see OrderEngine), so the flag would only
    // disable working functionality.
    sets.push_back(order.encode());

    PointerCapabilitySet pointer;
    pointer.color_pointer_cache_size = 32;
    pointer.pointer_cache_size = 32;
    sets.push_back(pointer.encode());

    InputCapabilitySet input;
    sets.push_back(input.encode());

    ShareCapabilitySet share;
    share.node_id = 0;  // the client SHOULD send zero
    sets.push_back(share.encode());

    FontCapabilitySet font;
    font.has_support_flags = true;
    font.font_support_flags = FontCapabilitySet::kFontSupportFontList;
    sets.push_back(font.encode());

    VirtualChannelCapabilitySet vc;
    vc.flags = VirtualChannelCapabilitySet::kNoComp;
    sets.push_back(vc.encode());

    GlyphCacheCapabilitySet glyphs;
    // Conservative cell sizes; the exact values only affect rendering quality.
    for (size_t i = 0; i < GlyphCacheCapabilitySet::kGlyphCaches; ++i) {
        CacheDefinition def;
        def.cache_entries = (i == 0) ? 254 : 0;
        def.maximum_cell_size = (i == 0) ? 4 : 0;
        glyphs.glyph_cache.push_back(def);
    }
    glyphs.frag_cache.cache_entries = 0;
    glyphs.frag_cache.maximum_cell_size = 0;
    glyphs.glyph_support_level = 0;
    sets.push_back(glyphs.encode());

    BitmapCacheRev2CapabilitySet rev2;
    rev2.cache_flags = 0;
    rev2.cell_info = {0x00000064, 0x00000064, 0x00000064};
    sets.push_back(rev2.encode());

    return sets;
}

}  // namespace rtsc::proto
