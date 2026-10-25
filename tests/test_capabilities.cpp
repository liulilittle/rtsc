#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/capabilities.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> FromHex(const std::string& hex) {
    std::vector<uint8_t> out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    int hi = -1;
    for (char c : hex) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        const int v = nib(c);
        if (v < 0) return {};
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

// Wraps a payload in a capability set header.
std::vector<uint8_t> WrapSet(uint16_t type, const std::vector<uint8_t>& payload) {
    ByteWriter w;
    w.u16le(type);
    w.u16le(static_cast<uint16_t>(4 + payload.size()));
    w.bytes(payload.data(), payload.size());
    return w.take();
}

}  // namespace

// ---- Type table -----------------------------------------------------------

RTSC_TEST(capability_type_table_has_28_assigned_values) {
    int assigned = 0;
    for (uint16_t raw = 0x0000; raw <= 0x0020; ++raw) {
        if (IsAssignedCapabilityType(raw)) ++assigned;
    }
    CHECK_EQ(assigned, 28);
}

RTSC_TEST(capability_type_holes_are_rejected) {
    // 0x0006 and 0x000B are holes inside 0x0001..0x001E.
    CHECK(!IsAssignedCapabilityType(0x0000));
    CHECK(!IsAssignedCapabilityType(0x0006));
    CHECK(!IsAssignedCapabilityType(0x000B));
    CHECK(!IsAssignedCapabilityType(0x001F));
    CHECK(!IsAssignedCapabilityType(0xFFFF));
    CHECK(IsAssignedCapabilityType(0x0001));
    CHECK(IsAssignedCapabilityType(0x001E));
}

RTSC_TEST(capability_numbers_match_spec) {
    // The task brief had these wrong; these are the spec values.
    // volatile keeps these from constant-folding into C4127.
    const volatile uint16_t general = static_cast<uint16_t>(CapabilityType::kGeneral);
    const volatile uint16_t bitmap = static_cast<uint16_t>(CapabilityType::kBitmap);
    const volatile uint16_t order = static_cast<uint16_t>(CapabilityType::kOrder);
    const volatile uint16_t pointer = static_cast<uint16_t>(CapabilityType::kPointer);
    const volatile uint16_t share = static_cast<uint16_t>(CapabilityType::kShare);
    const volatile uint16_t input = static_cast<uint16_t>(CapabilityType::kInput);
    const volatile uint16_t font = static_cast<uint16_t>(CapabilityType::kFont);
    const volatile uint16_t rev2 = static_cast<uint16_t>(CapabilityType::kBitmapCacheRev2);
    const volatile uint16_t vc = static_cast<uint16_t>(CapabilityType::kVirtualChannel);
    CHECK(general == 0x0001);
    CHECK(bitmap == 0x0002);
    CHECK(order == 0x0003);
    CHECK(pointer == 0x0008);
    CHECK(share == 0x0009);
    CHECK(input == 0x000D);
    CHECK(font == 0x000E);
    CHECK(rev2 == 0x0013);
    // VirtualChannel is 0x0014 (decimal 20), NOT 14. 14 is Font.
    CHECK(vc == 0x0014);
}

RTSC_TEST(capability_names_cover_all_and_reject_unknown) {
    CHECK(std::string(to_string(CapabilityType::kGeneral)) == "general");
    CHECK(std::string(to_string(CapabilityType::kVirtualChannel)) == "virtual-channel");
    CHECK(std::string(to_string(CapabilityType::kFrameAcknowledge)) ==
          "frame-acknowledge");
    CHECK(std::string(to_string(static_cast<CapabilityType>(0x0006))) == "unknown");
}

// ---- Capability set list --------------------------------------------------

RTSC_TEST(capability_list_parses_two_sets) {
    ByteWriter w;
    const auto general = WrapSet(0x0001, std::vector<uint8_t>(20, 0xAA));
    const auto bitmap = WrapSet(0x0002, std::vector<uint8_t>(24, 0xBB));
    w.bytes(general.data(), general.size());
    w.bytes(bitmap.data(), bitmap.size());
    const uint16_t combined = static_cast<uint16_t>(4 + general.size() + bitmap.size());

    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), 2, combined, list) ==
          Status::Ok);
    CHECK_EQ(list.sets.size(), static_cast<size_t>(2));
    CHECK(list.sets[0].type == CapabilityType::kGeneral);
    CHECK(list.sets[1].type == CapabilityType::kBitmap);
    CHECK_EQ(list.sets[0].data.size(), static_cast<size_t>(20));
    CHECK(!list.trailing_slack);
    CHECK(!list.count_mismatch);
    CHECK(list.find(CapabilityType::kBitmap) != nullptr);
    CHECK(list.find(CapabilityType::kOrder) == nullptr);
}

RTSC_TEST(capability_list_rejects_short_length) {
    // lengthCapability = 2 cannot contain its own header, so the walk cannot
    // advance. Without this check the parser would loop forever.
    ByteWriter w;
    w.u16le(0x0001);
    w.u16le(2);
    w.u16le(0);
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), 1, 8, list) ==
          Status::InvalidLength);
}

RTSC_TEST(capability_list_rejects_combined_below_four) {
    // lengthCombinedCapabilities < 4 would make (combined - 4) underflow.
    const auto data = FromHex("01 00 18 00 00 00 00 00");
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(data.data(), data.size(), 1, 2, list) ==
          Status::InvalidLength);
    CHECK(ParseCapabilitySets(data.data(), data.size(), 1, 0, list) ==
          Status::InvalidLength);
}

RTSC_TEST(capability_list_rejects_set_overrunning_window) {
    // One set claims 200 bytes but only 8 are present: the classic OOB read.
    ByteWriter w;
    w.u16le(0x0001);
    w.u16le(200);
    for (int i = 0; i < 4; ++i) w.u8(0);
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), 1, 12, list) ==
          Status::InvalidLength);
}

RTSC_TEST(capability_list_rejects_count_exceeding_window) {
    // Declared count 3 but the window holds one 8-byte set.
    ByteWriter w;
    w.u16le(0x0001);
    w.u16le(8);
    for (int i = 0; i < 4; ++i) w.u8(0);
    CapabilitySetList list;
    const Status s = ParseCapabilitySets(w.data().data(), w.data().size(), 3, 12, list);
    CHECK(s == Status::InvalidLength);
    CHECK(list.count_mismatch);
}

RTSC_TEST(capability_list_rejects_truncated_buffer) {
    // combined says 12 bytes of sets, only 4 are present.
    ByteWriter w;
    w.u16le(0x0001);
    w.u16le(8);
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), 1, 12, list) ==
          Status::InvalidLength);
}

RTSC_TEST(capability_list_flags_trailing_slack) {
    // Two sets present, but the window is larger than their sum.
    ByteWriter w;
    w.u16le(0x0001);
    w.u16le(8);
    for (int i = 0; i < 4; ++i) w.u8(0);
    w.u8(0);  // 1 extra byte of slack
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), 1, 13, list) ==
          Status::Ok);
    CHECK(list.trailing_slack);
}

RTSC_TEST(capability_list_allows_zero_count) {
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(nullptr, 0, 0, 4, list) == Status::Ok);
    CHECK_EQ(list.sets.size(), static_cast<size_t>(0));
    CHECK(!list.trailing_slack);
}

RTSC_TEST(capability_list_roundtrips) {
    std::vector<CapabilitySet> sets;
    CapabilitySet a;
    a.type = CapabilityType::kGeneral;
    a.data.assign(20, 0x11);
    sets.push_back(a);
    CapabilitySet b;
    b.type = CapabilityType::kPointer;
    b.data.assign(6, 0x22);
    sets.push_back(b);

    ByteWriter w;
    uint16_t count = 0;
    uint16_t combined = 0;
    WriteCapabilitySets(w, sets, count, combined);
    CHECK_EQ(count, static_cast<uint16_t>(2));
    CHECK_EQ(combined, static_cast<uint16_t>(4 + 24 + 10));

    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), count, combined,
                              list) == Status::Ok);
    CHECK_EQ(list.sets.size(), static_cast<size_t>(2));
    CHECK(list.sets[0].data == a.data);
    CHECK(list.sets[1].data == b.data);
}

// ---- Typed sets: layout ---------------------------------------------------

RTSC_TEST(general_set_is_24_bytes) {
    GeneralCapabilitySet g;
    g.os_major_type = 0x0001;
    g.os_minor_type = 0x0003;
    g.extra_flags = GeneralCapabilitySet::kFastpathOutputSupported;
    const auto set = g.encode();
    CHECK_EQ(set.wire_size(), static_cast<size_t>(24));
    CHECK_EQ(ExpectedCapabilityLength(0x0001), static_cast<uint16_t>(24));

    GeneralCapabilitySet back;
    CHECK(GeneralCapabilitySet::parse(set, back) == Status::Ok);
    CHECK_EQ(back.os_major_type, static_cast<uint16_t>(1));
    CHECK_EQ(back.os_minor_type, static_cast<uint16_t>(3));
    CHECK_EQ(back.protocol_version, static_cast<uint16_t>(0x0200));
    CHECK_EQ(back.extra_flags, static_cast<uint16_t>(0x0400));
}

RTSC_TEST(general_set_field_offsets) {
    // 11 x u16 + 2 x u8 = 24 bytes. Verify the byte positions directly.
    GeneralCapabilitySet g;
    g.os_major_type = 0xAAAA;
    g.os_minor_type = 0xBBBB;
    g.protocol_version = 0xCCCC;
    g.compression_types = 0xDDDD;
    g.extra_flags = 0xEEEE;
    g.update_capability_flag = 0x0101;
    g.remote_unshare_flag = 0x0202;
    g.compression_level = 0x0303;
    g.refresh_rect_support = 0x44;
    g.suppress_output_support = 0x55;
    const auto set = g.encode();
    CHECK_EQ(set.data.size(), static_cast<size_t>(20));
    // payload offsets: osMajor@0 osMinor@2 protocol@4 pad@6 compressionTypes@8
    CHECK_EQ(set.data[0], static_cast<uint8_t>(0xAA));
    CHECK_EQ(set.data[2], static_cast<uint8_t>(0xBB));
    CHECK_EQ(set.data[4], static_cast<uint8_t>(0xCC));
    CHECK_EQ(set.data[8], static_cast<uint8_t>(0xDD));
    CHECK_EQ(set.data[10], static_cast<uint8_t>(0xEE));
    CHECK_EQ(set.data[18], static_cast<uint8_t>(0x44));
    CHECK_EQ(set.data[19], static_cast<uint8_t>(0x55));
}

RTSC_TEST(bitmap_set_is_28_bytes) {
    BitmapCapabilitySet b;
    b.preferred_bits_per_pixel = 24;
    b.desktop_width = 1280;
    b.desktop_height = 1024;
    const auto set = b.encode();
    CHECK_EQ(set.wire_size(), static_cast<size_t>(28));
    CHECK_EQ(ExpectedCapabilityLength(0x0002), static_cast<uint16_t>(28));

    BitmapCapabilitySet back;
    CHECK(BitmapCapabilitySet::parse(set, back) == Status::Ok);
    CHECK_EQ(back.preferred_bits_per_pixel, static_cast<uint16_t>(24));
    CHECK_EQ(back.desktop_width, static_cast<uint16_t>(1280));
    CHECK_EQ(back.desktop_height, static_cast<uint16_t>(1024));
    // Both of these MUST be TRUE for the connection to proceed.
    CHECK_EQ(back.bitmap_compression_flag, static_cast<uint16_t>(1));
    CHECK_EQ(back.multiple_rectangle_support, static_cast<uint16_t>(1));
}

RTSC_TEST(order_set_is_88_bytes) {
    OrderCapabilitySet o;
    o.order_support[0x00] = 1;
    o.order_support[0x08] = 1;
    o.text_ansi_code_page = 0x04E4;
    const auto set = o.encode();
    CHECK_EQ(set.wire_size(), static_cast<size_t>(88));
    CHECK_EQ(ExpectedCapabilityLength(0x0003), static_cast<uint16_t>(88));

    OrderCapabilitySet back;
    CHECK(OrderCapabilitySet::parse(set, back) == Status::Ok);
    CHECK_EQ(back.order_flags, static_cast<uint16_t>(0x000A));
    CHECK_EQ(back.order_support.size(), static_cast<size_t>(32));
    CHECK_EQ(back.order_support[0x00], static_cast<uint8_t>(1));
    CHECK_EQ(back.order_support[0x08], static_cast<uint8_t>(1));
    CHECK_EQ(back.order_support[0x05], static_cast<uint8_t>(0));
    CHECK_EQ(back.text_ansi_code_page, static_cast<uint16_t>(0x04E4));
    CHECK_EQ(back.order_support_ex_flags, static_cast<uint16_t>(0));
}

RTSC_TEST(order_flags_match_ms_rdpbcgr_2_2_7_1_3) {
    // [MS-RDPBCGR] 2.2.7.1.3 TS_ORDER_CAPABILITYSET::orderFlags:
    //   NEGOTIATEORDERSUPPORT   = 0x0002 (MUST be set)
    //   ZEROBOUNDSDELTASSUPPORT = 0x0008 (MUST be set)
    // Official dump (2.2.7.1.3 example): orderFlags = 0x002a
    //   = COLORINDEXSUPPORT(0x0020) | ZEROBOUNDSDELTASSUPPORT(0x0008)
    //     | NEGOTIATEORDERSUPPORT(0x0002).
    const volatile uint16_t negotiate = OrderCapabilitySet::kNegotiateOrderSupport;
    const volatile uint16_t zero_bounds = OrderCapabilitySet::kZeroBoundsDeltaSupport;
    CHECK(negotiate == 0x0002);
    CHECK(zero_bounds == 0x0008);

    OrderCapabilitySet o;
    const auto set = o.encode();
    CHECK_EQ(set.data.size(), static_cast<size_t>(84));
    // orderFlags sits at payload offset 30 (after terminalDescriptor(16),
    // pad4octetsA(4) and five 2-byte fields), little-endian.
    CHECK_EQ(set.data[30], static_cast<uint8_t>(0x0A));
    CHECK_EQ(set.data[31], static_cast<uint8_t>(0x00));
    CHECK(set.data[30] != 0x03);
}

RTSC_TEST(input_set_is_88_bytes_and_requires_scancodes) {
    InputCapabilitySet i;
    const auto set = i.encode();
    CHECK_EQ(set.wire_size(), static_cast<size_t>(88));
    CHECK_EQ(ExpectedCapabilityLength(0x000D), static_cast<uint16_t>(88));

    InputCapabilitySet back;
    CHECK(InputCapabilitySet::parse(set, back) == Status::Ok);
    // At a minimum INPUT_FLAG_SCANCODES MUST be set.
    CHECK((back.input_flags & InputCapabilitySet::kInputFlagScancodes) != 0);
    CHECK_EQ(back.keyboard_layout, static_cast<uint32_t>(0x00000409));
    CHECK_EQ(back.keyboard_type, static_cast<uint32_t>(4));
    CHECK_EQ(back.keyboard_function_key, static_cast<uint32_t>(12));
    CHECK_EQ(back.ime_file_name.size(), static_cast<size_t>(64));
}

RTSC_TEST(pointer_set_is_10_bytes) {
    PointerCapabilitySet p;
    p.color_pointer_cache_size = 32;
    p.pointer_cache_size = 32;
    const auto set = p.encode();
    CHECK_EQ(set.wire_size(), static_cast<size_t>(10));
    CHECK_EQ(ExpectedCapabilityLength(0x0008), static_cast<uint16_t>(10));

    PointerCapabilitySet back;
    CHECK(PointerCapabilitySet::parse(set, back) == Status::Ok);
    CHECK_EQ(back.color_pointer_cache_size, static_cast<uint16_t>(32));
    CHECK_EQ(back.pointer_cache_size, static_cast<uint16_t>(32));
}

RTSC_TEST(share_set_is_8_bytes) {
    ShareCapabilitySet s;
    s.node_id = 0;
    const auto set = s.encode();
    CHECK_EQ(set.wire_size(), static_cast<size_t>(8));
    CHECK_EQ(ExpectedCapabilityLength(0x0009), static_cast<uint16_t>(8));
    ShareCapabilitySet back;
    CHECK(ShareCapabilitySet::parse(set, back) == Status::Ok);
    CHECK_EQ(back.node_id, static_cast<uint16_t>(0));
}

RTSC_TEST(font_set_tolerates_four_byte_server_form) {
    // The reference server sends lengthCapability = 4 (no payload at all); the
    // spec annotates this as a server bug. Parsing must not reject it.
    const auto set_bytes = FromHex("0e 00 04 00");
    ByteReader r(set_bytes.data(), set_bytes.size());
    uint16_t type = 0, len = 0;
    CHECK(r.u16le(type));
    CHECK(r.u16le(len));
    CapabilitySet set;
    set.type = static_cast<CapabilityType>(type);
    CHECK_EQ(len, static_cast<uint16_t>(4));

    FontCapabilitySet f;
    CHECK(FontCapabilitySet::parse(set, f) == Status::Ok);
    CHECK(!f.has_support_flags);  // the fields are simply absent
    CHECK_EQ(f.font_support_flags, static_cast<uint16_t>(0));

    // The full 8-byte form still parses.
    FontCapabilitySet full;
    full.has_support_flags = true;
    full.font_support_flags = FontCapabilitySet::kFontSupportFontList;
    const auto encoded = full.encode();
    CHECK_EQ(encoded.wire_size(), static_cast<size_t>(8));
    FontCapabilitySet back;
    CHECK(FontCapabilitySet::parse(encoded, back) == Status::Ok);
    CHECK(back.has_support_flags);
    CHECK_EQ(back.font_support_flags, static_cast<uint16_t>(0x0001));
}

RTSC_TEST(virtual_channel_accepts_both_lengths) {
    // 8-byte form: no VCChunkSize.
    VirtualChannelCapabilitySet v;
    v.flags = VirtualChannelCapabilitySet::kComprSc;
    auto set = v.encode();
    CHECK_EQ(set.wire_size(), static_cast<size_t>(8));
    VirtualChannelCapabilitySet back;
    CHECK(VirtualChannelCapabilitySet::parse(set, back) == Status::Ok);
    CHECK(!back.has_chunk_size);
    CHECK_EQ(back.flags, static_cast<uint32_t>(1));

    // 12-byte form: VCChunkSize present. There is no "fixed 12" rule.
    v.has_chunk_size = true;
    v.chunk_size = 1600;
    set = v.encode();
    CHECK_EQ(set.wire_size(), static_cast<size_t>(12));
    CHECK(VirtualChannelCapabilitySet::parse(set, back) == Status::Ok);
    CHECK(back.has_chunk_size);
    CHECK_EQ(back.chunk_size, static_cast<uint32_t>(1600));
}

RTSC_TEST(glyph_cache_set_is_52_bytes) {
    GlyphCacheCapabilitySet g;
    for (size_t i = 0; i < GlyphCacheCapabilitySet::kGlyphCaches; ++i) {
        CacheDefinition def;
        def.cache_entries = static_cast<uint16_t>(i + 1);
        def.maximum_cell_size = static_cast<uint16_t>(16 * (i + 1));
        g.glyph_cache.push_back(def);
    }
    g.frag_cache.cache_entries = 256;
    g.frag_cache.maximum_cell_size = 256;
    g.glyph_support_level = 3;
    const auto set = g.encode();
    CHECK_EQ(set.wire_size(), static_cast<size_t>(52));
    CHECK_EQ(ExpectedCapabilityLength(0x0010), static_cast<uint16_t>(52));

    GlyphCacheCapabilitySet back;
    CHECK(GlyphCacheCapabilitySet::parse(set, back) == Status::Ok);
    CHECK_EQ(back.glyph_cache.size(), static_cast<size_t>(10));
    CHECK_EQ(back.glyph_cache[0].cache_entries, static_cast<uint16_t>(1));
    CHECK_EQ(back.glyph_cache[9].maximum_cell_size, static_cast<uint16_t>(160));
    CHECK_EQ(back.frag_cache.cache_entries, static_cast<uint16_t>(256));
    CHECK_EQ(back.glyph_support_level, static_cast<uint16_t>(3));
}

RTSC_TEST(bitmap_cache_rev2_is_fixed_40_bytes) {
    BitmapCacheRev2CapabilitySet r;
    r.cache_flags = BitmapCacheRev2CapabilitySet::kPersistentKeysExpected;
    r.cell_info = {0x00000064, 0x00000064, 0x00000064};
    const auto set = r.encode();
    // [MS-RDPBCGR] 2.2.7.1.4.2: 4 (header) + 2 (CacheFlags) + 1 (Pad2)
    // + 1 (NumCellCaches) + 5*4 (BitmapCache0..4CellInfo) + 12 (Pad3) = 40.
    CHECK_EQ(set.wire_size(), static_cast<size_t>(40));
    CHECK_EQ(ExpectedCapabilityLength(0x0013), static_cast<uint16_t>(40));

    // Byte layout: CacheFlags | Pad2 | NumCellCaches | BitmapCache0CellInfo ...
    const auto& d = set.data;
    CHECK_EQ(d.size(), static_cast<size_t>(36));
    CHECK_EQ(d[0], static_cast<uint8_t>(0x02));  // CacheFlags low
    CHECK_EQ(d[1], static_cast<uint8_t>(0x00));  // CacheFlags high
    CHECK_EQ(d[2], static_cast<uint8_t>(0x00));  // Pad2
    CHECK_EQ(d[3], static_cast<uint8_t>(0x03));  // NumCellCaches
    CHECK_EQ(d[4], static_cast<uint8_t>(0x64));  // BitmapCache0CellInfo = 0x64
    CHECK_EQ(d[5], static_cast<uint8_t>(0x00));
    CHECK_EQ(d[6], static_cast<uint8_t>(0x00));
    CHECK_EQ(d[7], static_cast<uint8_t>(0x00));
    // Slots beyond NumCellCaches and all of Pad3 are zero.
    for (size_t i = 16; i < d.size(); ++i) {
        CHECK_EQ(d[i], static_cast<uint8_t>(0x00));
    }

    BitmapCacheRev2CapabilitySet back;
    const Status st = BitmapCacheRev2CapabilitySet::parse(set, back);
    CHECK(st == Status::Ok);
    if (st == Status::Ok) {
        CHECK_EQ(back.cache_flags, static_cast<uint16_t>(2));
        CHECK_EQ(back.num_cell_caches, static_cast<uint8_t>(3));
        CHECK_EQ(back.cell_info.size(), static_cast<size_t>(3));
        CHECK_EQ(back.cell_info[0], static_cast<uint32_t>(0x64));
    }
}

RTSC_TEST(bitmap_cache_rev2_zero_fills_truncated_cells) {
    // A payload truncated before all five cell infos still parses; the missing
    // fixed slots read as zero.
    ByteWriter b;
    b.u16le(0x0001);  // CacheFlags
    b.u8(0);          // Pad2
    b.u8(5);          // NumCellCaches
    b.u32le(0x64);    // only one CellInfo entry present
    CapabilitySet set;
    set.type = CapabilityType::kBitmapCacheRev2;
    set.data = b.take();
    BitmapCacheRev2CapabilitySet back;
    const Status st = BitmapCacheRev2CapabilitySet::parse(set, back);
    CHECK(st == Status::Ok);
    if (st == Status::Ok) {
        CHECK_EQ(back.num_cell_caches, static_cast<uint8_t>(5));
        CHECK_EQ(back.cell_info.size(), static_cast<size_t>(5));
        CHECK_EQ(back.cell_info[0], static_cast<uint32_t>(0x64));
        CHECK_EQ(back.cell_info[4], static_cast<uint32_t>(0));
    }
}

RTSC_TEST(bitmap_cache_rev2_rejects_count_above_spec_max) {
    // NumCellCaches is bounded by 5 ([MS-RDPBCGR] 2.2.7.1.4.2).
    ByteWriter b;
    b.u16le(0);  // CacheFlags
    b.u8(0);     // Pad2
    b.u8(6);     // NumCellCaches = 6 > 5
    for (int i = 0; i < 6; ++i) b.u32le(0x64);
    CapabilitySet set;
    set.type = CapabilityType::kBitmapCacheRev2;
    set.data = b.take();
    BitmapCacheRev2CapabilitySet back;
    CHECK(BitmapCacheRev2CapabilitySet::parse(set, back) ==
          Status::InvalidLength);
}

RTSC_TEST(bitmap_cache_rev2_rejects_missing_header) {
    CapabilitySet set;
    set.type = CapabilityType::kBitmapCacheRev2;
    set.data = {0x00, 0x00, 0x03};  // CacheFlags + Pad2, no NumCellCaches
    BitmapCacheRev2CapabilitySet back;
    CHECK(BitmapCacheRev2CapabilitySet::parse(set, back) ==
          Status::InvalidLength);
}

RTSC_TEST(typed_parsers_reject_wrong_type) {
    GeneralCapabilitySet g;
    const auto general = g.encode();
    BitmapCapabilitySet b;
    CHECK(BitmapCapabilitySet::parse(general, b) == Status::InvalidType);
    OrderCapabilitySet o;
    CHECK(OrderCapabilitySet::parse(general, o) == Status::InvalidType);
    InputCapabilitySet i;
    CHECK(InputCapabilitySet::parse(general, i) == Status::InvalidType);
}

// ---- Demand Active --------------------------------------------------------

namespace {

// Builds a Demand Active PDU with the given capability sets.
std::vector<uint8_t> BuildDemandActive(uint32_t share_id,
                                       const std::vector<CapabilitySet>& sets) {
    ByteWriter caps;
    uint16_t count = 0;
    uint16_t combined = 0;
    WriteCapabilitySets(caps, sets, count, combined);

    const std::string descriptor = "RDP";
    const size_t src_len = descriptor.size() + 1;  // includes NUL
    // totalLength = 14 (header..lengthCombinedCapabilities) + src_len
    //             + combined (already includes numberCapabilities+pad2Octets)
    //             + 4 (sessionId)
    const size_t total = 14 + src_len + combined + 4;

    ByteWriter w;
    w.u16le(static_cast<uint16_t>(total));
    w.u16le(0x0011);  // PDUTYPE_DEMANDACTIVEPDU | version 1
    w.u16le(0x03EA);  // pduSource = server channel
    w.u32le(share_id);
    w.u16le(static_cast<uint16_t>(src_len));
    w.u16le(combined);
    w.bytes(reinterpret_cast<const uint8_t*>(descriptor.data()), descriptor.size());
    w.u8(0);
    w.u16le(count);
    w.u16le(0);  // pad2Octets
    w.bytes(caps.data().data(), caps.size());
    w.u32le(0x00000001);  // sessionId
    return w.take();
}

}  // namespace

RTSC_TEST(demand_active_parses_full_pdu) {
    std::vector<CapabilitySet> sets;
    GeneralCapabilitySet g;
    g.os_major_type = 1;
    g.os_minor_type = 3;
    sets.push_back(g.encode());
    BitmapCapabilitySet b;
    b.desktop_width = 1280;
    b.desktop_height = 1024;
    sets.push_back(b.encode());

    const auto bytes = BuildDemandActive(0x000103EA, sets);
    DemandActivePdu pdu;
    CHECK(DemandActivePdu::parse(bytes.data(), bytes.size(), pdu) == Status::Ok);
    CHECK_EQ(pdu.total_length, static_cast<uint16_t>(bytes.size()));
    CHECK_EQ(pdu.pdu_source, static_cast<uint16_t>(0x03EA));
    CHECK_EQ(pdu.share_id, static_cast<uint32_t>(0x000103EA));
    CHECK_EQ(pdu.source_descriptor.size(), static_cast<size_t>(4));
    CHECK(pdu.source_descriptor[0] == 'R');
    CHECK_EQ(pdu.capabilities.sets.size(), static_cast<size_t>(2));
    CHECK(pdu.capabilities.find(CapabilityType::kGeneral) != nullptr);
    CHECK_EQ(pdu.session_id, static_cast<uint32_t>(1));

    const CapabilitySet* bmp = pdu.capabilities.find(CapabilityType::kBitmap);
    CHECK(bmp != nullptr);
    if (bmp != nullptr) {
        BitmapCapabilitySet parsed;
        CHECK(BitmapCapabilitySet::parse(*bmp, parsed) == Status::Ok);
        CHECK_EQ(parsed.desktop_width, static_cast<uint16_t>(1280));
    }
}

RTSC_TEST(demand_active_rejects_wrong_pdu_type) {
    auto bytes = BuildDemandActive(1, {});
    bytes[2] = 0x13;  // Confirm Active instead of Demand Active
    DemandActivePdu pdu;
    CHECK(DemandActivePdu::parse(bytes.data(), bytes.size(), pdu) ==
          Status::InvalidType);
}

RTSC_TEST(demand_active_rejects_total_length_mismatch) {
    auto bytes = BuildDemandActive(1, {});
    bytes[0] = static_cast<uint8_t>(bytes[0] + 4);
    DemandActivePdu pdu;
    CHECK(DemandActivePdu::parse(bytes.data(), bytes.size(), pdu) ==
          Status::InvalidLength);
}

// ---- Confirm Active -------------------------------------------------------

RTSC_TEST(confirm_active_roundtrips) {
    std::vector<CapabilitySet> sets;
    GeneralCapabilitySet g;
    g.extra_flags = GeneralCapabilitySet::kFastpathOutputSupported;
    sets.push_back(g.encode());
    PointerCapabilitySet p;
    p.color_pointer_cache_size = 32;
    p.pointer_cache_size = 32;
    sets.push_back(p.encode());

    const auto bytes = ConfirmActivePdu::encode(1007, 0x000103EA, 0x03EA, "MSTSC", sets);
    ConfirmActivePdu pdu;
    CHECK(ConfirmActivePdu::parse(bytes.data(), bytes.size(), pdu) == Status::Ok);
    CHECK_EQ(pdu.total_length, static_cast<uint16_t>(bytes.size()));
    CHECK_EQ(pdu.pdu_source, static_cast<uint16_t>(1007));
    CHECK_EQ(pdu.share_id, static_cast<uint32_t>(0x000103EA));
    CHECK_EQ(pdu.originator_id, static_cast<uint16_t>(0x03EA));
    CHECK_EQ(pdu.source_descriptor.size(), static_cast<size_t>(5));
    CHECK_EQ(pdu.capabilities.sets.size(), static_cast<size_t>(2));
    CHECK_EQ(pdu.capabilities.combined_length,
             static_cast<uint16_t>(4 + 24 + 10));
}

RTSC_TEST(confirm_active_offsets) {
    // totalLength(2) pduType(2) pduSource(2) shareID(4) originatorID(2)
    // lengthSourceDescriptor(2) lengthCombinedCapabilities(2) src(N)
    // numberCapabilities(2) pad2Octets(2) caps
    std::vector<CapabilitySet> sets;
    GeneralCapabilitySet g;
    sets.push_back(g.encode());
    const auto bytes = ConfirmActivePdu::encode(0x03EF, 0x11223344, 0x03EA, "AB", sets);
    CHECK_EQ(bytes[2], static_cast<uint8_t>(0x13));  // type 3 | version 1
    CHECK_EQ(bytes[3], static_cast<uint8_t>(0x00));
    CHECK_EQ(bytes[4], static_cast<uint8_t>(0xEF));  // pduSource = 0x03EF
    CHECK_EQ(bytes[5], static_cast<uint8_t>(0x03));
    CHECK_EQ(bytes[6], static_cast<uint8_t>(0x44));  // shareID LE
    CHECK_EQ(bytes[7], static_cast<uint8_t>(0x33));
    CHECK_EQ(bytes[8], static_cast<uint8_t>(0x22));
    CHECK_EQ(bytes[9], static_cast<uint8_t>(0x11));
    CHECK_EQ(bytes[10], static_cast<uint8_t>(0xEA));  // originatorID = 0x03EA
    CHECK_EQ(bytes[11], static_cast<uint8_t>(0x03));
    CHECK_EQ(bytes[12], static_cast<uint8_t>(0x02));  // lengthSourceDescriptor
    CHECK_EQ(bytes[13], static_cast<uint8_t>(0x00));
    // sourceDescriptor starts at 16 (12..13 = lengthSourceDescriptor,
    // 14..15 = lengthCombinedCapabilities).
    CHECK_EQ(bytes[14], static_cast<uint8_t>(0x1C));  // lengthCombinedCapabilities
    CHECK_EQ(bytes[15], static_cast<uint8_t>(0x00));
    CHECK_EQ(bytes[16], static_cast<uint8_t>('A'));
    CHECK_EQ(bytes[17], static_cast<uint8_t>('B'));
    CHECK_EQ(bytes[18], static_cast<uint8_t>(0x01));  // numberCapabilities
}

RTSC_TEST(confirm_active_rejects_wrong_type) {
    auto bytes = ConfirmActivePdu::encode(1, 2, 3, "", {});
    bytes[2] = 0x11;  // Demand Active
    ConfirmActivePdu pdu;
    CHECK(ConfirmActivePdu::parse(bytes.data(), bytes.size(), pdu) ==
          Status::InvalidType);
}

// ---- Default client set ---------------------------------------------------

RTSC_TEST(default_client_capabilities_are_well_formed) {
    const auto sets = BuildDefaultClientCapabilities(1280, 1024, 24);
    CHECK(sets.size() >= 9);

    // Every set's declared length must equal its actual size.
    for (const auto& set : sets) {
        const uint16_t expected = ExpectedCapabilityLength(static_cast<uint16_t>(set.type));
        if (expected != 0) {
            CHECK_EQ(set.wire_size(), static_cast<size_t>(expected));
        }
    }

    // Serialise and re-parse to prove the whole list is self-consistent.
    ByteWriter w;
    uint16_t count = 0;
    uint16_t combined = 0;
    WriteCapabilitySets(w, sets, count, combined);
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), count, combined,
                              list) == Status::Ok);
    CHECK_EQ(list.sets.size(), static_cast<size_t>(sets.size()));
    CHECK(!list.trailing_slack);
}

RTSC_TEST(default_client_capabilities_have_mandatory_bits) {
    const auto sets = BuildDefaultClientCapabilities(1280, 1024, 24);
    ByteWriter w;
    uint16_t count = 0;
    uint16_t combined = 0;
    WriteCapabilitySets(w, sets, count, combined);
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), count, combined,
                              list) == Status::Ok);

    // Bitmap: both flags MUST be TRUE or the connection cannot proceed.
    const CapabilitySet* bmp = list.find(CapabilityType::kBitmap);
    CHECK(bmp != nullptr);
    if (bmp != nullptr) {
        BitmapCapabilitySet b;
        CHECK(BitmapCapabilitySet::parse(*bmp, b) == Status::Ok);
        CHECK_EQ(b.bitmap_compression_flag, static_cast<uint16_t>(1));
        CHECK_EQ(b.multiple_rectangle_support, static_cast<uint16_t>(1));
        CHECK_EQ(b.desktop_width, static_cast<uint16_t>(1280));
        CHECK_EQ(b.desktop_height, static_cast<uint16_t>(1024));
    }

    // Input: at minimum SCANCODES.
    const CapabilitySet* input = list.find(CapabilityType::kInput);
    CHECK(input != nullptr);
    if (input != nullptr) {
        InputCapabilitySet i;
        CHECK(InputCapabilitySet::parse(*input, i) == Status::Ok);
        CHECK((i.input_flags & InputCapabilitySet::kInputFlagScancodes) != 0);
    }

    // Pointer: both cache sizes zero would earn ERRINFO_NOCURSORCACHE.
    const CapabilitySet* pointer = list.find(CapabilityType::kPointer);
    CHECK(pointer != nullptr);
    if (pointer != nullptr) {
        PointerCapabilitySet p;
        CHECK(PointerCapabilitySet::parse(*pointer, p) == Status::Ok);
        CHECK(p.color_pointer_cache_size != 0 || p.pointer_cache_size != 0);
    }

    // Share: the client SHOULD send nodeID 0.
    const CapabilitySet* share = list.find(CapabilityType::kShare);
    CHECK(share != nullptr);
    if (share != nullptr) {
        ShareCapabilitySet s;
        CHECK(ShareCapabilitySet::parse(*share, s) == Status::Ok);
        CHECK_EQ(s.node_id, static_cast<uint16_t>(0));
    }
}

RTSC_TEST(default_client_capabilities_omit_server_only_sets) {
    const auto sets = BuildDefaultClientCapabilities(1024, 768, 16);
    for (const auto& set : sets) {
        // BmpCacheHostSupport is server-to-client only.
        CHECK(set.type != CapabilityType::kBitmapCacheHostSupport);
    }
    // Fast-path output must not be advertised until the transport supports it.
    ByteWriter w;
    uint16_t count = 0;
    uint16_t combined = 0;
    WriteCapabilitySets(w, sets, count, combined);
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), count, combined,
                              list) == Status::Ok);
    const CapabilitySet* gen = list.find(CapabilityType::kGeneral);
    CHECK(gen != nullptr);
    if (gen != nullptr) {
        GeneralCapabilitySet g;
        CHECK(GeneralCapabilitySet::parse(*gen, g) == Status::Ok);
        CHECK((g.extra_flags & GeneralCapabilitySet::kFastpathOutputSupported) == 0);
    }
}

// The default order capability set must claim exactly the orders the client
// implements: negotiation indices 0x00 (DstBlt), 0x01 (PatBlt + OpaqueRect) and
// 0x02 (ScrBlt), and nothing else ([MS-RDPBCGR] 2.2.7.1.3).
RTSC_TEST(order_support_bits_exact) {
    const auto sets = BuildDefaultClientCapabilities(1280, 1024, 24);
    ByteWriter w;
    uint16_t count = 0;
    uint16_t combined = 0;
    WriteCapabilitySets(w, sets, count, combined);
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), count, combined,
                              list) == Status::Ok);
    const CapabilitySet* ord = list.find(CapabilityType::kOrder);
    CHECK(ord != nullptr);
    if (ord == nullptr) return;
    OrderCapabilitySet o;
    CHECK(OrderCapabilitySet::parse(*ord, o) == Status::Ok);
    CHECK_EQ(o.order_support.size(), static_cast<size_t>(32));
    CHECK_EQ(o.order_support[0x00], static_cast<uint8_t>(1));
    CHECK_EQ(o.order_support[0x01], static_cast<uint8_t>(1));
    CHECK_EQ(o.order_support[0x02], static_cast<uint8_t>(1));
    for (size_t i = 0; i < o.order_support.size(); ++i) {
        if (i == 0x00 || i == 0x01 || i == 0x02) continue;
        CHECK_EQ(o.order_support[i], static_cast<uint8_t>(0));
    }
}

RTSC_TEST(order_support_does_not_claim_unimplemented) {
    const auto sets = BuildDefaultClientCapabilities(1280, 1024, 24);
    ByteWriter w;
    uint16_t count = 0;
    uint16_t combined = 0;
    WriteCapabilitySets(w, sets, count, combined);
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), count, combined,
                              list) == Status::Ok);
    const CapabilitySet* ord = list.find(CapabilityType::kOrder);
    CHECK(ord != nullptr);
    if (ord == nullptr) return;
    OrderCapabilitySet o;
    CHECK(OrderCapabilitySet::parse(*ord, o) == Status::Ok);
    // MemBlt / Mem3Blt / SaveBitmap are not implemented, and 0x0A is an unused
    // index: claiming any of them would be a false declaration.
    CHECK_EQ(o.order_support[0x03], static_cast<uint8_t>(0));
    CHECK_EQ(o.order_support[0x04], static_cast<uint8_t>(0));
    CHECK_EQ(o.order_support[0x0A], static_cast<uint8_t>(0));
    CHECK_EQ(o.order_support[0x0B], static_cast<uint8_t>(0));
    CHECK_EQ(o.order_support[0x1C], static_cast<uint8_t>(0));
}

RTSC_TEST(order_flags_does_not_set_solidpatternbrushonly) {
    const auto sets = BuildDefaultClientCapabilities(1280, 1024, 24);
    ByteWriter w;
    uint16_t count = 0;
    uint16_t combined = 0;
    WriteCapabilitySets(w, sets, count, combined);
    CapabilitySetList list;
    CHECK(ParseCapabilitySets(w.data().data(), w.data().size(), count, combined,
                              list) == Status::Ok);
    const CapabilitySet* ord = list.find(CapabilityType::kOrder);
    CHECK(ord != nullptr);
    if (ord == nullptr) return;
    OrderCapabilitySet o;
    CHECK(OrderCapabilitySet::parse(*ord, o) == Status::Ok);
    CHECK((o.order_flags & OrderCapabilitySet::kNegotiateOrderSupport) != 0);
    CHECK((o.order_flags & OrderCapabilitySet::kZeroBoundsDeltaSupport) != 0);
    // SOLIDPATTERNBRUSHONLY must stay clear: hatched brushes are implemented and
    // an unsupported cached brush does not abort the order stream (see OrderEngine),
    // so setting it would only disable working functionality.
    CHECK((o.order_flags & OrderCapabilitySet::kSolidPatternBrushOnly) == 0);
}

int main() { return rtsc::test::run_all("rtsc_capabilities_tests"); }
