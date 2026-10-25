// Server fast-path output updates ([MS-RDPBCGR] 2.2.9.1.2).

#include "rtsc/proto/output.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

RTSC_TEST(fastpath_output_synchronize_update) {
    // fpOutputHeader(0x00) + length(0x05) + updateHeader(0x03) + size(0x0000).
    const std::vector<uint8_t> pdu = {0x00, 0x05, 0x03, 0x00, 0x00};
    FastPathOutputPdu out;
    CHECK(FastPathOutputPdu::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.updates.size(), static_cast<size_t>(1));
    CHECK(out.updates[0].code == FastPathUpdateCode::kSynchronize);
    CHECK(out.updates[0].data.empty());
    CHECK(out.updates[0].fragmentation == FastPathFragmentation::kSingle);
}

RTSC_TEST(fastpath_output_two_updates) {
    // synchronize(3 bytes) + pointer-position(code 8, 4-byte payload).
    const std::vector<uint8_t> pdu = {
        0x00, 0x0C,        // header + length = 12
        0x03, 0x00, 0x00,  // synchronize
        0x08, 0x04, 0x00,  // pointer position, size 4
        0x34, 0x12, 0x78, 0x56};
    FastPathOutputPdu out;
    CHECK(FastPathOutputPdu::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.updates.size(), static_cast<size_t>(2));
    CHECK(out.updates[0].code == FastPathUpdateCode::kSynchronize);
    CHECK(out.updates[1].code == FastPathUpdateCode::kPtrPosition);
    CHECK_EQ(out.updates[1].data.size(), static_cast<size_t>(4));
    CHECK_EQ(out.updates[1].data[0], static_cast<uint8_t>(0x34));
}

RTSC_TEST(fastpath_output_compression_flags_present) {
    // updateHeader 0x83 -> updateCode 3, frag 0, compression 2.
    const std::vector<uint8_t> pdu = {
        0x00, 0x06,        // header + length = 6
        0x83,              // updateCode 3, frag 0, compression 2
        0x20,              // compressionFlags (PACKET_COMPRESSED)
        0x00, 0x00};       // size 0
    FastPathOutputPdu out;
    CHECK(FastPathOutputPdu::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.updates.size(), static_cast<size_t>(1));
    CHECK(out.updates[0].has_compression_flags);
    CHECK_EQ(out.updates[0].compression_flags, static_cast<uint8_t>(0x20));
    CHECK(out.updates[0].is_compressed());
}

RTSC_TEST(fastpath_output_rejects_truncated_update) {
    // Declares 16 bytes of update data but only 3 follow.
    const std::vector<uint8_t> pdu = {0x00, 0x08, 0x01, 0x10, 0x00, 0xAA,
                                      0xBB, 0xCC};
    FastPathOutputPdu out;
    CHECK(FastPathOutputPdu::parse(pdu.data(), pdu.size(), out) ==
          Status::NeedMoreData);
}

RTSC_TEST(update_bitmap_data_parses_one_rectangle) {
    ByteWriter d;
    d.u16le(0x0001);  // UPDATETYPE_BITMAP
    d.u16le(1);       // numberRectangles
    d.u16le(0);       // destLeft
    d.u16le(0);       // destTop
    d.u16le(9);       // destRight
    d.u16le(9);       // destBottom
    d.u16le(10);      // width
    d.u16le(10);      // height
    d.u16le(32);      // bitsPerPixel
    d.u16le(0);       // flags
    d.u16le(4);       // bitmapLength
    d.u32le(0x11223344);
    const auto data = d.take();

    UpdateBitmapData bm;
    CHECK(UpdateBitmapData::parse(data.data(), data.size(), bm) == Status::Ok);
    CHECK_EQ(bm.number_rectangles, static_cast<uint16_t>(1));
    CHECK_EQ(bm.rectangles.size(), static_cast<size_t>(1));
    CHECK_EQ(bm.rectangles[0].width, static_cast<uint16_t>(10));
    CHECK_EQ(bm.rectangles[0].height, static_cast<uint16_t>(10));
    CHECK_EQ(bm.rectangles[0].bits_per_pixel, static_cast<uint16_t>(32));
    CHECK_EQ(bm.rectangles[0].dest_right, static_cast<uint16_t>(9));
    CHECK_EQ(bm.rectangles[0].bitmap_data.size(), static_cast<size_t>(4));
    CHECK_EQ(bm.rectangles[0].bitmap_data[0], static_cast<uint8_t>(0x44));
}

RTSC_TEST(update_bitmap_data_rejects_wrong_type) {
    ByteWriter d;
    d.u16le(0x0002);  // wrong: palette
    d.u16le(0);
    const auto data = d.take();
    UpdateBitmapData bm;
    CHECK(UpdateBitmapData::parse(data.data(), data.size(), bm) ==
          Status::InvalidType);
}

RTSC_TEST(update_palette_data_parses_entries) {
    ByteWriter d;
    d.u16le(0x0002);  // UPDATETYPE_PALETTE
    d.u16le(0);       // pad2Octets
    d.u16le(2);       // numberColors
    d.u8(0x11); d.u8(0x22); d.u8(0x33);
    d.u8(0x44); d.u8(0x55); d.u8(0x66);
    const auto data = d.take();

    UpdatePaletteData pal;
    CHECK(UpdatePaletteData::parse(data.data(), data.size(), pal) == Status::Ok);
    CHECK_EQ(pal.number_colors, static_cast<uint16_t>(2));
    CHECK_EQ(pal.entries.size(), static_cast<size_t>(6));
    CHECK_EQ(pal.entries[0], static_cast<uint8_t>(0x11));
    CHECK_EQ(pal.entries[5], static_cast<uint8_t>(0x66));
}

namespace {

// Builds a slow-path graphics update PDU (share data header + updateType + data).
std::vector<uint8_t> SlowPathUpdate(uint16_t update_type,
                                    const std::vector<uint8_t>& data) {
    ByteWriter w;
    w.u16le(static_cast<uint16_t>(ShareDataHeader::kSize + 2 + data.size()));
    w.u16le(0x0017);      // pduType: type=7 (datapdu), version=1
    w.u16le(0x03EF);      // pduSource
    w.u32le(0x000103EA);  // shareID
    w.u8(0);              // pad1
    w.u8(0x01);           // streamID
    w.u16le(0);           // uncompressedLength
    w.u8(0x02);           // pduType2 = PDUTYPE2_UPDATE
    w.u8(0);              // compressedType
    w.u16le(0);           // compressedLength
    w.u16le(update_type);
    if (!data.empty()) w.bytes(data.data(), data.size());
    return w.take();
}

}  // namespace

RTSC_TEST(slowpath_graphics_update_parses_bitmap) {
    // updateData = TS_UPDATE_BITMAP_DATA with 0 rectangles.
    ByteWriter d;
    d.u16le(0x0001);  // UPDATETYPE_BITMAP (repeated inside the update data)
    d.u16le(0);       // numberRectangles
    const auto pdu = SlowPathUpdate(kUpdateBitmap, d.take());

    SlowPathGraphicsUpdate out;
    CHECK(SlowPathGraphicsUpdate::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.update_type, static_cast<uint16_t>(kUpdateBitmap));
    CHECK_EQ(out.update_data.size(), static_cast<size_t>(4));

    UpdateBitmapData bm;
    CHECK(UpdateBitmapData::parse(out.update_data.data(), out.update_data.size(),
                                  bm) == Status::Ok);
    CHECK_EQ(bm.number_rectangles, static_cast<uint16_t>(0));
}

RTSC_TEST(slowpath_graphics_update_parses_synchronize) {
    // A synchronize update has no update data.
    const auto pdu = SlowPathUpdate(kUpdateSynchronize, {});
    SlowPathGraphicsUpdate out;
    CHECK(SlowPathGraphicsUpdate::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.update_type, static_cast<uint16_t>(kUpdateSynchronize));
    CHECK(out.update_data.empty());
}

RTSC_TEST(slowpath_graphics_update_rejects_wrong_pdu_type2) {
    // pduType2 = PDUTYPE2_SYNCHRONIZE (0x1F) instead of PDUTYPE2_UPDATE.
    ByteWriter w;
    w.u16le(22);
    w.u16le(0x0017);
    w.u16le(0x03EF);
    w.u32le(0x000103EA);
    w.u8(0);
    w.u8(0x01);
    w.u16le(0);
    w.u8(0x1F);  // wrong pduType2
    w.u8(0);
    w.u16le(0);
    w.u16le(0x0001);
    const auto pdu = w.take();
    SlowPathGraphicsUpdate out;
    CHECK(SlowPathGraphicsUpdate::parse(pdu.data(), pdu.size(), out) ==
          Status::InvalidType);
}

int main() { return ::rtsc::test::run_all("rtsc_output_tests"); }
