// Bitmap decoding ([MS-RDPBCGR] 2.2.9.1.1.3.1.2).

#include "rtsc/proto/bitmap.h"

#include <cstdint>
#include <string>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::string Hex(const std::vector<uint8_t>& b) {
    static const char* k = "0123456789abcdef";
    std::string s;
    for (uint8_t c : b) {
        s.push_back(k[c >> 4]);
        s.push_back(k[c & 0xF]);
    }
    return s;
}

std::vector<uint8_t> FromHex(const char* h) {
    std::vector<uint8_t> out;
    int hi = -1;
    for (const char* p = h; *p; ++p) {
        int v = -1;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else continue;
        if (hi < 0) hi = v;
        else { out.push_back(static_cast<uint8_t>((hi << 4) | v)); hi = -1; }
    }
    return out;
}

}  // namespace

RTSC_TEST(bitmap_compressed_header_parses) {
    const auto b = FromHex("02 00 34 12 80 02 00 08");
    BitmapCompressedHeader h;
    CHECK(BitmapCompressedHeader::parse(b.data(), b.size(), h) == Status::Ok);
    CHECK_EQ(h.first_row_size, static_cast<uint16_t>(2));
    CHECK_EQ(h.main_body_size, static_cast<uint16_t>(0x1234));
    CHECK_EQ(h.scan_width, static_cast<uint16_t>(0x0280));
    CHECK_EQ(h.uncompressed_size, static_cast<uint16_t>(0x0800));
}

RTSC_TEST(raw_24bpp_is_bottom_up_and_row_padded) {
    // 2x2, 24bpp: wire rows are 6 bytes padded to 8.
    // Bottom wire row: pixels (BGR) 10 20 30, 40 50 60; Top: 70 80 90, A0 B0 C0.
    const auto data = FromHex(
        "10 20 30 40 50 60 00 00"
        "70 80 90 a0 b0 c0 00 00");
    DecodedBitmap bm;
    CHECK(DecodeRawBitmap(data.data(), data.size(), 2, 2, 24, bm) == Status::Ok);
    CHECK_EQ(bm.width, static_cast<uint16_t>(2));
    CHECK_EQ(bm.height, static_cast<uint16_t>(2));
    CHECK_EQ(bm.pixels.size(), static_cast<size_t>(16));
    // Top output row comes from the second wire row (top-down conversion).
    CHECK(Hex(bm.pixels) == "908070ffc0b0a0ff302010ff605040ff");
}

RTSC_TEST(raw_32bpp_bgra) {
    // 1x1, 32bpp, wire pixel BGRA = 11 22 33 44 -> RGBA 33 22 11 FF.
    const auto data = FromHex("11 22 33 44");
    DecodedBitmap bm;
    CHECK(DecodeRawBitmap(data.data(), data.size(), 1, 1, 32, bm) == Status::Ok);
    CHECK(Hex(bm.pixels) == "332211ff");
}

RTSC_TEST(raw_16bpp_rgb565) {
    // 1x1, 16bpp, value 0xF800 = pure red in RGB565. Rows pad to 4 bytes.
    const auto data = FromHex("00 f8 00 00");
    DecodedBitmap bm;
    CHECK(DecodeRawBitmap(data.data(), data.size(), 1, 1, 16, bm) == Status::Ok);
    CHECK_EQ(bm.pixels.size(), static_cast<size_t>(4));
    CHECK_EQ(bm.pixels[0], static_cast<uint8_t>(0xFF));  // R
    CHECK_EQ(bm.pixels[1], static_cast<uint8_t>(0x00));  // G
    CHECK_EQ(bm.pixels[2], static_cast<uint8_t>(0x00));  // B
}

RTSC_TEST(raw_8bpp_uses_palette) {
    // 1x1, 8bpp, index 3; palette entry 3 = (0xAA, 0xBB, 0xCC). Rows pad to 4.
    std::vector<uint8_t> palette(768, 0);
    palette[3 * 3] = 0xAA;
    palette[3 * 3 + 1] = 0xBB;
    palette[3 * 3 + 2] = 0xCC;
    const auto data = FromHex("03 00 00 00");
    DecodedBitmap bm;
    CHECK(DecodeRawBitmap(data.data(), data.size(), 1, 1, 8, bm, &palette) ==
          Status::Ok);
    CHECK(Hex(bm.pixels) == "aabbccff");
}

RTSC_TEST(raw_bitmap_rejects_unsupported_bpp_and_short_data) {
    const auto data = FromHex("00 00 00 00");
    DecodedBitmap bm;
    CHECK(DecodeRawBitmap(data.data(), data.size(), 1, 1, 12, bm) ==
          Status::InvalidField);
    // 2x2 24bpp needs 16 bytes (padded); only 4 given.
    CHECK(DecodeRawBitmap(data.data(), data.size(), 2, 2, 24, bm) ==
          Status::NeedMoreData);
    // 8bpp without a palette is rejected.
    CHECK(DecodeRawBitmap(data.data(), data.size(), 1, 1, 8, bm) ==
          Status::InvalidField);
}

// ---- Interleaved RLE ------------------------------------------------------

RTSC_TEST(rle_color_run_fills_bitmap) {
    // 2x1 24bpp, REGULAR_COLOR_RUN run=2 (header 0x62), color BGR 10 20 30.
    const auto data = FromHex("62 10 20 30");
    DecodedBitmap bm;
    CHECK(DecodeRleBitmap(data.data(), data.size(), 2, 1, 24, bm) == Status::Ok);
    CHECK(Hex(bm.pixels) == "302010ff302010ff");
}

RTSC_TEST(rle_color_image_copies_pixels) {
    // 2x1 24bpp, REGULAR_COLOR_IMAGE run=2 (header 0x82).
    const auto data = FromHex("82 11 22 33 44 55 66");
    DecodedBitmap bm;
    CHECK(DecodeRleBitmap(data.data(), data.size(), 2, 1, 24, bm) == Status::Ok);
    CHECK(Hex(bm.pixels) == "332211ff665544ff");
}

RTSC_TEST(rle_bg_run_on_first_line_is_black) {
    // 2x1 24bpp, REGULAR_BG_RUN run=2 (header 0x02) -> black on the first line.
    const auto data = FromHex("02");
    DecodedBitmap bm;
    CHECK(DecodeRleBitmap(data.data(), data.size(), 2, 1, 24, bm) == Status::Ok);
    CHECK(Hex(bm.pixels) == "000000ff000000ff");
}

RTSC_TEST(rle_special_white_and_black) {
    // WHITE (0xFD) then BLACK (0xFE) for a 2x1 bitmap.
    const auto data = FromHex("fd fe");
    DecodedBitmap bm;
    CHECK(DecodeRleBitmap(data.data(), data.size(), 2, 1, 24, bm) == Status::Ok);
    CHECK(Hex(bm.pixels) == "ffffffff000000ff");
}

RTSC_TEST(rle_lite_dithered_run) {
    // 2x1 24bpp, LITE_DITHERED_RUN 1 pair (header 0xE1), two BGR colors.
    const auto data = FromHex("e1 10 20 30 40 50 60");
    DecodedBitmap bm;
    CHECK(DecodeRleBitmap(data.data(), data.size(), 2, 1, 24, bm) == Status::Ok);
    CHECK(Hex(bm.pixels) == "302010ff605040ff");
}

RTSC_TEST(rle_is_bottom_up_and_rejects_unknown_order) {
    // 1x2 24bpp: wire row 0 = red run, wire row 1 = green run.
    const auto data = FromHex("61 00 00 ff 61 00 ff 00");
    DecodedBitmap bm;
    CHECK(DecodeRleBitmap(data.data(), data.size(), 1, 2, 24, bm) == Status::Ok);
    // Top output row comes from wire row 1 (green); bottom from wire row 0 (red).
    CHECK(Hex(bm.pixels) == "00ff00ffff0000ff");

    // An undefined regular code (5) must be rejected.
    const auto bad = FromHex("a0");
    CHECK(DecodeRleBitmap(bad.data(), bad.size(), 1, 1, 24, bm) ==
          Status::InvalidField);
}

RTSC_TEST(rle_run_spans_scanlines) {
    // 2x2 24bpp: one MEGA_MEGA_COLOR_RUN of four pixels. A run length is a pixel
    // count ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.4) and MUST cross the scanline
    // boundary, so all four pixels (both rows) carry the same colour. A decoder
    // that clamps the run to the current row would consume the whole stream on
    // row 0 and then fail on row 1 with NeedMoreData.
    const auto data = FromHex("f3 04 00 30 20 10");
    DecodedBitmap bm;
    CHECK(DecodeRleBitmap(data.data(), data.size(), 2, 2, 24, bm) == Status::Ok);
    CHECK_EQ(bm.width, static_cast<uint16_t>(2));
    CHECK_EQ(bm.height, static_cast<uint16_t>(2));
    // Wire colour 30 20 10 is little-endian BGR (B=30, G=20, R=10).
    CHECK(Hex(bm.pixels) == "102030ff102030ff102030ff102030ff");
}

RTSC_TEST(rle_special_fgbg_uses_implicit_mask) {
    // SPECIAL_FGBG_1 (0xF9) and SPECIAL_FGBG_2 (0xFA) carry an implicit 8-pixel
    // mask (0x03 / 0x05) and MUST NOT consume a mask byte from the stream
    // ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.4). 8x1 24bpp on the first line: set bits
    // write the current foreground (white), clear bits are black.
    const auto data = FromHex("f9");
    DecodedBitmap bm;
    CHECK(DecodeRleBitmap(data.data(), data.size(), 8, 1, 24, bm) == Status::Ok);
    CHECK(Hex(bm.pixels) ==
          "ffffffff" "ffffffff" "000000ff" "000000ff" "000000ff" "000000ff"
          "000000ff" "000000ff");

    const auto data2 = FromHex("fa");
    CHECK(DecodeRleBitmap(data2.data(), data2.size(), 8, 1, 24, bm) == Status::Ok);
    // 0x05 = bits 0 and 2 set.
    CHECK(Hex(bm.pixels) ==
          "ffffffff" "000000ff" "ffffffff" "000000ff" "000000ff" "000000ff"
          "000000ff" "000000ff");
}

RTSC_TEST(rle_order_crossing_first_scanline_uses_first_line_rules) {
    // 2x2 24bpp. One red pixel, then a foreground run that starts on the first
    // scanline and crosses into the second. The reference decoder decides
    // "first line" once per order, so the whole run uses the first-line rule
    // (write the foreground, not XOR with the previous scanline).
    const auto data = FromHex("61 00 00 ff f1 03 00");
    DecodedBitmap bm;
    CHECK(DecodeRleBitmap(data.data(), data.size(), 2, 2, 24, bm) == Status::Ok);
    // Bottom wire row: red, white. Top wire row: white, white.
    CHECK(Hex(bm.pixels) == "ffffffff" "ffffffff" "ff0000ff" "ffffffff");
}

RTSC_TEST(raw_32bpp_multiple_pixels_use_four_bytes) {
    // 2x1 32bpp: the RGBA converter must advance four bytes per pixel, not the
    // two-byte stride used by 15/16 bpp.
    const auto data = FromHex("11 22 33 44 55 66 77 88");
    DecodedBitmap bm;
    CHECK(DecodeRawBitmap(data.data(), data.size(), 2, 1, 32, bm) == Status::Ok);
    CHECK(Hex(bm.pixels) == "332211ff776655ff");
}

int main() { return ::rtsc::test::run_all("rtsc_bitmap_tests"); }
