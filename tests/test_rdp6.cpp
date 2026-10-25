// RDP 6.0 bitmap compression framing ([MS-RDPEGDI] 2.2.2.5).

#include "rtsc/proto/rdp6.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

RTSC_TEST(rdp6_format_header_round_trip) {
    // CLL=3, CS=1, RLE=1, NA=0, Reserved=0 -> 0x03 | 0x08 | 0x10 = 0x1B.
    Rdp6FormatHeader h;
    CHECK(Rdp6FormatHeader::parse(0x1B, h) == Status::Ok);
    CHECK_EQ(h.cll, static_cast<uint8_t>(3));
    CHECK(h.chroma_subsampling);
    CHECK(h.rle);
    CHECK(!h.no_alpha);
    CHECK_EQ(h.encode(), static_cast<uint8_t>(0x1B));
}

RTSC_TEST(rdp6_format_header_argb_no_alpha) {
    // CLL=0 (ARGB), NA=1 (no alpha plane) -> 0x20.
    Rdp6FormatHeader h;
    CHECK(Rdp6FormatHeader::parse(0x20, h) == Status::Ok);
    CHECK_EQ(h.cll, static_cast<uint8_t>(0));
    CHECK(h.no_alpha);
    CHECK(!h.rle);
    CHECK(!h.chroma_subsampling);
    CHECK_EQ(h.encode(), static_cast<uint8_t>(0x20));
}

RTSC_TEST(rdp6_format_header_rejects_cs_without_cll) {
    // Chroma subsampling with CLL=0 is invalid.
    Rdp6FormatHeader h;
    CHECK(Rdp6FormatHeader::parse(0x08, h) == Status::InvalidField);
}

RTSC_TEST(rdp6_rle_segments_decode_raw_and_run) {
    // controlByte = cRawBytes (high nibble) | nRunLength (low nibble).
    // Segment 1: cb=0x30 -> 3 raw bytes.
    // Segment 2: cb=0x25 -> 2 raw bytes + 5 repeats of the last.
    const std::vector<uint8_t> data = {0x30, 0xAA, 0xBB, 0xCC, 0x25, 0xDD, 0xEE};
    std::vector<uint8_t> out;
    size_t consumed = 0;
    CHECK(DecodeRdp6RleSegments(data.data(), data.size(), 10, out, consumed) ==
          Status::Ok);
    CHECK_EQ(out.size(), static_cast<size_t>(10));
    CHECK_EQ(out[0], static_cast<uint8_t>(0xAA));
    CHECK_EQ(out[2], static_cast<uint8_t>(0xCC));
    CHECK_EQ(out[3], static_cast<uint8_t>(0xDD));
    CHECK_EQ(out[4], static_cast<uint8_t>(0xEE));
    CHECK_EQ(out[9], static_cast<uint8_t>(0xEE));
    CHECK_EQ(consumed, static_cast<size_t>(7));
}

RTSC_TEST(rdp6_rle_segment_extended_run) {
    // cb=0x10 -> 1 raw byte; cb=0x31 -> nRunLength=1 -> run = 16 + 3 = 19.
    const std::vector<uint8_t> data = {0x10, 0x77, 0x31};
    std::vector<uint8_t> out;
    size_t consumed = 0;
    CHECK(DecodeRdp6RleSegments(data.data(), data.size(), 20, out, consumed) ==
          Status::Ok);
    CHECK_EQ(out.size(), static_cast<size_t>(20));
    CHECK_EQ(out[0], static_cast<uint8_t>(0x77));
    CHECK_EQ(out[19], static_cast<uint8_t>(0x77));
}

RTSC_TEST(rdp6_rle_rejects_zero_control_byte) {
    const std::vector<uint8_t> data = {0x00, 0xAA};
    std::vector<uint8_t> out;
    size_t consumed = 0;
    CHECK(DecodeRdp6RleSegments(data.data(), data.size(), 4, out, consumed) ==
          Status::InvalidField);
}

RTSC_TEST(rdp6_rle_rejects_run_without_base_byte) {
    // First segment is a pure run (nRunLength=5, cRawBytes=0) -> no base byte.
    const std::vector<uint8_t> data = {0x05};
    std::vector<uint8_t> out;
    size_t consumed = 0;
    CHECK(DecodeRdp6RleSegments(data.data(), data.size(), 5, out, consumed) ==
          Status::InvalidField);
}

RTSC_TEST(rdp6_rle_rejects_truncated_raw) {
    // cb=0x50 claims 5 raw bytes (high nibble) but only 2 follow.
    const std::vector<uint8_t> data = {0x50, 0xAA, 0xBB};
    std::vector<uint8_t> out;
    size_t consumed = 0;
    CHECK(DecodeRdp6RleSegments(data.data(), data.size(), 5, out, consumed) ==
          Status::NeedMoreData);
}

RTSC_TEST(rdp6_bitmap_raw_argb_no_alpha) {
    // 2x1, ARGB, no alpha, raw planes: header + R + G + B + pad.
    const std::vector<uint8_t> data = {0x20, 0x10, 0x20, 0x30, 0x40,
                                       0x50, 0x60, 0x00};
    DecodedBitmap bm;
    CHECK(DecodeRdp6Bitmap(data.data(), data.size(), 2, 1, bm) == Status::Ok);
    CHECK_EQ(bm.pixels.size(), static_cast<size_t>(8));
    CHECK_EQ(bm.pixels[0], static_cast<uint8_t>(0x10));  // R
    CHECK_EQ(bm.pixels[1], static_cast<uint8_t>(0x30));  // G
    CHECK_EQ(bm.pixels[2], static_cast<uint8_t>(0x50));  // B
    CHECK_EQ(bm.pixels[3], static_cast<uint8_t>(0xFF));  // A (default opaque)
    CHECK_EQ(bm.pixels[4], static_cast<uint8_t>(0x20));
    CHECK_EQ(bm.pixels[7], static_cast<uint8_t>(0xFF));
}

RTSC_TEST(rdp6_bitmap_raw_argb_with_alpha) {
    // 1x1 with alpha: header(NA=0) + A + R + G + B + pad.
    const std::vector<uint8_t> data = {0x00, 0x80, 0x10, 0x20, 0x30, 0x00};
    DecodedBitmap bm;
    CHECK(DecodeRdp6Bitmap(data.data(), data.size(), 1, 1, bm) == Status::Ok);
    CHECK_EQ(bm.pixels.size(), static_cast<size_t>(4));
    CHECK_EQ(bm.pixels[0], static_cast<uint8_t>(0x10));
    CHECK_EQ(bm.pixels[1], static_cast<uint8_t>(0x20));
    CHECK_EQ(bm.pixels[2], static_cast<uint8_t>(0x30));
    CHECK_EQ(bm.pixels[3], static_cast<uint8_t>(0x80));  // alpha
}

RTSC_TEST(rdp6_bitmap_rle_with_row_delta) {
    // 1x2, ARGB, RLE planes. Row 0 absolute, row 1 signed-magnitude delta.
    // header 0x30 (CLL=0, RLE=1, NA=1).
    // Each plane: cb=0x20 -> 2 raw bytes. Delta byte d: bit0=sign, d>>1 magnitude.
    // R: {0x10, 0x0A} -> 0x0A -> +5 -> {0x10, 0x15}
    // G: {0x20, 0x06} -> +3 -> {0x20, 0x23}
    // B: {0x30, 0x02} -> +1 -> {0x30, 0x31}
    const std::vector<uint8_t> data = {0x30, 0x20, 0x10, 0x0A, 0x20, 0x20,
                                       0x06, 0x20, 0x30, 0x02};
    DecodedBitmap bm;
    CHECK(DecodeRdp6Bitmap(data.data(), data.size(), 1, 2, bm) == Status::Ok);
    CHECK_EQ(bm.pixels.size(), static_cast<size_t>(8));
    // Row 0.
    CHECK_EQ(bm.pixels[0], static_cast<uint8_t>(0x10));
    CHECK_EQ(bm.pixels[1], static_cast<uint8_t>(0x20));
    CHECK_EQ(bm.pixels[2], static_cast<uint8_t>(0x30));
    // Row 1 (delta added).
    CHECK_EQ(bm.pixels[4], static_cast<uint8_t>(0x15));
    CHECK_EQ(bm.pixels[5], static_cast<uint8_t>(0x23));
    CHECK_EQ(bm.pixels[6], static_cast<uint8_t>(0x31));
}

RTSC_TEST(rdp6_bitmap_rle_negative_delta) {
    // 1x2, ARGB, RLE: row 1 delta byte 0x07 -> bit0=1 -> -((7>>1)+1) = -4.
    // R: {0x20, 0x07} -> {0x20, 0x1C}; G: {0x20, 0x00} -> {0x20, 0x20};
    // B: {0x20, 0x00} -> {0x20, 0x20}.
    const std::vector<uint8_t> data = {0x30, 0x20, 0x20, 0x07, 0x20, 0x20,
                                       0x00, 0x20, 0x20, 0x00};
    DecodedBitmap bm;
    CHECK(DecodeRdp6Bitmap(data.data(), data.size(), 1, 2, bm) == Status::Ok);
    CHECK_EQ(bm.pixels[4], static_cast<uint8_t>(0x1C));  // 0x20 - 4
}

RTSC_TEST(rdp6_bitmap_aycocg_no_subsampling) {
    // 1x1, CLL=1, no alpha (NA=1), no subsampling. header = 0x01 | 0x20 = 0x21.
    // Planes: Y=0x80, Co=0x40, Cg=0x00.
    // T = Y - Cg = 128; R = T - Co = 64; G = Y + Cg = 128; B = T + Co = 192.
    const std::vector<uint8_t> data = {0x21, 0x80, 0x40, 0x00};
    DecodedBitmap bm;
    CHECK(DecodeRdp6Bitmap(data.data(), data.size(), 1, 1, bm) == Status::Ok);
    CHECK_EQ(bm.pixels[0], static_cast<uint8_t>(64));   // R
    CHECK_EQ(bm.pixels[1], static_cast<uint8_t>(128));  // G
    CHECK_EQ(bm.pixels[2], static_cast<uint8_t>(192));  // B
    CHECK_EQ(bm.pixels[3], static_cast<uint8_t>(0xFF));
}

RTSC_TEST(rdp6_bitmap_aycocg_chroma_subsampling) {
    // 2x2, CLL=1, CS=1, NA=1. header = 0x01 | 0x08 | 0x20 = 0x29.
    // Y plane = 4 bytes; Co/Cg planes = 1 byte each (2x2 -> 1x1).
    const std::vector<uint8_t> data = {0x29, 0x80, 0x80, 0x80, 0x80,
                                       0x40, 0x00};
    DecodedBitmap bm;
    CHECK(DecodeRdp6Bitmap(data.data(), data.size(), 2, 2, bm) == Status::Ok);
    // The single chroma sample is upsampled to all four pixels.
    for (size_t i = 0; i < 4; ++i) {
        CHECK_EQ(bm.pixels[i * 4 + 0], static_cast<uint8_t>(64));
        CHECK_EQ(bm.pixels[i * 4 + 1], static_cast<uint8_t>(128));
        CHECK_EQ(bm.pixels[i * 4 + 2], static_cast<uint8_t>(192));
    }
}

RTSC_TEST(rdp6_bitmap_aycocg_negative_chroma_clamps) {
    // CLL=1, Co = 0x80 -> (int8_t)0x80 = -128. Y=0x10, Cg=0.
    // T = 16; R = 16 - (-128) = 144; G = 16; B = 16 + (-128) = -112 -> clamp 0.
    const std::vector<uint8_t> data = {0x21, 0x10, 0x80, 0x00};
    DecodedBitmap bm;
    CHECK(DecodeRdp6Bitmap(data.data(), data.size(), 1, 1, bm) == Status::Ok);
    CHECK_EQ(bm.pixels[0], static_cast<uint8_t>(144));  // R
    CHECK_EQ(bm.pixels[1], static_cast<uint8_t>(16));   // G
    CHECK_EQ(bm.pixels[2], static_cast<uint8_t>(0));    // B clamped
}

int main() { return ::rtsc::test::run_all("rtsc_rdp6_tests"); }
