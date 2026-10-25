// NSCodec compressed bitmap stream ([MS-RDPNSC] 2.2.2 / 3.1.8).

#include "rtsc/proto/nsc.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> Header(uint32_t y, uint32_t co, uint32_t cg, uint32_t a,
                            uint8_t cll, uint8_t cs) {
    ByteWriter w;
    w.u32le(y);
    w.u32le(co);
    w.u32le(cg);
    w.u32le(a);
    w.u8(cll);
    w.u8(cs);
    w.u16le(0);  // reserved
    return w.take();
}

}  // namespace

RTSC_TEST(nsc_header_parses) {
    const auto h = Header(100, 50, 50, 200, 3, 1);
    CHECK_EQ(h.size(), static_cast<size_t>(20));
    NscHeader out;
    CHECK(NscHeader::parse(h.data(), h.size(), out) == Status::Ok);
    CHECK_EQ(out.plane_byte_count[0], static_cast<uint32_t>(100));  // Y
    CHECK_EQ(out.plane_byte_count[1], static_cast<uint32_t>(50));   // Co
    CHECK_EQ(out.plane_byte_count[2], static_cast<uint32_t>(50));   // Cg
    CHECK_EQ(out.plane_byte_count[3], static_cast<uint32_t>(200));  // A
    CHECK_EQ(out.color_loss_level, static_cast<uint8_t>(3));
    CHECK_EQ(out.chroma_subsampling_level, static_cast<uint8_t>(1));
    CHECK(NscHeader::parse(h.data(), 19, out) == Status::NeedMoreData);
}

RTSC_TEST(nsc_rle_literals_and_tail) {
    // originalSize 8: 4 literals then the trailing 4 bytes copied verbatim.
    const std::vector<uint8_t> in = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44};
    std::vector<uint8_t> out(8, 0);
    CHECK(NscRleDecode(in.data(), in.size(), out.data(), out.size(), 8) == Status::Ok);
    CHECK(out == in);
}

RTSC_TEST(nsc_rle_run) {
    // 0xAA 0xAA 0x00 -> run of 0x00 + 2 = 2 bytes; then literals; then tail.
    const std::vector<uint8_t> in = {0xAA, 0xAA, 0x00, 0xBB, 0xCC,
                                     0x11, 0x22, 0x33, 0x44};
    std::vector<uint8_t> out(8, 0);
    CHECK(NscRleDecode(in.data(), in.size(), out.data(), out.size(), 8) == Status::Ok);
    CHECK(out == std::vector<uint8_t>({0xAA, 0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33, 0x44}));
}

RTSC_TEST(nsc_rle_long_run) {
    // 0x55 0x55 0xFF <u32 len> -> long run.
    ByteWriter w;
    w.u8(0x55); w.u8(0x55); w.u8(0xFF);
    w.u32le(4);  // run of 4 bytes
    w.u8(0x11); w.u8(0x22); w.u8(0x33); w.u8(0x44);
    const auto in = w.take();

    std::vector<uint8_t> out(8, 0);
    CHECK(NscRleDecode(in.data(), in.size(), out.data(), out.size(), 8) == Status::Ok);
    CHECK(out == std::vector<uint8_t>({0x55, 0x55, 0x55, 0x55, 0x11, 0x22, 0x33, 0x44}));
}

RTSC_TEST(nsc_rle_rejects_truncated) {
    const std::vector<uint8_t> in = {0xAA};
    std::vector<uint8_t> out(8, 0);
    CHECK(NscRleDecode(in.data(), in.size(), out.data(), out.size(), 8) ==
          Status::NeedMoreData);
}

RTSC_TEST(nsc_rle_rejects_oversized_run) {
    // Run length 100 exceeds the remaining 6 bytes.
    const std::vector<uint8_t> in = {0xAA, 0xAA, 0x62};  // 0x62 + 2 = 100
    std::vector<uint8_t> out(8, 0);
    CHECK(NscRleDecode(in.data(), in.size(), out.data(), out.size(), 8) ==
          Status::InvalidLength);
}

namespace {

// Builds an NSCodec stream: header + four raw planes (Y, Co, Cg, A).
std::vector<uint8_t> RawStream(uint16_t width, uint16_t height, uint8_t cll,
                               uint8_t cs, uint8_t y, uint8_t co, uint8_t cg,
                               uint8_t a) {
    const uint16_t rw = static_cast<uint16_t>((width + 7) / 8 * 8);
    const uint16_t rh = static_cast<uint16_t>((height + 1) / 2 * 2);
    const uint32_t y_size = cs ? static_cast<uint32_t>(rw) * height
                               : static_cast<uint32_t>(width) * height;
    const uint32_t c_size = cs ? static_cast<uint32_t>(rw / 2) * (rh / 2)
                               : static_cast<uint32_t>(width) * height;
    const uint32_t a_size = static_cast<uint32_t>(width) * height;

    ByteWriter w;
    w.u32le(y_size);
    w.u32le(c_size);
    w.u32le(c_size);
    w.u32le(a_size);
    w.u8(cll);
    w.u8(cs);
    w.u16le(0);
    for (uint32_t i = 0; i < y_size; ++i) w.u8(y);
    for (uint32_t i = 0; i < c_size; ++i) w.u8(co);
    for (uint32_t i = 0; i < c_size; ++i) w.u8(cg);
    for (uint32_t i = 0; i < a_size; ++i) w.u8(a);
    return w.take();
}

}  // namespace

RTSC_TEST(nsc_decode_raw_planes_aycocg) {
    // 8x2, CLL=1, no subsampling. Y=0x80, Co=0x40, Cg=0x00, A=0xFF.
    // R = Y + Co - Cg = 0xC0; G = Y + Cg = 0x80; B = Y - Co - Cg = 0x40.
    const auto s = RawStream(8, 2, 1, 0, 0x80, 0x40, 0x00, 0xFF);
    DecodedBitmap bm;
    CHECK(NscDecodeBitmap(s.data(), s.size(), 8, 2, bm) == Status::Ok);
    CHECK_EQ(bm.pixels.size(), static_cast<size_t>(64));
    CHECK_EQ(bm.pixels[0], static_cast<uint8_t>(0xC0));  // R
    CHECK_EQ(bm.pixels[1], static_cast<uint8_t>(0x80));  // G
    CHECK_EQ(bm.pixels[2], static_cast<uint8_t>(0x40));  // B
    CHECK_EQ(bm.pixels[3], static_cast<uint8_t>(0xFF));  // A
}

RTSC_TEST(nsc_decode_chroma_subsampling) {
    // 8x2, CLL=1, CS=1: Y=8x2, Co/Cg = 4x1 (upsampled).
    const auto s = RawStream(8, 2, 1, 1, 0x80, 0x40, 0x00, 0xFF);
    DecodedBitmap bm;
    CHECK(NscDecodeBitmap(s.data(), s.size(), 8, 2, bm) == Status::Ok);
    for (size_t i = 0; i < 16; ++i) {
        CHECK_EQ(bm.pixels[i * 4 + 0], static_cast<uint8_t>(0xC0));
        CHECK_EQ(bm.pixels[i * 4 + 1], static_cast<uint8_t>(0x80));
        CHECK_EQ(bm.pixels[i * 4 + 2], static_cast<uint8_t>(0x40));
    }
}

RTSC_TEST(nsc_decode_zero_plane_count_fills_opaque) {
    // Alpha plane byte count 0 -> filled with 0xFF.
    ByteWriter w;
    w.u32le(16);  // Y
    w.u32le(16);  // Co
    w.u32le(16);  // Cg
    w.u32le(0);   // A (absent)
    w.u8(1);      // CLL
    w.u8(0);      // CS
    w.u16le(0);
    for (int i = 0; i < 48; ++i) w.u8(0x80);  // Y, Co, Cg all 0x80
    const auto s = w.take();

    DecodedBitmap bm;
    CHECK(NscDecodeBitmap(s.data(), s.size(), 8, 2, bm) == Status::Ok);
    // Chroma is SIGNED: 0x80 = -128. Y=0x80, Co=Cg=-128.
    // R = Y + Co - Cg = 0x80; G = Y + Cg = 0; B = Y - Co - Cg = 0x180 -> clamp 0xFF.
    CHECK_EQ(bm.pixels[0], static_cast<uint8_t>(0x80));  // R
    CHECK_EQ(bm.pixels[1], static_cast<uint8_t>(0x00));  // G
    CHECK_EQ(bm.pixels[2], static_cast<uint8_t>(0xFF));  // B clamped
    CHECK_EQ(bm.pixels[3], static_cast<uint8_t>(0xFF));  // A default
}

RTSC_TEST(nsc_decode_rejects_bad_cll) {
    auto s = RawStream(8, 2, 1, 0, 0x80, 0x40, 0x00, 0xFF);
    s[16] = 0;  // ColorLossLevel = 0 (out of 1..7)
    DecodedBitmap bm;
    CHECK(NscDecodeBitmap(s.data(), s.size(), 8, 2, bm) == Status::InvalidField);
}

int main() { return ::rtsc::test::run_all("rtsc_nsc_tests"); }

