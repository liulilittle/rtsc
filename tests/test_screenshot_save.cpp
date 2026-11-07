// Screenshot save helper: deterministic naming and a real 32bpp BMP on disk.
//
// The GUI's "保存截图" command must produce a file an operator can open, and it
// must do so from the exact RGBA surface the render loop composited. These
// cases cover the name format, the BMP header/pixel layout, the failure paths
// (empty path, unwritable path) and the no-partial-file guarantee.

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>

#include "screenshot_save.h"
#include "rtsc/ui/surface.h"
#include "test_framework.h"
#include "test_main.h"

namespace {

uint32_t ReadLe32(const std::vector<uint8_t>& bytes, size_t at) {
    return static_cast<uint32_t>(bytes[at]) |
           (static_cast<uint32_t>(bytes[at + 1]) << 8) |
           (static_cast<uint32_t>(bytes[at + 2]) << 16) |
           (static_cast<uint32_t>(bytes[at + 3]) << 24);
}

uint16_t ReadLe16(const std::vector<uint8_t>& bytes, size_t at) {
    return static_cast<uint16_t>(bytes[at]) |
           (static_cast<uint16_t>(bytes[at + 1]) << 8);
}

std::vector<uint8_t> ReadWholeFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(in),
                                std::istreambuf_iterator<char>());
}

std::string TempPath(const char* name) {
    char* dir = nullptr;
    size_t len = 0;
    if (_dupenv_s(&dir, &len, "TEMP") != 0 || dir == nullptr) {
        return std::string();
    }
    std::string base(dir);
    std::free(dir);
    return base + "\\" + name;
}

}  // namespace

RTSC_TEST(screenshot_default_name_is_utc_and_deterministic) {
    // 2024-03-04 05:06:07 UTC. The name is an identifier, so it is derived
    // from UTC and must not vary with the machine's time zone.
    std::tm tm{};
    tm.tm_year = 2024 - 1900;
    tm.tm_mon = 3 - 1;
    tm.tm_mday = 4;
    tm.tm_hour = 5;
    tm.tm_min = 6;
    tm.tm_sec = 7;
#if defined(_MSC_VER)
    const std::time_t now = _mkgmtime(&tm);
#else
    const std::time_t now = timegm(&tm);
#endif
    CHECK(rtsc::gui::DefaultScreenshotName(now) ==
          std::string("rtsc-screenshot-20240304-050607.bmp"));
    // A different instant yields a different name (no fixed string).
    CHECK(rtsc::gui::DefaultScreenshotName(now + 1) ==
          std::string("rtsc-screenshot-20240304-050608.bmp"));
}

RTSC_TEST(screenshot_bmp_has_valid_header_and_rgba_to_bgra_pixels) {
    rtsc::ui::Surface surface(3, 2);
    surface.Fill(10, 20, 30, 255);
    // A distinct top-left pixel proves the row order is top-down and that R and
    // B are swapped for the BMP byte order.
    surface.SetPixel(0, 0, 0x11, 0x22, 0x33, 0x44);

    const std::string path = TempPath("rtsc_shot_header.bmp");
    CHECK(!path.empty());
    if (path.empty()) return;

    std::string error;
    const bool saved = rtsc::gui::SaveScreenshotBmp(surface, path, error);
    CHECK(saved);
    if (!saved) {
        std::printf("save failed: %s\n", error.c_str());
        return;
    }
    const std::vector<uint8_t> bmp = ReadWholeFile(path);
    std::remove(path.c_str());

    // BITMAPFILEHEADER: 'BM', size, reserved, pixel offset 54.
    CHECK_EQ(bmp.size(), static_cast<size_t>(54 + 3 * 2 * 4));
    CHECK_EQ(bmp[0], static_cast<uint8_t>('B'));
    CHECK_EQ(bmp[1], static_cast<uint8_t>('M'));
    CHECK_EQ(ReadLe32(bmp, 2), static_cast<uint32_t>(54 + 3 * 2 * 4));
    CHECK_EQ(ReadLe32(bmp, 10), static_cast<uint32_t>(54));
    // BITMAPINFOHEADER: 40 bytes, width 3, height -2 (top-down), 32 bpp, BI_RGB.
    // biPlanes (offset 26) and biBitCount (offset 28) are 16-bit fields, so
    // they must not be read as 32-bit or the two values merge.
    CHECK_EQ(ReadLe32(bmp, 14), static_cast<uint32_t>(40));
    CHECK_EQ(static_cast<int32_t>(ReadLe32(bmp, 18)), 3);
    CHECK_EQ(static_cast<int32_t>(ReadLe32(bmp, 22)), -2);
    CHECK_EQ(ReadLe16(bmp, 26), static_cast<uint16_t>(1));
    CHECK_EQ(ReadLe16(bmp, 28), static_cast<uint16_t>(32));
    CHECK_EQ(ReadLe32(bmp, 30), static_cast<uint32_t>(0));
    CHECK_EQ(ReadLe32(bmp, 34), static_cast<uint32_t>(3 * 2 * 4));

    // Pixel (0,0) is the first 4 bytes after the header, stored BGRA.
    CHECK_EQ(bmp[54 + 0], static_cast<uint8_t>(0x33));  // B
    CHECK_EQ(bmp[54 + 1], static_cast<uint8_t>(0x22));  // G
    CHECK_EQ(bmp[54 + 2], static_cast<uint8_t>(0x11));  // R
    CHECK_EQ(bmp[54 + 3], static_cast<uint8_t>(0x44));  // A
    // Pixel (1,0) keeps the fill colour.
    CHECK_EQ(bmp[54 + 4], static_cast<uint8_t>(30));
    CHECK_EQ(bmp[54 + 5], static_cast<uint8_t>(20));
    CHECK_EQ(bmp[54 + 6], static_cast<uint8_t>(10));
    CHECK_EQ(bmp[54 + 7], static_cast<uint8_t>(255));
}

RTSC_TEST(screenshot_empty_path_and_unwritable_path_fail_without_a_file) {
    rtsc::ui::Surface surface(2, 2);
    surface.Fill(1, 2, 3, 255);

    std::string error;
    CHECK(!rtsc::gui::SaveScreenshotBmp(surface, "", error));
    CHECK(!error.empty());

    // A directory that cannot exist: the open must fail and report the path.
    error.clear();
    const std::string bad =
        TempPath("rtsc_shot_missing_dir") + "\\no_such_subdir\\x.bmp";
    CHECK(!rtsc::gui::SaveScreenshotBmp(surface, bad, error));
    CHECK(!error.empty());
    // Nothing was created (not even a zero-length placeholder).
    std::ifstream probe(bad, std::ios::binary);
    CHECK(!probe.good());
}

RTSC_TEST(screenshot_empty_surface_is_rejected) {
    rtsc::ui::Surface surface(0, 0);
    std::string error;
    CHECK(!rtsc::gui::SaveScreenshotBmp(surface, TempPath("rtsc_shot_empty.bmp"),
                                        error));
    CHECK(!error.empty());
}

int main() { return ::rtsc::test::run_all("rtsc_screenshot_tests"); }
