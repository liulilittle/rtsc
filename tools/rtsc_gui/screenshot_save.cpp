#include "screenshot_save.h"

#include <cstdio>
#include <fstream>

#include "rtsc/debug/gui_debug_host.h"

namespace rtsc::gui {

std::string DefaultScreenshotName(std::time_t now) {
    std::tm utc{};
#if defined(_MSC_VER)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    char stamp[32] = {};
    std::snprintf(stamp, sizeof(stamp), "%04d%02d%02d-%02d%02d%02d",
                  utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday, utc.tm_hour,
                  utc.tm_min, utc.tm_sec);
    return std::string("rtsc-screenshot-") + stamp + ".bmp";
}

bool SaveScreenshotBmp(const rtsc::ui::Surface& surface,
                       const std::string& path, std::string& error) {
    if (path.empty()) {
        error = "empty screenshot path";
        return false;
    }
    if (surface.width() == 0 || surface.height() == 0) {
        error = "empty surface";
        return false;
    }
    const std::string bmp = rtsc::debug::EncodeBmp32(
        surface.data(), surface.width(), surface.height());
    if (bmp.empty()) {
        error = "BMP encoding failed";
        return false;
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot open " + path;
        return false;
    }
    out.write(bmp.data(), static_cast<std::streamsize>(bmp.size()));
    out.close();
    if (!out) {
        error = "cannot write " + path;
        std::remove(path.c_str());
        return false;
    }
    return true;
}

}  // namespace rtsc::gui
