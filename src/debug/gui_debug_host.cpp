// GUI-side debug command handler. See the header for why it is separate from
// main() and what the ops answer.

#include "rtsc/debug/gui_debug_host.h"

#include <cstdio>
#include <string>

namespace rtsc::debug {
namespace {

// Copies a JSON string value, escaping the two characters that would otherwise
// break the reply. Host names are operator-supplied, so "a\"b" must not be able
// to truncate the object.
std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
    return out;
}

// Extracts a flat string field: "op":"value". The channel's commands are small
// objects of scalar fields, so this is enough and avoids a JSON dependency.
bool FieldValue(const std::string& body, const char* name, std::string& out) {
    const std::string key = std::string("\"") + name + "\"";
    size_t pos = body.find(key);
    if (pos == std::string::npos) return false;
    pos = body.find(':', pos + key.size());
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < body.size() &&
           (body[pos] == ' ' || body[pos] == '\t' || body[pos] == '\n' ||
            body[pos] == '\r')) {
        ++pos;
    }
    if (pos >= body.size() || body[pos] != '"') return false;
    ++pos;
    out.clear();
    bool escaped = false;
    for (; pos < body.size(); ++pos) {
        const char c = body[pos];
        if (escaped) {
            out += c;
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '"') return true;
        out += c;
    }
    return false;  // unterminated string
}

std::string Number(double v) {
    char buf[64];
    // %g keeps 1.25 as 1.25 and drops a trailing .0 for whole numbers.
    std::snprintf(buf, sizeof(buf), "%g", v);
    return buf;
}

std::string Bool(bool b) { return b ? "true" : "false"; }

}  // namespace

std::string ExecuteGuiCommand(const DebugSnapshot& s, const std::string& json_body) {
    std::string op;
    if (!FieldValue(json_body, "op", op) || op.empty()) {
        return "\"ok\":false,\"error\":\"missing op\"";
    }

    if (op == "ping") {
        return "\"ok\":true,\"pong\":true";
    }

    if (op == "state") {
        std::string r = "\"ok\":true";
        r += ",\"desktop_width\":" + std::to_string(s.desktop_width);
        r += ",\"desktop_height\":" + std::to_string(s.desktop_height);
        r += ",\"view_width\":" + std::to_string(s.view_width);
        r += ",\"view_height\":" + std::to_string(s.view_height);
        r += ",\"zoom\":" + Number(s.zoom);
        r += ",\"fit\":" + Bool(s.fit);
        r += ",\"frames_rendered\":" + std::to_string(s.frames_rendered);
        r += ",\"loop_iterations\":" + std::to_string(s.loop_iterations);
        r += ",\"input_events_sent\":" + std::to_string(s.input_events_sent);
        r += ",\"session_active\":" + Bool(s.session_active);
        r += ",\"host\":\"" + JsonEscape(s.host) + "\"";
        r += ",\"backend\":\"" + JsonEscape(s.backend) + "\"";
        return r;
    }

    if (op == "dirty") {
        const bool empty = s.dirty_right <= s.dirty_left ||
                           s.dirty_bottom <= s.dirty_top;
        std::string r = "\"ok\":true";
        r += ",\"left\":" + std::to_string(s.dirty_left);
        r += ",\"top\":" + std::to_string(s.dirty_top);
        r += ",\"right\":" + std::to_string(s.dirty_right);
        r += ",\"bottom\":" + std::to_string(s.dirty_bottom);
        r += ",\"empty\":" + Bool(empty);
        return r;
    }

    if (op == "surface") {
        std::string r = "\"ok\":true";
        r += ",\"non_black_pixels\":" + std::to_string(s.non_black_pixels);
        r += ",\"distinct_colours\":" + std::to_string(s.distinct_colours);
        r += ",\"total_pixels\":" + std::to_string(s.total_pixels);
        return r;
    }

    if (op == "screenshot") {
        // The library never writes the file itself (no platform API); it only
        // reports what main() should write. An empty path means "skip".
        if (s.screenshot_path.empty()) {
            return "\"ok\":true,\"skipped\":true";
        }
        std::string r = "\"ok\":true";
        r += ",\"path\":\"" + JsonEscape(s.screenshot_path) + "\"";
        return r;
    }

    if (op == "frames") {
        return FormatFrameSamples(s.frame_samples);
    }

    return "\"ok\":false,\"error\":\"unknown op: " + JsonEscape(op) + "\"";
}

bool CommandRequestsSurface(const std::string& json_body) {
    std::string op;
    return FieldValue(json_body, "op", op) && op == "surface";
}

bool CommandRequestsScreenshot(const std::string& json_body) {
    std::string op;
    return FieldValue(json_body, "op", op) && op == "screenshot";
}

bool CommandRequestsFrames(const std::string& json_body) {
    std::string op;
    return FieldValue(json_body, "op", op) && op == "frames";
}

std::string FormatFrameSamples(const std::vector<unsigned>& samples) {
    std::string r = "\"ok\":true,\"frames\":[";
    for (size_t i = 0; i < samples.size(); ++i) {
        if (i != 0) r += ",";
        r += std::to_string(samples[i]);
    }
    r += "]";
    return r;
}

bool ScreenshotPath(const std::string& json_body, std::string& path) {
    return FieldValue(json_body, "path", path);
}

std::string EncodeBmp32(const uint8_t* rgba, uint32_t width, uint32_t height) {
    if (width == 0 || height == 0 || rgba == nullptr) return std::string();
    const uint32_t row_bytes = width * 4;
    const uint32_t pixel_bytes = row_bytes * height;
    const uint32_t file_size = 14 + 40 + pixel_bytes;

    std::string bmp;
    bmp.reserve(file_size);

    // BITMAPFILEHEADER (14 bytes)
    bmp += 'B';
    bmp += 'M';
    // bfSize
    bmp += static_cast<char>(file_size & 0xFF);
    bmp += static_cast<char>((file_size >> 8) & 0xFF);
    bmp += static_cast<char>((file_size >> 16) & 0xFF);
    bmp += static_cast<char>((file_size >> 24) & 0xFF);
    // bfReserved1 + bfReserved2 = 0
    bmp.append(4, '\0');
    // bfOffBits = 14 + 40 = 54
    bmp += static_cast<char>(54 & 0xFF);
    bmp += static_cast<char>((54 >> 8) & 0xFF);
    bmp += static_cast<char>((54 >> 16) & 0xFF);
    bmp += static_cast<char>((54 >> 24) & 0xFF);

    // BITMAPINFOHEADER (40 bytes)
    // biSize = 40
    bmp += static_cast<char>(40 & 0xFF);
    bmp += static_cast<char>((40 >> 8) & 0xFF);
    bmp += static_cast<char>((40 >> 16) & 0xFF);
    bmp += static_cast<char>((40 >> 24) & 0xFF);
    // biWidth (signed)
    int32_t w = static_cast<int32_t>(width);
    bmp += static_cast<char>(w & 0xFF);
    bmp += static_cast<char>((w >> 8) & 0xFF);
    bmp += static_cast<char>((w >> 16) & 0xFF);
    bmp += static_cast<char>((w >> 24) & 0xFF);
    // biHeight = -height (top-down)
    int32_t h = -static_cast<int32_t>(height);
    bmp += static_cast<char>(h & 0xFF);
    bmp += static_cast<char>((h >> 8) & 0xFF);
    bmp += static_cast<char>((h >> 16) & 0xFF);
    bmp += static_cast<char>((h >> 24) & 0xFF);
    // biPlanes = 1
    bmp += static_cast<char>(1);
    bmp += static_cast<char>(0);
    // biBitCount = 32
    bmp += static_cast<char>(32);
    bmp += static_cast<char>(0);
    // biCompression = BI_RGB (0)
    bmp.append(4, '\0');
    // biSizeImage = pixel_bytes
    bmp += static_cast<char>(pixel_bytes & 0xFF);
    bmp += static_cast<char>((pixel_bytes >> 8) & 0xFF);
    bmp += static_cast<char>((pixel_bytes >> 16) & 0xFF);
    bmp += static_cast<char>((pixel_bytes >> 24) & 0xFF);
    // biXPelsPerMeter = 0
    bmp.append(4, '\0');
    // biYPelsPerMeter = 0
    bmp.append(4, '\0');
    // biClrUsed = 0
    bmp.append(4, '\0');
    // biClrImportant = 0
    bmp.append(4, '\0');

    // Pixel data: RGBA -> BGRA, top-down (row 0 first)
    for (uint32_t y = 0; y < height; ++y) {
        const uint8_t* row = rgba + y * row_bytes;
        for (uint32_t x = 0; x < width; ++x) {
            // RGBA in source -> BGRA in BMP
            bmp += static_cast<char>(row[2]); // B
            bmp += static_cast<char>(row[1]); // G
            bmp += static_cast<char>(row[0]); // R
            bmp += static_cast<char>(row[3]); // A
            row += 4;
        }
    }
    return bmp;
}

}  // namespace rtsc::debug
