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

// Parses exactly four hex digits at `pos`. Used by the JSON \uXXXX decoder.
bool Hex4(const std::string& body, size_t pos, uint16_t& out) {
    if (pos + 4 > body.size()) return false;
    uint16_t v = 0;
    for (size_t i = 0; i < 4; ++i) {
        const char c = body[pos + i];
        int d = 0;
        if (c >= '0' && c <= '9') {
            d = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            d = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            d = c - 'A' + 10;
        } else {
            return false;
        }
        v = static_cast<uint16_t>((v << 4) | d);
    }
    out = v;
    return true;
}

// Appends one code point as UTF-8. The channel's string fields are UTF-8 on the
// wire; decoding \uXXXX to something else would make a JSON-escaped Chinese
// path or text event differ from the raw-UTF-8 form of the same request.
void AppendUtf8(uint32_t cp, std::string& out) {
    if (cp <= 0x7F) {
        out += static_cast<char>(cp);
    } else if (cp <= 0x7FF) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp <= 0xFFFF) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
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
    for (; pos < body.size(); ++pos) {
        const char c = body[pos];
        if (c == '"') return true;
        if (c != '\\') {
            out += c;
            continue;
        }
        if (++pos >= body.size()) return false;
        switch (body[pos]) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                uint16_t unit = 0;
                if (!Hex4(body, pos + 1, unit)) return false;
                pos += 4;
                uint32_t cp = unit;
                if (unit >= 0xD800 && unit <= 0xDBFF) {
                    // A high surrogate must be followed by a low surrogate;
                    // a lone one cannot be represented as UTF-8.
                    if (pos + 6 >= body.size() || body[pos + 1] != '\\' ||
                        body[pos + 2] != 'u') {
                        return false;
                    }
                    uint16_t low = 0;
                    if (!Hex4(body, pos + 3, low) || low < 0xDC00 ||
                        low > 0xDFFF) {
                        return false;
                    }
                    cp = 0x10000 + ((static_cast<uint32_t>(unit) - 0xD800) << 10) +
                         (static_cast<uint32_t>(low) - 0xDC00);
                    pos += 6;
                } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
                    return false;
                }
                AppendUtf8(cp, out);
                break;
            }
            default:
                return false;
        }
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

// Defined with the other scalar field readers below; ResizeRequest needs it
// before that point because ExecuteGuiCommand calls it.
bool IntField(const std::string& body, const char* name, int& out);

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

    if (op == "input") {
        if (s.input_error.empty()) {
            return FormatInputReply(s.input_injected);
        }
        return "\"ok\":false,\"error\":\"input: " + JsonEscape(s.input_error) + "\"";
    }

    if (op == "resize") {
        int width = 0;
        int height = 0;
        std::string resize_error;
        if (!ResizeRequest(json_body, width, height, resize_error)) {
            return "\"ok\":false,\"error\":\"resize: " + JsonEscape(resize_error) + "\"";
        }
        // main() applies the resize before answering; the reply echoes the
        // requested size so an operator can confirm it reached the handler.
        return FormatResizeReply(width, height);
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

bool CommandRequestsInput(const std::string& json_body) {
    std::string op;
    return FieldValue(json_body, "op", op) && op == "input";
}

bool CommandRequestsResize(const std::string& json_body) {
    std::string op;
    return FieldValue(json_body, "op", op) && op == "resize";
}

bool ResizeRequest(const std::string& json_body, int& width, int& height,
                   std::string& error) {
    error.clear();
    if (!IntField(json_body, "width", width) || width <= 0 || width > 65535) {
        error = "width must be 1..65535";
        return false;
    }
    if (!IntField(json_body, "height", height) || height <= 0 || height > 65535) {
        error = "height must be 1..65535";
        return false;
    }
    return true;
}

std::string FormatResizeReply(int width, int height) {
    return "\"ok\":true,\"width\":" + std::to_string(width) +
           ",\"height\":" + std::to_string(height);
}

std::string FormatInputReply(int injected) {
    return "\"ok\":true,\"injected\":" + std::to_string(injected);
}

namespace {

// Numeric field: finds "name": <integer> in the object, tolerating spaces.
bool IntField(const std::string& body, const char* name, int& out) {
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
    if (pos >= body.size() || (body[pos] != '-' && (body[pos] < '0' || body[pos] > '9'))) {
        return false;
    }
    size_t end = pos;
    if (body[end] == '-') ++end;
    while (end < body.size() && body[end] >= '0' && body[end] <= '9') ++end;
    out = std::stoi(body.substr(pos, end - pos));
    return true;
}

// Boolean field: finds "name": true|false in the object, tolerating spaces.
bool BoolField(const std::string& body, const char* name, bool& out) {
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
    if (body.compare(pos, 4, "true") == 0) {
        out = true;
        return true;
    }
    if (body.compare(pos, 5, "false") == 0) {
        out = false;
        return true;
    }
    return false;
}

// Splits the body into the raw substrings of the objects inside "events":[...]
// so each call site only sees one event. The events contain no nested objects,
// so top-level braces are enough.
std::vector<std::string> SplitEvents(const std::string& body) {
    std::vector<std::string> out;
    size_t pos = body.find("\"events\"");
    if (pos == std::string::npos) return out;
    pos = body.find('[', pos);
    if (pos == std::string::npos) return out;
    ++pos;
    for (size_t i = pos; i < body.size(); ++i) {
        if (body[i] == '{') {
            size_t depth = 0;
            for (size_t j = i; j < body.size(); ++j) {
                if (body[j] == '{') ++depth;
                if (body[j] == '}') --depth;
                if (depth == 0) {
                    out.push_back(body.substr(i, j - i + 1));
                    i = j;
                    break;
                }
            }
        }
    }
    return out;
}

// Decodes raw UTF-8 (the form an HTTP client sends when it does not use \u
// escapes) into UTF-16 code units, the unit TS_FP_UNICODE_KEYBOARD_EVENT
// carries. Returns false on malformed or overlong input; a text event that
// silently dropped a bad byte would type a different string than requested.
bool DecodeUtf8ToUtf16(const std::string& text, std::vector<uint16_t>& units,
                       std::string& error) {
    units.clear();
    size_t i = 0;
    while (i < text.size()) {
        const unsigned char b0 = static_cast<unsigned char>(text[i]);
        uint32_t cp = 0;
        size_t len = 0;
        if (b0 < 0x80) {
            cp = b0;
            len = 1;
        } else if (b0 >= 0xC2 && b0 <= 0xDF) {
            cp = b0 & 0x1F;
            len = 2;
        } else if (b0 >= 0xE0 && b0 <= 0xEF) {
            cp = b0 & 0x0F;
            len = 3;
        } else if (b0 >= 0xF0 && b0 <= 0xF4) {
            cp = b0 & 0x07;
            len = 4;
        } else {
            error = "text event with invalid UTF-8";
            return false;
        }
        if (i + len > text.size()) {
            error = "text event with truncated UTF-8";
            return false;
        }
        for (size_t k = 1; k < len; ++k) {
            const unsigned char bk = static_cast<unsigned char>(text[i + k]);
            if ((bk & 0xC0) != 0x80) {
                error = "text event with invalid UTF-8";
                return false;
            }
            cp = (cp << 6) | (bk & 0x3F);
        }
        // Reject overlong encodings, surrogates, and out-of-range values.
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) ||
            (len == 4 && cp < 0x10000) || cp > 0x10FFFF ||
            (cp >= 0xD800 && cp <= 0xDFFF)) {
            error = "text event with invalid UTF-8";
            return false;
        }
        if (cp == 0) {
            error = "text event with NUL code point";
            return false;
        }
        if (cp <= 0xFFFF) {
            units.push_back(static_cast<uint16_t>(cp));
        } else {
            const uint32_t v = cp - 0x10000;
            units.push_back(static_cast<uint16_t>(0xD800 + (v >> 10)));
            units.push_back(static_cast<uint16_t>(0xDC00 + (v & 0x3FF)));
        }
        i += len;
    }
    return true;
}

}  // namespace

bool ParseInputEvents(const std::string& json_body, int desktop_width,
                      int desktop_height,
                      std::vector<InputEventSpec>& out, std::string& error) {
    out.clear();
    error.clear();
    const std::vector<std::string> raw = SplitEvents(json_body);
    if (raw.empty()) {
        error = "no input events";
        return false;
    }
    for (const std::string& element : raw) {
        std::string kind;
        if (!FieldValue(element, "kind", kind) || kind.empty()) {
            error = "input event missing kind";
            return false;
        }
        InputEventSpec spec;
        if (kind == "key") {
            spec.kind = InputEventSpec::Kind::kKey;
            int scancode = 0;
            if (!IntField(element, "scancode", scancode) || scancode == 0) {
                error = "key event with invalid scancode";
                return false;
            }
            spec.scancode = static_cast<uint8_t>(scancode);
            bool down = true;
            if (BoolField(element, "down", down)) spec.release = !down;
            BoolField(element, "extended", spec.extended);
        } else if (kind == "mouseclick") {
            spec.kind = InputEventSpec::Kind::kMouseClick;
            int button = 0;
            if (!IntField(element, "x", spec.x) || !IntField(element, "y", spec.y) ||
                !IntField(element, "button", button) || button == 0) {
                error = "click event with invalid button";
                return false;
            }
            spec.button = static_cast<uint8_t>(button);
            bool down = true;
            if (BoolField(element, "down", down)) spec.down = down;
        } else if (kind == "mousemove") {
            spec.kind = InputEventSpec::Kind::kMouseMove;
            if (!IntField(element, "x", spec.x) || !IntField(element, "y", spec.y)) {
                error = "mousemove event missing coordinates";
                return false;
            }
        } else if (kind == "wheel") {
            spec.kind = InputEventSpec::Kind::kMouseWheel;
            if (!IntField(element, "wheel_delta", spec.wheel_delta)) {
                error = "wheel event missing wheel_delta";
                return false;
            }
            BoolField(element, "horizontal", spec.horizontal);
        } else if (kind == "unicode") {
            spec.kind = InputEventSpec::Kind::kUnicode;
            int code = 0;
            if (!IntField(element, "code", code) || code <= 0 || code > 0xFFFF) {
                error = "unicode event with invalid code";
                return false;
            }
            spec.unicode_code = static_cast<uint16_t>(code);
            bool down = true;
            if (BoolField(element, "down", down)) spec.release = !down;
        } else if (kind == "text") {
            // One "text" element expands to one Unicode event per UTF-16 code
            // unit, so the operator types a string instead of a scancode list.
            std::string text;
            if (!FieldValue(element, "text", text) || text.empty()) {
                error = "text event with empty text";
                return false;
            }
            std::vector<uint16_t> units;
            if (!DecodeUtf8ToUtf16(text, units, error)) return false;
            for (size_t u = 0; u < units.size(); ++u) {
                // A short pause between code units is not modelled here: the
                // wire carries a down/up pair per unit, which is what a typed
                // character is.
                InputEventSpec down;
                down.kind = InputEventSpec::Kind::kUnicode;
                down.unicode_code = units[u];
                down.release = false;
                out.push_back(down);
                InputEventSpec up;
                up.kind = InputEventSpec::Kind::kUnicode;
                up.unicode_code = units[u];
                up.release = true;
                out.push_back(up);
            }
            continue;
        } else {
            error = "unknown input kind: " + kind;
            return false;
        }
        // Bounds check for mouse kinds.
        if (spec.kind == InputEventSpec::Kind::kMouseClick ||
            spec.kind == InputEventSpec::Kind::kMouseMove) {
            if (spec.x < 0 || spec.x >= desktop_width || spec.y < 0 ||
                spec.y >= desktop_height) {
                error = "mouse coordinates outside desktop";
                return false;
            }
        }
        out.push_back(spec);
    }
    return true;
}

bool ToUiInputEvent(const InputEventSpec& spec, rtsc::ui::InputEvent& out) {
    out = rtsc::ui::InputEvent();
    switch (spec.kind) {
        case InputEventSpec::Kind::kKey:
            out.kind = rtsc::ui::InputEvent::Kind::kKey;
            out.scancode = spec.scancode;
            out.key_release = spec.release;
            out.key_extended = spec.extended;
            return true;
        case InputEventSpec::Kind::kMouseMove:
            out.kind = rtsc::ui::InputEvent::Kind::kMouseMove;
            out.x = static_cast<uint16_t>(spec.x);
            out.y = static_cast<uint16_t>(spec.y);
            return true;
        case InputEventSpec::Kind::kMouseClick:
            // The channel calls it a "click"; the front-end calls the same
            // thing a button event, and the down flag decides press vs release.
            out.kind = rtsc::ui::InputEvent::Kind::kMouseButton;
            out.x = static_cast<uint16_t>(spec.x);
            out.y = static_cast<uint16_t>(spec.y);
            out.button = spec.button;
            out.button_down = spec.down;
            return true;
        case InputEventSpec::Kind::kMouseWheel:
            out.kind = rtsc::ui::InputEvent::Kind::kMouseWheel;
            out.wheel_delta = static_cast<int16_t>(spec.wheel_delta);
            out.horizontal = spec.horizontal;
            return true;
        case InputEventSpec::Kind::kUnicode:
            out.kind = rtsc::ui::InputEvent::Kind::kUnicode;
            out.unicode_code = spec.unicode_code;
            out.key_release = spec.release;
            return true;
    }
    return false;
}

bool ToUiInputEvents(const std::vector<InputEventSpec>& specs,
                     std::vector<rtsc::ui::InputEvent>& out) {
    out.clear();
    out.reserve(specs.size());
    for (const InputEventSpec& spec : specs) {
        rtsc::ui::InputEvent ev;
        if (!ToUiInputEvent(spec, ev)) return false;
        out.push_back(ev);
    }
    return true;
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
