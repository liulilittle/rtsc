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

    return "\"ok\":false,\"error\":\"unknown op: " + JsonEscape(op) + "\"";
}

bool CommandRequestsSurface(const std::string& json_body) {
    std::string op;
    return FieldValue(json_body, "op", op) && op == "surface";
}

}  // namespace rtsc::debug
