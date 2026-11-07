// RDP connection file (.rdp) settings codec.

#include "rtsc/config/rdp_file.h"

#include <cctype>
#include <cstdlib>
#include <string>
#include <vector>

namespace rtsc::config {
namespace {

std::string ToLower(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(
            std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

// Splits `key:type:value` into its three fields. Keys may contain spaces, so
// the first ':' ends the key and the second ends the type; the rest is the
// value (which may itself contain ':').
bool SplitLine(const std::string& line, std::string& key, char& type,
               std::string& value) {
    const size_t first = line.find(':');
    if (first == std::string::npos) return false;
    const size_t second = line.find(':', first + 1);
    if (second == std::string::npos) return false;
    if (second != first + 2) return false;  // exactly one type character
    key = line.substr(0, first);
    type = line[first + 1];
    value = line.substr(second + 1);
    return !key.empty();
}

bool ParseInt(const std::string& text, long& out) {
    if (text.empty()) return false;
    char* end = nullptr;
    const long value = std::strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != '\0') return false;
    out = value;
    return true;
}

// Applies an integer setting only when it is inside [low, high]. Out-of-range
// values are ignored so the default stays in effect.
void SetInt(const std::string& value, long low, long high, int& field) {
    long parsed = 0;
    if (!ParseInt(value, parsed)) return;
    if (parsed < low || parsed > high) return;
    field = static_cast<int>(parsed);
}

bool HasLineBreak(const std::string& s) {
    for (const char c : s) {
        if (c == '\r' || c == '\n' || c == '\0') return true;
    }
    return false;
}

}  // namespace

RdpFileSettings ParseRdpFile(const std::string& text) {
    RdpFileSettings out;
    size_t start = 0;
    while (start <= text.size()) {
        const size_t end = text.find('\n', start);
        std::string line = text.substr(
            start, end == std::string::npos ? std::string::npos : end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();

        std::string key;
        char type = 0;
        std::string value;
        if (SplitLine(line, key, type, value)) {
            const std::string name = ToLower(key);
            if (type == 's') {
                if (name == "full address") out.full_address = value;
                else if (name == "username") out.username = value;
                else if (name == "domain") out.domain = value;
                else if (name == "gatewayhostname") out.gateway_hostname = value;
                else if (name == "drivestoredirect") out.drive_redirect = value;
            } else if (type == 'i') {
                if (name == "screen mode id") {
                    SetInt(value, 1, 2, out.screen_mode_id);
                } else if (name == "desktopwidth") {
                    SetInt(value, 200, 8192, out.desktop_width);
                } else if (name == "desktopheight") {
                    SetInt(value, 200, 8192, out.desktop_height);
                } else if (name == "use multimon") {
                    SetInt(value, 0, 1, out.use_multimon);
                } else if (name == "smart sizing") {
                    SetInt(value, 0, 1, out.smart_sizing);
                } else if (name == "redirectclipboard") {
                    SetInt(value, 0, 1, out.redirect_clipboard);
                } else if (name == "redirectcomports") {
                    SetInt(value, 0, 1, out.redirect_comports);
                } else if (name == "redirectprinters") {
                    SetInt(value, 0, 1, out.redirect_printers);
                } else if (name == "audiomode") {
                    SetInt(value, 0, 2, out.audiomode);
                } else if (name == "authentication level") {
                    SetInt(value, 0, 3, out.authentication_level);
                } else if (name == "enablecredsspsupport") {
                    SetInt(value, 0, 1, out.enable_credssp);
                } else if (name == "redirectsmartcards") {
                    SetInt(value, 0, 1, out.redirect_smartcards);
                } else if (name == "keyboardhook") {
                    SetInt(value, 0, 3, out.keyboard_hook);
                }
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return out;
}

std::string WriteRdpFile(const RdpFileSettings& settings) {
    // A string value with a line break would add arbitrary keys to the file.
    const std::string* strings[] = {
        &settings.full_address, &settings.username, &settings.domain,
        &settings.gateway_hostname, &settings.drive_redirect};
    for (const std::string* value : strings) {
        if (HasLineBreak(*value)) return {};
    }

    std::string out;
    const auto write_s = [&out](const char* key, const std::string& value) {
        out += key;
        out += ":s:";
        out += value;
        out += "\r\n";
    };
    const auto write_i = [&out](const char* key, int value) {
        out += key;
        out += ":i:";
        out += std::to_string(value);
        out += "\r\n";
    };

    write_s("full address", settings.full_address);
    write_s("username", settings.username);
    write_s("domain", settings.domain);
    write_s("gatewayhostname", settings.gateway_hostname);
    write_i("screen mode id", settings.screen_mode_id);
    if (settings.desktop_width > 0) {
        write_i("desktopwidth", settings.desktop_width);
    }
    if (settings.desktop_height > 0) {
        write_i("desktopheight", settings.desktop_height);
    }
    write_i("use multimon", settings.use_multimon);
    write_i("smart sizing", settings.smart_sizing);
    write_i("redirectclipboard", settings.redirect_clipboard);
    write_i("redirectcomports", settings.redirect_comports);
    write_i("redirectprinters", settings.redirect_printers);
    write_i("audiomode", settings.audiomode);
    write_i("authentication level", settings.authentication_level);
    write_i("enablecredsspsupport", settings.enable_credssp);
    write_i("redirectsmartcards", settings.redirect_smartcards);
    write_i("keyboardhook", settings.keyboard_hook);
    if (!settings.drive_redirect.empty()) {
        write_s("drivestoredirect", settings.drive_redirect);
    }
    return out;
}

RdpFileSettings BuildSessionRdpFile(const std::string& full_address,
                                    const std::string& username,
                                    const std::string& domain,
                                    uint16_t width, uint16_t height,
                                    bool multimon, bool fit, bool fullscreen,
                                    bool clipboard, int audiomode,
                                    bool comports, bool printers) {
    RdpFileSettings out;
    out.full_address = full_address;
    out.username = username;
    out.domain = domain;
    out.desktop_width = width;
    out.desktop_height = height;
    out.use_multimon = multimon ? 1 : 0;
    out.smart_sizing = fit ? 1 : 0;
    out.screen_mode_id = fullscreen ? 2 : 1;
    out.redirect_clipboard = clipboard ? 1 : 0;
    out.audiomode = audiomode;
    out.redirect_comports = comports ? 1 : 0;
    out.redirect_printers = printers ? 1 : 0;
    return out;
}

}  // namespace rtsc::config
