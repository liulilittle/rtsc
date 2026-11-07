// RDP connection file (.rdp) settings codec.
//
// The format is the de-facto INI-like text mstsc reads and writes: one
// `key:type:value` line per entry, where the type is `s` (string) or `i`
// (integer/boolean). Keys are compared case-insensitively and may contain
// spaces ("full address", "screen mode id").
//
// Reference: "Supported RDP properties" (Microsoft Learn, rdp-files):
// https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/rdp-files
//
// This module only translates text <-> settings. It does not touch the
// network, the registry or the credential store.

#pragma once

#include <cstdint>
#include <string>

namespace rtsc::config {

struct RdpFileSettings {
    // "host" or "host:port" (the caller splits it; IPv6 literals keep their
    // brackets).
    std::string full_address;
    std::string username;
    std::string domain;
    std::string gateway_hostname;
    // drivestoredirect: empty = no drives, "*" = all, or "C:\;E:\;".
    std::string drive_redirect;

    // 1 = windowed, 2 = full screen.
    int screen_mode_id = 2;
    // 0 = unset (match the local device); otherwise 200..8192.
    int desktop_width = 0;
    int desktop_height = 0;
    int use_multimon = 0;
    int smart_sizing = 0;
    int redirect_clipboard = 0;
    // 0 = local, 1 = remote, 2 = none.
    int audiomode = 0;
    // 0..3, see "authentication level".
    int authentication_level = 3;
    int enable_credssp = 1;
    int redirect_smartcards = 1;
    // redirectcomports: 1 = share every local serial port.
    int redirect_comports = 0;
    // redirectprinters: 1 = share every local printer queue.
    int redirect_printers = 0;
    // 0..3, see "keyboardhook".
    int keyboard_hook = 2;
};

// Parses the file text. Unknown keys and malformed lines are ignored; a later
// duplicate key wins (mstsc behavior). Integers outside the documented range
// are ignored, so the default is kept instead of a surprising clamped value.
RdpFileSettings ParseRdpFile(const std::string& text);

// Writes the settings with CRLF line endings. Returns an empty string when a
// string value contains CR, LF or NUL: such a value would inject extra lines
// into the file.
std::string WriteRdpFile(const RdpFileSettings& settings);

// Builds the .rdp settings for the current session. `full_address` is already
// formatted (see FormatFullAddress in the GUI). The booleans map to the
// documented integer properties: multimon -> use multimon, fit -> smart
// sizing, fullscreen -> screen mode id 2 (windowed is 1), clipboard ->
// redirectclipboard, comports -> redirectcomports, printers ->
// redirectprinters.
RdpFileSettings BuildSessionRdpFile(const std::string& full_address,
                                    const std::string& username,
                                    const std::string& domain,
                                    uint16_t width, uint16_t height,
                                    bool multimon, bool fit, bool fullscreen,
                                    bool clipboard, int audiomode,
                                    bool comports = false,
                                    bool printers = false);

}  // namespace rtsc::config
