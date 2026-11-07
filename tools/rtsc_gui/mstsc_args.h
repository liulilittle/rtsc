// mstsc-compatible command-line parsing helpers.
//
// These are pure functions so the compatibility rules can be unit tested
// without starting a session: the GUI itself is not linkable in tests.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rtsc::gui {

// Switches that must be handled before any connection attempt.
enum class CliSpecial { kNone, kHelp, kVersion };

// Classifies --help/-h//? and --version/-V. Exact matches only: /h:1080 and
// /v:host must not be mistaken for help/version.
CliSpecial ClassifyCliSpecial(const std::string& arg);

struct MstscEndpoint {
    std::string host;
    uint16_t port = 3389;
};

// Parses the value of "/v:". Accepts "host", "host:port" and "[ipv6]:port".
// A bare IPv6 literal (two or more colons, no brackets) is treated as a host
// with the default port. Returns false for an empty host, a port outside
// 1..65535, trailing junk, or CR/LF/NUL/space in the host.
bool ParseMstscEndpoint(const std::string& value, MstscEndpoint& out);

// Parses the value of "/w:" or "/h:": decimal digits only, 1..65535.
bool ParseMstscDimension(const std::string& value, uint16_t& out);

// Resolves the connection endpoint with the mstsc precedence: an explicit
// host (positional or /v:) wins, then the .rdp "full address", then nothing.
// `explicit_port == 0` means "not given" and falls back to 3389. Returns false
// when no source yields a valid host.
bool ResolveEndpoint(const std::string& explicit_host, uint16_t explicit_port,
                     const std::string& rdp_full_address,
                     MstscEndpoint& out);

// Formats an endpoint as an .rdp "full address": a bare IPv6 host is
// bracketed and the default port (3389) is omitted.
std::string FormatFullAddress(const std::string& host, uint16_t port);

// Builds the static virtual channel name list for a desktop session:
// "rdpdr" always, "cliprdr" unless clipboard redirection is off, "rdpsnd"
// unless audio redirection is off, "rail" only in RemoteApp mode, "drdynvc"
// when USB or dynamic display needs it. Order is stable.
std::vector<std::string> BuildStaticChannelNames(bool rail_mode,
                                                 bool dynamic_channels,
                                                 bool clipboard_redirect,
                                                 bool audio_redirect);

}  // namespace rtsc::gui
