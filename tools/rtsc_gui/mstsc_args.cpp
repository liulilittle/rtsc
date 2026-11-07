// mstsc-compatible command-line parsing helpers.

#include "mstsc_args.h"

#include <cstddef>

namespace rtsc::gui {
namespace {

bool HostHasForbiddenByte(const std::string& host) {
    for (char c : host) {
        // CR/LF would smuggle a header break; NUL and space are never valid in
        // a host and would be rejected by the connect path anyway.
        if (c == '\r' || c == '\n' || c == '\0' || c == ' ') return true;
    }
    return false;
}

bool ParsePort(const std::string& value, uint16_t& out) {
    if (value.empty() || value.size() > 5) return false;
    uint32_t port = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        port = port * 10 + static_cast<uint32_t>(c - '0');
    }
    if (port == 0 || port > 65535) return false;
    out = static_cast<uint16_t>(port);
    return true;
}

}  // namespace

CliSpecial ClassifyCliSpecial(const std::string& arg) {
    if (arg == "--help" || arg == "-h" || arg == "/?") {
        return CliSpecial::kHelp;
    }
    if (arg == "--version" || arg == "-V") {
        return CliSpecial::kVersion;
    }
    return CliSpecial::kNone;
}

bool ParseMstscEndpoint(const std::string& value, MstscEndpoint& out) {
    if (value.empty()) return false;

    std::string host;
    std::string port_text;
    if (value.front() == '[') {
        const size_t close = value.find(']');
        if (close == std::string::npos || close == 1) return false;
        host = value.substr(1, close - 1);
        const std::string rest = value.substr(close + 1);
        if (!rest.empty()) {
            if (rest.front() != ':' || rest.size() == 1) return false;
            port_text = rest.substr(1);
        }
    } else {
        size_t colon_count = 0;
        for (char c : value) {
            if (c == ':') ++colon_count;
        }
        if (colon_count == 1) {
            const size_t colon = value.find(':');
            host = value.substr(0, colon);
            port_text = value.substr(colon + 1);
            if (port_text.empty()) return false;
        } else {
            // Zero colons: host only. Two or more: a bare IPv6 literal.
            host = value;
        }
    }

    if (host.empty() || HostHasForbiddenByte(host)) return false;

    MstscEndpoint endpoint;
    endpoint.host = host;
    if (!port_text.empty() && !ParsePort(port_text, endpoint.port)) {
        return false;
    }
    out = endpoint;
    return true;
}

bool ParseMstscDimension(const std::string& value, uint16_t& out) {
    if (value.empty() || value.size() > 5) return false;
    uint32_t v = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<uint32_t>(c - '0');
    }
    if (v == 0 || v > 65535) return false;
    out = static_cast<uint16_t>(v);
    return true;
}

bool ResolveEndpoint(const std::string& explicit_host, uint16_t explicit_port,
                     const std::string& rdp_full_address,
                     MstscEndpoint& out) {
    if (!explicit_host.empty()) {
        out.host = explicit_host;
        out.port = explicit_port != 0 ? explicit_port : 3389;
        return true;
    }
    if (rdp_full_address.empty()) return false;
    return ParseMstscEndpoint(rdp_full_address, out);
}

std::string FormatFullAddress(const std::string& host, uint16_t port) {
    std::string out;
    const bool already_bracketed =
        host.size() >= 2 && host.front() == '[' && host.back() == ']';
    if (!already_bracketed && host.find(':') != std::string::npos) {
        out = "[" + host + "]";
    } else {
        out = host;
    }
    if (port != 3389) {
        out += ":";
        out += std::to_string(port);
    }
    return out;
}

std::vector<std::string> BuildStaticChannelNames(bool rail_mode,
                                                 bool dynamic_channels,
                                                 bool clipboard_redirect,
                                                 bool audio_redirect) {
    std::vector<std::string> channels = {"rdpdr"};
    if (clipboard_redirect) channels.push_back("cliprdr");
    if (audio_redirect) channels.push_back("rdpsnd");
    if (rail_mode) channels.push_back("rail");
    if (dynamic_channels) channels.push_back("drdynvc");
    return channels;
}

}  // namespace rtsc::gui
