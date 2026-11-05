// rtsc_gui: a runnable RDP client that ties the connection driver, the
// graphics pipeline, and a window backend together.
//
// Usage:
//   rtsc_gui <host> [port] [domain] [user] [password] [width] [height] [backend]
//
// The backend is one of "headless" (default when no display is available),
// "win32", "x11", or "wayland"; an empty value asks for the platform default.
// The tool connects, then loops: pump the socket, composite the surface into
// the window, present, and forward window input as Fast-Path input PDUs.

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "connection_info_dialog_win32.h"
#include "help_dialog_win32.h"
#include "rtsc/debug/gui_debug_host.h"
#include "rtsc/debug/pending_command_queue.h"
#include "rtsc/debug/ui_debug_server.h"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <unordered_set>
#include "rtsc/audio/audio_sink.h"
#include "rtsc/channel/cliprdr_client.h"
#include "rtsc/channel/drdynvc_client.h"
#include "rtsc/channel/rdpdr_client.h"
#include "rtsc/channel/rdpsnd_client.h"
#include "rtsc/channel/rdpusb_client.h"
#include "rtsc/clipboard/clipboard.h"
#include "rtsc/clipboard/drop_files.h"
#include "rtsc/client/client.h"
#include "rtsc/client/session_info.h"
#include "rtsc/client/version.h"
#include "rtsc/client/view.h"
#include "rtsc/net/gateway_transport.h"
#include "rtsc/net/transport.h"
#include "rtsc/net/tls.h"
#include "rtsc/proto/connect_machine.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/rdpdr/drive_enum.h"
#include "rtsc/rdpdr/file_system.h"
#include "rtsc/security/connection_driver.h"
#include "rtsc/smartcard/backend.h"
#include "rtsc/ui/clipboard_bind.h"
#include "rtsc/ui/window.h"
#include "rtsc/ui/surface.h"
#include "rtsc/usb/usb_device.h"
#include "rtsc/usb/usb_gate.h"
#include "rtsc/util/crash_guard.h"
#if defined(_WIN32)
#include "rtsc/usb/usb_win32.h"
#endif

namespace {

constexpr const char* kVersion = "rtsc_gui " RTSC_VERSION_STRING;

// Static virtual channel ids assigned by the server in the Server Network Data
// block ([MS-RDPBCGR] 2.2.1.4.4) and parsed by the connection driver. Captured
// from the real peer (192.168.1.7): rdpdr=1004, cliprdr=1005, rdpsnd=1006.
// They are hardcoded here because the tool does not parse Server Network Data
// itself. The full per-channel protocols are a follow-up task, so the handlers
// only record that a chunk arrived.
constexpr uint16_t kChannelRdpdr = 1004;
constexpr uint16_t kChannelCliprdr = 1005;
constexpr uint16_t kChannelRdpsnd = 1006;

// RAIL ([MS-RDPERP]): the client's Handshake build number and the ClientStatus
// feature flags. Zero flags claim no optional RAIL features; the handler still
// parses every inbound order.
constexpr uint32_t kRailBuildNumber = 0x00001DB0;
constexpr uint32_t kRailClientFlags = 0;

// RTSC_REDIRECT_USB gate, mirroring the RTSC_REDIRECT_DRIVES opt-in policy
// (drive_enum_win32.cpp): an unset/empty spec redirects nothing, "ALL" shares
// every enumerated device, and a comma-separated "VID:PID" list is a
// whitelist. An invalid token selects nothing - it never widens the set.
#if defined(_WIN32)
bool UsbSpecAllows(const char* spec, const rtsc::usb::UsbDeviceInfo& info) {
    if (spec == nullptr || spec[0] == '\0') return false;
    std::string whole(spec);
    const auto trim = [](std::string s) {
        const size_t b = s.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) return std::string{};
        const size_t e = s.find_last_not_of(" \t\r\n");
        return s.substr(b, e - b + 1);
    };
    whole = trim(whole);
    for (char& c : whole) {
        c = static_cast<char>(
            std::toupper(static_cast<unsigned char>(c)));
    }
    if (whole == "ALL") return true;

    bool matched = false;
    size_t start = 0;
    while (true) {
        const size_t comma = whole.find(',', start);
        const std::string token = trim(whole.substr(
            start, comma == std::string::npos ? std::string::npos
                                              : comma - start));
        const size_t colon = token.find(':');
        if (colon == std::string::npos || colon == 0 ||
            token.size() < colon + 2) {
            return false;
        }
        const std::string vs = token.substr(0, colon);
        const std::string ps = token.substr(colon + 1);
        char* vid_end = nullptr;
        char* pid_end = nullptr;
        const unsigned long vid = std::strtoul(vs.c_str(), &vid_end, 16);
        const unsigned long pid = std::strtoul(ps.c_str(), &pid_end, 16);
        const bool vid_ok = vid_end != vs.c_str() && *vid_end == '\0' &&
                            vid <= 0xFFFFul;
        const bool pid_ok = pid_end != ps.c_str() && *pid_end == '\0' &&
                            pid <= 0xFFFFul;
        if (!vid_ok || !pid_ok) return false;
        if (static_cast<uint16_t>(vid) == info.vendor_id &&
            static_cast<uint16_t>(pid) == info.product_id) {
            matched = true;
        }
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return matched;
}

// True when the RTSC_REDIRECT_USB spec asks for every device (after the same
// trim + uppercase normalisation UsbSpecAllows applies), so the privacy notice
// can advertise the "ALL" scope without contradicting the effective filter.
bool UsbSpecIsAll(const char* spec) {
    if (spec == nullptr || spec[0] == '\0') return false;
    std::string whole(spec);
    const auto trim = [](std::string s) {
        const size_t b = s.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) return std::string{};
        const size_t e = s.find_last_not_of(" \t\r\n");
        return s.substr(b, e - b + 1);
    };
    whole = trim(whole);
    for (char& c : whole) {
        c = static_cast<char>(
            std::toupper(static_cast<unsigned char>(c)));
    }
    return whole == "ALL";
}
#endif  // _WIN32

void usage() {
    std::printf(
        "%s\n"
        "usage: rtsc_gui <host> [port] [domain] [user] [password] "
        "[width] [height] [backend] [zoom] [fit] [viewport_w] [viewport_h] "
        "[multimon] [--rdp] [--frames N] [--seconds N] [--input-probe]\n"
        "  --rdp  request PROTOCOL_RDP (Standard RDP Security, RC4 data plane)\n"
        "  --input-probe: queue one key and one mouse event after activation\n"
        "  (automation only; headless loopback input check).\n"
        "  port defaults to 3389; width/height default to the desktop size the\n"
        "  server grants (1280x1024), so the default view is 1:1 lossless.\n"
        "  backend: headless | win32 | x11 | wayland (default: platform).\n"
        "  zoom: 1.0 = 1:1 (the default). fit: 1 = fit to window.\n"
        "  viewport_w/h: force the window surface size (drives auto-resize).\n"
        "  multimon: 1 = one window per monitor when the server reports a\n"
        "  multi-monitor layout; 0 (default) = one span window for the union.\n"
        "  --gateway=host:port (or RTSC_GATEWAY): tunnel through an RD Gateway\n"
        "  (RDGSP, dual IN/OUT connections) instead of a direct TCP connection.\n"
        "  TLS: BOTH layers default to strict validation. Deregulate only with\n"
        "  explicit switches: --tls-insecure (inner RDP TLS/CredSSP), and for\n"
        "  the gateway TLS --gateway-insecure or --gateway-trust=<64-hex SPKI>.\n"
        "  --frames N / --seconds N: bound the run (automation only). The default\n"
        "  is unlimited, so a real session renders until the window is closed.\n"
        "  In-session: a plain wheel scrolls the remote desktop; Ctrl+wheel\n"
        "  zooms (fine steps), Ctrl+1..4 select 100/125/150/200%%, Ctrl+0 fits;\n"
        "  the View menu offers the same.\n",
        kVersion);
}

rtsc::security::ConnectionDriver MakeDriver(const std::string& host,
                                            const std::string& domain,
                                            const std::string& user,
                                            const std::string& password,
                                            bool standard_rdp,
                                            bool rail_mode,
                                            bool usb_redirect,
                                            bool tls_insecure) {
    rtsc::proto::ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    if (standard_rdp) {
        mcfg.requested_protocols = rtsc::proto::kProtocolRdp;
        // Advertise 40/128/56-bit Standard RDP Security. The server picks the
        // strongest method and returns the matching RSA certificate.
        mcfg.encryption_methods = 0x0000001B;
    } else {
        mcfg.requested_protocols = rtsc::proto::kProtocolSsl |
                                   rtsc::proto::kProtocolHybrid |
                                   rtsc::proto::kProtocolHybridEx;
        mcfg.encryption_methods = 0;
    }
    mcfg.client_name = "RTSC";
    // Static virtual channels ([MS-RDPBCGR] 2.2.1.11). The "rail" channel is
    // only advertised in RemoteApp (--rail): a desktop session claiming it
    // makes the server prepare a RemoteApp session with a black desktop.
    // "drdynvc" (the URBDRC dynamic-virtual-channel transport) is advertised
    // only when USB redirection is requested (RTSC_REDIRECT_USB); advertising
    // it unconditionally wastes a static channel and widens the attack surface
    // for no benefit.
    std::vector<std::string> channels = {"rdpdr", "cliprdr", "rdpsnd"};
    if (rail_mode) channels.push_back("rail");
    if (usb_redirect) channels.push_back("drdynvc");
    mcfg.channel_names = std::move(channels);

    rtsc::proto::ConnectMachine::Credentials creds;
    creds.domain = domain;
    creds.user_name = user;
    creds.password = password;

    rtsc::security::Config scfg;
    scfg.tls_config.peer_host = host;
    // D-A3 (P0): the inner RDP TLS/CredSSP transport defaults to STRICT
    // validation. kInsecure used to be the default, which let a MITM read the
    // CredSSP step-5 plaintext password. Deregation is now an explicit opt-in
    // (--tls-insecure) for isolated lab environments only.
    scfg.tls_config.cert_policy =
        tls_insecure ? rtsc::tls::CertPolicy::kInsecure
                     : rtsc::tls::CertPolicy::kStrict;
    scfg.credentials.domain = domain;
    scfg.credentials.user = user;
    scfg.credentials.password = password;

    return rtsc::security::ConnectionDriver(mcfg, creds, scfg);
}

// Splits "--gateway=host:port" into host and port. The last colon is the port
// separator unless the value is a bracketed IPv6 literal "[...]:port"; a bare
// IPv6 literal (no port) is accepted whole. Returns false for a bad port.
bool SplitGatewayAddress(const std::string& addr, std::string& host,
                         uint16_t& port) {
    host.clear();
    port = 443;
    if (addr.empty()) return false;
    const auto is_all_digits = [](const std::string& s) {
        return !s.empty() &&
               s.find_first_not_of("0123456789") == std::string::npos;
    };
    if (addr.size() >= 2 && addr.front() == '[') {
        const size_t close = addr.find(']');
        if (close == std::string::npos) return false;
        host = addr.substr(1, close - 1);
        if (host.empty()) return false;
        const std::string rest = addr.substr(close + 1);
        if (rest.empty()) return true;  // "[::1]" -> default port
        if (rest.front() != ':') return false;
        const std::string p = rest.substr(1);
        if (!is_all_digits(p)) return false;
        const unsigned long v = std::strtoul(p.c_str(), nullptr, 10);
        if (v == 0 || v > 65535) return false;
        port = static_cast<uint16_t>(v);
        return true;
    }
    const size_t colon = addr.rfind(':');
    if (colon == std::string::npos) {
        host = addr;
        return true;
    }
    // More than one colon and a non-numeric tail: treat the whole value as an
    // IPv6 literal (no port).
    if (addr.find(':') != colon || !is_all_digits(addr.substr(colon + 1))) {
        host = addr;
        return true;
    }
    host = addr.substr(0, colon);
    if (host.empty()) return false;
    const unsigned long v =
        std::strtoul(addr.substr(colon + 1).c_str(), nullptr, 10);
    if (v == 0 || v > 65535) return false;
    port = static_cast<uint16_t>(v);
    return true;
}

// Builds the RD Gateway transport chain (stage-2 D): TCP(+ outer gateway TLS)
// -> RdgspTransport, and RUNS the RdgspTransport handshake (H0-H8) here so a
// handshake failure surfaces as a clear error instead of a silent connect.
// The two channels share the gateway authority; each gets its own connection
// (dual-connection ruling, gateway-stage2-evidence.md section 10).
std::unique_ptr<rtsc::net::Transport> CreateGatewayTransport(
    const std::string& gateway_address, bool gateway_insecure,
    const std::array<uint8_t, 32>& pinned_spki, const std::string& domain,
    const std::string& user, const std::string& password,
    std::string& error) {
    std::string gw_host;
    uint16_t gw_port = 0;
    if (!SplitGatewayAddress(gateway_address, gw_host, gw_port) ||
        gw_host.empty()) {
        error = "--gateway / RTSC_GATEWAY must be host:port";
        return nullptr;
    }
    const bool has_pin =
        pinned_spki != std::array<uint8_t, 32>{};  // all-zero = no pin

    rtsc::net::RdgspTransport::Config cfg;
    cfg.host = gw_host;
    cfg.port = gw_port;
    // The connection id is a client-generated GUID carried on both channels.
    cfg.connection_id = rtsc::client::GenerateActivityId();
    cfg.domain = domain;
    cfg.user_name = user;
    cfg.password = password;
    // The factory's UA string; the rest of the header set comes from the
    // channel builder.
    cfg.user_agent = "MS-RDGateway/1.0";
    // Reduce the handshake deadlines from the factory table's general values
    // to something a CLI connect can wait for; the wire behaviour is governed
    // by the evidence table (120/60/30/90/30 s).
    cfg.connect_out = [gw_host, gw_port, gateway_insecure, pinned_spki,
                       has_pin, &error](
                          std::string& e) -> std::unique_ptr<rtsc::net::Transport> {
        auto tcp = rtsc::net::ConnectTcp(gw_host, gw_port, e);
        if (!tcp) return nullptr;
        if (gateway_insecure) return tcp;  // explicit deregulation only
        rtsc::tls::Config tls_cfg;
        tls_cfg.peer_host = gw_host;
        if (has_pin) {
            // Pinned SPKI: trust the pinned identity instead of the CA chain
            // (the only self-signed path short of --gateway-insecure).
            tls_cfg.cert_policy = rtsc::tls::CertPolicy::kTofu;
            tls_cfg.pinned_spki_sha256 = pinned_spki;
            tls_cfg.pin_is_set = true;
        } else {
            tls_cfg.cert_policy = rtsc::tls::CertPolicy::kStrict;
        }
        auto tls = rtsc::net::TlsByteTransport::Wrap(std::move(tcp), tls_cfg, e);
        if (!tls) return nullptr;
        return tls;
    };
    cfg.connect_in = cfg.connect_out;  // each channel runs its own connection

    auto transport = std::make_unique<rtsc::net::RdgspTransport>(cfg);
    if (!transport->Connect(error)) {
        if (error.empty()) error = "RD Gateway handshake failed";
        return nullptr;
    }
    return transport;
}

}  // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    rtsc::util::InstallCrashGuard("rtsc_gui");

    // Optional run bounds (automation only), parsed out of the positional list
    // so they can appear anywhere after the host. The default is unlimited: a
    // real session renders until the window is closed.
    long max_frames = 0;   // 0 = unlimited
    long max_seconds = 0;  // 0 = unlimited
    bool standard_rdp = false;
    bool input_probe = false;
    bool rail_mode = false;
    // TLS policy (D-A3, P0): the default on both TLS layers is STRICT. The
    // explicit switches are the only way to deregulate, for isolated labs.
    bool tls_insecure = false;
    bool gateway_insecure = false;
    std::string gateway_address;  // "--gateway=host:port"
    std::string gateway_pinned_spki;  // "--gateway-trust=<64-hex>"
    // 0 = debug channel disabled (the default). Binds 127.0.0.1 only.
    uint16_t ui_debug_port = 0;
    std::vector<std::string> args;
    args.reserve(static_cast<size_t>(argc));
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--rdp") == 0) {
            standard_rdp = true;
            continue;
        }
        if (std::strcmp(a, "--input-probe") == 0) {
            input_probe = true;
            continue;
        }
        // In-process debug channel (loopback HTTP + JSON). Default off:
        // nothing starts unless this flag is given. See
        // include/rtsc/debug/ui_debug_server.h for scope and safety.
        if (std::strncmp(a, "--ui-debug-port=", 16) == 0) {
            ui_debug_port = static_cast<uint16_t>(std::atoi(a + 16));
            continue;
        }
        if (std::strcmp(a, "--ui-debug-port") == 0 && i + 1 < argc) {
            ui_debug_port = static_cast<uint16_t>(std::atoi(argv[++i]));
            continue;
        }
        if (std::strcmp(a, "--rail") == 0) {
            // RemoteApp (RAIL) mode: advertise the rail channel, INFO_RAIL and
            // TS_RAIL_CAPS. A desktop session must NOT claim them (mstsc only
            // does in remoteapplicationmode:i:1).
            rail_mode = true;
            continue;
        }
        if (std::strcmp(a, "--frames") == 0 && i + 1 < argc) {
            max_frames = std::atol(argv[++i]);
            continue;
        }
        if (std::strcmp(a, "--seconds") == 0 && i + 1 < argc) {
            max_seconds = std::atol(argv[++i]);
            continue;
        }
        // D-A3 (P0): TLS deregulation switches. There is no other way to use
        // kInsecure; the default is strict on both the inner RDP TLS and the
        // outer gateway TLS.
        if (std::strcmp(a, "--tls-insecure") == 0) {
            tls_insecure = true;
            continue;
        }
        if (std::strcmp(a, "--gateway-insecure") == 0) {
            gateway_insecure = true;
            continue;
        }
        if (std::strncmp(a, "--gateway-trust=", 16) == 0) {
            gateway_pinned_spki = a + 16;
            continue;
        }
        if (std::strncmp(a, "--gateway=", 10) == 0) {
            gateway_address = a + 10;
            continue;
        }
        args.emplace_back(a);
    }
    // RTSC_GATEWAY environment fallback (same style as RTSC_REDIRECT_*). A
    // command-line --gateway wins over the environment.
    if (gateway_address.empty()) {
        char* env_gateway = nullptr;
        size_t env_len = 0;
        if (_dupenv_s(&env_gateway, &env_len, "RTSC_GATEWAY") == 0 &&
            env_gateway != nullptr) {
            gateway_address = env_gateway;
            std::free(env_gateway);
        }
    }
    // New external input surfaces are rejected up front for CR/LF/NUL (the
    // handshake builders would do the same, but a CLI value with a smuggled
    // header break must never reach them in the first place).
    if (gateway_address.find_first_of("\r\n") != std::string::npos ||
        gateway_address.find('\0') != std::string::npos) {
        std::printf("rtsc_gui: --gateway / RTSC_GATEWAY contains CRLF or NUL; "
                    "rejected\n");
        return 2;
    }
    std::array<uint8_t, 32> gateway_pin{};
    if (!gateway_pinned_spki.empty()) {
        // SPKI SHA-256 pin: exactly 64 lowercase/uppercase hex digits.
        if (gateway_pinned_spki.size() != 64 ||
            gateway_pinned_spki.find_first_not_of(
                "0123456789abcdefABCDEF") != std::string::npos) {
            std::printf(
                "rtsc_gui: --gateway-trust must be a 64-hex-digit SPKI SHA-256\n");
            return 2;
        }
        for (size_t i = 0; i < 32; ++i) {
            char hex[3] = {gateway_pinned_spki[i * 2],
                           gateway_pinned_spki[i * 2 + 1], 0};
            gateway_pin[i] =
                static_cast<uint8_t>(std::strtoul(hex, nullptr, 16));
        }
    }
    if (args.empty()) {
        usage();
        return 2;
    }

    // The default window/viewport size is the desktop size the server grants,
    // so the default view is 1:1 lossless. ConnectMachine's default is the
    // pre-negotiation value; the authoritative size is latched from the Demand
    // Active PDU once the session is up (see below).
    const uint16_t default_desktop_w = static_cast<uint16_t>(
        rtsc::proto::ConnectMachine::Config{}.desktop_width);
    const uint16_t default_desktop_h = static_cast<uint16_t>(
        rtsc::proto::ConnectMachine::Config{}.desktop_height);

    const std::string host = args[0];
    const uint16_t port =
        args.size() >= 2 ? static_cast<uint16_t>(std::atoi(args[1].c_str())) : 3389;
    const std::string domain = args.size() >= 3 ? args[2] : "";
    const std::string user = args.size() >= 4 ? args[3] : "";
    const std::string password = args.size() >= 5 ? args[4] : "";
    const uint16_t width =
        args.size() >= 6 ? static_cast<uint16_t>(std::atoi(args[5].c_str()))
                         : default_desktop_w;
    const uint16_t height =
        args.size() >= 7 ? static_cast<uint16_t>(std::atoi(args[6].c_str()))
                         : default_desktop_h;
    const std::string backend = args.size() >= 8 ? args[7] : "";
    // View options: zoom (1.0 = 1:1) and fit. The default is FIT: the remote
    // desktop is scaled to the application window (what mstsc calls "smart
    // sizing"), which is what a remote-desktop window is expected to do -- a
    // 1280x1024 session in a smaller window must be visible whole, not cropped.
    // Passing fit=0 explicitly selects the 1:1 lossless mode. Fit never enlarges
    // past 100%, so a window at least as large as the remote desktop still shows
    // a pixel-exact copy.
    // The pipeline/ZoomState defaults stay 1:1 (a library caller that asks for a
    // surface-sized frame keeps getting a pixel-exact copy); only this front-end
    // picks smart sizing.
    const bool has_zoom = args.size() >= 9 && std::atof(args[8].c_str()) > 0.0;
    const double zoom_arg = has_zoom ? std::atof(args[8].c_str()) : 1.0;
    bool fit_arg = args.size() >= 10 ? std::atoi(args[9].c_str()) != 0 : true;
    if (fit_arg && has_zoom) {
        // An explicit zoom means the caller asked for that scale; fit would
        // silently override it, so keep the requested zoom.
        fit_arg = false;
    }
    const uint16_t viewport_w =
        args.size() >= 11 ? static_cast<uint16_t>(std::atoi(args[10].c_str())) : 0;
    const uint16_t viewport_h =
        args.size() >= 12 ? static_cast<uint16_t>(std::atoi(args[11].c_str())) : 0;
    // Multi-monitor mode: one window per monitor. The default (0) is the
    // single-window span mode, which shows the whole virtual desktop.
    const bool multimon =
        args.size() >= 13 ? std::atoi(args[12].c_str()) != 0 : false;

    std::printf("rtsc_gui: connecting to %s:%u (%ux%u, %s)\n", host.c_str(),
                static_cast<unsigned>(port), static_cast<unsigned>(width),
                static_cast<unsigned>(height),
                standard_rdp ? "PROTOCOL_RDP" : "external security");

    std::string why;
    std::vector<std::unique_ptr<rtsc::ui::Window>> windows;
    {
        auto first = rtsc::ui::CreateWindow(width, height, backend, why);
        if (!first) {
            std::printf("no window backend: %s\n", why.c_str());
            return 1;
        }
        std::printf("window backend: %s\n", first->backend_name());
        windows.push_back(std::move(first));
    }
    if (viewport_w != 0 && viewport_h != 0) {
        // A forced viewport drives the same resize path WM_SIZE uses, which is
        // how auto-resize is exercised without a display (headless).
        windows[0]->Resize(viewport_w, viewport_h);
        std::printf("viewport forced to %ux%u\n",
                    static_cast<unsigned>(viewport_w),
                    static_cast<unsigned>(viewport_h));
    }

    std::string error;
    std::unique_ptr<rtsc::net::Transport> transport;
    if (!gateway_address.empty()) {
        // RD Gateway path (wired in phase 2 of the stage-2 work): the outer
        // gateway TLS policy is strict by default; --gateway-insecure or
        // --gateway-trust deregulate it. The transport chain itself is built
        // by CreateGatewayTransport below.
        std::printf("rtsc_gui: RD Gateway %s (gateway TLS %s%s)\n",
                    gateway_address.c_str(),
                    gateway_insecure ? "insecure" : "strict",
                    gateway_pinned_spki.empty() ? "" : ", SPKI pinned");
        transport = CreateGatewayTransport(
            gateway_address, gateway_insecure, gateway_pin, domain, user,
            password, error);
    } else {
        transport = rtsc::net::ConnectTcp(host, port, error);
    }
    if (!transport) {
        std::printf("connect failed: %s\n", error.c_str());
        return 1;
    }

    // USB redirection gate (RTSC_REDIRECT_USB), read before the driver is
    // built so the "drdynvc" static channel is only advertised when USB
    // redirection is actually requested. Unset and empty both mean off; "ALL"
    // = every device; "VID:PID,VID:PID" = a whitelist. Same opt-in policy as
    // RTSC_REDIRECT_DRIVES. The holder releases on every return path (RAII),
    // including the early Connect-failure return below.
    std::unique_ptr<char, decltype(&std::free)> usb_spec_holder(nullptr,
                                                               &std::free);
    size_t usb_spec_len = 0;
    char* usb_spec_raw = nullptr;
    if (_dupenv_s(&usb_spec_raw, &usb_spec_len, "RTSC_REDIRECT_USB") == 0 &&
        usb_spec_raw != nullptr) {
        usb_spec_holder.reset(usb_spec_raw);
    }
    const char* usb_spec = usb_spec_holder.get();

    rtsc::client::Client client(
        MakeDriver(host, domain, user, password, standard_rdp, rail_mode,
                   rtsc::usb::UsbGateEnabled(usb_spec), tls_insecure),
        width, height);

    // View (zoom / fit) state. The controller owns the state; the pipeline owns
    // the rendering. The default is 1:1 lossless: zoom 100% and fit off, so the
    // rendered frame is a pixel-for-pixel copy of the remote desktop.
    rtsc::client::ZoomState zs;
    zs.zoom = zoom_arg;
    zs.fit = fit_arg;
    client.graphics().set_zoom(zs.zoom);
    client.graphics().set_fit(zs.fit);

    // Publish the view state to the window backend so the View menu ticks and
    // labels match (zoom percent, "智能调整大小" checked/unchecked). It is
    // refreshed below whenever a view command changes the state.
    rtsc::ui::ViewMenuState menu_state;
    menu_state.zoom = zs.zoom;
    menu_state.fit = zs.fit;
    windows[0]->SetViewMenuState(menu_state);

    // Record the static virtual channel chunks the server sends; rdpdr is not
    // decoded, cliprdr runs the clipboard protocol, and rdpsnd runs the audio
    // protocol.
    unsigned vc_rdpdr = 0;
    unsigned vc_cliprdr = 0;
    unsigned vc_rail = 0;
    unsigned input_sends = 0;
    unsigned channel_sends = 0;

    // Audio output: decode the server's Wave2 PDUs and play them through the
    // platform backend. The handler only borrows the sink, which lives here.
#if defined(_WIN32)
    std::unique_ptr<rtsc::audio::AudioSink> audio_sink =
        rtsc::audio::CreateWaveOutSink();
    if (!audio_sink) {
        audio_sink = std::make_unique<rtsc::audio::NullAudioSink>();
    }
#else
    std::unique_ptr<rtsc::audio::AudioSink> audio_sink =
        std::make_unique<rtsc::audio::NullAudioSink>();
#endif

    // Sends a complete channel message (CHANNEL_PDU_HEADER + channel PDU) on a
    // static virtual channel through the application data plane. The client
    // picks the security model: TLS/CredSSP wraps the MCS frame in the TLS
    // stream, Standard RDP Security puts it in MCS and applies RC4.
    const auto send_channel = [&](uint16_t channel_id,
                                  const std::vector<uint8_t>& message) {
        std::string send_error;
        if (client.SendChannelPdu(*transport, channel_id, message, send_error)) {
            ++channel_sends;
        }
    };
    const auto send_rdpsnd = [&](const std::vector<uint8_t>& message) {
        send_channel(kChannelRdpsnd, message);
    };

    // RAIL (Remote Programs, [MS-RDPERP]): the client sends the RAIL orders on
    // the "rail" static virtual channel through the same application data
    // plane. The channel id is resolved from the Server Network Data once the
    // channel join completed, so the sender is bound here and used by
    // StartRailChannel() after Connect().
    client.SetRailSender([&](uint16_t channel_id,
                             const std::vector<uint8_t>& message) {
        send_channel(channel_id, message);
        return true;
    });

    // Clipboard redirection (CLIPRDR): decode the cliprdr static virtual channel
    // and synchronise the local clipboard with the remote session. The handler
    // only borrows the platform clipboard, which lives here.
    std::unique_ptr<rtsc::clipboard::Clipboard> local_clipboard =
        rtsc::clipboard::CreatePlatformClipboard();
    if (!local_clipboard) {
        local_clipboard = std::make_unique<rtsc::clipboard::NullClipboard>();
    }

    // Clipboard redirection (CLIPRDR) sends through the same application
    // data plane, so it works under both TLS and Standard RDP Security.
    const auto send_cliprdr = [&](const std::vector<uint8_t>& message) {
        send_channel(kChannelCliprdr, message);
    };

    rtsc::channel::CliprdrClient cliprdr(local_clipboard.get(), send_cliprdr);
    // Stream file clip (CB_FILECONTENTS) is off by default; direction A turns
    // it on here. Huge-file support stays off (v1 default).
    cliprdr.EnableFileClip();

    rtsc::channel::RdpsndClient rdpsnd(audio_sink.get(), send_rdpsnd);

    // Drive redirection (RDPDR): redirect local drives to the remote session.
    // The handler owns no file-system state; HostFileSystem must live at least
    // as long as RdpdrClient, and RdpdrClient must be declared before
    // RegisterChannel (the channel lambda captures it by reference).
    auto host_fs = std::make_unique<rtsc::rdpdr::HostFileSystem>();
    std::vector<rtsc::channel::RdpdrClient::Device> devices;
    {
        uint32_t device_id = 1;
        char* env_spec = nullptr;
        size_t env_spec_len = 0;
        const char* spec = nullptr;
        if (_dupenv_s(&env_spec, &env_spec_len, "RTSC_REDIRECT_DRIVES") == 0 &&
            env_spec != nullptr) {
            spec = env_spec;
        }
        for (const auto& drive : rtsc::rdpdr::EnumerateLocalDrives(spec)) {
            devices.push_back(
                {device_id++, drive.dos_name, drive.local_root});
        }
        std::free(env_spec);
        // Drive redirection is opt-in (RTSC_REDIRECT_DRIVES), so an empty list
        // is the normal case. Print what is actually shared - the remote peer
        // gets read/write access to every redirected drive, and silently
        // sharing a whole disk would be a nasty surprise.
        if (devices.empty()) {
            std::printf("rdpdr: no drives redirected "
                        "(set RTSC_REDIRECT_DRIVES=C,E or ALL)\n");
        } else {
            std::printf("rdpdr: redirecting %zu drive(s):", devices.size());
            for (const auto& device : devices) {
                std::printf(" %s", device.dos_name.c_str());
            }
            std::printf(" (remote peer has read/write access)\n");
        }
    }
    const auto send_rdpdr = [&](const std::vector<uint8_t>& message) {
        send_channel(kChannelRdpdr, message);
    };
    rtsc::channel::RdpdrClient rdpdr(host_fs.get(), std::move(devices), "RTSC",
                                     send_rdpdr);

    // Smart card redirection ([MS-RDPESC]) is opt-in like the drive and USB
    // redirection paths: RTSC_REDIRECT_SMARTCARD=1 announces the SCARD device
    // over rdpdr and answers its SCARD_IOCTL_* requests from the local Smart
    // Cards for Windows stack. The backend lives for the whole session
    // (RdpdrClient only borrows it). The device list is sent once, when the
    // server confirms the client id ([MS-RDPEFS] 2.2.2.9), so this must be
    // enabled before the first inbound message - the menu item below reports
    // that a reconnect is needed instead of pretending to hot-plug a device.
    std::unique_ptr<rtsc::smartcard::ISmartCardBackend> scard_backend;
    {
        char* scard_env = nullptr;
        size_t scard_env_len = 0;
        const bool requested =
            _dupenv_s(&scard_env, &scard_env_len, "RTSC_REDIRECT_SMARTCARD") == 0 &&
            scard_env != nullptr && scard_env[0] != '\0' && scard_env[0] != '0';
        std::free(scard_env);
        if (requested) {
            scard_backend = rtsc::smartcard::MakeSmartCardBackend();
            if (scard_backend != nullptr && scard_backend->available()) {
                rdpdr.EnableSmartCard(scard_backend.get());
                std::printf(
                    "rdpdr: smart card redirection enabled; the local smart card "
                    "readers are shared with the remote session\n");
            } else {
                scard_backend.reset();
                std::printf(
                    "rdpdr: RTSC_REDIRECT_SMARTCARD is set but the Smart Card "
                    "service (winscard.dll) is unavailable; no local smart card "
                    "is shared\n");
            }
        } else {
            std::printf(
                "rdpdr: smart card redirection off (set "
                "RTSC_REDIRECT_SMARTCARD=1 to share local readers)\n");
        }
        menu_state.smart_card = scard_backend != nullptr;
    }
    if (!windows.empty()) windows[0]->SetViewMenuState(menu_state);
    client.RegisterChannel(kChannelRdpdr,
                           [&](const uint8_t* data, size_t size) {
                               ++vc_rdpdr;
                               rdpdr.OnChannelData(data, size);
                           });
    client.RegisterChannel(kChannelCliprdr,
                           [&](const uint8_t* data, size_t size) {
                               ++vc_cliprdr;
                               cliprdr.OnChannelData(data, size);
                           });
    client.RegisterChannel(kChannelRdpsnd,
                           [&](const uint8_t* data, size_t size) {
                               rdpsnd.OnChannelData(data, size);
                           });
    // D-A6 (recorded, P2): Client::Connect is a synchronous handshake on the UI
    // thread, so a slow or dead peer freezes the message pump until the
    // connection deadline. This batch records the limitation only; converting
    // to an async handshake is a follow-up. The bounded Client::Connect
    // deadline (30 s) is the only thing standing between a dead gateway and a
    // frozen window.
    if (!client.Connect(*transport, error)) {
        std::printf("connection failed: %s\n", error.c_str());
        return 1;
    }
    cliprdr.Start();

    // Minimal direction-A GUI hook: as soon as the server advertises the
    // file-clip format (FileGroupDescriptorW), ask once for the remote file
    // list. RequestRemoteFileList no-ops when stream file clip was not
    // negotiated or the format is unknown.
    bool file_list_requested = false;

    // RAIL: register the handler on the server-assigned "rail" static virtual
    // channel and start the RAIL session. The server sends its Handshake first
    // ([MS-RDPERP] 2.2.2.2.1); the client responds and sends its ClientStatus.
    // Skipped entirely outside RemoteApp mode: the channel was never offered.
    if (rail_mode) {
        client.rail().SetHandler([&](const rtsc::proto::RailPdu& pdu) {
            ++vc_rail;
            (void)pdu;  // the RailClient state holds the decoded orders
        });
        const uint16_t rail_id =
            client.StartRailChannel(kRailBuildNumber, kRailClientFlags);
        if (rail_id == 0) {
            std::printf(
                "rail: server did not assign a rail static virtual channel\n");
        } else {
            std::printf("rail: static virtual channel id %u\n",
                        static_cast<unsigned>(rail_id));
        }
    }

    // USB device redirection (URBDRC over the drdynvc static virtual channel)
    // is opt-in: the RTSC_REDIRECT_USB gate was read above, and the drdynvc
    // channel is only advertised when it is set. Here the URBDRC state machine
    // is started for that same spec, and devices are announced once the
    // channel finished its capability exchange.
    bool usb_devices_added = false;
    unsigned usb_devices_added_count = 0;
    unsigned usb_devices_skipped = 0;
#if defined(_WIN32)
    std::unique_ptr<rtsc::channel::DrdynvcClient> drdynvc;
    std::unique_ptr<rtsc::usb::UsbDeviceEnumerator> usb_enumerator;
    std::unique_ptr<rtsc::channel::RdpUsbClient> rdpusb;
    if (rtsc::usb::UsbGateEnabled(usb_spec)) {
        const uint16_t drdynvc_id = client.driver().ChannelIdForName("drdynvc");
        if (drdynvc_id == 0) {
            std::printf(
                "rdpusb: server did not assign a drdynvc static virtual "
                "channel; USB redirection disabled\n");
        } else {
            usb_enumerator = rtsc::usb::CreateWin32Enumerator();
            if (usb_enumerator == nullptr) {
                std::printf("rdpusb: no WinUSB enumerator; USB redirection "
                            "disabled\n");
            } else {
                // drdynvc lives before rdpusb in declaration order so the
                // RdpUsbClient destructor (which removes its listener from the
                // transport) sees a live DrdynvcClient.
                const auto send_drdynvc = [&](const std::vector<uint8_t>& m) {
                    send_channel(drdynvc_id, m);
                };
                drdynvc = std::make_unique<rtsc::channel::DrdynvcClient>(
                    nullptr, send_drdynvc);
                client.RegisterChannel(
                    drdynvc_id,
                    [&](const uint8_t* data, size_t size) {
                        drdynvc->OnChannelData(data, size);
                    });
                drdynvc->Start();
                rdpusb = std::make_unique<rtsc::channel::RdpUsbClient>(
                    usb_enumerator.get(), drdynvc.get());
                rdpusb->Start();
                std::printf(
                    "rdpusb: drdynvc channel id %u, waiting for the URBDRC "
                    "channel before announcing devices\n",
                    static_cast<unsigned>(drdynvc_id));
            }
        }
    }
#endif

    // Size the window and the surface to the desktop the server granted (the
    // Demand Active bitmap capability). This is what makes the default 1:1 view
    // lossless even when the requested window size differed from the negotiated
    // desktop: the surface is recreated at the authoritative size before the
    // desktop is painted.
    const uint16_t desk_w = client.desktop_width();
    const uint16_t desk_h = client.desktop_height();
    const bool multi_window = multimon && client.has_monitor_layout();
    if (client.has_monitor_layout()) {
        // The server reported a multi-monitor session: the pipeline becomes a
        // virtual desktop (the union of the monitors) plus one surface per
        // monitor. Span mode shows the union in the single window; multi-window
        // mode replaces the single window with one window per monitor.
        const auto& monitors = client.monitors();
        client.graphics().set_monitor_layout(monitors);
        std::printf("monitor layout: %zu monitor(s)\n", monitors.size());
        for (size_t i = 0; i < monitors.size(); ++i) {
            std::printf("  monitor %zu: %dx%d at (%d,%d)%s\n", i,
                        static_cast<unsigned>(monitors[i].width()),
                        static_cast<unsigned>(monitors[i].height()),
                        monitors[i].left, monitors[i].top,
                        monitors[i].primary() ? " primary" : "");
        }
        if (multi_window) {
            windows.clear();
            for (const auto& m : monitors) {
                auto w = rtsc::ui::CreateWindow(
                    static_cast<uint16_t>(m.width()),
                    static_cast<uint16_t>(m.height()), backend, why);
                if (!w) {
                    std::printf("no window backend: %s\n", why.c_str());
                    return 1;
                }
                windows.push_back(std::move(w));
            }
        } else {
            windows[0]->Resize(
                static_cast<uint16_t>(client.graphics().virtual_width()),
                static_cast<uint16_t>(client.graphics().virtual_height()));
        }
    } else if (desk_w != 0 && desk_h != 0 &&
               (desk_w != windows[0]->surface().width() ||
                desk_h != windows[0]->surface().height())) {
        windows[0]->Resize(desk_w, desk_h);
        client.graphics().Resize(desk_w, desk_h);
        std::printf("desktop size %ux%u: window/surface resized from %ux%u\n",
                    static_cast<unsigned>(desk_w), static_cast<unsigned>(desk_h),
                    static_cast<unsigned>(width), static_cast<unsigned>(height));
    }
    // Attach the clipboard observer to the final window set. This must run
    // after the multi-monitor rebuild above: that path destroys the initial
    // window and creates one per monitor, so binding earlier (to windows[0])
    // would leave the live windows without a callback. One call covers both the
    // single-window and the multi-window layout.
    // Direction B: serve a local file selection to the peer. When the local
    // clipboard carries CF_HDROP, parse the selection into a DropFileList and
    // install it as the file-clip provider; when CF_HDROP leaves the clipboard
    // (or cannot be read) drop the provider so the serve path fails closed
    // again. The provider outlives the binding: it is captured by reference
    // and lives until the session ends, while the channel only borrows the raw
    // pointer (no ownership).
    std::vector<uint8_t> hdrop_bytes;
    std::unique_ptr<rtsc::clipboard::DropFileList> hdrop_provider;
    rtsc::ui::BindClipboardToWindows(windows, [&] {
        if (local_clipboard->read(rtsc::clipboard::kCfHdrop, hdrop_bytes)) {
            hdrop_provider =
                rtsc::clipboard::CreateDropFileListFromBytes(hdrop_bytes);
            cliprdr.SetFileListProvider(hdrop_provider.get());
        } else {
            // Single-threaded UI callback invariant: clear the channel's
            // borrowed pointer before dropping the owned provider, so no other
            // thread can touch the provider after it is released.
            cliprdr.SetFileListProvider(nullptr);
            hdrop_provider.reset();
        }
        cliprdr.OnLocalClipboardChanged();
    });
    if (input_probe) {
        rtsc::ui::InputEvent probe_key;
        probe_key.kind = rtsc::ui::InputEvent::Kind::kKey;
        probe_key.scancode = 0x1E;  // 'A'
        windows[0]->PushEventForTest(probe_key);
        rtsc::ui::InputEvent probe_move;
        probe_move.kind = rtsc::ui::InputEvent::Kind::kMouseMove;
        probe_move.x = 11;
        probe_move.y = 13;
        windows[0]->PushEventForTest(probe_move);
        std::printf("input probe queued: key 0x1E, mouse (11,13)\n");
    }
    std::printf("session active; desktop %ux%u; entering the render loop\n",
                static_cast<unsigned>(client.desktop_width()),
                static_cast<unsigned>(client.desktop_height()));

    unsigned frames = 0;    // loop iterations (input responsiveness)
    unsigned renders = 0;   // actual Present() calls
    const auto started = std::chrono::steady_clock::now();
    auto last_render = started;
    auto last_fps = started;
    unsigned fps_frames = 0;
    unsigned fps_renders = 0;
    bool view_dirty = true;  // the first frame must be rendered
    int last_view_w = static_cast<int>(windows[0]->surface().width());
    int last_view_h = static_cast<int>(windows[0]->surface().height());
    // At most ~60 FPS. A remote desktop rarely updates faster than that, and the
    // cap keeps a fast server from driving the render loop (and a core) to 100%.
    constexpr auto kMinFrameInterval = std::chrono::milliseconds(16);
    // True once every window is closed.
    const auto all_closed = [&windows]() {
        for (const auto& w : windows) {
            if (!w->closed()) return false;
        }
        return true;
    };

    // ---- In-process debug channel (opt-in) --------------------------------
    // The HTTP server runs on its own thread; commands are queued here and
    // answered from the render loop below, so a command can read live client
    // state without racing the compositor. Everything here is inert unless
    // --ui-debug-port was given.
    rtsc::debug::PendingCommandQueue dbg_queue;
    class GuiDebugHost final : public rtsc::debug::UiDebugHost {
     public:
        explicit GuiDebugHost(rtsc::debug::PendingCommandQueue* q) : q_(q) {}
        std::string Execute(const std::string& json_body) override {
            return q_ != nullptr ? q_->Run(json_body)
                                 : "\"ok\":false,\"error\":\"no queue\"";
        }
     private:
        rtsc::debug::PendingCommandQueue* q_;
    };

    GuiDebugHost dbg_host(&dbg_queue);
    rtsc::debug::UiDebugServer dbg_server;
    if (ui_debug_port != 0) {
        std::string dbg_error;
        if (dbg_server.Start(ui_debug_port, &dbg_host, dbg_error)) {
            std::printf("ui debug channel: http://127.0.0.1:%u/debug\n",
                        static_cast<unsigned>(dbg_server.port()));
        } else {
            std::printf("ui debug channel failed: %s\n", dbg_error.c_str());
        }
    }

    while (!all_closed()) {
        // Pump() waits at most kReadTimeoutMs for network data, so this loop
        // iterates several times a second even when the server is silent. That
        // is what keeps the Win32 window responsive: PollEvent() below runs
        // every iteration and its PeekMessageW is non-blocking, so keyboard and
        // mouse input is forwarded to the server promptly instead of the message
         // queue being starved while a blocking recv() waited on a quiet peer.
         // Answer queued debug commands on the UI thread, before the pump,
         // so a command sees the state the last frame left behind. Bounded:
         // one drain per iteration, never a blocking wait.
         rtsc::debug::PendingCommand cmd;
         while (dbg_queue.Pop(cmd)) {
             rtsc::debug::DebugSnapshot snap;
             snap.desktop_width = client.desktop_width();
             snap.desktop_height = client.desktop_height();
             snap.view_width = static_cast<int>(windows[0]->surface().width());
             snap.view_height = static_cast<int>(windows[0]->surface().height());
             snap.zoom = client.graphics().zoom();
             snap.fit = client.graphics().fit();
             snap.frames_rendered = renders;
             snap.loop_iterations = frames;
             snap.input_events_sent = input_sends;
             const auto& dr = client.graphics().dirty_region();
             snap.dirty_left = dr.left;
             snap.dirty_top = dr.top;
             snap.dirty_right = dr.right;
             snap.dirty_bottom = dr.bottom;
             snap.session_active = true;
             snap.host = host;
             snap.backend = windows[0]->backend_name();
// The pixel walk is O(width*height) with a hash set, so it runs only
              // when the command actually asked for it. A "state" or "ping" query
              // must not cost a full-surface scan.
              if (rtsc::debug::CommandRequestsSurface(cmd.body)) {
                  const rtsc::ui::Surface& srv = windows[0]->surface();
                  const size_t px_count =
                      static_cast<size_t>(srv.width()) * srv.height();
                  snap.total_pixels = static_cast<unsigned>(px_count);
                  if (px_count > 0) {
                      const uint8_t* p = srv.data();
                      unsigned non_black = 0;
                      std::unordered_set<std::uint64_t> colours;
                      colours.reserve(px_count);
                      for (size_t i = 0; i < px_count; ++i) {
                          const std::uint64_t rgba =
                              static_cast<std::uint64_t>(p[0]) |
                              (static_cast<std::uint64_t>(p[1]) << 8) |
                              (static_cast<std::uint64_t>(p[2]) << 16) |
                              (static_cast<std::uint64_t>(p[3]) << 24);
                          if ((rgba & 0x00FFFFFFu) != 0) ++non_black;
                          colours.insert(rgba);
                          p += 4;
                      }
                      snap.non_black_pixels = non_black;
                      snap.distinct_colours =
                          static_cast<unsigned>(colours.size());
                  }
              }

              if (rtsc::debug::CommandRequestsScreenshot(cmd.body)) {
                  std::string path;
                  if (rtsc::debug::ScreenshotPath(cmd.body, path) && !path.empty()) {
                      const rtsc::ui::Surface& srv = windows[0]->surface();
                      std::string bmp = rtsc::debug::EncodeBmp32(srv.data(), srv.width(), srv.height());
                      bool ok = false;
                      if (!bmp.empty()) {
                          FILE* f = nullptr;
                          errno_t err = fopen_s(&f, path.c_str(), "wb");
                          if (err == 0 && f) {
                              size_t written = fwrite(bmp.data(), 1, bmp.size(), f);
                              ok = (written == bmp.size());
                              fclose(f);
                          }
                      }
                      snap.screenshot_path = ok ? path : "";
                  } else {
                      snap.screenshot_path.clear();
                  }
              }

              dbg_queue.Answer(rtsc::debug::ExecuteGuiCommand(snap, cmd.body));
         }

        if (!client.Pump(*transport, error)) {
            std::printf("session ended: %s\n", error.c_str());
            break;
        }
        cliprdr.Poll(std::chrono::steady_clock::now());
        // USB device redirection: announce the whitelisted devices once the
        // URBDRC channel finished its capability exchange (it becomes ready
        // after the server created the "URBDRC" dynamic channel).
#if defined(_WIN32)
        if (!usb_devices_added && rdpusb != nullptr && rdpusb->ready()) {
            const auto usb_devices = usb_enumerator->Enumerate();
            // Count the devices the gate matches first so a "matched but not
            // opened" report is possible; the actual sharing is decided by the
            // AddDevice calls below (a device the backend cannot open is never
            // announced, so it is never shared).
            unsigned usb_matched = 0;
            for (const auto& device : usb_devices) {
                if (UsbSpecAllows(usb_spec, device)) {
                    ++usb_matched;
                } else {
                    ++usb_devices_skipped;
                }
            }
            for (const auto& device : usb_devices) {
                if (!UsbSpecAllows(usb_spec, device)) continue;
                if (rdpusb->AddDevice(device)) {
                    ++usb_devices_added_count;
                }
            }
            usb_devices_added = true;
            // Privacy notice AFTER the announcements, reporting the number of
            // devices actually redirected - never the gate-matched candidates,
            // which may include devices that failed to open.
            if (usb_devices_added_count > 0) {
                std::printf(
                    "rdpusb: redirected %u USB device(s)%s; "
                    "the remote peer can access the redirected local USB "
                    "devices\n",
                    usb_devices_added_count,
                    UsbSpecIsAll(usb_spec) ? " (ALL)" : "");
            } else if (usb_matched > 0) {
                std::printf(
                    "rdpusb: %u USB device(s) matched the gate but none could "
                    "be opened; no local USB device is shared\n",
                    usb_matched);
            } else {
                std::printf(
                    "rdpusb: RTSC_REDIRECT_USB is set but no device matched "
                    "the gate; no local USB device is shared\n");
            }
            std::printf("rdpusb: ready, %zu device(s) enumerated, %u redirected"
                        ", %u skipped by the RTSC_REDIRECT_USB gate\n",
                        usb_devices.size(), usb_devices_added_count,
                        usb_devices_skipped);
        }
#endif
        if (!file_list_requested && cliprdr.remote_file_list_format_id() != 0) {
            cliprdr.RequestRemoteFileList();
            file_list_requested = true;
        }

        for (size_t wi = 0; wi < windows.size(); ++wi) {
            rtsc::ui::InputEvent ev;
            while (windows[wi]->PollEvent(ev)) {
                if (ev.kind == rtsc::ui::InputEvent::Kind::kClose) {
                    for (auto& w : windows) w->Close();
                    break;
                }
                // SAS / Pause are client-side commands the window raises
                // (Ctrl+Alt+End, and the Pause/Break key). They must reach the
                // protocol as dedicated PDUs (EncodeCtrlAltDel / EncodePauseKey),
                // never as ordinary forwarded input, so they are dispatched here
                // before the view controls and the send path, in every window
                // mode (a plain input event would encode to nothing).
                if (ev.kind == rtsc::ui::InputEvent::Kind::kUiCommand &&
                    (ev.command == rtsc::ui::kCmdSendCtrlAltDel ||
                     ev.command == rtsc::ui::kCmdSendPause)) {
                    std::string cmd_error;
                    const bool sent =
                        ev.command == rtsc::ui::kCmdSendCtrlAltDel
                            ? client.SendCtrlAltDel(*transport, cmd_error)
                            : client.SendPauseKey(*transport, cmd_error);
                    if (!sent) {
                        std::printf("input write failed: %s\n",
                                    cmd_error.c_str());
                        for (auto& w : windows) w->Close();
                        break;
                    }
                    ++input_sends;
                    continue;
                }
                // Fullscreen is a window-owner command the 目标(M) menu raises
                // (kCmdToggleFullscreen). It must never fall through to the
                // send path: EncodeInput turns kUiCommand into nothing, so
                // without this branch the menu item was a silent no-op. Every
                // window toggles together; the View menu tick follows the state
                // of the first window (they all share it).
                if (ev.kind == rtsc::ui::InputEvent::Kind::kUiCommand &&
                    ev.command == rtsc::ui::kCmdToggleFullscreen) {
                    rtsc::ui::ToggleFullscreen(windows);
                    menu_state.fullscreen = windows[0]->fullscreen();
                    windows[0]->SetViewMenuState(menu_state);
                    continue;
                }
                // Connection information is a window-owner command the 连接信息(C)
                // menu raises (kCmdConnectionInfo). Like fullscreen it must never
                // fall through to the send path: EncodeInput turns kUiCommand into
                // nothing, so without this branch the menu item was a silent no-op.
                // The dialog runs modal to Windows and collects the live session
                // statistics through the client (frame rate from NoteFrame,
                // inbound traffic for bandwidth). The input round-trip stays
                // N/A: the front-end's NoteInputSent hook is not wired (a
                // non-encoding input would start a spurious RTT timer), so no
                // measurement is fabricated.
                // Help is a window-owner command the title-bar "帮助(H)"
                // item raises (kCmdHelp). Like fullscreen and connection info
                // it must never fall through to the send path: EncodeInput turns
                // kUiCommand into nothing, so before this branch the menu item
                // was a silent no-op. See help_dialog_win32.h for why this is an
                // about box and not a Windows Help viewer.
                if (ev.kind == rtsc::ui::InputEvent::Kind::kUiCommand &&
                    ev.command == rtsc::ui::kCmdHelp) {
                    rtsc::gui::ShowHelpDialog(windows[0]->native_handle(),
                                              kVersion);
                    continue;
                }
                // Smart card redirection is a session-level decision: the SCARD
                // device is announced once in the device list ([MS-RDPEFS]
                // 2.2.2.9) and that list was already sent. Report the actual
                // state instead of faking a hot-plug that the protocol cannot
                // express, and leave the menu tick alone.
                if (ev.kind == rtsc::ui::InputEvent::Kind::kUiCommand &&
                    ev.command == rtsc::ui::kCmdToggleSmartCard) {
                    std::printf(
                        "smartcard: redirection is %s for this session; "
                        "restart with RTSC_REDIRECT_SMARTCARD=1 to share local "
                        "readers\n",
                        scard_backend != nullptr ? "enabled" : "disabled");
                    menu_state.smart_card = scard_backend != nullptr;
                    windows[wi]->SetViewMenuState(menu_state);
                    continue;
                }
                if (ev.kind == rtsc::ui::InputEvent::Kind::kUiCommand &&
                    ev.command == rtsc::ui::kCmdConnectionInfo) {
                    const auto collect = [&]() -> rtsc::client::SessionInfo {
                        rtsc::client::SessionInfoInput input;
                        input.host = host;
                        input.frames_per_second = client.frames_per_second();
                        input.has_rtt = client.has_rtt();
                        input.rtt_ms = client.rtt_ms();
                        input.bandwidth_mbps = client.bandwidth_mbps();
                        // Stage-2 (E): when tunnelled through an RD Gateway the
                        // dialog reports the actual gateway + authentication
                        // method instead of "没有在使用中".
                        input.gateway_name = gateway_address;
                        if (!gateway_address.empty()) {
                            input.gateway_logon_method =
                                "NTLM (RDGSP)";
                        }
                        return rtsc::client::CollectSessionInfo(
                            input, std::time(nullptr));
                    };
#if defined(_WIN32)
                    rtsc::gui::ShowConnectionInfoDialog(nullptr, collect);
#else
                    (void)collect;
                    std::printf("connection info: no dialog backend on this "
                                "platform\n");
#endif
                    continue;
                }
                bool consumed = false;
                if (multi_window) {
                    // Each window is 1:1 with its monitor, so the local pointer
                    // is offset into the virtual desktop coordinate space. There
                    // is no zoom in this mode. Pointer events carry an unsigned
                    // position relative to the union of every monitor, so the
                    // union origin has to be subtracted: a monitor left of or
                    // above the primary has a negative left/top and adding it
                    // directly wrapped the coordinate (a -1920 edge became
                    // 63616).
                    if (ev.kind == rtsc::ui::InputEvent::Kind::kMouseMove ||
                        ev.kind == rtsc::ui::InputEvent::Kind::kMouseButton ||
                        ev.kind == rtsc::ui::InputEvent::Kind::kMouseWheel) {
                        const auto& m = client.monitors()[wi];
                        int origin_x = 0;
                        int origin_y = 0;
                        int union_w = 0;
                        int union_h = 0;
                        for (const auto& other : client.monitors()) {
                            origin_x = std::min(origin_x, other.left);
                            origin_y = std::min(origin_y, other.top);
                        }
                        for (const auto& other : client.monitors()) {
                            union_w = std::max(union_w, other.right - origin_x + 1);
                            union_h = std::max(union_h, other.bottom - origin_y + 1);
                        }
                        int dx = 0;
                        int dy = 0;
                        rtsc::client::MapMonitorPointToDesktop(
                            m.left, m.top, origin_x, origin_y, union_w, union_h,
                            static_cast<int>(ev.x), static_cast<int>(ev.y), dx, dy);
                        ev.x = static_cast<uint16_t>(dx);
                        ev.y = static_cast<uint16_t>(dy);
                    }
                } else {
                    // Client-side view controls: Ctrl+wheel and the menu presets
                    // are ours; a plain wheel belongs to the remote desktop (it
                    // used to be swallowed by the zoom handler, so the remote
                    // never scrolled). Menu commands are never forwarded.
                    if (ev.kind == rtsc::ui::InputEvent::Kind::kMouseWheel &&
                        zs.ctrl) {
                        consumed = rtsc::client::ApplyZoomInput(ev, zs);
                    } else if (ev.kind != rtsc::ui::InputEvent::Kind::kMouseWheel) {
                        consumed = rtsc::client::ApplyZoomInput(ev, zs);
                    }
                    if (consumed) {
                        client.graphics().set_zoom(zs.zoom);
                        client.graphics().set_fit(zs.fit);
                        view_dirty = true;
                        const std::string status = rtsc::client::ZoomStatusText(zs);
                        windows[0]->SetTitle(status);
                        // Keep the View menu ticked in sync with the zoom/fit
                        // state (matches the title-bar status line).
                        menu_state.zoom = zs.zoom;
                        menu_state.fit = zs.fit;
                        windows[0]->SetViewMenuState(menu_state);
                        std::printf("view: %s\n", status.c_str());
                    } else if (ev.kind == rtsc::ui::InputEvent::Kind::kMouseMove ||
                               ev.kind ==
                                   rtsc::ui::InputEvent::Kind::kMouseButton ||
                               ev.kind ==
                                   rtsc::ui::InputEvent::Kind::kMouseWheel) {
                        // While zoomed/fitted the local pointer must be mapped
                        // back to the remote desktop coordinate under it.
                        const auto vt = client.graphics().view_transform(
                            static_cast<int>(windows[0]->surface().width()),
                            static_cast<int>(windows[0]->surface().height()));
                        int rx = 0, ry = 0;
                        rtsc::client::MapViewportPoint(
                            vt, static_cast<int>(client.surface().width()),
                            static_cast<int>(client.surface().height()),
                            static_cast<int>(ev.x), static_cast<int>(ev.y), rx,
                            ry);
                        ev.x = static_cast<uint16_t>(rx);
                        ev.y = static_cast<uint16_t>(ry);
                    }
                }
                if (consumed) continue;
                // Post-active input is application data on the secured
                // transport. SendInput lets the connection driver pick the
                // framing: TLS/CredSSP sends the Fast-Path PDU unchanged,
                // Standard RDP Security puts it in MCS and applies RC4.
                std::string input_error;
                if (!client.SendInput(*transport, ev, input_error)) {
                    std::printf("input write failed: %s\n",
                                input_error.c_str());
                    for (auto& w : windows) w->Close();
                    break;
                }
                ++input_sends;
            }
        }

        // A window resize invalidates the current frame (the backend recreated
        // its surface), so the next render must repaint.
        for (const auto& w : windows) {
            if (static_cast<int>(w->surface().width()) != last_view_w ||
                static_cast<int>(w->surface().height()) != last_view_h) {
                last_view_w = static_cast<int>(w->surface().width());
                last_view_h = static_cast<int>(w->surface().height());
                view_dirty = true;
            }
        }

        // Render only when the surface or the view changed, and at most at
        // ~60 FPS. On an idle session neither is true, so the loop just waits
        // out the read timeout: this is what stops an idle remote desktop from
        // pinning a core.
        if (view_dirty || client.graphics().dirty()) {
            const auto now = std::chrono::steady_clock::now();
            if (now - last_render >= kMinFrameInterval) {
                // Only the changed part of the remote surface is re-composited
                // and re-uploaded. A full repaint (first frame, resize, zoom or
                // fit change) passes the whole viewport. The 16 ms gate above
                // stays in force either way: an update is never painted the
                // instant it arrives, only on the next frame boundary.
                const rtsc::client::Rect dirty =
                    view_dirty
                        ? rtsc::client::Rect{0, 0,
                                             static_cast<int>(windows[0]->surface().width()),
                                             static_cast<int>(windows[0]->surface().height())}
                        : client.graphics().dirty_region();
                if (multi_window) {
                    for (size_t i = 0; i < windows.size(); ++i) {
                        rtsc::client::Rect local;
                        if (!client.graphics().RenderMonitorTo(
                                i, windows[i]->surface(), dirty, local)) {
                            continue;  // this monitor saw no change
                        }
                        windows[i]->PresentRect(local.left, local.top,
                                                local.width(), local.height());
                    }
                } else {
                    client.graphics().RenderTo(windows[0]->surface(), dirty);
                    windows[0]->PresentRect(dirty.left, dirty.top,
                                            dirty.width(), dirty.height());
                }
                client.graphics().clear_dirty();
                view_dirty = false;
                last_render = now;
                ++renders;
                ++fps_renders;
                client.NoteFrame();
            }
        }

        ++frames;
        ++fps_frames;
        const auto now = std::chrono::steady_clock::now();
        if (now - last_fps >= std::chrono::seconds(1)) {
            const double secs =
                std::chrono::duration<double>(now - last_fps).count();
            std::printf(
                "fps: %.1f loop, %.1f rendered over %.1f s (%.1f ms/frame)\n",
                fps_frames / secs, fps_renders / secs, secs,
                secs * 1000.0 / static_cast<double>(fps_frames));
            last_fps = now;
            fps_frames = 0;
            fps_renders = 0;
        }

        // Bounded run for automation only. The default is unlimited, so a real
        // session (win32) renders until the window is closed.
        if (max_frames > 0 && frames >= static_cast<unsigned>(max_frames)) break;
        if (max_seconds > 0 &&
            std::chrono::duration_cast<std::chrono::seconds>(now - started)
                    .count() >= max_seconds) {
            break;
        }
    }

    // Surface statistics: a real session renders a non-trivial image (the
    // desktop), not a blank surface. Report non-black pixels and the number of
    // distinct colours so a run can be judged without a display. The same
    // statistics are reported for the scaled view (the window surface), which
    // verifies that scaling did not blank the image.
    {
        const auto count_non_black = [](const rtsc::ui::Surface& s) {
            const uint8_t* p = s.data();
            const size_t n = static_cast<size_t>(s.width()) * s.height();
            size_t non_black = 0;
            std::vector<uint32_t> colours;
            // Sample the WHOLE surface. The previous version pushed only the
            // first 1024 pixels (one row of a 1280-wide desktop), so a surface
            // whose first row was uniform reported 1 distinct colour even though
            // the rest of it was a full gradient. That made the only diagnostic
            // an operator has for 'is the desktop actually painted?' blind to
            // everything below row 0.
            colours.reserve(n);
            for (size_t i = 0; i < n; ++i) {
                const uint32_t v = static_cast<uint32_t>(p[i * 4]) |
                                    (static_cast<uint32_t>(p[i * 4 + 1]) << 8) |
                                    (static_cast<uint32_t>(p[i * 4 + 2]) << 16);
                if (v != 0) ++non_black;
                colours.push_back(v);
            }
            std::sort(colours.begin(), colours.end());
            const size_t distinct = static_cast<size_t>(
                std::unique(colours.begin(), colours.end()) - colours.begin());
            return std::pair<size_t, size_t>(non_black, distinct);
        };

        const auto& s = client.surface();
        const auto remote = count_non_black(s);
        std::printf(
            "surface: %ux%u, %zu pixels, %zu non-black, %zu distinct colours\n",
            static_cast<unsigned>(s.width()), static_cast<unsigned>(s.height()),
            static_cast<size_t>(s.width()) * s.height(), remote.first,
            remote.second);

        const auto& view = windows[0]->surface();
        const auto vt = client.graphics().view_transform(
            static_cast<int>(view.width()), static_cast<int>(view.height()));
        const auto scaled = count_non_black(view);
        std::printf(
            "view: %ux%u -> %dx%d at (%d,%d), scale %.3f (%s), %zu non-black\n",
            static_cast<unsigned>(s.width()), static_cast<unsigned>(s.height()),
            vt.width, vt.height, vt.x, vt.y, vt.scale,
            zs.fit ? "fit" : "zoom", scaled.first);

        // Lossless check: in the default 1:1 view the window surface must be a
        // byte-for-byte copy of the remote surface (no scaling loss).
        if (!zs.fit && zs.zoom == 1.0 &&
            vt.width == static_cast<int>(s.width()) &&
            vt.height == static_cast<int>(s.height()) && vt.x == 0 && vt.y == 0) {
            const bool identical = view.size() == s.size() &&
                                   std::memcmp(view.data(), s.data(), view.size()) == 0;
            std::printf("lossless 1:1: %s (%zu bytes compared)\n",
                        identical ? "bit-exact" : "MISMATCH", view.size());
        }
    }

    std::printf("virtual channel chunks: rdpdr=%u cliprdr=%u rail=%u\n", vc_rdpdr,
                vc_cliprdr, vc_rail);
#if defined(_WIN32)
    std::printf(
        "rdpusb: %s, devices added=%u skipped=%u\n",
        rdpusb != nullptr
            ? (usb_devices_added ? (rdpusb->ready() ? "ready" : "not-ready")
                                 : "not-started")
            : "off",
        usb_devices_added_count, usb_devices_skipped);
#endif
    std::printf("application sends: input=%u channel=%u\n", input_sends,
                channel_sends);
    std::printf(
        "rail: pdus=%u window_moves=%u minmax=%u taskbar=%u langbar=%u "
        "exec=%u exec_results=%u appid_req=%u appid_resp=%u incomplete=%u "
        "sent=%u\n",
        client.rail().pdu_count(), client.rail().window_move_count(),
        client.rail().minmax_info_count(), client.rail().taskbar_count(),
        client.rail().langbar_count(), client.rail().exec_count(),
        client.rail().exec_result_count(), client.rail().get_app_id_req_count(),
        client.rail().get_app_id_resp_count(),
        client.rail().incomplete_message_count(), client.rail().send_count());
    if (client.rail().has_app_id()) {
        std::printf("rail: appid window=%u appid=%s\n",
                    static_cast<unsigned>(client.rail().app_id_window()),
                    "received");
    }
    if (client.rail().has_exec_result()) {
        std::printf("rail: exec_result=%u raw=%u\n",
                    static_cast<unsigned>(client.rail().exec_result().exec_result),
                    static_cast<unsigned>(client.rail().exec_result().raw_result));
    }
    std::printf(
        "clipboard: long_names=%s remote_formats=%zu caps_sent=%u "
        "server_caps=%u remote_lists=%u local_lists=%u responses=%u "
        "data_req=%u data_resp_sent=%u data_resp=%u temp_dir=%s "
        "locks=%u/%u\n",
        cliprdr.long_format_names() ? "yes" : "no",
        cliprdr.remote_formats().size(), cliprdr.clip_caps_count(),
        cliprdr.server_caps_count(), cliprdr.remote_format_list_count(),
        cliprdr.local_format_list_count(), cliprdr.format_list_response_count(),
        cliprdr.format_data_request_count(),
        cliprdr.format_data_response_sent_count(),
        cliprdr.format_data_response_count(), cliprdr.temp_directory().c_str(),
        cliprdr.lock_clipdata_count(), cliprdr.unlock_clipdata_count());
    const auto& audio_format = rdpsnd.selected_format();
    std::printf(
        "audio: server_formats=%u client_formats=%u quality_mode=%u wave2=%u "
        "confirms=%u training=%u close=%u played=%zu received=%s\n",
        rdpsnd.server_formats_count(), rdpsnd.client_formats_count(),
        rdpsnd.quality_mode_count(), rdpsnd.wave2_count(),
        rdpsnd.wave_confirm_count(), rdpsnd.training_confirm_count(),
        rdpsnd.close_count(), rdpsnd.bytes_played(),
        rdpsnd.audio_received() ? "yes" : "no");
    std::printf(
        "audio: backend %s, server version %u, selected format %u Hz %u ch "
        "%u-bit PCM\n",
        audio_sink->ok() ? "ok" : "unavailable",
        static_cast<unsigned>(rdpsnd.server_version()),
        static_cast<unsigned>(audio_format.samples_per_sec),
        static_cast<unsigned>(audio_format.channels),
        static_cast<unsigned>(audio_format.bits_per_sample));
    std::printf("rtsc_gui: %u loop frames, %u rendered (%.1f fps loop)\n", frames,
                renders,
                static_cast<double>(frames) /
                    std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - started)
                        .count());
    return 0;
}
