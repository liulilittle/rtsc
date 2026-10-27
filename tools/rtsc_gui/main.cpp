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
#include "rtsc/audio/audio_sink.h"
#include "rtsc/channel/cliprdr_client.h"
#include "rtsc/channel/rdpsnd_client.h"
#include "rtsc/clipboard/clipboard.h"
#include "rtsc/client/client.h"
#include "rtsc/client/session_info.h"
#include "rtsc/client/version.h"
#include "rtsc/client/view.h"
#include "rtsc/net/transport.h"
#include "rtsc/proto/connect_machine.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/security/connection_driver.h"
#include "rtsc/ui/clipboard_bind.h"
#include "rtsc/ui/window.h"
#include "rtsc/util/crash_guard.h"

namespace {

constexpr const char* kVersion = "rtsc_gui " RTSC_VERSION_STRING;

// TEMPORARY INSTRUMENTATION (interaction-batch verification): when
// RTSC_DUMP_SURFACE is set, dump the client and view surfaces to BMP files
// once the first frames have been composited. Removed after use.
void DumpSurfaceBmp(const char* path, const rtsc::ui::Surface& s) {
    FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") != 0 || f == nullptr) {
        std::printf("surface dump failed: %s\n", path);
        return;
    }
    const uint32_t w = s.width();
    const uint32_t h = s.height();
    const uint32_t row = w * 4;
    const uint32_t data_size = row * h;
    uint8_t hdr[54] = {};
    hdr[0] = 'B';
    hdr[1] = 'M';
    const auto w32 = [&](size_t p, uint32_t v) {
        hdr[p] = static_cast<uint8_t>(v & 0xFF);
        hdr[p + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        hdr[p + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        hdr[p + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    };
    w32(2, 54 + data_size);
    w32(10, 54);
    w32(14, 40);
    w32(18, w);
    w32(22, h);
    hdr[26] = 1;
    hdr[28] = 32;
    w32(34, data_size);
    std::fwrite(hdr, 1, 54, f);
    std::vector<uint8_t> r(row);
    for (int y = static_cast<int>(h) - 1; y >= 0; --y) {
        const uint8_t* src = s.data() + static_cast<size_t>(y) * row;
        for (uint32_t x = 0; x < w; ++x) {
            r[x * 4 + 0] = src[x * 4 + 2];
            r[x * 4 + 1] = src[x * 4 + 1];
            r[x * 4 + 2] = src[x * 4 + 0];
            r[x * 4 + 3] = 255;
        }
        std::fwrite(r.data(), 1, row, f);
    }
    std::fclose(f);
    std::printf("surface dump: %s (%ux%u)\n", path, w, h);
}

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
        "  --frames N / --seconds N: bound the run (automation only). The default\n"
        "  is unlimited, so a real session renders until the window is closed.\n"
        "  In-session: wheel zooms, Ctrl+wheel zooms finely, Ctrl+1..4 select\n"
        "  100/125/150/200%%, Ctrl+0 fits; the View menu offers the same.\n",
        kVersion);
}

rtsc::security::ConnectionDriver MakeDriver(const std::string& host,
                                            const std::string& domain,
                                            const std::string& user,
                                            const std::string& password,
                                            bool standard_rdp,
                                            bool rail_mode) {
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
    if (rail_mode) {
        mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd", "rail"};
    } else {
        mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
    }

    rtsc::proto::ConnectMachine::Credentials creds;
    creds.domain = domain;
    creds.user_name = user;
    creds.password = password;

    rtsc::security::Config scfg;
    scfg.tls_config.peer_host = host;
    scfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    scfg.credentials.domain = domain;
    scfg.credentials.user = user;
    scfg.credentials.password = password;

    return rtsc::security::ConnectionDriver(mcfg, creds, scfg);
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
        args.emplace_back(a);
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
    // View options: zoom (1.0 = 1:1) and fit. The default is 1:1 lossless
    // (zoom 100%, fit off); an explicit fit=1 switches to smart sizing.
    const bool has_zoom = args.size() >= 9 && std::atof(args[8].c_str()) > 0.0;
    const double zoom_arg = has_zoom ? std::atof(args[8].c_str()) : 1.0;
    const bool fit_arg =
        args.size() >= 10 ? std::atoi(args[9].c_str()) != 0 : false;
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
    auto transport = rtsc::net::ConnectTcp(host, port, error);
    if (!transport) {
        std::printf("connect failed: %s\n", error.c_str());
        return 1;
    }

    rtsc::client::Client client(
        MakeDriver(host, domain, user, password, standard_rdp, rail_mode), width,
     height);

    // View (zoom / fit) state. The controller owns the state; the pipeline owns
    // the rendering. The default is 1:1 lossless: zoom 100% and fit off, so the
    // rendered frame is a pixel-for-pixel copy of the remote desktop.
    rtsc::client::ZoomState zs;
    zs.zoom = zoom_arg;
    zs.fit = fit_arg;
    client.graphics().set_zoom(zs.zoom);
    client.graphics().set_fit(zs.fit);

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

    rtsc::channel::RdpsndClient rdpsnd(audio_sink.get(), send_rdpsnd);
    client.RegisterChannel(kChannelRdpdr,
                           [&](const uint8_t*, size_t) { ++vc_rdpdr; });
    client.RegisterChannel(kChannelCliprdr,
                           [&](const uint8_t* data, size_t size) {
                               ++vc_cliprdr;
                               cliprdr.OnChannelData(data, size);
                           });
    client.RegisterChannel(kChannelRdpsnd,
                           [&](const uint8_t* data, size_t size) {
                               rdpsnd.OnChannelData(data, size);
                           });
    if (!client.Connect(*transport, error)) {
        std::printf("connection failed: %s\n", error.c_str());
        return 1;
    }
    cliprdr.Start();

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
    rtsc::ui::BindClipboardToWindows(
        windows, [&] { cliprdr.OnLocalClipboardChanged(); });
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
    while (!all_closed()) {
        // Pump() waits at most kReadTimeoutMs for network data, so this loop
        // iterates several times a second even when the server is silent. That
        // is what keeps the Win32 window responsive: PollEvent() below runs
        // every iteration and its PeekMessageW is non-blocking, so keyboard and
        // mouse input is forwarded to the server promptly instead of the message
        // queue being starved while a blocking recv() waited on a quiet peer.
        if (!client.Pump(*transport, error)) {
            std::printf("session ended: %s\n", error.c_str());
            break;
        }

        for (size_t wi = 0; wi < windows.size(); ++wi) {
            rtsc::ui::InputEvent ev;
            while (windows[wi]->PollEvent(ev)) {
                if (ev.kind == rtsc::ui::InputEvent::Kind::kClose) {
                    for (auto& w : windows) w->Close();
                    break;
                }
                bool consumed = false;
                if (multi_window) {
                    // Each window is 1:1 with its monitor, so the local pointer
                    // is offset into the virtual desktop coordinate space. There
                    // is no zoom in this mode.
                    if (ev.kind == rtsc::ui::InputEvent::Kind::kMouseMove ||
                        ev.kind == rtsc::ui::InputEvent::Kind::kMouseButton ||
                        ev.kind == rtsc::ui::InputEvent::Kind::kMouseWheel) {
                        const auto& m = client.monitors()[wi];
                        ev.x = static_cast<uint16_t>(static_cast<int>(ev.x) +
                                                     m.left);
                        ev.y = static_cast<uint16_t>(static_cast<int>(ev.y) +
                                                     m.top);
                    }
                } else {
                    // Client-side view controls first: a consumed event (wheel
                    // zoom, Ctrl+digit / menu preset) is never forwarded to the
                    // server.
                    consumed = rtsc::client::ApplyZoomInput(ev, zs);
                    if (consumed) {
                        client.graphics().set_zoom(zs.zoom);
                        client.graphics().set_fit(zs.fit);
                        view_dirty = true;
                        const std::string status = rtsc::client::ZoomStatusText(zs);
                        windows[0]->SetTitle(status);
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
                if (multi_window) {
                    for (size_t i = 0; i < windows.size(); ++i) {
                        client.graphics().RenderMonitorTo(i, windows[i]->surface());
                        windows[i]->Present();
                    }
                } else {
                    client.graphics().RenderTo(windows[0]->surface());
                    windows[0]->Present();
                }
                client.graphics().clear_dirty();
                view_dirty = false;
                last_render = now;
                ++renders;
                ++fps_renders;
                if (renders == 3) {
                    // TEMPORARY INSTRUMENTATION (interaction-batch): one-shot
                    // surface dump for offline orientation analysis.
                    char dump_base[MAX_PATH] = {};
                    size_t dump_len = 0;
                    if (getenv_s(&dump_len, dump_base, sizeof(dump_base),
                                 "RTSC_DUMP_SURFACE") == 0 &&
                        dump_len > 0) {
                        const std::string base = dump_base;
                        DumpSurfaceBmp((base + ".client.bmp").c_str(),
                                       client.surface());
                        DumpSurfaceBmp((base + ".view.bmp").c_str(),
                                       windows[0]->surface());
                    }
                }
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
            colours.reserve(1024);
            for (size_t i = 0; i < n; ++i) {
                const uint32_t v = static_cast<uint32_t>(p[i * 4]) |
                                    (static_cast<uint32_t>(p[i * 4 + 1]) << 8) |
                                    (static_cast<uint32_t>(p[i * 4 + 2]) << 16);
                if (v != 0) ++non_black;
                if (colours.size() < 1024) colours.push_back(v);
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
