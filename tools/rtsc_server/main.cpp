// rtsc_server_host: a minimal host for the RTSC RDP server role.
//
// The in-tree tests drive rtsc::server::RdpServer through the scripted peer in
// tests/test_server*.cpp. This tool exposes the same server to a real client:
// it builds a ServerConfig from the command line, wires the enhanced-security
// (TLS + CredSSP/NTLM) parameters, attaches a desktop capture source, and serves
// until stopped. It is the standalone entry point used to verify the server
// against Windows' own mstsc.exe.
//
// Clipboard redirection (CLIPRDR) is enabled by default: every session serves
// the host clipboard through the server's cliprdr virtual channel. Platforms
// without a clipboard backend fall back to a no-op clipboard (the channel still
// handshakes, it just never reads or writes local data).
//
// Usage:
//   rtsc_server_host [--port N] [--enhanced|--no-enhanced] [--user U]
//                    [--domain D] [--password P] [--any-user]
//                    [--test-pattern] [--monitor N] [--width W] [--height H]
//                    [--once] [--log FILE]
//
//   --port N          listen port (default 3390)
//   --enhanced        enable TLS + CredSSP/NLA (default on)
//   --no-enhanced     Standard RDP Security only
//   --user U          account accepted by CredSSP (default "rtsc")
//   --domain D        domain accepted by CredSSP (default "NTDEV")
//   --password P      password returned by the credential lookup (default
//                     "password"); use --any-user to accept any account name
//   --test-pattern    serve the synthetic test pattern instead of the GDI
//                     desktop capture (Windows-only source)
//   --monitor N       monitor index for the GDI capture (-1 = virtual screen)
//   --allow-any-credentials
//                     accept every client without checking the account name.
//                     DANGEROUS: credential validation is disabled, the
//                     startup log says so in a warning line, and the server
//                     should never be exposed to an untrusted network in this
//                     mode. By default the account carried by the Client Info
//                     PDU must match --user/--domain.
//   --width W         default desktop width (default 1280; valid range
//                     1..65535: zero, negative and non-numeric values are
//                     refused)
//   --height H        default desktop height (default 1024; same range)
//   --once            serve a single accepted connection, then exit
//   --tls-cert FILE   PEM leaf certificate for the TLS server identity
//                     (default: an ephemeral per-process self-signed cert)
//   --tls-key FILE    PEM private key matching --tls-cert; --tls-cert and
//                     --tls-key must be given together, and the key must be
//                     unencrypted
//   --audio MODE      server-side audio capture for the rdpsnd virtual
//                     channel: "off" (default; no capture) or "sine" (a
//                     deterministic 440 Hz test tone through the same source
//                     seam a WASAPI loopback backend will use later)
//   --allow-input     hand the local interactive desktop to the remote client:
//                     inbound keyboard and pointer events are injected with
//                     SendInput (default off). DANGEROUS: the peer can operate
//                     the machine this server runs on (files, browsers, the
//                     foreground window), and every session shares the same
//                     physical desktop. Refused together with --no-enhanced or
//                     --allow-any-credentials unless --allow-input-unverified
//                     is also given.
//   --allow-input-unverified
//                     accept the unsafe --allow-input combination above after
//                     printing a prominent warning. Only for isolated lab use.
//   --log FILE        append human-readable session lines to FILE
//
// The password is only ever handed to the NTLM computation; it is never written
// to disk. The --log file receives session lifecycle lines, not secrets.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include "rtsc/server/desktop_gdi.h"
#endif
#include "rtsc/audio/audio_source.h"
#include "rtsc/clipboard/clipboard.h"
#include "rtsc/net/tls.h"
#include "rtsc/server/desktop_input.h"
#include "rtsc/server/server.h"
#include "rtsc/util/crash_guard.h"

namespace {

constexpr const char* kVersion = "rtsc_server_host 0.1.0";

struct Options {
    uint16_t port = 3390;
    bool enhanced = true;
    std::string user = "rtsc";
    std::string domain = "NTDEV";
    std::string password = "password";
    bool any_user = false;
    bool allow_any_credentials = false;
    bool test_pattern = false;
    int monitor = -1;
    uint16_t width = 1280;
    uint16_t height = 1024;
    bool once = false;
    long seconds = 0;  // 0 = run until stopped
    std::string log_path;
    // Optional server identity (B layer). Empty = the ephemeral A2 certificate.
    std::string tls_cert_path;
    std::string tls_key_path;
    // Server-side audio capture for the rdpsnd virtual channel.
    enum class AudioSource { kOff, kSine };
    AudioSource audio = AudioSource::kOff;  // default: no capture (privacy)
    // Desktop input injection: off by default; the peer can operate the local
    // desktop (a stronger grant than screen viewing).
    bool allow_input = false;
    // Escape hatch for the deliberately unsafe combination of --allow-input
    // with --no-enhanced / --allow-any-credentials.
    bool allow_input_unverified = false;
    // How many sessions may control the shared local desktop at once. 0 means
    // unlimited; the default is 1 (one remote peer operates the desktop).
    size_t max_input_sessions = 1;
};

void usage() {
    std::printf(
        "%s\n"
        "usage: rtsc_server_host [--port N] [--enhanced|--no-enhanced] [--user U]\n"
        "                       [--domain D] [--password P] [--any-user]\n"
        "                       [--allow-any-credentials] [--test-pattern]\n"
        "                       [--monitor N] [--width W] [--height H]\n"
        "                       [--once] [--seconds N] [--audio off|sine]\n"
        "                       [--allow-input] [--allow-input-unverified]\n"
        "                       [--max-input-sessions N]\n"
        "                       [--tls-cert FILE] [--tls-key FILE]\n"
        "                       [--log FILE]\n",
        kVersion);
}

// Case-insensitive ASCII comparison, used for account and domain names.
bool EqualsIgnoreCase(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return true;
}

// Parses a desktop dimension. Only a decimal number in [1, 65535] is accepted:
// a zero value drives the server's frame path into an integer division by zero
// (0xC0000094) and a negative value would wrap around to a huge unsigned
// dimension when stored in the uint16_t field. Both are refused here, before
// the server is built.
bool ParseDimension(const std::string& text, const char* name, uint16_t* out) {
    if (text.empty()) {
        std::printf("invalid %s: empty value (expected 1..65535)\n", name);
        return false;
    }
    long value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') {
            std::printf("invalid %s: '%s' is not a decimal number in 1..65535\n",
                        name, text.c_str());
            return false;
        }
        value = value * 10 + (c - '0');
        if (value > 65535) {
            std::printf("invalid %s: '%s' is outside 1..65535\n", name,
                        text.c_str());
            return false;
        }
    }
    if (value == 0) {
        std::printf("invalid %s: '%s' must be at least 1\n", name, text.c_str());
        return false;
    }
    *out = static_cast<uint16_t>(value);
    return true;
}

// Parses a non-negative decimal count (0 is meaningful for
// --max-input-sessions: it disables the limit). A cap keeps a typo from
// overflowing size_t before the value reaches the server.
bool ParseCount(const std::string& text, const char* name, size_t* out) {
    if (text.empty()) {
        std::printf("invalid %s: empty value (expected a non-negative integer)\n",
                    name);
        return false;
    }
    size_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') {
            std::printf("invalid %s: '%s' is not a non-negative integer\n", name,
                        text.c_str());
            return false;
        }
        value = value * 10 + static_cast<size_t>(c - '0');
        if (value > 1000000) {
            std::printf("invalid %s: '%s' is too large (max 1000000)\n", name,
                        text.c_str());
            return false;
        }
    }
    *out = value;
    return true;
}

// Parses `--key value` / `--flag` pairs. Returns false on a malformed command
// line. Unknown options are reported and rejected.
bool ParseOptions(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const auto need = [&](std::string& out) -> bool {
            if (i + 1 >= argc) {
                std::printf("missing value for %s\n", arg.c_str());
                return false;
            }
            out = argv[++i];
            return true;
        };
        if (arg == "--port") {
            std::string v;
            if (!need(v)) return false;
            opt.port = static_cast<uint16_t>(std::atoi(v.c_str()));
        } else if (arg == "--enhanced") {
            opt.enhanced = true;
        } else if (arg == "--no-enhanced") {
            opt.enhanced = false;
        } else if (arg == "--user") {
            if (!need(opt.user)) return false;
        } else if (arg == "--domain") {
            if (!need(opt.domain)) return false;
        } else if (arg == "--password") {
            if (!need(opt.password)) return false;
        } else if (arg == "--any-user") {
            opt.any_user = true;
        } else if (arg == "--allow-any-credentials") {
            opt.allow_any_credentials = true;
        } else if (arg == "--test-pattern") {
            opt.test_pattern = true;
        } else if (arg == "--monitor") {
            std::string v;
            if (!need(v)) return false;
            opt.monitor = std::atoi(v.c_str());
        } else if (arg == "--width") {
            std::string v;
            if (!need(v)) return false;
            if (!ParseDimension(v, "--width", &opt.width)) return false;
        } else if (arg == "--height") {
            std::string v;
            if (!need(v)) return false;
            if (!ParseDimension(v, "--height", &opt.height)) return false;
        } else if (arg == "--once") {
            opt.once = true;
        } else if (arg == "--audio") {
            std::string v;
            if (!need(v)) return false;
            if (v == "off") {
                opt.audio = Options::AudioSource::kOff;
            } else if (v == "sine") {
                opt.audio = Options::AudioSource::kSine;
            } else {
                std::printf("invalid --audio: '%s' (expected off or sine)\n",
                            v.c_str());
                return false;
            }
        } else if (arg == "--allow-input") {
            opt.allow_input = true;
        } else if (arg == "--allow-input-unverified") {
            opt.allow_input_unverified = true;
        } else if (arg == "--max-input-sessions") {
            std::string v;
            if (!need(v)) return false;
            if (!ParseCount(v, "--max-input-sessions",
                            &opt.max_input_sessions)) {
                return false;
            }
        } else if (arg == "--seconds") {
            std::string v;
            if (!need(v)) return false;
            opt.seconds = std::atol(v.c_str());
        } else if (arg == "--log") {
            if (!need(opt.log_path)) return false;
        } else if (arg == "--tls-cert") {
            if (!need(opt.tls_cert_path)) return false;
        } else if (arg == "--tls-key") {
            if (!need(opt.tls_key_path)) return false;
        } else {
            std::printf("unknown option: %s\n", arg.c_str());
            return false;
        }
    }
    if (opt.tls_cert_path.empty() != opt.tls_key_path.empty()) {
        std::printf("--tls-cert and --tls-key must be given together\n");
        return false;
    }
    return true;
}

// Reads a whole file (the TLS PEM identity) into a string. Returns false and
// prints the reason when the file cannot be opened or is empty.
bool ReadFile(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::printf("cannot open %s\n", path.c_str());
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in),
               std::istreambuf_iterator<char>());
    if (out.empty()) {
        std::printf("empty file: %s\n", path.c_str());
        return false;
    }
    return true;
}

// Serialises session lifecycle lines to the --log file (and stdout). The
// callback runs on the server's session thread, so writes are guarded.
class SessionLog {
  public:
    explicit SessionLog(std::string path) : path_(std::move(path)) {}

    void line(const std::string& text) {
        std::lock_guard<std::mutex> lock(mu_);
        std::printf("%s\n", text.c_str());
        if (path_.empty()) return;
        std::ofstream out(path_, std::ios::app);
        if (out) out << text << "\n";
    }

  private:
    std::string path_;
    std::mutex mu_;
};

}  // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    rtsc::util::InstallCrashGuard("rtsc_server_host");

    Options opt;
    if (argc > 1 && (std::strcmp(argv[1], "-h") == 0 ||
                     std::strcmp(argv[1], "--help") == 0)) {
        usage();
        return 0;
    }
    if (!ParseOptions(argc, argv, opt)) {
        usage();
        return 2;
    }

    // Desktop input injection hands the peer operational control of this
    // machine. It must never be combined silently with a credential policy that
    // verifies nothing: --no-enhanced performs no password check at all, and
    // --allow-any-credentials accepts any account with the literal default
    // password. Refuse to start unless the operator explicitly acknowledges
    // the risk with --allow-input-unverified.
    const bool weakened_credentials = !opt.enhanced || opt.allow_any_credentials;
    const bool unsafe_input = opt.allow_input && weakened_credentials;
    if (unsafe_input && !opt.allow_input_unverified) {
        std::printf(
            "refusing to start: --allow-input requires verified credentials.\n");
        if (!opt.enhanced) {
            std::printf(
                "  conflicting option --no-enhanced: no password check at "
                "all.\n");
        }
        if (opt.allow_any_credentials) {
            std::printf(
                "  conflicting option --allow-any-credentials: every account "
                "is accepted.\n");
        }
        std::printf(
            "  Remove those options, or pass --allow-input-unverified to "
            "accept unauthenticated remote control.\n");
        return 2;
    }

    rtsc::server::ServerConfig cfg;
    cfg.port = opt.port;
    cfg.desktop_width = opt.width;
    cfg.desktop_height = opt.height;
    // Credential policy, set explicitly: the library default is
    // accept_any_credentials=false (the authenticator decides), and this host
    // only widens it when --allow-any-credentials is passed (which is
    // announced below and in the help).
    cfg.accept_any_credentials = opt.allow_any_credentials;
    cfg.enable_enhanced_security = opt.enhanced;
    // The server only consults an installed sink when this is true; the flag
    // mirrors --allow-input so the default configuration never injects.
    cfg.enable_desktop_input = opt.allow_input;
    // Sessions share one physical desktop, so by default only one may hold the
    // input lease at a time. --max-input-sessions 0 is the explicit unlimited
    // setting; values above 1 let several peers operate the same desktop.
    cfg.max_input_sessions = opt.max_input_sessions;
    cfg.tls_config.role = rtsc::tls::Role::kServer;
    cfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    cfg.credssp_version = 6;

    // Optional server identity (B layer): a PEM leaf certificate + key.
    // Mismatched or unreadable identities surface at server.Start() below; the
    // default remains the ephemeral A2 certificate.
    if (!opt.tls_cert_path.empty()) {
        if (!ReadFile(opt.tls_cert_path, cfg.tls_config.server_certificate_pem) ||
            !ReadFile(opt.tls_key_path, cfg.tls_config.server_private_key_pem)) {
            return 2;
        }
    }

    // The CredSSP/NTLM path cannot derive the session key without the account
    // password, so the lookup is mandatory when enhanced security is on. A null
    // lookup rejects every NLA connection.
    const std::string accepted_user = opt.user;
    const std::string accepted_domain = opt.domain;
    const std::string accepted_password = opt.password;
    const bool any_user = opt.any_user;
    cfg.credential_lookup = [accepted_user, accepted_domain, accepted_password,
                             any_user](const std::string& domain,
                                       const std::string& user)
                                -> std::optional<std::string> {
        if (user != accepted_user && !any_user) return std::nullopt;
        if (!domain.empty() && domain != accepted_domain && !any_user) {
            return std::nullopt;
        }
        return accepted_password;
    };

    // Server-side audio capture for the rdpsnd virtual channel (--audio). Off
    // by default: system-audio capture is privacy-sensitive and the operator
    // must opt in explicitly. `sine` drives the deterministic tone through the
    // same AudioCaptureSource seam a WASAPI loopback backend will use later.
    if (opt.audio == Options::AudioSource::kSine) {
        cfg.audio_source_factory = [] {
            return rtsc::audio::CreateSineSource();
        };
    }

    // Clipboard redirection (CLIPRDR): every session serves one shared host
    // clipboard. On platforms without a backend CreatePlatformClipboard()
    // returns nullptr and the no-op NullClipboard keeps the channel handshake
    // running (it just never reads or writes local data). The flag records the
    // real backend for the startup log below.
    //
    // Lifetime: the clipboard must outlive the server object, because the
    // session threads touch it until Stop() joins them. Declared before
    // `server`, it is destroyed after `server` (whose destructor stops it).
    std::unique_ptr<rtsc::clipboard::Clipboard> local_clipboard =
        rtsc::clipboard::CreatePlatformClipboard();
    const bool clipboard_unavailable = (local_clipboard == nullptr);
    if (clipboard_unavailable) {
        local_clipboard = std::make_unique<rtsc::clipboard::NullClipboard>();
    }

    // Desktop input injection (opt-in, --allow-input). The sink owns one worker
    // thread and has the same lifetime contract as the clipboard: session
    // threads call it until Stop() has joined them, so it is declared before
    // `server` and therefore destroyed only after the server has stopped.
    std::unique_ptr<rtsc::server::DesktopInputSink> input_sink;
    if (opt.allow_input) {
        input_sink = rtsc::server::MakeWin32DesktopInputSink();
    }

    SessionLog log(opt.log_path);
    log.line(std::string(kVersion) + " starting");
    log.line("port=" + std::to_string(cfg.port) +
             " enhanced=" + (opt.enhanced ? "true" : "false") +
             " credssp=" + std::to_string(cfg.credssp_version) +
             " account=" + accepted_user + "@" + accepted_domain +
             " desktop=" + std::to_string(cfg.desktop_width) + "x" +
             std::to_string(cfg.desktop_height) +
             " source=" + (opt.test_pattern ? "test-pattern" : "gdi-desktop") +
             " clipboard=" +
             std::string(clipboard_unavailable ? "unavailable (null backend)"
                                               : "enabled") +
             " audio=" +
             std::string(opt.audio == Options::AudioSource::kSine ? "sine"
                                                                   : "off") +
             " input=" + (opt.allow_input ? "on" : "off") +
             " input_max_sessions=" +
             std::to_string(opt.max_input_sessions));
    if (opt.allow_any_credentials) {
        log.line(
            "WARNING: credential validation is DISABLED "
            "(--allow-any-credentials): every client that reaches the server "
            "is accepted. Do not expose this server to an untrusted network.");
    } else {
        log.line("credentials: enforced (account " + accepted_user + "@" +
                 accepted_domain + " from the Client Info PDU)");
    }
    if (opt.allow_input) {
        log.line(
            "WARNING: desktop input injection is ENABLED (--allow-input): the "
            "remote client can move the pointer, type into the foreground "
            "window and operate this machine. Every session shares the same "
            "physical desktop; at most " +
            (opt.max_input_sessions == 0
                 ? std::string("all sessions (unlimited)")
                 : std::to_string(opt.max_input_sessions)) +
            " session(s) may hold the input lease at once.");
    }
    if (unsafe_input && opt.allow_input_unverified) {
        log.line(
            "**************************************************************"
            "********");
        log.line("WARNING: --allow-input-unverified is in effect.");
        log.line(
            "This server combines desktop input injection with a weakened "
            "credential policy");
        log.line(
            "(--no-enhanced and/or --allow-any-credentials). Any client that "
            "reaches the port");
        log.line(
            "can take control of this machine's interactive desktop. Use this "
            "only on an");
        log.line("isolated network with no untrusted peers.");
        log.line(
            "**************************************************************"
            "********");
    }

    // The server serves the same source to every session; it must outlive the
    // server object.
    std::unique_ptr<rtsc::server::DesktopSource> gdi_source;
    std::unique_ptr<rtsc::server::DesktopSource> pattern_source;
    rtsc::server::DesktopSource* source = nullptr;
    if (opt.test_pattern) {
        pattern_source = rtsc::server::MakeTestPatternSource();
        source = pattern_source.get();
    } else {
#ifdef _WIN32
        std::string error;
        gdi_source = rtsc::server::MakeGdiDesktopSource(opt.monitor, 0, 0, 0, 0,
                                                        &error);
        if (!gdi_source) {
            std::printf("GDI desktop capture unavailable: %s\n", error.c_str());
            std::printf("Falling back to the synthetic test pattern.\n");
            pattern_source = rtsc::server::MakeTestPatternSource();
            source = pattern_source.get();
        } else {
            source = gdi_source.get();
        }
#else
        std::printf("GDI capture is Windows-only; using the synthetic test pattern.\n");
        pattern_source = rtsc::server::MakeTestPatternSource();
        source = pattern_source.get();
#endif
    }

    rtsc::server::RdpServer server(cfg);
    // Credential policy. The library default is "do not accept everything", and
    // this host installs an authenticator unless --allow-any-credentials was
    // given. The account carried by the Client Info PDU must then match
    // --user/--domain (case insensitive; "DOMAIN\user" is accepted).
    //
    // Boundary, stated so it is not mistaken for full authentication: this path
    // checks the ACCOUNT NAME only. The Client Info password field is not
    // verified by the server. Password verification happens on the
    // enhanced-security path, where CredSSP/NTLM validates it against the
    // password returned by credential_lookup above (--enhanced, the default).
    // With --no-enhanced there is no password check at all.
    if (!opt.allow_any_credentials) {
        server.SetAuthenticator([accepted_user, accepted_domain, any_user](
                                    const rtsc::server::Credentials& creds) {
            if (any_user) return true;
            std::string user = creds.user_name;
            const size_t sep = user.find_last_of("\\/");
            if (sep != std::string::npos) user = user.substr(sep + 1);
            if (!EqualsIgnoreCase(user, accepted_user)) return false;
            if (!creds.domain.empty() &&
                !EqualsIgnoreCase(creds.domain, accepted_domain)) {
                return false;
            }
            return true;
        });
    }
    server.SetDesktopSource(source);
    server.SetClipboard(local_clipboard.get());
    if (input_sink) server.SetInputSink(input_sink.get());
    // Input events are only forwarded by the session's active loop, so a key or
    // pointer callback is a server-side proof that a session reached the active
    // phase. It is deliberately cheap and logs nothing sensitive.
    server.SetInputCallback([&log](const rtsc::server::InputEvent& ev) {
        const char* kind = "input";
        switch (ev.kind) {
            case rtsc::server::InputEvent::Kind::kKey: kind = "key"; break;
            case rtsc::server::InputEvent::Kind::kMouse: kind = "mouse"; break;
            case rtsc::server::InputEvent::Kind::kWheel: kind = "wheel"; break;
            case rtsc::server::InputEvent::Kind::kSync: kind = "sync"; break;
            case rtsc::server::InputEvent::Kind::kUnicode: kind = "unicode"; break;
        }
        log.line(std::string("session active: ") + kind + " event forwarded");
    });

    std::string error;
    if (!server.Start(error)) {
        std::printf("server start failed: %s\n", error.c_str());
        return 1;
    }
    log.line("listening on 0.0.0.0:" + std::to_string(cfg.port));

    if (opt.once) {
        log.line("serving one connection");
        const bool served = server.ServeOne();
        log.line(served ? "session served; exiting" : "no connection accepted");
        server.Stop();
        return served ? 0 : 1;
    }

    // The accept loop runs on its own thread so the main thread can surface the
    // session counter while the server runs. With --seconds the loop is bounded
    // and the process exits on its own; otherwise it runs until stopped.
    std::thread runner([&server]() { server.Run(); });
    size_t seen_live = 0;
    size_t seen_total = 0;
    bool lease_denied_reported = false;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(opt.seconds);
    const bool bounded = opt.seconds > 0;
    for (;;) {
        // session_count() is the number of sessions alive right now;
        // total_session_count() is the monotonic count of sessions launched
        // (a launcher that refused a thread is not counted). Log both so a
        // disconnect is visibly a live-count drop, not a lost session.
        const size_t live = server.session_count();
        const size_t total = server.total_session_count();
        if (live != seen_live || total != seen_total) {
            seen_live = live;
            seen_total = total;
            log.line("sessions: live=" + std::to_string(live) +
                     " total=" + std::to_string(total));
        }
        // A denied input lease means a session is sending input that the
        // configured cap keeps off the shared desktop. Report the first
        // denial once -- the counter alone would be silent -- and keep
        // counting without one line per event.
        const size_t lease_denied = server.input_lease_denied_count();
        if (!lease_denied_reported && lease_denied != 0) {
            lease_denied_reported = true;
            log.line(
                "WARNING: input lease denied (input_lease_denied_count=" +
                std::to_string(lease_denied) + "): at most " +
                (opt.max_input_sessions == 0
                     ? std::string("all sessions (unlimited)")
                     : std::to_string(opt.max_input_sessions)) +
                " session(s) may inject input at once; the other session's "
                "events are observed but not injected.");
        }
        if (bounded && std::chrono::steady_clock::now() >= deadline) {
            log.line("run window elapsed; stopping");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    server.Stop();
    runner.join();
    return 0;
}
