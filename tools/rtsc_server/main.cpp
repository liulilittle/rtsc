// rtsc_server_host: a minimal host for the RTSC RDP server role.
//
// The in-tree tests drive rtsc::server::RdpServer through the scripted peer in
// tests/test_server*.cpp. This tool exposes the same server to a real client:
// it builds a ServerConfig from the command line, wires the enhanced-security
// (TLS + CredSSP/NTLM) parameters, attaches a desktop capture source, and serves
// until stopped. It is the standalone entry point used to verify the server
// against Windows' own mstsc.exe.
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
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include "rtsc/server/desktop_gdi.h"
#endif
#include "rtsc/net/tls.h"
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
};

void usage() {
    std::printf(
        "%s\n"
        "usage: rtsc_server_host [--port N] [--enhanced|--no-enhanced] [--user U]\n"
        "                       [--domain D] [--password P] [--any-user]\n"
        "                       [--allow-any-credentials] [--test-pattern]\n"
        "                       [--monitor N] [--width W] [--height H]\n"
        "                       [--once] [--seconds N] [--log FILE]\n",
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
        } else if (arg == "--seconds") {
            std::string v;
            if (!need(v)) return false;
            opt.seconds = std::atol(v.c_str());
        } else if (arg == "--log") {
            if (!need(opt.log_path)) return false;
        } else {
            std::printf("unknown option: %s\n", arg.c_str());
            return false;
        }
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
    cfg.tls_config.role = rtsc::tls::Role::kServer;
    cfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    cfg.credssp_version = 6;

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

    SessionLog log(opt.log_path);
    log.line(std::string(kVersion) + " starting");
    log.line("port=" + std::to_string(cfg.port) +
             " enhanced=" + (opt.enhanced ? "true" : "false") +
             " credssp=" + std::to_string(cfg.credssp_version) +
             " account=" + accepted_user + "@" + accepted_domain +
             " desktop=" + std::to_string(cfg.desktop_width) + "x" +
             std::to_string(cfg.desktop_height) +
             " source=" + (opt.test_pattern ? "test-pattern" : "gdi-desktop"));
    if (opt.allow_any_credentials) {
        log.line(
            "WARNING: credential validation is DISABLED "
            "(--allow-any-credentials): every client that reaches the server "
            "is accepted. Do not expose this server to an untrusted network.");
    } else {
        log.line("credentials: enforced (account " + accepted_user + "@" +
                 accepted_domain + " from the Client Info PDU)");
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
