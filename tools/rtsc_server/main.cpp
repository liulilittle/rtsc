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
//   --width W         default desktop width (default 1280)
//   --height H        default desktop height (default 1024)
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
        "                       [--test-pattern] [--monitor N] [--width W]\n"
        "                       [--height H] [--once] [--seconds N] [--log FILE]\n",
        kVersion);
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
        } else if (arg == "--test-pattern") {
            opt.test_pattern = true;
        } else if (arg == "--monitor") {
            std::string v;
            if (!need(v)) return false;
            opt.monitor = std::atoi(v.c_str());
        } else if (arg == "--width") {
            std::string v;
            if (!need(v)) return false;
            opt.width = static_cast<uint16_t>(std::atoi(v.c_str()));
        } else if (arg == "--height") {
            std::string v;
            if (!need(v)) return false;
            opt.height = static_cast<uint16_t>(std::atoi(v.c_str()));
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
    size_t seen = 0;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(opt.seconds);
    const bool bounded = opt.seconds > 0;
    for (;;) {
        const size_t count = server.session_count();
        if (count != seen) {
            seen = count;
            log.line("session accepted (count=" + std::to_string(seen) + ")");
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
