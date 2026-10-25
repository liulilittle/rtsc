// RDP server: an independent server role for the RTSC protocol stack.
//
// Why this exists
// ---------------
// Windows Home does not expose a Remote Desktop *host* (no TermService, no
// Terminal Services licensing, no domain/Kerberos NLA). RTSC therefore
// implements the server side itself: this module listens on TCP 3389, runs the
// server half of the [MS-RDPBCGR] connection sequence, authenticates the peer
// with its own credential check, and serves a desktop framebuffer. Nothing here
// depends on TermService or on the machine being a member of a domain.
//
// Reference: [MS-RDPBCGR] 3.2/3.3 (server role), 4.1.x (connection sequence),
// 5.3 (standard RDP security), [MS-RDPELE] 1.3 (licensing).
//
// Design summary
// --------------
//   * RdpServer owns the listening socket; every accepted peer gets a
//     RdpSession running on its own thread (one thread per session). The
//     blocking net::Transport makes this the simplest correct model.
//   * Session isolation (D1): every session owns its X.224/MCS state, its
//     security state, its licensing state, its capability sets and its
//     framebuffer. There is no shared mutable static state; a future shared
//     desktop would copy each frame to every writer (single writer per
//     session).
//   * Security: the server generates its own RSA keypair per process, sends a
//     PROPRIETARYSERVERCERTIFICATE, decrypts the client random, and derives
//     per-session RC4 keys. Credentials are validated by a pluggable
//     authenticator (default: accept any) and are never written to disk.
//   * Licensing: a minimal state machine (Server License Request -> client
//     reply -> LICENSE_ERROR_ALERT STATUS_VALID_CLIENT) so mstsc completes the
//     licensing phase without a Terminal Services license server.
//   * Desktop source: a pluggable IDesktopSource. A test pattern is provided
//     for the first milestone; a GDI screen capture is the real-desktop path.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace rtsc::server {

struct ServerConfig {
    uint16_t port = 3389;

    // Negotiated desktop geometry. The client echoes these in the Confirm
    // Active / Client Core Data; the source must be able to produce them.
    uint16_t desktop_width = 1280;
    uint16_t desktop_height = 1024;
    uint16_t color_depth = 32;

    // Standard RDP security parameters ([MS-RDPBCGR] 5.3).
    uint32_t encryption_method = 0x00000008;  // 128-bit
    uint32_t encryption_level = 0x00000002;   // CLIENT_COMPATIBLE
    uint32_t rsa_bits = 1024;

    // When false, Authenticate() is consulted and unknown accounts are
    // rejected. The default is true so a first connection can be established
    // before an account database is wired in.
    bool accept_any_credentials = true;

    // When true, a client that requests external security (SSL / HYBRID / ...)
    // is answered with RDP_NEG_FAILURE. When false (the default) the server
    // falls back to Standard RDP Security, which is the only security it
    // implements in this milestone, so that a peer which only wants TLS can
    // still be served (or rejected by its own policy).
    bool require_external_security = false;

    // The server tells the client how many times it may reconnect with a saved
    // frame. Kept at zero for the first milestone.
    uint32_t session_id = 0;
};

// Produces the desktop image for a session. `rgba` receives
// width * height * 4 bytes, top-down, 8 bits per channel, R at the lowest
// address. Implementations must be usable from one thread per session.
class DesktopSource {
 public:
    virtual ~DesktopSource() = default;
    virtual bool Capture(uint16_t width, uint16_t height,
                         std::vector<uint8_t>& rgba) = 0;
};

// Credentials as sent by the peer in the Client Info PDU.
struct Credentials {
    std::string domain;
    std::string user_name;
    std::string password;
    std::string alternate_shell;
    std::string working_dir;
};

// Returns true when the credentials are accepted. The default implementation
// accepts everything and records the account; a real deployment would check
// the local SAM (LogonUser) or an account database. The password is used only
// for the check and is never persisted.
using Authenticator = std::function<bool(const Credentials&)>;

// One inbound input event decoded from a client Fast-Path input PDU
// ([MS-RDPBCGR] 2.2.8.1.2). The union of fields is interpreted by `kind`; the
// unused fields stay at their defaults. Callbacks run on the session thread, so
// an implementation must not block the session for long.
struct InputEvent {
    enum class Kind : uint8_t {
        kKey,       // scancode (or unicode) keyboard event
        kMouse,     // absolute pointer event
        kWheel,     // mouse wheel
        kSync,      // toggle-key sync
        kUnicode,   // unicode keyboard event
    };

    Kind kind = Kind::kKey;

    // kKey / kUnicode
    uint8_t scancode = 0;
    uint16_t unicode_code = 0;
    bool release = false;
    bool extended = false;

    // kMouse / kWheel
    uint16_t x = 0;
    uint16_t y = 0;
    uint16_t button = 0;   // 1 = left, 2 = middle, 3 = right
    bool button_down = false;
    int16_t wheel_delta = 0;

    // kSync
    uint8_t sync_flags = 0;
};

// Invoked once per decoded input event, on the session thread that received it.
using InputCallback = std::function<void(const InputEvent&)>;

// A deterministic test pattern: a two-axis colour gradient with a bright
// border, so a received frame is immediately recognisable.
std::unique_ptr<DesktopSource> MakeTestPatternSource();

class RdpServer {
 public:
    explicit RdpServer(const ServerConfig& config);
    ~RdpServer();

    RdpServer(const RdpServer&) = delete;
    RdpServer& operator=(const RdpServer&) = delete;

    // Sets the frame source used by every session. The pointer must outlive
    // the server; the server does not take ownership.
    void SetDesktopSource(DesktopSource* source);

    // Sets the credential check (nullptr restores the default accept-all).
    void SetAuthenticator(Authenticator auth);

    // Sets the input-event callback (nullptr clears it). The callback runs on
    // the session thread, once per decoded Fast-Path input event.
    void SetInputCallback(InputCallback cb);

    // Binds and listens. Returns false and fills `error` on failure.
    bool Start(std::string& error);
    // Closes the listener and every live session, then joins their threads.
    // Idempotent.
    void Stop();

    // Accepts and serves connections until Stop() is called. Blocks.
    void Run();

    // Serves exactly one accepted connection to completion. Returns true when
    // a connection was handled. Intended for tests and single-shot runs.
    bool ServeOne();

    // Number of sessions accepted so far.
    size_t session_count() const;
    const std::string& last_error() const { return last_error_; }

 private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    ServerConfig config_;
    DesktopSource* source_ = nullptr;
    Authenticator authenticator_;
    InputCallback input_callback_;
    std::string last_error_;
};

}  // namespace rtsc::server
