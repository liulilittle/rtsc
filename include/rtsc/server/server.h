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
#include <optional>
#include <string>
#include <vector>

#include "rtsc/audio/audio_source.h"
#include "rtsc/clipboard/clipboard.h"
#include "rtsc/clipboard/file_list.h"
#include "rtsc/net/tls.h"

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

    // When false, Authenticator() is consulted and unknown accounts are rejected.
    // The default is false so an embedder cannot accept every peer silently.
    // Note the incomplete-authentication boundary: with no authenticator
    // installed the Client Info PDU is accepted as-is, and on the Standard RDP
    // Security path an installed authenticator only sees the account name --
    // the Client Info password field is NOT verified. Password authentication
    // must go through CredSSP/NTLM (enable_enhanced_security +
    // credential_lookup); anything else is transport-level identification, not
    // authentication. Start() emits a WARNING whenever the effective policy is
    // accept-all (this flag true, or no authenticator installed).
    bool accept_any_credentials = false;

    // When true, a client that requests external security (SSL / HYBRID / ...)
    // is answered with RDP_NEG_FAILURE. When false (the default) the server
    // falls back to Standard RDP Security, which is the only security it
    // implements in this milestone, so that a peer which only wants TLS can
    // still be served (or rejected by its own policy).
    bool require_external_security = false;

    // ---- enhanced security (TLS + CredSSP / NLA) --------------------------
    // When false (the default) the server keeps its historical behaviour:
    // PROTOCOL_RDP only. When true, a client that asks for PROTOCOL_SSL or
    // PROTOCOL_HYBRID is answered with the matching protocol and the session
    // runs the TLS accept plus CredSSP before MCS, which is what mstsc needs.
    bool enable_enhanced_security = false;

    // TLS parameters for the server role. `role` is forced to kServer by the
    // session; the caller only needs to set the certificate policy and (for a
    // production deployment) the version window.
    tls::Config tls_config;

    // CredSSP version (5 or 6 recommended).
    uint32_t credssp_version = 6;

    // Account lookup for CredSSP/NTLM. Given the domain and user name from the
    // client's AUTHENTICATE, returns the account password. The server cannot
    // derive the NTLM session key without it, so a null lookup rejects every
    // enhanced-security connection (the TLS leg still completes).
    std::function<std::optional<std::string>(const std::string& domain,
                                             const std::string& user)>
        credential_lookup;

    // Starts the thread that serves one session. Returns false when the
    // platform could not create the thread (thread/handle exhaustion is
    // typically what a connection flood produces), in which case the server
    // drops that connection instead of counting a session that will never run.
    // Empty means "use std::thread detached". Tests inject a failing launcher
    // to cover that path; a deployment may point it at a thread pool.
    using SessionThreadLauncher = std::function<bool(std::function<void()>)>;
    SessionThreadLauncher session_thread_launcher;

    // Runs the server-side rdpdr (device redirection) minimum handshake on
    // every session: Server Announce, capabilities, ClientId Confirm and User
    // LoggedOn. The v1 serves no devices (the client sees an empty redirect
    // list), so enabling this only completes the channel-level negotiation; a
    // peer whose rdpdr support is unwanted can disable it. Enabled by default.
    bool enable_rdpdr_handshake = true;

    // Server-side rdpsnd (audio output): when the static virtual channel is
    // requested by the client, every session runs an RdpsndServer fed by its
    // own capture source created through `audio_source_factory`. The factory
    // is a seam: the deterministic sine source (`rtsc::audio::CreateSineSource`)
    // powers the tests / v1, a future WASAPI loopback backend slots in behind
    // the same interface. Enabled by default so a configured factory is
    // honoured everywhere, but with no factory installed the handler is not
    // created at all, so the default configuration has zero observable change.
    bool enable_rdpsnd = true;
    using AudioSourceFactory =
        std::function<std::unique_ptr<rtsc::audio::AudioCaptureSource>()>;
    AudioSourceFactory audio_source_factory;

    // The server tells the client how many times it may reconnect with a saved
    // frame. Kept at zero for the first milestone.
    uint32_t session_id = 0;
};

// Server-side limits on the negotiated desktop geometry.
//
// [MS-RDPBCGR] 2.2.1.3.2 (TS_CLIENT_CORE_DATA) carries desktopWidth and
// desktopHeight as two uint16 fields, so a client may legally ask for
// 65535 x 65535. The server cannot honour that: the RGBA framebuffer alone
// would be 65535 * 65535 * 4 = 17,179,344,900 bytes (~16 GiB) and the GDI
// source allocates a second buffer of the same size. These limits bound what
// one session may allocate:
//   * 8192 x 8192 px: above every current display (8K UHD is 7680 x 4320) and
//     far below the 65535 the wire format permits.
//   * 32 MiB framebuffer: covers 4K UHD (3840 * 2160 * 4 = 31.6 MiB) and caps
//     a session's framebuffer at 8,388,608 pixels.
// A client-declared geometry is clamped into these limits (the clamped size is
// what Demand Active announces); a configured default outside them is refused
// by Start()/Run()/ServeOne().
constexpr uint16_t kMaxDesktopWidth = 8192;
constexpr uint16_t kMaxDesktopHeight = 8192;
constexpr size_t kMaxFramebufferBytes = 32u * 1024u * 1024u;

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
//
// Scope warning: this hook receives the Client Info PDU, whose password field
// is not verified by the server (it is the account name and domain that are
// checked). Treat this as authorisation by account name only; password
// verification belongs to CredSSP/NTLM (`credential_lookup`).
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
        kMouseRel,  // relative pointer movement (TS_FP_RELPOINTER_EVENT)
    };

    Kind kind = Kind::kKey;

    // kKey / kUnicode
    uint8_t scancode = 0;
    uint16_t unicode_code = 0;
    bool release = false;
    // True when the keyCode is extended with the 0xE0 prefix
    // (FASTPATH_INPUT_KBDFLAGS_EXTENDED, [MS-RDPBCGR] 2.2.8.1.2.2.1). This is
    // a separate flag, NOT the value 0x100 added to the scancode: the prefix
    // is not part of keyCode on the wire.
    bool extended = false;
    // True for FASTPATH_INPUT_KBDFLAGS_EXTENDED1 (0x04), the 0xE1 prefix the
    // PAUSE sequence carries on its CTRL events. Faithful wire report only:
    // the injection seam cannot express 0xE1 through SendInput
    // ([MS-RDPBCGR] 2.2.8.1.2.2.1; see docs/spec/input-injection-seam.md P-6).
    bool extended1 = false;

    // kMouse / kWheel. The wire values are kept verbatim even for kWheel,
    // where they are meaningless: [MS-RDPBCGR] 2.2.8.1.1.3.1.1.3 says xPos and
    // yPos must be ignored for a wheel event, so the injection seam must not
    // emit a move for kWheel (docs/spec/input-injection-seam.md section 4.3).
    uint16_t x = 0;
    uint16_t y = 0;
    uint16_t button = 0;   // 1 = left, 2 = right, 3 = middle, 4 = X1, 5 = X2
    bool button_down = false;
    // kMouse only: PTRFLAGS_MOVE (0x0800) was set, i.e. the pointer must move
    // to (x, y). A button release carries the button bit without MOVE, so this
    // distinguishes "move" from "release" ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.3).
    // A relative event (kMouseRel) leaves this false: it has no absolute
    // position, and moving to (x, y) would teleport the pointer to (0, 0).
    // Consumers must use kind == kMouseRel plus rel_x/rel_y for relative
    // movement.
    bool is_move = false;
    int16_t wheel_delta = 0;  // wire units: WHEEL_DELTA (120) per notch
    // kWheel: set when the event was a PTRFLAGS_HWHEEL event (horizontal
    // scroll); a vertical wheel event leaves it false.
    bool horizontal = false;

    // kMouseRel: SIGNED relative displacement (xDelta/yDelta), unlike the
    // unsigned absolute x/y above ([MS-RDPBCGR] 2.2.8.1.2.2.7). kMouseRel is
    // the marker for relative movement; is_move stays false for it.
    int16_t rel_x = 0;
    int16_t rel_y = 0;

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

    // Sets the local clipboard served by every session's cliprdr virtual
    // channel (nullptr disables clipboard redirection). All sessions share one
    // clipboard (shared-desktop / last-writer-wins semantics); the Win32
    // backend serializes access. The pointer must outlive the server (including
    // Stop()): session threads read and write it until the server has stopped,
    // so the object it points to may be destroyed only after that. The server
    // does not take ownership.
    void SetClipboard(clipboard::Clipboard* clipboard);

    // Sets the file-list provider used by the cliprdr file-serve path (stream
    // file clip). nullptr leaves every file request failing (the v1 default).
    void SetFileListProvider(clipboard::FileListProvider* provider);

    // Binds and listens. Returns false and fills `error` on failure.
    bool Start(std::string& error);
    // Closes the listener and every live session, then joins their threads.
    // Idempotent.
    void Stop();

    // The TCP port the server is actually listening on, or 0 before the first
    // successful bind. Read it only after a successful Start()/Run()/ServeOne()
    // bind; it is not meaningful before that. With ServerConfig::port == 0 the
    // kernel picks a free port at bind time and this is the only way to learn
    // it; a test uses that to avoid racing every other process for a fixed
    // port. The value is captured at bind time, so it stays readable after
    // Stop().
    uint16_t bound_port() const;

    // Accepts and serves connections until Stop() is called. Blocks.
    void Run();

    // Serves exactly one accepted connection to completion. Returns true when
    // a connection was handled. Intended for tests and single-shot runs.
    bool ServeOne();

    // Number of sessions that are alive right now: accepted and not yet
    // finished. It falls back to zero when the client disconnects, because the
    // session object (transport, TLS/CredSSP state and the credential strings)
    // is released when its thread ends.
    size_t session_count() const;
    // Number of sessions launched since Start(): a session is counted only
    // when its thread actually started (see SessionThreadLauncher), so a
    // launcher that refuses the thread (thread/handle exhaustion during a
    // connection flood) does not inflate the count. Monotonic; never reset.
    // Use this for "how many sessions has this server launched" and
    // session_count() for "how many are connected now".
    size_t total_session_count() const;
    const std::string& last_error() const { return last_error_; }

    // Number of fast-path input events rejected because their eventCode is not
    // one of the known types, over the life of this server (monotonic, never
    // reset). The specification says the server SHOULD drop the connection
    // ([MS-RDPBCGR] 2.2.8.1.2.2); this server deliberately stays lenient and
    // only counts, so a capture can be used to identify the offending client
    // version without losing the session. Events that are recognised and
    // deliberately produce no callback (e.g. the QoE timestamp) are NOT
    // counted here.
    size_t unknown_input_event_count() const;

 private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    ServerConfig config_;
    DesktopSource* source_ = nullptr;
    Authenticator authenticator_;
    InputCallback input_callback_;
    // The shared local clipboard for the cliprdr virtual channel, and the
    // shared file-list provider for its file-serve path. Both are borrowed,
    // never owned, and read by every session thread (the Win32 backend
    // serializes clipboard access; the provider must be safe for concurrent
    // reads).
    clipboard::Clipboard* clipboard_ = nullptr;
    clipboard::FileListProvider* file_list_provider_ = nullptr;
    std::string last_error_;

    // Says the accept-all WARNING once, when the effective credential policy
    // accepts every peer. Invoked from Start(), Run() and ServeOne() so the
    // operator sees it no matter which entry point binds the listener.
    void WarnIfAcceptAll();
};

}  // namespace rtsc::server
