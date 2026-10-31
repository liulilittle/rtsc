// Desktop input injection seam for the RDP server role.
//
// The server decodes inbound Fast-Path / slow-path input into InputEvent
// (server.h) and can hand every event to a DesktopInputSink. The sink is a
// borrowed pointer owned by the embedder: RdpServer never destroys it and it
// must outlive the server (session threads call Inject() until Stop() has
// joined them), exactly like SetClipboard().
//
// Injection is opt-in twice: ServerConfig::enable_desktop_input must be true
// AND a sink must be installed. The default configuration therefore keeps its
// historical behaviour (input is only observed through SetInputCallback).
//
// Security: injecting into the local interactive desktop hands the remote peer
// control of this machine (pointer, keyboard focus, whatever window is in the
// foreground). See docs/spec/input-injection-seam.md section 2 for the threat
// model and the default-off rationale.

#pragma once

#include <cstdint>
#include <memory>

#include "rtsc/server/server.h"

namespace rtsc::server {

// Geometry the injected coordinates are expressed in: the negotiated desktop
// the client is drawing into (the framebuffer size). The mapping layer
// normalizes (x, y) into Win32's 0..65535 absolute range against it.
struct InjectGeometry {
    uint16_t width = 0;
    uint16_t height = 0;
};

// Receives decoded input for injection. Every method runs on the session thread
// and must return quickly: implementations queue the work and perform the
// platform call on their own worker thread, because a blocked session thread
// would stall that session's whole active loop.
class DesktopInputSink {
 public:
    virtual ~DesktopInputSink() = default;

    // Called when the session's negotiated geometry is known (and again if it
    // is renegotiated). Idempotent.
    virtual void SetGeometry(uint32_t session_id, const InjectGeometry& g) = 0;

    // Called once per decoded input event. Must not block the session thread.
    // session_id identifies the session so a sink can track (and release) the
    // keys and buttons each session holds down.
    virtual void Inject(uint32_t session_id, const InputEvent& ev) = 0;

    // Called when the session ends: releases every key/button that session
    // still holds down. Win32 does not reset the keyboard state, so skipping
    // this leaves the local machine with a stuck modifier or mouse button.
    virtual void ReleaseSession(uint32_t session_id) = 0;
};

// Creates the platform sink. On Windows this is the SendInput backend; on other
// platforms it is a counting no-op so the host builds and runs unchanged.
std::unique_ptr<DesktopInputSink> MakeWin32DesktopInputSink();

}  // namespace rtsc::server
