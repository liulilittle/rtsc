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

#include <cstddef>
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

// Cumulative injection counters, readable at any time (relaxed atomics in the
// Win32 backend). `injected` counts successful platform actions: for the Win32
// sink one successful SendInput call (an event that translates to several
// platform actions, e.g. a combined move+button, counts once per action); the
// null sink counts every Inject call it accepted and then dropped.
// `dropped_queue_full` counts platform actions refused by the bounded injection
// queue (including an older movement evicted to make room for the incoming
// action) or discarded when their session is released (the session-end purge
// drops the session's queued non-synthetic events), `dropped_rate_limited`
// counts platform actions refused by the
// injection rate limiter (400 actions/s and a burst of 800 per session,
// 1000 actions/s and a burst of 2000 globally; only a HELD release -- the up of
// a key/button the session actually holds down -- is exempt and never counted
// here), and `send_failures` counts SendInput calls that did not emit exactly
// one event. `release_failures` counts teardown attempts whose synthetic key
// and button ups could not be queued (an allocation failure while appending
// them): the released keys stay physically down, so the counter is the only
// way an operator can observe a release that was lost. The null backend, which
// has no queue, always reports zero. `worker_failures` counts platform actions
// dropped because one worker iteration threw (an allocation failure while
// dispatching or emitting): the worker survives and keeps draining, but that
// action is lost, so the counter is the only visible signal. The null backend
// has no worker and always reports zero.
struct InputStats {
    size_t injected = 0;
    size_t dropped_queue_full = 0;
    size_t dropped_rate_limited = 0;
    size_t send_failures = 0;
    size_t release_failures = 0;
    size_t worker_failures = 0;
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
    // Also forgets the session's move-rate bookkeeping, so a later session that
    // reuses the id (a restarted server restarts its input ids at 1) is not
    // throttled by the previous session's last-sent timestamp.
    virtual void ReleaseSession(uint32_t session_id) = 0;

    // Snapshot of the cumulative counters; never blocks and is safe to call
    // from any thread.
    virtual InputStats Stats() const = 0;
};

// Creates the platform sink. On Windows this is the SendInput backend; on other
// platforms it is a counting no-op so the host builds and runs unchanged.
std::unique_ptr<DesktopInputSink> MakeWin32DesktopInputSink();

}  // namespace rtsc::server
