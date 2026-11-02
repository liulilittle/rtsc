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
#include <string>

#include "rtsc/server/server.h"

namespace rtsc::server {

// A rectangle in virtual-screen physical pixels. The origin may be negative
// (a monitor left of or above the primary one).
struct InjectRect {
    int32_t x = 0;
    int32_t y = 0;
    int32_t width = 0;
    int32_t height = 0;
};

// Geometry the injected coordinates are expressed in.
//
// `width`/`height` are the negotiated framebuffer the client is drawing into
// (the client's coordinate space). `capture` is the rectangle of the physical
// virtual screen that the framebuffer was captured from, and `desktop` is the
// virtual-desktop bounding box that MOUSEEVENTF_VIRTUALDESK normalizes
// against. The mapping layer walks framebuffer pixel -> capture pixel ->
// physical pixel -> 0..65535.
//
// `mapped` is false when the capture/desktop rectangles are not known (a
// synthetic source, or a session that has not negotiated yet) and
// `pixels_are_physical` is false when the process DPI context could not be
// verified to report physical pixels. Either one makes absolute movement
// fail closed: a move is dropped rather than injected at a wrong position.
// Buttons, wheels and keys are unaffected.
struct InjectGeometry {
    uint16_t width = 0;
    uint16_t height = 0;
    InjectRect capture;
    InjectRect desktop;
    bool mapped = false;
    bool pixels_are_physical = false;
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
// has no worker and always reports zero. `dropped_unmapped` counts absolute
// pointer movements dropped because the session's geometry is not trusted
// (InjectGeometry::mapped or pixels_are_physical is false, or a rectangle is
// degenerate): the move is fail-closed, so this counter is the only visible
// signal. The null backend has no geometry and always reports zero.
struct InputStats {
    size_t injected = 0;
    size_t dropped_queue_full = 0;
    size_t dropped_rate_limited = 0;
    size_t send_failures = 0;
    size_t release_failures = 0;
    size_t worker_failures = 0;
    size_t dropped_unmapped = 0;
};

// The `input stats (...)` log line the shipped host writes. Pure so the line's
// fields and values are asserted directly, instead of by grepping the host's
// source text (a comment or a rename used to satisfy such a test).
std::string FormatInputStats(const char* reason, const InputStats& stats);

// True when `cur` differs from `prev` in any counter, i.e. the host should log
// a new stats line. `dropped_unmapped` is included: a session whose only fault
// is an untrusted geometry must still produce a periodic line (the server can
// note such moves without ever calling Inject).
bool InputStatsChanged(const InputStats& prev, const InputStats& cur);

// The line the host should write on a periodic sample: empty when nothing
// changed (so the host prints nothing and the log does not flood), otherwise
// exactly the `input stats (periodic): ...` line for `current`.
//
// `printed` is null before the first sample. The baseline is always emitted:
// otherwise an operator sees nothing at all until the first counter moves,
// and a host that never receives input produces no periodic line ever -- which
// also made the periodic call site unreachable from an automated run
// (.opencode/plan.md batch 27). A null baseline therefore means "print".
//
// Exists as one function rather than two calls at the call site so the
// decision is covered by a unit test even though a `--seconds` run with no
// peer can only ever reach the baseline branch.
std::string PeriodicInputStatsLine(const InputStats* printed,
                                   const InputStats& current);

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

    // Called when a pure pointer movement was fail-closed BEFORE reaching
    // Inject(): the session does not hold the input lease and the movement
    // cannot be mapped with its geometry (so it must not take the lease).
    // Such a movement never reaches Inject(), yet InputStats::dropped_unmapped
    // documents it as the only visible signal, so the counting has to happen
    // here. A session that already holds the lease goes through Inject(), which
    // counts the same condition itself; implementations must not double count.
    virtual void NoteUnmappableMove(uint32_t session_id) = 0;

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
