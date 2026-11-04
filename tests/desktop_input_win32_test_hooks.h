// Test-only seam into the Win32 desktop input sink.
//
// The production backend starts a worker thread and calls SendInput, so it cannot
// be driven directly by the desktop_input suite. The test build of
// src/server/desktop_input_win32.cpp (RTSC_DESKTOP_INPUT_TESTING) exposes just
// enough to reproduce the teardown failure paths without injecting real input:
//   * a hook that makes AppendReleasesLocked throw std::bad_alloc, so the
//     "synthetic ups could not be queued" branch can be observed;
//   * a way to seed the session's pressed set without enqueueing a real press
//     (no SendInput ever runs);
//   * read-only views of the state the teardown paths must leave behind
//     (sessions erased, forget request drained, worker joined).
#pragma once

#if defined(RTSC_DESKTOP_INPUT_TESTING)

#include <cstddef>
#include <cstdint>
#include <memory>

// Self-contained: DesktopInputEmitHook below names PlatformInput, which lives
// in desktop_input_map.h, NOT in desktop_input.h. Including only
// desktop_input.h used to compile solely because every caller happened to
// include the map header first (an implicit include-order dependency that
// fails with C2143/C4430 on a standalone include).
#include "rtsc/server/desktop_input.h"
#include "rtsc/server/desktop_input_map.h"

namespace rtsc::server {

// Returns true when the item at `item_index` of this session's synthetic release
// append must fail as if the queue allocation threw std::bad_alloc.
using DesktopInputAppendFailureHook = bool (*)(uint32_t session_id,
                                               size_t item_index);

void SetDesktopInputAppendFailureHook(DesktopInputAppendFailureHook hook);

// Returns true when the next worker Dispatch of `session_id` must fail as if
// the platform call threw. The worker catches it, counts it in
// InputStats::worker_failures and keeps draining; this is the only seam that
// makes the worker_failures counter increase, so a deleted count point (or a
// changed catch) turns the suite red instead of staying silently green.
using DesktopInputDispatchFailureHook = bool (*)(uint32_t session_id);

void SetDesktopInputDispatchFailureHook(DesktopInputDispatchFailureHook hook);

// The Win32 sink with the test hooks; the normal factory is compiled out in the
// test build so the suite keeps the null sink for its accounting test.
std::unique_ptr<DesktopInputSink> MakeWin32DesktopInputSinkForTest();

// Seeds one held key directly (never queued, never sent to the desktop).
void DesktopInputTestSeedPressedKey(DesktopInputSink* sink, uint32_t session_id,
                                    uint16_t scancode, bool extended);

size_t DesktopInputTestSessionCount(DesktopInputSink* sink);
// Sessions whose ReleaseSession asked the worker to forget them and that the
// worker has not drained yet. A worker that was never woken leaves this non-zero.
size_t DesktopInputTestPendingForgetCount(DesktopInputSink* sink);

// Runs the same teardown the destructor runs, while the object is still alive,
// so its post-conditions can be asserted.
void DesktopInputTestShutdown(DesktopInputSink* sink);

bool DesktopInputTestWorkerFinished(DesktopInputSink* sink);
bool DesktopInputTestWorkerJoinable(DesktopInputSink* sink);

// True while the worker is parked in the queue wait (set under the queue mutex
// before cv_.wait, cleared after it returns). Lets a case establish "the worker
// is asleep" as a deterministic precondition instead of racing it: without that
// the worker's first loop can drain the request on its own, and a removed
// notify_one would still look green.
bool DesktopInputTestWorkerWaiting(DesktopInputSink* sink);

// Events dropped because they have no platform form at all (a bare kMouse, a
// zero scan code, kSync, ...). Not part of InputStats: this hook exists so a
// test can prove a geometry fail-closed move is counted ONLY in
// InputStats::dropped_unmapped and never additionally here.
size_t DesktopInputTestDroppedUnsupported(DesktopInputSink* sink);

// Every platform action actually emitted (BuildNative succeeded), recorded on
// the worker thread. Lets a test assert WHAT was sent and in which order
// without depending on wall-clock timing or a real cursor.
//
// Both this hook and SetDesktopInputTestMoveIntervalMs are PROCESS-GLOBAL, not
// per sink: every sink in the process shares them. The suite relies on the
// EmitHooksForTest guard (one live sink per case, restored in its destructor)
// rather than on any isolation. A test that needs two concurrently live sinks
// with different expectations would see them interleave in one recorder.
using DesktopInputEmitHook = void (*)(const PlatformInput& input);
void SetDesktopInputTestEmitHook(DesktopInputEmitHook hook);

// Overrides the 4 ms move interval for every sink in the process (0 restores
// the production default). Tests use a long interval so "pending" is
// deterministic, never the real 4 ms.
void SetDesktopInputTestMoveIntervalMs(int64_t ms);

// Sizes of the worker-owned move maps, published by the worker after every
// mutation. acquire/release gives a race-free read, but it is EVENTUAL
// consistency only: a size observed here proves that store happened-before
// this load, NOT that the worker will emit nothing afterwards. A queued item
// can still be dispatched after the observer's read, so a test must poll with
// WaitUntil instead of treating a single observation as a barrier. The one
// point that does have a full happens-before edge is the publish after the
// worker is joined in Shutdown().
size_t DesktopInputTestPendingMoveCount(DesktopInputSink* sink);
size_t DesktopInputTestLastMoveSentCount(DesktopInputSink* sink);

}  // namespace rtsc::server

#endif  // RTSC_DESKTOP_INPUT_TESTING
