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

#include "rtsc/server/desktop_input.h"

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

}  // namespace rtsc::server

#endif  // RTSC_DESKTOP_INPUT_TESTING
