// A one-slot-at-a-time command queue between the debug channel's HTTP thread
// and the UI thread.
//
// The HTTP thread must not touch client/window state (the compositor owns it),
// so it parks the command here and blocks until the render loop has answered.
// The wait is bounded: a debugger that hangs the caller on a stalled UI is worse
// than one that reports a timeout.

#pragma once

#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>

namespace rtsc::debug {

struct PendingCommand {
    std::string body;
    std::string reply;
    bool done = false;
};

class PendingCommandQueue {
 public:
    // Called on the HTTP thread: enqueues the command and waits up to `timeout`
    // for the UI thread to answer. Returns the reply, or an ok=false error when
    // the UI thread did not respond in time.
    std::string Run(const std::string& json_body);

    // Called on the UI thread: takes the next queued command. Returns false when
    // nothing is pending, so the render loop never blocks.
    bool Pop(PendingCommand& out);

    // Called on the UI thread: completes the command taken by Pop(), waking the
    // waiting HTTP thread.
    void Answer(const std::string& reply);

    // Number of commands ever enqueued. Diagnostic only.
    unsigned enqueued() const;

 private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<PendingCommand*> queue_;
    PendingCommand* in_flight_ = nullptr;
    unsigned enqueued_ = 0;
};

}  // namespace rtsc::debug
