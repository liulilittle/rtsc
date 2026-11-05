// One-at-a-time command queue between the debug channel's HTTP thread and the
// UI thread. See the header for the threading contract.

#include "rtsc/debug/pending_command_queue.h"

#include <chrono>

namespace rtsc::debug {

std::string PendingCommandQueue::Run(const std::string& json_body) {
    PendingCommand cmd;
    cmd.body = json_body;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        queue_.push_back(&cmd);
        ++enqueued_;
    }
    cv_.notify_all();

    std::unique_lock<std::mutex> lk(mutex_);
    // Bounded: the render loop drains this every iteration, and a debugger must
    // never hang the HTTP thread on a stalled UI.
    const bool finished = cv_.wait_for(lk, std::chrono::seconds(2),
                                       [&] { return cmd.done; });
    if (!finished) {
        // The command may still be in the deque (UI thread not running). Remove
        // it so a later Pop() does not answer into a dead stack frame.
        for (auto it = queue_.begin(); it != queue_.end(); ++it) {
            if (*it == &cmd) {
                queue_.erase(it);
                break;
            }
        }
        return "\"ok\":false,\"error\":\"ui thread did not answer\"";
    }
    return cmd.reply;
}

bool PendingCommandQueue::Pop(PendingCommand& out) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (queue_.empty()) return false;
    PendingCommand* cmd = queue_.front();
    queue_.pop_front();
    in_flight_ = cmd;
    // Copy the body so the caller works on stable storage; the reply is written
    // back through Answer().
    out.body = cmd->body;
    out.reply.clear();
    out.done = false;
    return true;
}

void PendingCommandQueue::Answer(const std::string& reply) {
    PendingCommand* cmd = nullptr;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        cmd = in_flight_;
        in_flight_ = nullptr;
        if (cmd == nullptr) return;
        cmd->reply = reply;
        cmd->done = true;
    }
    cv_.notify_all();
}

unsigned PendingCommandQueue::enqueued() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return enqueued_;
}

}  // namespace rtsc::debug
