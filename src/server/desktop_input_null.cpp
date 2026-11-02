// Non-Windows desktop input sink: a counting no-op.
//
// There is no portable way to synthesize input into another application's
// session, so this backend accepts the events and drops them instead of
// pretending to inject. It keeps tools/rtsc_server and the library building on
// every platform with the same factory name; the counters make the drop
// observable to a debugger in the same spirit as NullClipboard.

#include "rtsc/server/desktop_input.h"

#include <atomic>
#include <memory>

namespace rtsc::server {
namespace {

class NullDesktopInputSink final : public DesktopInputSink {
 public:
    void SetGeometry(uint32_t session_id, const InjectGeometry& g) override {
        (void)session_id;
        (void)g;
    }

    void Inject(uint32_t session_id, const InputEvent& ev) override {
        (void)session_id;
        (void)ev;
        dropped_.fetch_add(1, std::memory_order_relaxed);
    }

    void ReleaseSession(uint32_t session_id) override { (void)session_id; }

    InputStats Stats() const override {
        // The null sink "injects" nothing but accepts every event, so the
        // accepted count is what the counters expose (see desktop_input.h).
        // It has no worker queue, so it never rate-limits and
        // dropped_queue_full/dropped_rate_limited stay zero.
        InputStats stats;
        stats.injected = static_cast<size_t>(
            dropped_.load(std::memory_order_relaxed));
        // No queue, so no synthetic up can ever fail to be queued. Explicit so
        // the field is never left to an aggregate default.
        stats.release_failures = 0;
        // No worker thread either, so no iteration can fail.
        stats.worker_failures = 0;
        // The null backend has no geometry, so it never fail-closes a move.
        stats.dropped_unmapped = 0;
        return stats;
    }

 private:
    std::atomic<uint64_t> dropped_{0};
};

}  // namespace

std::unique_ptr<DesktopInputSink> MakeWin32DesktopInputSink() {
    return std::make_unique<NullDesktopInputSink>();
}

}  // namespace rtsc::server
