// Pure construction / comparison of the host's input-stats log line.
//
// Kept outside tools/rtsc_server/main.cpp so tests can assert the exact fields
// and the change-detection semantics directly. Grepping the host source for a
// counter name was a false test: renaming the printed key while leaving a
// comment with the old name kept it green (see .opencode/discover.md example
// 34).

#include "rtsc/server/desktop_input.h"

#include <string>

namespace rtsc::server {

std::string FormatInputStats(const char* reason, const InputStats& stats) {
    return std::string("input stats (") + (reason != nullptr ? reason : "") +
           "): input_injected=" + std::to_string(stats.injected) +
           " input_dropped_queue=" +
           std::to_string(stats.dropped_queue_full) + " input_rate_limited=" +
           std::to_string(stats.dropped_rate_limited) +
           " input_send_failures=" + std::to_string(stats.send_failures) +
           " input_release_failures=" +
           std::to_string(stats.release_failures) +
           " input_worker_failures=" + std::to_string(stats.worker_failures) +
           " input_dropped_unmapped=" +
           std::to_string(stats.dropped_unmapped);
}

bool InputStatsChanged(const InputStats& prev, const InputStats& cur) {
    return prev.injected != cur.injected ||
           prev.dropped_queue_full != cur.dropped_queue_full ||
           prev.dropped_rate_limited != cur.dropped_rate_limited ||
           prev.send_failures != cur.send_failures ||
           prev.release_failures != cur.release_failures ||
           prev.worker_failures != cur.worker_failures ||
           prev.dropped_unmapped != cur.dropped_unmapped;
}

std::string PeriodicInputStatsLine(const InputStats& printed,
                                   const InputStats& current) {
    if (!InputStatsChanged(printed, current)) return std::string();
    return FormatInputStats("periodic", current);
}

}  // namespace rtsc::server
