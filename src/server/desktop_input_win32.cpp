// Win32 desktop input sink: turns DesktopInputSink calls into SendInput.
//
// Threading: the session thread must never call SendInput (a blocked session
// stalls its whole active loop, and eight sessions calling SendInput directly
// would interleave their event streams non-deterministically). Inject() only
// translates and enqueues under a mutex; one worker thread drains the queue and
// emits the events serially.
//
// Queue policy (docs/spec/input-injection-seam.md 1.5):
//   * consecutive pure movement for one session is coalesced, and output is
//     capped at 250 Hz per session (the latest position always wins);
//   * above the soft limit the oldest pure movement is evicted first; if the
//     queue holds no movement, a key/button is still accepted (the queue grows
//     temporarily) because losing an up event produces a stuck key or button;
//   * growth is bounded by a hard limit (4x the soft limit): once the queue is
//     there and no movement can be evicted, an incoming key/button/wheel PRESS
//     is DROPPED (fail closed). Trading a lost press for a hard memory bound is
//     deliberate: an unbounded queue driven by a hostile peer would exhaust
//     memory. A dropped press cannot leave a stuck key because the sink records
//     what each session holds down only AFTER the queue accepted the press, so a
//     dropped press was never tracked;
//   * only a HELD release -- the up of a key/button this session actually holds
//     down -- is exempt from the hard limit. It is bounded by the pressed set
//     (queue length <= hard limit + |pressed|) and dropping it is what leaves
//     the peer's key stuck. A release for something not held (a repeated up, or
//     the up of a dropped press) is treated like a press, so a flood of key-ups
//     cannot grow the queue.
//
// Failures are counted and logged at most once per five seconds; the session is
// never disconnected for an injection failure (UIPI and lock-screen failures
// are local-machine state, not a protocol violation).
//
// Rate limiting (docs/spec/input-injection-seam.md 2.3) happens on the worker
// thread right before dispatch: 400 evt/s per session (burst 800) and
// 1000 evt/s for all sessions together (burst 2000). An event above either
// limit is dropped and counted in InputStats::dropped_rate_limited. Releases
// are exempt (dropping one is what leaves a key stuck); see InputRateLimiter.

#include "rtsc/server/desktop_input.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <utility>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "rtsc/server/desktop_input_map.h"

namespace rtsc::server {
namespace {

using Clock = std::chrono::steady_clock;

constexpr size_t kMaxQueue = 256;
// Absolute bound on queued platform inputs. The soft limit allows short
// overruns for key/button state, but a peer must never be able to grow the
// queue without bound: 1024 queued INPUTs is already far above what one
// session can legitimately need between two worker drains.
constexpr size_t kHardQueueLimit = 4 * kMaxQueue;
constexpr Clock::duration kMoveInterval = std::chrono::milliseconds(4);  // 250 Hz
constexpr Clock::duration kFailureLogInterval = std::chrono::seconds(5);
// Marks the injected events for local diagnostics (see
// docs/spec/input-injection-seam.md 2.4): ASCII "RTSC".
constexpr ULONG_PTR kInjectTag = 0x52545343;

struct QueuedInput {
    uint32_t session_id = 0;
    PlatformInput input;
};

struct SessionInputState {
    InjectGeometry geometry;
    PressedInputs pressed;
};

class Win32DesktopInputSink final : public DesktopInputSink {
 public:
    Win32DesktopInputSink() {
        worker_ = std::thread([this]() { WorkerMain(); });
    }

    ~Win32DesktopInputSink() override { Shutdown(); }

    Win32DesktopInputSink(const Win32DesktopInputSink&) = delete;
    Win32DesktopInputSink& operator=(const Win32DesktopInputSink&) = delete;

    void SetGeometry(uint32_t session_id, const InjectGeometry& g) override {
        std::lock_guard<std::mutex> lock(mu_);
        sessions_[session_id].geometry = g;
    }

    void Inject(uint32_t session_id, const InputEvent& ev) override {
        std::lock_guard<std::mutex> lock(mu_);
        SessionInputState& session = sessions_[session_id];
        const std::vector<PlatformInput> inputs =
            TranslateInput(ev, session.geometry);
        if (inputs.empty()) {
            dropped_unsupported_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        for (const PlatformInput& input : inputs) {
            // A release may exceed the hard limit only when it lifts a key or
            // button this session actually holds down, so the question is
            // answered against the pressed set BEFORE the enqueue updates it.
            // EnqueueLocked (via AdmitInput) records the press/release only
            // when the queue accepted it: a press dropped at the hard limit was
            // never injected, so it must not appear held (and its later up is
            // not exempt either), which keeps the queue bounded by
            // hard_limit + |pressed|.
            const bool held_release = IsHeldRelease(input, session.pressed);
            EnqueueLocked(session_id, session, input, held_release);
        }
        cv_.notify_one();
    }

    void ReleaseSession(uint32_t session_id) override {
        {
            std::lock_guard<std::mutex> lock(mu_);
            // Forget the per-session bookkeeping even when no session state
            // exists: a restarted server restarts its input ids at 1, and a
            // stale last_move_sent_[session_id] or rate-limit bucket would
            // throttle the new session's first events. The worker owns the move
            // maps and the rate limiter, so only record the request here; the
            // worker drains it under the same mutex before it dispatches the
            // next queued item.
            forget_sessions_.insert(session_id);
            const auto it = sessions_.find(session_id);
            if (it == sessions_.end()) {
                cv_.notify_one();
                return;
            }
            AppendReleasesLocked(session_id, it->second);
            sessions_.erase(it);
        }
        cv_.notify_one();
    }

    InputStats Stats() const override {
        InputStats stats;
        stats.injected =
            injected_ok_.load(std::memory_order_relaxed);
        stats.dropped_queue_full =
            dropped_queue_full_.load(std::memory_order_relaxed);
        stats.dropped_rate_limited = rate_limiter_.dropped();
        stats.send_failures =
            injected_failed_.load(std::memory_order_relaxed);
        return stats;
    }

 private:
    // ---- queue-side helpers (mu_ held) ------------------------------------
    // Returns true when the event was queued (or coalesced into the tail).
    // Admission (including the "held release only" exemption) and the held-key
    // bookkeeping are the platform-neutral AdmitInput(); this function only
    // applies its decision to the queue container.
    bool EnqueueLocked(uint32_t session_id, SessionInputState& session,
                       const PlatformInput& input, bool held_release) {
        if (input.kind == PlatformInput::Kind::kMouseMove && !queue_.empty() &&
            queue_.back().session_id == session_id &&
            queue_.back().input.kind == PlatformInput::Kind::kMouseMove) {
            queue_.back().input = input;  // coalesce consecutive moves
            return true;
        }
        const auto oldest_move =
            std::find_if(queue_.begin(), queue_.end(),
                         [](const QueuedInput& queued) {
                             return queued.input.kind ==
                                    PlatformInput::Kind::kMouseMove;
                         });
        EnqueueState state;
        state.size = queue_.size();
        state.soft_limit = kMaxQueue;
        state.hard_limit = kHardQueueLimit;
        state.has_movable_move = oldest_move != queue_.end();
        switch (AdmitInput(state, session.pressed, input, held_release)) {
            case EnqueueAction::kEvictMove:
                queue_.erase(oldest_move);
                dropped_queue_full_.fetch_add(1, std::memory_order_relaxed);
                break;
            case EnqueueAction::kDrop:
                dropped_queue_full_.fetch_add(1, std::memory_order_relaxed);
                return false;
            case EnqueueAction::kAccept:
                break;
        }
        queue_.push_back({session_id, input});
        return true;
    }

    void AppendReleasesLocked(uint32_t session_id,
                              const SessionInputState& session) {
        // Win32 does not reset the keyboard state, so every key and button the
        // session still holds must be released explicitly. These internal
        // release events deliberately bypass the queue-policy call: they are
        // bounded by the pressed-key/button set (not by peer traffic) and they
        // are what makes a dropped key temporally harmless.
        for (const KeyId& key : session.pressed.keys) {
            PlatformInput up;
            up.kind = PlatformInput::Kind::kKey;
            up.scancode = key.scancode;
            up.extended = key.extended;
            up.release = true;
            queue_.push_back({session_id, up});
        }
        for (const uint8_t button : session.pressed.buttons) {
            PlatformInput up;
            up.kind = PlatformInput::Kind::kMouseButton;
            up.button = button;
            up.button_down = false;
            queue_.push_back({session_id, up});
        }
    }

    // ---- worker-only state -------------------------------------------------
    void WorkerMain() {
        for (;;) {
            EmitDueMoves();
            std::optional<QueuedInput> item;
            bool stop = false;
            {
                std::unique_lock<std::mutex> lock(mu_);
                ForgetReleasedSessionsLocked();
                if (!queue_.empty()) {
                    item.emplace(std::move(queue_.front()));
                    queue_.pop_front();
                } else if (stopping_) {
                    stop = true;
                } else {
                    const std::optional<Clock::time_point> deadline =
                        NextMoveDeadline();
                    if (deadline) {
                        cv_.wait_until(lock, *deadline);
                    } else {
                        cv_.wait(lock);
                    }
                }
            }
            if (stop) break;
            if (item) Dispatch(std::move(*item));
        }
        FlushMoves();
    }

    // Drops the move-rate timestamps and rate-limit buckets recorded for
    // sessions whose ReleaseSession has already run. Only the worker touches
    // last_move_sent_ and rate_limiter_, so this runs under mu_ (which also
    // guards forget_sessions_) and must be called before dispatching any queued
    // item: that way a move enqueued after ReleaseSession cannot be throttled
    // by the old session's timestamp, and a reused session id starts with a
    // full rate-limit burst.
    void ForgetReleasedSessionsLocked() {
        for (const uint32_t session_id : forget_sessions_) {
            last_move_sent_.erase(session_id);
            rate_limiter_.Forget(session_id);
        }
        forget_sessions_.clear();
    }

    Clock::time_point MoveDue(uint32_t session_id) const {
        const auto it = last_move_sent_.find(session_id);
        if (it == last_move_sent_.end()) return Clock::now();
        return it->second + kMoveInterval;
    }

    std::optional<Clock::time_point> NextMoveDeadline() const {
        std::optional<Clock::time_point> deadline;
        for (const auto& entry : pending_moves_) {
            const Clock::time_point due = MoveDue(entry.first);
            if (!deadline || due < *deadline) deadline = due;
        }
        return deadline;
    }

    void EmitDueMoves() {
        const Clock::time_point now = Clock::now();
        for (auto it = pending_moves_.begin(); it != pending_moves_.end();) {
            if (MoveDue(it->first) <= now) {
                Emit(it->second);
                last_move_sent_[it->first] = Clock::now();
                it = pending_moves_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void FlushSessionMove(uint32_t session_id) {
        const auto it = pending_moves_.find(session_id);
        if (it == pending_moves_.end()) return;
        Emit(it->second);
        last_move_sent_[session_id] = Clock::now();
        pending_moves_.erase(it);
    }

    void FlushMoves() {
        for (const auto& entry : pending_moves_) {
            Emit(entry.second);
            last_move_sent_[entry.first] = Clock::now();
        }
        pending_moves_.clear();
    }

    void Dispatch(QueuedInput item) {
        // Last gate before the platform call, on the single worker thread, so
        // the token buckets need no lock. Releases are exempt inside Allow();
        // a refused event is dropped and counted, never queued again.
        if (!rate_limiter_.Allow(item.session_id, IsReleaseInput(item.input),
                                 Clock::now())) {
            return;
        }
        if (item.input.kind == PlatformInput::Kind::kMouseMove) {
            // Movement is a state, not an event: keep only the newest position
            // per session and let the rate cap decide when it is sent.
            pending_moves_[item.session_id] = item.input;
            EmitDueMoves();
            return;
        }
        // A key/button/wheel must keep its position relative to the pending
        // move of the same session (a click has to land where the pointer was
        // when the client sent it).
        FlushSessionMove(item.session_id);
        Emit(item.input);
    }

    // ---- Win32 -------------------------------------------------------------
    static bool BuildNative(const PlatformInput& input, INPUT& native) {
        switch (input.kind) {
            case PlatformInput::Kind::kKey: {
                native.type = INPUT_KEYBOARD;
                native.ki.dwExtraInfo = kInjectTag;
                if (input.unicode != 0) {
                    // KEYEVENTF_UNICODE requires wVk == 0 and may only be
                    // combined with KEYEVENTF_KEYUP.
                    native.ki.wVk = 0;
                    native.ki.wScan = static_cast<WORD>(input.unicode);
                    native.ki.dwFlags = KEYEVENTF_UNICODE;
                    if (input.release) native.ki.dwFlags |= KEYEVENTF_KEYUP;
                    return true;
                }
                // The wire keyCode is the set-1 scan code; the 0xE0 prefix is
                // expressed by KEYEVENTF_EXTENDEDKEY, never by adding 0x100.
                native.ki.wVk = 0;
                native.ki.wScan = input.scancode;
                native.ki.dwFlags = KEYEVENTF_SCANCODE;
                if (input.extended) {
                    native.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
                }
                if (input.release) native.ki.dwFlags |= KEYEVENTF_KEYUP;
                return true;
            }
            case PlatformInput::Kind::kMouseMove: {
                native.type = INPUT_MOUSE;
                native.mi.dx = static_cast<LONG>(input.x);
                native.mi.dy = static_cast<LONG>(input.y);
                native.mi.dwFlags = static_cast<DWORD>(
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE |
                    MOUSEEVENTF_VIRTUALDESK);
                native.mi.dwExtraInfo = kInjectTag;
                return true;
            }
            case PlatformInput::Kind::kMouseButton: {
                DWORD flags = 0;
                DWORD data = 0;
                switch (input.button) {
                    case 1:
                        flags = static_cast<DWORD>(input.button_down
                                                       ? MOUSEEVENTF_LEFTDOWN
                                                       : MOUSEEVENTF_LEFTUP);
                        break;
                    case 2:
                        flags = static_cast<DWORD>(input.button_down
                                                       ? MOUSEEVENTF_RIGHTDOWN
                                                       : MOUSEEVENTF_RIGHTUP);
                        break;
                    case 3:
                        flags = static_cast<DWORD>(input.button_down
                                                       ? MOUSEEVENTF_MIDDLEDOWN
                                                       : MOUSEEVENTF_MIDDLEUP);
                        break;
                    case 4:
                        flags = static_cast<DWORD>(input.button_down
                                                       ? MOUSEEVENTF_XDOWN
                                                       : MOUSEEVENTF_XUP);
                        data = static_cast<DWORD>(XBUTTON1);
                        break;
                    case 5:
                        flags = static_cast<DWORD>(input.button_down
                                                       ? MOUSEEVENTF_XDOWN
                                                       : MOUSEEVENTF_XUP);
                        data = static_cast<DWORD>(XBUTTON2);
                        break;
                    default:
                        return false;
                }
                native.type = INPUT_MOUSE;
                native.mi.dwFlags = flags;
                native.mi.mouseData = data;
                native.mi.dwExtraInfo = kInjectTag;
                return true;
            }
            case PlatformInput::Kind::kWheel: {
                native.type = INPUT_MOUSE;
                // wheel_delta is already in WHEEL_DELTA units; scaling it here
                // would multiply by 120 again. mouseData is a DWORD, so a
                // negative delta is written as its two's-complement pattern.
                native.mi.dwFlags = static_cast<DWORD>(
                    input.horizontal ? MOUSEEVENTF_HWHEEL : MOUSEEVENTF_WHEEL);
                native.mi.mouseData = static_cast<DWORD>(input.wheel);
                native.mi.dwExtraInfo = kInjectTag;
                return true;
            }
        }
        return false;
    }

    void Emit(const PlatformInput& input) {
        INPUT native{};
        if (!BuildNative(input, native)) {
            dropped_unsupported_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const UINT sent = ::SendInput(1, &native, sizeof(INPUT));
        if (sent == 1) {
            injected_ok_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        injected_failed_.fetch_add(1, std::memory_order_relaxed);
        LogFailure(::GetLastError());
    }

    void LogFailure(DWORD error) {
        const Clock::time_point now = Clock::now();
        bool emit = false;
        {
            std::lock_guard<std::mutex> lock(log_mu_);
            if (!logged_failure_ || now - last_failure_log_ >= kFailureLogInterval) {
                logged_failure_ = true;
                last_failure_log_ = now;
                emit = true;
            }
        }
        if (emit) {
            std::fprintf(stderr,
                         "[rtsc-server] desktop input: SendInput failed "
                         "(error=%lu); the event was dropped and the session "
                         "is kept\n",
                         static_cast<unsigned long>(error));
        }
    }

    void Shutdown() {
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (stopping_) return;
            stopping_ = true;
            for (auto& entry : sessions_) {
                AppendReleasesLocked(entry.first, entry.second);
                entry.second.pressed = PressedInputs{};
            }
        }
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<QueuedInput> queue_;
    std::map<uint32_t, SessionInputState> sessions_;
    // Sessions whose ReleaseSession asked the worker to forget their per-session
    // state (guarded by mu_; the move maps and the rate limiter stay
    // worker-only).
    std::set<uint32_t> forget_sessions_;
    bool stopping_ = false;
    std::thread worker_;

    // Owned by the worker thread, never touched under mu_.
    std::map<uint32_t, PlatformInput> pending_moves_;
    std::map<uint32_t, Clock::time_point> last_move_sent_;
    InputRateLimiter rate_limiter_;

    std::atomic<uint64_t> injected_ok_{0};
    std::atomic<uint64_t> injected_failed_{0};
    std::atomic<uint64_t> dropped_queue_full_{0};
    std::atomic<uint64_t> dropped_unsupported_{0};

    std::mutex log_mu_;
    bool logged_failure_ = false;
    Clock::time_point last_failure_log_{};
};

}  // namespace

std::unique_ptr<DesktopInputSink> MakeWin32DesktopInputSink() {
    return std::make_unique<Win32DesktopInputSink>();
}

}  // namespace rtsc::server
