// Win32 desktop input sink: turns DesktopInputSink calls into SendInput.
//
// Threading: the session thread must never call SendInput (a blocked session
// stalls its whole active loop, and eight sessions calling SendInput directly
// would interleave their event streams non-deterministically). Inject() only
// translates and enqueues under a mutex; one worker thread drains the queue and
// emits the events serially.
//
// Queue policy (docs/spec/input-injection-seam.md 1.5):
//   * consecutive pure movement for one session is coalesced. The timer-driven
//     path emits at most once per 4 ms (250 Hz) per session, while a key/button
//     of the same session flushes the pending move immediately (the latest
//     position always wins), so the output rate is not strictly capped at
//     250 Hz;
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
//     down -- is exempt from the hard limit. A release for something not held
//     (a repeated up, or the up of a press that was never injected) is treated
//     like a press, so a flood of key-ups cannot grow the queue;
//   * peak bound (a PEAK, never an instantaneous invariant -- a release that
//     cleared |pressed| can still sit in the queue): every session that holds
//     the input lease contributes at most |pressed| <= 515 exempt releases on
//     top of hard_limit, i.e. hard_limit + 515 * K for K concurrently
//     lease-holding sessions. The default max_input_sessions = 1 gives
//     1024 + 515 = 1539. Teardown's synthetic ups are pushed directly by
//     AppendReleasesLocked (bypassing DecideEnqueue) and the purge keeps them,
//     so they are the same term, not an extra one on top of it;
//   * dropping a HELD release is what leaves the peer's key stuck, which is why
//     it is the only class exempt from the hard limit.
//
// Failures are counted and logged at most once per five seconds; the session is
// never disconnected for an injection failure (UIPI and lock-screen failures
// are local-machine state, not a protocol violation).
//
// Rate limiting (docs/spec/input-injection-seam.md 2.3) happens in Inject(),
// before the event can enter the queue, under the same mutex: 400 platform
// actions/s per session (burst 800) and 1000/s for all sessions together
// (burst 2000). An action above either limit is dropped and counted in
// InputStats::dropped_rate_limited, and it is NOT recorded as held (a refused
// press was never injected, so its up must not be exempt). Only a held release
// is exempt; an up for a key the session never pressed is limited like a press.
// Teardown's synthetic ups bypass Inject() and are therefore never limited.

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
#include <new>
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

#if defined(RTSC_DESKTOP_INPUT_TESTING)
#include "desktop_input_win32_test_hooks.h"
#endif

namespace rtsc::server {
namespace {

using Clock = std::chrono::steady_clock;

#if defined(RTSC_DESKTOP_INPUT_TESTING)
std::atomic<DesktopInputAppendFailureHook> g_append_failure_hook{nullptr};
#endif

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
    // True for the key/button ups AppendReleasesLocked synthesizes when a
    // session ends. They are the only queued items allowed to outlive
    // ReleaseSession: dropping them is what leaves the local key stuck.
    bool synthetic = false;
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
        // A session that has already been released must not revive its state
        // (or its rate-limit bucket) with a late event: drop and count.
        if (forget_sessions_.count(session_id) != 0) {
            dropped_unsupported_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        SessionInputState& session = sessions_[session_id];
        const std::vector<PlatformInput> inputs =
            TranslateInput(ev, session.geometry);
        if (inputs.empty()) {
            dropped_unsupported_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        for (const PlatformInput& input : inputs) {
            // Rate limit, held-release decision, queue admission and the
            // held-key bookkeeping are one platform-neutral step
            // (AdmitAndTrack): a press the limiter refused is never tracked,
            // and only a held release is exempt from the limiter and the hard
            // limit. See EnqueueLocked for the container side.
            EnqueueLocked(session_id, session, input);
        }
        cv_.notify_one();
    }

    void ReleaseSession(uint32_t session_id) override {
        {
            std::lock_guard<std::mutex> lock(mu_);
            // Forget the per-session bookkeeping even when no session state
            // exists: a restarted server restarts its input ids at 1, and a
            // stale last_move_sent_[session_id], pending move or rate-limit
            // bucket would throttle the new session's first events (or move
            // the pointer after the release). The move maps are worker-owned,
            // so only record the request here; the worker drains it under the
            // same mutex before it emits or dispatches anything else.
            //
            // Teardown must not be skipped by a failure while queueing the
            // synthetic ups: losing the ups leaves keys down, but leaving the
            // session (or the forget request) behind keeps the worker asleep
            // and permanently rejects the next session that reuses the id.
            try {
                forget_sessions_.insert(session_id);
            } catch (...) {
                // No forget request; the session state itself is still
                // released below.
            }
            const auto it = sessions_.find(session_id);
            if (it != sessions_.end()) {
                try {
                    AppendReleasesLocked(session_id, it->second);
                } catch (...) {
                    release_failures_.fetch_add(1,
                                                std::memory_order_relaxed);
                }
                // Unconditional: the session state and its pressed set must
                // not survive a failed append (the ups are lost either way,
                // and a retained state would keep the id unusable).
                sessions_.erase(it);
            }
        }
        // Unconditional: the worker must observe the forget request (or the
        // synthetic ups) even when the append above failed.
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
        stats.release_failures =
            release_failures_.load(std::memory_order_relaxed);
        return stats;
    }

#if defined(RTSC_DESKTOP_INPUT_TESTING)
    // Test seam (desktop_input_win32_test_hooks.h): the suite drives the real
    // teardown paths without injecting input. Not part of the production build.
    void SeedPressedKeyForTest(uint32_t session_id, uint16_t scancode,
                               bool extended) {
        std::lock_guard<std::mutex> lock(mu_);
        KeyId key;
        key.scancode = scancode;
        key.extended = extended;
        sessions_[session_id].pressed.keys.insert(key);
    }
    size_t SessionCountForTest() {
        std::lock_guard<std::mutex> lock(mu_);
        return sessions_.size();
    }
    size_t PendingForgetCountForTest() {
        std::lock_guard<std::mutex> lock(mu_);
        return forget_sessions_.size();
    }
    void ShutdownForTest() { Shutdown(); }
    bool WorkerJoinableForTest() { return worker_.joinable(); }
#endif

 private:
    // ---- queue-side helpers (mu_ held) ------------------------------------
    // Returns true when the event was queued (or coalesced into the tail).
    // Rate limiting, admission (including the "held release only" exemption)
    // and the held-key bookkeeping all live in the platform-neutral
    // AdmitAndTrack(); this function only applies its decision to the queue
    // container.
    bool EnqueueLocked(uint32_t session_id, SessionInputState& session,
                       const PlatformInput& input) {
        const Clock::time_point now = Clock::now();
        // A move that coalesces into this session's queued tail does not grow
        // the queue, but it is still a platform action: it passes the rate gate
        // like any other (a movement is never a held release).
        if (input.kind == PlatformInput::Kind::kMouseMove && !queue_.empty() &&
            queue_.back().session_id == session_id &&
            queue_.back().input.kind == PlatformInput::Kind::kMouseMove) {
            if (!rate_limiter_.Allow(session_id, false, now)) return false;
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
        const AdmitOutcome outcome = AdmitAndTrack(
            state, session.pressed, input,
            [this, session_id, now](bool held_release) {
                return rate_limiter_.Allow(session_id, held_release, now);
            });
        if (outcome.rate_limited) return false;
        switch (outcome.action) {
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

    // Queues the synthetic ups for every key and button the session still
    // holds. May throw (a deque allocation); the callers are the teardown
    // paths, which must finish their cleanup regardless (see ReleaseSession
    // and Shutdown).
    void AppendReleasesLocked(uint32_t session_id,
                              const SessionInputState& session) {
        // Win32 does not reset the keyboard state, so every key and button the
        // session still holds must be released explicitly. These internal
        // release events deliberately bypass the queue-policy call: they are
        // bounded by the pressed-key/button set (not by peer traffic) and they
        // are what makes a dropped key temporally harmless.
        size_t index = 0;
        for (const KeyId& key : session.pressed.keys) {
            PlatformInput up;
            up.kind = PlatformInput::Kind::kKey;
            up.scancode = key.scancode;
            up.extended = key.extended;
            up.release = true;
            AppendReleaseLocked(session_id, up, index++);
        }
        for (const uint8_t button : session.pressed.buttons) {
            PlatformInput up;
            up.kind = PlatformInput::Kind::kMouseButton;
            up.button = button;
            up.button_down = false;
            AppendReleaseLocked(session_id, up, index++);
        }
    }

    // Queues one synthetic up. The test hook makes it throw std::bad_alloc,
    // exactly like a real allocation failure, so the teardown callers can be
    // exercised without exhausting memory.
    void AppendReleaseLocked(uint32_t session_id, const PlatformInput& up,
                             size_t index) {
#if defined(RTSC_DESKTOP_INPUT_TESTING)
        const DesktopInputAppendFailureHook hook =
            g_append_failure_hook.load(std::memory_order_relaxed);
        if (hook != nullptr && hook(session_id, index)) {
            throw std::bad_alloc();
        }
#else
        (void)index;
#endif
        queue_.push_back({session_id, up, true});
    }

    // ---- worker-only state -------------------------------------------------
    void WorkerMain() noexcept {
        for (;;) {
            std::optional<QueuedInput> item;
            bool stop = false;
            // One failed iteration (an allocation failure in Dispatch or
            // EmitDueMoves) must not escape the thread function: that is
            // std::terminate, which would kill the whole process. Count it,
            // drop the item and keep draining.
            try {
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
                // Emit due moves only after the forget drain and before the
                // next dispatch: a pending move of a session whose
                // ReleaseSession has already been drained is gone by the time
                // this runs.
                EmitDueMoves();
                if (item) Dispatch(std::move(*item));
            } catch (...) {
                worker_failures_.fetch_add(1, std::memory_order_relaxed);
                if (stopping_) break;
            }
        }
        try {
            FlushMoves();
        } catch (...) {
            worker_failures_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // Drops the pending move, the move-rate timestamp and the rate-limit bucket
    // recorded for sessions whose ReleaseSession has already run. The move maps
    // are worker-owned and the rate limiter is guarded by mu_, so this runs on
    // the worker under mu_ (which also guards forget_sessions_) and is called
    // before emitting or dispatching anything: a move enqueued after
    // ReleaseSession cannot be throttled by the old session's timestamp, cannot
    // move the pointer after the release, and a reused session id starts with a
    // full rate-limit burst.
    void ForgetReleasedSessionsLocked() {
        for (const uint32_t session_id : forget_sessions_) {
            pending_moves_.erase(session_id);
            last_move_sent_.erase(session_id);
            rate_limiter_.Forget(session_id);
            // Input is real-time state: a queued press/move of a session that
            // has already ended must not be injected after the release (the
            // synthetic ups below are the exception -- they clear the physical
            // key/button state and must stay). Purging here also guarantees a
            // late Dispatch cannot recreate the rate-limit bucket.
            for (auto it = queue_.begin(); it != queue_.end();) {
                if (it->session_id == session_id && !it->synthetic) {
                    it = queue_.erase(it);
                    dropped_queue_full_.fetch_add(1,
                                                  std::memory_order_relaxed);
                } else {
                    ++it;
                }
            }
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
        // The rate limiter already ran in Inject(), before the event could
        // enter the queue, so a queued item is always admitted (including the
        // synthetic ups AppendReleasesLocked queues for teardown, which must
        // never be limited).
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

    // Teardown must be noexcept: it runs from the destructor, and a skipped
    // join makes ~std::thread call std::terminate. Every step is isolated, and
    // the notify/join run unconditionally.
    void Shutdown() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mu_);
            // The append pass runs once. Not returning early afterwards is
            // deliberate: if an earlier call failed before the join, this one
            // still has to wake and join the worker (both are idempotent).
            if (!stopping_) {
                stopping_ = true;
                for (auto& entry : sessions_) {
                    try {
                        AppendReleasesLocked(entry.first, entry.second);
                    } catch (...) {
                        release_failures_.fetch_add(
                            1, std::memory_order_relaxed);
                    }
                    try {
                        entry.second.pressed = PressedInputs{};
                    } catch (...) {
                        // Cannot normally throw; nothing may escape a
                        // destructor path.
                    }
                }
                try {
                    sessions_.clear();
                } catch (...) {
                }
            }
        } catch (...) {
            // A mutex-misuse exception is unrecoverable, but the worker still
            // has to be woken and joined below.
        }
        // Unconditional, and never an early return when stopping_ was already
        // set: if an earlier call failed before the join, this one still has to
        // wake and join the worker. A skipped notify or join leaves the worker
        // asleep and then makes ~std::thread terminate the process. Both
        // operations are idempotent.
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
        // The worker has drained the queue (FlushMoves ran on exit); release
        // the worker-owned move state explicitly so nothing survives a
        // shutdown that already appended the synthetic ups.
        try {
            pending_moves_.clear();
            last_move_sent_.clear();
        } catch (...) {
        }
    }

    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<QueuedInput> queue_;
    std::map<uint32_t, SessionInputState> sessions_;
    // Sessions whose ReleaseSession asked the worker to forget their per-session
    // state (guarded by mu_). The worker also drops their pending move and
    // move-rate timestamp; the rate-limit bucket is guarded by mu_ too.
    std::set<uint32_t> forget_sessions_;
    // Written under mu_ by Shutdown; read by the worker outside the lock on the
    // exception path, so it is atomic (relaxed suffices: the mutex provides the
    // ordering for the state it guards).
    std::atomic<bool> stopping_{false};
    std::thread worker_;

    // Move state: owned by the worker thread. `pending_moves_` and
    // `last_move_sent_` are only touched by the worker (including the forget
    // drain, which runs under mu_ on the worker) and cleared by Shutdown after
    // the join.
    std::map<uint32_t, PlatformInput> pending_moves_;
    std::map<uint32_t, Clock::time_point> last_move_sent_;
    // Guarded by mu_: Allow() runs in Inject() (session threads) and Forget()
    // runs on the worker, both while holding the queue mutex.
    InputRateLimiter rate_limiter_;

    std::atomic<uint64_t> injected_ok_{0};
    std::atomic<uint64_t> injected_failed_{0};
    std::atomic<uint64_t> dropped_queue_full_{0};
    std::atomic<uint64_t> dropped_unsupported_{0};
    // Teardown synthetic ups that could not be queued: the corresponding key or
    // button stays physically down, so this is the only place it is visible.
    std::atomic<uint64_t> release_failures_{0};
    // Worker iterations that threw and were skipped (see WorkerMain).
    std::atomic<uint64_t> worker_failures_{0};

    std::mutex log_mu_;
    bool logged_failure_ = false;
    Clock::time_point last_failure_log_{};
};

}  // namespace

#if defined(RTSC_DESKTOP_INPUT_TESTING)

void SetDesktopInputAppendFailureHook(DesktopInputAppendFailureHook hook) {
    g_append_failure_hook.store(hook, std::memory_order_relaxed);
}

std::unique_ptr<DesktopInputSink> MakeWin32DesktopInputSinkForTest() {
    return std::make_unique<Win32DesktopInputSink>();
}

namespace {

Win32DesktopInputSink* AsWin32(DesktopInputSink* sink) {
    return static_cast<Win32DesktopInputSink*>(sink);
}

}  // namespace

void DesktopInputTestSeedPressedKey(DesktopInputSink* sink, uint32_t session_id,
                                    uint16_t scancode, bool extended) {
    auto* win32 = AsWin32(sink);
    if (win32 == nullptr) return;
    win32->SeedPressedKeyForTest(session_id, scancode, extended);
}

size_t DesktopInputTestSessionCount(DesktopInputSink* sink) {
    auto* win32 = AsWin32(sink);
    if (win32 == nullptr) return 0;
    return win32->SessionCountForTest();
}

size_t DesktopInputTestPendingForgetCount(DesktopInputSink* sink) {
    auto* win32 = AsWin32(sink);
    if (win32 == nullptr) return 0;
    return win32->PendingForgetCountForTest();
}

void DesktopInputTestShutdown(DesktopInputSink* sink) {
    auto* win32 = AsWin32(sink);
    if (win32 == nullptr) return;
    win32->ShutdownForTest();
}

bool DesktopInputTestWorkerFinished(DesktopInputSink* sink) {
    return !DesktopInputTestWorkerJoinable(sink);
}

bool DesktopInputTestWorkerJoinable(DesktopInputSink* sink) {
    auto* win32 = AsWin32(sink);
    if (win32 == nullptr) return false;
    return win32->WorkerJoinableForTest();
}

#else

std::unique_ptr<DesktopInputSink> MakeWin32DesktopInputSink() {
    return std::make_unique<Win32DesktopInputSink>();
}

#endif

}  // namespace rtsc::server
