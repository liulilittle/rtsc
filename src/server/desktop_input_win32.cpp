// Win32 desktop input sink: turns DesktopInputSink calls into SendInput.
//
// Threading: the session thread must never call SendInput (a blocked session
// stalls its whole active loop, and eight sessions calling SendInput directly
// would interleave their event streams non-deterministically). Inject() only
// translates and enqueues under a mutex; one worker thread drains the queue and
// emits the events serially.
//
// Queue policy (docs/spec/input-injection-seam.md 1.5):
//   * keys, unicode characters, buttons and wheel events are never dropped;
//   * consecutive pure movement for one session is coalesced, and output is
//     capped at 250 Hz per session (the latest position always wins);
//   * when the bounded queue is full the oldest pure movement is evicted
//     first; if it holds no movement, a key/button is still accepted (the
//     queue grows temporarily) because losing an up event produces a stuck
//     key or button.
//
// Failures are counted and logged at most once per five seconds; the session is
// never disconnected for an injection failure (UIPI and lock-screen failures
// are local-machine state, not a protocol violation).

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
constexpr Clock::duration kMoveInterval = std::chrono::milliseconds(4);  // 250 Hz
constexpr Clock::duration kFailureLogInterval = std::chrono::seconds(5);
// Marks the injected events for local diagnostics (see
// docs/spec/input-injection-seam.md 2.4): ASCII "RTSC".
constexpr ULONG_PTR kInjectTag = 0x52545343;

struct KeyId {
    uint16_t scancode = 0;
    bool extended = false;

    bool operator<(const KeyId& other) const {
        if (scancode != other.scancode) return scancode < other.scancode;
        return extended < other.extended;
    }
};

struct QueuedInput {
    uint32_t session_id = 0;
    PlatformInput input;
};

struct SessionInputState {
    InjectGeometry geometry;
    std::set<KeyId> pressed_keys;
    std::set<uint8_t> pressed_buttons;
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
            TrackPressedLocked(session, input);
            EnqueueLocked(session_id, input);
        }
        cv_.notify_one();
    }

    void ReleaseSession(uint32_t session_id) override {
        {
            std::lock_guard<std::mutex> lock(mu_);
            const auto it = sessions_.find(session_id);
            if (it == sessions_.end()) return;
            AppendReleasesLocked(session_id, it->second);
            sessions_.erase(it);
        }
        cv_.notify_one();
    }

 private:
    // ---- queue-side helpers (mu_ held) ------------------------------------
    static void TrackPressedLocked(SessionInputState& session,
                                   const PlatformInput& input) {
        if (input.kind == PlatformInput::Kind::kKey && input.unicode == 0) {
            const KeyId key{input.scancode, input.extended};
            if (input.release) {
                session.pressed_keys.erase(key);
            } else {
                session.pressed_keys.insert(key);
            }
            return;
        }
        if (input.kind == PlatformInput::Kind::kMouseButton) {
            if (input.button_down) {
                session.pressed_buttons.insert(input.button);
            } else {
                session.pressed_buttons.erase(input.button);
            }
        }
    }

    void EnqueueLocked(uint32_t session_id, const PlatformInput& input) {
        if (input.kind == PlatformInput::Kind::kMouseMove && !queue_.empty() &&
            queue_.back().session_id == session_id &&
            queue_.back().input.kind == PlatformInput::Kind::kMouseMove) {
            queue_.back().input = input;  // coalesce consecutive moves
            return;
        }
        if (queue_.size() >= kMaxQueue) {
            const auto oldest_move =
                std::find_if(queue_.begin(), queue_.end(),
                             [](const QueuedInput& queued) {
                                 return queued.input.kind ==
                                        PlatformInput::Kind::kMouseMove;
                             });
            if (oldest_move != queue_.end()) {
                queue_.erase(oldest_move);
                dropped_queue_full_.fetch_add(1, std::memory_order_relaxed);
            } else if (input.kind == PlatformInput::Kind::kMouseMove) {
                // Nothing older to evict and the incoming event is itself
                // disposable: drop it rather than displace key/button state.
                dropped_queue_full_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
        queue_.push_back({session_id, input});
    }

    void AppendReleasesLocked(uint32_t session_id,
                              const SessionInputState& session) {
        // Win32 does not reset the keyboard state, so every key and button the
        // session still holds must be released explicitly.
        for (const KeyId& key : session.pressed_keys) {
            PlatformInput up;
            up.kind = PlatformInput::Kind::kKey;
            up.scancode = key.scancode;
            up.extended = key.extended;
            up.release = true;
            queue_.push_back({session_id, up});
        }
        for (const uint8_t button : session.pressed_buttons) {
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
                entry.second.pressed_keys.clear();
                entry.second.pressed_buttons.clear();
            }
        }
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<QueuedInput> queue_;
    std::map<uint32_t, SessionInputState> sessions_;
    bool stopping_ = false;
    std::thread worker_;

    // Owned by the worker thread, never touched under mu_.
    std::map<uint32_t, PlatformInput> pending_moves_;
    std::map<uint32_t, Clock::time_point> last_move_sent_;

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
