// Connection bar state machine (mstsc's fullscreen floating bar).
//
// In a fullscreen session mstsc shows a small bar at the top edge with the
// endpoint, a pin toggle, minimize/restore and close. The bar is hidden until
// the pointer reaches the top edge, and auto-hides after a few seconds unless
// the user pinned it. This class owns only that behaviour: visibility, the
// auto-hide timer, the pin state and the button layout/hit testing. Rendering
// and native window plumbing stay in the platform backend.
//
// The state machine is platform neutral and time-injected (every transition
// takes the current steady-clock time), so it is fully testable headlessly.

#pragma once

#include <chrono>
#include <cstdint>

namespace rtsc::ui {

enum class ConnectionBarButton : uint8_t {
    kNone = 0,
    kPin,
    kMinimize,
    kClose,
};

struct ConnectionBarConfig {
    // Bar height in window pixels.
    int height = 24;
    // The pointer must be within this many pixels of the top edge to reveal
    // the bar (mstsc's "push to the top" gesture).
    int reveal_zone = 8;
    // The bar hides this long after the last activity while unpinned.
    int auto_hide_ms = 3000;
    // Button edge length in pixels.
    int button_size = 20;
    // Gap between the buttons and from the right edge.
    int button_margin = 2;
};

class ConnectionBar {
 public:
    using Clock = std::chrono::steady_clock;

    explicit ConnectionBar(ConnectionBarConfig config = {});

    // Entering/leaving fullscreen. The bar only ever shows in fullscreen; a
    // pin set earlier survives (mstsc keeps the preference), but the bar is
    // hidden while windowed.
    void SetFullscreen(bool on, Clock::time_point now);
    bool fullscreen() const { return fullscreen_; }

    // Pin keeps the bar visible regardless of the auto-hide timer.
    void SetPinned(bool on, Clock::time_point now);
    bool pinned() const { return pinned_; }

    // The pointer moved to (x, y) in window coordinates. Reaching the top
    // reveal zone shows the bar; hovering the bar itself counts as activity.
    void OnMouseMove(int x, int y, Clock::time_point now);

    // Any other user activity (key, click) while the bar is visible restarts
    // the auto-hide timer.
    void OnActivity(Clock::time_point now);

    // Advances the auto-hide timer. Hides the bar when it expires unless it is
    // pinned. Call once per UI iteration.
    void Tick(Clock::time_point now);

    bool visible() const { return visible_; }
    int height() const { return config_.height; }

    // Where button `button` is drawn when the bar is visible. The buttons are
    // right-aligned in the order pin, minimize, close (left to right).
    struct ButtonRect {
        int x = 0;
        int y = 0;
        int w = 0;
        int h = 0;
    };
    ButtonRect ButtonRectFor(ConnectionBarButton button, int window_width) const;

    // Hit test in window coordinates. Returns kNone when the bar is hidden,
    // the point is outside the bar, or it is not on a button.
    ConnectionBarButton HitTest(int x, int y, int window_width) const;

 private:
    void Show(Clock::time_point now);

    ConnectionBarConfig config_;
    bool fullscreen_ = false;
    bool pinned_ = false;
    bool visible_ = false;
    Clock::time_point last_activity_{};
};

}  // namespace rtsc::ui
