// Connection bar state machine (see connection_bar.h).

#include "rtsc/ui/connection_bar.h"

#include <algorithm>

namespace rtsc::ui {

ConnectionBar::ConnectionBar(ConnectionBarConfig config) : config_(config) {
    if (config_.height <= 0) config_.height = 1;
    if (config_.reveal_zone < 0) config_.reveal_zone = 0;
    if (config_.auto_hide_ms < 0) config_.auto_hide_ms = 0;
    if (config_.button_size <= 0) config_.button_size = 1;
    if (config_.button_margin < 0) config_.button_margin = 0;
}

void ConnectionBar::SetFullscreen(bool on, Clock::time_point now) {
    if (fullscreen_ == on) return;
    fullscreen_ = on;
    if (!on) {
        // Windowed: the bar never shows, but the pin preference is kept.
        visible_ = false;
        return;
    }
    if (pinned_) Show(now);
}

void ConnectionBar::SetPinned(bool on, Clock::time_point now) {
    pinned_ = on;
    if (pinned_ && fullscreen_) {
        Show(now);
    }
}

void ConnectionBar::OnMouseMove(int x, int y, Clock::time_point now) {
    (void)x;
    if (!fullscreen_) return;
    if (y < config_.reveal_zone) {
        Show(now);
        return;
    }
    if (visible_ && y < config_.height) {
        // Hovering the bar keeps it up.
        last_activity_ = now;
    }
}

void ConnectionBar::OnActivity(Clock::time_point now) {
    if (visible_) last_activity_ = now;
}

void ConnectionBar::Tick(Clock::time_point now) {
    if (!visible_ || pinned_) return;
    const auto idle = std::chrono::duration_cast<std::chrono::milliseconds>(
                          now - last_activity_)
                          .count();
    if (idle >= config_.auto_hide_ms) visible_ = false;
}

ConnectionBar::ButtonRect ConnectionBar::ButtonRectFor(
    ConnectionBarButton button, int window_width) const {
    ButtonRect r;
    if (!visible_ || button == ConnectionBarButton::kNone) return r;
    const int size = config_.button_size;
    const int margin = config_.button_margin;
    // Right-aligned: close is rightmost, then minimize, then pin.
    int slot = 0;
    switch (button) {
        case ConnectionBarButton::kClose:
            slot = 0;
            break;
        case ConnectionBarButton::kMinimize:
            slot = 1;
            break;
        case ConnectionBarButton::kPin:
            slot = 2;
            break;
        case ConnectionBarButton::kNone:
            return r;
    }
    r.w = size;
    r.h = size;
    r.x = window_width - margin - (slot + 1) * size - slot * margin;
    r.y = (config_.height - size) / 2;
    return r;
}

ConnectionBarButton ConnectionBar::HitTest(int x, int y,
                                           int window_width) const {
    if (!visible_) return ConnectionBarButton::kNone;
    if (y < 0 || y >= config_.height) return ConnectionBarButton::kNone;
    for (const ConnectionBarButton b : {ConnectionBarButton::kClose,
                                        ConnectionBarButton::kMinimize,
                                        ConnectionBarButton::kPin}) {
        const ButtonRect r = ButtonRectFor(b, window_width);
        if (x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h) return b;
    }
    return ConnectionBarButton::kNone;
}

void ConnectionBar::Show(Clock::time_point now) {
    visible_ = true;
    last_activity_ = now;
}

}  // namespace rtsc::ui
