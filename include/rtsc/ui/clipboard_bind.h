// Attach a local-clipboard-change callback to a set of windows.
//
// The GUI owns a vector of windows. In multi-monitor mode it destroys the
// initial window and creates one window per monitor, so a callback attached
// before that rebuild would reference a destroyed window and the session would
// never learn about local clipboard changes. The GUI therefore calls
// BindClipboardToWindows once, after the window set is final; that single call
// covers both the single-window layout (one window) and the multi-window layout
// (one per monitor). Header-only so the GUI and its unit test share one
// definition.

#pragma once

#include <functional>
#include <memory>
#include <vector>

#include "rtsc/ui/window.h"

namespace rtsc::ui {

// Registers `callback` on every live window in `windows`. Null entries are
// skipped. Calling it again after the set changes is safe: each call overwrites
// the per-window callback.
inline void BindClipboardToWindows(
    const std::vector<std::unique_ptr<Window>>& windows,
    const std::function<void()>& callback) {
    for (const auto& window : windows) {
        if (window) window->SetClipboardChangeCallback(callback);
    }
}

}  // namespace rtsc::ui
