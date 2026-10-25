// UI window abstraction: the platform-neutral facade plus the headless backend.

#include "rtsc/ui/window.h"

#include <deque>
#include <utility>

#if defined(_WIN32)
#include "window_win32_internal.h"
#elif defined(RTSC_UI_X11)
#include "window_x11_internal.h"
#elif defined(RTSC_UI_WAYLAND)
#include "window_wayland_internal.h"
#endif

namespace rtsc::ui {
namespace {

// A window with no display: it owns a surface and an input queue but Present()
// is a no-op. This is what tests and headless CI use, and it proves the
// abstraction does not leak a platform dependency.
class HeadlessWindow final : public Window {
 public:
    HeadlessWindow(uint16_t width, uint16_t height) : surface_(width, height) {}

    Surface& surface() override { return surface_; }
    void Present() override { ++present_count_; }
    bool PollEvent(InputEvent& out) override {
        if (events_.empty()) return false;
        out = events_.front();
        events_.pop_front();
        return true;
    }
    void Close() override { closed_ = true; }
    bool closed() const override { return closed_; }
    const char* backend_name() const override { return "headless"; }

    void Resize(uint16_t width, uint16_t height) override {
        if (width == 0 || height == 0) return;
        surface_ = Surface(width, height);
    }

    void PushEventForTest(const InputEvent& event) override {
        events_.push_back(event);
    }

    size_t present_count() const { return present_count_; }

 private:
    Surface surface_;
    std::deque<InputEvent> events_;
    bool closed_ = false;
    size_t present_count_ = 0;
};

}  // namespace

std::unique_ptr<Window> CreateWindow(uint16_t width, uint16_t height,
                                     const std::string& backend, std::string& why) {
    why.clear();
    if (width == 0 || height == 0) {
        why = "window dimensions must be non-zero";
        return nullptr;
    }
    if (backend == "headless") {
        return std::make_unique<HeadlessWindow>(width, height);
    }
#if defined(_WIN32)
    if (backend.empty() || backend == "win32") {
        return CreateWin32Window(width, height, why);
    }
#elif defined(RTSC_UI_X11)
    if (backend.empty() || backend == "x11") {
        return CreateX11Window(width, height, why);
    }
#elif defined(RTSC_UI_WAYLAND)
    if (backend.empty() || backend == "wayland") {
        return CreateWaylandWindow(width, height, why);
    }
#endif
    if (backend.empty()) {
        // No platform backend on this build: fall back to headless.
        return std::make_unique<HeadlessWindow>(width, height);
    }
    // A named backend that is not wired in must report honestly instead of
    // silently falling back to headless (G9: a missing input is a failure).
    why = "no window backend named '" + backend + "' is available";
    return nullptr;
}

}  // namespace rtsc::ui
