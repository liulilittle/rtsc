// Wayland window backend for rtsc::ui::Window.
//
// Compiled only on non-Windows when RTSC_UI_WAYLAND=ON. It owns a wl_surface
// with an xdg-shell toplevel backed by a wl_shm buffer that mirrors the RGBA
// Surface. Present() copies RGBA into the shm buffer (the compositor's format
// is XRGB8888, i.e. BGRA on little-endian) and commits. Input comes from
// wl_seat's keyboard and pointer, translated into the normalised InputEvent.

#include "rtsc/ui/window.h"

#if !defined(_WIN32) && defined(RTSC_UI_WAYLAND)

#include <sys/mman.h>
#include <unistd.h>
#include <wayland-client.h>

#include <cstdlib>
#include <cstring>
#include <deque>
#include <string>
#include <utility>

#include "xdg-shell-client-protocol.h"

namespace rtsc::ui {
namespace {

// A shared-memory file the compositor can map.
int CreateShmFile(size_t size) {
    char name[] = "/rtsc-shm-XXXXXX";
    const int fd = memfd_create(name, 0);
    if (fd < 0) return -1;
    if (ftruncate(fd, static_cast<off_t>(size)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

class WaylandWindow final : public Window {
 public:
    WaylandWindow(uint16_t width, uint16_t height) : pixels_(width, height) {}
    ~WaylandWindow() override { Destroy(); }

    bool Start(std::string& why) {
        display_ = wl_display_connect(nullptr);
        if (display_ == nullptr) {
            why = "cannot connect to a Wayland display (WAYLAND_DISPLAY unset)";
            return false;
        }
        registry_ = wl_display_get_registry(display_);
        wl_registry_add_listener(registry_, &kRegistryListener, this);
        wl_display_roundtrip(display_);
        wl_display_roundtrip(display_);  // second round for seat capabilities

        if (compositor_ == nullptr || shm_ == nullptr || wm_base_ == nullptr) {
            why =
                "Wayland compositor is missing wl_compositor / wl_shm / xdg_wm_base";
            return false;
        }
        if (!CreateBuffer(why)) return false;

        surface_ = wl_compositor_create_surface(compositor_);
        xdg_surface_ = xdg_wm_base_get_xdg_surface(wm_base_, surface_);
        xdg_surface_add_listener(xdg_surface_, &kXdgSurfaceListener, this);
        toplevel_ = xdg_surface_get_toplevel(xdg_surface_);
        xdg_toplevel_add_listener(toplevel_, &kToplevelListener, this);
        xdg_toplevel_set_title(toplevel_, "RTSC");
        wl_surface_commit(surface_);
        wl_display_flush(display_);
        return true;
    }

    Surface& surface() override { return pixels_; }

    void Present() override {
        if (buffer_ == nullptr || shm_data_ == nullptr || surface_ == nullptr) {
            return;
        }
        const uint8_t* src = pixels_.data();
        uint8_t* dst = static_cast<uint8_t*>(shm_data_);
        const size_t n = pixels_.size();
        for (size_t i = 0; i + 3 < n; i += 4) {
            dst[i + 0] = src[i + 2];
            dst[i + 1] = src[i + 1];
            dst[i + 2] = src[i + 0];
            dst[i + 3] = 0xFF;
        }
        wl_surface_attach(surface_, buffer_, 0, 0);
        wl_surface_damage_buffer(surface_, 0, 0, pixels_.width(), pixels_.height());
        wl_surface_commit(surface_);
        wl_display_flush(display_);
        ++present_count_;
    }

    bool PollEvent(InputEvent& out) override {
        if (display_ != nullptr) {
            wl_display_dispatch_pending(display_);
            wl_display_flush(display_);
        }
        if (events_.empty()) return false;
        out = events_.front();
        events_.pop_front();
        return true;
    }

    void Close() override {
        closed_ = true;
        if (display_ != nullptr) wl_display_flush(display_);
    }
    bool closed() const override { return closed_; }
    const char* backend_name() const override { return "wayland"; }
    void PushEventForTest(const InputEvent& event) override {
        events_.push_back(event);
    }

    // ---- registry -----------------------------------------------------------
    static void OnGlobal(void* data, wl_registry* reg, uint32_t name,
                         const char* interface, uint32_t version) {
        (void)version;
        auto* self = static_cast<WaylandWindow*>(data);
        if (std::strcmp(interface, wl_compositor_interface.name) == 0) {
            self->compositor_ = static_cast<wl_compositor*>(
                wl_registry_bind(reg, name, &wl_compositor_interface, 4));
        } else if (std::strcmp(interface, wl_shm_interface.name) == 0) {
            self->shm_ = static_cast<wl_shm*>(
                wl_registry_bind(reg, name, &wl_shm_interface, 1));
        } else if (std::strcmp(interface, xdg_wm_base_interface.name) == 0) {
            self->wm_base_ = static_cast<xdg_wm_base*>(
                wl_registry_bind(reg, name, &xdg_wm_base_interface, 1));
            xdg_wm_base_add_listener(self->wm_base_, &kWmBaseListener, self);
        } else if (std::strcmp(interface, wl_seat_interface.name) == 0) {
            self->seat_ = static_cast<wl_seat*>(
                wl_registry_bind(reg, name, &wl_seat_interface, 5));
            wl_seat_add_listener(self->seat_, &kSeatListener, self);
        }
    }
    static void OnGlobalRemove(void*, wl_registry*, uint32_t) {}

    // ---- xdg_wm_base --------------------------------------------------------
    static void OnPing(void*, xdg_wm_base* base, uint32_t serial) {
        xdg_wm_base_pong(base, serial);
    }

    // ---- xdg_surface / toplevel --------------------------------------------
    static void OnConfigure(void* data, xdg_surface* s, uint32_t serial) {
        auto* self = static_cast<WaylandWindow*>(data);
        xdg_surface_ack_configure(s, serial);
        if (!self->configured_) {
            self->configured_ = true;
            self->Present();
        }
    }
    static void OnToplevelConfigure(void*, xdg_toplevel*, int32_t, int32_t,
                                    wl_array*) {}
    static void OnToplevelClose(void* data, xdg_toplevel*) {
        static_cast<WaylandWindow*>(data)->closed_ = true;
    }
    static void OnToplevelConfigureBounds(void*, xdg_toplevel*, int32_t, int32_t) {}

    // ---- seat / keyboard / pointer -----------------------------------------
    static void OnSeatCapabilities(void* data, wl_seat* seat, uint32_t caps) {
        auto* self = static_cast<WaylandWindow*>(data);
        if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && self->keyboard_ == nullptr) {
            self->keyboard_ = wl_seat_get_keyboard(seat);
            wl_keyboard_add_listener(self->keyboard_, &kKeyboardListener, self);
        }
        if ((caps & WL_SEAT_CAPABILITY_POINTER) && self->pointer_ == nullptr) {
            self->pointer_ = wl_seat_get_pointer(seat);
            wl_pointer_add_listener(self->pointer_, &kPointerListener, self);
        }
    }
    static void OnSeatName(void*, wl_seat*, const char*) {}

    static void OnKeymap(void*, wl_keyboard*, uint32_t, int32_t, uint32_t) {}
    static void OnEnter(void*, wl_keyboard*, uint32_t, wl_surface*, wl_array*) {}
    static void OnLeave(void*, wl_keyboard*, uint32_t, wl_surface*) {}
    static void OnKey(void* data, wl_keyboard*, uint32_t, uint32_t, uint32_t key,
                      uint32_t state) {
        auto* self = static_cast<WaylandWindow*>(data);
        InputEvent e;
        e.kind = InputEvent::Kind::kKey;
        e.scancode = static_cast<uint8_t>(key >= 8 ? key - 8 : key);
        e.key_release = (state == WL_KEYBOARD_KEY_STATE_RELEASED);
        self->events_.push_back(e);
    }
    static void OnModifiers(void*, wl_keyboard*, uint32_t, uint32_t, uint32_t,
                            uint32_t, uint32_t) {}
    static void OnRepeatInfo(void*, wl_keyboard*, int32_t, int32_t) {}

    static void OnPointerEnter(void*, wl_pointer*, uint32_t, wl_surface*,
                               wl_fixed_t, wl_fixed_t) {}
    static void OnPointerLeave(void*, wl_pointer*, uint32_t, wl_surface*) {}
    static void OnPointerMotion(void* data, wl_pointer*, uint32_t, wl_fixed_t x,
                                wl_fixed_t y) {
        auto* self = static_cast<WaylandWindow*>(data);
        InputEvent e;
        e.kind = InputEvent::Kind::kMouseMove;
        e.x = static_cast<uint16_t>(wl_fixed_to_int(x));
        e.y = static_cast<uint16_t>(wl_fixed_to_int(y));
        self->events_.push_back(e);
    }
    static void OnPointerButton(void* data, wl_pointer*, uint32_t, uint32_t,
                                uint32_t button, uint32_t state) {
        auto* self = static_cast<WaylandWindow*>(data);
        InputEvent e;
        e.kind = InputEvent::Kind::kMouseButton;
        // BTN_LEFT 0x110, BTN_RIGHT 0x111, BTN_MIDDLE 0x112.
        e.button = (button == 0x110) ? 1 : (button == 0x111) ? 2 : 3;
        e.button_down = (state == WL_POINTER_BUTTON_STATE_PRESSED);
        self->events_.push_back(e);
    }
    static void OnPointerAxis(void* data, wl_pointer*, uint32_t, uint32_t axis,
                              wl_fixed_t value) {
        if (axis != WL_POINTER_AXIS_VERTICAL_SCROLL) return;
        auto* self = static_cast<WaylandWindow*>(data);
        InputEvent e;
        e.kind = InputEvent::Kind::kMouseWheel;
        e.wheel_delta = static_cast<int16_t>(wl_fixed_to_int(value) > 0 ? -1 : 1);
        self->events_.push_back(e);
    }
    static void OnPointerFrame(void*, wl_pointer*) {}
    static void OnPointerAxisSource(void*, wl_pointer*, uint32_t) {}
    static void OnPointerAxisStop(void*, wl_pointer*, uint32_t, uint32_t) {}
    static void OnPointerAxisDiscrete(void*, wl_pointer*, uint32_t, int32_t) {}

 private:
    bool CreateBuffer(std::string& why) {
        const size_t stride = static_cast<size_t>(pixels_.width()) * 4;
        const size_t size = stride * pixels_.height();
        const int fd = CreateShmFile(size);
        if (fd < 0) {
            why = "cannot create the Wayland shm file";
            return false;
        }
        shm_data_ = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (shm_data_ == MAP_FAILED) {
            close(fd);
            shm_data_ = nullptr;
            why = "mmap of the Wayland shm buffer failed";
            return false;
        }
        wl_shm_pool* pool = wl_shm_create_pool(shm_, fd, static_cast<int>(size));
        buffer_ = wl_shm_pool_create_buffer(
            pool, 0, pixels_.width(), pixels_.height(), static_cast<int>(stride),
            WL_SHM_FORMAT_XRGB8888);
        wl_shm_pool_destroy(pool);
        close(fd);
        if (buffer_ == nullptr) {
            why = "wl_shm_pool_create_buffer failed";
            return false;
        }
        return true;
    }

    void Destroy() {
        if (buffer_ != nullptr) wl_buffer_destroy(buffer_);
        if (pointer_ != nullptr) wl_pointer_destroy(pointer_);
        if (keyboard_ != nullptr) wl_keyboard_destroy(keyboard_);
        if (seat_ != nullptr) wl_seat_destroy(seat_);
        if (toplevel_ != nullptr) xdg_toplevel_destroy(toplevel_);
        if (xdg_surface_ != nullptr) xdg_surface_destroy(xdg_surface_);
        if (surface_ != nullptr) wl_surface_destroy(surface_);
        if (wm_base_ != nullptr) xdg_wm_base_destroy(wm_base_);
        if (shm_ != nullptr) wl_shm_destroy(shm_);
        if (compositor_ != nullptr) wl_compositor_destroy(compositor_);
        if (registry_ != nullptr) wl_registry_destroy(registry_);
        if (display_ != nullptr) wl_display_disconnect(display_);
        if (shm_data_ != nullptr) {
            munmap(shm_data_,
                   static_cast<size_t>(pixels_.width()) * 4 * pixels_.height());
            shm_data_ = nullptr;
        }
    }

    static const wl_registry_listener kRegistryListener;
    static const xdg_wm_base_listener kWmBaseListener;
    static const xdg_surface_listener kXdgSurfaceListener;
    static const xdg_toplevel_listener kToplevelListener;
    static const wl_seat_listener kSeatListener;
    static const wl_keyboard_listener kKeyboardListener;
    static const wl_pointer_listener kPointerListener;

    Surface pixels_;
    wl_display* display_ = nullptr;
    wl_registry* registry_ = nullptr;
    wl_compositor* compositor_ = nullptr;
    wl_shm* shm_ = nullptr;
    xdg_wm_base* wm_base_ = nullptr;
    wl_seat* seat_ = nullptr;
    wl_keyboard* keyboard_ = nullptr;
    wl_pointer* pointer_ = nullptr;
    wl_surface* surface_ = nullptr;
    xdg_surface* xdg_surface_ = nullptr;
    xdg_toplevel* toplevel_ = nullptr;
    wl_buffer* buffer_ = nullptr;
    void* shm_data_ = nullptr;
    std::deque<InputEvent> events_;
    bool closed_ = false;
    bool configured_ = false;
    size_t present_count_ = 0;
};

// Designated initialisers leave the newer protocol members (e.g. xdg_toplevel
// wm_capabilities, wl_pointer axis_value120) zero-initialised, so this compiles
// against both older and newer wayland-protocols without listing every field.
// GCC still warns about the omitted fields; that warning is expected here.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
const wl_registry_listener WaylandWindow::kRegistryListener = {
    .global = OnGlobal,
    .global_remove = OnGlobalRemove};
const xdg_wm_base_listener WaylandWindow::kWmBaseListener = {.ping = OnPing};
const xdg_surface_listener WaylandWindow::kXdgSurfaceListener = {
    .configure = OnConfigure};
const xdg_toplevel_listener WaylandWindow::kToplevelListener = {
    .configure = OnToplevelConfigure,
    .close = OnToplevelClose,
    .configure_bounds = OnToplevelConfigureBounds};
const wl_seat_listener WaylandWindow::kSeatListener = {
    .capabilities = OnSeatCapabilities,
    .name = OnSeatName};
const wl_keyboard_listener WaylandWindow::kKeyboardListener = {
    .keymap = OnKeymap,
    .enter = OnEnter,
    .leave = OnLeave,
    .key = OnKey,
    .modifiers = OnModifiers,
    .repeat_info = OnRepeatInfo};
const wl_pointer_listener WaylandWindow::kPointerListener = {
    .enter = OnPointerEnter,
    .leave = OnPointerLeave,
    .motion = OnPointerMotion,
    .button = OnPointerButton,
    .axis = OnPointerAxis,
    .frame = OnPointerFrame,
    .axis_source = OnPointerAxisSource,
    .axis_stop = OnPointerAxisStop,
    .axis_discrete = OnPointerAxisDiscrete};
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

}  // namespace

std::unique_ptr<Window> CreateWaylandWindow(uint16_t width, uint16_t height,
                                            std::string& why) {
    auto w = std::make_unique<WaylandWindow>(width, height);
    if (!w->Start(why)) return nullptr;
    return w;
}

}  // namespace rtsc::ui

#endif  // !_WIN32 && RTSC_UI_WAYLAND
