// X11 window backend for rtsc::ui::Window.
//
// Compiled only on non-Windows when RTSC_UI_X11=ON and libX11 is present. It
// owns an X11 window and a persistent XImage that mirrors the RGBA Surface:
// Present() converts RGBA to the X server's BGRA byte order and XPutImage's it.
// Native events are translated into the normalised InputEvent shape.

#include "rtsc/ui/window.h"

#if !defined(_WIN32) && defined(RTSC_UI_X11)

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>

#include <cstdlib>
#include <cstring>
#include <deque>
#include <string>
#include <utility>

namespace rtsc::ui {
namespace {

// X11 keycodes are evdev scancodes + 8 on the standard PC layout; this maps
// back to the RDP set-1 scancode the Fast-Path input event wants.
uint8_t KeycodeToScancode(KeyCode kc) {
    if (kc >= 8) return static_cast<uint8_t>(kc - 8);
    return static_cast<uint8_t>(kc);
}

class X11Window final : public Window {
 public:
    X11Window(uint16_t width, uint16_t height) : surface_(width, height) {}
    ~X11Window() override { Destroy(); }

    bool Start(std::string& why) {
        dpy_ = XOpenDisplay(nullptr);
        if (dpy_ == nullptr) {
            why = "cannot open the X display (DISPLAY unset or no X server)";
            return false;
        }
        screen_ = DefaultScreen(dpy_);
        visual_ = DefaultVisual(dpy_, screen_);
        depth_ = DefaultDepth(dpy_, screen_);

        win_ = XCreateSimpleWindow(dpy_, RootWindow(dpy_, screen_), 0, 0,
                                   surface_.width(), surface_.height(), 0,
                                   BlackPixel(dpy_, screen_),
                                   BlackPixel(dpy_, screen_));
        if (win_ == 0) {
            why = "XCreateSimpleWindow failed";
            return false;
        }
        XSelectInput(dpy_, win_,
                     KeyPressMask | KeyReleaseMask | PointerMotionMask |
                         ButtonPressMask | ButtonReleaseMask | ExposureMask |
                         StructureNotifyMask);
        wm_delete_ = XInternAtom(dpy_, "WM_DELETE_WINDOW", False);
        XSetWMProtocols(dpy_, win_, &wm_delete_, 1);
        XStoreName(dpy_, win_, "RTSC");
        XMapWindow(dpy_, win_);
        gc_ = XCreateGC(dpy_, win_, 0, nullptr);
        if (gc_ == nullptr) {
            why = "XCreateGC failed";
            return false;
        }

        // A persistent XImage backed by a scratch buffer in the server's byte
        // order (BGRA on a little-endian TrueColor visual).
        image_data_ = static_cast<char*>(
            std::calloc(static_cast<size_t>(surface_.width()) * surface_.height(),
                        4));
        if (image_data_ == nullptr) {
            why = "cannot allocate the XImage buffer";
            return false;
        }
        img_ = XCreateImage(dpy_, visual_, depth_, ZPixmap, 0, image_data_,
                            surface_.width(), surface_.height(), 32, 0);
        if (img_ == nullptr) {
            why = "XCreateImage failed";
            return false;
        }
        XFlush(dpy_);
        return true;
    }

    Surface& surface() override { return surface_; }

    void Present() override {
        if (dpy_ == nullptr || img_ == nullptr) return;
        // Surface is RGBA; the X server wants BGRA.
        const uint8_t* src = surface_.data();
        uint8_t* dst = reinterpret_cast<uint8_t*>(img_->data);
        const size_t n = surface_.size();
        for (size_t i = 0; i + 3 < n; i += 4) {
            dst[i + 0] = src[i + 2];
            dst[i + 1] = src[i + 1];
            dst[i + 2] = src[i + 0];
            dst[i + 3] = 0xFF;
        }
        XPutImage(dpy_, win_, gc_, img_, 0, 0, 0, 0, surface_.width(),
                  surface_.height());
        XFlush(dpy_);
        ++present_count_;
    }

    bool PollEvent(InputEvent& out) override {
        if (dpy_ != nullptr) {
            while (XPending(dpy_) > 0) {
                XEvent ev;
                XNextEvent(dpy_, &ev);
                Translate(ev);
            }
        }
        if (events_.empty()) return false;
        out = events_.front();
        events_.pop_front();
        return true;
    }

    void Close() override {
        if (dpy_ != nullptr && win_ != 0) {
            XDestroyWindow(dpy_, win_);
            win_ = 0;
        }
        closed_ = true;
    }
    bool closed() const override { return closed_; }
    const char* backend_name() const override { return "x11"; }
    void PushEventForTest(const InputEvent& event) override {
        events_.push_back(event);
    }

 private:
    void Translate(const XEvent& ev) {
        switch (ev.type) {
            case KeyPress:
            case KeyRelease: {
                InputEvent e;
                e.kind = InputEvent::Kind::kKey;
                e.scancode = KeycodeToScancode(ev.xkey.keycode);
                e.key_release = (ev.type == KeyRelease);
                e.key_extended = false;
                events_.push_back(e);
                break;
            }
            case MotionNotify: {
                InputEvent e;
                e.kind = InputEvent::Kind::kMouseMove;
                e.x = static_cast<uint16_t>(ev.xmotion.x);
                e.y = static_cast<uint16_t>(ev.xmotion.y);
                events_.push_back(e);
                break;
            }
            case ButtonPress:
            case ButtonRelease: {
                InputEvent e;
                if (ev.xbutton.button == Button4 || ev.xbutton.button == Button5) {
                    e.kind = InputEvent::Kind::kMouseWheel;
                    e.wheel_delta = (ev.xbutton.button == Button4) ? 1 : -1;
                } else {
                    e.kind = InputEvent::Kind::kMouseButton;
                    e.x = static_cast<uint16_t>(ev.xbutton.x);
                    e.y = static_cast<uint16_t>(ev.xbutton.y);
                    e.button = (ev.xbutton.button == Button1)
                                   ? 1
                                   : (ev.xbutton.button == Button3) ? 2 : 3;
                    e.button_down = (ev.type == ButtonPress);
                }
                events_.push_back(e);
                break;
            }
            case ClientMessage:
                if (static_cast<Atom>(ev.xclient.data.l[0]) == wm_delete_) {
                    closed_ = true;
                }
                break;
            case DestroyNotify:
                closed_ = true;
                break;
            default:
                break;
        }
    }

    void Destroy() {
        if (img_ != nullptr) {
            // XDestroyImage frees img_->data, which is our calloc'd buffer.
            XDestroyImage(img_);
            img_ = nullptr;
            image_data_ = nullptr;
        }
        if (gc_ != nullptr) {
            XFreeGC(dpy_, gc_);
            gc_ = nullptr;
        }
        if (win_ != 0) {
            XDestroyWindow(dpy_, win_);
            win_ = 0;
        }
        if (dpy_ != nullptr) {
            XCloseDisplay(dpy_);
            dpy_ = nullptr;
        }
    }

    Surface surface_;
    Display* dpy_ = nullptr;
    ::Window win_ = 0;  // X11's Window (XID), not rtsc::ui::Window
    GC gc_ = nullptr;
    Visual* visual_ = nullptr;
    int screen_ = 0;
    int depth_ = 0;
    Atom wm_delete_ = 0;
    XImage* img_ = nullptr;
    char* image_data_ = nullptr;
    std::deque<InputEvent> events_;
    bool closed_ = false;
    size_t present_count_ = 0;
};

}  // namespace

std::unique_ptr<Window> CreateX11Window(uint16_t width, uint16_t height,
                                        std::string& why) {
    auto w = std::make_unique<X11Window>(width, height);
    if (!w->Start(why)) return nullptr;
    return w;
}

}  // namespace rtsc::ui

#endif  // !_WIN32 && RTSC_UI_X11
