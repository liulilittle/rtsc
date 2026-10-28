// UI window abstraction.
//
// The RDP client needs three things from a windowing system: a surface to draw
// into, a way to present it, and a stream of keyboard/mouse events. This header
// keeps those three behind one interface so the protocol/graphics layers never
// touch a platform API. A headless backend is always available (tests, CI);
// Win32 / X11 / Wayland backends plug in behind the same interface.

#pragma once

#include <cmath>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "rtsc/ui/surface.h"

// windows.h defines an object-like CreateWindow macro, which would rewrite the
// factory declared below (and every call to it) into CreateWindowA/W. Undefine
// it here so the platform-neutral name survives regardless of include order.
#ifdef CreateWindow
#undef CreateWindow
#endif

namespace rtsc::ui {

// The zoom presets offered by the View menu and the title-bar system menu:
// 50% .. 500% in 25% steps, with 50% and 75% first, matching mstsc's list.
// This is the single source of truth: the window uses it to label and tick its
// menu items and the view layer uses it to map a menu command to a zoom factor.
inline constexpr int kZoomPresetCount = 13;
inline constexpr double kZoomPresetValues[kZoomPresetCount] = {
    0.50, 0.75, 1.00, 1.25, 1.50, 1.75, 2.00,
    2.50, 3.00, 3.50, 4.00, 4.50, 5.00,
};

// The number of zoom presets. A function rather than a bare constant so a test
// can assert on it without tripping C4127 (constant condition) under /WX.
inline int ZoomPresetCount() { return kZoomPresetCount; }

// The zoom factor (1.0 == 1:1) of preset `index` (0 .. kZoomPresetCount-1).
// index 0 is 50%, index 2 is 100%, index 12 is 500%.
inline double ZoomPresetZoom(int index) {
    if (index < 0 || index >= kZoomPresetCount) return 1.0;
    return kZoomPresetValues[index];
}

// The menu label of preset `index`, e.g. "50%".
inline const char* ZoomPresetLabel(int index) {
    static const char* const kLabels[kZoomPresetCount] = {
        "50%",  "75%",  "100%", "125%", "150%", "175%", "200%",
        "250%", "300%", "350%", "400%", "450%", "500%",
    };
    if (index < 0 || index >= kZoomPresetCount) return "100%";
    return kLabels[index];
}

// The preset nearest to `zoom`, or -1 when the zoom is not on a preset (a
// wheel-driven value, or fit mode). Used to tick the menu item that matches
// the current zoom.
inline int ZoomPresetIndex(double zoom) {
    for (int i = 0; i < kZoomPresetCount; ++i) {
        if (std::fabs(zoom - kZoomPresetValues[i]) < 1e-9) return i;
    }
    return -1;
}

// Client-side UI command ids carried by InputEvent::kUiCommand. The window
// backend turns its menu items into these; they are never forwarded to the
// server. kCmdZoomPresetFirst..kCmdZoomPresetLast address the zoom presets by
// index (0 .. kZoomPresetCount-1).
constexpr uint8_t kCmdZoomPresetFirst = 1;
constexpr uint8_t kCmdZoomPresetLast = 13;
constexpr uint8_t kCmdFit = 14;              // fit the remote desktop to the window
constexpr uint8_t kCmdToggleSmartSizing = 15;  // same as fit, as a menu toggle
constexpr uint8_t kCmdToggleFullscreen = 16;
constexpr uint8_t kCmdConnectionInfo = 17;
constexpr uint8_t kCmdToggleSmartCard = 18;
// Send the Secure Attention Sequence (Ctrl+Alt+Del) to the remote session.
// mstsc maps this to Ctrl+Alt+End; the window backend raises it from that chord
// (and from the Input menu) so the protocol layer can send the SAS.
constexpr uint8_t kCmdSendCtrlAltDel = 19;
// Toggle where the Windows key is applied (see WinKeyMode). The window backend
// only forwards the Windows key while the mode asks for it.
constexpr uint8_t kCmdToggleWinKeyRemote = 20;

// Where the Windows key is applied. mstsc's "Apply Windows key combinations"
// setting has the same three choices. The default is kLocal: the Windows key
// opens the local Start menu, exactly as it does outside the session.
enum class WinKeyMode : uint8_t {
    kLocal = 0,
    kRemote = 1,
    kFullscreenOnly = 2,
};
constexpr uint8_t kCmdHelp = 19;

// The state the window needs in order to label and tick its view menu items.
// Kept platform neutral so rtsc::ui does not depend on rtsc::client.
struct ViewMenuState {
    double zoom = 1.0;        // 1.0 == 1:1
    bool fit = true;          // smart sizing (fit to window)
    bool fullscreen = false;
    bool smart_card = true;   // smart card redirection requested
};

// A normalised input event. The platform backend translates native events into
// this shape; the protocol layer turns them into Fast-Path input events.
struct InputEvent {
    enum class Kind : uint8_t {
        kNone,
        kKey,
        kMouseMove,
        kMouseButton,
        kMouseWheel,
        kClose,
        kUiCommand,  // client-side UI command (not forwarded to the server)
    };

    Kind kind = Kind::kNone;

    // kKey
    uint8_t scancode = 0;
    bool key_release = false;
    bool key_extended = false;

    // kMouseMove
    uint16_t x = 0;
    uint16_t y = 0;

    // kMouseButton (button: 1 = left, 2 = right, 3 = middle)
    uint8_t button = 0;
    bool button_down = false;

    // kMouseWheel (positive = up)
    int16_t wheel_delta = 0;

    // kUiCommand: one of the kCmd* ids above (zoom preset index, fit, smart
    // sizing, fullscreen, connection info, smart card).
    uint8_t command = 0;
};

#if defined(_WIN32)
// ---- Win32 key-message translation -------------------------------------
//
// The Win32 backend turns WM_KEYDOWN / WM_KEYUP / WM_SYSKEYDOWN / WM_SYSKEYUP
// into set-1 scancode key events ([MS-RDPBCGR] 2.2.8.1.2.2). The translation is
// a pure function of (message, virtual key, lParam) so it is testable without an
// HWND or an interactive desktop. The four message ids are mirrored as plain
// constants so this header stays free of windows.h.
//
// `vk_to_scancode` is the layout mapper (MapVirtualKeyW(vk, MAPVK_VK_TO_VSC));
// nullptr selects it. Tests inject a fake so the mapper's behaviour and its
// zero result are exercised deterministically.
struct KeyTranslation {
    // False when the message must be DROPPED instead of forwarded: the AltGr
    // pseudo-Ctrl, and any key whose scancode cannot be resolved (a scancode of
    // 0 on the wire is not a key and would type garbage remotely).
    bool forward = false;
    uint8_t scancode = 0;
    bool release = false;
    bool extended = false;
};

inline constexpr uint32_t kWin32WmKeyDown = 0x0100;
inline constexpr uint32_t kWin32WmKeyUp = 0x0101;
inline constexpr uint32_t kWin32WmSysKeyDown = 0x0104;
inline constexpr uint32_t kWin32WmSysKeyUp = 0x0105;

// AltGr reaches Windows as a pseudo Ctrl (VK_CONTROL / VK_LCONTROL with the
// extended bit set) plus a right Alt (VK_RMENU, or VK_MENU with the extended
// bit, delivered as WM_SYSKEYDOWN). The pseudo Ctrl is dropped so the remote
// does not see Ctrl+AltGr chords; the right Alt is forwarded as set-1 scancode
// 0x38 with the extended flag. A real right Ctrl (VK_RCONTROL) is unaffected.
KeyTranslation TranslateWin32KeyMessage(
    uint32_t msg, uint32_t vk, uint32_t lparam,
    uint32_t (*vk_to_scancode)(uint32_t vk) = nullptr);
#endif  // defined(_WIN32)

class Window {
 public:
    virtual ~Window() = default;

    // The RGBA surface to draw into. Present() makes it visible.
    virtual Surface& surface() = 0;
    virtual void Present() = 0;

    // Dequeues one pending input event. Returns false when the queue is empty.
    virtual bool PollEvent(InputEvent& out) = 0;

    virtual void Close() = 0;
    virtual bool closed() const = 0;
    virtual const char* backend_name() const = 0;

    // Resizes the backend's surface (and its native backing store) to the given
    // client-area size. The default is a no-op so backends without a resizable
    // buffer (X11 / Wayland) do not have to implement it; Win32 and headless do.
    virtual void Resize(uint16_t width, uint16_t height) {
        (void)width;
        (void)height;
    }

    // Updates the window title. The default is a no-op (e.g. headless).
    virtual void SetTitle(const std::string& title) { (void)title; }

    // Toggles borderless fullscreen (maximised, caption/menu/border hidden).
    // The default is a no-op so backends without a window (headless) and the
    // X11/Wayland backends, which manage the surface themselves, keep working.
    virtual void SetFullscreen(bool on) { (void)on; }
    virtual bool fullscreen() const { return false; }

    // Selects where the Windows key is applied (see WinKeyMode). The default is
    // a no-op so backends without a keyboard hook (headless, X11, Wayland) keep
    // working; the Win32 backend installs a low-level hook when the mode asks it
    // to forward the Windows key.
    virtual void SetWinKeyMode(WinKeyMode mode) { (void)mode; }
    virtual WinKeyMode win_key_mode() const { return WinKeyMode::kLocal; }

    // Publishes the view state the window uses to label and tick its menu
    // items (zoom percent, smart sizing, fullscreen, smart card).
    virtual void SetViewMenuState(const ViewMenuState& state) { (void)state; }

    // Registers a callback invoked when the local clipboard changed (Win32:
    // WM_CLIPBOARDUPDATE). The CLIPRDR channel handler uses it to push the new
    // clipboard formats to the server. The default is a no-op so backends
    // without a clipboard observer (headless, X11, Wayland) keep working.
    virtual void SetClipboardChangeCallback(std::function<void()> callback) {
        (void)callback;
    }

    // The native window handle (HWND on Win32, Window on X11, ...) or nullptr.
    // The front-end uses it to parent a native dialog (the connection
    // information dialog). The default is nullptr (headless / no window).
    virtual void* native_handle() const { return nullptr; }

    // Test hook: enqueue an event as if the platform had produced it.
    virtual void PushEventForTest(const InputEvent& event) = 0;
};

// Creates a window. An empty `backend` means the platform default. Returns
// nullptr with `why` set when no backend can serve the request (e.g. headless
// CI without a display). The "headless" backend is always available.
std::unique_ptr<Window> CreateWindow(uint16_t width, uint16_t height,
                                     const std::string& backend, std::string& why);

}  // namespace rtsc::ui
