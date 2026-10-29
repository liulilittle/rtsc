// Win32 window backend for rtsc::ui::Window.
//
// Compiled only on Windows. It owns a top-level window and a 32-bit DIB section
// that mirrors the RGBA Surface: Present() converts RGBA to the BGRA the DIB
// wants and BitBlt's it. Native messages are translated into the normalised
// InputEvent shape so the protocol layer never sees a Win32 type.
//
// The window carries the mstsc-style view menu (13 zoom presets, fullscreen,
// smart sizing, connection information, smart card redirection). The same
// items are reachable two ways, exactly like mstsc:
//   * the top menu bar ("查看"), and
//   * the title-bar system menu (right-click on the title bar), which is the
//     real system menu with the standard items plus ours.
// Both are rebuilt/updated from the ViewMenuState the front-end publishes, so
// the tick marks and the "缩放(Z)(N%)" label always reflect the live view.

#include "rtsc/ui/window.h"

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <windowsx.h>

#include <deque>
#include <string>
#include <utility>

namespace rtsc::ui {
namespace {

constexpr const wchar_t* kClassName = L"RtscWindowClass";

// Per-window pointer, set with SetWindowLongPtr in WM_NCCREATE.
constexpr const char* kProp = "rtsc_window";

// Menu command ids. These become InputEvent::kUiCommand values and are never
// forwarded to the server. The zoom presets are kMenuZoomBase + index.
enum : UINT {
    kMenuZoomBase = 1001,
    kMenuFullscreen = 1101,
    kMenuSmartSizing = 1102,
    kMenuConnInfo = 1103,
    kMenuSmartCard = 1104,
    kMenuHelp = 1105,
};

// UTF-8 (the codebase's string encoding) to UTF-16.
std::wstring ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(static_cast<size_t>(n) - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

// Index of the (single) submenu item in `menu`, or -1. Used to retitle the
// "缩放(Z)(N%)" entry when the zoom changes.
int FindPopupIndex(HMENU menu) {
    if (menu == nullptr) return -1;
    const int n = GetMenuItemCount(menu);
    for (int i = 0; i < n; ++i) {
        MENUITEMINFOW mii{};
        mii.cbSize = sizeof(mii);
        mii.fMask = MIIM_SUBMENU;
        if (GetMenuItemInfoW(menu, static_cast<UINT>(i), TRUE, &mii) &&
            mii.hSubMenu != nullptr) {
            return i;
        }
    }
    return -1;
}

// True when the system menu already carries our items (Windows can reset it on
// a maximize/restore, so this is re-checked before every use).
bool HasSystemItems(HMENU menu) {
    if (menu == nullptr) return false;
    MENUITEMINFOW mii{};
    mii.cbSize = sizeof(mii);
    mii.fMask = MIIM_ID;
    if (!GetMenuItemInfoW(menu, kMenuConnInfo, MF_BYCOMMAND, &mii)) return false;
    return mii.wID == kMenuConnInfo;
}

// Keys whose set-1 scancode is inherently an 0xE0-prefixed (extended) one.
// A real WM_KEY* carries that in lParam bit24, but synthetic / automation
// messages (lParam scancode field 0) do not, and the virtual key still tells us
// the key is extended. VK_LCONTROL/VK_CONTROL are deliberately absent: 0x1D is
// shared with VK_RCONTROL, which is listed.
//
// VK_NUMLOCK is deliberately absent: NumLock is never extended, and Pause (its
// scancode twin 0x45) is handled on its own two-key path. VK_SNAPSHOT is kept
// because PrintScreen's set-1 scancode (0x37) can be 0xE0-prefixed on some
// keyboards, but that classification is UNVERIFIED against a real machine.
bool IsInherentExtendedVirtualKey(uint32_t vk) {
    switch (vk) {
        case VK_RCONTROL:
        case VK_RMENU:
        case VK_LWIN:
        case VK_RWIN:
        case VK_INSERT:
        case VK_DELETE:
        case VK_HOME:
        case VK_END:
        case VK_PRIOR:
        case VK_NEXT:
        case VK_LEFT:
        case VK_UP:
        case VK_RIGHT:
        case VK_DOWN:
        case VK_SNAPSHOT:  // unverified: may be 0xE0 0x37 or plain 0x37
        case VK_DIVIDE:
            return true;
        default:
            return false;
    }
}

class Win32Window final : public Window {
 public:
    Win32Window(uint16_t width, uint16_t height) : surface_(width, height) {}
    ~Win32Window() override { Destroy(); }

    bool Start(std::string& why) {
        HINSTANCE inst = GetModuleHandleW(nullptr);
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = &Win32Window::WndProc;
        wc.hInstance = inst;
        wc.lpszClassName = kClassName;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        // RegisterClassEx may fail with ERROR_CLASS_ALREADY_EXISTS on the second
        // window; that is fine.
        if (RegisterClassExW(&wc) == 0 &&
            GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            why = "RegisterClassEx failed";
            return false;
        }

        // The top menu bar. It is built before the window so AdjustWindowRect
        // accounts for it in the client size.
        BuildMenus();

        RECT r{0, 0, surface_.width(), surface_.height()};
        AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, menu_ != nullptr);
        hwnd_ = CreateWindowExW(0, kClassName, L"RTSC", WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left,
                                r.bottom - r.top, nullptr, menu_, inst, this);
        if (hwnd_ == nullptr) {
            why = "CreateWindowEx failed";
            return false;
        }
        ShowWindow(hwnd_, SW_SHOW);
        UpdateWindow(hwnd_);
        // Observe local clipboard changes (WM_CLIPBOARDUPDATE) so the CLIPRDR
        // channel can push the new clipboard formats to the server.
        AddClipboardFormatListener(hwnd_);

        // The title-bar system menu is the real one, extended with our items.
        BuildSystemMenu();

        HDC screen = GetDC(nullptr);
        mem_dc_ = CreateCompatibleDC(screen);
        ReleaseDC(nullptr, screen);
        if (mem_dc_ == nullptr) {
            why = "CreateCompatibleDC failed";
            return false;
        }
        RecreateBitmap();
        if (bitmap_ == nullptr || bits_ == nullptr) {
            why = "CreateDIBSection failed";
            return false;
        }
        return true;
    }

    Surface& surface() override { return surface_; }

    void Resize(uint16_t width, uint16_t height) override {
        if (width == 0 || height == 0) return;
        if (width == surface_.width() && height == surface_.height()) return;
        surface_ = Surface(width, height);
        RecreateBitmap();
    }

    void SetTitle(const std::string& title) override {
        if (hwnd_ == nullptr) return;
        const std::wstring wide = ToWide(title);
        SetWindowTextW(hwnd_, wide.c_str());
    }

    void SetViewMenuState(const ViewMenuState& state) override {
        view_state_ = state;
        UpdateMenuState();
    }

    void SetClipboardChangeCallback(std::function<void()> callback) override {
        clipboard_callback_ = std::move(callback);
    }

    void SetFullscreen(bool on) override {
        if (hwnd_ == nullptr || on == fullscreen_) return;
        if (on) {
            GetWindowRect(hwnd_, &saved_rect_);
            saved_style_ = GetWindowLongPtrW(hwnd_, GWL_STYLE);
            // Borderless, menu-less, covering the monitor the window is on.
            SetMenu(hwnd_, nullptr);
            SetWindowLongPtrW(hwnd_, GWL_STYLE, WS_POPUP | WS_VISIBLE);
            MONITORINFO mi{};
            mi.cbSize = sizeof(mi);
            RECT area{};
            if (GetMonitorInfoW(MonitorFromWindow(hwnd_, MONITOR_DEFAULTTONEAREST),
                                &mi) != 0) {
                area = mi.rcMonitor;
            } else {
                SetRect(&area, 0, 0, GetSystemMetrics(SM_CXSCREEN),
                        GetSystemMetrics(SM_CYSCREEN));
            }
            SetWindowPos(hwnd_, HWND_TOP, area.left, area.top,
                         area.right - area.left, area.bottom - area.top,
                         SWP_FRAMECHANGED | SWP_NOOWNERZORDER);
        } else {
            SetWindowLongPtrW(hwnd_, GWL_STYLE, saved_style_);
            if (menu_ != nullptr) {
                SetMenu(hwnd_, menu_);
                DrawMenuBar(hwnd_);
            }
            SetWindowPos(hwnd_, nullptr, saved_rect_.left, saved_rect_.top,
                         saved_rect_.right - saved_rect_.left,
                         saved_rect_.bottom - saved_rect_.top,
                         SWP_FRAMECHANGED | SWP_NOZORDER);
        }
        fullscreen_ = on;
    }

    bool fullscreen() const override { return fullscreen_; }

    void SetWinKeyMode(WinKeyMode mode) override { win_key_mode_ = mode; }
    WinKeyMode win_key_mode() const override { return win_key_mode_; }

    void* native_handle() const override {
        return reinterpret_cast<void*>(hwnd_);
    }

    void Present() override {
        if (hwnd_ == nullptr || bits_ == nullptr) return;
        // Surface is RGBA; the DIB wants BGRA. RgbaToBgra runs the per-pixel
        // byte swap vectorised (two pixels per 64-bit word) so a full-screen
        // 1280x1024 Present measures ~0.35-0.45 ms instead of ~0.9-1.2 ms for
        // the old per-byte loop.
        RgbaToBgra(static_cast<uint8_t*>(bits_), surface_.data(),
                   surface_.size() / 4);
        InvalidateRect(hwnd_, nullptr, FALSE);
        UpdateWindow(hwnd_);
        ++present_count_;
    }

    bool PollEvent(InputEvent& out) override {
        MSG msg;
        while (PeekMessageW(&msg, hwnd_, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                closed_ = true;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (events_.empty()) return false;
        out = events_.front();
        events_.pop_front();
        return true;
    }

    void Close() override {
        ReleaseHeldKeys();
        ReleaseHeldButtons();
        if (hwnd_ != nullptr) {
            DestroyWindow(hwnd_);
            hwnd_ = nullptr;
        }
        closed_ = true;
    }
    bool closed() const override { return closed_; }
    const char* backend_name() const override { return "win32"; }
    void PushEventForTest(const InputEvent& event) override {
        events_.push_back(event);
    }

    // Called from the static WndProc. Returns true when the message is fully
    // handled, so WndProc must not also call DefWindowProc for it.
    bool OnNativeMessage(UINT msg, WPARAM wp, LPARAM lp) {
        switch (msg) {
            case WM_CLOSE:
                ReleaseHeldKeys();
                ReleaseHeldButtons();
                closed_ = true;
                PostQuitMessage(0);
                return false;  // DefWindowProc destroys the window
            case WM_KILLFOCUS:
                ReleaseHeldKeys();
                ReleaseHeldButtons();
                return false;
            case WM_ACTIVATE:
                // WA_INACTIVE is the observable focus-loss path for backends
                // that get WM_ACTIVATE without a WM_KILLFOCUS. Both the held
                // keys and the held mouse buttons are released so the remote
                // does not keep them latched.
                if (LOWORD(wp) == WA_INACTIVE) {
                    ReleaseHeldKeys();
                    ReleaseHeldButtons();
                }
                return false;
            case WM_SIZE: {
                const int w = LOWORD(lp);
                const int h = HIWORD(lp);
                if (w > 0 && h > 0) {
                    Resize(static_cast<uint16_t>(w), static_cast<uint16_t>(h));
                }
                return false;
            }
            case WM_CONTEXTMENU: {
                // Right-click on the title bar (any non-client area) opens the
                // system menu with our items; a client-area right-click keeps
                // the default behaviour.
                POINT pt{};
                BOOL have_pt = FALSE;
                if (lp == -1) {
                    // lParam == -1 means "no position": use the cursor.
                    have_pt = GetCursorPos(&pt);
                } else {
                    pt.x = GET_X_LPARAM(lp);
                    pt.y = GET_Y_LPARAM(lp);
                    have_pt = TRUE;
                }
                if (!have_pt) return false;
                const LRESULT hit =
                    SendMessageW(hwnd_, WM_NCHITTEST, 0,
                                 static_cast<LPARAM>(MAKELONG(
                                     static_cast<SHORT>(pt.x),
                                     static_cast<SHORT>(pt.y))));
                if (hit == HTCLIENT) return false;
                BuildSystemMenu();
                if (sys_menu_ != nullptr) {
                    TrackPopupMenuEx(sys_menu_,
                                     TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x,
                                     pt.y, hwnd_, nullptr);
                }
                return true;
            }
            case WM_COMMAND:
            case WM_SYSCOMMAND: {
                const UINT raw = static_cast<UINT>(wp);
                if (HandleCommand(raw)) return true;
                if (msg == WM_SYSCOMMAND && HandleCommand(raw & 0xFFF0)) {
                    return true;
                }
                return false;  // SC_* goes to DefWindowProc
            }
            case WM_KEYDOWN:
            case WM_KEYUP:
            case WM_SYSKEYDOWN:
            case WM_SYSKEYUP: {
                // The fast-path keyboard event carries the set-1 scancode
                // ([MS-RDPBCGR] 2.2.8.1.2.2), never the virtual-key code; see
                // TranslateWin32KeyMessage for the AltGr handling.
                const uint32_t vk = static_cast<uint32_t>(wp);
                // Pause/Break is the CTRL(EXTENDED1)+NUMLOCK sequence, never a
                // bare 0x45 (that is NumLock's scancode). Raise the UI command
                // once per press; the front-end sends EncodePauseKey().
                if (vk == VK_PAUSE) {
                    if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) {
                        if (!pause_down_) {
                            pause_down_ = true;
                            PushCommand(kCmdSendPause);
                        }
                    } else {
                        pause_down_ = false;
                    }
                    return true;
                }
                // kLocal keeps the Windows key for the local shell. Return
                // false so DefWindowProc still sees the message; it is never
                // forwarded to the remote. kFullscreenOnly is the same for now
                // (TODO: gate on fullscreen_ once that policy is decided).
                const bool win_key = vk == VK_LWIN || vk == VK_RWIN;
                if (win_key && win_key_mode_ != WinKeyMode::kRemote) {
                    return false;
                }
                const KeyTranslation key = TranslateWin32KeyMessage(
                    static_cast<uint32_t>(msg), vk,
                    static_cast<uint32_t>(lp), nullptr, win_key_mode_);
                switch (key_state_.Process(key)) {
                    case Win32KeyAction::kForward: {
                        InputEvent e;
                        e.kind = InputEvent::Kind::kKey;
                        e.scancode = key.scancode;
                        e.key_release = key.release;
                        e.key_extended = key.extended;
                        events_.push_back(e);
                        break;
                    }
                    case Win32KeyAction::kSendCtrlAltDel:
                        PushCommand(kCmdSendCtrlAltDel);
                        break;
                    case Win32KeyAction::kIgnore:
                        break;
                }
                // Alt+F4 stays local: TranslateWin32KeyMessage never forwards
                // it, and returning false lets DefWindowProc turn the message
                // into WM_CLOSE, exactly like mstsc. Every other system key
                // (right Alt, Alt+Space, Alt+<key>) is consumed here after
                // being forwarded so the local menu bar does not also react.
                const bool alt_f4 = vk == VK_F4 && ((lp & (1LL << 29)) != 0);
                return !alt_f4;
            }
            case WM_MOUSEMOVE: {
                InputEvent e;
                e.kind = InputEvent::Kind::kMouseMove;
                // lParam position is signed 16-bit; at the left/upper screen
                // edge it can go negative and LOWORD/HIWORD wrap it to ~65535.
                const int mx = GET_X_LPARAM(lp);
                const int my = GET_Y_LPARAM(lp);
                last_mouse_x_ = mx;
                last_mouse_y_ = my;
                e.x = static_cast<uint16_t>(mx < 0 ? 0 : mx);
                e.y = static_cast<uint16_t>(my < 0 ? 0 : my);
                events_.push_back(e);
                return true;
            }
            case WM_LBUTTONDOWN:
            case WM_LBUTTONUP:
            case WM_RBUTTONDOWN:
            case WM_RBUTTONUP:
            case WM_MBUTTONDOWN:
            case WM_MBUTTONUP:
            case WM_XBUTTONDOWN:
            case WM_XBUTTONUP: {
                InputEvent e;
                e.kind = InputEvent::Kind::kMouseButton;
                // Same signed-position handling as WM_MOUSEMOVE.
                const int bx = GET_X_LPARAM(lp);
                const int by = GET_Y_LPARAM(lp);
                last_mouse_x_ = bx;
                last_mouse_y_ = by;
                e.x = static_cast<uint16_t>(bx < 0 ? 0 : bx);
                e.y = static_cast<uint16_t>(by < 0 ? 0 : by);
                if (msg == WM_XBUTTONDOWN || msg == WM_XBUTTONUP) {
                    // GET_XBUTTON_WPARAM is 1 for X1 and 2 for X2.
                    e.button = static_cast<uint8_t>(
                        3 + GET_XBUTTON_WPARAM(wp));
                } else {
                    e.button = (msg == WM_LBUTTONDOWN || msg == WM_LBUTTONUP)
                                   ? 1
                                   : (msg == WM_RBUTTONDOWN ||
                                      msg == WM_RBUTTONUP)
                                         ? 2
                                         : 3;
                }
                const bool down = (msg == WM_LBUTTONDOWN ||
                                   msg == WM_RBUTTONDOWN ||
                                   msg == WM_MBUTTONDOWN ||
                                   msg == WM_XBUTTONDOWN);
                e.button_down = down;
                // Track the held buttons in a bitmask and derive the capture
                // lifetime from it: the first press installs SetCapture so a
                // drag that leaves the window still delivers the release, and
                // the last release drops it. A release that is lost (capture
                // stolen, see WM_CAPTURECHANGED) never strands the counter: the
                // mask is cleared and the missing up synthesised there.
                const uint32_t bit = 1u << e.button;
                if (down) {
                    if (held_buttons_ == 0) SetCapture(hwnd_);
                    held_buttons_ |= bit;
                } else {
                    held_buttons_ &= ~bit;
                    if (held_buttons_ == 0) ReleaseCapture();
                }
                events_.push_back(e);
                return true;
            }
            case WM_CAPTURECHANGED: {
                // The window lost the mouse capture (it was stolen by another
                // window, or released earlier). Any button that is still held
                // has lost its natural release message, so synthesise the ups
                // and clear the set; the next press re-arms SetCapture. A
                // normal ReleaseCapture at the last real up already cleared the
                // mask, so nothing is emitted here in the common case.
                ReleaseHeldButtons();
                return false;  // DefWindowProc keeps the bookkeeping
            }
            case WM_MOUSEWHEEL:
            case WM_MOUSEHWHEEL: {
                // Sub-notch mice report deltas of a fraction of WHEEL_DELTA
                // (120); the old integer division truncated 40/120 to 0 and
                // silently dropped the scroll. The raw delta is accumulated per
                // axis and an event is emitted only whenever a whole notch
                // crosses, carrying the sign; a delta that does not reach a
                // notch produces no event at all.
                const int raw_delta = GET_WHEEL_DELTA_WPARAM(wp);
                int& accum =
                    (msg == WM_MOUSEHWHEEL) ? wheel_accum_h_ : wheel_accum_v_;
                accum += raw_delta;
                const int steps = accum / WHEEL_DELTA;
                if (steps == 0) return true;
                accum -= steps * WHEEL_DELTA;
                InputEvent e;
                e.kind = InputEvent::Kind::kMouseWheel;
                const int16_t capped =
                    static_cast<int16_t>(steps > 32767 ? 32767
                                          : steps < -32768 ? -32768 : steps);
                e.wheel_delta = capped;
                e.horizontal = (msg == WM_MOUSEHWHEEL);
                // The pointer position has to travel with the wheel event: the
                // remote decides where to scroll from it. WM_MOUSEWHEEL carries
                // *screen* coordinates in lParam, unlike the other mouse
                // messages (reading them from wParam always yielded (0,0)).
                POINT pt{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
                if (::ScreenToClient(hwnd_, &pt)) {
                    e.x = static_cast<uint16_t>(pt.x < 0 ? 0 : pt.x);
                    e.y = static_cast<uint16_t>(pt.y < 0 ? 0 : pt.y);
                    last_mouse_x_ = pt.x;
                    last_mouse_y_ = pt.y;
                }
                events_.push_back(e);
                return true;
            }
            case WM_CLIPBOARDUPDATE: {
                if (clipboard_callback_) clipboard_callback_();
                return true;
            }
            case WM_PAINT: {
                PAINTSTRUCT ps;
                HDC dc = BeginPaint(hwnd_, &ps);
                if (mem_dc_ != nullptr) {
                    BitBlt(dc, 0, 0, surface_.width(), surface_.height(),
                           mem_dc_, 0, 0, SRCCOPY);
                }
                EndPaint(hwnd_, &ps);
                return false;
            }
            default:
                return false;
        }
    }

    size_t present_count() const { return present_count_; }

 private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        Win32Window* self = nullptr;
        if (msg == WM_NCCREATE) {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            self = static_cast<Win32Window*>(cs->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(self));
        } else {
            self = reinterpret_cast<Win32Window*>(
                GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        }
        if (self != nullptr && self->OnNativeMessage(msg, wp, lp)) {
            return 0;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }

    // The 13 zoom presets, with the current one ticked.
    HMENU BuildZoomPopup() {
        HMENU z = CreatePopupMenu();
        if (z == nullptr) return nullptr;
        for (int i = 0; i < kZoomPresetCount; ++i) {
            AppendMenuW(z, MF_STRING, kMenuZoomBase + static_cast<UINT>(i),
                        ToWide(ZoomPresetLabel(i)).c_str());
        }
        return z;
    }

    // Appends the zoom popup and the view commands to `menu`.
    void AppendViewCommands(HMENU menu, HMENU zoom) {
        if (menu == nullptr) return;
        const int current = ZoomPresetIndex(view_state_.zoom);
        const std::string label = std::string("缩放(Z)(") +
                                  ZoomPresetLabel(current < 0 ? 2 : current) + ")";
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(zoom),
                    ToWide(label).c_str());
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, kMenuFullscreen, L"全屏(F)");
        AppendMenuW(menu, MF_STRING, kMenuSmartSizing, L"智能调整大小(A)");
        AppendMenuW(menu, MF_STRING, kMenuConnInfo, L"连接信息(C)");
        AppendMenuW(menu, MF_STRING, kMenuSmartCard, L"重定向智能卡(D)");
    }

    void BuildMenus() {
        HMENU menu = CreateMenu();
        HMENU view = CreatePopupMenu();
        HMENU zoom = BuildZoomPopup();
        if (menu == nullptr || view == nullptr || zoom == nullptr) return;
        AppendViewCommands(view, zoom);
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(view),
                    L"查看(&V)");
        menu_ = menu;
        view_menu_ = view;
        zoom_menu_top_ = zoom;
    }

    void BuildSystemMenu() {
        if (hwnd_ == nullptr) return;
        HMENU sys = GetSystemMenu(hwnd_, FALSE);
        if (sys == nullptr) return;
        if (!HasSystemItems(sys)) {
            // Reorder: the standard items keep their system labels, then our
            // items, then 关闭(C) last (mstsc puts it at the bottom).
            RemoveMenu(sys, SC_CLOSE, MF_BYCOMMAND);
            AppendMenuW(sys, MF_STRING, kMenuHelp, L"帮助(H)");
            AppendMenuW(sys, MF_SEPARATOR, 0, nullptr);
            zoom_menu_sys_ = BuildZoomPopup();
            AppendViewCommands(sys, zoom_menu_sys_);
            AppendMenuW(sys, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(sys, MF_STRING, SC_CLOSE, L"关闭(C)");
        }
        sys_menu_ = sys;
        UpdateMenuState();
    }

    // Retitles the "缩放(Z)(N%)" entries and re-ticks the checkable items.
    void UpdateMenuState() {
        const int current = ZoomPresetIndex(view_state_.zoom);
        const std::string label = std::string("缩放(Z)(") +
                                  ZoomPresetLabel(current < 0 ? 2 : current) + ")";
        std::wstring wide = ToWide(label);
        const bool tick_zoom = !view_state_.fit;
        const UINT fit_check =
            view_state_.fit ? MF_CHECKED : MF_UNCHECKED;
        const UINT fs_check =
            view_state_.fullscreen ? MF_CHECKED : MF_UNCHECKED;
        const UINT sc_check =
            view_state_.smart_card ? MF_CHECKED : MF_UNCHECKED;

        for (HMENU z : {zoom_menu_top_, zoom_menu_sys_}) {
            if (z == nullptr) continue;
            for (int i = 0; i < kZoomPresetCount; ++i) {
                CheckMenuItem(z, kMenuZoomBase + static_cast<UINT>(i),
                              MF_BYCOMMAND |
                                  (tick_zoom && i == current ? MF_CHECKED
                                                             : MF_UNCHECKED));
            }
        }
        for (HMENU m : {view_menu_, sys_menu_}) {
            if (m == nullptr) continue;
            const int idx = FindPopupIndex(m);
            if (idx >= 0) {
                MENUITEMINFOW mii{};
                mii.cbSize = sizeof(mii);
                mii.fMask = MIIM_STRING;
                mii.dwTypeData = wide.data();
                SetMenuItemInfoW(m, static_cast<UINT>(idx), TRUE, &mii);
            }
            CheckMenuItem(m, kMenuSmartSizing, MF_BYCOMMAND | fit_check);
            CheckMenuItem(m, kMenuFullscreen, MF_BYCOMMAND | fs_check);
            CheckMenuItem(m, kMenuSmartCard, MF_BYCOMMAND | sc_check);
        }
    }

    bool HandleCommand(UINT id) {
        if (id >= kMenuZoomBase &&
            id < kMenuZoomBase + static_cast<UINT>(kZoomPresetCount)) {
            PushCommand(static_cast<uint8_t>(kCmdZoomPresetFirst +
                                             (id - kMenuZoomBase)));
            return true;
        }
        switch (id) {
            case kMenuFullscreen:
                PushCommand(kCmdToggleFullscreen);
                return true;
            case kMenuSmartSizing:
                PushCommand(kCmdToggleSmartSizing);
                return true;
            case kMenuConnInfo:
                PushCommand(kCmdConnectionInfo);
                return true;
            case kMenuSmartCard:
                PushCommand(kCmdToggleSmartCard);
                return true;
            case kMenuHelp:
                PushCommand(kCmdHelp);
                return true;
            default:
                return false;
        }
    }

    void PushCommand(uint8_t command) {
        InputEvent e;
        e.kind = InputEvent::Kind::kUiCommand;
        e.command = command;
        events_.push_back(e);
    }

    // Releases every key still forwarded-down. Called on the observable focus
    // loss / close paths so the remote does not keep Ctrl/Alt/Shift/Win latched
    // (the shell eats WM_KEYUP for the Windows key, so its up may never
    // arrive). Engineering implementation keyed off focus messages; the mstsc
    // trigger timing is not claimed to be identical.
    void ReleaseHeldKeys() {
        for (const InputEvent& e : key_state_.ReleaseAll()) {
            events_.push_back(e);
        }
        // The Pause press latch is keyed off a down/up pair like any other key:
        // focus loss may eat the up (WM_KEYUP never arrives after WM_KILLFOCUS),
        // so without this reset the next Pause after refocus would be swallowed
        // and the Pause command lost.
        pause_down_ = false;
    }

    // Releases every mouse button still held (synthesising the missing up) and
    // clears the capture. Called on focus loss / close / WM_CAPTURECHANGED so a
    // drag that never delivered its release cannot leave the remote latched.
    void ReleaseHeldButtons() {
        const bool was_held = held_buttons_ != 0;
        for (uint8_t b = 1; b <= 5; ++b) {
            if ((held_buttons_ & (1u << b)) == 0) continue;
            InputEvent e;
            e.kind = InputEvent::Kind::kMouseButton;
            e.button = b;
            e.button_down = false;
            e.x = static_cast<uint16_t>(last_mouse_x_ < 0 ? 0 : last_mouse_x_);
            e.y = static_cast<uint16_t>(last_mouse_y_ < 0 ? 0 : last_mouse_y_);
            events_.push_back(e);
        }
        held_buttons_ = 0;
        if (was_held && hwnd_ != nullptr &&
            ::GetCapture() == hwnd_) {
            ::ReleaseCapture();
        }
    }

    void Destroy() {
        if (bitmap_ != nullptr) {
            DeleteObject(bitmap_);
            bitmap_ = nullptr;
            bits_ = nullptr;
        }
        if (mem_dc_ != nullptr) {
            DeleteDC(mem_dc_);
            mem_dc_ = nullptr;
        }
        if (hwnd_ != nullptr) {
            RemoveClipboardFormatListener(hwnd_);
            DestroyWindow(hwnd_);
            hwnd_ = nullptr;
        }
        if (menu_ != nullptr) {
            DestroyMenu(menu_);
            menu_ = nullptr;
        }
    }

    // Recreates the 32-bit top-down DIB at the current surface size. Called at
    // startup and on every Resize so the DIB always matches the client area.
    void RecreateBitmap() {
        if (bitmap_ != nullptr) {
            DeleteObject(bitmap_);
            bitmap_ = nullptr;
            bits_ = nullptr;
        }
        if (mem_dc_ == nullptr) return;

        BITMAPINFO bi{};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = surface_.width();
        bi.bmiHeader.biHeight = -surface_.height();  // top-down
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;

        bitmap_ =
            CreateDIBSection(mem_dc_, &bi, DIB_RGB_COLORS, &bits_, nullptr, 0);
        if (bitmap_ != nullptr) SelectObject(mem_dc_, bitmap_);
    }

    Surface surface_;
    HWND hwnd_ = nullptr;
    HDC mem_dc_ = nullptr;
    HBITMAP bitmap_ = nullptr;
    void* bits_ = nullptr;
    std::deque<InputEvent> events_;
    bool closed_ = false;
    size_t present_count_ = 0;

    HMENU menu_ = nullptr;         // top menu bar
    HMENU view_menu_ = nullptr;    // the "查看" popup
    HMENU zoom_menu_top_ = nullptr;
    HMENU zoom_menu_sys_ = nullptr;
    HMENU sys_menu_ = nullptr;     // the real system menu, extended
    ViewMenuState view_state_;
    std::function<void()> clipboard_callback_;
    WinKeyMode win_key_mode_ = WinKeyMode::kRemote;
    Win32KeyState key_state_;
    // Which mouse buttons are currently held (bit N == button N, 1..5). The
    // capture lifetime is derived from it: the first press installs SetCapture
    // so a drag out of the window still delivers the release, the last release
    // drops it, and WM_CAPTURECHANGED / focus loss clear it and synthesise the
    // missing ups (a lost release used to leave the counter permanently > 0).
    uint32_t held_buttons_ = 0;
    int last_mouse_x_ = 0;  // last known pointer position (signed client coords)
    int last_mouse_y_ = 0;
    // Residual wheel deltas for sub-notch mice (a delta of 40 is a third of a
    // WHEEL_DELTA notch); an event leaves only the remainder here.
    int wheel_accum_v_ = 0;
    int wheel_accum_h_ = 0;
    bool pause_down_ = false;
    bool fullscreen_ = false;
    RECT saved_rect_{};
    LONG_PTR saved_style_ = 0;
};

}  // namespace

bool Win32KeyState::IsDown(uint8_t scancode, bool extended) const {
    for (const DownKey& key : down_) {
        if (key.scancode == scancode && key.extended == extended) return true;
    }
    return false;
}

Win32KeyAction Win32KeyState::Process(const KeyTranslation& key) {
    if (!key.forward) return Win32KeyAction::kIgnore;

    // Ctrl+Alt+End -> SAS is a PRODUCT REQUIREMENT, not mstsc evidence (there
    // is no binary proof of mstsc's Ctrl+Alt+End mapping). The End key is
    // swallowed for the whole chord so the remote never sees a bare End
    // scancode; the SAS command is raised only once, on a fresh press.
    const bool ctrl_down = IsDown(kWin32ScancodeCtrl, false) ||
                           IsDown(kWin32ScancodeCtrl, true);
    const bool alt_down = IsDown(kWin32ScancodeAlt, false) ||
                          IsDown(kWin32ScancodeAlt, true);
    if (key.scancode == kWin32ScancodeEnd && key.extended) {
        // The End was tracked as forwarded-down (pre-pressed before the chord):
        // swallowing its release would leak it into down_ and emit a phantom
        // key-up on focus loss. Remove the tracking record and forward the up
        // so the remote (which already saw the End down) sees the release too.
        const bool end_was_tracked = IsDown(kWin32ScancodeEnd, true);
        if (sas_end_held_) {
            if (key.release) {
                sas_end_held_ = false;
                if (end_was_tracked) {
                    for (auto it = down_.begin(); it != down_.end(); ++it) {
                        if (it->scancode == kWin32ScancodeEnd && it->extended) {
                            down_.erase(it);
                            break;
                        }
                    }
                    return Win32KeyAction::kForward;
                }
            }
            return Win32KeyAction::kIgnore;
        }
        // A held End auto-repeats while Ctrl+Alt is held: the repeat is NOT a
        // new SAS press, so it must not raise the command again (and must be
        // forwarded like any other auto-repeat). Only a truly new End down --
        // one not already tracked -- raises the SAS.
        if (!key.release && ctrl_down && alt_down && !end_was_tracked) {
            sas_end_held_ = true;
            return Win32KeyAction::kSendCtrlAltDel;
        }
    }

    if (key.release) {
        for (auto it = down_.begin(); it != down_.end(); ++it) {
            if (it->scancode == key.scancode && it->extended == key.extended) {
                down_.erase(it);
                break;
            }
        }
    } else if (!IsDown(key.scancode, key.extended)) {
        down_.push_back({key.scancode, key.extended});
    }
    return Win32KeyAction::kForward;
}

std::vector<InputEvent> Win32KeyState::ReleaseAll() {
    // Newest first (LIFO): the key pressed last is released first, which keeps
    // modifier combinations consistent while unwinding.
    std::vector<InputEvent> out;
    out.reserve(down_.size());
    for (auto it = down_.rbegin(); it != down_.rend(); ++it) {
        InputEvent e;
        e.kind = InputEvent::Kind::kKey;
        e.scancode = it->scancode;
        e.key_release = true;
        e.key_extended = it->extended;
        out.push_back(e);
    }
    down_.clear();
    sas_end_held_ = false;
    return out;
}

KeyTranslation TranslateWin32KeyMessage(uint32_t msg, uint32_t vk,
                                        uint32_t lparam,
                                        uint32_t (*vk_to_scancode)(uint32_t),
                                        WinKeyMode win_key_mode) {
    KeyTranslation out;

    // Only the four keyboard transitions are keys. Anything else (WM_CHAR,
    // WM_MOUSEMOVE, ...) must never be treated as a key-down.
    if (msg != kWin32WmKeyDown && msg != kWin32WmKeyUp &&
        msg != kWin32WmSysKeyDown && msg != kWin32WmSysKeyUp) {
        return out;
    }
    out.release = (msg == kWin32WmKeyUp || msg == kWin32WmSysKeyUp);
    bool extended = (lparam & (1u << 24)) != 0;

    // AltGr: Windows injects a pseudo Ctrl for AltGr (VK_CONTROL/VK_LCONTROL
    // with the extended bit). Drop it, otherwise every AltGr chord arrives as
    // Ctrl+Alt+key. A real right Ctrl reports VK_RCONTROL and is untouched.
    if (extended && (vk == VK_CONTROL || vk == VK_LCONTROL)) return out;

    // Right Alt: VK_RMENU, or VK_MENU carrying the extended bit (Windows uses
    // either depending on the message path), arrives as WM_SYSKEY*. Forward it
    // as set-1 scancode 0x38 + extended so the remote sees a real AltGr.
    if (vk == VK_RMENU || (vk == VK_MENU && extended)) {
        out.forward = true;
        out.scancode = 0x38;
        out.extended = true;
        return out;
    }

    // Alt+F4 (lParam bit 29 = context code) closes the local session window,
    // exactly like mstsc. It is never also forwarded, or the remote window
    // would close too.
    if (vk == VK_F4 && (lparam & (1u << 29)) != 0) return out;

    // Bits 16..23 of lParam hold the set-1 scancode of a real message ('A' is
    // VK 0x41 but scancode 0x1E; sending the VK as a scancode types another key
    // remotely, e.g. 0x41 is F7). VK-only synthetic messages (automation) carry
    // 0 there and fall back to the layout mapping.
    uint32_t scancode = (lparam >> 16) & 0xFF;
    const bool scancode_in_lparam = scancode != 0;
    if (scancode == 0) {
        // VK_PROCESSKEY (0xE5) is an IME marker with no key of its own. With no
        // scancode in lParam there is nothing real to send; mapping 0xE5 would
        // produce garbage. (When lParam does carry a scancode, that is used as
        // usual: an IME still reports the physical key there.)
        if (vk == VK_PROCESSKEY) return out;
        scancode = (vk_to_scancode != nullptr)
                       ? vk_to_scancode(vk)
                       : static_cast<uint32_t>(
                             MapVirtualKeyW(vk, MAPVK_VK_TO_VSC));
        scancode &= 0xFF;
    }
    // No mapping: drop the event rather than forward scancode 0, which is not a
    // key and would type garbage on the remote.
    if (scancode == 0) return out;

    // A real message's bit24 is authoritative: the set-1 scancode cannot tell
    // numpad-off Home (0x47, not extended) from the nav-cluster Home
    // (0xE0 0x47, extended), and NumLock (0x45) is never extended. Only
    // synthetic / automation messages (lParam scancode field 0) fall back to
    // the virtual-key table, which lists keys whose scancode is inherently
    // 0xE0-prefixed.
    if (!scancode_in_lparam &&
        (IsInherentExtendedVirtualKey(vk) || scancode == 0x5B ||
         scancode == 0x5C)) {
        extended = true;
    }

    // Windows key policy. kRemote (the mstsc-compatible default) forwards;
    // kLocal keeps LWIN/RWIN for the local shell; kFullscreenOnly is treated as
    // kLocal for now (TODO: decide the fullscreen policy).
    if ((scancode == 0x5B || scancode == 0x5C) &&
        win_key_mode != WinKeyMode::kRemote) {
        return out;
    }

    out.forward = true;
    out.scancode = static_cast<uint8_t>(scancode);
    out.extended = extended;
    return out;
}

std::unique_ptr<Window> CreateWin32Window(uint16_t width, uint16_t height,
                                          std::string& why) {
    auto w = std::make_unique<Win32Window>(width, height);
    if (!w->Start(why)) return nullptr;
    return w;
}

}  // namespace rtsc::ui

#endif  // _WIN32
