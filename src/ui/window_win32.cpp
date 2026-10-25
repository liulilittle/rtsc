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

    void* native_handle() const override {
        return reinterpret_cast<void*>(hwnd_);
    }

    void Present() override {
        if (hwnd_ == nullptr || bits_ == nullptr) return;
        // Surface is RGBA; the DIB wants BGRA.
        const uint8_t* src = surface_.data();
        uint8_t* dst = static_cast<uint8_t*>(bits_);
        const size_t n = surface_.size();
        for (size_t i = 0; i + 3 < n; i += 4) {
            dst[i + 0] = src[i + 2];
            dst[i + 1] = src[i + 1];
            dst[i + 2] = src[i + 0];
            dst[i + 3] = src[i + 3];
        }
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
                closed_ = true;
                PostQuitMessage(0);
                return false;  // DefWindowProc destroys the window
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
            case WM_KEYUP: {
                InputEvent e;
                e.kind = InputEvent::Kind::kKey;
                e.scancode = static_cast<uint8_t>(wp & 0xFF);
                e.key_release = (msg == WM_KEYUP);
                e.key_extended = (lp & (1 << 24)) != 0;
                events_.push_back(e);
                return true;
            }
            case WM_MOUSEMOVE: {
                InputEvent e;
                e.kind = InputEvent::Kind::kMouseMove;
                e.x = static_cast<uint16_t>(LOWORD(lp));
                e.y = static_cast<uint16_t>(HIWORD(lp));
                events_.push_back(e);
                return true;
            }
            case WM_LBUTTONDOWN:
            case WM_LBUTTONUP:
            case WM_RBUTTONDOWN:
            case WM_RBUTTONUP:
            case WM_MBUTTONDOWN:
            case WM_MBUTTONUP: {
                InputEvent e;
                e.kind = InputEvent::Kind::kMouseButton;
                e.x = static_cast<uint16_t>(LOWORD(lp));
                e.y = static_cast<uint16_t>(HIWORD(lp));
                e.button = (msg == WM_LBUTTONDOWN || msg == WM_LBUTTONUP)
                               ? 1
                               : (msg == WM_RBUTTONDOWN || msg == WM_RBUTTONUP) ? 2
                                                                                : 3;
                e.button_down = (msg == WM_LBUTTONDOWN || msg == WM_RBUTTONDOWN ||
                                 msg == WM_MBUTTONDOWN);
                events_.push_back(e);
                return true;
            }
            case WM_MOUSEWHEEL: {
                InputEvent e;
                e.kind = InputEvent::Kind::kMouseWheel;
                e.wheel_delta =
                    static_cast<int16_t>(GET_WHEEL_DELTA_WPARAM(wp) / WHEEL_DELTA);
                events_.push_back(e);
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
        return false;
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
    bool fullscreen_ = false;
    RECT saved_rect_{};
    LONG_PTR saved_style_ = 0;
};

}  // namespace

std::unique_ptr<Window> CreateWin32Window(uint16_t width, uint16_t height,
                                          std::string& why) {
    auto w = std::make_unique<Win32Window>(width, height);
    if (!w->Start(why)) return nullptr;
    return w;
}

}  // namespace rtsc::ui

#endif  // _WIN32
