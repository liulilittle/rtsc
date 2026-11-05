// Win32 connection-information dialog (mstsc parity). See the header.

#include "connection_info_dialog_win32.h"

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <windowsx.h>

#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace rtsc::gui {
namespace {

using rtsc::client::SessionInfo;

constexpr const wchar_t* kClassName = L"RtscConnInfoDialog";
constexpr const wchar_t* kTitle = L"连接信息";

// Client-area layout, in pixels. The detail groups occupy kDetailTop ..
// kDetailBottom; collapsing them shrinks the window by that many pixels.
constexpr int kClientWidth = 460;
constexpr int kFullClientHeight = 360;
constexpr int kCollapsedClientHeight = 96;
constexpr int kDetailTop = 88;
constexpr int kDetailHeight = 232;

constexpr DWORD kStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE;

// Control ids.
enum : int {
    kIdQuality = 1,
    kIdTimestamp,
    kIdActivity,
    kIdClientVersion,
    kIdLocalOs,
    kIdProtocol,
    kIdRtt,
    kIdBandwidth,
    kIdFrameRate,
    kIdSessionType,
    kIdGatewayName,
    kIdGatewayMethod,
    kIdRemoteComputer,
    kIdToggleDetails,
    kIdOk,
};

std::wstring ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(static_cast<size_t>(n) - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

class ConnInfoDialog {
 public:
    bool Create(void* parent, const std::function<SessionInfo()>& collect) {
        parent_ = reinterpret_cast<HWND>(parent);
        collect_ = collect;
        HINSTANCE inst = GetModuleHandleW(nullptr);
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = &ConnInfoDialog::WndProc;
        wc.hInstance = inst;
        wc.lpszClassName = kClassName;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
        if (RegisterClassExW(&wc) == 0 &&
            GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            return false;
        }

        RECT r{0, 0, kClientWidth, kFullClientHeight};
        AdjustWindowRect(&r, kStyle, FALSE);
        hwnd_ = CreateWindowExW(WS_EX_DLGMODALFRAME, kClassName, kTitle, kStyle,
                                CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left,
                                r.bottom - r.top, parent_, nullptr, inst, this);
        if (hwnd_ == nullptr) {
            return false;
        }

        CreateControls();
        ApplyInfo(collect_());
        SetTimer(hwnd_, 1, 1000, nullptr);
        CenterOnParent();
        return true;
    }

    void RunModal() {
        if (parent_ != nullptr) EnableWindow(parent_, FALSE);
        ShowWindow(hwnd_, SW_SHOW);
        UpdateWindow(hwnd_);
        MSG msg;
        while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
            if (IsDialogMessageW(hwnd_, &msg)) continue;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (done_) break;
        }
        if (parent_ != nullptr) {
            EnableWindow(parent_, TRUE);
            SetForegroundWindow(parent_);
        }
    }

 private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        ConnInfoDialog* self = nullptr;
        if (msg == WM_NCCREATE) {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            self = static_cast<ConnInfoDialog*>(cs->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(self));
        } else {
            self = reinterpret_cast<ConnInfoDialog*>(
                GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        }
        if (self == nullptr) return DefWindowProcW(hwnd, msg, wp, lp);
        return self->Handle(hwnd, msg, wp, lp);
    }

    LRESULT Handle(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        switch (msg) {
            case WM_COMMAND:
                if (HandleCommand(LOWORD(wp))) return 0;
                break;
            case WM_TIMER:
                // Keep the live fields (frame rate, round-trip, timestamp)
                // current while the dialog is open.
                ApplyInfo(collect_());
                return 0;
            case WM_CLOSE:
                done_ = true;
                DestroyWindow(hwnd_);
                return 0;
            case WM_DESTROY:
                KillTimer(hwnd_, 1);
                return 0;
            default:
                break;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }

    bool HandleCommand(int id) {
        switch (id) {
            case kIdOk:
                done_ = true;
                DestroyWindow(hwnd_);
                return true;
            case kIdToggleDetails:
                ToggleDetails();
                return true;
            default:
                return false;
        }
    }

    void ToggleDetails() {
        expanded_ = !expanded_;
        const UINT cmd = expanded_ ? SW_SHOW : SW_HIDE;
        for (HWND h : detail_controls_) ShowWindow(h, cmd);
        const int height = expanded_ ? kFullClientHeight : kCollapsedClientHeight;
        RECT r{0, 0, kClientWidth, height};
        AdjustWindowRect(&r, kStyle, FALSE);
        SetWindowPos(hwnd_, nullptr, 0, 0, r.right - r.left, r.bottom - r.top,
                     SWP_NOMOVE | SWP_NOZORDER);
        SetWindowTextW(details_button_, expanded_ ? L"隐藏详细信息(D)"
                                                  : L"显示详细信息(D)");
        CenterOnParent();
    }

    void CreateControls() {
        HINSTANCE inst = GetModuleHandleW(nullptr);
        const auto static_ctl = [this, inst](int id, const wchar_t* text, int x,
                                             int y, int w, int h, bool detail) {
            HWND c = CreateWindowExW(0, L"STATIC", text,
                                     WS_CHILD | WS_VISIBLE | SS_LEFT, x, y, w, h,
                                     hwnd_, reinterpret_cast<HMENU>(
                                                 static_cast<INT_PTR>(id)),
                                     inst, nullptr);
            if (detail) detail_controls_.push_back(c);
            return c;
        };
        const auto group = [this, inst](const wchar_t* text, int x, int y, int w,
                                        int h) {
            HWND c = CreateWindowExW(0, L"BUTTON", text,
                                     WS_CHILD | WS_VISIBLE | BS_GROUPBOX, x, y,
                                     w, h, hwnd_, nullptr, inst, nullptr);
            detail_controls_.push_back(c);
            return c;
        };

        // Header: quality banner, timestamp, activity id (always visible).
        static_ctl(kIdQuality, L"", 12, 12, 428, 20, false);
        static_ctl(kIdTimestamp, L"", 12, 40, 428, 20, false);
        static_ctl(kIdActivity, L"", 12, 64, 428, 20, false);

        // [Client details]
        group(L"[Client details]", 8, kDetailTop, 428, 56);
        static_ctl(kIdClientVersion, L"", 16, kDetailTop + 18, 412, 20, true);
        static_ctl(kIdLocalOs, L"", 16, kDetailTop + 38, 412, 20, true);

        // [Network details]
        group(L"[Network details]", 8, kDetailTop + 64, 428, 96);
        static_ctl(kIdProtocol, L"", 16, kDetailTop + 82, 412, 20, true);
        static_ctl(kIdRtt, L"", 16, kDetailTop + 102, 412, 20, true);
        static_ctl(kIdBandwidth, L"", 16, kDetailTop + 122, 412, 20, true);
        static_ctl(kIdFrameRate, L"", 16, kDetailTop + 142, 412, 20, true);

        // [Remote computer details]
        group(L"[Remote computer details]", 8, kDetailTop + 168, 428, 76);
        static_ctl(kIdSessionType, L"", 16, kDetailTop + 186, 412, 20, true);
        static_ctl(kIdGatewayName, L"", 16, kDetailTop + 206, 412, 20, true);
        static_ctl(kIdGatewayMethod, L"", 16, kDetailTop + 226, 412, 20, true);
        static_ctl(kIdRemoteComputer, L"", 16, kDetailTop + 246, 412, 20, true);

        details_button_ = CreateWindowExW(
            0, L"BUTTON", L"隐藏详细信息(D)",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, 8,
            kFullClientHeight - 36, 140, 24, hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdToggleDetails)),
            inst, nullptr);
        CreateWindowExW(0, L"BUTTON", L"确定",
                        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
                        kClientWidth - 92, kFullClientHeight - 36, 80, 24, hwnd_,
                        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdOk)),
                        inst, nullptr);
    }

    void ApplyInfo(const SessionInfo& si) {
        SetText(kIdQuality, si.quality);
        SetText(kIdTimestamp, "时间戳(UTC): " + si.timestamp_utc);
        SetText(kIdActivity, "活动 ID: " + si.activity_id);
        SetText(kIdClientVersion, "客户端版本: " + si.client_version);
        SetText(kIdLocalOs, "本地 OS: " + si.local_os);
        SetText(kIdProtocol, "传输协议: " + si.transport_protocol);
        SetText(kIdRtt, "往返时间: " + si.round_trip_time);
        SetText(kIdBandwidth, "可用带宽: " + si.available_bandwidth);
        SetText(kIdFrameRate, "帧速率(FPS): " + si.frame_rate);
        SetText(kIdSessionType, "远程会话类型: " + si.remote_session_type);
        SetText(kIdGatewayName, "网关名称: " + si.gateway_name);
        SetText(kIdGatewayMethod, "网关登录方法: " + si.gateway_logon_method);
        SetText(kIdRemoteComputer, "远程计算机: " + si.remote_computer);
    }

    void SetText(int id, const std::string& text) {
        HWND c = GetDlgItem(hwnd_, id);
        if (c == nullptr) return;
        const std::wstring wide = ToWide(text);
        SetWindowTextW(c, wide.c_str());
    }

    void CenterOnParent() {
        if (parent_ == nullptr) return;
        RECT pr{};
        if (!GetWindowRect(parent_, &pr)) return;
        RECT cr{};
        if (!GetWindowRect(hwnd_, &cr)) return;
        const int w = cr.right - cr.left;
        const int h = cr.bottom - cr.top;
        SetWindowPos(hwnd_, nullptr,
                     pr.left + ((pr.right - pr.left) - w) / 2,
                     pr.top + ((pr.bottom - pr.top) - h) / 2, 0, 0,
                     SWP_NOSIZE | SWP_NOZORDER);
    }

    HWND hwnd_ = nullptr;
    HWND parent_ = nullptr;
    HWND details_button_ = nullptr;
    std::function<SessionInfo()> collect_;
    std::vector<HWND> detail_controls_;
    bool expanded_ = true;
    bool done_ = false;
};

}  // namespace

void ShowConnectionInfoDialog(
    void* parent, const std::function<rtsc::client::SessionInfo()>& collect) {
    ConnInfoDialog dlg;
    if (!dlg.Create(parent, collect)) {
        return;
    }
    dlg.RunModal();
}

}  // namespace rtsc::gui

#endif  // _WIN32
