// Win32 help/about dialog. See the header for scope and the no-mstsc-claim note.

#include "help_dialog_win32.h"

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include <string>

namespace rtsc::gui {
namespace {

constexpr const wchar_t* kClassName = L"RtscHelpDialog";
constexpr const wchar_t* kTitle = L"关于 RTSC";

constexpr int kClientWidth = 420;
constexpr int kFullClientHeight = 176;

enum : int {
    kIdTitle = 1,
    kIdVersion,
    kIdPurpose,
    kIdNotice,
    kIdOk,
};

// The text is ASCII-only on purpose: it goes through MultiByteToWideChar with
// CP_UTF8 above, and keeping the literals ASCII removes any dependence on the
// compilation unit's encoding.
constexpr const char* kPurposeText =
    "A C++ reimplementation of the Remote Desktop Protocol client.";
constexpr const char* kNoticeText =
    "Help content is not bundled with this build.";

std::wstring ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(static_cast<size_t>(n) - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

class HelpDialog {
 public:
    bool Create(void* parent, const char* version) {
        parent_ = reinterpret_cast<HWND>(parent);
        version_ = version != nullptr ? version : "";

        HINSTANCE inst = GetModuleHandleW(nullptr);
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = &HelpDialog::WndProc;
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
        if (hwnd_ == nullptr) return false;

        CreateControls();
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
    static constexpr DWORD kStyle =
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE;

    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        HelpDialog* self = nullptr;
        if (msg == WM_NCCREATE) {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            self = static_cast<HelpDialog*>(cs->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(self));
        } else {
            self = reinterpret_cast<HelpDialog*>(
                GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        }
        if (self == nullptr) return DefWindowProcW(hwnd, msg, wp, lp);
        // DefWindowProc must receive the HWND this call was given, never the
        // member: during WM_NCCREATE the member is still null, and
        // DefWindowProcW(nullptr, WM_NCCREATE, ...) returns FALSE, which aborts
        // window creation (that exact bug shipped in the connection-info dialog
        // and was fixed in batch 85).
        return self->Handle(hwnd, msg, wp, lp);
    }

    LRESULT Handle(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        switch (msg) {
            case WM_COMMAND:
                if (LOWORD(wp) == kIdOk) {
                    done_ = true;
                    DestroyWindow(hwnd);
                    return 0;
                }
                break;
            case WM_CLOSE:
                done_ = true;
                DestroyWindow(hwnd);
                return 0;
            default:
                break;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }

    void CreateControls() {
        HINSTANCE inst = GetModuleHandleW(nullptr);
        const auto text = [this, inst](int id, const std::wstring& s, int x,
                                       int y, int w, int h, DWORD extra) {
            CreateWindowExW(0, L"STATIC", s.c_str(),
                            WS_CHILD | WS_VISIBLE | SS_LEFT | extra, x, y, w, h,
                            hwnd_,
                            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                            inst, nullptr);
        };

        text(kIdTitle, L"RTSC", 16, 14, 388, 24, SS_LEFT);
        text(kIdVersion, ToWide(version_), 16, 42, 388, 20, SS_LEFT);
        text(kIdPurpose, ToWide(kPurposeText), 16, 70, 388, 20, SS_LEFT);
        text(kIdNotice, ToWide(kNoticeText), 16, 94, 388, 20, SS_LEFT);

        CreateWindowExW(
            0, L"BUTTON", L"确定",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 330, 130, 74,
            28, hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdOk)), inst, nullptr);
    }

    void CenterOnParent() {
        RECT pr{};
        RECT wr{};
        if (parent_ != nullptr && GetWindowRect(parent_, &pr) &&
            GetWindowRect(hwnd_, &wr)) {
            const int w = wr.right - wr.left;
            const int h = wr.bottom - wr.top;
            SetWindowPos(hwnd_, nullptr,
                         pr.left + ((pr.right - pr.left) - w) / 2,
                         pr.top + ((pr.bottom - pr.top) - h) / 2, 0, 0,
                         SWP_NOSIZE | SWP_NOZORDER);
        }
    }

    HWND hwnd_ = nullptr;
    HWND parent_ = nullptr;
    std::string version_;
    bool done_ = false;
};

}  // namespace

void ShowHelpDialog(void* parent, const char* version) {
    HelpDialog dlg;
    if (!dlg.Create(parent, version)) return;
    dlg.RunModal();
}

}  // namespace rtsc::gui

#else  // !_WIN32

namespace rtsc::gui {
void ShowHelpDialog(void* /*parent*/, const char* /*version*/) {}
}  // namespace rtsc::gui

#endif  // _WIN32
