// Platform clipboard backend for the CLIPRDR virtual channel.

#include "rtsc/clipboard/clipboard.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstring>
#endif

namespace rtsc::clipboard {
namespace {

#if defined(_WIN32)
// The Win32 clipboard. The clipboard is a process-wide resource, so the window
// handle passed to OpenClipboard is nullptr (no WM_DRAWCLIPBOARD owner needed
// here: the window backend observes changes itself).
class Win32Clipboard final : public Clipboard {
 public:
    std::vector<uint32_t> formats() override {
        std::vector<uint32_t> out;
        if (!OpenClipboard(nullptr)) return out;
        UINT format = EnumClipboardFormats(0);
        while (format != 0) {
            out.push_back(format);
            format = EnumClipboardFormats(format);
        }
        CloseClipboard();
        return out;
    }

    bool read(uint32_t format, std::vector<uint8_t>& out) override {
        out.clear();
        if (!OpenClipboard(nullptr)) return false;
        HANDLE handle = GetClipboardData(format);
        if (handle == nullptr) {
            CloseClipboard();
            return false;
        }
        const SIZE_T size = GlobalSize(handle);
        const void* data = GlobalLock(handle);
        if (data != nullptr && size != 0) {
            out.assign(static_cast<const uint8_t*>(data),
                       static_cast<const uint8_t*>(data) + size);
        }
        if (data != nullptr) GlobalUnlock(handle);
        CloseClipboard();
        return !out.empty();
    }

    bool write(uint32_t format, const std::vector<uint8_t>& data) override {
        if (!OpenClipboard(nullptr)) return false;
        EmptyClipboard();
        bool ok = true;
        if (!data.empty()) {
            HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE, data.size());
            if (handle == nullptr) {
                ok = false;
            } else {
                void* ptr = GlobalLock(handle);
                if (ptr == nullptr) {
                    GlobalFree(handle);
                    ok = false;
                } else {
                    std::memcpy(ptr, data.data(), data.size());
                    GlobalUnlock(handle);
                    if (SetClipboardData(format, handle) == nullptr) ok = false;
                }
            }
        }
        CloseClipboard();
        return ok;
    }
};
#endif

}  // namespace

std::unique_ptr<Clipboard> CreatePlatformClipboard() {
#if defined(_WIN32)
    return std::make_unique<Win32Clipboard>();
#else
    return nullptr;
#endif
}

}  // namespace rtsc::clipboard
