// Platform clipboard backend for the CLIPRDR virtual channel.

#include "rtsc/clipboard/clipboard.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstring>
#include <mutex>
#endif

namespace rtsc::clipboard {
namespace {

#if defined(_WIN32)
// The Win32 clipboard. The clipboard is a process-wide resource, so the window
// handle passed to OpenClipboard is nullptr (no WM_DRAWCLIPBOARD owner needed
// here: the window backend observes changes itself).
//
// The server serves one shared clipboard to every session (shared desktop
// semantics). OpenClipboard is process-global and OpenClipboard/CloseClipboard
// pairs from two session threads must never interleave, so every backend call
// is serialized by a process-level mutex; the sequence number the poll reads is
// lock-free and intentionally outside it.
std::mutex g_clipboard_mutex;

class Win32Clipboard final : public Clipboard {
 public:
    std::vector<uint32_t> formats() override {
        std::lock_guard<std::mutex> lock(g_clipboard_mutex);
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
        std::lock_guard<std::mutex> lock(g_clipboard_mutex);
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
        std::lock_guard<std::mutex> lock(g_clipboard_mutex);
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

    uint64_t sequence_number() const override {
        return static_cast<uint64_t>(GetClipboardSequenceNumber());
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
