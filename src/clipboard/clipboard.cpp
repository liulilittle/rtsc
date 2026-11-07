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

uint32_t MapAdvertisedFormat(uint32_t format) {
    switch (format) {
        case kCfBitmap:
            // An HBITMAP cannot be sent as bytes; the packed DIB can.
            return kCfDib;
        case kCfPalette:
        case kCfMetafilepict:
        case kCfEnhmetafile:
            // GDI handle only: no serializable representation.
            return 0;
        default:
            return format;
    }
}

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

// Converts an HBITMAP to a packed CF_DIB (BITMAPINFOHEADER + 32bpp pixels,
// bottom-up). CF_BITMAP is a GDI handle, so it cannot be copied as a global
// memory block; this is the byte form the peer can consume.
bool BitmapToDib(HBITMAP bitmap, std::vector<uint8_t>& out) {
    BITMAP bm{};
    if (bitmap == nullptr || GetObject(bitmap, sizeof(bm), &bm) == 0) {
        return false;
    }
    if (bm.bmWidth <= 0 || bm.bmHeight <= 0) return false;
    BITMAPINFOHEADER bih{};
    bih.biSize = sizeof(BITMAPINFOHEADER);
    bih.biWidth = bm.bmWidth;
    bih.biHeight = bm.bmHeight;
    bih.biPlanes = 1;
    bih.biBitCount = 32;
    bih.biCompression = BI_RGB;
    const size_t stride =
        ((static_cast<size_t>(bm.bmWidth) * 32 + 31) / 32) * 4;
    const size_t image = stride * static_cast<size_t>(bm.bmHeight);
    out.assign(sizeof(BITMAPINFOHEADER) + image, 0);
    std::memcpy(out.data(), &bih, sizeof(bih));
    HDC dc = GetDC(nullptr);
    if (dc == nullptr) {
        out.clear();
        return false;
    }
    const int lines = GetDIBits(
        dc, bitmap, 0, static_cast<UINT>(bm.bmHeight),
        out.data() + sizeof(BITMAPINFOHEADER),
        reinterpret_cast<BITMAPINFO*>(out.data()), DIB_RGB_COLORS);
    ReleaseDC(nullptr, dc);
    if (lines != bm.bmHeight) {
        out.clear();
        return false;
    }
    return true;
}

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
        if (format == kCfBitmap) {
            const bool ok = BitmapToDib(
                static_cast<HBITMAP>(GetClipboardData(kCfBitmap)), out);
            CloseClipboard();
            return ok;
        }
        HANDLE handle = GetClipboardData(format);
        if (handle == nullptr && (format == kCfDib || format == kCfDibV5)) {
            // The source application published only CF_BITMAP; the advertised
            // CF_DIB is synthesized from the bitmap handle.
            const bool ok = BitmapToDib(
                static_cast<HBITMAP>(GetClipboardData(kCfBitmap)), out);
            CloseClipboard();
            return ok;
        }
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
