// Platform-neutral local clipboard facade for the CLIPRDR virtual channel.
//
// The cliprdr channel handler reads and writes the local clipboard through this
// interface, so the protocol layer never touches a platform API. The Windows
// backend maps it to the Win32 clipboard (OpenClipboard / GetClipboardData /
// SetClipboardData); tests inject a fake.
//
// Reference: [MS-RDPECLIP] 1.3.1.2 (clipboard formats).

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

namespace rtsc::clipboard {

// Standard clipboard format IDs ([MS-RDPECLIP] 1.3.1.2). These are the
// hard-coded IDs that are constant across Windows machines; custom formats use
// a name and are exchanged through the CLIPRDR format-name fields.
enum ClipboardFormat : uint32_t {
    kCfText = 1,
    kCfBitmap = 2,
    kCfMetafilepict = 3,
    kCfSylk = 4,
    kCfDif = 5,
    kCfTiff = 6,
    kCfOemtext = 7,
    kCfDib = 8,
    kCfPalette = 9,
    kCfPendata = 10,
    kCfRiff = 11,
    kCfWave = 12,
    kCfUnicodetext = 13,
    kCfEnhmetafile = 14,
    kCfHdrop = 15,
    kCfLocale = 16,
    kCfDibV5 = 17,
};

// The local clipboard. `formats()` enumerates the formats currently available,
// `read()` returns the raw bytes of one format, and `write()` replaces the whole
// clipboard with a single format.
class Clipboard {
 public:
    virtual ~Clipboard() = default;

    virtual std::vector<uint32_t> formats() = 0;
    virtual bool read(uint32_t format, std::vector<uint8_t>& out) = 0;
    virtual bool write(uint32_t format, const std::vector<uint8_t>& data) = 0;

    // A process-local, monotonic clipboard version. The Win32 backend maps it to
    // GetClipboardSequenceNumber(); test doubles override it to simulate local
    // edits. The cliprdr server uses it to notice external clipboard changes on
    // its 1 s poll and to swallow the echo of its own remote-applied write
    // (design: "自回声吞用应用后 seq").
    virtual uint64_t sequence_number() const { return 0; }
};

// No-op clipboard for platforms without a backend (and as a test double).
class NullClipboard final : public Clipboard {
 public:
    std::vector<uint32_t> formats() override { return {}; }
    bool read(uint32_t format, std::vector<uint8_t>& out) override {
        (void)format;
        out.clear();
        return false;
    }
    bool write(uint32_t format, const std::vector<uint8_t>& data) override {
        (void)format;
        (void)data;
        return false;
    }
};

// Creates the platform clipboard backend, or nullptr when the platform has
// none (non-Windows). The caller owns the returned object.
std::unique_ptr<Clipboard> CreatePlatformClipboard();

}  // namespace rtsc::clipboard
