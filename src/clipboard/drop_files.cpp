// Direction-B file-list backend: Win32 CF_HDROP -> FileListProvider.

#include "rtsc/clipboard/drop_files.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace rtsc::clipboard {
namespace {

// DROPFILES fixed header (shellapi.h): pFiles(4) | pt(8) | fNC(4) | fWide(4).
constexpr size_t kDropFilesHeaderSize = 20;
constexpr size_t kOffsetPFiles = 0;   // file table offset from struct start.
constexpr size_t kOffsetFWide = 16;   // 0 = ANSI table, 1 = UTF-16LE table.

uint32_t ReadU32Le(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint32_t>(b[off]) |
           (static_cast<uint32_t>(b[off + 1]) << 8) |
           (static_cast<uint32_t>(b[off + 2]) << 16) |
           (static_cast<uint32_t>(b[off + 3]) << 24);
}

uint16_t ReadU16Le(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint16_t>(static_cast<uint16_t>(b[off]) |
                                 (static_cast<uint16_t>(b[off + 1]) << 8));
}

// The file-name component of a full path, accepting both backslash and slash
// separators (CF_HDROP uses backslashes; handle both defensively). Trailing
// separators are stripped so "C:\dir\" yields "dir".
std::u16string Basename(const std::u16string& full) {
    size_t end = full.size();
    while (end > 0 && (full[end - 1] == u'\\' || full[end - 1] == u'/')) {
        --end;
    }
    const std::u16string trimmed = full.substr(0, end);
    const size_t sep = trimmed.find_last_of(u"\\/");
    if (sep == std::u16string::npos) return trimmed;
    return trimmed.substr(sep + 1);
}

}  // namespace

DropFileList::DropFileList(std::vector<std::u16string> full_paths)
    : full_paths_(std::move(full_paths)) {}

uint32_t DropFileList::file_count() const {
    return static_cast<uint32_t>(full_paths_.size());
}

bool DropFileList::file_info(uint32_t index, FileInfo& out) const {
    if (index >= full_paths_.size()) return false;
    const std::u16string& full = full_paths_[index];
    out = FileInfo{};
    out.name = Basename(full);
    try {
        const std::filesystem::path p(full);
        std::error_code ec;
        if (std::filesystem::is_directory(p, ec)) {
            out.is_directory = true;
            out.attributes |= kFileAttributeDirectory;
            out.size = 0;
            return true;
        }
        // A non-directory whose stat failed (missing or un-accessible file)
        // cannot be served: fail so the SIZE answer does not fabricate a
        // zero-length file for the peer ([MS-RDPECLIP] 3.1.5.4.6 MUST FAIL).
        if (ec) return false;
        const std::uintmax_t size = std::filesystem::file_size(p, ec);
        if (ec) return false;
        out.size = static_cast<uint64_t>(size);
        out.attributes |= kFileAttributeNormal;
        return true;
    } catch (...) {
        return false;
    }
}

bool DropFileList::read_range(uint32_t index, uint64_t offset, uint32_t count,
                              std::vector<uint8_t>& out) {
    if (index >= full_paths_.size()) return false;
    try {
        const std::filesystem::path p(full_paths_[index]);
        std::error_code ec;
        if (std::filesystem::is_directory(p, ec)) return false;
        const std::uintmax_t size = std::filesystem::file_size(p, ec);
        if (ec) return false;
        if (offset > static_cast<uint64_t>(size)) return false;
        if (count == 0) return true;  // nothing to read, offset within range.
        std::ifstream f(p, std::ios::binary);
        if (!f) return false;
        f.seekg(static_cast<std::streamoff>(offset));
        if (!f) return false;
        const uint64_t to_read =
            std::min<uint64_t>(count, static_cast<uint64_t>(size) - offset);
        std::vector<uint8_t> buf(static_cast<size_t>(to_read));
        f.read(reinterpret_cast<char*>(buf.data()),
               static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = f.gcount();
        out.insert(out.end(), buf.begin(), buf.begin() + got);
        return true;
    } catch (...) {
        return false;
    }
}

std::unique_ptr<DropFileList> CreateDropFileListFromBytes(
    const std::vector<uint8_t>& bytes) {
    if (bytes.size() < kDropFilesHeaderSize) return nullptr;
    const uint32_t p_files = ReadU32Le(bytes, kOffsetPFiles);
    // The table must start inside the buffer (pFiles == size is an allowed
    // empty table; anything beyond the buffer is malformed).
    if (p_files < kDropFilesHeaderSize ||
        static_cast<size_t>(p_files) > bytes.size()) {
        return nullptr;
    }
    const uint32_t f_wide = ReadU32Le(bytes, kOffsetFWide);
    // v1 supports only UTF-16 (fWide == 1) tables. The ANSI (fWide == 0)
    // variant is treated as "not provided".
    if (f_wide != 1) return nullptr;

    std::vector<std::u16string> paths;
    size_t pos = p_files;
    while (pos + 2 <= bytes.size()) {
        if (ReadU16Le(bytes, pos) == 0) break;  // empty string ends the list.
        std::u16string name;
        bool terminated = false;
        while (pos + 2 <= bytes.size()) {
            const uint16_t c = ReadU16Le(bytes, pos);
            pos += 2;
            if (c == 0) {
                terminated = true;
                break;
            }
            name.push_back(static_cast<char16_t>(c));
        }
        if (!terminated) break;  // truncated name: stop, keep what we parsed.
        paths.push_back(std::move(name));
        if (pos >= bytes.size()) break;
    }
    return std::make_unique<DropFileList>(std::move(paths));
}

}  // namespace rtsc::clipboard