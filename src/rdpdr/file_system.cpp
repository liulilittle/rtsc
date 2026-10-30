// Local file system bridge for RDPDR drive redirection ([MS-RDPEFS] 3.1).

#include "rtsc/rdpdr/file_system.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>

namespace rtsc::rdpdr {

namespace {

namespace fs = std::filesystem;

// [MS-FSCC] 2.4 file information classes used by the directory query.
constexpr uint32_t kFileDirectoryInformation = 0x01;
constexpr uint32_t kFileFullDirectoryInformation = 0x02;
constexpr uint32_t kFileBothDirectoryInformation = 0x03;
constexpr uint32_t kFileNamesInformation = 0x0C;

constexpr uint64_t kAppendOffset = 0xFFFFFFFFFFFFFFFFULL;

void AppendU16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

void AppendU32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

void AppendU64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

// Converts a std::filesystem file_time_type to a Windows FILETIME (100 ns
// intervals since 1601-01-01).
uint64_t ToFileTime(const fs::file_time_type& time) {
    const auto sys_now = std::chrono::system_clock::now();
    const auto fs_now = fs::file_time_type::clock::now();
    const auto sys_time = sys_now + (time - fs_now);
    const auto since_epoch = sys_time.time_since_epoch();
    const auto seconds =
        std::chrono::duration_cast<std::chrono::seconds>(since_epoch).count();
    const auto remainder = since_epoch - std::chrono::seconds(seconds);
    const auto millis =
        std::chrono::duration_cast<std::chrono::milliseconds>(remainder)
            .count();
    const uint64_t secs = static_cast<uint64_t>(seconds) + 11644473600ULL;
    return secs * 10000000ULL + static_cast<uint64_t>(millis) * 10000ULL;
}

std::vector<uint8_t> Utf16Le(const std::u16string& text) {
    std::vector<uint8_t> out;
    out.reserve(text.size() * 2);
    for (const char16_t c : text) {
        const uint16_t unit = static_cast<uint16_t>(c);
        out.push_back(static_cast<uint8_t>(unit & 0xFF));
        out.push_back(static_cast<uint8_t>((unit >> 8) & 0xFF));
    }
    return out;
}

// Encodes one directory entry in the requested [MS-FSCC] 2.4 layout. Returns an
// empty vector when the entry's stat data cannot be read (a dangling symlink,
// or a file deleted mid-enumeration): the caller skips such entries instead of
// letting a filesystem_error escape the enumeration.
std::vector<uint8_t> EncodeDirectoryEntry(const fs::directory_entry& entry,
                                          uint32_t info_class) {
    const fs::path path = entry.path();
    const std::u16string name = path.filename().u16string();
    const std::vector<uint8_t> name_utf16 = Utf16Le(name);
    const uint32_t name_len = static_cast<uint32_t>(name_utf16.size());
    const uint32_t attributes = entry.is_directory() ? 0x10 : 0x20;

    std::error_code ec;
    const uint64_t file_size =
        entry.is_directory()
            ? 0
            : static_cast<uint64_t>(fs::file_size(path, ec));
    if (ec) return {};
    ec.clear();
    const auto last = fs::last_write_time(path, ec);
    if (ec) return {};
    const uint64_t write = ToFileTime(last);

    std::vector<uint8_t> out;
    switch (info_class) {
        case kFileDirectoryInformation:
        case kFileFullDirectoryInformation:
        case kFileBothDirectoryInformation: {
            AppendU32(out, 0);  // NextEntryOffset: no following entry
            AppendU32(out, 0);  // FileIndex
            AppendU64(out, write);  // CreationTime
            AppendU64(out, write);  // LastAccessTime
            AppendU64(out, write);  // LastWriteTime
            AppendU64(out, write);  // ChangeTime
            AppendU64(out, file_size);
            AppendU64(out, file_size);
            AppendU32(out, attributes);
            if (info_class == kFileBothDirectoryInformation) {
                AppendU32(out, name_len);
                AppendU32(out, 0);  // EaSize
                out.push_back(0);   // ShortNameLength
                out.push_back(0);   // Reserved
                for (int i = 0; i < 12; ++i) AppendU16(out, 0);  // ShortName
            } else if (info_class == kFileFullDirectoryInformation) {
                AppendU32(out, name_len);
                AppendU32(out, 0);  // EaSize
            } else {
                AppendU32(out, name_len);
            }
            out.insert(out.end(), name_utf16.begin(), name_utf16.end());
            break;
        }
        case kFileNamesInformation:
            AppendU32(out, 0);  // NextEntryOffset
            AppendU32(out, 0);  // FileIndex
            AppendU32(out, name_len);
            out.insert(out.end(), name_utf16.begin(), name_utf16.end());
            break;
        default:
            break;
    }
    return out;
}

}  // namespace

HostFileSystem::HostFileSystem() = default;

HostFileSystem::~HostFileSystem() = default;

HostFileSystem::File* HostFileSystem::Find(uint32_t file_id) {
    auto it = files_.find(file_id);
    return it == files_.end() ? nullptr : it->second.get();
}

bool HostFileSystem::Open(const std::string& local_path, bool for_write,
                          bool create, bool truncate, uint32_t& file_id) {
    std::error_code ec;
    const fs::path path(local_path);
    const bool is_directory = fs::is_directory(path, ec);
    if (is_directory) {
        auto file = std::make_unique<File>();
        file->is_directory = true;
        file->directory = local_path;
        file_id = next_id_++;
        files_.emplace(file_id, std::move(file));
        return true;
    }

    const bool exists = fs::exists(path, ec);
    if (!exists) {
        if (!create) return false;
        // A stream opened for reading cannot create the file, so create it
        // first and then open the handle with the requested access mode.
        std::ofstream creator(path, std::ios::binary);
        if (!creator.is_open()) return false;
        creator.close();
    } else if (truncate && !for_write) {
        // Truncation is decided by the create disposition ([MS-SMB2] 2.2.13),
        // not by the access mask, so a read-only handle still sees the file
        // emptied after FILE_SUPERSEDE / FILE_OVERWRITE(_IF).
        std::ofstream truncater(path, std::ios::binary | std::ios::trunc);
        if (!truncater.is_open()) return false;
        truncater.close();
    }

    auto file = std::make_unique<File>();
    std::ios::openmode mode = std::ios::binary;
    if (for_write) {
        mode |= std::ios::in | std::ios::out;
        if (truncate) mode |= std::ios::trunc;
    } else {
        mode |= std::ios::in;
    }
    file->stream.open(path, mode);
    if (!file->stream.is_open()) return false;
    file_id = next_id_++;
    files_.emplace(file_id, std::move(file));
    return true;
}

bool HostFileSystem::Read(uint32_t file_id, uint64_t offset, uint32_t length,
                          std::vector<uint8_t>& out) {
    File* file = Find(file_id);
    if (file == nullptr || file->is_directory || !file->stream.is_open()) {
        return false;
    }
    if (length > kMaxReadLength) {
        out.clear();
        return false;
    }
    file->stream.clear();
    file->stream.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    try {
        out.resize(length);
    } catch (const std::bad_alloc&) {
        out.clear();
        return false;
    } catch (const std::length_error&) {
        out.clear();
        return false;
    }
    file->stream.read(reinterpret_cast<char*>(out.data()),
                      static_cast<std::streamsize>(length));
    const std::streamsize got = file->stream.gcount();
    out.resize(got > 0 ? static_cast<size_t>(got) : 0);
    return true;
}

bool HostFileSystem::Write(uint32_t file_id, uint64_t offset,
                           const std::vector<uint8_t>& data,
                           uint32_t& written) {
    File* file = Find(file_id);
    if (file == nullptr || file->is_directory || !file->stream.is_open()) {
        return false;
    }
    file->stream.clear();
    if (offset == kAppendOffset) {
        file->stream.seekp(0, std::ios::end);
    } else {
        file->stream.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
    }
    file->stream.write(reinterpret_cast<const char*>(data.data()),
                       static_cast<std::streamsize>(data.size()));
    if (!file->stream.good()) return false;
    written = static_cast<uint32_t>(data.size());
    return true;
}

bool HostFileSystem::Close(uint32_t file_id) {
    return files_.erase(file_id) > 0;
}

void HostFileSystem::BuildDirectoryEntries(File& file,
                                           const std::string& local_path) {
    file.entries.clear();
    file.next_entry = 0;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(local_path, ec)) {
        file.entries.push_back(entry.path().string());
    }
    std::sort(file.entries.begin(), file.entries.end());
}

bool HostFileSystem::QueryDirectory(uint32_t file_id, bool initial,
                                    uint32_t fs_information_class,
                                    std::vector<uint8_t>& out) {
    File* file = Find(file_id);
    if (file == nullptr || !file->is_directory) return false;
    if (initial) BuildDirectoryEntries(*file, file->directory);
    while (file->next_entry < file->entries.size()) {
        const std::string full_path = file->entries[file->next_entry++];
        std::error_code ec;
        const fs::directory_entry entry(full_path, ec);
        if (ec) continue;  // unreachable entry: skip
        out = EncodeDirectoryEntry(entry, fs_information_class);
        if (out.empty()) continue;  // stat failed (e.g. dangling symlink): skip
        return true;
    }
    return false;
}

bool HostFileSystem::Stat(const std::string& local_path, bool& is_directory) {
    std::error_code ec;
    const fs::file_status status = fs::status(local_path, ec);
    if (ec) return false;
    is_directory = fs::is_directory(status);
    return true;
}

}  // namespace rtsc::rdpdr
