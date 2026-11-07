// Local file system bridge for RDPDR drive redirection ([MS-RDPEFS] 3.1).

#include "rtsc/rdpdr/file_system.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

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

void AppendUtf16(std::vector<uint8_t>& out, const std::u16string& s) {
    for (const char16_t c : s) AppendU16(out, static_cast<uint16_t>(c));
}

#if defined(_WIN32)
std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                      static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        out.data(), n);
    return out;
}

std::u16string Utf16FromWide(const wchar_t* s) {
    std::u16string out;
    for (; s != nullptr && *s != L'\0'; ++s) {
        out.push_back(static_cast<char16_t>(*s));
    }
    return out;
}

uint64_t FileTimeValue(const FILETIME& ft) {
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) |
           ft.dwLowDateTime;
}

// Returns the volume root ("X:\") that contains `path`, or an empty string when
// it cannot be determined.
std::wstring VolumeRootOf(const std::wstring& path) {
    if (path.empty()) return std::wstring();
    if (path.size() >= 3 && path[1] == L':' && path[2] == L'\\') {
        return path.substr(0, 3);
    }
    const size_t slash = path.find(L'\\');
    if (slash == std::wstring::npos) return std::wstring();
    return path.substr(0, slash + 1);
}
#endif

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

bool EncodeVolumeInfo(uint32_t fs_information_class, const VolumeInfo& info,
                      std::vector<uint8_t>& out) {
    out.clear();
    switch (fs_information_class) {
        case 0x01: {  // FileFsVolumeInformation
            AppendU64(out, info.creation_time);
            AppendU32(out, info.serial);
            // VolumeLabelLength includes the trailing NUL.
            AppendU32(out,
                      static_cast<uint32_t>((info.label.size() + 1) * 2));
            out.push_back(info.supports_objects ? 1 : 0);
            // [MS-RDPEFS] 2.2.3.3.6: the Reserved byte MUST NOT be present.
            AppendUtf16(out, info.label);
            AppendU16(out, 0);
            return true;
        }
        case 0x04: {  // FileFsDeviceInformation
            AppendU32(out, info.device_type);
            AppendU32(out, info.characteristics);
            return true;
        }
        case 0x05: {  // FileFsAttributeInformation
            AppendU32(out, info.file_system_attributes);
            AppendU32(out, info.max_component_length);
            AppendU32(out,
                      static_cast<uint32_t>(info.file_system_name.size() * 2));
            AppendUtf16(out, info.file_system_name);
            return true;
        }
        default:
            return false;
    }
}

bool EncodeFileInformation(uint32_t fs_information_class, const FileInfo& info,
                           std::vector<uint8_t>& out) {
    out.clear();
    switch (fs_information_class) {
        case 0x04: {  // FileBasicInformation
            AppendU64(out, info.creation_time);
            AppendU64(out, info.last_access_time);
            AppendU64(out, info.last_write_time);
            AppendU64(out, info.change_time);
            AppendU32(out, info.attributes);
            // [MS-RDPEFS] 2.2.3.3.8: the Reserved field MUST NOT be present.
            return true;
        }
        case 0x05: {  // FileStandardInformation
            AppendU64(out, info.allocation_size);
            AppendU64(out, info.end_of_file);
            AppendU32(out, info.number_of_links);
            out.push_back(info.delete_pending ? 1 : 0);
            out.push_back(info.is_directory ? 1 : 0);
            // [MS-RDPEFS] 2.2.3.3.8: the Reserved field MUST NOT be present.
            return true;
        }
        case 0x23: {  // FileAttributeTagInformation
            AppendU32(out, info.attributes);
            AppendU32(out, info.reparse_tag);
            return true;
        }
        default:
            return false;
    }
}

HostFileSystem::HostFileSystem() = default;

HostFileSystem::~HostFileSystem() = default;

HostFileSystem::File* HostFileSystem::Find(uint32_t file_id) {
    auto it = files_.find(file_id);
    return it == files_.end() ? nullptr : it->second.get();
}

uint32_t HostFileSystem::AllocateId() {
    if (free_ids_.empty()) return next_id_++;
    const uint32_t id = free_ids_.back();
    free_ids_.pop_back();
    return id;
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
        file->local_path = local_path;
        file_id = AllocateId();
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
    file->local_path = local_path;
    std::ios::openmode mode = std::ios::binary;
    if (for_write) {
        mode |= std::ios::in | std::ios::out;
        if (truncate) mode |= std::ios::trunc;
    } else {
        mode |= std::ios::in;
    }
    file->stream.open(path, mode);
    if (!file->stream.is_open()) return false;
    file_id = AllocateId();
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
    if (files_.erase(file_id) == 0) return false;
    // [MS-RDPEFS] 2.2.1.5.1: the id is reused after a close response.
    free_ids_.push_back(file_id);
    return true;
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

bool HostFileSystem::QueryVolume(uint32_t file_id,
                                 uint32_t fs_information_class,
                                 std::vector<uint8_t>& out) {
    out.clear();
    File* file = Find(file_id);
    if (file == nullptr) return false;
#if defined(_WIN32)
    constexpr uint32_t kFileFsVolumeInformation = 0x01;
    constexpr uint32_t kFileFsSizeInformation = 0x03;
    constexpr uint32_t kFileFsDeviceInformation = 0x04;
    constexpr uint32_t kFileFsAttributeInformation = 0x05;
    constexpr uint32_t kFileFsFullSizeInformation = 0x07;

    const std::wstring path = Utf8ToWide(file->local_path);
    if (path.empty()) return false;
    // The volume root ("X:\") is what the volume APIs expect.
    const std::wstring root = VolumeRootOf(path);
    if (root.empty()) return false;

    if (fs_information_class == kFileFsVolumeInformation ||
        fs_information_class == kFileFsAttributeInformation) {
        wchar_t label[MAX_PATH + 1] = {};
        wchar_t fs_name[MAX_PATH + 1] = {};
        DWORD serial = 0;
        DWORD max_component = 0;
        DWORD flags = 0;
        if (!GetVolumeInformationW(root.c_str(), label, MAX_PATH, &serial,
                                   &max_component, &flags, fs_name,
                                   MAX_PATH)) {
            return false;
        }
        VolumeInfo info;
        info.serial = serial;
        info.supports_objects = false;
        info.file_system_attributes = flags;
        info.max_component_length = max_component;
        info.label = Utf16FromWide(label);
        info.file_system_name = Utf16FromWide(fs_name);
        return EncodeVolumeInfo(fs_information_class, info, out);
    }

    if (fs_information_class == kFileFsDeviceInformation) {
        const UINT type = GetDriveTypeW(root.c_str());
        VolumeInfo info;
        info.device_type = type == DRIVE_CDROM ? 0x00000002 : 0x00000007;
        info.characteristics = 0x00000020;  // FILE_DEVICE_IS_MOUNTED
        if (type == DRIVE_REMOVABLE || type == DRIVE_CDROM) {
            info.characteristics |= 0x00000001;  // FILE_REMOVABLE_MEDIA
        }
        if (type == DRIVE_CDROM) {
            info.characteristics |= 0x00000002;  // FILE_READ_ONLY_DEVICE
        }
        if (type == DRIVE_REMOTE) {
            info.characteristics |= 0x00000010;  // FILE_REMOTE_DEVICE
        }
        return EncodeVolumeInfo(fs_information_class, info, out);
    }

    if (fs_information_class != kFileFsSizeInformation &&
        fs_information_class != kFileFsFullSizeInformation) {
        return false;
    }
    ULARGE_INTEGER free_bytes{};
    ULARGE_INTEGER total_bytes{};
    ULARGE_INTEGER total_free{};
    if (!GetDiskFreeSpaceExW(path.c_str(), &free_bytes, &total_bytes,
                             &total_free)) {
        return false;
    }
    DWORD sectors_per_cluster = 0;
    DWORD bytes_per_sector = 0;
    DWORD free_clusters = 0;
    DWORD total_clusters = 0;
    if (!GetDiskFreeSpaceW(root.c_str(), &sectors_per_cluster,
                           &bytes_per_sector, &free_clusters,
                           &total_clusters)) {
        return false;
    }
    const uint64_t unit =
        static_cast<uint64_t>(sectors_per_cluster) * bytes_per_sector;
    if (unit == 0) return false;
    const uint64_t total_units =
        static_cast<uint64_t>(total_bytes.QuadPart) / unit;
    const uint64_t available_units =
        static_cast<uint64_t>(total_free.QuadPart) / unit;
    AppendU64(out, total_units);
    if (fs_information_class == kFileFsSizeInformation) {
        AppendU64(out, available_units);
    } else {
        // CallerAvailableAllocationUnits then ActualAvailableAllocationUnits.
        AppendU64(out, static_cast<uint64_t>(free_bytes.QuadPart) / unit);
        AppendU64(out, available_units);
    }
    AppendU32(out, sectors_per_cluster);
    AppendU32(out, bytes_per_sector);
    return true;
#else
    (void)fs_information_class;
    return false;
#endif
}

bool HostFileSystem::Rename(const std::string& local_path,
                            const std::string& new_path, bool replace) {
    std::error_code ec;
    if (!replace && fs::exists(new_path, ec)) return false;
    if (replace) {
        ec.clear();
        // std::filesystem::rename does not replace on Windows, so drop the
        // target first. A missing target is not an error.
        fs::remove(new_path, ec);
    }
    ec.clear();
    fs::rename(local_path, new_path, ec);
    return !ec;
}

bool HostFileSystem::Delete(const std::string& local_path) {
    std::error_code ec;
    const bool removed = fs::remove(local_path, ec);
    return removed && !ec;
}

bool HostFileSystem::QueryInformation(uint32_t file_id,
                                      uint32_t fs_information_class,
                                      std::vector<uint8_t>& out) {
    out.clear();
    File* file = Find(file_id);
    if (file == nullptr) return false;
    FileInfo info;
    info.is_directory = file->is_directory;
    info.attributes = file->is_directory ? 0x10 : 0x20;
    if (!file->is_directory) {
        std::error_code ec;
        const uint64_t size =
            static_cast<uint64_t>(fs::file_size(file->local_path, ec));
        if (!ec) {
            info.end_of_file = size;
            // AllocationSize must be a cluster multiple; the exact cluster
            // size is not exposed portably, so report the logical size.
            info.allocation_size = size;
        }
    }
#if defined(_WIN32)
    const std::wstring path = Utf8ToWide(file->local_path);
    if (!path.empty()) {
        WIN32_FILE_ATTRIBUTE_DATA data{};
        if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) {
            info.attributes = data.dwFileAttributes;
            info.creation_time = FileTimeValue(data.ftCreationTime);
            info.last_access_time = FileTimeValue(data.ftLastAccessTime);
            info.last_write_time = FileTimeValue(data.ftLastWriteTime);
            info.change_time = info.last_write_time;
            if (!file->is_directory) {
                info.end_of_file =
                    (static_cast<uint64_t>(data.nFileSizeHigh) << 32) |
                    data.nFileSizeLow;
                info.allocation_size = info.end_of_file;
            }
        }
    }
#endif
    return EncodeFileInformation(fs_information_class, info, out);
}

bool HostFileSystem::SetVolumeName(uint32_t file_id,
                                    const std::string& label) {
    File* file = Find(file_id);
    if (file == nullptr) return false;
#if defined(_WIN32)
    const std::wstring path = Utf8ToWide(file->local_path);
    if (path.empty()) return false;
    const std::wstring root = VolumeRootOf(path);
    if (root.empty()) return false;
    const std::wstring wide_label = Utf8ToWide(label);
    // SetVolumeLabelW needs administrator rights and a volume that supports
    // labels; a failure maps to ACCESS_DENIED at the client.
    return SetVolumeLabelW(root.c_str(), wide_label.c_str()) != FALSE;
#else
    (void)label;
    return false;
#endif
}

}  // namespace rtsc::rdpdr
