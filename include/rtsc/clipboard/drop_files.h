// Direction-B file-list backend: a FileListProvider served from a local Win32
// CF_HDROP clipboard selection.
//
// The cliprdr channel serves file clips through the FileListProvider seam
// (CliprdrClient::SetFileListProvider). This slice turns a local CF_HDROP byte
// blob (the Clipboard::read() of kCfHdrop) into a provider: a fixed,
// index-addressed list of full paths that answers size/directory queries
// against the local filesystem and serves file ranges from disk.
//
// Reference: DROPFILES / DragQueryFile in shellapi.h.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "rtsc/clipboard/file_list.h"

namespace rtsc::clipboard {

// Win32 file attributes mirrored here so the header stays windows.h-free (it
// must build on every platform).
constexpr uint32_t kFileAttributeNormal = 0x00000080;  // FILE_ATTRIBUTE_NORMAL
constexpr uint32_t kFileAttributeDirectory = 0x00000010;  // FILE_ATTRIBUTE_DIRECTORY

// A file-list provider fixed at construction to a set of full local paths.
//
// file_info() reports the basename (the FILEDESCRIPTORW cFileName) plus a
// live filesystem snapshot (size, directory bit) at query time, so the sizes
// stay fresh if a file changes between parse and serve. A path that is a
// directory reports is_directory with size 0; any other path whose stat fails
// (missing or un-accessible file, a file whose size cannot be read) makes
// file_info return false instead of fabricating a size for the peer.
// read_range() re-opens the file for every call, so a file that disappears or
// cannot be opened fails the read instead of serving stale bytes.
class DropFileList final : public FileListProvider {
 public:
    explicit DropFileList(std::vector<std::u16string> full_paths);

    uint32_t file_count() const override;
    bool file_info(uint32_t index, FileInfo& out) const override;
    bool read_range(uint32_t index, uint64_t offset, uint32_t count,
                    std::vector<uint8_t>& out) override;

 private:
    std::vector<std::u16string> full_paths_;
};

// Parses a Win32 CF_HDROP byte blob into a DropFileList. Returns nullptr when
// the blob is not a well-formed UTF-16 (fWide==1) DROPFILES structure: too
// short to hold the header, a pFiles offset that falls outside the buffer, or
// an ANSI (fWide==0) table (unsupported in v1). An empty file table is legal
// and yields a zero-file provider. A malformed tail (a file name truncated
// without its terminator) stops the parse and keeps the names parsed so far.
std::unique_ptr<DropFileList> CreateDropFileListFromBytes(
    const std::vector<uint8_t>& bytes);

}  // namespace rtsc::clipboard