// Local file-list provider for the CLIPRDR file-clip (CB_FILECONTENTS) path.
//
// The channel serves files to the remote peer (and is pointed at by the
// direction-B store gate) exclusively through this seam. This layer defines the
// seam only; the direction-B backend that serves a local CF_HDROP selection is
// DropFileList in rtsc/clipboard/drop_files.h (covered by
// tests/test_drop_files.cpp). The provider-gate behaviour stays here: with no
// provider installed, every file-contents request fails.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rtsc::clipboard {

// One entry of a local file list that the cliprdr channel can serve.
struct FileInfo {
    uint32_t attributes = 0;
    uint64_t size = 0;
    std::u16string name;
    bool is_directory = false;
};

// Serves a fixed, index-addressed file list. `read_range()` copies at most
// `count` bytes starting at `offset` into `out`; bounds are the provider's
// job and are validated against the reported `file_info().size`.
class FileListProvider {
 public:
    virtual ~FileListProvider() = default;

    virtual uint32_t file_count() const = 0;
    virtual bool file_info(uint32_t index, FileInfo& out) const = 0;
    virtual bool read_range(uint32_t index, uint64_t offset, uint32_t count,
                            std::vector<uint8_t>& out) = 0;
};

}  // namespace rtsc::clipboard