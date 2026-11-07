// Byte-range lock table for redirected drive files ([MS-RDPEFS] 2.2.1.6).
//
// The table tracks the locks the server took through IRP_MJ_LOCK_CONTROL so
// that conflicting ranges fail and unlocks only succeed for a range that was
// locked before. A length of zero is a valid zero-length region: it never
// conflicts, but it is still recorded so an exact unlock can succeed.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace rtsc::rdpdr {

class LockTable {
 public:
    struct Range {
        uint64_t offset = 0;
        uint64_t length = 0;
    };
    enum class Result { kOk, kConflict, kNotLocked };

    // Takes every range or none (a later conflict leaves the table unchanged).
    Result Lock(uint32_t file_id, const Range& range, bool exclusive);
    Result LockMany(uint32_t file_id, const std::vector<Range>& ranges,
                    bool exclusive);
    // Unlocks every range or none; each range must match a held lock exactly.
    Result Unlock(uint32_t file_id, const Range& range);
    Result UnlockMany(uint32_t file_id, const std::vector<Range>& ranges);
    // Drops every lock held by the handle (called when the handle closes).
    void ReleaseFile(uint32_t file_id);
    void Clear();
    size_t size() const { return locks_.size(); }

 private:
    struct Entry {
        uint32_t file_id = 0;
        Range range;
        bool exclusive = false;
    };
    std::vector<Entry> locks_;
};

}  // namespace rtsc::rdpdr
