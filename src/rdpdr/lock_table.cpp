#include "rtsc/rdpdr/lock_table.h"

#include <algorithm>
#include <utility>

namespace rtsc::rdpdr {

namespace {

uint64_t RangeEnd(const LockTable::Range& range) {
    if (range.offset > UINT64_MAX - range.length) return UINT64_MAX;
    return range.offset + range.length;
}

bool Overlaps(const LockTable::Range& a, const LockTable::Range& b) {
    return a.offset < RangeEnd(b) && b.offset < RangeEnd(a);
}

}  // namespace

LockTable::Result LockTable::Lock(uint32_t file_id, const Range& range,
                                  bool exclusive) {
    return LockMany(file_id, {range}, exclusive);
}

LockTable::Result LockTable::LockMany(uint32_t file_id,
                                      const std::vector<Range>& ranges,
                                      bool exclusive) {
    std::vector<Entry> next = locks_;
    for (const Range& range : ranges) {
        for (const Entry& lock : next) {
            if (!Overlaps(range, lock.range)) continue;
            if (exclusive || lock.exclusive) return Result::kConflict;
        }
        Entry entry;
        entry.file_id = file_id;
        entry.range = range;
        entry.exclusive = exclusive;
        next.push_back(entry);
    }
    locks_ = std::move(next);
    return Result::kOk;
}

LockTable::Result LockTable::Unlock(uint32_t file_id, const Range& range) {
    return UnlockMany(file_id, {range});
}

LockTable::Result LockTable::UnlockMany(uint32_t file_id,
                                        const std::vector<Range>& ranges) {
    std::vector<Entry> next = locks_;
    for (const Range& range : ranges) {
        const auto it = std::find_if(
            next.begin(), next.end(), [&](const Entry& lock) {
                return lock.file_id == file_id &&
                       lock.range.offset == range.offset &&
                       lock.range.length == range.length;
            });
        if (it == next.end()) return Result::kNotLocked;
        next.erase(it);
    }
    locks_ = std::move(next);
    return Result::kOk;
}

void LockTable::ReleaseFile(uint32_t file_id) {
    locks_.erase(std::remove_if(locks_.begin(), locks_.end(),
                                [file_id](const Entry& lock) {
                                    return lock.file_id == file_id;
                                }),
                 locks_.end());
}

void LockTable::Clear() { locks_.clear(); }

}  // namespace rtsc::rdpdr
