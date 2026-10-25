#include "rtsc/proto/tpkt.h"

namespace rtsc::proto {

Status TpktHeader::parse(const uint8_t* data, size_t size, TpktHeader& out) {
    if (size < kSize) return Status::NeedMoreData;
    if (data[0] != kVersion) return Status::InvalidVersion;
    if (data[1] != 0) return Status::InvalidReserved;
    out.length = static_cast<uint16_t>((static_cast<uint16_t>(data[2]) << 8) |
                                       static_cast<uint16_t>(data[3]));
    return Status::Ok;
}

Status TpktHeader::validate(size_t available) const {
    if (length < kSize) return Status::InvalidLength;
    if (length > kMaxLength) return Status::InvalidLength;
    if (available < length) return Status::NeedMoreData;
    return Status::Ok;
}

std::vector<uint8_t> TpktHeader::encode() const {
    ByteWriter w;
    w.u8(kVersion);
    w.u8(0);
    w.u16be(length);
    return w.take();
}

}  // namespace rtsc::proto
