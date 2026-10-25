// Surface Commands framing ([MS-RDPBCGR] 2.2.9.2).

#include "rtsc/proto/surface.h"

namespace rtsc::proto {

Status ParseSurfaceCommands(const uint8_t* data, size_t size,
                            std::vector<SurfaceCommand>& out) {
    out.clear();
    if (data == nullptr) return Status::NeedMoreData;

    size_t pos = 0;
    while (pos < size) {
        if (pos + 4 > size) return Status::NeedMoreData;
        const uint16_t type =
            static_cast<uint16_t>(data[pos] | (data[pos + 1] << 8));
        const uint16_t len =
            static_cast<uint16_t>(data[pos + 2] | (data[pos + 3] << 8));
        if (len < 4) return Status::InvalidLength;  // cannot advance
        if (pos + len > size) return Status::NeedMoreData;

        SurfaceCommand cmd;
        cmd.cmd_type = type;
        cmd.data.assign(data + pos + 4, data + pos + len);
        out.push_back(std::move(cmd));
        pos += len;
    }
    return Status::Ok;
}

}  // namespace rtsc::proto
