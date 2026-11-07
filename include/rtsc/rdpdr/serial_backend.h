// Serial port redirection backend ([MS-RDPEFS] §Device redirection, serial
// devices). The rdpdr client announces serial devices and drives their
// CREATE/READ/WRITE/CLOSE/DEVICE_CONTROL requests through this seam. The
// platform layer (Win32 COM ports) or a test double implements it.
//
// The interface is deliberately small and platform neutral so the channel
// handler stays testable without touching real hardware.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rtsc::rdpdr {

class ISerialBackend {
 public:
    virtual ~ISerialBackend() = default;

    // Opens `port` (e.g. "COM1"). Returns a nonzero handle on success, or 0 on
    // failure (missing port, in use, or unsupported).
    virtual uint32_t Open(const std::string& port) = 0;

    // Reads up to `length` bytes. Returns false when the handle is unknown or
    // the read fails; `out` may be shorter than `length` (short read).
    virtual bool Read(uint32_t handle, uint32_t length,
                      std::vector<uint8_t>& out) = 0;

    // Writes `data`; returns false on failure. `written` is the number of bytes
    // accepted.
    virtual bool Write(uint32_t handle, const std::vector<uint8_t>& data,
                       uint32_t& written) = 0;

    // Closes the handle. Returns false when the handle is unknown.
    virtual bool Close(uint32_t handle) = 0;

    // Applies a serial IOCTL ([MS-RDPEFS] IRP_MJ_DEVICE_CONTROL on a serial
    // device). `input`/`output` are the raw buffers. Returns false for an
    // unsupported or failing IOCTL.
    virtual bool Control(uint32_t handle, uint32_t ioctl,
                         const std::vector<uint8_t>& input,
                         std::vector<uint8_t>& output) = 0;
};

}  // namespace rtsc::rdpdr
