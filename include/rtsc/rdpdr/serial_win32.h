// Win32 serial port backend for RDPDR serial redirection.
//
// Opens local COM ports through CreateFileW. Reads use short timeouts so the
// channel thread never blocks indefinitely waiting for bytes.

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "rtsc/rdpdr/serial_backend.h"

namespace rtsc::rdpdr {

class Win32SerialBackend final : public ISerialBackend {
 public:
    Win32SerialBackend();
    ~Win32SerialBackend() override;
    Win32SerialBackend(const Win32SerialBackend&) = delete;
    Win32SerialBackend& operator=(const Win32SerialBackend&) = delete;

    uint32_t Open(const std::string& port) override;
    bool Read(uint32_t handle, uint32_t length,
              std::vector<uint8_t>& out) override;
    bool Write(uint32_t handle, const std::vector<uint8_t>& data,
               uint32_t& written) override;
    bool Close(uint32_t handle) override;
    bool Control(uint32_t handle, uint32_t ioctl,
                 const std::vector<uint8_t>& input,
                 std::vector<uint8_t>& output) override;

 private:
    struct Port {
        void* handle = nullptr;  // HANDLE, kept opaque in this header
    };
    std::map<uint32_t, Port> ports_;
    uint32_t next_id_ = 1;
};

// Enumerates the local serial ports (e.g. {"COM1", "COM3"}) through
// QueryDosDeviceW. Returns an empty list on non-Windows.
std::vector<std::string> EnumerateSerialPorts();

}  // namespace rtsc::rdpdr
