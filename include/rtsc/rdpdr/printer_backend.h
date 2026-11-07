// Printer redirection backend ([MS-RDPEPC]). The rdpdr client announces
// printer devices and drives their CREATE/WRITE/CLOSE requests through this
// seam. The platform layer (Win32 print spooler) or a test double implements
// it.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rtsc::rdpdr {

class IPrinterBackend {
 public:
    virtual ~IPrinterBackend() = default;

    // Starts a print job for `printer_name` (the local queue name). Returns a
    // nonzero job handle on success, or 0 on failure.
    virtual uint32_t OpenJob(const std::string& printer_name) = 0;

    // Appends `data` to the job. Returns false on a hard failure (unknown job
    // or spooler error); on success `written` receives the number of bytes
    // accepted, which may be less than `data.size()` for a short write.
    // [MS-RDPEPC] 3.2.5.1.10 requires DR_WRITE_RSP.Length to be the bytes
    // written successfully, so partial writes MUST surface as success with a
    // smaller count rather than an error.
    virtual bool Write(uint32_t job, const std::vector<uint8_t>& data,
                       uint32_t& written) = 0;

    // Finishes the job. Returns false when the handle is unknown.
    virtual bool CloseJob(uint32_t job) = 0;
};

}  // namespace rtsc::rdpdr
