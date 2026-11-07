// Win32 printer backend for RDPDR printer redirection ([MS-RDPEPC]).
//
// Drives the local print spooler through winspool.drv: OpenPrinterW,
// StartDocPrinterW (RAW datatype), WritePrinter, EndDocPrinter, ClosePrinter.
// The server sends the print job bytes verbatim; the local driver renders them.

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "rtsc/rdpdr/printer_backend.h"

namespace rtsc::rdpdr {

class Win32PrinterBackend final : public IPrinterBackend {
 public:
    Win32PrinterBackend();
    ~Win32PrinterBackend() override;
    Win32PrinterBackend(const Win32PrinterBackend&) = delete;
    Win32PrinterBackend& operator=(const Win32PrinterBackend&) = delete;

    uint32_t OpenJob(const std::string& printer_name) override;
    bool Write(uint32_t job, const std::vector<uint8_t>& data,
               uint32_t& written) override;
    bool CloseJob(uint32_t job) override;

 private:
    struct Job {
        void* printer = nullptr;  // HANDLE, kept opaque in this header
        bool page_open = false;
    };
    std::map<uint32_t, Job> jobs_;
    uint32_t next_id_ = 1;
};

struct LocalPrinter {
    std::string name;    // queue name, e.g. "Microsoft Print to PDF"
    std::string driver;  // driver name, e.g. "Microsoft Print To PDF"
};

// Enumerates the local and connection printers through EnumPrintersW level 2.
// Returns an empty list on non-Windows or when the spooler is unavailable.
std::vector<LocalPrinter> EnumeratePrinters();

}  // namespace rtsc::rdpdr
