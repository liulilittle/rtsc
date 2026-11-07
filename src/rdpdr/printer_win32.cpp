// Win32 printer backend implementation ([MS-RDPEPC]).

#include "rtsc/rdpdr/printer_win32.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winspool.h>
#endif

namespace rtsc::rdpdr {

namespace {

#ifdef _WIN32

std::wstring WideFromUtf8(const std::string& text) {
    if (text.empty()) return {};
    const int len = MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (len <= 0) return {};
    std::wstring out(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(),
                        static_cast<int>(text.size()), out.data(), len);
    return out;
}

std::string Utf8FromWide(const std::wstring& text) {
    if (text.empty()) return {};
    const int len = WideCharToMultiByte(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0,
        nullptr, nullptr);
    if (len <= 0) return {};
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        out.data(), len, nullptr, nullptr);
    return out;
}

#endif  // _WIN32

}  // namespace

Win32PrinterBackend::Win32PrinterBackend() = default;

Win32PrinterBackend::~Win32PrinterBackend() {
    while (!jobs_.empty()) {
        CloseJob(jobs_.begin()->first);
    }
}

uint32_t Win32PrinterBackend::OpenJob(const std::string& printer_name) {
#ifdef _WIN32
    if (printer_name.empty()) return 0;
    const std::wstring wide = WideFromUtf8(printer_name);
    if (wide.empty()) return 0;
    HANDLE printer = nullptr;
    if (!OpenPrinterW(const_cast<wchar_t*>(wide.c_str()), &printer, nullptr)) {
        return 0;
    }
    DOC_INFO_1W info{};
    info.pDocName = const_cast<wchar_t*>(L"RTSC Print Job");
    info.pDatatype = const_cast<wchar_t*>(L"RAW");
    if (StartDocPrinterW(printer, 1, reinterpret_cast<LPBYTE>(&info)) == 0) {
        ClosePrinter(printer);
        return 0;
    }
    if (!StartPagePrinter(printer)) {
        EndDocPrinter(printer);
        ClosePrinter(printer);
        return 0;
    }
    Job job;
    job.printer = printer;
    job.page_open = true;
    const uint32_t id = next_id_++;
    jobs_[id] = job;
    return id;
#else
    (void)printer_name;
    return 0;
#endif
}

bool Win32PrinterBackend::Write(uint32_t job, const std::vector<uint8_t>& data,
                                uint32_t& written) {
    written = 0;
#ifdef _WIN32
    const auto it = jobs_.find(job);
    if (it == jobs_.end()) return false;
    if (data.empty()) return true;
    DWORD accepted = 0;
    if (!WritePrinter(it->second.printer, const_cast<uint8_t*>(data.data()),
                      static_cast<DWORD>(data.size()), &accepted)) {
        return false;
    }
    written = static_cast<uint32_t>(accepted);
    return true;
#else
    (void)job;
    (void)data;
    return false;
#endif
}

bool Win32PrinterBackend::CloseJob(uint32_t job) {
#ifdef _WIN32
    const auto it = jobs_.find(job);
    if (it == jobs_.end()) return false;
    HANDLE printer = static_cast<HANDLE>(it->second.printer);
    if (it->second.page_open) {
        EndPagePrinter(printer);
    }
    EndDocPrinter(printer);
    ClosePrinter(printer);
    jobs_.erase(it);
    return true;
#else
    (void)job;
    return false;
#endif
}

std::vector<LocalPrinter> EnumeratePrinters() {
    std::vector<LocalPrinter> printers;
#ifdef _WIN32
    const DWORD flags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS;
    DWORD needed = 0;
    DWORD returned = 0;
    EnumPrintersW(flags, nullptr, 2, nullptr, 0, &needed, &returned);
    if (needed == 0) return printers;
    std::vector<uint8_t> buffer(needed);
    if (!EnumPrintersW(flags, nullptr, 2, buffer.data(), needed, &needed,
                       &returned)) {
        return printers;
    }
    auto* infos = reinterpret_cast<PRINTER_INFO_2W*>(buffer.data());
    for (DWORD i = 0; i < returned; ++i) {
        LocalPrinter entry;
        if (infos[i].pPrinterName != nullptr) {
            entry.name = Utf8FromWide(infos[i].pPrinterName);
        }
        if (infos[i].pDriverName != nullptr) {
            entry.driver = Utf8FromWide(infos[i].pDriverName);
        }
        if (!entry.name.empty()) printers.push_back(entry);
    }
#endif
    return printers;
}

}  // namespace rtsc::rdpdr
