// Win32 serial port backend for RDPDR serial redirection.
//
// Opens local COM ports through CreateFileW. Reads use short timeouts so the
// channel thread never blocks indefinitely waiting for bytes.

#include "rtsc/rdpdr/serial_win32.h"

#include <algorithm>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace rtsc::rdpdr {

namespace {

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                      static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        out.data(), n);
    return out;
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.data(),
                                      static_cast<int>(s.size()), nullptr, 0,
                                      nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        out.data(), n, nullptr, nullptr);
    return out;
}

}  // namespace

Win32SerialBackend::Win32SerialBackend() = default;

Win32SerialBackend::~Win32SerialBackend() {
    for (const auto& entry : ports_) {
        if (entry.second.handle != nullptr) {
            CloseHandle(static_cast<HANDLE>(entry.second.handle));
        }
    }
}

uint32_t Win32SerialBackend::Open(const std::string& port) {
    if (port.empty()) return 0;
    const std::wstring device = L"\\\\.\\" + Utf8ToWide(port);
    HANDLE handle = CreateFileW(device.c_str(), GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return 0;

    // 9600 8N1, no flow control; the server reconfigures through IOCTLs.
    DCB dcb{};
    dcb.DCBlength = sizeof(DCB);
    if (!GetCommState(handle, &dcb)) {
        CloseHandle(handle);
        return 0;
    }
    dcb.BaudRate = CBR_9600;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE;
    dcb.fParity = FALSE;
    dcb.fOutxCtsFlow = FALSE;
    dcb.fOutxDsrFlow = FALSE;
    dcb.fDtrControl = DTR_CONTROL_DISABLE;
    dcb.fDsrSensitivity = FALSE;
    dcb.fTXContinueOnXoff = FALSE;
    dcb.fOutX = FALSE;
    dcb.fInX = FALSE;
    dcb.fErrorChar = FALSE;
    dcb.fNull = FALSE;
    dcb.fRtsControl = RTS_CONTROL_DISABLE;
    dcb.fAbortOnError = FALSE;
    dcb.XonLim = 2048;
    dcb.XoffLim = 512;
    if (!SetCommState(handle, &dcb)) {
        CloseHandle(handle);
        return 0;
    }

    // Reads return within 100 ms with whatever bytes are available; writes
    // complete synchronously.
    COMMTIMEOUTS timeouts{};
    timeouts.ReadIntervalTimeout = MAXDWORD;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.ReadTotalTimeoutConstant = 100;
    timeouts.WriteTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 0;
    if (!SetCommTimeouts(handle, &timeouts)) {
        CloseHandle(handle);
        return 0;
    }

    const uint32_t id = next_id_++;
    Port entry;
    entry.handle = handle;
    ports_[id] = entry;
    return id;
}

bool Win32SerialBackend::Read(uint32_t handle, uint32_t length,
                              std::vector<uint8_t>& out) {
    out.clear();
    const auto it = ports_.find(handle);
    if (it == ports_.end()) return false;
    if (length == 0) return true;
    out.resize(length);
    DWORD read = 0;
    if (!ReadFile(static_cast<HANDLE>(it->second.handle), out.data(), length,
                  &read, nullptr)) {
        out.clear();
        return false;
    }
    out.resize(read);
    return true;
}

bool Win32SerialBackend::Write(uint32_t handle,
                               const std::vector<uint8_t>& data,
                               uint32_t& written) {
    written = 0;
    const auto it = ports_.find(handle);
    if (it == ports_.end()) return false;
    DWORD wrote = 0;
    if (!WriteFile(static_cast<HANDLE>(it->second.handle), data.data(),
                   static_cast<DWORD>(data.size()), &wrote, nullptr)) {
        return false;
    }
    written = static_cast<uint32_t>(wrote);
    return true;
}

bool Win32SerialBackend::Close(uint32_t handle) {
    const auto it = ports_.find(handle);
    if (it == ports_.end()) return false;
    const bool ok =
        CloseHandle(static_cast<HANDLE>(it->second.handle)) != FALSE;
    ports_.erase(it);
    return ok;
}

bool Win32SerialBackend::Control(uint32_t handle, uint32_t ioctl,
                                 const std::vector<uint8_t>& input,
                                 std::vector<uint8_t>& output) {
    output.clear();
    const auto it = ports_.find(handle);
    if (it == ports_.end()) return false;
    // The channel handler passes an empty vector; serial IOCTLs need room for
    // their return structure, so provide a bounded buffer.
    constexpr size_t kMaxControlOutput = 4096;
    output.resize(kMaxControlOutput);
    DWORD returned = 0;
    if (!DeviceIoControl(static_cast<HANDLE>(it->second.handle), ioctl,
                         const_cast<uint8_t*>(input.data()),
                         static_cast<DWORD>(input.size()), output.data(),
                         static_cast<DWORD>(output.size()), &returned,
                         nullptr)) {
        output.clear();
        return false;
    }
    output.resize(returned);
    return true;
}

std::vector<std::string> EnumerateSerialPorts() {
    std::vector<std::string> ports;
    constexpr DWORD kBufferChars = 65536;
    std::vector<wchar_t> buffer(kBufferChars);
    const DWORD chars = QueryDosDeviceW(nullptr, buffer.data(), kBufferChars);
    if (chars == 0) return ports;
    const wchar_t* cursor = buffer.data();
    const wchar_t* end = buffer.data() + chars;
    while (cursor < end && *cursor != L'\0') {
        const std::wstring name(cursor);
        cursor += name.size() + 1;
        if (name.size() <= 3 || name.compare(0, 3, L"COM") != 0) continue;
        bool digits = true;
        for (size_t i = 3; i < name.size(); ++i) {
            if (name[i] < L'0' || name[i] > L'9') {
                digits = false;
                break;
            }
        }
        if (!digits) continue;
        ports.push_back(WideToUtf8(name));
    }
    std::sort(ports.begin(), ports.end());
    return ports;
}

}  // namespace rtsc::rdpdr
