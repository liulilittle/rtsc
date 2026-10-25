// Windows USB backend for the URBDRC client (SetupAPI + WinUSB).

#include "rtsc/usb/usb_win32.h"

#ifdef _WIN32

#include <windows.h>

#include <devguid.h>
#include <devpkey.h>
#include <setupapi.h>
#include <usbiodef.h>
#include <winusb.h>

#include <cstdint>
#include <string>
#include <vector>

namespace rtsc::usb {

namespace {

// GUID_DEVINTERFACE_USB_DEVICE ({A5DCBF10-6530-11D2-901F-00C04FB951ED}).
constexpr GUID kUsbDeviceClassGuid = {0xA5DCBF10,
                                      0x6530,
                                      0x11D2,
                                      {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51,
                                       0xED}};

std::string WideToUtf8(const std::wstring& in) {
    if (in.empty()) return {};
    const int len = WideCharToMultiByte(CP_UTF8, 0, in.data(),
                                        static_cast<int>(in.size()), nullptr, 0,
                                        nullptr, nullptr);
    std::string out(static_cast<size_t>(len), '\0');
    if (len > 0) {
        WideCharToMultiByte(CP_UTF8, 0, in.data(), static_cast<int>(in.size()),
                            out.data(), len, nullptr, nullptr);
    }
    return out;
}

std::wstring Utf8ToWide(const std::string& in) {
    if (in.empty()) return {};
    const int len = MultiByteToWideChar(CP_UTF8, 0, in.data(),
                                        static_cast<int>(in.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(len), L'\0');
    if (len > 0) {
        MultiByteToWideChar(CP_UTF8, 0, in.data(), static_cast<int>(in.size()),
                            out.data(), len);
    }
    return out;
}

uint16_t ParseHex4(const std::wstring& s, const std::wstring& key) {
    const size_t pos = s.find(key);
    if (pos == std::wstring::npos) return 0;
    const size_t start = pos + key.size();
    uint32_t v = 0;
    for (size_t i = 0; i < 4 && start + i < s.size(); ++i) {
        const wchar_t c = s[start + i];
        uint32_t d = 0;
        if (c >= L'0' && c <= L'9') {
            d = static_cast<uint32_t>(c - L'0');
        } else if (c >= L'a' && c <= L'f') {
            d = static_cast<uint32_t>(c - L'a') + 10;
        } else if (c >= L'A' && c <= L'F') {
            d = static_cast<uint32_t>(c - L'A') + 10;
        } else {
            break;
        }
        v = (v << 4) | d;
    }
    return static_cast<uint16_t>(v);
}

std::string GuidToString(const GUID& g) {
    wchar_t buf[40] = {};
    StringFromGUID2(g, buf, 40);
    return WideToUtf8(buf);
}

// Reads a UTF-16 multisz registry property and splits it on NULs.
std::vector<std::string> ReadMultiSz(HDEVINFO devs, SP_DEVINFO_DATA& dev,
                                     DWORD property) {
    std::vector<std::string> out;
    DWORD type = 0;
    DWORD needed = 0;
    SetupDiGetDeviceRegistryPropertyW(devs, &dev, property, &type, nullptr, 0,
                                      &needed);
    if (needed == 0 || type != REG_MULTI_SZ) return out;
    std::vector<uint8_t> buf(needed);
    if (!SetupDiGetDeviceRegistryPropertyW(devs, &dev, property, &type,
                                            buf.data(), needed, nullptr)) {
        return out;
    }
    const wchar_t* p = reinterpret_cast<const wchar_t*>(buf.data());
    const size_t count = needed / sizeof(wchar_t);
    std::wstring current;
    for (size_t i = 0; i < count; ++i) {
        if (p[i] == L'\0') {
            if (!current.empty()) out.push_back(WideToUtf8(current));
            current.clear();
        } else {
            current.push_back(p[i]);
        }
    }
    return out;
}

UsbDeviceInfo ReadDeviceInfo(HDEVINFO devs, SP_DEVINFO_DATA& dev,
                             const std::wstring& path) {
    UsbDeviceInfo info;
    wchar_t instance[256] = {};
    DWORD needed = 0;
    if (SetupDiGetDeviceInstanceIdW(devs, &dev, instance, 256, &needed)) {
        info.instance_id = WideToUtf8(instance);
    }
    info.hardware_ids = ReadMultiSz(devs, dev, SPDRP_HARDWAREID);
    info.compatibility_ids = ReadMultiSz(devs, dev, SPDRP_COMPATIBLEIDS);
    for (const std::string& h : info.hardware_ids) {
        info.vendor_id = ParseHex4(Utf8ToWide(h), L"VID_");
        info.product_id = ParseHex4(Utf8ToWide(h), L"PID_");
        if (info.vendor_id != 0) break;
    }

    DEVPROPTYPE type = 0;
    GUID container = {};
    ULONG size = sizeof(container);
    if (SetupDiGetDevicePropertyW(devs, &dev, &DEVPKEY_Device_ContainerId, &type,
                                  reinterpret_cast<PBYTE>(&container), size,
                                  &size, 0)) {
        info.container_id = GuidToString(container);
    }
    (void)path;
    return info;
}

// Opens the physical device behind one enumerated interface.
HANDLE OpenDeviceHandle(const std::wstring& path) {
    return CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                       OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
}

}  // namespace

class UsbDeviceWin32 final : public UsbDevice {
 public:
    UsbDeviceWin32(std::wstring path, UsbDeviceInfo info)
        : path_(std::move(path)), info_(std::move(info)) {}
    ~UsbDeviceWin32() override { Close(); }

    bool Open() override {
        if (opened_) return true;
        handle_ = OpenDeviceHandle(path_);
        if (handle_ == INVALID_HANDLE_VALUE) return false;
        if (!WinUsb_Initialize(handle_, &winusb_)) {
            Close();
            return false;
        }
        opened_ = true;
        QueryInterfaces();
        return true;
    }

    void Close() override {
        if (winusb_ != nullptr) {
            WinUsb_Free(winusb_);
            winusb_ = nullptr;
        }
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
        opened_ = false;
    }

    const UsbDeviceInfo& info() const override { return info_; }

    bool SelectConfiguration(
        const std::vector<UsbInterfaceInfo>& interfaces,
        uint32_t& configuration_handle) override {
        (void)interfaces;
        configuration_handle = 0x10;
        return opened_;
    }

    bool SelectInterface(uint32_t, const UsbInterfaceInfo& iface,
                         uint32_t& interface_handle) override {
        if (!opened_) return false;
        for (const UsbInterfaceInfo& i : interfaces_) {
            if (i.number == iface.number &&
                i.alternate_setting == iface.alternate_setting) {
                if (!WinUsb_SetCurrentAlternateSetting(
                        winusb_, static_cast<UCHAR>(i.alternate_setting))) {
                    return false;
                }
                interface_handle = 0x20 + i.number;
                return true;
            }
        }
        return false;
    }

    bool ControlTransfer(uint32_t, uint32_t transfer_flags,
                         const std::vector<uint8_t>& setup,
                         const std::vector<uint8_t>& input,
                         UrbResult& result) override {
        if (winusb_ == nullptr || setup.size() != 8) {
            result.usbd_status = 0xC0000000;
            return false;
        }
        WINUSB_SETUP_PACKET pkt{};
        pkt.RequestType = setup[0];
        pkt.Request = setup[1];
        pkt.Value = static_cast<USHORT>(setup[2] | (setup[3] << 8));
        pkt.Index = static_cast<USHORT>(setup[4] | (setup[5] << 8));
        pkt.Length = static_cast<USHORT>(setup[6] | (setup[7] << 8));
        const bool in = (transfer_flags & 0x1) != 0;
        std::vector<uint8_t> buffer(in ? static_cast<size_t>(pkt.Length)
                                       : input.size());
        ULONG transferred = 0;
        if (!WinUsb_ControlTransfer(
                winusb_, pkt, buffer.empty() ? nullptr : buffer.data(),
                static_cast<ULONG>(buffer.size()), &transferred, nullptr)) {
            result.usbd_status = 0xC0000000;
            return false;
        }
        if (in) buffer.resize(transferred);
        result.usbd_status = 0;
        result.output_buffer = buffer;
        return true;
    }

    bool BulkOrInterruptTransfer(uint32_t pipe_handle, uint32_t transfer_flags,
                                 const std::vector<uint8_t>& input,
                                 UrbResult& result) override {
        if (winusb_ == nullptr) {
            result.usbd_status = 0xC0000000;
            return false;
        }
        const auto pipe = static_cast<UCHAR>(pipe_handle & 0xFF);
        const bool in = (transfer_flags & 0x1) != 0;
        ULONG transferred = 0;
        if (in) {
            std::vector<uint8_t> buffer(65536);
            ULONG len = static_cast<ULONG>(buffer.size());
            if (!WinUsb_ReadPipe(winusb_, pipe, buffer.data(), len,
                                 &transferred, nullptr)) {
                result.usbd_status = 0xC0000000;
                return false;
            }
            buffer.resize(transferred);
            result.output_buffer = buffer;
        } else {
            std::vector<uint8_t> copy = input;
            ULONG len = static_cast<ULONG>(copy.size());
            if (!WinUsb_WritePipe(winusb_, pipe, copy.empty() ? nullptr
                                                              : copy.data(),
                                  len, &transferred, nullptr)) {
                result.usbd_status = 0xC0000000;
                return false;
            }
        }
        result.usbd_status = 0;
        return true;
    }

    bool ResetPipe(uint32_t pipe_handle) override {
        if (winusb_ == nullptr) return false;
        return WinUsb_ResetPipe(winusb_,
                                static_cast<UCHAR>(pipe_handle & 0xFF)) != 0;
    }

    bool CancelRequest(uint32_t) override {
        // WinUSB does not track request ids; cancelling is a pipe-level abort.
        if (winusb_ == nullptr) return false;
        for (UCHAR pipe = 0x01; pipe <= 0x0F; ++pipe) {
            WinUsb_AbortPipe(winusb_, pipe);
        }
        return true;
    }

 private:
    void QueryInterfaces() {
        interfaces_.clear();
        for (UCHAR i = 0; i < 16; ++i) {
            USB_INTERFACE_DESCRIPTOR desc{};
            if (!WinUsb_QueryInterfaceSettings(winusb_, i, &desc)) break;
            UsbInterfaceInfo u{};
            u.number = desc.bInterfaceNumber;
            u.alternate_setting = desc.bAlternateSetting;
            u.device_class = desc.bInterfaceClass;
            u.sub_class = desc.bInterfaceSubClass;
            u.protocol = desc.bInterfaceProtocol;
            for (UCHAR p = 0; p < desc.bNumEndpoints; ++p) {
                WINUSB_PIPE_INFORMATION pipe{};
                if (!WinUsb_QueryPipe(winusb_, i, p, &pipe)) continue;
                UsbEndpointInfo e{};
                e.address = pipe.PipeId;
                e.max_packet_size = pipe.MaximumPacketSize;
                e.type = static_cast<uint8_t>(pipe.PipeType);
                e.interval = pipe.Interval;
                u.endpoints.push_back(e);
            }
            interfaces_.push_back(u);
        }
    }

    std::wstring path_;
    UsbDeviceInfo info_;
    std::vector<UsbInterfaceInfo> interfaces_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    WINUSB_INTERFACE_HANDLE winusb_ = nullptr;
    bool opened_ = false;
};

class UsbDeviceEnumeratorWin32 final : public UsbDeviceEnumerator {
 public:
    std::vector<UsbDeviceInfo> Enumerate() override {
        std::vector<UsbDeviceInfo> out;
        HDEVINFO devs = SetupDiGetClassDevsW(
            &kUsbDeviceClassGuid, nullptr, nullptr,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (devs == INVALID_HANDLE_VALUE) return out;
        SP_DEVICE_INTERFACE_DATA ifc{};
        ifc.cbSize = sizeof(ifc);
        for (DWORD i = 0;
             SetupDiEnumDeviceInterfaces(devs, nullptr, &kUsbDeviceClassGuid, i,
                                         &ifc);
             ++i) {
            DWORD required = 0;
            SetupDiGetDeviceInterfaceDetailW(devs, &ifc, nullptr, 0, &required,
                                             nullptr);
            if (required == 0) continue;
            std::vector<uint8_t> buf(required);
            auto* detail =
                reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buf.data());
            detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
            SP_DEVINFO_DATA dev{};
            dev.cbSize = sizeof(dev);
            if (!SetupDiGetDeviceInterfaceDetailW(devs, &ifc, detail, required,
                                                  nullptr, &dev)) {
                continue;
            }
            UsbDeviceInfo info = ReadDeviceInfo(devs, dev, detail->DevicePath);
            if (!info.instance_id.empty()) out.push_back(info);
        }
        SetupDiDestroyDeviceInfoList(devs);
        return out;
    }

    std::unique_ptr<UsbDevice> Open(const std::string& instance_id) override {
        HDEVINFO devs = SetupDiGetClassDevsW(
            &kUsbDeviceClassGuid, nullptr, nullptr,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (devs == INVALID_HANDLE_VALUE) return nullptr;
        std::unique_ptr<UsbDevice> result;
        SP_DEVICE_INTERFACE_DATA ifc{};
        ifc.cbSize = sizeof(ifc);
        for (DWORD i = 0;
             SetupDiEnumDeviceInterfaces(devs, nullptr, &kUsbDeviceClassGuid, i,
                                         &ifc);
             ++i) {
            DWORD required = 0;
            SetupDiGetDeviceInterfaceDetailW(devs, &ifc, nullptr, 0, &required,
                                             nullptr);
            if (required == 0) continue;
            std::vector<uint8_t> buf(required);
            auto* detail =
                reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buf.data());
            detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
            SP_DEVINFO_DATA dev{};
            dev.cbSize = sizeof(dev);
            if (!SetupDiGetDeviceInterfaceDetailW(devs, &ifc, detail, required,
                                                  nullptr, &dev)) {
                continue;
            }
            UsbDeviceInfo info = ReadDeviceInfo(devs, dev, detail->DevicePath);
            if (info.instance_id != instance_id) continue;
            auto device = std::make_unique<UsbDeviceWin32>(detail->DevicePath,
                                                           info);
            if (device->Open()) result = std::move(device);
            break;
        }
        SetupDiDestroyDeviceInfoList(devs);
        return result;
    }
};

std::unique_ptr<UsbDeviceEnumerator> CreateWin32Enumerator() {
    return std::make_unique<UsbDeviceEnumeratorWin32>();
}

}  // namespace rtsc::usb

#endif  // _WIN32
