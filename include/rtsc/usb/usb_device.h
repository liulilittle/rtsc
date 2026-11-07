// Platform-neutral USB device abstraction used by the URBDRC client.
//
// The URBDRC channel handler ([MS-RDPEUSB] 1.3.1.3) forwards TS_URB requests
// to a physical device through this interface. The platform backend (Windows:
// SetupAPI + WinUSB, see src/usb/usb_win32.cpp) implements it; tests inject a
// fake.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace rtsc::usb {

// USB endpoint type values ([MS-RDPEUSB] 2.2.12).
enum UsbTransferType : uint8_t {
    kTransferControl = 0,
    kTransferIsochronous = 1,
    kTransferBulk = 2,
    kTransferInterrupt = 3,
};

struct UsbEndpointInfo {
    uint8_t address = 0;
    uint8_t type = kTransferControl;
    uint16_t max_packet_size = 0;
    uint8_t interval = 0;
};

struct UsbInterfaceInfo {
    uint8_t number = 0;
    uint8_t alternate_setting = 0;
    uint8_t device_class = 0;
    uint8_t sub_class = 0;
    uint8_t protocol = 0;
    std::vector<UsbEndpointInfo> endpoints;
};

// Static description of a redirectable USB device.
struct UsbDeviceInfo {
    std::string instance_id;
    std::vector<std::string> hardware_ids;
    std::vector<std::string> compatibility_ids;
    std::string container_id;
    uint16_t vendor_id = 0;
    uint16_t product_id = 0;
    uint8_t device_class = 0;
    bool high_speed = false;
    uint32_t supported_usb_version = 0x0200;
};

// Outcome of one URB execution.
struct UrbResult {
    // USBD_STATUS_* value ([MS-RDPEUSB] 2.2.10.1.1).
    uint32_t usbd_status = 0;
    std::vector<uint8_t> output_buffer;
};

// A handle to a physical USB device. Implementations execute URB requests.
class UsbDevice {
 public:
    virtual ~UsbDevice() = default;

    virtual bool Open() = 0;
    virtual void Close() = 0;
    virtual const UsbDeviceInfo& info() const = 0;

    // TS_URB_SELECT_CONFIGURATION ([MS-RDPEUSB] 2.2.9.2). Returns the
    // configuration handle.
    virtual bool SelectConfiguration(
        const std::vector<UsbInterfaceInfo>& interfaces,
        uint32_t& configuration_handle) = 0;

    // TS_URB_SELECT_INTERFACE ([MS-RDPEUSB] 2.2.9.3).
    virtual bool SelectInterface(uint32_t configuration_handle,
                                 const UsbInterfaceInfo& iface,
                                 uint32_t& interface_handle) = 0;

    // TS_URB_CONTROL_TRANSFER ([MS-RDPEUSB] 2.2.9.6). `setup` is the 8-byte
    // setup packet; `input` is the data stage payload (may be empty).
    virtual bool ControlTransfer(uint32_t pipe_handle, uint32_t transfer_flags,
                                 const std::vector<uint8_t>& setup,
                                 const std::vector<uint8_t>& input,
                                 UrbResult& result) = 0;

    // TS_URB_BULK_OR_INTERRUPT_TRANSFER ([MS-RDPEUSB] 2.2.9.7).
    // `input` is the OUT payload (may be empty for an IN transfer);
    // `max_read_size` caps the IN read buffer the backend allocates (the
    // client's TS_URB output buffer size), so a request that wants a few bytes
    // never allocates a 64 KiB staging buffer.
    virtual bool BulkOrInterruptTransfer(uint32_t pipe_handle,
                                         uint32_t transfer_flags,
                                         const std::vector<uint8_t>& input,
                                         uint32_t max_read_size,
                                         UrbResult& result) = 0;

    // TS_URB_PIPE_REQUEST ([MS-RDPEUSB] 2.2.9.4): reset or cancel a pipe.
    virtual bool ResetPipe(uint32_t pipe_handle) = 0;
    virtual bool CancelRequest(uint32_t request_id) = 0;

    // IO_CONTROL / INTERNAL_IO_CONTROL ([MS-RDPEUSB] 2.2.6.3 / 2.2.6.4):
    // forward a device IOCTL to the physical device. `output` receives the
    // result (at most `output_buffer_size` bytes); `information` is the byte
    // count reported by the device; `hresult` is S_OK (0) on success or an
    // HRESULT error. The default reports E_NOTIMPL so a backend that does not
    // implement device IOCTLs still lets the channel answer the server instead
    // of leaving it waiting for a completion.
    virtual bool IoControl(uint32_t /*io_control_code*/,
                           const std::vector<uint8_t>& /*input*/,
                           uint32_t /*output_buffer_size*/,
                           std::vector<uint8_t>& output, uint32_t& information,
                           uint32_t& hresult) {
        output.clear();
        information = 0;
        hresult = 0x80004001u;  // E_NOTIMPL
        return false;
    }
};

// Enumerates the redirectable USB devices and opens them by instance id.
class UsbDeviceEnumerator {
 public:
    virtual ~UsbDeviceEnumerator() = default;

    virtual std::vector<UsbDeviceInfo> Enumerate() = 0;
    // Returns nullptr when no device matches `instance_id`.
    virtual std::unique_ptr<UsbDevice> Open(const std::string& instance_id) = 0;
};

}  // namespace rtsc::usb
