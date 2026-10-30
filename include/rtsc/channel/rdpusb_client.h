// URBDRC (RemoteFX USB redirection) client channel handler ([MS-RDPEUSB]).
//
// The handler runs on top of a drdynvc transport ([MS-RDPEDYC]): it exchanges
// the channel capability, announces USB devices, and forwards TS_URB requests
// from the server to a physical device through rtsc::usb::UsbDevice.
//
// State machine ([MS-RDPEUSB] 1.3.1):
//   Idle -> CapabilityExchange -> Ready -> (AddVirtualChannel -> AddDevice
//   -> DeviceIo) -> ... -> Idle.

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "rtsc/channel/drdynvc_client.h"
#include "rtsc/proto/rdpusb.h"
#include "rtsc/usb/usb_device.h"

namespace rtsc::channel {

// ITVCProvider ([MS-RDPEUSB] 3.1): the application callbacks for URBDRC
// device lifecycle events.
class ITvcProvider {
 public:
    virtual ~ITvcProvider() = default;

    virtual void OnDeviceAdded(uint32_t, const usb::UsbDeviceInfo&) {}
    virtual void OnDeviceRemoved(uint32_t) {}
};

class RdpUsbClient : public IDrdynvcListener {
 public:
    // Ownership: the enumerator, transport and provider are borrowed for the
    // lifetime of this object.
    RdpUsbClient(usb::UsbDeviceEnumerator* enumerator,
                 DrdynvcClient* transport,
                 ITvcProvider* provider = nullptr);
    ~RdpUsbClient() override;

    RdpUsbClient(const RdpUsbClient&) = delete;
    RdpUsbClient& operator=(const RdpUsbClient&) = delete;

    // Creates the "URBDRC" control channel and starts the capability exchange.
    void Start();

    // Announces a device: sends ADD_VIRTUAL_CHANNEL on the control channel,
    // opens a per-device dynamic channel and sends ADD_DEVICE on it.
    bool AddDevice(const usb::UsbDeviceInfo& info);
    // Stops redirecting a previously announced device.
    void RemoveDevice(uint32_t usb_device);

    // IDrdynvcListener ([MS-RDPEDYC] 2.2).
    void OnCapsResponse(uint16_t version) override;
    void OnChannelCreated(uint32_t channel_id) override;
    void OnChannelData(uint32_t channel_id,
                       const std::vector<uint8_t>& data) override;
    void OnChannelClosed(uint32_t channel_id) override;

    // ---- diagnostics -------------------------------------------------------
    bool started() const { return started_; }
    bool ready() const { return state_ == State::kReady; }
    bool control_channel_open() const { return control_channel_ != 0; }
    uint32_t control_channel() const { return control_channel_; }
    uint32_t last_device_channel() const { return last_device_channel_; }
    uint32_t request_completion() const { return request_completion_; }
    size_t device_count() const { return devices_.size(); }
    unsigned channel_created_count() const { return channel_created_count_; }
    unsigned add_virtual_channel_count() const {
        return add_virtual_channel_count_;
    }
    unsigned add_device_count() const { return add_device_count_; }
    unsigned transfer_in_count() const { return transfer_in_count_; }
    unsigned transfer_out_count() const { return transfer_out_count_; }
    unsigned urb_completion_count() const { return urb_completion_count_; }
    unsigned retract_device_count() const { return retract_device_count_; }
    uint16_t version() const { return version_; }

 private:
    enum class State { kIdle, kCapabilityExchange, kReady };

    struct Device {
        uint32_t usb_device = 0;
        uint32_t channel_id = 0;
        std::string instance_id;
        std::unique_ptr<usb::UsbDevice> device;
        bool channel_open = false;
        uint32_t configuration_handle = 0;
    };

    void OnControlMessage(const std::vector<uint8_t>& msg);
    void OnDeviceMessage(uint32_t channel_id, const std::vector<uint8_t>& msg);
    void SendControl(const std::vector<uint8_t>& msg);
    void SendOnChannel(uint32_t channel_id, const std::vector<uint8_t>& msg);
    void HandleTransferIn(uint32_t channel_id, uint32_t usb_device,
                          const rtsc::proto::RdpUsbTransferInRequest& req);
    void HandleTransferOut(
        uint32_t channel_id, uint32_t usb_device,
        const rtsc::proto::RdpUsbTransferOutRequest& req);
    void ExecuteUrb(Device& device, const rtsc::proto::RdpUsbTsUrb& urb,
                    uint32_t output_buffer_size,
                    const std::vector<uint8_t>& output,
                    usb::UrbResult& result,
                    std::vector<uint8_t>& result_body);
    void CompleteUrb(uint32_t channel_id, uint32_t interface_id,
                     uint32_t request_id, uint16_t urb_function,
                     uint32_t usbd_status,
                     const std::vector<uint8_t>& result,
                     const std::vector<uint8_t>& output);
    Device* FindDevice(uint32_t usb_device);

    usb::UsbDeviceEnumerator* enumerator_;
    DrdynvcClient* transport_;
    ITvcProvider* provider_;

    State state_ = State::kIdle;
    bool started_ = false;
    uint16_t version_ = 0;
    uint32_t control_channel_ = 0;
    uint32_t last_device_channel_ = 0;
    uint32_t request_completion_ = 0;
    bool request_completion_valid_ = false;
    uint32_t next_usb_device_ = 1;

    std::map<uint32_t, Device> devices_;       // keyed by usb_device
    std::map<uint32_t, uint32_t> channel_to_device_;  // channel -> usb_device

    unsigned channel_created_count_ = 0;
    unsigned add_virtual_channel_count_ = 0;
    unsigned add_device_count_ = 0;
    unsigned transfer_in_count_ = 0;
    unsigned transfer_out_count_ = 0;
    unsigned urb_completion_count_ = 0;
    unsigned retract_device_count_ = 0;
};

}  // namespace rtsc::channel
