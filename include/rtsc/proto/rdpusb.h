// Remote Desktop Protocol: USB Devices Virtual Channel Extension (URBDRC)
// wire structures ([MS-RDPEUSB] 2.2).
//
// Reference: [MS-RDPEUSB] 2.2.1 (SHARED_MSG_HEADER), 2.2.3 (RIM capabilities),
// 2.2.4 (device sink), 2.2.5 (channel created), 2.2.6 (server requests),
// 2.2.7 (client completions), 2.2.9/2.2.10 (TS_URB / TS_URB_RESULT) and
// 2.2.11 (USB_DEVICE_CAPABILITIES).
//
// The extension runs over the dynamic virtual channel named "URBDRC"
// ([MS-RDPEDYC]); each PDU below is the payload of one dynamic virtual channel
// data message, so there is no outer length field (the drdynvc layer frames it).

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// The dynamic virtual channel name ([MS-RDPEUSB] 2.1).
inline constexpr const char* kRdpUsbChannelName = "URBDRC";

// ---- interface identifiers ([MS-RDPEUSB] 2.2.2) --------------------------
enum class RdpUsbInterface : uint32_t {
    kCapabilitiesNegotiator = 0x00000000,
    kClientDeviceSink = 0x00000001,
    kServerChannelNotification = 0x00000002,
    kClientChannelNotification = 0x00000003,
};

// The Mask field of SHARED_MSG_HEADER ([MS-RDPEUSB] 2.2.1).
enum class RdpUsbStreamId : uint32_t {
    kNone = 0x00000000,
    kProxy = 0x00000001,
    kStub = 0x00000002,
};

inline constexpr uint32_t kRdpUsbStreamIdMask = 0xC0000000;
inline constexpr uint32_t kRdpUsbInterfaceIdMask = 0x3FFFFFFF;

// ---- function identifiers ([MS-RDPEUSB] 2.2.3 .. 2.2.7) -----------------
enum class RdpUsbFunction : uint32_t {
    kRimExchangeCapabilityRequest = 0x00000100,
    kRimExchangeCapabilityResponse = 0x00000100,
    kChannelCreated = 0x00000100,
    kAddVirtualChannel = 0x00000100,
    kAddDevice = 0x00000101,
    kCancelRequest = 0x00000100,
    kRegisterRequestCallback = 0x00000101,
    kIoControl = 0x00000102,
    kInternalIoControl = 0x00000103,
    kQueryDeviceText = 0x00000104,
    kTransferInRequest = 0x00000105,
    kTransferOutRequest = 0x00000106,
    kRetractDevice = 0x00000107,
    kIoControlCompletion = 0x00000100,
    kUrbCompletion = 0x00000101,
    kUrbCompletionNoData = 0x00000102,
};

// RIM capability value ([MS-RDPEUSB] 2.2.3.1).
inline constexpr uint32_t kRdpUsbRimCapabilityVersion01 = 0x00000001;

// CHANNEL_CREATED capabilities ([MS-RDPEUSB] 2.2.5.1).
inline constexpr uint32_t kRdpUsbChannelCapabilityVersion01 = 0x00000001;
inline constexpr uint32_t kRdpUsbChannelMajorVersion = 0x00000001;
inline constexpr uint32_t kRdpUsbChannelMinorVersion = 0x00000000;

// ---- TS_URB function codes ([MS-RDPEUSB] 2.2.9) -------------------------
enum class RdpUsbUrbFunction : uint16_t {
    kSelectConfiguration = 0x0000,
    kSelectInterface = 0x0001,
    kPipeRequest = 0x0002,
    kGetCurrentFrameNumber = 0x0007,
    kControlTransfer = 0x0008,
    kBulkOrInterruptTransfer = 0x0009,
    kIsochTransfer = 0x000A,
    kControlDescriptorRequest = 0x000B,
    kControlFeatureRequest = 0x000D,
    kControlGetStatusRequest = 0x0013,
    kControlVendorOrClassRequest = 0x0017,
    kControlGetConfigurationRequest = 0x0026,
    kControlGetInterfaceRequest = 0x0027,
    kOsFeatureDescriptorRequest = 0x002A,
    kControlTransferEx = 0x0032,
};

// USBD status values ([MS-RDPEUSB] 2.2.10.1.1).
enum class RdpUsbUsbdStatus : uint32_t {
    kSuccess = 0x00000000,
    kPending = 0x40000000,
    kCanceled = 0xC0010000,
    kStallPid = 0xC0000004,
    kTimeout = 0xC0006000,
    kDeviceGone = 0xC0007000,
    kInvalidUrbFunction = 0x80000200,
    kInvalidParameter = 0x80000300,
    kRequestFailed = 0x80000500,
    kInvalidPipeHandle = 0x80000600,
};

// USBD transfer flags ([MS-RDPEUSB] 2.2.9.6).
inline constexpr uint32_t kRdpUsbTransferDirection = 0x00000001;
inline constexpr uint32_t kRdpUsbShortTransferOk = 0x00000002;
inline constexpr uint32_t kRdpUsbStartIsoTransferAsap = 0x00000004;
inline constexpr uint32_t kRdpUsbDefaultPipeTransfer = 0x00000008;

// TS_URB_PIPE_REQUEST operation ([MS-RDPEUSB] 2.2.9.4).
enum class RdpUsbPipeRequestOp : uint32_t {
    kCancel = 0,
    kReset = 1,
};

// USB device speed ([MS-RDPEUSB] 2.2.11).
enum class RdpUsbDeviceSpeed : uint32_t {
    kFullSpeed = 0x00000000,
    kHighSpeed = 0x00000001,
};

// ---- SHARED_MSG_HEADER ([MS-RDPEUSB] 2.2.1), 12 bytes -------------------
struct RdpUsbHeader {
    static constexpr size_t kSize = 12;

    // InterfaceId (30 bits) | Mask (2 bits, STREAM_ID_MASK).
    uint32_t interface_id = 0;
    uint32_t message_id = 0;
    uint32_t function_id = 0;

    static Status parse(const uint8_t* data, size_t size, RdpUsbHeader& out);
    void write(ByteWriter& w) const;

    uint32_t stream_id() const { return (interface_id >> 30) & 0x3; }
    uint32_t interface_only() const {
        return interface_id & kRdpUsbInterfaceIdMask;
    }

    static uint32_t MakeInterfaceId(RdpUsbInterface id, RdpUsbStreamId mask) {
        return (static_cast<uint32_t>(id) & kRdpUsbInterfaceIdMask) |
               ((static_cast<uint32_t>(mask) << 30) & kRdpUsbStreamIdMask);
    }
};

// ---- capability exchange ------------------------------------------------

// RIM_EXCHANGE_CAPABILITY_REQUEST / _RESPONSE ([MS-RDPEUSB] 2.2.3).
struct RdpUsbRimExchangeCapability {
    RdpUsbHeader header;
    uint32_t capability = kRdpUsbRimCapabilityVersion01;
    // Present only in the response.
    uint32_t result = 0;

    std::vector<uint8_t> encode(bool is_response) const;
};

// CHANNEL_CREATED ([MS-RDPEUSB] 2.2.5.1).
struct RdpUsbChannelCreated {
    RdpUsbHeader header;
    uint32_t major_version = kRdpUsbChannelMajorVersion;
    uint32_t minor_version = kRdpUsbChannelMinorVersion;
    uint32_t capabilities = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbChannelCreated& out);
    std::vector<uint8_t> encode() const;
};

// ---- USB_DEVICE_CAPABILITIES ([MS-RDPEUSB] 2.2.11), 28 bytes ------------
// Declared before RdpUsbAddDevice, which embeds it.
struct RdpUsbDeviceCapabilities {
    static constexpr size_t kSize = 28;

    uint32_t cb_size = kSize;
    uint32_t usb_bus_interface_version = 0;
    uint32_t usbdi_version = 0x00000500;
    uint32_t supported_usb_version = 0x0200;
    uint32_t hcd_capabilities = 0;
    uint32_t device_is_high_speed = 0;
    uint32_t no_ack_isoch_write_jitter_buffer_size_in_ms = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbDeviceCapabilities& out);
    void write(ByteWriter& w) const;
};

// ---- device sink ---------------------------------------------------------

// ADD_VIRTUAL_CHANNEL ([MS-RDPEUSB] 2.2.4.1): header only.
std::vector<uint8_t> BuildRdpUsbAddVirtualChannel();

// ADD_DEVICE ([MS-RDPEUSB] 2.2.4.2).
struct RdpUsbAddDevice {
    RdpUsbHeader header;
    uint32_t num_usb_device = 1;
    uint32_t usb_device = 0;
    std::u16string device_instance_id;
    std::u16string hardware_ids;
    std::u16string compatibility_ids;
    std::u16string container_id;
    RdpUsbDeviceCapabilities capabilities;

    static Status parse(const uint8_t* data, size_t size, RdpUsbAddDevice& out);
    std::vector<uint8_t> encode() const;
};

// RETRACT_DEVICE ([MS-RDPEUSB] 2.2.6.9).
struct RdpUsbRetractDevice {
    RdpUsbHeader header;
    uint32_t reason = 0x00000001;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbRetractDevice& out);
    std::vector<uint8_t> encode() const;
};

// ---- server -> client requests -------------------------------------------

// REGISTER_REQUEST_CALLBACK ([MS-RDPEUSB] 2.2.6.2).
struct RdpUsbRegisterRequestCallback {
    RdpUsbHeader header;
    uint32_t num_request_completion = 0;
    uint32_t request_completion = 0;
    bool has_request_completion = false;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbRegisterRequestCallback& out);
    std::vector<uint8_t> encode() const;
};

// CANCEL_REQUEST ([MS-RDPEUSB] 2.2.6.1).
struct RdpUsbCancelRequest {
    RdpUsbHeader header;
    uint32_t request_id = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbCancelRequest& out);
    std::vector<uint8_t> encode() const;
};

// IO_CONTROL / INTERNAL_IO_CONTROL ([MS-RDPEUSB] 2.2.6.3 / 2.2.6.4).
struct RdpUsbIoControl {
    RdpUsbHeader header;
    uint32_t io_control_code = 0;
    std::vector<uint8_t> input_buffer;
    uint32_t output_buffer_size = 0;
    uint32_t request_id = 0;

    static Status parse(const uint8_t* data, size_t size, RdpUsbIoControl& out);
    std::vector<uint8_t> encode() const;
};

// QUERY_DEVICE_TEXT ([MS-RDPEUSB] 2.2.6.5).
struct RdpUsbQueryDeviceText {
    RdpUsbHeader header;
    uint32_t text_type = 0;
    uint32_t locale_id = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbQueryDeviceText& out);
    std::vector<uint8_t> encode() const;
};

// QUERY_DEVICE_TEXT_RSP ([MS-RDPEUSB] 2.2.6.6).
struct RdpUsbQueryDeviceTextResponse {
    RdpUsbHeader header;
    std::u16string device_description;
    uint32_t hresult = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbQueryDeviceTextResponse& out);
    std::vector<uint8_t> encode() const;
};

// ---- TS_URB ([MS-RDPEUSB] 2.2.9) ----------------------------------------

// TS_URB_HEADER ([MS-RDPEUSB] 2.2.9.1.1), 8 bytes.
struct RdpUsbTsUrbHeader {
    static constexpr size_t kSize = 8;

    uint16_t size = kSize;
    RdpUsbUrbFunction urb_function = RdpUsbUrbFunction::kSelectConfiguration;
    uint32_t request_id = 0;
    bool no_ack = false;

    static Status parse(const uint8_t* data, size_t size, RdpUsbTsUrbHeader& out);
    void write(ByteWriter& w) const;

    uint32_t request_id_and_no_ack() const {
        return (request_id & 0x7FFFFFFFu) | (no_ack ? 0x80000000u : 0u);
    }
    void set_request_id_and_no_ack(uint32_t v) {
        request_id = v & 0x7FFFFFFFu;
        no_ack = (v & 0x80000000u) != 0;
    }
};

// A parsed TS_URB: the common header plus the function-specific body. The raw
// body is retained so that unknown functions round-trip byte-for-byte.
struct RdpUsbTsUrb {
    RdpUsbTsUrbHeader header;
    std::vector<uint8_t> body;

    static Status parse(const uint8_t* data, size_t size, RdpUsbTsUrb& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_SELECT_CONFIGURATION ([MS-RDPEUSB] 2.2.9.2).
struct RdpUsbTsUsbdPipeInformation {
    uint16_t maximum_packet_size = 0;
    uint32_t maximum_transfer_size = 0;
    uint32_t pipe_flags = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUsbdPipeInformation& out);
    void write(ByteWriter& w) const;
};

struct RdpUsbTsUsbdInterfaceInformation {
    uint16_t length = 0;
    uint16_t number_of_pipes_expected = 0;
    uint8_t interface_number = 0;
    uint8_t alternate_setting = 0;
    uint32_t number_of_pipes = 0;
    std::vector<RdpUsbTsUsbdPipeInformation> pipes;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUsbdInterfaceInformation& out);
    std::vector<uint8_t> encode() const;
};

struct RdpUsbTsUrbSelectConfiguration {
    bool configuration_descriptor_is_valid = false;
    uint32_t num_interfaces = 0;
    std::vector<RdpUsbTsUsbdInterfaceInformation> interfaces;
    std::vector<uint8_t> configuration_descriptor;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbSelectConfiguration& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_SELECT_INTERFACE ([MS-RDPEUSB] 2.2.9.3).
struct RdpUsbTsUrbSelectInterface {
    uint32_t configuration_handle = 0;
    RdpUsbTsUsbdInterfaceInformation interface;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbSelectInterface& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_PIPE_REQUEST ([MS-RDPEUSB] 2.2.9.4). The cancel/reset operation is
// implied by the URB function code that selected this structure.
struct RdpUsbTsUrbPipeRequest {
    uint32_t pipe_handle = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbPipeRequest& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_CONTROL_TRANSFER ([MS-RDPEUSB] 2.2.9.6).
struct RdpUsbTsUrbControlTransfer {
    uint32_t pipe_handle = 0;
    uint32_t transfer_flags = 0;
    std::vector<uint8_t> setup_packet;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbControlTransfer& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_BULK_OR_INTERRUPT_TRANSFER ([MS-RDPEUSB] 2.2.9.7).
struct RdpUsbTsUrbBulkOrInterruptTransfer {
    uint32_t pipe_handle = 0;
    uint32_t transfer_flags = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbBulkOrInterruptTransfer& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_CONTROL_DESCRIPTOR_REQUEST ([MS-RDPEUSB] 2.2.9.9).
struct RdpUsbTsUrbControlDescriptorRequest {
    uint8_t index = 0;
    uint8_t descriptor_type = 0;
    uint16_t language_id = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbControlDescriptorRequest& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_CONTROL_VENDOR_OR_CLASS_REQUEST ([MS-RDPEUSB] 2.2.9.12).
struct RdpUsbTsUrbControlVendorOrClassRequest {
    uint32_t transfer_flags = 0;
    uint8_t request_type_reserved_bits = 0;
    uint8_t request = 0;
    uint16_t value = 0;
    uint16_t index = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbControlVendorOrClassRequest& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_CONTROL_FEATURE_REQUEST ([MS-RDPEUSB] 2.2.9.10).
struct RdpUsbTsUrbControlFeatureRequest {
    uint16_t feature_selector = 0;
    uint16_t index = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbControlFeatureRequest& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_CONTROL_GET_STATUS_REQUEST ([MS-RDPEUSB] 2.2.9.11).
struct RdpUsbTsUrbControlGetStatusRequest {
    uint16_t index = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbControlGetStatusRequest& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_CONTROL_GET_INTERFACE_REQUEST ([MS-RDPEUSB] 2.2.9.14).
struct RdpUsbTsUrbControlGetInterfaceRequest {
    uint16_t interface = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbControlGetInterfaceRequest& out);
    std::vector<uint8_t> encode() const;
};

// ---- transfer requests ---------------------------------------------------

// TRANSFER_IN_REQUEST ([MS-RDPEUSB] 2.2.6.7).
struct RdpUsbTransferInRequest {
    RdpUsbHeader header;
    RdpUsbTsUrb ts_urb;
    uint32_t output_buffer_size = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTransferInRequest& out);
    std::vector<uint8_t> encode() const;
};

// TRANSFER_OUT_REQUEST ([MS-RDPEUSB] 2.2.6.8).
struct RdpUsbTransferOutRequest {
    RdpUsbHeader header;
    RdpUsbTsUrb ts_urb;
    uint32_t output_buffer_size = 0;
    std::vector<uint8_t> output_buffer;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTransferOutRequest& out);
    std::vector<uint8_t> encode() const;
};

// ---- client completions --------------------------------------------------

// IOCONTROL_COMPLETION ([MS-RDPEUSB] 2.2.7.1).
struct RdpUsbIoControlCompletion {
    RdpUsbHeader header;
    uint32_t request_id = 0;
    uint32_t hresult = 0;
    uint32_t information = 0;
    std::vector<uint8_t> output_buffer;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbIoControlCompletion& out);
    std::vector<uint8_t> encode() const;
};

// URB_COMPLETION ([MS-RDPEUSB] 2.2.7.2).
struct RdpUsbUrbCompletion {
    RdpUsbHeader header;
    uint32_t request_id = 0;
    std::vector<uint8_t> ts_urb_result;
    uint32_t hresult = 0;
    std::vector<uint8_t> output_buffer;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbUrbCompletion& out);
    std::vector<uint8_t> encode() const;
};

// URB_COMPLETION_NO_DATA ([MS-RDPEUSB] 2.2.7.3).
struct RdpUsbUrbCompletionNoData {
    RdpUsbHeader header;
    uint32_t request_id = 0;
    std::vector<uint8_t> ts_urb_result;
    uint32_t hresult = 0;
    uint32_t output_buffer_size = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbUrbCompletionNoData& out);
    std::vector<uint8_t> encode() const;
};

// ---- TS_URB_RESULT ([MS-RDPEUSB] 2.2.10) ---------------------------------

// TS_URB_RESULT_HEADER ([MS-RDPEUSB] 2.2.10.1.1), 8 bytes.
struct RdpUsbTsUrbResultHeader {
    static constexpr size_t kSize = 8;

    uint16_t size = kSize;
    uint32_t usbd_status = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbResultHeader& out);
    void write(ByteWriter& w) const;
};

// TS_USBD_PIPE_INFORMATION_RESULT ([MS-RDPEUSB] 2.2.10.1.3).
struct RdpUsbTsUsbdPipeInformationResult {
    uint16_t maximum_packet_size = 0;
    uint8_t endpoint_address = 0;
    uint8_t interval = 0;
    uint32_t pipe_type = 0;
    uint32_t pipe_handle = 0;
    uint32_t maximum_transfer_size = 0;
    uint32_t pipe_flags = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUsbdPipeInformationResult& out);
    void write(ByteWriter& w) const;
};

// TS_USBD_INTERFACE_INFORMATION_RESULT ([MS-RDPEUSB] 2.2.10.1.2).
struct RdpUsbTsUsbdInterfaceInformationResult {
    uint16_t length = 0;
    uint8_t interface_number = 0;
    uint8_t alternate_setting = 0;
    uint8_t class_ = 0;
    uint8_t sub_class = 0;
    uint8_t protocol = 0;
    uint32_t interface_handle = 0;
    uint32_t number_of_pipes = 0;
    std::vector<RdpUsbTsUsbdPipeInformationResult> pipes;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUsbdInterfaceInformationResult& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_SELECT_CONFIGURATION_RESULT ([MS-RDPEUSB] 2.2.10.2).
struct RdpUsbTsUrbSelectConfigurationResult {
    uint32_t configuration_handle = 0;
    std::vector<RdpUsbTsUsbdInterfaceInformationResult> interfaces;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbSelectConfigurationResult& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_SELECT_INTERFACE_RESULT ([MS-RDPEUSB] 2.2.10.3).
struct RdpUsbTsUrbSelectInterfaceResult {
    RdpUsbTsUsbdInterfaceInformationResult interface;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbSelectInterfaceResult& out);
    std::vector<uint8_t> encode() const;
};

// TS_URB_GET_CURRENT_FRAME_NUMBER_RESULT ([MS-RDPEUSB] 2.2.10.4).
struct RdpUsbTsUrbGetCurrentFrameNumberResult {
    uint32_t frame_number = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpUsbTsUrbGetCurrentFrameNumberResult& out);
    std::vector<uint8_t> encode() const;
};

}  // namespace rtsc::proto
