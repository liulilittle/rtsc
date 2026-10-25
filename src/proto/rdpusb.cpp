// Remote Desktop Protocol: USB Devices Virtual Channel Extension (URBDRC)
// wire structures ([MS-RDPEUSB] 2.2).

#include "rtsc/proto/rdpusb.h"

#include <utility>

namespace rtsc::proto {

namespace {

uint32_t ReadU32Le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint16_t ReadU16Le(const uint8_t* p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                 (static_cast<uint16_t>(p[1]) << 8));
}

// Reads `cch` UTF-16 code units, dropping trailing null terminators.
bool ReadUtf16(ByteReader& r, uint32_t cch, std::u16string& out) {
    out.clear();
    if (cch > r.remaining() / 2) return false;
    for (uint32_t i = 0; i < cch; ++i) {
        uint16_t ch = 0;
        if (!r.u16le(ch)) return false;
        out.push_back(static_cast<char16_t>(ch));
    }
    while (!out.empty() && out.back() == u'\0') out.pop_back();
    return true;
}

// Writes `s` followed by `terminators` null code units; cch includes them.
void WriteUtf16(ByteWriter& w, const std::u16string& s, size_t terminators) {
    w.u32le(static_cast<uint32_t>(s.size() + terminators));
    for (const char16_t c : s) w.u16le(static_cast<uint16_t>(c));
    for (size_t i = 0; i < terminators; ++i) w.u16le(0);
}

}  // namespace

// ---- SHARED_MSG_HEADER ---------------------------------------------------

Status RdpUsbHeader::parse(const uint8_t* data, size_t size, RdpUsbHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    out.interface_id = ReadU32Le(data);
    out.message_id = ReadU32Le(data + 4);
    out.function_id = ReadU32Le(data + 8);
    return Status::Ok;
}

void RdpUsbHeader::write(ByteWriter& w) const {
    w.u32le(interface_id);
    w.u32le(message_id);
    w.u32le(function_id);
}

// ---- capability exchange -------------------------------------------------

std::vector<uint8_t> RdpUsbRimExchangeCapability::encode(bool is_response) const {
    ByteWriter w;
    header.write(w);
    w.u32le(capability);
    if (is_response) w.u32le(result);
    return w.take();
}

Status RdpUsbChannelCreated::parse(const uint8_t* data, size_t size,
                                   RdpUsbChannelCreated& out) {
    if (data == nullptr || size < RdpUsbHeader::kSize + 12) {
        return Status::NeedMoreData;
    }
    const Status s =
        RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    out.major_version = ReadU32Le(data + 12);
    out.minor_version = ReadU32Le(data + 16);
    out.capabilities = ReadU32Le(data + 20);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbChannelCreated::encode() const {
    ByteWriter w;
    header.write(w);
    w.u32le(major_version);
    w.u32le(minor_version);
    w.u32le(capabilities);
    return w.take();
}

// ---- device sink ---------------------------------------------------------

std::vector<uint8_t> BuildRdpUsbAddVirtualChannel() {
    ByteWriter w;
    RdpUsbHeader h;
    h.interface_id =
        RdpUsbHeader::MakeInterfaceId(RdpUsbInterface::kClientDeviceSink,
                                      RdpUsbStreamId::kProxy);
    h.function_id = static_cast<uint32_t>(RdpUsbFunction::kAddVirtualChannel);
    h.write(w);
    return w.take();
}

Status RdpUsbAddDevice::parse(const uint8_t* data, size_t size,
                              RdpUsbAddDevice& out) {
    out = RdpUsbAddDevice{};
    if (data == nullptr || size < RdpUsbHeader::kSize) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    ByteReader r(data + RdpUsbHeader::kSize, size - RdpUsbHeader::kSize);
    if (!r.u32le(out.num_usb_device) || !r.u32le(out.usb_device)) {
        return Status::NeedMoreData;
    }
    uint32_t cch = 0;
    if (!r.u32le(cch)) return Status::NeedMoreData;
    if (!ReadUtf16(r, cch, out.device_instance_id)) return Status::InvalidLength;
    if (!r.u32le(cch)) return Status::NeedMoreData;
    if (!ReadUtf16(r, cch, out.hardware_ids)) return Status::InvalidLength;
    if (!r.u32le(cch)) return Status::NeedMoreData;
    if (!ReadUtf16(r, cch, out.compatibility_ids)) {
        return Status::InvalidLength;
    }
    if (!r.u32le(cch)) return Status::NeedMoreData;
    if (!ReadUtf16(r, cch, out.container_id)) return Status::InvalidLength;
    const uint8_t* cap = r.cursor();
    const size_t cap_size = r.remaining();
    if (RdpUsbDeviceCapabilities::parse(cap, cap_size, out.capabilities) !=
        Status::Ok) {
        return Status::InvalidField;
    }
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbAddDevice::encode() const {
    ByteWriter w;
    header.write(w);
    w.u32le(num_usb_device);
    w.u32le(usb_device);
    WriteUtf16(w, device_instance_id, 1);
    WriteUtf16(w, hardware_ids, 2);
    WriteUtf16(w, compatibility_ids, 2);
    WriteUtf16(w, container_id, 1);
    capabilities.write(w);
    return w.take();
}

Status RdpUsbRetractDevice::parse(const uint8_t* data, size_t size,
                                  RdpUsbRetractDevice& out) {
    out = RdpUsbRetractDevice{};
    if (data == nullptr || size < RdpUsbHeader::kSize + 4) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    out.reason = ReadU32Le(data + RdpUsbHeader::kSize);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbRetractDevice::encode() const {
    ByteWriter w;
    header.write(w);
    w.u32le(reason);
    return w.take();
}

// ---- USB_DEVICE_CAPABILITIES --------------------------------------------

Status RdpUsbDeviceCapabilities::parse(const uint8_t* data, size_t size,
                                       RdpUsbDeviceCapabilities& out) {
    out = RdpUsbDeviceCapabilities{};
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    out.cb_size = ReadU32Le(data);
    out.usb_bus_interface_version = ReadU32Le(data + 4);
    out.usbdi_version = ReadU32Le(data + 8);
    out.supported_usb_version = ReadU32Le(data + 12);
    out.hcd_capabilities = ReadU32Le(data + 16);
    out.device_is_high_speed = ReadU32Le(data + 20);
    out.no_ack_isoch_write_jitter_buffer_size_in_ms = ReadU32Le(data + 24);
    if (out.cb_size != kSize) return Status::InvalidField;
    return Status::Ok;
}

void RdpUsbDeviceCapabilities::write(ByteWriter& w) const {
    w.u32le(cb_size);
    w.u32le(usb_bus_interface_version);
    w.u32le(usbdi_version);
    w.u32le(supported_usb_version);
    w.u32le(hcd_capabilities);
    w.u32le(device_is_high_speed);
    w.u32le(no_ack_isoch_write_jitter_buffer_size_in_ms);
}

// ---- TS_URB_HEADER -------------------------------------------------------

Status RdpUsbTsUrbHeader::parse(const uint8_t* data, size_t size,
                                RdpUsbTsUrbHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    out.size = ReadU16Le(data);
    out.urb_function =
        static_cast<RdpUsbUrbFunction>(ReadU16Le(data + 2));
    out.set_request_id_and_no_ack(ReadU32Le(data + 4));
    return Status::Ok;
}

void RdpUsbTsUrbHeader::write(ByteWriter& w) const {
    w.u16le(size);
    w.u16le(static_cast<uint16_t>(urb_function));
    w.u32le(request_id_and_no_ack());
}

Status RdpUsbTsUrb::parse(const uint8_t* data, size_t size, RdpUsbTsUrb& out) {
    out.body.clear();
    const Status s = RdpUsbTsUrbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    if (out.header.size < RdpUsbTsUrbHeader::kSize) return Status::InvalidField;
    if (size < out.header.size) return Status::NeedMoreData;
    out.body.assign(data + RdpUsbTsUrbHeader::kSize,
                    data + out.header.size);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrb::encode() const {
    ByteWriter w;
    RdpUsbTsUrbHeader h = header;
    h.size = static_cast<uint16_t>(RdpUsbTsUrbHeader::kSize + body.size());
    h.write(w);
    w.bytes(body.data(), body.size());
    return w.take();
}

Status RdpUsbTsUsbdPipeInformation::parse(const uint8_t* data, size_t size,
                                          RdpUsbTsUsbdPipeInformation& out) {
    out = RdpUsbTsUsbdPipeInformation{};
    // MaximumPacketSize(2) + Padding(2) + MaximumTransferSize(4) + PipeFlags(4).
    if (data == nullptr || size < 12) return Status::NeedMoreData;
    out.maximum_packet_size = ReadU16Le(data);
    out.maximum_transfer_size = ReadU32Le(data + 4);
    out.pipe_flags = ReadU32Le(data + 8);
    return Status::Ok;
}

void RdpUsbTsUsbdPipeInformation::write(ByteWriter& w) const {
    w.u16le(maximum_packet_size);
    w.u16le(0);  // padding
    w.u32le(maximum_transfer_size);
    w.u32le(pipe_flags);
}

Status RdpUsbTsUsbdInterfaceInformation::parse(
    const uint8_t* data, size_t size,
    RdpUsbTsUsbdInterfaceInformation& out) {
    out = RdpUsbTsUsbdInterfaceInformation{};
    if (data == nullptr || size < 12) return Status::NeedMoreData;
    out.length = ReadU16Le(data);
    out.number_of_pipes_expected = ReadU16Le(data + 2);
    out.interface_number = data[4];
    out.alternate_setting = data[5];
    out.number_of_pipes = ReadU32Le(data + 8);
    if (out.length < 12) return Status::InvalidField;
    if (size < out.length) return Status::NeedMoreData;
    const uint8_t* p = data + 12;
    size_t consumed = 12;
    for (uint32_t i = 0; i < out.number_of_pipes; ++i) {
        RdpUsbTsUsbdPipeInformation pipe;
        const Status s =
            RdpUsbTsUsbdPipeInformation::parse(p, size - consumed, pipe);
        if (s != Status::Ok) return s;
        out.pipes.push_back(pipe);
        p += 12;
        consumed += 12;
    }
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUsbdInterfaceInformation::encode() const {
    ByteWriter w;
    const uint16_t encoded_length =
        static_cast<uint16_t>(12 + pipes.size() * 12);
    w.u16le(encoded_length);
    w.u16le(static_cast<uint16_t>(pipes.size()));
    w.u8(interface_number);
    w.u8(alternate_setting);
    w.u16le(0);  // padding
    w.u32le(static_cast<uint32_t>(pipes.size()));
    for (const RdpUsbTsUsbdPipeInformation& p : pipes) p.write(w);
    return w.take();
}

Status RdpUsbTsUrbSelectConfiguration::parse(
    const uint8_t* data, size_t size,
    RdpUsbTsUrbSelectConfiguration& out) {
    out = RdpUsbTsUrbSelectConfiguration{};
    if (data == nullptr || size < 8) return Status::NeedMoreData;
    out.configuration_descriptor_is_valid = data[0] != 0;
    out.num_interfaces = ReadU32Le(data + 4);
    const uint8_t* p = data + 8;
    for (uint32_t i = 0; i < out.num_interfaces; ++i) {
        RdpUsbTsUsbdInterfaceInformation iface;
        const Status s = RdpUsbTsUsbdInterfaceInformation::parse(p, size - 8, iface);
        if (s != Status::Ok) return s;
        out.interfaces.push_back(iface);
        p += iface.length;
    }
    out.configuration_descriptor.assign(p, data + size);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrbSelectConfiguration::encode() const {
    ByteWriter w;
    w.u8(configuration_descriptor_is_valid ? 1 : 0);
    w.u8(0);
    w.u8(0);
    w.u8(0);
    w.u32le(num_interfaces);
    for (const RdpUsbTsUsbdInterfaceInformation& i : interfaces) {
        const std::vector<uint8_t> b = i.encode();
        w.bytes(b.data(), b.size());
    }
    w.bytes(configuration_descriptor.data(), configuration_descriptor.size());
    return w.take();
}

Status RdpUsbTsUrbSelectInterface::parse(const uint8_t* data, size_t size,
                                         RdpUsbTsUrbSelectInterface& out) {
    out = RdpUsbTsUrbSelectInterface{};
    if (data == nullptr || size < 4) return Status::NeedMoreData;
    out.configuration_handle = ReadU32Le(data);
    return RdpUsbTsUsbdInterfaceInformation::parse(data + 4, size - 4,
                                                   out.interface);
}

std::vector<uint8_t> RdpUsbTsUrbSelectInterface::encode() const {
    ByteWriter w;
    w.u32le(configuration_handle);
    const std::vector<uint8_t> b = interface.encode();
    w.bytes(b.data(), b.size());
    return w.take();
}

Status RdpUsbTsUrbPipeRequest::parse(const uint8_t* data, size_t size,
                                     RdpUsbTsUrbPipeRequest& out) {
    out = RdpUsbTsUrbPipeRequest{};
    if (data == nullptr || size < 4) return Status::NeedMoreData;
    out.pipe_handle = ReadU32Le(data);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrbPipeRequest::encode() const {
    ByteWriter w;
    w.u32le(pipe_handle);
    return w.take();
}

Status RdpUsbTsUrbControlTransfer::parse(
    const uint8_t* data, size_t size, RdpUsbTsUrbControlTransfer& out) {
    out = RdpUsbTsUrbControlTransfer{};
    if (data == nullptr || size < 16) return Status::NeedMoreData;
    out.pipe_handle = ReadU32Le(data);
    out.transfer_flags = ReadU32Le(data + 4);
    out.setup_packet.assign(data + 8, data + 16);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrbControlTransfer::encode() const {
    ByteWriter w;
    w.u32le(pipe_handle);
    w.u32le(transfer_flags);
    w.bytes(setup_packet.data(), setup_packet.size());
    return w.take();
}

Status RdpUsbTsUrbBulkOrInterruptTransfer::parse(
    const uint8_t* data, size_t size,
    RdpUsbTsUrbBulkOrInterruptTransfer& out) {
    out = RdpUsbTsUrbBulkOrInterruptTransfer{};
    if (data == nullptr || size < 8) return Status::NeedMoreData;
    out.pipe_handle = ReadU32Le(data);
    out.transfer_flags = ReadU32Le(data + 4);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrbBulkOrInterruptTransfer::encode() const {
    ByteWriter w;
    w.u32le(pipe_handle);
    w.u32le(transfer_flags);
    return w.take();
}

Status RdpUsbTsUrbControlDescriptorRequest::parse(
    const uint8_t* data, size_t size,
    RdpUsbTsUrbControlDescriptorRequest& out) {
    out = RdpUsbTsUrbControlDescriptorRequest{};
    if (data == nullptr || size < 4) return Status::NeedMoreData;
    out.index = data[0];
    out.descriptor_type = data[1];
    out.language_id = ReadU16Le(data + 2);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrbControlDescriptorRequest::encode() const {
    ByteWriter w;
    w.u8(index);
    w.u8(descriptor_type);
    w.u16le(language_id);
    return w.take();
}

Status RdpUsbTsUrbControlFeatureRequest::parse(
    const uint8_t* data, size_t size, RdpUsbTsUrbControlFeatureRequest& out) {
    out = RdpUsbTsUrbControlFeatureRequest{};
    if (data == nullptr || size < 4) return Status::NeedMoreData;
    out.feature_selector = ReadU16Le(data);
    out.index = ReadU16Le(data + 2);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrbControlFeatureRequest::encode() const {
    ByteWriter w;
    w.u16le(feature_selector);
    w.u16le(index);
    return w.take();
}

Status RdpUsbTsUrbControlGetStatusRequest::parse(
    const uint8_t* data, size_t size,
    RdpUsbTsUrbControlGetStatusRequest& out) {
    out = RdpUsbTsUrbControlGetStatusRequest{};
    if (data == nullptr || size < 4) return Status::NeedMoreData;
    out.index = ReadU16Le(data);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrbControlGetStatusRequest::encode() const {
    ByteWriter w;
    w.u16le(index);
    w.u16le(0);  // padding
    return w.take();
}

Status RdpUsbTsUrbControlVendorOrClassRequest::parse(
    const uint8_t* data, size_t size,
    RdpUsbTsUrbControlVendorOrClassRequest& out) {
    out = RdpUsbTsUrbControlVendorOrClassRequest{};
    if (data == nullptr || size < 12) return Status::NeedMoreData;
    out.transfer_flags = ReadU32Le(data);
    out.request_type_reserved_bits = data[4];
    out.request = data[5];
    out.value = ReadU16Le(data + 6);
    out.index = ReadU16Le(data + 8);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrbControlVendorOrClassRequest::encode() const {
    ByteWriter w;
    w.u32le(transfer_flags);
    w.u8(request_type_reserved_bits);
    w.u8(request);
    w.u16le(value);
    w.u16le(index);
    w.u16le(0);  // padding
    return w.take();
}

Status RdpUsbTsUrbControlGetInterfaceRequest::parse(
    const uint8_t* data, size_t size,
    RdpUsbTsUrbControlGetInterfaceRequest& out) {
    out = RdpUsbTsUrbControlGetInterfaceRequest{};
    if (data == nullptr || size < 4) return Status::NeedMoreData;
    out.interface = ReadU16Le(data);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrbControlGetInterfaceRequest::encode() const {
    ByteWriter w;
    w.u16le(interface);
    w.u16le(0);  // padding
    return w.take();
}

// ---- server -> client requests -------------------------------------------

Status RdpUsbRegisterRequestCallback::parse(
    const uint8_t* data, size_t size, RdpUsbRegisterRequestCallback& out) {
    out = RdpUsbRegisterRequestCallback{};
    if (data == nullptr || size < RdpUsbHeader::kSize + 4) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    ByteReader r(data + RdpUsbHeader::kSize, size - RdpUsbHeader::kSize);
    if (!r.u32le(out.num_request_completion)) return Status::NeedMoreData;
    if (out.num_request_completion >= 1) {
        if (!r.u32le(out.request_completion)) return Status::NeedMoreData;
        out.has_request_completion = true;
    }
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbRegisterRequestCallback::encode() const {
    ByteWriter w;
    header.write(w);
    w.u32le(num_request_completion);
    if (num_request_completion >= 1) w.u32le(request_completion);
    return w.take();
}

Status RdpUsbCancelRequest::parse(const uint8_t* data, size_t size,
                                  RdpUsbCancelRequest& out) {
    out = RdpUsbCancelRequest{};
    if (data == nullptr || size < RdpUsbHeader::kSize + 4) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    out.request_id = ReadU32Le(data + RdpUsbHeader::kSize);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbCancelRequest::encode() const {
    ByteWriter w;
    header.write(w);
    w.u32le(request_id);
    return w.take();
}

Status RdpUsbIoControl::parse(const uint8_t* data, size_t size,
                              RdpUsbIoControl& out) {
    out = RdpUsbIoControl{};
    if (data == nullptr || size < RdpUsbHeader::kSize + 16) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    ByteReader r(data + RdpUsbHeader::kSize, size - RdpUsbHeader::kSize);
    if (!r.u32le(out.io_control_code)) return Status::NeedMoreData;
    uint32_t input_size = 0;
    if (!r.u32le(input_size)) return Status::NeedMoreData;
    if (r.remaining() < input_size) return Status::NeedMoreData;
    out.input_buffer.assign(r.cursor(), r.cursor() + input_size);
    r.skip(input_size);
    if (!r.u32le(out.output_buffer_size) || !r.u32le(out.request_id)) {
        return Status::NeedMoreData;
    }
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbIoControl::encode() const {
    ByteWriter w;
    header.write(w);
    w.u32le(io_control_code);
    w.u32le(static_cast<uint32_t>(input_buffer.size()));
    w.bytes(input_buffer.data(), input_buffer.size());
    w.u32le(output_buffer_size);
    w.u32le(request_id);
    return w.take();
}

Status RdpUsbQueryDeviceText::parse(const uint8_t* data, size_t size,
                                    RdpUsbQueryDeviceText& out) {
    out = RdpUsbQueryDeviceText{};
    if (data == nullptr || size < RdpUsbHeader::kSize + 8) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    out.text_type = ReadU32Le(data + RdpUsbHeader::kSize);
    out.locale_id = ReadU32Le(data + RdpUsbHeader::kSize + 4);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbQueryDeviceText::encode() const {
    ByteWriter w;
    header.write(w);
    w.u32le(text_type);
    w.u32le(locale_id);
    return w.take();
}

Status RdpUsbQueryDeviceTextResponse::parse(
    const uint8_t* data, size_t size, RdpUsbQueryDeviceTextResponse& out) {
    out = RdpUsbQueryDeviceTextResponse{};
    if (data == nullptr || size < RdpUsbHeader::kSize + 8) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    ByteReader r(data + RdpUsbHeader::kSize, size - RdpUsbHeader::kSize);
    uint32_t cch = 0;
    if (!r.u32le(cch)) return Status::NeedMoreData;
    if (!ReadUtf16(r, cch, out.device_description)) {
        return Status::InvalidLength;
    }
    if (!r.u32le(out.hresult)) return Status::NeedMoreData;
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbQueryDeviceTextResponse::encode() const {
    ByteWriter w;
    header.write(w);
    WriteUtf16(w, device_description, 1);
    w.u32le(hresult);
    return w.take();
}

// ---- transfer requests ---------------------------------------------------

Status RdpUsbTransferInRequest::parse(const uint8_t* data, size_t size,
                                      RdpUsbTransferInRequest& out) {
    out = RdpUsbTransferInRequest{};
    if (data == nullptr || size < RdpUsbHeader::kSize + 8) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    ByteReader r(data + RdpUsbHeader::kSize, size - RdpUsbHeader::kSize);
    uint32_t cb = 0;
    if (!r.u32le(cb)) return Status::NeedMoreData;
    if (r.remaining() < cb + 4) return Status::NeedMoreData;
    if (RdpUsbTsUrb::parse(r.cursor(), cb, out.ts_urb) != Status::Ok) {
        return Status::InvalidField;
    }
    r.skip(cb);
    if (!r.u32le(out.output_buffer_size)) return Status::NeedMoreData;
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTransferInRequest::encode() const {
    ByteWriter w;
    header.write(w);
    const std::vector<uint8_t> urb = ts_urb.encode();
    w.u32le(static_cast<uint32_t>(urb.size()));
    w.bytes(urb.data(), urb.size());
    w.u32le(output_buffer_size);
    return w.take();
}

Status RdpUsbTransferOutRequest::parse(const uint8_t* data, size_t size,
                                       RdpUsbTransferOutRequest& out) {
    out = RdpUsbTransferOutRequest{};
    if (data == nullptr || size < RdpUsbHeader::kSize + 8) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    ByteReader r(data + RdpUsbHeader::kSize, size - RdpUsbHeader::kSize);
    uint32_t cb = 0;
    if (!r.u32le(cb)) return Status::NeedMoreData;
    if (r.remaining() < cb + 4) return Status::NeedMoreData;
    if (RdpUsbTsUrb::parse(r.cursor(), cb, out.ts_urb) != Status::Ok) {
        return Status::InvalidField;
    }
    r.skip(cb);
    if (!r.u32le(out.output_buffer_size)) return Status::NeedMoreData;
    if (r.remaining() < out.output_buffer_size) return Status::NeedMoreData;
    out.output_buffer.assign(r.cursor(),
                             r.cursor() + out.output_buffer_size);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTransferOutRequest::encode() const {
    ByteWriter w;
    header.write(w);
    const std::vector<uint8_t> urb = ts_urb.encode();
    w.u32le(static_cast<uint32_t>(urb.size()));
    w.bytes(urb.data(), urb.size());
    w.u32le(output_buffer_size);
    w.bytes(output_buffer.data(), output_buffer.size());
    return w.take();
}

// ---- client completions --------------------------------------------------

Status RdpUsbIoControlCompletion::parse(const uint8_t* data, size_t size,
                                        RdpUsbIoControlCompletion& out) {
    out = RdpUsbIoControlCompletion{};
    if (data == nullptr || size < RdpUsbHeader::kSize + 16) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    ByteReader r(data + RdpUsbHeader::kSize, size - RdpUsbHeader::kSize);
    uint32_t out_size = 0;
    if (!r.u32le(out.request_id) || !r.u32le(out.hresult) ||
        !r.u32le(out.information) || !r.u32le(out_size)) {
        return Status::NeedMoreData;
    }
    if (r.remaining() < out_size) return Status::NeedMoreData;
    out.output_buffer.assign(r.cursor(), r.cursor() + out_size);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbIoControlCompletion::encode() const {
    ByteWriter w;
    header.write(w);
    w.u32le(request_id);
    w.u32le(hresult);
    w.u32le(information);
    w.u32le(static_cast<uint32_t>(output_buffer.size()));
    w.bytes(output_buffer.data(), output_buffer.size());
    return w.take();
}

Status RdpUsbUrbCompletion::parse(const uint8_t* data, size_t size,
                                  RdpUsbUrbCompletion& out) {
    out = RdpUsbUrbCompletion{};
    if (data == nullptr || size < RdpUsbHeader::kSize + 16) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    ByteReader r(data + RdpUsbHeader::kSize, size - RdpUsbHeader::kSize);
    uint32_t cb = 0;
    uint32_t out_size = 0;
    if (!r.u32le(out.request_id) || !r.u32le(cb)) {
        return Status::NeedMoreData;
    }
    if (r.remaining() < cb) return Status::NeedMoreData;
    out.ts_urb_result.assign(r.cursor(), r.cursor() + cb);
    r.skip(cb);
    if (!r.u32le(out.hresult) || !r.u32le(out_size)) {
        return Status::NeedMoreData;
    }
    if (r.remaining() < out_size) return Status::NeedMoreData;
    out.output_buffer.assign(r.cursor(), r.cursor() + out_size);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbUrbCompletion::encode() const {
    ByteWriter w;
    header.write(w);
    w.u32le(request_id);
    w.u32le(static_cast<uint32_t>(ts_urb_result.size()));
    w.bytes(ts_urb_result.data(), ts_urb_result.size());
    w.u32le(hresult);
    w.u32le(static_cast<uint32_t>(output_buffer.size()));
    w.bytes(output_buffer.data(), output_buffer.size());
    return w.take();
}

Status RdpUsbUrbCompletionNoData::parse(const uint8_t* data, size_t size,
                                        RdpUsbUrbCompletionNoData& out) {
    out = RdpUsbUrbCompletionNoData{};
    if (data == nullptr || size < RdpUsbHeader::kSize + 16) {
        return Status::NeedMoreData;
    }
    const Status s = RdpUsbHeader::parse(data, size, out.header);
    if (s != Status::Ok) return s;
    ByteReader r(data + RdpUsbHeader::kSize, size - RdpUsbHeader::kSize);
    uint32_t cb = 0;
    if (!r.u32le(out.request_id) || !r.u32le(cb)) {
        return Status::NeedMoreData;
    }
    if (r.remaining() < cb) return Status::NeedMoreData;
    out.ts_urb_result.assign(r.cursor(), r.cursor() + cb);
    r.skip(cb);
    if (!r.u32le(out.hresult) || !r.u32le(out.output_buffer_size)) {
        return Status::NeedMoreData;
    }
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbUrbCompletionNoData::encode() const {
    ByteWriter w;
    header.write(w);
    w.u32le(request_id);
    w.u32le(static_cast<uint32_t>(ts_urb_result.size()));
    w.bytes(ts_urb_result.data(), ts_urb_result.size());
    w.u32le(hresult);
    w.u32le(output_buffer_size);
    return w.take();
}

// ---- TS_URB_RESULT -------------------------------------------------------

Status RdpUsbTsUrbResultHeader::parse(const uint8_t* data, size_t size,
                                      RdpUsbTsUrbResultHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    out.size = ReadU16Le(data);
    out.usbd_status = ReadU32Le(data + 4);
    return Status::Ok;
}

void RdpUsbTsUrbResultHeader::write(ByteWriter& w) const {
    w.u16le(size);
    w.u16le(0);  // padding
    w.u32le(usbd_status);
}

Status RdpUsbTsUsbdPipeInformationResult::parse(
    const uint8_t* data, size_t size,
    RdpUsbTsUsbdPipeInformationResult& out) {
    out = RdpUsbTsUsbdPipeInformationResult{};
    if (data == nullptr || size < 20) return Status::NeedMoreData;
    out.maximum_packet_size = ReadU16Le(data);
    out.endpoint_address = data[2];
    out.interval = data[3];
    out.pipe_type = ReadU32Le(data + 4);
    out.pipe_handle = ReadU32Le(data + 8);
    out.maximum_transfer_size = ReadU32Le(data + 12);
    out.pipe_flags = ReadU32Le(data + 16);
    return Status::Ok;
}

void RdpUsbTsUsbdPipeInformationResult::write(ByteWriter& w) const {
    w.u16le(maximum_packet_size);
    w.u8(endpoint_address);
    w.u8(interval);
    w.u32le(pipe_type);
    w.u32le(pipe_handle);
    w.u32le(maximum_transfer_size);
    w.u32le(pipe_flags);
}

Status RdpUsbTsUsbdInterfaceInformationResult::parse(
    const uint8_t* data, size_t size,
    RdpUsbTsUsbdInterfaceInformationResult& out) {
    out = RdpUsbTsUsbdInterfaceInformationResult{};
    if (data == nullptr || size < 16) return Status::NeedMoreData;
    out.length = ReadU16Le(data);
    out.interface_number = data[2];
    out.alternate_setting = data[3];
    out.class_ = data[4];
    out.sub_class = data[5];
    out.protocol = data[6];
    out.interface_handle = ReadU32Le(data + 8);
    out.number_of_pipes = ReadU32Le(data + 12);
    if (out.length < 16) return Status::InvalidField;
    if (size < out.length) return Status::NeedMoreData;
    const uint8_t* p = data + 16;
    size_t consumed = 16;
    for (uint32_t i = 0; i < out.number_of_pipes; ++i) {
        RdpUsbTsUsbdPipeInformationResult pipe;
        const Status s =
            RdpUsbTsUsbdPipeInformationResult::parse(p, size - consumed, pipe);
        if (s != Status::Ok) return s;
        out.pipes.push_back(pipe);
        p += 20;
        consumed += 20;
    }
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUsbdInterfaceInformationResult::encode() const {
    ByteWriter w;
    const uint16_t encoded_length = static_cast<uint16_t>(16 + pipes.size() * 20);
    w.u16le(encoded_length);
    w.u8(interface_number);
    w.u8(alternate_setting);
    w.u8(class_);
    w.u8(sub_class);
    w.u8(protocol);
    w.u8(0);  // padding
    w.u32le(interface_handle);
    w.u32le(static_cast<uint32_t>(pipes.size()));
    for (const RdpUsbTsUsbdPipeInformationResult& p : pipes) p.write(w);
    return w.take();
}

Status RdpUsbTsUrbSelectConfigurationResult::parse(
    const uint8_t* data, size_t size,
    RdpUsbTsUrbSelectConfigurationResult& out) {
    out = RdpUsbTsUrbSelectConfigurationResult{};
    if (data == nullptr || size < 8) return Status::NeedMoreData;
    out.configuration_handle = ReadU32Le(data);
    const uint32_t num = ReadU32Le(data + 4);
    const uint8_t* p = data + 8;
    for (uint32_t i = 0; i < num; ++i) {
        RdpUsbTsUsbdInterfaceInformationResult iface;
        const Status s = RdpUsbTsUsbdInterfaceInformationResult::parse(
            p, size - 8, iface);
        if (s != Status::Ok) return s;
        out.interfaces.push_back(iface);
        p += iface.length;
    }
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrbSelectConfigurationResult::encode() const {
    ByteWriter w;
    w.u32le(configuration_handle);
    w.u32le(static_cast<uint32_t>(interfaces.size()));
    for (const RdpUsbTsUsbdInterfaceInformationResult& i : interfaces) {
        const std::vector<uint8_t> b = i.encode();
        w.bytes(b.data(), b.size());
    }
    return w.take();
}

Status RdpUsbTsUrbSelectInterfaceResult::parse(
    const uint8_t* data, size_t size, RdpUsbTsUrbSelectInterfaceResult& out) {
    out = RdpUsbTsUrbSelectInterfaceResult{};
    return RdpUsbTsUsbdInterfaceInformationResult::parse(data, size,
                                                         out.interface);
}

std::vector<uint8_t> RdpUsbTsUrbSelectInterfaceResult::encode() const {
    return interface.encode();
}

Status RdpUsbTsUrbGetCurrentFrameNumberResult::parse(
    const uint8_t* data, size_t size,
    RdpUsbTsUrbGetCurrentFrameNumberResult& out) {
    out = RdpUsbTsUrbGetCurrentFrameNumberResult{};
    if (data == nullptr || size < 4) return Status::NeedMoreData;
    out.frame_number = ReadU32Le(data);
    return Status::Ok;
}

std::vector<uint8_t> RdpUsbTsUrbGetCurrentFrameNumberResult::encode() const {
    ByteWriter w;
    w.u32le(frame_number);
    return w.take();
}

}  // namespace rtsc::proto
