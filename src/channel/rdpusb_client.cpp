// URBDRC (RemoteFX USB redirection) client channel handler ([MS-RDPEUSB]).

#include "rtsc/channel/rdpusb_client.h"

#include <algorithm>
#include <utility>

namespace rtsc::channel {

namespace {

std::u16string Utf8ToUtf16(const std::string& in) {
    std::u16string out;
    size_t i = 0;
    while (i < in.size()) {
        const uint32_t c = static_cast<uint8_t>(in[i]);
        uint32_t cp = c;
        size_t extra = 0;
        if (c < 0x80) {
            cp = c;
        } else if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1F;
            extra = 1;
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0F;
            extra = 2;
        } else {
            cp = c & 0x07;
            extra = 3;
        }
        ++i;
        for (size_t k = 0; k < extra && i < in.size(); ++k, ++i) {
            cp = (cp << 6) | (static_cast<uint8_t>(in[i]) & 0x3F);
        }
        out.push_back(static_cast<char16_t>(cp));
    }
    return out;
}

[[maybe_unused]] std::string Utf16ToUtf8(const std::u16string& in) {
    std::string out;
    for (const char16_t ch : in) {
        const uint32_t cp = static_cast<uint32_t>(ch);
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

std::string Join(const std::vector<std::string>& parts, char sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) out.push_back(sep);
        out += parts[i];
    }
    return out;
}

std::vector<uint8_t> BuildResultHeader(uint16_t size, uint32_t usbd_status) {
    rtsc::proto::ByteWriter w;
    w.u16le(size);
    w.u16le(0);  // padding
    w.u32le(usbd_status);
    return w.take();
}

}  // namespace

RdpUsbClient::RdpUsbClient(usb::UsbDeviceEnumerator* enumerator,
                           DrdynvcClient* transport,
                           ITvcProvider* provider)
    : enumerator_(enumerator), transport_(transport), provider_(provider) {
    if (transport_ != nullptr) transport_->AddListener(this);
}

RdpUsbClient::~RdpUsbClient() {
    if (transport_ != nullptr) transport_->RemoveListener(this);
}

void RdpUsbClient::Start() {
    if (started_ || transport_ == nullptr) return;
    started_ = true;
    state_ = State::kCapabilityExchange;
    control_channel_ = transport_->CreateChannel(rtsc::proto::kRdpUsbChannelName);
}

void RdpUsbClient::OnCapsResponse(uint16_t version) {
    version_ = version;
}

void RdpUsbClient::OnChannelCreated(uint32_t channel_id) {
    if (channel_id == control_channel_) {
        if (state_ == State::kCapabilityExchange) {
            rtsc::proto::RdpUsbChannelCreated cc;
            cc.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
                rtsc::proto::RdpUsbInterface::kClientChannelNotification,
                rtsc::proto::RdpUsbStreamId::kProxy);
            cc.header.function_id =
                static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kChannelCreated);
            SendControl(cc.encode());
            state_ = State::kReady;
        }
        return;
    }
    const auto it = channel_to_device_.find(channel_id);
    if (it == channel_to_device_.end()) return;
    Device& d = devices_[it->second];
    d.channel_open = true;

    rtsc::proto::RdpUsbAddDevice add;
    add.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    add.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kAddDevice);
    add.usb_device = d.usb_device;
    if (d.device != nullptr) {
        const usb::UsbDeviceInfo& info = d.device->info();
        add.device_instance_id = Utf8ToUtf16(info.instance_id);
        add.hardware_ids = Utf8ToUtf16(Join(info.hardware_ids, '\0'));
        add.compatibility_ids = Utf8ToUtf16(Join(info.compatibility_ids, '\0'));
        add.container_id = Utf8ToUtf16(info.container_id);
        add.capabilities.supported_usb_version = info.supported_usb_version;
        add.capabilities.device_is_high_speed = info.high_speed ? 1 : 0;
    }
    SendOnChannel(channel_id, add.encode());
    ++add_device_count_;
}

void RdpUsbClient::OnChannelData(uint32_t channel_id,
                                 const std::vector<uint8_t>& data) {
    if (channel_id == control_channel_) {
        OnControlMessage(data);
        return;
    }
    OnDeviceMessage(channel_id, data);
}

void RdpUsbClient::OnChannelClosed(uint32_t channel_id) {
    const auto it = channel_to_device_.find(channel_id);
    if (it != channel_to_device_.end()) {
        devices_.erase(it->second);
        channel_to_device_.erase(it);
    }
}

void RdpUsbClient::OnControlMessage(const std::vector<uint8_t>& msg) {
    rtsc::proto::RdpUsbHeader header;
    if (rtsc::proto::RdpUsbHeader::parse(msg.data(), msg.size(), header) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    const uint32_t iface = header.interface_only();
    if (iface == static_cast<uint32_t>(
                    rtsc::proto::RdpUsbInterface::kCapabilitiesNegotiator) &&
        header.function_id ==
            static_cast<uint32_t>(
                rtsc::proto::RdpUsbFunction::kRimExchangeCapabilityRequest)) {
        rtsc::proto::RdpUsbRimExchangeCapability rsp;
        rsp.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
            rtsc::proto::RdpUsbInterface::kCapabilitiesNegotiator,
            rtsc::proto::RdpUsbStreamId::kNone);
        rsp.header.message_id = header.message_id;
        rsp.capability = rtsc::proto::kRdpUsbRimCapabilityVersion01;
        rsp.result = 0;
        SendControl(rsp.encode(true));
        return;
    }
    if (iface == static_cast<uint32_t>(
                    rtsc::proto::RdpUsbInterface::kServerChannelNotification) &&
        header.function_id ==
            static_cast<uint32_t>(
                rtsc::proto::RdpUsbFunction::kChannelCreated)) {
        rtsc::proto::RdpUsbChannelCreated cc;
        if (rtsc::proto::RdpUsbChannelCreated::parse(msg.data(), msg.size(),
                                                     cc) ==
            rtsc::proto::Status::Ok) {
            ++channel_created_count_;
        }
    }
}

void RdpUsbClient::OnDeviceMessage(uint32_t channel_id,
                                   const std::vector<uint8_t>& msg) {
    (void)channel_id;
    rtsc::proto::RdpUsbHeader header;
    if (rtsc::proto::RdpUsbHeader::parse(msg.data(), msg.size(), header) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    const uint32_t usb_device = header.interface_only();
    switch (header.function_id) {
        case static_cast<uint32_t>(
            rtsc::proto::RdpUsbFunction::kRegisterRequestCallback): {
            rtsc::proto::RdpUsbRegisterRequestCallback c;
            if (rtsc::proto::RdpUsbRegisterRequestCallback::parse(
                    msg.data(), msg.size(), c) == rtsc::proto::Status::Ok &&
                c.has_request_completion) {
                request_completion_ = c.request_completion;
                request_completion_valid_ = true;
            }
            break;
        }
        case static_cast<uint32_t>(
            rtsc::proto::RdpUsbFunction::kTransferInRequest): {
            rtsc::proto::RdpUsbTransferInRequest req;
            if (rtsc::proto::RdpUsbTransferInRequest::parse(
                    msg.data(), msg.size(), req) == rtsc::proto::Status::Ok) {
                ++transfer_in_count_;
                HandleTransferIn(usb_device, req);
            }
            break;
        }
        case static_cast<uint32_t>(
            rtsc::proto::RdpUsbFunction::kTransferOutRequest): {
            rtsc::proto::RdpUsbTransferOutRequest req;
            if (rtsc::proto::RdpUsbTransferOutRequest::parse(
                    msg.data(), msg.size(), req) == rtsc::proto::Status::Ok) {
                ++transfer_out_count_;
                HandleTransferOut(usb_device, req);
            }
            break;
        }
        case static_cast<uint32_t>(
            rtsc::proto::RdpUsbFunction::kCancelRequest): {
            rtsc::proto::RdpUsbCancelRequest c;
            if (rtsc::proto::RdpUsbCancelRequest::parse(msg.data(), msg.size(),
                                                        c) ==
                    rtsc::proto::Status::Ok &&
                FindDevice(usb_device) != nullptr) {
                FindDevice(usb_device)->device->CancelRequest(c.request_id);
            }
            break;
        }
        case static_cast<uint32_t>(
            rtsc::proto::RdpUsbFunction::kRetractDevice): {
            ++retract_device_count_;
            RemoveDevice(usb_device);
            break;
        }
        default:
            break;
    }
}

void RdpUsbClient::SendControl(const std::vector<uint8_t>& msg) {
    if (control_channel_ == 0 || transport_ == nullptr) return;
    transport_->SendChannelData(control_channel_, msg);
}

void RdpUsbClient::SendOnChannel(uint32_t channel_id,
                                 const std::vector<uint8_t>& msg) {
    if (transport_ == nullptr) return;
    transport_->SendChannelData(channel_id, msg);
}

bool RdpUsbClient::AddDevice(const usb::UsbDeviceInfo& info) {
    if (!ready() || transport_ == nullptr) return false;
    SendControl(rtsc::proto::BuildRdpUsbAddVirtualChannel());
    ++add_virtual_channel_count_;

    const uint32_t usb_device = next_usb_device_++;
    const uint32_t channel_id =
        transport_->CreateChannel(rtsc::proto::kRdpUsbChannelName);

    Device d;
    d.usb_device = usb_device;
    d.channel_id = channel_id;
    d.instance_id = info.instance_id;
    if (enumerator_ != nullptr) d.device = enumerator_->Open(info.instance_id);
    devices_[usb_device] = std::move(d);
    channel_to_device_[channel_id] = usb_device;
    last_device_channel_ = channel_id;
    if (provider_ != nullptr) provider_->OnDeviceAdded(usb_device, info);
    return true;
}

void RdpUsbClient::RemoveDevice(uint32_t usb_device) {
    const auto it = devices_.find(usb_device);
    if (it == devices_.end()) return;
    if (transport_ != nullptr && it->second.channel_id != 0) {
        transport_->CloseChannel(it->second.channel_id);
    }
    channel_to_device_.erase(it->second.channel_id);
    devices_.erase(it);
    if (provider_ != nullptr) provider_->OnDeviceRemoved(usb_device);
}

RdpUsbClient::Device* RdpUsbClient::FindDevice(uint32_t usb_device) {
    const auto it = devices_.find(usb_device);
    return it == devices_.end() ? nullptr : &it->second;
}

uint32_t RdpUsbClient::MakeHeaderInterfaceId(uint32_t interface) const {
    return rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        static_cast<rtsc::proto::RdpUsbInterface>(
            interface & rtsc::proto::kRdpUsbInterfaceIdMask),
        rtsc::proto::RdpUsbStreamId::kProxy);
}

void RdpUsbClient::HandleTransferIn(
    uint32_t usb_device, const rtsc::proto::RdpUsbTransferInRequest& req) {
    Device* d = FindDevice(usb_device);
    std::vector<uint8_t> result;
    std::vector<uint8_t> output;
    uint32_t usbd_status = static_cast<uint32_t>(
        rtsc::proto::RdpUsbUsbdStatus::kInvalidPipeHandle);
    if (d != nullptr && d->device != nullptr) {
        usb::UrbResult urb{};
        ExecuteUrb(*d, req.ts_urb, req.output_buffer_size, urb, result);
        usbd_status = urb.usbd_status;
        output = urb.output_buffer;
    }
    CompleteUrb(usb_device, req.ts_urb.header.request_id,
                static_cast<uint16_t>(req.ts_urb.header.urb_function),
                usbd_status, result, output);
}

void RdpUsbClient::HandleTransferOut(
    uint32_t usb_device, const rtsc::proto::RdpUsbTransferOutRequest& req) {
    Device* d = FindDevice(usb_device);
    std::vector<uint8_t> result;
    std::vector<uint8_t> output;
    uint32_t usbd_status = static_cast<uint32_t>(
        rtsc::proto::RdpUsbUsbdStatus::kInvalidPipeHandle);
    if (d != nullptr && d->device != nullptr) {
        usb::UrbResult urb{};
        ExecuteUrb(*d, req.ts_urb, req.output_buffer_size, urb, result);
        usbd_status = urb.usbd_status;
        output = urb.output_buffer;
    }
    CompleteUrb(usb_device, req.ts_urb.header.request_id,
                static_cast<uint16_t>(req.ts_urb.header.urb_function),
                usbd_status, result, output);
}

void RdpUsbClient::ExecuteUrb(Device& d, const rtsc::proto::RdpUsbTsUrb& urb,
                              uint32_t output_buffer_size,
                              usb::UrbResult& result,
                              std::vector<uint8_t>& result_body) {
    using rtsc::proto::RdpUsbUrbFunction;
    (void)output_buffer_size;
    const auto fn = urb.header.urb_function;
    const std::vector<uint8_t>& body = urb.body;
    result.usbd_status = static_cast<uint32_t>(
        rtsc::proto::RdpUsbUsbdStatus::kInvalidUrbFunction);

    if (fn == RdpUsbUrbFunction::kSelectConfiguration) {
        rtsc::proto::RdpUsbTsUrbSelectConfiguration sel;
        if (rtsc::proto::RdpUsbTsUrbSelectConfiguration::parse(
                body.data(), body.size(), sel) != rtsc::proto::Status::Ok) {
            result_body = BuildResultHeader(8, result.usbd_status);
            return;
        }
        std::vector<usb::UsbInterfaceInfo> ifaces;
        for (const auto& i : sel.interfaces) {
            usb::UsbInterfaceInfo u{};
            u.number = i.interface_number;
            u.alternate_setting = i.alternate_setting;
            if (d.device != nullptr) {
                const usb::UsbDeviceInfo& info = d.device->info();
                u.device_class = info.device_class;
            }
            for (const auto& p : i.pipes) {
                usb::UsbEndpointInfo ep{};
                ep.max_packet_size = p.maximum_packet_size;
                u.endpoints.push_back(ep);
            }
            ifaces.push_back(u);
        }
        if (d.device == nullptr ||
            !d.device->SelectConfiguration(ifaces, d.configuration_handle)) {
            result.usbd_status = static_cast<uint32_t>(
                rtsc::proto::RdpUsbUsbdStatus::kInvalidParameter);
            result_body = BuildResultHeader(8, result.usbd_status);
            return;
        }
        rtsc::proto::RdpUsbTsUrbSelectConfigurationResult r;
        r.configuration_handle = d.configuration_handle;
        for (const auto& i : ifaces) {
            rtsc::proto::RdpUsbTsUsbdInterfaceInformationResult ir;
            ir.interface_number = i.number;
            ir.alternate_setting = i.alternate_setting;
            ir.class_ = i.device_class;
            ir.interface_handle = 0x100 + i.number;
            for (const auto& e : i.endpoints) {
                rtsc::proto::RdpUsbTsUsbdPipeInformationResult pr;
                pr.maximum_packet_size = e.max_packet_size;
                pr.endpoint_address = e.address;
                pr.interval = e.interval;
                pr.pipe_handle = 0x200 + e.address;
                ir.pipes.push_back(pr);
            }
            r.interfaces.push_back(ir);
        }
        result_body = BuildResultHeader(
            static_cast<uint16_t>(8 + r.encode().size()), 0);
        const std::vector<uint8_t> rb = r.encode();
        result_body.insert(result_body.end(), rb.begin(), rb.end());
        result.usbd_status = 0;
        return;
    }

    if (fn == RdpUsbUrbFunction::kSelectInterface) {
        rtsc::proto::RdpUsbTsUrbSelectInterface sel;
        if (rtsc::proto::RdpUsbTsUrbSelectInterface::parse(
                body.data(), body.size(), sel) != rtsc::proto::Status::Ok) {
            result_body = BuildResultHeader(8, result.usbd_status);
            return;
        }
        usb::UsbInterfaceInfo u{};
        u.number = sel.interface.interface_number;
        u.alternate_setting = sel.interface.alternate_setting;
        uint32_t handle = 0;
        if (d.device == nullptr ||
            !d.device->SelectInterface(d.configuration_handle, u, handle)) {
            result.usbd_status = static_cast<uint32_t>(
                rtsc::proto::RdpUsbUsbdStatus::kInvalidParameter);
            result_body = BuildResultHeader(8, result.usbd_status);
            return;
        }
        rtsc::proto::RdpUsbTsUrbSelectInterfaceResult r;
        r.interface.interface_number = u.number;
        r.interface.alternate_setting = u.alternate_setting;
        r.interface.interface_handle = handle;
        result_body = BuildResultHeader(
            static_cast<uint16_t>(8 + r.encode().size()), 0);
        const std::vector<uint8_t> rb = r.encode();
        result_body.insert(result_body.end(), rb.begin(), rb.end());
        result.usbd_status = 0;
        return;
    }

    if (fn == RdpUsbUrbFunction::kPipeRequest) {
        rtsc::proto::RdpUsbTsUrbPipeRequest p;
        if (rtsc::proto::RdpUsbTsUrbPipeRequest::parse(body.data(), body.size(),
                                                       p) !=
            rtsc::proto::Status::Ok) {
            result_body = BuildResultHeader(8, result.usbd_status);
            return;
        }
        const bool ok = d.device != nullptr && d.device->ResetPipe(p.pipe_handle);
        result.usbd_status = ok ? 0 : static_cast<uint32_t>(
                                         rtsc::proto::RdpUsbUsbdStatus::kRequestFailed);
        result_body = BuildResultHeader(8, result.usbd_status);
        return;
    }

    if (fn == RdpUsbUrbFunction::kGetCurrentFrameNumber) {
        rtsc::proto::RdpUsbTsUrbGetCurrentFrameNumberResult r;
        r.frame_number = 0;
        result_body = BuildResultHeader(
            static_cast<uint16_t>(8 + r.encode().size()), 0);
        const std::vector<uint8_t> rb = r.encode();
        result_body.insert(result_body.end(), rb.begin(), rb.end());
        result.usbd_status = 0;
        return;
    }

    if (fn == RdpUsbUrbFunction::kControlTransfer) {
        rtsc::proto::RdpUsbTsUrbControlTransfer c;
        if (rtsc::proto::RdpUsbTsUrbControlTransfer::parse(
                body.data(), body.size(), c) != rtsc::proto::Status::Ok) {
            result_body = BuildResultHeader(8, result.usbd_status);
            return;
        }
        const bool ok = d.device != nullptr &&
                        d.device->ControlTransfer(c.pipe_handle,
                                                  c.transfer_flags,
                                                  c.setup_packet, {}, result);
        if (!ok) result.usbd_status = static_cast<uint32_t>(
                rtsc::proto::RdpUsbUsbdStatus::kRequestFailed);
        result_body = BuildResultHeader(8, result.usbd_status);
        return;
    }

    if (fn == RdpUsbUrbFunction::kBulkOrInterruptTransfer) {
        rtsc::proto::RdpUsbTsUrbBulkOrInterruptTransfer b;
        if (rtsc::proto::RdpUsbTsUrbBulkOrInterruptTransfer::parse(
                body.data(), body.size(), b) != rtsc::proto::Status::Ok) {
            result_body = BuildResultHeader(8, result.usbd_status);
            return;
        }
        const bool ok =
            d.device != nullptr &&
            d.device->BulkOrInterruptTransfer(b.pipe_handle,
                                              b.transfer_flags, {}, result);
        if (!ok) result.usbd_status = static_cast<uint32_t>(
                rtsc::proto::RdpUsbUsbdStatus::kRequestFailed);
        result_body = BuildResultHeader(8, result.usbd_status);
        return;
    }

    // Remaining control URB functions map onto a control transfer with a
    // synthesised setup packet.
    result.usbd_status = static_cast<uint32_t>(
        rtsc::proto::RdpUsbUsbdStatus::kInvalidUrbFunction);
    result_body = BuildResultHeader(8, result.usbd_status);
}

void RdpUsbClient::CompleteUrb(uint32_t usb_device, uint32_t request_id,
                               uint16_t urb_function,
                               uint32_t usbd_status,
                               const std::vector<uint8_t>& result,
                               const std::vector<uint8_t>& output) {
    (void)urb_function;
    (void)usbd_status;
    Device* d = FindDevice(usb_device);
    if (d == nullptr) return;
    const uint32_t interface_id =
        MakeHeaderInterfaceId(request_completion_valid_ ? request_completion_
                                                       : d->usb_device);
    if (!output.empty()) {
        rtsc::proto::RdpUsbUrbCompletion c;
        c.header.interface_id = interface_id;
        c.header.function_id =
            static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kUrbCompletion);
        c.request_id = request_id;
        c.ts_urb_result = result;
        c.hresult = 0;
        c.output_buffer = output;
        SendOnChannel(d->channel_id, c.encode());
    } else {
        rtsc::proto::RdpUsbUrbCompletionNoData c;
        c.header.interface_id = interface_id;
        c.header.function_id = static_cast<uint32_t>(
            rtsc::proto::RdpUsbFunction::kUrbCompletionNoData);
        c.request_id = request_id;
        c.ts_urb_result = result;
        c.hresult = 0;
        SendOnChannel(d->channel_id, c.encode());
    }
    ++urb_completion_count_;
}

}  // namespace rtsc::channel
