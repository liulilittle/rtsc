// RDP USB redirection (URBDRC) wire structures ([MS-RDPEUSB] 2.2) and the
// drdynvc transport ([MS-RDPEDYC] 2.2).

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "rtsc/channel/drdynvc_client.h"
#include "rtsc/channel/rdpusb_client.h"
#include "rtsc/proto/channel.h"
#include "rtsc/proto/drdynvc.h"
#include "rtsc/proto/rdpusb.h"
#include "rtsc/usb/usb_device.h"
#include "rtsc/usb/usb_gate.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

uint32_t ReadU32Le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

RdpUsbHeader SinkHeader(RdpUsbFunction fn) {
    RdpUsbHeader h;
    h.interface_id = RdpUsbHeader::MakeInterfaceId(
        RdpUsbInterface::kClientDeviceSink, RdpUsbStreamId::kProxy);
    h.function_id = static_cast<uint32_t>(fn);
    return h;
}

}  // namespace

// ---- SHARED_MSG_HEADER ([MS-RDPEUSB] 2.2.1) ------------------------------

RTSC_TEST(rdpusb_header_parses_bitfields) {
    // InterfaceId 1 | Mask PROXY (1<<30) | MessageId 0x11223344 | Function 0x101.
    const std::vector<uint8_t> b = {0x01, 0x00, 0x00, 0x40, 0x44, 0x33,
                                    0x22, 0x11, 0x01, 0x01, 0x00, 0x00};
    RdpUsbHeader h;
    CHECK(RdpUsbHeader::parse(b.data(), b.size(), h) == Status::Ok);
    CHECK_EQ(h.interface_only(), static_cast<uint32_t>(1));
    CHECK_EQ(h.stream_id(), static_cast<uint32_t>(RdpUsbStreamId::kProxy));
    CHECK_EQ(h.message_id, static_cast<uint32_t>(0x11223344));
    CHECK_EQ(h.function_id, static_cast<uint32_t>(0x00000101));
    CHECK(RdpUsbHeader::parse(b.data(), b.size() - 1, h) ==
          Status::NeedMoreData);
}

RTSC_TEST(rdpusb_header_round_trip_preserves_mask) {
    RdpUsbHeader h;
    h.interface_id = RdpUsbHeader::MakeInterfaceId(
        RdpUsbInterface::kServerChannelNotification, RdpUsbStreamId::kProxy);
    h.message_id = 0x0BADC0DE;
    h.function_id = static_cast<uint32_t>(RdpUsbFunction::kChannelCreated);
    ByteWriter w;
    h.write(w);
    CHECK_EQ(w.size(), RdpUsbHeader::kSize);
    RdpUsbHeader out;
    CHECK(RdpUsbHeader::parse(w.data().data(), w.data().size(), out) ==
          Status::Ok);
    CHECK_EQ(out.interface_id, h.interface_id);
    CHECK_EQ(out.message_id, h.message_id);
    CHECK_EQ(out.function_id, h.function_id);
}

// ---- CHANNEL_CREATED ([MS-RDPEUSB] 2.2.5.1) ------------------------------

RTSC_TEST(rdpusb_channel_created_round_trip) {
    RdpUsbChannelCreated cc;
    cc.header = SinkHeader(RdpUsbFunction::kChannelCreated);
    cc.major_version = 1;
    cc.minor_version = 0;
    cc.capabilities = 0;
    const std::vector<uint8_t> pdu = cc.encode();
    CHECK_EQ(pdu.size(), static_cast<size_t>(24));
    RdpUsbChannelCreated out;
    CHECK(RdpUsbChannelCreated::parse(pdu.data(), pdu.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.major_version, static_cast<uint32_t>(1));
    CHECK_EQ(out.minor_version, static_cast<uint32_t>(0));
    CHECK_EQ(out.header.function_id,
             static_cast<uint32_t>(RdpUsbFunction::kChannelCreated));
}

RTSC_TEST(rdpusb_channel_created_rejects_truncated) {
    const std::vector<uint8_t> pdu = {0x01, 0x00, 0x00, 0x40, 0, 0, 0, 0,
                                      0,   0,   1,   0,   1, 0, 0, 0};
    RdpUsbChannelCreated out;
    CHECK(RdpUsbChannelCreated::parse(pdu.data(), pdu.size(), out) ==
          Status::NeedMoreData);
}

// ---- RIM capability exchange ([MS-RDPEUSB] 2.2.3) ------------------------

RTSC_TEST(rdpusb_rim_capability_request_and_response) {
    RdpUsbRimExchangeCapability req;
    req.header.interface_id = RdpUsbHeader::MakeInterfaceId(
        RdpUsbInterface::kCapabilitiesNegotiator, RdpUsbStreamId::kNone);
    req.header.function_id =
        static_cast<uint32_t>(RdpUsbFunction::kRimExchangeCapabilityRequest);
    req.capability = kRdpUsbRimCapabilityVersion01;
    const std::vector<uint8_t> req_pdu = req.encode(false);
    CHECK_EQ(req_pdu.size(), static_cast<size_t>(16));  // header + capability

    RdpUsbRimExchangeCapability rsp;
    rsp.header = req.header;
    rsp.capability = kRdpUsbRimCapabilityVersion01;
    rsp.result = 0;
    const std::vector<uint8_t> rsp_pdu = rsp.encode(true);
    CHECK_EQ(rsp_pdu.size(), static_cast<size_t>(20));
    // Response = capability + result.
    CHECK_EQ(ReadU32Le(rsp_pdu.data() + 12), kRdpUsbRimCapabilityVersion01);
    CHECK_EQ(ReadU32Le(rsp_pdu.data() + 16), static_cast<uint32_t>(0));
}

// ---- ADD_VIRTUAL_CHANNEL / ADD_DEVICE / RETRACT_DEVICE -------------------

RTSC_TEST(rdpusb_add_virtual_channel_is_header_only) {
    const std::vector<uint8_t> pdu = BuildRdpUsbAddVirtualChannel();
    CHECK_EQ(pdu.size(), RdpUsbHeader::kSize);
    RdpUsbHeader h;
    CHECK(RdpUsbHeader::parse(pdu.data(), pdu.size(), h) == Status::Ok);
    CHECK_EQ(h.interface_only(),
             static_cast<uint32_t>(RdpUsbInterface::kClientDeviceSink));
    CHECK_EQ(h.stream_id(), static_cast<uint32_t>(RdpUsbStreamId::kProxy));
    CHECK_EQ(h.function_id,
             static_cast<uint32_t>(RdpUsbFunction::kAddVirtualChannel));
}

RTSC_TEST(rdpusb_add_device_round_trip) {
    RdpUsbAddDevice d;
    d.header = SinkHeader(RdpUsbFunction::kAddDevice);
    d.usb_device = 0x1234;
    d.device_instance_id = std::u16string(u"USB\\VID_1234&PID_5678\\01");
    d.hardware_ids = std::u16string(u"USB\\VID_1234&PID_5678");
    d.compatibility_ids = std::u16string(u"USB\\Class_03");
    d.container_id = std::u16string(u"{00000000-0000-0000-0000-000000000001}");
    d.capabilities.supported_usb_version = 0x0200;
    d.capabilities.device_is_high_speed = 1;

    const std::vector<uint8_t> pdu = d.encode();
    RdpUsbAddDevice out;
    CHECK(RdpUsbAddDevice::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.num_usb_device, static_cast<uint32_t>(1));
    CHECK_EQ(out.usb_device, static_cast<uint32_t>(0x1234));
    CHECK(out.device_instance_id == d.device_instance_id);
    CHECK(out.hardware_ids == d.hardware_ids);
    CHECK(out.compatibility_ids == d.compatibility_ids);
    CHECK(out.container_id == d.container_id);
    CHECK_EQ(out.capabilities.supported_usb_version, static_cast<uint32_t>(0x0200));
    CHECK_EQ(out.capabilities.device_is_high_speed, static_cast<uint32_t>(1));
}

RTSC_TEST(rdpusb_add_device_multisz_preserves_embedded_nulls) {
    RdpUsbAddDevice d;
    d.header = SinkHeader(RdpUsbFunction::kAddDevice);
    d.usb_device = 5;
    d.device_instance_id = std::u16string(u"USB\\VID_1&PID_1\\0A");
    d.hardware_ids = std::u16string(u"USB\\VID_1&PID_1\0USB\\Class_03");
    const std::vector<uint8_t> pdu = d.encode();
    RdpUsbAddDevice out;
    CHECK(RdpUsbAddDevice::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK(out.hardware_ids == d.hardware_ids);
}

RTSC_TEST(rdpusb_add_device_rejects_bad_capability_size) {
    RdpUsbAddDevice d;
    d.header = SinkHeader(RdpUsbFunction::kAddDevice);
    d.device_instance_id = std::u16string(u"USB\\VID_1");
    d.hardware_ids = std::u16string(u"USB\\VID_1");
    d.container_id = std::u16string(u"{1}");
    d.capabilities.cb_size = 27;  // MUST be 28
    const std::vector<uint8_t> pdu = d.encode();
    RdpUsbAddDevice out;
    CHECK(RdpUsbAddDevice::parse(pdu.data(), pdu.size(), out) ==
          Status::InvalidField);
}

RTSC_TEST(rdpusb_retract_device_round_trip) {
    RdpUsbRetractDevice r;
    r.header = SinkHeader(RdpUsbFunction::kRetractDevice);
    r.reason = 1;
    const std::vector<uint8_t> pdu = r.encode();
    CHECK_EQ(pdu.size(), static_cast<size_t>(16));
    RdpUsbRetractDevice out;
    CHECK(RdpUsbRetractDevice::parse(pdu.data(), pdu.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.reason, static_cast<uint32_t>(1));
}

// ---- server -> client requests -------------------------------------------

RTSC_TEST(rdpusb_register_request_callback_round_trip) {
    RdpUsbRegisterRequestCallback c;
    c.header = SinkHeader(RdpUsbFunction::kRegisterRequestCallback);
    c.num_request_completion = 1;
    c.has_request_completion = true;
    c.request_completion = 0xABCD;
    const std::vector<uint8_t> pdu = c.encode();
    RdpUsbRegisterRequestCallback out;
    CHECK(RdpUsbRegisterRequestCallback::parse(pdu.data(), pdu.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.num_request_completion, static_cast<uint32_t>(1));
    CHECK(out.has_request_completion);
    CHECK_EQ(out.request_completion, static_cast<uint32_t>(0xABCD));

    // NumRequestCompletion = 0 -> no RequestCompletion field.
    RdpUsbRegisterRequestCallback none;
    none.header = c.header;
    none.num_request_completion = 0;
    const std::vector<uint8_t> pdu2 = none.encode();
    CHECK_EQ(pdu2.size(), RdpUsbHeader::kSize + 4);
    RdpUsbRegisterRequestCallback out2;
    CHECK(RdpUsbRegisterRequestCallback::parse(pdu2.data(), pdu2.size(),
                                               out2) == Status::Ok);
    CHECK(!out2.has_request_completion);
}

RTSC_TEST(rdpusb_cancel_request_round_trip) {
    RdpUsbCancelRequest c;
    c.header = SinkHeader(RdpUsbFunction::kCancelRequest);
    c.request_id = 0x77;
    const std::vector<uint8_t> pdu = c.encode();
    RdpUsbCancelRequest out;
    CHECK(RdpUsbCancelRequest::parse(pdu.data(), pdu.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.request_id, static_cast<uint32_t>(0x77));
}

RTSC_TEST(rdpusb_io_control_round_trip) {
    RdpUsbIoControl io;
    io.header = SinkHeader(RdpUsbFunction::kIoControl);
    io.io_control_code = 0x00220003;
    io.input_buffer = {1, 2, 3, 4};
    io.output_buffer_size = 8;
    io.request_id = 0x99;
    const std::vector<uint8_t> pdu = io.encode();
    RdpUsbIoControl out;
    CHECK(RdpUsbIoControl::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.io_control_code, static_cast<uint32_t>(0x00220003));
    CHECK(out.input_buffer == io.input_buffer);
    CHECK_EQ(out.output_buffer_size, static_cast<uint32_t>(8));
    CHECK_EQ(out.request_id, static_cast<uint32_t>(0x99));
}

RTSC_TEST(rdpusb_query_device_text_round_trip) {
    RdpUsbQueryDeviceText q;
    q.header = SinkHeader(RdpUsbFunction::kQueryDeviceText);
    q.text_type = 0;
    q.locale_id = 0x0409;
    const std::vector<uint8_t> pdu = q.encode();
    RdpUsbQueryDeviceText out;
    CHECK(RdpUsbQueryDeviceText::parse(pdu.data(), pdu.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.text_type, static_cast<uint32_t>(0));
    CHECK_EQ(out.locale_id, static_cast<uint32_t>(0x0409));
}

RTSC_TEST(rdpusb_query_device_text_response_round_trip) {
    RdpUsbQueryDeviceTextResponse r;
    r.header = SinkHeader(RdpUsbFunction::kQueryDeviceText);
    r.device_description = std::u16string(u"USB Device");
    r.hresult = 0;
    const std::vector<uint8_t> pdu = r.encode();
    RdpUsbQueryDeviceTextResponse out;
    CHECK(RdpUsbQueryDeviceTextResponse::parse(pdu.data(), pdu.size(), out) ==
          Status::Ok);
    CHECK(out.device_description == r.device_description);
    CHECK_EQ(out.hresult, static_cast<uint32_t>(0));
}

// ---- TS_URB_HEADER ([MS-RDPEUSB] 2.2.9.1.1) ------------------------------

RTSC_TEST(rdpusb_ts_urb_header_no_ack_bit) {
    RdpUsbTsUrbHeader h;
    h.size = 8;
    h.urb_function = RdpUsbUrbFunction::kSelectConfiguration;
    h.set_request_id_and_no_ack(0x80000005);
    CHECK_EQ(h.request_id, static_cast<uint32_t>(5));
    CHECK(h.no_ack);
    CHECK_EQ(h.request_id_and_no_ack(), static_cast<uint32_t>(0x80000005));

    ByteWriter w;
    h.write(w);
    CHECK_EQ(w.size(), RdpUsbTsUrbHeader::kSize);
    CHECK_EQ(w.data()[4], static_cast<uint8_t>(0x05));
    CHECK_EQ(w.data()[7], static_cast<uint8_t>(0x80));
}

// ---- TS_URB ---------------------------------------------------------------

RTSC_TEST(rdpusb_ts_urb_preserves_unknown_body) {
    RdpUsbTsUrb urb;
    urb.header.size = 8 + 3;
    urb.header.urb_function = static_cast<RdpUsbUrbFunction>(0x7F);
    urb.header.request_id = 3;
    urb.body = {0xAA, 0xBB, 0xCC};
    const std::vector<uint8_t> pdu = urb.encode();
    CHECK_EQ(pdu.size(), static_cast<size_t>(11));
    RdpUsbTsUrb out;
    CHECK(RdpUsbTsUrb::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(static_cast<uint16_t>(out.header.urb_function),
             static_cast<uint16_t>(0x7F));
    CHECK(out.body == urb.body);
}

RTSC_TEST(rdpusb_ts_urb_rejects_truncated) {
    RdpUsbTsUrb urb;
    urb.header.size = 16;
    urb.body = {1, 2};
    const std::vector<uint8_t> pdu = urb.encode();
    RdpUsbTsUrb out;
    CHECK(RdpUsbTsUrb::parse(pdu.data(), pdu.size() - 1, out) ==
          Status::NeedMoreData);
}

RTSC_TEST(rdpusb_select_configuration_round_trip) {
    RdpUsbTsUsbdPipeInformation pipe;
    pipe.maximum_packet_size = 64;
    pipe.maximum_transfer_size = 4096;
    pipe.pipe_flags = 0;

    RdpUsbTsUsbdInterfaceInformation iface;
    iface.interface_number = 0;
    iface.alternate_setting = 1;
    iface.pipes = {pipe};

    RdpUsbTsUrbSelectConfiguration sel;
    sel.configuration_descriptor_is_valid = true;
    sel.num_interfaces = 1;
    sel.interfaces = {iface};
    sel.configuration_descriptor = {9, 2, 25, 0, 1, 0, 0, 0x80, 50};

    const std::vector<uint8_t> body = sel.encode();
    RdpUsbTsUrbSelectConfiguration out;
    CHECK(RdpUsbTsUrbSelectConfiguration::parse(body.data(), body.size(),
                                                out) == Status::Ok);
    CHECK(out.configuration_descriptor_is_valid);
    CHECK_EQ(out.num_interfaces, static_cast<uint32_t>(1));
    CHECK_EQ(out.interfaces.size(), static_cast<size_t>(1));
    CHECK_EQ(out.interfaces[0].interface_number, static_cast<uint8_t>(0));
    CHECK_EQ(out.interfaces[0].alternate_setting, static_cast<uint8_t>(1));
    CHECK_EQ(out.interfaces[0].pipes.size(), static_cast<size_t>(1));
    CHECK_EQ(out.interfaces[0].pipes[0].maximum_packet_size,
             static_cast<uint16_t>(64));
    CHECK(out.configuration_descriptor == sel.configuration_descriptor);
}

RTSC_TEST(rdpusb_select_interface_round_trip) {
    RdpUsbTsUsbdInterfaceInformation iface;
    iface.interface_number = 2;
    iface.pipes = {};
    RdpUsbTsUrbSelectInterface sel;
    sel.configuration_handle = 0x40;
    sel.interface = iface;
    const std::vector<uint8_t> body = sel.encode();
    RdpUsbTsUrbSelectInterface out;
    CHECK(RdpUsbTsUrbSelectInterface::parse(body.data(), body.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.configuration_handle, static_cast<uint32_t>(0x40));
    CHECK_EQ(out.interface.interface_number, static_cast<uint8_t>(2));
}

RTSC_TEST(rdpusb_pipe_request_round_trip) {
    RdpUsbTsUrbPipeRequest p;
    p.pipe_handle = 0x1234;
    const std::vector<uint8_t> body = p.encode();
    CHECK_EQ(body.size(), static_cast<size_t>(4));
    RdpUsbTsUrbPipeRequest out;
    CHECK(RdpUsbTsUrbPipeRequest::parse(body.data(), body.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.pipe_handle, static_cast<uint32_t>(0x1234));
}

RTSC_TEST(rdpusb_control_transfer_round_trip) {
    RdpUsbTsUrbControlTransfer c;
    c.pipe_handle = 7;
    c.transfer_flags = kRdpUsbTransferDirection;
    c.setup_packet = {0x80, 0x06, 0, 1, 0, 0, 0x12, 0};
    const std::vector<uint8_t> body = c.encode();
    CHECK_EQ(body.size(), static_cast<size_t>(16));
    RdpUsbTsUrbControlTransfer out;
    CHECK(RdpUsbTsUrbControlTransfer::parse(body.data(), body.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.pipe_handle, static_cast<uint32_t>(7));
    CHECK_EQ(out.transfer_flags, static_cast<uint32_t>(kRdpUsbTransferDirection));
    CHECK(out.setup_packet == c.setup_packet);
}

RTSC_TEST(rdpusb_bulk_or_interrupt_round_trip) {
    RdpUsbTsUrbBulkOrInterruptTransfer b;
    b.pipe_handle = 9;
    b.transfer_flags = kRdpUsbTransferDirection;
    const std::vector<uint8_t> body = b.encode();
    RdpUsbTsUrbBulkOrInterruptTransfer out;
    CHECK(RdpUsbTsUrbBulkOrInterruptTransfer::parse(body.data(), body.size(),
                                                    out) == Status::Ok);
    CHECK_EQ(out.pipe_handle, static_cast<uint32_t>(9));
    CHECK_EQ(out.transfer_flags, static_cast<uint32_t>(kRdpUsbTransferDirection));
}

// ---- transfer requests ---------------------------------------------------

RTSC_TEST(rdpusb_transfer_in_request_round_trip) {
    RdpUsbTsUrbPipeRequest pipe;
    pipe.pipe_handle = 3;
    RdpUsbTsUrb urb;
    urb.header.urb_function = RdpUsbUrbFunction::kPipeRequest;
    urb.body = pipe.encode();

    RdpUsbTransferInRequest req;
    req.header = SinkHeader(RdpUsbFunction::kTransferInRequest);
    req.ts_urb = urb;
    req.output_buffer_size = 0;
    const std::vector<uint8_t> pdu = req.encode();
    RdpUsbTransferInRequest out;
    CHECK(RdpUsbTransferInRequest::parse(pdu.data(), pdu.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.header.function_id,
             static_cast<uint32_t>(RdpUsbFunction::kTransferInRequest));
    CHECK(out.ts_urb.body == urb.body);
    CHECK_EQ(out.output_buffer_size, static_cast<uint32_t>(0));
}

RTSC_TEST(rdpusb_transfer_out_request_round_trip) {
    RdpUsbTsUrbBulkOrInterruptTransfer b;
    b.pipe_handle = 2;
    b.transfer_flags = 0;
    RdpUsbTsUrb urb;
    urb.header.urb_function = RdpUsbUrbFunction::kBulkOrInterruptTransfer;
    urb.body = b.encode();

    RdpUsbTransferOutRequest req;
    req.header = SinkHeader(RdpUsbFunction::kTransferOutRequest);
    req.ts_urb = urb;
    req.output_buffer_size = 4;
    req.output_buffer = {0xDE, 0xAD, 0xBE, 0xEF};
    const std::vector<uint8_t> pdu = req.encode();
    RdpUsbTransferOutRequest out;
    CHECK(RdpUsbTransferOutRequest::parse(pdu.data(), pdu.size(), out) ==
          Status::Ok);
    CHECK(out.output_buffer == req.output_buffer);
    CHECK_EQ(out.output_buffer_size, static_cast<uint32_t>(4));
}

// ---- client completions --------------------------------------------------

RTSC_TEST(rdpusb_urb_completion_round_trip) {
    RdpUsbUrbCompletion c;
    c.header = SinkHeader(RdpUsbFunction::kUrbCompletion);
    c.request_id = 11;
    c.ts_urb_result = {8, 0, 0, 0, 0, 0, 0, 0};  // TS_URB_RESULT_HEADER
    c.hresult = 0;
    c.output_buffer = {1, 2, 3};
    const std::vector<uint8_t> pdu = c.encode();
    RdpUsbUrbCompletion out;
    CHECK(RdpUsbUrbCompletion::parse(pdu.data(), pdu.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.request_id, static_cast<uint32_t>(11));
    CHECK(out.ts_urb_result == c.ts_urb_result);
    CHECK(out.output_buffer == c.output_buffer);
}

RTSC_TEST(rdpusb_urb_completion_no_data_round_trip) {
    RdpUsbUrbCompletionNoData c;
    c.header = SinkHeader(RdpUsbFunction::kUrbCompletionNoData);
    c.request_id = 12;
    c.ts_urb_result = {8, 0, 0, 0, 0, 0, 0, 0};
    c.hresult = 0;
    c.output_buffer_size = 0;
    const std::vector<uint8_t> pdu = c.encode();
    RdpUsbUrbCompletionNoData out;
    CHECK(RdpUsbUrbCompletionNoData::parse(pdu.data(), pdu.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.request_id, static_cast<uint32_t>(12));
    CHECK(out.ts_urb_result == c.ts_urb_result);
}

RTSC_TEST(rdpusb_io_control_completion_round_trip) {
    RdpUsbIoControlCompletion c;
    c.header = SinkHeader(RdpUsbFunction::kIoControlCompletion);
    c.request_id = 13;
    c.hresult = 0;
    c.information = 2;
    c.output_buffer = {0x10, 0x20};
    const std::vector<uint8_t> pdu = c.encode();
    RdpUsbIoControlCompletion out;
    CHECK(RdpUsbIoControlCompletion::parse(pdu.data(), pdu.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.request_id, static_cast<uint32_t>(13));
    CHECK(out.output_buffer == c.output_buffer);
    CHECK_EQ(out.information, static_cast<uint32_t>(2));
}

// ---- TS_URB_RESULT -------------------------------------------------------

RTSC_TEST(rdpusb_ts_urb_result_header_round_trip) {
    RdpUsbTsUrbResultHeader h;
    h.size = 8;
    h.usbd_status = static_cast<uint32_t>(RdpUsbUsbdStatus::kSuccess);
    ByteWriter w;
    h.write(w);
    CHECK_EQ(w.size(), RdpUsbTsUrbResultHeader::kSize);
    RdpUsbTsUrbResultHeader out;
    CHECK(RdpUsbTsUrbResultHeader::parse(w.data().data(), w.data().size(),
                                         out) == Status::Ok);
    CHECK_EQ(out.usbd_status, static_cast<uint32_t>(0));
}

RTSC_TEST(rdpusb_select_configuration_result_round_trip) {
    RdpUsbTsUsbdPipeInformationResult pipe;
    pipe.maximum_packet_size = 64;
    pipe.endpoint_address = 0x81;
    pipe.interval = 1;
    pipe.pipe_type = 3;
    pipe.pipe_handle = 0x50;

    RdpUsbTsUsbdInterfaceInformationResult iface;
    iface.interface_number = 0;
    iface.interface_handle = 0x60;
    iface.pipes = {pipe};

    RdpUsbTsUrbSelectConfigurationResult r;
    r.configuration_handle = 0x70;
    r.interfaces = {iface};
    const std::vector<uint8_t> body = r.encode();
    RdpUsbTsUrbSelectConfigurationResult out;
    CHECK(RdpUsbTsUrbSelectConfigurationResult::parse(body.data(), body.size(),
                                                      out) == Status::Ok);
    CHECK_EQ(out.configuration_handle, static_cast<uint32_t>(0x70));
    CHECK_EQ(out.interfaces.size(), static_cast<size_t>(1));
    CHECK_EQ(out.interfaces[0].interface_handle, static_cast<uint32_t>(0x60));
    CHECK_EQ(out.interfaces[0].pipes[0].pipe_handle,
             static_cast<uint32_t>(0x50));
}

RTSC_TEST(rdpusb_get_current_frame_number_result_round_trip) {
    RdpUsbTsUrbGetCurrentFrameNumberResult r;
    r.frame_number = 123456;
    const std::vector<uint8_t> body = r.encode();
    RdpUsbTsUrbGetCurrentFrameNumberResult out;
    CHECK(RdpUsbTsUrbGetCurrentFrameNumberResult::parse(body.data(),
                                                        body.size(),
                                                        out) == Status::Ok);
    CHECK_EQ(out.frame_number, static_cast<uint32_t>(123456));
}

// ---- USB_DEVICE_CAPABILITIES --------------------------------------------

RTSC_TEST(rdpusb_device_capabilities_round_trip) {
    RdpUsbDeviceCapabilities c;
    c.cb_size = 28;
    c.usb_bus_interface_version = 2;
    c.usbdi_version = 0x00000500;
    c.supported_usb_version = 0x0200;
    c.device_is_high_speed = 1;
    c.no_ack_isoch_write_jitter_buffer_size_in_ms = 64;
    ByteWriter w;
    c.write(w);
    CHECK_EQ(w.size(), RdpUsbDeviceCapabilities::kSize);
    RdpUsbDeviceCapabilities out;
    CHECK(RdpUsbDeviceCapabilities::parse(w.data().data(), w.data().size(),
                                          out) == Status::Ok);
    CHECK_EQ(out.cb_size, static_cast<uint32_t>(28));
    CHECK_EQ(out.usbdi_version, static_cast<uint32_t>(0x00000500));
    CHECK_EQ(out.no_ack_isoch_write_jitter_buffer_size_in_ms,
             static_cast<uint32_t>(64));
}

// ---- drdynvc transport ([MS-RDPEDYC] 2.2) --------------------------------

namespace {

// Feeds one drdynvc PDU to the transport as a complete static channel message.
void FeedDvc(rtsc::channel::DrdynvcClient& t,
             const std::vector<uint8_t>& dvc_pdu) {
    for (const auto& chunk : rtsc::proto::FragmentChannelMessage(dvc_pdu)) {
        t.OnChannelData(chunk.data(), chunk.size());
    }
}

// Extracts the payload of a sent channel message (DYNVC_HEADER + ChannelId
// stripped).
std::vector<uint8_t> DvcPayload(const std::vector<uint8_t>& chunk) {
    rtsc::proto::DynvcPdu pdu;
    const Status s = rtsc::proto::DynvcPdu::parse(
        chunk.data() + rtsc::proto::ChannelPduHeader::kSize,
        chunk.size() - rtsc::proto::ChannelPduHeader::kSize, pdu);
    CHECK(s == Status::Ok);
    return pdu.data;
}

struct CapturedSend {
    std::vector<std::vector<uint8_t>> chunks;
    void Add(const std::vector<uint8_t>& c) { chunks.push_back(c); }
    const std::vector<uint8_t>* Last() const {
        return chunks.empty() ? nullptr : &chunks.back();
    }
};

// RDP 8.0 Lite "unencoded run" segment ([MS-RDPEGFX] 3.1.9.1.2.4): match prefix
// 10001, 5-bit distance 0, 15-bit length, padding, then the raw bytes.
std::vector<uint8_t> BulkRawRun(const std::vector<uint8_t>& raw) {
    // Bits: match prefix 10001 (5), distance 00000 (5), 15-bit length, then
    // padding to the byte boundary; the raw bytes follow; trailer = 0.
    const uint32_t length = static_cast<uint32_t>(raw.size());
    std::vector<uint8_t> out{0xE0, 0x26};
    out.push_back(0x88);
    out.push_back(static_cast<uint8_t>((length >> 9) & 0x3F));
    out.push_back(static_cast<uint8_t>((length >> 1) & 0xFF));
    out.push_back(static_cast<uint8_t>((length & 0x01) << 7));
    out.insert(out.end(), raw.begin(), raw.end());
    out.push_back(0x00);  // trailer: every bit used
    return out;
}

struct CountingListener final : rtsc::channel::IDrdynvcListener {
    unsigned data = 0;
    std::vector<uint8_t> last;
    void OnChannelData(uint32_t, const std::vector<uint8_t>& message) override {
        ++data;
        last = message;
    }
};;

// Source-level regression helpers (W11 repair batch): a pure in-memory scan
// that locates a source line by substring, mirroring the guard pattern in
// test_server_rdpdr_e2e.cpp.
size_t FindLineIn(const std::vector<std::string>& lines, const char* needle) {
    for (size_t i = 0; i < lines.size(); ++i) {
        if (lines[i].find(needle) != std::string::npos) return i;
    }
    return std::string::npos;
}

}  // namespace

RTSC_TEST(drdynvc_start_sends_caps_request) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr, [&](const std::vector<uint8_t>& c) {
        cap.Add(c);
    });
    t.Start();
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(1));
    const std::vector<uint8_t> dvc =
        cap.chunks[0].size() > rtsc::proto::ChannelPduHeader::kSize
            ? std::vector<uint8_t>(
                  cap.chunks[0].begin() + rtsc::proto::ChannelPduHeader::kSize,
                  cap.chunks[0].end())
            : std::vector<uint8_t>{};
    CHECK_EQ(dvc.size(), static_cast<size_t>(4));
    CHECK_EQ(dvc[0], static_cast<uint8_t>(0x50));  // Cmd=CAPABILITY, cbId=0
    CHECK_EQ(dvc[1], static_cast<uint8_t>(0x00));  // Pad, MUST be 0
    // VERSION1 CAPS_REQ ([MS-RDPEDYC] 2.2.1.1.1) = header + Pad + Version,
    // with NO PriorityCharge fields.
    CHECK_EQ(static_cast<uint16_t>(dvc[2] | (dvc[3] << 8)),
             static_cast<uint16_t>(0x0001));
    CHECK_EQ(t.caps_request_count(), static_cast<unsigned>(1));
}

RTSC_TEST(drdynvc_caps_response_version_read_at_offset_2) {
    struct Listener final : rtsc::channel::IDrdynvcListener {
        uint16_t version = 0;
        void OnCapsResponse(uint16_t v) override { version = v; }
    } listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    // DYNVC_CAPS VERSION2 ([MS-RDPEDYC] 2.2.1.1.2): header + Pad + Version +
    // PriorityCharge0..3; the Version field still lives at offset 2.
    const std::vector<uint8_t> rsp = {0x50, 0x00, 0x02, 0x00,
                                      0x01, 0x00, 0x02, 0x00,
                                      0x03, 0x00, 0x04, 0x00};
    FeedDvc(t, rsp);
    CHECK_EQ(listener.version, static_cast<uint16_t>(2));
    CHECK(t.ready());
}

// [MS-RDPEDYC] 2.2.1 / 3.2.3.1.4: the client MUST answer a DYNVC_CAPS_VERSION1/2/3
// PDU with a DYNVC_CAPS_RSP carrying the highest version the client supports
// (capped by what the server announced).
RTSC_TEST(drdynvc_caps_request_is_answered_with_caps_response) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr, [&](const std::vector<uint8_t>& c) {
        cap.Add(c);
    });
    const std::vector<uint8_t> server_caps_v1 = {0x50, 0x00, 0x01, 0x00};
    FeedDvc(t, server_caps_v1);
    const std::vector<uint8_t>* response = cap.Last();
    CHECK(response != nullptr);
    if (response != nullptr) {
        const std::vector<uint8_t> dvc(
            response->begin() + rtsc::proto::ChannelPduHeader::kSize,
            response->end());
        CHECK_EQ(dvc.size(), static_cast<size_t>(4));
        CHECK_EQ(dvc[0], static_cast<uint8_t>(0x50));  // Cmd=CAPABILITY, cbId=0
        CHECK_EQ(dvc[1], static_cast<uint8_t>(0x00));  // Pad MUST be 0
        CHECK_EQ(static_cast<uint16_t>(dvc[2] | (dvc[3] << 8)),
                 static_cast<uint16_t>(0x0001));
    }
    CHECK_EQ(t.negotiated_version(), static_cast<uint16_t>(1));
}

RTSC_TEST(drdynvc_caps_response_is_capped_by_client_maximum) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr, [&](const std::vector<uint8_t>& c) {
        cap.Add(c);
    });
    // VERSION3 request (12 bytes) from a server that supports version 3: the
    // client now implements RDP 8.0 Lite decompression, so it answers 3.
    const std::vector<uint8_t> server_caps_v3 = {0x50, 0x00, 0x03, 0x00,
                                                 0x01, 0x00, 0x02, 0x00,
                                                 0x03, 0x00, 0x04, 0x00};
    FeedDvc(t, server_caps_v3);
    const std::vector<uint8_t>* response = cap.Last();
    CHECK(response != nullptr);
    if (response != nullptr) {
        const std::vector<uint8_t> dvc(
            response->begin() + rtsc::proto::ChannelPduHeader::kSize,
            response->end());
        CHECK_EQ(dvc.size(), static_cast<size_t>(4));
        CHECK_EQ(static_cast<uint16_t>(dvc[2] | (dvc[3] << 8)),
                 static_cast<uint16_t>(0x0003));
    }
    CHECK_EQ(t.negotiated_version(), static_cast<uint16_t>(3));
}

RTSC_TEST(drdynvc_compressed_data_requires_version3) {
    CountingListener listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener, [&](const std::vector<uint8_t>& c) {
        cap.Add(c);
    });
    // VERSION1 negotiation: compressed PDUs are not allowed on this transport
    // ([MS-RDPEDYC] 2.2.3.3/2.2.3.4), so they must be rejected rather than
    // decoded.
    FeedDvc(t, {0x50, 0x00, 0x01, 0x00});
    const uint32_t id = t.CreateChannel("URBDRC");
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kCreate, 0,
                                          id, {0, 0, 0, 0}));
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataCompressed, 0, id,
                   BulkRawRun({0x41, 0x42})));
    CHECK_EQ(listener.data, static_cast<unsigned>(0));
    CHECK_EQ(t.compressed_data_count(), static_cast<unsigned>(0));
    CHECK_EQ(t.compressed_failure_count(), static_cast<unsigned>(1));
}

RTSC_TEST(drdynvc_compressed_data_runs_after_version3) {
    CountingListener listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener, [&](const std::vector<uint8_t>& c) {
        cap.Add(c);
    });
    FeedDvc(t, {0x50, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
                0x04, 0x00});
    const uint32_t id = t.CreateChannel("URBDRC");
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kCreate, 0,
                                          id, {0, 0, 0, 0}));
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataCompressed, 0, id,
                   BulkRawRun({0x41, 0x42})));
    CHECK_EQ(t.compressed_failure_count(), static_cast<unsigned>(0));
    CHECK_EQ(t.compressed_data_count(), static_cast<unsigned>(1));
    CHECK_EQ(listener.data, static_cast<unsigned>(1));
    CHECK(listener.last == std::vector<uint8_t>({0x41, 0x42}));
}
RTSC_TEST(drdynvc_create_response_opens_channel) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr, [&](const std::vector<uint8_t>& c) {
        cap.Add(c);
    });
    const uint32_t id = t.CreateChannel("URBDRC");
    CHECK_EQ(t.pending_channels(), static_cast<size_t>(1));

    const auto rsp = rtsc::proto::BuildDynvcPdu(
        rtsc::proto::DynvcCmd::kCreate, 0, id, {0, 0, 0, 0});
    FeedDvc(t, rsp);
    CHECK_EQ(t.pending_channels(), static_cast<size_t>(0));
    CHECK_EQ(t.create_response_count(), static_cast<unsigned>(1));
}

RTSC_TEST(drdynvc_server_initiated_create_accepted) {
    struct Listener final : rtsc::channel::IDrdynvcListener {
        std::string requested;
        unsigned data = 0;
        bool OnChannelCreateRequest(const std::string& name) override {
            requested = name;
            return true;
        }
        void OnChannelData(uint32_t, const std::vector<uint8_t>&) override {
            ++data;
        }
    } listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    // DYNVC_CREATE_REQ: Cmd=Create, cbId=0, ChannelId=7, "URBDRC\0".
    std::vector<uint8_t> req = {0x10, 0x07};
    for (char c : std::string("URBDRC")) {
        req.push_back(static_cast<uint8_t>(c));
    }
    req.push_back(0);
    FeedDvc(t, req);
    CHECK(listener.requested == "URBDRC");
    CHECK_EQ(t.server_create_count(), static_cast<unsigned>(1));
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(1));
    if (!cap.chunks.empty()) {
        rtsc::proto::DynvcPdu rsp;
        const std::vector<uint8_t>& chunk = cap.chunks[0];
        CHECK(rtsc::proto::DynvcPdu::parse(
                  chunk.data() + rtsc::proto::ChannelPduHeader::kSize,
                  chunk.size() - rtsc::proto::ChannelPduHeader::kSize,
                  rsp) == rtsc::proto::Status::Ok);
        CHECK_EQ(rsp.channel_id, static_cast<uint32_t>(7));
        CHECK_EQ(rsp.data.size(), static_cast<size_t>(4));
        if (rsp.data.size() == 4) {
            const uint32_t status =
                static_cast<uint32_t>(rsp.data[0]) |
                (static_cast<uint32_t>(rsp.data[1]) << 8) |
                (static_cast<uint32_t>(rsp.data[2]) << 16) |
                (static_cast<uint32_t>(rsp.data[3]) << 24);
            CHECK_EQ(status, static_cast<uint32_t>(0));
        }
    }
    // Data on the accepted server-created channel reaches the listener.
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataFirst, 0, 7, {9, 9}));
    CHECK_EQ(listener.data, static_cast<unsigned>(1));
}

RTSC_TEST(drdynvc_server_initiated_create_rejected) {
    struct Listener final : rtsc::channel::IDrdynvcListener {
        unsigned data = 0;
        bool OnChannelCreateRequest(const std::string&) override {
            return false;
        }
        void OnChannelData(uint32_t, const std::vector<uint8_t>&) override {
            ++data;
        }
    } listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    std::vector<uint8_t> req = {0x10, 0x09};
    for (char c : std::string("NOPE")) {
        req.push_back(static_cast<uint8_t>(c));
    }
    req.push_back(0);
    FeedDvc(t, req);
    CHECK_EQ(t.server_create_count(), static_cast<unsigned>(1));
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(1));
    if (!cap.chunks.empty()) {
        rtsc::proto::DynvcPdu rsp;
        const std::vector<uint8_t>& chunk = cap.chunks[0];
        CHECK(rtsc::proto::DynvcPdu::parse(
                  chunk.data() + rtsc::proto::ChannelPduHeader::kSize,
                  chunk.size() - rtsc::proto::ChannelPduHeader::kSize,
                  rsp) == rtsc::proto::Status::Ok);
        CHECK_EQ(rsp.channel_id, static_cast<uint32_t>(9));
        if (rsp.data.size() == 4) {
            const uint32_t status =
                static_cast<uint32_t>(rsp.data[0]) |
                (static_cast<uint32_t>(rsp.data[1]) << 8) |
                (static_cast<uint32_t>(rsp.data[2]) << 16) |
                (static_cast<uint32_t>(rsp.data[3]) << 24);
            CHECK_EQ(status, static_cast<uint32_t>(0xC0000001u));
        }
    }
    // A rejected id is not active: data is dropped without a callback.
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataFirst, 0, 9, {1, 2}));
    CHECK_EQ(listener.data, static_cast<unsigned>(0));
}

RTSC_TEST(drdynvc_client_close_stops_delivery) {
    struct Listener final : rtsc::channel::IDrdynvcListener {
        unsigned data = 0;
        unsigned closed = 0;
        void OnChannelData(uint32_t, const std::vector<uint8_t>&) override {
            ++data;
        }
        void OnChannelClosed(uint32_t) override { ++closed; }
    } listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    const uint32_t id = t.CreateChannel("URBDRC");
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kCreate, 0, id, {0, 0, 0, 0}));
    t.CloseChannel(id);
    // Closing locally stops delivery at once; the listener is told when the
    // server answers with its CLOSE.
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataFirst, 0, id, {1, 2}));
    CHECK_EQ(listener.data, static_cast<unsigned>(0));
    CHECK_EQ(listener.closed, static_cast<unsigned>(0));
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kClose, 0,
                                          id, {}));
    CHECK_EQ(listener.closed, static_cast<unsigned>(1));
}

RTSC_TEST(drdynvc_close_unknown_channel_is_ignored) {
    struct Listener final : rtsc::channel::IDrdynvcListener {
        unsigned closed = 0;
        void OnChannelClosed(uint32_t) override { ++closed; }
    } listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kClose, 0,
                                          99, {}));
    CHECK_EQ(listener.closed, static_cast<unsigned>(0));
}

// [MS-RDPEDYC] 2.2.3.3: DYNVC_DATA_FIRST_COMPRESSED header bits 2-3 are Len,
// not Sp; Len selects a 1-, 2- or 4-byte Length field.
RTSC_TEST(drdynvc_parse_data_first_compressed_len2) {
    const std::vector<uint8_t> raw{0x64, 0x05, 0xD2, 0x04, 0xAA};
    rtsc::proto::DynvcPdu pdu;
    const rtsc::proto::Status st =
        rtsc::proto::DynvcPdu::parse(raw.data(), raw.size(), pdu);
    CHECK(st == rtsc::proto::Status::Ok);
    if (st != rtsc::proto::Status::Ok) return;
    CHECK_EQ(pdu.channel_id, static_cast<uint32_t>(5));
    CHECK_EQ(pdu.length, static_cast<uint32_t>(1234));
    CHECK_EQ(pdu.data.size(), static_cast<size_t>(1));
    CHECK_EQ(pdu.data[0], 0xAA);
}

RTSC_TEST(drdynvc_parse_data_first_compressed_len1) {
    const std::vector<uint8_t> raw{0x60, 0x05, 0x07, 0xBB};
    rtsc::proto::DynvcPdu pdu;
    const rtsc::proto::Status st =
        rtsc::proto::DynvcPdu::parse(raw.data(), raw.size(), pdu);
    CHECK(st == rtsc::proto::Status::Ok);
    if (st != rtsc::proto::Status::Ok) return;
    CHECK_EQ(pdu.length, static_cast<uint32_t>(7));
    CHECK_EQ(pdu.data.size(), static_cast<size_t>(1));
    CHECK_EQ(pdu.data[0], 0xBB);
}

RTSC_TEST(drdynvc_parse_data_first_compressed_len3_invalid) {
    const std::vector<uint8_t> raw{0x6C, 0x05, 0x00, 0x00, 0x00, 0x00};
    rtsc::proto::DynvcPdu pdu;
    CHECK(rtsc::proto::DynvcPdu::parse(raw.data(), raw.size(), pdu) ==
          rtsc::proto::Status::InvalidField);
}

RTSC_TEST(drdynvc_build_data_first_compressed_round_trip) {
    const std::vector<uint8_t> raw =
        rtsc::proto::BuildDynvcDataFirstCompressedPdu(1, 5, 1234, {0xAA});
    const std::vector<uint8_t> expected{0x64, 0x05, 0xD2, 0x04, 0xAA};
    CHECK(raw == expected);
    rtsc::proto::DynvcPdu pdu;
    const rtsc::proto::Status st =
        rtsc::proto::DynvcPdu::parse(raw.data(), raw.size(), pdu);
    CHECK(st == rtsc::proto::Status::Ok);
    if (st != rtsc::proto::Status::Ok) return;
    CHECK_EQ(pdu.length, static_cast<uint32_t>(1234));
    CHECK_EQ(pdu.data.size(), static_cast<size_t>(1));
}

RTSC_TEST(drdynvc_client_decompresses_compressed_data) {
    CountingListener listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    // Compressed DVC data requires version 3 ([MS-RDPEDYC] 2.2.1).
    FeedDvc(t, {0x50, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
                0x04, 0x00});
    const uint32_t id = t.CreateChannel("URBDRC");
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kCreate, 0, id, {0, 0, 0, 0}));
    CHECK_EQ(t.compressed_data_count(), static_cast<unsigned>(0));

    const std::vector<uint8_t> payload = BulkRawRun({0x41, 0x42, 0x43});
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataCompressed, 0, id, payload));
    CHECK_EQ(t.compressed_data_count(), static_cast<unsigned>(1));
    CHECK_EQ(t.compressed_failure_count(), static_cast<unsigned>(0));
    CHECK_EQ(listener.data, static_cast<unsigned>(1));
    CHECK(listener.last == std::vector<uint8_t>({0x41, 0x42, 0x43}));
}

RTSC_TEST(drdynvc_client_reassembles_compressed_fragments) {
    CountingListener listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    // Compressed DVC data requires version 3 ([MS-RDPEDYC] 2.2.1).
    FeedDvc(t, {0x50, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
                0x04, 0x00});
    const uint32_t id = t.CreateChannel("URBDRC");
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kCreate, 0, id, {0, 0, 0, 0}));

    const std::vector<uint8_t> first_half(30, 0x41);
    FeedDvc(t, rtsc::proto::BuildDynvcDataFirstCompressedPdu(
                   1, id, 60, BulkRawRun(first_half)));
    CHECK_EQ(listener.data, static_cast<unsigned>(0));

    // Second block: a match at distance 1 with length 30, taken from the
    // history the first block left in this channel's dedicated context.
    const std::vector<uint8_t> second_payload = {0xE0, 0x26, 0x88,
                                                0x7B, 0x80, 0x06};
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataCompressed, 0, id,
                   second_payload));
    CHECK_EQ(t.compressed_failure_count(), static_cast<unsigned>(0));
    CHECK_EQ(listener.data, static_cast<unsigned>(1));
    CHECK_EQ(listener.last.size(), static_cast<size_t>(60));
    bool all_a = true;
    for (const uint8_t byte : listener.last) {
        if (byte != 0x41) all_a = false;
    }
    CHECK(all_a);
}

RTSC_TEST(drdynvc_client_corrupt_compressed_data_fails_closed) {
    CountingListener listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    const uint32_t id = t.CreateChannel("URBDRC");
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kCreate, 0, id, {0, 0, 0, 0}));
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataCompressed, 0, id, {0xDE, 0xAD}));
    CHECK_EQ(t.compressed_data_count(), static_cast<unsigned>(0));
    CHECK_EQ(t.compressed_failure_count(), static_cast<unsigned>(1));
    CHECK_EQ(listener.data, static_cast<unsigned>(0));

    // A rejected block must not poison later uncompressed reassembly.
    FeedDvc(t, rtsc::proto::BuildDynvcDataFirstPdu(0, id, 2, {0x41, 0x42}));
    CHECK_EQ(listener.data, static_cast<unsigned>(1));
}

RTSC_TEST(drdynvc_client_compressed_unknown_channel_ignored) {
    CountingListener listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    const std::vector<uint8_t> payload = BulkRawRun({0x41});
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataCompressed, 0, 77, payload));
    CHECK_EQ(listener.data, static_cast<unsigned>(0));
    CHECK_EQ(t.compressed_data_count(), static_cast<unsigned>(0));
    CHECK_EQ(t.compressed_failure_count(), static_cast<unsigned>(0));
}
RTSC_TEST(drdynvc_send_refused_for_unknown_channel) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    CHECK(!t.SendChannelData(99, {1, 2}));
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(0));
    CHECK_EQ(t.refused_data_count(), static_cast<unsigned>(1));
}

RTSC_TEST(drdynvc_send_refused_after_local_close) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    const uint32_t id = t.CreateChannel("URBDRC");
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kCreate, 0, id, {0, 0, 0, 0}));
    CHECK(t.SendChannelData(id, {0x41}));  // open: allowed
    const size_t after_open = cap.chunks.size();
    t.CloseChannel(id);
    const size_t after_close = cap.chunks.size();
    CHECK(after_close > after_open);
    CHECK(!t.SendChannelData(id, {0x42}));
    CHECK_EQ(cap.chunks.size(), after_close);
    CHECK_EQ(t.refused_data_count(), static_cast<unsigned>(1));
    // The server's CLOSE only answers ours: the id stays unusable.
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kClose, 0,
                                          id, {}));
    CHECK(!t.SendChannelData(id, {0x43}));
    CHECK_EQ(t.refused_data_count(), static_cast<unsigned>(2));
}

RTSC_TEST(drdynvc_send_allowed_while_pending) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    const uint32_t id = t.CreateChannel("URBDRC");
    CHECK(t.SendChannelData(id, {0x41}));
    CHECK_EQ(t.refused_data_count(), static_cast<unsigned>(0));
}

RTSC_TEST(drdynvc_fans_out_to_all_listeners) {
    struct Listener final : rtsc::channel::IDrdynvcListener {
        unsigned caps = 0;
        unsigned created = 0;
        unsigned data = 0;
        unsigned closed = 0;
        void OnCapsResponse(uint16_t) override { ++caps; }
        void OnChannelCreated(uint32_t) override { ++created; }
        void OnChannelData(uint32_t, const std::vector<uint8_t>&) override {
            ++data;
        }
        void OnChannelClosed(uint32_t) override { ++closed; }
    } a, b;
    rtsc::channel::DrdynvcClient t(nullptr,
                                   [](const std::vector<uint8_t>&) {});
    t.AddListener(&a);
    t.AddListener(&b);
    // A second AddListener of the same pointer must not double-deliver.
    t.AddListener(&a);

    FeedDvc(t, {0x50, 0x00, 0x02, 0x00, 0x01, 0x00,
                0x02, 0x00, 0x03, 0x00, 0x04, 0x00});
    const uint32_t id = t.CreateChannel("DISP");
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kCreate, 0, id, {0, 0, 0, 0}));
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataFirst, 0, id, {1, 2, 3}));

    CHECK_EQ(a.caps, static_cast<unsigned>(1));
    CHECK_EQ(b.caps, static_cast<unsigned>(1));
    CHECK_EQ(a.created, static_cast<unsigned>(1));
    CHECK_EQ(b.created, static_cast<unsigned>(1));
    CHECK_EQ(a.data, static_cast<unsigned>(1));
    CHECK_EQ(b.data, static_cast<unsigned>(1));

    // Removing one listener stops its delivery without affecting the other.
    t.RemoveListener(&b);
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataFirst, 0, id, {4, 5, 6}));
    CHECK_EQ(a.data, static_cast<unsigned>(2));
    CHECK_EQ(b.data, static_cast<unsigned>(1));

    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kClose, 0, id, {}));
    CHECK_EQ(a.closed, static_cast<unsigned>(1));
    CHECK_EQ(b.closed, static_cast<unsigned>(0));
}

RTSC_TEST(drdynvc_data_delivered_to_listener) {
    struct Listener final : rtsc::channel::IDrdynvcListener {
        unsigned data_count = 0;
        uint32_t last_id = 0;
        std::vector<uint8_t> last_data;
        void OnChannelData(uint32_t channel_id,
                           const std::vector<uint8_t>& data) override {
            ++data_count;
            last_id = channel_id;
            last_data = data;
        }
    } listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    const uint32_t id = t.CreateChannel("URBDRC");
    FeedDvc(t, rtsc::proto::BuildDynvcPdu(
                   rtsc::proto::DynvcCmd::kDataFirst, 0, id, {1, 2, 3}));
    CHECK_EQ(listener.data_count, static_cast<unsigned>(1));
    CHECK_EQ(listener.last_id, id);
    CHECK(listener.last_data == std::vector<uint8_t>({1, 2, 3}));
}

// ---- URBDRC client state machine ([MS-RDPEUSB] 1.3.1) --------------------

namespace {

class FakeUsbDevice final : public rtsc::usb::UsbDevice {
 public:
    bool Open() override { return true; }
    void Close() override {}
    const rtsc::usb::UsbDeviceInfo& info() const override { return info_; }
    bool SelectConfiguration(
        const std::vector<rtsc::usb::UsbInterfaceInfo>&,
        uint32_t& configuration_handle) override {
        configuration_handle = 0x10;
        return true;
    }
    bool SelectInterface(uint32_t, const rtsc::usb::UsbInterfaceInfo&,
                         uint32_t& interface_handle) override {
        interface_handle = 0x20;
        return true;
    }
    bool ControlTransfer(uint32_t, uint32_t,
                         const std::vector<uint8_t>&,
                         const std::vector<uint8_t>&,
                         rtsc::usb::UrbResult& result) override {
        result.usbd_status = 0;
        result.output_buffer = {0xAA, 0xBB};
        return true;
    }
    bool BulkOrInterruptTransfer(uint32_t, uint32_t,
                                 const std::vector<uint8_t>&, uint32_t,
                                 rtsc::usb::UrbResult& result) override {
        result.usbd_status = 0;
        result.output_buffer = {0xCC};
        return true;
    }
    bool ResetPipe(uint32_t) override { return true; }
    bool CancelRequest(uint32_t) override { return true; }

    rtsc::usb::UsbDeviceInfo info_;
};

class FakeEnumerator final : public rtsc::usb::UsbDeviceEnumerator {
 public:
    std::vector<rtsc::usb::UsbDeviceInfo> Enumerate() override { return {}; }
    std::unique_ptr<rtsc::usb::UsbDevice> Open(
        const std::string& instance_id) override {
        auto d = std::make_unique<FakeUsbDevice>();
        d->info_.instance_id = instance_id;
        return d;
    }
};

// Captures every OUT payload the client forwards to the backend and lets the
// test inject the IN response, so the OUT/IN transfer path can be asserted
// byte-for-byte without a real USB device.
class RecordingUsbDevice final : public rtsc::usb::UsbDevice {
 public:
    bool Open() override { return true; }
    void Close() override {}
    const rtsc::usb::UsbDeviceInfo& info() const override { return info_; }
    bool SelectConfiguration(
        const std::vector<rtsc::usb::UsbInterfaceInfo>&,
        uint32_t& configuration_handle) override {
        configuration_handle = 0x10;
        return true;
    }
    bool SelectInterface(uint32_t, const rtsc::usb::UsbInterfaceInfo&,
                         uint32_t& interface_handle) override {
        interface_handle = 0x20;
        return true;
    }
    bool ControlTransfer(uint32_t, uint32_t,
                         const std::vector<uint8_t>& setup,
                         const std::vector<uint8_t>& input,
                         rtsc::usb::UrbResult& result) override {
        control_setups_.push_back(setup);
        control_inputs_.push_back(input);
        result.usbd_status = 0;
        result.output_buffer = control_output_;
        return true;
    }
    bool BulkOrInterruptTransfer(uint32_t, uint32_t,
                                 const std::vector<uint8_t>& input,
                                 uint32_t max_read_size,
                                 rtsc::usb::UrbResult& result) override {
        bulk_inputs_.push_back(input);
        last_max_read_ = max_read_size;
        result.usbd_status = 0;
        result.output_buffer = bulk_output_;
        return true;
    }
    bool ResetPipe(uint32_t) override { return true; }
    bool CancelRequest(uint32_t) override { return true; }
    bool IoControl(uint32_t io_control_code, const std::vector<uint8_t>& input,
                   uint32_t output_buffer_size, std::vector<uint8_t>& output,
                   uint32_t& information, uint32_t& hresult) override {
        io_control_codes_.push_back(io_control_code);
        io_control_inputs_.push_back(input);
        io_control_output_sizes_.push_back(output_buffer_size);
        output = io_control_output_;
        information = io_control_information_;
        hresult = io_control_hresult_;
        return io_control_ok_;
    }

    rtsc::usb::UsbDeviceInfo info_;
    std::vector<std::vector<uint8_t>> control_setups_;
    std::vector<std::vector<uint8_t>> control_inputs_;
    std::vector<std::vector<uint8_t>> bulk_inputs_;
    uint32_t last_max_read_ = 0;
    std::vector<uint8_t> control_output_;
    std::vector<uint8_t> bulk_output_;
    std::vector<uint32_t> io_control_codes_;
    std::vector<std::vector<uint8_t>> io_control_inputs_;
    std::vector<uint32_t> io_control_output_sizes_;
    std::vector<uint8_t> io_control_output_;
    uint32_t io_control_information_ = 0;
    uint32_t io_control_hresult_ = 0;
    bool io_control_ok_ = true;
};

class RecordingEnumerator final : public rtsc::usb::UsbDeviceEnumerator {
 public:
    std::vector<rtsc::usb::UsbDeviceInfo> Enumerate() override { return {}; }
    std::unique_ptr<rtsc::usb::UsbDevice> Open(
        const std::string& instance_id) override {
        auto d = std::make_unique<RecordingUsbDevice>();
        d->info_.instance_id = instance_id;
        last_device = d.get();
        return d;
    }

    RecordingUsbDevice* last_device = nullptr;
};

// The backend cannot open anything: the device is not ready.
class FailingEnumerator final : public rtsc::usb::UsbDeviceEnumerator {
 public:
    std::vector<rtsc::usb::UsbDeviceInfo> Enumerate() override { return {}; }
    std::unique_ptr<rtsc::usb::UsbDevice> Open(
        const std::string& /*instance_id*/) override {
        return nullptr;
    }
};

// Puts a no-callback transport into the ready state: start the caps exchange
// and open the URBDRC control channel.
void MakeUsbClientReady(rtsc::channel::DrdynvcClient& transport,
                        rtsc::channel::RdpUsbClient& client) {
    client.Start();
    const uint32_t control = client.control_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, control,
                           {0, 0, 0, 0}));
    CHECK(client.ready());
}

// Announces one device and opens its device DVC; returns the channel id.
uint32_t OpenRecordingDevice(rtsc::channel::DrdynvcClient& transport,
                             rtsc::channel::RdpUsbClient& client,
                             const char* instance_id) {
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = instance_id;
    CHECK(client.AddDevice(info));
    const uint32_t channel = client.last_device_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, channel,
                           {0, 0, 0, 0}));
    return channel;
}

// Sends one TRANSFER_OUT_REQUEST carrying `function`/`body` and returns the
// completion payload (DYNVC header stripped).
std::vector<uint8_t> SendTransferOut(rtsc::channel::DrdynvcClient& transport,
                                     CapturedSend& cap, uint32_t channel,
                                     rtsc::proto::RdpUsbUrbFunction function,
                                     const std::vector<uint8_t>& body,
                                     uint32_t output_buffer_size,
                                     const std::vector<uint8_t>& data) {
    rtsc::proto::RdpUsbTsUrb urb;
    urb.header.urb_function = function;
    urb.body = body;
    rtsc::proto::RdpUsbTransferOutRequest req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kTransferOutRequest);
    req.ts_urb = urb;
    req.output_buffer_size = output_buffer_size;
    req.output_buffer = data;
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0, channel,
                           req.encode()));
    return DvcPayload(cap.chunks.back());
}

// Sends one TRANSFER_IN_REQUEST carrying `function`/`body` and returns the
// completion payload (DYNVC header stripped).
std::vector<uint8_t> SendTransferIn(rtsc::channel::DrdynvcClient& transport,
                                    CapturedSend& cap, uint32_t channel,
                                    rtsc::proto::RdpUsbUrbFunction function,
                                    const std::vector<uint8_t>& body,
                                    uint32_t output_buffer_size) {
    rtsc::proto::RdpUsbTsUrb urb;
    urb.header.urb_function = function;
    urb.body = body;
    rtsc::proto::RdpUsbTransferInRequest req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kTransferInRequest);
    req.ts_urb = urb;
    req.output_buffer_size = output_buffer_size;
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0, channel,
                           req.encode()));
    return DvcPayload(cap.chunks.back());
}

}  // namespace

RTSC_TEST(rdpusb_client_start_opens_control_channel_and_becomes_ready) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    FakeEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);

    client.Start();
    CHECK_EQ(transport.pending_channels(), static_cast<size_t>(1));
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(1));  // CREATE req

    const uint32_t control = client.control_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                          rtsc::proto::DynvcCmd::kCreate, 0, control,
                          {0, 0, 0, 0}));
    CHECK(client.ready());
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(2));  // + CHANNEL_CREATED
    const std::vector<uint8_t> payload = DvcPayload(cap.chunks[1]);
    rtsc::proto::RdpUsbChannelCreated cc;
    CHECK(rtsc::proto::RdpUsbChannelCreated::parse(payload.data(),
                                                   payload.size(),
                                                   cc) == Status::Ok);
    CHECK_EQ(cc.major_version, static_cast<uint32_t>(1));
}

RTSC_TEST(rdpusb_client_add_device_announces_over_new_channel) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    FakeEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    client.Start();
    const uint32_t control = client.control_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                          rtsc::proto::DynvcCmd::kCreate, 0, control,
                          {0, 0, 0, 0}));
    CHECK(client.ready());

    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1234&PID_5678\\01";
    info.hardware_ids = {"USB\\VID_1234&PID_5678"};
    CHECK(client.AddDevice(info));
    CHECK_EQ(client.add_virtual_channel_count(), static_cast<unsigned>(1));

    const size_t before_device = cap.chunks.size();
    const uint32_t device_channel = client.last_device_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                          rtsc::proto::DynvcCmd::kCreate, 0, device_channel,
                          {0, 0, 0, 0}));
    CHECK_EQ(client.add_device_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.device_count(), static_cast<size_t>(1));
    CHECK(cap.chunks.size() > before_device);
    const std::vector<uint8_t> payload = DvcPayload(cap.chunks.back());
    rtsc::proto::RdpUsbAddDevice add;
    CHECK(rtsc::proto::RdpUsbAddDevice::parse(payload.data(), payload.size(),
                                              add) == Status::Ok);
    CHECK_EQ(add.usb_device, static_cast<uint32_t>(1));
}

RTSC_TEST(rdpusb_client_transfer_in_completes) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    FakeEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    client.Start();
    const uint32_t control = client.control_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                          rtsc::proto::DynvcCmd::kCreate, 0, control,
                          {0, 0, 0, 0}));
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1&PID_1\\0A";
    CHECK(client.AddDevice(info));
    const uint32_t device_channel = client.last_device_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                          rtsc::proto::DynvcCmd::kCreate, 0, device_channel,
                          {0, 0, 0, 0}));
    CHECK_EQ(client.device_count(), static_cast<size_t>(1));
    const size_t before = cap.chunks.size();

    rtsc::proto::RdpUsbTsUrbPipeRequest pipe;
    pipe.pipe_handle = 5;
    rtsc::proto::RdpUsbTsUrb urb;
    urb.header.urb_function = rtsc::proto::RdpUsbUrbFunction::kPipeRequest;
    urb.body = pipe.encode();
    rtsc::proto::RdpUsbTransferInRequest req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kTransferInRequest);
    req.ts_urb = urb;
    req.output_buffer_size = 0;
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                          rtsc::proto::DynvcCmd::kDataFirst, 0, device_channel,
                          req.encode()));

    CHECK_EQ(client.transfer_in_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.urb_completion_count(), static_cast<unsigned>(1));
    CHECK(cap.chunks.size() == before + 1);
    const std::vector<uint8_t> payload = DvcPayload(cap.chunks.back());
    rtsc::proto::RdpUsbUrbCompletionNoData done;
    CHECK(rtsc::proto::RdpUsbUrbCompletionNoData::parse(
              payload.data(), payload.size(), done) == Status::Ok);
    CHECK_EQ(done.request_id, static_cast<uint32_t>(0));
}

RTSC_TEST(rdpusb_client_retract_removes_device) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    FakeEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    client.Start();
    const uint32_t control = client.control_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                          rtsc::proto::DynvcCmd::kCreate, 0, control,
                          {0, 0, 0, 0}));
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1&PID_1\\0A";
    CHECK(client.AddDevice(info));
    const uint32_t device_channel = client.last_device_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                          rtsc::proto::DynvcCmd::kCreate, 0, device_channel,
                          {0, 0, 0, 0}));
    CHECK_EQ(client.device_count(), static_cast<size_t>(1));

    rtsc::proto::RdpUsbRetractDevice retract;
    retract.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    retract.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kRetractDevice);
    retract.reason = 1;
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                          rtsc::proto::DynvcCmd::kDataFirst, 0, device_channel,
                          retract.encode()));

    CHECK_EQ(client.retract_device_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.device_count(), static_cast<size_t>(0));
}

RTSC_TEST(drdynvc_create_channel_def_round_trip) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr, [&](const std::vector<uint8_t>& c) {
        cap.Add(c);
    });
    const rtsc::channel::ChannelDef def{"URBDRC", 0};
    const uint32_t id = t.CreateChannel(def);
    CHECK_EQ(id, static_cast<uint32_t>(1));
    CHECK_EQ(t.pending_channels(), static_cast<size_t>(1));
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(1));
    const std::vector<uint8_t> dvc = DvcPayload(cap.chunks[0]);
    // CREATE payload = null-terminated "URBDRC".
    CHECK_EQ(dvc.size(), static_cast<size_t>(7));
    CHECK_EQ(dvc[0], static_cast<uint8_t>('U'));
    CHECK_EQ(dvc[5], static_cast<uint8_t>('C'));
    CHECK_EQ(dvc[6], static_cast<uint8_t>(0));
}

RTSC_TEST(rdpusb_client_provider_notified_on_add_and_remove) {
    struct Provider final : rtsc::channel::ITvcProvider {
        unsigned added = 0;
        unsigned removed = 0;
        uint32_t last_added = 0;
        uint32_t last_removed = 0;
        void OnDeviceAdded(uint32_t usb_device,
                           const rtsc::usb::UsbDeviceInfo&) override {
            ++added;
            last_added = usb_device;
        }
        void OnDeviceRemoved(uint32_t usb_device) override {
            ++removed;
            last_removed = usb_device;
        }
    } provider;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    FakeEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport, &provider);
    client.Start();
    const uint32_t control = client.control_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, control,
                           {0, 0, 0, 0}));
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1&PID_1\\0A";
    CHECK(client.AddDevice(info));
    CHECK_EQ(provider.added, static_cast<unsigned>(1));
    CHECK_EQ(provider.last_added, static_cast<uint32_t>(1));
    client.RemoveDevice(1);
    CHECK_EQ(provider.removed, static_cast<unsigned>(1));
    CHECK_EQ(provider.last_removed, static_cast<uint32_t>(1));
}

RTSC_TEST(rdpusb_client_out_control_payload_reaches_backend) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1234&PID_5678\\01";
    CHECK(client.AddDevice(info));
    const uint32_t device_channel = client.last_device_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, device_channel,
                           {0, 0, 0, 0}));

    rtsc::proto::RdpUsbTsUrbControlTransfer ctrl;
    ctrl.pipe_handle = 7;
    ctrl.transfer_flags = 0;  // OUT: the data stage carries the payload
    ctrl.setup_packet = {0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00};
    rtsc::proto::RdpUsbTsUrb urb;
    urb.header.urb_function = rtsc::proto::RdpUsbUrbFunction::kControlTransfer;
    urb.body = ctrl.encode();
    rtsc::proto::RdpUsbTransferOutRequest req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kTransferOutRequest);
    req.ts_urb = urb;
    req.output_buffer_size = 4;
    req.output_buffer = {0xDE, 0x0D, 0xBE, 0xEF};
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           device_channel, req.encode()));

    CHECK_EQ(client.transfer_out_count(), static_cast<unsigned>(1));
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device != nullptr) {
        CHECK(!enumerator.last_device->control_inputs_.empty());
        if (!enumerator.last_device->control_inputs_.empty()) {
            CHECK_BYTES(enumerator.last_device->control_inputs_[0], 0xDE, 0x0D,
                        0xBE, 0xEF);
        }
        CHECK(!enumerator.last_device->control_setups_.empty());
        if (!enumerator.last_device->control_setups_.empty()) {
            CHECK_BYTES(enumerator.last_device->control_setups_[0], 0x40, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x04, 0x00);
        }
    }
}

RTSC_TEST(rdpusb_client_out_bulk_payload_reaches_backend) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1&PID_1\\0A";
    CHECK(client.AddDevice(info));
    const uint32_t device_channel = client.last_device_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, device_channel,
                           {0, 0, 0, 0}));

    rtsc::proto::RdpUsbTsUrbBulkOrInterruptTransfer blk;
    blk.pipe_handle = 9;
    blk.transfer_flags = 0;  // OUT
    rtsc::proto::RdpUsbTsUrb urb;
    urb.header.urb_function =
        rtsc::proto::RdpUsbUrbFunction::kBulkOrInterruptTransfer;
    urb.body = blk.encode();
    rtsc::proto::RdpUsbTransferOutRequest req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kTransferOutRequest);
    req.ts_urb = urb;
    req.output_buffer_size = 4;
    req.output_buffer = {0xAA, 0xBB, 0xCC, 0xDD};
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           device_channel, req.encode()));

    CHECK_EQ(client.transfer_out_count(), static_cast<unsigned>(1));
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device != nullptr) {
        CHECK(!enumerator.last_device->bulk_inputs_.empty());
        if (!enumerator.last_device->bulk_inputs_.empty()) {
            CHECK_BYTES(enumerator.last_device->bulk_inputs_[0], 0xAA, 0xBB,
                        0xCC, 0xDD);
        }
    }
}

// [MS-RDPEUSB] 2.2.9.1.1: when TS_URB_HEADER.NoAck is set on a
// TRANSFER_OUT_REQUEST the client must not send a URB_COMPLETION. The transfer
// itself still runs: NoAck suppresses the reply, not the write.
RTSC_TEST(rdpusb_client_no_ack_transfer_out_sends_no_completion) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1&PID_1\\0A";
    CHECK(client.AddDevice(info));
    const uint32_t device_channel = client.last_device_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, device_channel,
                           {0, 0, 0, 0}));

    rtsc::proto::RdpUsbTsUrbBulkOrInterruptTransfer blk;
    blk.pipe_handle = 9;
    blk.transfer_flags = 0;  // OUT
    rtsc::proto::RdpUsbTsUrb urb;
    urb.header.urb_function =
        rtsc::proto::RdpUsbUrbFunction::kBulkOrInterruptTransfer;
    urb.header.no_ack = true;
    urb.body = blk.encode();
    rtsc::proto::RdpUsbTransferOutRequest req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kTransferOutRequest);
    req.ts_urb = urb;
    req.output_buffer_size = 4;
    req.output_buffer = {0x11, 0x22, 0x33, 0x44};
    const size_t before = cap.chunks.size();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           device_channel, req.encode()));

    CHECK_EQ(client.transfer_out_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.urb_completion_count(), static_cast<unsigned>(0));
    CHECK_EQ(client.no_ack_urb_count(), static_cast<unsigned>(1));
    CHECK_EQ(cap.chunks.size(), before);  // no completion frame left the client
    // The write still reached the device backend.
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device != nullptr) {
        CHECK(!enumerator.last_device->bulk_inputs_.empty());
        if (!enumerator.last_device->bulk_inputs_.empty()) {
            CHECK_BYTES(enumerator.last_device->bulk_inputs_[0], 0x11, 0x22,
                        0x33, 0x44);
        }
    }
}

// The paired control case: without NoAck the same request must complete.
RTSC_TEST(rdpusb_client_ack_transfer_out_still_completes) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1&PID_1\\0B";
    CHECK(client.AddDevice(info));
    const uint32_t device_channel = client.last_device_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, device_channel,
                           {0, 0, 0, 0}));

    rtsc::proto::RdpUsbTsUrbBulkOrInterruptTransfer blk;
    blk.pipe_handle = 9;
    blk.transfer_flags = 0;
    rtsc::proto::RdpUsbTsUrb urb;
    urb.header.urb_function =
        rtsc::proto::RdpUsbUrbFunction::kBulkOrInterruptTransfer;
    urb.header.no_ack = false;
    urb.body = blk.encode();
    rtsc::proto::RdpUsbTransferOutRequest req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kTransferOutRequest);
    req.ts_urb = urb;
    req.output_buffer_size = 2;
    req.output_buffer = {0x55, 0x66};
    const size_t before = cap.chunks.size();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           device_channel, req.encode()));

    CHECK_EQ(client.transfer_out_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.urb_completion_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.no_ack_urb_count(), static_cast<unsigned>(0));
    CHECK_EQ(cap.chunks.size(), before + 1);  // exactly one completion frame
}

// [MS-RDPEUSB] 2.2.6.3/2.2.7.1: IO_CONTROL and INTERNAL_IO_CONTROL are
// forwarded to the device and answered with IOCONTROL_COMPLETION carrying the
// same RequestId, the backend HResult/Information and its output bytes.
RTSC_TEST(rdpusb_client_io_control_completes_with_backend_result) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    const uint32_t device_channel =
        OpenRecordingDevice(transport, client, "USB\\VID_2&PID_2\\01");
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device == nullptr) return;
    enumerator.last_device->io_control_output_ = {0xAB, 0xCD};
    enumerator.last_device->io_control_information_ = 2;

    const auto make_request = [&](rtsc::proto::RdpUsbFunction function,
                                  uint32_t request_id) {
        rtsc::proto::RdpUsbIoControl req;
        req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
            rtsc::proto::RdpUsbInterface::kClientDeviceSink,
            rtsc::proto::RdpUsbStreamId::kProxy);
        req.header.function_id = static_cast<uint32_t>(function);
        req.io_control_code = 0x00220004;
        req.input_buffer = {0x01, 0x02};
        req.output_buffer_size = 4;
        req.request_id = request_id;
        return req;
    };

    const size_t before = cap.chunks.size();
    const auto io = make_request(rtsc::proto::RdpUsbFunction::kIoControl, 77);
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           device_channel, io.encode()));
    CHECK_EQ(client.io_control_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.io_control_completion_count(), static_cast<unsigned>(1));
    CHECK_EQ(cap.chunks.size(), before + 1);
    rtsc::proto::RdpUsbIoControlCompletion done;
    const std::vector<uint8_t> payload = DvcPayload(cap.chunks.back());
    CHECK(rtsc::proto::RdpUsbIoControlCompletion::parse(
              payload.data(), payload.size(), done) == Status::Ok);
    CHECK_EQ(done.request_id, static_cast<uint32_t>(77));
    CHECK_EQ(done.hresult, static_cast<uint32_t>(0));
    CHECK_EQ(done.information, static_cast<uint32_t>(2));
    CHECK(done.output_buffer == std::vector<uint8_t>({0xAB, 0xCD}));
    // The backend saw the IOCTL code, input buffer and output size.
    CHECK_EQ(enumerator.last_device->io_control_codes_.size(),
             static_cast<size_t>(1));
    if (!enumerator.last_device->io_control_codes_.empty()) {
        CHECK_EQ(enumerator.last_device->io_control_codes_[0],
                 static_cast<uint32_t>(0x00220004));
    }
    CHECK(!enumerator.last_device->io_control_inputs_.empty());
    if (!enumerator.last_device->io_control_inputs_.empty()) {
        CHECK(enumerator.last_device->io_control_inputs_[0] ==
              std::vector<uint8_t>({0x01, 0x02}));
    }
    CHECK(!enumerator.last_device->io_control_output_sizes_.empty());
    if (!enumerator.last_device->io_control_output_sizes_.empty()) {
        CHECK_EQ(enumerator.last_device->io_control_output_sizes_[0],
                 static_cast<uint32_t>(4));
    }

    // INTERNAL_IO_CONTROL takes the same path and gets its own completion.
    const auto internal = make_request(
        rtsc::proto::RdpUsbFunction::kInternalIoControl, 78);
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           device_channel, internal.encode()));
    CHECK_EQ(client.io_control_count(), static_cast<unsigned>(2));
    CHECK_EQ(client.io_control_completion_count(), static_cast<unsigned>(2));
    rtsc::proto::RdpUsbIoControlCompletion done2;
    const std::vector<uint8_t> payload2 = DvcPayload(cap.chunks.back());
    CHECK(rtsc::proto::RdpUsbIoControlCompletion::parse(
              payload2.data(), payload2.size(), done2) == Status::Ok);
    CHECK_EQ(done2.request_id, static_cast<uint32_t>(78));
}

// An unknown device cannot be serviced, but the server must still get a
// completion or it waits forever.
RTSC_TEST(rdpusb_client_io_control_unknown_device_reports_failure) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    // Open a real device DVC so the message reaches the device dispatcher, but
    // address the IO_CONTROL to a different (unknown) UsbDevice id.
    const uint32_t device_channel =
        OpenRecordingDevice(transport, client, "USB\\VID_5&PID_5\\01");

    rtsc::proto::RdpUsbIoControl req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        static_cast<rtsc::proto::RdpUsbInterface>(99),
        rtsc::proto::RdpUsbStreamId::kProxy);
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kIoControl);
    req.io_control_code = 0x00220004;
    req.output_buffer_size = 4;
    req.request_id = 5;
    const size_t before = cap.chunks.size();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           device_channel, req.encode()));

    CHECK_EQ(client.io_control_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.io_control_completion_count(), static_cast<unsigned>(1));
    CHECK_EQ(cap.chunks.size(), before + 1);
    rtsc::proto::RdpUsbIoControlCompletion done;
    const std::vector<uint8_t> payload = DvcPayload(cap.chunks.back());
    CHECK(rtsc::proto::RdpUsbIoControlCompletion::parse(
              payload.data(), payload.size(), done) == Status::Ok);
    CHECK_EQ(done.request_id, static_cast<uint32_t>(5));
    CHECK(done.hresult != 0);
    CHECK_EQ(done.information, static_cast<uint32_t>(0));
    CHECK(done.output_buffer.empty());
}

// A backend that does not implement device IOCTLs still answers (E_NOTIMPL)
// instead of leaving the server waiting.
RTSC_TEST(rdpusb_client_io_control_default_backend_reports_not_implemented) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    FakeEnumerator enumerator;  // FakeUsbDevice: no IoControl override
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_3&PID_3\\01";
    CHECK(client.AddDevice(info));
    const uint32_t device_channel = client.last_device_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, device_channel,
                           {0, 0, 0, 0}));

    rtsc::proto::RdpUsbIoControl req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kIoControl);
    req.io_control_code = 0x00220004;
    req.output_buffer_size = 4;
    req.request_id = 6;
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           device_channel, req.encode()));

    CHECK_EQ(client.io_control_completion_count(), static_cast<unsigned>(1));
    rtsc::proto::RdpUsbIoControlCompletion done;
    const std::vector<uint8_t> payload = DvcPayload(cap.chunks.back());
    CHECK(rtsc::proto::RdpUsbIoControlCompletion::parse(
              payload.data(), payload.size(), done) == Status::Ok);
    CHECK_EQ(done.hresult, static_cast<uint32_t>(0x80004001));  // E_NOTIMPL
    CHECK(done.output_buffer.empty());
}

// [MS-RDPEUSB] 2.2.6.3: more data than OutputBufferSize terminates the DVC.
RTSC_TEST(rdpusb_client_io_control_overflow_terminates_channel) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    const uint32_t device_channel =
        OpenRecordingDevice(transport, client, "USB\\VID_4&PID_4\\01");
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device == nullptr) return;
    enumerator.last_device->io_control_output_ = {1, 2, 3, 4, 5, 6, 7, 8};

    rtsc::proto::RdpUsbIoControl req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kIoControl);
    req.io_control_code = 0x00220004;
    req.output_buffer_size = 4;
    req.request_id = 7;
    const size_t before = cap.chunks.size();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           device_channel, req.encode()));

    CHECK_EQ(client.io_control_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.io_control_completion_count(), static_cast<unsigned>(0));
    CHECK_EQ(client.io_control_overflow_count(), static_cast<unsigned>(1));
    CHECK_EQ(cap.chunks.size(), before + 1);  // the DYNVC_CLOSE, no completion
    rtsc::proto::DynvcPdu close;
    const std::vector<uint8_t> pdu = cap.chunks.back();
    CHECK(pdu.size() > rtsc::proto::ChannelPduHeader::kSize);
    CHECK(rtsc::proto::DynvcPdu::parse(
              pdu.data() + rtsc::proto::ChannelPduHeader::kSize,
              pdu.size() - rtsc::proto::ChannelPduHeader::kSize,
              close) == Status::Ok);
    CHECK(close.header.cmd == rtsc::proto::DynvcCmd::kClose);
    CHECK_EQ(close.channel_id, device_channel);
}

// [MS-RDPEUSB] 2.2.9.9: GET_DESCRIPTOR is synthesized as
// 0x80/0x06/(type<<8|index)/langId/length and sent through ControlTransfer.
RTSC_TEST(rdpusb_client_control_descriptor_synthesizes_setup) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    const uint32_t device_channel =
        OpenRecordingDevice(transport, client, "USB\\VID_6&PID_6\\01");
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device == nullptr) return;
    enumerator.last_device->control_output_ = {0x04, 0x03, 0x09, 0x04};

    rtsc::proto::RdpUsbTsUrbControlDescriptorRequest desc;
    desc.index = 2;            // string descriptor index (distinct from type)
    desc.descriptor_type = 3;  // USB_STRING_DESCRIPTOR_TYPE
    desc.language_id = 0x0409; // en-US
    const std::vector<uint8_t> payload = SendTransferIn(
        transport, cap, device_channel,
        rtsc::proto::RdpUsbUrbFunction::kControlDescriptorRequest,
        desc.encode(), 255);

    CHECK(!enumerator.last_device->control_setups_.empty());
    if (!enumerator.last_device->control_setups_.empty()) {
        CHECK_BYTES(enumerator.last_device->control_setups_.back(), 0x80, 0x06,
                    0x02, 0x03, 0x09, 0x04, 0xFF, 0x00);
    }
    rtsc::proto::RdpUsbUrbCompletion done;
    CHECK(rtsc::proto::RdpUsbUrbCompletion::parse(
              payload.data(), payload.size(), done) == Status::Ok);
    CHECK(done.output_buffer == std::vector<uint8_t>({0x04, 0x03, 0x09, 0x04}));
    CHECK_EQ(done.hresult, static_cast<uint32_t>(0));
    CHECK_EQ(done.ts_urb_result.size(), static_cast<size_t>(8));
    if (done.ts_urb_result.size() >= 8) {
        CHECK_EQ(done.ts_urb_result[4], static_cast<uint8_t>(0));
        CHECK_EQ(done.ts_urb_result[7], static_cast<uint8_t>(0));
    }
}

// [MS-RDPEUSB] 2.2.9.11: GET_STATUS from the device.
RTSC_TEST(rdpusb_client_control_get_status_synthesizes_setup) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    const uint32_t device_channel =
        OpenRecordingDevice(transport, client, "USB\\VID_7&PID_7\\01");
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device == nullptr) return;
    enumerator.last_device->control_output_ = {0x01, 0x00};

    rtsc::proto::RdpUsbTsUrbControlGetStatusRequest status;
    status.index = 0;
    const std::vector<uint8_t> payload = SendTransferIn(
        transport, cap, device_channel,
        rtsc::proto::RdpUsbUrbFunction::kControlGetStatusRequest,
        status.encode(), 2);

    CHECK(!enumerator.last_device->control_setups_.empty());
    if (!enumerator.last_device->control_setups_.empty()) {
        CHECK_BYTES(enumerator.last_device->control_setups_.back(), 0x80, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x02, 0x00);
    }
    rtsc::proto::RdpUsbUrbCompletion done;
    CHECK(rtsc::proto::RdpUsbUrbCompletion::parse(
              payload.data(), payload.size(), done) == Status::Ok);
    CHECK(done.output_buffer == std::vector<uint8_t>({0x01, 0x00}));
}

// [MS-RDPEUSB] 2.2.9.13: GET_CONFIGURATION has no URB body; the length comes
// from the TRANSFER_IN_REQUEST OutputBufferSize.
RTSC_TEST(rdpusb_client_control_get_configuration_synthesizes_setup) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    const uint32_t device_channel =
        OpenRecordingDevice(transport, client, "USB\\VID_8&PID_8\\01");
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device == nullptr) return;
    enumerator.last_device->control_output_ = {0x01};

    const std::vector<uint8_t> payload = SendTransferIn(
        transport, cap, device_channel,
        rtsc::proto::RdpUsbUrbFunction::kControlGetConfigurationRequest, {}, 1);

    CHECK(!enumerator.last_device->control_setups_.empty());
    if (!enumerator.last_device->control_setups_.empty()) {
        CHECK_BYTES(enumerator.last_device->control_setups_.back(), 0x80, 0x08,
                    0x00, 0x00, 0x00, 0x00, 0x01, 0x00);
    }
    rtsc::proto::RdpUsbUrbCompletion done;
    CHECK(rtsc::proto::RdpUsbUrbCompletion::parse(
              payload.data(), payload.size(), done) == Status::Ok);
    CHECK(done.output_buffer == std::vector<uint8_t>({0x01}));
}

// [MS-RDPEUSB] 2.2.9.14: GET_INTERFACE uses bmRequestType 0x81 and wIndex=the
// interface number.
RTSC_TEST(rdpusb_client_control_get_interface_synthesizes_setup) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    const uint32_t device_channel =
        OpenRecordingDevice(transport, client, "USB\\VID_9&PID_9\\01");
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device == nullptr) return;
    enumerator.last_device->control_output_ = {0x02};

    rtsc::proto::RdpUsbTsUrbControlGetInterfaceRequest get_iface;
    get_iface.interface = 2;
    const std::vector<uint8_t> payload = SendTransferIn(
        transport, cap, device_channel,
        rtsc::proto::RdpUsbUrbFunction::kControlGetInterfaceRequest,
        get_iface.encode(), 1);

    CHECK(!enumerator.last_device->control_setups_.empty());
    if (!enumerator.last_device->control_setups_.empty()) {
        CHECK_BYTES(enumerator.last_device->control_setups_.back(), 0x81, 0x0A,
                    0x00, 0x00, 0x02, 0x00, 0x01, 0x00);
    }
    rtsc::proto::RdpUsbUrbCompletion done;
    CHECK(rtsc::proto::RdpUsbUrbCompletion::parse(
              payload.data(), payload.size(), done) == Status::Ok);
    CHECK(done.output_buffer == std::vector<uint8_t>({0x02}));
}

// [MS-RDPEUSB] 2.2.9.10: SET_FEATURE_TO_DEVICE (0x000D) is a device-recipient
// standard request with no data stage.
RTSC_TEST(rdpusb_client_control_set_feature_synthesizes_setup) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    const uint32_t device_channel =
        OpenRecordingDevice(transport, client, "USB\\VID_10&PID_10\\01");
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device == nullptr) return;

    rtsc::proto::RdpUsbTsUrbControlFeatureRequest feat;
    feat.feature_selector = 1;  // DEVICE_REMOTE_WAKEUP
    feat.index = 0;
    const std::vector<uint8_t> payload = SendTransferIn(
        transport, cap, device_channel,
        rtsc::proto::RdpUsbUrbFunction::kControlFeatureRequest, feat.encode(),
        0);

    CHECK(!enumerator.last_device->control_setups_.empty());
    if (!enumerator.last_device->control_setups_.empty()) {
        CHECK_BYTES(enumerator.last_device->control_setups_.back(), 0x00, 0x03,
                    0x01, 0x00, 0x00, 0x00, 0x00, 0x00);
    }
    rtsc::proto::RdpUsbUrbCompletionNoData done;
    CHECK(rtsc::proto::RdpUsbUrbCompletionNoData::parse(
              payload.data(), payload.size(), done) == Status::Ok);
    CHECK_EQ(done.ts_urb_result.size(), static_cast<size_t>(8));
    if (done.ts_urb_result.size() >= 8) {
        CHECK_EQ(done.ts_urb_result[7], static_cast<uint8_t>(0));
    }
}

// [MS-RDPEUSB] 2.2.9.12: vendor/class request, OUT direction (TransferFlags
// bit 0 clear). The data stage comes from the TRANSFER_OUT_REQUEST buffer.
RTSC_TEST(rdpusb_client_control_vendor_out_uses_data_stage) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    const uint32_t device_channel =
        OpenRecordingDevice(transport, client, "USB\\VID_11&PID_11\\01");
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device == nullptr) return;

    rtsc::proto::RdpUsbTsUrbControlVendorOrClassRequest vendor;
    vendor.transfer_flags = 0;  // OUT
    vendor.request = 0x42;
    vendor.value = 0x1234;
    vendor.index = 0x5678;
    const std::vector<uint8_t> payload = SendTransferOut(
        transport, cap, device_channel,
        rtsc::proto::RdpUsbUrbFunction::kControlVendorOrClassRequest,
        vendor.encode(), 2, {0xAA, 0xBB});

    CHECK(!enumerator.last_device->control_setups_.empty());
    if (!enumerator.last_device->control_setups_.empty()) {
        CHECK_BYTES(enumerator.last_device->control_setups_.back(), 0x40, 0x42,
                    0x34, 0x12, 0x78, 0x56, 0x02, 0x00);
    }
    CHECK(!enumerator.last_device->control_inputs_.empty());
    if (!enumerator.last_device->control_inputs_.empty()) {
        CHECK_BYTES(enumerator.last_device->control_inputs_.back(), 0xAA, 0xBB);
    }
    rtsc::proto::RdpUsbUrbCompletionNoData done;
    CHECK(rtsc::proto::RdpUsbUrbCompletionNoData::parse(
              payload.data(), payload.size(), done) == Status::Ok);
}

// [MS-RDPEUSB] 2.2.9.12: vendor/class request, IN direction (TransferFlags
// bit 0 set) adds 0x80 to bmRequestType and returns the device data.
RTSC_TEST(rdpusb_client_control_vendor_in_sets_direction_bit) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    const uint32_t device_channel =
        OpenRecordingDevice(transport, client, "USB\\VID_12&PID_12\\01");
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device == nullptr) return;
    enumerator.last_device->control_output_ = {0x99};

    rtsc::proto::RdpUsbTsUrbControlVendorOrClassRequest vendor;
    vendor.transfer_flags = 1;  // IN
    vendor.request = 0x43;
    vendor.value = 0x0001;
    vendor.index = 0;
    const std::vector<uint8_t> payload = SendTransferIn(
        transport, cap, device_channel,
        rtsc::proto::RdpUsbUrbFunction::kControlVendorOrClassRequest,
        vendor.encode(), 1);

    CHECK(!enumerator.last_device->control_setups_.empty());
    if (!enumerator.last_device->control_setups_.empty()) {
        CHECK_BYTES(enumerator.last_device->control_setups_.back(), 0xC0, 0x43,
                    0x01, 0x00, 0x00, 0x00, 0x01, 0x00);
    }
    rtsc::proto::RdpUsbUrbCompletion done;
    CHECK(rtsc::proto::RdpUsbUrbCompletion::parse(
              payload.data(), payload.size(), done) == Status::Ok);
    CHECK(done.output_buffer == std::vector<uint8_t>({0x99}));
}

RTSC_TEST(rdpusb_client_in_truncated_to_output_buffer_size) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    RecordingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1&PID_1\\0A";
    CHECK(client.AddDevice(info));
    const uint32_t device_channel = client.last_device_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, device_channel,
                           {0, 0, 0, 0}));
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device != nullptr) {
        enumerator.last_device->bulk_output_ = {0x01, 0x02, 0x03, 0x04, 0x05};
    }
    const size_t before = cap.chunks.size();

    rtsc::proto::RdpUsbTsUrbBulkOrInterruptTransfer blk;
    blk.pipe_handle = 9;
    blk.transfer_flags = rtsc::proto::kRdpUsbTransferDirection;  // IN
    rtsc::proto::RdpUsbTsUrb urb;
    urb.header.urb_function =
        rtsc::proto::RdpUsbUrbFunction::kBulkOrInterruptTransfer;
    urb.body = blk.encode();
    rtsc::proto::RdpUsbTransferInRequest req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kProxy);
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kTransferInRequest);
    req.ts_urb = urb;
    req.output_buffer_size = 2;
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           device_channel, req.encode()));

    CHECK_EQ(client.transfer_in_count(), static_cast<unsigned>(1));
    CHECK(cap.chunks.size() == before + 1);
    if (cap.chunks.size() != before + 1) return;
    const std::vector<uint8_t> payload = DvcPayload(cap.chunks.back());
    rtsc::proto::RdpUsbUrbCompletion done;
    CHECK(rtsc::proto::RdpUsbUrbCompletion::parse(payload.data(),
                                                  payload.size(), done) ==
          rtsc::proto::Status::Ok);
    CHECK_BYTES(done.output_buffer, 0x01, 0x02);
    // The backend read buffer is capped at the requested size.
    CHECK(enumerator.last_device != nullptr);
    if (enumerator.last_device != nullptr) {
        CHECK_EQ(enumerator.last_device->last_max_read_,
                 static_cast<uint32_t>(2));
    }
}

RTSC_TEST(rdpusb_client_unknown_device_still_completes) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    FakeEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    CHECK_EQ(client.device_count(), static_cast<size_t>(0));
    // A dynamic channel that was never announced carries the stray request.
    const uint32_t stray_channel = transport.CreateChannel("URBDRC");
    const size_t before = cap.chunks.size();

    rtsc::proto::RdpUsbTsUrbPipeRequest pipe;
    pipe.pipe_handle = 5;
    rtsc::proto::RdpUsbTsUrb urb;
    urb.header.urb_function = rtsc::proto::RdpUsbUrbFunction::kPipeRequest;
    urb.body = pipe.encode();
    rtsc::proto::RdpUsbTransferInRequest req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kStub);  // raw, non-proxy stream id
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kTransferInRequest);
    req.ts_urb = urb;
    req.output_buffer_size = 0;
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           stray_channel, req.encode()));

    CHECK_EQ(client.transfer_in_count(), static_cast<unsigned>(1));
    // The unknown device must still receive a completion (never a silent drop).
    CHECK(cap.chunks.size() == before + 1);
    if (cap.chunks.size() != before + 1) return;
    const std::vector<uint8_t> payload = DvcPayload(cap.chunks.back());
    rtsc::proto::RdpUsbUrbCompletionNoData done;
    CHECK(rtsc::proto::RdpUsbUrbCompletionNoData::parse(payload.data(),
                                                        payload.size(),
                                                        done) ==
          rtsc::proto::Status::Ok);
    // The interface id echoes the request verbatim, stream bits included.
    CHECK_EQ(done.header.interface_id,
             static_cast<uint32_t>(rtsc::proto::RdpUsbHeader::MakeInterfaceId(
                 rtsc::proto::RdpUsbInterface::kClientDeviceSink,
                 rtsc::proto::RdpUsbStreamId::kStub)));
    // The result header reports the failure instead of a fabricated success.
    rtsc::proto::RdpUsbTsUrbResultHeader rh;
    CHECK(rtsc::proto::RdpUsbTsUrbResultHeader::parse(
              done.ts_urb_result.data(), done.ts_urb_result.size(), rh) ==
          rtsc::proto::Status::Ok);
    CHECK_EQ(rh.usbd_status,
             static_cast<uint32_t>(
                 rtsc::proto::RdpUsbUsbdStatus::kRequestFailed));
}

RTSC_TEST(rdpusb_client_add_device_skips_unopenable_device) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    FailingEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    const size_t before = cap.chunks.size();

    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1&PID_1\\0A";
    CHECK(!client.AddDevice(info));
    // The backend failed to open the device: it is not announced at all.
    CHECK_EQ(client.device_count(), static_cast<size_t>(0));
    CHECK_EQ(client.add_virtual_channel_count(), static_cast<unsigned>(0));
    CHECK(cap.chunks.size() == before);
}

RTSC_TEST(rdpusb_client_completion_echoes_request_interface_id) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    FakeEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport);
    MakeUsbClientReady(transport, client);
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1&PID_1\\0A";
    CHECK(client.AddDevice(info));
    const uint32_t device_channel = client.last_device_channel();
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, device_channel,
                           {0, 0, 0, 0}));
    const size_t before = cap.chunks.size();

    rtsc::proto::RdpUsbTsUrbPipeRequest pipe;
    pipe.pipe_handle = 5;
    rtsc::proto::RdpUsbTsUrb urb;
    urb.header.urb_function = rtsc::proto::RdpUsbUrbFunction::kPipeRequest;
    urb.body = pipe.encode();
    rtsc::proto::RdpUsbTransferInRequest req;
    req.header.interface_id = rtsc::proto::RdpUsbHeader::MakeInterfaceId(
        rtsc::proto::RdpUsbInterface::kClientDeviceSink,
        rtsc::proto::RdpUsbStreamId::kStub);  // 0x80000001, not kProxy
    req.header.function_id =
        static_cast<uint32_t>(rtsc::proto::RdpUsbFunction::kTransferInRequest);
    req.ts_urb = urb;
    req.output_buffer_size = 0;
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           device_channel, req.encode()));

    CHECK(cap.chunks.size() == before + 1);
    if (cap.chunks.size() != before + 1) return;
    const std::vector<uint8_t> payload = DvcPayload(cap.chunks.back());
    rtsc::proto::RdpUsbUrbCompletionNoData done;
    CHECK(rtsc::proto::RdpUsbUrbCompletionNoData::parse(payload.data(),
                                                        payload.size(),
                                                        done) ==
          rtsc::proto::Status::Ok);
    // The stub stream id must not be rewritten to kProxy.
    CHECK_EQ(done.header.interface_id,
             static_cast<uint32_t>(rtsc::proto::RdpUsbHeader::MakeInterfaceId(
                 rtsc::proto::RdpUsbInterface::kClientDeviceSink,
                 rtsc::proto::RdpUsbStreamId::kStub)));
}

RTSC_TEST(drdynvc_bundled_pdus_in_one_static_message_all_consumed) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr, [&](const std::vector<uint8_t>& c) {
        cap.Add(c);
    });
    const uint32_t id1 = t.CreateChannel("URBDRC");
    const uint32_t id2 = t.CreateChannel("URBDRC");
    CHECK_EQ(t.pending_channels(), static_cast<size_t>(2));

    // Two DYNVC_CREATE_RSP PDUs bundled into one static channel message
    // ([MS-RDPEDYC] 2.2.2.2): a server that opened several dynamic channels
    // quickly can coalesce them. Each response is exactly
    // header + ChannelId + CreationStatus(4) - there is NO channel name in
    // the response, so the PDU boundary is fixed and must not depend on a
    // NUL terminator.
    std::vector<uint8_t> bundle;
    for (const uint32_t id : {id1, id2}) {
        const auto pdu = rtsc::proto::BuildDynvcPdu(
            rtsc::proto::DynvcCmd::kCreate, 0, id, {0, 0, 0, 0});
        bundle.insert(bundle.end(), pdu.begin(), pdu.end());
    }
    FeedDvc(t, bundle);

    CHECK_EQ(t.create_response_count(), static_cast<unsigned>(2));
    CHECK_EQ(t.pending_channels(), static_cast<size_t>(0));
}

RTSC_TEST(drdynvc_bundled_caps_v1_then_create_response) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr, [&](const std::vector<uint8_t>& c) {
        cap.Add(c);
    });
    const uint32_t id = t.CreateChannel("URBDRC");

    // DYNVC_CAPS VERSION1 ([MS-RDPEDYC] 2.2.1.1.1) = header + Pad + Version
    // (4 bytes), followed by a CREATE_RSP in the same static message.
    std::vector<uint8_t> bundle = {0x50, 0x00, 0x01, 0x00};
    const auto rsp = rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kCreate,
                                                0, id, {0, 0, 0, 0});
    bundle.insert(bundle.end(), rsp.begin(), rsp.end());
    FeedDvc(t, bundle);

    CHECK_EQ(t.version(), static_cast<uint16_t>(1));
    CHECK(t.ready());
    CHECK_EQ(t.create_response_count(), static_cast<unsigned>(1));
    CHECK_EQ(t.pending_channels(), static_cast<size_t>(0));
}

RTSC_TEST(drdynvc_bundled_caps_v2_then_create_response) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr, [&](const std::vector<uint8_t>& c) {
        cap.Add(c);
    });
    const uint32_t id = t.CreateChannel("URBDRC");

    // DYNVC_CAPS VERSION2 ([MS-RDPEDYC] 2.2.1.1.2) = header + Pad + Version +
    // PriorityCharge0..3 (8 bytes) = 12 bytes, followed by a CREATE_RSP. The
    // bundling consumer must size the capability PDU by its version, not by a
    // fixed 4 bytes, or the following CREATE_RSP is misparsed.
    std::vector<uint8_t> bundle = {0x50, 0x00, 0x02, 0x00,
                                   0x01, 0x00, 0x02, 0x00,
                                   0x03, 0x00, 0x04, 0x00};
    const auto rsp = rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kCreate,
                                                0, id, {0, 0, 0, 0});
    bundle.insert(bundle.end(), rsp.begin(), rsp.end());
    FeedDvc(t, bundle);

    CHECK_EQ(t.version(), static_cast<uint16_t>(2));
    CHECK(t.ready());
    CHECK_EQ(t.create_response_count(), static_cast<unsigned>(1));
    CHECK_EQ(t.pending_channels(), static_cast<size_t>(0));
}

RTSC_TEST(rdpusb_win32_control_transfer_copies_out_input) {
    // W11 repair batch: the WinUSB ControlTransfer used to allocate a
    // zero-initialised buffer for the OUT data stage and never copy `input`
    // into it, so every OUT control payload was sent as N zero bytes. The
    // WinUSB call has no test seam, so this pins the wiring at the source
    // level: the ControlTransfer body must copy `input`. Removing that copy
    // is a red mutation. RTSC_SOURCE_DIR is provided by CMake.
#ifdef RTSC_SOURCE_DIR
    const std::filesystem::path src =
        std::filesystem::path(RTSC_SOURCE_DIR) / "src" / "usb" / "usb_win32.cpp";
    std::ifstream in(src, std::ios::binary);
    CHECK(in.is_open());
    if (!in.is_open()) {
        std::printf("  FAIL: cannot open %s\n", src.string().c_str());
        return;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);

    const size_t ctrl = FindLineIn(lines, "bool ControlTransfer");
    const size_t bulk = FindLineIn(lines, "bool BulkOrInterruptTransfer");
    CHECK(ctrl != std::string::npos);
    CHECK(bulk != std::string::npos);
    if (ctrl != std::string::npos && bulk != std::string::npos) {
        bool copied = false;
        for (size_t i = ctrl + 1; i < bulk; ++i) {
            if (lines[i].find("buffer.assign(input") != std::string::npos ||
                lines[i].find("std::copy(input") != std::string::npos) {
                copied = true;
            }
        }
        CHECK(copied);
    }
#else
    std::printf(
        "  FAIL: RTSC_SOURCE_DIR not defined; cannot locate usb_win32.cpp\n");
    CHECK(false);
#endif
}

RTSC_TEST(gui_main_advertises_drdynvc_only_when_needed) {
    // The GUI must not advertise the "drdynvc" static virtual channel unless
    // something needs the dynamic-channel transport: USB redirection
    // (RTSC_REDIRECT_USB) or dynamic display resize (--disp). The drdynvc
    // name may only appear in a channel_names assignment that is gated behind
    // those two flags.
#ifdef RTSC_SOURCE_DIR
    const std::filesystem::path src =
        std::filesystem::path(RTSC_SOURCE_DIR) / "tools" / "rtsc_gui" /
        "main.cpp";
    std::ifstream in(src, std::ios::binary);
    CHECK(in.is_open());
    if (!in.is_open()) {
        std::printf("  FAIL: cannot open %s\n", src.string().c_str());
        return;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);

    bool assignment_has_drdynvc = false;
    for (const std::string& l : lines) {
        if (l.find("channel_names") != std::string::npos &&
            l.find("\"drdynvc\"") != std::string::npos) {
            assignment_has_drdynvc = true;
        }
    }
    const size_t call = FindLineIn(lines, "BuildStaticChannelNames(");
    const size_t gate = FindLineIn(lines, "usb_redirect || disp_enabled");
    CHECK(!assignment_has_drdynvc);
    CHECK(call != std::string::npos);
    CHECK(gate != std::string::npos);
    if (call != std::string::npos && gate != std::string::npos) {
        // The dynamic-channel argument must sit at or after the builder call
        // (the list itself is assembled in BuildStaticChannelNames).
        CHECK(gate >= call);
    }
#else
    std::printf("  FAIL: RTSC_SOURCE_DIR not defined; cannot locate main.cpp\n");
    CHECK(false);
#endif
}

// The RTSC_REDIRECT_USB gate: an unset OR empty spec disables USB redirection
// (the GUI used to treat RTSC_REDIRECT_USB= as "on", advertising the drdynvc
// channel for a redirect that shares nothing).
RTSC_TEST(usb_gate_enabled_semantics) {
    CHECK(!rtsc::usb::UsbGateEnabled(nullptr));
    CHECK(!rtsc::usb::UsbGateEnabled(""));
    CHECK(rtsc::usb::UsbGateEnabled("ALL"));
    CHECK(rtsc::usb::UsbGateEnabled("1234:5678"));
    CHECK(rtsc::usb::UsbGateEnabled(" 1234 : 5678 , 90ab:cdef "));
}

// W11 wrap-up: the GUI's privacy notice must never overstate what is actually
// shared with the remote peer. It reports the number of devices the backend
// actually redirected (usb_devices_added_count), never the gate-matched
// candidates (usb_matched) - AddDevice can fail to open a device, so the claim
// "the remote peer can access ..." is printed only after every announcement.
// The two fallbacks ("none could be opened" for a matched-but-unopened set,
// "no device matched the gate" for an empty match) must stay in their own
// printf statements. Printing the notice before AddDevice, citing usb_matched,
// or merging/swapping the fallbacks is a red mutation.
RTSC_TEST(gui_main_usb_privacy_notice_uses_actual_redirected_count) {
#ifdef RTSC_SOURCE_DIR
    const std::filesystem::path src =
        std::filesystem::path(RTSC_SOURCE_DIR) / "tools" / "rtsc_gui" /
        "main.cpp";
    std::ifstream in(src, std::ios::binary);
    CHECK(in.is_open());
    if (!in.is_open()) {
        std::printf("  FAIL: cannot open %s\n", src.string().c_str());
        return;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);

    const size_t notice = FindLineIn(lines, "the remote peer can");
    const size_t add_device = FindLineIn(lines, "rdpusb->AddDevice(device)");
    CHECK(notice != std::string::npos);
    CHECK(add_device != std::string::npos);
    if (notice != std::string::npos && add_device != std::string::npos) {
        // The notice comes after every announcement, never before one.
        CHECK(add_device < notice);
    }
    // The notice statement must cite the actual redirected count, never the
    // gate-matched candidate count. The scan runs from the notice string to
    // the printf terminator (the first line ending with ");").
    if (notice != std::string::npos) {
        bool used_added = false;
        bool used_matched = false;
        for (size_t i = notice;
             i < lines.size() && lines[i].find(");") == std::string::npos;
             ++i) {
            if (lines[i].find("usb_devices_added_count") != std::string::npos) {
                used_added = true;
            }
            if (lines[i].find("usb_matched") != std::string::npos) {
                used_matched = true;
            }
        }
        CHECK(used_added);
        CHECK(!used_matched);
    }
    // The two fallback branches must stay distinct. "none could be opened"
    // (matched > 0 but every open failed) is the matched>0 branch and must
    // precede "no device matched the gate" (matched == 0). Their string
    // literals are split across two source lines, so each token is matched as
    // a head fragment on one line plus the tail fragment on the next. Each
    // token must sit in its own std::printf: a merged branch puts both under
    // one printf, a swapped branch breaks the head/tail pairing and inverts
    // their order.
    const auto find_split = [&](const char* head, const char* tail) -> size_t {
        for (size_t i = 0; i + 1 < lines.size(); ++i) {
            if (lines[i].find(head) != std::string::npos &&
                lines[i + 1].find(tail) != std::string::npos) {
                return i;
            }
        }
        return std::string::npos;
    };
    const size_t none_opened = find_split("none could ", "be opened;");
    const size_t no_match = find_split("no device matched ", "the gate;");
    CHECK(none_opened != std::string::npos);
    CHECK(no_match != std::string::npos);
    if (none_opened != std::string::npos &&
        no_match != std::string::npos) {
        CHECK(none_opened != no_match);  // different lines, not one merged line
        // The matched>0 fallback precedes the matched==0 fallback.
        CHECK(none_opened < no_match);
        // Each token is enclosed by a different std::printf statement.
        const auto printf_start_of = [&](size_t token_line) -> size_t {
            size_t i = token_line;
            while (i > 0 &&
                   lines[i].find("std::printf(") == std::string::npos) {
                --i;
            }
            return i;
        };
        CHECK(printf_start_of(none_opened) != printf_start_of(no_match));
    }
#else
    std::printf("  FAIL: RTSC_SOURCE_DIR not defined; cannot locate main.cpp\n");
    CHECK(false);
#endif
}

// W11 wrap-up: usb_spec_storage must be released by RAII (a manual
// std::free after the render loop leaked on the early Connect-failure return).
RTSC_TEST(gui_main_usb_spec_released_by_raii) {
#ifdef RTSC_SOURCE_DIR
    const std::filesystem::path src =
        std::filesystem::path(RTSC_SOURCE_DIR) / "tools" / "rtsc_gui" /
        "main.cpp";
    std::ifstream in(src, std::ios::binary);
    CHECK(in.is_open());
    if (!in.is_open()) {
        std::printf("  FAIL: cannot open %s\n", src.string().c_str());
        return;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);

    const size_t raii = FindLineIn(lines, "decltype(&std::free)");
    CHECK(raii != std::string::npos);
    // A manual free that can be skipped by an early return must not remain.
    const size_t manual_free = FindLineIn(lines, "std::free(usb_spec_storage)");
    CHECK(manual_free == std::string::npos);
#else
    std::printf("  FAIL: RTSC_SOURCE_DIR not defined; cannot locate main.cpp\n");
    CHECK(false);
#endif
}

RTSC_TEST(drdynvc_create_response_failure_clears_pending) {
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(nullptr, [&](const std::vector<uint8_t>& c) {
        cap.Add(c);
    });
    const uint32_t id = t.CreateChannel("URBDRC");
    CHECK_EQ(t.pending_channels(), static_cast<size_t>(1));

    // DYNVC_CREATE_RSP with a non-zero Status: the channel never opens, so the
    // request must not stay pending forever.
    const auto rsp = rtsc::proto::BuildDynvcPdu(rtsc::proto::DynvcCmd::kCreate,
                                                0, id, {1, 0, 0, 0});
    FeedDvc(t, rsp);

    CHECK_EQ(t.create_response_count(), static_cast<unsigned>(1));
    CHECK_EQ(t.pending_channels(), static_cast<size_t>(0));
}

RTSC_TEST(drdynvc_caps_response_version2_with_charges) {
    struct Listener final : rtsc::channel::IDrdynvcListener {
        uint16_t version = 0;
        void OnCapsResponse(uint16_t v) override { version = v; }
    } listener;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient t(&listener,
                                   [&](const std::vector<uint8_t>& c) {
                                       cap.Add(c);
                                   });
    // DYNVC_CAPS_VERSION2 ([MS-RDPEDYC] 2.2.1.1.2): header + Pad + Version +
    // PriorityCharge0..3 (optional tail for VERSION1 parsing).
    const std::vector<uint8_t> rsp = {0x50, 0x00, 0x02, 0x00,
                                      0x01, 0x00, 0x02, 0x00,
                                      0x03, 0x00, 0x04, 0x00};
    FeedDvc(t, rsp);
    CHECK_EQ(listener.version, static_cast<uint16_t>(2));
    CHECK(t.ready());
}

RTSC_TEST(rdpusb_pipe_information_exactly_12_bytes_parses) {
    // TS_USBD_PIPE_INFORMATION ([MS-RDPEUSB] 2.2.9.1.3) is 12 bytes:
    // MaximumPacketSize(2) + Padding(2) + MaximumTransferSize(4) + PipeFlags(4).
    // Regression: the parse guard used to require 16 bytes, so a pipe with no
    // trailing bytes failed.
    rtsc::proto::RdpUsbTsUsbdPipeInformation pipe;
    pipe.maximum_packet_size = 8;
    pipe.maximum_transfer_size = 64;
    pipe.pipe_flags = 0;
    rtsc::proto::ByteWriter w;
    pipe.write(w);
    CHECK_EQ(w.size(), static_cast<size_t>(12));
    rtsc::proto::RdpUsbTsUsbdPipeInformation out;
    CHECK(rtsc::proto::RdpUsbTsUsbdPipeInformation::parse(
              w.data().data(), w.data().size(), out) == Status::Ok);
    CHECK_EQ(out.maximum_packet_size, static_cast<uint16_t>(8));
    CHECK_EQ(out.maximum_transfer_size, static_cast<uint32_t>(64));
}

RTSC_TEST(rdpusb_select_configuration_without_descriptor_parses) {
    // A SELECT_CONFIGURATION whose interface has exactly one 12-byte pipe and
    // no configuration descriptor must parse (regression for the 16-byte
    // pipe guard).
    rtsc::proto::RdpUsbTsUsbdInterfaceInformation iface;
    iface.interface_number = 0;
    rtsc::proto::RdpUsbTsUsbdPipeInformation pipe;
    pipe.maximum_packet_size = 64;
    iface.pipes = {pipe};
    rtsc::proto::RdpUsbTsUrbSelectConfiguration sel;
    sel.num_interfaces = 1;
    sel.interfaces = {iface};
    const std::vector<uint8_t> body = sel.encode();
    rtsc::proto::RdpUsbTsUrbSelectConfiguration out;
    CHECK(rtsc::proto::RdpUsbTsUrbSelectConfiguration::parse(
              body.data(), body.size(), out) == Status::Ok);
    CHECK_EQ(out.interfaces.size(), static_cast<size_t>(1));
    if (!out.interfaces.empty()) {
        CHECK_EQ(out.interfaces[0].pipes.size(), static_cast<size_t>(1));
    }
}

// After a reconnect the dynamic channels are gone. Reset() must drop the
// capability state, channel ids and announced devices, and notify the provider;
// a later Start() runs the capability exchange again.
RTSC_TEST(rdpusb_client_reset_drops_session_state) {
    struct Provider final : rtsc::channel::ITvcProvider {
        unsigned removed = 0;
        uint32_t last_removed = 0;
        void OnDeviceRemoved(uint32_t usb_device) override {
            ++removed;
            last_removed = usb_device;
        }
    } provider;
    CapturedSend cap;
    rtsc::channel::DrdynvcClient transport(nullptr,
                                           [&](const std::vector<uint8_t>& c) {
                                               cap.Add(c);
                                           });
    FakeEnumerator enumerator;
    rtsc::channel::RdpUsbClient client(&enumerator, &transport, &provider);
    MakeUsbClientReady(transport, client);
    rtsc::usb::UsbDeviceInfo info;
    info.instance_id = "USB\\VID_1&PID_1\\0A";
    CHECK(client.AddDevice(info));
    CHECK_EQ(client.device_count(), static_cast<size_t>(1));

    client.Reset();
    CHECK(!client.started());
    CHECK(!client.ready());
    CHECK_EQ(client.control_channel(), static_cast<uint32_t>(0));
    CHECK_EQ(client.device_count(), static_cast<size_t>(0));
    CHECK_EQ(provider.removed, static_cast<unsigned>(1));
    CHECK_EQ(provider.last_removed, static_cast<uint32_t>(1));

    // The new session re-runs the capability exchange.
    cap.chunks.clear();
    client.Start();
    CHECK(client.started());
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(1));
    const uint32_t control = client.control_channel();
    CHECK(control != 0);
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, control,
                           {0, 0, 0, 0}));
    CHECK(client.ready());
}

int main() { return ::rtsc::test::run_all("rtsc_rdpusb_tests"); }
