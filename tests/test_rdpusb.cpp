// RDP USB redirection (URBDRC) wire structures ([MS-RDPEUSB] 2.2) and the
// drdynvc transport ([MS-RDPEDYC] 2.2).

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "rtsc/channel/drdynvc_client.h"
#include "rtsc/channel/rdpusb_client.h"
#include "rtsc/proto/channel.h"
#include "rtsc/proto/drdynvc.h"
#include "rtsc/proto/rdpusb.h"
#include "rtsc/usb/usb_device.h"
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
};

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
    // DYNVC_CAPS_RSP ([MS-RDPEDYC] 2.2.1.2) VERSION1 = header + Pad + Version.
    const std::vector<uint8_t> rsp = {0x50, 0x00, 0x02, 0x00};
    FeedDvc(t, rsp);
    CHECK_EQ(listener.version, static_cast<uint16_t>(2));
    CHECK(t.ready());
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
                                 const std::vector<uint8_t>&,
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

int main() { return ::rtsc::test::run_all("rtsc_rdpusb_tests"); }
