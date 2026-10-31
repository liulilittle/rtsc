// GUI send path: input and static virtual channels through the application
// data plane.
//
// The GUI used to reach into ConnectionDriver::security() directly, which is
// null under Standard RDP Security (PROTOCOL_RDP). Input and channel messages
// were therefore silently dropped on that path. These tests exercise the same
// Client methods the GUI calls, against the in-tree RDP server over
// PROTOCOL_RDP, and prove that both cross the wire (the server's input callback
// observes the event; the recorded transport shows the MCS channel id).

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "rtsc/channel/drdynvc_client.h"
#include "rtsc/channel/rdpusb_client.h"
#include "rtsc/client/client.h"
#include "rtsc/net/transport.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/server/server.h"
#include "rtsc/ui/window.h"
#include "rtsc/usb/usb_device.h"
#include "test_framework.h"
#include "test_main.h"

namespace {

[[maybe_unused]] rtsc::security::ConnectionDriver MakeGuiDriver() {
    rtsc::proto::ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.requested_protocols = rtsc::proto::kProtocolRdp;
    mcfg.client_name = "RTSC";
    // Mirrors tools/rtsc_gui/main.cpp: the URBDRC extension rides on the
    // drdynvc static virtual channel, so it is always advertised.
    mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd", "drdynvc"};
    mcfg.encryption_methods = 0x0000001B;

    rtsc::proto::ConnectMachine::Credentials creds;
    creds.domain = "NTDEV";
    creds.user_name = "rtsc";

    rtsc::security::Config scfg;  // unused by Standard RDP Security
    return rtsc::security::ConnectionDriver(mcfg, creds, scfg);
}

// Records every byte the client writes, then forwards it to the real socket.
// The MCS channel id is outside the Standard RDP Security encryption, so the
// channel routing is visible even when the userData is RC4-protected.
class RecordingTransport final : public rtsc::net::Transport {
 public:
    explicit RecordingTransport(std::unique_ptr<rtsc::net::Transport> inner)
        : inner_(std::move(inner)) {}

    int Read(uint8_t* buf, size_t size) override {
        return inner_->Read(buf, size);
    }
    bool Write(const uint8_t* data, size_t size) override {
        writes_.emplace_back(data, data + size);
        return inner_->Write(data, size);
    }
    void Close() override { inner_->Close(); }

    const std::vector<std::vector<uint8_t>>& writes() const { return writes_; }

 private:
    std::unique_ptr<rtsc::net::Transport> inner_;
    std::vector<std::vector<uint8_t>> writes_;
};

[[maybe_unused]] bool FindChannelWrite(const RecordingTransport& transport, uint16_t channel_id,
                      std::vector<uint8_t>* user_data) {
    for (const auto& wire : transport.writes()) {
        rtsc::proto::McsSendData sd;
        if (rtsc::proto::McsSendData::parse(wire.data(), wire.size(), sd) !=
            rtsc::proto::Status::Ok) {
            continue;
        }
        if (sd.channel_id != channel_id) continue;
        if (user_data != nullptr) *user_data = sd.user_data;
        return true;
    }
    return false;
}

// USB device/enumerator stubs for the URBDRC wiring test: the hookup must
// reach the rdpusb "ready" state and announce a device without any real
// hardware.
class StubUsbDevice final : public rtsc::usb::UsbDevice {
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
        return true;
    }
    bool BulkOrInterruptTransfer(uint32_t, uint32_t,
                                 const std::vector<uint8_t>&, uint32_t,
                                 rtsc::usb::UrbResult& result) override {
        result.usbd_status = 0;
        return true;
    }
    bool ResetPipe(uint32_t) override { return true; }
    bool CancelRequest(uint32_t) override { return true; }

    rtsc::usb::UsbDeviceInfo info_;
};

class StubEnumerator final : public rtsc::usb::UsbDeviceEnumerator {
 public:
    std::vector<rtsc::usb::UsbDeviceInfo> Enumerate() override {
        rtsc::usb::UsbDeviceInfo info;
        info.instance_id = "USB\\VID_1234&PID_5678\\01";
        info.hardware_ids = {"USB\\VID_1234&PID_5678"};
        return {info};
    }
    std::unique_ptr<rtsc::usb::UsbDevice> Open(
        const std::string& instance_id) override {
        auto d = std::make_unique<StubUsbDevice>();
        d->info_.instance_id = instance_id;
        return d;
    }
};

// Scans the DYNVC-framed channel messages DrdynvcClient handed to its send
// callback for one whose URBDRC payload carries `want_function`. This proves
// the DrdynvcClient -> RdpUsbClient plumbing produced the announcement.
// Only the Windows-only URBDRC test below uses it, so it is marked unused to
// keep -Werror=unused-function quiet on the POSIX build.
[[maybe_unused]] bool FindDynvcUrbdcFunction(
    const std::vector<std::vector<uint8_t>>& messages, uint32_t want_function,
    std::vector<uint8_t>* rdp_payload) {
    for (const auto& message : messages) {
        rtsc::proto::ChannelPduHeader cph;
        if (rtsc::proto::ChannelPduHeader::parse(message.data(),
                                                 message.size(), cph) !=
            rtsc::proto::Status::Ok) {
            continue;
        }
        rtsc::proto::DynvcPdu dvc;
        if (rtsc::proto::DynvcPdu::parse(
                message.data() + rtsc::proto::ChannelPduHeader::kSize,
                message.size() - rtsc::proto::ChannelPduHeader::kSize,
                dvc) != rtsc::proto::Status::Ok) {
            continue;
        }
        rtsc::proto::RdpUsbHeader h;
        if (rtsc::proto::RdpUsbHeader::parse(dvc.data.data(),
                                             dvc.data.size(), h) !=
            rtsc::proto::Status::Ok) {
            continue;
        }
        // Function ids collide across interfaces (0x100 is CHANNEL_CREATED
        // too); restrict ADD_VIRTUAL_CHANNEL to the device-sink interface.
        if (h.function_id != want_function ||
            h.interface_only() !=
                static_cast<uint32_t>(
                    rtsc::proto::RdpUsbInterface::kClientDeviceSink)) {
            continue;
        }
        if (rdp_payload != nullptr) *rdp_payload = dvc.data;
        return true;
    }
    return false;
}

}  // namespace

#if defined(_WIN32)
RTSC_TEST(gui_send_uses_the_application_plane_under_standard_rdp) {
    rtsc::server::ServerConfig scfg;
    scfg.port = 0;  // ephemeral: the kernel picks a free port
    scfg.desktop_width = 64;
    scfg.desktop_height = 48;
    auto source = rtsc::server::MakeTestPatternSource();
    rtsc::server::RdpServer server(scfg);
    server.SetDesktopSource(source.get());

    std::mutex input_mu;
    std::vector<rtsc::server::InputEvent> input_events;
    server.SetInputCallback([&](const rtsc::server::InputEvent& ev) {
        std::lock_guard<std::mutex> lock(input_mu);
        input_events.push_back(ev);
    });

    std::string error;
    CHECK(server.Start(error));
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    auto socket = rtsc::net::ConnectTcp("127.0.0.1", port, error);
    CHECK(socket != nullptr);
    if (socket != nullptr) {
        RecordingTransport transport(std::move(socket));
        rtsc::client::Client client(MakeGuiDriver(), 64, 48);
        CHECK(client.Connect(transport, error));
        CHECK(client.active());
        CHECK(client.driver().standard_rdp());
        // This is the precondition that broke the old GUI send path.
        CHECK(client.driver().security() == nullptr);

        // Horizontal wheel: the in-tree server advertises INPUT_FLAG_MOUSE_HWHEEL
        // (0x0100), so the client must encode the PTRFLAGS_HWHEEL event
        // (0x0400 | WHEEL_DELTA 120 = 0x0478), not gate it away. The rotation
        // unit is WHEEL_DELTA per notch, exactly as for the vertical wheel.
        rtsc::ui::InputEvent hwheel;
        hwheel.kind = rtsc::ui::InputEvent::Kind::kMouseWheel;
        hwheel.horizontal = true;
        hwheel.wheel_delta = 1;
        const auto hwheel_pdu = client.EncodeInput(hwheel);
        CHECK(hwheel_pdu.size() == static_cast<size_t>(9));
        if (hwheel_pdu.size() == 9) {
            CHECK_EQ(static_cast<uint8_t>(hwheel_pdu[3]), static_cast<uint8_t>(0x78));
            CHECK_EQ(static_cast<uint8_t>(hwheel_pdu[4]), static_cast<uint8_t>(0x04));
        }

        // Negative HWHEEL (N6): one notch left is -120 rotation units, encoded
        // as 0x0400 | (-120 & 0x01FF = 0x188) = 0x0588. The sign lives inside
        // the 9-bit two's-complement mask; no separate negative flag is OR'ed.
        rtsc::ui::InputEvent hwheel_left;
        hwheel_left.kind = rtsc::ui::InputEvent::Kind::kMouseWheel;
        hwheel_left.horizontal = true;
        hwheel_left.wheel_delta = -1;
        const auto hwheel_left_pdu = client.EncodeInput(hwheel_left);
        CHECK(hwheel_left_pdu.size() == static_cast<size_t>(9));
        if (hwheel_left_pdu.size() == 9) {
            CHECK_EQ(static_cast<uint8_t>(hwheel_left_pdu[3]),
                     static_cast<uint8_t>(0x88));
            CHECK_EQ(static_cast<uint8_t>(hwheel_left_pdu[4]),
                     static_cast<uint8_t>(0x05));
        }

        // 1) Keyboard input through the same Client method the GUI calls.
        rtsc::ui::InputEvent key;
        key.kind = rtsc::ui::InputEvent::Kind::kKey;
        key.scancode = 0x1E;  // 'A'
        CHECK(client.SendInput(transport, key, error));

        bool got_key = false;
        const auto key_deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!got_key && std::chrono::steady_clock::now() < key_deadline) {
            if (!client.Pump(transport, error)) break;
            std::lock_guard<std::mutex> lock(input_mu);
            for (const auto& ev : input_events) {
                if (ev.kind == rtsc::server::InputEvent::Kind::kKey &&
                    ev.scancode == 0x1E && !ev.release) {
                    got_key = true;
                }
            }
        }
        CHECK(got_key);

        // 2) Static virtual channels through the same Client method the GUI's
        //    rdpdr/cliprdr/rdpsnd send callbacks use. The payload is a
        //    plausible CHANNEL_PDU_HEADER + body; its low byte keeps the
        //    server's input decoder from mistaking it for a Fast-Path PDU.
        const std::vector<uint8_t> channel_message = {
            0x11, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20, 0x30};
        const uint16_t channel_ids[] = {1004, 1005, 1006};
        for (uint16_t channel_id : channel_ids) {
            CHECK(client.SendChannelPdu(transport, channel_id, channel_message,
                                        error));
            std::vector<uint8_t> channel_user_data;
            CHECK(FindChannelWrite(transport, channel_id, &channel_user_data));
            // With encryption on, the userData carries the 12-byte security
            // header in front of the channel message.
            CHECK(channel_user_data.size() >= channel_message.size());
        }

        // 3) The channel PDU must not desynchronise the stream: a following
        //    input event still reaches the server.
        rtsc::ui::InputEvent move;
        move.kind = rtsc::ui::InputEvent::Kind::kMouseMove;
        move.x = 7;
        move.y = 9;
        CHECK(client.SendInput(transport, move, error));

        bool got_move = false;
        const auto move_deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!got_move && std::chrono::steady_clock::now() < move_deadline) {
            if (!client.Pump(transport, error)) break;
            std::lock_guard<std::mutex> lock(input_mu);
            for (const auto& ev : input_events) {
                if (ev.kind == rtsc::server::InputEvent::Kind::kMouse &&
                    ev.x == 7 && ev.y == 9) {
                    got_move = true;
                }
            }
        }
        CHECK(got_move);

        transport.Close();
    }

    server.Stop();
    runner.join();
}

// URBDRC wiring verification: the drdynvc static virtual channel is advertised
// by the client, the server assigns it an id, and the GUI-style hookup
// (ChannelIdForName -> RegisterChannel -> DrdynvcClient -> RdpUsbClient) drives
// the state machine to ready and announces a device over the real wire. No
// physical USB device is required - the enumerator and device are stubs.
RTSC_TEST(gui_send_drdynvc_hookup_reaches_urbdrc_ready) {
    rtsc::server::ServerConfig scfg;
    scfg.port = 0;
    scfg.desktop_width = 64;
    scfg.desktop_height = 48;
    auto source = rtsc::server::MakeTestPatternSource();
    rtsc::server::RdpServer server(scfg);
    server.SetDesktopSource(source.get());

    std::string error;
    CHECK(server.Start(error));
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    auto socket = rtsc::net::ConnectTcp("127.0.0.1", port, error);
    CHECK(socket != nullptr);
    if (socket != nullptr) {
        RecordingTransport transport(std::move(socket));
        rtsc::client::Client client(MakeGuiDriver(), 64, 48);
        CHECK(client.Connect(transport, error));
        CHECK(client.active());
        CHECK(client.driver().standard_rdp());

        const uint16_t drdynvc_id = client.driver().ChannelIdForName("drdynvc");
        CHECK(drdynvc_id != 0);
        if (drdynvc_id != 0) {
            StubEnumerator enumerator;
            // The GUI connects DrdynvcClient to the drdynvc static channel.
            std::vector<std::vector<uint8_t>> drdynvc_sent;
            const auto send_drdynvc = [&](const std::vector<uint8_t>& message) {
                drdynvc_sent.push_back(message);
                client.SendChannelPdu(transport, drdynvc_id, message, error);
            };
            rtsc::channel::DrdynvcClient drdynvc(nullptr, send_drdynvc);
            client.RegisterChannel(drdynvc_id,
                                   [&](const uint8_t* d, size_t sz) {
                                       drdynvc.OnChannelData(d, sz);
                                   });
            rtsc::channel::RdpUsbClient rdpusb(&enumerator, &drdynvc);
            drdynvc.Start();
            rdpusb.Start();

            // Server-side stub: the drdynvc capability response and the
            // CREATE_RSP for the "URBDRC" dynamic channel are framed as static
            // channel messages and fed through the registered handler.
            const auto feed_dvc = [&](const std::vector<uint8_t>& dvc_pdu) {
                for (const auto& chunk :
                     rtsc::proto::FragmentChannelMessage(dvc_pdu)) {
                    drdynvc.OnChannelData(chunk.data(), chunk.size());
                }
            };
            feed_dvc({0x50, 0x00, 0x01, 0x00});  // DYNVC_CAPS_RSP VERSION1
            const uint32_t control = rdpusb.control_channel();
            CHECK(control != 0);
            feed_dvc(rtsc::proto::BuildDynvcPdu(
                rtsc::proto::DynvcCmd::kCreate, 0, control, {0, 0, 0, 0}));
            CHECK(rdpusb.ready());
            CHECK(drdynvc.ready());

            // The GUI announces every whitelisted device once the URBDRC
            // channel is ready.
            rtsc::usb::UsbDeviceInfo info;
            info.instance_id = "USB\\VID_1234&PID_5678\\01";
            CHECK(rdpusb.AddDevice(info));

            // The announcement left the drdynvc transport as a DYNVC_DATA and
            // was written on the server-assigned static channel id.
            std::vector<uint8_t> payload;
            CHECK(FindDynvcUrbdcFunction(
                drdynvc_sent,
                static_cast<uint32_t>(
                    rtsc::proto::RdpUsbFunction::kAddVirtualChannel),
                &payload));
            std::vector<uint8_t> user_data;
            CHECK(FindChannelWrite(transport, drdynvc_id, &user_data));
            CHECK(user_data.size() > payload.size());
        }

        transport.Close();
    }

    server.Stop();
    runner.join();
}
#endif  // _WIN32

int main() { return ::rtsc::test::run_all("rtsc_gui_send_tests"); }
