// GUI send path: input and static virtual channels through the application
// data plane.
//
// The GUI used to reach into ConnectionDriver::security() directly, which is
// null under Standard RDP Security (PROTOCOL_RDP). Input and channel messages
// were therefore silently dropped on that path. These tests exercise the same
// Client methods the GUI calls, against the in-tree RDP server over
// PROTOCOL_RDP, and prove that both cross the wire (the server's input callback
// observes the event; the recorded transport shows the MCS channel id).

#include "rtsc/client/client.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "rtsc/net/transport.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/server/server.h"
#include "rtsc/ui/window.h"
#include "test_framework.h"
#include "test_main.h"

namespace {

[[maybe_unused]] rtsc::security::ConnectionDriver MakeGuiDriver() {
    rtsc::proto::ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.requested_protocols = rtsc::proto::kProtocolRdp;
    mcfg.client_name = "RTSC";
    mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
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

}  // namespace

#if defined(_WIN32)
RTSC_TEST(gui_send_uses_the_application_plane_under_standard_rdp) {
    const uint16_t port = 3396;
    rtsc::server::ServerConfig scfg;
    scfg.port = port;
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
#endif  // _WIN32

int main() { return ::rtsc::test::run_all("rtsc_gui_send_tests"); }
