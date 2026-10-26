// End-to-end RDP client: ties the connection driver (protocol + security) to
// the graphics pipeline and the window's input, so a socket loop plus a window
// is all a front-end needs.
//
// The connection driver already sequences X.224 -> TLS -> CredSSP -> MCS ->
// Client Info -> licensing -> capability exchange -> finalization. Once the
// session is active the driver hands every inbound PDU here, where Fast-Path
// and slow-path graphics updates are composited onto the surface. Window input
// is encoded back into Fast-Path input PDUs.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "rtsc/channel/rail_client.h"
#include "rtsc/client/graphics.h"
#include "rtsc/client/session_info.h"
#include "rtsc/net/transport.h"
#include "rtsc/security/connection_driver.h"
#include "rtsc/ui/window.h"

namespace rtsc::client {

class Client {
 public:
    Client(security::ConnectionDriver driver, uint16_t width, uint16_t height);

    // Test hook: install a scripted TLS transport before Connect().
    void SetTlsTransportForTest(std::unique_ptr<tls::TlsTransport> tls) {
        driver_.SetTlsTransportForTest(std::move(tls));
    }

    // Registers a handler for inbound PDUs on a static virtual channel. The
    // handler receives the raw MCS Send Data PDU bytes. This only forwards to
    // the connection driver, which routes post-active PDUs by MCS channel id;
    // the I/O channel stays with the graphics handler installed at
    // construction.
    void RegisterChannel(uint16_t channel_id,
                         std::function<void(const uint8_t*, size_t)> handler) {
        driver_.SetChannelHandler(channel_id, std::move(handler));
    }

    // Sets the function used to send complete rail channel messages. The
    // function receives the MCS channel id the server assigned to the rail
    // channel and the message (CHANNEL_PDU_HEADER + RAIL orders); it returns
    // false on a write failure. Must be called before StartRailChannel().
    void SetRailSender(
        std::function<bool(uint16_t, const std::vector<uint8_t>&)> send) {
        rail_send_ = std::move(send);
        rail_.SetSendFn([this](const std::vector<uint8_t>& m) {
            if (rail_channel_id_ != 0 && rail_send_) {
                rail_send_(rail_channel_id_, m);
            }
        });
    }

    // The RAIL handler. The front-end installs an OrderHandler to react to the
    // inbound server orders (window move / minmax / taskbar / exec result /
    // get appid response, ...).
    channel::RailClient& rail() { return rail_; }

    // Resolves the rail static virtual channel id from the Server Network Data,
    // registers the RAIL handler on it and starts the RAIL session (Handshake +
    // ClientStatus). Returns the channel id, or 0 when the server did not assign
    // a rail channel. Call after Connect(), once the channel join completed.
    uint16_t StartRailChannel(uint32_t build_number = 0,
                              uint32_t client_flags = 0);

    // Drives the connection sequence to the active session. Blocking.
    bool Connect(net::Transport& transport, std::string& error);

    // One read/process/write cycle after Connect(). Blocking. Returns false on
    // disconnect or a protocol failure.
    bool Pump(net::Transport& transport, std::string& error);

    // Encodes a window input event as a Fast-Path input PDU.
    std::vector<uint8_t> EncodeInput(const ui::InputEvent& ev) const;

    // Encodes the Secure Attention Sequence (Ctrl+Alt+Del) as a Fast-Path input
    // PDU: six scancode events (Ctrl down, Alt down, Delete down, Delete up,
    // Alt up, Ctrl up) in one PDU. mstsc triggers this from Ctrl+Alt+End.
    std::vector<uint8_t> EncodeCtrlAltDel() const;

    // Sends an input event through the post-active application data plane
    // (TLS or Standard RDP Security). Returns false with `error` set on a
    // write failure.
    bool SendInput(net::Transport& transport, const ui::InputEvent& ev,
                   std::string& error);

    // Sends a static virtual channel message (CHANNEL_PDU_HEADER + channel PDU)
    // through the post-active application data plane. Returns false with
    // `error` set on a write failure.
    bool SendChannelPdu(net::Transport& transport, uint16_t channel_id,
                        const std::vector<uint8_t>& pdu, std::string& error);

    // Sends the SAS over `transport` through the security layer. Returns false
    // with `error` set on a write failure.
    bool SendCtrlAltDel(net::Transport& transport, std::string& error);

    ui::Surface& surface() { return graphics_.surface(); }
    GraphicsPipeline& graphics() { return graphics_; }
    bool active() const { return driver_.session_active(); }

    // The desktop size the server granted (Demand Active). The front-end uses
    // this to size its window and surface so the default view is 1:1 lossless.
    uint16_t desktop_width() const { return driver_.desktop_width(); }
    uint16_t desktop_height() const { return driver_.desktop_height(); }
    security::ConnectionDriver& driver() { return driver_; }

    // The multi-monitor layout the server reported (Monitor Layout PDU,
    // 2.2.12.1). Empty for a single-monitor session.
    const std::vector<proto::MonitorDef>& monitors() const {
        return driver_.monitors();
    }
    bool has_monitor_layout() const { return driver_.has_monitor_layout(); }

    // Session statistics for the Connection information dialog. NoteFrame() is
    // called by the front-end after each Present(). NoteInputSent() is called
    // right before an input PDU is written to the transport; the round-trip is
    // then closed by the next inbound server data (NoteInboundData).
    void NoteFrame();
    double frames_per_second() const noexcept;
    void NoteInputSent();
    void NoteInboundData(size_t bytes);
    bool has_rtt() const noexcept { return has_rtt_; }
    double rtt_ms() const noexcept { return rtt_ms_; }
    double bandwidth_mbps() const noexcept;

    // The connection's activity id (generated once at construction), shown in
    // the dialog next to the UTC timestamp.
    const std::string& activity_id() const noexcept { return activity_id_; }

 private:
    // Applies one inbound post-session PDU (Fast-Path or slow-path).
    void OnSessionPdu(const std::vector<uint8_t>& pdu);

    // Wraps `pdu` in the security layer and writes it to `transport`. Returns
    // false with `error` set on a write failure. An empty PDU is not sent.
    bool SendPdu(net::Transport& transport, const std::vector<uint8_t>& pdu,
                 std::string& error);

    security::ConnectionDriver driver_;
    GraphicsPipeline graphics_;
    channel::RailClient rail_;
    std::function<bool(uint16_t, const std::vector<uint8_t>&)> rail_send_;
    uint16_t rail_channel_id_ = 0;

    using Clock = std::chrono::steady_clock;
    std::deque<Clock::time_point> frame_times_;
    std::deque<std::pair<Clock::time_point, size_t>> inbound_bytes_;
    Clock::time_point last_input_send_{};
    bool has_input_pending_ = false;
    bool has_rtt_ = false;
    double rtt_ms_ = 0.0;
    std::string activity_id_;
};

}  // namespace rtsc::client
