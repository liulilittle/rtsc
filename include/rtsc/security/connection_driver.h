// Connection driver: ties the protocol state machine (ConnectMachine) and the
// security layer (SecurityLayer) into one in-memory byte pump.
//
// Reference: docs/spec/security-integration.audit-a.md section 5.1.
//
// The driver owns no socket. Start() emits the first plaintext PDU; OnData()
// consumes whatever the peer sent and returns the next bytes to send. That
// makes the whole connection sequence (X.224 -> TLS -> CredSSP -> EUAR -> MCS ->
// Client Info) drivable from a test vector, a capture replay, or a socket loop.
//
// The precise hand-off point matters and is fixed here:
//   * X.224 Connection Request / Confirm travel in the clear.
//   * After the Confirm selects an external protocol, the security layer runs.
//   * MCS Connect Initial and everything after it is sent through the layer.
//
// A plaintext TPKT framer is kept separately from the security layer because
// before the handshake there is no encryption to hide the TPKT header, and
// after it the security layer returns whole frames itself.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "rtsc/proto/connect_machine.h"
#include "rtsc/proto/licensing_machine.h"
#include "rtsc/proto/session_setup.h"
#include "rtsc/security/security_layer.h"

namespace rtsc::security {

struct DriverStep {
    std::vector<uint8_t> to_send;  // bytes for the socket (possibly empty)
    bool done = false;             // Client Info PDU has been sent
    bool active = false;           // session reached S4 (Font Map received)
    bool failed = false;
    std::string error;
};

class ConnectionDriver {
 public:
    ConnectionDriver(proto::ConnectMachine::Config machine_config,
                     proto::ConnectMachine::Credentials credentials,
                     Config security_config);

    // Move-only: owns the security layer (a unique_ptr) and the machine.
    ConnectionDriver(ConnectionDriver&&) = default;
    ConnectionDriver& operator=(ConnectionDriver&&) = default;
    ConnectionDriver(const ConnectionDriver&) = delete;
    ConnectionDriver& operator=(const ConnectionDriver&) = delete;

    // Test hook: install a scripted TLS transport in the security layer the
    // driver builds when the handshake starts.
    void SetTlsTransportForTest(std::unique_ptr<tls::TlsTransport> tls) {
        tls_for_test_ = std::move(tls);
    }

    // Emits the X.224 Connection Request (plaintext).
    DriverStep Start();

    // Consumes bytes from the peer and returns the next bytes to send.
    DriverStep OnData(const uint8_t* data, size_t size);

    proto::ConnectMachine& machine() { return machine_; }
    SecurityLayer* security() { return security_.get(); }
    bool security_active() const { return security_ != nullptr; }
    const std::string& phase_name() const;

    // The handler receives each inbound PDU once the session is active (i.e.
    // after the capability exchange / connection finalization completed). The
    // graphics layer uses it to consume bitmap / pointer updates. This is the
    // I/O channel's handler: PDUs whose MCS channel id equals io_channel_id_.
    void SetSessionPduHandler(
        std::function<void(const std::vector<uint8_t>&)> handler) {
        session_pdu_handler_ = std::move(handler);
    }

    // Registers a handler for inbound PDUs on a static virtual channel (any
    // MCS channel id other than the I/O channel). The handler receives the raw
    // MCS Send Data PDU bytes (transport header included). A PDU on an
    // unregistered channel is counted and dropped, never handed to the graphics
    // handler: a virtual channel must not be mistaken for graphics data.
    void SetChannelHandler(
        uint16_t channel_id,
        std::function<void(const uint8_t*, size_t)> handler) {
        channel_handlers_[channel_id] = std::move(handler);
    }
    size_t unrouted_channel_count() const { return unrouted_channel_count_; }

    bool session_active() const { return session_ != nullptr && session_->active(); }

    // The desktop size the server granted, taken from the Demand Active bitmap
    // capability set. Before that PDU is processed this falls back to the size
    // the client advertised (machine_config_), so a caller can always size its
    // surface from the negotiated desktop.
    uint16_t desktop_width() const {
        if (session_ != nullptr && session_->state().desktop_width != 0) {
            return session_->state().desktop_width;
        }
        return static_cast<uint16_t>(machine_config_.desktop_width);
    }
    uint16_t desktop_height() const {
        if (session_ != nullptr && session_->state().desktop_height != 0) {
            return session_->state().desktop_height;
        }
        return static_cast<uint16_t>(machine_config_.desktop_height);
    }

    // The multi-monitor layout the server reported (Monitor Layout PDU,
    // 2.2.12.1). Empty for a single-monitor session.
    const std::vector<proto::MonitorDef>& monitors() const {
        static const std::vector<proto::MonitorDef> kEmpty;
        return session_ != nullptr ? session_->state().monitors : kEmpty;
    }
    bool has_monitor_layout() const {
        return session_ != nullptr && session_->state().has_monitor_layout;
    }

 private:
    DriverStep Fail(const std::string& reason);
    // Runs the security handshake with the buffered ciphertext; returns the
    // bytes to send (may be empty while more input is needed).
    DriverStep DriveSecurity(const uint8_t* data, size_t size);
    // Routes a post-Client-Info PDU to the licensing / session setup machine.
    void RoutePostConnect(const std::vector<uint8_t>& pdu, DriverStep& out);

    proto::ConnectMachine machine_;
    proto::ConnectMachine::Config machine_config_;
    Config security_config_;
    std::unique_ptr<SecurityLayer> security_;
    std::unique_ptr<tls::TlsTransport> tls_for_test_;
    proto::ConnectMachine::Credentials credentials_;

    // Post-Client-Info phase.
    std::unique_ptr<proto::LicensingMachine> licensing_;
    std::unique_ptr<proto::SessionSetupMachine> session_;
    std::function<void(const std::vector<uint8_t>&)> session_pdu_handler_;

    // Post-active routing: I/O channel id (from Server Network Data) and the
    // static virtual channel handlers. io_channel_id_ is latched once the MCS
    // connection response has been parsed.
    uint16_t io_channel_id_ = 0;
    std::map<uint16_t, std::function<void(const uint8_t*, size_t)>> channel_handlers_;
    size_t unrouted_channel_count_ = 0;

    // Plaintext phase: accumulate bytes and peel complete TPKT frames. The
    // header is kept because ConnectMachine::OnData requires the whole frame.
    std::vector<uint8_t> plain_buf_;
    bool client_info_sent_ = false;
};

}  // namespace rtsc::security
