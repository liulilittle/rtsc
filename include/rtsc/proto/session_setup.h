// Client-side session setup state machine: the Capability Exchange and
// Connection Finalization phases that follow the Client Info PDU.
//
// Reference: docs/spec/capabilities.md section 12 (the S0..S6 state machine),
// [MS-RDPBCGR] 1.3.1.1 phase 8 and 3.2.5.3.13..3.2.5.3.22.
//
// This machine sits above ConnectMachine. It consumes complete inbound MCS Send
// Data PDUs (already decrypted by the security layer, already TPKT-framed) and
// produces the client PDUs, each wrapped in its own MCS Send Data frame.
//
// Enhanced RDP Security note (docs/spec/security-layer.md section 1.3): under
// TLS/CredSSP there is no RDP security header on any PDU except Client Info and
// licensing, so the share control header follows the MCS payload directly.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/capabilities.h"
#include "rtsc/proto/multimon.h"

namespace rtsc::proto {

// States S0..S6 of capabilities.md section 12.1.
enum class SessionPhase : uint8_t {
    kInit,              // S0: before the licensing phase completes
    kWaitDemandActive,  // S1: waiting for the Demand Active PDU
    kConfirmSent,       // S2: Confirm Active sent, finalization batch emitted
    kFinalizing,        // S3: waiting for the server's Synchronize/Control/FontMap
    kActive,            // S4: Font Map received, the session is usable
    kDeactivated,       // S5: Deactivate All received
    kClosed,            // S6: connection dropped
};

const char* to_string(SessionPhase phase);

struct SessionSetupState {
    SessionPhase phase = SessionPhase::kInit;
    uint16_t user_channel_id = 0;
    uint16_t server_channel_id = 0;  // Demand Active pduSource
    uint32_t share_id = 0;
    CapabilitySetList server_capabilities;
    // The desktop size the server actually granted, taken from the bitmap
    // capability set of the Demand Active PDU. The client advertises its own
    // size, but the server's answer is authoritative for a lossless 1:1 view.
    uint16_t desktop_width = 0;
    uint16_t desktop_height = 0;
    // The server's advertised Input capability flags (TS_INPUT_CAPABILITYSET
    // inputFlags, [MS-RDPBCGR] 2.2.7.1.6). Gates client input features the
    // server did not accept, e.g. PTRFLAGS_HWHEEL MUST NOT be sent unless
    // INPUT_FLAG_MOUSE_HWHEEL (0x0100) is set.
    uint16_t server_input_flags = 0;
    // Multi-monitor layout reported by the server's optional Monitor Layout PDU
    // (2.2.12.1). Empty until that PDU arrives; a single-monitor session never
    // sends it, so the client keeps its single-surface path.
    bool has_monitor_layout = false;
    std::vector<MonitorDef> monitors;
    // Last Set Error Info PDU, if any (recorded but does not change the state).
    bool has_error_info = false;
    uint32_t error_info = 0;
    std::string error;  // populated when phase == kClosed due to a failure
};

// One step's output: the client PDUs to send (each already MCS-framed) and the
// resulting session status.
struct SessionStep {
    std::vector<std::vector<uint8_t>> to_send;
    bool active = false;  // reached S4
    bool failed = false;
    std::string error;
};

class SessionSetupMachine {
 public:
    struct Config {
        uint16_t user_channel_id = 0;  // from Attach User Confirm
        uint16_t io_channel_id = 0;    // from Server Network Data
        uint16_t desktop_width = 1280;
        uint16_t desktop_height = 1024;
        uint16_t color_depth = 24;
        std::string source_descriptor = "RTSC";
        // RemoteApp (RAIL) session: only then may the Confirm Active carry
        // TS_RAIL_CAPS ([MS-RDPERP]; mstsc sets it via remoteapplicationmode).
        bool rail_mode = false;
    };

    explicit SessionSetupMachine(const Config& config);

    // Enters S1 (waiting for Demand Active). Call once the licensing phase is
    // done, i.e. right after the Client Info PDU has been sent.
    void Start();

    // Consumes a complete inbound PDU (TPKT-framed MCS Send Data) and returns
    // the client PDUs to send.
    SessionStep OnPdu(const uint8_t* data, size_t size);

    const SessionSetupState& state() const { return state_; }
    bool active() const { return state_.phase == SessionPhase::kActive; }

 private:
    SessionStep Fail(const std::string& reason);

    // S1: a Demand Active PDU -> build Confirm Active + the finalization batch.
    SessionStep HandleDemandActive(const uint8_t* data, size_t size);
    // S2/S3: dispatch on the share PDU type.
    SessionStep HandleSharePdu(const uint8_t* data, size_t size);

    // Wraps a slow-path data payload into an MCS Send Data frame.
    std::vector<uint8_t> FrameDataPdu(ShareDataPduType type,
                                      const std::vector<uint8_t>& payload) const;

    Config config_;
    SessionSetupState state_;
    bool confirm_sent_ = false;
};

}  // namespace rtsc::proto
