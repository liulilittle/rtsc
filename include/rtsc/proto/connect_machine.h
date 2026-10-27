#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/client_info.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/multimon.h"

namespace rtsc::proto {

// Client-side connection establishment state machine, from the X.224 Connection
// Request through the Client Info PDU ([MS-RDPBCGR] 1.3.1.1 / 3.2.5).
//
// The machine is transport agnostic: it produces the bytes to send and consumes
// the bytes received, so it can be driven by a socket, a test vector, or a
// capture replay. Crypto (TLS, CredSSP, RC4) is deliberately outside: when the
// negotiated protocol is not PROTOCOL_RDP the caller must run the external
// security handshake before feeding MCS PDUs in.
enum class ConnectPhase : uint8_t {
    kIdle,                  // nothing sent yet
    kAwaitNegotiation,      // sent X.224 CRQ, awaiting Connection Confirm
    kAwaitExternalSecurity, // server selected TLS/CredSSP: run that handshake
    kAwaitConnectResponse,  // sent MCS Connect Initial, awaiting Connect Response
    kAwaitAttachUser,       // sent Attach User Request, awaiting Confirm
    kAwaitChannelJoin,      // sent a Channel Join Request, awaiting Confirm
    kReadyToSendClientInfo, // all channels joined
    kAwaitClientInfoAck,    // sent Client Info, awaiting server's first PDU
    kFailed,
};

const char* to_string(ConnectPhase p);

// One step's output: the bytes to put on the wire, plus whether the machine
// needs more input before it can continue.
struct ConnectStep {
    std::vector<uint8_t> output;
    bool needs_input = false;
};

// Everything the client needs to know after the negotiation + Connect Response.
struct ConnectState {
    ConnectPhase phase = ConnectPhase::kIdle;
    uint32_t negotiated_protocol = 0;  // PROTOCOL_* from RDP_NEG_RSP
    uint32_t server_result = 0;        // MCS Connect Response result
    uint16_t user_channel_id = 0;      // from Attach User Confirm
    uint16_t io_channel_id = 0;        // from Server Network Data
    uint16_t message_channel_id = 0;   // from Server Message Channel Data (0 = skip)
    std::vector<uint16_t> static_virtual_channels;  // from Server Network Data

    // Channels still to join, in order: user, I/O, message (if non-zero), VCs.
    std::vector<uint16_t> join_queue;
    size_t join_index = 0;

    std::string error;  // populated when phase == kFailed
};

// Drives the client half of the connection sequence.
//
// Usage:
//   ConnectMachine m(config);
//   auto step = m.Start();           // -> X.224 CRQ bytes
//   send(step.output);
//   ... receive bytes ...
//   step = m.OnData(received);       // -> next bytes to send, or needs_input
class ConnectMachine {
public:
    struct Config {
        std::string cookie;             // optional "Cookie: mstshash=..." payload
        uint32_t requested_protocols = 0;  // PROTOCOL_* bitmap
        bool include_correlation_info = false;

        // Client Core Data values used for the Connect Initial.
        uint32_t desktop_width = 1280;
        uint32_t desktop_height = 1024;
        uint32_t color_depth = 0xCA01;   // 8 bpp
        uint32_t client_build = 0;
        std::string client_name;
        uint32_t keyboard_layout = 0x00000409;
        // [MS-RDPBCGR] 2.2.1.3.2: highColorDepth has no value 32 (valid: 4, 8,
        // 15, 16, 24). The session colour depth is advertised as
        // highColorDepth=24, and supportedColorDepths lists ONLY the depths
        // this client can decode — 32bpp compressed is RDP6-planar, which the
        // decoder does not cover yet, and a real Windows server answers a
        // 32bpp advertisement with a 32bpp session (dual-audit real-machine
        // evidence). The mstsc-style 32bpp combination (24 + 0x0002 + 0x0009)
        // returns once the planar decoder lands.
        uint16_t high_color_depth = 24;
        uint16_t supported_color_depths = 0x0001;
        uint16_t early_capability_flags = 0x0001;
        uint32_t connection_type = 0;

        // Multi-monitor: the client's local monitor layout. When non-empty a
        // Client Monitor Data (CS_MONITOR 0xC005) block is added to the Connect
        // Initial so the server builds a multi-monitor session, and the CS_CORE
        // desktop size is widened to the virtual desktop union. The caller
        // normally fills this from the local display enumeration.
        std::vector<MonitorDef> monitors;
        // Advertise RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU so the server sends the
        // Monitor Layout PDU (2.2.12.1). mstsc sets the same flag.
        bool support_monitor_layout_pdu = true;

        // Client Network Data: channel names to request, in order.
        std::vector<std::string> channel_names;

        // Client Security Data encryption methods bitmap.
        uint32_t encryption_methods = 0x0000001B;
    };

    // Client Info credentials, sent after all channels are joined.
    struct Credentials {
        std::string domain;
        std::string user_name;
        std::string password;
        std::string alternate_shell;
        std::string working_dir;
        bool autologon = false;
    };

    ConnectMachine(const Config& config, const Credentials& credentials);

    // Emits the first PDU (X.224 Connection Request).
    ConnectStep Start();

    // Consumes a complete inbound PDU and advances. `output` in the result is
    // the next PDU to send (possibly empty when only waiting for input).
    ConnectStep OnData(const uint8_t* data, size_t size);

    // Called by the caller after the external security handshake (TLS, CredSSP)
    // finishes successfully. Only valid in phase kAwaitExternalSecurity.
    ConnectStep OnExternalSecurityComplete();

    const ConnectState& state() const { return state_; }
    bool failed() const { return state_.phase == ConnectPhase::kFailed; }
    bool done() const { return state_.phase == ConnectPhase::kAwaitClientInfoAck; }

private:
    void Fail(const char* reason);
    ConnectStep Step(ConnectPhase next);
    ConnectStep SendChannelJoin();
    ConnectStep SendConnectInitial();

    Config config_;
    Credentials credentials_;
    ConnectState state_;
};

}  // namespace rtsc::proto
