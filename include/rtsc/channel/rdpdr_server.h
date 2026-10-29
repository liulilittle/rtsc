// Device redirection virtual channel (rdpdr) server handler ([MS-RDPEFS] 3.2.5).
//
// The server half of the rdpdr static virtual channel. The connection driver
// hands this class the raw MCS Send Data user_data of the channel, it
// reassembles the chunked channel message and runs the channel-level
// initialization sequence of the *server* role: Server Announce first, then,
// on the client announce reply, the Server Capability plus the ClientId
// Confirm and an optional User LoggedOn. The v1 scope is the minimum handshake
// only: the server announces no devices (an empty device list is legal), so no
// DR_DEVICE_IOREQUEST is ever answered and a stray one is merely counted.
//
// The ClientId Confirm is sent together with the Server Capability right after
// the client announce reply, not gated on first receiving a client capability.
// This client's handler only emits its capability in answer to the
// confirmation (src/channel/rdpdr_client.cpp OnClientIdConfirm), so gating the
// confirmation on a capability that can never precede it would deadlock the
// channel (FreeRDP's rdpdr server sends the two together for the same reason).
//
// One RdpdrServer is created per session and used only from the session
// thread. There are no devices and no file I/O in v1 (documented in
// docs/spec/rdpdr-server-design.md).
//
// Reference: [MS-RDPEFS] 1.3, 2.2 (headers and core messages), 3.2.5 (server).

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "rtsc/proto/channel.h"
#include "rtsc/proto/rdpdr.h"

namespace rtsc::channel {

class RdpdrServer {
 public:
    // Receives one complete channel chunk (CHANNEL_PDU_HEADER + rdpdr data).
    // The caller wraps it in an MCS Send Data Indication and writes it. A
    // message larger than the negotiated chunk size is delivered as several
    // chunks, each with its own CHANNEL_PDU_HEADER.
    using SendFn = std::function<void(const std::vector<uint8_t>&)>;

    RdpdrServer(SendFn send);
    ~RdpdrServer();

    RdpdrServer(const RdpdrServer&) = delete;
    RdpdrServer& operator=(const RdpdrServer&) = delete;

    // ---- connection lifecycle ----------------------------------------------

    // Arms the handler and runs the server initialization sequence exactly
    // once: the Server Announce ([MS-RDPEFS] 3.2.5.1). Idempotent.
    void Start();

    // Feeds one inbound virtual-channel chunk (the MCS Send Data user_data of
    // one channel indication). A message may be split across calls.
    void OnChannelData(const uint8_t* data, size_t size);

    // ---- diagnostics -------------------------------------------------------

    // The protocol phase:
    //   kIdle -> Start() -> kAwaitClientAnnounce -> (client announce reply) ->
    //   kReady. After kReady the server has sent its whole initialization
    //   batch; the client's own capability / device list are informational.
    enum class Phase { kIdle, kAwaitClientAnnounce, kReady };
    static const char* to_string(Phase p);
    Phase phase() const { return phase_; }

    bool started() const { return started_; }
    // The client id the server assigned and used in the announce and the
    // confirmation.
    uint32_t client_id() const { return client_id_; }
    uint16_t version_major() const { return version_major_; }
    uint16_t version_minor() const { return version_minor_; }
    bool client_announce_received() const { return client_announce_received_; }
    bool client_capability_received() const { return client_capability_received_; }
    bool user_logged_on_sent() const { return user_logged_on_sent_; }
    const std::string& client_computer_name() const {
        return client_computer_name_;
    }

    unsigned server_announce_count() const { return server_announce_count_; }
    unsigned server_capability_count() const { return server_capability_count_; }
    unsigned clientid_confirm_count() const { return clientid_confirm_count_; }
    unsigned user_loggedon_count() const { return user_loggedon_count_; }
    unsigned client_announce_count() const { return client_announce_count_; }
    unsigned client_name_count() const { return client_name_count_; }
    unsigned client_capability_count() const { return client_capability_count_; }
    unsigned device_list_announce_count() const {
        return device_list_announce_count_;
    }
    unsigned device_io_request_count() const { return device_io_request_count_; }
    unsigned out_of_order_count() const { return out_of_order_count_; }
    unsigned malformed_pdu_count() const { return malformed_pdu_count_; }

 private:
    void OnMessage(const std::vector<uint8_t>& message);
    void OnClientAnnounce(const std::vector<uint8_t>& message);
    void OnClientName(const std::vector<uint8_t>& message);
    void OnClientCapability(const std::vector<uint8_t>& message);
    void OnDeviceListAnnounce(const std::vector<uint8_t>& message);
    void OnDeviceIoRequest(const std::vector<uint8_t>& message);

    void SendRaw(const std::vector<uint8_t>& pdu);
    std::vector<uint8_t> BuildServerCapabilities() const;

    SendFn send_;
    rtsc::proto::ChannelReassembler reassembler_;

    Phase phase_ = Phase::kIdle;
    bool started_ = false;
    uint32_t client_id_ = 0;
    uint16_t version_major_ = 1;
    uint16_t version_minor_ = 0x000C;
    bool client_announce_received_ = false;
    bool client_capability_received_ = false;
    bool user_logged_on_sent_ = false;
    std::string client_computer_name_;

    unsigned server_announce_count_ = 0;
    unsigned server_capability_count_ = 0;
    unsigned clientid_confirm_count_ = 0;
    unsigned user_loggedon_count_ = 0;
    unsigned client_announce_count_ = 0;
    unsigned client_name_count_ = 0;
    unsigned client_capability_count_ = 0;
    unsigned device_list_announce_count_ = 0;
    unsigned device_io_request_count_ = 0;
    unsigned out_of_order_count_ = 0;
    unsigned malformed_pdu_count_ = 0;
};

}  // namespace rtsc::channel