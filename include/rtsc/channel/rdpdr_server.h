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

#include <chrono>
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

    // ---- route-A asynchronous I/O -----------------------------------------

    // Upper bound on the number of DR_DEVICE_IOREQUESTs the server may keep in
    // flight against the client at once. When the table is full every active
    // call returns 0 (failure) instead of overrunning the session.
    static constexpr size_t kMaxOutstanding = 256;
    // Default IRP lifetime: a completion that has not arrived within this
    // window is reaped by Poll() and its callback fails with
    // STATUS_IO_TIMEOUT.
    static constexpr std::chrono::steady_clock::duration kIrpTimeout =
        std::chrono::seconds(30);

    // Receives the outcome of one issued IRP. `io_status` is the NTSTATUS of
    // the matching DR_DEVICE_IOCOMPLETION and `data` is the parsed response
    // payload (Create: 4-byte LE file id; Read / QueryDirectory: the returned
    // bytes; Write / Close: empty).
    using IrpCallback =
        std::function<void(uint32_t io_status, const std::vector<uint8_t>& data)>;

    // Issues an IRP toward the client's shared device and returns the
    // completion id that will identify the matching completion (0 = rejected:
    // the channel is not READY or the outstanding table is full). The callback
    // fires asynchronously on the matching DR_DEVICE_IOCOMPLETION, on timeout,
    // or on session teardown.
    uint32_t CreateFile(uint32_t device_id, const std::string& path,
                        uint32_t desired_access, uint32_t disposition,
                        IrpCallback cb);
    uint32_t ReadFile(uint32_t device_id, uint32_t file_id, uint64_t offset,
                      uint32_t length, IrpCallback cb);
    uint32_t WriteFile(uint32_t device_id, uint32_t file_id, uint64_t offset,
                       const std::vector<uint8_t>& data, IrpCallback cb);
    uint32_t CloseFile(uint32_t device_id, uint32_t file_id, IrpCallback cb);
    uint32_t QueryDirectory(uint32_t device_id, uint32_t file_id,
                            uint32_t info_class, bool initial, IrpCallback cb);

    // Reaps IRPs whose deadline has passed: their callbacks are failed with
    // STATUS_IO_TIMEOUT and they are removed from the table. Idempotent; call
    // from the session thread at whatever cadence is convenient (the default
    // uses the wall clock at the moment of the call).
    void Poll(const std::chrono::steady_clock::time_point& now =
                  std::chrono::steady_clock::now());

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
    unsigned device_reply_count() const { return device_reply_count_; }
    unsigned device_io_request_count() const { return device_io_request_count_; }
    unsigned out_of_order_count() const { return out_of_order_count_; }
    unsigned malformed_pdu_count() const { return malformed_pdu_count_; }

    // ---- route-A I/O diagnostics ------------------------------------------

    // IRPs currently awaiting a DR_DEVICE_IOCOMPLETION.
    size_t outstanding_count() const { return outstanding_.size(); }
    // The next completion id to hand out (0 is reserved for "rejected").
    uint32_t next_completion_id() const { return next_completion_id_; }
    // DR_DEVICE_IOCOMPLETION messages matched to an outstanding IRP.
    unsigned device_io_completion_count() const {
        return device_io_completion_count_;
    }
    // DR_DEVICE_IOCOMPLETION messages with no matching outstanding IRP
    // (unknown or replayed id). Recorded and dropped, never delivered.
    unsigned unknown_completion_count() const {
        return unknown_completion_count_;
    }
    // IRPs reaped by Poll() that expired without a completion.
    unsigned device_io_timeout_count() const { return device_io_timeout_count_; }

 private:
    void OnMessage(const std::vector<uint8_t>& message);
    void OnClientAnnounce(const std::vector<uint8_t>& message);
    void OnClientName(const std::vector<uint8_t>& message);
    void OnClientCapability(const std::vector<uint8_t>& message);
    void OnDeviceListAnnounce(const std::vector<uint8_t>& message);
    void OnDeviceIoRequest(const std::vector<uint8_t>& message);
    void OnDeviceIoCompletion(const std::vector<uint8_t>& body);

    // One in-flight IRP: the metadata needed to recognise its completion, the
    // major function that decides how to parse the response payload, the
    // timeout deadline and the callback to wake.
    struct PendingIrp {
        uint32_t device_id = 0;
        uint32_t file_id = 0;
        uint32_t completion_id = 0;
        uint32_t major_function = 0;
        std::chrono::steady_clock::time_point deadline;
        IrpCallback callback;
    };

    void SendRaw(const std::vector<uint8_t>& pdu);
    std::vector<uint8_t> BuildServerCapabilities() const;

    // Common IRP issuance path: gates on READY + capacity, allocates the
    // completion id, sends the assembled IOREQUEST and registers the pending
    // entry. `tail` is the request body following the DR_DEVICE_IOREQUEST
    // header fields.
    uint32_t SubmitIrp(uint32_t device_id, uint32_t file_id,
                       uint32_t major_function, uint32_t minor_function,
                       const std::vector<uint8_t>& tail, IrpCallback cb);

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

    std::vector<PendingIrp> outstanding_;
    uint32_t next_completion_id_ = 1;

    unsigned server_announce_count_ = 0;
    unsigned server_capability_count_ = 0;
    unsigned clientid_confirm_count_ = 0;
    unsigned user_loggedon_count_ = 0;
    unsigned client_announce_count_ = 0;
    unsigned client_name_count_ = 0;
    unsigned client_capability_count_ = 0;
    unsigned device_list_announce_count_ = 0;
    unsigned device_reply_count_ = 0;
    unsigned device_io_request_count_ = 0;
    unsigned device_io_completion_count_ = 0;
    unsigned unknown_completion_count_ = 0;
    unsigned device_io_timeout_count_ = 0;
    unsigned out_of_order_count_ = 0;
    unsigned malformed_pdu_count_ = 0;
};

}  // namespace rtsc::channel