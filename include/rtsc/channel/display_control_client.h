// Display Control dynamic virtual channel client ([MS-RDPEDISP]).
//
// Opens the "Microsoft::Windows::RDS::DisplayControl" channel through an
// existing drdynvc transport, waits for DISPLAYCONTROL_CAPS_PDU, and sends
// DISPLAYCONTROL_MONITOR_LAYOUT_PDU requests that satisfy those caps.

#pragma once

#include <cstdint>
#include <vector>

#include "rtsc/channel/drdynvc_client.h"
#include "rtsc/proto/display_control.h"

namespace rtsc::channel {

class DisplayControlClient final : public IDrdynvcListener {
 public:
    // The transport must outlive this client.
    explicit DisplayControlClient(DrdynvcClient& transport);
    ~DisplayControlClient() override;

    DisplayControlClient(const DisplayControlClient&) = delete;
    DisplayControlClient& operator=(const DisplayControlClient&) = delete;

    // Opens the dynamic channel and starts listening. Returns false when the
    // channel was already opened (idempotent true) or the id is exhausted.
    bool Start();

    // Drops the per-session state after the transport was replaced
    // (auto-reconnect, [MS-RDPBCGR] 1.3.5). The listener registration and a
    // pending layout request are kept; the negotiated caps and the old channel
    // id are not. A later Start() opens a fresh dynamic channel.
    void Reset();

    // Requests a layout. Returns true only when the PDU was handed to the
    // transport. Before the server caps arrive the request is remembered and
    // sent automatically once caps are accepted; the return value is false
    // until then. Invalid monitors or a layout beyond the server caps are
    // rejected without sending.
    bool SetMonitors(
        const std::vector<rtsc::proto::DisplayControlMonitor>& monitors);

    // ---- state -------------------------------------------------------------
    bool ready() const { return ready_; }
    bool channel_opened() const { return channel_opened_; }
    uint32_t channel_id() const { return channel_id_; }
    bool has_pending() const { return has_pending_; }
    const rtsc::proto::DisplayControlCaps& caps() const { return caps_; }
    unsigned layout_count() const { return layout_count_; }

    // ---- IDrdynvcListener --------------------------------------------------
    void OnChannelCreated(uint32_t channel_id) override;
    void OnChannelData(uint32_t channel_id,
                       const std::vector<uint8_t>& data) override;
    void OnChannelClosed(uint32_t channel_id) override;

 private:
    bool SendPending();

    DrdynvcClient& transport_;
    uint32_t channel_id_ = 0;
    bool started_ = false;
    bool channel_opened_ = false;
    bool ready_ = false;
    rtsc::proto::DisplayControlCaps caps_;
    std::vector<rtsc::proto::DisplayControlMonitor> pending_;
    bool has_pending_ = false;
    unsigned layout_count_ = 0;
};

}  // namespace rtsc::channel
