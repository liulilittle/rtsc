// Display Control dynamic virtual channel client ([MS-RDPEDISP]).

#include "rtsc/channel/display_control_client.h"

namespace rtsc::channel {
namespace {

constexpr const char* kChannelName =
    "Microsoft::Windows::RDS::DisplayControl";

}  // namespace

DisplayControlClient::DisplayControlClient(DrdynvcClient& transport)
    : transport_(transport) {}

DisplayControlClient::~DisplayControlClient() {
    transport_.RemoveListener(this);
}

void DisplayControlClient::Reset() {
    channel_id_ = 0;
    started_ = false;
    channel_opened_ = false;
    ready_ = false;
    caps_ = rtsc::proto::DisplayControlCaps{};
    pending_.clear();
    has_pending_ = false;
}

bool DisplayControlClient::Start() {
    if (started_) return true;
    transport_.AddListener(this);
    channel_id_ = transport_.CreateChannel(kChannelName);
    if (channel_id_ == 0) {
        transport_.RemoveListener(this);
        return false;
    }
    started_ = true;
    return true;
}

void DisplayControlClient::OnChannelCreated(uint32_t channel_id) {
    if (channel_id == channel_id_) channel_opened_ = true;
}

void DisplayControlClient::OnChannelData(
    uint32_t channel_id, const std::vector<uint8_t>& data) {
    if (channel_id != channel_id_) return;
    rtsc::proto::DisplayControlCaps caps;
    if (!rtsc::proto::ParseDisplayControlCaps(data.data(), data.size(),
                                              caps)) {
        // A malformed caps PDU leaves the channel unusable: do not send a
        // layout against caps we could not validate.
        ready_ = false;
        return;
    }
    caps_ = caps;
    ready_ = true;
    if (has_pending_) SendPending();
}

void DisplayControlClient::OnChannelClosed(uint32_t channel_id) {
    if (channel_id != channel_id_) return;
    channel_opened_ = false;
    ready_ = false;
    caps_ = rtsc::proto::DisplayControlCaps{};
}

bool DisplayControlClient::SetMonitors(
    const std::vector<rtsc::proto::DisplayControlMonitor>& monitors) {
    if (!rtsc::proto::DisplayControlLayoutValid(monitors)) return false;
    if (!ready_) {
        // The server has not stated its caps yet; keep only the latest request.
        pending_ = monitors;
        has_pending_ = true;
        return false;
    }
    if (!rtsc::proto::DisplayControlLayoutWithinCaps(monitors, caps_)) {
        return false;
    }
    const std::vector<uint8_t> pdu =
        rtsc::proto::EncodeDisplayControlMonitorLayout(monitors);
    if (pdu.empty()) return false;
    if (!transport_.SendChannelData(channel_id_, pdu)) return false;
    ++layout_count_;
    pending_.clear();
    has_pending_ = false;
    return true;
}

bool DisplayControlClient::SendPending() {
    if (!has_pending_) return true;
    const std::vector<rtsc::proto::DisplayControlMonitor> monitors = pending_;
    pending_.clear();
    has_pending_ = false;
    if (!rtsc::proto::DisplayControlLayoutValid(monitors)) return false;
    if (!rtsc::proto::DisplayControlLayoutWithinCaps(monitors, caps_)) {
        return false;
    }
    const std::vector<uint8_t> pdu =
        rtsc::proto::EncodeDisplayControlMonitorLayout(monitors);
    if (pdu.empty()) return false;
    if (!transport_.SendChannelData(channel_id_, pdu)) return false;
    ++layout_count_;
    return true;
}

}  // namespace rtsc::channel
