// Dynamic virtual channel (drdynvc) client transport ([MS-RDPEDYC] 2.2).
//
// The URBDRC extension rides on a dynamic virtual channel named "URBDRC". This
// class implements the drdynvc state machine on top of a static virtual
// channel: it exchanges the capability PDU, creates and closes channels, and
// fragments / reassembles channel data.
//
// The static channel is already framed by the caller: SendFn receives a
// complete channel message (CHANNEL_PDU_HEADER + one drdynvc PDU), matching
// the other channel handlers in this project.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "rtsc/proto/channel.h"
#include "rtsc/proto/drdynvc.h"

namespace rtsc::channel {

// Callbacks delivered for inbound dynamic virtual channel activity.
class IDrdynvcListener {
 public:
    virtual ~IDrdynvcListener() = default;

    // DYNVC_CAPS_RSP ([MS-RDPEDYC] 2.2.3.1).
    virtual void OnCapsResponse(uint16_t) {}
    // DYNVC_CREATE_RSP ([MS-RDPEDYC] 2.2.2.2) succeeded.
    virtual void OnChannelCreated(uint32_t) {}
    // A complete channel data message (DYNVC_DATA_FIRST / DYNVC_DATA).
    virtual void OnChannelData(uint32_t, const std::vector<uint8_t>&) {}
    // DYNVC_CLOSE ([MS-RDPEDYC] 2.2.2.5).
    virtual void OnChannelClosed(uint32_t) {}
};

// CHANNEL_DEF ([MS-RDPEDYC] 2.2.2.1): the name and options of a dynamic
// virtual channel requested from the server.
struct ChannelDef {
    std::string name;
    uint32_t options = 0;
};

class DrdynvcClient {
 public:
    // Receives a complete channel message (CHANNEL_PDU_HEADER + drdynvc PDU).
    using SendFn = std::function<void(const std::vector<uint8_t>&)>;

    DrdynvcClient(IDrdynvcListener* listener, SendFn send);
    ~DrdynvcClient();

    // Sets the single listener that receives inbound channel activity.
    void AddListener(IDrdynvcListener* listener) { listener_ = listener; }
    void RemoveListener(IDrdynvcListener* listener) {
        if (listener_ == listener) listener_ = nullptr;
    }

    DrdynvcClient(const DrdynvcClient&) = delete;
    DrdynvcClient& operator=(const DrdynvcClient&) = delete;

    // Sends the DYNVC_CAPS_REQ PDU. Call once the static channel is joined.
    void Start();

    // Feeds one inbound static virtual-channel chunk (MCS Send Data user_data).
    void OnChannelData(const uint8_t* data, size_t size);

    // Opens a named dynamic virtual channel and returns its channel id. The
    // id is assigned locally and confirmed by DYNVC_CREATE_RSP.
    uint32_t CreateChannel(const ChannelDef& def);
    uint32_t CreateChannel(const std::string& name) {
        return CreateChannel(ChannelDef{name, 0});
    }

    // Sends a complete channel message on `channel_id`, fragmenting with
    // DYNVC_DATA_FIRST / DYNVC_DATA when it exceeds one PDU.
    void SendChannelData(uint32_t channel_id,
                         const std::vector<uint8_t>& data);

    // Closes a dynamic virtual channel.
    void CloseChannel(uint32_t channel_id);

    // ---- diagnostics -------------------------------------------------------
    bool ready() const { return caps_done_; }
    uint16_t version() const { return version_; }
    unsigned caps_request_count() const { return caps_request_count_; }
    unsigned create_request_count() const { return create_request_count_; }
    unsigned create_response_count() const { return create_response_count_; }
    unsigned close_count() const { return close_count_; }
    size_t pending_channels() const { return pending_.size(); }

 private:
    void OnCaps(const rtsc::proto::DynvcPdu& pdu);
    void OnCreateResponse(const rtsc::proto::DynvcPdu& pdu);
    void OnData(const rtsc::proto::DynvcPdu& pdu);
    void OnClose(const rtsc::proto::DynvcPdu& pdu);

    void SendPdu(const std::vector<uint8_t>& dvc_pdu);

    IDrdynvcListener* listener_;
    SendFn send_;
    rtsc::proto::ChannelReassembler reassembler_;

    bool caps_done_ = false;
    uint16_t version_ = 0;
    uint32_t next_channel_id_ = 1;
    std::map<uint32_t, std::string> pending_;
    std::map<uint32_t, std::vector<uint8_t>> buffers_;

    unsigned caps_request_count_ = 0;
    unsigned create_request_count_ = 0;
    unsigned create_response_count_ = 0;
    unsigned close_count_ = 0;
};

}  // namespace rtsc::channel
