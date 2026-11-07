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
#include <set>
#include <string>
#include <vector>

#include "rtsc/proto/bulk.h"
#include "rtsc/proto/channel.h"
#include "rtsc/proto/drdynvc.h"

namespace rtsc::channel {

// Callbacks delivered for inbound dynamic virtual channel activity.
class IDrdynvcListener {
 public:
    virtual ~IDrdynvcListener() = default;

    // DYNVC_CAPS_RSP ([MS-RDPEDYC] 2.2.3.1).
    virtual void OnCapsResponse(uint16_t) {}
    // DYNVC_CREATE_REQ ([MS-RDPEDYC] 2.2.2.1): the server asks the client to
    // open a channel named `name`. Return true to accept the channel; the
    // default rejects it (the client answers with a failure HRESULT).
    virtual bool OnChannelCreateRequest(const std::string&) { return false; }
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
    void AddListener(IDrdynvcListener* listener) {
        if (listener == nullptr) return;
        for (IDrdynvcListener* existing : listeners_) {
            if (existing == listener) return;
        }
        listeners_.push_back(listener);
    }
    void RemoveListener(IDrdynvcListener* listener) {
        for (size_t i = 0; i < listeners_.size(); ++i) {
            if (listeners_[i] == listener) {
                listeners_.erase(listeners_.begin() +
                                 static_cast<std::ptrdiff_t>(i));
                return;
            }
        }
    }

    DrdynvcClient(const DrdynvcClient&) = delete;
    DrdynvcClient& operator=(const DrdynvcClient&) = delete;

    // Sends the DYNVC_CAPS_REQ PDU. Call once the static channel is joined.
    void Start();

    // Drops the per-session protocol state after the transport was replaced
    // (auto-reconnect, [MS-RDPBCGR] 1.3.5). The configuration (listener,
    // send function) is kept; every negotiated version, capability exchange
    // state and dynamic channel id are not. A later Start() re-runs the
    // capability exchange against the new session.
    void Reset();

    // Feeds one inbound static virtual-channel chunk (MCS Send Data user_data).
    void OnChannelData(const uint8_t* data, size_t size);

    // Opens a named dynamic virtual channel and returns its channel id. The
    // id is assigned locally and confirmed by DYNVC_CREATE_RSP.
    uint32_t CreateChannel(const ChannelDef& def);
    uint32_t CreateChannel(const std::string& name) {
        return CreateChannel(ChannelDef{name, 0});
    }

    // Sends a complete channel message on `channel_id`, fragmenting with
    // DYNVC_DATA_FIRST / DYNVC_DATA when it exceeds one PDU. Returns false
    // (and sends nothing) when the channel is neither open nor pending: the
    // server would drop the data, and a closed id may already be reused.
    bool SendChannelData(uint32_t channel_id,
                         const std::vector<uint8_t>& data);

    // Closes a dynamic virtual channel.
    void CloseChannel(uint32_t channel_id);

    // ---- diagnostics -------------------------------------------------------
    bool ready() const { return caps_done_; }
    uint16_t version() const { return version_; }
    // Version actually in effect after answering the server with a
    // DYNVC_CAPS_RSP: min(client maximum, server-declared version).
    uint16_t negotiated_version() const { return negotiated_version_; }
    unsigned caps_request_count() const { return caps_request_count_; }
    // DYNVC_CAPS_RSP PDUs sent in answer to the server capabilities PDU.
    unsigned caps_response_count() const { return caps_response_count_; }
    unsigned create_request_count() const { return create_request_count_; }
    unsigned create_response_count() const { return create_response_count_; }
    unsigned server_create_count() const { return server_create_count_; }
    unsigned close_count() const { return close_count_; }
    // Compressed DATA PDUs decoded successfully ([MS-RDPEDYC] 2.2.3.3/2.2.3.4).
    unsigned compressed_data_count() const { return compressed_data_count_; }
    // Compressed DATA PDUs rejected by the RDP 8.0 bulk decompressor.
    unsigned compressed_failure_count() const {
        return compressed_failure_count_;
    }
    // Data sends refused because the channel was unknown or already closed.
    unsigned refused_data_count() const { return refused_data_count_; }
    size_t pending_channels() const { return pending_.size(); }

 private:
    void OnCaps(const rtsc::proto::DynvcPdu& pdu);
    void OnCreateResponse(const rtsc::proto::DynvcPdu& pdu);
    void OnCreateRequest(const rtsc::proto::DynvcPdu& pdu);
    void OnData(const rtsc::proto::DynvcPdu& pdu);
    void OnCompressedData(const rtsc::proto::DynvcPdu& pdu);
    void OnClose(const rtsc::proto::DynvcPdu& pdu);

    void SendPdu(const std::vector<uint8_t>& dvc_pdu);

    std::vector<IDrdynvcListener*> listeners_;
    SendFn send_;
    rtsc::proto::ChannelReassembler reassembler_;

    bool caps_done_ = false;
    uint16_t version_ = 0;
    uint16_t negotiated_version_ = 0;
    uint32_t next_channel_id_ = 1;
    std::map<uint32_t, std::string> pending_;
    std::set<uint32_t> open_channels_;
    // Channels closed locally, awaiting the server's DYNVC_CLOSE response.
    std::set<uint32_t> closing_;
    rtsc::proto::DynvcReassembler dvc_reassembler_;
    // One bulk decompression context per channel ([MS-RDPEDYC] 2.2.3.3): any
    // compressed block refers only to prior data on that same channel.
    std::map<uint32_t, rtsc::proto::BulkDecompressor> decompressors_;

    unsigned caps_request_count_ = 0;
    unsigned caps_response_count_ = 0;
    unsigned create_request_count_ = 0;
    unsigned create_response_count_ = 0;
    unsigned server_create_count_ = 0;
    unsigned close_count_ = 0;
    unsigned compressed_data_count_ = 0;
    unsigned compressed_failure_count_ = 0;
    unsigned refused_data_count_ = 0;
};

}  // namespace rtsc::channel
