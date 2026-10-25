// Clipboard virtual channel (cliprdr) client handler ([MS-RDPECLIP]).
//
// The connection driver hands this class the raw MCS Send Data user_data of the
// cliprdr static virtual channel, which is a CHANNEL_PDU_HEADER followed by one
// or more cliprdr PDUs. The handler reassembles the chunked channel message and
// runs the clipboard virtual channel protocol: it exchanges capabilities,
// advertises the local clipboard formats, and synchronises clipboard data with
// the remote peer.
//
// Reference: [MS-RDPECLIP] 1.3.2 (protocol flow) and 2.2 (message syntax).

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "rtsc/clipboard/clipboard.h"
#include "rtsc/proto/channel.h"
#include "rtsc/proto/cliprdr.h"

namespace rtsc::channel {

// General capability flags ([MS-RDPECLIP] 2.2.2.1.1.1).
constexpr uint32_t kClipCapsUseLongFormatNames = 0x00000002;
constexpr uint32_t kClipCapsStreamFileClip = 0x00000004;
constexpr uint32_t kClipCapsFileClipNoPaths = 0x00000008;
constexpr uint32_t kClipCapsCanLockClipData = 0x00000010;
constexpr uint32_t kClipCapsHugeFileSupport = 0x00000020;

// The flags this client sets in its CB_CLIP_CAPS. Long format names are used;
// stream file clip is not implemented, so its flags are not advertised.
constexpr uint32_t kClientGeneralFlags = kClipCapsUseLongFormatNames;

class CliprdrClient {
 public:
    // Receives a complete channel message (CHANNEL_PDU_HEADER + cliprdr PDU).
    // The caller wraps it in an MCS Send Data Request and writes it.
    using SendFn = std::function<void(const std::vector<uint8_t>&)>;

    CliprdrClient(clipboard::Clipboard* clipboard, SendFn send);
    ~CliprdrClient();

    CliprdrClient(const CliprdrClient&) = delete;
    CliprdrClient& operator=(const CliprdrClient&) = delete;

    // Feeds one inbound virtual-channel chunk (the MCS Send Data user_data). A
    // message may be split across calls.
    void OnChannelData(const uint8_t* data, size_t size);

    // Sends the initialization sequence: CB_MONITOR_READY, CB_CLIP_CAPS, and a
    // CB_FORMAT_LIST of the formats currently on the local clipboard. Call once
    // the channel has been joined.
    void Start();

    // Re-sends the local clipboard format list. Called when the local clipboard
    // changed. A change caused by applying remote data is swallowed.
    void OnLocalClipboardChanged();

    // Requests the data for one of the remote formats ([MS-RDPECLIP] 3.1.5.4.1).
    void RequestRemoteFormat(uint32_t format);

    // ---- diagnostics -------------------------------------------------------
    bool started() const { return started_; }
    bool long_format_names() const { return long_format_names_; }
    uint32_t client_flags() const { return kClientGeneralFlags; }
    uint32_t server_flags() const { return server_flags_; }
    const std::vector<uint32_t>& remote_formats() const {
        return remote_formats_;
    }
    const std::string& temp_directory() const { return temp_directory_; }
    uint32_t locked_clipdata_id() const { return locked_clipdata_id_; }

    unsigned monitor_ready_count() const { return monitor_ready_count_; }
    unsigned clip_caps_count() const { return clip_caps_count_; }
    unsigned server_caps_count() const { return server_caps_count_; }
    unsigned remote_format_list_count() const { return remote_format_list_count_; }
    unsigned local_format_list_count() const { return local_format_list_count_; }
    unsigned format_list_response_count() const {
        return format_list_response_count_;
    }
    unsigned format_data_request_count() const {
        return format_data_request_count_;
    }
    unsigned format_data_response_count() const {
        return format_data_response_count_;
    }
    unsigned format_data_response_sent_count() const {
        return format_data_response_sent_count_;
    }
    unsigned temp_directory_count() const { return temp_directory_count_; }
    unsigned lock_clipdata_count() const { return lock_clipdata_count_; }
    unsigned unlock_clipdata_count() const { return unlock_clipdata_count_; }

 private:
    void OnMessage(const std::vector<uint8_t>& message);
    void OnPdu(const rtsc::proto::CliprdrPdu& pdu);
    void OnServerClipCaps(const std::vector<uint8_t>& body);
    void OnFormatList(const rtsc::proto::CliprdrPdu& pdu);
    void OnFormatDataRequest(const std::vector<uint8_t>& body);
    void OnFormatDataResponse(const rtsc::proto::CliprdrPdu& pdu);
    void OnTempDirectory(const std::vector<uint8_t>& body);
    void OnLockClipData(const std::vector<uint8_t>& body, bool lock);

    void SendPdu(rtsc::proto::CliprdrMsgType type, uint16_t flags,
                 const std::vector<uint8_t>& body);
    void SendClipCaps();
    void SendFormatList();
    void SendFormatListResponse(bool ok);
    void SendFormatDataResponse(const std::vector<uint8_t>& data, bool ok);
    uint32_t PickPreferredFormat() const;

    clipboard::Clipboard* clipboard_;
    SendFn send_;
    rtsc::proto::ChannelReassembler reassembler_;

    bool started_ = false;
    bool caps_sent_ = false;
    // Long format names are used when both endpoints advertise them; until the
    // server capabilities arrive the client assumes they are supported (it
    // advertises them), so it sends the long variant.
    bool long_format_names_ = (kClientGeneralFlags & kClipCapsUseLongFormatNames) != 0;
    uint32_t server_flags_ = 0;
    bool remote_sync_pending_ = false;
    uint32_t pending_format_ = 0;

    std::vector<uint32_t> remote_formats_;
    std::string temp_directory_;
    uint32_t locked_clipdata_id_ = 0;

    unsigned monitor_ready_count_ = 0;
    unsigned clip_caps_count_ = 0;
    unsigned server_caps_count_ = 0;
    unsigned remote_format_list_count_ = 0;
    unsigned local_format_list_count_ = 0;
    unsigned format_list_response_count_ = 0;
    unsigned format_data_request_count_ = 0;
    unsigned format_data_response_count_ = 0;
    unsigned format_data_response_sent_count_ = 0;
    unsigned temp_directory_count_ = 0;
    unsigned lock_clipdata_count_ = 0;
    unsigned unlock_clipdata_count_ = 0;
};

}  // namespace rtsc::channel
