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

// The fixed size of the Temporary Directory PDU's wszTempDir field
// ([MS-RDPECLIP] 2.2.2.3): a 520-byte block holding a null-terminated path.
constexpr size_t kTempDirectoryFieldSize = 520;

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

    // Arms the handler once the channel has been joined. The client does NOT
    // send a Monitor Ready PDU: [MS-RDPECLIP] 2.2.2.2 defines it as a
    // server-to-client PDU. The client answers the server's Monitor Ready PDU
    // with Clipboard Capabilities, the Temporary Directory and a Format List
    // ([MS-RDPECLIP] 1.3.2.1 steps 3-5). If the server's Monitor Ready PDU
    // arrived before Start(), the answer is sent now.
    void Start();

    // Overrides the temporary directory advertised to the server in the
    // Temporary Directory PDU. The path MUST be absolute on the local client
    // system ([MS-RDPECLIP] 2.2.2.3). When it is not set the handler falls back
    // to the platform temp directory (see SendTemporaryDirectory).
    void SetTemporaryDirectory(std::string path);

    // Re-sends the local clipboard format list. Called when the local clipboard
    // changed. A change caused by applying remote data is swallowed.
    void OnLocalClipboardChanged();

    // Requests the data for one of the remote formats ([MS-RDPECLIP] 3.1.5.4.1).
    void RequestRemoteFormat(uint32_t format);

    // ---- diagnostics -------------------------------------------------------
    bool started() const { return started_; }
    bool long_format_names() const { return long_format_names_; }
    bool server_caps_received() const { return server_caps_received_; }
    uint32_t client_flags() const { return kClientGeneralFlags; }
    uint32_t server_flags() const { return server_flags_; }
    const std::vector<uint32_t>& remote_formats() const {
        return remote_formats_;
    }
    // The peer's temporary directory, when a peer sends one (the PDU is
    // specified client-to-server, so this stays empty in a correct session).
    const std::string& temp_directory() const { return temp_directory_; }
    // The temporary directory this client advertised to the server.
    const std::string& local_temp_directory() const {
        return local_temp_directory_;
    }
    uint32_t locked_clipdata_id() const { return locked_clipdata_id_; }

    // Monitor Ready PDUs sent by this client. The client never sends one
    // ([MS-RDPECLIP] 2.2.2.2), so this stays 0; see the received counter.
    unsigned monitor_ready_count() const { return monitor_ready_count_; }
    unsigned clip_caps_count() const { return clip_caps_count_; }
    unsigned server_caps_count() const { return server_caps_count_; }
    // Monitor Ready PDUs received from the server.
    unsigned monitor_ready_received_count() const {
        return monitor_ready_received_count_;
    }
    // Format List Response PDUs this client sent to the server.
    unsigned format_list_response_count() const {
        return format_list_response_count_;
    }
    // Format List Response PDUs received from the server (its verdict on the
    // format list this client sent).
    unsigned format_list_response_received_count() const {
        return format_list_response_received_count_;
    }
    // The verdict carried by the last received Format List Response PDU:
    // true for CB_RESPONSE_OK (0x0001), false for CB_RESPONSE_FAIL (0x0002).
    bool last_format_list_response_ok() const {
        return last_format_list_response_ok_;
    }
    unsigned remote_format_list_count() const { return remote_format_list_count_; }
    unsigned local_format_list_count() const { return local_format_list_count_; }
    unsigned format_data_request_count() const {
        return format_data_request_count_;
    }
    unsigned format_data_response_count() const {
        return format_data_response_count_;
    }
    unsigned format_data_response_sent_count() const {
        return format_data_response_sent_count_;
    }
    // Temporary Directory PDUs this client sent to the server.
    unsigned temp_directory_sent_count() const {
        return temp_directory_sent_count_;
    }
    // Temporary Directory PDUs received (see temp_directory()).
    unsigned temp_directory_count() const { return temp_directory_count_; }
    unsigned lock_clipdata_count() const { return lock_clipdata_count_; }
    unsigned unlock_clipdata_count() const { return unlock_clipdata_count_; }

 private:
    void OnMessage(const std::vector<uint8_t>& message);
    void OnPdu(const rtsc::proto::CliprdrPdu& pdu);
    void OnServerClipCaps(const std::vector<uint8_t>& body);
    void OnMonitorReady();
    void OnFormatList(const rtsc::proto::CliprdrPdu& pdu);
    void OnFormatListResponse(const rtsc::proto::CliprdrPdu& pdu);
    void OnFormatDataRequest(const std::vector<uint8_t>& body);
    void OnFormatDataResponse(const rtsc::proto::CliprdrPdu& pdu);
    void OnTempDirectory(const std::vector<uint8_t>& body);
    void OnLockClipData(const std::vector<uint8_t>& body, bool lock);

    void SendPdu(rtsc::proto::CliprdrMsgType type, uint16_t flags,
                 const std::vector<uint8_t>& body);
    void SendClipCaps();
    void SendTemporaryDirectory();
    std::string ResolveLocalTempDirectory() const;
    void SendFormatList();
    void SendFormatListResponse(bool ok);
    void SendFormatDataResponse(const std::vector<uint8_t>& data, bool ok);
    // The initialization sequence triggered by the server Monitor Ready PDU.
    void RunInitializationSequence();
    uint32_t PickPreferredFormat() const;

    clipboard::Clipboard* clipboard_;
    SendFn send_;
    rtsc::proto::ChannelReassembler reassembler_;

    bool started_ = false;
    bool caps_sent_ = false;
    // True once the server's Monitor Ready PDU arrived, and true once the
    // answer (caps, temp directory, format list) was sent: the answer is sent
    // once, and only after the channel has been joined.
    bool monitor_ready_received_ = false;
    bool init_sequence_done_ = false;
    // Long format names are used only when both endpoints advertise
    // CB_USE_LONG_FORMAT_NAMES ([MS-RDPECLIP] 2.2.2.1.1.1). Until the server
    // capabilities arrive the client must not assume them: the conservative
    // default is the short format name variant.
    bool long_format_names_ = false;
    bool server_caps_received_ = false;
    uint32_t server_flags_ = 0;
    bool remote_sync_pending_ = false;
    uint32_t pending_format_ = 0;
    // The local clipboard fingerprint after the last remote write: the data
    // for `last_applied_format_` and the format list. One write can fire more
    // than one WM_CLIPBOARDUPDATE, so the fingerprint recognises (and swallows)
    // every event caused by our own write. `has_last_applied_` keeps the guard
    // armed even for a zero-length write, which carries no data to compare.
    bool has_last_applied_ = false;
    uint32_t last_applied_format_ = 0;
    std::vector<uint8_t> last_applied_data_;
    std::vector<uint32_t> last_applied_formats_;

    std::vector<uint32_t> remote_formats_;
    std::string temp_directory_;
    // The local temporary directory advertised to the server: the value set
    // with SetTemporaryDirectory(), or the platform temp directory.
    std::string local_temp_directory_;
    uint32_t locked_clipdata_id_ = 0;

    unsigned monitor_ready_count_ = 0;
    unsigned monitor_ready_received_count_ = 0;
    unsigned clip_caps_count_ = 0;
    unsigned server_caps_count_ = 0;
    unsigned remote_format_list_count_ = 0;
    unsigned local_format_list_count_ = 0;
    unsigned format_list_response_count_ = 0;
    unsigned format_list_response_received_count_ = 0;
    bool last_format_list_response_ok_ = false;
    unsigned format_data_request_count_ = 0;
    unsigned format_data_response_count_ = 0;
    unsigned format_data_response_sent_count_ = 0;
    unsigned temp_directory_count_ = 0;
    unsigned temp_directory_sent_count_ = 0;
    unsigned lock_clipdata_count_ = 0;
    unsigned unlock_clipdata_count_ = 0;
};

}  // namespace rtsc::channel
