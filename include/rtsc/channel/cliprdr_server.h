// Clipboard virtual channel (cliprdr) server handler ([MS-RDPECLIP]).
//
// The mirror of cliprdr_client.h on the server role: the connection driver
// hands this class the raw MCS Send Data user_data of the cliprdr static
// virtual channel, it reassembles the chunked channel message and runs the
// clipboard virtual channel protocol for the *server* half ([MS-RDPECLIP]
// 1.3.2.1). Unlike the client, the server speaks first: Start() sends Clipboard
// Capabilities, then Monitor Ready, then a Format List (an empty list is still
// sent). That ordering is what avoids the server/client initialization
// deadlock (design: "服务器先发").
//
// One CliprdrServer is created per session, but every session shares one local
// clipboard (shared-desktop / last-writer-wins semantics); the Win32 backend
// serializes access. The handler is used only from the session thread.
//
// Reference: [MS-RDPECLIP] 1.3.2, 2.2 (message syntax), 3.1.5 (server rules).

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "rtsc/channel/cliprdr_client.h"
#include "rtsc/clipboard/clipboard.h"
#include "rtsc/clipboard/file_list.h"
#include "rtsc/proto/channel.h"
#include "rtsc/proto/cliprdr.h"

namespace rtsc::channel {

// The general flags the server advertises by default: long format names, the
// same base as the client. STREAM_FILECLIP (0x04) is added by
// EnableFileClip() and HUGE_FILE_SUPPORT (0x20) by EnableHugeFileSupport().
constexpr uint32_t kServerGeneralFlagsBase = kClipCapsUseLongFormatNames;

class CliprdrServer {
 public:
    // Receives one complete channel chunk (CHANNEL_PDU_HEADER + cliprdr data).
    // The caller wraps it in an MCS Send Data Indication and writes it. A
    // message larger than the negotiated chunk size is delivered as several
    // chunks, each with its own CHANNEL_PDU_HEADER.
    using SendFn = std::function<void(const std::vector<uint8_t>&)>;

    CliprdrServer(clipboard::Clipboard* clipboard, SendFn send);
    ~CliprdrServer();

    CliprdrServer(const CliprdrServer&) = delete;
    CliprdrServer& operator=(const CliprdrServer&) = delete;

    // ---- connection lifecycle ----------------------------------------------

    // Arms the handler and runs the server initialization sequence exactly
    // once: Clipboard Capabilities, Monitor Ready, then a Format List ([MS-
    // RDPECLIP] 1.3.2.1 -- the server's Monitor Ready PDU is what orders the
    // client's initialization answer). The Format List is sent even when the
    // local clipboard is empty. Idempotent.
    void Start();

    // Feeds one inbound virtual-channel chunk (the MCS Send Data user_data of
    // one channel indication). A message may be split across calls, and may
    // legitimately arrive before Start() (pre-active channel data).
    void OnChannelData(const uint8_t* data, size_t size);

    // ---- local clipboard ---------------------------------------------------

    // Re-sends the local (server) clipboard format list. Called when the
    // server clipboard changed outside the protocol. A change caused by
    // applying remote data (RequestClientFormat) is swallowed.
    void OnLocalClipboardChanged();

    // Requests remote (client) clipboard data for one format ([MS-RDPECLIP]
    // 3.1.5.4.1). The client's answer is written to the local clipboard and the
    // resulting change is swallowed via the post-application sequence number.
    // Returns false when the channel is not started, the format is a
    // file-list format, or a request is already in flight.
    bool RequestClientFormat(uint32_t format);

    // Periodic housekeeping: detects external local-clipboard changes through
    // the sequence number and reports them (the server has no window message
    // pump). Call on the ~1 s server read tick. `now` is for future transfer
    // timeouts.
    void Poll(std::chrono::steady_clock::time_point now);

    // ---- stream file clip --------------------------------------------------
    //
    // v1 scope keeps text + DIB; the server does not advertise
    // CB_STREAM_FILECLIP_ENABLED unless EnableFileClip() is called, and every
    // CB_FILECONTENTS_REQUEST fails when file clip is off (or no provider is
    // installed).

    void EnableFileClip();
    void EnableHugeFileSupport();
    void SetFileListProvider(rtsc::clipboard::FileListProvider* provider);

    // ---- diagnostics -------------------------------------------------------

    // The protocol state machine (design §3.2):
    //   kIdle -> Start() -> kInitSent -> client caps -> kCapsReceived ->
    //   first client Format List -> kSynced -> (both) -> kActive.
    enum class State { kIdle, kInitSent, kCapsReceived, kSynced, kActive };
    static const char* to_string(State s);
    State state() const;
    bool started() const { return started_; }
    bool long_format_names() const { return long_format_names_; }
    bool client_caps_received() const { return client_caps_received_; }
    // The flags this server advertises (Start()/caps).
    uint32_t server_flags() const { return server_general_flags_; }
    // The flags the client advertised in its Clipboard Capabilities.
    uint32_t client_flags() const { return client_general_flags_; }
    bool file_clip_enabled() const { return file_clip_enabled_; }
    bool huge_file_support() const { return huge_enabled_; }
    const std::vector<uint32_t>& remote_formats() const {
        return remote_formats_;
    }
    // The temporary directory the client announced (a client-to-server PDU;
    // where the server may deposit files it copies to the client).
    const std::string& temp_directory() const { return temp_directory_; }
    uint32_t locked_clipdata_id() const { return locked_clipdata_id_; }

    unsigned monitor_ready_count() const { return monitor_ready_count_; }
    unsigned clip_caps_count() const { return clip_caps_count_; }
    unsigned client_caps_count() const { return client_caps_count_; }
    unsigned local_format_list_count() const { return local_format_list_count_; }
    unsigned remote_format_list_count() const { return remote_format_list_count_; }
    unsigned format_list_response_count() const {
        return format_list_response_count_;
    }
    unsigned format_list_response_received_count() const {
        return format_list_response_received_count_;
    }
    bool last_format_list_response_ok() const {
        return last_format_list_response_ok_;
    }
    unsigned format_data_request_count() const {
        return format_data_request_count_;
    }
    unsigned format_data_request_sent() const {
        return format_data_request_sent_count_;
    }
    unsigned format_data_response_sent() const {
        return format_data_response_sent_count_;
    }
    unsigned format_data_response_received() const {
        return format_data_response_received_count_;
    }
    unsigned format_data_applied_count() const {
        return format_data_applied_count_;
    }
    unsigned temp_directory_count() const { return temp_directory_count_; }
    unsigned lock_clipdata_count() const { return lock_clipdata_count_; }
    unsigned unlock_clipdata_count() const { return unlock_clipdata_count_; }
    unsigned malformed_pdu_count() const { return malformed_pdu_count_; }
    unsigned file_contents_request_received() const {
        return file_contents_request_received_;
    }
    unsigned file_contents_request_rejected() const {
        return file_contents_request_rejected_;
    }
    unsigned file_contents_response_sent() const {
        return file_contents_response_sent_;
    }
    unsigned file_contents_response_received() const {
        return file_contents_response_received_;
    }
    // The format id of the outstanding Format Data Request (0 = none). Test
    // hook mirroring the client's stale-response guard.
    uint32_t pending_format_for_test() const { return pending_format_; }

 private:
    void OnMessage(const std::vector<uint8_t>& message);
    void OnPdu(const rtsc::proto::CliprdrPdu& pdu);
    void OnClientClipCaps(const std::vector<uint8_t>& body);
    void OnFormatList(const rtsc::proto::CliprdrPdu& pdu);
    void OnFormatListResponse(const rtsc::proto::CliprdrPdu& pdu);
    void OnFormatDataRequest(const std::vector<uint8_t>& body);
    void OnFormatDataResponse(const rtsc::proto::CliprdrPdu& pdu);
    void OnTempDirectory(const std::vector<uint8_t>& body);
    void OnLockClipData(const std::vector<uint8_t>& body, bool lock);
    void OnFileContentsRequest(const rtsc::proto::CliprdrPdu& pdu);
    void OnFileContentsResponse(const rtsc::proto::CliprdrPdu& pdu);
    void ServeFileSizeRequest(const rtsc::proto::CliprdrFileContentsRequest& req);
    void ServeFileRangeRequest(const rtsc::proto::CliprdrFileContentsRequest& req);

    void SendPdu(rtsc::proto::CliprdrMsgType type, uint16_t flags,
                 const std::vector<uint8_t>& body);
    void SendClipCaps();
    void SendFormatList();
    void SendFormatListResponse(bool ok);
    void SendFormatDataResponse(const std::vector<uint8_t>& data, bool ok);
    void SendFileContentsResponse(uint32_t stream_id, bool ok,
                                  const std::vector<uint8_t>& data);
    uint32_t PickPreferredFormat() const;

    clipboard::Clipboard* clipboard_;
    SendFn send_;
    rtsc::proto::ChannelReassembler reassembler_;

    bool started_ = false;
    bool client_caps_received_ = false;
    bool first_format_list_received_ = false;
    // Long format names are used only when both endpoints advertise
    // CB_USE_LONG_FORMAT_NAMES. The server always advertises it, so the client
    // flag decides the negotiated variant; until the client caps arrive the
    // conservative default is the short variant (mirrors the client).
    bool long_format_names_ = false;
    uint32_t client_general_flags_ = 0;
    uint32_t server_general_flags_ = kServerGeneralFlagsBase;

    bool file_clip_enabled_ = false;
    bool huge_enabled_ = false;
    rtsc::clipboard::FileListProvider* provider_ = nullptr;

    uint32_t pending_format_ = 0;
    std::vector<uint32_t> remote_formats_;
    std::string temp_directory_;
    uint32_t locked_clipdata_id_ = 0;

    // ---- sequence-based change detection -----------------------------------
    // The server clipboard has no window message pump, so external changes are
    // found by Poll() comparing sequence_number(). When the server applies a
    // remote write itself the post-application sequence is remembered and the
    // resulting "change" is swallowed ("自回声吞用应用后 seq").
    uint64_t last_observed_seq_ = 0;
    bool has_observed_seq_ = false;
    uint64_t last_applied_seq_ = 0;
    bool has_last_applied_seq_ = false;

    unsigned monitor_ready_count_ = 0;
    unsigned clip_caps_count_ = 0;
    unsigned client_caps_count_ = 0;
    unsigned local_format_list_count_ = 0;
    unsigned remote_format_list_count_ = 0;
    unsigned format_list_response_count_ = 0;
    unsigned format_list_response_received_count_ = 0;
    bool last_format_list_response_ok_ = false;
    unsigned format_data_request_count_ = 0;
    unsigned format_data_request_sent_count_ = 0;
    unsigned format_data_response_sent_count_ = 0;
    unsigned format_data_response_received_count_ = 0;
    unsigned format_data_applied_count_ = 0;
    unsigned temp_directory_count_ = 0;
    unsigned lock_clipdata_count_ = 0;
    unsigned unlock_clipdata_count_ = 0;
    unsigned malformed_pdu_count_ = 0;
    unsigned file_contents_request_received_ = 0;
    unsigned file_contents_request_rejected_ = 0;
    unsigned file_contents_response_sent_ = 0;
    unsigned file_contents_response_received_ = 0;
};

}  // namespace rtsc::channel