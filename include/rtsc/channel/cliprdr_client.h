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

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "rtsc/clipboard/clipboard.h"
#include "rtsc/clipboard/file_list.h"
#include "rtsc/proto/channel.h"
#include "rtsc/proto/cliprdr.h"

namespace rtsc::channel {

// General capability flags ([MS-RDPECLIP] 2.2.2.1.1.1).
constexpr uint32_t kClipCapsUseLongFormatNames = 0x00000002;
constexpr uint32_t kClipCapsStreamFileClip = 0x00000004;
constexpr uint32_t kClipCapsFileClipNoPaths = 0x00000008;
constexpr uint32_t kClipCapsCanLockClipData = 0x00000010;
constexpr uint32_t kClipCapsHugeFileSupport = 0x00000020;

// The general flags this client advertises by default: long format names.
// Stream file clip (0x04) is added by EnableFileClip() and huge-file support
// (0x20) by EnableHugeFileSupport().
constexpr uint32_t kClientGeneralFlagsBase = kClipCapsUseLongFormatNames;

// The fixed size of the Temporary Directory PDU's wszTempDir field
// ([MS-RDPECLIP] 2.2.2.3): a 520-byte block holding a null-terminated path.
constexpr size_t kTempDirectoryFieldSize = 520;

// A single file range this client is willing to serve ([MS-RDPECLIP] treats
// oversized requests as an error). 1 MiB keeps a large copy move bounded while
// still streaming.
constexpr uint64_t kMaxServeRange = 1u << 20;

// The default window size used by the download range loop.
constexpr uint32_t kDefaultFileTransferWindow = 64 * 1024;

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

    // Drops the per-session protocol state after the transport was replaced
    // (auto-reconnect, [MS-RDPBCGR] 1.3.5). The configuration (clipboard, file
    // clip flags, temporary directory override) is kept; every negotiated
    // flag, the reassembly buffer and the in-flight file transfers are not.
    // A later Start() re-runs the initialization sequence against the new
    // session. In-flight transfers are completed as failures so a caller
    // waiting on a callback is never left hanging.
    void Reset();

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

    // ---- stream file clip (CB_FILECONTENTS) --------------------------------
    //
    // Direction A: this client serves a local file list through an injected
    // FileListProvider and downloads remote files through CB_FILECONTENTS.
    // Direction B is a FileListProvider implementation, not part of this class:
    // DropFileList (rtsc/clipboard/drop_files.h) serves a local CF_HDROP
    // selection and is covered by tests/test_drop_files.cpp. What lives here is
    // the gate: with no provider installed every file-contents request fails.

    // Advertises CB_STREAM_FILECLIP_ENABLED in the next Clipboard Capabilities
    // PDU. Off by default.
    void EnableFileClip();
    // Advertises CB_HUGE_FILE_SUPPORT_ENABLED (0x20) independently. Off by
    // default; the GUI never turns it on.
    void EnableHugeFileSupport();
    // Installs the local file-list server. nullptr leaves the serve path
    // failing every request (the direction-B store gate).
    void SetFileListProvider(rtsc::clipboard::FileListProvider* provider);

    // Requests the remote FILELIST (a Format Data Request for the format the
    // peer advertised as FileGroupDescriptorW). No-op until the server
    // negotiated CB_STREAM_FILECLIP_ENABLED and announced the file format, and
    // while a format-data request is already in flight.
    void RequestRemoteFileList();

    // Callback for a finished download:
    // (lindex, file name, size, bytes, ok).
    using FileContentsDone =
        std::function<void(uint32_t, std::u16string, uint64_t,
                           const std::vector<uint8_t>&, bool)>;

    // Starts downloading remote file `lindex`. Returns false when the peer did
    // not negotiate stream file clip, when a transfer is already in flight, or
    // when the descriptor is a directory / out of range.
    bool RequestRemoteFile(uint32_t lindex, FileContentsDone done);

    // Per-transfer timeout in milliseconds. 0 disables timeouts. Default 30 s.
    void SetTransferTimeoutMs(uint32_t ms);
    // Bytes requested per RANGE chunk of a download. 0 restores the default.
    void SetFileTransferWindow(uint32_t bytes);

    // Ends every in-flight transfer as failed. Must be called periodically with
    // a recent timestamp so transfer timeouts fire.
    void Poll(std::chrono::steady_clock::time_point now);
    void CancelRemoteFileContents();

    // ---- diagnostics -------------------------------------------------------
    bool started() const { return started_; }
    bool long_format_names() const { return long_format_names_; }
    bool server_caps_received() const { return server_caps_received_; }
    uint32_t client_flags() const { return client_general_flags_; }
    uint32_t server_flags() const { return server_flags_; }
    bool file_clip_enabled() const { return file_clip_enabled_; }
    bool huge_file_support() const { return huge_enabled_; }
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

    // The file-clip diagnostics.
    unsigned file_contents_request_sent() const {
        return file_contents_request_sent_;
    }
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
    unsigned remote_file_list_received() const {
        return remote_file_list_received_;
    }
    unsigned transfer_timeout_count() const { return transfer_timeout_count_; }
    const std::vector<rtsc::proto::CliprdrFileDescriptor>& remote_file_list()
        const {
        return remote_file_list_;
    }
    uint32_t remote_file_list_format_id() const {
        return remote_file_list_format_id_;
    }
    bool have_remote_file_list() const { return have_remote_file_list_; }
    size_t in_flight_file_ops() const { return pending_.size(); }
    // The format id of the outstanding Format Data Request (0 = none). A
    // test/diagnostic hook for the D4 stale-response guard.
    uint32_t pending_format_for_test() const { return pending_format_; }

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
    void OnFileContentsRequest(const rtsc::proto::CliprdrPdu& pdu);
    void OnFileContentsResponse(const rtsc::proto::CliprdrPdu& pdu);
    // Serves a validated SIZE / RANGE request from the installed provider.
    void ServeFileSizeRequest(const rtsc::proto::CliprdrFileContentsRequest& req);
    void ServeFileRangeRequest(const rtsc::proto::CliprdrFileContentsRequest& req);

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

    // Sends one CB_FILECONTENTS_REQUEST. The position is a 64-bit offset split
    // into the low/high halves.
    void SendFileContentsRequest(uint32_t stream_id, uint32_t lindex,
                                 uint32_t dw_flags, uint64_t position,
                                 uint32_t cb_requested, bool has_clip_data_id,
                                 uint32_t clip_data_id);
    // Sends a CB_FILECONTENTS_RESPONSE with the given verdict and payload.
    void SendFileContentsResponse(uint32_t stream_id, bool ok,
                                  const std::vector<uint8_t>& data);
    // Start (or continue) the RANGE loop of the transfer `stream_id`; finishes
    // the transfer when the requested window size drops to zero.
    void SendFileRangeRequest(uint32_t stream_id);
    // Allocates a stream id that is neither 0 nor currently in flight.
    uint32_t AllocateStreamId();
    std::u16string FilenameFor(uint32_t lindex) const;

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
    // The general flags this client advertises. Long format names are always
    // set; EnableFileClip()/EnableHugeFileSupport() add their bits.
    uint32_t client_general_flags_ = kClientGeneralFlagsBase;
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

    // ---- stream file clip state ----
    bool file_clip_enabled_ = false;
    bool huge_enabled_ = false;
    rtsc::clipboard::FileListProvider* provider_ = nullptr;
    // The format id the peer announced as FileGroupDescriptorW; 0 when the
    // current remote format list carries no file format.
    uint32_t remote_file_list_format_id_ = 0;
    bool have_remote_file_list_ = false;
    // The remote FILELIST last received as format data. Never written to the
    // local clipboard.
    std::vector<rtsc::proto::CliprdrFileDescriptor> remote_file_list_;
    // One in-flight download. kMaxInflightFileOps bounds it; on a successful
    // slot reuse next_stream_id_ walks over 0 and any occupied id.
    struct PendingFileContents {
        uint32_t lindex = 0;
        uint64_t offset = 0;
        uint64_t file_size = 0;
        bool size_pending = true;
        uint32_t cb_requested = 0;
        std::vector<uint8_t> data;
        FileContentsDone done;
        std::chrono::steady_clock::time_point deadline;
    };
    static constexpr size_t kMaxInflightFileOps = 1;
    std::map<uint32_t, PendingFileContents> pending_;
    uint32_t next_stream_id_ = 0;
    uint32_t transfer_timeout_ms_ = 30000;
    uint32_t transfer_window_ = kDefaultFileTransferWindow;

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
    unsigned file_contents_request_sent_ = 0;
    unsigned file_contents_request_received_ = 0;
    unsigned file_contents_request_rejected_ = 0;
    unsigned file_contents_response_sent_ = 0;
    unsigned file_contents_response_received_ = 0;
    unsigned remote_file_list_received_ = 0;
    unsigned transfer_timeout_count_ = 0;
};

}  // namespace rtsc::channel
