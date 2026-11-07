// Device redirection virtual channel (rdpdr) client handler ([MS-RDPEFS] 3.1).
//
// The connection driver hands this class the raw MCS Send Data user_data of the
// rdpdr static virtual channel, which is a CHANNEL_PDU_HEADER followed by one
// or more rdpdr PDUs. The handler reassembles the chunked channel message and
// runs the drive redirection protocol: it answers the server announce, sends
// its client name and capability, announces the redirected drives, and serves
// the server's file I/O requests against the local file system.
//
// Reference: [MS-RDPEFS] 3.1 (client), 2.2 (message syntax).

#pragma once

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "rtsc/proto/channel.h"
#include "rtsc/proto/rdpdr.h"
#include "rtsc/proto/smartcard.h"
#include "rtsc/rdpdr/file_system.h"
#include "rtsc/rdpdr/lock_table.h"
#include "rtsc/rdpdr/path_guard.h"
#include "rtsc/rdpdr/printer_backend.h"
#include "rtsc/rdpdr/serial_backend.h"

namespace rtsc::smartcard {
class ISmartCardBackend;
}  // namespace rtsc::smartcard

namespace rtsc::channel {

// The path containment guard shared with every redirected-side handler; see
// rtsc/rdpdr/path_guard.h. Kept as an alias so existing call sites that spell
// the fully qualified rtsc::channel::ResolvePathUnderRoot keep working.
using rtsc::rdpdr::ResolvePathUnderRoot;

class RdpdrClient {
 public:
    // Receives a complete channel message (CHANNEL_PDU_HEADER + rdpdr PDU).
    // The caller wraps it in an MCS Send Data Request and writes it.
    using SendFn = std::function<void(const std::vector<uint8_t>&)>;

    // One redirected device. `dos_name` is the 8-character field of the
    // DEVICE_ANNOUNCE (e.g. "C:" for a drive, "COM1" for a serial port);
    // `local_root` is the local directory a drive maps to (e.g. "C:\\") and is
    // unused for serial devices.
    enum class DeviceType { kDrive = 0, kSerial = 1, kPrinter = 2 };
    struct Device {
        uint32_t device_id = 0;
        std::string dos_name;
        std::string local_root;
        DeviceType type = DeviceType::kDrive;
        // Printer devices: the local queue name and the server-side driver.
        std::string printer_name;
        std::string printer_driver;
    };

    // Protocol phase, following [MS-RDPEFS] 3.1.3.
    enum class Phase {
        kAwaitServerAnnounce,
        kAwaitClientIdConfirm,
        kReady,
    };

    RdpdrClient(rdpdr::IFileSystem* fs, std::vector<Device> devices,
                std::string client_name, SendFn send);
    ~RdpdrClient();

    // Enables smart card redirection ([MS-RDPESC] 3.1.4). `backend` must
    // outlive this handler (rtsc_gui owns it for the whole session). Passing
    // nullptr disables the feature and the SCARD device is not announced.
    //
    // Must be called before the first inbound message: the device list is sent
    // when the server confirms the client id, and [MS-RDPEFS] 2.2.2.9 has no
    // "add device later" form for a device that was never announced.
    void EnableSmartCard(::rtsc::smartcard::ISmartCardBackend* backend);

    // Enables serial port redirection. Serial devices configured in `devices`
    // are announced with RDPDR_DTYP_SERIAL and their I/O is routed to
    // `backend`. Must be called before the first inbound message (like
    // EnableSmartCard). Passing nullptr leaves serial devices announced but
    // every CREATE fails closed with ACCESS_DENIED.
    void EnableSerial(rdpdr::ISerialBackend* backend);

    // Enables printer redirection. Printer devices configured in `devices` are
    // announced with RDPDR_DTYP_PRINT and their job I/O is routed to
    // `backend`. Must be called before the first inbound message. Passing
    // nullptr leaves printers announced but every CREATE fails closed.
    void EnablePrinter(rdpdr::IPrinterBackend* backend);

    // Removes an announced device from the server's view ([MS-RDPEFS]
    // 2.2.3.2). Open files that belong to the device are closed first. Returns
    // false (and sends nothing) when the id is not an announced device or the
    // handshake has not reached the device-list stage.
    bool RemoveDevice(uint32_t device_id);

    // Smart card IOCTL execution mode. In the default (synchronous) mode
    // OnChannelData() runs the backend call on the caller's thread. In
    // asynchronous mode it only queues the call; a worker thread runs it and
    // PollSmartCard() must be called periodically on the thread that owns the
    // transport to write the completions back. This keeps a long
    // SCardGetStatusChange (up to the request timeout, possibly INFINITE) from
    // freezing the GUI event loop.
    //
    // Both methods must be called on the same thread (the transport owner).
    // The backend must outlive this handler: the worker is joined in the
    // destructor, and the join can block until the in-flight backend call
    // returns.
    void SetAsyncSmartCard(bool enable);
    // Sends every completion the worker finished since the last call. Returns
    // true when at least one completion was written.
    bool PollSmartCard();
    bool async_smart_card() const { return scard_async_; }

    RdpdrClient(const RdpdrClient&) = delete;
    RdpdrClient& operator=(const RdpdrClient&) = delete;

    // Feeds one inbound virtual-channel chunk (the MCS Send Data user_data). A
    // message may be split across calls.
    void OnChannelData(const uint8_t* data, size_t size);

    // Drops the per-session protocol state after the transport was replaced
    // (auto-reconnect, [MS-RDPBCGR] 1.3.5). The configuration (file system,
    // device list, smart card backend) is kept; every negotiated capability,
    // channel id and file handle are not. A later OnChannelData() re-runs the
    // announce handshake against the new session.
    void Reset();

    // ---- diagnostics -------------------------------------------------------
    Phase phase() const { return phase_; }
    uint32_t client_id() const { return client_id_; }
    uint16_t version_major() const { return version_major_; }
    uint16_t version_minor() const { return version_minor_; }
    const std::string& client_name() const { return client_name_; }
    const std::vector<Device>& devices() const { return devices_; }
    bool user_logged_on() const { return user_logged_on_; }
    unsigned server_announce_count() const { return server_announce_count_; }
    unsigned server_capability_count() const {
        return server_capability_count_;
    }
    unsigned client_announce_count() const { return client_announce_count_; }
    unsigned client_name_count() const { return client_name_count_; }
    unsigned client_capability_count() const { return client_capability_count_; }
    unsigned device_list_announce_count() const {
        return device_list_announce_count_;
    }
    unsigned device_reply_count() const { return device_reply_count_; }
    unsigned device_remove_count() const { return device_remove_count_; }
    unsigned create_count() const { return create_count_; }
    unsigned read_count() const { return read_count_; }
    unsigned write_count() const { return write_count_; }
    unsigned close_count() const { return close_count_; }
    unsigned query_directory_count() const { return query_directory_count_; }
    unsigned query_volume_count() const { return query_volume_count_; }
    unsigned query_information_count() const { return query_information_count_; }
    unsigned set_information_count() const { return set_information_count_; }
    unsigned set_volume_count() const { return set_volume_count_; }
    unsigned notify_change_count() const { return notify_change_count_; }
    unsigned lock_control_count() const { return lock_control_count_; }
    // Serial READ/WRITE operations served through the serial backend.
    unsigned serial_io_count() const { return serial_io_count_; }
    // Handles currently open on serial devices.
    size_t open_serial_count() const { return serial_handles_.size(); }
    // Printer WRITE operations served through the printer backend.
    unsigned printer_io_count() const { return printer_io_count_; }
    // Print jobs currently open.
    size_t open_printer_count() const { return printer_handles_.size(); }
    unsigned control_count() const { return control_count_; }
    // SCARD_IOCTL_* requests answered through the smart card backend.
    unsigned smartcard_count() const { return smartcard_count_; }
    // Requests whose decoded packet or IOCTL was rejected (fail closed).
    unsigned smartcard_reject_count() const { return smartcard_reject_count_; }
    const std::string& last_scard_ioctl_name() const {
        return last_scard_ioctl_name_;
    }
    const std::string& last_remote_path() const { return last_remote_path_; }
    const std::string& last_local_path() const { return last_local_path_; }
    // Devices whose configured local_root does not exist / is not a directory.
    // Such devices are recorded here and never served an I/O request.
    unsigned device_root_invalid_count() const {
        return device_root_invalid_count_;
    }

 private:
    void OnMessage(const std::vector<uint8_t>& message);
    void OnServerAnnounce(const std::vector<uint8_t>& message);
    void OnServerCapability(const std::vector<uint8_t>& message);
    void OnClientIdConfirm(const std::vector<uint8_t>& message);
    void OnDeviceReply(const std::vector<uint8_t>& message);
    void OnDeviceIoRequest(const std::vector<uint8_t>& message);

    void OnCreate(const std::vector<uint8_t>& body);
    void OnRead(const std::vector<uint8_t>& body);
    void OnWrite(const std::vector<uint8_t>& body);
    void OnClose(const std::vector<uint8_t>& body);
    void OnQueryDirectory(const std::vector<uint8_t>& body);
    void OnControl(const std::vector<uint8_t>& message);
    void OnQueryVolume(const std::vector<uint8_t>& body);
    void OnQueryInformation(const std::vector<uint8_t>& body);
    void OnSetInformation(const std::vector<uint8_t>& body);
    void OnSetVolumeInformation(const std::vector<uint8_t>& body);
    void OnNotifyChangeDirectory(const std::vector<uint8_t>& body);
    void OnLockControl(const std::vector<uint8_t>& body);
    void OnSmartCardControl(const proto::RdpdrControlReq& req);

    // One completed SCARD_IOCTL, ready to be written back to the server.
    // `rejected` marks a malformed/unsupported call or an unencodable return.
    // `generation` pins the completion to the session that issued the call so
    // Reset() can drop answers that belong to a replaced transport (D18).
    struct ScardCompletion {
        proto::RdpdrDeviceIoRequest request;
        uint32_t status = 0;
        std::vector<uint8_t> output;
        bool rejected = false;
        uint64_t generation = 0;
    };
    struct ScardJob {
        proto::RdpdrControlReq request;
        uint64_t generation = 0;
    };
    // Runs the whole SCARD_IOCTL call on the calling thread. Pure with respect
    // to the wire: it does not send anything, so it can later run on a worker
    // thread without touching the transport.
    ScardCompletion BuildSmartCardCompletion(const proto::RdpdrControlReq& req);
    // Counts and writes one completion. Must run on the transport thread.
    void CompleteSmartCard(const ScardCompletion& completion);
    // Worker loop for SetAsyncSmartCard(true).
    void SmartCardWorkerLoop();

    const Device* FindDevice(uint32_t device_id) const;
    // True when `device_id` is an announced serial device.
    bool IsSerialDevice(uint32_t device_id) const;
    // True when `file_id` is an open serial handle.
    bool IsSerialHandle(uint32_t file_id) const;
    // True when `device_id` is an announced printer device.
    bool IsPrinterDevice(uint32_t device_id) const;
    // True when `file_id` is an open print job.
    bool IsPrinterHandle(uint32_t file_id) const;
    std::string MapRemotePath(const std::string& remote,
                              uint32_t device_id) const;
    // Applies a deferred rename/delete recorded by OnSetInformation and drops
    // the handle's path entry. Must run after the file itself is closed.
    void ApplyPendingFileOperation(uint32_t file_id);

    void SendRaw(const std::vector<uint8_t>& pdu);
    void SendIoCompletion(const proto::RdpdrDeviceIoRequest& request,
                          uint32_t status);
    // DR_CONTROL_RSP ([MS-RDPEFS] 2.2.1.5.5): DeviceIoReply + OutputBufferLength
    // + OutputBuffer. `output` is the NDR-encoded *_Return structure.
    void SendControlCompletion(const proto::RdpdrDeviceIoRequest& request,
                               uint32_t status,
                               const std::vector<uint8_t>& output);
    // DR_DRIVE_LOCK_RSP ([MS-RDPEFS] 2.2.3.4.12): DeviceIoReply + 5 bytes of
    // padding.
    void SendLockCompletion(const proto::RdpdrDeviceIoRequest& request,
                            uint32_t status);
    // DR_DRIVE_SET_VOLUME_INFORMATION_RSP ([MS-RDPEFS] 2.2.3.4.7): the
    // DeviceIoReply followed by Length, which MUST match the request Length.
    void SendSetVolumeCompletion(const proto::RdpdrDeviceIoRequest& request,
                                 uint32_t status, uint32_t length);
    // Answers a SCARD_IOCTL with `status` and the matching [MS-RDPESC] 2.2.3.x
    // return (already NDR framed), honouring the server's OutputBufferLength.
    void SendScardCompletion(const ScardCompletion& completion);
    std::vector<uint8_t> BuildClientCapabilities() const;
    std::vector<uint8_t> BuildDeviceListAnnounce() const;

    rdpdr::IFileSystem* fs_;
    rdpdr::ISerialBackend* serial_ = nullptr;
    rdpdr::IPrinterBackend* printer_ = nullptr;
    SendFn send_;
    rtsc::proto::ChannelReassembler reassembler_;
    ::rtsc::smartcard::ISmartCardBackend* scard_ = nullptr;
    uint32_t scard_device_id_ = 0;

    Phase phase_ = Phase::kAwaitServerAnnounce;
    std::vector<Device> devices_;
    std::string client_name_;
    uint32_t client_id_ = 0;
    uint16_t version_major_ = 0;
    uint16_t version_minor_ = 0;

    bool user_logged_on_ = false;
    std::map<uint32_t, uint32_t> device_replies_;
    std::map<uint32_t, uint32_t> open_files_;
    // Per-handle write permission derived from DR_CREATE_REQ.DesiredAccess.
    std::map<uint32_t, bool> file_writable_;
    // Per-handle local path, used to apply a deferred rename/delete on close.
    std::map<uint32_t, std::string> file_paths_;
    // FileDispositionInformation(DeleteFile=TRUE) is applied when the handle
    // closes, like Windows delete-on-close: an open std::fstream cannot be
    // removed on Windows.
    std::set<uint32_t> pending_delete_;
    struct PendingRename {
        std::string path;
        bool replace = false;
    };
    // FileRenameInformation is likewise applied on close.
    std::map<uint32_t, PendingRename> pending_rename_;
    // Byte-range locks taken through IRP_MJ_LOCK_CONTROL, keyed by handle.
    rdpdr::LockTable lock_table_;
    // Serial handles: file_id -> backend handle. Serial file ids are allocated
    // from a high range so they never collide with the file system's ids.
    std::map<uint32_t, uint32_t> serial_handles_;
    // Free serial file ids, reused per [MS-RDPEFS] 2.2.1.5.1.
    std::vector<uint32_t> free_serial_file_ids_;
    uint32_t next_serial_file_id_ = 0x40000000u;

    std::map<uint32_t, uint32_t> printer_handles_;
    // Free printer file ids, reused per [MS-RDPEFS] 2.2.1.5.1.
    std::vector<uint32_t> free_printer_file_ids_;
    uint32_t next_printer_file_id_ = 0x50000000u;

    std::string last_remote_path_;
    std::string last_local_path_;
    unsigned device_root_invalid_count_ = 0;

    unsigned server_announce_count_ = 0;
    unsigned server_capability_count_ = 0;
    unsigned client_announce_count_ = 0;
    unsigned client_name_count_ = 0;
    unsigned client_capability_count_ = 0;
    unsigned device_list_announce_count_ = 0;
    unsigned device_reply_count_ = 0;
    unsigned device_remove_count_ = 0;
    unsigned create_count_ = 0;
    unsigned read_count_ = 0;
    unsigned write_count_ = 0;
    unsigned close_count_ = 0;
    unsigned query_directory_count_ = 0;
    unsigned query_volume_count_ = 0;
    unsigned query_information_count_ = 0;
    unsigned set_information_count_ = 0;
    unsigned set_volume_count_ = 0;
    unsigned notify_change_count_ = 0;
    unsigned lock_control_count_ = 0;
    unsigned serial_io_count_ = 0;
    unsigned printer_io_count_ = 0;
    unsigned control_count_ = 0;
    unsigned smartcard_count_ = 0;
    unsigned smartcard_reject_count_ = 0;
    std::string last_scard_ioctl_name_;

    // Async smart card execution. scard_async_ is only touched by the
    // transport thread; the queues and stop flag are shared with the worker.
    std::thread scard_worker_;
    std::mutex scard_mutex_;
    std::condition_variable scard_cv_;
    std::deque<ScardJob> scard_queue_;
    std::deque<ScardCompletion> scard_done_;
    // Bumped by Reset(): completions tagged with an older generation are
    // dropped instead of being written to the new session.
    uint64_t scard_generation_ = 0;
    bool scard_stop_ = false;
    bool scard_async_ = false;
};

}  // namespace rtsc::channel
