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

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "rtsc/proto/channel.h"
#include "rtsc/proto/rdpdr.h"
#include "rtsc/rdpdr/file_system.h"
#include "rtsc/rdpdr/path_guard.h"

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

    // One redirected drive. `dos_name` is the 8-character field of the
    // DEVICE_ANNOUNCE (e.g. "C:"); `local_root` is the local directory the
    // drive maps to (e.g. "C:\\").
    struct Device {
        uint32_t device_id = 0;
        std::string dos_name;
        std::string local_root;
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

    RdpdrClient(const RdpdrClient&) = delete;
    RdpdrClient& operator=(const RdpdrClient&) = delete;

    // Feeds one inbound virtual-channel chunk (the MCS Send Data user_data). A
    // message may be split across calls.
    void OnChannelData(const uint8_t* data, size_t size);

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
    unsigned create_count() const { return create_count_; }
    unsigned read_count() const { return read_count_; }
    unsigned write_count() const { return write_count_; }
    unsigned close_count() const { return close_count_; }
    unsigned query_directory_count() const { return query_directory_count_; }
    unsigned control_count() const { return control_count_; }
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

    const Device* FindDevice(uint32_t device_id) const;
    std::string MapRemotePath(const std::string& remote,
                              uint32_t device_id) const;

    void SendRaw(const std::vector<uint8_t>& pdu);
    void SendIoCompletion(const proto::RdpdrDeviceIoRequest& request,
                          uint32_t status);
    std::vector<uint8_t> BuildClientCapabilities() const;
    std::vector<uint8_t> BuildDeviceListAnnounce() const;

    rdpdr::IFileSystem* fs_;
    SendFn send_;
    rtsc::proto::ChannelReassembler reassembler_;

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
    unsigned create_count_ = 0;
    unsigned read_count_ = 0;
    unsigned write_count_ = 0;
    unsigned close_count_ = 0;
    unsigned query_directory_count_ = 0;
    unsigned control_count_ = 0;
};

}  // namespace rtsc::channel
