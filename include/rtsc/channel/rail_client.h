// RAIL (Remote Programs Virtual Channel) client handler ([MS-RDPERP]).
//
// The connection driver hands this class the raw MCS Send Data user_data of the
// "rail" static virtual channel, which is a CHANNEL_PDU_HEADER followed by one
// or more RAIL orders. The handler reassembles the chunked channel message with
// proto::RailChannel, decodes each order, tracks the RemoteApp window state the
// server reports, and exposes the client-to-server orders (Exec, Syscommand,
// GetAppIdReq, ...).
//
// Direction ([MS-RDPERP] 2.2.2): the client SENDS TS_RAIL_ORDER_EXEC,
// TS_RAIL_ORDER_SYSCOMMAND, TS_RAIL_ORDER_GET_APPID_REQ, ... and RECEIVES
// TS_RAIL_ORDER_EXEC_RESULT, TS_RAIL_ORDER_GET_APPID_RESP,
// TS_RAIL_ORDER_WINDOWMOVE, TS_RAIL_ORDER_MINMAXINFO, TS_RAIL_ORDER_TASKBARINFO
// and TS_RAIL_ORDER_LANGBARINFO. This class follows that direction. For
// robustness it also answers a peer that sends GetAppIdReq with GetAppIdResp
// (see set_auto_respond_get_app_id).
//
// Reference: [MS-RDPERP] 2.2.2 (client orders), 2.2.2.8 (GetAppIdResp),
// 2.2.2.2 (Handshake / ClientStatus).

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "rtsc/proto/rail.h"

namespace rtsc::channel {

class RailClient {
 public:
    // Receives a complete channel message (CHANNEL_PDU_HEADER + RAIL orders).
    // The caller wraps it in an MCS Send Data Request and writes it.
    using SendFn = std::function<void(const std::vector<uint8_t>&)>;

    // Receives each decoded inbound RAIL order. The handler has already updated
    // the window state and counters; the callback can react to the order.
    using OrderHandler = std::function<void(const rtsc::proto::RailPdu&)>;

    RailClient();
    explicit RailClient(SendFn send);
    ~RailClient();

    RailClient(const RailClient&) = delete;
    RailClient& operator=(const RailClient&) = delete;

    // Rebinds the send function (e.g. after the rail channel id is known).
    void SetSendFn(SendFn send) { send_ = std::move(send); }
    bool has_send_fn() const { return static_cast<bool>(send_); }

    // Feeds one inbound virtual-channel chunk (the MCS Send Data user_data). A
    // message may be split across calls.
    void OnChannelData(const uint8_t* data, size_t size);

    // Drops the per-session state after the transport was replaced
    // (auto-reconnect, [MS-RDPBCGR] 1.3.5). The configuration (send function,
    // order handler, AppUserModelID map) is kept; the server-reported window
    // state and the reassembly buffer are not.
    void Reset();

    void SetHandler(OrderHandler handler) { handler_ = std::move(handler); }

    // Sends the client's opening orders: the Handshake (a response to the
    // server's Handshake, [MS-RDPERP] 2.2.2.2.1) and the Client Information
    // (ClientStatus). Call once the rail channel has been joined.
    void Start(uint32_t build_number = 0, uint32_t client_flags = 0);

    // ---- client -> server orders -------------------------------------------
    bool SendHandshake(uint32_t build_number);
    bool SendHandshakeEx(uint32_t build_number, uint32_t flags);
    bool SendClientStatus(uint32_t flags);
    bool SendExec(const rtsc::proto::RailClientExecute& exec);
    bool SendSyscommand(uint32_t window_id, uint16_t command);
    bool SendSysmenu(uint32_t window_id, int16_t left, int16_t top);
    bool SendGetAppIdReq(uint32_t window_id);
    // The ApplicationId field is a fixed 512-byte null-terminated UTF-16 string
    // ([MS-RDPERP] 2.2.2.8.1); orderLength is 520.
    bool SendGetAppIdResp(uint32_t window_id, const std::u16string& app_id);
    bool SendActivate(uint32_t window_id, bool enabled);
    bool SendLangbarInfo(uint32_t status);
    bool SendSysparam(const rtsc::proto::RailSysparamOrder& order);
    bool SendLocalMoveSize(const rtsc::proto::RailLocalMoveSize& order);

    // The AppUserModelID this client reports for `window_id` when it answers a
    // GetAppIdReq. Empty means an empty (null-terminated) ApplicationId.
    void SetAppUserModelId(uint32_t window_id, const std::u16string& app_id) {
        app_ids_[window_id] = app_id;
    }
    // When true (the default) a peer that sends GetAppIdReq is answered with a
    // GetAppIdResp. A conformant server only sends GetAppIdResp, so this is a
    // no-op against a spec-conformant peer.
    void set_auto_respond_get_app_id(bool on) { auto_respond_get_app_id_ = on; }
    bool auto_respond_get_app_id() const { return auto_respond_get_app_id_; }

    // ---- server -> client state --------------------------------------------
    bool has_window_move() const { return has_window_move_; }
    const rtsc::proto::RailWindowMove& window_move() const { return window_move_; }
    bool has_minmax_info() const { return has_minmax_info_; }
    const rtsc::proto::RailMinMaxInfo& minmax_info() const { return minmax_info_; }
    bool has_taskbar_info() const { return has_taskbar_info_; }
    const rtsc::proto::RailTaskbarInfo& taskbar_info() const {
        return taskbar_info_;
    }
    bool has_langbar_info() const { return has_langbar_info_; }
    const rtsc::proto::RailLangbarInfo& langbar_info() const {
        return langbar_info_;
    }
    bool has_exec_result() const { return has_exec_result_; }
    const rtsc::proto::RailExecuteResult& exec_result() const { return exec_result_; }
    bool has_app_id() const { return has_app_id_; }
    uint32_t app_id_window() const { return app_id_window_; }
    const std::u16string& app_id() const { return app_id_; }
    // The extended response (0x0018, [MS-RDPERP] 2.2.2.8.2): the ApplicationId
    // plus the process id and image name.
    bool has_app_id_ex() const { return has_app_id_ex_; }
    uint32_t app_id_ex_window() const { return app_id_ex_window_; }
    const rtsc::proto::RailGetAppIdRespEx& app_id_ex() const { return app_id_ex_; }

    // ---- diagnostics -------------------------------------------------------
    unsigned pdu_count() const;
    unsigned handshake_count() const;
    unsigned handshake_ex_count() const;
    unsigned client_status_count() const;
    unsigned exec_count() const;
    unsigned exec_result_count() const;
    unsigned syscommand_count() const;
    unsigned sysmenu_count() const;
    unsigned window_move_count() const;
    unsigned minmax_info_count() const;
    unsigned taskbar_count() const;
    unsigned langbar_count() const;
    unsigned get_app_id_req_count() const { return get_app_id_req_count_; }
    unsigned get_app_id_resp_count() const { return get_app_id_resp_count_; }
    unsigned get_app_id_resp_ex_count() const { return get_app_id_resp_ex_count_; }
    unsigned incomplete_message_count() const;
    unsigned send_count() const { return send_count_; }

 private:
    void OnPdu(const rtsc::proto::RailPdu& pdu);
    bool SendRaw(const std::vector<uint8_t>& pdu);

    rtsc::proto::RailChannel channel_;
    SendFn send_;
    OrderHandler handler_;

    bool auto_respond_get_app_id_ = true;
    std::map<uint32_t, std::u16string> app_ids_;

    bool has_window_move_ = false;
    rtsc::proto::RailWindowMove window_move_{};
    bool has_minmax_info_ = false;
    rtsc::proto::RailMinMaxInfo minmax_info_{};
    bool has_taskbar_info_ = false;
    rtsc::proto::RailTaskbarInfo taskbar_info_{};
    bool has_langbar_info_ = false;
    rtsc::proto::RailLangbarInfo langbar_info_{};
    bool has_exec_result_ = false;
    rtsc::proto::RailExecuteResult exec_result_{};
    bool has_app_id_ = false;
    uint32_t app_id_window_ = 0;
    std::u16string app_id_;
    bool has_app_id_ex_ = false;
    uint32_t app_id_ex_window_ = 0;
    rtsc::proto::RailGetAppIdRespEx app_id_ex_{};

    unsigned client_status_count_ = 0;
    unsigned minmax_info_count_ = 0;
    unsigned get_app_id_req_count_ = 0;
    unsigned get_app_id_resp_count_ = 0;
    unsigned get_app_id_resp_ex_count_ = 0;
    unsigned send_count_ = 0;
};

}  // namespace rtsc::channel
